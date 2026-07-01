"""
Real Hardhat blockchain backend for Experiments 3 and 4.

Implements the same interface as SimulatedBlockchain but uses web3.py
to submit actual transactions to a local Hardhat node, returning
real gas costs and measured latencies.

Usage:
    The Hardhat node must already be running. Either start it manually:
        cd smart-contracts && npx hardhat node &
    Or it will be started by the experiment runner.

    from relay_system.hardhat_backend import HardhatBackend
    backend = HardhatBackend()
    backend.deploy_contracts()
    tx_hash = backend.submit_meta_transaction(...)
"""

import hashlib
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from shared.config import (
    HARDHAT_URL,
    HARDHAT_CHAIN_ID,
    FALCON_512_PUBLIC_KEY_SIZE,
    FALCON_512_SIGNATURE_SIZE_MAX,
)


class HardhatBackend:
    """
    Real Hardhat blockchain backend.

    Provides the same interface as SimulatedBlockchain but uses web3.py
    for actual EVM execution. Returns real gas costs from transaction
    receipts and measures actual submission latency.

    Thread-safe: all web3 calls are serialized via self._lock to prevent
    race conditions when used from concurrent threads (scalability).
    """

    # Theoretical on-chain Falcon verification gas (see derivation in iot_client.py)
    GAS_THEORETICAL_FALCON = 500_000_000

    def __init__(self, hardhat_url: str = HARDHAT_URL, chain_id: int = HARDHAT_CHAIN_ID):
        self.hardhat_url = hardhat_url
        self.chain_id = chain_id
        self._w3 = None
        self._did_registry = None
        self._meta_tx_relay = None
        self._ecdsa_verify = None
        self._lock = threading.Lock()
        self._transactions: dict[str, dict] = {}
        self._tx_order: list[str] = []
        self._block_number = 0
        self._registered_dids: set[bytes] = set()
        self._ecdsa_keys: dict[str, tuple] = {}  # sender -> (address, private_key)
        self._owner = None
        self._relay_account = None

    def _get_w3(self):
        """Lazy-init web3 connection."""
        if self._w3 is not None:
            return self._w3
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(self.hardhat_url))
        if not w3.is_connected():
            raise ConnectionError(
                f"Cannot connect to Hardhat at {self.hardhat_url}. "
                f"Start with: cd smart-contracts && npx hardhat node"
            )
        self._w3 = w3
        return w3

    def _load_artifact(self, contract_name: str) -> dict:
        """Load compiled contract artifact."""
        smart_contracts_dir = Path(__file__).parent.parent / "smart-contracts"
        artifact_path = (
            smart_contracts_dir / "artifacts" / "contracts" / f"{contract_name}.sol" / f"{contract_name}.json"
        )
        if not artifact_path.exists():
            raise FileNotFoundError(
                f"Contract artifact not found: {artifact_path}. "
                f"Run: cd smart-contracts && npx hardhat compile"
            )
        return json.loads(artifact_path.read_text())

    def deploy_contracts(self) -> dict:
        """Deploy DIDRegistry, MetaTxRelay, and ECDSAVerify contracts.

        Returns dict with contract addresses and deploy gas.
        """
        w3 = self._get_w3()
        accounts = w3.eth.accounts

        # Load artifacts
        did_artifact = self._load_artifact("DIDRegistry")
        meta_artifact = self._load_artifact("MetaTxRelay")
        ecdsa_artifact = self._load_artifact("ECDSAVerify")

        # Deploy DIDRegistry
        did_contract = w3.eth.contract(
            abi=did_artifact["abi"],
            bytecode=did_artifact["bytecode"],
        )
        did_tx_hash = did_contract.constructor().transact({"from": accounts[0]})
        did_receipt = w3.eth.wait_for_transaction_receipt(did_tx_hash)
        did_registry = w3.eth.contract(
            address=did_receipt.contractAddress,
            abi=did_artifact["abi"],
        )

        # Deploy MetaTxRelay (needs DIDRegistry address)
        meta_contract = w3.eth.contract(
            abi=meta_artifact["abi"],
            bytecode=meta_artifact["bytecode"],
        )
        meta_tx_hash = meta_contract.constructor(
            did_registry.address
        ).transact({"from": accounts[0]})
        meta_receipt = w3.eth.wait_for_transaction_receipt(meta_tx_hash)
        meta_tx_relay = w3.eth.contract(
            address=meta_receipt.contractAddress,
            abi=meta_artifact["abi"],
        )

        # Deploy ECDSAVerify (for fair ECDSA baseline comparison)
        ecdsa_contract = w3.eth.contract(
            abi=ecdsa_artifact["abi"],
            bytecode=ecdsa_artifact["bytecode"],
        )
        ecdsa_tx_hash = ecdsa_contract.constructor().transact({"from": accounts[0]})
        ecdsa_receipt = w3.eth.wait_for_transaction_receipt(ecdsa_tx_hash)
        ecdsa_verify = w3.eth.contract(
            address=ecdsa_receipt.contractAddress,
            abi=ecdsa_artifact["abi"],
        )

        self._did_registry = did_registry
        self._meta_tx_relay = meta_tx_relay
        self._ecdsa_verify = ecdsa_verify
        self._owner = accounts[0]
        self._relay_account = accounts[1]

        return {
            "did_registry_address": did_registry.address,
            "meta_tx_relay_address": meta_tx_relay.address,
            "ecdsa_verify_address": ecdsa_verify.address,
            "deployer": accounts[0],
            "deploy_gas": did_receipt.gasUsed + meta_receipt.gasUsed + ecdsa_receipt.gasUsed,
        }

    def _ensure_did_registered(self, did_hash: bytes, public_key: bytes) -> None:
        """Register a DID on-chain if not already registered (thread-safe)."""
        with self._lock:
            if did_hash in self._registered_dids:
                return
            w3 = self._get_w3()
            tx_hash = self._did_registry.functions.registerDID(
                did_hash, public_key
            ).transact({"from": self._owner})
            w3.eth.wait_for_transaction_receipt(tx_hash)
            self._registered_dids.add(did_hash)

    def _get_ecdsa_key(self, sender: str) -> tuple[str, bytes]:
        """Get or create an ECDSA key pair for a sender.

        Returns (address, private_key_bytes).
        """
        if sender in self._ecdsa_keys:
            return self._ecdsa_keys[sender]

        from eth_account import Account

        # Create a deterministic account from sender string
        priv_key_bytes = hashlib.sha256(sender.encode()).digest()
        account = Account.from_key(priv_key_bytes)

        # Store raw bytes for signing (account.key type varies by version)
        self._ecdsa_keys[sender] = (account.address, priv_key_bytes)
        return account.address, priv_key_bytes

    @staticmethod
    def _sign_hash(data_hash_bytes32: bytes, priv_key_bytes: bytes):
        """Sign a raw hash with a private key (for ecrecover compatibility).

        Handles version differences between eth_account releases.
        """
        from eth_account import Account

        # signHash renamed to unsafe_sign_hash in eth_account >= 0.10
        sign_fn = getattr(Account, "signHash", None)
        if sign_fn is None:
            sign_fn = getattr(Account, "unsafe_sign_hash")
        return sign_fn(data_hash_bytes32, priv_key_bytes)

    def submit_transaction(
        self, sender: str, data_hash: str, payload_size: int,
        store_signature: bool = True,
    ) -> str:
        """Submit a direct ECDSA-verified transaction (fair baseline).

        Uses the ECDSAVerify contract to perform actual ecrecover()
        signature verification on-chain. When store_signature=True (default),
        also stores the full 64-byte ECDSA signature (r, s) on-chain,
        making this a fair comparison against the relay meta-transaction
        which stores the full Falcon signature.

        Gas costs:
          - store_signature=False: ~35K gas (ecrecover + dataHash + signer)
          - store_signature=True:  ~50K gas (above + sigR + sigS storage)
        """
        w3 = self._get_w3()
        accounts = w3.eth.accounts

        # Get ECDSA key pair for this sender
        sender_addr, sender_privkey = self._get_ecdsa_key(sender)

        # Hash the data with keccak256 (matches Solidity keccak256)
        data_bytes = bytes.fromhex(data_hash[:64]) if len(data_hash) >= 64 else data_hash.encode()
        from web3 import Web3
        data_hash_bytes32 = Web3.keccak(data_bytes)

        # Sign with ECDSA private key (raw hash for ecrecover)
        signature = self._sign_hash(data_hash_bytes32, sender_privkey)

        r_bytes = signature.r.to_bytes(32, "big") if isinstance(signature.r, int) else signature.r
        s_bytes = signature.s.to_bytes(32, "big") if isinstance(signature.s, int) else signature.s

        start = time.perf_counter()

        with self._lock:
            # Send from a Hardhat pre-funded account (accounts[2]).
            # The signature is from our derived key; the contract's ecrecover
            # will recover sender_addr.
            if store_signature:
                # Fair baseline: stores full ECDSA signature (64 bytes)
                tx_hash_bytes = self._ecdsa_verify.functions.submitVerifyAndStore(
                    data_hash_bytes32,
                    signature.v,
                    r_bytes,
                    s_bytes,
                ).transact({"from": accounts[2]})
            else:
                tx_hash_bytes = self._ecdsa_verify.functions.submitAndVerify(
                    data_hash_bytes32,
                    signature.v,
                    r_bytes,
                    s_bytes,
                ).transact({"from": accounts[2]})
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash_bytes)

        latency = (time.perf_counter() - start) * 1000

        # Generate a tracking ID
        tx_id = receipt.transactionHash.hex()

        self._block_number = max(self._block_number, receipt.blockNumber)
        self._transactions[tx_id] = {
            "sender": sender,
            "data_hash": data_hash,
            "payload_size": payload_size,
            "gas_used": receipt.gasUsed,
            "block_number": receipt.blockNumber,
            "latency_ms": latency,
            "timestamp": time.time(),
            "store_signature": store_signature,
        }
        self._tx_order.append(tx_id)
        return tx_id

    def submit_meta_transaction(
        self,
        relay_address: str,
        data_hash: str,
        signature_size: int,
        did_active: bool = True,
        # Additional parameters for real blockchain
        data_hash_bytes: bytes = None,
        did_hash_bytes: bytes = None,
        signature_bytes: bytes = None,
        did_public_key: bytes = None,
    ) -> str:
        """Submit a relay-assisted meta-transaction to Hardhat.

        Returns real gas cost and measured latency.
        Thread-safe: serialized via self._lock.
        """
        w3 = self._get_w3()

        # Use provided bytes or generate defaults
        if data_hash_bytes is None:
            data_hash_bytes = hashlib.sha256(data_hash.encode()).digest()
        if did_hash_bytes is None:
            did_hash_bytes = hashlib.sha256(b"did:falconiot:default-device").digest()
        if signature_bytes is None:
            signature_bytes = os.urandom(min(signature_size, FALCON_512_SIGNATURE_SIZE_MAX))
        if did_public_key is None:
            did_public_key = os.urandom(FALCON_512_PUBLIC_KEY_SIZE)

        # Ensure DID is registered on-chain (thread-safe internally)
        self._ensure_did_registered(did_hash_bytes, did_public_key)

        start = time.perf_counter()

        with self._lock:
            tx_hash = self._meta_tx_relay.functions.submitTransaction(
                data_hash_bytes,
                did_hash_bytes,
                signature_bytes,
                did_active,
            ).transact({"from": self._relay_account})
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        latency = (time.perf_counter() - start) * 1000

        tx_id = receipt.transactionHash.hex()
        self._block_number = max(self._block_number, receipt.blockNumber)
        self._transactions[tx_id] = {
            "sender": relay_address,
            "data_hash": data_hash,
            "signature_size": signature_size,
            "gas_used": receipt.gasUsed,
            "block_number": receipt.blockNumber,
            "latency_ms": latency,
            "timestamp": time.time(),
            "type": "meta_transaction",
        }
        self._tx_order.append(tx_id)
        return tx_id

    def submit_batch_transaction(
        self,
        relay_address: str,
        batch_data: list[dict],
    ) -> list[str]:
        """Submit a batch of meta-transactions to Hardhat.

        Each item in batch_data should have:
          - data_hash (str)
          - data_hash_bytes (bytes, optional)
          - did_hash_bytes (bytes, optional)
          - signature_bytes (bytes, optional)
          - did_public_key (bytes, optional)
          - verified (bool, optional, default True)
          - signature_size (int, optional)
        """
        tx_ids = []
        for item in batch_data:
            tx_id = self.submit_meta_transaction(
                relay_address=relay_address,
                data_hash=item["data_hash"],
                signature_size=item.get("signature_size", FALCON_512_SIGNATURE_SIZE_MAX),
                did_active=item.get("verified", True),
                data_hash_bytes=item.get("data_hash_bytes"),
                did_hash_bytes=item.get("did_hash_bytes"),
                signature_bytes=item.get("signature_bytes"),
                did_public_key=item.get("did_public_key"),
            )
            tx_ids.append(tx_id)
        return tx_ids

    def get_receipt(self, tx_hash: str) -> dict | None:
        """Get receipt for a previously submitted transaction."""
        return self._transactions.get(tx_hash)

    def transaction_count(self) -> int:
        return len(self._tx_order)

    def block_number(self) -> int:
        return self._block_number

    def compute_data_hash(self, payload: bytes) -> str:
        """Compute SHA-256 hash of payload, returning hex digest."""
        return hashlib.sha256(payload).hexdigest()

    def get_gas_decomposition(self) -> dict:
        """Decompose gas costs from completed transactions.

        Breaks down the relay meta-transaction gas into components:
          - Base transaction cost (21,000 gas for ETH transfer)
          - DID active check (SLOAD)
          - Replay commitment (SSTORE for mapping + keccak256)
          - Public key hash (keccak256 of 897-byte key)
          - Falcon signature storage (SSTORE for 752 bytes in dynamic array)
          - Event emission (LOG1 for TransactionSubmitted)

        Returns dict with estimated gas breakdown.
        """
        relay_txs = []
        ecdsa_txs = []
        ecdsa_store_txs = []

        for tx_id in self._tx_order:
            tx = self._transactions.get(tx_id, {})
            if tx.get("type") == "meta_transaction":
                relay_txs.append(tx["gas_used"])
            elif tx.get("store_signature"):
                ecdsa_store_txs.append(tx["gas_used"])
            elif "gas_used" in tx:
                ecdsa_txs.append(tx["gas_used"])

        result = {}

        if relay_txs:
            avg_relay_gas = sum(relay_txs) / len(relay_txs)
            result["relay_avg_gas"] = avg_relay_gas
            result["relay_tx_count"] = len(relay_txs)
            # Decompose: base tx (21K) + contract overhead
            base_tx = 21_000
            result["relay_base_tx_gas"] = base_tx
            result["relay_contract_overhead"] = avg_relay_gas - base_tx

        if ecdsa_txs:
            result["ecdsa_verify_avg_gas"] = sum(ecdsa_txs) / len(ecdsa_txs)
            result["ecdsa_tx_count"] = len(ecdsa_txs)

        if ecdsa_store_txs:
            result["ecdsa_store_avg_gas"] = sum(ecdsa_store_txs) / len(ecdsa_store_txs)
            result["ecdsa_store_tx_count"] = len(ecdsa_store_txs)

        # Cross-comparison
        if relay_txs and ecdsa_store_txs:
            relay_avg = sum(relay_txs) / len(relay_txs)
            ecdsa_avg = sum(ecdsa_store_txs) / len(ecdsa_store_txs)
            result["relay_vs_ecdsa_store_ratio"] = relay_avg / ecdsa_avg if ecdsa_avg > 0 else 0

        return result

    @staticmethod
    def is_available(url: str = HARDHAT_URL) -> bool:
        """Check if Hardhat node is running."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(url))
            return w3.is_connected()
        except Exception:
            return False
