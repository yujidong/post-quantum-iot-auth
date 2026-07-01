"""
Real Hardhat blockchain runner for Experiment 3.

Provides an optional real-blockchain mode that uses web3.py to deploy
smart contracts and submit actual transactions to a local Hardhat node.

Falls back to SimulatedBlockchain if Hardhat is not available.

Usage:
    # Start Hardhat in background first:
    cd smart-contracts && npx hardhat node &

    # Then run comparison with real blockchain:
    python -c "
    from relay_system.hardhat_runner import HardhatRunner
    runner = HardhatRunner()
    runner.run_gas_comparison()
    "
"""
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from shared.config import (
    HARDHAT_URL,
    HARDHAT_CHAIN_ID,
    FALCON_512_PUBLIC_KEY_SIZE,
    FALCON_512_SIGNATURE_SIZE_MAX,
)


class HardhatRunner:
    """
    Runs relay vs direct comparison using a real Hardhat local blockchain.

    Uses web3.py to interact with deployed Solidity contracts.
    Measures actual gas costs from Hardhat receipts.
    """

    def __init__(
        self,
        hardhat_url: str = HARDHAT_URL,
        chain_id: int = HARDHAT_CHAIN_ID,
    ):
        self.hardhat_url = hardhat_url
        self.chain_id = chain_id
        self._w3 = None
        self._did_registry = None
        self._meta_tx_relay = None
        self._hardhat_process = None

    def _get_w3(self):
        """Lazy-init web3 connection."""
        if self._w3 is not None:
            return self._w3

        try:
            from web3 import Web3
        except ImportError:
            raise ImportError(
                "web3.py is required for real blockchain mode. "
                "Install with: pip install web3"
            )

        w3 = Web3(Web3.HTTPProvider(self.hardhat_url))
        if not w3.is_connected():
            raise ConnectionError(
                f"Cannot connect to Hardhat at {self.hardhat_url}. "
                f"Start with: cd smart-contracts && npx hardhat node"
            )
        self._w3 = w3
        return w3

    def start_hardhat(self) -> bool:
        """Start Hardhat local node in background.

        Returns True if started successfully.
        """
        smart_contracts_dir = Path(__file__).parent.parent / "smart-contracts"
        if not (smart_contracts_dir / "hardhat.config.js").exists():
            return False

        try:
            self._hardhat_process = subprocess.Popen(
                ["npx", "hardhat", "node"],
                cwd=str(smart_contracts_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Wait for Hardhat to start
            for _ in range(30):
                time.sleep(1)
                try:
                    w3 = self._get_w3()
                    if w3.is_connected():
                        return True
                except Exception:
                    pass
            return False
        except Exception:
            return False

    def stop_hardhat(self):
        """Stop the background Hardhat node."""
        if self._hardhat_process:
            self._hardhat_process.terminate()
            self._hardhat_process.wait(timeout=10)
            self._hardhat_process = None

    def deploy_contracts(self) -> dict:
        """Deploy DIDRegistry and MetaTxRelay contracts.

        Returns dict with contract addresses.
        """
        w3 = self._get_w3()
        accounts = w3.eth.accounts

        # Load compiled contract artifacts
        smart_contracts_dir = Path(__file__).parent.parent / "smart-contracts"

        # DIDRegistry
        did_artifact_path = smart_contracts_dir / "artifacts" / "contracts" / "DIDRegistry.sol" / "DIDRegistry.json"
        meta_artifact_path = smart_contracts_dir / "artifacts" / "contracts" / "MetaTxRelay.sol" / "MetaTxRelay.json"

        if not did_artifact_path.exists() or not meta_artifact_path.exists():
            # Try compiling
            subprocess.run(
                ["npx", "hardhat", "compile"],
                cwd=str(smart_contracts_dir),
                capture_output=True, timeout=120,
            )

        did_artifact = json.loads(did_artifact_path.read_text())
        meta_artifact = json.loads(meta_artifact_path.read_text())

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

        # Deploy MetaTxRelay
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

        self._did_registry = did_registry
        self._meta_tx_relay = meta_tx_relay

        return {
            "did_registry_address": did_registry.address,
            "meta_tx_relay_address": meta_tx_relay.address,
            "deployer": accounts[0],
            "deploy_gas": did_receipt.gasUsed + meta_receipt.gasUsed,
        }

    def register_did(self, did_hash: bytes, public_key: bytes, sender: str) -> int:
        """Register a DID. Returns gas used."""
        tx_hash = self._did_registry.functions.registerDID(
            did_hash, public_key
        ).transact({"from": sender})
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt.gasUsed

    def submit_relay_transaction(
        self,
        data_hash: bytes,
        did_hash: bytes,
        signature: bytes,
        verified: bool,
        sender: str,
    ) -> dict:
        """Submit a relay meta-transaction. Returns metrics dict."""
        start = time.perf_counter()
        tx_hash = self._meta_tx_relay.functions.submitTransaction(
            data_hash, did_hash, signature, verified
        ).transact({"from": sender})
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        latency = (time.perf_counter() - start) * 1000

        return {
            "gas_used": receipt.gasUsed,
            "latency_ms": latency,
            "block_number": receipt.blockNumber,
            "tx_hash": receipt.transactionHash.hex(),
        }

    def run_gas_comparison(
        self,
        num_transactions: int = 20,
    ) -> dict:
        """Run a gas cost comparison using real Hardhat transactions.

        Args:
            num_transactions: Number of transactions to submit.

        Returns:
            Comparison results with real gas costs.
        """
        w3 = self._get_w3()
        accounts = w3.eth.accounts
        deploy_info = self.deploy_contracts()

        owner = accounts[0]
        relay = accounts[1]

        # Register DID for relay tests
        did_hash = hashlib.sha256(b"did:falconiot:hardhat-test").digest()
        pub_key = os.urandom(FALCON_512_PUBLIC_KEY_SIZE)
        reg_gas = self.register_did(did_hash, pub_key, owner)

        # Submit relay transactions
        relay_gas_costs = []
        relay_latencies = []

        for i in range(num_transactions):
            data_hash = hashlib.sha256(f"test-data-{i}".encode()).digest()
            sig = os.urandom(FALCON_512_SIGNATURE_SIZE_MAX)

            result = self.submit_relay_transaction(
                data_hash=data_hash,
                did_hash=did_hash,
                signature=sig,
                verified=True,
                sender=relay,
            )
            relay_gas_costs.append(result["gas_used"])
            relay_latencies.append(result["latency_ms"])

        avg_gas = sum(relay_gas_costs) / len(relay_gas_costs)
        avg_lat = sum(relay_latencies) / len(relay_latencies)

        return {
            "blockchain": "hardhat",
            "transactions": num_transactions,
            "did_registration_gas": reg_gas,
            "relay_avg_gas": avg_gas,
            "relay_min_gas": min(relay_gas_costs),
            "relay_max_gas": max(relay_gas_costs),
            "relay_avg_latency_ms": avg_lat,
            "contract_addresses": {
                "did_registry": deploy_info["did_registry_address"],
                "meta_tx_relay": deploy_info["meta_tx_relay_address"],
            },
        }

    def is_available(self) -> bool:
        """Check if Hardhat blockchain is available."""
        try:
            w3 = self._get_w3()
            return w3.is_connected()
        except Exception:
            return False
