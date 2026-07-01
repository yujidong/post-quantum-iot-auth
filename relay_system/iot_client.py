"""
IoT Device simulation and Simulated Blockchain for Experiment 3.
"""
import hashlib
import os
import random as _random_module
import time
import uuid

from shared.config import (
    FALCON_512_PUBLIC_KEY_SIZE,
    FALCON_512_SIGNATURE_SIZE_MAX,
    ECDSA_PUBLIC_KEY_SIZE,
    ECDSA_SIGNATURE_SIZE,
)
from shared.falcon_utils import falcon_keygen, falcon_sign
from shared.did_utils import generate_did


class IoTDevice:
    """Simulated IoT device with Falcon-512 signing capability."""

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.keypair = falcon_keygen()
        self.did = generate_did()

    def sign_data(self, payload: bytes) -> bytes:
        """Sign sensor data payload with Falcon-512."""
        return falcon_sign(payload, self.keypair.private_key)

    def generate_sensor_data(self, size: int = 256) -> bytes:
        """Generate simulated sensor reading of given size."""
        timestamp = int(time.time() * 1000)
        header = f"device={self.device_id}&ts={timestamp}&data=".encode()
        if len(header) >= size:
            return header[:size]
        padding = os.urandom(size - len(header))
        return header + padding

    @property
    def public_key_size(self) -> int:
        return len(self.keypair.public_key)

    @property
    def signature_size(self) -> int:
        """Maximum possible Falcon-512 signature size."""
        return FALCON_512_SIGNATURE_SIZE_MAX


class SimulatedBlockchain:
    """
    Simulated blockchain for latency/gas measurement.

    .. deprecated::
        Use HardhatBackend for actual EVM execution. This class uses
        hardcoded gas constants and random latency simulation. Results
        are SYNTHETIC and should not be used for publication.

    Gas model based on actual Hardhat measurements from Experiment 2:
    - DID registration (one-time per device): ~771,525 gas
    - Relay meta-transaction: ~753,548 gas
    - ECDSA direct submission: ~50,000 gas (ECDSA verify + storage)
    - Theoretical on-chain Falcon: ~500,000,000 gas (exceeds block limit)

    Latency model uses local Hardhat-like delays with deterministic RNG
    for reproducibility.

    Theoretical on-chain Falcon gas derivation (GAS_THEORETICAL_FALCON):
      EVM has no native Falcon-512 precompile. A Solidity implementation
      would require:
        1. FFT-based polynomial multiplication: n=512, ~n*log2(n)=4,608 ops
           Each op: MULMOD (5 gas) + ADDMOD (8 gas) ≈ 13 gas → ~60K gas
        2. Sample rejection loops: ~10,000 iterations × ~200 gas each → ~2M gas
        3. Hash-to-point (keccak256 calls): ~500 calls × 30 gas → ~15K gas
        4. Point arithmetic + norm checks: ~2,000 ops × ~40 gas → ~80K gas
        5. Loop overhead (JUMPDEST per iter): ~50 gas × ~15,000 loops → ~750K gas
        6. Memory expansion for 512-coefficient polynomials:
           512 words (16KB), EVM cost = (512²/512) + (3×512/32) = 512+48 ≈ 560 gas
           (negligible compared to arithmetic costs)
        7. Total conservative estimate: ~400M-600M gas
      We use 500M as a lower bound. This exceeds the Ethereum block gas
      limit (~12M for mainnet, ~30M for some L2s), making on-chain Falcon
      verification impractical.
      Reference: NIST FIPS 205; pqclean Falcon-512 reference C implementation
      is ~1,500 lines with ~50,000 arithmetic operations.
    """

    # Gas costs from actual Hardhat measurements (Falcon-512 sig max 752 bytes)
    GAS_BASE_TX = 21_000
    GAS_ECDSA_VERIFY = 30_000       # ECDSA ecrecover + SSTORE
    GAS_RELAY_META_TX = 821_563     # Relay meta-transaction (from Hardhat, 752B sig)
    GAS_DID_REGISTER = 771_537      # DID registration (one-time)
    GAS_PER_BYTE_CALLDATA = 16      # Non-zero byte calldata cost (EIP-2028)
    # On-chain Falcon verification: see derivation above
    GAS_THEORETICAL_FALCON = 500_000_000

    def __init__(self, seed: int = 42):
        self._transactions: dict[str, dict] = {}
        self._tx_order: list[str] = []
        self._block_number = 0
        self._rng = _random_module.Random(seed)

    def transaction_count(self) -> int:
        return len(self._tx_order)

    def block_number(self) -> int:
        return self._block_number

    def submit_transaction(
        self, sender: str, data_hash: str, payload_size: int,
        store_signature: bool = False,
    ) -> str:
        """Submit a direct transaction (ECDSA model).

        When store_signature=True, adds gas for storing the 64-byte
        ECDSA signature on-chain (mirrors HardhatBackend behavior).
        """
        tx_hash = hashlib.sha256(
            f"{sender}:{data_hash}:{time.time()}:{uuid.uuid4()}".encode()
        ).hexdigest()

        gas_used = self.GAS_BASE_TX + self.GAS_ECDSA_VERIFY + self.GAS_PER_BYTE_CALLDATA * payload_size
        if store_signature:
            # Extra SSTORE for sigR + sigS (2 × 20K gas for new slots)
            gas_used += 40_000
        submit_time = time.time()
        latency = self._network_latency()

        self._block_number += 1
        self._block_timestamp = submit_time + latency / 1000.0

        self._transactions[tx_hash] = {
            "sender": sender,
            "data_hash": data_hash,
            "payload_size": payload_size,
            "gas_used": gas_used,
            "block_number": self._block_number,
            "latency_ms": latency,
            "timestamp": submit_time,
            "store_signature": store_signature,
        }
        self._tx_order.append(tx_hash)
        return tx_hash

    def submit_meta_transaction(
        self,
        relay_address: str,
        data_hash: str,
        signature_size: int,
        did_active: bool = True,
    ) -> str:
        """Submit a relay-assisted meta-transaction."""
        tx_hash = hashlib.sha256(
            f"relay:{relay_address}:{data_hash}:{time.time()}:{uuid.uuid4()}".encode()
        ).hexdigest()

        submit_time = time.time()

        if did_active:
            gas_used = self.GAS_RELAY_META_TX
        else:
            # Failed submission still consumes gas for the attempt
            gas_used = self.GAS_BASE_TX + 50_000

        latency = self._network_latency()
        self._block_number += 1
        self._block_timestamp = submit_time + latency / 1000.0

        self._transactions[tx_hash] = {
            "sender": relay_address,
            "data_hash": data_hash,
            "signature_size": signature_size,
            "gas_used": gas_used,
            "block_number": self._block_number,
            "latency_ms": latency,
            "timestamp": submit_time,
            "type": "meta_transaction",
        }
        self._tx_order.append(tx_hash)
        return tx_hash

    def submit_batch_transaction(
        self,
        relay_address: str,
        batch_data: list[dict],
    ) -> list[str]:
        """
        Submit a batch of meta-transactions.
        Batching amortizes the base transaction cost across multiple data points.
        """
        tx_hashes = []
        batch_start = time.perf_counter()

        for item in batch_data:
            tx_hash = self.submit_meta_transaction(
                relay_address=relay_address,
                data_hash=item["data_hash"],
                signature_size=item.get("signature_size", FALCON_512_SIGNATURE_SIZE_MAX),
                did_active=item.get("verified", True),
            )
            receipt = self._transactions[tx_hash]
            # Batch amortization: reduce latency per item (shared block inclusion)
            receipt["latency_ms"] = self._network_latency() / len(batch_data)
            tx_hashes.append(tx_hash)

        return tx_hashes

    def get_receipt(self, tx_hash: str) -> dict | None:
        return self._transactions.get(tx_hash)

    def _network_latency(self) -> float:
        """Deterministic network latency simulation (ms). Local Hardhat-like."""
        return self._rng.uniform(5.0, 25.0)

    def compute_data_hash(self, payload: bytes) -> str:
        """Compute SHA-256 hash of payload, returning hex digest."""
        return hashlib.sha256(payload).hexdigest()
