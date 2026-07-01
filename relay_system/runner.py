"""
Comparison runner for Experiment 3.

Three-way comparison:
1. Direct ECDSA: Each device submits data directly with ECDSA signatures (baseline)
2. Relay Falcon: Off-chain Falcon verification + relay meta-transactions (proposed)
3. Theoretical On-chain Falcon: ~500M gas (impossible, reference point)

When use_real_blockchain=True (default), uses a real Hardhat node for
actual EVM execution with real gas costs and measured latencies.
Falls back to SimulatedBlockchain if Hardhat is unavailable.
"""
import hashlib
import json
import os
import time
from pathlib import Path

from shared.config import RELAY_TEST_PAYLOAD_SIZE, FALCON_512_PUBLIC_KEY_SIZE
from shared.did_utils import did_to_bytes32
from relay_system.iot_client import IoTDevice, SimulatedBlockchain


def _create_blockchain(use_real_blockchain: bool = True):
    """Create the appropriate blockchain backend.

    Returns (blockchain, backend_name) tuple.
    """
    if use_real_blockchain:
        try:
            from relay_system.hardhat_backend import HardhatBackend
            backend = HardhatBackend()
            # Test connectivity
            backend._get_w3()
            return backend, "hardhat"
        except Exception as e:
            print(f"  WARNING: Hardhat not available ({e}), falling back to simulation")
            print(f"  WARNING: SimulatedBlockchain results are SYNTHETIC — not from real EVM execution")

    bc = SimulatedBlockchain()
    if use_real_blockchain:
        print(f"  WARNING: Using SimulatedBlockchain — results are SYNTHETIC")
    return bc, "simulated"


class ComparisonRunner:
    """
    Orchestrates the comparison between direct and relay-assisted
    blockchain submission paths.
    """

    def __init__(
        self,
        device_count: int = 10,
        transactions_per_device: int = 10,
        payload_size: int = RELAY_TEST_PAYLOAD_SIZE,
        batch_size: int = 10,
        use_real_blockchain: bool = True,
    ):
        self.device_count = device_count
        self.transactions_per_device = transactions_per_device
        self.payload_size = payload_size
        self.batch_size = batch_size
        self.use_real_blockchain = use_real_blockchain
        self._devices = self._create_devices()

    def _create_devices(self) -> list[IoTDevice]:
        return [
            IoTDevice(device_id=f"device-{i:04d}")
            for i in range(self.device_count)
        ]

    def _setup_real_backend(self, bc):
        """Deploy contracts and register DIDs for real blockchain."""
        if not hasattr(bc, 'deploy_contracts'):
            return None
        deploy_info = bc.deploy_contracts()
        print(f"  Deployed contracts — gas: {deploy_info['deploy_gas']:,}")
        return deploy_info

    def _register_device_dids(self, bc, backend_name: str):
        """Pre-register all device DIDs on the blockchain."""
        if backend_name != "hardhat":
            return
        for device in self._devices:
            did_hash_bytes = hashlib.sha256(device.did.encode()).digest()
            did_public_key = device.keypair.public_key
            bc._ensure_did_registered(did_hash_bytes, did_public_key)

    def run_direct_path(self) -> dict:
        """
        Direct path (ECDSA baseline): each IoT device submits data directly
        to the blockchain using ECDSA signatures with full signature storage.

        Uses submitVerifyAndStore to store the full 64-byte ECDSA signature
        on-chain, making it a fair comparison against the relay meta-transaction
        which stores the full Falcon signature (≤752 bytes).
        """
        bc, backend_name = _create_blockchain(self.use_real_blockchain)
        deploy_info = self._setup_real_backend(bc)

        total_transactions = 0
        total_latency = 0.0
        total_gas = 0

        start = time.perf_counter()

        for device in self._devices:
            for _ in range(self.transactions_per_device):
                payload = device.generate_sensor_data(self.payload_size)
                data_hash = hashlib.sha256(payload).hexdigest()

                # store_signature=True (default): stores full ECDSA sig on-chain
                tx_hash = bc.submit_transaction(
                    sender=device.did,
                    data_hash=data_hash,
                    payload_size=len(data_hash) // 2,
                    store_signature=True,
                )
                receipt = bc.get_receipt(tx_hash)

                total_transactions += 1
                total_latency += receipt["latency_ms"]
                total_gas += receipt["gas_used"]

        wall_time = (time.perf_counter() - start) * 1000

        result = {
            "total_transactions": total_transactions,
            "total_latency_ms": total_latency,
            "avg_latency_ms": total_latency / total_transactions if total_transactions else 0,
            "total_gas": total_gas,
            "avg_gas_per_tx": total_gas / total_transactions if total_transactions else 0,
            "wall_time_ms": wall_time,
            "device_count": self.device_count,
            "transactions_per_device": self.transactions_per_device,
            "backend": backend_name,
        }
        if deploy_info:
            result["deploy_gas"] = deploy_info["deploy_gas"]

        # Add gas decomposition if using Hardhat
        if backend_name == "hardhat" and hasattr(bc, "get_gas_decomposition"):
            result["gas_decomposition"] = bc.get_gas_decomposition()

        return result

    def run_relay_path(self) -> dict:
        """
        Relay-assisted path (Falcon-512): devices send data to gateway,
        gateway verifies off-chain, relay submits verified meta-transactions
        to blockchain in batches.
        """
        from relay_system.gateway import Gateway
        from relay_system.relay import RelayNode

        bc, backend_name = _create_blockchain(self.use_real_blockchain)
        deploy_info = self._setup_real_backend(bc)

        gateway = Gateway(gateway_id="gw-relay-test")

        # For real blockchain, we need the raw backend (not SimulatedBlockchain)
        relay_bc = bc

        # Create relay node - only works with SimulatedBlockchain interface
        # For Hardhat, we handle submission directly
        relay = RelayNode(relay_id="relay-node-001", blockchain=SimulatedBlockchain()) if backend_name != "hardhat" else None

        # Pre-register device DIDs
        self._register_device_dids(bc, backend_name)

        total_transactions = 0
        total_latency = 0.0
        total_gas = 0
        failed_verifications = 0
        verify_latencies = []
        all_gas_costs = []
        all_latencies = []

        pending_items: list[dict] = []  # items for current batch

        start = time.perf_counter()

        for device in self._devices:
            for _ in range(self.transactions_per_device):
                payload = device.generate_sensor_data(self.payload_size)
                sig = device.sign_data(payload)

                # Step 1: Device sends to gateway (off-chain, local network)
                t0 = time.perf_counter()
                gw_result = gateway.relay_data(
                    device_did=device.did,
                    device_pubkey=device.keypair.public_key,
                    payload=payload,
                    signature=sig,
                )
                verify_latency = (time.perf_counter() - t0) * 1000
                verify_latencies.append(verify_latency)

                if gw_result["verified"]:
                    did_hash_bytes = hashlib.sha256(device.did.encode()).digest()
                    pending_items.append({
                        "device_did": device.did,
                        "data_hash": gw_result["data_hash"],
                        "data_hash_bytes": hashlib.sha256(payload).digest(),
                        "did_hash_bytes": did_hash_bytes,
                        "signature_bytes": sig,
                        "did_public_key": device.keypair.public_key,
                        "signature_size": len(sig),
                        "verified": True,
                    })

                    # Step 2: Submit batch when full
                    if len(pending_items) >= self.batch_size:
                        batch_gas, batch_lat = self._submit_batch(
                            bc, backend_name, relay, pending_items, verify_latency
                        )
                        total_transactions += len(pending_items)
                        total_gas += batch_gas
                        all_gas_costs.extend(batch_gas if isinstance(batch_gas, list) else [batch_gas])
                        all_latencies.extend(batch_lat if isinstance(batch_lat, list) else [batch_lat])
                        pending_items = []
                else:
                    failed_verifications += 1

        # Flush remaining batch
        if pending_items:
            batch_gas, batch_lat = self._submit_batch(
                bc, backend_name, relay, pending_items, verify_latency
            )
            total_transactions += len(pending_items)
            total_gas += batch_gas
            all_gas_costs.extend(batch_gas if isinstance(batch_gas, list) else [batch_gas])
            all_latencies.extend(batch_lat if isinstance(batch_lat, list) else [batch_lat])

        wall_time = (time.perf_counter() - start) * 1000

        # Compute averages
        avg_gas = total_gas / total_transactions if total_transactions else 0
        avg_lat = sum(all_latencies) / len(all_latencies) if all_latencies else 0

        result = {
            "total_transactions": total_transactions,
            "total_latency_ms": sum(all_latencies) if all_latencies else 0,
            "avg_latency_ms": avg_lat,
            "total_gas": total_gas,
            "avg_gas_per_tx": avg_gas,
            "wall_time_ms": wall_time,
            "avg_verify_time_ms": sum(verify_latencies) / len(verify_latencies) if verify_latencies else 0,
            "failed_verifications": failed_verifications,
            "device_count": self.device_count,
            "transactions_per_device": self.transactions_per_device,
            "batch_size": self.batch_size,
            "backend": backend_name,
        }
        if deploy_info:
            result["deploy_gas"] = deploy_info["deploy_gas"]

        # Add gas decomposition if using Hardhat
        if backend_name == "hardhat" and hasattr(bc, "get_gas_decomposition"):
            result["gas_decomposition"] = bc.get_gas_decomposition()

        return result

    def _submit_batch(self, bc, backend_name, relay, items, verify_latency):
        """Submit a batch of items. Returns (total_gas, list_of_latencies)."""
        gas_costs = []
        latencies = []

        if backend_name == "hardhat":
            # Submit directly to Hardhat
            for item in items:
                tx_hash = bc.submit_meta_transaction(
                    relay_address="relay-node-001",
                    data_hash=item["data_hash"],
                    signature_size=item["signature_size"],
                    did_active=True,
                    data_hash_bytes=item["data_hash_bytes"],
                    did_hash_bytes=item["did_hash_bytes"],
                    signature_bytes=item["signature_bytes"],
                    did_public_key=item["did_public_key"],
                )
                receipt = bc.get_receipt(tx_hash)
                gas_costs.append(receipt["gas_used"])
                latencies.append(verify_latency + receipt["latency_ms"])
        else:
            # Use SimulatedBlockchain via relay
            for item in items:
                relay_result = relay.submit_verified_transaction(
                    device_did=item["device_did"],
                    data_hash=item["data_hash"],
                    signature=item["signature_bytes"],
                    verified=item["verified"],
                    return_metrics=True,
                )
                gas_costs.append(relay_result["gas_used"])
                latencies.append(verify_latency + relay_result["total_latency_ms"])

        return sum(gas_costs), latencies

    def run_comparison(self, rounds: int = 1) -> dict:
        """Run both paths and produce comparison metrics.

        Args:
            rounds: Number of independent rounds to run for statistical
                    significance. When > 1, reports mean ± std for gas
                    and latency across rounds.
        """
        if rounds <= 1:
            direct = self.run_direct_path()
            relay = self.run_relay_path()
        else:
            # Multi-round execution for statistical significance
            print(f"  Running {rounds} rounds for statistical significance...")
            direct_results = []
            relay_results = []
            for i in range(rounds):
                print(f"    Round {i+1}/{rounds}...")
                direct_results.append(self.run_direct_path())
                relay_results.append(self.run_relay_path())

            # Aggregate: use last round's raw data, add stats
            direct = direct_results[-1]
            relay = relay_results[-1]

            # Compute statistics across rounds
            import statistics
            direct_gas_vals = [r["avg_gas_per_tx"] for r in direct_results]
            relay_gas_vals = [r["avg_gas_per_tx"] for r in relay_results]
            direct_lat_vals = [r["avg_latency_ms"] for r in direct_results]
            relay_lat_vals = [r["avg_latency_ms"] for r in relay_results]

            if len(direct_gas_vals) > 1:
                direct["gas_std"] = statistics.stdev(direct_gas_vals)
                direct["latency_std"] = statistics.stdev(direct_lat_vals)
                relay["gas_std"] = statistics.stdev(relay_gas_vals)
                relay["latency_std"] = statistics.stdev(relay_lat_vals)
                direct["rounds"] = rounds
                relay["rounds"] = rounds

        # Gas comparison
        direct_per_tx = direct["avg_gas_per_tx"]
        relay_per_tx = relay["avg_gas_per_tx"]

        # The key comparison: relay enables Falcon at feasible cost
        # vs. theoretical on-chain Falcon which is impossible
        theoretical_falcon = SimulatedBlockchain.GAS_THEORETICAL_FALCON
        relay_vs_falcon_ratio = theoretical_falcon / relay_per_tx if relay_per_tx > 0 else float("inf")

        # Latency comparison
        latency_ratio = (
            direct["avg_latency_ms"] / relay["avg_latency_ms"]
            if relay["avg_latency_ms"] > 0
            else float("inf")
        )

        result = {
            "direct_ecdsa": direct,
            "relay_falcon": relay,
            "comparison": {
                "direct_ecdsa_avg_gas": direct_per_tx,
                "relay_falcon_avg_gas": relay_per_tx,
                "theoretical_falcon_gas": theoretical_falcon,
                "relay_vs_falcon_ratio": relay_vs_falcon_ratio,
                "relay_vs_ecdsa_gas_ratio": relay_per_tx / direct_per_tx if direct_per_tx > 0 else float("inf"),
                "latency_ratio": latency_ratio,
                "direct_avg_latency_ms": direct["avg_latency_ms"],
                "relay_avg_latency_ms": relay["avg_latency_ms"],
                "relay_failed_verifications": relay["failed_verifications"],
                "backend": relay.get("backend", "unknown"),
                "note": "Both paths store full signatures on-chain for fair comparison: "
                        "ECDSA stores 64 bytes, relay stores Falcon-512 signature (≤752 bytes). "
                        "Relay uses more gas but enables quantum-safe Falcon-512 signatures. "
                        "On-chain Falcon verification (~500M gas) exceeds the Ethereum block "
                        "gas limit (~12M).",
            },
        }

        # Include round-level statistics if multi-round
        if rounds > 1 and "gas_std" in direct:
            result["comparison"]["direct_gas_std"] = direct["gas_std"]
            result["comparison"]["direct_latency_std"] = direct["latency_std"]
            result["comparison"]["relay_gas_std"] = relay["gas_std"]
            result["comparison"]["relay_latency_std"] = relay["latency_std"]
            result["comparison"]["rounds"] = rounds

        return result

    def save_results(self, result: dict, path) -> None:
        """Save comparison results to JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, default=str))
