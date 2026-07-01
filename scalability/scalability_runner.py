"""
Scalability runner for Experiment 4.

Runs concurrent multi-device blockchain interactions and measures
throughput, latency percentiles, and gas costs at different scales.

When use_real_blockchain=True (default), uses a real Hardhat node
for actual EVM execution. Falls back to SimulatedBlockchain with
a warning if Hardhat is unavailable.
"""
import hashlib
import json
import os
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from shared.config import FALCON_512_SIGNATURE_SIZE_MAX
from relay_system.iot_client import IoTDevice, SimulatedBlockchain
from relay_system.gateway import Gateway
from relay_system.relay import RelayNode


@dataclass
class ScalabilityResult:
    """Results from a single scalability test run."""
    device_count: int
    transactions_per_device: int
    total_transactions: int
    total_time_ms: float
    throughput_tps: float
    avg_latency_ms: float
    p50_latency_ms: float
    p99_latency_ms: float
    total_gas: int
    avg_gas_per_tx: float
    failed_transactions: int
    concurrent_threads: int
    backend: str = "simulated"
    # Phase-separated metrics (gateway verification vs blockchain submission)
    gateway_verify_tps: float = 0.0
    gateway_avg_latency_ms: float = 0.0
    gateway_p99_latency_ms: float = 0.0
    blockchain_submit_tps: float = 0.0
    blockchain_avg_latency_ms: float = 0.0
    blockchain_p99_latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "device_count": self.device_count,
            "transactions_per_device": self.transactions_per_device,
            "total_transactions": self.total_transactions,
            "total_time_ms": self.total_time_ms,
            "throughput_tps": self.throughput_tps,
            "avg_latency_ms": self.avg_latency_ms,
            "p50_latency_ms": self.p50_latency_ms,
            "p99_latency_ms": self.p99_latency_ms,
            "total_gas": self.total_gas,
            "avg_gas_per_tx": self.avg_gas_per_tx,
            "failed_transactions": self.failed_transactions,
            "concurrent_threads": self.concurrent_threads,
            "backend": self.backend,
            "gateway_verify_tps": self.gateway_verify_tps,
            "gateway_avg_latency_ms": self.gateway_avg_latency_ms,
            "gateway_p99_latency_ms": self.gateway_p99_latency_ms,
            "blockchain_submit_tps": self.blockchain_submit_tps,
            "blockchain_avg_latency_ms": self.blockchain_avg_latency_ms,
            "blockchain_p99_latency_ms": self.blockchain_p99_latency_ms,
        }


def _create_blockchain(use_real_blockchain: bool = True):
    """Create the appropriate blockchain backend.

    Returns (blockchain, backend_name) tuple.
    """
    if use_real_blockchain:
        try:
            from relay_system.hardhat_backend import HardhatBackend
            backend = HardhatBackend()
            backend._get_w3()  # Test connectivity
            return backend, "hardhat"
        except Exception as e:
            print(f"  WARNING: Hardhat not available ({e}), falling back to simulation")
            print(f"  WARNING: SimulatedBlockchain results are SYNTHETIC — not from real EVM execution")

    bc = SimulatedBlockchain()
    if use_real_blockchain:
        print(f"  WARNING: Using SimulatedBlockchain — results are SYNTHETIC")
    return bc, "simulated"


class ScalabilityRunner:
    """
    Runs scalability tests using the relay-assisted architecture.

    Uses real Hardhat blockchain by default for actual EVM execution.
    Thread count scales with device count to produce meaningful
    scalability curves (not flat lines).
    """

    def __init__(
        self,
        device_count: int = 50,
        transactions_per_device: int = 5,
        concurrent_threads: int | None = None,
        payload_size: int = 256,
        use_real_blockchain: bool = True,
    ):
        self.device_count = device_count
        self.transactions_per_device = transactions_per_device
        self.payload_size = payload_size
        self.use_real_blockchain = use_real_blockchain
        # Scale thread count with device count for meaningful scalability data
        if concurrent_threads is not None:
            self.concurrent_threads = concurrent_threads
        else:
            # More devices → more concurrent threads to show actual scaling
            self.concurrent_threads = min(device_count, max(4, device_count // 5))

    def run(self) -> ScalabilityResult:
        """Execute the scalability test and return results.

        The test runs in two distinct phases:
          Phase 1 — Gateway Verification: All devices sign data and submit
            to the gateway for Falcon-512 signature verification in parallel.
            This is CPU-bound and scales with thread count.
          Phase 2 — Blockchain Submission: Verified transactions are submitted
            to the blockchain sequentially (serialized by the Hardhat node).
            This measures the on-chain throughput bottleneck.

        Separating these phases reveals that gateway verification scales
        with device count while blockchain submission is constant-rate.
        """
        bc, backend_name = _create_blockchain(self.use_real_blockchain)

        # Deploy contracts if using real blockchain
        if backend_name == "hardhat":
            deploy_info = bc.deploy_contracts()
            print(f"    Deployed contracts for {self.device_count} devices")

        gateway = Gateway(gateway_id="gw-scale")
        relay = RelayNode(relay_id="relay-scale", blockchain=SimulatedBlockchain()) if backend_name != "hardhat" else None

        # Pre-create devices and register DIDs
        devices = [
            IoTDevice(device_id=f"scale-device-{i:05d}")
            for i in range(self.device_count)
        ]

        # Register all device DIDs on real blockchain
        if backend_name == "hardhat":
            for device in devices:
                did_hash_bytes = hashlib.sha256(device.did.encode()).digest()
                bc._ensure_did_registered(did_hash_bytes, device.keypair.public_key)

        # ── Phase 1: Gateway Verification (parallel, CPU-bound) ──
        # Each worker signs data and verifies via gateway concurrently.
        gateway_latencies: list[float] = []
        verified_items: list[dict] = []
        failed_transactions = 0
        lock = threading.Lock()

        def verify_worker(device: IoTDevice) -> tuple[int, list[float], list[dict]]:
            """Worker: sign payloads and verify via gateway (no blockchain)."""
            local_failed = 0
            local_gw_latencies = []
            local_items = []

            for _ in range(self.transactions_per_device):
                payload = device.generate_sensor_data(self.payload_size)
                sig = device.sign_data(payload)

                t0 = time.perf_counter()
                gw_result = gateway.relay_data(
                    device_did=device.did,
                    device_pubkey=device.keypair.public_key,
                    payload=payload,
                    signature=sig,
                )
                verify_time = (time.perf_counter() - t0) * 1000
                local_gw_latencies.append(verify_time)

                if gw_result["verified"]:
                    local_items.append({
                        "device": device,
                        "payload": payload,
                        "sig": sig,
                        "data_hash": gw_result["data_hash"],
                        "verify_time_ms": verify_time,
                    })
                else:
                    local_failed += 1

            return local_failed, local_gw_latencies, local_items

        phase1_start = time.perf_counter()

        with ThreadPoolExecutor(max_workers=self.concurrent_threads) as executor:
            futures = [executor.submit(verify_worker, d) for d in devices]
            for future in as_completed(futures):
                local_failed, local_gw_lat, local_items_list = future.result()
                with lock:
                    failed_transactions += local_failed
                    gateway_latencies.extend(local_gw_lat)
                    verified_items.extend(local_items_list)

        phase1_time = (time.perf_counter() - phase1_start) * 1000

        # ── Phase 2: Blockchain Submission (sequential, I/O-bound) ──
        bc_latencies: list[float] = []
        gas_costs: list[int] = []

        phase2_start = time.perf_counter()

        for item in verified_items:
            device = item["device"]
            payload = item["payload"]
            sig = item["sig"]
            verify_time = item["verify_time_ms"]

            if backend_name == "hardhat":
                did_hash_bytes = hashlib.sha256(device.did.encode()).digest()
                tx_hash = bc.submit_meta_transaction(
                    relay_address="relay-scale",
                    data_hash=item["data_hash"],
                    signature_size=len(sig),
                    did_active=True,
                    data_hash_bytes=hashlib.sha256(payload).digest(),
                    did_hash_bytes=did_hash_bytes,
                    signature_bytes=sig,
                    did_public_key=device.keypair.public_key,
                )
                receipt = bc.get_receipt(tx_hash)
                bc_latencies.append(receipt["latency_ms"])
                gas_costs.append(receipt["gas_used"])
            else:
                relay_result = relay.submit_verified_transaction(
                    device_did=device.did,
                    data_hash=item["data_hash"],
                    signature=sig,
                    verified=True,
                    return_metrics=True,
                )
                bc_latencies.append(relay_result["total_latency_ms"])
                gas_costs.append(relay_result["gas_used"])

        phase2_time = (time.perf_counter() - phase2_start) * 1000

        # ── Compute metrics ──
        total_transactions = len(verified_items)
        total_time = phase1_time + phase2_time

        # Overall latency = gateway verify + blockchain submit per transaction
        overall_latencies = [
            gw_lat + bc_lat
            for gw_lat, bc_lat in zip(
                [item["verify_time_ms"] for item in verified_items],
                bc_latencies,
            )
        ]

        throughput = total_transactions / (total_time / 1000) if total_time > 0 else 0
        avg_latency = statistics.mean(overall_latencies) if overall_latencies else 0
        sorted_lat = sorted(overall_latencies) if overall_latencies else [0]
        p50 = sorted_lat[int(len(sorted_lat) * 0.50)]
        p99 = sorted_lat[int(len(sorted_lat) * 0.99)]
        total_gas = sum(gas_costs)
        avg_gas = total_gas / len(gas_costs) if gas_costs else 0

        # Phase 1 metrics (gateway verification, parallel)
        gw_throughput = len(gateway_latencies) / (phase1_time / 1000) if phase1_time > 0 else 0
        gw_avg = statistics.mean(gateway_latencies) if gateway_latencies else 0
        sorted_gw = sorted(gateway_latencies) if gateway_latencies else [0]
        gw_p99 = sorted_gw[int(len(sorted_gw) * 0.99)]

        # Phase 2 metrics (blockchain submission, sequential)
        bc_throughput = len(bc_latencies) / (phase2_time / 1000) if phase2_time > 0 else 0
        bc_avg = statistics.mean(bc_latencies) if bc_latencies else 0
        sorted_bc = sorted(bc_latencies) if bc_latencies else [0]
        bc_p99 = sorted_bc[int(len(sorted_bc) * 0.99)]

        return ScalabilityResult(
            device_count=self.device_count,
            transactions_per_device=self.transactions_per_device,
            total_transactions=total_transactions,
            total_time_ms=total_time,
            throughput_tps=throughput,
            avg_latency_ms=avg_latency,
            p50_latency_ms=p50,
            p99_latency_ms=p99,
            total_gas=total_gas,
            avg_gas_per_tx=avg_gas,
            failed_transactions=failed_transactions,
            concurrent_threads=self.concurrent_threads,
            backend=backend_name,
            gateway_verify_tps=round(gw_throughput, 1),
            gateway_avg_latency_ms=round(gw_avg, 2),
            gateway_p99_latency_ms=round(gw_p99, 2),
            blockchain_submit_tps=round(bc_throughput, 1),
            blockchain_avg_latency_ms=round(bc_avg, 2),
            blockchain_p99_latency_ms=round(bc_p99, 2),
        )


def run_scalability_suite(
    device_counts: list[int] | None = None,
    transactions_per_device: int = 5,
    concurrent_threads: int | None = None,
    use_real_blockchain: bool = True,
) -> list[ScalabilityResult]:
    """Run scalability tests across multiple device counts."""
    if device_counts is None:
        device_counts = [50, 100, 500, 1000]

    results = []
    for count in device_counts:
        # Thread count scales with device count for meaningful curves
        threads = concurrent_threads or min(count, max(4, count // 5))

        print(f"  Running scalability test: {count} devices, {threads} threads...")
        runner = ScalabilityRunner(
            device_count=count,
            transactions_per_device=transactions_per_device,
            concurrent_threads=threads,
            use_real_blockchain=use_real_blockchain,
        )
        result = runner.run()
        results.append(result)

    return results


def save_scalability_results(
    results: list[ScalabilityResult],
    json_path: Path,
    csv_path: Path,
) -> None:
    """Save scalability results to JSON and CSV."""
    json_path = Path(json_path)
    csv_path = Path(csv_path)
    json_path.parent.mkdir(parents=True, exist_ok=True)

    # JSON
    data = [r.to_dict() for r in results]
    json_path.write_text(json.dumps(data, indent=2))

    # CSV
    if results:
        headers = list(results[0].to_dict().keys())
        lines = [",".join(headers)]
        for r in results:
            row = [str(r.to_dict()[h]) for h in headers]
            lines.append(",".join(row))
        csv_path.write_text("\n".join(lines))
