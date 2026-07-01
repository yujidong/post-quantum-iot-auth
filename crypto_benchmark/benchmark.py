"""
Experiment 1: Cryptographic benchmark — Falcon-512 vs ECDSA vs Dilithium.

Measures key generation, signing, and verification performance across
multiple post-quantum and classical signature schemes.

NOTE: Sign/verify iterations reuse the key pair from the last keygen
iteration to isolate per-operation latency. Each iteration uses a fresh
random message to capture per-message variance.
"""

import csv
import json
import os
import statistics
import time
import tracemalloc
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Optional

from shared.config import (
    BENCHMARK_MESSAGE_SIZE,
    BENCHMARK_WARMUP_ITERATIONS,
    DILITHIUM2_PUBLIC_KEY_SIZE,
    DILITHIUM2_SIGNATURE_SIZE,
    DILITHIUM3_PUBLIC_KEY_SIZE,
    DILITHIUM3_SIGNATURE_SIZE,
    ECDSA_PUBLIC_KEY_SIZE,
    ECDSA_SIGNATURE_SIZE,
    FALCON_512_PUBLIC_KEY_SIZE,
    FALCON_512_SIGNATURE_SIZE_MAX,
)

# Top-level imports for ECDSA (avoid repeated import in benchmark loops)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256K1,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

__all__ = [
    "BenchmarkResult",
    "CryptoScheme",
    "detect_environment",
    "get_hardware_info",
    "run_benchmark",
    "run_full_benchmark_suite",
    "save_results_csv",
    "save_results_json",
]


@dataclass
class BenchmarkResult:
    """Result from a single benchmark iteration."""

    scheme: str
    operation: str  # "keygen", "sign", "verify"
    time_ns: int
    memory_kb: float
    message_size: int
    key_size: int
    signature_size: int
    iteration: int
    backend: str  # "liboqs", "pqcrypto", or "simulation"
    environment: str = "default"  # "iot", "gateway", "validator", or "default"

    @property
    def time_ms(self) -> float:
        """Return elapsed time in milliseconds."""
        return self.time_ns / 1_000_000

    def to_dict(self) -> dict:
        """Serialize to a dictionary."""
        return {
            "scheme": self.scheme,
            "operation": self.operation,
            "time_ns": self.time_ns,
            "time_ms": round(self.time_ms, 6),
            "memory_kb": round(self.memory_kb, 2),
            "message_size": self.message_size,
            "key_size": self.key_size,
            "signature_size": self.signature_size,
            "iteration": self.iteration,
            "backend": self.backend,
            "environment": self.environment,
        }


# ---------------------------------------------------------------------------
# Scheme sizes lookup
# ---------------------------------------------------------------------------

_SCHEME_SIZES = {
    "Falcon-512": {
        "public_key_size": FALCON_512_PUBLIC_KEY_SIZE,
        "signature_size": FALCON_512_SIGNATURE_SIZE_MAX,
    },
    "ECDSA": {
        "public_key_size": ECDSA_PUBLIC_KEY_SIZE,
        "signature_size": ECDSA_SIGNATURE_SIZE,
    },
    "Dilithium2": {
        "public_key_size": DILITHIUM2_PUBLIC_KEY_SIZE,
        "signature_size": DILITHIUM2_SIGNATURE_SIZE,
    },
    "Dilithium3": {
        "public_key_size": DILITHIUM3_PUBLIC_KEY_SIZE,
        "signature_size": DILITHIUM3_SIGNATURE_SIZE,
    },
}


def _get_backend() -> str:
    """Return the current PQC backend name."""
    try:
        from shared.falcon_utils import get_backend
        return get_backend()
    except Exception:
        return "unknown"


def detect_environment() -> str:
    """Detect the Docker-imposed resource environment.

    Reads cgroup/cpu and memory limits to classify as:
      - "iot":        <=1 CPU, <=512MB RAM
      - "gateway":    <=2 CPUs, <=2GB RAM
      - "validator":  full resources

    Falls back to "default" if detection fails (non-Linux or no cgroups).
    """
    import platform
    if platform.system() != "Linux":
        return "default"

    try:
        # cgroup v2 CPU max
        cpu_max_path = "/sys/fs/cgroup/cpu.max"
        if os.path.exists(cpu_max_path):
            with open(cpu_max_path) as f:
                content = f.read().strip()
            # Format: "max 100000" or "100000 100000"
            quota_str = content.split()[0]
            if quota_str != "max":
                quota = int(quota_str)
                with open("/sys/fs/cgroup/cpu.max") as f:
                    period = int(f.read().strip().split()[1])
                cpu_count = quota / period
            else:
                cpu_count = os.cpu_count() or 4
        else:
            # cgroup v1
            cpu_quota_path = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
            cpu_period_path = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
            if os.path.exists(cpu_quota_path) and os.path.exists(cpu_period_path):
                with open(cpu_quota_path) as f:
                    quota = int(f.read().strip())
                with open(cpu_period_path) as f:
                    period = int(f.read().strip())
                if quota > 0 and period > 0:
                    cpu_count = quota / period
                else:
                    cpu_count = os.cpu_count() or 4
            else:
                cpu_count = os.cpu_count() or 4

        # Memory limit
        mem_path = "/sys/fs/cgroup/memory.max"  # cgroup v2
        if not os.path.exists(mem_path):
            mem_path = "/sys/fs/cgroup/memory/memory.limit_in_bytes"  # cgroup v1
        if os.path.exists(mem_path):
            with open(mem_path) as f:
                content = f.read().strip()
            if content == "max":
                mem_bytes = float("inf")
            else:
                mem_bytes = int(content)
        else:
            mem_bytes = float("inf")

        mem_mb = mem_bytes / (1024 * 1024) if mem_bytes != float("inf") else float("inf")

        if cpu_count <= 1.0 and mem_mb <= 600:
            return "iot"
        elif cpu_count <= 2.5 and mem_mb <= 2500:
            return "gateway"
        else:
            return "validator"
    except Exception:
        return "default"


def get_hardware_info() -> dict:
    """Collect hardware and software environment information.

    Returns a dict with OS, CPU model, RAM, Python version, and
    library versions for reproducibility reporting.
    """
    import platform

    info = {
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }

    # CPU model (Linux /proc/cpuinfo)
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "model name" in line.lower():
                        info["cpu_model"] = line.split(":", 1)[1].strip()
                        break
        except Exception:
            pass

    # RAM (Linux /proc/meminfo)
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    info["ram_gb"] = round(
                        int(line.split()[1]) / (1024 * 1024), 1
                    )
                    break
    except Exception:
        pass

    # liboqs version
    try:
        import oqs
        info["liboqs_version"] = oqs.oqs_version()
    except Exception:
        pass

    # Cryptography library version
    try:
        import cryptography
        info["cryptography_version"] = cryptography.__version__
    except Exception:
        pass

    # web3 version
    try:
        import web3
        info["web3_version"] = web3.__version__
    except Exception:
        pass

    # Docker/cgroup environment label
    info["environment_label"] = detect_environment()

    return info


def _dilithium_keygen(scheme_name: str) -> tuple[bytes, bytes]:
    """Generate Dilithium key pair. Prefers liboqs, falls back to pqcrypto."""
    import platform
    if platform.system() == "Linux":
        oqs_names = {"Dilithium2": "ML-DSA-44", "Dilithium3": "ML-DSA-65"}
        try:
            import oqs
            oqs_name = oqs_names[scheme_name]
            with oqs.Signature(oqs_name) as signer:
                pk = signer.generate_keypair()
                sk = signer.export_secret_key()
            return pk, sk
        except Exception:
            pass
    # Fallback: pqcrypto
    if scheme_name == "Dilithium2":
        from pqcrypto.sign import ml_dsa_44
        return ml_dsa_44.generate_keypair()
    elif scheme_name == "Dilithium3":
        from pqcrypto.sign import ml_dsa_65
        return ml_dsa_65.generate_keypair()
    raise ValueError(f"Unknown Dilithium scheme: {scheme_name}")


def _dilithium_sign(scheme_name: str, message: bytes, private_key: bytes) -> bytes:
    """Sign with Dilithium. Prefers liboqs, falls back to pqcrypto."""
    import platform
    if platform.system() == "Linux":
        oqs_names = {"Dilithium2": "ML-DSA-44", "Dilithium3": "ML-DSA-65"}
        try:
            import oqs
            oqs_name = oqs_names[scheme_name]
            with oqs.Signature(oqs_name, secret_key=private_key) as signer:
                return signer.sign(message)
        except Exception:
            pass
    # Fallback: pqcrypto (note: sk is first arg)
    if scheme_name == "Dilithium2":
        from pqcrypto.sign import ml_dsa_44
        return ml_dsa_44.sign(private_key, message)
    elif scheme_name == "Dilithium3":
        from pqcrypto.sign import ml_dsa_65
        return ml_dsa_65.sign(private_key, message)
    raise ValueError(f"Unknown Dilithium scheme: {scheme_name}")


def _dilithium_verify(scheme_name: str, message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify Dilithium signature. Prefers liboqs, falls back to pqcrypto."""
    import platform
    if platform.system() == "Linux":
        oqs_names = {"Dilithium2": "ML-DSA-44", "Dilithium3": "ML-DSA-65"}
        try:
            import oqs
            oqs_name = oqs_names[scheme_name]
            with oqs.Signature(oqs_name) as verifier:
                return verifier.verify(message, signature, public_key)
        except Exception:
            pass
    # Fallback: pqcrypto (note: pk is first arg)
    try:
        if scheme_name == "Dilithium2":
            from pqcrypto.sign import ml_dsa_44
            return ml_dsa_44.verify(public_key, message, signature)
        elif scheme_name == "Dilithium3":
            from pqcrypto.sign import ml_dsa_65
            return ml_dsa_65.verify(public_key, message, signature)
    except Exception:
        return False
    raise ValueError(f"Unknown Dilithium scheme: {scheme_name}")


class CryptoScheme:
    """Abstraction over a cryptographic signature scheme for benchmarking."""

    def __init__(self, name: str):
        if name not in _SCHEME_SIZES:
            raise ValueError(
                f"Unsupported scheme: {name}. "
                f"Supported: {list(_SCHEME_SIZES.keys())}"
            )
        self.name = name
        sizes = _SCHEME_SIZES[name]
        self.public_key_size = sizes["public_key_size"]
        self.signature_size = sizes["signature_size"]

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate key pair. Returns (public_key, private_key)."""
        if self.name == "Falcon-512":
            from shared.falcon_utils import falcon_keygen

            kp = falcon_keygen()
            return kp.public_key, kp.private_key

        elif self.name == "ECDSA":
            priv = ec.generate_private_key(SECP256K1())
            pub = priv.public_key()
            pub_bytes = pub.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )[1:]  # strip 0x04 prefix, keep x+y = 64 bytes
            priv_bytes = priv.private_numbers().private_value.to_bytes(32, "big")
            return pub_bytes, priv_bytes

        elif self.name.startswith("Dilithium"):
            return _dilithium_keygen(self.name)

        raise ValueError(f"Unknown scheme: {self.name}")

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message."""
        if self.name == "Falcon-512":
            from shared.falcon_utils import falcon_sign

            return falcon_sign(message, private_key)

        elif self.name == "ECDSA":
            priv_val = int.from_bytes(private_key, "big")
            priv = ec.derive_private_key(priv_val, SECP256K1())
            sig_der = priv.sign(message, ECDSA(SHA256()))
            r, s = decode_dss_signature(sig_der)
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")

        elif self.name.startswith("Dilithium"):
            return _dilithium_sign(self.name, message, private_key)

        raise ValueError(f"Unknown scheme: {self.name}")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature."""
        if self.name == "Falcon-512":
            from shared.falcon_utils import falcon_verify

            return falcon_verify(message, signature, public_key)

        elif self.name == "ECDSA":
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            sig_der = encode_dss_signature(r, s)

            pub_bytes = b"\x04" + public_key  # add uncompressed prefix
            try:
                pub = ec.EllipticCurvePublicKey.from_encoded_point(
                    SECP256K1(), pub_bytes
                )
                pub.verify(sig_der, message, ECDSA(SHA256()))
                return True
            except Exception:
                return False

        elif self.name.startswith("Dilithium"):
            return _dilithium_verify(self.name, message, signature, public_key)

        raise ValueError(f"Unknown scheme: {self.name}")


# ---------------------------------------------------------------------------
# Benchmark execution
# ---------------------------------------------------------------------------


def _measure_operation(func, *args) -> tuple[int, float, object]:
    """Measure execution time (ns) and peak memory (KB) of a function.

    Note: tracemalloc measures Python heap allocations only, not total
    process RSS. Memory figures are suitable for relative comparison
    between schemes but not absolute memory usage claims.
    """
    tracemalloc.start()
    start = time.perf_counter_ns()
    result = func(*args)
    elapsed = time.perf_counter_ns() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return elapsed, peak / 1024, result


def run_benchmark(
    scheme: CryptoScheme,
    iterations: int = 100,
    message_size: int = BENCHMARK_MESSAGE_SIZE,
    warmup: int = BENCHMARK_WARMUP_ITERATIONS,
) -> List[BenchmarkResult]:
    """Run benchmark for a single scheme.

    Keygen, sign, and verify are measured in separate passes. Sign and
    verify reuse the key pair from the last keygen iteration to isolate
    per-operation latency.

    Args:
        scheme: The CryptoScheme to benchmark.
        iterations: Number of iterations per operation.
        message_size: Size of test message in bytes.
        warmup: Number of warmup iterations (not recorded).

    Returns:
        List of BenchmarkResult (iterations * 3 entries).
    """
    backend = _get_backend()
    environment = detect_environment()
    results: List[BenchmarkResult] = []

    # Warmup with a single message
    warmup_msg = os.urandom(message_size) if message_size > 0 else b""
    for _ in range(warmup):
        pub, priv = scheme.keygen()
        sig = scheme.sign(warmup_msg, priv)
        scheme.verify(warmup_msg, sig, pub)

    # Benchmark keygen
    for i in range(iterations):
        elapsed_ns, mem_kb, (pub, priv) = _measure_operation(scheme.keygen)
        results.append(
            BenchmarkResult(
                scheme=scheme.name,
                operation="keygen",
                time_ns=elapsed_ns,
                memory_kb=mem_kb,
                message_size=0,
                key_size=scheme.public_key_size,
                signature_size=0,
                iteration=i,
                backend=backend,
                environment=environment,
            )
        )

    # Benchmark sign (reuses last keygen's pub/priv, fresh message per iteration)
    for i in range(iterations):
        msg = os.urandom(message_size) if message_size > 0 else b""
        elapsed_ns, mem_kb, sig = _measure_operation(
            scheme.sign, msg, priv
        )
        results.append(
            BenchmarkResult(
                scheme=scheme.name,
                operation="sign",
                time_ns=elapsed_ns,
                memory_kb=mem_kb,
                message_size=message_size,
                key_size=scheme.public_key_size,
                signature_size=len(sig) if sig else scheme.signature_size,
                iteration=i,
                backend=backend,
                environment=environment,
            )
        )

    # Benchmark verify (reuses last keygen's pub, last sign's sig, fresh message per iteration)
    for i in range(iterations):
        msg = os.urandom(message_size) if message_size > 0 else b""
        # Sign this message for verification
        sig = scheme.sign(msg, priv)
        elapsed_ns, mem_kb, _ = _measure_operation(
            scheme.verify, msg, sig, pub
        )
        results.append(
            BenchmarkResult(
                scheme=scheme.name,
                operation="verify",
                time_ns=elapsed_ns,
                memory_kb=mem_kb,
                message_size=message_size,
                key_size=scheme.public_key_size,
                signature_size=scheme.signature_size,
                iteration=i,
                backend=backend,
                environment=environment,
            )
        )

    return results


def run_full_benchmark_suite(
    schemes: Optional[List[str]] = None,
    iterations: int = 100,
    message_size: int = BENCHMARK_MESSAGE_SIZE,
) -> List[BenchmarkResult]:
    """Run benchmarks across multiple schemes.

    Args:
        schemes: List of scheme names to benchmark.
        iterations: Number of iterations per operation per scheme.
        message_size: Test message size in bytes.

    Returns:
        Combined list of BenchmarkResult from all schemes.
    """
    if schemes is None:
        schemes = ["Falcon-512", "ECDSA", "Dilithium2", "Dilithium3"]

    all_results: List[BenchmarkResult] = []
    for name in schemes:
        scheme = CryptoScheme(name)
        results = run_benchmark(
            scheme,
            iterations=iterations,
            message_size=message_size,
            warmup=min(10, iterations // 10),
        )
        all_results.extend(results)

    return all_results


# ---------------------------------------------------------------------------
# Result serialization
# ---------------------------------------------------------------------------


def save_results_json(results: List[BenchmarkResult], path: str) -> None:
    """Save benchmark results to a JSON file."""
    data = [r.to_dict() for r in results]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def save_results_csv(results: List[BenchmarkResult], path: str) -> None:
    """Save benchmark results to a CSV file."""
    if not results:
        return
    fieldnames = list(results[0].to_dict().keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_dict())


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Crypto Benchmark")
    parser.add_argument(
        "--iterations", type=int, default=1000,
        help="Iterations per operation",
    )
    parser.add_argument(
        "--message-size", type=int, default=256,
        help="Test message size in bytes",
    )
    parser.add_argument(
        "--output-dir", type=str, default=None,
        help="Output directory for results",
    )
    parser.add_argument(
        "--schemes", nargs="+",
        default=["Falcon-512", "ECDSA", "Dilithium2", "Dilithium3"],
        help="Schemes to benchmark",
    )
    args = parser.parse_args()

    print(f"Running crypto benchmark suite...")
    print(f"  Schemes: {args.schemes}")
    print(f"  Iterations: {args.iterations}")
    print(f"  Message size: {args.message_size} bytes")
    print(f"  Backend: {_get_backend()}")
    print(f"  Environment: {detect_environment()}")

    hw = get_hardware_info()
    print(f"  Hardware: CPU={hw.get('cpu_model', 'unknown')}, "
          f"RAM={hw.get('ram_gb', '?')}GB, "
          f"Cores={hw.get('cpu_count', '?')}")
    print(f"  Software: {hw.get('liboqs_version', 'N/A')} liboqs, "
          f"Python {hw.get('python_version', '?')}")

    results = run_full_benchmark_suite(
        schemes=args.schemes,
        iterations=args.iterations,
        message_size=args.message_size,
    )

    # Print summary
    summary = defaultdict(list)
    for r in results:
        key = (r.scheme, r.operation)
        summary[key].append(r.time_ms)

    print("\n=== Benchmark Results ===")
    print(f"{'Scheme':<15} {'Operation':<10} {'Mean(ms)':<12} {'Std(ms)':<12} {'Min(ms)':<10} {'P99(ms)':<10}")
    print("-" * 70)
    for (scheme, op), times in sorted(summary.items()):
        mean = statistics.mean(times)
        std = statistics.stdev(times) if len(times) > 1 else 0
        mn = min(times)
        p99 = sorted(times)[int(len(times) * 0.99)]
        print(f"{scheme:<15} {op:<10} {mean:<12.4f} {std:<12.4f} {mn:<10.4f} {p99:<10.4f}")

    if args.output_dir:
        import pathlib

        out = pathlib.Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        save_results_json(results, str(out / "benchmark_results.json"))
        save_results_csv(results, str(out / "benchmark_results.csv"))
        print(f"\nResults saved to {out}")
