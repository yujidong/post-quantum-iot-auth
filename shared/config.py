"""
Shared configuration for all experiments.
"""

import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
SHARED_DIR = Path(__file__).parent

# Experiment 1: Crypto Benchmark
CRYPTO_BENCHMARK_DIR = PROJECT_ROOT / "crypto_benchmark"
CRYPTO_BENCHMARK_RESULTS = CRYPTO_BENCHMARK_DIR / "results"

# Experiment 2: Smart Contract
SMART_CONTRACTS_DIR = PROJECT_ROOT / "smart-contracts"
SMART_CONTRACTS_RESULTS = SMART_CONTRACTS_DIR / "results"

# Experiment 3: Relay Comparison
RELAY_SYSTEM_DIR = PROJECT_ROOT / "relay_system"
RELAY_SYSTEM_RESULTS = RELAY_SYSTEM_DIR / "results"

# Experiment 4: Scalability
SCALABILITY_DIR = PROJECT_ROOT / "scalability"
SCALABILITY_RESULTS = SCALABILITY_DIR / "results"

# Backward-compatible aliases (deprecated, will be removed in a future release)
EXP1_DIR = CRYPTO_BENCHMARK_DIR
EXP1_RESULTS = CRYPTO_BENCHMARK_RESULTS
EXP2_DIR = SMART_CONTRACTS_DIR
EXP2_RESULTS = SMART_CONTRACTS_RESULTS
EXP3_DIR = RELAY_SYSTEM_DIR
EXP3_RESULTS = RELAY_SYSTEM_RESULTS
EXP4_DIR = SCALABILITY_DIR
EXP4_RESULTS = SCALABILITY_RESULTS

# Benchmark parameters
BENCHMARK_ITERATIONS = 10000
BENCHMARK_MESSAGE_SIZE = 256  # bytes
BENCHMARK_WARMUP_ITERATIONS = 100

# Docker resource limits for IoT simulation
IOT_CPU_LIMIT = "1.0"
IOT_MEMORY_LIMIT = "512m"

GATEWAY_CPU_LIMIT = "2.0"
GATEWAY_MEMORY_LIMIT = "2g"

# Blockchain (Hardhat) configuration
HARDHAT_URL = os.environ.get("HARDHAT_URL", "http://127.0.0.1:8545")
HARDHAT_CHAIN_ID = 31337

# Falcon-512 parameters (NIST FIPS 205 / pqcrypto verified)
FALCON_512_PUBLIC_KEY_SIZE = 897  # bytes (pqcrypto confirmed)
FALCON_512_PRIVATE_KEY_SIZE = 1281  # bytes (pqcrypto confirmed)
FALCON_512_SIGNATURE_SIZE_AVG = 666  # bytes (NIST average)
FALCON_512_SIGNATURE_SIZE_MAX = 752  # bytes (pqcrypto PQCLEAN max)

# ECDSA parameters (secp256k1)
ECDSA_PUBLIC_KEY_SIZE = 64  # bytes (uncompressed x+y)
ECDSA_SIGNATURE_SIZE = 64  # bytes

# ML-DSA / Dilithium parameters (pqcrypto verified)
ML_DSA_44_PUBLIC_KEY_SIZE = 1312   # Dilithium2 / ML-DSA-44
ML_DSA_44_SIGNATURE_SIZE = 2420
ML_DSA_65_PUBLIC_KEY_SIZE = 1952   # Dilithium3 / ML-DSA-65
ML_DSA_65_SIGNATURE_SIZE = 3309

# Legacy aliases for backward compatibility
DILITHIUM2_PUBLIC_KEY_SIZE = ML_DSA_44_PUBLIC_KEY_SIZE
DILITHIUM2_SIGNATURE_SIZE = ML_DSA_44_SIGNATURE_SIZE
DILITHIUM3_PUBLIC_KEY_SIZE = ML_DSA_65_PUBLIC_KEY_SIZE
DILITHIUM3_SIGNATURE_SIZE = ML_DSA_65_SIGNATURE_SIZE

# Scalability test parameters
SCALABILITY_DEVICE_COUNTS = [50, 100, 500, 1000]
SCALABILITY_TEST_DURATION_SECS = 60  # per run
SCALABILITY_WARMUP_SECS = 10

# Relay comparison parameters
RELAY_TEST_TRANSACTION_COUNT = 1000
RELAY_TEST_PAYLOAD_SIZE = 256  # bytes
