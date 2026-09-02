# Post-Quantum IoT Blockchain Authentication

A relay-assisted architecture that enables post-quantum signature schemes (Falcon-512) on EVM-compatible blockchains by performing signing at the IoT device layer and verification off-chain, bridged to the chain via meta-transactions and decentralized identifiers (DIDs).

## Overview

Direct on-chain verification of lattice-based signatures exceeds current block gas limits by orders of magnitude. This codebase implements a **decoupled architecture** that separates post-quantum authentication from on-chain settlement:

- **IoT devices** sign transactions with Falcon-512
- **Edge gateways** perform lightweight verification and DID resolution
- **Relay nodes** construct ECDSA-signed meta-transactions for EVM compatibility, under stake and with attributable, contestable endorsements (`AccountableRelay`)
- **Smart contracts** record authentication artifacts and enforce DID-key binding

The architecture and experimental results are reported in the companion paper (under review). Smart-contract gas costs and 500-device scalability have been validated on the Ethereum Sepolia L1 and Base Sepolia L2 testnets; see `results/testnet-validation-summary.md` for the cross-environment comparison.

## Directory Structure

```
.
├── crypto_benchmark/         # Post-quantum signature benchmarking (liboqs)
│   ├── benchmark.py          # Python benchmark (Falcon-512, ML-DSA-44/65, ECDSA)
│   ├── benchmark_pqc.c       # Native C benchmark
│   └── results/              # Benchmark CSV/JSON output
│
├── smart-contracts/          # Solidity contracts (Hardhat project)
│   ├── contracts/
│   │   ├── DIDRegistry.sol       # DID registration and public key anchoring
│   │   ├── MetaTxRelay.sol       # Relay-assisted meta-transaction processing (V1 baseline)
│   │   ├── AccountableRelay.sol  # Staked relays + optimistic verification (V2)
│   │   └── ECDSAVerify.sol       # ECDSA signature verification helper
│   ├── test/                     # Contract test suite (Chai + Ethers.js)
│   ├── scripts/
│   │   ├── deploy.js             # Local Hardhat deployment
│   │   ├── gas-report.js         # Generate gas cost report
│   │   ├── sepolia-verify.js     # Basic Sepolia L1 deployment + smoke test
│   │   ├── sepolia-validate.js   # Full Sepolia L1 validation (gas + security tests)
│   │   ├── l2-scalability.js     # 500-device scalability test on Base Sepolia L2
│   │   └── bridge-to-base.js     # Bridge ETH from Sepolia L1 to Base Sepolia L2
│   ├── hardhat.config.js
│   └── package.json
│
├── relay_system/             # Relay-assisted meta-transaction simulation
│   ├── iot_client.py             # IoT device signing simulation
│   ├── gateway.py                # Edge gateway verification
│   ├── relay.py                  # Relay node meta-transaction construction
│   ├── runner.py                 # Experiment orchestrator
│   ├── hardhat_backend.py        # Hardhat blockchain backend interface
│   └── hardhat_runner.py         # Hardhat network lifecycle management
│
├── scalability/              # System scalability testing
│   └── scalability_runner.py     # Multi-device scalability experiment
│
├── security/                 # Threat model and attack simulation
│   ├── threat_model.py           # Threat model definitions
│   └── attack_simulation.py      # Adversarial transaction simulation
│
├── shared/                   # Shared utilities
│   ├── config.py                 # Configuration constants
│   ├── falcon_utils.py           # Falcon-512 key/sign/verify helpers
│   ├── did_utils.py              # DID operations
│   └── visualization.py          # Plotting helpers
│
├── fog-simulation/           # iFogSim fog computing simulation (Java)
│   └── PQCFogAuthentication.java
│
├── tests/                    # pytest test suite
│
├── results/                  # Experiment results
│   ├── crypto-benchmark/         # Signature performance data
│   ├── gas-costs/                # Smart contract gas measurements
│   ├── scalability/              # Throughput and latency at scale
│   ├── fog-simulation/           # iFogSim energy and latency sweeps
│   ├── testnet-validation-summary.md         # Cross-environment testnet report
│   ├── sepolia-l1-scalability-500.txt        # Sepolia L1 500-device raw log
│   └── base-sepolia-scalability-500.txt      # Base Sepolia L2 500-device raw log
│
├── scripts/                  # Utility shell scripts
│   ├── docker-entrypoint.sh
│   └── run-all-tests.sh
│
├── Dockerfile                # Experiment environment
├── docker-compose.yml
├── requirements.txt          # Python dependencies
└── conftest.py               # pytest configuration
```

## Requirements

### Python
- Python 3.10+
- liboqs 0.15.0+ (for post-quantum schemes)
- See `requirements.txt` for the full dependency list

### Node.js
- Node.js 18+
- Hardhat (installed via `npm install` in `smart-contracts/`)

### Java (optional, for fog simulation)
- JDK 11+
- iFogSim framework (clone separately, place `PQCFogAuthentication.java` in the test package)
- CloudSim 3.0.3, json-simple, commons-math3, guava

## Quick Start

### 1. Crypto Benchmark

```bash
pip install -r requirements.txt
python crypto_benchmark/benchmark.py --iterations 1000
```

Results are saved to `crypto_benchmark/results/`.

### 2. Smart Contract Gas Analysis

```bash
cd smart-contracts
npm install
npx hardhat test              # Run contract tests
node scripts/gas-report.js    # Generate gas cost report
```

### 3. Relay-Assisted Transaction Flow

```bash
# Start a local Hardhat node in another terminal
cd smart-contracts && npx hardhat node

# Run the relay simulation
python relay_system/runner.py
```

### 4. Scalability Test

```bash
python scalability/scalability_runner.py --devices 500
```

### 5. Testnet Validation (Optional)

Testnet validation requires funded accounts on Ethereum Sepolia (L1) and Base Sepolia (L2). Copy `smart-contracts/.env.example` to `smart-contracts/.env` and fill in your own values — **never commit the `.env` file**.

```bash
cd smart-contracts

# Gas accuracy + security tests on Sepolia L1
node scripts/sepolia-verify.js
node scripts/sepolia-validate.js

# Optional: bridge ETH from Sepolia L1 to Base Sepolia L2
node scripts/bridge-to-base.js

# 500-device scalability test on Base Sepolia L2
node scripts/l2-scalability.js
```

The `results/` directory contains the raw outputs from the test runs reported in the paper. The `testnet-validation-summary.md` file summarizes the cross-environment gas and cost comparison.

### 6. Docker Environment

```bash
docker compose build
docker compose run --rm experiments pytest tests/ -v
```

## Key Components

### Falcon-512 Authentication
IoT devices generate Falcon-512 signatures using liboqs. The signing operation is lightweight enough for constrained devices, while verification is performed off-chain at the edge gateway and relay layers.

### DID Registry
The `DIDRegistry` contract maps decentralized identifiers to Falcon-512 public keys. Each IoT device registers its DID during provisioning, and the smart contract enforces that only registered identities can submit authenticated transactions.

### Meta-Transaction Relay
The `MetaTxRelay` contract processes relay-submitted transactions that carry Falcon signatures and DID references. The relay signs with ECDSA for EVM compatibility, while the Falcon signature is stored on-chain for auditability without being verified on-chain.

### Accountable Relaying and Optimistic Verification (`AccountableRelay`)
The V2 contract closes the trust gap of conventional meta-transaction relays, in which the ledger trusts a single quantum-vulnerable ECDSA relay key:

- **Staked, attributable relays** — every on-chain record names its endorsing relay; submissions require a stake and consume an on-chain-assigned per-DID nonce inside a domain-separated commitment binding (identity, nonce, payload, signature).
- **Optimistic verification** — records land in the `Provisional` state and are finalized by anyone after a challenge window; during the window any watchdog can open a dispute backed by a bond.
- **Committee adjudication with slashing** — staked verifiers re-run Falcon verification off-chain and submit signed attestations; confirmed fraud revokes the record and slashes the relay, spurious disputes compensate the relay from the challenger's bond, and undecided disputes fail closed.
- **Bound-leaf batching** — batch submissions carry the raw signatures as calldata; the contract assigns nonces, hashes each signature slice, builds the Merkle tree over (DID, nonce, payload hash, signature hash) leaves itself, and stores only the root and availability commitment.

Measured overhead (Hardhat, optimizer 200 runs, see `results/accountability/`): the accountable submission costs 816,879 gas vs 821,562 for the V1 baseline (**-0.57%, accountability is free**); finalization 49,398; full fraud-dispute path ~474k; batch amortization 60,721 / 48,669 / 47,506 gas per transaction at k = 10 / 50 / 100. The V3 contract hardens adjudication: a spurious verdict returns the target to the provisional state (no early confirmation), every 'valid' attestation stays registered and slashable until finalization, verifiers are an explicit q-of-n roster with rewards and ejection, fail-closed expiry burns half the bond, and batch leaves are disputable in parallel. The complete lifecycle, including a multi-role fraud dispute with independent keys, has been executed end to end on Ethereum Sepolia; see `results/accountability/accountable-sepolia-validation.json`.

```bash
# Hardhat benchmark + correctness invariants (14 checks)
cd smart-contracts && npx hardhat run scripts/accountable-gas-report.js

# Full lifecycle on Sepolia L1 (deploy, stake, submit, batch, finalize, dispute, slash)
npx hardhat run scripts/sepolia-accountable-validate.js --network sepolia
```

## Testing

```bash
# Python tests
pytest tests/ -v

# Smart contract tests
cd smart-contracts && npx hardhat test
```

## License

MIT. See `LICENSE` for details.
