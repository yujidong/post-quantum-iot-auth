#!/bin/bash
# Entrypoint for the PQC IoT Blockchain experiment container.
set -e

echo "============================================================"
echo " Post-Quantum IoT Blockchain Experiment Environment"
echo "============================================================"
echo ""

# Report crypto backend
python3 -c "
from shared.falcon_utils import get_backend
print(f'  Crypto backend: {get_backend()}')
" 2>/dev/null || echo "  (backend check pending)"

# Report liboqs
python3 -c "
import oqs
print(f'  liboqs version: {oqs.oqs_version()}')
algs = [a for a in oqs.get_enabled_sig_mechanisms() if 'Falcon' in a or 'ML-DSA' in a]
print(f'  Signature schemes: {algs}')
" 2>/dev/null || echo "  WARNING: liboqs not available"

# Report pqcrypto fallback
python3 -c "
from pqcrypto.sign import falcon_512
print('  pqcrypto: available as fallback')
" 2>/dev/null

# Report environment
python3 -c "
from crypto_benchmark.benchmark import detect_environment
print(f'  Environment: {detect_environment()}')
" 2>/dev/null

# Report Hardhat
cd /app/experiments/smart-contracts
HARDHAT_VERSION=$(npx hardhat version 2>/dev/null | head -1)
echo "  Hardhat: ${HARDHAT_VERSION:-not found}"
echo ""

# Compile smart contracts if needed
if [ ! -f "artifacts/contracts/MetaTxRelay.sol/MetaTxRelay.json" ]; then
    echo "  Compiling smart contracts..."
    npx hardhat compile || echo "  WARNING: Contract compilation failed"
else
    echo "  Smart contracts already compiled"
fi

# Start Hardhat node in background for real blockchain experiments
echo "  Starting Hardhat node in background..."
npx hardhat node > /tmp/hardhat-node.log 2>&1 &
HARDHAT_PID=$!
echo "  Hardhat PID: $HARDHAT_PID"

# Wait for Hardhat to be ready (up to 15 seconds)
for i in $(seq 1 15); do
    if curl -s -o /dev/null http://127.0.0.1:8545 2>/dev/null; then
        echo "  Hardhat node ready on http://127.0.0.1:8545"
        break
    fi
    sleep 1
done

cd /app/experiments

echo ""
echo "  Experiments:"
echo "    1. Crypto Benchmark     (crypto_benchmark)"
echo "    2. Smart Contracts      (smart-contracts)"
echo "    3. Relay Comparison     (relay_system)"
echo "    4. Scalability          (scalability)"
echo "    5. Security Analysis    (security)"
echo ""
echo "============================================================"
echo ""

exec "$@"
