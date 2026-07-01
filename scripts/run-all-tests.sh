#!/bin/bash
# Run all tests (Python + Solidity) inside the Docker container.
set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Phase 1: Python Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd /app/experiments
python3 -m pytest tests/ -v --tb=short
PYTHON_RESULT=$?

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Phase 2: Solidity Tests (Hardhat)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cd /app/experiments/smart-contracts
npx hardhat test
SOLIDITY_RESULT=$?

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Results Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $PYTHON_RESULT -eq 0 ]; then
    echo "  Python tests:   PASS ✓"
else
    echo "  Python tests:   FAIL ✗"
fi
if [ $SOLIDITY_RESULT -eq 0 ]; then
    echo "  Solidity tests: PASS ✓"
else
    echo "  Solidity tests: FAIL ✗"
fi

exit $((PYTHON_RESULT || SOLIDITY_RESULT))
