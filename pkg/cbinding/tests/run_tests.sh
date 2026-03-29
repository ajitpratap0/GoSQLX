#!/usr/bin/env bash
# pkg/cbinding/tests/run_tests.sh
#
# Build the GoSQLX C shared library and run the Python ctypes integration tests.
#
# Usage:
#   bash pkg/cbinding/tests/run_tests.sh
#
# Prerequisites:
#   - Go toolchain with CGo enabled
#   - Python 3.7+
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CBINDING_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Building GoSQLX C shared library ==="
cd "${CBINDING_DIR}"
bash build.sh

echo ""
echo "=== Running Python ctypes integration tests ==="
cd "${SCRIPT_DIR}"
python3 test_ctypes.py -v

echo ""
echo "=== Done ==="
