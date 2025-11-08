#!/usr/bin/env bash
set -euo pipefail

# Brief: Run test suite with coverage enforcement (>=80%). Falls back to plain pytest if pytest-cov is unavailable.
# Inputs: none
# Outputs: exits non-zero on coverage <80% when pytest-cov is available.

if python -c "import pytest_cov" >/dev/null 2>&1; then
  PYTHONPATH=src pytest -q "$@"
  PYTHONPATH=src python scripts/check_per_file_coverage.py
else
  echo "pytest-cov not installed; running tests without coverage." 1>&2
  PYTHONPATH=src pytest -q "$@"
fi
