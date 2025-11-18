"""
Fallback to accept --cov options when pytest-cov is not installed to avoid CLI errors.
This does NOT collect coverage; use scripts/run_coverage.sh for enforcement.
"""

import importlib


def _cov_available() -> bool:
    try:
        importlib.import_module("pytest_cov")
        return True
    except Exception:
        return False


def pytest_addoption(parser):  # pragma: no cover - trivial option plumbing
    if _cov_available():
        return
    # Define no-op options to prevent pytest from erroring on unknown args
    parser.addoption("--cov", action="append", default=[])
    parser.addoption("--cov-report", action="append", default=[])
    parser.addoption("--cov-fail-under", action="store", default=None)
