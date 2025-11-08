"""
Brief: Global pytest configuration enforcing per-test 10s timeout.

Inputs:
  - None

Outputs:
  - None
"""
import signal
import pytest


def _alarm_handler(signum, frame):
    """
    Brief: Signal handler that raises TimeoutError when alarm triggers.

    Inputs:
      - signum: signal number (int)
      - frame: current frame (ignored)

    Outputs:
      - None: Raises TimeoutError to fail the test
    """
    raise TimeoutError("Test exceeded 10 seconds")


# Install handler if supported on this platform
if hasattr(signal, "SIGALRM"):
    signal.signal(signal.SIGALRM, _alarm_handler)


@pytest.fixture(autouse=True)
def enforce_test_timeout():
    """
    Brief: Enforce a hard 10-second timeout for each test.

    Inputs:
      - None

    Outputs:
      - None: Cancels alarm after test
    """
    if hasattr(signal, "SIGALRM"):
        signal.alarm(10)
        try:
            yield
        finally:
            signal.alarm(0)
    else:
        # Fallback: no-op on platforms without SIGALRM
        yield
