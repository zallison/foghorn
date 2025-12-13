"""Compatibility shim for the legacy import path `foghorn.dot_server`.

Inputs:
  - None

Outputs:
  - Re-exports public names from `foghorn.servers.dot_server`.
"""

from .servers.dot_server import *  # noqa: F401,F403
