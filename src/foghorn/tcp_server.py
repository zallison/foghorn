"""Compatibility shim for the legacy import path `foghorn.tcp_server`.

Inputs:
  - None

Outputs:
  - Re-exports public names from `foghorn.servers.tcp_server`.
"""

from .servers.tcp_server import *  # noqa: F401,F403
