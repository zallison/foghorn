"""Compatibility shim for the legacy import path `foghorn.udp_server`.

Inputs:
  - None

Outputs:
  - Re-exports public names from `foghorn.servers.udp_server`.
"""

from .servers.udp_server import *  # noqa: F401,F403
