"""Compatibility shim for the legacy import path `foghorn.doh_server`.

Inputs:
  - None

Outputs:
  - Re-exports public names from `foghorn.servers.doh_server`.
"""

from .servers.doh_server import *  # noqa: F401,F403
