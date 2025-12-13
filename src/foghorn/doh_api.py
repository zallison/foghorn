"""Compatibility shim for the legacy import path `foghorn.doh_api`.

Inputs:
  - None

Outputs:
  - Re-exports public names from `foghorn.servers.doh_api`.
"""

from .servers.doh_api import *  # noqa: F401,F403
