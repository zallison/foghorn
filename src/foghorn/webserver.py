"""Compatibility shim for the legacy import path `foghorn.webserver`.

Inputs:
  - None

Outputs:
  - Re-exports public names from `foghorn.servers.webserver`.
"""

from .servers.webserver import *  # noqa: F401,F403
