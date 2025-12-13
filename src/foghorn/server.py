"""Compatibility shim for the legacy import path `foghorn.server`.

Brief:
  Historically the project exposed helpers under `foghorn.server`. The canonical
  implementation now lives in `foghorn.servers.server`.

Inputs:
  - None

Outputs:
  - Ensures `import foghorn.server` returns the same module object as
    `import foghorn.servers.server`, so monkeypatching works via either path.
"""

from __future__ import annotations

import sys

from .servers import server as _servers_server

# Make this legacy module path an alias of the canonical module.
sys.modules[__name__] = _servers_server

# Populate globals for tools / introspection that look at this module object.
globals().update(_servers_server.__dict__)
