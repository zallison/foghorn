"""Public facade for the Foghorn admin HTTP server.

Historically, the entire admin FastAPI application and its helpers lived
directly inside :mod:`foghorn.servers.webserver` (this ``__init__`` module),
which grew quite large. The full implementation now lives in the
:mod:`foghorn.servers.webserver.core` module.

To preserve backwards compatibility, this package aliases
``foghorn.servers.webserver`` to the implementation module so that existing
imports such as::

    import foghorn.servers.webserver as web_mod
    from foghorn.servers.webserver import RuntimeState, create_app, start_webserver

continue to work unchanged, including tests and callers that monkeypatch
internal helpers on the ``webserver`` module.
"""

from __future__ import annotations

import sys as _sys

# Import the implementation module and then alias this package name to it in
# sys.modules. After this runs, ``foghorn.servers.webserver`` and
# ``foghorn.servers.webserver.core`` both refer to the same module object.
from . import core as _impl

_sys.modules[__name__] = _impl
