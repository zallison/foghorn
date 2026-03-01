"""Deprecated compatibility shim: implementations moved to server_management.py/threaded_handlers.py."""  # pragma: nocover - [legacy module retained for backwards-compatible imports]

from __future__ import (  # pragma: nocover - [legacy module retained for backwards-compatible imports]
    annotations,
)

from .server_management import (  # pragma: nocover - [re-export legacy API from new module location]
    _AdminHTTPServer,
    _start_admin_server_threaded,
)
from .threaded_handlers import (  # pragma: nocover - [re-export legacy API from new module location]
    _ThreadedAdminRequestHandler,
)

__all__ = [  # pragma: nocover - [explicit re-export surface]
    "_AdminHTTPServer",  # pragma: nocover - [explicit re-export surface]
    "_ThreadedAdminRequestHandler",  # pragma: nocover - [explicit re-export surface]
    "_start_admin_server_threaded",  # pragma: nocover - [explicit re-export surface]
]  # pragma: nocover - [explicit re-export surface]
