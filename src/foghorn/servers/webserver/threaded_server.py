"""Deprecated compatibility shim: implementations moved to server_management.py/threaded_handlers.py."""  # pragma: nocover - [legacy module retained for backwards-compatible imports]

from __future__ import (
    annotations,
)  # pragma: nocover - [legacy module retained for backwards-compatible imports]

from .server_management import (
    _AdminHTTPServer,
    _start_admin_server_threaded,
)  # pragma: nocover - [re-export legacy API from new module location]
from .threaded_handlers import (
    _ThreadedAdminRequestHandler,
)  # pragma: nocover - [re-export legacy API from new module location]

__all__ = [  # pragma: nocover - [explicit re-export surface]
    "_AdminHTTPServer",  # pragma: nocover - [explicit re-export surface]
    "_ThreadedAdminRequestHandler",  # pragma: nocover - [explicit re-export surface]
    "_start_admin_server_threaded",  # pragma: nocover - [explicit re-export surface]
]  # pragma: nocover - [explicit re-export surface]
