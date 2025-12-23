"""Compatibility module exposing the FastAPI app instance for uvicorn.

This module simply re-exports a FastAPI application created by
foghorn.servers.webserver.create_app so that command-line tools like uvicorn can
run "foghorn.app:app" directly in addition to the in-process webserver
integration used by foghorn.main.
"""

from __future__ import annotations

from typing import Any, Dict

from .servers.webserver import RingBuffer, create_app


def _empty_config() -> Dict[str, Any]:
    """Return minimal default configuration for standalone app usage.

    Inputs: none
    Outputs: dict with a minimal webserver section enabled on localhost.

    Example:
      >>> cfg = _empty_config()
      >>> cfg["webserver"]["enabled"]
      True
    """

    return {
        "webserver": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8053,
            "index": True,
        }
    }


# Standalone convenience: app usable as `foghorn.app:app` with uvicorn
_stats = None  # type: ignore[assignment]
_config = _empty_config()
_log_buffer = RingBuffer(capacity=500)
app = create_app(_stats, _config, _log_buffer)
