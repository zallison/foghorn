from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

import logging
from .logging_utils import RingBuffer


logger = logging.getLogger("foghorn.webserver")


class LogEntry(BaseModel):
    """Structured log entry stored in the in-memory buffer.

    Inputs:
      - timestamp: ISO 8601 string in UTC
      - level: Log level name (e.g., "INFO")
      - message: Log message text
      - extra: Optional dict with additional fields

    Outputs:
      - Pydantic model representing a log entry.

    Example:
      >>> entry = LogEntry(timestamp="2024-01-01T00:00:00Z", level="INFO", message="ok")
      >>> entry.level
      'INFO'
    """

    timestamp: str
    level: str
    message: str
    extra: Dict[str, Any] | None = None


class WebServerHandle:
    """Handle for a background admin webserver thread.

    Inputs (constructor):
      - thread: Thread object running the HTTP/uvicorn server loop.
      - server: Optional server instance with shutdown/server_close methods.

    Outputs:
      - WebServerHandle instance with stop() and is_running().

    Example:
      >>> # created via start_webserver() in main
    """

    def __init__(self, thread: threading.Thread, server: Any | None = None) -> None:
        self._thread = thread
        self._server = server

    def is_running(self) -> bool:
        """Return True if the underlying thread is alive.

        Inputs: none
        Outputs: bool indicating thread liveness.
        """

        return self._thread.is_alive()

    def stop(self, timeout: float = 5.0) -> None:
        """Best-effort stop; shuts down server if possible and waits for thread.

        Inputs:
          - timeout: Seconds to wait for thread to exit.

        Outputs:
          - None

        Notes:
          - For uvicorn-based servers, this relies on process lifetime matching
            server lifetime and only joins the thread.
          - For threaded HTTP fallbacks, this also calls shutdown/server_close
            on the underlying server instance when present.
        """

        try:
            if self._server is not None:
                try:
                    shutdown = getattr(self._server, "shutdown", None)
                    if callable(shutdown):
                        shutdown()

                    close = getattr(self._server, "server_close", None)
                    if callable(close):
                        close()
                except Exception:
                    logger.exception("Error while shutting down webserver instance")
            # Always wait for the thread to exit, regardless of whether
            # a server instance was attached or shutdown raised.
            self._thread.join(timeout=timeout)
        except Exception:
            logger.exception("Error while stopping webserver thread")
