from __future__ import annotations

import base64
import logging
from typing import Any, Callable, Optional

from fastapi import FastAPI, HTTPException, Request, Response, status

logger = logging.getLogger("foghorn.doh_api")

_DNS_CT = "application/dns-message"


def _b64url_decode_nopad(s: str) -> bytes:
    """
    Brief: Decode base64url without padding.

    Inputs:
    - s: base64url string without '='

    Outputs:
    - bytes: decoded binary

    Example:
        >>> _b64url_decode_nopad('AQI')
        b'\x01\x02'
    """
    if not isinstance(s, str):
        raise ValueError("input must be str")
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def create_doh_app(
    resolver: Callable[[bytes, str], bytes],
) -> FastAPI:
    """
    Brief: Create FastAPI app implementing RFC 8484 DoH endpoints.

    Inputs:
    - resolver: callable (query_bytes, client_ip) -> response_bytes

    Outputs:
    - FastAPI application that serves /dns-query via GET and POST.

    Example:
      >>> def _echo(q: bytes, ip: str) -> bytes: return q
      >>> app = create_doh_app(_echo)
    """

    app = FastAPI(
        title="Foghorn DoH",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/dns-query")
    async def doh_get(request: Request) -> Response:
        """
        Brief: Handle GET /dns-query?dns=<base64url>.

        Inputs:
        - request: FastAPI Request

        Outputs:
        - Response with application/dns-message body on success.
        """
        dns_param = request.query_params.get("dns")
        if not dns_param:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        try:
            qbytes = _b64url_decode_nopad(dns_param)
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        # Resolve using provided resolver (sync on threadpool would be ideal; keep simple)
        client_ip = request.client.host if request.client else "0.0.0.0"
        try:
            resp = resolver(qbytes, client_ip)
        except Exception:
            logger.exception("resolver raised")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        return Response(
            content=resp, media_type=_DNS_CT, headers={"Connection": "close"}
        )

    @app.post("/dns-query")
    async def doh_post(request: Request) -> Response:
        """
        Brief: Handle POST /dns-query with Content-Type: application/dns-message.

        Inputs:
        - request: FastAPI Request

        Outputs:
        - Response with application/dns-message body on success.
        """
        ctype = request.headers.get("content-type", "")
        if _DNS_CT not in ctype:
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
        body = await request.body()
        client_ip = request.client.host if request.client else "0.0.0.0"
        try:
            resp = resolver(body, client_ip)
        except Exception:
            logger.exception("resolver raised")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        return Response(
            content=resp, media_type=_DNS_CT, headers={"Connection": "close"}
        )

    return app


class DoHServerHandle:
    """
    Brief: Handle for a background uvicorn server thread running DoH app.

    Inputs (constructor):
    - thread: Thread object

    Outputs:
    - DoHServerHandle with is_running() and stop().
    """

    def __init__(self, thread) -> None:
        self._thread = thread

    def is_running(self) -> bool:
        """
        Brief: Return True if thread is alive.

        Inputs: None
        Outputs: bool
        """
        return self._thread.is_alive()

    def stop(self, timeout: float = 5.0) -> None:
        """
        Brief: Best-effort stop; waits for thread join.

        Inputs:
        - timeout: seconds to wait
        Outputs: None
        """
        try:
            self._thread.join(timeout=timeout)
        except Exception:
            logger.exception("Error while stopping DoH thread")


def start_doh_server(
    host: str,
    port: int,
    resolver: Callable[[bytes, str], bytes],
    *,
    cert_file: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Optional[DoHServerHandle]:
    """
    Brief: Start FastAPI-based DoH server on host:port using uvicorn in a background thread.

    Inputs:
    - host: listen address
    - port: listen port
    - resolver: callable (query_bytes, client_ip) -> response_bytes
    - cert_file: optional TLS certificate path
    - key_file: optional TLS key path

    Outputs:
    - DoHServerHandle if server started, else None

    Example:
      >>> handle = start_doh_server('127.0.0.1', 8053, lambda q, ip: q)
    """
    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover
        logger.error("uvicorn not available for DoH: %s", exc)
        return None

    app = create_doh_app(resolver)

    ssl_cert = cert_file or None
    ssl_key = key_file or None

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        ssl_certfile=ssl_cert,
        ssl_keyfile=ssl_key,
    )
    server = uvicorn.Server(config)

    import threading as _threading

    def _runner() -> None:
        try:
            server.run()
        except Exception:  # pragma: no cover
            logger.exception("Unhandled exception in DoH server thread")

    thread = _threading.Thread(target=_runner, name="foghorn-doh", daemon=True)
    thread.start()
    logger.info("Started DoH server on %s:%d", host, port)
    return DoHServerHandle(thread)
