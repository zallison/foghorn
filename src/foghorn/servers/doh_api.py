import base64
import http.server
import logging
import ssl
import threading
import urllib.parse
from typing import Any, Callable, Optional

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
) -> Any:
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

    try:
        from fastapi import FastAPI, HTTPException, Request, Response, status
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "FastAPI is required for the uvicorn-based DoH server. Install fastapi or run with use_asyncio: false to use the threaded fallback."
        ) from exc

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
        # Interpret an empty response as an explicit drop/timeout request from
        # the shared resolver. For DoH we surface this as an HTTP 504 so that
        # callers can distinguish it from protocol errors while still getting a
        # well-formed HTTP response.
        if not resp:
            raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT)
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
        # Empty response -> explicit drop/timeout from resolver; return HTTP
        # 504 so DoH clients can treat this as a timeout-equivalent condition.
        if not resp:
            raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT)
        return Response(
            content=resp, media_type=_DNS_CT, headers={"Connection": "close"}
        )

    return app


class _ThreadedDoHRequestHandler(http.server.BaseHTTPRequestHandler):
    """Brief: Minimal HTTP/1.1 DoH handler using the standard library.

    Inputs:
    - Inherits request/connection attributes from BaseHTTPRequestHandler.

    Outputs:
    - Handles GET/POST /dns-query with RFC 8484-compatible semantics.

    Notes:
    - Resolver callable is attached via the class attribute ``resolver``.
    """

    # Resolver will be injected by the server factory.
    resolver: Callable[[bytes, str], bytes] | None = None

    def _client_ip(self) -> str:
        """Brief: Return best-effort client IP.

        Inputs: None
        Outputs: str IP address string.
        """
        addr = getattr(self, "client_address", None)
        if isinstance(addr, tuple) and addr:
            return str(addr[0])
        return "0.0.0.0"

    def _send_bytes(self, status_code: int, body: bytes, content_type: str) -> None:
        """Brief: Send raw bytes with given status and content type.

        Inputs:
        - status_code: HTTP status code
        - body: response payload as bytes
        - content_type: MIME type string

        Outputs:
        - None
        """
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_empty(self, status_code: int) -> None:
        """Brief: Send an empty response body with the given HTTP status code.

        Inputs:
        - status_code: HTTP status code
        Outputs:
        - None
        """
        self._send_bytes(status_code, b"", "text/plain; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802 (HTTP verb name)
        """Brief: Handle GET /dns-query?dns=<base64url> requests.

        Inputs: None
        Outputs: None (writes HTTP response to client socket).
        """
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/dns-query":
            self._send_empty(404)
            return

        params = urllib.parse.parse_qs(parsed.query)
        dns_param = params.get("dns", [None])[0]
        if not dns_param:
            self._send_empty(400)
            return

        try:
            qbytes = _b64url_decode_nopad(str(dns_param))
        except Exception:
            self._send_empty(400)
            return

        resolver = self.resolver or (lambda q, ip: q)
        client_ip = self._client_ip()
        try:
            resp = resolver(qbytes, client_ip)
        except Exception:
            logger.exception("resolver raised in threaded DoH GET")
            self._send_empty(400)
            return

        # Empty response means explicit drop/timeout from resolver; for the
        # threaded HTTP path we simply close the connection without sending an
        # HTTP response so DoH clients observe a network-level timeout.
        if not resp:
            self.close_connection = True
            return

        self._send_bytes(200, resp, _DNS_CT)

    def do_POST(self) -> None:  # noqa: N802 (HTTP verb name)
        """Brief: Handle POST /dns-query with DNS message body.

        Inputs: None
        Outputs: None (writes HTTP response to client socket).
        """
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/dns-query":
            self._send_empty(404)
            return

        ctype = self.headers.get("Content-Type", "")
        if _DNS_CT not in ctype:
            self._send_empty(415)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""

        resolver = self.resolver or (lambda q, ip: q)
        client_ip = self._client_ip()
        try:
            resp = resolver(body, client_ip)
        except Exception:
            logger.exception("resolver raised in threaded DoH POST")
            self._send_empty(400)
            return

        # Empty response -> explicit drop/timeout from resolver; close the
        # connection without sending an HTTP response so clients see a
        # timeout-style failure.
        if not resp:
            self.close_connection = True
            return

        self._send_bytes(200, resp, _DNS_CT)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        """Brief: Route handler logs through the module logger instead of stderr.

        Inputs:
        - format: format string
        - args: format arguments

        Outputs:
        - None
        """
        try:
            msg = format % args
        except Exception:
            msg = format
        logger.info("DoH HTTP: %s", msg)


def _start_doh_server_threaded(
    host: str,
    port: int,
    resolver: Callable[[bytes, str], bytes],
    *,
    cert_file: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Optional["DoHServerHandle"]:
    """Brief: Start a threaded HTTP DoH server without using asyncio.

    Inputs:
    - host: listen address
    - port: listen port
    - resolver: callable (query_bytes, client_ip) -> response_bytes
    - cert_file: optional TLS certificate path
    - key_file: optional TLS key path

    Outputs:
    - DoHServerHandle if server started successfully, else None.

    Example:
      >>> handle = _start_doh_server_threaded('127.0.0.1', 8153, lambda q, ip: q)
    """
    handler_cls = _ThreadedDoHRequestHandler
    handler_cls.resolver = staticmethod(resolver)  # type: ignore[assignment]

    try:
        httpd = http.server.ThreadingHTTPServer((host, port), handler_cls)
    except OSError as exc:  # pragma: no cover - hard to force in unit tests
        logger.error("Failed to bind threaded DoH server on %s:%d: %s", host, port, exc)
        return None

    if cert_file and key_file:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        except Exception as exc:  # pragma: no cover - TLS misconfig
            logger.error("Failed to configure TLS for threaded DoH server: %s", exc)
            try:
                httpd.server_close()
            except Exception:
                pass
            return None

    def _serve() -> None:
        try:
            httpd.serve_forever()
        except Exception:  # pragma: no cover - unexpected runtime error
            logger.exception("Unhandled exception in threaded DoH server")
        finally:
            try:
                httpd.server_close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

    thread = threading.Thread(target=_serve, name="foghorn-doh-threaded", daemon=True)
    thread.start()
    logger.info("Started threaded DoH server on %s:%d", host, port)
    return DoHServerHandle(thread, server=httpd)


class DoHServerHandle:
    """Brief: Handle for a background DoH server thread.

    Inputs (constructor):
    - thread: Thread object running the HTTP/uvicorn server loop.
    - server: Optional server instance with shutdown/server_close methods.

    Outputs:
    - DoHServerHandle with is_running() and stop().

    Example:
      >>> # typically created by start_doh_server()
    """

    def __init__(self, thread, server: Any | None = None) -> None:
        self._thread = thread
        self._server = server

    def is_running(self) -> bool:
        """Brief: Return True if thread is alive.

        Inputs: None
        Outputs: bool
        """
        return self._thread.is_alive()

    def stop(self, timeout: float = 5.0) -> None:
        """Brief: Best-effort stop; shuts down server if possible and waits for thread.

        Inputs:
        - timeout: seconds to wait
        Outputs: None
        """
        try:
            if self._server is not None:
                try:
                    # Graceful shutdown for threaded HTTP servers.
                    shutdown = getattr(self._server, "shutdown", None)
                    if callable(shutdown):
                        shutdown()
                    close = getattr(self._server, "server_close", None)
                    if callable(close):
                        close()
                except Exception:
                    logger.exception("Error while shutting down DoH server instance")
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
    use_asyncio: bool = True,
) -> Optional[DoHServerHandle]:
    """Brief: Start DoH server, preferring uvicorn but falling back to threaded HTTP.

    Inputs:
    - host: listen address
    - port: listen port
    - resolver: callable (query_bytes, client_ip) -> response_bytes
    - cert_file: optional TLS certificate path
    - key_file: optional TLS key path

    Outputs:
    - DoHServerHandle if server started, else None.

    Example:
      >>> handle = start_doh_server('127.0.0.1', 8153, lambda q, ip: q)
    """
    # First, detect environments where asyncio cannot create its self-pipe
    # (e.g., restricted containers or seccomp profiles). In that case, skip
    # uvicorn entirely and use the threaded HTTP implementation. Also honor the
    # global foghorn.use_asyncio knob when provided by callers.
    can_use_asyncio = bool(use_asyncio)
    if can_use_asyncio:
        try:  # pragma: no cover - difficult to exercise PermissionError in CI
            import asyncio

            loop = asyncio.new_event_loop()
            loop.close()
        except (
            PermissionError
        ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.warning(
                "Asyncio loop creation failed for DoH; falling back to threaded HTTP server: %s",
                exc,
            )
            can_use_asyncio = False
        except Exception:
            # For other issues we still attempt uvicorn and rely on its own error
            # handling; the threaded fallback remains available on ImportError.
            can_use_asyncio = bool(use_asyncio)

    if not can_use_asyncio:
        return _start_doh_server_threaded(
            host,
            port,
            resolver,
            cert_file=cert_file,
            key_file=key_file,
        )

    try:
        import uvicorn
    except (
        Exception
    ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        logger.error("uvicorn not available for DoH: %s; using threaded fallback", exc)
        return _start_doh_server_threaded(
            host,
            port,
            resolver,
            cert_file=cert_file,
            key_file=key_file,
        )

    try:
        app = create_doh_app(resolver)
    except Exception as exc:  # pragma: no cover
        logger.error("FastAPI not available for DoH: %s; using threaded fallback", exc)
        return _start_doh_server_threaded(
            host,
            port,
            resolver,
            cert_file=cert_file,
            key_file=key_file,
        )

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
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.exception("Unhandled exception in DoH server thread")

    thread = _threading.Thread(target=_runner, name="foghorn-doh", daemon=True)
    thread.start()
    logger.info("Started DoH server on %s:%d", host, port)
    return DoHServerHandle(thread)
