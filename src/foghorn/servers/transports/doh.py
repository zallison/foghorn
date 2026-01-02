import base64
import http.client
import importlib
import ssl
import urllib.parse
from typing import Dict, Optional, Tuple

try:
    FOGHORN_VERSION = importlib.metadata.version("foghorn")
except (
    Exception
):  # pragma: no cover - defensive: metadata may be unavailable in some environments
    FOGHORN_VERSION = "unknown"


class DoHError(Exception):
    """
    Brief: DNS-over-HTTPS transport error.

    Inputs:
    - message: Description of the error

    Outputs:
    - Exception instance
    """

    pass


def _b64url_no_pad(data: bytes) -> str:
    """
    Brief: Base64url-encode without padding per RFC 8484.

    Inputs:
    - data: raw bytes to encode

    Outputs:
    - str: base64url string without '=' padding

    Example:
        >>> _b64url_no_pad(b"\x01\x02")
        'AQI'
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _build_ssl_ctx(
    verify: bool = True, ca_file: Optional[str] = None
) -> Optional[ssl.SSLContext]:
    """
    Brief: Build SSLContext for HTTPS connections.

    Inputs:
    - verify: whether to verify TLS certs
    - ca_file: optional CA bundle path

    Outputs:
    - ssl.SSLContext or None

    Example:
        >>> _build_ssl_ctx(True, None)  # doctest: +ELLIPSIS
        <ssl.SSLContext...>
    """
    if not verify:
        return ssl._create_unverified_context()
    return (
        ssl.create_default_context(cafile=ca_file)
        if ca_file
        else ssl.create_default_context()
    )


def doh_query(
    url: str,
    query: bytes,
    *,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    timeout_ms: int = 1500,
    verify: bool = True,
    ca_file: Optional[str] = None,
) -> Tuple[bytes, Dict[str, str]]:
    """
    Brief: Perform a DNS-over-HTTPS query (RFC 8484) using the standard library.

    Inputs:
    - url: Target DoH endpoint, e.g. https://dns.google/dns-query
    - query: Wire-format DNS query bytes
    - method: 'POST' or 'GET'
    - headers: Optional extra headers to include
    - timeout_ms: Total timeout per request
    - verify: Verify TLS certificates (HTTPS only)
    - ca_file: Optional CA bundle path for verification

    Outputs:
    - (body, resp_headers): tuple containing response body bytes and headers

    Notes:
    - For POST: sends body as application/dns-message.
    - For GET: appends ?dns=<base64url> and sends Accept: application/dns-message.
    - Raises DoHError for non-200 responses or network/TLS errors.

    Example:
        >>> # Minimal usage (errors if no server available)
        >>> try:
        ...     doh_query('https://example.invalid/dns-query', b'\x00\x01')
        ... except DoHError:
        ...     pass
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise DoHError(f"Unsupported URL scheme: {parsed.scheme}")

    connect_timeout = timeout_ms / 1000.0
    path = parsed.path or "/dns-query"
    extra_headers = {k: v for (k, v) in (headers or {}).items()}

    # Ensure a sensible default User-Agent when caller does not provide one.
    # Preserve any explicit header regardless of casing.
    if not any(k.lower() == "user-agent" for k in extra_headers):
        extra_headers["User-Agent"] = f"Foghorn v{FOGHORN_VERSION}"

    if method.upper() == "GET":
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs["dns"] = [_b64url_no_pad(query)]
        qstr = urllib.parse.urlencode(
            [(k, v if isinstance(v, str) else v[0]) for k, v in qs.items()]
        )
        target = path + ("?" + qstr if qstr else "")
        body = None
        hdrs = {"Accept": "application/dns-message", **extra_headers}
    else:
        target = path + ("?" + parsed.query if parsed.query else "")
        body = query
        hdrs = {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            **extra_headers,
        }

    try:
        if parsed.scheme == "https":
            ctx = _build_ssl_ctx(verify=verify, ca_file=ca_file)
            conn = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port or 443,
                timeout=connect_timeout,
                context=ctx,
            )
        else:
            conn = http.client.HTTPConnection(
                parsed.hostname,
                parsed.port or 80,
                timeout=connect_timeout,
            )
        try:
            conn.request(method.upper(), target, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            if resp.status != 200:
                raise DoHError(f"HTTP {resp.status}: {resp.reason}")
            # Return raw body; caller decides how to parse
            headers_out = {k.lower(): v for k, v in resp.getheaders()}
            return data, headers_out
        finally:
            try:
                conn.close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
    except ssl.SSLError as e:
        raise DoHError(f"TLS error: {e}")
    except OSError as e:
        raise DoHError(f"Network error: {e}")
