"""Shared helpers for hosts-like resolve plugins.

Brief:
  - Pure helpers for TXT sanitize, TLS path resolve, DNS labels, map merge,
    and authoritative A/AAAA/PTR reply packing (used by Docker/Proxmox/K8s,
    EtcHosts, and MdnsBridge).
  - DynamicHostsPlugin base: host maps, reload loop, shutdown, and shared
    A/AAAA/PTR/TXT pre_resolve answering (sticky condition logs via condition_logging).
"""

from __future__ import annotations

import logging
import os
import re
import threading
import warnings
from collections.abc import Iterable
from typing import Any, ClassVar

import requests
from dnslib import AAAA, PTR, QTYPE, RR, TXT, A, DNSHeader, DNSRecord
from requests.adapters import HTTPAdapter

from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision
from foghorn.utils import condition_logging as condition_log
from foghorn.utils.dns_names import normalize_name, qualify_name
from foghorn.utils.ip_networks import parse_ip, parse_network

logger = logging.getLogger(__name__)

_DNS_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# verify=False triggers urllib3 InsecureRequestWarning on every request (and
# logging.captureWarnings routes those into py.warnings). Suppress once and
# emit a single compact operator notice per target URL/host instead.
_INSECURE_TLS_NOTICES: set[str] = set()
_INSECURE_TLS_LOCK = threading.Lock()
_INSECURE_WARNING_FILTER_INSTALLED = False


def sanitize_txt_chunk(text: str, max_bytes: int = 253) -> str:
    """Brief: Remove control characters and clamp TXT chunk UTF-8 bytes.

    Inputs:
      - text: Raw text to emit as a DNS TXT character-string.
      - max_bytes: Maximum UTF-8 byte budget for the chunk (default 253).

    Outputs:
      - Sanitized text chunk.
    """

    cleaned = _CONTROL_CHARS_RE.sub("", str(text or ""))
    encoded = cleaned.encode("utf-8")[: int(max_bytes)]
    return encoded.decode("utf-8", errors="ignore")


def resolve_plugin_tls_path(path: str) -> str:
    """Brief: Resolve a plugin TLS path via config dir / CWD defaults.

    Inputs:
      - path: Absolute or relative cert/key/CA path from plugin config.

    Outputs:
      - Resolved filesystem path (may not exist yet).

    Notes:
      - Wraps foghorn.servers.webserver.tls_certs.resolve_tls_path after
        locating the active config path (runtime, FOGHORN_CONFIG, defaults).
    """

    from foghorn.servers.webserver.tls_certs import resolve_tls_path

    config_path = None
    try:
        from foghorn.runtime_config import get_config_path

        config_path = get_config_path()
    except Exception:
        config_path = None
    if not config_path:
        for candidate in (
            os.environ.get("FOGHORN_CONFIG"),
            "config/config.yaml",
            "/foghorn/config/config.yaml",
        ):
            if candidate and os.path.isfile(candidate):
                config_path = candidate
                break
    return resolve_tls_path(path, config_path=config_path)


def is_valid_dns_label(name: str) -> bool:
    """Brief: Validate a single publishable DNS label (no underscores).

    Inputs:
      - name: Candidate label without dots.

    Outputs:
      - True when the label is publishable under LDH rules.
    """

    label = normalize_name(name)
    if not label or "." in label or len(label) > 63:
        return False
    return bool(_DNS_LABEL_RE.match(label))


def is_valid_dns_hostname(name: str) -> bool:
    """Brief: Validate a single- or multi-label hostname (LDH labels).

    Inputs:
      - name: Candidate hostname; may contain dots (no trailing dot).

    Outputs:
      - True when every label is publishable under LDH rules after
        normalize_host_label (lowercase, strip dots, underscores to hyphens).

    Notes:
      - Validation runs on the normalized form, so names with underscores can
        pass when the hyphenated equivalent is valid (e.g. "api_internal" ->
        "api-internal" -> True).

    Example:
      is_valid_dns_hostname("api") -> True
      is_valid_dns_hostname("api.internal") -> True
      is_valid_dns_hostname("_bad") -> False
    """

    host = normalize_host_label(name)
    if not host or len(host) > 253:
        return False
    return all(is_valid_dns_label(part) for part in host.split(".") if part)


def dns_names_from_labels(
    labels: dict | None,
    label_key: str = "dns_name",
) -> list[str]:
    """Brief: Extract publishable DNS names from a labels/tags mapping.

    Inputs:
      - labels: Mapping of label key -> value (Docker Labels / K8s metadata.labels).
      - label_key: Label name to read (default "dns_name").

    Outputs:
      - Deduped list of normalized hostnames. Values may be comma- or
        whitespace-separated multi-names. Invalid tokens are dropped.

    Example:
      dns_names_from_labels({"dns_name": "api, web"}) -> ["api", "web"]
    """

    key = str(label_key or "").strip() or "dns_name"
    if not isinstance(labels, dict) or not key:
        return []
    raw = labels.get(key)
    if raw is None:
        # Case-insensitive key match for operator convenience.
        key_l = key.lower()
        for k, v in labels.items():
            if str(k).lower() == key_l:
                raw = v
                break
        else:
            return []
    text = str(raw).strip()
    if not text:
        return []
    # Split on commas and/or whitespace so "api,web" and "api web" both work.
    tokens = [t for t in re.split(r"[\s,]+", text) if t]
    out: list[str] = []
    seen: set[str] = set()
    for tok in tokens:
        host = normalize_host_label(tok)
        if not host or host in seen:
            continue
        if not is_valid_dns_hostname(host):
            continue
        seen.add(host)
        out.append(host)
    return out


def normalize_suffix(raw: object) -> str:
    """Brief: Normalize a DNS suffix; None/empty yield "".

    Inputs:
      - raw: Config value.

    Outputs:
      - Normalized suffix without leading/trailing dots, or empty string.
        None/empty/"none"/"null" yield "".
    """

    if raw is None:
        return ""
    text = str(raw).strip()
    if not text or text.lower() in {"none", "null"}:
        return ""
    return normalize_name(text)


def normalize_host_label(value: str) -> str:
    """Brief: DNS-safe hostname: lower, strip dots, underscores to hyphens.

    Inputs:
      - value: Raw resource/container/guest name.

    Outputs:
      - Normalized name string (may still contain dots for multi-label names).
    """

    return normalize_name(str(value or "").replace("_", "-"))


def join_host_suffix(name: str, suffix: str | None) -> str:
    """Brief: Append optional DNS suffix using dns_names helpers.

    Inputs:
      - name: Base hostname (no trailing dot).
      - suffix: Optional domain suffix.

    Outputs:
      - Combined name without trailing dot. Returns base when suffix empty or
        when base already ends with the suffix.
    """

    base = normalize_host_label(name)
    if not base:
        return ""
    suf = normalize_name(suffix or "")
    if not suf:
        return base
    if base == suf or base.endswith("." + suf):
        return base
    qualified = qualify_name(base, suf)
    return qualified if qualified else f"{base}.{suf}"


def merge_list_map(dst: dict[str, list[str]], src: dict[str, list[str]]) -> None:
    """Brief: Merge hostname -> list[str] maps without duplicates.

    Inputs:
      - dst / src: Destination and source maps.

    Outputs:
      - None (mutates dst).
    """

    for key, values in src.items():
        bucket = dst.setdefault(key, [])
        for v in values:
            if v not in bucket:
                bucket.append(v)


def ptr_owner(hostname: str) -> str:
    """Brief: Ensure a PTR rdata owner ends with a trailing dot.

    Inputs:
      - hostname: Canonical hostname from reverse maps.

    Outputs:
      - Hostname with exactly one trailing dot.
    """

    host = str(hostname or "").strip()
    if not host:
        return "."
    return host if host.endswith(".") else host + "."


def format_exception_brief(exc: BaseException) -> str:
    """Brief: Human-readable exception text that stays useful when str(exc) is empty.

    Inputs:
      - exc: Caught exception instance.

    Outputs:
      - "Type: message" when message is non-empty; otherwise just the type name.

    Example:
      format_exception_brief(NotImplementedError()) -> "NotImplementedError"
      format_exception_brief(RuntimeError("boom")) -> "RuntimeError: boom"
    """

    name = type(exc).__name__
    msg = str(exc).strip()
    if not msg:
        return name
    return f"{name}: {msg}"


def is_reverse_ptr_name(name: str) -> bool:
    """Brief: True when name is an in-addr.arpa or ip6.arpa reverse owner.

    Inputs:
      - name: Normalized DNS owner (no trailing dot expected).

    Outputs:
      - bool.
    """

    text = str(name or "").lower().rstrip(".")
    return text.endswith(".in-addr.arpa") or text.endswith(".ip6.arpa")


def ip_matches_qtype(ip_text: str, qtype: int) -> bool:
    """Brief: True when an address string is compatible with A or AAAA qtype.

    Inputs:
      - ip_text: Address text (may be unparsed; uses ':' / '.' heuristics).
      - qtype: Numeric QTYPE (A or AAAA).

    Outputs:
      - False when the family clearly mismatches the query type.
    """

    ip = str(ip_text or "")
    is_v6 = ":" in ip
    is_v4 = "." in ip
    if qtype == QTYPE.AAAA and is_v4 and not is_v6:
        return False
    if qtype == QTYPE.A and is_v6 and not is_v4:
        return False
    return True


def parse_dns_request(
    req: bytes,
    *,
    log: logging.Logger | None = None,
    log_message: str | None = None,
    log_args: tuple[object, ...] = (),
) -> DNSRecord | None:
    """Brief: Parse wire DNS request bytes into a DNSRecord.

    Inputs:
      - req: Raw DNS query bytes.
      - log: Optional logger for parse failures.
      - log_message: Optional warning template when parse fails.
      - log_args: %-format args for log_message.

    Outputs:
      - DNSRecord, or None on parse failure.
    """

    try:
        return DNSRecord.parse(req)
    except Exception as exc:
        if log is not None and log_message:
            log.warning(log_message, *log_args, exc)
        elif log is not None:
            log.warning("DNS request parse failure: %s", exc)
        return None


def authoritative_reply(request: DNSRecord) -> DNSRecord:
    """Brief: Build an empty AA+RA response shell matching the request question.

    Inputs:
      - request: Parsed DNS query.

    Outputs:
      - DNSRecord reply with qr/aa/ra set and the same question.
    """

    return DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)


def rr_a(rname: object, ip: str, ttl: int) -> RR:
    """Brief: Build an A RR.

    Inputs:
      - rname: Owner name (dnslib name or str).
      - ip: IPv4 text.
      - ttl: TTL seconds.

    Outputs:
      - RR instance.
    """

    return RR(rname=rname, rtype=QTYPE.A, rclass=1, ttl=int(ttl), rdata=A(ip))


def rr_aaaa(rname: object, ip: str, ttl: int) -> RR:
    """Brief: Build an AAAA RR.

    Inputs:
      - rname: Owner name (dnslib name or str).
      - ip: IPv6 text.
      - ttl: TTL seconds.

    Outputs:
      - RR instance.
    """

    return RR(rname=rname, rtype=QTYPE.AAAA, rclass=1, ttl=int(ttl), rdata=AAAA(ip))


def rr_ptr(rname: object, hostname: str, ttl: int) -> RR:
    """Brief: Build a PTR RR (hostname normalized with trailing dot).

    Inputs:
      - rname: Owner name (dnslib name or str).
      - hostname: PTR target hostname.
      - ttl: TTL seconds.

    Outputs:
      - RR instance.
    """

    return RR(
        rname=rname,
        rtype=QTYPE.PTR,
        rclass=1,
        ttl=int(ttl),
        rdata=PTR(ptr_owner(hostname)),
    )


def rr_txt(
    rname: object, values: Iterable[str], ttl: int, *, sanitize: bool = True
) -> RR:
    """Brief: Build a TXT RR from string chunks.

    Inputs:
      - rname: Owner name (dnslib name or str).
      - values: TXT character-strings.
      - ttl: TTL seconds.
      - sanitize: When True, run each chunk through sanitize_txt_chunk.

    Outputs:
      - RR instance.
    """

    chunks = [
        sanitize_txt_chunk(str(v)) if sanitize else str(v) for v in values if str(v)
    ]
    return RR(
        rname=rname,
        rtype=QTYPE.TXT,
        rclass=1,
        ttl=int(ttl),
        rdata=TXT(chunks),
    )


def limit_txt_values(
    values: Iterable[str],
    *,
    max_strings: int = 0,
    max_bytes: int = 0,
    sanitize: bool = False,
) -> list[str]:
    """Brief: Cap TXT strings by count and total UTF-8 bytes.

    Inputs:
      - values: Candidate TXT strings.
      - max_strings: Max strings (0 = unlimited).
      - max_bytes: Max total UTF-8 bytes across emitted strings (0 = unlimited).
      - sanitize: When True, sanitize each kept chunk.

    Outputs:
      - Possibly truncated list of strings (order preserved).
    """

    out: list[str] = []
    total_bytes = 0
    for item in values:
        text = sanitize_txt_chunk(str(item)) if sanitize else str(item)
        if not text and not str(item):
            continue
        if max_strings > 0 and len(out) >= max_strings:
            break
        try:
            encoded = text.encode("utf-8", errors="replace")
        except Exception:
            encoded = repr(text).encode("utf-8", errors="replace")
        if max_bytes > 0 and total_bytes + len(encoded) > max_bytes:
            break
        out.append(text)
        total_bytes += len(encoded)
    return out


def make_a_aaaa_response(
    req: bytes,
    qtype: int,
    addrs: Iterable[str],
    ttl: int,
    *,
    qname: str | None = None,
    log: logging.Logger | None = None,
) -> bytes | None:
    """Brief: Pack an authoritative A/AAAA answer for one question.

    Inputs:
      - req: Raw DNS request bytes.
      - qtype: QTYPE.A or QTYPE.AAAA (other values treated as A).
      - addrs: Address strings to include (may be empty -> NOERROR empty answer).
      - ttl: Answer TTL seconds.
      - qname: Optional name for parse-failure logs.
      - log: Optional logger.

    Outputs:
      - Packed response bytes, or None when req cannot be parsed.

    Example:
      wire = make_a_aaaa_response(req, QTYPE.A, ["10.0.0.1"], 300)
    """

    name = qname or "?"
    request = parse_dns_request(
        req,
        log=log,
        log_message="parse failure building response for %s %s: %s",
        log_args=(name, QTYPE.get(qtype, str(qtype))),
    )
    if request is None:
        return None

    reply = authoritative_reply(request)
    addrs_list = [str(a) for a in addrs]
    if not addrs_list:
        return reply.pack()

    use_aaaa = qtype == QTYPE.AAAA
    for ipaddr in addrs_list:
        if use_aaaa:
            reply.add_answer(rr_aaaa(request.q.qname, ipaddr, ttl))
        else:
            reply.add_answer(rr_a(request.q.qname, ipaddr, ttl))
    return reply.pack()


def make_ptr_response(
    req: bytes,
    hostname: str,
    ttl: int,
    *,
    qname: str | None = None,
    log: logging.Logger | None = None,
) -> bytes | None:
    """Brief: Pack an authoritative PTR answer for one question.

    Inputs:
      - req: Raw DNS request bytes.
      - hostname: PTR target hostname (trailing dot optional).
      - ttl: Answer TTL seconds.
      - qname: Optional reverse name for parse-failure logs.
      - log: Optional logger.

    Outputs:
      - Packed response bytes, or None when req cannot be parsed.
    """

    name = qname or "?"
    request = parse_dns_request(
        req,
        log=log,
        log_message="parse failure for PTR %s: %s",
        log_args=(name,),
    )
    if request is None:
        return None

    reply = authoritative_reply(request)
    reply.add_answer(rr_ptr(request.q.qname, hostname, ttl))
    return reply.pack()


def empty_host_maps() -> dict[str, Any]:
    """Brief: Allocate empty forward/reverse/TXT map dicts.

    Inputs:
      - None.

    Outputs:
      - Dict with keys forward_v4, forward_v6, reverse, ttl_v4, ttl_v6,
        ttl_ptr, aggregate_txt, ttl_txt.
    """

    return {
        "forward_v4": {},
        "forward_v6": {},
        "reverse": {},
        "ttl_v4": {},
        "ttl_v6": {},
        "ttl_ptr": {},
        "aggregate_txt": {},
        "ttl_txt": {},
    }


def parse_str_list(raw: object, *, lower: bool = True) -> list[str]:
    """Brief: Normalize a config str/list value to a deduped string list.

    Inputs:
      - raw: str, list, None, or other single value.
      - lower: When True, lower-case entries.

    Outputs:
      - Deduped non-empty strings (order preserved).
    """

    if raw is None:
        items: list[object] = []
    elif isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = list(raw)
    else:
        items = [raw]
    out: list[str] = []
    for item in items:
        name = str(item or "").strip()
        if lower:
            name = name.lower()
        if name and name not in out:
            out.append(name)
    return out


def parse_cidr_list(
    raw: object,
    *,
    option_name: str = "cidrs",
    log: logging.Logger | None = None,
) -> list[Any]:
    """Brief: Parse a config list of CIDR/network strings via ip_networks.

    Inputs:
      - raw: str, list, or None from config.
      - option_name: Config key name for warnings.
      - log: Optional logger (defaults to module logger).

    Outputs:
      - list of ipaddress network objects.
    """

    lg = log or logger
    if raw is None:
        items: list[object] = []
    elif isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = list(raw)
    else:
        items = [raw]

    networks: list[Any] = []
    for item in items:
        text = str(item or "").strip()
        if not text:
            continue
        net = parse_network(text, strict=False)
        if net is None:
            lg.warning("ignoring invalid %s entry %r", option_name, item)
            continue
        networks.append(net)
    return networks


def is_usable_ip(ip_text: str) -> bool:
    """Brief: True when address is publishable (not loopback/link-local/etc).

    Inputs:
      - ip_text: Address string.

    Outputs:
      - True when structurally publishable.
    """

    ip = parse_ip(ip_text)
    if ip is None:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return False
    return True


def ip_passes_cidr_filters(
    ip_text: str,
    *,
    include_cidrs: Iterable[Any] | None = None,
    exclude_cidrs: Iterable[Any] | None = None,
) -> bool:
    """Brief: Apply usable-IP plus optional include/exclude CIDR filters.

    Inputs:
      - ip_text: Address string.
      - include_cidrs: Optional parsed networks; empty means unrestricted.
      - exclude_cidrs: Optional parsed networks to block.

    Outputs:
      - True when the address should be published.
    """

    text = str(ip_text).strip()
    if not is_usable_ip(text):
        return False
    ip = parse_ip(text)
    if ip is None:
        return False
    include = list(include_cidrs or [])
    if include and not any(ip in net for net in include):
        return False
    exclude = list(exclude_cidrs or [])
    if exclude and any(ip in net for net in exclude):
        return False
    return True


def apply_address_limit(
    v4: list[str], v6: list[str], limit: int
) -> tuple[list[str], list[str]]:
    """Brief: Truncate per-family address lists when limit > 0.

    Inputs:
      - v4 / v6: Ordered address lists.
      - limit: Max addresses per family (0 = unlimited).

    Outputs:
      - Possibly truncated (v4, v6).
    """

    cap = int(limit or 0)
    if cap <= 0:
        return v4, v6
    return v4[:cap], v6[:cap]


def discovery_owner(record_label: str, suffix: str | None = None) -> str:
    """Brief: Build a discovery TXT owner like _containers.<suffix>.

    Inputs:
      - record_label: Leading label such as "_containers" or "_hosts".
      - suffix: Optional DNS suffix (internal empty labels collapsed).

    Outputs:
      - Owner name without trailing dot.
    """

    label = str(record_label or "").strip().strip(".").lower()
    if not label:
        label = "_hosts"
    # Collapse runs of dots in raw suffix the same way docker owner helpers did
    # historically (e.g. ".docker..mycorp." -> "docker.mycorp").
    raw = str(suffix or "").strip().strip(".")
    parts = [p for p in raw.split(".") if p]
    suf = ".".join(parts).lower()
    if suf:
        return f"{label}.{suf}"
    return label


def normalize_publishable_hostname(value: str) -> str:
    """Brief: Normalize a guest/container name to a publishable hostname.

    Inputs:
      - value: Raw name (may be multi-label).

    Outputs:
      - Lowercase hostname with underscores as hyphens. Multi-label names are
        kept when every label is valid; otherwise only the first label is
        considered and returned if it is a valid DNS label, else "". Later
        labels are not scanned for a valid fallback.
    """

    text = normalize_host_label(value)
    if not text:
        return ""
    if "." in text:
        parts = [p for p in text.split(".") if p]
        if parts and all(is_valid_dns_label(p) for p in parts):
            return ".".join(parts)
        text = parts[0] if parts else ""
    if is_valid_dns_label(text):
        return text
    return ""


def fold_tls_aliases(
    data: Any,
    *,
    pairs: tuple[tuple[str, str], ...] | None = None,
) -> Any:
    """Brief: Copy tls_* alias keys onto canonical TLS field names.

    Inputs:
      - data: Raw config mapping or other value.
      - pairs: Optional (src, dst) alias pairs. Default maps docker/proxmox-style
        tls_ca/tls_cert/tls_key/tls_name/verify_tls onto ca_cert/client_*/tls_*.

    Outputs:
      - Mapping with aliases folded, or the original non-mapping value.
    """

    if not isinstance(data, dict):
        return data
    out = dict(data)
    default_pairs = (
        ("tls_ca", "ca_cert"),
        ("tls_cert", "client_cert"),
        ("tls_key", "client_key"),
        ("tls_name", "tls_server_name"),
        ("verify_tls", "tls_verify"),
    )
    for src, dst in pairs or default_pairs:
        if out.get(dst) in (None, "") and out.get(src) not in (None, ""):
            out[dst] = out[src]
    return out


class DynamicHostsPlugin(BasePlugin):
    """Brief: Base for inventory-backed hosts plugins (Docker/Proxmox/K8s).

    Provides in-memory host maps, background reload loop, shutdown signaling,
    and shared A/AAAA/PTR/TXT pre_resolve answers. Sticky condition logging via
    foghorn.utils.condition_logging. Subclasses implement `_reload_maps()` and call
    `_init_dynamic_hosts_state()` from setup().
    """

    setup_provides_dns: ClassVar[bool] = True
    setup_requires_dns: ClassVar[bool] = True

    def _init_dynamic_hosts_state(self, *, default_ttl: int = 300) -> None:
        """Brief: Initialize maps, locks, stop event, and condition-log state.

        Inputs:
          - default_ttl: Fallback TTL when maps omit a per-name value.

        Outputs:
          - None.
        """

        self._ttl = int(default_ttl)
        self._lock = threading.RLock()
        maps = empty_host_maps()
        self._forward_v4: dict[str, list[str]] = maps["forward_v4"]
        self._forward_v6: dict[str, list[str]] = maps["forward_v6"]
        self._reverse: dict[str, str] = maps["reverse"]
        self._ttl_v4: dict[str, int] = maps["ttl_v4"]
        self._ttl_v6: dict[str, int] = maps["ttl_v6"]
        self._ttl_ptr: dict[str, int] = maps["ttl_ptr"]
        self._aggregate_txt: dict[str, list[str]] = maps["aggregate_txt"]
        self._ttl_txt: dict[str, int] = maps["ttl_txt"]
        self._stop_event = threading.Event()
        self._reload_interval = 0.0
        self._expose_txt_in_additional = False
        condition_log.init_condition_logging(self)

    def _note_condition_failure(self, key: str, message: str, *args: object) -> None:
        """Brief: Log a sticky condition failure (wraps condition_log.note_condition_failure)."""
        condition_log.note_condition_failure(self, key, message, *args)

    def _note_condition_ok(
        self, key: str, recovery_message: str | None = None, *args: object
    ) -> None:
        """Brief: Clear a sticky failure condition (wraps condition_log.note_condition_ok)."""
        condition_log.note_condition_ok(self, key, recovery_message, *args)

    def _reload_maps(self) -> None:
        """Brief: Rebuild in-memory host maps from the backend.

        Inputs:
          - None.

        Outputs:
          - None.

        Notes:
          - Subclasses must override. Called by _reload_loop and usually once
            during setup().
        """

        raise NotImplementedError

    def _start_reload_loop(self, *, thread_name: str) -> None:
        """Brief: Start daemon reload thread when _reload_interval > 0.

        Inputs:
          - thread_name: Thread name for diagnostics.

        Outputs:
          - None.
        """

        interval = float(getattr(self, "_reload_interval", 0.0) or 0.0)
        if interval <= 0:
            return
        if not hasattr(self, "_stop_event") or self._stop_event is None:
            self._stop_event = threading.Event()
        t = threading.Thread(
            target=self._reload_loop,
            name=thread_name,
            daemon=True,
        )
        t.start()

    def _reload_loop(self) -> None:
        """Brief: Periodically call _reload_maps until stop_event is set.

        Inputs:
          - None (uses self._reload_interval and _reload_maps()).

        Outputs:
          - None.
        """

        interval = float(getattr(self, "_reload_interval", 0.0) or 0.0)
        if interval <= 0:
            return
        stop = getattr(self, "_stop_event", None)
        if stop is None:
            return
        while True:
            if stop.wait(timeout=interval):
                return
            try:
                self._reload_maps()
                condition_log.note_condition_ok(
                    self,
                    "periodic-reload-error",
                    "periodic reload recovered",
                )
            except Exception as exc:  # pragma: nocover defensive
                condition_log.note_condition_failure(
                    self,
                    "periodic-reload-error",
                    "error during periodic reload; keeping previous mappings: %s",
                    format_exception_brief(exc),
                )

    def _shutdown_resources(self) -> None:
        """Brief: Subclass hook to close clients / temp files after stop signal.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        return

    def shutdown(self) -> None:
        """Brief: Signal background reload thread to stop and release resources.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        try:
            stop = getattr(self, "_stop_event", None)
            if stop is not None:
                stop.set()
        except Exception:
            pass
        try:
            self._shutdown_resources()
        except Exception:
            logger.debug("hosts plugin shutdown_resources failed", exc_info=True)

    def _make_ip_response(
        self,
        qname: str,
        qtype: int,
        req: bytes,
        addrs: list[str],
        ttl: int,
    ) -> bytes | None:
        """Brief: Build a minimal A/AAAA DNS response for a single owner.

        Inputs:
          - qname: Owner name for the DNS question (logging only).
          - qtype: Numeric QTYPE (A or AAAA).
          - req: Raw DNS request wire bytes.
          - addrs: IP address strings to include as answers.
          - ttl: TTL seconds for each answer RR.

        Outputs:
          - Packed DNS response bytes, or None when req cannot be parsed.
        """

        return make_a_aaaa_response(
            req,
            qtype,
            addrs,
            ttl,
            qname=qname,
            log=getattr(self, "logger", logger),
        )

    def _build_address_reply(
        self,
        req: bytes,
        qname: str,
        rtype: int,
        addrs: list[str],
        ttl: int,
        txts: list[str],
        txt_ttl: int,
        *,
        rdata_cls: Any,
    ) -> PluginDecision | None:
        """Brief: Build an A/AAAA override reply with optional TXT additionals.

        Inputs:
          - req / qname / rtype / addrs / ttl / txts / txt_ttl / rdata_cls.

        Outputs:
          - PluginDecision or None on parse failure.
        """

        request = parse_dns_request(
            req,
            log=logger,
            log_message="parse failure for %s %s: %s",
            log_args=(QTYPE.get(rtype, str(rtype)), qname),
        )
        if request is None:
            return None
        reply = authoritative_reply(request)
        for ipaddr in addrs:
            if rdata_cls is AAAA or rtype == QTYPE.AAAA:
                reply.add_answer(rr_aaaa(request.q.qname, ipaddr, ttl))
            else:
                reply.add_answer(rr_a(request.q.qname, ipaddr, ttl))
        if getattr(self, "_expose_txt_in_additional", False):
            for line in txts:
                reply.add_ar(
                    rr_txt(request.q.qname, [str(line)], txt_ttl, sanitize=True)
                )
            try:
                if len(reply.pack()) > 512:
                    reply.ar = []
                    reply.header.tc = 1
            except Exception:
                reply.ar = []
                reply.header.tc = 1
        return PluginDecision(action="override", response=reply.pack())

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> PluginDecision | None:
        """Brief: Answer A/AAAA/PTR/TXT from in-memory host maps.

        Inputs:
          - qname: Queried name.
          - qtype: DNS query type.
          - req: Wire request bytes.
          - ctx: Plugin context.

        Outputs:
          - PluginDecision(override) when answered; else None.
        """

        if not self.targets(ctx):
            return None

        name = normalize_name(qname)
        default_ttl = int(getattr(self, "_ttl", 300) or 300)

        if qtype == QTYPE.A:
            with self._lock:
                addrs = list(self._forward_v4.get(name, []))
                ttl = int(self._ttl_v4.get(name, default_ttl))
                txts = list(self._aggregate_txt.get(name, []))
                txt_ttl = int(self._ttl_txt.get(name, default_ttl))
            if not addrs and not txts:
                return None
            return self._build_address_reply(
                req, qname, QTYPE.A, addrs, ttl, txts, txt_ttl, rdata_cls=A
            )

        if qtype == QTYPE.AAAA:
            with self._lock:
                addrs = list(self._forward_v6.get(name, []))
                ttl = int(self._ttl_v6.get(name, default_ttl))
                txts = list(self._aggregate_txt.get(name, []))
                txt_ttl = int(self._ttl_txt.get(name, default_ttl))
            if not addrs and not txts:
                return None
            return self._build_address_reply(
                req, qname, QTYPE.AAAA, addrs, ttl, txts, txt_ttl, rdata_cls=AAAA
            )

        if qtype == QTYPE.TXT:
            with self._lock:
                txts = list(self._aggregate_txt.get(name, []))
                txt_ttl = int(self._ttl_txt.get(name, default_ttl))
                a_addrs = list(self._forward_v4.get(name, []))
                a_ttl = int(self._ttl_v4.get(name, default_ttl))
                aaaa_addrs = list(self._forward_v6.get(name, []))
                aaaa_ttl = int(self._ttl_v6.get(name, default_ttl))
            if not txts and not a_addrs and not aaaa_addrs:
                return None
            request = parse_dns_request(
                req,
                log=logger,
                log_message="parse failure for TXT %s: %s",
                log_args=(qname,),
            )
            if request is None:
                return None
            reply = authoritative_reply(request)
            for line in txts:
                reply.add_answer(
                    rr_txt(request.q.qname, [str(line)], txt_ttl, sanitize=True)
                )
            for ipaddr in a_addrs:
                reply.add_answer(rr_a(request.q.qname, ipaddr, a_ttl))
            for ipaddr in aaaa_addrs:
                reply.add_answer(rr_aaaa(request.q.qname, ipaddr, aaaa_ttl))
            return PluginDecision(action="override", response=reply.pack())

        if qtype == QTYPE.PTR:
            with self._lock:
                hostname = self._reverse.get(name)
                ttl = int(self._ttl_ptr.get(name, default_ttl))
            if not hostname:
                return None
            wire = make_ptr_response(req, str(hostname), ttl, qname=qname, log=logger)
            if wire is None:
                return None
            return PluginDecision(action="override", response=wire)

        return None


def add_forward_records(
    *,
    names: Iterable[str],
    ips: Iterable[str],
    ttl: int,
    use_v4: bool = True,
    use_v6: bool = True,
    canonical: str | None = None,
    txt_lines: list[str] | None = None,
    source: str | None = None,
    forward_v4: dict[str, list[str]],
    forward_v6: dict[str, list[str]],
    ttl_v4: dict[str, int],
    ttl_v6: dict[str, int],
    reverse: dict[str, str],
    ttl_ptr: dict[str, int],
    aggregate_txt: dict[str, list[str]] | None = None,
    ttl_txt: dict[str, int] | None = None,
    entry_sources: dict[str, str] | None = None,
) -> None:
    """Brief: Insert hostname forward/reverse/TXT mappings for one resource.

    Inputs:
      - names: Hostnames to publish (already suffix-qualified as needed).
      - ips: Address strings.
      - ttl / use_v4 / use_v6: DNS policy.
      - canonical: Optional PTR target; defaults to first published name.
      - txt_lines / source: Optional metadata.
      - map dicts: Mutable accumulators.

    Outputs:
      - None (mutates accumulators).
    """

    import ipaddress

    clean_ips: list[tuple[str, str]] = []
    for raw in ips:
        try:
            obj = ipaddress.ip_address(str(raw).strip())
        except Exception:
            continue
        fam = "v6" if obj.version == 6 else "v4"
        if fam == "v4" and not use_v4:
            continue
        if fam == "v6" and not use_v6:
            continue
        clean_ips.append((fam, str(obj)))
    if not clean_ips:
        return

    published: list[str] = []
    for name in names:
        host = normalize_name(name)
        if not host:
            continue
        if host not in published:
            published.append(host)

    if not published:
        return

    ptr_target = normalize_name(canonical) if canonical else published[0]

    for host in published:
        for fam, ip in clean_ips:
            bucket = forward_v4 if fam == "v4" else forward_v6
            ttl_map = ttl_v4 if fam == "v4" else ttl_v6
            lst = bucket.setdefault(host, [])
            if ip not in lst:
                lst.append(ip)
            ttl_map[host] = int(ttl)
        if entry_sources is not None and source:
            entry_sources[host] = source
        if txt_lines and aggregate_txt is not None and ttl_txt is not None:
            existing = aggregate_txt.setdefault(host, [])
            for line in txt_lines:
                if line and line not in existing:
                    existing.append(line)
            ttl_txt[host] = int(ttl)

    for _fam, ip in clean_ips:
        try:
            rev = ipaddress.ip_address(ip).reverse_pointer.lower()
        except Exception:
            continue
        reverse.setdefault(rev, ptr_target)
        ttl_ptr[rev] = int(ttl)


class _SNIAdapter(HTTPAdapter):
    """HTTPAdapter that forces a TLS server_hostname (SNI / cert name)."""

    def __init__(self, server_hostname: str | None = None, **kwargs: Any) -> None:
        """Brief: Create adapter with optional SNI override.

        Inputs:
          - server_hostname: Hostname sent in SNI and used for cert matching.
          - kwargs: Passed to HTTPAdapter.

        Outputs:
          - None.
        """

        self._server_hostname = (
            str(server_hostname).strip() if server_hostname else None
        )
        super().__init__(**kwargs)

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        """Brief: Initialize urllib3 pool with server_hostname when set.

        Inputs:
          - connections / maxsize / block: Pool sizing flags.
          - pool_kwargs: Extra urllib3 pool kwargs.

        Outputs:
          - None.
        """

        if self._server_hostname:
            pool_kwargs["server_hostname"] = self._server_hostname
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


def suppress_insecure_request_warnings() -> None:
    """Brief: Globally silence urllib3 InsecureRequestWarning (idempotent).

    Inputs:
      - None.

    Outputs:
      - None.

    Notes:
      - Uses both urllib3.disable_warnings and warnings filters so the noise is
        suppressed even when logging.captureWarnings(True) is enabled.
    """

    global _INSECURE_WARNING_FILTER_INSTALLED
    with _INSECURE_TLS_LOCK:
        if _INSECURE_WARNING_FILTER_INSTALLED:
            return
        try:
            import urllib3
            from urllib3.exceptions import InsecureRequestWarning

            urllib3.disable_warnings(InsecureRequestWarning)
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            warnings.filterwarnings(
                "ignore",
                message=r"Unverified HTTPS request is being made.*",
            )
        except Exception:
            # urllib3 may be absent in minimal installs; nothing to suppress.
            pass
        _INSECURE_WARNING_FILTER_INSTALLED = True


def note_insecure_tls(
    target: str,
    *,
    log: logging.Logger | None = None,
) -> None:
    """Brief: Suppress InsecureRequestWarning flood; log one notice per target.

    Inputs:
      - target: Host/URL label for the one-shot warning message.
      - log: Optional logger (defaults to hosts_common logger).

    Outputs:
      - None.

    Example:
      note_insecure_tls("https://pve.lan:8006", log=logger)
    """

    suppress_insecure_request_warnings()
    host = str(target or "").strip().rstrip("/") or "unknown"
    with _INSECURE_TLS_LOCK:
        already = host in _INSECURE_TLS_NOTICES
        if not already:
            _INSECURE_TLS_NOTICES.add(host)
    if already:
        return
    (log or logger).warning("TLS verify disabled for %s", host)


def get_sni_session(server_hostname: str | None) -> requests.Session:
    """Brief: Create a requests.Session with SNI support if requested.

    Inputs:
      - server_hostname: Hostname sent in SNI and used for cert matching.

    Outputs:
      - requests.Session with optional SNI adapter.
    """

    session = requests.Session()
    if server_hostname:
        adapter = _SNIAdapter(server_hostname=str(server_hostname))
        session.mount("https://", adapter)
    return session
