"""Shared helpers for dynamic inventory hosts plugins (Docker/Proxmox/K8s).

Brief:
  - Pure helpers for TXT sanitize, TLS path resolve, DNS labels, map merge.
  - DynamicHostsPlugin base: sticky condition logs, host maps, reload loop,
    shutdown, and shared A/AAAA/PTR/TXT pre_resolve answering.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections.abc import Iterable
from typing import Any, ClassVar

from dnslib import AAAA, PTR, QTYPE, RR, TXT, A, DNSHeader, DNSRecord

from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision
from foghorn.utils.dns_names import normalize_name, qualify_name
from foghorn.utils.ip_networks import parse_ip, parse_network

logger = logging.getLogger(__name__)

_DNS_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


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
        kept when every label is valid; otherwise the first valid label, or "".
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

    Provides sticky condition logging, in-memory host maps, background reload
    loop, shutdown signaling, and shared A/AAAA/PTR/TXT pre_resolve answers.
    Subclasses implement `_reload_maps()` and call `_init_dynamic_hosts_state()`
    from setup().
    """

    setup_provides_dns: ClassVar[bool] = True
    setup_requires_dns: ClassVar[bool] = True
    _condition_rewarn_interval_seconds: ClassVar[float] = 3600.0

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
        self._init_condition_logging()

    def _init_condition_logging(self) -> None:
        """Brief: Initialize sticky condition-log lock and maps.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        self._condition_log_lock = threading.Lock()
        self._condition_failed_by_key: dict[str, bool] = {}
        self._condition_suppressed_by_key: dict[str, int] = {}
        self._condition_last_warned_by_key: dict[str, float] = {}
        if not hasattr(self, "_condition_rewarn_interval_seconds"):
            self._condition_rewarn_interval_seconds = 3600.0

    def _ensure_condition_log_state(self) -> None:
        """Brief: Lazily initialize sticky condition-log lock and maps.

        Inputs:
          - None.

        Outputs:
          - None; creates lock/maps when setup() has not run yet (tests).
        """

        if not hasattr(self, "_condition_log_lock") or self._condition_log_lock is None:
            self._condition_log_lock = threading.Lock()
        if (
            not hasattr(self, "_condition_failed_by_key")
            or self._condition_failed_by_key is None
        ):
            self._condition_failed_by_key = {}
        if (
            not hasattr(self, "_condition_suppressed_by_key")
            or self._condition_suppressed_by_key is None
        ):
            self._condition_suppressed_by_key = {}
        if (
            not hasattr(self, "_condition_last_warned_by_key")
            or self._condition_last_warned_by_key is None
        ):
            self._condition_last_warned_by_key = {}
        if not hasattr(self, "_condition_rewarn_interval_seconds"):
            self._condition_rewarn_interval_seconds = 3600.0

    def _note_condition_failure(self, key: str, message: str, *args: object) -> None:
        """Brief: Log sticky-condition failures without flooding reload loops.

        Inputs:
          - key: Stable identifier for the condition.
          - message: Log message template for logger.warning().
          - args: Optional %-format arguments for message.

        Outputs:
          - None.
        """

        self._ensure_condition_log_state()
        now = time.monotonic()
        interval = float(getattr(self, "_condition_rewarn_interval_seconds", 3600.0))
        with self._condition_log_lock:
            prev_failed = bool(self._condition_failed_by_key.get(key, False))
            last_warned = self._condition_last_warned_by_key.get(key)
            if prev_failed:
                should_rewarn = interval > 0 and (
                    last_warned is None or (now - last_warned) >= interval
                )
                if should_rewarn:
                    suppressed = self._condition_suppressed_by_key.get(key, 0)
                    self._condition_suppressed_by_key[key] = 0
                    self._condition_last_warned_by_key[key] = now
                else:
                    self._condition_suppressed_by_key[key] = (
                        self._condition_suppressed_by_key.get(key, 0) + 1
                    )
                    suppressed = self._condition_suppressed_by_key[key]
            else:
                self._condition_failed_by_key[key] = True
                self._condition_suppressed_by_key[key] = 0
                self._condition_last_warned_by_key[key] = now
                suppressed = 0
                should_rewarn = False

        log = logging.getLogger(type(self).__module__)
        if not prev_failed:
            log.warning(message, *args)
            return

        if should_rewarn:
            if suppressed > 0:
                log.warning(
                    message + " (still failing; suppressed %d repeated warning(s))",
                    *args,
                    suppressed,
                )
            else:
                log.warning(message + " (still failing)", *args)
            return

        log.debug(
            "suppressed repeated condition %s (count=%d): " + message,
            key,
            suppressed,
            *args,
        )

    def _note_condition_ok(
        self,
        key: str,
        recovery_message: str | None = None,
        *args: object,
    ) -> None:
        """Brief: Clear a sticky failure condition and log recovery once.

        Inputs:
          - key: Same identifier passed to _note_condition_failure().
          - recovery_message: Optional logger.info() template.
          - args: Optional %-format arguments for recovery_message.

        Outputs:
          - None.
        """

        self._ensure_condition_log_state()
        with self._condition_log_lock:
            was_failed = bool(self._condition_failed_by_key.get(key, False))
            suppressed = int(self._condition_suppressed_by_key.get(key, 0) or 0)
            self._condition_failed_by_key[key] = False
            self._condition_suppressed_by_key[key] = 0
            self._condition_last_warned_by_key.pop(key, None)

        if not was_failed or not recovery_message:
            return

        log = logging.getLogger(type(self).__module__)
        if suppressed > 0:
            log.info(
                recovery_message + " (suppressed %d repeated failure warning(s))",
                *args,
                suppressed,
            )
            return

        if args:
            log.info(recovery_message, *args)
        else:
            log.info("%s", recovery_message)

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
                self._note_condition_ok(
                    "periodic-reload-error",
                    "periodic reload recovered",
                )
            except Exception as exc:  # pragma: nocover defensive
                self._note_condition_failure(
                    "periodic-reload-error",
                    "error during periodic reload; keeping previous mappings: %s",
                    exc,
                )

    def _shutdown_resources(self) -> None:
        """Brief: Subclass hook to close clients / temp files after stop signal.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        return None

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

        try:
            request = DNSRecord.parse(req)
        except Exception as exc:
            log = getattr(self, "logger", logger)
            log.warning(
                "parse failure building response for %s %s: %s",
                qname,
                QTYPE.get(qtype, str(qtype)),
                exc,
            )
            return None

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )
        if not addrs:
            return reply.pack()

        for ipaddr in addrs:
            if qtype == QTYPE.AAAA:
                rdata = AAAA(ipaddr)
                rtype = QTYPE.AAAA
            else:
                rdata = A(ipaddr)
                rtype = QTYPE.A
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=rtype,
                    rclass=1,
                    ttl=int(ttl),
                    rdata=rdata,
                )
            )
        return reply.pack()

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

        try:
            request = DNSRecord.parse(req)
        except Exception as exc:
            logger.warning(
                "parse failure for %s %s: %s",
                QTYPE.get(rtype, str(rtype)),
                qname,
                exc,
            )
            return None
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )
        for ipaddr in addrs:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=rtype,
                    rclass=1,
                    ttl=int(ttl),
                    rdata=rdata_cls(ipaddr),
                )
            )
        if getattr(self, "_expose_txt_in_additional", False):
            for line in txts:
                reply.add_ar(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.TXT,
                        rclass=1,
                        ttl=int(txt_ttl),
                        rdata=TXT([sanitize_txt_chunk(str(line))]),
                    )
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
            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("parse failure for TXT %s: %s", qname, exc)
                return None
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            for line in txts:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.TXT,
                        rclass=1,
                        ttl=txt_ttl,
                        rdata=TXT([sanitize_txt_chunk(str(line))]),
                    )
                )
            for ipaddr in a_addrs:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=a_ttl,
                        rdata=A(ipaddr),
                    )
                )
            for ipaddr in aaaa_addrs:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.AAAA,
                        rclass=1,
                        ttl=aaaa_ttl,
                        rdata=AAAA(ipaddr),
                    )
                )
            return PluginDecision(action="override", response=reply.pack())

        if qtype == QTYPE.PTR:
            with self._lock:
                hostname = self._reverse.get(name)
                ttl = int(self._ttl_ptr.get(name, default_ttl))
            if not hostname:
                return None
            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("parse failure for PTR %s: %s", qname, exc)
                return None
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.PTR,
                    rclass=1,
                    ttl=ttl,
                    rdata=PTR(ptr_owner(str(hostname))),
                )
            )
            return PluginDecision(action="override", response=reply.pack())

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
