"""Brief: Zone transfer export helpers for AXFR/IXFR.

Inputs/Outputs:
  - Export RRsets for zone transfers.
  - Build AXFR/IXFR message streams for TCP/DoT responders.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Iterable, Iterator, Optional
import dns.exception
import dns.message
import dns.tsig
import dns.tsigkeyring

from dnslib import QTYPE, RCODE, RR, DNSHeader, DNSRecord

from foghorn.utils.register_caches import registered_lru_cached

logger = logging.getLogger(__name__)
_AXFR_LIMIT_LOCK = threading.Lock()
_AXFR_ACTIVE_TRANSFERS = 0
_AXFR_CLIENT_RATE_STATE: dict[str, tuple[float, float]] = {}


def iter_zone_rrs_for_transfer(
    plugin: object,
    zone_apex: str,
    client_ip: Optional[str] = None,
) -> Optional[Iterable[RR]]:
    """Brief: Export authoritative RRsets for a zone for AXFR/IXFR.

    Inputs:
      - plugin: ZoneRecords plugin instance with records and zone state.
      - zone_apex: Zone apex name (with or without trailing dot), case-insensitive.
      - client_ip: Optional IP address of the AXFR/IXFR client.

    Outputs:
      - Iterable[RR]: RR stream in the zone suitable for AXFR/IXFR transfer, or
        None when this plugin is not authoritative for the requested apex.

    Notes:
      - The iterable is built from a snapshot of the plugin's name index.
        When plugin._records_lock is available, the snapshot is taken under that
        lock so mid-transfer reloads do not change the view.
      - DNSSEC-related RR types (for example, DNSKEY, RRSIG) are included when
        present in the zone data; AXFR-specific DNSSEC policy is intentionally
        out of scope for this helper.
    """
    from foghorn.utils import dns_names

    apex = dns_names.normalize_name(zone_apex) if zone_apex is not None else ""
    if not apex:
        return None

    lock = getattr(plugin, "_records_lock", None)
    if lock is None:
        name_index = dict(getattr(plugin, "_name_index", {}) or {})
        zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})
    else:
        with lock:
            name_index = dict(getattr(plugin, "_name_index", {}) or {})
            zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})

    if apex not in zone_soa:
        return None

    def _iter_snapshot() -> Iterator[RR]:
        for owner, rrsets in name_index.items():
            owner_norm = dns_names.normalize_name(owner)
            if owner_norm != apex and not owner_norm.endswith("." + apex):
                continue
            for qtype_code, entry in rrsets.items():
                ttl = entry[0]
                values = entry[1]
                rr_type_name = QTYPE.get(qtype_code, str(qtype_code))
                for value in values:
                    zone_line = f"{owner_norm}. {ttl} IN {rr_type_name} {value}"
                    try:
                        parsed = RR.fromZone(zone_line)
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "ZoneRecords transfer: skipping RR %r for %s type %s: %s",
                            value,
                            owner_norm,
                            rr_type_name,
                            exc,
                        )
                        continue
                    for rr in parsed:
                        yield rr

    return _iter_snapshot()


def _get_axfr_policy() -> dict:
    """Brief: Read AXFR policy knobs from RuntimeSnapshot.

    Inputs:
      - None.

    Outputs:
      - dict: AXFR policy fields with defensive defaults.
    """
    try:
        from foghorn.runtime_config import get_runtime_snapshot

        snap = get_runtime_snapshot()
        return {
            "enabled": bool(getattr(snap, "axfr_enabled", False)),
            "allow_clients": list(getattr(snap, "axfr_allow_clients", []) or []),
            "max_zone_rrs": getattr(snap, "axfr_max_zone_rrs", None),
            "max_concurrent_transfers": max(
                1, int(getattr(snap, "axfr_max_concurrent_transfers", 4) or 4)
            ),
            "rate_limit_per_client_per_second": max(
                0.0,
                float(
                    getattr(snap, "axfr_rate_limit_per_client_per_second", 0.0) or 0.0
                ),
            ),
            "rate_limit_burst": max(
                1.0, float(getattr(snap, "axfr_rate_limit_burst", 2.0) or 2.0)
            ),
            "max_transfer_rate_bytes_per_second": getattr(
                snap, "axfr_max_transfer_rate_bytes_per_second", None
            ),
            "message_max_bytes": max(
                512, min(65535, int(getattr(snap, "axfr_message_max_bytes", 64000)))
            ),
            "require_tsig": bool(getattr(snap, "axfr_require_tsig", False)),
            "tsig_keys": list(getattr(snap, "axfr_tsig_keys", []) or []),
            "plugins": list(getattr(snap, "plugins", []) or []),
        }
    except Exception:
        return {
            "enabled": False,
            "allow_clients": [],
            "max_zone_rrs": None,
            "max_concurrent_transfers": 4,
            "rate_limit_per_client_per_second": 0.0,
            "rate_limit_burst": 2.0,
            "max_transfer_rate_bytes_per_second": None,
            "message_max_bytes": 64000,
            "require_tsig": False,
            "tsig_keys": [],
            "plugins": [],
        }


def _normalize_tsig_algorithm(algorithm: str) -> str:
    """Brief: Normalize TSIG algorithm names to canonical short forms.

    Inputs:
      - algorithm: TSIG algorithm name from config.

    Outputs:
      - str: Canonical algorithm string used by dnspython.
    """
    alg = str(algorithm or "").strip().rstrip(".").lower()
    if "hmac-sha512" in alg:
        return "hmac-sha512"
    if "hmac-sha384" in alg:
        return "hmac-sha384"
    if "hmac-sha256" in alg:
        return "hmac-sha256"
    if "hmac-sha1" in alg:
        return "hmac-sha1"
    if "hmac-md5" in alg:
        return "hmac-md5"
    return alg or "hmac-sha256"


def _prepare_axfr_tsig_signer(
    req_wire: Optional[bytes],
    policy: dict,
) -> tuple[Optional[dict], Optional[str]]:
    """Brief: Verify AXFR request TSIG and build signer context when needed.

    Inputs:
      - req_wire: Raw query wire bytes.
      - policy: AXFR policy mapping.

    Outputs:
      - (signer, error): Signer context dict on success, or an error message.
    """
    require_tsig = bool(policy.get("require_tsig", False))
    raw_keys = list(policy.get("tsig_keys", []) or [])
    if not require_tsig and not raw_keys:
        return None, None

    if not req_wire:
        if require_tsig:
            return None, "missing AXFR request wire for TSIG verification"
        return None, None

    usable_keys = []
    text_keyring = {}
    for key in raw_keys:
        if not isinstance(key, dict):
            continue
        name = key.get("name")
        secret = key.get("secret")
        if not name or not secret:
            continue
        algorithm = _normalize_tsig_algorithm(key.get("algorithm", "hmac-sha256"))
        usable_keys.append(
            {
                "name": str(name),
                "secret": str(secret),
                "algorithm": algorithm,
            }
        )
        text_keyring[str(name)] = str(secret)

    if not text_keyring:
        if require_tsig:
            return (
                None,
                "AXFR TSIG required but no usable server.axfr.tsig_keys configured",
            )
        return None, None

    try:
        keyring = dns.tsigkeyring.from_text(text_keyring)
    except Exception as exc:
        return None, f"failed to build AXFR TSIG keyring: {exc}"

    try:
        request = dns.message.from_wire(bytes(req_wire), keyring=keyring)
    except dns.tsig.PeerBadKey as exc:
        return None, f"unknown TSIG key: {exc}"
    except dns.tsig.BadSignature:
        return None, "TSIG signature verification failed"
    except dns.tsig.PeerBadTime:
        return None, "TSIG time verification failed"
    except dns.exception.DNSException as exc:
        return None, f"TSIG verification error: {exc}"
    except Exception as exc:
        return None, f"TSIG verification error: {exc}"

    had_tsig = bool(getattr(request, "had_tsig", False))
    if not had_tsig:
        if require_tsig:
            return None, "TSIG required but missing on AXFR/IXFR request"
        return None, None

    keyname = str(getattr(request, "keyname", ""))
    keyalgorithm = _normalize_tsig_algorithm(getattr(request, "keyalgorithm", ""))
    selected = None
    for key in usable_keys:
        if str(key.get("name", "")).rstrip(".").lower() != keyname.rstrip(".").lower():
            continue
        if _normalize_tsig_algorithm(key.get("algorithm", "")) != keyalgorithm:
            continue
        selected = key
        break

    if selected is None:
        return None, "TSIG key or algorithm not configured for AXFR"

    return (
        {
            "keyring": keyring,
            "keyname": selected["name"],
            "algorithm": selected["algorithm"],
            "request_mac": bytes(getattr(request, "mac", b"") or b""),
            "tsig_ctx": None,
        },
        None,
    )


def _maybe_sign_axfr_wire(wire: bytes, req: DNSRecord, signer: Optional[dict]) -> bytes:
    """Brief: TSIG-sign a packed AXFR response message when signer is provided.

    Inputs:
      - wire: Packed DNS response bytes produced by dnslib.
      - req: Original AXFR/IXFR request.
      - signer: Optional signer context from _prepare_axfr_tsig_signer().

    Outputs:
      - bytes: Original wire or TSIG-signed wire.
    """
    if not signer:
        return wire
    msg = dns.message.from_wire(bytes(wire))
    msg.use_tsig(
        keyring=signer["keyring"],
        keyname=signer["keyname"],
        algorithm=signer["algorithm"],
        original_id=int(req.header.id),
    )
    msg.request_mac = signer.get("request_mac", b"")
    signed_wire = msg.to_wire(multi=True, tsig_ctx=signer.get("tsig_ctx"))
    signer["tsig_ctx"] = msg.tsig_ctx
    return signed_wire


@registered_lru_cached(maxsize=256)
def _compiled_allowlist_networks(cidr_values: tuple[str, ...]) -> tuple:
    """Brief: Compile allowlist CIDRs into parsed network objects.

    Inputs:
      - cidr_values: Tuple of CIDR strings.

    Outputs:
      - tuple: Parsed network objects for membership checks.
    """
    from foghorn.utils import ip_networks

    parsed = []
    for cidr in cidr_values:
        net = ip_networks.parse_network(cidr, strict=False)
        if net is not None:
            parsed.append(net)
    return tuple(parsed)


def _client_allowed_for_axfr(client_ip: str | None) -> bool:
    """Brief: Check whether a client is allowed to perform AXFR/IXFR.

    Inputs:
      - client_ip: Source IP address string.

    Outputs:
      - bool: True when AXFR is enabled and the client matches allowlist.

    Notes:
      - Policy is controlled via runtime snapshot values axfr_enabled and
        axfr_allow_clients.
      - Empty or missing allowlist denies all transfers when enabled.
    """
    policy = _get_axfr_policy()
    if not bool(policy.get("enabled", False)):
        return False
    if not client_ip:
        return False
    allow_raw = list(policy.get("allow_clients", []) or [])
    if not allow_raw:
        return False

    from foghorn.utils import ip_networks

    ip_text = str(client_ip).strip()
    ip_obj = ip_networks.parse_ip(ip_text)
    if ip_obj is None:
        logger.debug("AXFR denied: malformed client_ip=%r", client_ip)
        return False
    networks = _compiled_allowlist_networks(tuple(str(x) for x in allow_raw))
    if not networks:
        return False
    return ip_networks.ip_in_any_network(ip_obj, networks)


def _soa_identity(rr: RR) -> tuple[str, str]:
    """Brief: Build a stable identity tuple for SOA comparison.

    Inputs:
      - rr: SOA RR object.

    Outputs:
      - tuple[str, str]: Normalized owner and RDATA text.
    """
    from foghorn.utils import dns_names

    return (dns_names.normalize_name(rr.rname), str(rr.rdata))


def _axfr_rate_limited(client_ip: str | None, policy: dict) -> bool:
    """Brief: Apply per-client token-bucket rate limiting for AXFR starts.

    Inputs:
      - client_ip: Source client IP string.
      - policy: AXFR policy mapping.

    Outputs:
      - bool: True when request should be refused due to rate limiting.
    """
    rate = float(policy.get("rate_limit_per_client_per_second", 0.0) or 0.0)
    burst = float(policy.get("rate_limit_burst", 1.0) or 1.0)
    if rate <= 0.0:
        return False
    if not client_ip:
        return True
    key = str(client_ip).strip()
    if not key:
        return True
    now = time.monotonic()
    with _AXFR_LIMIT_LOCK:
        last_ts, tokens = _AXFR_CLIENT_RATE_STATE.get(key, (now, burst))
        elapsed = max(0.0, now - float(last_ts))
        tokens = min(burst, float(tokens) + elapsed * rate)
        if tokens < 1.0:
            _AXFR_CLIENT_RATE_STATE[key] = (now, tokens)
            return True
        _AXFR_CLIENT_RATE_STATE[key] = (now, tokens - 1.0)
        return False


def _axfr_try_acquire_slot(policy: dict) -> bool:
    """Brief: Try to reserve one global concurrent AXFR transfer slot.

    Inputs:
      - policy: AXFR policy mapping.

    Outputs:
      - bool: True when a slot was acquired.
    """
    global _AXFR_ACTIVE_TRANSFERS
    max_transfers = max(1, int(policy.get("max_concurrent_transfers", 4) or 4))
    with _AXFR_LIMIT_LOCK:
        if _AXFR_ACTIVE_TRANSFERS >= max_transfers:
            return False
        _AXFR_ACTIVE_TRANSFERS += 1
        return True


def _axfr_release_slot() -> None:
    """Brief: Release one global concurrent AXFR transfer slot.

    Inputs:
      - None.

    Outputs:
      - None.
    """
    global _AXFR_ACTIVE_TRANSFERS
    with _AXFR_LIMIT_LOCK:
        _AXFR_ACTIVE_TRANSFERS = max(0, int(_AXFR_ACTIVE_TRANSFERS) - 1)


def iter_axfr_messages(
    req: DNSRecord,
    client_ip: str | None = None,
    req_wire: Optional[bytes] = None,
) -> Iterable[bytes]:
    """Brief: Build AXFR/IXFR response message sequence for an authoritative zone.

    Inputs:
      - req: Parsed DNSRecord representing the client's AXFR or IXFR query.
      - client_ip: Optional source IP address of the AXFR/IXFR client.
      - req_wire: Optional raw query wire bytes for TSIG verification.

    Outputs:
      - Iterable[bytes]: Packed DNS response messages to stream over TCP/DoT.
        When transfer is refused, yields a single REFUSED response.

    Notes:
      - This helper relies on resolve plugins advertising an
        iter_zone_rrs_for_transfer(zone_apex, client_ip=None) method. The first
        such plugin that claims authority for the requested apex is used.
      - IXFR is currently implemented as a full AXFR-style transfer; the
        question section retains QTYPE=IXFR but the answer stream is a full
        zone dump bounded by matching SOA records.
    """

    def _refused_wire(signer: Optional[dict] = None) -> bytes:
        r = req.reply()
        r.header.rcode = RCODE.REFUSED
        return _maybe_sign_axfr_wire(r.pack(), req, signer)

    try:
        if not getattr(req, "questions", None):
            raise ValueError("AXFR/IXFR query has no questions")
        q = req.questions[0]
        from foghorn.utils import dns_names

        zone_apex = dns_names.normalize_name(q.qname)
    except Exception as exc:  # pragma: no cover - defensive parsing
        logger.warning("iter_axfr_messages: malformed query: %s", exc)
        yield _refused_wire()
        return

    policy = _get_axfr_policy()
    tsig_signer, tsig_error = _prepare_axfr_tsig_signer(req_wire, policy)
    if tsig_error:
        logger.info(
            "AXFR refused: TSIG verification failed client=%s zone=%s error=%s",
            client_ip,
            zone_apex,
            tsig_error,
        )
        yield _refused_wire(tsig_signer)
        return
    if not _client_allowed_for_axfr(client_ip):
        logger.info(
            "AXFR refused: unauthorized client=%s zone=%s",
            client_ip,
            zone_apex,
        )
        yield _refused_wire(tsig_signer)
        return
    if _axfr_rate_limited(client_ip, policy):
        logger.info(
            "AXFR refused: rate-limited client=%s zone=%s",
            client_ip,
            zone_apex,
        )
        yield _refused_wire(tsig_signer)
        return
    if not _axfr_try_acquire_slot(policy):
        logger.info(
            "AXFR refused: max concurrent transfers reached client=%s zone=%s",
            client_ip,
            zone_apex,
        )
        yield _refused_wire(tsig_signer)
        return

    started_at = time.perf_counter()
    transferred_rr_count = 0
    transferred_message_count = 0
    transferred_bytes = 0
    try:
        plugins = list(policy.get("plugins", []) or [])
        selected_plugin = None
        selected_exporter = None
        for plugin in plugins:
            exporter = getattr(plugin, "iter_zone_rrs_for_transfer", None)
            if not callable(exporter):
                continue
            try:
                try:
                    probe_exported = exporter(zone_apex, client_ip)
                except TypeError:
                    probe_exported = exporter(zone_apex)
            except Exception as exc:
                logger.warning(
                    "iter_axfr_messages: plugin %r export failure for %s: %s",
                    plugin,
                    zone_apex,
                    exc,
                )
                continue
            if probe_exported is None:
                continue
            probe_iter = iter(probe_exported)
            try:
                next(probe_iter)
            except StopIteration:
                continue
            except Exception as exc:
                logger.warning(
                    "iter_axfr_messages: plugin %r export failure for %s: %s",
                    plugin,
                    zone_apex,
                    exc,
                )
                continue
            selected_plugin = plugin
            selected_exporter = exporter
            break

        if selected_exporter is None:
            logger.info(
                "AXFR refused: no transfer-capable plugin for zone=%s", zone_apex
            )
            yield _refused_wire(tsig_signer)
            return

        def _iter_zone_rrs() -> Iterator[RR]:
            assert selected_exporter is not None
            try:
                try:
                    exported = selected_exporter(zone_apex, client_ip)
                except TypeError:
                    exported = selected_exporter(zone_apex)
            except Exception as exc:
                logger.warning(
                    "iter_axfr_messages: plugin %r export failure for %s: %s",
                    selected_plugin,
                    zone_apex,
                    exc,
                )
                return
            if exported is None:
                return
            for rr in exported:
                if rr is not None:
                    yield rr

        from foghorn.utils import dns_names

        apex_owner = dns_names.normalize_name(zone_apex)
        max_zone_rrs_raw = policy.get("max_zone_rrs")
        max_zone_rrs = (
            int(max_zone_rrs_raw)
            if max_zone_rrs_raw is not None and int(max_zone_rrs_raw) > 0
            else None
        )

        primary_soa: RR | None = None
        first_pass_rr_count = 0
        for rr in _iter_zone_rrs():
            first_pass_rr_count += 1
            if max_zone_rrs is not None and first_pass_rr_count > max_zone_rrs:
                logger.warning(
                    "AXFR refused: zone=%s exceeds max_zone_rrs=%d",
                    zone_apex,
                    max_zone_rrs,
                )
                yield _refused_wire(tsig_signer)
                return
            owner_norm = dns_names.normalize_name(rr.rname)
            if (
                rr.rtype == QTYPE.SOA
                and owner_norm == apex_owner
                and primary_soa is None
            ):
                primary_soa = rr

        if primary_soa is None:
            logger.info("AXFR refused: missing apex SOA zone=%s", zone_apex)
            yield _refused_wire(tsig_signer)
            return

        primary_soa_id = _soa_identity(primary_soa)
        max_len = int(policy.get("message_max_bytes", 64000) or 64000)
        max_rate_bps_raw = policy.get("max_transfer_rate_bytes_per_second")
        max_rate_bps = (
            int(max_rate_bps_raw)
            if max_rate_bps_raw is not None and int(max_rate_bps_raw) > 0
            else None
        )
        current = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1), q=req.q)

        def _yield_message(wire: bytes) -> Iterator[bytes]:
            nonlocal transferred_message_count, transferred_bytes
            wire = _maybe_sign_axfr_wire(wire, req, tsig_signer)
            transferred_message_count += 1
            transferred_bytes += len(wire)
            if max_rate_bps is not None and max_rate_bps > 0:
                elapsed = max(0.001, time.perf_counter() - started_at)
                expected_elapsed = float(transferred_bytes) / float(max_rate_bps)
                if expected_elapsed > elapsed:
                    time.sleep(min(expected_elapsed - elapsed, 0.25))
            yield wire

        def _append_rr(rr: RR) -> Iterator[bytes]:
            current.add_answer(rr)
            try:
                packed = current.pack()
            except Exception as exc:
                logger.warning("iter_axfr_messages: pack failure: %s", exc)
                current.rr.pop()
                return
            if len(packed) > max_len and len(current.rr) > 1:
                last = current.rr.pop()
                try:
                    flush_wire = current.pack()
                except Exception as exc:
                    logger.warning("iter_axfr_messages: pack failure: %s", exc)
                    current.add_answer(last)
                    return
                yield from _yield_message(flush_wire)
                current.rr = []
                current.add_answer(last)

        transferred_rr_count += 1
        yield from _append_rr(primary_soa)
        skipped_primary = False
        for rr in _iter_zone_rrs():
            if not skipped_primary and rr.rtype == QTYPE.SOA:
                if _soa_identity(rr) == primary_soa_id:
                    from foghorn.utils import dns_names as _dns_names2

                    if _dns_names2.normalize_name(rr.rname) == apex_owner:
                        skipped_primary = True
                        continue
            transferred_rr_count += 1
            yield from _append_rr(rr)

        transferred_rr_count += 1
        yield from _append_rr(primary_soa)
        try:
            final_wire = current.pack()
        except Exception as exc:
            logger.warning("iter_axfr_messages: final pack failure: %s", exc)
            if transferred_message_count == 0:
                yield _refused_wire(tsig_signer)
            return
        yield from _yield_message(final_wire)
    finally:
        _axfr_release_slot()
        elapsed_ms = max(0.0, (time.perf_counter() - started_at) * 1000.0)
        logger.info(
            "AXFR transfer finished client=%s zone=%s rr_count=%d messages=%d bytes=%d duration_ms=%.1f",
            client_ip,
            zone_apex,
            transferred_rr_count,
            transferred_message_count,
            transferred_bytes,
            elapsed_ms,
        )
