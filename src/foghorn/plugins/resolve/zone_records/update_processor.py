"""Brief: DNS UPDATE message parsing and processing.

Inputs/Outputs:
  - Parse UPDATE message sections (Zone, Prerequisites, Update, Additional).
  - Verify TSIG credentials and apply allow/block filters.

Outputs:
  - The top-level entry point returns a wire-format DNS response (bytes).

Notes:
  - Full RFC 2136 prerequisite checks and update operations are scaffolded.
  - PSK authentication support is implemented but currently not used by
    process_update_message() (TSIG-only for now).
"""

from __future__ import annotations

import logging
import hashlib
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
from dnslib import DNSRecord, QTYPE, RR
from foghorn.utils.register_caches import registered_ttl_cache

logger = logging.getLogger(__name__)

# Timestamp skew fudge (in seconds). BIND and dnspython default to 300.
TSIG_TIMESTAMP_FUDGE = 300


@registered_ttl_cache(maxsize=4096, ttl=3600)
def _normalize_dns_name(name: str) -> str:
    """Brief: Normalize a DNS name for comparisons.

    Inputs:
      - name: DNS name, with or without trailing dot.

    Outputs:
      - Lowercased name without trailing dot.
    """
    from foghorn.utils import dns_names

    return dns_names.normalize_name(name)


@registered_ttl_cache(maxsize=1024, ttl=3600)
def _normalize_tsig_algorithm(alg: str) -> str:
    """Brief: Normalize a TSIG algorithm name.

    Inputs:
      - alg: TSIG algorithm text (e.g. 'hmac-sha256.', 'hmac-md5.sig-alg.reg.int.').

    Outputs:
      - Normalized algorithm identifier (e.g. 'hmac-sha256', 'hmac-md5').
    """
    a = str(alg).rstrip(".").lower()
    if "hmac-sha512" in a:
        return "hmac-sha512"
    if "hmac-sha384" in a:
        return "hmac-sha384"
    if "hmac-sha256" in a:
        return "hmac-sha256"
    if "hmac-sha1" in a:
        return "hmac-sha1"
    if "hmac-md5" in a:
        return "hmac-md5"
    return a


def verify_tsig_auth(
    request_data: bytes,
    key_configs: List[dict],
) -> Tuple[bool, Optional[str], Optional[dict]]:
    """Brief: Verify TSIG authentication (RFC 2845) using shared tsig_utils.

    Inputs:
      - request_data: Raw DNS message bytes.
      - key_configs: List of configured TSIG keys.
        Each dict should include:
          * name: key name (DNS name)
          * algorithm: 'hmac-md5' | 'hmac-sha256' | 'hmac-sha512'
          * secret: base64-encoded secret

    Outputs:
      - (authorized, error_message, key_config)
        where key_config is the matching dict on success.

    Notes:
      - Delegates to foghorn.servers.tsig_utils.verify_request_tsig so QUERY,
        UPDATE, AXFR, and opcode paths share one implementation.
      - Enforces a maximum allowed TSIG fudge (300s) via TSIG_TIMESTAMP_FUDGE.
    """
    from foghorn.servers.tsig_utils import verify_request_tsig

    result = verify_request_tsig(
        request_data,
        key_configs,
        max_fudge_seconds=int(TSIG_TIMESTAMP_FUDGE),
    )
    if result.ok:
        return True, None, result.key_config
    return False, result.error_text or "TSIG verification failed", None


def verify_psk_auth(
    request_token: str,
    zone_config: dict,
    listener: Optional[str],
    token_configs: List[dict],
) -> Tuple[bool, Optional[str]]:
    """Brief: Verify PSK authentication.

    Inputs:
      - request_token: Token from request.
      - zone_config: Zone configuration.
      - listener: Listener type (dot/doh/udp/tcp).
      - token_configs: List of PSK token configurations.

    Outputs:
      - Tuple of (authorized, error_message).
    """
    # PSK only allowed on secure listeners (DoT/DoH)
    if listener and listener.lower() not in ("dot", "doh"):
        return False, "PSK authentication only allowed on DoT/DoH listeners"

    try:
        import bcrypt
    except ImportError:
        return False, "bcrypt module not available"

    # Find matching token configuration
    token_config = None
    for cfg in token_configs:
        if isinstance(cfg, dict):
            stored_token = cfg.get("token", "")
            if bcrypt.checkpw(
                request_token.encode("utf-8"), stored_token.encode("utf-8")
            ):
                token_config = cfg
                break

    if not token_config:
        return False, "Invalid PSK token"

    return True, None


class UpdateContext:
    """Brief: Context for DNS UPDATE processing.

    Contains zone info, auth results, and update operations.
    """

    def __init__(
        self,
        zone_apex: str,
        client_ip: str,
        listener: Optional[str],
        plugin: object,
    ):
        self.zone_apex = zone_apex
        self.client_ip = client_ip
        self.listener = listener
        self.plugin = plugin
        self.is_authorized = False
        self.auth_method: Optional[str] = None
        self.request_snapshot: Optional[Dict] = None
        self.tsig_key_config: Optional[dict] = None
        self.psk_token_config: Optional[dict] = None


def _clone_records_for_update_processing(
    records: Dict[Tuple[str, int], Tuple[int, List[str], List[str]]],
) -> Dict[Tuple[str, int], Tuple[int, List[str], List[str]]]:
    """Brief: Build an isolated, mutable clone of a records mapping.

    Inputs:
      - records: Mapping of (owner, qtype) -> (ttl, values[, sources]).

    Outputs:
      - Detached mapping with copied values/sources lists for safe mutation.
    """
    cloned: Dict[Tuple[str, int], Tuple[int, List[str], List[str]]] = {}
    for key, entry in (records or {}).items():
        try:
            owner, qtype = key
        except (TypeError, ValueError):
            continue

        try:
            ttl, values, sources = entry
        except (TypeError, ValueError):
            try:
                ttl, values = entry
                sources = []
            except (TypeError, ValueError):
                continue

        try:
            qtype_int = int(qtype)
            ttl_int = int(ttl)
        except (TypeError, ValueError):
            continue

        if isinstance(values, set):
            values_list = sorted((str(value) for value in values), key=str)
        elif isinstance(values, (list, tuple)):
            values_list = list(values)
        elif values is None:
            values_list = []
        else:
            values_list = [str(values)]

        if isinstance(sources, set):
            sources_list = sorted((str(source) for source in sources), key=str)
        elif isinstance(sources, (list, tuple)):
            sources_list = list(sources)
        elif sources is None:
            sources_list = []
        else:
            sources_list = [str(sources)]

        cloned[(str(owner), qtype_int)] = (ttl_int, values_list, sources_list)
    return cloned


def _prune_dns_update_rate_buckets(
    buckets: Dict[str, Dict[str, float | int]],
    now: float,
    *,
    window_seconds: float = 60.0,
) -> None:
    """Brief: Remove stale DNS UPDATE rate-limit token buckets.

    Inputs:
      - buckets: Mutable bucket map keyed by client/key identifier.
      - now: Current epoch seconds.
      - window_seconds: Active token-window duration.

    Outputs:
      - None. Mutates ``buckets`` in place by deleting stale entries.
    """
    stale_keys: List[str] = []
    for bucket_key, bucket_value in buckets.items():
        if not isinstance(bucket_value, dict):
            stale_keys.append(bucket_key)
            continue
        try:
            start = float(bucket_value.get("start", now))
        except (TypeError, ValueError):
            stale_keys.append(bucket_key)
            continue
        if now - start >= window_seconds:
            stale_keys.append(bucket_key)
    for stale_key in stale_keys:
        buckets.pop(stale_key, None)


def process_update_message(
    request_data: bytes,
    zone_apex: str,
    zone_config: dict,
    *,
    plugin: object,
    client_ip: str,
    listener: Optional[str] = None,
) -> bytes:
    """Brief: Process a DNS UPDATE message (RFC 2136).

    Inputs:
      - request_data: Wire-format UPDATE request.
      - zone_apex: Zone apex (no trailing dot preferred).
      - zone_config: Zone configuration dict for the specific apex.
      - plugin: ZoneRecords plugin instance.
      - client_ip: Client IP address string.
      - listener: Listener type (dot/doh/udp/tcp).

    Outputs:
      - Wire-format DNS response bytes.

    Notes:
      - Parsing is done with dnspython to support RFC 2136 messages which may
        contain empty RRs in prereq/update sections.
      - Applies configured validation/auth checks, prerequisite evaluation, and
        update operations, then returns an RFC-appropriate response code
        (typically NOERROR on success).
    """

    # 1) Parse the request using dnspython. If TSIG keys are configured, require
    # TSIG and verify signature.
    from foghorn.plugins.resolve.zone_records import update_helpers as uh

    source_loaders = getattr(plugin, "_dns_update_tsig_key_source_loaders", None)
    if not isinstance(source_loaders, dict):
        source_loaders = None
    key_configs = uh.resolve_tsig_key_configs(
        zone_config,
        source_loaders=source_loaders,
    )

    have_auth_config = bool(key_configs)

    # Build keyring mapping for dnspython.
    keyring_text: Dict[str, str] = {}
    for cfg in key_configs:
        if not isinstance(
            cfg, dict
        ):  # pragma: no cover - nocover: helper normalizes to dict configs
            continue
        name = cfg.get("name")
        secret = cfg.get("secret")
        if (
            not name or not secret
        ):  # pragma: no cover - nocover: invalid key entries filtered by helper
            continue
        keyring_text[str(name)] = str(secret)

    try:
        keyring = dns.tsigkeyring.from_text(keyring_text) if keyring_text else None
    except Exception:
        keyring = None

    request_msg: dns.message.Message | None = None
    tsig_parse_error: Optional[str] = None
    matching_tsig_cfg: Optional[dict] = None

    if keyring is not None:
        try:
            request_msg = dns.message.from_wire(request_data, keyring=keyring)
        except dns.message.UnknownTSIGKey:
            request_msg = None
            tsig_parse_error = "badkey"
        except dns.tsig.PeerBadKey:
            request_msg = None
            tsig_parse_error = "badkey"
        except dns.tsig.BadSignature:
            request_msg = None
            tsig_parse_error = "badsig"
        except dns.tsig.PeerBadTime:
            request_msg = None
            tsig_parse_error = "badtime"
        except dns.exception.DNSException:
            request_msg = None
            tsig_parse_error = "dns"
    else:
        # No keys configured; still parse so we can build a response.
        try:
            request_msg = dns.message.from_wire(request_data, ignore_trailing=True)
        except Exception:
            request_msg = None

    if request_msg is None:
        if tsig_parse_error is not None:
            try:
                configured_key_names = [
                    str(cfg.get("name", ""))
                    for cfg in key_configs
                    if isinstance(cfg, dict) and cfg.get("name")
                ]
            except (
                Exception
            ):  # pragma: no cover - nocover: defensive against malformed mapping objects
                configured_key_names = []
            logger.warning(
                "DNS UPDATE TSIG verification failed: reason=%s zone=%s configured_keys=%s client_ip=%s",
                tsig_parse_error,
                str(zone_apex),
                configured_key_names,
                str(client_ip),
            )
        # Try to recover enough structure (opcode/id/question) to return a
        # protocol-correct response even when TSIG verification fails.
        recovered_msg: Optional[dns.message.Message] = None
        try:
            recovered_msg = dns.message.from_wire(request_data, continue_on_error=True)
        except Exception:
            recovered_msg = None

        if recovered_msg is not None:
            resp = dns.message.make_response(recovered_msg)
            try:
                resp.set_opcode(recovered_msg.opcode())
            except (
                Exception
            ):  # pragma: no cover - nocover: defensive for malformed recovered opcode access
                pass
            if tsig_parse_error is not None:
                resp.set_rcode(dns.rcode.NOTAUTH)
            else:
                resp.set_rcode(dns.rcode.FORMERR)
            return resp.to_wire()

        # Worst-case fallback: cannot parse any structure from the request.
        try:
            import struct

            mid = (
                struct.unpack("!H", request_data[:2])[0]
                if len(request_data) >= 2
                else 0
            )
            flags = (
                struct.unpack("!H", request_data[2:4])[0]
                if len(request_data) >= 4
                else 0
            )
            opcode = int((flags >> 11) & 0xF)
        except (
            Exception
        ):  # pragma: no cover - nocover: requires severely malformed non-bytes request payload
            mid = 0
            opcode = int(dns.opcode.UPDATE)
        resp = dns.message.Message(id=int(mid))
        resp.flags |= dns.flags.QR
        try:
            resp.set_opcode(opcode)
        except (
            Exception
        ):  # pragma: no cover - nocover: defensive around malformed update rrset iteration
            pass
        if tsig_parse_error is not None:
            resp.set_rcode(dns.rcode.NOTAUTH)
        else:  # pragma: no cover - nocover: requires unrecoverable parse with no TSIG parse reason
            resp.set_rcode(dns.rcode.FORMERR)
        return resp.to_wire()

    # Enforce opcode=UPDATE.
    try:
        if int(request_msg.opcode()) != int(
            dns.opcode.UPDATE
        ):  # pragma: no cover - nocover: UPDATE entrypoint already filters opcode
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.FORMERR)
            return resp.to_wire()
    except Exception:
        resp = dns.message.make_response(request_msg)
        resp.set_rcode(dns.rcode.FORMERR)
        return resp.to_wire()

    # 2) Zone section validation: must contain exactly one SOA RR, and the owner
    # must match the configured zone apex.
    try:
        apex_norm = _normalize_dns_name(zone_apex)
    except (
        Exception
    ):  # pragma: no cover - nocover: defensive zone_apex normalization fallback
        apex_norm = ""

    # Zone section must contain exactly one SOA RRset for the zone apex. In
    # UPDATE messages the SOA RRset is often *empty* (no rdata); we validate the
    # owner name and type/class rather than requiring any rdatas.
    try:
        zone_rrsets = list(getattr(request_msg, "zone", []) or [])
    except (
        Exception
    ):  # pragma: no cover - nocover: defensive for message.zone accessor failures
        zone_rrsets = []

    zone_rrset = zone_rrsets[0] if len(zone_rrsets) == 1 else None
    if zone_rrset is None:
        resp = dns.message.make_response(request_msg)
        resp.set_rcode(dns.rcode.NOTZONE)
        if (
            getattr(request_msg, "had_tsig", False) and keyring is not None
        ):  # pragma: no cover - nocover: requires TSIG-signed malformed zone section
            try:
                resp.use_tsig(
                    keyring=keyring,
                    keyname=request_msg.keyname,
                    algorithm=request_msg.keyalgorithm,
                )
            except (
                Exception
            ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                pass
        return resp.to_wire()

    try:
        zone_owner_norm = _normalize_dns_name(getattr(zone_rrset, "name", ""))
    except (
        Exception
    ):  # pragma: no cover - nocover: defensive normalization of zone owner
        zone_owner_norm = ""

    try:
        zone_class = int(getattr(zone_rrset, "rdclass", 0) or 0)
    except Exception:
        zone_class = 0

    try:
        zone_type = int(getattr(zone_rrset, "rdtype", 0) or 0)
    except Exception:
        zone_type = 0

    if (
        zone_owner_norm != apex_norm
        or zone_class != int(dns.rdataclass.IN)
        or zone_type != int(dns.rdatatype.SOA)
    ):  # pragma: no cover - nocover: malformed zone-section shape is parser-dependent
        resp = dns.message.make_response(request_msg)
        resp.set_rcode(dns.rcode.NOTZONE)
        if getattr(request_msg, "had_tsig", False) and keyring is not None:
            try:
                resp.use_tsig(
                    keyring=keyring,
                    keyname=request_msg.keyname,
                    algorithm=request_msg.keyalgorithm,
                )
            except (
                Exception
            ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                pass
        return resp.to_wire()

    # 3) Authorization: client allowlist + TSIG requirement (TSIG-only for now).
    ctx = UpdateContext(
        zone_apex=apex_norm, client_ip=str(client_ip), listener=listener, plugin=plugin
    )

    # 3a) Replication role policy gate for UPDATE writes.
    try:
        dns_update_cfg = getattr(plugin, "_dns_update_config", None)
        replication_cfg = {}
        if isinstance(dns_update_cfg, dict):
            rcfg = dns_update_cfg.get("replication")
            if isinstance(rcfg, dict):
                replication_cfg = rcfg
        role = str(replication_cfg.get("role", "primary")).strip().lower()
        if role == "replica":
            reject_direct = bool(
                replication_cfg.get("reject_direct_update_on_replica", False)
            )
            if reject_direct:
                resp = dns.message.make_response(request_msg)
                resp.set_rcode(dns.rcode.REFUSED)
                return resp.to_wire()
            # Forward-to-owner mode is configured but explicit forwarding is
            # not yet wired in this path; fail closed for now.
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.REFUSED)
            return resp.to_wire()
    except (
        Exception
    ):  # pragma: no cover - nocover: defensive around plugin replication metadata shape
        pass

    ok, _err = verify_client_authorization(ctx, zone_config=zone_config)
    if not ok:
        resp = dns.message.make_response(request_msg)
        resp.set_rcode(dns.rcode.REFUSED)
        if getattr(request_msg, "had_tsig", False) and keyring is not None:
            try:
                resp.use_tsig(
                    keyring=keyring,
                    keyname=request_msg.keyname,
                    algorithm=request_msg.keyalgorithm,
                )
            except (
                Exception
            ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                pass
        return resp.to_wire()

    # Require TSIG when keys are configured; otherwise refuse as "not authorized".
    if have_auth_config:
        if not getattr(request_msg, "had_tsig", False):
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.NOTAUTH)
            return resp.to_wire()

        # Enforce configured algorithm mapping for this key.
        try:
            keyname_norm = _normalize_dns_name(getattr(request_msg, "keyname", ""))
            keyalg_norm = _normalize_tsig_algorithm(
                getattr(request_msg, "keyalgorithm", "")
            )
        except Exception:
            keyname_norm = ""
            keyalg_norm = ""

        for cfg in key_configs:
            if not isinstance(
                cfg, dict
            ):  # pragma: no cover - nocover: normalized TSIG key configs are dicts
                continue
            if (
                _normalize_dns_name(cfg.get("name", "")) != keyname_norm
            ):  # pragma: no cover - nocover: depends on mixed-key config ordering/shape
                continue
            expected_alg = _normalize_tsig_algorithm(
                cfg.get("algorithm", "hmac-sha256")
            )
            if expected_alg and expected_alg != keyalg_norm:
                resp = dns.message.make_response(request_msg)
                resp.set_rcode(dns.rcode.NOTAUTH)
                if getattr(request_msg, "had_tsig", False) and keyring is not None:
                    try:
                        resp.use_tsig(
                            keyring=keyring,
                            keyname=request_msg.keyname,
                            algorithm=request_msg.keyalgorithm,
                        )
                    except (
                        Exception
                    ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                        pass
                return resp.to_wire()
            matching_tsig_cfg = cfg
            break

        if matching_tsig_cfg is None:
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.NOTAUTH)
            if getattr(request_msg, "had_tsig", False) and keyring is not None:
                try:
                    resp.use_tsig(
                        keyring=keyring,
                        keyname=request_msg.keyname,
                        algorithm=request_msg.keyalgorithm,
                    )
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                    pass
            return resp.to_wire()

        # Enforce max fudge.
        try:
            tsig_rr = request_msg.tsig[0]
            fudge = int(getattr(tsig_rr, "fudge", 0) or 0)
        except (
            Exception
        ):  # pragma: no cover - nocover: defensive when TSIG list shape is malformed
            fudge = 0
        if fudge and fudge > TSIG_TIMESTAMP_FUDGE:
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.NOTAUTH)
            if getattr(request_msg, "had_tsig", False) and keyring is not None:
                try:
                    resp.use_tsig(
                        keyring=keyring,
                        keyname=request_msg.keyname,
                        algorithm=request_msg.keyalgorithm,
                    )
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                    pass
            return resp.to_wire()

        ctx.is_authorized = True
        ctx.auth_method = "tsig"
        ctx.tsig_key_config = matching_tsig_cfg
    else:
        # No auth configured for this zone: refuse to avoid accidental open updates.
        resp = dns.message.make_response(request_msg)
        resp.set_rcode(dns.rcode.NOTAUTH)
        return resp.to_wire()

    # 4) Process prerequisites and updates
    try:
        prereqs = list(getattr(request_msg, "prerequisite", []) or [])
        updates = list(getattr(request_msg, "update", []) or [])
    except (
        Exception
    ):  # pragma: no cover - nocover: defensive message object accessor path
        prereqs = []
        updates = []

    # 4a) Security limits and basic rate limiting.
    try:
        dns_update_cfg = getattr(plugin, "_dns_update_config", None)
        security_cfg = {}
        if isinstance(dns_update_cfg, dict):
            scfg = dns_update_cfg.get("security")
            if isinstance(scfg, dict):
                security_cfg = scfg

        max_updates_per_message = int(
            security_cfg.get("max_updates_per_message", 0) or 0
        )
        max_rr_values_per_rrset = int(
            security_cfg.get("max_rr_values_per_rrset", 0) or 0
        )
        max_owner_length = int(security_cfg.get("max_owner_length", 0) or 0)
        max_rdata_length = int(security_cfg.get("max_rdata_length", 0) or 0)
        max_ttl_range = int(security_cfg.get("max_ttl_range", 0) or 0)

        if max_updates_per_message > 0 and len(updates) > max_updates_per_message:
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.REFUSED)
            return resp.to_wire()

        for rrset in updates:
            owner_text = _normalize_dns_name(getattr(rrset, "name", ""))
            if max_owner_length > 0 and len(owner_text) > max_owner_length:
                resp = dns.message.make_response(request_msg)
                resp.set_rcode(dns.rcode.REFUSED)
                return resp.to_wire()
            ttl_val = int(getattr(rrset, "ttl", 0) or 0)
            if max_ttl_range > 0 and ttl_val > max_ttl_range:
                resp = dns.message.make_response(request_msg)
                resp.set_rcode(dns.rcode.REFUSED)
                return resp.to_wire()
            rr_values = [str(rdata) for rdata in rrset]
            if max_rr_values_per_rrset > 0 and len(rr_values) > max_rr_values_per_rrset:
                resp = dns.message.make_response(request_msg)
                resp.set_rcode(dns.rcode.REFUSED)
                return resp.to_wire()
            if max_rdata_length > 0:
                for value in rr_values:
                    if len(value) > max_rdata_length:
                        resp = dns.message.make_response(request_msg)
                        resp.set_rcode(dns.rcode.REFUSED)
                        return resp.to_wire()

        # Token bucket style (minute window) per-client and per-key.
        now = float(time.time())
        buckets = getattr(plugin, "_dns_update_rate_buckets", None)
        if not isinstance(buckets, dict):
            buckets = {}
            setattr(plugin, "_dns_update_rate_buckets", buckets)
        last_prune = getattr(plugin, "_dns_update_rate_buckets_last_prune", 0.0)
        try:
            last_prune_ts = float(last_prune)
        except (TypeError, ValueError):
            last_prune_ts = 0.0
        if now - last_prune_ts >= 60.0:
            _prune_dns_update_rate_buckets(buckets, now, window_seconds=60.0)
            setattr(plugin, "_dns_update_rate_buckets_last_prune", now)

        limit_client = int(security_cfg.get("rate_limit_per_client", 0) or 0)
        if limit_client > 0:
            key = f"client:{ctx.client_ip}"
            ts_count = buckets.get(key, {"start": now, "count": 0})
            start = float(ts_count.get("start", now))
            count = int(ts_count.get("count", 0))
            if now - start >= 60.0:
                start = now
                count = 0
            count += 1
            buckets[key] = {"start": start, "count": count}
            if count > limit_client:
                try:
                    plugin._dns_update_rate_limit_hits = int(
                        getattr(plugin, "_dns_update_rate_limit_hits", 0) + 1
                    )
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive metrics increment path
                    pass
                resp = dns.message.make_response(request_msg)
                resp.set_rcode(dns.rcode.REFUSED)
                return resp.to_wire()

        limit_key = int(security_cfg.get("rate_limit_per_key", 0) or 0)
        if limit_key > 0 and isinstance(ctx.tsig_key_config, dict):
            key_name = str(ctx.tsig_key_config.get("name", ""))
            if key_name:
                key = f"tsig:{key_name}"
                ts_count = buckets.get(key, {"start": now, "count": 0})
                start = float(ts_count.get("start", now))
                count = int(ts_count.get("count", 0))
                if now - start >= 60.0:
                    start = now
                    count = 0  # pragma: no cover - nocover: requires controlled multi-minute per-key rate window
                count += 1
                buckets[key] = {"start": start, "count": count}
                if count > limit_key:
                    try:
                        plugin._dns_update_rate_limit_hits = int(
                            getattr(plugin, "_dns_update_rate_limit_hits", 0) + 1
                        )
                    except (
                        Exception
                    ):  # pragma: no cover - nocover: defensive metrics increment path
                        pass
                    resp = dns.message.make_response(request_msg)
                    resp.set_rcode(dns.rcode.REFUSED)
                    return resp.to_wire()
    except Exception as exc:
        logger.warning(
            "DNS UPDATE security validation failed for zone=%s client=%s: %s",
            apex_norm,
            ctx.client_ip,
            exc,
            exc_info=True,
        )
        resp = dns.message.make_response(request_msg)
        resp.set_rcode(dns.rcode.REFUSED)
        if getattr(request_msg, "had_tsig", False) and keyring is not None:
            try:
                resp.use_tsig(
                    keyring=keyring,
                    keyname=request_msg.keyname,
                    algorithm=request_msg.keyalgorithm,
                )
            except (
                Exception
            ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                pass
        return resp.to_wire()

    # Get current records
    records_lock = getattr(plugin, "_records_lock", None)
    if records_lock is None:
        current_records = _clone_records_for_update_processing(
            getattr(plugin, "records", {}) or {}
        )
    else:
        with records_lock:
            current_records = _clone_records_for_update_processing(
                getattr(plugin, "records", {}) or {}
            )

    # Check prerequisites
    if prereqs:
        prereq_rcode, prereq_err = check_prerequisites(
            prereqs, current_records, apex_norm
        )
        if prereq_rcode != 0:
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(prereq_rcode)
            if getattr(request_msg, "had_tsig", False) and keyring is not None:
                try:
                    resp.use_tsig(
                        keyring=keyring,
                        keyname=request_msg.keyname,
                        algorithm=request_msg.keyalgorithm,
                    )
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                    pass
            return resp.to_wire()

    # Enforce auth scope from the authenticated principal (TSIG key or PSK token).
    auth_scope_config: Optional[dict] = None
    if isinstance(ctx.tsig_key_config, dict):
        auth_scope_config = ctx.tsig_key_config
    elif isinstance(ctx.psk_token_config, dict):
        auth_scope_config = ctx.psk_token_config
    auth_scope_cache_prefix: Optional[str] = None
    if isinstance(ctx.tsig_key_config, dict):
        key_name = _normalize_dns_name(ctx.tsig_key_config.get("name", ""))
        auth_scope_cache_prefix = f"{apex_norm}_tsig_{key_name or 'unnamed'}"
    elif isinstance(ctx.psk_token_config, dict):
        token = str(ctx.psk_token_config.get("token", ""))
        token_hash = (
            hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            if token
            else "anonymous"
        )
        auth_scope_cache_prefix = f"{apex_norm}_psk_{token_hash}"

    # Check name/value authorization for each update RRset
    for update_rrset in updates:
        # Get owner name from the RRset
        try:
            owner_norm = _normalize_dns_name(str(update_rrset.name))
        except Exception:
            owner_norm = ""

        if not verify_name_authorization(
            owner_norm,
            zone_config,
            auth_scope_config=auth_scope_config,
            plugin=plugin,
            zone_apex=apex_norm,
            auth_scope_cache_prefix=auth_scope_cache_prefix,
        ):
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.NOTAUTH)
            if getattr(request_msg, "had_tsig", False) and keyring is not None:
                try:
                    resp.use_tsig(
                        keyring=keyring,
                        keyname=request_msg.keyname,
                        algorithm=request_msg.keyalgorithm,
                    )
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                    pass
            return resp.to_wire()

        # For A/AAAA records, verify IP values (rrset contains rdata objects)
        try:
            qtype_int = int(getattr(update_rrset, "rdtype", 0))
            # Convert rdata to string for value authorization
            for rdata in update_rrset:
                rdata_str = str(rdata)
                if not verify_value_authorization(
                    rdata_str,
                    qtype_int,
                    zone_config,
                    auth_scope_config=auth_scope_config,
                    plugin=plugin,
                    zone_apex=apex_norm,
                    auth_scope_cache_prefix=auth_scope_cache_prefix,
                ):
                    resp = dns.message.make_response(request_msg)
                    resp.set_rcode(dns.rcode.NOTAUTH)
                    if getattr(request_msg, "had_tsig", False) and keyring is not None:
                        try:
                            resp.use_tsig(
                                keyring=keyring,
                                keyname=request_msg.keyname,
                                algorithm=request_msg.keyalgorithm,
                            )
                        except (
                            Exception
                        ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                            pass
                    return resp.to_wire()
        except (
            Exception
        ):  # pragma: no cover - nocover: defensive update RRset iteration/access failure path
            pass

    # Apply update operations
    if updates:
        # Prepare for journaling if persistence is configured
        journal_writer = None
        actor = None
        dns_update_cfg = getattr(plugin, "_dns_update_config", None)
        persistence_enabled = False
        if isinstance(dns_update_cfg, dict):
            persistence_enabled = dns_update_cfg.get("persistence", {}).get(
                "enabled", False
            )

        if persistence_enabled:
            from .journal import JournalWriter

            state_dir = dns_update_cfg.get("persistence", {}).get("state_dir")
            if state_dir is None:
                try:
                    from foghorn.runtime_config import get_runtime_state_dir

                    state_dir = get_runtime_state_dir()
                    if state_dir:
                        state_dir = os.path.join(state_dir, "zone_records")
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive runtime-state discovery failure
                    pass

            if state_dir:
                try:
                    journal_writer = JournalWriter(
                        zone_apex=apex_norm, base_dir=state_dir
                    )
                    if journal_writer.acquire_lock():
                        actor = {
                            "client_ip": str(ctx.client_ip),
                            "auth_method": (
                                ctx.auth_method or "tsig"
                                if ctx.is_authorized
                                else "none"
                            ),
                            "tsig_key_name": (
                                ctx.tsig_key_config.get("name")
                                if ctx.tsig_key_config
                                else None
                            ),
                        }
                    else:  # pragma: no cover - nocover: lock contention path is scheduler/environment dependent
                        try:
                            journal_writer.close()
                        except (
                            Exception
                        ):  # pragma: no cover - nocover: defensive close failure on lock-contention path
                            pass
                        journal_writer = None
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive journal initialization failure
                    journal_writer = None

        try:
            update_rcode, update_err = apply_update_operations(
                updates,
                plugin,
                apex_norm,
                journal_writer=journal_writer,
                actor=actor,
                require_journal_persistence=bool(persistence_enabled),
            )
        finally:
            if journal_writer is not None:
                try:
                    journal_writer.release_lock()
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive lock-release failure after update processing
                    pass
                try:
                    journal_writer.close()
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive close failure after update processing
                    pass
        if update_rcode != 0:
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(update_rcode)
            if getattr(request_msg, "had_tsig", False) and keyring is not None:
                try:
                    resp.use_tsig(
                        keyring=keyring,
                        keyname=request_msg.keyname,
                        algorithm=request_msg.keyalgorithm,
                    )
                except (
                    Exception
                ):  # pragma: no cover - nocover: defensive TSIG signing failure path
                    pass
            return resp.to_wire()

    # All checks passed, Return NOERROR
    resp = dns.message.make_response(request_msg)
    resp.set_rcode(dns.rcode.NOERROR)

    # Sign the response when the request was TSIG-verified.
    if getattr(request_msg, "had_tsig", False) and keyring is not None:
        try:
            resp.use_tsig(
                keyring=keyring,
                keyname=request_msg.keyname,
                algorithm=request_msg.keyalgorithm,
            )
        except (
            Exception
        ):  # pragma: no cover - nocover: defensive TSIG signing failure path
            pass

    return resp.to_wire()


def verify_client_authorization(
    ctx: UpdateContext,
    zone_config: dict,
) -> Tuple[bool, Optional[str]]:
    """Brief: Verify client IP authorization.

    Inputs:
      - ctx: UpdateContext.
      - zone_config: Zone configuration dict.

    Outputs:
      - Tuple of (authorized, error_message).
    """
    from foghorn.plugins.resolve.zone_records import update_helpers as uh
    from foghorn.utils import ip_networks

    allow_clients = zone_config.get("allow_clients", [])
    allow_clients_files = zone_config.get("allow_clients_files", [])

    if not allow_clients and not allow_clients_files:
        return True, None

    cache_key = f"{_normalize_dns_name(ctx.zone_apex)}_allow_clients"
    clients_list = uh.get_cached_combined_list(
        plugin=ctx.plugin,
        cache_key=cache_key,
        inline=allow_clients,
        files=allow_clients_files,
        loader_func=uh.load_cidr_list_from_file,
    )

    if not clients_list:
        return False, "allow_clients configured but resolved empty"

    if not ip_networks.ip_string_in_cidrs(ctx.client_ip, clients_list):
        return False, "Client IP not in allow_clients"

    return True, None


def verify_name_authorization(
    name: str,
    zone_config: dict,
    auth_scope_config: Optional[dict] = None,
    plugin: Optional[object] = None,
    zone_apex: Optional[str] = None,
    auth_scope_cache_prefix: Optional[str] = None,
) -> bool:
    """Brief: Verify name is allowed for updates.

    Inputs:
      - name: Domain name to update.
      - zone_config: Zone configuration.
      - auth_scope_config: Optional per-principal scope config (TSIG key or PSK token).
      - plugin: Optional ZoneRecords plugin instance for cached file-list resolution.
      - zone_apex: Optional zone apex used to namespace cache keys.
      - auth_scope_cache_prefix: Optional per-principal cache key prefix.

    Outputs:
      - bool: True if name is allowed.
    """
    from foghorn.plugins.resolve.zone_records import update_helpers as uh

    zone_prefix = f"{_normalize_dns_name(zone_apex)}_zone" if zone_apex else "zone"
    auth_prefix = auth_scope_cache_prefix or "auth_scope"
    scopes: List[Tuple[dict, str]] = []
    if isinstance(zone_config, dict):
        scopes.append((zone_config, zone_prefix))
    if isinstance(auth_scope_config, dict):
        scopes.append((auth_scope_config, auth_prefix))

    # Any matching block list from any scope denies the update.
    for scope, scope_prefix in scopes:
        blocked_list = uh.get_cached_combined_list(
            plugin=plugin,
            cache_key=f"{scope_prefix}_block_names",
            inline=scope.get("block_names", []),
            files=scope.get("block_names_files", []),
            loader_func=uh.load_names_list_from_file,
        )
        if blocked_list and uh.matches_name_pattern(name, blocked_list):
            return False

    # If a scope defines allow names, this name must match that scope.
    # Multiple allow scopes therefore behave as intersection.
    for scope, scope_prefix in scopes:
        allow_names = scope.get("allow_names", [])
        allow_names_files = scope.get("allow_names_files", [])
        if allow_names or allow_names_files:
            allowed_list = uh.get_cached_combined_list(
                plugin=plugin,
                cache_key=f"{scope_prefix}_allow_names",
                inline=allow_names,
                files=allow_names_files,
                loader_func=uh.load_names_list_from_file,
            )
            if not allowed_list:
                return False
            if not uh.matches_name_pattern(name, allowed_list):
                return False

    return True


def verify_value_authorization(
    value: str,
    qtype: int,
    zone_config: dict,
    auth_scope_config: Optional[dict] = None,
    plugin: Optional[object] = None,
    zone_apex: Optional[str] = None,
    auth_scope_cache_prefix: Optional[str] = None,
) -> bool:
    """Brief: Verify A/AAAA record value is allowed.

    Inputs:
      - value: IP address value.
      - qtype: Record type (A=1, AAAA=28).
      - zone_config: Zone configuration.
      - auth_scope_config: Optional per-principal scope config (TSIG key or PSK token).
      - plugin: Optional ZoneRecords plugin instance for cached file-list resolution.
      - zone_apex: Optional zone apex used to namespace cache keys.
      - auth_scope_cache_prefix: Optional per-principal cache key prefix.

    Outputs:
      - bool: True if value is allowed.
    """
    # Only validate A and AAAA records
    if qtype not in (QTYPE.A, QTYPE.AAAA):
        return True

    from foghorn.plugins.resolve.zone_records import update_helpers as uh
    from foghorn.utils import ip_networks

    zone_prefix = f"{_normalize_dns_name(zone_apex)}_zone" if zone_apex else "zone"
    auth_prefix = auth_scope_cache_prefix or "auth_scope"
    scopes: List[Tuple[dict, str]] = []
    if isinstance(zone_config, dict):
        scopes.append((zone_config, zone_prefix))
    if isinstance(auth_scope_config, dict):
        scopes.append((auth_scope_config, auth_prefix))

    # Any matching block list from any scope denies the update.
    for scope, scope_prefix in scopes:
        blocked_list = uh.get_cached_combined_list(
            plugin=plugin,
            cache_key=f"{scope_prefix}_block_update_ips",
            inline=scope.get("block_update_ips", []),
            files=scope.get("block_update_ips_files", []),
            loader_func=uh.load_cidr_list_from_file,
        )
        if blocked_list and ip_networks.ip_string_in_cidrs(value, blocked_list):
            return False

    # If a scope defines allow_update_ips, the value must match that scope.
    for scope, scope_prefix in scopes:
        allow_ips = scope.get("allow_update_ips", [])
        allow_ips_files = scope.get("allow_update_ips_files", [])
        if allow_ips or allow_ips_files:
            allowed_list = uh.get_cached_combined_list(
                plugin=plugin,
                cache_key=f"{scope_prefix}_allow_update_ips",
                inline=allow_ips,
                files=allow_ips_files,
                loader_func=uh.load_cidr_list_from_file,
            )
            if not allowed_list:
                return False
            if not ip_networks.ip_string_in_cidrs(value, allowed_list):
                return False

    return True


def parse_update_message(data: bytes) -> Optional[dns.message.Message]:
    """Brief: Parse an UPDATE-like DNS message using dnspython.

    Inputs:
      - data: Wire-format DNS message bytes.

    Outputs:
      - dnspython Message object, or None on parse error.

    Notes:
      - This uses dnspython (not dnslib) so that RFC 2136 UPDATE messages with
        empty RRs in prerequisite/update sections can be parsed.
    """
    try:
        return dns.message.from_wire(data, ignore_trailing=True)
    except Exception as exc:
        logger.warning("Failed to parse UPDATE message: %s", exc)
        return None


def check_prerequisites(
    prereqs: List[RR],
    records: Dict,
    zone_apex: str,
) -> Tuple[int, Optional[str]]:
    """Brief: Check prerequisite conditions per RFC 2136 Section 3.2.

    Inputs:
      - prereqs: Prerequisite RRs from dnspython Update.prerequisite.
      - records: Current zone records (name_index not needed for prereqs).
      - zone_apex: Zone apex.

    Outputs:
      - Tuple of (rcode, error_message). RCODE=0 (NOERROR) if all pass.

    Notes:
      - RFC 2136 prerequisite types:
        * CLASS=ANY, TYPE!=ANY: RRset existence or specific RR existence
        * CLASS=NONE, TYPE!=ANY: RRset nonexistence or name not in use
        * TYPE=ANY, CLASS=NONE: Name must exist (any RRset at name)
        * TYPE=ANY, CLASS=IN: Name must exist with at least one RRset
    """
    try:
        apex_norm = _normalize_dns_name(zone_apex)
    except Exception:
        apex_norm = ""

    for prereq_rrset in prereqs:
        try:
            owner_norm = _normalize_dns_name(str(prereq_rrset.name))
        except (
            Exception
        ):  # pragma: no cover - nocover: defensive malformed owner objects in prereq rrsets
            owner_norm = ""

        qtype_int = int(getattr(prereq_rrset, "rdtype", 0))
        qclass = int(getattr(prereq_rrset, "rdclass", 0))
        ttl = getattr(prereq_rrset, "ttl", 0)

        # Ensure owner is within the zone
        if not owner_norm.endswith(apex_norm) and owner_norm != apex_norm:
            return 9, f"Prerequisite owner {owner_norm} not in zone {apex_norm}"

        record_key = (owner_norm, qtype_int)
        existing_rrset = records.get(record_key, None)

        # RFC 2136 Section 3.2.4 Prerequisite Specification

        # CLASS NONE: These are requirements that the RRset or name NOT exist
        if qclass == dns.rdataclass.NONE:
            # TYPE ANY, CLASS NONE: Name must not exist (no RRsets at this name)
            if qtype_int == dns.rdatatype.ANY:
                # Check if any RRset exists at this name
                for (name, qtype), _ in records.items():
                    if name == owner_norm:
                        return 1, f"Name {owner_norm} already in use"
            # Specific type, CLASS NONE: RRset must not exist
            else:
                if existing_rrset is not None:
                    return (
                        1,
                        f"RRset {owner_norm}/{QTYPE.get(qtype_int, qtype_int)} already exists",
                    )

        # CLASS IN: These are requirements that the RRset or name DOES exist
        elif qclass == dns.rdataclass.IN:
            # TYPE ANY: Name must exist with at least one RRset
            if qtype_int == dns.rdatatype.ANY:
                has_any_rrset = False
                for (name, _), _ in records.items():
                    if name == owner_norm:
                        has_any_rrset = True
                        break
                if not has_any_rrset:
                    return 1, f"Name {owner_norm} does not exist"
            # Specific type: RRset must exist (or exact RR if ttl > 0)
            else:
                if existing_rrset is None:
                    return (
                        1,
                        f"RRset {owner_norm}/{QTYPE.get(qtype_int, qtype_int)} does not exist",
                    )
                # For exact RR matching with non-zero TTL, verify the specific RR exists
                if ttl > 0:
                    # Check if any rdata in the rrset matches
                    found_match = False
                    for rdata in prereq_rrset:
                        rdata_str = str(rdata)
                        existing_ttl, existing_values, _ = existing_rrset
                        if rdata_str in existing_values:
                            found_match = True
                            break
                    if not found_match:
                        return (
                            1,
                            f"RR {owner_norm}/{QTYPE.get(qtype_int, qtype_int)} does not exist",
                        )

        # CLASS ANY: Specific RR or RRset must exist (RFC 2136 3.2.4.1)
        elif qclass == dns.rdataclass.ANY:
            if qtype_int == dns.rdatatype.ANY:
                # Name must exist with at least one RRset
                has_any_rrset = False
                for (name, _), _ in records.items():
                    if name == owner_norm:
                        has_any_rrset = True
                        break
                if not has_any_rrset:
                    return 1, f"Name {owner_norm} does not exist"
            else:
                if existing_rrset is None:
                    return (
                        1,
                        f"RRset {owner_norm}/{QTYPE.get(qtype_int, qtype_int)} does not exist",
                    )

        # Unsupported or malformed prerequisite classes
        else:
            return 1, f"Unsupported prerequisite class {qclass}"

    return 0, None


def resolve_tsig_key_by_name(
    key_name: str,
    zone: dict,
    dns_update_config: dict,
) -> Optional[dict]:
    """Brief: Look up TSIG key configuration by name.

    Inputs:
      - key_name: TSIG key name from TSIG record.
      - zone: Zone configuration dict.
      - dns_update_config: DNS UPDATE config.

    Outputs:
      - TSIG key configuration dict, or None if not found.
    """
    from foghorn.plugins.resolve.zone_records import update_helpers as uh

    source_loaders = None
    if isinstance(dns_update_config, dict):
        maybe_loaders = dns_update_config.get("tsig_key_source_loaders")
        if isinstance(maybe_loaders, dict):
            source_loaders = maybe_loaders

    keys = uh.resolve_tsig_key_configs(zone, source_loaders=source_loaders)
    for key in keys:
        if isinstance(key, dict) and key.get("name", "") == key_name:
            return key

    return None


def apply_update_operations(
    updates: List[RR],
    plugin: object,
    zone_apex: str,
    *,
    journal_writer: Optional[object] = None,
    actor: Optional[Dict] = None,
    require_journal_persistence: bool = False,
) -> Tuple[int, Optional[str]]:
    """Brief: Apply update operations atomically per RFC 2136 Section 3.4.

    Inputs:
      - updates: Update RRs from dnspython Update.update.
      - plugin: ZoneRecords plugin instance.
      - zone_apex: Zone apex.
      - journal_writer: Optional JournalWriter for persistence.
      - actor: Optional actor metadata for journal entries.
      - require_journal_persistence: If True, fail closed unless journaling is active.

    Outputs:
      - Tuple of (rcode, error_message). RCODE=0 (NOERROR) on success.

    Notes:
      - Translates RFC 2136 update RRsets into normalized actions, then commits
        via commit.commit_record_actions (shared with admin API mutations).
      - If journal_writer is provided and journaling fails, memory is not mutated (fail-closed).
      - If require_journal_persistence is True, updates fail if journaling cannot be used.
    """
    from . import commit as zone_commit

    if require_journal_persistence and (
        journal_writer is None or actor is None
    ):  # pragma: no cover - nocover: validated in process_update_message integration paths
        return 2, "Journal unavailable"

    try:
        apex_norm = _normalize_dns_name(zone_apex)
    except Exception:
        apex_norm = ""

    default_ttl = 300
    actions: List[Dict[str, Any]] = []

    for update_rrset in list(updates or []):
        try:
            owner_norm = _normalize_dns_name(str(update_rrset.name))
        except Exception:
            return 1, "Invalid owner name in update RRset"

        qtype_int = int(getattr(update_rrset, "rdtype", 0))
        qclass = int(getattr(update_rrset, "rdclass", 0))
        ttl = int(getattr(update_rrset, "ttl", default_ttl))

        if apex_norm and not owner_norm.endswith(apex_norm) and owner_norm != apex_norm:
            return 9, f"Update owner {owner_norm} not in zone {apex_norm}"

        rdata_values = [str(rdata) for rdata in update_rrset]

        # CLASS NONE: Add RRs to RRset (or create RRset if needed)
        if qclass == dns.rdataclass.NONE:
            if qtype_int == dns.rdatatype.ANY:
                return 1, "TYPE ANY with CLASS NONE is invalid"
            for rdata_str in rdata_values:
                actions.append(
                    {
                        "type": "rr_add",
                        "owner": owner_norm,
                        "qtype": qtype_int,
                        "ttl": ttl,
                        "value": rdata_str,
                        "source": "update",
                    }
                )

        # CLASS ANY: Delete RR or RRset
        elif qclass == dns.rdataclass.ANY:
            if qtype_int == dns.rdatatype.ANY:
                actions.append({"type": "name_delete_all", "owner": owner_norm})
            else:
                if rdata_values:
                    for rdata_str in rdata_values:
                        actions.append(
                            {
                                "type": "rr_delete_values",
                                "owner": owner_norm,
                                "qtype": qtype_int,
                                "value": rdata_str,
                            }
                        )
                else:
                    # Empty rdata with CLASS ANY deletes the whole RRset.
                    actions.append(
                        {
                            "type": "rr_delete_rrset",
                            "owner": owner_norm,
                            "qtype": qtype_int,
                        }
                    )

        # CLASS IN: Replace entire RRset
        elif qclass == dns.rdataclass.IN:
            if qtype_int == dns.rdatatype.ANY:
                return 1, "TYPE ANY with CLASS IN is invalid"
            if rdata_values:
                actions.append(
                    {
                        "type": "rr_replace",
                        "owner": owner_norm,
                        "qtype": qtype_int,
                        "ttl": ttl,
                        "values": rdata_values,
                        "source": "update",
                    }
                )
        else:
            return 1, f"Unsupported update class {qclass}"

    result = zone_commit.commit_record_actions(
        plugin,
        apex_norm,
        actions,
        actor=actor,
        journal_writer=journal_writer,
        require_journal_persistence=require_journal_persistence,
        bump_soa=True,
        send_notify=None,
        mark_update_managed=True,
        default_source="update",
        enforce_zone_boundary=True,
    )
    if result.ok:
        return 0, None
    return int(result.rcode), result.error


def build_update_response(
    rcode: int,
    request: DNSRecord,
    ede_code: Optional[int] = None,
    ede_text: Optional[str] = None,
) -> bytes:
    """Brief: Build UPDATE response.

    Inputs:
      - rcode: Response code.
      - request: Original request.
      - ede_code: Optional EDE code.
      - ede_text: Optional EDE text.

    Outputs:
      - Wire-format response bytes.

    Notes:
      - EDE option attachment is scaffolded and currently not implemented.
    """

    reply = request.reply()
    reply.header.rcode = rcode

    # EDE handling if client supports EDNS
    if ede_code is not None:
        # Attach EDE option
        pass

    return reply.pack()
