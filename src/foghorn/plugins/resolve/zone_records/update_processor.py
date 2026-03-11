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
from typing import Dict, List, Optional, Tuple

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
from dnslib import DNSRecord, QTYPE, RCODE, RR

logger = logging.getLogger(__name__)

# Timestamp skew fudge (in seconds). BIND and dnspython default to 300.
TSIG_TIMESTAMP_FUDGE = 300


def _normalize_dns_name(name: str) -> str:
    """Brief: Normalize a DNS name for comparisons.

    Inputs:
      - name: DNS name, with or without trailing dot.

    Outputs:
      - Lowercased name without trailing dot.
    """
    return str(name).rstrip(".").lower()


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
    """Brief: Verify TSIG authentication (RFC 2845) using dnspython.

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
      - dnspython performs the full canonical TSIG MAC calculation per RFC 2845,
        including correct treatment of the TSIG RR and message header counts.
      - We additionally enforce a maximum allowed TSIG fudge (300s) to match the
        project's security expectations.
    """
    if not key_configs:
        return False, "No TSIG keys configured", None

    textring: Dict[str, object] = {}
    for cfg in key_configs:
        if not isinstance(cfg, dict):
            continue
        name = cfg.get("name")
        secret = cfg.get("secret")
        if not name or not secret:
            continue
        # dns.tsigkeyring.from_text supports mapping name -> base64_secret
        # (we enforce algorithm separately after verification)
        textring[str(name)] = str(secret)

    if not textring:
        return False, "No usable TSIG keys configured", None

    try:
        keyring = dns.tsigkeyring.from_text(textring)
    except Exception as exc:
        return False, f"Failed to build TSIG keyring: {exc}", None

    try:
        msg = dns.message.from_wire(request_data, keyring=keyring)
    except dns.tsig.PeerBadKey as exc:
        return False, f"Unknown TSIG key: {exc}", None
    except dns.tsig.BadSignature:
        return False, "TSIG signature verification failed", None
    except dns.tsig.PeerBadTime:
        return False, "TSIG time verification failed", None
    except dns.exception.DNSException as exc:
        return False, f"TSIG verification error: {exc}", None

    if not getattr(msg, "had_tsig", False):
        return False, "No TSIG present", None

    try:
        tsig_rr = msg.tsig[0]
        fudge = int(getattr(tsig_rr, "fudge", 0))
    except Exception:
        fudge = 0

    if fudge and fudge > TSIG_TIMESTAMP_FUDGE:
        return False, f"TSIG fudge too large ({fudge}s)", None

    keyname = _normalize_dns_name(getattr(msg, "keyname", ""))
    keyalgorithm = _normalize_tsig_algorithm(getattr(msg, "keyalgorithm", ""))

    for cfg in key_configs:
        if not isinstance(cfg, dict):
            continue
        if _normalize_dns_name(cfg.get("name", "")) != keyname:
            continue
        expected_alg = _normalize_tsig_algorithm(cfg.get("algorithm", "hmac-sha256"))
        if expected_alg and expected_alg != keyalgorithm:
            return (
                False,
                f"TSIG algorithm mismatch (expected {expected_alg}, got {keyalgorithm})",
                None,
            )
        return True, None, cfg

    return (
        False,
        "TSIG key not configured",
        None,
    )  # pragma: nocover - [unreachable: verified key must exist in key_configs]


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
      - For now, this function performs basic validation and TSIG authentication
        and returns NOTIMP after authorization succeeds.
    """

    # 1) Parse the request using dnspython. If TSIG keys are configured, require
    # TSIG and verify signature.
    tsig_cfg = zone_config.get("tsig") if isinstance(zone_config, dict) else None
    if isinstance(tsig_cfg, dict):
        key_configs = list(tsig_cfg.get("keys") or [])
    else:
        key_configs = []

    have_auth_config = bool(key_configs)

    # Build keyring mapping for dnspython.
    keyring_text: Dict[str, str] = {}
    for cfg in key_configs:
        if not isinstance(cfg, dict):
            continue
        name = cfg.get("name")
        secret = cfg.get("secret")
        if not name or not secret:
            continue
        keyring_text[str(name)] = str(secret)

    try:
        keyring = dns.tsigkeyring.from_text(keyring_text) if keyring_text else None
    except Exception:
        keyring = None

    request_msg: dns.message.Message | None = None
    matching_tsig_cfg: Optional[dict] = None

    if keyring is not None:
        try:
            request_msg = dns.message.from_wire(request_data, keyring=keyring)
        except dns.tsig.PeerBadKey:
            request_msg = None
        except dns.tsig.BadSignature:
            request_msg = None
        except dns.tsig.PeerBadTime:
            request_msg = None
        except dns.exception.DNSException:
            request_msg = None
    else:
        # No keys configured; still parse so we can build a response.
        try:
            request_msg = dns.message.from_wire(request_data, ignore_trailing=True)
        except Exception:
            request_msg = None

    if request_msg is None:
        # Worst-case fallback: cannot parse; return a bare FORMERR response.
        try:
            import struct

            mid = (
                struct.unpack("!H", request_data[:2])[0]
                if len(request_data) >= 2
                else 0
            )
        except Exception:
            mid = 0
        resp = dns.message.Message(id=int(mid))
        resp.flags |= dns.flags.QR
        resp.set_rcode(dns.rcode.FORMERR)
        return resp.to_wire()

    # Enforce opcode=UPDATE.
    try:
        if int(request_msg.opcode()) != int(dns.opcode.UPDATE):
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
    except Exception:
        apex_norm = str(zone_apex).rstrip(".").lower()

    # Zone section must contain exactly one SOA RRset for the zone apex. In
    # UPDATE messages the SOA RRset is often *empty* (no rdata); we validate the
    # owner name and type/class rather than requiring any rdatas.
    try:
        zone_rrsets = list(getattr(request_msg, "zone", []) or [])
    except Exception:
        zone_rrsets = []

    zone_rrset = zone_rrsets[0] if len(zone_rrsets) == 1 else None
    if zone_rrset is None:
        resp = dns.message.make_response(request_msg)
        resp.set_rcode(dns.rcode.NOTZONE)
        if getattr(request_msg, "had_tsig", False) and keyring is not None:
            try:
                resp.use_tsig(
                    keyring=keyring,
                    keyname=request_msg.keyname,
                    algorithm=request_msg.keyalgorithm,
                )
            except Exception:
                pass
        return resp.to_wire()

    try:
        zone_owner_norm = _normalize_dns_name(getattr(zone_rrset, "name", ""))
    except Exception:
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
    ):
        resp = dns.message.make_response(request_msg)
        resp.set_rcode(dns.rcode.NOTZONE)
        if getattr(request_msg, "had_tsig", False) and keyring is not None:
            try:
                resp.use_tsig(
                    keyring=keyring,
                    keyname=request_msg.keyname,
                    algorithm=request_msg.keyalgorithm,
                )
            except Exception:
                pass
        return resp.to_wire()

    # 3) Authorization: client allowlist + TSIG requirement (TSIG-only for now).
    ctx = UpdateContext(
        zone_apex=apex_norm, client_ip=str(client_ip), listener=listener, plugin=plugin
    )

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
            except Exception:
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
            if not isinstance(cfg, dict):
                continue
            if _normalize_dns_name(cfg.get("name", "")) != keyname_norm:
                continue
            expected_alg = _normalize_tsig_algorithm(
                cfg.get("algorithm", "hmac-sha256")
            )
            if expected_alg and expected_alg != keyalg_norm:
                resp = dns.message.make_response(request_msg)
                resp.set_rcode(dns.rcode.NOTAUTH)
                return resp.to_wire()
            matching_tsig_cfg = cfg
            break

        if matching_tsig_cfg is None:
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.NOTAUTH)
            return resp.to_wire()

        # Enforce max fudge.
        try:
            tsig_rr = request_msg.tsig[0]
            fudge = int(getattr(tsig_rr, "fudge", 0) or 0)
        except Exception:
            fudge = 0
        if fudge and fudge > TSIG_TIMESTAMP_FUDGE:
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.NOTAUTH)
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
    except Exception:
        prereqs = []
        updates = []

    # Get current records
    current_records = dict(getattr(plugin, "records", {}))

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
                except Exception:
                    pass
            return resp.to_wire()

    # Check name/value authorization for each update RRset
    for update_rrset in updates:
        # Get owner name from the RRset
        try:
            owner_norm = _normalize_dns_name(str(update_rrset.name))
        except Exception:
            owner_norm = ""

        if not verify_name_authorization(owner_norm, zone_config):
            resp = dns.message.make_response(request_msg)
            resp.set_rcode(dns.rcode.NOTAUTH)
            if getattr(request_msg, "had_tsig", False) and keyring is not None:
                try:
                    resp.use_tsig(
                        keyring=keyring,
                        keyname=request_msg.keyname,
                        algorithm=request_msg.keyalgorithm,
                    )
                except Exception:
                    pass
            return resp.to_wire()

        # For A/AAAA records, verify IP values (rrset contains rdata objects)
        try:
            qtype_int = int(getattr(update_rrset, "rdtype", 0))
            # Convert rdata to string for value authorization
            for rdata in update_rrset:
                rdata_str = str(rdata)
                if not verify_value_authorization(rdata_str, qtype_int, zone_config):
                    resp = dns.message.make_response(request_msg)
                    resp.set_rcode(dns.rcode.NOTAUTH)
                    if getattr(request_msg, "had_tsig", False) and keyring is not None:
                        try:
                            resp.use_tsig(
                                keyring=keyring,
                                keyname=request_msg.keyname,
                                algorithm=request_msg.keyalgorithm,
                            )
                        except Exception:
                            pass
                    return resp.to_wire()
        except Exception:
            pass

    # Apply update operations
    if updates:
        update_rcode, update_err = apply_update_operations(updates, plugin, apex_norm)
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
                except Exception:
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
        except Exception:
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

    allow_clients = zone_config.get("allow_clients", [])
    allow_clients_files = zone_config.get("allow_clients_files", [])

    if not allow_clients and not allow_clients_files:
        return True, None

    clients_list = uh.combine_lists(
        allow_clients,
        allow_clients_files,
        uh.load_cidr_list_from_file,
    )

    if not clients_list:
        return True, None

    if not uh.is_ip_in_cidr_list(ctx.client_ip, clients_list):
        return False, "Client IP not in allow_clients"

    return True, None


def verify_name_authorization(
    name: str,
    zone_config: dict,
) -> bool:
    """Brief: Verify name is allowed for updates.

    Inputs:
      - name: Domain name to update.
      - zone_config: Zone configuration.

    Outputs:
      - bool: True if name is allowed.
    """
    from foghorn.plugins.resolve.zone_records import update_helpers as uh

    block_names = zone_config.get("block_names", [])
    block_names_files = zone_config.get("block_names_files", [])
    allow_names = zone_config.get("allow_names", [])
    allow_names_files = zone_config.get("allow_names_files", [])

    # Check blocked names first
    blocked_list = uh.combine_lists(
        block_names,
        block_names_files,
        uh.load_names_list_from_file,
    )
    if blocked_list and uh.matches_name_pattern(name, blocked_list):
        return False

    # Check allowed names
    if allow_names or allow_names_files:
        allowed_list = uh.combine_lists(
            allow_names,
            allow_names_files,
            uh.load_names_list_from_file,
        )
        if allowed_list and not uh.matches_name_pattern(name, allowed_list):
            return False

    return True


def verify_value_authorization(
    value: str,
    qtype: int,
    zone_config: dict,
) -> bool:
    """Brief: Verify A/AAAA record value is allowed.

    Inputs:
      - value: IP address value.
      - qtype: Record type (A=1, AAAA=28).
      - zone_config: Zone configuration.

    Outputs:
      - bool: True if value is allowed.
    """
    # Only validate A and AAAA records
    if qtype not in (QTYPE.A, QTYPE.AAAA):
        return True

    from foghorn.plugins.resolve.zone_records import update_helpers as uh

    block_ips = zone_config.get("block_update_ips", [])
    block_ips_files = zone_config.get("block_update_ips_files", [])
    allow_ips = zone_config.get("allow_update_ips", [])
    allow_ips_files = zone_config.get("allow_update_ips_files", [])

    # Check blocked IPs first
    blocked_list = uh.combine_lists(
        block_ips,
        block_ips_files,
        uh.load_cidr_list_from_file,
    )
    if blocked_list and uh.is_ip_in_cidr_list(value, blocked_list):
        return False

    # Check allowed IPs
    if allow_ips or allow_ips_files:
        allowed_list = uh.combine_lists(
            allow_ips,
            allow_ips_files,
            uh.load_cidr_list_from_file,
        )
        if allowed_list and not uh.is_ip_in_cidr_list(value, allowed_list):
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
        apex_norm = str(zone_apex).rstrip(".").lower()

    for prereq_rrset in prereqs:
        try:
            owner_norm = _normalize_dns_name(str(prereq_rrset.name))
        except Exception:
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
    tsig_cfg = zone.get("tsig")
    if not tsig_cfg:
        return None

    keys = tsig_cfg.get("keys", []) or []
    for key in keys:
        if isinstance(key, dict) and key.get("name", "") == key_name:
            return key

    return None


def apply_update_operations(
    updates: List[RR],
    plugin: object,
    zone_apex: str,
) -> Tuple[int, Optional[str]]:
    """Brief: Apply update operations atomically per RFC 2136 Section 3.4.

    Inputs:
      - updates: Update RRs from dnspython Update.update.
      - plugin: ZoneRecords plugin instance.
      - zone_apex: Zone apex.

    Outputs:
      - Tuple of (rcode, error_message). RCODE=0 (NOERROR) on success.

    Notes:
      - Update semantics per RFC 2136:
        * CLASS NONE, TYPE!=ANY: Add RR to RRset (create if needed)
        * CLASS ANY, TYPE!=ANY: Delete RR from RRset (delete entire RRset if rdata empty)
        * CLASS ANY, TYPE=ANY: Delete all RRsets at an owner
        * CLASS IN, TYPE!=ANY: Replace entire RRset with provided RR(s)
    """
    try:
        apex_norm = _normalize_dns_name(zone_apex)
    except Exception:
        apex_norm = str(zone_apex).rstrip(".").lower()

    # Snapshot current records
    lock = getattr(plugin, "_records_lock", None)
    if lock is None:
        snapshot = dict(getattr(plugin, "records", {}))
    else:
        with lock:
            snapshot = dict(getattr(plugin, "records", {}))

    new_records = dict(snapshot)
    default_ttl = 300  # Default TTL for updates without explicit TTL

    for update_rrset in updates:
        # Get owner name from the RRset
        try:
            owner_norm = _normalize_dns_name(str(update_rrset.name))
        except Exception:
            return 1, "Invalid owner name in update RRset"

        qtype_int = int(getattr(update_rrset, "rdtype", 0))
        qclass = int(getattr(update_rrset, "rdclass", 0))
        ttl = int(getattr(update_rrset, "ttl", default_ttl))

        # Ensure owner is within the zone
        if not owner_norm.endswith(apex_norm) and owner_norm != apex_norm:
            return 9, f"Update owner {owner_norm} not in zone {apex_norm}"

        record_key = (owner_norm, qtype_int)

        # Collect rdata strings from the RRset
        rdata_values = [str(rdata) for rdata in update_rrset]

        # RFC 2136 Section 3.4 Update Operations

        # CLASS NONE: Add RRs to RRset (or create RRset if needed)
        if qclass == dns.rdataclass.NONE:
            if qtype_int == dns.rdatatype.ANY:
                return 1, "TYPE ANY with CLASS NONE is invalid"
            for rdata_str in rdata_values:
                if record_key not in new_records:
                    new_records[record_key] = (ttl, [rdata_str], ["update"])
                else:
                    existing_ttl, existing_values, sources = new_records[record_key]
                    if rdata_str not in existing_values:
                        new_values = existing_values + [rdata_str]
                        new_records[record_key] = (ttl, new_values, sources)

        # CLASS ANY: Delete RR or RRset
        elif qclass == dns.rdataclass.ANY:
            if qtype_int == dns.rdatatype.ANY:
                # Delete all RRsets at this owner
                keys_to_delete = [k for k in new_records if k[0] == owner_norm]
                for k in keys_to_delete:
                    del new_records[k]
            else:
                # Delete specific RRs from RRset, or delete RRset if empty/optional
                if record_key in new_records:
                    existing_ttl, existing_values, sources = new_records[record_key]
                    for rdata_str in rdata_values:
                        if rdata_str in existing_values:
                            if len(existing_values) > 1:
                                existing_values.remove(rdata_str)
                                new_records[record_key] = (
                                    ttl,
                                    existing_values,
                                    sources,
                                )
                            else:
                                del new_records[record_key]
                                break

        # CLASS IN: Replace entire RRset
        elif qclass == dns.rdataclass.IN:
            if qtype_int == dns.rdatatype.ANY:
                return 1, "TYPE ANY with CLASS IN is invalid"
            # Replace entire RRset with all RRs from this update_rrset
            if rdata_values:
                new_records[record_key] = (ttl, rdata_values, ["update"])

        else:
            return 1, f"Unsupported update class {qclass}"

    # Commit under lock
    if lock is None:
        plugin.records = new_records
    else:
        with lock:
            plugin.records = new_records

    return 0, None


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
    import struct

    reply = request.reply()
    reply.header.rcode = rcode

    # EDE handling if client supports EDNS
    if ede_code is not None:
        # Attach EDE option
        pass

    return reply.pack()
