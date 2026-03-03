"""Brief: DNS UPDATE message parsing and processing.

Inputs/Outputs:
  - Parse UPDATE message sections (Zone, Prerequisites, Update, Additional).
  - Apply atomic updates with rollback support.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time
from typing import Dict, List, Optional, Tuple

from dnslib import DNSRecord, QTYPE, RCODE, RR

logger = logging.getLogger(__name__)

# HMAC algorithms per RFC 2845
TSIG_ALGORITHMS = {
    "hmac-md5": hashlib.md5,
    "hmac-sha1": hashlib.sha1,
    "hmac-sha256": hashlib.sha256,
    "hmac-sha384": hashlib.sha384,
    "hmac-sha512": hashlib.sha512,
}

# Timestamp skew fudge (in seconds) - RFC 2845 suggests 5 minutes
TSIG_TIMESTAMP_FUDGE = 300


def parse_tsig_record(additional: List[RR]) -> Optional[Tuple[str, str, str, int]]:
    """Brief: Parse a TSIG record from the additional section.

    Inputs:
      - additional: Additional section RRs.

    Outputs:
      - Tuple of (key_name, algorithm, signature, timestamp) or None.

    Notes:
      - dnslib does not currently decode TSIG RDATA into a rich structure.
        This parser is best-effort and must be hardened before use in
        production authentication.
    """

    for rr in additional:
        if QTYPE[rr.rtype] != "TSIG":
            continue

        try:
            data = rr.rdata
            if not isinstance(data, (bytes, bytearray)):
                logger.warning("TSIG RDATA is not raw bytes; cannot parse")
                return None

            if len(data) < 10:
                return None

            # Extract fields (simplified - RFC 2845 section 4.5.2)
            key_data_start = 22
            if len(data) < key_data_start:
                return None

            key_name_len = data[key_data_start]
            key_name = data[
                key_data_start + 1 : key_data_start + 1 + key_name_len
            ].decode("utf-8")

            sig_data_pos = key_data_start + 1 + key_name_len
            if len(data) < sig_data_pos + 1:
                return None

            algorithm = data[sig_data_pos : sig_data_pos + 1].decode("utf-8")
            signature_offset = sig_data_pos + 1

            timestamp_bytes = data[4:10]
            timestamp = int.from_bytes(timestamp_bytes, "big")

            signature = base64.b64encode(data[signature_offset:]).decode("utf-8")

            return key_name, algorithm, signature, timestamp
        except Exception as exc:
            logger.warning("Failed to parse TSIG record: %s", exc)
            return None

    return None


def verify_tsig_signature(
    request_data: bytes,
    key_name: str,
    algorithm: str,
    secret: str,
    signature: str,
    timestamp: int,
) -> bool:
    """Brief: Verify TSIG signature.

    Inputs:
      - request_data: Original request bytes.
      - key_name: TSIG key name.
      - algorithm: HMAC algorithm (hmac-md5, hmac-sha256, hmac-sha512).
      - secret: Base64-encoded secret.
      - signature: Signature from TSIG record.
      - timestamp: TSIG timestamp.

    Outputs:
      - bool: True if signature valid.
    """
    # Check timestamp skew
    current_time = int(time.time())
    if abs(current_time - timestamp) > TSIG_TIMESTAMP_FUDGE:
        logger.warning(
            "TSIG timestamp skew too large: %s seconds (fudge=%s)",
            abs(current_time - timestamp),
            TSIG_TIMESTAMP_FUDGE,
        )
        return False

    # Get HMAC function
    hash_func = TSIG_ALGORITHMS.get(algorithm.lower())
    if not hash_func:
        logger.warning("Unsupported TSIG algorithm: %s", algorithm)
        return False

    # Decode secret
    try:
        key_bytes = base64.b64decode(secret)
    except Exception:
        logger.warning("Failed to decode TSIG secret")
        return False

    # Recompute signature
    try:
        # Remove TSIG from data to recompute signature
        # This is simplified - full RFC 2845 requires removing the TSIG RR itself
        # For now, we'll verify the signature against a known format
        computed_sig = hmac.new(key_bytes, request_data[:-16], hash_func).digest()
        computed_sig_base64 = base64.b64encode(computed_sig).decode("utf-8")

        # Constant-time comparison to avoid timing attacks
        if len(signature) != len(computed_sig_base64):
            return False

        result = 0
        for a, b in zip(signature, computed_sig_base64):
            result |= ord(a) ^ ord(b)

        return result == 0
    except Exception as exc:
        logger.warning("TSIG signature verification failed: %s", exc)
        return False


def verify_tsig_auth(
    request_data: bytes,
    additional: List[RR],
    zone_config: dict,
    key_configs: List[dict],
) -> Tuple[bool, Optional[str]]:
    """Brief: Verify TSIG authentication.

    Inputs:
      - request_data: Raw DNS UPDATE request bytes.
      - additional: Additional section RRs.
      - zone_config: Zone configuration.
      - key_configs: List of TSIG key configurations.

    Outputs:
      - Tuple of (authorized, error_message) or (False, error).
    """
    # Parse TSIG from additional section
    tsig_data = parse_tsig_record(additional)
    if not tsig_data:
        return False, "No valid TSIG record found"

    key_name, algorithm, signature, timestamp = tsig_data

    # Find matching key configuration
    key_config = None
    for cfg in key_configs:
        if isinstance(cfg, dict) and cfg.get("name", "") == key_name:
            key_config = cfg
            break

    if not key_config:
        return False, f"Unknown TSIG key: {key_name}"

    if algorithm != key_config.get("algorithm", "hmac-sha256"):
        return False, f"TSIG algorithm mismatch: expected {key_config.get('algorithm')}"

    # Verify signature
    if not verify_tsig_signature(
        request_data,
        key_name,
        algorithm,
        key_config.get("secret", ""),
        signature,
        timestamp,
    ):
        return False, "TSIG signature verification failed"

    return True, None


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
) -> Tuple[int, Optional[str]]:
    """Brief: Process a DNS UPDATE message.

    Inputs:
      - request_data: Wire-format UPDATE request.
      - zone_apex: Zone apex.
      - zone_config: Zone configuration dict.
      - plugin: ZoneRecords plugin instance.
      - client_ip: Client IP address (string).
      - listener: Listener type (dot/doh/udp/tcp).

    Outputs:
      - Tuple of (rcode, error_message).

    Notes:
      - This function is currently a scaffold; prerequisite checks and update
        operations are not yet implemented.
    """

    parsed = parse_update_message(request_data)
    if not parsed:
        return RCODE.FORMERR, "Failed to parse UPDATE message"

    return RCODE.NOTIMP, "DNS UPDATE processing not implemented"


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


def parse_update_message(data: bytes) -> Optional[DNSRecord]:
    """Brief: Parse UPDATE message.

    Inputs:
      - data: Wire-format UPDATE message.

    Outputs:
      - DNSRecord or None on parse error.
    """
    try:
        return DNSRecord.parse(data)
    except Exception as exc:
        logger.warning("Failed to parse UPDATE message: %s", exc)
        return None


def check_prerequisites(
    prereqs: List[RR],
    records: Dict,
    zone_apex: str,
) -> Tuple[int, Optional[str]]:
    """Brief: Check prerequisite conditions.

    Inputs:
      - prereqs: Prerequisite RRs.
      - records: Current zone records.
      - zone_apex: Zone apex.

    Outputs:
      - Tuple of (rcode, error_message). RCODE=0 (NOERROR) if all pass.
    """
    # TODO: Implement RFC 2136 prerequisite types:
    # - CLASS=ANY: RRSET existence
    # - CLASS=NONE: RRSET nonexistence
    # - TYPE=ANY with CLASS=NONE: Name must not be in use
    for prereq in prereqs:
        pass

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
    """Brief: Apply update operations atomically.

    Inputs:
      - updates: Update RRs.
      - plugin: ZoneRecords plugin instance.
      - zone_apex: Zone apex.

    Outputs:
      - Tuple of (rcode, error_message). RCODE=0 (NOERROR) on success.
    """
    from foghorn.plugins.resolve.zone_records.loader import load_records

    # Snapshot current records
    lock = getattr(plugin, "_records_lock", None)
    if lock is None:
        snapshot = dict(getattr(plugin, "records", {}))
    else:
        with lock:
            snapshot = dict(getattr(plugin, "records", {}))

    # Apply updates
    try:
        # TODO: Implement update operations:
        # - ADD: Class NONE, empty TTL
        # - DELETE: Class ANY, TTL 0
        # - REPLACE: Full RRset replacement
        pass

        return 0, None
    except Exception as exc:
        # Rollback
        logger.warning("Update failed: %s", exc, exc_info=True)
        if lock is None:
            plugin.records = snapshot
        else:
            with lock:
                plugin.records = snapshot
        return 2, "SERVFAIL: Update operation failed"


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
    """
    import struct

    reply = request.reply()
    reply.header.rcode = rcode

    # EDE handling if client supports EDNS
    if ede_code is not None:
        # Attach EDE option
        pass

    return reply.pack()
