"""Brief: DNS UPDATE message parsing and processing.

Inputs/Outputs:
  - Parse UPDATE message sections (Zone, Prerequisites, Update, Additional).
  - Apply atomic updates with rollback support.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from dnslib import DNSRecord, DNSHeader, QTYPE, RCODE, RR

from foghorn.plugins.resolve.base import PluginContext, PluginDecision
from foghorn.plugins.resolve.zone_records import update_helpers

logger = logging.getLogger(__name__)


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
