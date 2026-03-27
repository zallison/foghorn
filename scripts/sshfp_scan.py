#!/usr/bin/env python3
"""Paramiko-based SSHFP key scanner CLI wrapper.

Brief:
  Given a hostname (and optional port), or a CIDR such as ``192.0.2.0/24``,
  connects using multiple host key algorithms and prints SSHFP records
  equivalent to ``ssh-keyscan -D <host>``.
  For IP targets, reverse PTR lookup is enabled by default and additional
  SSHFP records are emitted for discovered hostnames; disable this with
  ``--no-reverse-ptr``.

Inputs:
  - Command-line arguments; see ``parse_args`` for details.

Outputs:
  - Prints one or more ``<hostname> IN SSHFP <alg> <fptype> <fingerprint>``
    lines to stdout and returns an exit status code.
"""

import argparse
import ipaddress
import socket
import sys
from typing import List, Optional, Set, Tuple

from foghorn.utils import ssh_keyscan


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Inputs:
      argv: Optional list of argument strings (defaults to sys.argv[1:]).

    Outputs:
      An argparse.Namespace with attributes: targets, port, timeout,
      zone_record_format, zone_ttl, reverse_ptr.
    """
    parser = argparse.ArgumentParser(
        description="Scan SSH host keys and print DNS SSHFP records "
        "(similar to ssh-keyscan -D).",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help=(
            "One or more hostnames, IP addresses, or CIDR ranges "
            "(e.g. lemur.zaa, 192.0.2.10, 192.0.2.0/24)."
        ),
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=22,
        help="SSH port (default: 22).",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="Connection and handshake timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--zone-record-format",
        action="store_true",
        help=(
            'When set, print records as "<domain>|SSHFP|<ttl>|<value>" lines '
            "suitable for the ZoneRecords plugin, where <value> is "
            '"<alg> <fptype> <fingerprint>" and <ttl> comes from --zone-ttl.'
        ),
    )
    parser.add_argument(
        "--zone-ttl",
        type=int,
        default=300,
        help="TTL to use for --zone-format output (default: 300).",
    )
    parser.add_argument(
        "--reverse-ptr",
        dest="reverse_ptr",
        action="store_true",
        help=(
            "Enable reverse PTR lookups for IP targets and emit additional "
            "SSHFP records for returned hostnames (default: enabled)."
        ),
    )
    parser.add_argument(
        "--no-reverse-ptr",
        dest="reverse_ptr",
        action="store_false",
        help="Disable reverse PTR lookups for IP targets.",
    )
    parser.set_defaults(reverse_ptr=True)
    return parser.parse_args(argv)


def _is_ip_target(value: str) -> bool:
    """Check whether a target string is an IP address literal.

    Inputs:
      - value: Candidate hostname/IP string from CLI targets.

    Outputs:
      - bool: True when ``value`` is a valid IPv4/IPv6 literal, else False.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _resolve_ptr_hostnames(ip_value: str) -> List[str]:
    """Resolve reverse PTR hostnames for an IP target.

    Inputs:
      - ip_value: IPv4/IPv6 address string to reverse-resolve.

    Outputs:
      - list[str]: De-duplicated, lower-cased hostnames (without trailing
        dots) from reverse DNS. Entries that are themselves IP literals are
        ignored.
    """
    try:
        primary, aliases, _ = socket.gethostbyaddr(ip_value)
    except (socket.herror, socket.gaierror, OSError):
        return []

    hostnames: List[str] = []
    seen: Set[str] = set()
    for candidate in [primary, *aliases]:
        normalized = str(candidate).strip().rstrip(".").lower()
        if not normalized:
            continue
        if _is_ip_target(normalized):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        hostnames.append(normalized)

    return hostnames


def _parse_sshfp_line(line: str) -> Optional[Tuple[str, str]]:
    """Parse a DNS-style SSHFP line into owner and rdata.

    Inputs:
      - line: Record line in the form
        ``<owner> IN SSHFP <alg> <fptype> <fingerprint>``.

    Outputs:
      - tuple[str, str] | None: ``(owner, rdata)`` where rdata is
        ``<alg> <fptype> <fingerprint>``, or None if ``line`` is not in the
        expected SSHFP format.
    """
    parts = str(line).split()
    if len(parts) < 6:
        return None

    owner, maybe_in, qtype_token = parts[0], parts[1], parts[2]
    if maybe_in.upper() != "IN" or qtype_token.upper() != "SSHFP":
        return None

    return owner, " ".join(parts[3:])


def _format_sshfp_output_line(
    owner: str, rdata: str, *, zone_record_format: bool, zone_ttl: int
) -> str:
    """Format an SSHFP output line for standard or zone-record output.

    Inputs:
      - owner: Record owner name to emit.
      - rdata: SSHFP rdata value ``<alg> <fptype> <fingerprint>``.
      - zone_record_format: Whether to emit ZoneRecords plugin pipe format.
      - zone_ttl: TTL to include when ``zone_record_format`` is True.

    Outputs:
      - str: Either ``<owner> IN SSHFP <rdata>`` or
        ``<owner>|SSHFP|<ttl>|<rdata>`` with normalized owner for zone format.
    """
    if not zone_record_format:
        return f"{owner} IN SSHFP {rdata}"

    normalized_owner = owner.rstrip(".").lower()
    return f"{normalized_owner}|SSHFP|{zone_ttl}|{rdata}"


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point: parse arguments, collect SSHFP records, print them.

    Inputs:
      - argv: Optional list of CLI arguments (defaults to ``sys.argv[1:]``).

    Outputs:
      - int: Zero on success, non-zero on error.
    """

    args = parse_args(argv)
    zone_ttl = int(getattr(args, "zone_ttl", 300) or 300)

    # Accept one or more hostnames/IPs, and/or CIDRs such as ``192.0.2.0/24``,
    # and expand CIDRs to individual IP addresses.
    targets: List[str] = []
    for raw_arg in args.targets:
        raw = str(raw_arg)
        if "/" in raw:
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:  # pragma: no cover - CLI validation
                print(f"Invalid CIDR {raw!r}: {exc}", file=sys.stderr)
                return 2
            cidr_hosts = [str(ip) for ip in network.hosts()]
            if not cidr_hosts:
                print(
                    f"CIDR {raw!r} did not contain any host addresses",
                    file=sys.stderr,
                )
                return 1
            targets.extend(cidr_hosts)
        else:
            targets.append(raw)

    any_records = False
    for host in targets:
        records = ssh_keyscan.collect_sshfp_records(
            hostname=host,
            port=int(args.port),
            timeout=float(args.timeout),
        )

        if not records:
            print(f"No SSHFP records found for {host}", file=sys.stderr)
            continue

        any_records = True
        ptr_hostnames: List[str] = []
        if bool(args.reverse_ptr) and _is_ip_target(host):
            ptr_hostnames = _resolve_ptr_hostnames(host)

        for line in records:
            if not args.zone_record_format and not ptr_hostnames:
                print(line)
                continue

            parsed = _parse_sshfp_line(str(line))
            if parsed is None:
                # Fallback: emit original line when format is unexpected.
                print(line)
                continue

            owner, rdata = parsed
            output_owners: List[str] = [owner]
            seen_owners: Set[str] = {owner.rstrip(".").lower()}
            for ptr_hostname in ptr_hostnames:
                if ptr_hostname in seen_owners:
                    continue
                seen_owners.add(ptr_hostname)
                output_owners.append(ptr_hostname)

            for output_owner in output_owners:
                print(
                    _format_sshfp_output_line(
                        output_owner,
                        rdata,
                        zone_record_format=bool(args.zone_record_format),
                        zone_ttl=zone_ttl,
                    )
                )

    return 0 if any_records else 1


if __name__ == "__main__":
    raise SystemExit(main())
