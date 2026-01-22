#!/usr/bin/env python3
"""Paramiko-based SSHFP key scanner CLI wrapper.

Brief:
  Given a hostname (and optional port), or a CIDR such as ``192.0.2.0/24``,
  connects using multiple host key algorithms and prints SSHFP records
  equivalent to ``ssh-keyscan -D <host>``.

Inputs:
  - Command-line arguments; see ``parse_args`` for details.

Outputs:
  - Prints one or more ``<hostname> IN SSHFP <alg> <fptype> <fingerprint>``
    lines to stdout and returns an exit status code.
"""

import argparse
import ipaddress
import sys
from typing import List, Optional

from foghorn.utils import ssh_keyscan


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Inputs:
      argv: Optional list of argument strings (defaults to sys.argv[1:]).

    Outputs:
      An argparse.Namespace with attributes: targets, port, timeout,
      zone_record_format, zone_ttl.
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
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point: parse arguments, collect SSHFP records, print them.

    Inputs:
      - argv: Optional list of CLI arguments (defaults to ``sys.argv[1:]``).

    Outputs:
      - int: Zero on success, non-zero on error.
    """

    args = parse_args(argv)

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
        for line in records:
            if not args.zone_record_format:
                print(line)
                continue

            # Expect lines in the form:
            #   "<hostname> IN SSHFP <alg> <fptype> <fingerprint>"
            parts = str(line).split()
            if len(parts) < 6:
                # Fallback: emit the original line when the format is
                # unexpected, rather than raising.
                print(line)
                continue

            owner, maybe_in, qtype_token = parts[0], parts[1], parts[2]
            if maybe_in.upper() != "IN" or qtype_token.upper() != "SSHFP":
                print(line)
                continue

            domain = owner.rstrip(".").lower()
            ttl = int(getattr(args, "zone_ttl", 300) or 300)
            rdata = " ".join(parts[3:])
            print(f"{domain}|SSHFP|{ttl}|{rdata}")

    return 0 if any_records else 1


if __name__ == "__main__":
    raise SystemExit(main())
