from __future__ import annotations

import logging
import os
import pathlib
from typing import Dict, Iterable, List, Optional

from dnslib import AAAA, QTYPE, RR, A, DNSHeader, DNSRecord

from foghorn.plugins.base import (BasePlugin, PluginContext, PluginDecision,
                                  plugin_aliases)

logger = logging.getLogger(__name__)


@plugin_aliases("hosts", "etc-hosts", "/etc/hosts")
class EtcHosts(BasePlugin):
    """
    Brief: Resolve A/AAAA queries from one or more hosts files.

    Load IPs and hostnames from /etc/hosts or other host files. Supports reading
    multiple files; when the same hostname appears in more than one file, entries
    from later files override earlier ones.
    """

    def setup(self) -> None:
        """
        Brief: Initialize the plugin and load host mappings.

        Inputs:
          - file_path (str, optional): Single hosts file path (legacy, preserved)
          - file_paths (list[str], optional): List of hosts file paths
            to load and merge in order (later overrides earlier)

        Outputs:
          - None

        Example:
          Legacy single file:
            EtcHosts(file_path="/custom/hosts")

          Multiple files (preferred):
            EtcHosts(file_paths=["/etc/hosts", "/etc/hosts.d/extra"])
        """

        # Normalize configuration into a list of paths. Default to /etc/hosts
        legacy = self.config.get("file_path")
        provided = self.config.get("file_paths")
        self.file_paths: List[str] = self._normalize_paths(provided, legacy)

        self._load_hosts()

    def _normalize_paths(
        self, file_paths: Optional[Iterable[str]], legacy: Optional[str]
    ) -> List[str]:
        """
        Brief: Coerce provided file path inputs into an ordered, de-duplicated list.

        Inputs:
          - file_paths: iterable of file path strings (may be None)
          - legacy: single legacy file path string (may be None)

        Outputs:
          - list[str]: Non-empty list of unique paths (order preserved). Defaults
            to ["/etc/hosts"]. If both file_paths and legacy file_path are given,
            the legacy path is included in the set of file paths.

        Example:
          _normalize_paths(["/a", "/b"], None) -> ["/a", "/b"]
          _normalize_paths(["/a", "/b"], "/a") -> ["/a", "/b"]
          _normalize_paths(None, "/a") -> ["/a"]
          _normalize_paths(None, None) -> ["/etc/hosts"]
        """
        paths: List[str] = []
        if file_paths:
            for p in file_paths:
                paths.append(os.path.expanduser(str(p)))
        if legacy:
            # Include legacy file_path in the set of file paths
            paths.append(os.path.expanduser(str(legacy)))
        if not paths:
            paths = ["/etc/hosts"]  # pragma: no cover
        # De-duplicate while preserving order
        paths = list(dict.fromkeys(paths))
        return paths

    def _load_hosts(self) -> None:
        """
        Brief: Read hosts files and build a mapping of domain -> IP.

        - Supports comments beginning with '#', including inline comments.
        - Requires at least one hostname after the IP on each non-comment line.
        - Multiple hostnames per line are supported and mapped to the same IP.
        - When multiple files are provided, later files override earlier ones on
          conflicts for the same hostname.

        Inputs:
          - None (uses self.file_paths)
        Outputs:
          - None (populates self.hosts: Dict[str, str])
        """
        mapping: Dict[str, str] = {}

        for fp in self.file_paths:
            hosts_path = pathlib.Path(fp)
            with hosts_path.open("r", encoding="utf-8") as f:
                for raw_line in f:
                    # Remove inline comments and surrounding whitespace
                    line = raw_line.split("#", 1)[0].strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        raise ValueError(
                            f"File {hosts_path} malformed line: {raw_line}"
                        )

                    ip = parts[0]
                    for domain in parts[1:]:
                        # Later files override earlier ones by assignment
                        mapping[domain] = ip
        self.hosts = mapping

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Brief: Return an override decision if qname exists in loaded hosts.

        Inputs:
            qname: Queried domain name.
            qtype: DNS record type.
            req: Raw DNS request bytes.
            ctx: Plugin context.
        Outputs:
            PluginDecision("override") when domain is mapped (and type matches),
            otherwise None.

        """
        if qtype not in (QTYPE.A, QTYPE.AAAA):
            return None

        qname = qname.rstrip(".")
        ip = self.hosts.get(qname)

        if not ip:
            return None

        # If the requested type doesn't match the IP version we have, let normal
        # resolution continue (avoid constructing invalid AAAA from IPv4, etc.).
        is_v6 = ":" in ip
        is_v4 = "." in ip
        if qtype == QTYPE.AAAA and is_v4 and not is_v6:
            return None
        if qtype == QTYPE.A and is_v6 and not is_v4:
            return None

        # Build a proper DNS response with the same TXID
        wire = self._make_a_response(qname, qtype, req, ctx, ip)
        return PluginDecision(action="override", response=wire)

    def _make_a_response(
        self,
        qname: str,
        query_type: int,
        raw_req: bytes,
        ctx: PluginContext,
        ipaddr: str,
    ) -> Optional[bytes]:
        try:
            request = DNSRecord.parse(raw_req)
        except Exception as e:
            logger.warning("parse failure: %s", e)
            return None

        # Normalize domain
        # qname = str(request.q.qname).rstrip(".")

        ip = ipaddr
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        if query_type == QTYPE.A:
            reply.add_answer(
                RR(rname=request.q.qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A(ip))
            )
        elif query_type == QTYPE.AAAA:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.AAAA,
                    rclass=1,
                    ttl=60,
                    rdata=AAAA(ip),
                )
            )

        return reply.pack()

    def close(self) -> None:
        """
        Brief: Stop any background watchers and release resources.

        Inputs:
          - None
        Outputs:
          - None
        """
        try:
            if self._notifier is not None:
                self._notifier.stop()
        except Exception:  # pragma: no cover
            pass
        self._notifier = None
