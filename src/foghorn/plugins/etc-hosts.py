from __future__ import annotations
import time
from dnslib import DNSRecord, QTYPE, A, AAAA, QR, RR, DNSHeader
import os
import logging
import pathlib
from typing import Dict, Optional

from foghorn.plugins.base import PluginDecision, PluginContext
from foghorn.plugins.base import BasePlugin, plugin_aliases

logger = logging.getLogger(__name__)


@plugin_aliases("hosts", "etc-hosts", "/etc/hosts")
class EtcHosts(BasePlugin):
    """
    Load /etc/hosts

    Brief: Load ips and host names from /etc/hosts, or another host file.
    """

    def __init__(self, **config) -> None:
        """
        Read file in /etc/hosts format

        Inputs:
            **config: Supported keys
              - file_path (str): Path to the `hosts` file

        Outputs:
            None
        """
        super().__init__(**config)

        # Configuration
        self.file_path: str = self.config.get("file_path", "/etc/hosts")
        self._load_hosts()

    def _load_hosts(self) -> None:
        """
        Read the system hosts file (/etc/hosts) and return a dictionary
        mapping each domain name to its corresponding IP address.

        The hosts file may contain comments and multiple domain names per IP.
        Only the first IP per line is used for the mapping.

        Returns:
        A dictionary where keys are domain names and values are IP addresses.
        """
        hosts_path = pathlib.Path(self.file_path)
        mapping: Dict[str, str] = {}

        with hosts_path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                for domain in parts[1:]:
                    mapping[domain] = ip
        self.hosts = mapping

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Decide whether to deny the query based on stored mode.

        Inputs:
            qname: Queried domain name.
            qtype: DNS record type (unused).
            req: Raw DNS request bytes (unused).
            ctx: Plugin context.
        Outputs:
            PluginDecision("override") when domain is mapped, None to continue

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
        qname = str(request.q.qname).rstrip(".")

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

    ## def _make_a_response(
    ##     self, qname: str, query_type: int, raw_req: bytes, ctx: PluginContext, ipaddr: str
    ## ) -> bytes:
    ##     """
    ##     Return a DNS response that carries the original transaction ID,
    ##     but with the payload replaced.
    ##     """
    ##     print("make repo")
    ##     try:
    ##         request = DNSRecord.parse(raw_req)
    ##     except Exception as e:
    ##         logger.warning("parse failure: %s", e)
    ##         return None

    ##     qname = str(request.q.qname)
    ##     if qname not in self.hosts:
    ##         logger.debug("unknown query: %s", qname)
    ##         return None

    ##     ip = self.hosts[qname]
    ##     logger.debug("resolve %s -> %s", qname, ip)

    ##     reply = DNSRecord(
    ##         DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
    ##         q=request.
    ##     )

    ##     reply.add_answer(
    ##         RR(rname=req.q.qname, rtype=QTYPE.A, rclass=1, ttl=65, rdata=A(ip))
    ##     )

    ##     return reply.pack()
