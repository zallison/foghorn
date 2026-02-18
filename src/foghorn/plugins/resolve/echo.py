from __future__ import annotations

from typing import Optional

from dnslib import DNSHeader, DNSRecord, QTYPE, RR, TXT

from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision


class EchoPlugin(BasePlugin):
    """Brief: Simple resolve plugin that echoes qname/qtype in a TXT answer."""

    def pre_resolve(
        self,
        qname: str,
        qtype: int,
        req: bytes,
        ctx: PluginContext,
    ) -> Optional[PluginDecision]:
        """Brief: Synthesize a TXT response containing the query name and type.

        Inputs:
          - qname: Queried domain name (string-like). The echoed value is
            normalized by stripping a trailing dot while preserving case.
          - qtype: DNS RR type as an integer code.
          - req: Raw DNS request wire bytes.
          - ctx: PluginContext describing the client and listener.

        Outputs:
          - PluginDecision(action="override", response=wire) with a packed DNS
            response containing a single TXT answer when the plugin targets the
            request and the request bytes can be parsed.
          - None when ctx is not targeted, or when req cannot be parsed.
        """
        if not self.targets(ctx):
            return None

        try:
            request = DNSRecord.parse(req)
        except Exception:
            return None

        name = BasePlugin.normalize_qname(qname, lower=False, strip_trailing_dot=True)
        qtype_name = BasePlugin.qtype_name(qtype)
        text = f"{name} {qtype_name}"

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
            q=request.q,
        )
        ttl = getattr(self.__class__, "ttl", 300)
        reply.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.TXT,
                rclass=1,
                ttl=ttl,
                rdata=TXT(text),
            ),
        )

        return PluginDecision(action="override", response=reply.pack())
