import logging
from ipaddress import ip_network, ip_address
from typing import List
from dnslib import DNSRecord, QTYPE, RCODE
from foghorn.plugins.base import BasePlugin, PluginDecision, PluginContext

logger = logging.getLogger(__name__)

class ResponseFilterPlugin(BasePlugin):
    """
    Filters DNS responses based on a blocklist of IPs/CIDRs.

    Config:
      mode: "ip" | "domain"   # default: "ip"
      blocklist: [ "1.2.3.4", "198.51.100.0/24", "2001:db8::/32" ]
    """

    def __init__(self, **config):
        super().__init__(**config)
        mode = str(self.config.get("mode", "ip")).strip().lower()
        if mode not in ("ip", "domain"):
            raise ValueError("ResponseFilterPlugin.mode must be 'ip' or 'domain'")
        self.mode = mode

        raw = self.config.get("blocklist") or self.config.get("block_list") or []
        if not isinstance(raw, list):
            raise ValueError("ResponseFilterPlugin.blocklist must be a list")
        nets: List = []
        for item in raw:
            try:
                nets.append(ip_network(str(item), strict=False))
            except Exception as e:
                logger.warning("ResponseFilterPlugin: invalid blocklist entry '%s' - skipping (%s)", item, e)
        self.networks = nets

    def post_resolve(self, qname, qtype, response_wire: bytes, ctx: PluginContext):
        if not self.networks:
            return None
        try:
            reply = DNSRecord.parse(response_wire)
        except Exception as e:
            logger.error("ResponseFilterPlugin: failed to parse upstream reply: %s", e)
            return None

        if reply.header.rcode != RCODE.NOERROR:
            return None

        if self.mode == "ip":
            return self._filter_ip_mode(qname, reply, ctx)
        else:
            return self._filter_domain_mode(qname, reply, ctx)

    def _filter_ip_mode(self, qname, reply: DNSRecord, ctx: PluginContext):
        changed = False
        filtered_rr = []
        for rr in reply.rr:
            if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                try:
                    ip = ip_address(str(rr.rdata))
                except Exception:
                    filtered_rr.append(rr)
                    continue
                if any(ip in net for net in self.networks):
                    changed = True
                    logger.debug("ResponseFilterPlugin: filtering %s for %s (client=%s)", ip, qname, getattr(ctx, "client_ip", None))
                    continue
            filtered_rr.append(rr)

        if not changed:
            return None

        # If all A/AAAA were removed, deny the entire response (NXDOMAIN).
        any_ip_left = any(rr.rtype in (QTYPE.A, QTYPE.AAAA) for rr in filtered_rr)
        if not any_ip_left:
            logger.info("ResponseFilterPlugin: all IPs for %s are blocked; returning NXDOMAIN", qname)
            denied = self._nxdomain(reply)
            return PluginDecision(action="override", response=denied)

        reply.rr = filtered_rr
        return PluginDecision(action="override", response=reply.pack())

    def _filter_domain_mode(self, qname, reply: DNSRecord, ctx: PluginContext):
        for rr in reply.rr:
            if rr.rtype in (QTYPE.A, QTYPE.AAAA):
                try:
                    ip = ip_address(str(rr.rdata))
                except Exception:
                    continue
                if any(ip in net for net in self.networks):
                    logger.info("ResponseFilterPlugin: blocking domain %s due to blocked IP in answers; returning NXDOMAIN", qname)
                    denied = self._nxdomain(reply)
                    return PluginDecision(action="override", response=denied)
        return None

    @staticmethod
    def _nxdomain(reply: DNSRecord) -> bytes:
        # Preserve header id and question, set NXDOMAIN and clear sections.
        reply.header.rcode = RCODE.NXDOMAIN
        reply.rr = []
        reply.auth = []
        reply.ar = []
        return reply.pack()
