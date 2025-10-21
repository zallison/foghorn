from __future__ import annotations
import ipaddress
from typing import List, Optional
from .base import BasePlugin, PluginDecision, PluginContext

class AccessControlPlugin(BasePlugin):
    def __init__(self, **config):
        super().__init__(**config)
        self.default = (self.config.get("default", "allow")).lower()
        self.allow_nets = [ipaddress.ip_network(n) for n in self.config.get("allow", [])]
        self.deny_nets = [ipaddress.ip_network(n) for n in self.config.get("deny", [])]

    def pre_resolve(self, qname: str, qtype: int, ctx: PluginContext) -> Optional[PluginDecision]:
        ip = ipaddress.ip_address(ctx.client_ip)
        # Deny takes precedence
        for n in self.deny_nets:
            if ip in n:
                return PluginDecision(action="deny")
        for n in self.allow_nets:
            if ip in n:
                return PluginDecision(action="allow")
        return PluginDecision(action=self.default)
