from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple

@dataclass
class PluginDecision:
    action: str  # "allow", "deny", or "override"
    response: Optional[bytes] = None

class PluginContext:
    def __init__(self, client_ip: str) -> None:
        self.client_ip = client_ip
        # Optional per-request upstream override (host, port)
        self.upstream_override: Optional[Tuple[str, int]] = None

class BasePlugin:
    def __init__(self, **config):
        self.config = config

    def pre_resolve(self, qname: str, qtype: int, ctx: PluginContext) -> Optional[PluginDecision]:
        return None

    def post_resolve(self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext) -> Optional[PluginDecision]:
        return None
