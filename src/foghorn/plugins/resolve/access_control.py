from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from typing import Dict, List, Optional

from dnslib import QTYPE, RCODE, DNSRecord
from pydantic import BaseModel, Field, ConfigDict

from .base import (
    AdminPageSpec,
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)
from foghorn.utils import ip_networks

logger = logging.getLogger(__name__)


@lru_cache(maxsize=2048)
def _parse_client_ip(client_ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Brief: Parse and cache client IPs for AccessControl hot-path lookups.

    Inputs:
      - client_ip: Client IP string (IPv4 or IPv6).

    Outputs:
      - ipaddress.IPv4Address | ipaddress.IPv6Address: Parsed address object.

    Notes:
      - This keeps per-query overhead low when many requests repeat the same
        client IPs.
    """
    parsed = ip_networks.parse_ip(client_ip)
    if parsed is None:
        raise ValueError(f"invalid client ip {client_ip!r}")
    return parsed


class AccessControlConfig(BaseModel):
    """Brief: Typed configuration model for AccessControl used for startup validation.

    Inputs:
      - default: Default policy ("allow" or "deny").
      - allow: List of CIDR/IP strings to allow.
      - deny: List of CIDR/IP strings to deny.
      - deny_response: Response code when denying ('nxdomain', 'refused', 'servfail',
        'noerror_empty'/'nodata', 'ip', or 'drop').

    Outputs:
      - AccessControlConfig instance with normalized types.
    """

    default: str = Field(default="allow")
    allow: List[str] = Field(default_factory=list)
    deny: List[str] = Field(default_factory=list)
    deny_response: str = Field(default="refused")

    model_config = ConfigDict(extra="allow")


@plugin_aliases("acl", "access_control")
class AccessControl(BasePlugin):
    """
    A plugin that provides access control based on client IP addresses.

    Example use:
        In config.yaml:
        plugins:
          - module: foghorn.plugins.access_control.AccessControl
            config:
              default: deny
              allow:
                - 192.168.1.0/24
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - AccessControlConfig class for use by the core config loader.
        """

        return AccessControlConfig

    def setup(self, **config):
        """Brief: Initialize AccessControl network rules and deny-response policy.

        Inputs:
          - default (str, optional): "allow" or "deny".
          - allow (list[str], optional): CIDR/IP strings to allow.
          - deny (list[str], optional): CIDR/IP strings to deny.
          - deny_response (str, optional): One of: nxdomain, refused, servfail,
            noerror_empty/nodata, ip, drop.
          - deny_response_ip4 (str, optional): IPv4 for deny_response="ip".
          - deny_response_ip6 (str, optional): IPv6 for deny_response="ip".
          - ttl (int, optional): TTL used for synthesized A responses.

        Outputs:
          - None

        Example:
          >>> plugin = AccessControl(default='deny', deny_response='refused')
          >>> plugin.setup()
          >>> plugin.default
          'deny'
        """

        self.default = str(self.config.get("default", "allow") or "allow").lower()
        if self.default not in {"allow", "deny"}:
            logger.warning(
                "AccessControl: invalid default %r; using 'allow'", self.default
            )
            self.default = "allow"

        def _parse_network_or_raise(value: object) -> ipaddress._BaseNetwork:
            net = ip_networks.parse_network(value)
            if net is None:
                raise ValueError(f"invalid network {value!r}")
            return net

        self.allow_nets = [
            _parse_network_or_raise(n) for n in self.config.get("allow", [])
        ]
        self.deny_nets = [
            _parse_network_or_raise(n) for n in self.config.get("deny", [])
        ]

        deny_resp = str(
            self.config.get("deny_response", "refused") or "refused"
        ).lower()
        valid_deny = {
            "nxdomain",
            "refused",
            "servfail",
            "noerror_empty",
            "nodata",
            "ip",
            "drop",
        }
        if deny_resp not in valid_deny:
            logger.warning(
                "AccessControl: unknown deny_response %r; defaulting to 'refused'",
                deny_resp,
            )
            deny_resp = "refused"
        self.deny_response = deny_resp

        # Optional IP-mode parameters (AccessControlConfig permits extras).
        self.deny_response_ip4 = self.config.get("deny_response_ip4")
        self.deny_response_ip6 = self.config.get("deny_response_ip6")

        # Used by BasePlugin._make_a_response for A records.
        try:
            self._ttl = int(self.config.get("ttl", 60))
        except (TypeError, ValueError):  # pragma: no cover - defensive
            self._ttl = 60

    def _build_deny_decision(
        self, qname: str, qtype: int, raw_req: bytes, ctx: PluginContext
    ) -> PluginDecision:
        """Brief: Build a PluginDecision for an access-control deny.

        Inputs:
          - qname: Queried domain name.
          - qtype: DNS query type integer.
          - raw_req: Raw DNS request bytes.
          - ctx: PluginContext.

        Outputs:
          - PluginDecision with one of:
              * action="deny" (NXDOMAIN via core server) when deny_response == 'nxdomain'
              * action="drop" when deny_response == 'drop'
              * action="override" with a synthesized response when deny_response is
                refused/servfail/noerror_empty/nodata/ip
        """

        mode = str(getattr(self, "deny_response", "refused") or "refused").lower()
        if mode == "drop":
            return self._decision(action="drop", stat="access_control")

        if mode == "nxdomain":
            return self._decision(action="deny", stat="access_control")

        if mode in {"refused", "servfail", "noerror_empty", "nodata"}:
            try:
                request = DNSRecord.parse(raw_req)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "AccessControl: failed to parse request while building deny response: %s",
                    exc,
                )
                return self._decision(action="deny", stat="access_control")

            reply = request.reply()
            if mode == "refused":
                reply.header.rcode = RCODE.REFUSED
            elif mode == "servfail":
                reply.header.rcode = RCODE.SERVFAIL
            else:
                reply.header.rcode = RCODE.NOERROR
                reply.rr = []

            return self._decision(
                action="override",
                response=reply.pack(),
                stat="access_control",
            )

        if mode == "ip":
            ipaddr: Optional[str] = None
            if qtype == QTYPE.A and getattr(self, "deny_response_ip4", None):
                ipaddr = str(self.deny_response_ip4)
            elif qtype == QTYPE.AAAA and getattr(self, "deny_response_ip6", None):
                ipaddr = str(self.deny_response_ip6)
            elif getattr(self, "deny_response_ip4", None) or getattr(
                self, "deny_response_ip6", None
            ):
                ipaddr = str(
                    getattr(self, "deny_response_ip4", None)
                    or getattr(self, "deny_response_ip6", None)
                )

            if ipaddr:
                wire = self._make_a_response(qname, qtype, raw_req, ctx, ipaddr)
                if wire is not None:
                    return self._decision(
                        action="override",
                        response=wire,
                        stat="access_control",
                    )

        # Fallback: NXDOMAIN-style deny.
        return self._decision(action="deny", stat="access_control")

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Enforce allow/deny lists and default policy for client IPs.

        Inputs:
          - qname: The queried domain name.
          - qtype: The DNS query type.
          - req: The raw DNS request.
          - ctx: The plugin context.

        Outputs:
          - Optional[PluginDecision]:
              * None to continue normal processing
              * PluginDecision("override"/"deny"/"drop") when blocked
              * PluginDecision("allow") when the default policy is allow
        """

        if not self.targets(ctx):
            return None

        ip = _parse_client_ip(str(ctx.client_ip))

        # Deny takes precedence.
        for n in self.deny_nets:
            if ip in n:
                logger.warning(
                    "Access denied for %s (deny rule: %s)", ctx.client_ip, str(n)
                )
                return self._build_deny_decision(qname, qtype, req, ctx)

        for n in self.allow_nets:
            if ip in n:
                logger.debug(
                    "Access allowed for %s (allow rule: %s)", ctx.client_ip, str(n)
                )
                return None

        logger.debug("Access %s for %s (default policy)", self.default, ctx.client_ip)
        if self.default == "deny":
            return self._build_deny_decision(qname, qtype, req, ctx)
        return self._decision(action="allow")

    def get_admin_pages(self) -> List[AdminPageSpec]:
        """Brief: Describe the AccessControl admin page for the web UI.

        Inputs:
          - None; uses the plugin instance name for routing.

        Outputs:
          - list[AdminPageSpec]: A single page descriptor for access control rules.
        """

        return [
            AdminPageSpec(
                slug="access-control",
                title="Access Control",
                description=(
                    "Access control rules configured for this AccessControl instance."
                ),
                layout="one_column",
                kind="access_control",
            )
        ]

    def get_admin_ui_descriptor(self) -> Dict[str, object]:
        """Brief: Describe AccessControl admin UI using a generic snapshot layout.

        Inputs:
          - None (uses the plugin instance name for routing).

        Outputs:
          - dict with keys:
              * name: Effective plugin instance name.
              * title: Human-friendly tab title.
              * order: Integer ordering hint among plugin tabs.
              * endpoints: Mapping with at least a "snapshot" URL.
              * layout: Generic section/column description for the frontend.
        """

        plugin_name = getattr(self, "name", "access_control")
        snapshot_url = f"/api/v1/plugins/{plugin_name}/access_control"
        base_title = "Access Control"
        title = f"{base_title} ({plugin_name})" if plugin_name else base_title

        layout: Dict[str, object] = {
            "sections": [
                {
                    "id": "policy",
                    "title": "Policy",
                    "type": "kv",
                    "path": "policy",
                    "rows": [
                        {"key": "default", "label": "Default"},
                        {"key": "deny_response", "label": "Deny response"},
                        {"key": "allow_rules", "label": "Allow rules"},
                        {"key": "deny_rules", "label": "Deny rules"},
                    ],
                },
                {
                    "id": "config",
                    "title": "Config",
                    "type": "table",
                    "path": "config_items",
                    "columns": [
                        {"key": "key", "label": "Key"},
                        {"key": "value", "label": "Value"},
                    ],
                },
            ]
        }

        return {
            "name": str(plugin_name),
            "title": str(title),
            "order": 80,
            "endpoints": {"snapshot": snapshot_url},
            "layout": layout,
        }

    def get_http_snapshot(self) -> Dict[str, object]:
        """Brief: Summarize AccessControl configuration and derived rule counts.

        Inputs:
          - None (reads plugin config and parsed allow/deny networks).

        Outputs:
          - dict with keys:
              * summary/config_items (from BasePlugin.get_http_snapshot)
              * policy: derived policy details
        """

        snapshot = super().get_http_snapshot()

        allow_nets = getattr(self, "allow_nets", []) or []
        deny_nets = getattr(self, "deny_nets", []) or []

        def _safe_len(value: object) -> int:
            try:
                return len(value)  # type: ignore[arg-type]
            except Exception:
                return 0

        snapshot["policy"] = {
            "default": str(
                getattr(self, "default", self.config.get("default", "allow"))
            ),
            "deny_response": str(
                getattr(
                    self, "deny_response", self.config.get("deny_response", "refused")
                )
            ),
            "allow_rules": int(_safe_len(allow_nets)),
            "deny_rules": int(_safe_len(deny_nets)),
        }
        return snapshot
