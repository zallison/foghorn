from __future__ import annotations

import ipaddress
import logging
from typing import List, Literal

from dnslib import QTYPE, DNSRecord
from pydantic import BaseModel, ConfigDict, Field

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

logger = logging.getLogger(__name__)

_DEFAULT_PRIVATE_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)


class DnsRebindingConfig(BaseModel):
    """Brief: Typed configuration model for DnsRebinding.

    Inputs:
      - allowlist_domains: Domain names allowed to resolve to private addresses.
      - allowlist_mode: Domain matching mode ('suffix' or 'exact').
      - private_cidrs: CIDRs treated as private/rebinding-sensitive.

    Outputs:
      - DnsRebindingConfig instance with normalized field types.
    """

    allowlist_domains: List[str] = Field(default_factory=list)
    allowlist_mode: Literal["suffix", "exact"] = Field(default="suffix")
    private_cidrs: List[str] = Field(
        default_factory=lambda: list(_DEFAULT_PRIVATE_CIDRS)
    )

    model_config = ConfigDict(extra="allow")


@plugin_aliases("dns_rebinding", "no_rebinding", "rebinding")
class DnsRebinding(BasePlugin):
    """Brief: Deny private A/AAAA answers for non-allowlisted public names.

    Inputs:
      - Plugin config from DnsRebindingConfig plus BasePlugin options.

    Outputs:
      - PluginDecision(action='deny') for rebinding-like answers, otherwise skip/None.
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - DnsRebindingConfig class for use by the core config loader.
        """

        return DnsRebindingConfig

    def setup(self) -> None:
        """Brief: Parse allowlist and private CIDR configuration for runtime checks.

        Inputs:
          - None (reads configuration from self.config).

        Outputs:
          - None (initializes parsed allowlist domains and private CIDR networks).
        """

        self._allowlist_mode = (
            str(self.config.get("allowlist_mode", "suffix") or "suffix").strip().lower()
        )
        if self._allowlist_mode not in {"suffix", "exact"}:
            logger.warning(
                "DnsRebinding: invalid allowlist_mode %r; defaulting to 'suffix'",
                self._allowlist_mode,
            )
            self._allowlist_mode = "suffix"

        self._allowlist_domains = self._normalize_allowlist_domains(
            self.config.get("allowlist_domains", [])
        )
        self._private_networks = self._parse_private_networks(
            self.config.get("private_cidrs", list(_DEFAULT_PRIVATE_CIDRS))
        )

    @staticmethod
    def _normalize_allowlist_domains(raw_domains: object) -> List[str]:
        """Brief: Normalize allowlist domain configuration into canonical names.

        Inputs:
          - raw_domains: Domain list value (string or list-like).

        Outputs:
          - list[str]: Lower-cased domains without trailing dots.
        """

        if isinstance(raw_domains, str):
            candidates = [raw_domains]
        elif isinstance(raw_domains, (list, tuple, set)):
            candidates = [str(v) for v in raw_domains]
        else:
            candidates = []

        out: List[str] = []
        for candidate in candidates:
            normalized = BasePlugin.normalize_qname(
                candidate, lower=True, strip_trailing_dot=True
            )
            if normalized:
                out.append(normalized)
        return out

    @staticmethod
    def _parse_private_networks(
        raw_cidrs: object,
    ) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Brief: Parse private CIDR strings into ipaddress network objects.

        Inputs:
          - raw_cidrs: CIDR list value (string or list-like).

        Outputs:
          - list[IPv4Network | IPv6Network]: Parsed networks; invalid entries are skipped.
        """

        if isinstance(raw_cidrs, str):
            candidates = [raw_cidrs]
        elif isinstance(raw_cidrs, (list, tuple, set)):
            candidates = [str(v) for v in raw_cidrs]
        else:
            logger.warning(
                "DnsRebinding: invalid private_cidrs %r; using defaults",
                raw_cidrs,
            )
            candidates = list(_DEFAULT_PRIVATE_CIDRS)

        networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in candidates:
            text = str(cidr).strip()
            if not text:
                continue
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError:
                logger.warning(
                    "DnsRebinding: skipping invalid private_cidrs entry %r", text
                )
                continue
            networks.append(network)

        if not networks:
            networks = [
                ipaddress.ip_network(cidr, strict=False)
                for cidr in _DEFAULT_PRIVATE_CIDRS
            ]
        return networks

    def _is_allowlisted(self, qname: str) -> bool:
        """Brief: Return True when qname matches the configured allowlist.

        Inputs:
          - qname: Queried domain name.

        Outputs:
          - bool indicating whether the query is allowlisted.
        """

        if not self._allowlist_domains:
            return False

        query_name = BasePlugin.normalize_qname(
            qname, lower=True, strip_trailing_dot=True
        )
        if not query_name:
            return False

        if self._allowlist_mode == "exact":
            return query_name in self._allowlist_domains

        return any(
            query_name == allow_domain or query_name.endswith("." + allow_domain)
            for allow_domain in self._allowlist_domains
        )

    def _is_private_answer_ip(
        self, ip_value: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> bool:
        """Brief: Check whether an answer IP falls inside configured private CIDRs.

        Inputs:
          - ip_value: Parsed answer address.

        Outputs:
          - bool indicating whether the address is in a configured private CIDR.
        """

        return any(ip_value in network for network in self._private_networks)

    def post_resolve(
        self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext
    ) -> PluginDecision | None:
        """Brief: Deny DNS answers with private A/AAAA addresses for public names.

        Inputs:
          - qname: Queried domain name.
          - qtype: Query type.
          - response_wire: Upstream DNS response bytes.
          - ctx: PluginContext carrying request metadata.

        Outputs:
          - PluginDecision(action='deny') when a rebinding-style answer is detected.
          - PluginDecision(action='skip') when no policy violation is detected.
          - None when BasePlugin targeting excludes the request.
        """

        if not self.targets(ctx):
            return None
        if not self.targets_qtype(qtype):
            return None
        if self._is_allowlisted(qname):
            return self._decision(action="skip")

        try:
            response = DNSRecord.parse(response_wire)
        except Exception as exc:
            logger.warning(
                "DnsRebinding: failed parsing response for %s from %s: %s",
                qname,
                getattr(ctx, "client_ip", "unknown"),
                exc,
            )
            return self._decision(action="skip")

        private_hits: List[str] = []
        for record in response.rr:
            if record.rtype not in (QTYPE.A, QTYPE.AAAA):
                continue
            try:
                answer_ip = ipaddress.ip_address(str(record.rdata))
            except ValueError:
                continue
            if self._is_private_answer_ip(answer_ip):
                private_hits.append(str(answer_ip))

        if not private_hits:
            return self._decision(action="skip")

        logger.info(
            "DnsRebinding: denied %s for private answers [%s]",
            qname,
            ", ".join(private_hits),
        )
        return self._decision(
            action="deny",
            stat="dns_rebinding",
            ede_code=15,
            ede_text="blocked potential dns rebinding response",
        )
