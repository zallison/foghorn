from __future__ import annotations
from typing import Optional, Union, List
import logging

from dnslib import DNSRecord, QTYPE, A, AAAA
from .base import BasePlugin, PluginDecision, PluginContext
from foghorn.plugins.base import BasePlugin, plugin_aliases

logger = logging.getLogger(__name__)


@plugin_aliases("examples")
class ExamplesPlugin(BasePlugin):
    """
    Deny over-deep or too-long domains pre-resolve; rewrite the first IPv4 A answer post-resolve.

    Args:
        config: Configuration dict with the following keys:
            - max_subdomains (int, default 5): Deny if subdomains > max_subdomains.
            - max_length_no_dots (int, default 50): Deny if length excluding dots > threshold.
            - base_labels (int, default 2): Rightmost labels treated as the base domain (e.g., example.com).
            - apply_to_qtypes (list[str], default ["*"]): Qtypes to which pre-resolve filtering applies ("*" = all).
            - rewrite_first_ipv4 (list[dict], default []): List of IP rewrite rules, each with:
                - apply_to_qtypes (list[str]): Query types this rule applies to
                - ip_override (str): IP address to inject into the first A RR

    Returns:
        Initialized plugin instance.

    Example usage (YAML):
        plugins:
          - module: examples | foghorn.plugins.examples.ExamplesPlugin
            config:
              max_subdomains: 5
              max_length_no_dots: 50
              base_labels: 2
              apply_to_qtypes: ["A","AAAA"]
              rewrite_first_ipv4:
                - apply_to_qtypes: ["A"]
                  ip_override: 127.0.0.1
                - apply_to_qtypes: ["AAAA"]
                  ip_override: ::1

    Behavior:
        - a.b.c.d.e.f.example.com -> 6 subdomains -> denied pre-resolve.
        - Domains with > 50 non-dot characters -> denied pre-resolve.
        - A responses: first A RR is rewritten per matching rewrite rules.
    """

    def __init__(self, **config) -> None:
        """
        Initialize plugin with provided config or defaults.

        Args:
            **config: Configuration keys as described in the class docstring.

        Returns:
            None
        """
        super().__init__(**config)
        self.max_subdomains = int(self.config.get("max_subdomains", 5))
        self.max_length_no_dots = int(self.config.get("max_length_no_dots", 50))
        self.base_labels = int(self.config.get("base_labels", 2))
        self.apply_to_qtypes: List[str] = [
            str(s).upper() for s in self.config.get("apply_to_qtypes", ["*"])
        ]

        # Parse rewrite rules - each rule has its own qtypes and override IP
        self.rewrite_rules: List[dict] = []
        rewrite_config = self.config.get("rewrite_first_ipv4", [])
        if isinstance(rewrite_config, list):
            for rule in rewrite_config:
                if isinstance(rule, dict):
                    qtypes = [
                        str(s).upper() for s in rule.get("apply_to_qtypes", ["*"])
                    ]
                    ip = str(rule.get("ip_override", "127.0.0.1"))
                    self.rewrite_rules.append(
                        {"apply_to_qtypes": qtypes, "ip_override": ip}
                    )

    def _qtype_name(self, qtype: Union[int, str]) -> str:
        """
        Normalize qtype to its uppercase mnemonic.

        Args:
            qtype: int (QTYPE) or str name.

        Returns:
            Uppercase qtype name (e.g., "A"), or string form if unknown.
        """
        if isinstance(qtype, int):
            return QTYPE.get(qtype, str(qtype))
        return str(qtype).upper()

    def _applies(self, qtype: Union[int, str]) -> bool:
        """
        Check if this plugin should run for the given qtype per config.

        Args:
            qtype: int or str query type.

        Returns:
            True if applies to this qtype.
        """
        name = self._qtype_name(qtype)
        return "*" in self.apply_to_qtypes or name in self.apply_to_qtypes

    def _rule_applies(self, rule: dict, qtype: Union[int, str]) -> bool:
        """
        Check if a specific rewrite rule applies to the given qtype.

        Args:
            rule: Rewrite rule dict with apply_to_qtypes key.
            qtype: int or str query type.

        Returns:
            True if rule applies to this qtype.
        """
        name = self._qtype_name(qtype)
        rule_qtypes = rule.get("apply_to_qtypes", ["*"])
        return "*" in rule_qtypes or name in rule_qtypes

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Deny requests with too many subdomains or excessive length (excluding dots).

        Args:
            qname: Domain name object/str from dnslib; will be stringified.
            qtype: Query type (int/str).
            ctx: PluginContext (e.g., client_ip).

        Returns:
            PluginDecision("deny") to block, or None to allow.

        Example:
            >>> from foghorn.plugins.examples import ExamplesPlugin
            >>> from foghorn.plugins.base import PluginContext
            >>> plugin = ExamplesPlugin()
            >>> ctx = PluginContext("1.2.3.4")
            >>> decision = plugin.pre_resolve("a.b.c.d.e.f.example.com", 1, ctx)
            >>> decision.action
            'deny'
        """
        try:
            name = str(qname).rstrip(".")
        except Exception:
            name = str(qname)

        if not self._applies(qtype):
            return None

        subdomains = _count_subdomains(name, self.base_labels)
        length_no_dots = _length_without_dots(name)

        if subdomains > self.max_subdomains:
            logger.info(
                "ExamplesPlugin deny: %s has %d subdomains > %d",
                name,
                subdomains,
                self.max_subdomains,
            )
            return PluginDecision(action="deny")

        if length_no_dots > self.max_length_no_dots:
            logger.info(
                "ExamplesPlugin deny: %s length_no_dots=%d > %d",
                name,
                length_no_dots,
                self.max_length_no_dots,
            )
            return PluginDecision(action="deny")

        return None

    def post_resolve(
        self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Rewrite the first A or AAAA RR in the answer using matching rewrite rules.

        Args:
            qname: Domain name object/str.
            qtype: Query type (int/str).
            response_wire: Bytes of the DNS response to potentially modify.
            ctx: PluginContext.

        Returns:
            PluginDecision("override", response=bytes) if modified; otherwise None.

        Example:
            If upstream returns A answers [93.184.216.34, 93.184.216.35] and there's a
            matching rewrite rule, this writes the rule's ip_override into the first A RR only.
        """
        if not self.rewrite_rules:
            return None

        # Find the first matching rewrite rule for this qtype
        matching_rule = None
        for rule in self.rewrite_rules:
            if self._rule_applies(rule, qtype):
                matching_rule = rule
                break

        if not matching_rule:
            return None

        try:
            reply = DNSRecord.parse(response_wire)
        except Exception as e:
            logger.warning("ExamplesPlugin parse failure: %s", e)
            return None

        changed = False
        for rr in reply.rr:
            if rr.rtype == QTYPE.A:
                ip_override = matching_rule["ip_override"]
                rr.rdata = A(ip_override)
                changed = True
                logger.debug(
                    "ExamplesPlugin rewrite: first A record -> %s", ip_override
                )
                break
            elif rr.rtype == QTYPE.AAAA:
                ip_override = matching_rule["ip_override"]
                rr.rdata = AAAA(ip_override)
                changed = True
                logger.debug(
                    "ExamplesPlugin rewrite: first AAAA record -> %s", ip_override
                )
                break

        if changed:
            try:
                return PluginDecision(action="override", response=reply.pack())
            except Exception as e:
                logger.warning("ExamplesPlugin pack failure: %s", e)
                return None

        return None


def _count_subdomains(qname: str, base_labels: int = 2) -> int:
    """
    Count subdomains as label_count - base_labels (never below 0).

    Args:
        qname: Fully-qualified domain name (string); trailing dot allowed.
        base_labels: Number of rightmost labels considered the base domain (default 2, e.g., example.com).

    Returns:
        Count of subdomain labels (>= 0).

    Example:
        >>> _count_subdomains('a.b.c.example.com')
        3
        >>> _count_subdomains('a.b.c.d.e.f.example.com')
        6
    """
    name = qname.rstrip(".")
    if not name:
        return 0
    labels = [p for p in name.split(".") if p]
    return max(0, len(labels) - int(base_labels))


def _length_without_dots(qname: str) -> int:
    """
    Compute domain length excluding dots.

    Args:
        qname: Domain name string (may include a trailing dot).

    Returns:
        Count of all characters excluding '.'.

    Example:
        >>> _length_without_dots('ab.cd.com')
        7
    """
    # Remove final trailing dot first (if any), then count non-dot characters
    s = qname.rstrip(".")
    return len(s.replace(".", ""))
