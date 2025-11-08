from __future__ import annotations
import logging
import ipaddress
import secrets
import random
from typing import List, Optional, Union

from dnslib import DNSRecord, RCODE, QTYPE

from .base import BasePlugin, PluginDecision, PluginContext, plugin_aliases

logger = logging.getLogger(__name__)


@plugin_aliases("flaky_server", "flaky", "buggy")
class FlakyServer(BasePlugin):
    """
    Brief: Simulate an unreliable server by randomly returning SERVFAIL or NXDOMAIN for specific clients.

    Inputs:
      - config (dict):
        - allow (list[str] | str | None): List of CIDR/IPs (or a single string) to target. If omitted/empty, the plugin is a no-op.
        - client_ip (str | None): Single client IP to target (shorthand). Combined with "allow" if both are provided.
        - servfail_one_in (int, default 4): Probability denominator for SERVFAIL (1 in N). Minimum 1.
        - nxdomain_one_in (int, default 10): Probability denominator for NXDOMAIN (1 in N). Minimum 1.
        - apply_to_qtypes (list[str], default ["*"]): Qtypes to affect (e.g., ["A","AAAA"]). "*" means all.
        - seed (int | None, default None): If provided, decisions become deterministic for testing.
        - pre_priority/post_priority/priority (int): Standard BasePlugin priority knobs. Default pre=15.

    Outputs:
      - Initialized plugin instance that may short-circuit requests in pre_resolve with SERVFAIL or NXDOMAIN.

    Non-trivial behavior:
      - Targeting: Only applies when the requestor's ctx.client_ip matches any configured allow entry or equals client_ip.
      - Precedence: SERVFAIL draw is evaluated first; if it triggers, NXDOMAIN is not considered.
      - Determinism: Set seed for repeatable tests; otherwise cryptographically-strong randomness is used.

    Example usage (YAML):
      plugins:
        - name: flaky_server
          pre_priority: 15
          config:
            allow: ["192.0.2.0/24", "2001:db8::/32"]
            # or: client_ip: 192.0.2.55
            servfail_one_in: 4
            nxdomain_one_in: 10
            seed: 12345
    """

    # Default: run relatively early in pre chain
    pre_priority: int = 15

    def __init__(self, **config) -> None:
        """
        Brief: Parse and normalize configuration for flakiness decisions.

        Inputs:
          - **config: See class docstring for keys.

        Outputs:
          - None (sets instance attributes)

        Example:
          >>> FlakyServer(allow=["10.0.0.0/8"], servfail_one_in=2, nxdomain_one_in=3)
        """
        super().__init__(**config)

        self._allow_networks: List[
            Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
        ] = []

        # Collect targets from allow and/or client_ip
        allow_cfg = config.get("allow")
        client_ip = config.get("client_ip")

        # Normalize allow to list[str]
        if isinstance(allow_cfg, str):
            allow_list = [allow_cfg]
        elif isinstance(allow_cfg, list):
            allow_list = [str(x) for x in allow_cfg]
        elif allow_cfg is None:
            allow_list = []
        else:
            logger.warning("FlakyServer: ignoring invalid 'allow' value: %r", allow_cfg)
            allow_list = []

        if client_ip:
            allow_list.append(str(client_ip))

        for entry in allow_list:
            try:
                # ip_network handles both single IPs and CIDRs (strict=False allows host bits set)
                net = ipaddress.ip_network(entry, strict=False)
                self._allow_networks.append(net)
            except Exception as e:
                logger.warning(
                    "FlakyServer: skipping invalid allow entry %r: %s", entry, e
                )

        # If no allow targets are configured, plugin becomes a no-op
        if not self._allow_networks:
            logger.info("FlakyServer: no targets configured; plugin will be a no-op")

        # Probabilities with clamping
        self.servfail_one_in = self._clamp_one_in(
            config.get("servfail_one_in", 4), key="servfail_one_in"
        )
        self.nxdomain_one_in = self._clamp_one_in(
            config.get("nxdomain_one_in", 10), key="nxdomain_one_in"
        )

        # Qtype filter
        raw_qtypes = config.get("apply_to_qtypes", ["*"])
        if isinstance(raw_qtypes, list) and raw_qtypes:
            self.apply_to_qtypes = [str(x).upper() for x in raw_qtypes]
        else:
            self.apply_to_qtypes = ["*"]

        # RNG
        seed = config.get("seed")
        if seed is not None:
            try:
                self._rng: Union[random.Random, secrets.SystemRandom] = random.Random(
                    int(seed)
                )
            except Exception:
                logger.warning("FlakyServer: bad seed %r; using SystemRandom()", seed)
                self._rng = secrets.SystemRandom()
        else:
            self._rng = secrets.SystemRandom()

    @staticmethod
    def _clamp_one_in(value, key: str) -> int:
        """
        Brief: Coerce a 1-in-N value to int and clamp to >=1.

        Inputs:
          - value: Any, intended to represent an integer N
          - key: str, config key name for logging context

        Outputs:
          - int: N >= 1
        """
        try:
            n = int(value)
        except Exception:
            logger.warning("FlakyServer: %s non-integer %r -> default to 1", key, value)
            return 1
        if n < 1:
            logger.warning("FlakyServer: %s < 1 (%d); clamping to 1", key, n)
            return 1
        return n

    def _is_target_client(self, ip: str) -> bool:
        """
        Brief: Check if the client IP is within any configured allow network.

        Inputs:
          - ip (str): Client IP address from PluginContext.client_ip

        Outputs:
          - bool: True if targeted, else False

        Example:
          >>> p = FlakyServer(allow=["192.0.2.0/24"])  # doctest: +SKIP
          >>> p._is_target_client("192.0.2.55")  # doctest: +SKIP
          True
        """
        if not self._allow_networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        return any(addr in net for net in self._allow_networks)

    def _is_target_qtype(self, qtype: Union[int, str]) -> bool:
        """
        Brief: Check if the query type matches the configured apply_to_qtypes set.

        Inputs:
          - qtype (int|str): DNS RR type

        Outputs:
          - bool: True if applies, else False
        """
        if not self.apply_to_qtypes:
            return True
        if "*" in self.apply_to_qtypes:
            return True
        name = (
            QTYPE.get(qtype, str(qtype))
            if isinstance(qtype, int)
            else str(qtype).upper()
        )
        return name in self.apply_to_qtypes

    def _make_response(self, req_wire: bytes, rcode: int) -> Optional[bytes]:
        """
        Brief: Build a minimal reply with the same ID and desired rcode.

        Inputs:
          - req_wire (bytes): Original DNS request wire bytes
          - rcode (int): dnslib.RCODE value (e.g., RCODE.SERVFAIL)

        Outputs:
          - bytes | None: Packed DNS response wire, or None if parse fails
        """
        try:
            req = DNSRecord.parse(req_wire)
            rep = req.reply()
            rep.header.rcode = rcode
            return rep.pack()
        except Exception as e:
            logger.debug("FlakyServer: failed to synthesize response: %s", e)
            return None

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Brief: Randomly override matching client requests with SERVFAIL or NXDOMAIN.

        Inputs:
          - qname (str): Query name
          - qtype (int): Query type
          - req (bytes): Raw DNS request wire
          - ctx (PluginContext): Contains client_ip

        Outputs:
          - PluginDecision | None: override with SERVFAIL/NXDOMAIN or None to continue normal flow

        Example:
          >>> # For a targeted client, force 1-in-1 SERVFAIL
          >>> p = FlakyServer(client_ip="192.0.2.55", servfail_one_in=1, nxdomain_one_in=10, seed=1)  # doctest: +SKIP
          >>> # decision = p.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.55"))
        """
        # Quick exits
        if not self._is_target_client(getattr(ctx, "client_ip", "")):
            return None
        if not self._is_target_qtype(qtype):
            return None

        # Draw SERVFAIL first (precedence over NXDOMAIN)
        try:
            if self._rng.randrange(self.servfail_one_in) == 0:
                wire = self._make_response(req, RCODE.SERVFAIL)
                if wire is not None:
                    return PluginDecision(action="override", response=wire)
        except Exception as e:
            logger.debug("FlakyServer: SERVFAIL draw error: %s", e)

        # Then NXDOMAIN
        try:
            if self._rng.randrange(self.nxdomain_one_in) == 0:
                wire = self._make_response(req, RCODE.NXDOMAIN)
                if wire is not None:
                    return PluginDecision(action="override", response=wire)
        except Exception as e:
            logger.debug("FlakyServer: NXDOMAIN draw error: %s", e)

        return None
