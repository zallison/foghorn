from __future__ import annotations

import logging
import random
import secrets
from typing import List, Optional, Union

from dnslib import QTYPE, RCODE, DNSRecord
from pydantic import BaseModel, Field

from .base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

logger = logging.getLogger(__name__)


class FlakyServerConfig(BaseModel):
    """Brief: Typed configuration model for FlakyServer.

    Inputs:
      - servfail_one_in / nxdomain_one_in: Legacy 1-in-N probabilities for
        SERVFAIL/NXDOMAIN (still accepted; converted to percentages).
      - servfail_percent / nxdomain_percent: Percent probabilities (0–100) for
        SERVFAIL/NXDOMAIN draws; override the legacy one-in-N fields when set.
      - timeout_percent: Percent probability (0–100) of dropping the query and
        sending no response (client observes a timeout).
      - truncate_percent: Percent probability (0–100) of setting the TC bit on
        responses to encourage client fallback to TCP.
      - formerr_percent: Percent probability (0–100) of replying with FORMERR
        instead of forwarding.
      - noerror_empty_percent: Percent probability (0–100) of replying with
        NOERROR and an empty answer section.
      - apply_to_qtypes: Qtypes this plugin applies to.
      - fuzz_percent: Percent of matching responses to fuzz at the byte level.
      - min_fuzz_bytes / max_fuzz_bytes: Bounds for how many bytes to mutate
        when fuzzing a response.
      - wrong_qtype_percent: Percent of matching responses whose question
        qtype is rewritten to a different RR type.
      - fuzz_actions: Fuzz primitives to use (e.g. ["bit_flip", "swap_bytes"]).
      - seed: Optional RNG seed.

    Outputs:
      - FlakyServerConfig instance with normalized field types.
    """

    servfail_percent: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    nxdomain_percent: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    timeout_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    truncate_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    formerr_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    noerror_empty_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    apply_to_qtypes: List[str] = Field(default_factory=lambda: ["*"])
    fuzz_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    min_fuzz_bytes: int = Field(default=1, ge=1)
    max_fuzz_bytes: int = Field(default=4, ge=1)
    wrong_qtype_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    fuzz_actions: List[str] = Field(default_factory=lambda: ["bit_flip", "swap_bytes"])
    seed: Optional[int] = None

    class Config:
        extra = "allow"


@plugin_aliases("flaky_server", "flaky", "buggy")
class FlakyServer(BasePlugin):
    """
    Brief: Simulate an unreliable server by randomly failing or corrupting
    responses for specific clients.

    Inputs:
      - config (dict):
        - targets / targets_ignore: BasePlugin targeting fields that control
          which client IPs this plugin applies to. When neither is configured,
          FlakyServer behaves as a no-op (for backwards compatibility with the
          previous allow/client_ip default).
        - servfail_percent / nxdomain_percent (float 0–100): Per-request
          probabilities of short-circuiting with SERVFAIL or NXDOMAIN. When not
          provided, legacy servfail_one_in/nxdomain_one_in 1-in-N fields are
          accepted and converted to equivalent percentages.
        - apply_to_qtypes (list[str], default ["*"]): Qtypes to affect (e.g.,
          ["A", "AAAA"]). "*" means all.
        - fuzz_percent (float 0–100, default 0): Chance to fuzz a matching
          upstream response at the byte level in post_resolve.
        - min_fuzz_bytes / max_fuzz_bytes (int): Minimum/maximum number of
          response bytes to mutate when fuzzing.
        - wrong_qtype_percent (float 0–100, default 0): Chance to rewrite the
          question qtype in the final response to a different RR type.
        - fuzz_actions (list[str]): Fuzz primitives to use; supported values are
          "bit_flip" and "swap_bytes".
        - seed (int | None, default None): If provided, decisions become
          deterministic for testing.
        - pre_priority/post_priority (int): Standard BasePlugin priority knobs.
          Default pre=15.

    Outputs:
      - Initialized plugin instance that may short-circuit requests in
        pre_resolve with SERVFAIL/NXDOMAIN and/or fuzz responses in post_resolve.

    Non-trivial behavior:
      - Targeting: Only applies when BasePlugin.targets(ctx) is True, i.e. the
        client is included by targets/targets_ignore configuration.
      - Precedence: SERVFAIL draw is evaluated first; if it triggers, NXDOMAIN
        is not considered.
      - Determinism: Set seed for repeatable tests; otherwise
        cryptographically-strong randomness is used.

    Example usage (YAML):
      plugins:
        - name: flaky_server
          pre_priority: 15
          config:
            targets: ["192.0.2.0/24", "2001:db8::/32"]
            servfail_percent: 25.0   # ~25% SERVFAIL
            nxdomain_percent: 10.0  # ~10% NXDOMAIN
            fuzz_percent: 5.0       # occasionally fuzz responses
            min_fuzz_bytes: 1
            max_fuzz_bytes: 4
            wrong_qtype_percent: 2.0
            seed: 12345
    """

    # Default: run relatively early in pre chain
    pre_priority: int = 15

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - FlakyServerConfig class for use by the core config loader.
        """

        return FlakyServerConfig

    def __init__(self, **config) -> None:
        """Brief: Parse and normalize configuration for flakiness decisions.

        Inputs:
          - **config: See class docstring for keys.

        Outputs:
          - None (sets instance attributes).

        Example:
          >>> FlakyServer(targets=["10.0.0.0/8"], servfail_percent=50.0)
        """
        super().__init__(**config)

        # Determine whether BasePlugin-level targets/targets_ignore were
        # configured. When neither is set, this plugin acts as a no-op so that
        # behaviour matches the previous allow/client_ip-default of "no
        # explicit targets -> no-op".
        self._has_base_targets = bool(
            getattr(self, "_target_networks", None)
            or getattr(self, "_ignore_networks", None)
        )
        if not self._has_base_targets:
            logger.info(
                "FlakyServer: no BasePlugin targets configured; plugin will be a no-op"
            )

        # Percent-based probabilities only; legacy 1-in-N fields are no longer
        # supported. Configs must use explicit percent values.
        self.servfail_prob = self._compute_probability(
            percent=config.get("servfail_percent"),
            one_in=None,
            percent_key="servfail_percent",
            one_in_key="servfail_one_in",
            default_percent=25.0,
        )
        self.nxdomain_prob = self._compute_probability(
            percent=config.get("nxdomain_percent"),
            one_in=None,
            percent_key="nxdomain_percent",
            one_in_key="nxdomain_one_in",
            default_percent=10.0,
        )

        # Additional percent-based behaviours.
        self.timeout_prob = (
            self._clamp_percent(
                config.get("timeout_percent", 0.0), key="timeout_percent"
            )
            / 100.0
        )
        self.truncate_prob = (
            self._clamp_percent(
                config.get("truncate_percent", 0.0), key="truncate_percent"
            )
            / 100.0
        )
        self.formerr_prob = (
            self._clamp_percent(
                config.get("formerr_percent", 0.0), key="formerr_percent"
            )
            / 100.0
        )
        self.noerror_empty_prob = (
            self._clamp_percent(
                config.get("noerror_empty_percent", 0.0), key="noerror_empty_percent"
            )
            / 100.0
        )

        # Qtype filter
        raw_qtypes = config.get("apply_to_qtypes", ["*"])
        if isinstance(raw_qtypes, list) and raw_qtypes:
            self.apply_to_qtypes = [str(x).upper() for x in raw_qtypes]
        else:
            self.apply_to_qtypes = ["*"]

        # Fuzzing configuration
        self.fuzz_prob = (
            self._clamp_percent(config.get("fuzz_percent", 0.0), key="fuzz_percent")
            / 100.0
        )
        try:
            self.min_fuzz_bytes = int(config.get("min_fuzz_bytes", 1))
        except Exception:
            self.min_fuzz_bytes = 1
        if self.min_fuzz_bytes < 1:
            self.min_fuzz_bytes = 1
        try:
            self.max_fuzz_bytes = int(config.get("max_fuzz_bytes", 4))
        except Exception:
            self.max_fuzz_bytes = 4
        if self.max_fuzz_bytes < self.min_fuzz_bytes:
            self.max_fuzz_bytes = self.min_fuzz_bytes

        self.wrong_qtype_prob = (
            self._clamp_percent(
                config.get("wrong_qtype_percent", 0.0), key="wrong_qtype_percent"
            )
            / 100.0
        )

        raw_actions = config.get("fuzz_actions", ["bit_flip", "swap_bytes"])
        if isinstance(raw_actions, list) and raw_actions:
            actions = [str(a).strip().lower() for a in raw_actions]
        else:
            actions = ["bit_flip", "swap_bytes"]
        self._fuzz_actions = [
            a for a in actions if a in {"bit_flip", "swap_bytes"}
        ] or ["bit_flip", "swap_bytes"]

        # RNG
        seed = config.get("seed")
        if seed is not None:
            try:
                self._rng: Union[random.Random, secrets.SystemRandom] = random.Random(
                    int(seed)
                )
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                logger.warning("FlakyServer: bad seed %r; using SystemRandom()", seed)
                self._rng = secrets.SystemRandom()
        else:
            self._rng = secrets.SystemRandom()

    @staticmethod
    def _clamp_one_in(value, key: str) -> int:
        """Brief: Coerce a 1-in-N value to int and clamp to >= 1.

        Inputs:
          - value: Any, intended to represent an integer N.
          - key: str, config key name for logging context.

        Outputs:
          - int: N >= 1.
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

    @staticmethod
    def _clamp_percent(value: object, key: str) -> float:
        """Brief: Coerce a percentage-like value into [0.0, 100.0].

        Inputs:
          - value: Any numeric-like percent (e.g. 25 or "25").
          - key: str, config key name for logging context.

        Outputs:
          - float: Percent value clamped into the inclusive range [0.0, 100.0].
        """
        try:
            pct = float(value)
        except Exception:
            logger.warning(
                "FlakyServer: %s non-numeric percent %r -> default to 0", key, value
            )
            return 0.0
        if pct < 0.0:
            logger.warning("FlakyServer: %s percent < 0 (%s); clamping to 0", key, pct)
            return 0.0
        if pct > 100.0:
            logger.warning(
                "FlakyServer: %s percent > 100 (%s); clamping to 100", key, pct
            )
            return 100.0
        return pct

    @classmethod
    def _compute_probability(
        cls,
        *,
        percent: object | None,
        one_in: object | None,
        percent_key: str,
        one_in_key: str,
        default_percent: float,
    ) -> float:
        """Brief: Resolve a probability from percent or legacy one-in-N fields.

        Inputs:
          - percent: Explicit percent value (0–100) when provided.
          - one_in: Legacy 1-in-N denominator when percent is omitted.
          - percent_key: Config key name for logging percent.
          - one_in_key: Config key name for logging one-in-N.
          - default_percent: Default percent used when neither is provided.

        Outputs:
          - float: Probability in [0.0, 1.0].
        """
        if percent is not None:
            pct = cls._clamp_percent(percent, percent_key)
            return max(0.0, min(1.0, pct / 100.0))

        if one_in is not None:
            n = cls._clamp_one_in(one_in, key=one_in_key)
        else:
            # Fall back to a reasonable default percent when both are omitted.
            pct = cls._clamp_percent(default_percent, percent_key)
            return max(0.0, min(1.0, pct / 100.0))

        # Convert 1-in-N to probability, clamped to 1.0.
        try:
            return max(0.0, min(1.0, 1.0 / float(n)))
        except Exception:
            return 0.0

    def _is_target_qtype(self, qtype: Union[int, str]) -> bool:
        """Brief: Check if the query type matches the configured apply_to_qtypes set.

        Inputs:
          - qtype (int|str): DNS RR type.

        Outputs:
          - bool: True if applies, else False.
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
        """Brief: Build a minimal reply with the same ID and desired rcode.

        Inputs:
          - req_wire (bytes): Original DNS request wire bytes.
          - rcode (int): dnslib.RCODE value (e.g., RCODE.SERVFAIL).

        Outputs:
          - bytes | None: Packed DNS response wire, or None if parse fails.
        """
        try:
            req = DNSRecord.parse(req_wire)
            rep = req.reply()
            rep.header.rcode = rcode
            return rep.pack()
        except Exception as e:
            logger.debug("FlakyServer: failed to synthesize response: %s", e)
            return None

    def _fuzz_wire(self, wire: bytes) -> Optional[bytes]:
        """Brief: Apply byte-level mutations to a DNS message for fuzz testing.

        Inputs:
          - wire (bytes): Original DNS response wire.

        Outputs:
          - bytes | None: Mutated wire, or None if no mutation was applied.
        """
        if not wire:
            return None

        buf = bytearray(wire)
        length = len(buf)
        if length == 0:
            return None

        min_bytes = max(1, int(self.min_fuzz_bytes))
        max_bytes = max(min_bytes, int(self.max_fuzz_bytes))
        span = min(max_bytes, length)
        count = self._rng.randint(min_bytes, span)

        for _ in range(count):
            action = self._rng.choice(self._fuzz_actions)
            if action == "bit_flip":
                idx = self._rng.randrange(length)
                bit = 1 << self._rng.randrange(8)
                buf[idx] ^= bit
            elif action == "swap_bytes" and length > 1:
                i = self._rng.randrange(length)
                j = self._rng.randrange(length)
                if i == j:
                    continue
                buf[i], buf[j] = buf[j], buf[i]

        return bytes(buf)

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Randomly drop or override matching client requests with error codes.

        Inputs:
          - qname (str): Query name.
          - qtype (int): Query type.
          - req (bytes): Raw DNS request wire.
          - ctx (PluginContext): Contains client_ip.

        Outputs:
          - PluginDecision | None: Override with SERVFAIL/NXDOMAIN or None to
            continue normal flow.

        Example:
          >>> # For a targeted client, force 100% SERVFAIL
          >>> p = FlakyServer(targets=["192.0.2.55"], servfail_percent=100.0)  # doctest: +SKIP
          >>> # decision = p.pre_resolve("example.com", QTYPE.A, wire, PluginContext("192.0.2.55"))
          >>>"""
        if not self._has_base_targets:
            return None
        if not self.targets(ctx):
            return None
        if not self._is_target_qtype(qtype):
            return None

        # Timeouts: drop the query entirely so the client observes no response.
        try:
            if self.timeout_prob > 0.0 and self._rng.random() < self.timeout_prob:
                logger.debug(
                    "FlakyServer: dropping %s type %s for timeout", qname, qtype
                )
                return PluginDecision(action="drop")
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("FlakyServer: timeout draw error: %s", e)

        # Draw SERVFAIL first (precedence over NXDOMAIN and other rcodes).
        try:
            if self.servfail_prob > 0.0 and self._rng.random() < self.servfail_prob:
                wire = self._make_response(req, RCODE.SERVFAIL)
                if wire is not None:
                    return PluginDecision(action="override", response=wire)
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("FlakyServer: SERVFAIL draw error: %s", e)

        # Then NXDOMAIN.
        try:
            if self.nxdomain_prob > 0.0 and self._rng.random() < self.nxdomain_prob:
                wire = self._make_response(req, RCODE.NXDOMAIN)
                if wire is not None:
                    return PluginDecision(action="override", response=wire)
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("FlakyServer: NXDOMAIN draw error: %s", e)

        # FORMERR.
        try:
            if self.formerr_prob > 0.0 and self._rng.random() < self.formerr_prob:
                wire = self._make_response(req, RCODE.FORMERR)
                if wire is not None:
                    return PluginDecision(action="override", response=wire)
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("FlakyServer: FORMERR draw error: %s", e)

        # NOERROR with empty answer section.
        try:
            if (
                self.noerror_empty_prob > 0.0
                and self._rng.random() < self.noerror_empty_prob
            ):
                wire = self._make_response(req, RCODE.NOERROR)
                if wire is not None:
                    return PluginDecision(action="override", response=wire)
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("FlakyServer: NOERROR-empty draw error: %s", e)

        return None

    def post_resolve(
        self, qname: str, qtype: int, response_wire: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Optionally fuzz or rewrite responses for targeted clients.

        Inputs:
          - qname (str): Query name.
          - qtype (int): Query type.
          - response_wire (bytes): Upstream DNS response wire.
          - ctx (PluginContext): Contains client_ip.

        Outputs:
          - PluginDecision | None: Override mutated response or None to pass
            through the upstream response unchanged.
        """
        if not self._has_base_targets:
            return None
        if not self.targets(ctx):
            return None
        if not self._is_target_qtype(qtype):
            return None

        mutated = False
        wire = response_wire

        # Wrong-qtype mutation: change the question qtype to a different RR type.
        if self.wrong_qtype_prob > 0.0 and self._rng.random() < self.wrong_qtype_prob:
            try:
                rec = DNSRecord.parse(wire)
                if rec.questions:
                    q = rec.questions[0]
                    original_qtype = q.qtype
                    alt_types = [
                        QTYPE.A,
                        QTYPE.AAAA,
                        QTYPE.TXT,
                        QTYPE.MX,
                        QTYPE.SRV,
                        QTYPE.CNAME,
                    ]
                    candidates = [t for t in alt_types if t != original_qtype]
                    if candidates:
                        q.qtype = self._rng.choice(candidates)
                        wire = rec.pack()
                        mutated = True
            except Exception as e:  # pragma: no cover - defensive
                logger.debug("FlakyServer: wrong_qtype mutation failed: %s", e)

        # Byte-level fuzzing.
        if self.fuzz_prob > 0.0 and self._rng.random() < self.fuzz_prob:
            try:
                fuzzed = self._fuzz_wire(wire)
                if fuzzed is not None:
                    wire = fuzzed
                    mutated = True
            except Exception as e:  # pragma: no cover - defensive
                logger.debug("FlakyServer: fuzzing mutation failed: %s", e)

        # Truncation: set TC=1 to encourage client fallback to TCP.
        if self.truncate_prob > 0.0 and self._rng.random() < self.truncate_prob:
            try:
                rec = DNSRecord.parse(wire)
                rec.header.tc = 1
                wire = rec.pack()
                mutated = True
            except Exception as e:  # pragma: no cover - defensive
                logger.debug("FlakyServer: truncation mutation failed: %s", e)

        if mutated:
            return PluginDecision(action="override", response=wire)

        return None
