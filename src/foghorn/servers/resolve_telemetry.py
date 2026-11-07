"""Resolve-pipeline telemetry bus: emit lifecycle events to observers.

Brief:
    Decouples DNS resolve stages from StatsCollector policy. Stages emit
    structured ResolveEvent values; observers map them to record_* calls.

Inputs:
    - Observer implementations registered on ResolveTelemetry.
    - ResolveEvent payloads built by pipeline stages.

Outputs:
    - ResolveTelemetry.emit fans out to observers (best-effort).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("foghorn.resolve_telemetry")


class ResolveEventKind(str, Enum):
    """Lifecycle event kinds emitted by the shared resolve pipeline."""

    QUERY_RECEIVED = "query_received"
    GATE_SHORT_CIRCUIT = "gate_short_circuit"
    PRE_PLUGIN_DECISION = "pre_plugin_decision"
    CACHE_LOOKUP = "cache_lookup"
    UPSTREAM_ATTEMPT = "upstream_attempt"
    POST_PLUGIN_DECISION = "post_plugin_decision"
    RESPONSE_FINALIZED = "response_finalized"


@dataclass(frozen=True)
class ResolveEvent:
    """Immutable resolve-pipeline telemetry event.

    Inputs:
        kind: Event classification.
        client_ip/qname/qtype_label: Common query identity (optional per kind).
        t0: Optional perf_counter start; terminal events may record latency.
        request_result_meta: Per-request metadata merged into query_log rows.
        Extra fields: kind-specific optional attributes (see observers).

    Outputs:
        Frozen ResolveEvent instance.
    """

    kind: ResolveEventKind
    client_ip: str = ""
    qname: str = ""
    qtype_label: str = "UNKNOWN"
    t0: float | None = None
    request_result_meta: dict[str, Any] = field(default_factory=dict)
    # gate_short_circuit / shared early finish
    rcode_name: str | None = None
    status: str | None = None
    error: Any = None
    result: dict[str, Any] | None = None
    record_rcode: bool = True
    record_query_result: bool = True
    upstream_id: str | None = None
    upstream_url: str = ""
    # plugin decisions
    action: str | None = None
    plugin_label: str = ""
    stat_label: str | None = None
    suppress_query_log: bool = False
    ede_code: int | None = None
    ede_text: str | None = None
    dnssec_status: str | None = None
    # When set, used for record_dnssec_status; query_log still uses dnssec_status.
    dnssec_recorded: str | None = None
    answers: list[dict[str, Any]] | None = None
    first: str | None = None
    # cache
    cache_outcome: str | None = None  # "hit" | "miss"
    # upstream
    upstream_outcome: str | None = None
    total_failure: bool = False


@runtime_checkable
class ResolveObserver(Protocol):
    """Protocol for resolve telemetry observers.

    Inputs:
        event: ResolveEvent from the pipeline.

    Outputs:
        None (side effects only).
    """

    def on_event(self, event: ResolveEvent) -> None:
        """Handle one resolve lifecycle event."""


class ResolveTelemetry:
    """Fan-out bus for resolve lifecycle events.

    Inputs:
        observers: Sequence of ResolveObserver instances (copied to tuple).

    Outputs:
        ResolveTelemetry with emit() and active property.
    """

    __slots__ = ("_observers",)

    def __init__(self, observers: Sequence[ResolveObserver] | None = None) -> None:
        """Initialize with an optional observer list.

        Inputs:
            observers: Observers to notify on emit.

        Outputs:
            None.
        """
        self._observers: tuple[ResolveObserver, ...] = tuple(observers or ())

    @classmethod
    def empty(cls) -> ResolveTelemetry:
        """Return a no-op telemetry bus.

        Inputs: none
        Outputs: ResolveTelemetry with zero observers.
        """
        return cls(())

    @property
    def active(self) -> bool:
        """True when at least one observer is registered."""
        return bool(self._observers)

    def emit(self, event: ResolveEvent) -> None:
        """Deliver event to all observers; swallow observer errors.

        Inputs:
            event: ResolveEvent to publish.

        Outputs:
            None.
        """
        for obs in self._observers:
            try:
                obs.on_event(event)
            except Exception:
                logger.debug(
                    "ResolveTelemetry observer %r failed on %s",
                    obs,
                    getattr(event, "kind", None),
                    exc_info=True,
                )


_EMPTY = ResolveTelemetry.empty()


def telemetry_from_stats(stats: object | None) -> ResolveTelemetry:
    """Build or reuse ResolveTelemetry bound to a StatsCollector.

    Inputs:
        stats: StatsCollector-like object or None.

    Outputs:
        ResolveTelemetry: empty when stats is None; otherwise a bus with
        StatsCollectorObserver. Cached on stats._resolve_telemetry when possible.
    """
    if stats is None:
        return _EMPTY
    existing = getattr(stats, "_resolve_telemetry", None)
    if isinstance(existing, ResolveTelemetry) and existing.active:
        return existing
    try:
        from foghorn.stats.observer import StatsCollectorObserver

        tel = ResolveTelemetry((StatsCollectorObserver(stats),))
    except Exception:
        logger.debug("Failed to build StatsCollectorObserver", exc_info=True)
        return _EMPTY
    try:
        stats._resolve_telemetry = tel
    except Exception:
        pass
    return tel


def latency_since(t0: float | None) -> float | None:
    """Compute elapsed seconds from t0 when set.

    Inputs:
        t0: perf_counter start or None.

    Outputs:
        Elapsed seconds or None.
    """
    if t0 is None:
        return None
    try:
        return time.perf_counter() - float(t0)
    except Exception:
        return None


def build_answers_from_parsed(
    parsed: object,
) -> tuple[list[dict[str, Any]], str | None]:
    """Extract answer summaries from a parsed DNSRecord-like object.

    Inputs:
        parsed: Object with .rr iterable of resource records.

    Outputs:
        (answers list, first rdata string or None).
    """
    from dnslib import QTYPE

    answers: list[dict[str, Any]] = []
    try:
        for rr in getattr(parsed, "rr", None) or []:
            answers.append(
                {
                    "name": str(rr.rname),
                    "type": QTYPE.get(rr.rtype, str(rr.rtype)),
                    "ttl": int(getattr(rr, "ttl", 0)),
                    "rdata": str(rr.rdata),
                }
            )
    except Exception:
        return [], None
    first = answers[0]["rdata"] if answers else None
    return answers, str(first) if first is not None else None
