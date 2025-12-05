from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Tuple

from .recursive_resolver import (
    AnswerEntry,
    NegativeEntry,
    RRsetEntry,
    RRsetKey,
    RecursiveCache,
)


class InMemoryRecursiveCache(RecursiveCache):
    """Thread-safe in-memory implementation of RecursiveCache.

    Inputs:
      - now_ms: Optional callable that returns current time in milliseconds.
        When omitted, time.time() is used.
      - max_answers: Soft cap on positive answer entries.
      - max_negatives: Soft cap on negative entries.
      - max_rrsets: Soft cap on RRset entries.

    Outputs:
      - In-memory cache instance suitable for use by resolve_iterative.

    Notes:
      - Expiry is enforced on lookup based on the expires_at_ms fields stored in
        AnswerEntry, NegativeEntry, and RRsetEntry.
      - Capacity limits are best-effort; when a map grows beyond its cap, an
        arbitrary existing entry is evicted to make room for new data.
    """

    def __init__(
        self,
        *,
        now_ms: Callable[[], int] | None = None,
        max_answers: int = 4096,
        max_negatives: int = 4096,
        max_rrsets: int = 4096,
    ) -> None:
        """Initialize the cache with optional time source and capacity caps.

        Inputs:
          - now_ms: Optional callable for current time in milliseconds.
          - max_answers: Maximum number of positive answers to retain.
          - max_negatives: Maximum number of negative entries to retain.
          - max_rrsets: Maximum number of RRset entries to retain.

        Outputs:
          - None
        """

        self._now_ms: Callable[[], int] = now_ms or (lambda: int(time.time() * 1000))
        self._max_answers = max(1, int(max_answers))
        self._max_negatives = max(1, int(max_negatives))
        self._max_rrsets = max(1, int(max_rrsets))

        self._answers: Dict[Tuple[str, int], AnswerEntry] = {}
        self._negatives: Dict[Tuple[str, int], NegativeEntry] = {}
        self._rrsets: Dict[RRsetKey, RRsetEntry] = {}
        self._lock = threading.RLock()

    # Positive answers -----------------------------------------------------

    def lookup_answer(self, qname: str, qtype: int) -> AnswerEntry | None:
        """Return a cached positive answer, or None if missing or expired.

        Inputs:
          - qname: Query name.
          - qtype: Numeric query type.

        Outputs:
          - AnswerEntry when present and not expired, else None.
        """

        key = (qname, int(qtype))
        now = self._now_ms()
        with self._lock:
            entry = self._answers.get(key)
            if entry is None:
                return None
            if entry.expires_at_ms <= now:
                self._answers.pop(key, None)
                return None
            return entry

    def store_answer(self, qname: str, qtype: int, entry: AnswerEntry) -> None:
        """Store a positive answer for (qname, qtype), evicting if over capacity.

        Inputs:
          - qname: Query name.
          - qtype: Numeric query type.
          - entry: AnswerEntry with populated expires_at_ms.

        Outputs:
          - None
        """

        key = (qname, int(qtype))
        with self._lock:
            # Drop immediately expired entries to keep maps small.
            if entry.expires_at_ms <= self._now_ms():
                self._answers.pop(key, None)
                return
            if len(self._answers) >= self._max_answers and key not in self._answers:
                # Best-effort eviction of an arbitrary entry.
                try:
                    victim = next(iter(self._answers))
                    self._answers.pop(victim, None)
                except StopIteration:
                    pass
            self._answers[key] = entry

    # Negative answers -----------------------------------------------------

    def lookup_negative(self, qname: str, qtype: int) -> NegativeEntry | None:
        """Return a cached negative entry, or None if missing or expired.

        Inputs:
          - qname: Query name.
          - qtype: Numeric query type.

        Outputs:
          - NegativeEntry when present and not expired, else None.
        """

        key = (qname, int(qtype))
        now = self._now_ms()
        with self._lock:
            entry = self._negatives.get(key)
            if entry is None:
                return None
            if entry.expires_at_ms <= now:
                self._negatives.pop(key, None)
                return None
            return entry

    def store_negative(self, qname: str, qtype: int, entry: NegativeEntry) -> None:
        """Store a negative result for (qname, qtype), with expiry enforcement.

        Inputs:
          - qname: Query name.
          - qtype: Numeric query type.
          - entry: NegativeEntry with populated expires_at_ms.

        Outputs:
          - None
        """

        key = (qname, int(qtype))
        with self._lock:
            if entry.expires_at_ms <= self._now_ms():
                self._negatives.pop(key, None)
                return
            if (
                len(self._negatives) >= self._max_negatives
                and key not in self._negatives
            ):
                try:
                    victim = next(iter(self._negatives))
                    self._negatives.pop(victim, None)
                except StopIteration:
                    pass
            self._negatives[key] = entry

    # RRset cache ----------------------------------------------------------

    def lookup_rrset(self, key: RRsetKey) -> RRsetEntry | None:
        """Return a cached RRset for the given key, or None if not usable.

        Inputs:
          - key: RRsetKey identifying the desired RRset.

        Outputs:
          - RRsetEntry when present and not expired, else None.
        """

        now = self._now_ms()
        with self._lock:
            entry = self._rrsets.get(key)
            if entry is None:
                return None
            if entry.expires_at_ms <= now:
                self._rrsets.pop(key, None)
                return None
            return entry

    def store_rrset(self, key: RRsetKey, entry: RRsetEntry) -> None:
        """Store an RRset for authority or DNSSEC use, enforcing expiry/capacity.

        Inputs:
          - key: RRsetKey for the RRset.
          - entry: RRsetEntry with populated expires_at_ms.

        Outputs:
          - None
        """

        with self._lock:
            if entry.expires_at_ms <= self._now_ms():
                self._rrsets.pop(key, None)
                return
            if len(self._rrsets) >= self._max_rrsets and key not in self._rrsets:
                try:
                    victim = next(iter(self._rrsets))
                    self._rrsets.pop(victim, None)
                except StopIteration:
                    pass
            self._rrsets[key] = entry
