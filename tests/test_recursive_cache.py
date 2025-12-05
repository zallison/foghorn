"""Tests for the in-memory RecursiveCache implementation.

Inputs:
  - None (pytest discovers and runs tests).

Outputs:
  - None (assertions validate cache expiry and capacity behavior).
"""

from __future__ import annotations

from typing import Callable

from foghorn.recursive_cache import InMemoryRecursiveCache
from foghorn.recursive_resolver import AnswerEntry, NegativeEntry, RRsetEntry, RRsetKey


def _make_clock(start: int = 0) -> tuple[Callable[[], int], Callable[[int], None]]:
    """Brief: Build a simple controllable millisecond clock for tests.

    Inputs:
      - start: Initial time in milliseconds.

    Outputs:
      - (now, advance):
        * now(): returns the current time in ms.
        * advance(delta): advances the clock by delta ms.
    """

    current = {"value": int(start)}

    def now() -> int:
        return int(current["value"])

    def advance(delta: int) -> None:
        current["value"] += int(delta)

    return now, advance


def test_lookup_answer_respects_expiry() -> None:
    """Brief: AnswerEntry is returned before expiry and evicted after.

    Inputs:
      - None

    Outputs:
      - Ensures lookup_answer returns the entry only while it is fresh.
    """

    now, advance = _make_clock(start=1_000_000)
    cache = InMemoryRecursiveCache(now_ms=now)

    entry = AnswerEntry(wire=b"x", rcode=0, expires_at_ms=1_000_500)
    cache.store_answer("example.test", 1, entry)

    # Before expiry, lookup should return the stored entry.
    found = cache.lookup_answer("example.test", 1)
    assert found is entry

    # After advancing past expiry, the entry should be gone.
    advance(1_000)
    assert cache.lookup_answer("example.test", 1) is None


def test_lookup_negative_respects_expiry() -> None:
    """Brief: NegativeEntry is returned only while within its TTL window.

    Inputs:
      - None

    Outputs:
      - Ensures expired negatives are evicted and not returned.
    """

    now, advance = _make_clock(start=2_000_000)
    cache = InMemoryRecursiveCache(now_ms=now)

    neg = NegativeEntry(rcode=3, soa_owner="example.test", expires_at_ms=2_000_100)
    cache.store_negative("nx.example", 1, neg)

    assert cache.lookup_negative("nx.example", 1) is neg

    advance(200)
    assert cache.lookup_negative("nx.example", 1) is None


def test_lookup_rrset_respects_expiry() -> None:
    """Brief: RRsetEntry lookups drop expired authority data.

    Inputs:
      - None

    Outputs:
      - Ensures lookup_rrset enforces expires_at_ms for RRset entries.
    """

    now, advance = _make_clock(start=3_000_000)
    cache = InMemoryRecursiveCache(now_ms=now)

    key = RRsetKey(name="example.test", rrtype=2)
    entry = RRsetEntry(rrset_wire=b"rr", expires_at_ms=3_000_050)
    cache.store_rrset(key, entry)

    assert cache.lookup_rrset(key) is entry

    advance(100)
    assert cache.lookup_rrset(key) is None


def test_capacity_limits_trigger_eviction() -> None:
    """Brief: capacity caps cause older entries to be evicted on insert.

    Inputs:
      - None

    Outputs:
      - Ensures the cache does not grow beyond its configured capacities.
    """

    now, _ = _make_clock(start=4_000_000)
    cache = InMemoryRecursiveCache(
        now_ms=now, max_answers=1, max_negatives=1, max_rrsets=1
    )

    # Answers: inserting a second distinct key should evict one entry.
    e1 = AnswerEntry(wire=b"a1", rcode=0, expires_at_ms=4_000_500)
    e2 = AnswerEntry(wire=b"a2", rcode=0, expires_at_ms=4_000_500)
    cache.store_answer("a.test", 1, e1)
    cache.store_answer("b.test", 1, e2)
    remaining = [
        key for key in ("a.test", "b.test") if cache.lookup_answer(key, 1) is not None
    ]
    assert len(remaining) == 1

    # Negatives: same idea.
    n1 = NegativeEntry(rcode=3, soa_owner="example.test", expires_at_ms=4_000_500)
    n2 = NegativeEntry(rcode=3, soa_owner="example.test", expires_at_ms=4_000_500)
    cache.store_negative("nx1.test", 1, n1)
    cache.store_negative("nx2.test", 1, n2)
    remaining_neg = [
        key
        for key in ("nx1.test", "nx2.test")
        if cache.lookup_negative(key, 1) is not None
    ]
    assert len(remaining_neg) == 1

    # RRsets: ensure at most one key survives.
    k1 = RRsetKey(name="z1.test", rrtype=2)
    k2 = RRsetKey(name="z2.test", rrtype=2)
    r1 = RRsetEntry(rrset_wire=b"r1", expires_at_ms=4_000_500)
    r2 = RRsetEntry(rrset_wire=b"r2", expires_at_ms=4_000_500)
    cache.store_rrset(k1, r1)
    cache.store_rrset(k2, r2)
    remaining_rr = [k for k in (k1, k2) if cache.lookup_rrset(k) is not None]
    assert len(remaining_rr) == 1
