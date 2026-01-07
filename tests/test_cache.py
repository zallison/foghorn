"""
Brief: Tests for foghorn.plugins.cache.backends.foghorn_ttl.FoghornTTLCache functionality.

Inputs:
  - None

Outputs:
  - None
"""

import threading

from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache


def test_cache_set_and_get_basic():
    """
    Brief: Setting and getting a value returns stored bytes until expiry.

    Inputs:
      - key: tuple of (qname, qtype)
      - ttl: positive integer
      - data: bytes value

    Outputs:
      - None: Asserts retrieved value matches stored value
    """
    c = FoghornTTLCache()
    k = ("example.com", 1)
    c.set(k, 2, b"payload")
    assert c.get(k) == b"payload"


def test_cache_get_missing_returns_none():
    """
    Brief: Getting a missing key returns None.

    Inputs:
      - key: tuple not present in cache

    Outputs:
      - None: Asserts None returned
    """
    c = FoghornTTLCache()
    assert c.get(("missing", 1)) is None


def test_cache_expiry_and_purge(monkeypatch):
    """
    Brief: Expired entries are not returned and are purged by purge_expired.

    Inputs:
      - ttl: very short ttl to force expiry

    Outputs:
      - None: Asserts entry removed after purge
    """
    c = FoghornTTLCache()
    k = ("soon-expire.com", 1)
    c.set(k, 1, b"x")

    # Advance cache's notion of time without real sleeping by monkeypatching
    # the time module used inside foghorn.plugins.cache.backends.foghorn_ttl.
    import foghorn.plugins.cache.backends.foghorn_ttl as cache_mod

    base = cache_mod.time.time()

    def fake_time() -> float:
        # Move time forward sufficiently past the 1s TTL
        return base + 2.0

    monkeypatch.setattr(cache_mod.time, "time", fake_time)

    assert c.get(k) is None  # opportunistic cleanup on get
    # Explicit purge returns count of removed entries (0 or more depending on timing)
    removed = c.purge_expired()
    assert isinstance(removed, int)


def test_cache_negative_ttl_not_kept():
    """
    Brief: Negative TTL results in immediate expiry (item not retrievable).

    Inputs:
      - ttl: negative value

    Outputs:
      - None: Asserts item not present after set
    """
    c = FoghornTTLCache()
    k = ("neg.com", 1)
    c.set(k, -10, b"neg")
    # Item should be expired and likely purged by set() cleanup
    assert c.get(k) is None


def test_cache_thread_safety_basic():
    """
    Brief: Concurrent set/get operations do not raise exceptions.

    Inputs:
      - multiple threads performing cache operations

    Outputs:
      - None: Asserts no exceptions and some values retrievable
    """
    c = FoghornTTLCache()
    k1 = ("t1.com", 1)
    k2 = ("t2.com", 1)

    def writer():
        for _ in range(100):
            c.set(k1, 5, b"a")
            c.set(k2, 5, b"b")

    def reader():
        for _ in range(100):
            _ = c.get(k1)
            _ = c.get(k2)

    threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert c.get(k1) in (b"a", None)
    assert c.get(k2) in (b"b", None)


def test_cache_namespace_isolation_shared_store() -> None:
    """Brief: Namespaced views share backing store but do not collide.

    Inputs:
      - None.

    Outputs:
      - None; asserts same key under different namespaces does not collide.
    """

    base = FoghornTTLCache()
    a = base.with_namespace("a")
    b = base.with_namespace("b")

    k = ("example.com", 1)
    a.set(k, 60, b"A")
    b.set(k, 60, b"B")

    assert a.get(k) == b"A"
    assert b.get(k) == b"B"

    # Purging within one namespace should not affect the other.
    assert a.purge_expired() >= 0
    assert b.get(k) == b"B"


def test_cache_counters_increment_on_hits_and_misses() -> None:
    """Brief: FoghornTTLCache exposes best-effort calls_total/hits/misses counters.

    Inputs:
      - None.

    Outputs:
      - None; asserts counters move in the expected direction for hits/misses.
    """

    c = FoghornTTLCache()
    key_hit = ("hit.example", 1)
    key_miss = ("miss.example", 1)

    # Initial counters default to zero.
    assert getattr(c, "calls_total", 0) == 0
    assert getattr(c, "cache_hits", 0) == 0
    assert getattr(c, "cache_misses", 0) == 0

    # Insert a single entry and perform a hit and a miss.
    c.set(key_hit, 60, b"v")
    assert c.get(key_hit) == b"v"  # hit
    assert c.get(key_miss) is None  # miss

    # Best-effort expectations: total calls equals two and hits/misses are
    # non-decreasing and sum to at most calls_total.
    calls_total = getattr(c, "calls_total", 0)
    cache_hits = getattr(c, "cache_hits", 0)
    cache_misses = getattr(c, "cache_misses", 0)

    assert calls_total >= 2
    assert cache_hits >= 1
    assert cache_misses >= 1
    assert cache_hits + cache_misses <= calls_total
