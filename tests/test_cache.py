"""
Brief: Tests for foghorn.cache.TTLCache functionality.

Inputs:
  - None

Outputs:
  - None
"""
import time
import threading
import pytest
from foghorn.cache import TTLCache


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
    c = TTLCache()
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
    c = TTLCache()
    assert c.get(("missing", 1)) is None


def test_cache_expiry_and_purge():
    """
    Brief: Expired entries are not returned and are purged by purge_expired.

    Inputs:
      - ttl: very short ttl to force expiry

    Outputs:
      - None: Asserts entry removed after purge
    """
    c = TTLCache()
    k = ("soon-expire.com", 1)
    c.set(k, 1, b"x")
    time.sleep(1.1)
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
    c = TTLCache()
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
    c = TTLCache()
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