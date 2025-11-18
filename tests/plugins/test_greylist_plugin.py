"""
Brief: Unit tests for GreylistPlugin covering first-seen deny, windowed deny, and allow after window.

Inputs:
  - None (uses temporary sqlite DB and mocked time)

Outputs:
  - None (assertions on decisions, DB state, and cache behavior)
"""

from dnslib import QTYPE

from foghorn.plugins.base import PluginContext
from foghorn.plugins.greylist import GreylistPlugin


def test_first_seen_inserts_and_denies(tmp_path, monkeypatch):
    """
    Brief: First query for base domain inserts first_seen, caches it, and denies.

    Inputs:
      - duration_seconds=60; qname='sub.example.com.'; now=1000

    Outputs:
      - None: asserts deny and first_seen==1000 in DB and cache-load path
    """
    db = tmp_path / "grey.db"
    p = GreylistPlugin(db_path=str(db), duration_seconds=60, cache_ttl_seconds=300)
    p.start()
    ctx = PluginContext(client_ip="1.2.3.4")

    monkeypatch.setattr("time.time", lambda: 1000)
    dec = p.pre_resolve("sub.example.com.", QTYPE.A, b"", ctx)
    assert dec.action == "deny"

    # DB contains first_seen
    assert p._db_get_first_seen("example.com") == 1000
    # Cache-get should return same (and not hit DB)
    assert p._cache_get_or_db_load("example.com") == 1000


def test_within_window_denies_again_without_updating_first_seen(tmp_path, monkeypatch):
    """
    Brief: Subsequent query within window is denied and first_seen is not updated.

    Inputs:
      - duration_seconds=60; first call at t=1000 then t=1050

    Outputs:
      - None: asserts deny and DB first_seen remains 1000
    """
    db = tmp_path / "grey.db"
    p = GreylistPlugin(db_path=str(db), duration_seconds=60, cache_ttl_seconds=300)
    p.start()
    ctx = PluginContext(client_ip="1.2.3.4")

    monkeypatch.setattr("time.time", lambda: 1000)
    p.pre_resolve("sub.example.com.", QTYPE.A, b"", ctx)
    assert p._db_get_first_seen("example.com") == 1000

    # Within window
    monkeypatch.setattr("time.time", lambda: 1050)
    dec2 = p.pre_resolve("sub.example.com.", QTYPE.A, b"", ctx)
    assert dec2.action == "deny"
    # Still 1000 (INSERT OR IGNORE means no update)
    assert p._db_get_first_seen("example.com") == 1000


def test_after_window_allows_and_does_not_update_first_seen(tmp_path, monkeypatch):
    """
    Brief: After the greylist window, pre_resolve allows and first_seen persists.

    Inputs:
      - duration_seconds=60; first at t=1000; then at t=1065

    Outputs:
      - None: asserts None decision and first_seen still 1000
    """
    db = tmp_path / "grey.db"
    p = GreylistPlugin(db_path=str(db), duration_seconds=60, cache_ttl_seconds=300)
    p.start()
    ctx = PluginContext(client_ip="1.2.3.4")

    monkeypatch.setattr("time.time", lambda: 1000)
    p.pre_resolve("sub.example.com.", QTYPE.A, b"", ctx)
    assert p._db_get_first_seen("example.com") == 1000

    # After window
    monkeypatch.setattr("time.time", lambda: 1065)
    dec = p.pre_resolve("sub.example.com.", QTYPE.A, b"", ctx)
    assert dec is None
    assert p._db_get_first_seen("example.com") == 1000


def test_to_base_domain_extraction_cases():
    """
    Brief: _to_base_domain extracts last two labels and normalizes case/trailing dots.

    Inputs:
      - qnames: 'Sub.Example.COM.', 'example.com', 'com', 'a.b', 'a'

    Outputs:
      - None: asserts expected base-domain strings
    """
    p = GreylistPlugin(db_path=":memory:", duration_seconds=60)
    assert p._to_base_domain("Sub.Example.COM.") == "example.com"
    assert p._to_base_domain("example.com") == "example.com"
    assert p._to_base_domain("com") == "com"
    assert p._to_base_domain("a.b") == "a.b"
    assert p._to_base_domain("a") == "a"


def test_cache_hit_bypasses_db(monkeypatch, tmp_path):
    """
    Brief: When cache contains first_seen, DB lookup is not invoked.

    Inputs:
      - cache: (example.com, 0) -> b"2000"; now=2100; duration=50

    Outputs:
      - None: asserts allow (since 2100-2000>=50) and no DB call
    """
    db = tmp_path / "grey.db"
    p = GreylistPlugin(db_path=str(db), duration_seconds=50, cache_ttl_seconds=300)
    p.start()
    ctx = PluginContext(client_ip="1.2.3.4")

    # Seed cache directly
    p._cache.set(("example.com", 0), 300, b"2000")

    # If DB is consulted, raise
    def boom(*a, **k):
        raise RuntimeError("DB should not be called on cache hit")

    monkeypatch.setattr(p, "_db_get_first_seen", boom)
    monkeypatch.setattr("time.time", lambda: 2100)

    dec = p.pre_resolve("a.example.com", QTYPE.A, b"", ctx)
    assert dec is None


def test_db_load_populates_cache(tmp_path, monkeypatch):
    """
    Brief: When cache misses, value is loaded from DB and then cached for future lookups.

    Inputs:
      - DB first_seen(example.com)=1000; cache empty; duration doesn't matter

    Outputs:
      - None: asserts first load uses DB; second load hits cache (DB bypass)
    """
    db = tmp_path / "grey.db"
    p = GreylistPlugin(db_path=str(db), duration_seconds=60, cache_ttl_seconds=300)
    p.start()

    # Insert directly into DB
    p._db_upsert_first_seen("example.com", 1000)

    # First call should fetch from DB and seed cache
    assert p._cache_get_or_db_load("example.com") == 1000

    # Now make DB path explode; subsequent call should come from cache
    def boom(*a, **k):
        raise RuntimeError("DB should not be called on cache hit")

    monkeypatch.setattr(p, "_db_get_first_seen", boom)
    assert p._cache_get_or_db_load("example.com") == 1000
