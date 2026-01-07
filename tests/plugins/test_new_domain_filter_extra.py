"""
Brief: Extra tests for NewDomainFilterExample covering DB freshness, cache corruption tolerance.

Inputs:
  - None

Outputs:
  - None
"""

import datetime as dt
from contextlib import closing

from foghorn.plugins.resolve.new_domain_filter import NewDomainFilterExample


def test_fetch_creation_date_uses_fresh_db_and_seeds_cache(tmp_path, monkeypatch):
    """
    Brief: Fresh DB record returns immediately and seeds in-memory cache.

    Inputs:
      - DB: creation_ts=1700000000, fetched_at=now_ts; refresh window=86400

    Outputs:
      - None: asserts returned datetime matches and cache populated
    """
    db = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db), whois_refresh_seconds=86400)
    plugin.setup()
    now_ts = 2000000000
    domain = "fresh.com"

    with closing(plugin._conn):
        # Seed DB with fresh record
        plugin._db_upsert_creation_record(domain, 1700000000, now_ts)

        # time.time returns now_ts
        monkeypatch.setattr("time.time", lambda: now_ts)

        d = plugin._fetch_creation_date(domain)
        assert isinstance(d, dt.datetime) and int(d.timestamp()) == 1700000000
        # Ensure memory cache got populated
        cached = plugin._whois_cache.get((domain, 1))
        assert cached is not None and int(cached.decode()) == 1700000000


def test_fetch_creation_date_refreshes_stale_db(tmp_path, monkeypatch):
    """
    Brief: Stale DB record triggers whois lookup; DB and cache updated.

    Inputs:
      - DB: stale fetched_at; whois returns newer creation date

    Outputs:
      - None: asserts returned date is new, DB updated, and cache set
    """
    db = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db), whois_refresh_seconds=100)
    plugin.setup()
    domain = "stale.com"

    with closing(plugin._conn):
        old_creation = 1600000000
        old_fetch = 1000
        plugin._db_upsert_creation_record(domain, old_creation, old_fetch)

        now_ts = 2000
        monkeypatch.setattr("time.time", lambda: now_ts)

        new_dt = dt.datetime(2023, 1, 1, tzinfo=dt.timezone.utc)
        # Force lookup to return new_dt
        monkeypatch.setattr(plugin, "_whois_lookup_creation_date", lambda d: new_dt)

        d = plugin._fetch_creation_date(domain)
        assert d == new_dt

        # DB updated to new creation_ts and new fetched_at
        rec = plugin._db_get_creation_record(domain)
        assert rec is not None
        creation_ts, fetched_at = rec
        assert creation_ts == int(new_dt.timestamp())
        assert fetched_at == now_ts

        # Cache populated
        cached = plugin._whois_cache.get((domain, 1))
        assert cached is not None and int(cached.decode()) == int(new_dt.timestamp())


def test_fetch_creation_date_bad_cached_value_is_ignored(tmp_path, monkeypatch):
    """
    Brief: Corrupted cache value is ignored; DB path is used instead.

    Inputs:
      - memory cache: non-integer bytes; DB has valid record

    Outputs:
      - None: asserts returned date comes from DB and cache repaired
    """
    db = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db), whois_refresh_seconds=999999)
    plugin.setup()
    domain = "cachecorrupt.com"

    with closing(plugin._conn):
        # Corrupt cache value
        plugin._whois_cache.set((domain, 1), 3600, b"not-an-int")

        # DB has valid record
        creation_ts = 1710000000
        now_ts = creation_ts + 100
        plugin._db_upsert_creation_record(domain, creation_ts, now_ts)

        monkeypatch.setattr("time.time", lambda: now_ts)

        d = plugin._fetch_creation_date(domain)
        assert isinstance(d, dt.datetime) and int(d.timestamp()) == creation_ts
        # Cache should be repaired with correct int string
        cached = plugin._whois_cache.get((domain, 1))
        assert cached is not None and cached.decode().isdigit()
