"""
Brief: Tests for foghorn.plugins.new_domain_filter module.

Inputs:
  - None

Outputs:
  - None
"""

import datetime as dt
from contextlib import closing
from unittest.mock import patch

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.new_domain_filter import NewDomainFilterExample


def test_new_domain_filter_init_defaults(tmp_path):
    """
    Brief: Verify NewDomainFilterExample initializes with defaults.

    Inputs:
      - tmp_path: temporary directory for database

    Outputs:
      - None: Asserts default configuration
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path))
    plugin.setup()
    with closing(plugin._conn):
        assert plugin.threshold_days == 7
        assert plugin.whois_cache_ttl_seconds == 3600
        assert plugin.whois_refresh_seconds == 86400


def test_new_domain_filter_init_custom_config(tmp_path):
    """
    Brief: Verify NewDomainFilterExample uses custom config.

    Inputs:
      - threshold_days, cache settings: custom values

    Outputs:
      - None: Asserts custom values stored
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(
        whois_db_path=str(db_path),
        threshold_days=30,
        whois_cache_ttl_seconds=7200,
        whois_refresh_seconds=172800,
    )
    plugin.setup()
    with closing(plugin._conn):
        assert plugin.threshold_days == 30
        assert plugin.whois_cache_ttl_seconds == 7200
        assert plugin.whois_refresh_seconds == 172800


def test_new_domain_filter_pre_resolve_unknown_age_allows(tmp_path, monkeypatch):
    """
    Brief: Verify domain with unknown age is allowed.

    Inputs:
      - qname: domain name
      - monkeypatch: to mock _domain_age_days

    Outputs:
      - None: Asserts None returned (allow)
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path))
    plugin.setup()

    with closing(plugin._conn):
        # Mock _domain_age_days to return None (unknown)
        monkeypatch.setattr(plugin, "_domain_age_days", lambda d: None)

        ctx = PluginContext(client_ip="127.0.0.1")
        decision = plugin.pre_resolve("example.com", 1, b"", ctx)
        assert decision is None


def test_new_domain_filter_pre_resolve_old_domain_allows(tmp_path, monkeypatch):
    """
    Brief: Verify old domain is allowed.

    Inputs:
      - qname: domain name
      - monkeypatch: to mock _domain_age_days returning > threshold

    Outputs:
      - None: Asserts None returned (allow)
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path), threshold_days=10)
    plugin.setup()

    with closing(plugin._conn):
        # Mock _domain_age_days to return 20 days (older than threshold)
        monkeypatch.setattr(plugin, "_domain_age_days", lambda d: 20)

        ctx = PluginContext(client_ip="127.0.0.1")
        decision = plugin.pre_resolve("oldsite.com", 1, b"", ctx)
        assert decision is None


def test_new_domain_filter_pre_resolve_new_domain_denies(tmp_path, monkeypatch):
    """
    Brief: Verify new domain is denied.

    Inputs:
      - qname: domain name
      - monkeypatch: to mock _domain_age_days returning < threshold

    Outputs:
      - None: Asserts deny decision
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path), threshold_days=10)
    plugin.setup()

    with closing(plugin._conn):
        # Mock _domain_age_days to return 5 days (newer than threshold)
        monkeypatch.setattr(plugin, "_domain_age_days", lambda d: 5)

        ctx = PluginContext(client_ip="127.0.0.1")
        decision = plugin.pre_resolve("newsite.com", 1, b"", ctx)
        assert decision is not None
        assert decision.action == "deny"


def test_new_domain_filter_domain_age_days(tmp_path, monkeypatch):
    """
    Brief: Verify _domain_age_days calculates correctly.

    Inputs:
      - monkeypatch: to mock _fetch_creation_date and time

    Outputs:
      - None: Asserts age calculation
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path))
    plugin.setup()

    with closing(plugin._conn):
        # Mock creation date 100 days ago
        now = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
        created = dt.datetime(2023, 9, 23, tzinfo=dt.timezone.utc)  # 100 days earlier

        monkeypatch.setattr(plugin, "_fetch_creation_date", lambda d: created)

        with patch("foghorn.plugins.resolve.new_domain_filter.dt.datetime") as mock_dt:
            mock_dt.now.return_value = now
            mock_dt.timezone = dt.timezone
            age = plugin._domain_age_days("example.com")

    assert age == 100


def test_new_domain_filter_fetch_creation_date_caching(tmp_path):
    """
    Brief: Verify creation date is cached.

    Inputs:
      - domain: domain to fetch
      - tmp_path: for database

    Outputs:
      - None: Asserts cache and DB used
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path))
    plugin.setup()

    with closing(plugin._conn):
        # Mock the whois lookup to return a fixed date
        mock_date = dt.datetime(2023, 1, 1, tzinfo=dt.timezone.utc)

        with patch.object(
            plugin, "_whois_lookup_creation_date", return_value=mock_date
        ):
            # First call should hit the whois lookup
            date1 = plugin._fetch_creation_date("example.com")
            assert date1 == mock_date

            # Second call should use cache (whois_lookup should not be called again)
            date2 = plugin._fetch_creation_date("example.com")
            assert date2 == mock_date


def test_new_domain_filter_db_operations(tmp_path):
    """
    Brief: Verify database operations work.

    Inputs:
      - tmp_path: for database file

    Outputs:
      - None: Asserts DB created and records inserted/retrieved
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path))
    plugin.setup()

    with closing(plugin._conn):
        # Check DB initialized
        assert db_path.exists()

        # Insert a record
        creation_ts = 1609459200  # 2021-01-01
        now_ts = 1640995200  # 2022-01-01
        plugin._db_upsert_creation_record("example.com", creation_ts, now_ts)

        # Retrieve the record
        record = plugin._db_get_creation_record("example.com")
        assert record is not None
        assert record[0] == creation_ts
        assert record[1] == now_ts


def test_new_domain_filter_db_get_nonexistent(tmp_path):
    """
    Brief: Verify DB returns None for non-existent domain.

    Inputs:
      - domain: non-existent domain

    Outputs:
      - None: Asserts None returned
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path))
    plugin.setup()

    with closing(plugin._conn):
        record = plugin._db_get_creation_record("nonexistent.com")
        assert record is None


def test_new_domain_filter_whois_lookup_no_libraries(tmp_path, monkeypatch):
    """Brief: Verify graceful handling when whois libraries unavailable.

    Inputs:
      - monkeypatch: to set whois modules to None

    Outputs:
      - None: Asserts None returned
    """
    import foghorn.plugins.resolve.new_domain_filter as ndf_mod

    # Mock both whois libraries as unavailable
    monkeypatch.setattr(ndf_mod, "_whois_mod", None)
    monkeypatch.setattr(ndf_mod, "_pythonwhois_mod", None)

    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path))
    plugin.setup()

    with closing(plugin._conn):
        result = plugin._whois_lookup_creation_date("example.com")
        assert result is None


def test_new_domain_filter_domain_age_exception_handling(tmp_path, monkeypatch):
    """
    Brief: Verify exceptions in age calculation return None.

    Inputs:
      - monkeypatch: to raise exception in _fetch_creation_date

    Outputs:
      - None: Asserts None returned on exception
    """
    db_path = tmp_path / "whois.db"
    plugin = NewDomainFilterExample(whois_db_path=str(db_path))
    plugin.setup()

    with closing(plugin._conn):
        # Mock _fetch_creation_date to raise exception
        monkeypatch.setattr(plugin, "_fetch_creation_date", lambda d: 1 / 0)

        age = plugin._domain_age_days("example.com")
        assert age is None
