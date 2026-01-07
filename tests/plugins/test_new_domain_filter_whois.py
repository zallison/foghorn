"""
Brief: WHOIS-path and age-calculation edge-case tests for NewDomainFilterExample.

Inputs:
  - None

Outputs:
  - None
"""

import datetime as dt

import foghorn.plugins.resolve.new_domain_filter as ndf_mod
from foghorn.plugins.resolve.new_domain_filter import NewDomainFilterExample as NDF


def test_whois_lookup_with_whois_returns_min_from_list(monkeypatch):
    """
    Brief: _whois_lookup_creation_date uses whois.whois and picks the earliest when list.

    Inputs:
      - _whois_mod.whois returns object with creation_date=[d2,d1]

    Outputs:
      - None: asserts min date returned
    """
    d1 = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    d2 = dt.datetime(2021, 1, 1, tzinfo=dt.timezone.utc)

    class WObj:
        def __init__(self):
            self.creation_date = [d2, d1]

    class WMod:
        def whois(self, domain):
            return WObj()

    monkeypatch.setattr(ndf_mod, "_whois_mod", WMod())
    monkeypatch.setattr(ndf_mod, "_pythonwhois_mod", None)

    p = NDF(whois_db_path=":memory:")
    out = p._whois_lookup_creation_date("example.com")
    assert out == d1


def test_whois_lookup_with_query_returns_value(monkeypatch):
    """
    Brief: _whois_lookup_creation_date uses whois.query alternative when available.

    Inputs:
      - _whois_mod.query returns object with creation_date=d

    Outputs:
      - None: asserts that date is returned
    """
    d = dt.datetime(2019, 5, 5, tzinfo=dt.timezone.utc)

    class QObj:
        def __init__(self):
            self.creation_date = d

    class WMod:
        def query(self, domain):
            return QObj()

    monkeypatch.setattr(ndf_mod, "_whois_mod", WMod())
    monkeypatch.setattr(ndf_mod, "_pythonwhois_mod", None)

    p = NDF(whois_db_path=":memory:")
    out = p._whois_lookup_creation_date("example.org")
    assert out == d


def test_pythonwhois_lookup_returns_min_from_list(monkeypatch):
    """
    Brief: _whois_lookup_creation_date uses pythonwhois.get_whois with creation_date list.

    Inputs:
      - _pythonwhois_mod.get_whois returns {'creation_date': [d2, d1]}

    Outputs:
      - None: asserts min date returned
    """
    d1 = dt.datetime(2018, 1, 1, tzinfo=dt.timezone.utc)
    d2 = dt.datetime(2018, 2, 1, tzinfo=dt.timezone.utc)

    class PWhois:
        def get_whois(self, domain):
            return {"creation_date": [d2, d1]}

    monkeypatch.setattr(ndf_mod, "_whois_mod", None)
    monkeypatch.setattr(ndf_mod, "_pythonwhois_mod", PWhois())

    p = NDF(whois_db_path=":memory:")
    out = p._whois_lookup_creation_date("example.net")
    assert out == d1


def test_fetch_creation_date_uses_memory_cache(monkeypatch, tmp_path):
    """
    Brief: _fetch_creation_date returns from in-memory cache without DB/network.

    Inputs:
      - Cache: (domain,1) -> bytes(ts)

    Outputs:
      - None: asserts datetime returned and DB methods not called
    """
    db = tmp_path / "whois.db"
    p = NDF(whois_db_path=str(db))
    p.setup()
    domain = "cached.com"
    ts = 1700000000
    p._whois_cache.set((domain, 1), 3600, str(ts).encode())

    # Explode DB/network if touched
    monkeypatch.setattr(
        p,
        "_db_get_creation_record",
        lambda d: (_ for _ in ()).throw(RuntimeError("db")),
    )
    monkeypatch.setattr(
        p,
        "_whois_lookup_creation_date",
        lambda d: (_ for _ in ()).throw(RuntimeError("net")),
    )

    d = p._fetch_creation_date(domain)
    assert isinstance(d, dt.datetime) and int(d.timestamp()) == ts


def test_domain_age_days_handles_naive_creation_date(monkeypatch, tmp_path):
    """
    Brief: _domain_age_days treats naive creation_date as UTC and computes age.

    Inputs:
      - naive creation_date; mocked now

    Outputs:
      - None: asserts computed days
    """
    db = tmp_path / "whois.db"
    p = NDF(whois_db_path=str(db))
    p.setup()

    created = dt.datetime(2023, 1, 1)  # naive
    now = dt.datetime(2023, 1, 11, tzinfo=dt.timezone.utc)

    monkeypatch.setattr(p, "_fetch_creation_date", lambda d: created)

    # Patch module datetime.now to controlled value
    class FakeDT(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr(ndf_mod.dt, "datetime", FakeDT)
    monkeypatch.setattr(ndf_mod.dt, "timezone", dt.timezone)

    age = p._domain_age_days("x.com")
    assert age == 10


def test_domain_age_days_exception_returns_none(monkeypatch, tmp_path):
    """
    Brief: _domain_age_days returns None when _fetch_creation_date raises.

    Inputs:
      - _fetch_creation_date: raises RuntimeError

    Outputs:
      - None: asserts None returned
    """
    p = NDF(whois_db_path=str(tmp_path / "whois.db"))
    p.setup()
    monkeypatch.setattr(
        p, "_fetch_creation_date", lambda d: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert p._domain_age_days("y.com") is None


def test_fetch_creation_date_persists_naive_datetime(tmp_path, monkeypatch):
    """
    Brief: _fetch_creation_date handles naive datetime by attaching UTC and persisting.

    Inputs:
      - whois lookup returns naive datetime

    Outputs:
      - None: asserts DB creation_ts equals timestamp of UTC-aware date
    """
    db = tmp_path / "whois.db"
    p = NDF(whois_db_path=str(db))
    p.setup()
    domain = "naive.com"

    naive = dt.datetime(2020, 6, 1)  # naive
    monkeypatch.setattr(p, "_whois_lookup_creation_date", lambda d: naive)
    # Ensure time.time returns stable value
    monkeypatch.setattr("time.time", lambda: 1234567890)

    d = p._fetch_creation_date(domain)
    assert d.tzinfo is not None
    rec = p._db_get_creation_record(domain)
    assert rec is not None
    creation_ts, fetched_at = rec
    assert creation_ts == int(d.timestamp())
