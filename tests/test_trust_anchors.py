"""Brief: Unit tests for foghorn.trust_anchors store and RFC 5011 helpers.

Inputs:
  - None (pytest harness).

Outputs:
  - None (pytest assertions over trust anchor store behaviour).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
import pathlib

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from foghorn.dnssec import dnssec_validate as dval
from foghorn.dnssec import trust_anchors as ta


def _root_dnskey_rrset() -> dns.rrset.RRset:
    """Brief: Helper to build a DNSKEY rrset from the baked-in root anchor.

    Inputs:
      - None.

    Outputs:
      - dns.rrset.RRset containing at least one SEP (KSK) DNSKEY.
    """

    name = dns.name.from_text(".")
    txt = dval.ROOT_DNSKEY_STR.replace("\n", " ")
    rrs = dns.rrset.from_text_list(
        name,
        0,
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        [txt.split(" DNSKEY ")[1]],
    )
    return rrs


def test_load_store_variants(tmp_path: pathlib.Path) -> None:
    """Brief: load_store handles missing/invalid/valid files safely.

    Inputs:
      - tmp_path: pytest-provided temporary directory factory.

    Outputs:
      - None; asserts empty stores for error cases and dict for valid JSON.
    """

    # Empty path -> empty store.
    assert ta.load_store("") == {}

    path = tmp_path / "store.json"

    # Non-existent file -> empty store.
    assert ta.load_store(str(path)) == {}

    # Non-dict JSON -> empty store.
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    assert ta.load_store(str(path)) == {}

    # Invalid JSON -> empty store via exception path.
    path.write_text("{not-json}", encoding="utf-8")
    assert ta.load_store(str(path)) == {}

    # Valid dict JSON -> returned as-is.
    data = {".": {"keys": []}}
    path.write_text(json.dumps(data), encoding="utf-8")
    assert ta.load_store(str(path)) == data


def test_save_store_empty_and_write(tmp_path: pathlib.Path) -> None:
    """Brief: save_store ignores empty path and writes JSON atomically.

    Inputs:
      - tmp_path: pytest temporary directory factory.

    Outputs:
      - None; asserts no crash on empty path and valid JSON is written.
    """

    # Empty path should be a no-op.
    ta.save_store("", {})

    path = tmp_path / "store.json"
    store = {"example.com.": {"keys": []}}
    ta.save_store(str(path), store)

    # File should exist with the same JSON content.
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded == store


def test_anchors_for_zone_filters_and_handles_errors() -> None:
    """Brief: anchors_for_zone returns trusted keys and skips bad entries.

    Inputs:
      - None.

    Outputs:
      - None; asserts only trusted, well-formed entries become DNSKEY RDATAs.
    """

    store: ta.Store = {}
    bucket = ta._zone_bucket(store, ".")

    # Build a valid trusted entry from the baked-in root DNSKEY.
    rrset = _root_dnskey_rrset()
    dnskey = rrset[0]
    alg = int(dnskey.algorithm)
    pub_b64 = dnskey.to_text().split()[-1]

    bucket["keys"] = [
        {
            "key_tag": dns.dnssec.key_id(dnskey),
            "algorithm": alg,
            "public_key_b64": pub_b64,
            "status": "trusted",
            "first_seen": "2020-01-01T00:00:00+00:00",
            "last_seen": "2020-01-01T00:00:00+00:00",
            "promoted_at": "2020-01-01T00:00:00+00:00",
        },
        # Non-trusted status should be ignored.
        {
            "key_tag": 0,
            "algorithm": alg,
            "public_key_b64": pub_b64,
            "status": "pending_add",
            "first_seen": "2020-01-01T00:00:00+00:00",
            "last_seen": "2020-01-01T00:00:00+00:00",
        },
        # Malformed algorithm triggers exception and is skipped.
        {
            "key_tag": 1,
            "algorithm": "not-an-int",
            "public_key_b64": pub_b64,
            "status": "trusted",
            "first_seen": "2020-01-01T00:00:00+00:00",
            "last_seen": "2020-01-01T00:00:00+00:00",
        },
    ]

    out = ta.anchors_for_zone(store, ".")
    assert len(out) == 1
    assert isinstance(out[0], dns.rdata.Rdata)


def test_bootstrap_from_rrset_ksk_filter_and_error() -> None:
    """Brief: bootstrap_from_rrset seeds trusted keys and skips bad records.

    Inputs:
      - None.

    Outputs:
      - None; asserts KSK selection and exception path are both exercised.
    """

    store: ta.Store = {}

    # Valid rrset derived from the baked-in root DNSKEY.
    rrset = _root_dnskey_rrset()
    ta.bootstrap_from_rrset(store, ".", rrset)

    bucket = store.get(".")
    assert bucket is not None
    assert bucket["keys"]
    first = bucket["keys"][0]
    assert first["status"] == "trusted"

    # Error path: an rrset element that triggers an exception inside the loop.
    class _BadDNSKEY:
        def __init__(self) -> None:
            self.flags = int(getattr(dns.dnssec.Flag, "SEP", 0))
            self.algorithm = 8
            # Minimal attributes so dns.rrset.RRset.add() accepts this stub.
            self.rdclass = dns.rdataclass.IN
            self.rdtype = dns.rdatatype.DNSKEY

        def to_text(self) -> str:  # noqa: D401
            """Raise to exercise the exception handler in bootstrap loop."""

            raise RuntimeError("boom")

    bad_rrset = dns.rrset.RRset(
        dns.name.from_text("."), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    bad_rrset.add(_BadDNSKEY())

    # Should not raise and should not overwrite existing keys.
    ta.bootstrap_from_rrset(store, ".", bad_rrset)
    assert store["."]["keys"] == bucket["keys"]


def test_update_from_dnskey_rrset_rfc5011_state_machine() -> None:
    """Brief: update_from_dnskey_rrset handles add/promote/remove lifecycle.

    Inputs:
      - None.

    Outputs:
      - None; asserts pending_add -> trusted -> pending_remove -> removed.
    """

    store: ta.Store = {}
    zone = "."
    rrset = _root_dnskey_rrset()
    dnskey = rrset[0]
    dns.dnssec.key_id(dnskey)

    # Start with now derived via _now_utc() to exercise the default path.
    t0 = datetime(2020, 1, 1, tzinfo=timezone.utc)

    def fake_now() -> datetime:  # noqa: D401
        """Return a fixed timestamp for deterministic tests."""

        return t0

    # Patch _now_utc so update_from_dnskey_rrset uses our timestamp.
    original_now = ta._now_utc
    ta._now_utc = fake_now
    try:
        changed = ta.update_from_dnskey_rrset(
            store,
            zone,
            rrset,
            hold_down_add_days=1,
            hold_down_remove_days=1,
        )
    finally:
        ta._now_utc = original_now

    assert changed is True
    entries = store[zone]["keys"]
    assert len(entries) == 1
    assert entries[0]["status"] == "pending_add"

    # After hold-down, the key should be promoted to trusted.
    t1 = t0 + timedelta(days=2)
    changed2 = ta.update_from_dnskey_rrset(
        store,
        zone,
        rrset,
        now=t1,
        hold_down_add_days=1,
        hold_down_remove_days=1,
    )
    assert changed2 is True
    assert entries[0]["status"] == "trusted"
    assert entries[0]["promoted_at"] == t1.isoformat()

    # If the key disappears from the live rrset, it enters pending_remove.
    empty_rrset = dns.rrset.RRset(
        dns.name.from_text(zone), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    t2 = t1 + timedelta(days=1)
    changed3 = ta.update_from_dnskey_rrset(
        store,
        zone,
        empty_rrset,
        now=t2,
        hold_down_add_days=1,
        hold_down_remove_days=1,
    )
    assert changed3 is True
    assert entries[0]["status"] == "pending_remove"

    # After the removal hold-down expires, the key should be dropped entirely.
    t3 = t2 + timedelta(days=2)
    changed4 = ta.update_from_dnskey_rrset(
        store,
        zone,
        empty_rrset,
        now=t3,
        hold_down_add_days=1,
        hold_down_remove_days=1,
    )
    assert changed4 is True
    assert store[zone]["keys"] == []


def test_update_from_dnskey_rrset_error_paths_and_existing_entries() -> None:
    """Brief: update_from_dnskey_rrset handles bad rdatas and malformed entries.

    Inputs:
      - None.

    Outputs:
      - None; asserts exceptions in live set and entries are ignored.
    """

    store: ta.Store = {}
    zone = "."

    # Existing malformed entry: bad first_seen timestamp so fromisoformat fails.
    bad_entry = {
        "key_tag": 1234,
        "algorithm": 8,
        "public_key_b64": "AAA=",
        "status": "trusted",
        "first_seen": "not-a-timestamp",
        "last_seen": "not-a-timestamp",
    }
    ta._zone_bucket(store, zone)["keys"] = [bad_entry]

    # rrset contains one good KSK and one bad object that causes key_id() to fail.
    rrset = _root_dnskey_rrset()
    good_dnskey = rrset[0]

    class _BadDNSKEY:
        def __init__(self) -> None:
            self.flags = int(getattr(dns.dnssec.Flag, "SEP", 0))
            self.algorithm = 8
            self.rdclass = dns.rdataclass.IN
            self.rdtype = dns.rdatatype.DNSKEY

        def to_text(self) -> str:  # noqa: D401
            """Return bogus text so key_id raises internally."""

            return "257 3 8 BADKEY"

    mixed_rrset = dns.rrset.RRset(
        dns.name.from_text(zone), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    mixed_rrset.add(good_dnskey)
    mixed_rrset.add(_BadDNSKEY())

    now = datetime(2020, 1, 1, tzinfo=timezone.utc)
    changed = ta.update_from_dnskey_rrset(
        store,
        zone,
        mixed_rrset,
        now=now,
        hold_down_add_days=0,
        hold_down_remove_days=0,
    )

    # The malformed entry should still be present (exception path hit), and
    # the function should have registered at least one valid live key.
    assert changed is True
    bucket = store[zone]
    assert any(e.get("key_tag") == bad_entry["key_tag"] for e in bucket["keys"])
    assert any(e.get("status") in {"pending_add", "trusted"} for e in bucket["keys"])
