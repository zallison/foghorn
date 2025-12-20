from datetime import datetime, timedelta, timezone

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from foghorn.dnssec import trust_anchors as ta


def _make_dnskey(flags: int, algorithm: int, pub_b64: str) -> dns.rdata.Rdata:
    """Create a DNSKEY rdata from simple components.

    Inputs:
      - flags: DNSKEY flags field.
      - algorithm: Algorithm number.
      - pub_b64: Base64-encoded public key.

    Outputs:
      - dns.rdata.Rdata DNSKEY instance.
    """

    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        f"{flags} 3 {algorithm} {pub_b64}",
    )


def test_trust_anchors_bootstrap_and_anchors_for_zone(tmp_path):
    """Bootstrapping from a DNSKEY rrset creates trusted anchors for a zone.

    Inputs:
      - tmp_path: pytest tmp path fixture.

    Outputs:
      - Verifies that anchors_for_zone() returns DNSKEYs from the bootstrapped
        store.
    """

    k = _make_dnskey(257, 8, "AAAA")
    rrset = dns.rrset.RRset(
        dns.name.from_text("."), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    rrset.add(k)

    store = {}
    store = ta.bootstrap_from_rrset(store, ".", rrset)

    # Save and reload to exercise JSON encode/decode.
    path = tmp_path / "anchors.json"
    ta.save_store(str(path), store)
    loaded = ta.load_store(str(path))

    anchors = ta.anchors_for_zone(loaded, ".")
    assert anchors, "Expected at least one trusted anchor after bootstrap"


def test_trust_anchors_rfc5011_add_and_promote():
    """New KSK moves from pending_add to trusted after hold-down period.

    Simulates seeing a live DNSKEY rrset over multiple days and ensures
    update_from_dnskey_rrset() promotes a pending_add key to trusted.
    """

    zone = "."
    base_key = _make_dnskey(257, 8, "AAAA")
    new_key = _make_dnskey(257, 8, "AQAB")

    base_rrset = dns.rrset.RRset(
        dns.name.from_text(zone), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    base_rrset.add(base_key)

    store = {}
    store = ta.bootstrap_from_rrset(store, zone, base_rrset)

    # Day 0: introduce new_key alongside base_key.
    rrset = dns.rrset.RRset(
        dns.name.from_text(zone), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    rrset.add(base_key)
    rrset.add(new_key)

    day0 = datetime(2025, 1, 1, tzinfo=timezone.utc)
    changed = ta.update_from_dnskey_rrset(
        store, zone, rrset, now=day0, hold_down_add_days=2, hold_down_remove_days=2
    )
    assert changed is True

    # New key should be pending_add.
    bucket = store[zone]
    statuses = {e["key_tag"]: e["status"] for e in bucket["keys"]}
    new_tag = dns.dnssec.key_id(new_key)
    assert statuses[new_tag] == "pending_add"

    # Day 1: still pending_add.
    day1 = day0 + timedelta(days=1)
    changed = ta.update_from_dnskey_rrset(
        store, zone, rrset, now=day1, hold_down_add_days=2, hold_down_remove_days=2
    )
    bucket = store[zone]
    statuses = {e["key_tag"]: e["status"] for e in bucket["keys"]}
    assert statuses[new_tag] == "pending_add"

    # Day 3: hold-down (2 days) has elapsed; key should be trusted.
    day3 = day0 + timedelta(days=3)
    changed = ta.update_from_dnskey_rrset(
        store, zone, rrset, now=day3, hold_down_add_days=2, hold_down_remove_days=2
    )
    bucket = store[zone]
    statuses = {e["key_tag"]: e["status"] for e in bucket["keys"]}
    assert statuses[new_tag] == "trusted"


def test_trust_anchors_rfc5011_removal_after_hold_down():
    """Trusted key transitions to pending_remove and is removed after hold-down.

    Simulates a previously trusted key disappearing from the DNSKEY rrset and
    ensures it is only dropped after the configured removal hold-down.
    """

    zone = "."
    key = _make_dnskey(257, 8, "AQAB")

    rrset = dns.rrset.RRset(
        dns.name.from_text(zone), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    rrset.add(key)

    store = {}
    store = ta.bootstrap_from_rrset(store, zone, rrset)

    bucket = store[zone]
    tag = dns.dnssec.key_id(key)
    assert any(e["key_tag"] == tag and e["status"] == "trusted" for e in bucket["keys"])

    # Day 0: key disappears from live rrset.
    empty_rrset = dns.rrset.RRset(
        dns.name.from_text(zone), dns.rdataclass.IN, dns.rdatatype.DNSKEY
    )
    day0 = datetime(2025, 1, 1, tzinfo=timezone.utc)
    ta.update_from_dnskey_rrset(
        store,
        zone,
        empty_rrset,
        now=day0,
        hold_down_add_days=2,
        hold_down_remove_days=2,
    )

    bucket = store[zone]
    pending = [e for e in bucket["keys"] if e["key_tag"] == tag][0]
    assert pending["status"] == "pending_remove"

    # Day 1: still pending_remove.
    day1 = day0 + timedelta(days=1)
    ta.update_from_dnskey_rrset(
        store,
        zone,
        empty_rrset,
        now=day1,
        hold_down_add_days=2,
        hold_down_remove_days=2,
    )
    bucket = store[zone]
    pending = [e for e in bucket["keys"] if e["key_tag"] == tag][0]
    assert pending["status"] == "pending_remove"

    # Day 3: removal hold-down elapsed; key should be removed.
    day3 = day0 + timedelta(days=3)
    ta.update_from_dnskey_rrset(
        store,
        zone,
        empty_rrset,
        now=day3,
        hold_down_add_days=2,
        hold_down_remove_days=2,
    )
    bucket = store[zone]
    assert all(e["key_tag"] != tag for e in bucket["keys"])
