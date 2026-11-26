"""Brief: Coverage for operator trust-anchor config wiring.

Inputs:
  - pytest harness / tmp_path / monkeypatch.

Outputs:
  - Assertions over configure helpers, live RFC 5011 updates, custom anchors,
    and runtime snapshot apply.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from foghorn.dnssec import dnssec_validate as dval
from foghorn.dnssec import trust_anchors as ta


def _clear_ta_state(monkeypatch, tmp_path: Path | None = None) -> str | None:
    """Brief: Reset module trust-anchor globals for isolated tests.

    Inputs:
      - monkeypatch: pytest monkeypatch.
      - tmp_path: optional path for a store file.

    Outputs:
      - store path string when tmp_path provided, else None.
    """

    store = str(tmp_path / "ta.json") if tmp_path is not None else None
    dval.configure_trust_anchors(
        mode="static",
        store_path=None,
        hold_down_add_days=2,
        hold_down_remove_days=2,
        custom_anchors=None,
    )
    dval._DNSKEY_CACHE.clear()
    dval._DS_CACHE.clear()
    return store


def _root_key_rrset() -> dns.rrset.RRset:
    """Brief: Build a DNSKEY rrset from the baked-in root constant.

    Inputs:
      - None.

    Outputs:
      - DNSKEY RRset for '.'.
    """

    return dval._baked_in_root_dnskey_rrset()


def test_configure_from_dnssec_cfg_parses_custom_and_mode(tmp_path: Path) -> None:
    """Brief: configure_trust_anchors_from_dnssec_cfg applies mode/store/customs.

    Inputs:
      - tmp_path: temporary directory for store path.

    Outputs:
      - None; asserts globals and custom DNSKEY/DS maps.
    """

    store = str(tmp_path / "store.json")
    pub = _root_key_rrset()[0].to_text().split()[-1]
    dval.configure_trust_anchors_from_dnssec_cfg(
        {
            "trust_anchor_mode": "rfc5011",
            "trust_anchor_store_path": store,
            "hold_down_add_days": 5,
            "hold_down_remove_days": 7,
            "trust_anchors": [
                {
                    "zone": ".",
                    "type": "dnskey",
                    "algorithm": 8,
                    "flags": 257,
                    "public_key": pub,
                },
                {
                    "zone": "internal.example.",
                    "type": "ds",
                    "key_tag": 12345,
                    "algorithm": 8,
                    "digest_type": 2,
                    "digest": "ab" * 32,
                },
            ],
        },
        enforce_data_root=False,
    )
    assert dval._TRUST_ANCHOR_MODE == "rfc5011"
    assert dval._TRUST_ANCHOR_STORE_PATH == store
    assert dval._TRUST_ANCHOR_HOLD_ADD_DAYS == 5
    assert dval._TRUST_ANCHOR_HOLD_REMOVE_DAYS == 7
    assert "." in dval._CUSTOM_DNSKEY_ANCHORS
    assert "internal.example." in dval._CUSTOM_DS_ANCHORS


def test_maybe_rfc5011_update_promotes_new_key(tmp_path: Path, monkeypatch) -> None:
    """Brief: Live authenticated root DNSKEY updates the RFC 5011 store.

    Inputs:
      - tmp_path / monkeypatch.

    Outputs:
      - None; asserts pending_add then trusted after hold-down.
    """

    store_path = _clear_ta_state(monkeypatch, tmp_path)
    assert store_path is not None
    base = _root_key_rrset()
    # Seed store with baked-in key as trusted.
    store: ta.Store = {}
    ta.bootstrap_from_rrset(store, ".", base)
    ta.save_store(store_path, store)

    dval.configure_trust_anchors(
        mode="rfc5011",
        store_path=store_path,
        hold_down_add_days=1,
        hold_down_remove_days=1,
    )

    new_key = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.DNSKEY, "257 3 8 AQAB"
    )
    live = dns.rrset.RRset(dns.name.root, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    live.add(base[0])
    live.add(new_key)

    day0 = datetime(2025, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(ta, "_now_utc", lambda: day0)
    dval._maybe_rfc5011_update_from_live_dnskey(".", live)

    loaded = ta.load_store(store_path)
    statuses = {e["key_tag"]: e["status"] for e in loaded["."]["keys"]}
    new_tag = dns.dnssec.key_id(new_key)
    assert statuses[new_tag] == "pending_add"

    day2 = day0 + timedelta(days=2)
    monkeypatch.setattr(ta, "_now_utc", lambda: day2)
    dval._maybe_rfc5011_update_from_live_dnskey(".", live)
    loaded = ta.load_store(store_path)
    statuses = {e["key_tag"]: e["status"] for e in loaded["."]["keys"]}
    assert statuses[new_tag] == "trusted"


def test_maybe_rfc5011_noop_in_static_mode(tmp_path: Path) -> None:
    """Brief: static mode does not write the store on live DNSKEY observation.

    Inputs:
      - tmp_path.

    Outputs:
      - None; asserts store file absent after update attempt.
    """

    store_path = str(tmp_path / "unused.json")
    dval.configure_trust_anchors(mode="static", store_path=store_path)
    dval._maybe_rfc5011_update_from_live_dnskey(".", _root_key_rrset())
    assert not Path(store_path).exists()


def test_root_dnskey_merges_custom_root_anchor() -> None:
    """Brief: custom root DNSKEY anchors appear in _root_dnskey_rrset.

    Inputs:
      - None.

    Outputs:
      - None; asserts two keys when custom differs from baked-in.
    """

    dval.configure_trust_anchors(
        mode="static",
        custom_anchors=[
            {
                "zone": ".",
                "algorithm": 8,
                "flags": 257,
                "public_key": "AQAB",
            }
        ],
    )
    rrset = dval._root_dnskey_rrset()
    assert rrset is not None
    assert len(list(rrset)) >= 2


def test_apply_dnssec_validation_runtime_sets_resolver() -> None:
    """Brief: apply_dnssec_validation_runtime configures forward validation NS.

    Inputs:
      - None.

    Outputs:
      - None; asserts nameserver list for local validate + forward.
    """

    dval.apply_dnssec_validation_runtime(
        dnssec_cfg={"trust_anchor_mode": "static"},
        dnssec_mode="validate",
        dnssec_validation="local",
        resolver_mode="forward",
        upstream_hosts=["192.0.2.1", "203.0.113.1"],
        enforce_data_root=False,
    )
    assert dval._VALIDATION_NAMESERVERS == ["192.0.2.1", "203.0.113.1"]
    assert dval._VALIDATION_VIA_RECURSIVE is False

    dval.apply_dnssec_validation_runtime(
        dnssec_cfg={},
        dnssec_mode="validate",
        dnssec_validation="local",
        resolver_mode="recursive",
        upstream_hosts=None,
        enforce_data_root=False,
    )
    assert dval._VALIDATION_VIA_RECURSIVE is True


def test_runtime_snapshot_apply_reconfigures_trust_anchors(tmp_path: Path) -> None:
    """Brief: _apply_snapshot_to_runtime_globals reapplies dnssec TA knobs.

    Inputs:
      - tmp_path.

    Outputs:
      - None; asserts mode/store after snapshot apply.
    """

    from foghorn import runtime_config as rc

    store = str(tmp_path / "reload-ta.json")
    snap = rc._default_snapshot()
    # frozen dataclass — rebuild with cfg carrying dnssec block
    cfg = {
        "server": {
            "dnssec": {
                "mode": "validate",
                "validation": "local",
                "trust_anchor_mode": "rfc5011",
                "trust_anchor_store_path": store,
                "hold_down_add_days": 9,
            }
        }
    }
    snap = rc.RuntimeSnapshot(
        **{
            **snap.__dict__,
            "cfg": cfg,
            "dnssec_mode": "validate",
            "dnssec_validation": "local",
            "resolver_mode": "forward",
            "upstream_addrs": [{"host": "127.0.0.1"}],
        }
    )
    rc._apply_snapshot_to_runtime_globals(snap)
    assert dval._TRUST_ANCHOR_MODE == "rfc5011"
    assert dval._TRUST_ANCHOR_STORE_PATH == store
    assert dval._TRUST_ANCHOR_HOLD_ADD_DAYS == 9
    assert dval._VALIDATION_NAMESERVERS == ["127.0.0.1"]


def test_ds_matches_dnskey_helper() -> None:
    """Brief: _ds_matches_dnskey returns False for empty/mismatched sets.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    name = dns.name.from_text("example.")
    empty_ds = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.DS)
    dnskey = _root_key_rrset()
    assert dval._ds_matches_dnskey(name, empty_ds, dnskey) is False
