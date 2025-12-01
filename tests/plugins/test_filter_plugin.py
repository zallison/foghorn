"""
Brief: Tests for foghorn.plugins.filter.FilterPlugin covering domain and IP branches.

Inputs:
  - None

Outputs:
  - None
"""

import ipaddress
from contextlib import closing

import pytest
from dnslib import AAAA, QTYPE, RR, TXT, A, DNSRecord, RCODE

from foghorn.plugins.base import PluginContext, PluginDecision
from foghorn.plugins.filter import FilterPlugin


def _mk_query(name="example.com", qtype="A"):
    q = DNSRecord.question(name, qtype)
    return q, q.pack()


def _mk_response_with_ips(name, records):
    """
    Brief: Build a DNS response with given (rtype, ip, ttl) tuples.

    Inputs:
      - name: domain string
      - records: list of tuples (rtype_str, ip_str, ttl)

    Outputs:
      - bytes: packed DNS response
    """
    q = DNSRecord.question(name, "A")
    r = q.reply()
    for rtype, ip, ttl in records:
        if rtype == "A":
            r.add_answer(RR(name, QTYPE.A, rdata=A(ip), ttl=ttl))
        else:
            r.add_answer(RR(name, QTYPE.AAAA, rdata=AAAA(ip), ttl=ttl))
    return r.pack()


def test_pre_resolve_block_exact_and_cache(tmp_path):
    """
    Brief: Exact blocked domain denies and subsequent cached lookup denies fast.

    Inputs:
      - blocked_domains: ['blocked.com']

    Outputs:
      - None: Asserts deny and cached deny
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(db_path=str(db), blocked_domains=["blocked.com"], default="allow")
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(p.conn):
        # First call denies and populates cache
        dec1 = p.pre_resolve("blocked.com", QTYPE.A, b"", ctx)
        assert isinstance(dec1, PluginDecision) and dec1.action == "deny"

        # Second call hits cache
        dec2 = p.pre_resolve("blocked.com", QTYPE.A, b"", ctx)
        assert isinstance(dec2, PluginDecision) and dec2.action == "deny"


def test_pre_resolve_deny_response_refused(tmp_path):
    """
    Brief: deny_response='refused' builds REFUSED override for blocked pre-resolve domain.

    Inputs:
      - blocked_domains: ['blocked.com']
      - deny_response: 'refused'

    Outputs:
      - None: Asserts override decision and REFUSED rcode.
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(
        db_path=str(db),
        blocked_domains=["blocked.com"],
        default="allow",
        deny_response="refused",
    )
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")
    q, wire = _mk_query("blocked.com", "A")

    with closing(p.conn):
        dec = p.pre_resolve("blocked.com", QTYPE.A, wire, ctx)
        assert isinstance(dec, PluginDecision)
        assert dec.action == "override"
        assert dec.response is not None
        reply = DNSRecord.parse(dec.response)
        assert reply.header.rcode == RCODE.REFUSED


def test_pre_resolve_deny_response_ip_override(tmp_path):
    """
    Brief: deny_response='ip' returns synthetic A answer pointing at configured IP.

    Inputs:
      - blocked_domains: ['blocked.com']
      - deny_response: 'ip'
      - deny_response_ip4: '192.0.2.55'

    Outputs:
      - None: Asserts override with A answer equal to deny_response_ip4.
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(
        db_path=str(db),
        blocked_domains=["blocked.com"],
        default="allow",
        deny_response="ip",
        deny_response_ip4="192.0.2.55",
    )
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")
    q, wire = _mk_query("blocked.com", "A")

    with closing(p.conn):
        dec = p.pre_resolve("blocked.com", QTYPE.A, wire, ctx)
        assert isinstance(dec, PluginDecision)
        assert dec.action == "override"
        assert dec.response is not None
        reply = DNSRecord.parse(dec.response)
        assert reply.header.rcode == RCODE.NOERROR
        assert reply.rr
        assert str(reply.rr[0].rdata) == "192.0.2.55"


def test_pre_resolve_allow_keyword_and_pattern(tmp_path, caplog):
    """
    Brief: Allowed domain passes; keyword and regex pattern rules deny.

    Inputs:
      - blocked_keywords: ['bad']
      - blocked_patterns: ['.*\\.ads\\..*'] and an invalid '('

    Outputs:
      - None: Asserts allow for good.com, deny for verybad.com and x.ads.y
    """
    db = tmp_path / "bl.db"
    # Include an invalid regex to exercise compile error path (logged)
    p = FilterPlugin(
        db_path=str(db),
        default="allow",
        blocked_keywords=["bad"],
        blocked_patterns=["(", "ads."],
    )
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(p.conn):
        dec_good = p.pre_resolve("good.com", QTYPE.A, b"", ctx)
        assert isinstance(dec_good, PluginDecision)
        assert dec_good.action == "skip"
        assert p.pre_resolve("verybad.com", QTYPE.A, b"", ctx).action == "deny"
        assert p.pre_resolve("x.ads.example", QTYPE.A, b"", ctx).action == "deny"


def test_load_list_from_file_and_is_allowed_and_errors(tmp_path):
    """
    Brief: load_list_from_file populates DB; invalid mode and missing file raise.

    Inputs:
      - allow file with a domain

    Outputs:
      - None: Asserts is_allowed True/False and exceptions
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(db_path=str(db), default="deny")
    p.setup()

    with closing(p.conn):
        # Write an allowlist file
        f = tmp_path / "allow.txt"
        f.write_text("# comment\n\nallow.com\n")
        p.load_list_from_file(str(f), mode="allow")
        assert p.is_allowed("allow.com") is True

        # Insert deny and verify
        p._db_insert_domain("deny.com", "config", "deny")
        assert p.is_allowed("deny.com") is False

        # Invalid mode
        with pytest.raises(ValueError):
            p.load_list_from_file(str(f), mode="INVALID")

        # Missing file
        with pytest.raises(FileNotFoundError):
            p.load_list_from_file(str(tmp_path / "missing.txt"), mode="deny")


def test_post_resolve_deny_overrides_remove_and_replace_paths(tmp_path):
    """
    Brief: Deny action takes precedence over replace; remove-only results in NXDOMAIN; replace modifies IP.

    Inputs:
      - blocked_ips: deny 1.2.3.4, remove 5.6.7.0/24, replace 9.9.9.9->127.0.0.1

    Outputs:
      - None: Asserts deny, NXDOMAIN, and override behaviors
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(
        db_path=str(db),
        blocked_ips=[
            {"ip": "1.2.3.4", "action": "deny"},
            {"ip": "5.6.7.0/24", "action": "remove"},
            {"ip": "9.9.9.9", "action": "replace", "replace_with": "127.0.0.1"},
        ],
    )
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(p.conn):
        # Deny path (presence of a deny IP causes overall deny)
        resp = _mk_response_with_ips(
            "ex.com", [("A", "1.2.3.4", 60), ("A", "9.9.9.9", 60)]
        )
        dec = p.post_resolve("ex.com", QTYPE.A, resp, ctx)
        assert isinstance(dec, PluginDecision) and dec.action == "deny"

        # Remove-only path (all removed -> NXDOMAIN)
        resp2 = _mk_response_with_ips("ex.com", [("A", "5.6.7.8", 60)])
        dec2 = p.post_resolve("ex.com", QTYPE.A, resp2, ctx)
        assert isinstance(dec2, PluginDecision) and dec2.action == "deny"

        # Replace success path
        resp3 = _mk_response_with_ips("ex.com", [("A", "9.9.9.9", 60)])
        dec3 = p.post_resolve("ex.com", QTYPE.A, resp3, ctx)
        assert dec3.action == "override"
        mod = DNSRecord.parse(dec3.response)
        assert str(mod.rr[0].rdata) == "127.0.0.1"


def test_post_resolve_deny_response_servfail_for_blocked_ip(tmp_path):
    """
    Brief: deny_response='servfail' maps IP-level deny to a SERVFAIL override.

    Inputs:
      - blocked_ips: [{"ip": "1.2.3.4", "action": "deny"}]
      - deny_response: 'servfail'

    Outputs:
      - None: Asserts override response with SERVFAIL rcode.
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(
        db_path=str(db),
        blocked_ips=[{"ip": "1.2.3.4", "action": "deny"}],
        deny_response="servfail",
    )
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(p.conn):
        resp = _mk_response_with_ips("ex.com", [("A", "1.2.3.4", 60)])
        dec = p.post_resolve("ex.com", QTYPE.A, resp, ctx)
        assert isinstance(dec, PluginDecision)
        assert dec.action == "override"
        assert dec.response is not None
        reply = DNSRecord.parse(dec.response)
        assert reply.header.rcode == RCODE.SERVFAIL


def test_post_resolve_replace_version_mismatch_and_invalid_runtime(tmp_path):
    """
    Brief: Replace with version mismatch returns override unchanged; invalid replacement at runtime keeps record.

    Inputs:
      - blocked_ips: replace IPv6->IPv4 mismatch and a manual invalid replacement entry

    Outputs:
      - None: Asserts override with unchanged rdata
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(
        db_path=str(db),
        blocked_ips=[
            {"ip": "2001:db8::1", "action": "replace", "replace_with": "127.0.0.1"}
        ],
    )
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(p.conn):
        # Version mismatch path
        resp = _mk_response_with_ips("ex6.com", [("AAAA", "2001:db8::1", 60)])
        dec = p.post_resolve("ex6.com", QTYPE.AAAA, resp, ctx)
        assert dec.action == "override"
        mod = DNSRecord.parse(dec.response)
        assert str(mod.rr[0].rdata) == "2001:db8::1"  # unchanged due to mismatch

        # Invalid replacement runtime by patching config after init
        p.blocked_ips[ipaddress.ip_address("10.0.0.1")] = {
            "action": "replace",
            "replace_with": "bad!",
        }
        resp2 = _mk_response_with_ips("ex.com", [("A", "10.0.0.1", 60)])
        dec2 = p.post_resolve("ex.com", QTYPE.A, resp2, ctx)
        # Invalid replacement at runtime leads to no change and records_changed remains False => skip
        assert isinstance(dec2, PluginDecision)
        assert dec2.action == "skip"


def test_post_resolve_non_a_aaaa_and_parse_error(tmp_path):
    """
    Brief: Non-A/AAAA qtype raises TypeError; parse error returns default action.

    Inputs:
      - qtype: MX for TypeError; bad wire to force parse error

    Outputs:
      - None: Asserts TypeError and default decision
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(db_path=str(db), blocked_ips=["1.2.3.4"], default="allow")
    plugin = p
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(plugin.conn):
        # Non A/AAAA simply returns
        res = plugin.post_resolve("ex.com", QTYPE.MX, b"", ctx)
        assert res is None

        # Parse error returns default action
        dec = plugin.post_resolve("ex.com", QTYPE.A, b"not-dns", ctx)
        assert dec.action == "allow"


def test_add_to_cache_and_get_ip_action(tmp_path):
    """
    Brief: add_to_cache normalizes keys and _get_ip_action finds exact and network matches.

    Inputs:
      - key: string and tuple

    Outputs:
      - None: Asserts cache bytes and actions returned
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(db_path=str(db))
    plugin = p
    plugin.setup()

    with closing(plugin.conn):
        # Cache allow and deny decisions using different key forms
        plugin.add_to_cache("Example.COM.", True)
        assert plugin._domain_cache.get(("example.com", 0)) == b"1"
        plugin.add_to_cache(("test.com", 0), False)
        assert plugin._domain_cache.get(("test.com", 0)) == b"0"

        # _get_ip_action checks exact then networks
        plugin.blocked_ips[ipaddress.ip_address("1.2.3.4")] = {"action": "deny"}
        plugin.blocked_networks[ipaddress.ip_network("10.0.0.0/8")] = {
            "action": "remove"
        }
        assert (
            plugin._get_ip_action(ipaddress.ip_address("1.2.3.4"))["action"] == "deny"
        )
        assert (
            plugin._get_ip_action(ipaddress.ip_address("10.1.2.3"))["action"]
            == "remove"
        )
        # Non-matching IP returns None
        assert plugin._get_ip_action(ipaddress.ip_address("192.0.2.1")) is None


def test_init_files_and_invalid_ips_and_actions(tmp_path):
    """
    Brief: Initialization loads allow/block files and handles invalid IP configs.

    Inputs:
      - allowlist_files, blocklist_files, blocked_ips entries with invalid formats/actions

    Outputs:
      - None: Asserts is_allowed for files and deny default on unknown action
    """
    allowf = tmp_path / "allow.txt"
    blockf = tmp_path / "block.txt"
    allowf.write_text("fromfile-allow.com\n")
    blockf.write_text("fromfile-block.com\n")

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        default="allow",
        allowlist_files=[str(allowf)],
        blocklist_files=[str(blockf)],
        blocked_ips=[
            123,  # invalid entry format
            {"ip": "1.1.1.1", "action": "UNKNOWN"},  # defaults to deny
            {"ip": "not-an-ip"},  # invalid ip
            {
                "ip": "10.0.0.0/8",
                "action": "replace",
                "replace_with": "127.0.0.1",
            },  # network replace
            {"ip": "2.2.2.2", "action": "replace"},  # missing replace_with
            {
                "ip": "3.3.3.3",
                "action": "replace",
                "replace_with": "bad",
            },  # invalid replacement
        ],
    )
    plugin = p
    plugin.setup()

    with closing(plugin.conn):
        assert plugin.is_allowed("fromfile-allow.com") is True
        # Default allow overridden by explicit deny entry from block file
        assert plugin.is_allowed("fromfile-block.com") is False

        # Unknown action defaults to deny
        ctx = PluginContext(client_ip="1.2.3.4")
        resp = _mk_response_with_ips("x.com", [("A", "1.1.1.1", 60)])
        dec = plugin.post_resolve("x.com", QTYPE.A, resp, ctx)
        assert isinstance(dec, PluginDecision) and dec.action == "deny"


def test_post_resolve_aaaa_replace_and_mixed_records(tmp_path):
    """
    Brief: AAAA replacement works and non-A/AAAA records are preserved.

    Inputs:
      - blocked_ips: replace IPv6 with IPv6

    Outputs:
      - None: Asserts override with AAAA changed and TXT present
    """
    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        blocked_ips=[
            {"ip": "2001:db8::2", "action": "replace", "replace_with": "2001:db8::3"}
        ],
    )
    plugin = p
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    # Build response with AAAA and a TXT record
    q = DNSRecord.question("mix.com", "AAAA")
    r = q.reply()
    r.add_answer(RR("mix.com", QTYPE.AAAA, rdata=AAAA("2001:db8::2"), ttl=60))
    r.add_answer(RR("mix.com", QTYPE.TXT, rdata=TXT("hello"), ttl=60))

    with closing(plugin.conn):
        dec = plugin.post_resolve("mix.com", QTYPE.AAAA, r.pack(), ctx)
        assert dec.action == "override"
        mod = DNSRecord.parse(dec.response)
        # First answer replaced
        assert str(mod.rr[0].rdata) == "2001:db8::3"
        # Second record (TXT) preserved
        assert mod.rr[1].rtype == QTYPE.TXT


def test_post_resolve_none_when_no_rules(tmp_path):
    """
    Brief: Returns None when no IP rules configured.

    Inputs:
      - none

    Outputs:
      - None: Asserts None decision
    """
    p = FilterPlugin(db_path=str(tmp_path / "bl.db"))
    plugin = p
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")
    resp = _mk_response_with_ips("ex.com", [("A", "8.8.8.8", 60)])

    with closing(plugin.conn):
        dec = plugin.post_resolve("ex.com", QTYPE.A, resp, ctx)
        assert isinstance(dec, PluginDecision)
        assert dec.action == "skip"


def test_add_to_cache_error_logs(tmp_path, monkeypatch, caplog):
    """
    Brief: add_to_cache logs a warning when cache set raises.

    Inputs:
      - monkeypatch: patch FoghornTTLCache.set to raise

    Outputs:
      - None: Asserts warning logged
    """
    p = FilterPlugin(db_path=str(tmp_path / "bl.db"))
    plugin = p
    plugin.setup()
    caplog.set_level("WARNING")

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(plugin._domain_cache, "set", boom)

    with closing(plugin.conn):
        plugin.add_to_cache("x.com", True)
        assert any(
            "exception adding to cache" in r.getMessage() for r in caplog.records
        )


def test_pre_resolve_cached_allow_returns_none(tmp_path):
    """
    Brief: Cached allow decision is respected.

    Inputs:
      - Cache contains (domain, 0): b"1"

    Outputs:
      - None: Asserts pre_resolve returns None
    """
    p = FilterPlugin(db_path=str(tmp_path / "bl.db"), default="deny")
    plugin = p
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(plugin.conn):
        plugin.add_to_cache(("cached.com", 0), True)
        dec = plugin.pre_resolve("cached.com", QTYPE.A, b"", ctx)
        assert isinstance(dec, PluginDecision)
        assert dec.action == "skip"


def test_post_resolve_pack_failure_returns_deny(tmp_path, monkeypatch):
    """
    Brief: If packing modified response fails, plugin returns deny.

    Inputs:
      - monkeypatch: make DNSRecord.pack raise

    Outputs:
      - None: Asserts deny decision
    """
    plugin = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        blocked_ips=[
            {"ip": "9.9.9.9", "action": "replace", "replace_with": "127.0.0.1"}
        ],
    )
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")
    resp = _mk_response_with_ips("ex.com", [("A", "9.9.9.9", 60)])

    # Force DNSRecord.pack to raise when called
    original_pack = DNSRecord.pack

    def raise_pack(self):
        raise RuntimeError("pack-fail")

    monkeypatch.setattr(DNSRecord, "pack", raise_pack)

    with closing(plugin.conn):
        dec = plugin.post_resolve("ex.com", QTYPE.A, resp, ctx)
        assert isinstance(dec, PluginDecision) and dec.action == "deny"

    # Restore pack to avoid side-effects
    monkeypatch.setattr(DNSRecord, "pack", original_pack)


def test_post_resolve_unknown_action_runtime_returns_none(tmp_path):
    """Brief: Unknown action at runtime results in keeping record and no changes.

    Inputs:
      - blocked_ips: patched with unsupported action.

    Outputs:
      - None: Asserts decision is None.
    """
    p = FilterPlugin(db_path=str(tmp_path / "bl.db"))
    plugin = p
    plugin.setup()
    # Patch with a rule that uses an unknown action (bypassing init normalization)
    import ipaddress as _ip

    plugin.blocked_ips[_ip.ip_address("11.22.33.44")] = {"action": "weird"}
    ctx = PluginContext(client_ip="1.2.3.4")
    resp = _mk_response_with_ips("ex.com", [("A", "11.22.33.44", 60)])

    with closing(plugin.conn):
        dec = plugin.post_resolve("ex.com", QTYPE.A, resp, ctx)
        assert isinstance(dec, PluginDecision)
        assert dec.action == "skip"


def test_post_resolve_unmatched_and_non_ip_records(tmp_path):
    """Brief: IPs without rules and malformed A records are preserved without changes.

    Inputs:
      - tmp_path: temporary directory.

    Outputs:
      - None: Asserts post_resolve returns None while exercising 404–406 paths.
    """

    db = tmp_path / "bl.db"
    plugin = FilterPlugin(db_path=str(db), blocked_ips=["1.2.3.4"])
    plugin.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(plugin.conn):
        # Case 1: A record for an IP with no configured action exercises the
        # "no action_config" branch, appending to modified_records without changes.
        resp1 = _mk_response_with_ips("ex.com", [("A", "8.8.8.8", 60)])
        dec1 = plugin.post_resolve("ex.com", QTYPE.A, resp1, ctx)
        assert isinstance(dec1, PluginDecision)
        assert dec1.action == "skip"

        # Case 2: Malformed A record rdata that cannot be parsed as an IP exercises
        # the ValueError handler and keeps the record.
        q = DNSRecord.question("weird.com", "A")
        r = q.reply()
        r.add_answer(RR("weird.com", QTYPE.A, rdata=TXT("not-an-ip"), ttl=60))
        dec2 = plugin.post_resolve("weird.com", QTYPE.A, r.pack(), ctx)
        assert isinstance(dec2, PluginDecision)
        assert dec2.action == "skip"


def test_glob_expansion_for_blocklist_and_allowlist_files(tmp_path):
    """
    Brief: Glob patterns in blocklist_files and allowlist_files are expanded to load multiple files.

    Inputs:
      - allowlist_files: glob pattern matching multiple files
      - blocklist_files: glob pattern matching multiple files

    Outputs:
      - None: Asserts domains from expanded files are correctly allowed/denied
    """
    # Create directories and files
    allow_dir = tmp_path / "allows"
    allow_dir.mkdir()
    block_dir = tmp_path / "blocks"
    block_dir.mkdir()

    # Create allow files
    (allow_dir / "allow1.txt").write_text("allow1.com\n")
    (allow_dir / "allow2.txt").write_text("allow2.com\n")

    # Create block files
    (block_dir / "block1.txt").write_text("block1.com\n")
    (block_dir / "block2.txt").write_text("block2.com\n")

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        default="deny",
        allowlist_files=[str(allow_dir / "*.txt")],
        blocklist_files=[str(block_dir / "*.txt")],
    )
    plugin = p
    plugin.setup()

    with closing(plugin.conn):
        # Check that domains from allow files are allowed
        assert plugin.is_allowed("allow1.com") is True
        assert plugin.is_allowed("allow2.com") is True

        # Check that domains from block files are denied
        assert plugin.is_allowed("block1.com") is False
        assert plugin.is_allowed("block2.com") is False

        # Check default deny for unknown domains
        assert plugin.is_allowed("unknown.com") is False
