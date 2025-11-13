"""
Brief: Extended tests for FilterPlugin file-backed inputs (domains, patterns, keywords, IPs).

Inputs:
  - None

Outputs:
  - None
"""

import ipaddress
import pytest
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, TXT

from foghorn.plugins.filter import FilterPlugin
from foghorn.plugins.base import PluginDecision, PluginContext


def _mk_response_with_ips(name, records):
    """
    Brief: Build a DNS response with given (rtype, ip, ttl) tuples.

    Args:
        name (str): domain string
        records (list[tuple[str, str, int]]): tuples (rtype_str, ip_str, ttl)

    Returns:
        bytes: packed DNS response

    Example:
        >>> # path=null start=null
        >>> _mk_response_with_ips('ex.com', [('A','1.2.3.4', 60)])  # doctest: +SKIP
    """
    q = DNSRecord.question(name, "A")
    r = q.reply()
    for rtype, ip, ttl in records:
        if rtype == "A":
            r.add_answer(RR(name, QTYPE.A, rdata=A(ip), ttl=ttl))
        else:
            r.add_answer(RR(name, QTYPE.AAAA, rdata=AAAA(ip), ttl=ttl))
    return r.pack()


def test_domains_files_allow_and_block(tmp_path):
    allowf = tmp_path / "allows.txt"
    blockf = tmp_path / "blocks.txt"
    allowf.write_text("ok.com\n")
    blockf.write_text("bad.com\n")

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        allowed_domains_files=[str(allowf)],
        blocked_domains_files=[str(blockf)],
        default="deny",
    )

    assert p.is_allowed("ok.com") is True
    assert p.is_allowed("bad.com") is False
    assert p.is_allowed("unknown.com") is False


def test_patterns_and_keywords_files(tmp_path, caplog):
    pats = tmp_path / "patterns.re"
    keys = tmp_path / "keywords.txt"
    pats.write_text("# comment\n(\n^ads\\.\n")  # includes an invalid and a valid
    keys.write_text("\nTracker\n#x\nanalytics\n")

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        blocked_patterns_files=[str(pats)],
        blocked_keywords_files=[str(keys)],
        default="allow",
    )
    ctx = PluginContext(client_ip="1.2.3.4")

    assert p.pre_resolve("ads.example", QTYPE.A, b"", ctx).action == "deny"
    assert p.pre_resolve("mytracker.site", QTYPE.A, b"", ctx).action == "deny"
    assert p.pre_resolve("best-analytics.io", QTYPE.A, b"", ctx).action == "deny"


def test_blocked_ips_files_csv_simple_and_jsonl(tmp_path):
    ips = tmp_path / "ips.csv"
    ips.write_text(
        "\n".join(
            [
                "192.0.2.1",
                "198.51.100.0/24",
                "203.0.113.1,remove",
                "203.0.113.2,replace,203.0.113.200",
                "2001:db8::1,replace,2001:db8::ffff",
                "203.0.113.5,replace",  # invalid, missing replacement
                "bogus,deny",  # invalid ip
                "203.0.113.6,foo",  # unknown action => deny
                "203.0.113.7,replace,not_ip",
            ]
        )
    )
    jsonl = tmp_path / "ips.jsonl"
    jsonl.write_text(
        "\n".join(
            [
                '{"ip": "203.0.113.9", "action": "deny"}',
                '{"ip": "203.0.113.10", "action": "replace", "replace_with": "203.0.113.200"}',
                '{"ip": "198.51.100.128/25", "action": "remove"}',
                '{"ip": "", "action": "deny"}',  # invalid missing ip
                '{"ip": "203.0.113.11", "action": "replace"}',  # missing replace_with
                '{"ip": "bad", "action": "deny"}',  # invalid ip
            ]
        )
    )

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        blocked_ips_files=[str(ips), str(jsonl)],
        default="allow",
    )
    ctx = PluginContext(client_ip="1.2.3.4")

    # Deny dominates overall when present (from simple/CSV and JSONL)
    resp = _mk_response_with_ips(
        "ex.com",
        [
            ("A", "192.0.2.1", 60),
            ("A", "203.0.113.2", 60),
            ("A", "203.0.113.9", 60),
        ],
    )
    dec = p.post_resolve("ex.com", QTYPE.A, resp, ctx)
    assert isinstance(dec, PluginDecision) and dec.action == "deny"

    # Remove-only path => NXDOMAIN when all removed (CIDR remove from either file)
    resp2 = _mk_response_with_ips("ex.com", [("A", "198.51.100.200", 60)])
    dec2 = p.post_resolve("ex.com", QTYPE.A, resp2, ctx)
    assert isinstance(dec2, PluginDecision) and dec2.action == "deny"

    # Replace path from JSONL
    resp3 = _mk_response_with_ips("ex.com", [("A", "203.0.113.10", 60)])
    dec3 = p.post_resolve("ex.com", QTYPE.A, resp3, ctx)
    assert dec3.action == "override"
    mod = DNSRecord.parse(dec3.response)
    assert str(mod.rr[0].rdata) == "203.0.113.200"

    # IPv6 replace path remains override with changed AAAA
    q = DNSRecord.question("ex6.com", "AAAA")
    r = q.reply()
    r.add_answer(RR("ex6.com", QTYPE.AAAA, rdata=AAAA("2001:db8::1"), ttl=60))
    dec4 = p.post_resolve("ex6.com", QTYPE.AAAA, r.pack(), ctx)
    assert dec4.action == "override"
    mod4 = DNSRecord.parse(dec4.response)
    assert str(mod4.rr[0].rdata) == "2001:db8::ffff"


def test_glob_expansion_for_new_files(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "k1.txt").write_text("x\n")
    (d / "k2.txt").write_text("y\n")
    (d / "p1.re").write_text("^test$\n")
    (d / "p2.re").write_text("^demo$\n")

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        blocked_keywords_files=[str(d / "k*.txt")],
        blocked_patterns_files=[str(d / "p*.re")],
        default="allow",
    )
    ctx = PluginContext(client_ip="1.2.3.4")

    # keywords
    assert p.pre_resolve("xhost", QTYPE.A, b"", ctx).action == "deny"
    assert p.pre_resolve("yhost", QTYPE.A, b"", ctx).action == "deny"

    # patterns
    assert p.pre_resolve("test", QTYPE.A, b"", ctx).action == "deny"
    assert p.pre_resolve("demo", QTYPE.A, b"", ctx).action == "deny"


def test_missing_files_raise(tmp_path):
    with pytest.raises(FileNotFoundError):
        FilterPlugin(
            db_path=str(tmp_path / "bl.db"),
            blocked_patterns_files=[str(tmp_path / "nope.re")],
        )
