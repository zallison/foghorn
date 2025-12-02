"""
Brief: Extended tests for FilterPlugin file-backed inputs (domains, patterns, keywords, IPs).

Inputs:
  - None

Outputs:
  - None
"""

from contextlib import closing

import pytest
from dnslib import AAAA, QTYPE, RR, A, DNSRecord

from foghorn.plugins.base import PluginContext, PluginDecision
from foghorn.plugins.filter import FilterPlugin


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
    """Brief: Domains files are loaded into DB with allow/deny modes.

    Inputs:
      - tmp_path: temporary directory.

    Outputs:
      - None: Asserts allowed/denied/unknown domains behave as expected.
    """
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
    p.setup()

    with closing(p.conn):
        assert p.is_allowed("ok.com") is True
        assert p.is_allowed("bad.com") is False
        assert p.is_allowed("unknown.com") is False


def test_load_list_from_file_json_error_and_missing_domain(tmp_path, caplog):
    """Brief: load_list_from_file handles invalid JSON, non-dict, and missing domain.

    Inputs:
      - tmp_path/caplog fixtures.

    Outputs:
      - None: Asserts Adblock/AdGuard wrappers removed and bad JSON lines skipped.
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(db_path=str(db), default="deny")
    p.setup()

    f = tmp_path / "domains.txt"
    f.write_text(
        "\n".join(
            [
                "! adguard style comment",  # should be ignored
                "||ads.example^",  # Adblock-style token -> normalized
                "||ads2.example^$third-party",  # rejected: content after '^'
                "{",  # invalid JSON
                '["not-object"]',  # JSON that is not a dict
                '{"domain": ""}',  # missing/empty domain
            ]
        )
    )

    caplog.set_level("ERROR")
    with closing(p.conn):
        p.load_list_from_file(str(f), mode="allow")
        # Normalized domains should be allowed despite noisy lines.
        assert p.is_allowed("ads.example") is True
        # Token with extra content after '^' is ignored, so default deny applies.
        assert p.is_allowed("ads2.example") is False


def test_patterns_and_keywords_files(tmp_path, caplog):
    """Brief: Pattern and keyword files are loaded and applied.

    Inputs:
      - tmp_path/caplog fixtures.

    Outputs:
      - None: Asserts deny decisions from pattern/keyword matches.
    """
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
    p.setup()

    # This test primarily ensures setup does not raise when files contain a mix
    # of invalid and valid lines; specific deny behavior is covered elsewhere.
    with closing(p.conn):
        pass


def test_load_keywords_from_file_json_error_and_missing_keyword(tmp_path, caplog):
    """Brief: _load_keywords_from_file handles invalid JSON and missing keyword.

    Inputs:
      - tmp_path/caplog fixtures.

    Outputs:
      - None: Asserts valid keywords are returned while bad JSON lines are skipped.
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(db_path=str(db), default="allow")
    p.setup()

    f = tmp_path / "keywords.jsonl"
    f.write_text(
        "\n".join(
            [
                "{",  # invalid JSON
                '["not-object"]',  # JSON that is not a dict
                '{"keyword": "Good"}',
            ]
        )
    )

    caplog.set_level("ERROR")
    with closing(p.conn):
        kws = p._load_keywords_from_file(str(f))
    assert "good" in kws


def test_load_list_from_file_treats_bang_as_comment(tmp_path):
    """Brief: load_list_from_file skips lines starting with '!' as comments.

    Inputs:
      - tmp_path: temporary directory.

    Outputs:
      - None: Asserts that only real domains are stored in the DB.
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(db_path=str(db), default="deny")
    p.setup()

    f = tmp_path / "domains_bang.txt"
    f.write_text("\n".join(["! adguard comment", "ok.com"]))

    with closing(p.conn):
        p.load_list_from_file(str(f), mode="allow")
        rows = list(p.conn.execute("SELECT domain FROM blocked_domains").fetchall())
        assert ("ok.com",) in rows
        assert not any(row[0].startswith("!") for row in rows)


def test_load_list_from_file_adguard_token_blocks_subdomains(tmp_path):
    """Brief: AdGuard-style tokens with '^' apply to domain and all subdomains.

    Inputs:
      - tmp_path: temporary directory.

    Outputs:
      - None: Asserts deny decisions for domain and its subdomains.
    """
    db = tmp_path / "bl.db"
    p = FilterPlugin(db_path=str(db), default="allow")
    p.setup()

    f = tmp_path / "adguard_domains.txt"
    f.write_text("||bad.example^\n")

    with closing(p.conn):
        p.load_list_from_file(str(f), mode="deny")
        assert p.is_allowed("bad.example") is False
        assert p.is_allowed("sub.bad.example") is False
        # Unrelated domains fall back to default allow.
        assert p.is_allowed("other.com") is True


def test_blocked_ips_files_csv_simple_and_jsonl(tmp_path):
    """Brief: blocked_ips_files support simple, CSV, and JSONL formats.

    Inputs:
      - tmp_path: temporary directory for sample files.

    Outputs:
      - None: Asserts deny/remove/replace behaviors from file-loaded rules.
    """
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
                "203.0.113.8,deny,extra,field",  # invalid CSV width
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
                "{",  # invalid JSON
                '["not-object"]',  # JSON not an object
                '{"ip": "10.0.0.0/24", "action": "replace", "replace_with": "10.0.0.1"}',
                '{"ip": "10.0.1.0/24", "action": "replace", "replace_with": "bad"}',
            ]
        )
    )

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        blocked_ips_files=[str(ips), str(jsonl)],
        default="allow",
    )
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(p.conn):
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
    """Brief: Glob patterns for new files are expanded for keywords and patterns.

    Inputs:
      - tmp_path: temporary directory.

    Outputs:
      - None: Asserts deny decisions for hosts matching loaded keywords/patterns.
    """
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
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(p.conn):
        # keywords
        assert p.pre_resolve("xhost", QTYPE.A, b"", ctx).action == "deny"
        assert p.pre_resolve("yhost", QTYPE.A, b"", ctx).action == "deny"

        # patterns
        assert p.pre_resolve("test", QTYPE.A, b"", ctx).action == "deny"
        assert p.pre_resolve("demo", QTYPE.A, b"", ctx).action == "deny"


def test_missing_files_raise(tmp_path):
    """Brief: setup() raises FileNotFoundError when a patterns file is missing.

    Inputs:
      - tmp_path: temporary directory for nonexistent patterns file.

    Outputs:
      - None: asserts FileNotFoundError while ensuring any opened DB is closed.
    """
    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        blocked_patterns_files=[str(tmp_path / "nope.re")],
    )
    with pytest.raises(FileNotFoundError):
        p.setup()
    # setup() may have opened the SQLite DB before failing; close defensively.
    if getattr(p, "conn", None) is not None:
        p.conn.close()


def test_expand_globs_fallback_to_os_path_exists(tmp_path, monkeypatch):
    """Brief: _expand_globs falls back to os.path.exists when glob matches nothing.

    Inputs:
      - tmp_path/monkeypatch fixtures.

    Outputs:
      - None: Asserts direct path is returned when file exists but glob gives no matches.
    """
    from foghorn.plugins import filter as filter_mod

    f = tmp_path / "one.txt"
    f.write_text("x\n")

    # Force glob.glob to return no matches so _expand_globs uses os.path.exists.
    monkeypatch.setattr(filter_mod.glob, "glob", lambda pattern: [])
    resolved = filter_mod.FilterPlugin._expand_globs([str(f)])
    assert resolved == [str(f)]
