"""
Brief: Additional tests for JSON Lines support in domains, patterns, and keywords files.

Inputs:
  - None

Outputs:
  - None
"""

from contextlib import closing

from dnslib import QTYPE

from foghorn.plugins.resolve.base import PluginContext
from foghorn.plugins.resolve.filter import FilterPlugin


def test_domains_jsonl_with_modes(tmp_path):
    f = tmp_path / "domains.jsonl"
    f.write_text(
        "\n".join(
            [
                '{"domain":"a-allow.com","mode":"allow"}',
                '{"domain":"b-deny.com","mode":"deny"}',
                '{"domain":"c-default.com"}',
            ]
        )
    )

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        allowed_domains_files=[str(f)],  # initial mode allow, per-line override applies
        default="deny",
    )
    p.setup()

    with closing(p.conn):
        assert p.is_allowed("a-allow.com") is True
        assert p.is_allowed("b-deny.com") is False
        # Falls back to file-level mode 'allow'
        assert p.is_allowed("c-default.com") is True


def test_patterns_keywords_jsonl(tmp_path):
    pats = tmp_path / "patterns.jsonl"
    keys = tmp_path / "keywords.jsonl"
    pats.write_text(
        "\n".join(
            [
                '{"pattern": "^ads\\\\.", "flags": ["IGNORECASE"]}',
                '{"pattern": "^track\\\\.", "flags": []}',
            ]
        )
    )
    keys.write_text(
        "\n".join(
            [
                '{"keyword": "Tracker"}',
                '{"keyword": "analytics"}',
            ]
        )
    )

    p = FilterPlugin(
        db_path=str(tmp_path / "bl.db"),
        blocked_patterns_files=[str(pats)],
        blocked_keywords_files=[str(keys)],
        default="allow",
    )
    p.setup()
    ctx = PluginContext(client_ip="1.2.3.4")

    with closing(p.conn):
        assert p.pre_resolve("ads.example", QTYPE.A, b"", ctx).action == "deny"
        assert p.pre_resolve("track.example", QTYPE.A, b"", ctx).action == "deny"
        assert p.pre_resolve("xtrackerx.example", QTYPE.A, b"", ctx).action == "deny"
        assert p.pre_resolve("best-analytics.io", QTYPE.A, b"", ctx).action == "deny"
