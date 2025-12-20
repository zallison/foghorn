"""
Brief: Tests for normalize_upstream_config handling of DoH url entries.

Inputs:
  - None

Outputs:
  - None
"""

from foghorn.config.config_parser import normalize_upstream_config


def test_normalize_upstream_config_doh_url():
    cfg = {
        "upstreams": [
            {
                "transport": "doh",
                "url": "https://dns.google/dns-query",
                "method": "GET",
                "headers": {"u": "a"},
                "tls": {"verify": True},
            },
            {"host": "1.1.1.1", "port": 53},
        ],
        "foghorn": {"timeout_ms": 1234},
    }
    ups, to = normalize_upstream_config(cfg)
    assert to == 1234
    assert any(u.get("transport") == "doh" and "url" in u for u in ups)
    assert any("host" in u for u in ups)
