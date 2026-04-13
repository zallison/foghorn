"""Test rate limit configuration warnings."""

from __future__ import annotations

import logging

from foghorn.config.rate_limit_check import check_rate_limit_plugin_config
from foghorn.plugins.resolve.base import BasePlugin


class MockRateLimitPlugin(BasePlugin):
    """Mock rate limit plugin for testing."""

    pass


def test_warn_on_exposed_without_rate_limit(caplog: logging.LogCaptureFixture) -> None:
    """Brief: Warn about missing rate limit on exposed listeners.

    Inputs:
      - caplog: Pytest logging fixture.

    Outputs:
      - None; asserts warning is logged.

    When listeners bind to 0.0.0.0 and no rate limit plugin is configured,
    the checker should emit a warning with recommended configuration.
    """
    cfg = {
        "server": {
            "listen": {"dns": {"host": "0.0.0.0"}},
        }
    }

    with caplog.at_level(logging.WARNING):
        check_rate_limit_plugin_config(plugins=[], cfg=cfg)

    assert "No rate limiting plugin" in caplog.text
    assert "type: rate" in caplog.text
    assert "50 RPS" in caplog.text
    assert "REFUSED" in caplog.text


def test_no_warn_on_loopback_without_rate_limit(
    caplog: logging.LogCaptureFixture,
) -> None:
    """Brief: Don't warn when listeners are loopback-only.

    Inputs:
      - caplog: Pytest logging fixture.

    Outputs:
      - None; asserts no warning is logged.

    When all listeners bind to 127.0.0.1, there's no need for rate limiting.
    """
    cfg = {
        "server": {
            "listen": {"dns": {"host": "127.0.0.1"}},
        }
    }

    with caplog.at_level(logging.WARNING):
        check_rate_limit_plugin_config(plugins=[], cfg=cfg)

    assert not caplog.text


def test_no_warn_with_rate_limit_present(caplog: logging.LogCaptureFixture) -> None:
    """Brief: Don't warn when rate limit plugin is configured.

    Inputs:
      - caplog: Pytest logging fixture.

    Outputs:
      - None; asserts no warning is logged.

    When a rate limit plugin is present, exposure is acceptable.
    """
    cfg = {
        "server": {
            "listen": {"dns": {"host": "0.0.0.0"}},
        }
    }
    plugins = [MockRateLimitPlugin(name="rate_limit", enabled=True)]

    with caplog.at_level(logging.WARNING):
        check_rate_limit_plugin_config(plugins=plugins, cfg=cfg)

    assert not caplog.text


def test_warn_on_specific_listener_exposure(
    caplog: logging.LogCaptureFixture,
) -> None:
    """Brief: Detect exposure from per-listener host overrides.

    Inputs:
      - caplog: Pytest logging fixture.

    Outputs:
      - None; asserts warning is logged.

    When at least one listener (UDP/TCP/DoT/DoH) binds to exposed address,
    a warning should be emitted.
    """
    cfg = {
        "server": {
            "listen": {
                "dns": {"host": "127.0.0.1"},
                "udp": {"enabled": True, "host": "0.0.0.0"},
            }
        }
    }

    with caplog.at_level(logging.WARNING):
        check_rate_limit_plugin_config(plugins=[], cfg=cfg)

    assert "No rate limiting plugin" in caplog.text


def test_ipv6_loopback_no_warning(
    caplog: logging.LogCaptureFixture,
) -> None:
    """Brief: Recognize IPv6 loopback addresses as loopback.

    Inputs:
      - caplog: Pytest logging fixture.

    Outputs:
      - None; asserts no warning is logged.

    When listeners bind to ::1, no rate limit warning should be emitted.
    """
    cfg = {
        "server": {
            "listen": {"dns": {"host": "::1"}},
        }
    }

    with caplog.at_level(logging.WARNING):
        check_rate_limit_plugin_config(plugins=[], cfg=cfg)

    assert not caplog.text


def test_localhost_no_warning(caplog: logging.LogCaptureFixture) -> None:
    """Brief: Recognize 'localhost' as loopback.

    Inputs:
      - caplog: Pytest logging fixture.

    Outputs:
      - None; asserts no warning is logged.

    When listeners bind to 'localhost', no rate limit warning should be emitted.
    """
    cfg = {
        "server": {
            "listen": {"dns": {"host": "localhost"}},
        }
    }

    with caplog.at_level(logging.WARNING):
        check_rate_limit_plugin_config(plugins=[], cfg=cfg)

    assert not caplog.text
