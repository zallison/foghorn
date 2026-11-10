"""Tests for startup pre-flight backend validation orchestration in main().

Brief: Verifies the validate_connection() orchestration added at startup:
the _validate_backend_connections loop, fatal BackendUnavailableError on
configured-but-unreachable backends, and main() returning a non-zero exit
code when a configured Redis/PostgreSQL backend is offline.

Inputs:
  - None (pytest fixtures only; no network services required).

Outputs:
  - None (pytest assertions).
"""

import argparse
import logging
import socket
from unittest import mock

import pytest

import foghorn.main as main_mod
from foghorn.main_config_helpers import BackendUnavailableError


def _closed_port() -> int:
    """Brief: Get a TCP port that is very likely closed on loopback.

    Inputs:
      - None
    Outputs:
      - int: A port number just released by the test process.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class _Healthy:
    def validate_connection(self) -> bool:
        return True


class _Unreachable:
    def validate_connection(self) -> bool:
        return False


class _Exploding:
    def validate_connection(self) -> bool:
        raise RuntimeError("offline")


def test_validate_backend_connections_all_none_ok(caplog):
    """Brief: Nothing configured means nothing to validate.

    Inputs:
      - caplog fixture.
    Outputs:
      - None; asserts True with no CRITICAL output.
    """

    logger = logging.getLogger("foghorn.main")
    with caplog.at_level(logging.CRITICAL, logger="foghorn.main"):
        ok = main_mod._validate_backend_connections(
            logger=logger, cache_plugin=None, stats_persistence_store=None
        )
    assert ok is True
    assert not [r for r in caplog.records if r.levelno == logging.CRITICAL]


def test_validate_backend_connections_unreachable_cache_is_fatal(caplog):
    """Brief: A False validate_connection aborts startup with a CRITICAL log.

    Inputs:
      - caplog fixture.
    Outputs:
      - None; asserts False plus a CRITICAL line naming the backend.
    """

    logger = logging.getLogger("foghorn.main")
    with caplog.at_level(logging.CRITICAL, logger="foghorn.main"):
        ok = main_mod._validate_backend_connections(
            logger=logger,
            cache_plugin=_Unreachable(),
            stats_persistence_store=None,
        )
    assert ok is False
    criticals = [
        r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL
    ]
    assert any("cache" in msg and "_Unreachable" in msg for msg in criticals)


def test_validate_backend_connections_exception_is_fatal(caplog):
    """Brief: A raising validate_connection aborts startup with a CRITICAL log.

    Inputs:
      - caplog fixture.
    Outputs:
      - None; asserts False plus a CRITICAL line naming the backend.
    """

    logger = logging.getLogger("foghorn.main")
    with caplog.at_level(logging.CRITICAL, logger="foghorn.main"):
        ok = main_mod._validate_backend_connections(
            logger=logger,
            cache_plugin=None,
            stats_persistence_store=_Exploding(),
        )
    assert ok is False
    criticals = [
        r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL
    ]
    assert any("stats_store" in msg and "_Exploding" in msg for msg in criticals)


def test_validate_backend_connections_healthy_backends_ok(caplog):
    """Brief: Healthy backends pass validation silently.

    Inputs:
      - caplog fixture.
    Outputs:
      - None; asserts True with no CRITICAL output.
    """

    logger = logging.getLogger("foghorn.main")
    with caplog.at_level(logging.CRITICAL, logger="foghorn.main"):
        ok = main_mod._validate_backend_connections(
            logger=logger,
            cache_plugin=_Healthy(),
            stats_persistence_store=_Healthy(),
        )
    assert ok is True
    assert not [r for r in caplog.records if r.levelno == logging.CRITICAL]


def test_load_cache_plugin_from_cfg_raises_when_configured(monkeypatch):
    """Brief: A configured cache that fails to load raises BackendUnavailableError.

    Inputs:
      - monkeypatch fixture.
    Outputs:
      - None; asserts the exception names the cache backend.
    """

    from foghorn.plugins.cache import registry

    def boom(cfg):
        raise RuntimeError("cannot reach redis")

    monkeypatch.setattr(registry, "load_cache_plugin", boom)
    with pytest.raises(BackendUnavailableError) as excinfo:
        main_mod._load_cache_plugin_from_cfg(
            cfg={"cache": {"module": "redis"}},
            server_cfg={},
            logger=logging.getLogger("test"),
        )
    assert "cache" in str(excinfo.value)


def test_load_cache_plugin_from_cfg_default_when_unconfigured():
    """Brief: No cache configured means the default in-memory cache loads.

    Inputs:
      - None
    Outputs:
      - None; asserts an InMemoryTTLCache instance is returned.
    """

    from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache

    plugin = main_mod._load_cache_plugin_from_cfg(
        cfg={}, server_cfg={}, logger=logging.getLogger("test")
    )
    assert isinstance(plugin, InMemoryTTLCache)


def test_initialize_statistics_subsystem_raises_when_persistence_fails(monkeypatch):
    """Brief: Configured persistence that fails to construct is fatal.

    Inputs:
      - monkeypatch fixture.
    Outputs:
      - None; asserts BackendUnavailableError names the stats_store backend.
    """

    def boom(cfg):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(main_mod, "load_stats_store_backend", boom)
    cfg = {"logging": {"backends": [{"backend": "postgres"}]}}
    with pytest.raises(BackendUnavailableError) as excinfo:
        main_mod._initialize_statistics_subsystem(
            cfg=cfg,
            logging_cfg={},
            args=argparse.Namespace(rebuild=False),
            logger=logging.getLogger("test"),
        )
    assert "stats_store" in str(excinfo.value)


def test_initialize_statistics_subsystem_ok_when_not_configured(monkeypatch):
    """Brief: No persistence configured keeps memory-only mode non-fatal.

    Inputs:
      - monkeypatch fixture.
    Outputs:
      - None; asserts no exception and a None store.
    """

    def boom(cfg):
        raise AssertionError("load_stats_store_backend should not be called")

    monkeypatch.setattr(main_mod, "load_stats_store_backend", boom)
    _collector, _reporter, store = main_mod._initialize_statistics_subsystem(
        cfg={},
        logging_cfg={},
        args=argparse.Namespace(rebuild=False),
        logger=logging.getLogger("test"),
    )
    assert store is None


def test_main_aborts_when_configured_redis_cache_offline(monkeypatch, caplog):
    """Brief: main() exits non-zero when a configured Redis cache is offline.

    Inputs:
      - monkeypatch/caplog fixtures; config with an offline Redis cache.
    Outputs:
      - None; asserts return code 1 and a CRITICAL log naming the backend.
    """

    port = _closed_port()
    yaml_data = (
        "server:\n"
        "  http:\n"
        "    enabled: false\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: false\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "  cache:\n"
        "    module: redis\n"
        "    config:\n"
        "      host: 127.0.0.1\n"
        f"      port: {port}\n"
        "      socket_timeout: 0.5\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **kw: None)

    with (
        mock.patch("builtins.open", mock.mock_open(read_data=yaml_data)),
        caplog.at_level(logging.CRITICAL, logger="foghorn.main"),
    ):
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 1
    criticals = [
        r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL
    ]
    assert any("RedisCache" in msg and "cache" in msg for msg in criticals)


def test_main_aborts_when_configured_postgres_store_offline(monkeypatch, caplog):
    """Brief: main() exits non-zero when a configured PostgreSQL store is offline.

    Inputs:
      - monkeypatch/caplog fixtures; config with an offline PostgreSQL store.
    Outputs:
      - None; asserts return code 1 and a CRITICAL log naming the backend.
    """

    port = _closed_port()
    yaml_data = (
        "server:\n"
        "  http:\n"
        "    enabled: false\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: false\n"
        "      host: 127.0.0.1\n"
        "      port: 5354\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "logging:\n"
        "  backends:\n"
        "    - backend: postgresql\n"
        "      config:\n"
        "        host: 127.0.0.1\n"
        f"        port: {port}\n"
        "        database: foghorn\n"
        "upstreams:\n"
        "  strategy: failover\n"
        "  max_concurrent: 1\n"
        "  endpoints:\n"
        "    - host: 1.1.1.1\n"
        "      port: 53\n"
    )

    monkeypatch.setattr(main_mod, "init_logging", lambda cfg: None)
    monkeypatch.setattr(main_mod, "start_webserver", lambda *a, **kw: None)
    monkeypatch.setattr(main_mod, "load_plugins", lambda _specs: [])
    monkeypatch.setattr(main_mod, "run_setup_plugins", lambda _plugins, **_kw: None)

    with (
        mock.patch("builtins.open", mock.mock_open(read_data=yaml_data)),
        caplog.at_level(logging.CRITICAL, logger="foghorn.main"),
    ):
        rc = main_mod.main(["--config", "cfg.yaml"])

    assert rc == 1
    criticals = [
        r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL
    ]
    assert any("stats_store" in msg for msg in criticals)
