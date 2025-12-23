import json
import types

import pytest

import foghorn.servers.webserver as web_mod
from foghorn.servers.webserver import RuntimeState, evaluate_readiness


def test_runtime_state_ignores_empty_names() -> None:
    """Brief: RuntimeState setter methods should no-op when name is empty.

    Inputs:
      - RuntimeState instance.
      - Empty-string listener name.

    Outputs:
      - snapshot() contains no listener entries.
    """

    state = RuntimeState()
    state.set_listener("", enabled=True, thread=None)
    state.set_listener_error("", Exception("boom"))

    snap = state.snapshot()
    assert snap["listeners"] == {}


def test_thread_is_alive_handles_is_alive_and_is_running_and_exceptions() -> None:
    """Brief: _thread_is_alive should handle is_alive/is_running and exceptions.

    Inputs:
      - Thread-like objects with is_alive/is_running attributes.

    Outputs:
      - Returns True/False based on callable return values.
      - Returns False on exceptions.
    """

    class Alive:
        def is_alive(self) -> bool:
            return True

    class RunningOnly:
        def is_running(self) -> bool:
            return True

    class Boom:
        def is_alive(self) -> bool:
            raise RuntimeError("boom")

    assert web_mod._thread_is_alive(None) is False
    assert web_mod._thread_is_alive(Alive()) is True
    assert web_mod._thread_is_alive(RunningOnly()) is True
    assert web_mod._thread_is_alive(Boom()) is False


def test_get_package_build_info_env_pep610_and_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: _get_package_build_info should prefer env vars, parse PEP610, and tolerate failures.

    Inputs:
      - Env vars (FOGHORN_GIT_SHA, FOGHORN_BUILD_ID).
      - Monkeypatched importlib_metadata.distribution() returning a PEP610 direct_url.json.
      - Monkeypatched importlib_metadata.distribution() raising an exception.

    Outputs:
      - Returned dict contains expected keys populated from env/PEP610.
      - On distribution() error, function still returns a dict without raising.
    """

    # Ensure a clean cache between scenarios. Newer implementations of
    # _get_package_build_info may not use functools.lru_cache, so guard this
    # call to support both cached and non-cached designs.
    cache_clear = getattr(web_mod._get_package_build_info, "cache_clear", None)
    if callable(cache_clear):  # pragma: no cover - compatibility path
        cache_clear()

    monkeypatch.setenv("FOGHORN_GIT_SHA", "env-sha")
    monkeypatch.setenv("FOGHORN_BUILD_ID", "env-build")

    direct_url = json.dumps(
        {
            "url": "https://example.invalid/repo.git",
            "vcs_info": {
                "commit_id": "pep610-sha",
                "requested_revision": "main",
            },
        }
    )

    class DummyDist:
        def read_text(self, name: str) -> str | None:
            if name == "direct_url.json":
                return direct_url
            return None

    monkeypatch.setattr(
        web_mod.importlib_metadata, "distribution", lambda _n: DummyDist()
    )

    info = web_mod._get_package_build_info()
    # Env wins over PEP610.
    assert info["git_sha"] == "env-sha"
    assert info["build_id"] == "env-build"
    assert info["vcs_url"] == "https://example.invalid/repo.git"
    assert info["requested_revision"] == "main"

    # Now exercise the exception path, again tolerating implementations that
    # are not cache-wrapped.
    cache_clear = getattr(web_mod._get_package_build_info, "cache_clear", None)
    if callable(cache_clear):  # pragma: no cover - compatibility path
        cache_clear()
    monkeypatch.setattr(
        web_mod.importlib_metadata,
        "distribution",
        lambda _n: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    info2 = web_mod._get_package_build_info()
    assert isinstance(info2, dict)
    assert set(info2.keys()) >= {
        "git_sha",
        "vcs_url",
        "requested_revision",
        "build_time",
        "build_id",
    }


def test_evaluate_readiness_covers_config_and_store_health_branches() -> None:
    """Brief: evaluate_readiness should report common misconfigurations.

    Inputs:
      - Config with forward resolver mode and missing/invalid upstreams.
      - RuntimeState with startup_complete False and listener missing/running/error.
      - Various dummy stats store health configurations.

    Outputs:
      - not_ready contains expected human-readable reasons.
    """

    class NotAliveThread:
        def is_alive(self) -> bool:
            return False

    state = RuntimeState(startup_complete=False)
    state.set_listener("udp", enabled=True, thread=NotAliveThread())
    state.set_listener_error("udp", "boom")

    cfg = {
        "listen": {"udp": {"enabled": True}},
        # Trigger resolver_cfg not-dict branch and default mode=forward.
        "resolver": "not-a-dict",
        # Trigger statistics persistence checks.
        "statistics": {"enabled": True, "persistence": {"enabled": True}},
        # Trigger upstreams misconfiguration.
        "upstreams": "not-a-list",
    }

    # 1) No store available.
    ready1, reasons1, _details1 = evaluate_readiness(
        stats=None, config=cfg, runtime_state=state
    )
    assert ready1 is False
    assert "startup not complete" in reasons1
    assert "no upstreams configured" in reasons1
    assert any("udp error:" in r for r in reasons1)
    assert "statistics persistence store not available" in reasons1

    # 2) Store health_check returning False.
    class StoreBad:
        def health_check(self) -> bool:
            return False

    stats2 = types.SimpleNamespace(_store=StoreBad())
    ready2, reasons2, _details2 = evaluate_readiness(
        stats=stats2, config=cfg, runtime_state=state
    )
    assert ready2 is False
    assert "statistics persistence store not healthy" in reasons2

    # 3) Store health_check raising.
    class StoreBoom:
        def health_check(self) -> bool:
            raise RuntimeError("kaboom")

    stats3 = types.SimpleNamespace(_store=StoreBoom())
    ready3, reasons3, _details3 = evaluate_readiness(
        stats=stats3, config=cfg, runtime_state=state
    )
    assert ready3 is False
    assert any("statistics persistence store error:" in r for r in reasons3)

    # 4) Defensive: tolerate non-dict statistics/persistence config blocks.
    cfg2 = dict(cfg)
    cfg2["statistics"] = "not-a-dict"
    ready4, reasons4, _details4 = evaluate_readiness(
        stats=None, config=cfg2, runtime_state=state
    )
    assert ready4 is False
    assert "statistics persistence store not available" not in reasons4

    cfg3 = dict(cfg)
    cfg3["statistics"] = {"enabled": True, "persistence": "not-a-dict"}
    ready5, _reasons5, _details5 = evaluate_readiness(
        stats=None, config=cfg3, runtime_state=state
    )
    assert ready5 is False
