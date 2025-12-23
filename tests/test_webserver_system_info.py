import types

import pytest

import foghorn.servers.webserver as webserver
from foghorn.stats import StatsCollector
from foghorn.servers.webserver import RingBuffer, create_app


def _reset_system_info_cache() -> None:
    """Reset webserver system info cache for deterministic tests.

    Inputs:
      - None.

    Outputs:
      - None. Mutates module-level cache globals in foghorn.servers.webserver.
    """

    webserver._last_system_info = None
    webserver._last_system_info_ts = 0.0


def test_get_system_info_uses_cache_for_quick_repeats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure get_system_info reuses cached payload within the TTL.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture for isolating globals.

    Outputs:
      - None. Asserts that the expensive inner function runs once.
    """

    _reset_system_info_cache()

    call_counter = {"count": 0}

    def fake_read_proc_meminfo(path: str = "/proc/meminfo") -> dict[str, int]:
        call_counter["count"] += 1
        return {}

    monkeypatch.setattr(webserver, "_read_proc_meminfo", fake_read_proc_meminfo)
    monkeypatch.setattr(webserver, "_SYSTEM_INFO_CACHE_TTL_SECONDS", 1000.0)

    first = webserver.get_system_info()
    second = webserver.get_system_info()

    assert call_counter["count"] == 1
    assert first == second


def test_get_system_info_expires_cache_after_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify get_system_info recomputes after the cache TTL elapses.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture for isolating globals.

    Outputs:
      - None. Asserts that underlying computation is invoked twice.
    """

    _reset_system_info_cache()

    call_counter = {"count": 0}

    def fake_read_proc_meminfo(path: str = "/proc/meminfo") -> dict[str, int]:
        call_counter["count"] += 1
        return {}

    # Controlled time source for the webserver module
    t = {"now": 1_000_000.0}

    def fake_time() -> float:
        return t["now"]

    monkeypatch.setattr(webserver, "_read_proc_meminfo", fake_read_proc_meminfo)
    monkeypatch.setattr(webserver.time, "time", fake_time)
    monkeypatch.setattr(webserver, "_SYSTEM_INFO_CACHE_TTL_SECONDS", 1.0)

    # First call populates cache
    webserver.get_system_info()
    assert call_counter["count"] == 1

    # Second call within TTL uses cache
    webserver.get_system_info()
    assert call_counter["count"] == 1

    # Advance time beyond TTL and call again; should recompute
    t["now"] += 2.0
    webserver.get_system_info()
    assert call_counter["count"] == 2


def test_system_info_ttl_overridden_by_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Config.webserver.system_info_ttl_seconds should tune cache TTL bounds.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture for isolating TTL global.

    Outputs:
      - Verifies that create_app() applies the configured TTL within bounds.
    """

    # Start from a known TTL value
    monkeypatch.setattr(webserver, "_SYSTEM_INFO_CACHE_TTL_SECONDS", 2.0, raising=False)

    cfg = {"webserver": {"enabled": True, "system_info_ttl_seconds": 5.5}}
    # Creating the app should apply the TTL override
    create_app(stats=None, config=cfg, log_buffer=RingBuffer())

    assert webserver._SYSTEM_INFO_CACHE_TTL_SECONDS == pytest.approx(5.5)


def test_system_info_basic_detail_skips_heavy_psutil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detail mode "basic" must avoid open_files()/connections but keep keys.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture used to stub psutil.Process.

    Outputs:
      - Ensures process_open_files_count/process_connections_count remain None
        and the dummy Process implementation never sees open_files()/connections
        calls when system_metrics_detail="basic".
    """

    class DummyMemInfo:
        def __init__(self) -> None:
            self.rss = 1234

    class DummyCpuTimes:
        def _asdict(self) -> dict[str, float]:
            return {"user": 0.1, "system": 0.2}

    class DummyIoCounters:
        def _asdict(self) -> dict[str, int]:
            return {"read_bytes": 0, "write_bytes": 0}

    class DummyProc:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def memory_info(self) -> DummyMemInfo:
            return DummyMemInfo()

        def cpu_times(self) -> DummyCpuTimes:
            return DummyCpuTimes()

        def cpu_percent(self, interval: float = 0.0) -> float:  # noqa: ARG002
            return 0.0

        def io_counters(self) -> DummyIoCounters:
            return DummyIoCounters()

        def open_files(self) -> list[object]:
            self.calls.append("open_files")
            return []

        def connections(self) -> list[object]:  # noqa: D401
            """Record that connections() was invoked and return empty list."""

            self.calls.append("connections")
            return []

    dummy_proc = DummyProc()

    def fake_process(_pid: int) -> DummyProc:  # noqa: ARG001
        return dummy_proc

    fake_psutil = types.SimpleNamespace(Process=fake_process)

    _reset_system_info_cache()
    monkeypatch.setattr(webserver, "psutil", fake_psutil, raising=True)

    cfg = {"webserver": {"enabled": True, "system_metrics_detail": "basic"}}
    create_app(
        stats=StatsCollector(track_uniques=False), config=cfg, log_buffer=RingBuffer()
    )

    info = webserver.get_system_info()

    # Keys must be present but left as None when detail mode is basic.
    assert "process_open_files_count" in info
    assert "process_connections_count" in info
    assert info["process_open_files_count"] is None
    assert info["process_connections_count"] is None

    # open_files()/connections() should never have been called on DummyProc.
    assert "open_files" not in dummy_proc.calls
    assert "connections" not in dummy_proc.calls
