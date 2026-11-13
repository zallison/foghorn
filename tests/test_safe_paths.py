"""Brief: Tests for server.data_root path containment helpers.

Inputs:
  - None (uses tmp_path fixtures).

Outputs:
  - pytest assertions for resolve/enforce behavior.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from foghorn.utils import safe_paths


def test_enforce_without_data_root_allows_any_absolute(tmp_path: Path) -> None:
    """Brief: Legacy mode (no data_root) only expands/absolutizes paths.

    Inputs:
      - tmp_path: pytest temp directory.

    Outputs:
      - None: asserts absolute resolution without containment.
    """

    safe_paths.set_data_root(None)
    outside = tmp_path / "outside.txt"
    outside.write_text("x\n", encoding="utf-8")
    resolved = safe_paths.enforce_data_root_path(str(outside), kind="test")
    assert Path(resolved).is_absolute()
    assert Path(resolved) == outside.resolve()


def test_enforce_rejects_path_outside_data_root(tmp_path: Path) -> None:
    """Brief: Absolute paths outside data_root raise ValueError.

    Inputs:
      - tmp_path: pytest temp directory.

    Outputs:
      - None: asserts containment failure for /etc/shadow-style paths.
    """

    root = tmp_path / "data"
    root.mkdir()
    safe_paths.set_data_root(str(root))
    try:
        with pytest.raises(ValueError, match="data_root"):
            safe_paths.enforce_data_root_path("/etc/shadow", kind="secret")
    finally:
        safe_paths.set_data_root(None)


def test_enforce_resolves_relative_under_data_root(tmp_path: Path) -> None:
    """Brief: Relative paths resolve under data_root when set.

    Inputs:
      - tmp_path: pytest temp directory.

    Outputs:
      - None: asserts relative path lands under data_root.
    """

    root = tmp_path / "data"
    root.mkdir()
    safe_paths.set_data_root(str(root))
    try:
        resolved = safe_paths.enforce_data_root_path("logs/q.jsonl", kind="json")
        assert Path(resolved) == (root / "logs" / "q.jsonl").resolve()
        assert str(resolved).startswith(str(root.resolve()))
    finally:
        safe_paths.set_data_root(None)


def test_json_logging_rejects_escape_when_data_root_set(tmp_path: Path) -> None:
    """Brief: JsonLogging construction fails when file_path escapes data_root.

    Inputs:
      - tmp_path: pytest temp directory.

    Outputs:
      - None: asserts ValueError before opening the target file.
    """

    root = tmp_path / "data"
    root.mkdir()
    safe_paths.set_data_root(str(root))
    try:
        from foghorn.plugins.querylog.json_logging import JsonLogging

        with pytest.raises(ValueError, match="data_root"):
            JsonLogging(file_path="/etc/passwd")
    finally:
        safe_paths.set_data_root(None)


def test_json_logging_accepts_path_under_data_root(tmp_path: Path) -> None:
    """Brief: JsonLogging opens a file_path under data_root successfully.

    Inputs:
      - tmp_path: pytest temp directory.

    Outputs:
      - None: asserts healthy backend with path under root.
    """

    root = tmp_path / "data"
    root.mkdir()
    safe_paths.set_data_root(str(root))
    try:
        from foghorn.plugins.querylog.json_logging import JsonLogging

        backend = JsonLogging(file_path="logs/queries.jsonl")
        assert backend._healthy is True
        assert str(backend._file_path).startswith(str(root.resolve()))
        backend.close()
    finally:
        safe_paths.set_data_root(None)


def test_etc_hosts_rejects_default_etc_hosts_when_data_root_set(
    tmp_path: Path,
) -> None:
    """Brief: EtcHosts default /etc/hosts fails under a configured data_root.

    Inputs:
      - tmp_path: pytest temp directory.

    Outputs:
      - None: asserts setup raises ValueError for the system default path.
    """

    root = tmp_path / "data"
    root.mkdir()
    safe_paths.set_data_root(str(root))
    try:
        from foghorn.plugins.resolve.etc_hosts import EtcHosts

        plugin = EtcHosts(file_paths=None)
        with pytest.raises(ValueError, match="data_root"):
            plugin.setup()
    finally:
        safe_paths.set_data_root(None)


def test_etc_hosts_accepts_hosts_file_under_data_root(tmp_path: Path) -> None:
    """Brief: EtcHosts loads a hosts file stored under data_root.

    Inputs:
      - tmp_path: pytest temp directory with a hosts file.

    Outputs:
      - None: asserts setup succeeds and maps the entry.
    """

    root = tmp_path / "data"
    root.mkdir()
    hosts = root / "hosts"
    ip = ".".join(["127", "0", "0", "1"])
    hosts.write_text(f"{ip} local.test\n", encoding="utf-8")
    safe_paths.set_data_root(str(root))
    try:
        from foghorn.plugins.resolve.etc_hosts import EtcHosts

        plugin = EtcHosts(
            file_paths=[str(hosts)],
            watchdog_enabled=False,
            watchdog_poll_interval_seconds=0,
        )
        plugin.setup()
        assert "local.test" in plugin.hosts
        assert plugin.hosts["local.test"] == ip
    finally:
        safe_paths.set_data_root(None)


def test_apply_data_root_from_config(tmp_path: Path) -> None:
    """Brief: apply_data_root_from_config publishes server.data_root.

    Inputs:
      - tmp_path: pytest temp directory.

    Outputs:
      - None: asserts get_data_root matches configured absolute path.
    """

    root = tmp_path / "var"
    root.mkdir()
    from foghorn.runtime_config import apply_data_root_from_config

    try:
        out = apply_data_root_from_config(
            {"server": {"data_root": str(root)}},
            config_path=str(tmp_path / "config.yaml"),
        )
        assert out == str(root.resolve())
        assert safe_paths.get_data_root() == str(root.resolve())
    finally:
        safe_paths.set_data_root(None)
