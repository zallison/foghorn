"""Brief: Unit tests for foghorn.servers.webserver.config_persistence helpers.

Inputs:
  - pytest fixtures (tmp_path, monkeypatch).

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from foghorn.servers.webserver import config_persistence as cp


def test_backup_file_if_exists_copies_only_when_source_exists(tmp_path: Path) -> None:
    """Brief: backup_file_if_exists should no-op for missing source and copy when present.

    Inputs:
      - tmp_path fixture used to build source and backup paths.

    Outputs:
      - Backup file is absent for missing source, then created with copied content.
    """

    src = tmp_path / "config.yaml"
    backup = tmp_path / "config.yaml.bak"

    cp.backup_file_if_exists(str(src), str(backup))
    assert not backup.exists()

    src.write_text("a: 1\n", encoding="utf-8")
    cp.backup_file_if_exists(str(src), str(backup))
    assert backup.read_text(encoding="utf-8") == "a: 1\n"


def test_write_text_file_overwrites_existing_content(tmp_path: Path) -> None:
    """Brief: write_text_file should overwrite the destination with provided text.

    Inputs:
      - tmp_path fixture used to build destination file path.

    Outputs:
      - Destination file contains only the latest provided text.
    """

    dst = tmp_path / "out.txt"
    dst.write_text("old", encoding="utf-8")

    cp.write_text_file(str(dst), "new")
    assert dst.read_text(encoding="utf-8") == "new"


def test_list_timestamped_backups_filters_by_prefix_and_regular_files(
    tmp_path: Path,
) -> None:
    """Brief: list_timestamped_backups_for_path should include only matching backup files.

    Inputs:
      - tmp_path fixture with matching and non-matching filesystem entries.

    Outputs:
      - Returns only regular files with the expected '.bak.' prefix.
    """

    dst = tmp_path / "config.yaml"
    keep_1 = tmp_path / "config.yaml.bak.1"
    keep_2 = tmp_path / "config.yaml.bak.2"
    skip_dir = tmp_path / "config.yaml.bak.dir"
    skip_other = tmp_path / "other.yaml.bak.1"

    keep_1.write_text("one", encoding="utf-8")
    keep_2.write_text("two", encoding="utf-8")
    skip_dir.mkdir()
    skip_other.write_text("other", encoding="utf-8")

    out = cp.list_timestamped_backups_for_path(str(dst))
    assert set(out) == {str(keep_1), str(keep_2)}


def test_list_timestamped_backups_returns_empty_on_listdir_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: list_timestamped_backups_for_path should return [] when listdir fails.

    Inputs:
      - os.listdir monkeypatched to raise.

    Outputs:
      - Empty list.
    """

    monkeypatch.setattr(
        cp.os,
        "listdir",
        lambda _path: (_ for _ in ()).throw(OSError("boom")),
    )
    assert cp.list_timestamped_backups_for_path("/tmp/config.yaml") == []


def test_prune_timestamped_backups_skips_lookup_when_keep_count_non_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: prune_timestamped_backups should return early when keep_count <= 0.

    Inputs:
      - list_timestamped_backups_for_path monkeypatched to fail if called.

    Outputs:
      - Function returns without querying backups.
    """

    monkeypatch.setattr(
        cp,
        "list_timestamped_backups_for_path",
        lambda _dst_path: (_ for _ in ()).throw(AssertionError("unexpected call")),
    )
    cp.prune_timestamped_backups(dst_path="/tmp/config.yaml", keep_count=0)


def test_prune_timestamped_backups_skips_remove_when_count_is_within_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: prune_timestamped_backups should no-op when backup count is within keep limit.

    Inputs:
      - Backup list length equal to keep_count.
      - os.remove monkeypatched to fail if called.

    Outputs:
      - No delete attempt is made.
    """

    monkeypatch.setattr(
        cp,
        "list_timestamped_backups_for_path",
        lambda _dst_path: ["/tmp/a", "/tmp/b"],
    )
    monkeypatch.setattr(
        cp.os,
        "remove",
        lambda _path: (_ for _ in ()).throw(AssertionError("unexpected remove")),
    )
    cp.prune_timestamped_backups(dst_path="/tmp/config.yaml", keep_count=2)


def test_prune_timestamped_backups_sorts_by_mtime_and_ignores_delete_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: prune_timestamped_backups should keep newest files and ignore delete failures.

    Inputs:
      - Three backup paths with mtime fallback for one path.
      - os.remove raises for one old file.

    Outputs:
      - Old files are targeted in descending age order and errors are ignored.
    """

    backups = ["/tmp/a", "/tmp/b", "/tmp/c"]
    removed: list[str] = []

    monkeypatch.setattr(cp, "list_timestamped_backups_for_path", lambda _dst: backups)

    def _mtime(path: str) -> float:
        if path == "/tmp/c":
            return 200.0
        if path == "/tmp/a":
            return 100.0
        raise OSError("missing")

    def _remove(path: str) -> None:
        removed.append(path)
        if path == "/tmp/a":
            raise OSError("cannot remove")

    monkeypatch.setattr(cp.os.path, "getmtime", _mtime)
    monkeypatch.setattr(cp.os, "remove", _remove)

    cp.prune_timestamped_backups(dst_path="/tmp/config.yaml", keep_count=1)
    assert removed == ["/tmp/a", "/tmp/b"]


def test_write_raw_yaml_via_copy_updates_destination_and_keeps_tmp(
    tmp_path: Path,
) -> None:
    """Brief: write_raw_yaml_via_copy should write tmp and copy it into destination.

    Inputs:
      - tmp_path fixture with destination and temp paths.

    Outputs:
      - Destination and temp files both contain the written YAML text.
    """

    dst = tmp_path / "config.yaml"
    tmp = tmp_path / "config.yaml.new"
    dst.write_text("old: true\n", encoding="utf-8")

    cp.write_raw_yaml_via_copy(
        dst_path=str(dst),
        raw_yaml="new: true\n",
        tmp_path=str(tmp),
    )
    assert dst.read_text(encoding="utf-8") == "new: true\n"
    assert tmp.read_text(encoding="utf-8") == "new: true\n"


def test_write_raw_yaml_via_replace_updates_destination_and_removes_tmp(
    tmp_path: Path,
) -> None:
    """Brief: write_raw_yaml_via_replace should atomically replace destination from temp.

    Inputs:
      - tmp_path fixture with destination and temp paths.

    Outputs:
      - Destination contains new YAML text and temp path no longer exists.
    """

    dst = tmp_path / "config.yaml"
    tmp = tmp_path / "config.yaml.new"
    dst.write_text("old: true\n", encoding="utf-8")

    cp.write_raw_yaml_via_replace(
        dst_path=str(dst),
        raw_yaml="new: true\n",
        tmp_path=str(tmp),
    )
    assert dst.read_text(encoding="utf-8") == "new: true\n"
    assert not tmp.exists()


def test_safe_write_raw_yaml_copy_with_backup_prune_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: safe_write_raw_yaml(copy) should back up, write, prune, and clean tmp file.

    Inputs:
      - Existing destination file content and explicit backup/tmp paths.
      - prune_timestamped_backups monkeypatched to capture call arguments.

    Outputs:
      - Destination updated, backup captured old content, prune called, tmp removed.
    """

    dst = tmp_path / "config.yaml"
    backup = tmp_path / "config.yaml.bak.1"
    tmp = tmp_path / "config.yaml.new"
    dst.write_text("old: true\n", encoding="utf-8")
    prune_calls: list[tuple[str, int]] = []

    monkeypatch.setattr(
        cp,
        "prune_timestamped_backups",
        lambda *, dst_path, keep_count: prune_calls.append(
            (str(dst_path), int(keep_count))
        ),
    )

    cp.safe_write_raw_yaml(
        dst_path=str(dst),
        raw_yaml="new: true\n",
        backup_path=str(backup),
        tmp_path=str(tmp),
        strategy="copy",
        cleanup_tmp=True,
        backup_retention_count=7,
    )

    assert dst.read_text(encoding="utf-8") == "new: true\n"
    assert backup.read_text(encoding="utf-8") == "old: true\n"
    assert not tmp.exists()
    assert prune_calls == [(str(dst), 7)]


def test_safe_write_raw_yaml_replace_without_backup_skips_prune(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: safe_write_raw_yaml(replace) without backup should not invoke prune helper.

    Inputs:
      - Existing destination and temp paths.
      - prune_timestamped_backups monkeypatched to fail if called.

    Outputs:
      - Destination updated successfully without prune invocation.
    """

    dst = tmp_path / "config.yaml"
    tmp = tmp_path / "config.yaml.new"
    dst.write_text("old: true\n", encoding="utf-8")

    monkeypatch.setattr(
        cp,
        "prune_timestamped_backups",
        lambda **_kw: (_ for _ in ()).throw(AssertionError("unexpected prune")),
    )

    cp.safe_write_raw_yaml(
        dst_path=str(dst),
        raw_yaml="new: true\n",
        backup_path=None,
        tmp_path=str(tmp),
        strategy="replace",
        cleanup_tmp=True,
    )

    assert dst.read_text(encoding="utf-8") == "new: true\n"
    assert not tmp.exists()


def test_safe_write_raw_yaml_invalid_strategy_still_runs_finally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: safe_write_raw_yaml should still prune and cleanup when strategy is invalid.

    Inputs:
      - Existing destination file and pre-created temp file.
      - prune_timestamped_backups monkeypatched to capture invocation.

    Outputs:
      - ValueError is raised, backup is written, prune is called, tmp file is removed.
    """

    dst = tmp_path / "config.yaml"
    backup = tmp_path / "config.yaml.bak.1"
    tmp = tmp_path / "config.yaml.new"
    dst.write_text("old: true\n", encoding="utf-8")
    tmp.write_text("stale-temp", encoding="utf-8")
    prune_calls: list[tuple[str, int]] = []

    monkeypatch.setattr(
        cp,
        "prune_timestamped_backups",
        lambda *, dst_path, keep_count: prune_calls.append(
            (str(dst_path), int(keep_count))
        ),
    )

    with pytest.raises(ValueError, match="strategy must be"):
        cp.safe_write_raw_yaml(
            dst_path=str(dst),
            raw_yaml="new: true\n",
            backup_path=str(backup),
            tmp_path=str(tmp),
            strategy="invalid",
            cleanup_tmp=True,
            backup_retention_count=5,
        )

    assert backup.read_text(encoding="utf-8") == "old: true\n"
    assert prune_calls == [(str(dst), 5)]
    assert not tmp.exists()


def test_safe_write_raw_yaml_ignores_prune_and_cleanup_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: safe_write_raw_yaml should treat prune/cleanup failures as non-fatal.

    Inputs:
      - prune_timestamped_backups monkeypatched to raise.
      - os.remove monkeypatched to raise for tmp cleanup.

    Outputs:
      - Write succeeds and destination content is updated despite cleanup errors.
    """

    dst = tmp_path / "config.yaml"
    backup = tmp_path / "config.yaml.bak.1"
    tmp = tmp_path / "config.yaml.new"
    dst.write_text("old: true\n", encoding="utf-8")
    real_remove = cp.os.remove

    monkeypatch.setattr(
        cp,
        "prune_timestamped_backups",
        lambda **_kw: (_ for _ in ()).throw(RuntimeError("prune-failed")),
    )

    def _remove(path: str) -> None:
        if str(path) == str(tmp):
            raise OSError("cleanup-failed")
        real_remove(path)

    monkeypatch.setattr(cp.os, "remove", _remove)

    cp.safe_write_raw_yaml(
        dst_path=str(dst),
        raw_yaml="new: true\n",
        backup_path=str(backup),
        tmp_path=str(tmp),
        strategy="copy",
        cleanup_tmp=True,
    )

    assert dst.read_text(encoding="utf-8") == "new: true\n"
    assert tmp.exists()


def test_safe_write_raw_yaml_cleanup_tmp_false_preserves_tmp_file(
    tmp_path: Path,
) -> None:
    """Brief: safe_write_raw_yaml should leave temp file when cleanup_tmp is False.

    Inputs:
      - copy strategy with cleanup_tmp=False.

    Outputs:
      - Destination updated and tmp file remains on disk.
    """

    dst = tmp_path / "config.yaml"
    tmp = tmp_path / "config.yaml.new"
    dst.write_text("old: true\n", encoding="utf-8")

    cp.safe_write_raw_yaml(
        dst_path=str(dst),
        raw_yaml="new: true\n",
        backup_path=None,
        tmp_path=str(tmp),
        strategy="copy",
        cleanup_tmp=False,
    )

    assert dst.read_text(encoding="utf-8") == "new: true\n"
    assert tmp.exists()
