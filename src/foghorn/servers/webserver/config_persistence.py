"""Shared config persistence helpers for the admin webserver.

These helpers implement common file-system operations used by both the FastAPI
and threaded admin webserver implementations.

They intentionally do not:
- validate YAML syntax,
- schedule signals,
- raise framework-specific exceptions.
"""

from __future__ import annotations

import os
import shutil


def backup_file_if_exists(src_path: str, backup_path: str) -> None:
    """Brief: Copy src_path to backup_path if src_path exists.

    Inputs:
      - src_path: Path to the existing file.
      - backup_path: Path to write the backup copy.

    Outputs:
      - None.

    Notes:
      - Uses shutil.copy() to preserve permissions where possible.
    """

    if os.path.exists(src_path):
        shutil.copy(src_path, backup_path)


def write_text_file(path: str, text: str, *, encoding: str = "utf-8") -> None:
    """Brief: Write text to a file, overwriting any existing contents.

    Inputs:
      - path: Destination path.
      - text: Contents to write.
      - encoding: Text encoding.

    Outputs:
      - None.
    """

    with open(path, "w", encoding=encoding) as f:
        f.write(text)


def write_raw_yaml_via_copy(
    *,
    dst_path: str,
    raw_yaml: str,
    tmp_path: str,
) -> None:
    """Brief: Write raw YAML using a tmp file and then copy over dst_path.

    Inputs:
      - dst_path: Destination YAML file path.
      - raw_yaml: YAML document text.
      - tmp_path: Temporary file path to write before copying.

    Outputs:
      - None.

    Notes:
      - This mirrors the FastAPI implementation's historic behaviour.
      - tmp_path is left on disk only if an exception is raised before cleanup.
    """

    write_text_file(tmp_path, raw_yaml)
    shutil.copy(tmp_path, dst_path)


def write_raw_yaml_via_replace(
    *,
    dst_path: str,
    raw_yaml: str,
    tmp_path: str,
) -> None:
    """Brief: Write raw YAML using atomic os.replace().

    Inputs:
      - dst_path: Destination YAML file path.
      - raw_yaml: YAML document text.
      - tmp_path: Temporary file path to write before replace.

    Outputs:
      - None.

    Notes:
      - This mirrors the threaded fallback implementation's behaviour.
    """

    write_text_file(tmp_path, raw_yaml)
    os.replace(tmp_path, dst_path)


def safe_write_raw_yaml(
    *,
    dst_path: str,
    raw_yaml: str,
    backup_path: str | None,
    tmp_path: str,
    strategy: str,
    cleanup_tmp: bool = True,
) -> None:
    """Brief: Safely write raw YAML with optional backup and optional cleanup.

    Inputs:
      - dst_path: Destination YAML file path.
      - raw_yaml: YAML document text.
      - backup_path: Optional backup file path.
      - tmp_path: Temporary file used during write.
      - strategy: Either 'copy' or 'replace'.
      - cleanup_tmp: When True, remove tmp_path if it still exists at the end.

    Outputs:
      - None.

    Raises:
      - Propagates any underlying OSError/IOError exceptions.

    Example:
      >>> safe_write_raw_yaml(dst_path='config.yaml', raw_yaml='a: 1\n', backup_path=None, tmp_path='config.yaml.new', strategy='replace')
    """

    try:
        if backup_path:
            backup_file_if_exists(dst_path, backup_path)

        if strategy == "copy":
            write_raw_yaml_via_copy(
                dst_path=dst_path,
                raw_yaml=raw_yaml,
                tmp_path=tmp_path,
            )
        elif strategy == "replace":
            write_raw_yaml_via_replace(
                dst_path=dst_path,
                raw_yaml=raw_yaml,
                tmp_path=tmp_path,
            )
        else:
            raise ValueError("strategy must be 'copy' or 'replace'")
    finally:
        if cleanup_tmp:
            # Best-effort cleanup: remove tmp_path if it still exists.
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
