#!/usr/bin/env python3
"""
Brief: Cleanup duplicated tests using Option B policy (keep numbered tests, remove unnumbered counterparts).

Inputs:
  - Command-line args specifying mode and optional filters (see main())

Outputs:
  - Writes JSON reports under var/ (can be overridden) and prints concise summaries

Non-trivial notes:
  - Numbered tests are defined as files whose base name begins with digits followed by '_' or '-'.
  - Duplicate pair candidates are files in the same directory where the normalized base (with the numeric prefix removed) matches.
  - The 'verify' mode additionally reports identical-content duplicates anywhere in the repo.

Example usage:
  python tools/cleanup_duplicated_tests.py dry-run
  python tools/cleanup_duplicated_tests.py apply --output var/duplicates_applied.json --removed-list var/removed_files.txt
  python tools/cleanup_duplicated_tests.py verify > var/duplicates_verify_report.txt
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

DEFAULT_BLOCKLIST = {
    "venv",
    ".git",
    ".hg",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "build",
    "dist",
    ".idea",
    ".vscode",
    ".cache",
}
DEFAULT_PATTERNS = ["test*.py", "*_test.py"]


@dataclass
class Pair:
    """
    Brief: Represents an Option B duplicate pair for a single normalized key.

    Inputs:
      - numbered: path to the numbered test file
      - unnumbered: path to the unnumbered counterpart

    Outputs:
      - None (data container)
    """

    numbered: Path
    unnumbered: Path


def normalize_test_key(path: Path) -> Tuple[str, bool]:
    """
    Brief: Normalize a test filename to a comparison key and signal if it is numbered.

    Inputs:
      - path: Path object to a test file

    Outputs:
      - key: normalized base name with any leading numeric prefix and delimiter removed (no extension)
      - is_numbered: True if the filename starts with digits followed by '_' or '-'

    Example usage:
      >>> normalize_test_key(Path("001_test_alpha.py"))
      ('test_alpha', True)
    """
    stem = path.stem
    i = 0
    while i < len(stem) and stem[i].isdigit():
        i += 1
    is_numbered = i > 0 and i < len(stem) and stem[i] in {"_", "-"}
    if is_numbered:
        key = stem[i + 1 :]
    else:
        key = stem
    return key, is_numbered


def find_test_files(
    root: Path,
    allowlist_dirs: Iterable[str] | None = None,
    blocklist_dirs: Iterable[str] | None = None,
    patterns: Iterable[str] | None = None,
) -> List[Path]:
    """
    Brief: Recursively find test files honoring allowlist and blocklist rules.

    Inputs:
      - root: directory to start scanning
      - allowlist_dirs: optional list of relative directories to restrict scanning
      - blocklist_dirs: directories to skip entirely
      - patterns: filename glob patterns to include (default: test*.py, *_test.py)

    Outputs:
      - List of Path objects pointing to candidate test files

    Example usage:
      >>> find_test_files(Path('.'), None, {'venv'}, ['test*.py'])
      [Path('tests/foo/test_bar.py'), ...]
    """
    root = root.resolve()
    allow = {str((root / d).resolve()) for d in (allowlist_dirs or [])}
    block = set(blocklist_dirs or DEFAULT_BLOCKLIST)
    pats = list(patterns or DEFAULT_PATTERNS)

    results: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune blocklisted dirs
        dirnames[:] = [d for d in dirnames if d not in block]
        abs_dir = os.path.abspath(dirpath)
        if allow and not any(abs_dir.startswith(a) for a in allow):
            continue
        for fn in filenames:
            if any(fnmatch.fnmatch(fn, p) for p in pats):
                results.append(Path(abs_dir) / fn)
    return results


def group_option_b_duplicates(files: Iterable[Path]) -> Dict[str, Dict[str, Pair]]:
    """
    Brief: Group files by directory and normalized base name to identify Option B duplicate pairs.

    Inputs:
      - files: iterable of test file paths

    Outputs:
      - Mapping: dir -> normalized_key -> Pair(numbered, unnumbered)

    Non-trivial notes:
      - Only pairs where both a numbered and unnumbered file exist are returned.
    """
    by_dir: Dict[str, Dict[str, Pair]] = {}
    temp: Dict[Tuple[str, str], Dict[str, Path]] = {}

    for p in files:
        key, is_num = normalize_test_key(p)
        dkey = str(p.parent.resolve())
        temp.setdefault((dkey, key), {})["numbered" if is_num else "unnumbered"] = p

    for (dkey, key), entry in temp.items():
        if "numbered" in entry and "unnumbered" in entry:
            by_dir.setdefault(dkey, {})[key] = Pair(
                entry["numbered"], entry["unnumbered"]
            )
    return by_dir


def compute_content_duplicates(files: Iterable[Path]) -> Dict[str, List[str]]:
    """
    Brief: Compute identical-content duplicates among provided files using SHA-1 hashes.

    Inputs:
      - files: iterable of file paths

    Outputs:
      - Mapping of sha1 hex digest -> list of file paths sharing that content (only keys with >=2 files)

    Example usage:
      >>> compute_content_duplicates([Path('a.py'), Path('b.py')])
      {'<sha1>': ['a.py', 'b.py']}
    """
    by_hash: Dict[str, List[str]] = {}
    for p in files:
        data = p.read_bytes()
        h = hashlib.sha1(data).hexdigest()
        by_hash.setdefault(h, []).append(str(p))
    return {h: paths for h, paths in by_hash.items() if len(paths) > 1}


def ensure_outdir(path: Path) -> None:
    """
    Brief: Ensure the parent directory for a path exists.

    Inputs:
      - path: output file path

    Outputs:
      - None (creates directories as needed)
    """
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)


def apply_option_b_cleanup(
    pairs: Dict[str, Dict[str, Pair]],
    *,
    dry_run: bool,
    output_json: Path,
    removed_list_path: Path | None = None,
) -> Dict[str, Dict[str, Dict[str, str]]]:
    """
    Brief: Apply or simulate deletions of unnumbered test files according to Option B.

    Inputs:
      - pairs: mapping of dir -> key -> Pair(numbered, unnumbered)
      - dry_run: if True, report only
      - output_json: file path to write a JSON summary
      - removed_list_path: optional file to write newline-delimited removed paths

    Outputs:
      - A summary dict (also written to JSON) containing planned/applied changes

    Example usage:
      >>> apply_option_b_cleanup(pairs, dry_run=True, output_json=Path('var/plan.json'))
      {...}
    """
    ensure_outdir(output_json)
    removed: List[str] = []
    summary: Dict[str, Dict[str, Dict[str, str]]] = {}

    for d, items in pairs.items():
        for key, pair in items.items():
            summary.setdefault(d, {})[key] = {
                "keep": str(pair.numbered),
                "remove": str(pair.unnumbered),
            }
            if not dry_run:
                try:
                    os.remove(pair.unnumbered)
                    removed.append(str(pair.unnumbered))
                except FileNotFoundError:
                    pass

    output_json.write_text(json.dumps(summary, indent=2))
    if removed_list_path and not dry_run:
        ensure_outdir(removed_list_path)
        removed_list_path.write_text("\n".join(removed) + ("\n" if removed else ""))
    return summary


def main(argv: List[str] | None = None) -> int:
    """
    Brief: CLI entrypoint for duplicate test cleanup.

    Inputs:
      - argv: optional argument list; if None, uses sys.argv

    Outputs:
      - Process exit code (0 success, non-zero on error)

    Modes:
      - dry-run: detect and report Option B duplicates without changes
      - apply: remove unnumbered counterparts per Option B
      - verify: report identical-content duplicates anywhere (no removals)

    Example usage:
      python tools/cleanup_duplicated_tests.py dry-run --root . --output var/duplicates_dry_run.json
    """
    parser = argparse.ArgumentParser(
        prog="cleanup_duplicated_tests", description="Clean duplicated tests (Option B)"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--root", default=".", help="Root directory to scan")
        p.add_argument(
            "--allow",
            nargs="*",
            default=None,
            help="Allowlist of relative directories to include (default: entire repo)",
        )
        p.add_argument(
            "--block",
            nargs="*",
            default=None,
            help=f"Blocklist of directory names to skip (default: {sorted(DEFAULT_BLOCKLIST)})",
        )
        p.add_argument(
            "--patterns",
            nargs="*",
            default=None,
            help=f"Filename patterns to include (default: {DEFAULT_PATTERNS})",
        )

    p_dry = sub.add_parser(
        "dry-run", help="Detect Option B duplicates without modifying files"
    )
    add_common(p_dry)
    p_dry.add_argument(
        "--output", default="var/duplicates_dry_run.json", help="Path to JSON report"
    )

    p_apply = sub.add_parser(
        "apply", help="Remove unnumbered counterparts per Option B"
    )
    add_common(p_apply)
    p_apply.add_argument(
        "--output", default="var/duplicates_applied.json", help="Path to JSON report"
    )
    p_apply.add_argument(
        "--removed-list",
        default="var/removed_files.txt",
        help="Path to write removed file list",
    )

    p_verify = sub.add_parser(
        "verify", help="Report identical-content duplicates (no changes)"
    )
    add_common(p_verify)

    args = parser.parse_args(argv)

    root = Path(args.root)
    files = find_test_files(root, args.allow, args.block, args.patterns)

    if args.mode == "verify":
        dup = compute_content_duplicates(files)
        if not dup:
            print("No identical-content duplicates found.")
            return 0
        for h, paths in dup.items():
            print(len(paths), h)
            for p in paths:
                print("  ", p)
        return 0

    pairs = group_option_b_duplicates(files)
    if args.mode == "dry-run":
        summary = apply_option_b_cleanup(
            pairs, dry_run=True, output_json=Path(args.output)
        )
        total = sum(len(v) for v in summary.values())
        print(f"Option B duplicate pairs found: {total}")
        for d, items in summary.items():
            print(f"  {d} -> {len(items)} pairs")
        return 0

    if args.mode == "apply":
        summary = apply_option_b_cleanup(
            pairs,
            dry_run=False,
            output_json=Path(args.output),
            removed_list_path=Path(args.removed_list),
        )
        total = sum(len(v) for v in summary.values())
        print(
            f"Removed {total} unnumbered files. See {args.output} and {args.removed_list}."
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
