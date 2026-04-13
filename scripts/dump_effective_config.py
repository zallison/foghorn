#!/usr/bin/env python3
"""Dump a fully-resolved Foghorn configuration.

Brief:
  This script loads a Foghorn YAML config, expands variables via
  foghorn.config.config_parser.parse_config_file(), then makes core runtime
  defaults explicit via foghorn.config.config_dump.build_effective_config_for_display().

Inputs:
  - --config: Path to a YAML config file.
  - --var: Optional KEY=YAML overrides (may be repeated).
  - --config-extras: Unknown-key policy (ignore|warn|error).
  - --format: Output format (yaml|json).

Outputs:
  - Writes the effective configuration text to stdout.

Example:
  PYTHONPATH=src ./scripts/dump_effective_config.py --config config.yaml --format json
"""

from __future__ import annotations

import argparse
import sys
from typing import List

from foghorn.config.config_dump import (
    build_effective_config_for_display,
    dump_config_text,
)
from foghorn.config.config_parser import parse_config_file


def main(argv: List[str] | None = None) -> int:
    """Brief: CLI entrypoint for dumping effective config.

    Inputs:
      - argv: Optional CLI argv list (excluding program name).

    Outputs:
      - int: Process exit code (0 on success, non-zero on error).

    Example:
      >>> isinstance(main(["--help"]), int)
      True
    """

    parser = argparse.ArgumentParser(
        description="Dump the effective Foghorn config (variables expanded + runtime defaults explicit)"
    )
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config")
    parser.add_argument(
        "-v",
        "--var",
        action="append",
        default=[],
        help=(
            "Set a configuration variable (KEY=YAML). May be provided multiple times; "
            "CLI overrides environment overrides config file variables."
        ),
    )
    parser.add_argument(
        "--config-extras",
        dest="config_extras",
        choices=["ignore", "warn", "error"],
        default="warn",
        help=(
            "Policy for unknown config keys not described by the JSON Schema: "
            "ignore (keep current behaviour), warn (default), or error."
        ),
    )
    parser.add_argument(
        "--format",
        dest="fmt",
        choices=["yaml", "json"],
        default="yaml",
        help="Output format (yaml or json).",
    )
    args = parser.parse_args(argv)

    try:
        cfg = parse_config_file(
            args.config,
            cli_vars=list(getattr(args, "var", []) or []),
            unknown_keys=str(getattr(args, "config_extras", "warn") or "warn"),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    effective = build_effective_config_for_display(cfg)
    text = dump_config_text(effective, fmt=str(getattr(args, "fmt", "yaml") or "yaml"))
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
