#!/usr/bin/env python3
"""Brief: Generate a Mermaid diagram describing plugin ordering and potential overrides.

Inputs:
  - --config (str): Path to a Foghorn YAML config file. Default: ./config/config.yaml
  - --output (str, optional): Write the Mermaid text to this path. When omitted,
    output is written to stdout.
  - --png (flag): Also render the diagram to PNG (requires `mmdc` or python_mermaid).
  - --png-output (str, optional): Output path for the PNG. Default: <config_dir>/diagram.png
  - --direction (TB|LR): Mermaid flow direction. Default: TB (top-to-bottom).
  - --font-size (int): Diagram font size (px) applied via Mermaid init directive.
  - --node-spacing (int): Mermaid flowchart node spacing (init directive).
  - --rank-spacing (int): Mermaid flowchart rank spacing (init directive).
  - --no-init: Disable Mermaid init directive.

Outputs:
  - Mermaid flowchart text ("flowchart TB") showing:
      - listener configuration (UDP/TCP/DoT/DoH) from the config
      - upstream endpoint configuration (when resolver.mode == forward)
      - pre_resolve execution order (pre_priority)
      - cache hit/miss branching
      - resolver mode (forward/recursive/master)
      - post_resolve execution order (post_priority)
      - potential short-circuits (deny/override/drop) and upstream routing
  - When --png is set, writes a PNG to diagram.png by default.

Notes:
  - This script reads the config file but does not modify it.
  - Plugin alias/module resolution prefers the generated JSON schema registry
    under `assets/config-schema.json` ("$defs.PluginConfigs") so aliases match
    runtime discovery.
  - Priority extraction supports both legacy keys (pre_priority/post_priority/
    setup_priority/priority) and the v2-style blocks used in config files:
      - setup: {priority: <int>}
      - hooks:
          pre_resolve:  {priority: <int>}
          post_resolve: {priority: <int>}

Example:
  PYTHONPATH=src python3 scripts/generate_config_mermaid.py --config ./config/config.yaml > plugins.mmd
  PYTHONPATH=src python3 scripts/generate_config_mermaid.py --config ./config/config.yaml --png --output ./config/diagram.mmd
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

# Add the 'src' directory to sys.path to resolve 'foghorn' module imports.
# This keeps the script runnable from a fresh checkout without installation.
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
src_dir = project_root / "src"
if src_dir.is_dir() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from foghorn.utils import config_mermaid as cm


def main(argv: Optional[list[str]] = None) -> int:
    """Brief: CLI entry point.

    Inputs:
      - argv: Optional CLI args (defaults to sys.argv).

    Outputs:
      - int: Exit code (0 on success).

    Example:
      PYTHONPATH=src python3 scripts/generate_config_mermaid.py --config ./config/config.yaml
    """

    parser = argparse.ArgumentParser(description="Generate config Mermaid diagram")
    parser.add_argument(
        "--config",
        default=str(project_root / "config" / "config.yaml"),
        help="Path to YAML config (default: ./config/config.yaml)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write Mermaid text output to this file (default: stdout)",
    )
    parser.add_argument(
        "--png",
        action="store_true",
        help="Also render the diagram to PNG (requires mmdc or python_mermaid)",
    )
    parser.add_argument(
        "--png-output",
        default=None,
        help="Write PNG output to this path (default: <config_dir>/diagram.png)",
    )
    parser.add_argument(
        "--direction",
        choices=["TB", "LR"],
        default="TB",
        help="Mermaid flow direction (default: TB = top-to-bottom)",
    )
    parser.add_argument(
        "--font-size",
        type=int,
        default=18,
        help="Mermaid theme font size in pixels (default: 18)",
    )
    parser.add_argument(
        "--node-spacing",
        type=int,
        default=80,
        help="Mermaid flowchart node spacing (default: 80)",
    )
    parser.add_argument(
        "--rank-spacing",
        type=int,
        default=90,
        help="Mermaid flowchart rank spacing (default: 90)",
    )
    parser.add_argument(
        "--no-init",
        action="store_true",
        help="Disable Mermaid init directive (theme/spacing tweaks)",
    )

    args = parser.parse_args(argv)

    config_path = str(args.config)

    text = cm.generate_mermaid_text_from_config_path(
        config_path,
        direction=str(args.direction),
        font_size_px=int(args.font_size),
        node_spacing=int(args.node_spacing),
        rank_spacing=int(args.rank_spacing),
        include_init=not bool(args.no_init),
    )

    if args.output:
        Path(str(args.output)).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    if args.png:
        cfg_dir = Path(config_path).resolve().parent
        png_path = (
            Path(str(args.png_output)) if args.png_output else (cfg_dir / "diagram.png")
        )
        # For UI/debugging, prefer writing Mermaid next to the PNG when the user
        # didn't explicitly choose a --output path.
        mmd_path = Path(str(args.output)) if args.output else (cfg_dir / "diagram.mmd")

        ok, detail, _png_path = cm.ensure_config_diagram_png(
            config_path=config_path,
            output_png_path=str(png_path),
            output_mmd_path=str(mmd_path),
            direction=str(args.direction),
            font_size_px=int(args.font_size),
            node_spacing=int(args.node_spacing),
            rank_spacing=int(args.rank_spacing),
            include_init=not bool(args.no_init),
        )
        if not ok:
            sys.stderr.write(f"Failed to render PNG: {detail}\n")
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
