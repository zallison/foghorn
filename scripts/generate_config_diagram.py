#!/usr/bin/env python3
"""Brief: Generate a GraphViz dot diagram describing plugin ordering and short-circuits.

Inputs:
  - --config (str): Path to a Foghorn YAML config file. Default: ./config/config.yaml
  - --output (str, optional): Write the dot text to this path. When omitted,
    output is written to stdout.
  - --png (flag): Also render the diagram to PNG (requires `dot`).
  - --png-output (str, optional): Output path for the PNG. Default: <config_dir>/diagram.png
  - --direction (TB|LR): GraphViz rankdir. Default: TB (top-to-bottom).
  - --font-size (int): Font size in pixels.
  - --node-spacing (float): GraphViz nodesep.
  - --rank-spacing (float): GraphViz ranksep.
  - --no-init: Disable GraphViz attributes.

Outputs:
  - GraphViz dot text describing:
      - listener configuration (UDP/TCP/DoT/DoH)
      - upstream endpoints (when resolver.mode == forward)
      - pre/post plugin order
      - cache hit/miss branching
      - resolver mode
      - potential short-circuits (deny/override/drop) and upstream routing

Example:
  PYTHONPATH=src python3 scripts/generate_config_diagram.py --config ./config/config.yaml > diagram.dot
  PYTHONPATH=src python3 scripts/generate_config_diagram.py --config ./config/config.yaml --png --output ./config/diagram.dot
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

from foghorn.utils import config_diagram as cm


def main(argv: Optional[list[str]] = None) -> int:
    """Brief: CLI entry point.

    Inputs:
      - argv: Optional CLI args (defaults to sys.argv).

    Outputs:
      - int: Exit code (0 on success).

    Example:
      PYTHONPATH=src python3 scripts/generate_config_diagram.py --config ./config/config.yaml
    """

    parser = argparse.ArgumentParser(description="Generate config diagram")
    parser.add_argument(
        "--config",
        default=str(project_root / "config" / "config.yaml"),
        help="Path to YAML config (default: ./config/config.yaml)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write dot text output to this file (default: stdout)",
    )
    parser.add_argument(
        "--png",
        action="store_true",
        help="Also render the diagram to PNG (requires dot)",
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
        help="GraphViz rankdir (default: TB = top-to-bottom)",
    )
    parser.add_argument(
        "--font-size",
        type=int,
        default=18,
        help="Font size in pixels (default: 18)",
    )
    parser.add_argument(
        "--node-spacing",
        type=float,
        default=0.8,
        help="GraphViz nodesep (default: 0.8)",
    )
    parser.add_argument(
        "--rank-spacing",
        type=float,
        default=0.9,
        help="GraphViz ranksep (default: 0.9)",
    )
    parser.add_argument(
        "--no-init",
        action="store_true",
        help="Disable GraphViz attributes",
    )

    args = parser.parse_args(argv)

    config_path = str(args.config)

    text = cm.generate_dot_text_from_config_path(
        config_path,
        direction=str(args.direction),
        font_size_px=int(args.font_size),
        node_spacing=float(args.node_spacing),
        rank_spacing=float(args.rank_spacing),
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
        # For UI/debugging, prefer writing dot next to the PNG when the user
        # didn't explicitly choose a --output path.
        dot_path = Path(str(args.output)) if args.output else (cfg_dir / "diagram.dot")

        ok, detail, _png_path = cm.ensure_config_diagram_png(
            config_path=config_path,
            output_png_path=str(png_path),
            output_dot_path=str(dot_path),
            direction=str(args.direction),
            font_size_px=int(args.font_size),
            node_spacing=float(args.node_spacing),
            rank_spacing=float(args.rank_spacing),
            include_init=not bool(args.no_init),
        )
        if not ok:
            sys.stderr.write(f"Failed to render PNG: {detail}\n")
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
