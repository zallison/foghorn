#!/usr/bin/env python3
"""
generate_arch_diagram.py — Extended version with CLI options
Scans the Foghorn repo and generates a Mermaid architecture diagram.
"""
import os
import argparse
from pathlib import Path

def generate_mermaid(root_dir: Path, plugins_only=False):
    lines = ["graph TD"]
    if not plugins_only:
        lines += [
            "    A[Client DNS Query] --> B[Pre-resolve Plugins]",
            "    B --> C[Cache Layer]",
            "    C -->|Cache miss| D[Upstream Resolver(s)]",
            "    C -->|Cache hit| G[Return Cached Response]",
            "    D --> E[Post-resolve Plugins]",
            "    E --> F[Response Logger]",
            "    F --> G[DNS Response to Client]",
        ]
    plugins_dir = root_dir / "src" / "foghorn" / "plugins"
    if plugins_dir.exists():
        lines.append("    subgraph Plugins")
        for f in plugins_dir.glob("*.py"):
            name = f.stem
            if name != "__init__":
                lines.append(f"        P_{name}[{name}]")
        lines.append("    end")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Generate a Mermaid architecture diagram for Foghorn.")
    parser.add_argument("--root", default=".", help="Root directory of Foghorn project.")
    parser.add_argument("--output", default="docs/arch_diagram.mmd", help="Output Mermaid diagram path.")
    parser.add_argument("--plugins-only", action="store_true", help="Generate plugin graph only.")
    args = parser.parse_args()

    root_dir = Path(args.root).resolve()
    mermaid = generate_mermaid(root_dir, plugins_only=args.plugins_only)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(mermaid)
    print(f"[OK] Mermaid diagram written to {out_path}")

if __name__ == "__main__":
    main()
