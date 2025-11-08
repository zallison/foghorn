#!/usr/bin/env python3
"""
Brief: Enforce per-file coverage >= 90% by parsing coverage.xml (Cobertura XML).

Inputs:
  - Path to coverage XML (default: coverage.xml)

Outputs:
  - Exit code 0 on success; non-zero if any file is below threshold.
"""

import sys
import xml.etree.ElementTree as ET

THRESHOLD = 0.90


def main(path: str) -> int:
    tree = ET.parse(path)
    root = tree.getroot()
    # Cobertura schema: packages/package/classes/class line-rate attribute
    failures = []
    for pkg in root.findall("packages/package"):
        for cls in pkg.findall("classes/class"):
            filename = cls.get("filename", "")
            line_rate = float(cls.get("line-rate", "0"))
            if filename.startswith("foghorn/") and line_rate < THRESHOLD:
                failures.append((filename, line_rate))
    if failures:
        sys.stderr.write("Per-file coverage below threshold (90%):\n")
        for fn, rate in failures:
            sys.stderr.write(f"  {fn}: {rate*100:.1f}%\n")
        return 2
    return 0


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "coverage.xml"
    raise SystemExit(main(path))
