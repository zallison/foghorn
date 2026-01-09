"""Brief: Tests for the generate_foghorn_schema helper script.

Inputs:
  - None directly; uses pytest fixtures like tmp_path.

Outputs:
  - None; asserts that the schema generator script runs successfully and writes
    a JSON document.
"""

from __future__ import annotations

from pathlib import Path

import json
import runpy
import sys


def _load_schema_module():
    """Brief: Load the generate_foghorn_schema module via runpy.run_path.

    Inputs:
      - None; uses sys.executable and the scripts/generate_foghorn_schema.py path.

    Outputs:
      - Module-like object (a dict) containing the script's global namespace.
    """

    script_path = Path(__file__).resolve().parents[1] / "scripts" / "generate_foghorn_schema.py"
    return runpy.run_path(str(script_path))


def test_generate_foghorn_schema_main_writes_json(tmp_path) -> None:
    """Brief: generate_foghorn_schema.main writes a JSON schema file.

    Inputs:
      - tmp_path: pytest-provided temporary directory for the output file.

    Outputs:
      - None; asserts main() returns 0 and the output file contains valid JSON.
    """

    out_path = tmp_path / "schema.json"

    # Load the script as a module-like namespace and invoke its main() function.
    ns = _load_schema_module()
    main_fn = ns.get("main")
    assert callable(main_fn)

    rc = main_fn(["-o", str(out_path)])
    assert rc == 0
    assert out_path.is_file()

    # Ensure the file contains syntactically valid JSON and a top-level object.
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
