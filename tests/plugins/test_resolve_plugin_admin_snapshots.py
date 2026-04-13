"""Brief: Smoke tests for resolve plugin admin UI snapshot helpers.

Inputs:
  - Temporary filesystem paths provided by pytest tmp_path.

Outputs:
  - None (pytest assertions). Ensures get_http_snapshot() payloads are JSON-safe.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from foghorn.plugins.resolve.access_control import AccessControl
from foghorn.plugins.resolve.echo import Echo
from foghorn.plugins.resolve.file_downloader import FileDownloader
from foghorn.plugins.resolve.filter import Filter
from foghorn.plugins.resolve.flaky_server import FlakyServer
from foghorn.plugins.resolve.rate_limit import RateLimit
from foghorn.plugins.resolve.ssh_keys import SshKeys
from foghorn.plugins.resolve.upstream_router import UpstreamRouter


def _assert_json_safe(payload: Dict[str, Any]) -> None:
    """Brief: Assert a payload can be JSON-serialized.

    Inputs:
      - payload: dict expected to be JSON-safe.

    Outputs:
      - None. Raises AssertionError on failure.
    """

    json.dumps(payload)


def _maybe_setup(plugin: object) -> None:
    """Brief: Call plugin.setup() when present.

    Inputs:
      - plugin: Plugin instance.

    Outputs:
      - None.
    """

    setup = getattr(plugin, "setup", None)
    if callable(setup):
        setup()


@pytest.mark.parametrize(
    "factory",
    [
        lambda tmp: Echo(name="echo"),
        lambda tmp: AccessControl(
            name="access_control", default="allow", allow=[], deny=[]
        ),
        lambda tmp: FileDownloader(
            name="file_downloader",
            download_path=str(tmp / "lists"),
            urls=[],
            url_files=[],
        ),
        lambda tmp: Filter(name="filter", db_path=str(tmp / "filter.db"), clear=1),
        lambda tmp: FlakyServer(
            name="flaky_server", seed=123, servfail_percent=0.0, nxdomain_percent=0.0
        ),
        lambda tmp: RateLimit(name="rate_limit", db_path=str(tmp / "rate_limit.db")),
        lambda tmp: SshKeys(
            name="ssh_keys", db_path=str(tmp / "ssh_keys.db"), targets=[]
        ),
        lambda tmp: UpstreamRouter(
            name="upstream_router",
            routes=[
                {
                    "domain": "example.com",
                    "upstreams": [{"host": "1.1.1.1", "port": 53}],
                },
                {
                    "suffix": "corp",
                    "upstreams": [
                        {"host": "10.0.0.2", "port": 53},
                        {"host": "10.0.0.3", "port": 53},
                    ],
                },
            ],
        ),
    ],
)
def test_plugin_http_snapshot_is_json_safe(tmp_path: Path, factory) -> None:  # type: ignore[no-untyped-def]
    plugin = factory(tmp_path)
    _maybe_setup(plugin)

    snap = plugin.get_http_snapshot()  # type: ignore[attr-defined]
    assert isinstance(snap, dict)
    assert "summary" in snap
    assert "config_items" in snap

    _assert_json_safe(snap)
