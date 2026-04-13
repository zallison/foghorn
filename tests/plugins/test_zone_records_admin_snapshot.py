"""Brief: Tests for ZoneRecords admin HTTP snapshot payload.

Inputs:
  - Temporary records files and inline record config.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

from pathlib import Path

from foghorn.plugins.resolve.zone_records import ZoneRecords


def test_zone_records_snapshot_includes_sources(tmp_path: Path) -> None:
    """Brief: ZoneRecords.get_http_snapshot includes per-record source labels.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - None.

    Notes:
      - This test disables watchdog and polling so plugin.setup() does not spawn
        background threads.
    """

    records_path = tmp_path / "zone_records.txt"
    records_path.write_text(
        "\n".join(
            [
                "example.com|SOA|300|ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300",
                "example.com|A|300|1.1.1.1",
                "www.example.com|A|300|2.2.2.2",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    plugin = ZoneRecords(
        name="zone_records",
        file_paths=[str(records_path)],
        records=[
            "example.com|A|300|1.1.1.1",
            "example.com|A|300|1.1.1.2",
        ],
        load_mode="replace",
        merge_policy="add",
        watchdog_enabled=False,
        watchdog_poll_interval_seconds=0.0,
        axfr_zones=[],
    )

    try:
        plugin.setup()
        snap = plugin.get_http_snapshot()

        assert "summary" in snap
        assert "zones" in snap
        assert "records" in snap

        zones = snap["zones"]
        assert any(z.get("zone") == "example.com" for z in zones)

        rows = snap["records"]
        match = None
        for row in rows:
            if (
                row.get("zone") == "example.com"
                and row.get("owner") == "example.com"
                and row.get("qtype") == "A"
                and row.get("value") == "1.1.1.1"
            ):
                match = row
                break

        assert match is not None
        sources = match.get("sources")
        assert isinstance(sources, list)
        assert "inline-config-records" in sources
        assert str(records_path) in sources
    finally:
        plugin.close()
