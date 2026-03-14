"""Brief: Integration tests for ZoneRecords DNS UPDATE persistence behavior.

Inputs:
  - Temporary records/state files.
  - TSIG-signed DNS UPDATE messages.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

from pathlib import Path

import dns.message
import dns.update
from dnslib import QTYPE

from foghorn.plugins.resolve.zone_records import ZoneRecords
from foghorn.plugins.resolve.zone_records.journal import JournalWriter
from foghorn.plugins.resolve.zone_records import update_processor as up


def _zone_records_config(
    *,
    records_path: Path,
    state_dir: Path,
    zone: str,
    key_name: str,
    secret_b64: str,
) -> dict:
    """Brief: Build a ZoneRecords config with DNS UPDATE persistence enabled.

    Inputs:
      - records_path: Static records file path.
      - state_dir: Persistence base directory for journal data.
      - zone: Zone apex.
      - key_name: TSIG key name.
      - secret_b64: Base64 TSIG secret.

    Outputs:
      - dict with ZoneRecords constructor kwargs.
    """
    return {
        "file_paths": [str(records_path)],
        "watchdog_enabled": False,
        "watchdog_poll_interval_seconds": 0.0,
        "dns_update": {
            "enabled": True,
            "zones": [
                {
                    "zone": zone,
                    "tsig": {
                        "keys": [
                            {
                                "name": key_name,
                                "algorithm": "hmac-sha256",
                                "secret": secret_b64,
                                "allow_names": [f"*.{zone}", zone],
                            }
                        ]
                    },
                }
            ],
            "persistence": {
                "enabled": True,
                "state_dir": str(state_dir),
                "fsync_mode": "always",
            },
            "replication": {
                "notify_on_update": False,
                "node_id": "test-node",
            },
        },
    }


def _apply_update_with_journal(
    *,
    plugin: ZoneRecords,
    zone: str,
    mutate_cb,
) -> None:
    """Brief: Apply one UPDATE transaction through update_processor + journal.

    Inputs:
      - plugin: ZoneRecords instance.
      - zone: Zone apex.
      - mutate_cb: Callable that mutates a dns.update.Update message.

    Outputs:
      - None. Raises assertion failures on operation errors.
    """
    msg = dns.update.Update(f"{zone}.")
    mutate_cb(msg)
    updates = list(getattr(msg, "update", []) or [])
    writer = JournalWriter(
        zone_apex=zone,
        base_dir=str(plugin._dns_update_journal_state_dir),
    )
    assert writer.acquire_lock() is True
    try:
        rcode, err = up.apply_update_operations(
            updates,
            plugin,
            zone,
            journal_writer=writer,
            actor={
                "client_ip": "192.0.2.10",
                "auth_method": "tsig",
                "tsig_key_name": "key.example.com.",
            },
        )
    finally:
        writer.release_lock()
        writer.close()
    assert rcode == 0
    assert err is None


def test_restart_replay_restores_add_delete_replace(tmp_path: Path) -> None:
    """Brief: Restart replay restores committed dynamic add/delete/replace actions.

    Inputs:
      - tmp_path: pytest temporary path root.

    Outputs:
      - None. Asserts dynamic state is preserved across plugin restart.
    """
    zone = "example.com"
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    records_path = tmp_path / "records.txt"
    state_dir = tmp_path / "state"
    records_path.write_text(
        "\n".join(
            [
                "example.com|SOA|300|ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    cfg = _zone_records_config(
        records_path=records_path,
        state_dir=state_dir,
        zone=zone,
        key_name=key_name,
        secret_b64=secret_b64,
    )

    plugin = ZoneRecords(name="zone_records", **cfg)
    plugin.setup()
    try:
        _apply_update_with_journal(
            plugin=plugin,
            zone=zone,
            mutate_cb=lambda m: (
                m.add("dyn-del.example.com.", 60, "A", "192.0.2.11"),
                m.add("dyn-repl.example.com.", 60, "A", "192.0.2.20"),
                m.replace("dyn-repl.example.com.", 60, "A", "192.0.2.21"),
                m.delete("dyn-del.example.com."),
            ),
        )
    finally:
        plugin.close()

    plugin2 = ZoneRecords(name="zone_records", **cfg)
    plugin2.setup()
    try:
        assert ("dyn-repl.example.com", int(QTYPE.A)) in plugin2.records
        _ttl, values, _sources = plugin2.records[("dyn-repl.example.com", int(QTYPE.A))]
        assert values == ["192.0.2.21"]
        assert ("dyn-del.example.com", int(QTYPE.A)) not in plugin2.records
    finally:
        plugin2.close()


def test_static_reload_then_replay_keeps_dynamic_precedence(tmp_path: Path) -> None:
    """Brief: Reload applies static sources first then journal replay as overlay.

    Inputs:
      - tmp_path: pytest temporary path root.

    Outputs:
      - None. Asserts dynamic value keeps precedence after static file changes.
    """
    zone = "example.com"
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    records_path = tmp_path / "records.txt"
    state_dir = tmp_path / "state"
    records_path.write_text(
        "\n".join(
            [
                "example.com|SOA|300|ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300",
                "host.example.com|A|300|192.0.2.1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cfg = _zone_records_config(
        records_path=records_path,
        state_dir=state_dir,
        zone=zone,
        key_name=key_name,
        secret_b64=secret_b64,
    )
    plugin = ZoneRecords(name="zone_records", **cfg)
    plugin.setup()
    try:
        _apply_update_with_journal(
            plugin=plugin,
            zone=zone,
            mutate_cb=lambda m: m.replace("host.example.com.", 60, "A", "192.0.2.200"),
        )
        records_path.write_text(
            "\n".join(
                [
                    "example.com|SOA|300|ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300",
                    "host.example.com|A|300|192.0.2.250",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        plugin._load_records()

        assert ("host.example.com", int(QTYPE.A)) in plugin.records
        _ttl, values, _sources = plugin.records[("host.example.com", int(QTYPE.A))]
        assert values == ["192.0.2.200"]
    finally:
        plugin.close()


def test_axfr_export_reflects_replayed_dynamic_state_after_restart(
    tmp_path: Path,
) -> None:
    """Brief: AXFR export reflects journal-replayed dynamic data after restart.

    Inputs:
      - tmp_path: pytest temporary path root.

    Outputs:
      - None. Asserts transfer export includes dynamic value after replay.
    """
    zone = "example.com"
    key_name = "key.example.com."
    secret_b64 = "dGVzdHNlY3JldA=="
    records_path = tmp_path / "records.txt"
    state_dir = tmp_path / "state"
    records_path.write_text(
        "\n".join(
            [
                "example.com|SOA|300|ns1.example.com. hostmaster.example.com. 1 3600 600 604800 300",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cfg = _zone_records_config(
        records_path=records_path,
        state_dir=state_dir,
        zone=zone,
        key_name=key_name,
        secret_b64=secret_b64,
    )
    plugin = ZoneRecords(name="zone_records", **cfg)
    plugin.setup()
    try:
        _apply_update_with_journal(
            plugin=plugin,
            zone=zone,
            mutate_cb=lambda m: m.add(
                "axfr-dyn.example.com.", 60, "A", "198.51.100.77"
            ),
        )
    finally:
        plugin.close()

    plugin2 = ZoneRecords(name="zone_records", **cfg)
    plugin2.setup()
    try:
        rrs = plugin2.iter_zone_rrs_for_transfer(zone)
        assert rrs is not None
        rendered = {
            (str(rr.rname).rstrip(".").lower(), int(rr.rtype), str(rr.rdata))
            for rr in rrs
        }
        assert ("axfr-dyn.example.com", int(QTYPE.A), "198.51.100.77") in rendered
    finally:
        plugin2.close()
