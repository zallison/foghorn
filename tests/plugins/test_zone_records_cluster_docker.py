"""Brief: Docker-marked cluster-oriented tests for ZoneRecords update replication behavior.

Inputs:
  - Temporary records/state files.
  - TSIG-signed UPDATE messages.

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import dns.message
import dns.rcode
import dns.tsigkeyring
import dns.update
import pytest
from dnslib import QTYPE

from foghorn.plugins.resolve.zone_records import ZoneRecords
from foghorn.plugins.resolve.zone_records import notify as notify_mod
from foghorn.plugins.resolve.zone_records import update_processor as up


def _is_docker_available() -> bool:
    """Brief: Check whether docker CLI is available.

    Inputs:
      - None.

    Outputs:
      - bool: True when docker is callable.
    """
    try:
        subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            timeout=5,
            check=True,
        )
        return True
    except Exception:
        return False


pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not _is_docker_available(),
        reason="Docker not available - skipping Docker-based integration tests",
    ),
]


def _unused_high_port() -> int:
    """Brief: Reserve and release a random high TCP port.

    Inputs:
      - None.

    Outputs:
      - int: An available high TCP port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _zone_cfg(
    *, zone: str, key_name: str, secret_b64: str, state_dir: Path, role: str
) -> dict:
    """Brief: Build ZoneRecords config for clustered update tests.

    Inputs:
      - zone: Zone apex.
      - key_name: TSIG key name.
      - secret_b64: Base64 TSIG secret.
      - state_dir: Shared persistence directory.
      - role: replication role value.

    Outputs:
      - dict: constructor kwargs for ZoneRecords.
    """
    return {
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
                "role": role,
                "notify_on_update": False,
                "reject_direct_update_on_replica": True,
                "node_id": f"{role}-node",
            },
        },
    }


def _signed_update_wire(
    *,
    zone: str,
    key_name: str,
    secret_b64: str,
    owner_fqdn: str,
    value: str,
) -> tuple[bytes, dns.tsigkeyring.Keyring]:
    """Brief: Build one TSIG-signed UPDATE wire payload.

    Inputs:
      - zone: Zone apex.
      - key_name: TSIG key name.
      - secret_b64: Base64 TSIG secret.
      - owner_fqdn: Owner FQDN to add.
      - value: A-record value.

    Outputs:
      - tuple[bytes, keyring]: request wire and keyring used to sign/verify.
    """
    keyring = dns.tsigkeyring.from_text({key_name: secret_b64})
    msg = dns.update.Update(f"{zone}.")
    msg.use_tsig(keyring=keyring, keyname=key_name, algorithm="hmac-sha256")
    msg.add(owner_fqdn, 60, "A", value)
    return msg.to_wire(), keyring


def test_primary_and_replicas_converge_via_shared_journal_state(tmp_path: Path) -> None:
    """Brief: One writer with shared journal state yields converged replay state.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - None. Asserts two replica instances replay the primary's committed update.
    """
    zone = "cluster.example"
    key_name = "k.cluster.example."
    secret_b64 = "dGVzdHNlY3JldA=="
    shared_state = tmp_path / "shared_state"
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "cluster.example|SOA|300|ns1.cluster.example. hostmaster.cluster.example. 1 3600 600 604800 300\n",
        encoding="utf-8",
    )

    primary = ZoneRecords(
        name="zone_records",
        file_paths=[str(records_file)],
        **_zone_cfg(
            zone=zone,
            key_name=key_name,
            secret_b64=secret_b64,
            state_dir=shared_state,
            role="primary",
        ),
    )
    primary.setup()
    try:
        req_wire, keyring = _signed_update_wire(
            zone=zone,
            key_name=key_name,
            secret_b64=secret_b64,
            owner_fqdn="node1.cluster.example.",
            value="198.51.100.45",
        )
        req_msg = dns.message.from_wire(req_wire, keyring=keyring)
        zone_cfg = primary._dns_update_config["zones"][0]  # type: ignore[index]
        resp_wire = up.process_update_message(
            req_wire,
            zone_apex=zone,
            zone_config=zone_cfg,
            plugin=primary,
            client_ip="192.0.2.10",
            listener="udp",
        )
        resp = dns.message.from_wire(
            resp_wire, keyring=keyring, request_mac=req_msg.mac
        )
        assert resp.rcode() == dns.rcode.NOERROR
    finally:
        primary.close()

    replica_a = ZoneRecords(
        name="zone_records",
        file_paths=[str(records_file)],
        **_zone_cfg(
            zone=zone,
            key_name=key_name,
            secret_b64=secret_b64,
            state_dir=shared_state,
            role="replica",
        ),
    )
    replica_b = ZoneRecords(
        name="zone_records",
        file_paths=[str(records_file)],
        **_zone_cfg(
            zone=zone,
            key_name=key_name,
            secret_b64=secret_b64,
            state_dir=shared_state,
            role="replica",
        ),
    )
    replica_a.setup()
    replica_b.setup()
    try:
        key = ("node1.cluster.example", int(QTYPE.A))
        assert key in replica_a.records
        assert key in replica_b.records
        assert replica_a.records[key][1] == ["198.51.100.45"]
        assert replica_b.records[key][1] == ["198.51.100.45"]
    finally:
        replica_a.close()
        replica_b.close()


def test_three_node_single_writer_policy_rejects_non_owner_direct_updates(
    tmp_path: Path,
) -> None:
    """Brief: Non-owner nodes (replica role) reject direct client UPDATE writes.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - None. Asserts REFUSED from non-owner/replica nodes.
    """
    zone = "peer.example"
    key_name = "k.peer.example."
    secret_b64 = "dGVzdHNlY3JldA=="
    shared_state = tmp_path / "shared_state"
    records_file = tmp_path / "records.txt"
    records_file.write_text(
        "peer.example|SOA|300|ns1.peer.example. hostmaster.peer.example. 1 3600 600 604800 300\n",
        encoding="utf-8",
    )

    replica = ZoneRecords(
        name="zone_records",
        file_paths=[str(records_file)],
        **_zone_cfg(
            zone=zone,
            key_name=key_name,
            secret_b64=secret_b64,
            state_dir=shared_state,
            role="replica",
        ),
    )
    replica.setup()
    try:
        req_wire, keyring = _signed_update_wire(
            zone=zone,
            key_name=key_name,
            secret_b64=secret_b64,
            owner_fqdn="blocked.peer.example.",
            value="203.0.113.33",
        )
        req_msg = dns.message.from_wire(req_wire, keyring=keyring)
        zone_cfg = replica._dns_update_config["zones"][0]  # type: ignore[index]
        resp_wire = up.process_update_message(
            req_wire,
            zone_apex=zone,
            zone_config=zone_cfg,
            plugin=replica,
            client_ip="192.0.2.20",
            listener="udp",
        )
        resp = dns.message.from_wire(
            resp_wire, keyring=keyring, request_mac=req_msg.mac
        )
        assert resp.rcode() == dns.rcode.REFUSED
    finally:
        replica.close()


def test_misconfigured_self_peer_notify_target_skipped_on_random_high_port(
    monkeypatch,
) -> None:
    """Brief: Self-peer NOTIFY target is skipped when it maps to local endpoint.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None. Asserts local target is filtered out while remote target is sent.
    """
    high_port = _unused_high_port()

    class Plugin:
        _axfr_notify_static_targets = [
            {"host": "127.0.0.1", "port": high_port, "transport": "tcp"},
            {"host": "203.0.113.120", "port": high_port, "transport": "tcp"},
        ]
        _axfr_notify_learned = {}

    sent: list[tuple[str, dict]] = []

    monkeypatch.setattr(
        notify_mod,
        "_get_local_dns_listener_endpoints",
        lambda: {("127.0.0.1", high_port)},
        raising=True,
    )
    monkeypatch.setattr(
        notify_mod,
        "_resolve_target_ips",
        lambda host: {str(host)},
        raising=True,
    )
    monkeypatch.setattr(
        notify_mod,
        "send_notify_to_target",
        lambda zone_apex, target: sent.append((zone_apex, dict(target))),
        raising=True,
    )

    notify_mod.send_notify_for_zones(Plugin(), ["peer.example"])
    assert sent == [
        (
            "peer.example",
            {"host": "203.0.113.120", "port": high_port, "transport": "tcp"},
        )
    ]
