"""Brief: Tests for foghorn CLI actions (init/status/config/service/reload).

Inputs:
  - tmp_path, monkeypatch, capsys fixtures

Outputs:
  - Assertions covering command dispatch and PID helpers.
"""

from __future__ import annotations

import os
import signal
from argparse import Namespace
from pathlib import Path

import foghorn.cli_actions as cli
import foghorn.main as main_mod


def _ns(**kwargs) -> Namespace:
    """Brief: Build a Namespace with CLI defaults.

    Inputs:
      - kwargs: Field overrides.

    Outputs:
      - Namespace.
    """

    base = {
        "action": "serve",
        "config": "config.yaml",
        "subcommand": None,
        "var": [],
        "rebuild": False,
        "config_extras": "error",
        "skip_schema_validation": False,
    }
    base.update(kwargs)
    return Namespace(**base)


def test_normalize_legacy_config_flag():
    """Brief: --config PATH rewrites to serve PATH."""

    assert main_mod._normalize_legacy_cli_argv(["--config", "a.yaml"]) == [
        "serve",
        "a.yaml",
    ]
    assert main_mod._normalize_legacy_cli_argv(["-v", "X=1", "--config", "a.yaml"]) == [
        "serve",
        "a.yaml",
        "-v",
        "X=1",
    ]
    assert main_mod._normalize_legacy_cli_argv(["serve", "a.yaml"]) == [
        "serve",
        "a.yaml",
    ]


def test_cli_accepts_config_flag_and_positional():
    """Brief: status/init/config accept --config and bare config paths.

    Inputs:
      - None.

    Outputs:
      - None; asserts resolved args.config for common invocation forms.
    """

    from foghorn.main_config_helpers import (
        _build_main_arg_parser,
        resolve_cli_config_path,
    )

    parser = _build_main_arg_parser()

    def _parse(argv: list[str]) -> object:
        args = parser.parse_args(argv)
        resolve_cli_config_path(args)
        return args

    for argv in (
        ["status", "foo.yaml"],
        ["status", "--config", "foo.yaml"],
        ["status", "-c", "foo.yaml"],
        ["init", "foo.yaml"],
        ["init", "--config", "foo.yaml"],
        ["config", "validate", "foo.yaml"],
        ["config", "validate", "--config", "foo.yaml"],
        ["config", "--config", "foo.yaml", "validate"],
        ["config", "show", "foo.yaml"],
    ):
        args = _parse(argv)
        assert args.config == "foo.yaml", argv

    bare = _parse(["status"])
    assert bare.config == "config.yaml"


def test_pid_file_write_read_remove(tmp_path, monkeypatch):
    """Brief: PID helpers round-trip and only remove matching pid."""

    monkeypatch.delenv("FOGHORN_PID_FILE", raising=False)
    pid_path = str(tmp_path / "foghorn.pid")
    monkeypatch.setenv("FOGHORN_PID_FILE", pid_path)

    resolved = cli.resolve_pid_file_path("cfg.yaml")
    assert resolved == os.path.abspath(pid_path)

    cli.write_pid_file(pid_path, pid=12345)
    assert cli.read_pid_file(pid_path) == 12345

    # Wrong pid should not remove.
    cli.remove_pid_file(pid_path, pid=999)
    assert Path(pid_path).is_file()

    cli.remove_pid_file(pid_path, pid=12345)
    assert not Path(pid_path).exists()


def test_cmd_init_creates_config_and_dirs(tmp_path, monkeypatch):
    """Brief: init writes default config and data dirs."""

    monkeypatch.setattr(
        cli, "discover_system_nameservers", lambda: ["1.1.1.1", "9.9.9.9"]
    )
    cfg = tmp_path / "my-config.yaml"
    rc = cli.cmd_init(_ns(action="init", config=str(cfg)))
    assert rc == 0
    assert cfg.is_file()
    text = cfg.read_text(encoding="utf-8")
    assert "host: 1.1.1.1" in text
    assert "host: 9.9.9.9" in text
    assert "dns.example" not in text
    assert (tmp_path / "data" / "cache").is_dir()
    assert (tmp_path / "data" / "logs").is_dir()

    # Second init is idempotent.
    rc2 = cli.cmd_init(_ns(action="init", config=str(cfg)))
    assert rc2 == 0


def test_nameservers_from_resolv_conf(tmp_path):
    """Brief: resolv.conf parser extracts unique non-loopback nameservers.

    Inputs:
      - tmp_path fixture with a synthetic resolv.conf.

    Outputs:
      - None; asserts order, dedupe, and loopback filtering.
    """

    path = tmp_path / "resolv.conf"
    path.write_text(
        "\n".join(
            [
                "# comment",
                "nameserver 1.1.1.1",
                "nameserver 9.9.9.9",
                "nameserver 127.0.0.1",
                "nameserver ::1",
                "nameserver 1.1.1.1",
                "nameserver fe80::1%eth0",
                "search example.test",
                "",
            ]
        ),
        encoding="utf-8",
    )
    hosts = cli._nameservers_from_resolv_conf(path)
    assert hosts == ["1.1.1.1", "9.9.9.9", "fe80::1"]


def test_build_default_config_yaml_fallback_and_seed():
    """Brief: default YAML uses discovered hosts or dns.example fallback."""

    seeded = cli.build_default_config_yaml(nameservers=["8.8.8.8", "127.0.0.1"])
    assert "host: 8.8.8.8" in seeded
    assert "127.0.0.1" not in seeded
    assert "seeded from system DNS" in seeded

    fallback = cli.build_default_config_yaml(nameservers=[])
    assert "host: dns.example" in fallback
    assert "placeholder upstream" in fallback


def test_cmd_init_uses_system_dns_placeholder_when_empty(tmp_path, monkeypatch, capsys):
    """Brief: init falls back to dns.example when discovery returns nothing."""

    monkeypatch.setattr(cli, "discover_system_nameservers", lambda: [])
    cfg = tmp_path / "empty-dns.yaml"
    rc = cli.cmd_init(_ns(action="init", config=str(cfg)))
    assert rc == 0
    body = cfg.read_text(encoding="utf-8")
    assert "host: dns.example" in body
    out = capsys.readouterr().out
    assert "No system DNS" in out


def test_cmd_config_validate_ok_and_schema_fail(tmp_path, capsys):
    """Brief: validate returns 0 for schema failure; 1 for missing file."""

    missing = tmp_path / "missing.yaml"
    rc = cli.cmd_config(
        _ns(action="config", subcommand="validate", config=str(missing))
    )
    assert rc == 1

    bad = tmp_path / "bad.yaml"
    bad.write_text("server:\n  listen: not-a-mapping\n", encoding="utf-8")
    rc = cli.cmd_config(_ns(action="config", subcommand="validate", config=str(bad)))
    # Schema/validation failure must not exit 1.
    assert rc == 0
    out = capsys.readouterr().out
    assert "FAILED" in out

    good = tmp_path / "good.yaml"
    good.write_text(
        "upstreams:\n  endpoints:\n    - host: dns.example\n" "server:\n  listen: {}\n",
        encoding="utf-8",
    )
    rc = cli.cmd_config(_ns(action="config", subcommand="validate", config=str(good)))
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_cmd_config_show(tmp_path, capsys):
    """Brief: show prints effective YAML."""

    cfg = tmp_path / "show.yaml"
    cfg.write_text(
        "upstreams:\n  endpoints:\n    - host: dns.example\n" "server:\n  listen: {}\n",
        encoding="utf-8",
    )
    rc = cli.cmd_config(_ns(action="config", subcommand="show", config=str(cfg)))
    assert rc == 0
    out = capsys.readouterr().out
    assert "upstreams:" in out
    assert "server:" in out


def test_cmd_status_not_running(tmp_path, monkeypatch, capsys):
    """Brief: status exits 1 when no PID file."""

    pid_path = tmp_path / "x.pid"
    monkeypatch.setenv("FOGHORN_PID_FILE", str(pid_path))
    rc = cli.cmd_status(_ns(action="status", config=str(tmp_path / "c.yaml")))
    assert rc == 1
    assert "not running" in capsys.readouterr().out


def test_cmd_status_running(tmp_path, monkeypatch, capsys):
    """Brief: status exits 0 when PID is live."""

    pid_path = tmp_path / "x.pid"
    monkeypatch.setenv("FOGHORN_PID_FILE", str(pid_path))
    cli.write_pid_file(str(pid_path), pid=os.getpid())
    # Config load will fail; still running.
    rc = cli.cmd_status(_ns(action="status", config=str(tmp_path / "missing.yaml")))
    assert rc == 0
    out = capsys.readouterr().out
    assert "status: running" in out


def test_cmd_status_health_defaults_to_port_5380(tmp_path, monkeypatch, capsys):
    """Brief: status health probe defaults to admin port 5380.

    Inputs:
      - tmp_path / monkeypatch / capsys fixtures.

    Outputs:
      - None; asserts /health URL uses :5380 when config omits port.
    """

    pid_path = tmp_path / "h.pid"
    monkeypatch.setenv("FOGHORN_PID_FILE", str(pid_path))
    cli.write_pid_file(str(pid_path), pid=os.getpid())

    cfg = tmp_path / "health.yaml"
    cfg.write_text(
        "upstreams:\n  endpoints:\n    - host: dns.example\n"
        "server:\n  listen: {}\n  http:\n    enabled: true\n    host: localhost\n",
        encoding="utf-8",
    )

    opened: list[str] = []

    class _Resp:
        def read(self) -> bytes:
            return b'{"status": "ok"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(url, timeout=2.0, context=None):  # noqa: ARG001
        opened.append(str(url))
        assert context is None
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    rc = cli.cmd_status(_ns(action="status", config=str(cfg)))
    assert rc == 0
    out = capsys.readouterr().out
    assert "status: running" in out
    assert opened == ["http://localhost:5380/health"]
    assert "5380" in out
    assert "8053" not in out


def test_cmd_status_health_https_skips_tls_verify(tmp_path, monkeypatch, capsys):
    """Brief: HTTPS health probe uses an unverified SSL context.

    Inputs:
      - tmp_path / monkeypatch / capsys fixtures.

    Outputs:
      - None; asserts urlopen receives context with verify disabled.
    """

    pid_path = tmp_path / "tls.pid"
    monkeypatch.setenv("FOGHORN_PID_FILE", str(pid_path))
    cli.write_pid_file(str(pid_path), pid=os.getpid())

    cfg = tmp_path / "tls-health.yaml"
    cfg.write_text(
        "upstreams:\n  endpoints:\n    - host: dns.example\n"
        "server:\n  listen: {}\n  http:\n    enabled: true\n"
        "    host: localhost\n    port: 5380\n    cert_file: /tmp/cert.pem\n",
        encoding="utf-8",
    )

    opened: list[tuple[str, object]] = []

    class _Resp:
        def read(self) -> bytes:
            return b'{"status": "ok"}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(url, timeout=2.0, context=None):  # noqa: ARG001
        opened.append((str(url), context))
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    rc = cli.cmd_status(_ns(action="status", config=str(cfg)))
    assert rc == 0
    assert len(opened) == 1
    url, context = opened[0]
    assert url == "https://localhost:5380/health"
    assert context is not None
    assert getattr(context, "check_hostname", None) is False
    assert getattr(context, "verify_mode", None) == 0  # ssl.CERT_NONE
    assert "health: ok" in capsys.readouterr().out


def test_cmd_reload_sends_sigusr1(tmp_path, monkeypatch, capsys):
    """Brief: reload reads PID file and sends SIGUSR1."""

    pid_path = tmp_path / "r.pid"
    monkeypatch.setenv("FOGHORN_PID_FILE", str(pid_path))
    cli.write_pid_file(str(pid_path), pid=424242)

    sent: list[tuple[int, int]] = []

    def fake_kill(pid, sig):
        sent.append((pid, sig))

    monkeypatch.setattr(os, "kill", fake_kill)
    rc = cli.cmd_reload(_ns(action="reload", config=str(tmp_path / "c.yaml")))
    assert rc == 0
    assert sent == [(424242, signal.SIGUSR1)]
    assert "SIGUSR1" in capsys.readouterr().out


def test_cmd_service_install_writes_unit(tmp_path, monkeypatch, capsys):
    """Brief: service install writes a systemd unit file."""

    cfg = tmp_path / "svc.yaml"
    cfg.write_text(
        "upstreams:\n  endpoints:\n    - host: dns.example\nserver:\n  listen: {}\n",
        encoding="utf-8",
    )
    unit = tmp_path / "foghorn.service"
    monkeypatch.setenv("FOGHORN_SYSTEMD_UNIT", str(unit))
    monkeypatch.setattr(cli, "_run_systemctl", lambda *a, **k: -1)
    monkeypatch.setattr(cli, "_systemctl_available", lambda: False)

    rc = cli.cmd_service(_ns(action="service", subcommand="install", config=str(cfg)))
    assert rc == 0
    text = unit.read_text(encoding="utf-8")
    assert "ExecStart=" in text
    assert "serve" in text
    assert str(cfg.resolve()) in text


def test_cmd_service_uninstall_removes_unit(tmp_path, monkeypatch, capsys):
    """Brief: service uninstall removes unit file."""

    unit = tmp_path / "foghorn.service"
    unit.write_text("[Unit]\nDescription=x\n", encoding="utf-8")
    monkeypatch.setenv("FOGHORN_SYSTEMD_UNIT", str(unit))
    monkeypatch.setattr(cli, "_run_systemctl", lambda *a, **k: -1)

    rc = cli.cmd_service(_ns(action="service", subcommand="uninstall"))
    assert rc == 0
    assert not unit.exists()


def test_dispatch_routes_actions(tmp_path, monkeypatch):
    """Brief: dispatch_non_serve_action routes and leaves serve as None."""

    assert cli.dispatch_non_serve_action(_ns(action="serve")) is None

    cfg = tmp_path / "d.yaml"
    monkeypatch.setattr(cli, "cmd_init", lambda args: 42)
    assert cli.dispatch_non_serve_action(_ns(action="init", config=str(cfg))) == 42


def test_main_dispatches_init(tmp_path):
    """Brief: main() routes init without starting the server."""

    cfg = tmp_path / "from-main.yaml"
    rc = main_mod.main(["init", str(cfg)])
    assert rc == 0
    assert cfg.is_file()
