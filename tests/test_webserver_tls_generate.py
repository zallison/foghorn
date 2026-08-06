"""Tests for optional admin TLS auto-generation via openssl."""

from __future__ import annotations

from pathlib import Path

import pytest

from foghorn.servers.webserver.tls_certs import (
    default_admin_tls_paths,
    ensure_admin_tls_files,
    generate_self_signed_admin_tls,
    normalize_generate_policy,
)


def test_normalize_generate_policy_aliases() -> None:
    """Brief: generate policy accepts yes/no/maybe and common aliases.

    Inputs:
      - Representative raw policy values.

    Outputs:
      - Normalized yes/no/maybe strings; invalid values raise ValueError.
    """

    assert normalize_generate_policy(None) == "no"
    assert normalize_generate_policy("no") == "no"
    assert normalize_generate_policy(False) == "no"
    assert normalize_generate_policy("YES") == "yes"
    assert normalize_generate_policy(True) == "yes"
    assert normalize_generate_policy("maybe") == "maybe"
    assert normalize_generate_policy("on") == "yes"
    assert normalize_generate_policy("0") == "no"
    with pytest.raises(ValueError):
        normalize_generate_policy("sometimes")


def test_default_admin_tls_paths_use_config_dir(tmp_path: Path) -> None:
    """Brief: default paths sit under <config_dir>/keys when config_path is set.

    Inputs:
      - tmp_path fixture and a fake config file path.

    Outputs:
      - cert/key basenames foghorn_admin.pem/.key under keys/.
    """

    cfg = tmp_path / "config.yaml"
    cfg.write_text("server: {}\n", encoding="utf-8")
    cert, key = default_admin_tls_paths(config_path=str(cfg))
    assert cert.endswith("keys/foghorn_admin.pem") or cert.endswith(
        "keys\\foghorn_admin.pem"
    )
    assert key.endswith("keys/foghorn_admin.key") or key.endswith(
        "keys\\foghorn_admin.key"
    )


def test_ensure_admin_tls_files_generate_no_is_passthrough(tmp_path: Path) -> None:
    """Brief: generate=no never creates files and keeps explicit paths.

    Inputs:
      - web_cfg with generate=no and explicit cert/key paths.

    Outputs:
      - Same paths returned; no files created.
    """

    cert = tmp_path / "a.pem"
    key = tmp_path / "a.key"
    cfg = {
        "generate": "no",
        "cert_file": str(cert),
        "key_file": str(key),
    }
    out = ensure_admin_tls_files(cfg, host="127.0.0.1")
    assert out == (str(cert), str(key))
    assert not cert.exists()
    assert not key.exists()


def test_ensure_admin_tls_files_warns_when_default_keys_exist_but_tls_off(
    tmp_path: Path, caplog
) -> None:
    """Brief: default foghorn_admin files trigger a warning when TLS is off.

    Inputs:
      - generate=no, no cert_file/key_file, default keys present under keys_dir.

    Outputs:
      - (None, None) and a WARNING mentioning default admin TLS files.
    """

    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "foghorn_admin.pem").write_text("CERT", encoding="utf-8")
    (keys / "foghorn_admin.key").write_text("KEY", encoding="utf-8")
    cfg = {"generate": "no", "keys_dir": str(keys)}
    with caplog.at_level("WARNING", logger="foghorn.webserver"):
        cert, key = ensure_admin_tls_files(cfg, host="127.0.0.1")
    assert cert is None and key is None
    msgs = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("Default admin TLS files are present" in m for m in msgs)
    assert any("server.http.cert_file" in m for m in msgs)
    assert any("make ssl-cert" in m for m in msgs)


def test_ensure_admin_tls_files_generate_maybe_creates_with_openssl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Brief: generate=maybe creates self-signed material when openssl is present.

    Inputs:
      - tmp_path keys_dir and monkeypatched openssl generator.

    Outputs:
      - cert/key files exist and paths are returned.
    """

    keys = tmp_path / "keys"
    created: dict[str, str] = {}

    def fake_generate(
        *,
        cert_file: str,
        key_file: str,
        host: str = "localhost",
        days: int = 3650,
        openssl_bin: str | None = None,
    ) -> None:
        Path(cert_file).parent.mkdir(parents=True, exist_ok=True)
        Path(cert_file).write_text("CERT", encoding="utf-8")
        Path(key_file).write_text("KEY", encoding="utf-8")
        created["cert"] = cert_file
        created["key"] = key_file
        created["host"] = host

    monkeypatch.setattr(
        "foghorn.servers.webserver.tls_certs.generate_self_signed_admin_tls",
        fake_generate,
    )
    monkeypatch.setattr(
        "foghorn.servers.webserver.tls_certs._openssl_available",
        lambda: "/usr/bin/openssl",
    )

    cfg = {"generate": "maybe", "keys_dir": str(keys)}
    cert, key = ensure_admin_tls_files(cfg, host="192.168.1.10", config_path=None)
    assert cert is not None and key is not None
    assert Path(cert).is_file()
    assert Path(key).is_file()
    assert created["host"] == "192.168.1.10"
    assert cfg["cert_file"] == cert
    assert cfg["key_file"] == key


def test_ensure_admin_tls_files_generate_maybe_without_openssl_skips(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog
) -> None:
    """Brief: generate=maybe continues without TLS when openssl is missing.

    Inputs:
      - keys_dir under tmp_path and openssl unavailable.

    Outputs:
      - (None, None) returned and a warning is logged.
    """

    monkeypatch.setattr(
        "foghorn.servers.webserver.tls_certs._openssl_available",
        lambda: None,
    )
    cfg = {"generate": "maybe", "keys_dir": str(tmp_path / "keys")}
    with caplog.at_level("WARNING", logger="foghorn.webserver"):
        cert, key = ensure_admin_tls_files(cfg, host="127.0.0.1")
    assert cert is None and key is None
    assert any("openssl is unavailable" in r.getMessage() for r in caplog.records)


def test_ensure_admin_tls_files_generate_yes_without_openssl_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Brief: generate=yes fails when openssl is missing and files are absent.

    Inputs:
      - keys_dir under tmp_path and openssl unavailable.

    Outputs:
      - RuntimeError is raised.
    """

    monkeypatch.setattr(
        "foghorn.servers.webserver.tls_certs._openssl_available",
        lambda: None,
    )
    cfg = {"generate": "yes", "keys_dir": str(tmp_path / "keys")}
    with pytest.raises(RuntimeError, match="openssl is unavailable"):
        ensure_admin_tls_files(cfg, host="127.0.0.1")


def test_ensure_admin_tls_files_incomplete_pair_errors(tmp_path: Path) -> None:
    """Brief: one existing file and one missing is rejected.

    Inputs:
      - cert exists, key missing, generate=maybe.

    Outputs:
      - ValueError mentioning incomplete TLS files.
    """

    cert = tmp_path / "only.pem"
    key = tmp_path / "only.key"
    cert.write_text("CERT", encoding="utf-8")
    cfg = {
        "generate": "maybe",
        "cert_file": str(cert),
        "key_file": str(key),
    }
    with pytest.raises(ValueError, match="incomplete"):
        ensure_admin_tls_files(cfg, host="127.0.0.1")


def test_generate_self_signed_admin_tls_invokes_openssl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog
) -> None:
    """Brief: generator builds an openssl req -x509 command and writes outputs.

    Inputs:
      - tmp_path destinations and a fake subprocess.run.

    Outputs:
      - Command includes -newkey/-nodes and paths; files are written by fake.
    """

    import foghorn.servers.webserver.tls_certs as tls

    cert = tmp_path / "c.pem"
    key = tmp_path / "k.key"
    seen: dict[str, object] = {}

    def fake_run(
        cmd, check=False, capture_output=False, text=False, timeout=None
    ):  # noqa: ANN001
        seen["cmd"] = list(cmd)
        Path(cmd[cmd.index("-out") + 1]).write_text("CERT", encoding="utf-8")
        Path(cmd[cmd.index("-keyout") + 1]).write_text("KEY", encoding="utf-8")
        return type("R", (), {"returncode": 0, "stderr": "", "stdout": ""})()

    monkeypatch.setattr(tls.subprocess, "run", fake_run)
    with caplog.at_level("WARNING", logger="foghorn.webserver"):
        generate_self_signed_admin_tls(
            cert_file=str(cert),
            key_file=str(key),
            host="app.local",
            days=30,
            openssl_bin="/bin/openssl",
        )
    cmd = seen["cmd"]
    assert cmd[0] == "/bin/openssl"
    assert "req" in cmd
    assert "-x509" in cmd
    assert str(cert) in cmd
    assert str(key) in cmd
    assert cert.is_file() and key.is_file()
    warn_msgs = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("make ssl-cert" in m for m in warn_msgs)
    assert any("make ssl-cert-pem" in m for m in warn_msgs)
    assert any("docs/open-ssl-make-easy.md" in m for m in warn_msgs)


def test_start_webserver_generate_maybe_enables_tls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Brief: start_webserver uses generated certs when generate=maybe.

    Inputs:
      - Dummy uvicorn and fake ensure path via real ensure with stubbed openssl gen.

    Outputs:
      - Dummy Config receives ssl_certfile/ssl_keyfile.
    """

    import sys
    import time
    import types

    from foghorn.servers.webserver import RingBuffer, WebServerHandle, start_webserver

    keys = tmp_path / "keys"

    def fake_generate(
        *,
        cert_file: str,
        key_file: str,
        host: str = "localhost",
        days: int = 3650,
        openssl_bin: str | None = None,
    ) -> None:
        Path(cert_file).parent.mkdir(parents=True, exist_ok=True)
        Path(cert_file).write_text("CERT", encoding="utf-8")
        Path(key_file).write_text("KEY", encoding="utf-8")

    monkeypatch.setattr(
        "foghorn.servers.webserver.tls_certs.generate_self_signed_admin_tls",
        fake_generate,
    )
    monkeypatch.setattr(
        "foghorn.servers.webserver.tls_certs._openssl_available",
        lambda: "/usr/bin/openssl",
    )

    state: dict[str, object] = {}

    class DummyConfig:
        def __init__(
            self, app, host, port, log_level, **kwargs
        ):  # noqa: ANN001, ANN003
            self.app = app
            self.host = host
            self.port = port
            self.log_level = log_level
            self.kwargs = kwargs
            self.ssl_certfile = kwargs.get("ssl_certfile")
            self.ssl_keyfile = kwargs.get("ssl_keyfile")

    class DummyServer:
        def __init__(self, config):  # noqa: ANN001
            state["config"] = config

        def run(self) -> None:
            state["ran"] = True

    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        types.SimpleNamespace(Config=DummyConfig, Server=DummyServer),
    )

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 0,
                "generate": "maybe",
                "keys_dir": str(keys),
            }
        }
    }
    handle = start_webserver(stats=None, config=cfg, log_buffer=RingBuffer())
    assert isinstance(handle, WebServerHandle)
    time.sleep(0.05)
    cfg_obj = state.get("config")
    assert isinstance(cfg_obj, DummyConfig)
    assert cfg_obj.ssl_certfile and Path(str(cfg_obj.ssl_certfile)).is_file()
    assert cfg_obj.ssl_keyfile and Path(str(cfg_obj.ssl_keyfile)).is_file()


def test_tls_path_allowlist_rejects_escape(tmp_path: Path) -> None:
    """Brief: cert/key outside the config directory are rejected when config_path is set.

    Inputs:
      - tmp_path config file and paths under /etc.

    Outputs:
      - ValueError from ensure_admin_tls_files.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be under config directory"):
        ensure_admin_tls_files(
            {
                "generate": "no",
                "cert_file": "/etc/ssl/cert.pem",
                "key_file": "/etc/ssl/key.pem",
            },
            config_path=str(cfg_path),
        )


def test_tls_path_allowlist_accepts_under_config_dir(tmp_path: Path) -> None:
    """Brief: cert/key under the config directory are accepted.

    Inputs:
      - tmp_path config and keys beneath it.

    Outputs:
      - Paths returned unchanged.
    """

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")
    keys = tmp_path / "keys"
    keys.mkdir()
    cert = keys / "a.pem"
    key = keys / "a.key"
    cert.write_text("C", encoding="utf-8")
    key.write_text("K", encoding="utf-8")
    out = ensure_admin_tls_files(
        {
            "generate": "no",
            "cert_file": str(cert),
            "key_file": str(key),
        },
        config_path=str(cfg_path),
    )
    assert out == (str(cert), str(key))


def test_enable_admin_false_hides_reload_restart() -> None:
    """Brief: enable_admin=false removes reload/restart control-plane routes.

    Inputs:
      - create_app with enable_api=true and enable_admin=false.

    Outputs:
      - /api/v1/health is 200; /api/v1/reload and /api/v1/restart are not found.
    """

    try:
        from fastapi.testclient import TestClient
    except ModuleNotFoundError:  # pragma: no cover
        pytest.skip("fastapi not installed")

    from foghorn.servers.webserver import RingBuffer, create_app

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "enable_api": True,
                "enable_admin": False,
                "auth": {"mode": "none"},
            }
        }
    }
    app = create_app(stats=None, config=cfg, log_buffer=RingBuffer())
    client = TestClient(app)
    assert client.get("/api/v1/health").status_code == 200
    # Unregistered routes yield 404 (or 405 if a catch-all matches); either means
    # the control-plane handler is not exposed.
    assert client.post("/api/v1/reload").status_code in {404, 405}
    assert client.post("/api/v1/restart", json={}).status_code in {404, 405}
    assert client.get("/api/v1/admin/status").status_code == 404


def test_start_webserver_refuses_public_api_without_auth_even_with_tls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog
) -> None:
    """Brief: TLS does not bypass fail-closed public bind without auth.

    Inputs:
      - Public host, enable_api=true, auth.mode=none, cert/key present.

    Outputs:
      - start_webserver returns None with refuse error.
    """

    import sys
    import types

    from foghorn.servers.webserver import RingBuffer, start_webserver

    cert = tmp_path / "admin.pem"
    key = tmp_path / "admin.key"
    cert.write_text("CERT", encoding="utf-8")
    key.write_text("KEY", encoding="utf-8")
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("server: {}\n", encoding="utf-8")

    class DummyConfig:
        def __init__(self, *args, **kwargs):  # noqa: ANN002, ANN003
            pass

    class DummyServer:
        def __init__(self, config):  # noqa: ANN001
            self.config = config

        def run(self) -> None:
            return None

    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        types.SimpleNamespace(Config=DummyConfig, Server=DummyServer),
    )

    cfg = {
        "server": {
            "http": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 0,
                "enable_api": True,
                "auth": {"mode": "none"},
                "cert_file": str(cert),
                "key_file": str(key),
            }
        }
    }
    with caplog.at_level("ERROR", logger="foghorn.webserver"):
        handle = start_webserver(
            stats=None,
            config=cfg,
            log_buffer=RingBuffer(),
            config_path=str(cfg_path),
        )
    assert handle is None
    assert any(
        "Refusing to start admin webserver" in r.getMessage() for r in caplog.records
    )
