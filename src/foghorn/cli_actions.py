"""CLI action handlers for the foghorn command-based interface.

Brief:
  Implements non-serve actions dispatched from foghorn.main:
    - init: create default config and directory layout
    - status: report process/PID health
    - config validate|show: schema-check or dump effective config
    - service install|uninstall: systemd unit management
    - reload: signal a running foghorn process via its PID file

  Also provides PID-file helpers used by the serve path.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import platform
import re
import signal
import sys
from pathlib import Path
from typing import Any

import yaml

from foghorn.config.config_dump import (
    build_effective_config_for_display,
    dump_config_text,
)
from foghorn.config.config_parser import parse_config_file, parse_config_variables
from foghorn.config.config_schema import validate_config
from foghorn.stats.meta import FOGHORN_VERSION

logger = logging.getLogger("foghorn.cli")

_DEFAULT_CONFIG_NAME = "config.yaml"
_CONFIG_SUBCOMMANDS = frozenset({"validate", "show"})
_SERVICE_SUBCOMMANDS = frozenset({"install", "uninstall"})
_FALLBACK_UPSTREAM_HOST = "dns.example"
_RESOLV_CONF_PATHS = (
    "/etc/resolv.conf",
    "/var/run/resolv.conf",
    "/run/systemd/resolve/resolv.conf",
)


def _is_loopback_nameserver(host: str) -> bool:
    """Brief: Return True when host is a loopback address.

    Inputs:
      - host: Nameserver host string (IP or name).

    Outputs:
      - bool: True for loopback IPs (e.g. 127.0.0.1, ::1).
    """

    try:
        return bool(ipaddress.ip_address(str(host).strip()).is_loopback)
    except ValueError:
        return str(host).strip().lower() in {"localhost", "localhost."}


def _normalize_nameserver_host(raw: str) -> str | None:
    """Brief: Normalize a nameserver token from OS config.

    Inputs:
      - raw: Raw nameserver string (may include zone id or brackets).

    Outputs:
      - str | None: Clean host suitable for upstreams.endpoints[].host,
        or None when empty/invalid/loopback.
    """

    host = str(raw or "").strip()
    if not host:
        return None
    # Drop IPv6 zone id (fe80::1%eth0) and brackets ([2001:db8::1]).
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    if "%" in host:
        host = host.split("%", 1)[0].strip()
    if not host or _is_loopback_nameserver(host):
        return None
    return host


def _nameservers_from_resolv_conf(path: str | Path) -> list[str]:
    """Brief: Parse nameserver entries from a resolv.conf-style file.

    Inputs:
      - path: Filesystem path to resolv.conf.

    Outputs:
      - list[str]: Ordered unique non-loopback nameserver hosts.
    """

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    found: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        parts = stripped.split()
        if len(parts) < 2 or parts[0].lower() != "nameserver":
            continue
        host = _normalize_nameserver_host(parts[1])
        if host is None or host in seen:
            continue
        seen.add(host)
        found.append(host)
    return found


def _nameservers_from_macos_scutil() -> list[str]:
    """Brief: Read DNS servers from macOS `scutil --dns`.

    Inputs:
      - None.

    Outputs:
      - list[str]: Ordered unique non-loopback nameserver hosts.
    """

    if platform.system() != "Darwin":
        return []
    try:
        import subprocess

        completed = subprocess.run(
            ["scutil", "--dns"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3.0,
        )
    except OSError:
        return []
    except Exception:
        # Includes subprocess.TimeoutExpired without requiring the name at import time.
        return []
    if completed.returncode != 0 or not completed.stdout:
        return []

    found: list[str] = []
    seen: set[str] = set()
    # Example line: "  nameserver[0] : 8.8.8.8"
    pattern = re.compile(r"nameserver\[\d+\]\s*:\s*(\S+)", re.IGNORECASE)
    for match in pattern.finditer(completed.stdout):
        host = _normalize_nameserver_host(match.group(1))
        if host is None or host in seen:
            continue
        seen.add(host)
        found.append(host)
    return found


def _nameservers_from_windows() -> list[str]:
    """Brief: Read DNS servers from Windows IP helper FIXED_INFO.

    Inputs:
      - None.

    Outputs:
      - list[str]: Ordered unique non-loopback nameserver hosts.
    """

    if platform.system() != "Windows" and sys.platform != "win32":
        return []
    try:
        import ctypes
        from ctypes import POINTER, Structure, byref, c_char, c_ulong, sizeof, windll
    except Exception:
        return []

    class IP_ADDR_STRING(Structure):
        pass

    IP_ADDR_STRING._fields_ = [
        ("Next", POINTER(IP_ADDR_STRING)),
        ("IpAddress", c_char * 16),
        ("IpMask", c_char * 16),
        ("Context", c_ulong),
    ]

    class FIXED_INFO_W(Structure):
        _fields_ = [
            ("HostName", c_char * 132),
            ("DomainName", c_char * 132),
            ("CurrentDnsServer", POINTER(IP_ADDR_STRING)),
            ("DnsServerList", IP_ADDR_STRING),
            ("NodeType", c_ulong),
            ("ScopeId", c_char * 260),
            ("EnableRouting", c_ulong),
            ("EnableProxy", c_ulong),
            ("EnableDns", c_ulong),
        ]

    try:
        iphlpapi = windll.iphlpapi
        buflen = c_ulong(sizeof(FIXED_INFO_W))
        buf = ctypes.create_string_buffer(buflen.value)
        ret = iphlpapi.GetNetworkParams(buf, byref(buflen))
        if ret == 111:  # ERROR_BUFFER_OVERFLOW
            buf = ctypes.create_string_buffer(buflen.value)
            ret = iphlpapi.GetNetworkParams(buf, byref(buflen))
        if ret != 0:
            return []
        info = ctypes.cast(buf, POINTER(FIXED_INFO_W)).contents
        found: list[str] = []
        seen: set[str] = set()
        node = ctypes.pointer(info.DnsServerList)
        while node:
            raw = node.contents.IpAddress
            try:
                text = raw.value.decode("ascii", errors="ignore").strip("\x00").strip()
            except Exception:
                text = ""
            host = _normalize_nameserver_host(text)
            if host is not None and host not in seen:
                seen.add(host)
                found.append(host)
            nxt = node.contents.Next
            if not nxt:
                break
            node = nxt
        return found
    except Exception:
        logger.debug("Windows DNS server discovery failed", exc_info=True)
        return []


def discover_system_nameservers() -> list[str]:
    """Brief: Discover configured system DNS nameservers for this host.

    Inputs:
      - None.

    Outputs:
      - list[str]: Ordered unique non-loopback nameserver hosts.

    Notes:
      - Linux/BSD: /etc/resolv.conf (+ common alternate paths).
      - macOS: scutil --dns, then resolv.conf.
      - Windows: IP Helper GetNetworkParams DNS server list.
      - Loopback addresses are skipped to avoid init creating a forward loop
        when the local stub already points at 127.0.0.1.
    """

    found: list[str] = []
    seen: set[str] = set()

    def _extend(hosts: list[str]) -> None:
        for host in hosts:
            if host in seen:
                continue
            seen.add(host)
            found.append(host)

    system = platform.system()
    if system == "Darwin":
        _extend(_nameservers_from_macos_scutil())
    if system == "Windows" or sys.platform == "win32":
        _extend(_nameservers_from_windows())

    if os.name == "posix":
        for path in _RESOLV_CONF_PATHS:
            _extend(_nameservers_from_resolv_conf(path))
            if found:
                break

    return found


def build_default_config_yaml(
    *,
    nameservers: list[str] | None = None,
) -> str:
    """Brief: Build the default YAML written by `foghorn init`.

    Inputs:
      - nameservers: Optional explicit upstream hosts. When None, discovers
        system nameservers; falls back to dns.example when none found.

    Outputs:
      - str: YAML config text (including trailing newline).

    Example:
      >>> yaml = build_default_config_yaml(nameservers=["8.8.8.8"])
      >>> "host: 8.8.8.8" in yaml
      True
    """

    if nameservers is None:
        nameservers = discover_system_nameservers()
    clean: list[str] = []
    seen: set[str] = set()
    for raw in nameservers or []:
        host = _normalize_nameserver_host(str(raw))
        if host is None or host in seen:
            continue
        seen.add(host)
        clean.append(host)

    if clean:
        source_note = (
            "# upstreams seeded from system DNS "
            "(/etc/resolv.conf, scutil, or Windows DNS)\n"
        )
        hosts = clean
    else:
        source_note = (
            "# no system DNS nameservers detected; placeholder upstream\n"
            "# replace dns.example with your real recursive resolver\n"
        )
        hosts = [_FALLBACK_UPSTREAM_HOST]

    endpoint_lines: list[str] = []
    for host in hosts:
        endpoint_lines.append(f"    - host: {host}")
        endpoint_lines.append("      port: 53")
    endpoints_block = "\n".join(endpoint_lines)

    return (
        "# Foghorn default configuration (generated by `foghorn init`)\n"
        f"{source_note}"
        "upstreams:\n"
        "  endpoints:\n"
        f"{endpoints_block}\n"
        "server:\n"
        "  listen:\n"
        "    udp:\n"
        "      enabled: true\n"
        "      host: localhost\n"
        "      port: 5353\n"
        "    tcp:\n"
        "      enabled: false\n"
        "  resolver:\n"
        "    mode: forward\n"
        "    timeout_ms: 2000\n"
        "  http:\n"
        "    enabled: false\n"
        "logging:\n"
        "  python:\n"
        "    level: info\n"
        "    stderr: true\n"
    )


def resolve_pid_file_path(config_path: str | None = None) -> str:
    """Brief: Resolve the PID file path for this config/instance.

    Inputs:
      - config_path: Optional path to the YAML config (used for a stable default).

    Outputs:
      - str: Absolute PID file path.

    Notes:
      - FOGHORN_PID_FILE overrides everything.
      - Otherwise prefers /run/user/<uid>/foghorn.pid, then /tmp/foghorn.pid,
        with a config-basename suffix when config_path is provided.
    """

    env_path = os.environ.get("FOGHORN_PID_FILE")
    if env_path and str(env_path).strip():
        return os.path.abspath(str(env_path).strip())

    suffix = ""
    if config_path:
        base = Path(str(config_path)).resolve().name
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in base)
        if safe and safe != _DEFAULT_CONFIG_NAME:
            suffix = f"-{safe}"

    uid = os.getuid()
    run_user = f"/run/user/{uid}"
    if os.path.isdir(run_user) and os.access(run_user, os.W_OK):
        return os.path.join(run_user, f"foghorn{suffix}.pid")
    return os.path.join("/tmp", f"foghorn{suffix}.pid")


def write_pid_file(pid_path: str, *, pid: int | None = None) -> None:
    """Brief: Write the current process PID to pid_path.

    Inputs:
      - pid_path: Destination file path.
      - pid: Optional PID override; defaults to os.getpid().

    Outputs:
      - None.
    """

    path = Path(pid_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    target_pid = int(pid if pid is not None else os.getpid())
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(f"{target_pid}\n", encoding="utf-8")
    os.replace(str(tmp_path), str(path))
    logger.debug("Wrote PID file %s (pid=%d)", path, target_pid)


def remove_pid_file(pid_path: str, *, pid: int | None = None) -> None:
    """Brief: Remove pid_path when it still refers to this process.

    Inputs:
      - pid_path: PID file path.
      - pid: Expected PID; defaults to os.getpid(). Only remove when matching.

    Outputs:
      - None.
    """

    path = Path(pid_path)
    if not path.is_file():
        return
    expected = int(pid if pid is not None else os.getpid())
    try:
        text = path.read_text(encoding="utf-8").strip()
        file_pid = int(text.split()[0])
    except (OSError, ValueError, IndexError):
        return
    if file_pid != expected:
        return
    try:
        path.unlink()
        logger.debug("Removed PID file %s", path)
    except OSError:
        logger.debug("Could not remove PID file %s", path, exc_info=True)


def read_pid_file(pid_path: str) -> int | None:
    """Brief: Read a PID from pid_path.

    Inputs:
      - pid_path: PID file path.

    Outputs:
      - int | None: PID when readable and valid, else None.
    """

    try:
        text = Path(pid_path).read_text(encoding="utf-8").strip()
        if not text:
            return None
        return int(text.split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _cli_var_list(args: Any) -> list[str]:
    """Brief: Extract -v/--var list from argparse namespace.

    Inputs:
      - args: argparse.Namespace.

    Outputs:
      - list[str]: CLI variable assignments.
    """

    return list(getattr(args, "var", None) or [])


def _unknown_keys_policy(args: Any) -> str:
    """Brief: Extract unknown-keys policy from argparse namespace.

    Inputs:
      - args: argparse.Namespace.

    Outputs:
      - str: ignore|warn|error.
    """

    return str(getattr(args, "config_extras", "error") or "error")


def _skip_schema(args: Any) -> bool:
    """Brief: Whether schema validation should be skipped.

    Inputs:
      - args: argparse.Namespace.

    Outputs:
      - bool.
    """

    return bool(getattr(args, "skip_schema_validation", False))


def _load_config_for_cli(args: Any) -> dict[str, Any]:
    """Brief: Parse and validate config using CLI flags.

    Inputs:
      - args: argparse.Namespace with config/var/config_extras fields.

    Outputs:
      - dict: Parsed configuration.

    Raises:
      - ValueError: On parse or validation failure.
    """

    return parse_config_file(
        str(getattr(args, "config", _DEFAULT_CONFIG_NAME) or _DEFAULT_CONFIG_NAME),
        cli_vars=_cli_var_list(args),
        unknown_keys=_unknown_keys_policy(args),
        skip_schema_validation=_skip_schema(args),
    )


def cmd_init(args: Any) -> int:
    """Brief: Create a default config file and supporting directories.

    Inputs:
      - args: argparse.Namespace (uses args.config as destination path).

    Outputs:
      - int: Exit code (0 success, 1 failure).

    Notes:
      - Seeds upstreams.endpoints from system DNS nameservers when available.
    """

    config_path = Path(
        str(getattr(args, "config", _DEFAULT_CONFIG_NAME) or _DEFAULT_CONFIG_NAME)
    )
    try:
        config_path = (
            config_path if config_path.is_absolute() else Path.cwd() / config_path
        )
        config_path.parent.mkdir(parents=True, exist_ok=True)

        data_dir = config_path.parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "cache").mkdir(exist_ok=True)
        (data_dir / "logs").mkdir(exist_ok=True)

        if config_path.exists():
            print(f"Config already exists: {config_path}")
            print(f"Data directory ready: {data_dir}")
            return 0

        nameservers = discover_system_nameservers()
        config_text = build_default_config_yaml(nameservers=nameservers)
        config_path.write_text(config_text, encoding="utf-8")
        print(f"Wrote default config: {config_path}")
        if nameservers:
            print("Seeded upstreams from system DNS: " + ", ".join(nameservers))
        else:
            print(
                "No system DNS nameservers found; wrote placeholder upstream "
                f"{_FALLBACK_UPSTREAM_HOST}"
            )
        print(f"Created data directory: {data_dir}")
        print("Next: foghorn serve " + str(config_path))
        return 0
    except OSError as exc:
        print(f"foghorn init failed: {exc}", file=sys.stderr)
        return 1


def cmd_status(args: Any) -> int:
    """Brief: Report whether a foghorn process appears to be running.

    Inputs:
      - args: argparse.Namespace (config path selects the PID file).

    Outputs:
      - int: 0 when running/healthy, 1 when not running or check failed.

    Notes:
      - Uses the PID file plus os.kill(pid, 0) liveness probe.
      - When config loads and server.http is enabled, also probes /health.
      - HTTPS health probes deliberately skip TLS certificate validation so
        self-signed/admin certs do not fail the check.
    """

    config_path = str(
        getattr(args, "config", _DEFAULT_CONFIG_NAME) or _DEFAULT_CONFIG_NAME
    )
    pid_path = resolve_pid_file_path(config_path)
    pid = read_pid_file(pid_path)

    print(f"config: {os.path.abspath(config_path)}")
    print(f"pid_file: {pid_path}")

    if pid is None:
        print("status: not running (no PID file)")
        return 1

    print(f"pid: {pid}")
    try:
        os.kill(pid, 0)
        alive = True
    except ProcessLookupError:
        alive = False
    except PermissionError:
        # Process exists but we cannot signal it; treat as running.
        alive = True
    except OSError as exc:
        print(f"status: error probing pid {pid}: {exc}")
        return 1

    if not alive:
        print("status: not running (stale PID file)")
        return 1

    print("status: running")

    # Best-effort admin health probe when config is available.
    try:
        cfg = _load_config_for_cli(args)
    except (OSError, ValueError) as exc:
        print(f"health: skipped (config load failed: {exc})")
        return 0

    server_cfg = cfg.get("server") if isinstance(cfg, dict) else None
    http_cfg: dict[str, Any] = {}
    if isinstance(server_cfg, dict) and isinstance(server_cfg.get("http"), dict):
        http_cfg = server_cfg["http"]
    elif isinstance(cfg.get("http"), dict):
        http_cfg = cfg["http"]
    elif isinstance(cfg.get("webserver"), dict):
        http_cfg = cfg["webserver"]

    enabled = http_cfg.get("enabled")
    has_http = bool(http_cfg)
    web_enabled = bool(enabled) if enabled is not None else has_http
    if not web_enabled:
        print("health: admin http disabled")
        return 0

    host = str(http_cfg.get("host") or "localhost")
    # Default matches server.http.port schema default (5380), not legacy 8053.
    port = int(http_cfg.get("port") or 5380)
    scheme = "https" if http_cfg.get("tls") or http_cfg.get("cert_file") else "http"
    url = f"{scheme}://{host}:{port}/health"
    try:
        import ssl
        import urllib.error
        import urllib.request

        # Local admin health checks should not fail on self-signed or expired
        # certs; connectivity + /health payload is what matters.
        open_kwargs: dict[str, Any] = {"timeout": 2.0}
        if scheme == "https":
            open_kwargs["context"] = ssl._create_unverified_context()

        with urllib.request.urlopen(url, **open_kwargs) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            print(f"health: ok ({url}) {body.strip()}")
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"health: unreachable ({url}): {exc}")
        # Process is running; health endpoint failure is informational.
    return 0


def cmd_config(args: Any) -> int:
    """Brief: Handle `foghorn config validate|show`.

    Inputs:
      - args: argparse.Namespace with subcommand and config path.

    Outputs:
      - int: Exit code.

    Notes:
      - validate: exit 1 only on parse/IO failure; schema validation failure
        prints a failure message but returns 0.
      - show: dumps effective interpolated config as YAML.
    """

    sub = str(getattr(args, "subcommand", "") or "").strip().lower()
    if sub not in _CONFIG_SUBCOMMANDS:
        print(
            "foghorn config requires a subcommand: validate | show",
            file=sys.stderr,
        )
        return 2

    config_path = str(
        getattr(args, "config", _DEFAULT_CONFIG_NAME) or _DEFAULT_CONFIG_NAME
    )

    if sub == "validate":
        return _cmd_config_validate(args, config_path=config_path)
    return _cmd_config_show(args, config_path=config_path)


def _cmd_config_validate(args: Any, *, config_path: str) -> int:
    """Brief: Validate config YAML and schema; print success/failure.

    Inputs:
      - args: argparse.Namespace for CLI vars/policies.
      - config_path: Path to YAML config.

    Outputs:
      - int: 1 on parse/IO failure; 0 on schema success or schema failure.
    """

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(
            f"config validate: FAILED (file not found: {config_path})", file=sys.stderr
        )
        return 1
    except OSError as exc:
        print(
            f"config validate: FAILED (cannot read {config_path}: {exc})",
            file=sys.stderr,
        )
        return 1
    except yaml.YAMLError as exc:
        print(f"config validate: FAILED (YAML error: {exc})", file=sys.stderr)
        return 1

    if not isinstance(cfg, dict):
        print("config validate: FAILED (root must be a mapping)", file=sys.stderr)
        return 1

    try:
        parse_config_variables(cfg, cli_vars=_cli_var_list(args))
    except ValueError as exc:
        print(f"config validate: FAILED (variables: {exc})", file=sys.stderr)
        return 1

    if _skip_schema(args):
        print(f"config validate: OK (schema skipped) path={config_path}")
        return 0

    try:
        validate_config(
            cfg,
            config_path=config_path,
            unknown_keys=_unknown_keys_policy(args),
            skip_schema_validation=False,
        )
    except ValueError as exc:
        # Schema/validation failure: report but do not exit 1.
        print(f"config validate: FAILED ({exc})")
        return 0

    print(f"config validate: OK path={config_path}")
    return 0


def _cmd_config_show(args: Any, *, config_path: str) -> int:
    """Brief: Load config with interpolation and print effective YAML/JSON.

    Inputs:
      - args: argparse.Namespace.
      - config_path: Path to YAML config.

    Outputs:
      - int: 0 on success, 1 on failure.
    """

    try:
        cfg = parse_config_file(
            config_path,
            cli_vars=_cli_var_list(args),
            unknown_keys=_unknown_keys_policy(args),
            skip_schema_validation=_skip_schema(args),
        )
    except ValueError as exc:
        print(f"config show: failed: {exc}", file=sys.stderr)
        return 1

    effective = build_effective_config_for_display(cfg)
    text = dump_config_text(effective, fmt="yaml")
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    return 0


def cmd_service(args: Any) -> int:
    """Brief: Handle `foghorn service install|uninstall` for systemd.

    Inputs:
      - args: argparse.Namespace with subcommand and config path.

    Outputs:
      - int: Exit code.
    """

    sub = str(getattr(args, "subcommand", "") or "").strip().lower()
    if sub not in _SERVICE_SUBCOMMANDS:
        print(
            "foghorn service requires a subcommand: install | uninstall",
            file=sys.stderr,
        )
        return 2

    if sub == "install":
        return _cmd_service_install(args)
    return _cmd_service_uninstall(args)


def _systemd_unit_path() -> Path:
    """Brief: Resolve systemd unit file path (system or user).

    Inputs:
      - None.

    Outputs:
      - Path: Unit file destination.
    """

    env = os.environ.get("FOGHORN_SYSTEMD_UNIT")
    if env and str(env).strip():
        return Path(str(env).strip())
    if os.geteuid() == 0:
        return Path("/etc/systemd/system/foghorn.service")
    # User unit
    base = Path.home() / ".config" / "systemd" / "user"
    return base / "foghorn.service"


def _resolve_foghorn_executable() -> str:
    """Brief: Best-effort path to the foghorn entrypoint.

    Inputs:
      - None.

    Outputs:
      - str: Absolute executable path or sys.executable -m form.
    """

    # Prefer the console_script when available on PATH via argv[0].
    argv0 = str(sys.argv[0] or "")
    if argv0 and not argv0.endswith(".py") and os.path.isfile(argv0):
        return os.path.abspath(argv0)
    which = None
    try:
        import shutil

        which = shutil.which("foghorn")
    except OSError:
        which = None
    if which:
        return which
    return f"{sys.executable} -m foghorn.main"


def _cmd_service_install(args: Any) -> int:
    """Brief: Write and enable a systemd unit for foghorn serve.

    Inputs:
      - args: argparse.Namespace.

    Outputs:
      - int: Exit code.
    """

    config_path = os.path.abspath(
        str(getattr(args, "config", _DEFAULT_CONFIG_NAME) or _DEFAULT_CONFIG_NAME)
    )
    if not os.path.isfile(config_path):
        print(
            f"service install: config not found: {config_path}",
            file=sys.stderr,
        )
        return 1

    unit_path = _systemd_unit_path()
    exe = _resolve_foghorn_executable()
    pid_path = resolve_pid_file_path(config_path)
    workdir = str(Path(config_path).parent)

    exec_start = f"{exe} serve {config_path}"

    # User units must not set User=; system units default to root.
    wanted_by = "default.target" if os.geteuid() != 0 else "multi-user.target"

    unit = f"""\
[Unit]
Description=Foghorn DNS server
Documentation=https://github.com/zackallison/foghorn
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={workdir}
Environment=FOGHORN_PID_FILE={pid_path}
ExecStart={exec_start}
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure
RestartSec=2
KillMode=mixed
TimeoutStopSec=15

[Install]
WantedBy={wanted_by}
"""
    try:
        unit_path.parent.mkdir(parents=True, exist_ok=True)
        unit_path.write_text(unit, encoding="utf-8")
        print(f"Wrote systemd unit: {unit_path}")
    except OSError as exc:
        print(f"service install: failed to write unit: {exc}", file=sys.stderr)
        return 1

    # Best-effort enable/daemon-reload; do not fail hard if systemctl missing.
    scope = "--user" if os.geteuid() != 0 else ""
    _run_systemctl(["daemon-reload"], scope=scope)
    _run_systemctl(["enable", "--now", "foghorn.service"], scope=scope)
    print(
        "service install: unit written"
        + (
            " and enable attempted"
            if _systemctl_available()
            else " (systemctl not available)"
        )
    )
    print(f"PID file: {pid_path}")
    print(f"Config: {config_path}")
    return 0


def _cmd_service_uninstall(args: Any) -> int:
    """Brief: Stop/disable and remove the foghorn systemd unit.

    Inputs:
      - args: argparse.Namespace (config unused except for messaging).

    Outputs:
      - int: Exit code.
    """

    unit_path = _systemd_unit_path()
    scope = "--user" if os.geteuid() != 0 else ""
    _run_systemctl(["disable", "--now", "foghorn.service"], scope=scope)

    if unit_path.is_file():
        try:
            unit_path.unlink()
            print(f"Removed systemd unit: {unit_path}")
        except OSError as exc:
            print(f"service uninstall: failed to remove unit: {exc}", file=sys.stderr)
            return 1
    else:
        print(f"No unit file at {unit_path}")

    _run_systemctl(["daemon-reload"], scope=scope)
    print("service uninstall: done")
    return 0


def _systemctl_available() -> bool:
    """Brief: Return True when systemctl is on PATH.

    Inputs:
      - None.

    Outputs:
      - bool.
    """

    try:
        import shutil

        return shutil.which("systemctl") is not None
    except OSError:
        return False


def _run_systemctl(argv: list[str], *, scope: str = "") -> int:
    """Brief: Best-effort systemctl invocation.

    Inputs:
      - argv: systemctl arguments after the binary name.
      - scope: Optional '--user' for user units.

    Outputs:
      - int: subprocess return code, or -1 when systemctl is unavailable.
    """

    if not _systemctl_available():
        return -1
    import subprocess

    cmd = ["systemctl"]
    if scope:
        cmd.append(scope)
    cmd.extend(argv)
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            logger.debug(
                "systemctl %s failed rc=%s stderr=%s",
                argv,
                completed.returncode,
                (completed.stderr or "").strip(),
            )
        return int(completed.returncode)
    except OSError as exc:
        logger.debug("systemctl invocation failed: %s", exc)
        return -1


def cmd_reload(args: Any) -> int:
    """Brief: Send SIGUSR1 to the running foghorn process for config reload.

    Inputs:
      - args: argparse.Namespace (config selects PID file).

    Outputs:
      - int: 0 on success, 1 on failure.
    """

    config_path = str(
        getattr(args, "config", _DEFAULT_CONFIG_NAME) or _DEFAULT_CONFIG_NAME
    )
    pid_path = resolve_pid_file_path(config_path)
    pid = read_pid_file(pid_path)
    if pid is None:
        print(f"reload: failed (no PID file at {pid_path})", file=sys.stderr)
        return 1

    try:
        os.kill(pid, signal.SIGUSR1)
    except ProcessLookupError:
        print(f"reload: failed (process {pid} not found)", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(
            f"reload: failed (permission denied for pid {pid}): {exc}", file=sys.stderr
        )
        return 1
    except OSError as exc:
        print(f"reload: failed (pid {pid}): {exc}", file=sys.stderr)
        return 1

    print(f"reload: sent SIGUSR1 to pid {pid} (pid_file={pid_path})")
    return 0


def dispatch_non_serve_action(args: Any) -> int | None:
    """Brief: Dispatch non-serve CLI actions; return None for serve.

    Inputs:
      - args: argparse.Namespace with action field.

    Outputs:
      - int exit code for handled actions, or None when action is serve/unknown
        (caller should handle serve).
    """

    action = str(getattr(args, "action", "") or "").strip().lower()
    if action == "serve":
        return None
    if action == "init":
        return cmd_init(args)
    if action == "status":
        return cmd_status(args)
    if action == "config":
        return cmd_config(args)
    if action == "service":
        return cmd_service(args)
    if action == "reload":
        return cmd_reload(args)
    return None


def format_version_line() -> str:
    """Brief: Return a short version string for CLI banners.

    Inputs:
      - None.

    Outputs:
      - str.
    """

    return f"foghorn {FOGHORN_VERSION}"
