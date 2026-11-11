"""ProxmoxHosts plugin: resolve VM/CT hostnames via the Proxmox VE API.

Brief:
  - Polls one or more Proxmox node API endpoints (any node answers for the
    whole cluster) and builds in-memory A/AAAA/PTR (+ optional TXT) maps.
  - Prefers QEMU guest-agent / LXC interface addresses, with config fallbacks.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin

import requests
from dnslib import AAAA, PTR, QTYPE, RR, TXT, A, DNSHeader, DNSRecord
from pydantic import BaseModel, ConfigDict, Field

from foghorn.plugins.resolve.base import (
    AdminPageSpec,
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

logger = logging.getLogger(__name__)

_DNS_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_IPCONFIG_RE = re.compile(
    r"(?:^|,)\s*ip=([^,/\s]+)(?:/(\d+))?",
    re.IGNORECASE,
)
_IPCONFIG6_RE = re.compile(
    r"(?:^|,)\s*ip6=([^,/\s]+)(?:/(\d+))?",
    re.IGNORECASE,
)


class ProxmoxEndpointConfig(BaseModel):
    """Brief: Per-endpoint Proxmox API connection settings.

    Inputs:
      - url: Base URL, e.g. https://pve1.lan:8006
      - token_id: Full token id USER@REALM!TOKENID (or token name only with user)
      - token_secret: Token secret UUID
      - user / password: Optional ticket-auth fallback when token is absent
      - verify_tls: Verify HTTPS certificates (default True)
      - tls_ca: Optional CA bundle path
      - use_ipv4 / use_ipv6: Optional host IP overrides for all guests
      - ttl: Optional TTL override for this endpoint
      - suffix: Optional DNS suffix override
      - reload_interval_second: Hint used for global poll interval

    Outputs:
      - ProxmoxEndpointConfig instance.
    """

    url: str
    token_id: str | None = None
    token_secret: str | None = None
    user: str | None = None
    password: str | None = None
    verify_tls: bool = True
    tls_ca: str | None = None
    use_ipv4: str | None = None
    use_ipv6: str | None = None
    ttl: int | None = Field(default=None, ge=0)
    suffix: str | None = None
    reload_interval_second: float = Field(default=30.0, ge=0)


class ProxmoxHostsConfig(BaseModel):
    """Brief: Typed configuration for ProxmoxHosts.

    Inputs:
      - endpoints: Proxmox API endpoints (failover order)
      - ttl: Default answer TTL
      - reload_interval_second: Background poll interval
      - status: Guest status allowlist (default: running)
      - include_types: qemu and/or lxc
      - include_templates: When true, publish template guests
      - use_guest_agent: Query QEMU agent for NICs
      - merge_addresses: Merge all address sources instead of first-wins
      - publish_vmid / publish_tags: Extra name aliases
      - discovery / expose_txt_in_additional: TXT inventory controls
      - suffix: Default DNS suffix
      - max_workers: Parallel per-guest fetch concurrency

    Outputs:
      - ProxmoxHostsConfig instance.
    """

    endpoints: list[ProxmoxEndpointConfig] = Field(default_factory=list)
    ttl: int = Field(default=60, ge=0)
    reload_interval_second: float = Field(default=30.0, ge=0)
    status: list[str] = Field(default_factory=lambda: ["running"])
    include_types: list[str] = Field(default_factory=lambda: ["qemu", "lxc"])
    include_templates: bool = False
    use_guest_agent: bool = True
    merge_addresses: bool = False
    publish_vmid: bool = False
    publish_tags: bool = False
    discovery: bool = False
    expose_txt_in_additional: bool = False
    suffix: str | None = None
    max_workers: int = Field(default=4, ge=1, le=32)

    model_config = ConfigDict(extra="allow")


class _PveClient:
    """Brief: Thin Proxmox API client (token or ticket auth).

    Inputs:
      - base_url, auth fields, TLS settings from endpoint config.

    Outputs:
      - JSON helpers via get_json().
    """

    def __init__(
        self,
        *,
        base_url: str,
        token_id: str | None,
        token_secret: str | None,
        user: str | None,
        password: str | None,
        verify: bool | str,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.token_id = (token_id or "").strip() or None
        self.token_secret = (token_secret or "").strip() or None
        self.user = (user or "").strip() or None
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self._session = requests.Session()
        self._ticket: str | None = None
        self._csrf: str | None = None
        self._ticket_expires: float = 0.0

    def close(self) -> None:
        """Brief: Close the underlying HTTP session.

        Inputs:
          - None.
        Outputs:
          - None.
        """

        try:
            self._session.close()
        except Exception:
            return

    def _ensure_ticket(self) -> None:
        """Brief: Obtain or refresh a PVEAuth cookie when using password auth.

        Inputs:
          - None (uses self.user/password).
        Outputs:
          - None; sets ticket headers on the session.
        """

        if self.token_id and self.token_secret:
            return
        if not self.user or self.password is None:
            raise RuntimeError(
                "Proxmox endpoint needs token_id/token_secret or user/password"
            )
        now = time.time()
        if self._ticket and now < self._ticket_expires - 60:
            return
        url = urljoin(self.base_url, "api2/json/access/ticket")
        resp = self._session.post(
            url,
            data={"username": self.user, "password": self.password},
            verify=self.verify,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        payload = resp.json().get("data") or {}
        ticket = payload.get("ticket")
        csrf = payload.get("CSRFPreventionToken")
        if not ticket:
            raise RuntimeError("Proxmox ticket auth returned no ticket")
        self._ticket = str(ticket)
        self._csrf = str(csrf) if csrf else None
        # Tickets last ~2 hours.
        self._ticket_expires = now + 7200.0
        self._session.cookies.set("PVEAuthCookie", self._ticket)

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Brief: GET a Proxmox API path and return the JSON ``data`` field.

        Inputs:
          - path: Absolute or relative path under the API root
            (e.g. ``/api2/json/cluster/resources`` or ``cluster/resources``).
          - params: Optional query parameters.

        Outputs:
          - Parsed ``data`` value from the JSON envelope (may be list/dict/None).

        Raises:
          - requests.HTTPError on non-2xx responses.
        """

        path = str(path or "").lstrip("/")
        if not path.startswith("api2/"):
            path = f"api2/json/{path}"
        url = urljoin(self.base_url, path)

        headers: dict[str, str] = {}
        if self.token_id and self.token_secret:
            headers["Authorization"] = (
                f"PVEAPIToken={self.token_id}={self.token_secret}"
            )
        else:
            self._ensure_ticket()
            if self._csrf:
                headers["CSRFPreventionToken"] = self._csrf

        resp = self._session.get(
            url,
            params=params,
            headers=headers,
            verify=self.verify,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data")


@plugin_aliases("proxmox_hosts", "proxmox-hosts", "proxmox", "pve")
class ProxmoxHosts(BasePlugin):
    """Resolve Proxmox VE guest names via the cluster API.

    Brief:
      - setup() connects to configured endpoints, loads cluster guest inventory,
        and builds forward/reverse maps with a background refresher.
      - pre_resolve() answers matching A/AAAA/PTR/TXT queries.
    """

    setup_provides_dns = True
    setup_requires_dns = True
    _condition_rewarn_interval_seconds = 3600.0

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic config model for this plugin.

        Inputs:
          - None.
        Outputs:
          - ProxmoxHostsConfig class.
        """

        return ProxmoxHostsConfig

    def _ensure_condition_log_state(self) -> None:
        """Brief: Lazily initialize sticky condition-log lock and maps.

        Inputs:
          - None.
        Outputs:
          - None.
        """

        if not hasattr(self, "_condition_log_lock") or self._condition_log_lock is None:
            self._condition_log_lock = threading.Lock()
        if (
            not hasattr(self, "_condition_failed_by_key")
            or self._condition_failed_by_key is None
        ):
            self._condition_failed_by_key = {}
        if (
            not hasattr(self, "_condition_suppressed_by_key")
            or self._condition_suppressed_by_key is None
        ):
            self._condition_suppressed_by_key = {}
        if (
            not hasattr(self, "_condition_last_warned_by_key")
            or self._condition_last_warned_by_key is None
        ):
            self._condition_last_warned_by_key = {}

    def _note_condition_failure(self, key: str, message: str, *args: object) -> None:
        """Brief: Log sticky failures without flooding reload loops.

        Inputs:
          - key: Stable condition id.
          - message: logger.warning template.
          - args: Format args.
        Outputs:
          - None.
        """

        self._ensure_condition_log_state()
        now = time.monotonic()
        interval = float(getattr(self, "_condition_rewarn_interval_seconds", 3600.0))
        with self._condition_log_lock:
            prev_failed = bool(self._condition_failed_by_key.get(key, False))
            last_warned = self._condition_last_warned_by_key.get(key)
            if prev_failed:
                should_rewarn = interval > 0 and (
                    last_warned is None or (now - last_warned) >= interval
                )
                if should_rewarn:
                    suppressed = self._condition_suppressed_by_key.get(key, 0)
                    self._condition_suppressed_by_key[key] = 0
                    self._condition_last_warned_by_key[key] = now
                else:
                    self._condition_suppressed_by_key[key] = (
                        self._condition_suppressed_by_key.get(key, 0) + 1
                    )
                    suppressed = self._condition_suppressed_by_key[key]
            else:
                self._condition_failed_by_key[key] = True
                self._condition_suppressed_by_key[key] = 0
                self._condition_last_warned_by_key[key] = now
                suppressed = 0
                should_rewarn = False

        if not prev_failed:
            logger.warning(message, *args)
            return
        if should_rewarn:
            if suppressed > 0:
                logger.warning(
                    message + " (still failing; suppressed %d repeated warning(s))",
                    *args,
                    suppressed,
                )
            else:
                logger.warning(message + " (still failing)", *args)
            return
        logger.debug(
            "ProxmoxHosts: suppressed repeated condition %s (count=%d): " + message,
            key,
            suppressed,
            *args,
        )

    def _note_condition_ok(
        self,
        key: str,
        recovery_message: str | None = None,
        *args: object,
    ) -> None:
        """Brief: Clear a sticky failure and optionally log recovery.

        Inputs:
          - key: Same id passed to _note_condition_failure.
          - recovery_message: Optional INFO template.
          - args: Format args.
        Outputs:
          - None.
        """

        self._ensure_condition_log_state()
        with self._condition_log_lock:
            was_failed = bool(self._condition_failed_by_key.get(key, False))
            suppressed = int(self._condition_suppressed_by_key.get(key, 0) or 0)
            self._condition_failed_by_key[key] = False
            self._condition_suppressed_by_key[key] = 0
            self._condition_last_warned_by_key.pop(key, None)

        if not was_failed or not recovery_message:
            return
        if suppressed > 0:
            logger.info(
                recovery_message + " (suppressed %d repeated failure warning(s))",
                *args,
                suppressed,
            )
            return
        if args:
            logger.info(recovery_message, *args)
        else:
            logger.info("%s", recovery_message)

    @staticmethod
    def _normalize_suffix(raw: object) -> str:
        """Brief: Normalize a DNS suffix to lowercase dotted labels.

        Inputs:
          - raw: Config value.
        Outputs:
          - Normalized suffix without leading/trailing dots, or empty string.
        """

        text = str(raw or "").strip().strip(".")
        if not text:
            return ""
        parts = [p for p in text.split(".") if p]
        return ".".join(parts).lower() if parts else ""

    @staticmethod
    def _is_valid_dns_label(name: str) -> bool:
        """Brief: Validate a single DNS label for publication.

        Inputs:
          - name: Candidate label without dots.
        Outputs:
          - True when publishable.
        """

        label = str(name or "").strip().strip(".").lower()
        if not label or "." in label or len(label) > 63:
            return False
        return bool(_DNS_LABEL_RE.match(label))

    @staticmethod
    def _sanitize_txt_chunk(text: str, max_bytes: int = 253) -> str:
        """Brief: Remove control characters and clamp TXT UTF-8 size.

        Inputs:
          - text: Raw TXT chunk.
          - max_bytes: Max UTF-8 bytes.
        Outputs:
          - Sanitized string.
        """

        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", str(text or ""))
        encoded = cleaned.encode("utf-8")[:max_bytes]
        return encoded.decode("utf-8", errors="ignore")

    @staticmethod
    @staticmethod
    def _is_usable_ip(ip_text: str) -> bool:
        """Brief: Filter loopback, link-local, and invalid addresses.

        Inputs:
          - ip_text: Address string.
        Outputs:
          - True when the address should be published.
        """

        try:
            ip = ipaddress.ip_address(str(ip_text).strip())
        except ValueError:
            return False
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return False
        return True

    @staticmethod
    def _resolve_tls_path(path: str) -> str:
        """Brief: Resolve a TLS CA path relative to config dir / CWD.

        Inputs:
          - path: Absolute or relative CA path.
        Outputs:
          - Resolved filesystem path.
        """

        import os

        from foghorn.servers.webserver.tls_certs import resolve_tls_path

        config_path = None
        try:
            from foghorn.runtime_config import get_config_path

            config_path = get_config_path()
        except Exception:
            config_path = None
        if not config_path:
            for candidate in (
                os.environ.get("FOGHORN_CONFIG"),
                "config/config.yaml",
                "/foghorn/config/config.yaml",
            ):
                if candidate and os.path.isfile(candidate):
                    config_path = candidate
                    break
        return resolve_tls_path(path, config_path=config_path)

    def setup(self) -> None:
        """Brief: Initialize ProxmoxHosts and build the initial guest mapping.

        Inputs:
          - Plugin config keys (endpoints, ttl, suffix, status, …).
        Outputs:
          - None; populates maps and starts the poller when interval > 0.
        """

        self._ttl = int(self.config.get("ttl", 60))
        self._condition_log_lock = threading.Lock()
        self._condition_failed_by_key: dict[str, bool] = {}
        self._condition_suppressed_by_key: dict[str, int] = {}
        self._condition_last_warned_by_key: dict[str, float] = {}

        self._suffix = self._normalize_suffix(self.config.get("suffix"))
        self._discovery = bool(self.config.get("discovery", False))
        self._expose_txt_in_additional = bool(
            self.config.get("expose_txt_in_additional", False)
        )
        self._use_guest_agent = bool(self.config.get("use_guest_agent", True))
        self._merge_addresses = bool(self.config.get("merge_addresses", False))
        self._publish_vmid = bool(self.config.get("publish_vmid", False))
        self._publish_tags = bool(self.config.get("publish_tags", False))
        self._include_templates = bool(self.config.get("include_templates", False))
        try:
            self._max_workers = max(1, min(32, int(self.config.get("max_workers", 4))))
        except (TypeError, ValueError):
            self._max_workers = 4

        raw_status = self.config.get("status")
        if raw_status is None:
            status_items = ["running"]
        elif isinstance(raw_status, str):
            status_items = [raw_status]
        elif isinstance(raw_status, list):
            status_items = [str(x) for x in raw_status]
        else:
            status_items = [str(raw_status)]
        self._status_allowlist = [
            s.strip().lower() for s in status_items if str(s).strip()
        ] or ["running"]

        raw_types = self.config.get("include_types")
        if raw_types is None:
            type_items = ["qemu", "lxc"]
        elif isinstance(raw_types, str):
            type_items = [raw_types]
        elif isinstance(raw_types, list):
            type_items = [str(x) for x in raw_types]
        else:
            type_items = [str(raw_types)]
        allowed_types = {"qemu", "lxc", "openvz"}
        include_types: list[str] = []
        for item in type_items:
            key = str(item).strip().lower()
            if key in ("vm", "kvm"):
                key = "qemu"
            if key in ("ct", "container"):
                key = "lxc"
            if key not in allowed_types:
                logger.warning(
                    "ProxmoxHosts: ignoring unsupported include_types %r", item
                )
                continue
            if key not in include_types:
                include_types.append(key)
        self._include_types = include_types or ["qemu", "lxc"]

        raw_endpoints = self.config.get("endpoints") or []
        endpoints_cfg: list[dict[str, object]] = []
        for item in raw_endpoints:
            if not isinstance(item, dict):
                logger.warning("ProxmoxHosts: ignoring non-mapping endpoint %r", item)
                continue
            url_raw = str(item.get("url") or "").strip()
            if not url_raw:
                logger.warning("ProxmoxHosts: endpoint missing url; skipping %r", item)
                continue
            if not url_raw.startswith(("http://", "https://")):
                url_raw = "https://" + url_raw

            token_id = str(item.get("token_id") or "").strip() or None
            token_secret = str(item.get("token_secret") or "").strip() or None
            user = str(item.get("user") or "").strip() or None
            password = item.get("password")
            if password is not None:
                password = str(password)
            if not ((token_id and token_secret) or (user and password is not None)):
                logger.warning(
                    "ProxmoxHosts: endpoint %s needs "
                    "token_id+token_secret or user+password",
                    url_raw,
                )
                continue

            interval_raw = item.get(
                "reload_interval_second",
                self.config.get("reload_interval_second", 30.0),
            )
            try:
                interval = float(interval_raw)
            except (TypeError, ValueError):
                interval = 30.0
            if interval < 0:
                interval = 0.0

            host_ipv4 = None
            host_ipv6 = None
            raw_v4 = item.get("use_ipv4")
            if raw_v4:
                try:
                    ip_obj = ipaddress.ip_address(str(raw_v4))
                    if ip_obj.version == 4:
                        host_ipv4 = str(ip_obj)
                    else:
                        logger.warning("ProxmoxHosts: use_ipv4=%r is not IPv4", raw_v4)
                except ValueError:
                    logger.warning("ProxmoxHosts: invalid use_ipv4 %r", raw_v4)
            raw_v6 = item.get("use_ipv6")
            if raw_v6:
                try:
                    ip_obj = ipaddress.ip_address(str(raw_v6))
                    if ip_obj.version == 6:
                        host_ipv6 = str(ip_obj)
                    else:
                        logger.warning("ProxmoxHosts: use_ipv6=%r is not IPv6", raw_v6)
                except ValueError:
                    logger.warning("ProxmoxHosts: invalid use_ipv6 %r", raw_v6)

            ttl_override = None
            ttl_raw = item.get("ttl")
            if ttl_raw is not None:
                try:
                    ttl_val = int(ttl_raw)
                    ttl_override = ttl_val if ttl_val >= 0 else None
                except (TypeError, ValueError):
                    logger.warning(
                        "ProxmoxHosts: invalid ttl %r for %s", ttl_raw, url_raw
                    )

            verify_tls = bool(item.get("verify_tls", True))
            tls_ca = str(item.get("tls_ca") or "").strip() or None
            if tls_ca:
                tls_ca = self._resolve_tls_path(tls_ca)
            verify: bool | str
            if not verify_tls:
                verify = False
            elif tls_ca:
                verify = tls_ca
            else:
                verify = True

            ep_suffix = (
                self._normalize_suffix(item.get("suffix")) if item.get("suffix") else ""
            )

            endpoints_cfg.append(
                {
                    "url": url_raw.rstrip("/"),
                    "token_id": token_id,
                    "token_secret": token_secret,
                    "user": user,
                    "password": password,
                    "verify": verify,
                    "interval": interval,
                    "host_ipv4": host_ipv4,
                    "host_ipv6": host_ipv6,
                    "ttl": ttl_override,
                    "suffix": ep_suffix,
                }
            )

        if not endpoints_cfg:
            logger.warning(
                "ProxmoxHosts: no usable endpoints configured; plugin will stay empty"
            )

        self._endpoints = endpoints_cfg
        self._lock = threading.RLock()
        self._forward_v4: dict[str, list[str]] = {}
        self._forward_v6: dict[str, list[str]] = {}
        self._reverse: dict[str, str] = {}
        self._ttl_v4: dict[str, int] = {}
        self._ttl_v6: dict[str, int] = {}
        self._ttl_ptr: dict[str, int] = {}
        self._aggregate_txt: dict[str, list[str]] = {}
        self._ttl_txt: dict[str, int] = {}
        self._guests_meta: list[dict[str, object]] = []
        self._stop_event = threading.Event()
        self._clients: dict[str, _PveClient] = {}

        for ep in self._endpoints:
            url = str(ep["url"])
            try:
                client = _PveClient(
                    base_url=url,
                    token_id=ep.get("token_id"),  # type: ignore[arg-type]
                    token_secret=ep.get("token_secret"),  # type: ignore[arg-type]
                    user=ep.get("user"),  # type: ignore[arg-type]
                    password=ep.get("password"),  # type: ignore[arg-type]
                    verify=ep["verify"],  # type: ignore[arg-type]
                )
                self._clients[url] = client
                logger.info("ProxmoxHosts: configured endpoint %s", url)
            except Exception as exc:
                self._note_condition_failure(
                    f"endpoint:{url}",
                    "ProxmoxHosts: failed to init client for %s: %s",
                    url,
                    exc,
                )

        positive = [
            float(ep["interval"]) for ep in self._endpoints if float(ep["interval"]) > 0
        ]
        cfg_interval = float(self.config.get("reload_interval_second", 30.0) or 0.0)
        if positive:
            self._reload_interval = min(positive)
        elif cfg_interval > 0:
            self._reload_interval = cfg_interval
        else:
            self._reload_interval = 0.0

        self._reload_from_proxmox()

        if self._reload_interval > 0:
            t = threading.Thread(
                target=self._reload_loop,
                name="ProxmoxHostsPoller",
                daemon=True,
            )
            t.start()

    def _reload_loop(self) -> None:
        """Brief: Periodically refresh guest mappings.

        Inputs:
          - None.
        Outputs:
          - None; runs until stop_event is set.
        """

        interval = float(getattr(self, "_reload_interval", 0.0))
        if interval <= 0:
            return
        while True:
            if self._stop_event.wait(timeout=interval):
                return
            try:
                self._reload_from_proxmox()
                self._note_condition_ok(
                    "periodic-reload-error",
                    "ProxmoxHosts: periodic reload recovered",
                )
            except Exception as exc:
                self._note_condition_failure(
                    "periodic-reload-error",
                    "ProxmoxHosts: error during periodic reload; "
                    "keeping previous maps: %s",
                    exc,
                )

    def shutdown(self) -> None:
        """Brief: Stop the poller and close HTTP clients.

        Inputs:
          - None.
        Outputs:
          - None.
        """

        try:
            self._stop_event.set()
        except Exception:
            pass
        for client in list(getattr(self, "_clients", {}).values()):
            try:
                client.close()
            except Exception:
                continue

    def _get_client(self, endpoint: dict[str, object]) -> _PveClient | None:
        """Brief: Return or create an API client for an endpoint.

        Inputs:
          - endpoint: Normalized endpoint mapping.
        Outputs:
          - _PveClient or None on failure.
        """

        url = str(endpoint["url"])
        client = self._clients.get(url)
        if client is not None:
            return client
        try:
            client = _PveClient(
                base_url=url,
                token_id=endpoint.get("token_id"),  # type: ignore[arg-type]
                token_secret=endpoint.get("token_secret"),  # type: ignore[arg-type]
                user=endpoint.get("user"),  # type: ignore[arg-type]
                password=endpoint.get("password"),  # type: ignore[arg-type]
                verify=endpoint["verify"],  # type: ignore[arg-type]
            )
        except Exception as exc:
            self._note_condition_failure(
                f"endpoint:{url}",
                "ProxmoxHosts: failed to create client for %s: %s",
                url,
                exc,
            )
            return None
        self._clients[url] = client
        return client

    def _fetch_cluster_vms(self, client: _PveClient) -> list[dict[str, Any]]:
        """Brief: List QEMU/LXC resources from /cluster/resources.

        Inputs:
          - client: Authenticated PVE client.
        Outputs:
          - List of resource dicts (type qemu/lxc).
        """

        data = client.get_json("cluster/resources", params={"type": "vm"})
        if not isinstance(data, list):
            return []
        out: list[dict[str, Any]] = []
        for item in data:
            if isinstance(item, dict):
                out.append(item)
        return out

    def _fetch_cluster_nodes(self, client: _PveClient) -> list[dict[str, Any]]:
        """Brief: List nodes from /cluster/resources?type=node.

        Inputs:
          - client: Authenticated PVE client.
        Outputs:
          - List of node resource dicts.
        """

        try:
            data = client.get_json("cluster/resources", params={"type": "node"})
        except Exception:
            return []
        if not isinstance(data, list):
            return []
        return [x for x in data if isinstance(x, dict)]

    @staticmethod
    def _extract_agent_ips(payload: Any) -> tuple[list[str], list[str]]:
        """Brief: Parse guest-agent network-get-interfaces payload.

        Inputs:
          - payload: API ``data`` (often ``{result: [...]}``).
        Outputs:
          - (ipv4_list, ipv6_list) usable addresses.
        """

        v4: list[str] = []
        v6: list[str] = []
        result = payload
        if isinstance(payload, dict):
            result = payload.get("result", payload)
        if not isinstance(result, list):
            return v4, v6
        for iface in result:
            if not isinstance(iface, dict):
                continue
            name = str(iface.get("name") or "")
            if name == "lo" or name.startswith("lo."):
                continue
            addrs = iface.get("ip-addresses") or iface.get("ip_addresses") or []
            if not isinstance(addrs, list):
                continue
            for entry in addrs:
                if not isinstance(entry, dict):
                    continue
                ip_text = str(
                    entry.get("ip-address") or entry.get("ip_address") or ""
                ).strip()
                if not ip_text or not ProxmoxHosts._is_usable_ip(ip_text):
                    continue
                try:
                    ip_obj = ipaddress.ip_address(ip_text)
                except ValueError:
                    continue
                if ip_obj.version == 4:
                    if ip_text not in v4:
                        v4.append(ip_text)
                elif ip_text not in v6:
                    v6.append(ip_text)
        return v4, v6

    @staticmethod
    def _extract_lxc_interface_ips(payload: Any) -> tuple[list[str], list[str]]:
        """Brief: Parse LXC /interfaces response for guest IPs.

        Inputs:
          - payload: API data list/dict.
        Outputs:
          - (ipv4_list, ipv6_list).
        """

        v4: list[str] = []
        v6: list[str] = []
        items = payload if isinstance(payload, list) else []
        if isinstance(payload, dict):
            maybe = payload.get("result") or payload.get("data") or []
            if isinstance(maybe, list):
                items = maybe
        for iface in items:
            if not isinstance(iface, dict):
                continue
            for key in ("inet", "ip", "address", "hwaddr"):
                # Prefer explicit inet / inet6 style fields.
                pass
            inet = iface.get("inet") or iface.get("ip") or iface.get("address")
            if isinstance(inet, str):
                # May be "10.0.0.5/24"
                ip_text = inet.split("/", 1)[0].strip()
                if ProxmoxHosts._is_usable_ip(ip_text):
                    try:
                        if (
                            ipaddress.ip_address(ip_text).version == 4
                            and ip_text not in v4
                        ):
                            v4.append(ip_text)
                    except ValueError:
                        pass
            inet6 = iface.get("inet6")
            if isinstance(inet6, str):
                ip_text = inet6.split("/", 1)[0].strip()
                if ProxmoxHosts._is_usable_ip(ip_text):
                    try:
                        if (
                            ipaddress.ip_address(ip_text).version == 6
                            and ip_text not in v6
                        ):
                            v6.append(ip_text)
                    except ValueError:
                        pass
            # Some PVE versions return ip-addresses like the agent.
            nested = iface.get("ip-addresses")
            if nested:
                a4, a6 = ProxmoxHosts._extract_agent_ips({"result": [iface]})
                for ip in a4:
                    if ip not in v4:
                        v4.append(ip)
                for ip in a6:
                    if ip not in v6:
                        v6.append(ip)
        return v4, v6

    @staticmethod
    def _extract_ipconfig_ips(config: dict[str, Any]) -> tuple[list[str], list[str]]:
        """Brief: Parse cloud-init ipconfigN static addresses from guest config.

        Inputs:
          - config: Guest config dict.
        Outputs:
          - (ipv4_list, ipv6_list); skips dhcp/dhcpv6-only values.
        """

        v4: list[str] = []
        v6: list[str] = []
        for key, value in config.items():
            if not str(key).startswith("ipconfig"):
                continue
            text = str(value or "")
            for match in _IPCONFIG_RE.finditer(text):
                ip_text = match.group(1).strip()
                if ip_text.lower() in {"dhcp", "manual"}:
                    continue
                if ProxmoxHosts._is_usable_ip(ip_text):
                    try:
                        if (
                            ipaddress.ip_address(ip_text).version == 4
                            and ip_text not in v4
                        ):
                            v4.append(ip_text)
                    except ValueError:
                        continue
            for match in _IPCONFIG6_RE.finditer(text):
                ip_text = match.group(1).strip()
                if ip_text.lower() in {"dhcp", "dhcpv6", "auto", "manual"}:
                    continue
                if ProxmoxHosts._is_usable_ip(ip_text):
                    try:
                        if (
                            ipaddress.ip_address(ip_text).version == 6
                            and ip_text not in v6
                        ):
                            v6.append(ip_text)
                    except ValueError:
                        continue
        return v4, v6

    def _resolve_guest_addresses(
        self,
        client: _PveClient,
        guest: dict[str, Any],
    ) -> tuple[list[str], list[str], str | None]:
        """Brief: Resolve IPv4/IPv6 for one guest using ordered sources.

        Inputs:
          - client: PVE client.
          - guest: cluster/resources row.
        Outputs:
          - (v4, v6, agent_hostname_or_None).
        """

        node = str(guest.get("node") or "").strip()
        vmid = guest.get("vmid")
        gtype = str(guest.get("type") or "qemu").strip().lower()
        if not node or vmid is None:
            return [], [], None

        kind = "qemu" if gtype in {"qemu", "kvm"} else "lxc"
        v4: list[str] = []
        v6: list[str] = []
        agent_hostname: str | None = None

        def _take(src_v4: list[str], src_v6: list[str]) -> bool:
            nonlocal v4, v6
            if self._merge_addresses:
                for ip in src_v4:
                    if ip not in v4:
                        v4.append(ip)
                for ip in src_v6:
                    if ip not in v6:
                        v6.append(ip)
                return bool(src_v4 or src_v6)
            if not v4 and src_v4:
                v4 = list(src_v4)
            if not v6 and src_v6:
                v6 = list(src_v6)
            return bool(v4 or v6) and not self._merge_addresses and bool(v4 and v6)

        if kind == "qemu" and self._use_guest_agent:
            try:
                payload = client.get_json(
                    f"nodes/{node}/qemu/{int(vmid)}/agent/network-get-interfaces"
                )
                a4, a6 = self._extract_agent_ips(payload)
                _take(a4, a6)
            except Exception as exc:
                logger.debug(
                    "ProxmoxHosts: agent NICs failed for %s/%s: %s",
                    node,
                    vmid,
                    exc,
                )
            if self._merge_addresses or not (v4 and v6):
                try:
                    # Best-effort hostname from agent.
                    host_payload = client.get_json(
                        f"nodes/{node}/qemu/{int(vmid)}/agent/get-host-name"
                    )
                    if isinstance(host_payload, dict):
                        result = host_payload.get("result") or host_payload
                        if isinstance(result, dict):
                            hn = result.get("host-name") or result.get("hostname")
                            if hn:
                                agent_hostname = str(hn).strip()
                        elif isinstance(result, str):
                            agent_hostname = result.strip()
                except Exception:
                    pass

        if kind == "lxc" and (self._merge_addresses or not (v4 and v6)):
            try:
                payload = client.get_json(f"nodes/{node}/lxc/{int(vmid)}/interfaces")
                a4, a6 = self._extract_lxc_interface_ips(payload)
                _take(a4, a6)
            except Exception as exc:
                logger.debug(
                    "ProxmoxHosts: lxc interfaces failed for %s/%s: %s",
                    node,
                    vmid,
                    exc,
                )

        if self._merge_addresses or not (v4 and v6):
            try:
                status = client.get_json(
                    f"nodes/{node}/{kind}/{int(vmid)}/status/current"
                )
                if isinstance(status, dict):
                    for key in ("ip", "agent-ip"):
                        val = status.get(key)
                        if not isinstance(val, str) or not self._is_usable_ip(val):
                            continue
                        ip_obj = ipaddress.ip_address(val)
                        if ip_obj.version == 4:
                            if self._merge_addresses:
                                if val not in v4:
                                    v4.append(val)
                            elif not v4:
                                v4 = [val]
                        elif ip_obj.version == 6:
                            if self._merge_addresses:
                                if val not in v6:
                                    v6.append(val)
                            elif not v6:
                                v6 = [val]
            except Exception:
                pass

        if self._merge_addresses or not (v4 or v6):
            try:
                cfg = client.get_json(f"nodes/{node}/{kind}/{int(vmid)}/config")
                if isinstance(cfg, dict):
                    c4, c6 = self._extract_ipconfig_ips(cfg)
                    if self._merge_addresses:
                        for ip in c4:
                            if ip not in v4:
                                v4.append(ip)
                        for ip in c6:
                            if ip not in v6:
                                v6.append(ip)
                    else:
                        if not v4:
                            v4 = list(c4)
                        if not v6:
                            v6 = list(c6)
            except Exception as exc:
                logger.debug(
                    "ProxmoxHosts: config fallback failed for %s/%s: %s",
                    node,
                    vmid,
                    exc,
                )

        return v4, v6, agent_hostname

    def _normalize_name_label(self, value: str) -> str:
        """Brief: Normalize a candidate hostname to a DNS label.

        Inputs:
          - value: Raw name (may contain dots; first label used when multi-label).
        Outputs:
          - Lowercase label with underscores converted, or empty if invalid.
        """

        text = str(value or "").strip().strip(".").lower().replace("_", "-")
        if not text:
            return ""
        # Multi-label guest names: keep full name if all labels valid, else first.
        if "." in text:
            parts = [p for p in text.split(".") if p]
            if parts and all(self._is_valid_dns_label(p) for p in parts):
                return ".".join(parts)
            text = parts[0] if parts else ""
        if self._is_valid_dns_label(text):
            return text
        return ""

    def _names_for_guest(
        self,
        guest: dict[str, Any],
        agent_hostname: str | None,
        suffix: str,
    ) -> tuple[str, list[str]]:
        """Brief: Build canonical name and aliases for a guest.

        Inputs:
          - guest: cluster resource row.
          - agent_hostname: Optional agent hostname.
          - suffix: Effective DNS suffix.
        Outputs:
          - (canonical_fqdn_or_label, list_of_published_names).
        """

        gtype = str(guest.get("type") or "qemu").lower()
        vmid = guest.get("vmid")
        raw_name = str(guest.get("name") or "").strip()
        base = self._normalize_name_label(raw_name)
        if not base and agent_hostname:
            base = self._normalize_name_label(agent_hostname)
        if not base:
            prefix = "ct" if gtype == "lxc" else "vm"
            base = f"{prefix}{vmid}"

        labels: list[str] = [base]
        if agent_hostname:
            alt = self._normalize_name_label(agent_hostname)
            if alt and alt not in labels:
                labels.append(alt)
        if self._publish_vmid and vmid is not None:
            vlabel = f"vm{vmid}" if gtype != "lxc" else f"ct{vmid}"
            if self._is_valid_dns_label(vlabel) and vlabel not in labels:
                labels.append(vlabel)
        if self._publish_tags:
            tags_raw = guest.get("tags")
            tag_parts: list[str] = []
            if isinstance(tags_raw, str):
                tag_parts = re.split(r"[;,|\s]+", tags_raw)
            elif isinstance(tags_raw, list):
                tag_parts = [str(t) for t in tags_raw]
            for tag in tag_parts:
                tlabel = self._normalize_name_label(tag)
                if tlabel and tlabel not in labels:
                    labels.append(tlabel)

        published: list[str] = []
        for lab in labels:
            if suffix:
                # Only first label of multi-label base gets suffix when base has dots?
                # Publish full base + suffix when base is single or multi label.
                name = f"{lab}.{suffix}"
            else:
                name = lab
            if name not in published:
                published.append(name)

        canonical = (
            published[0] if published else (f"{base}.{suffix}" if suffix else base)
        )
        return canonical, published

    def _reload_from_proxmox(self) -> None:
        """Brief: Rebuild forward/reverse maps from the Proxmox cluster API.

        Inputs:
          - None (uses self._endpoints).
        Outputs:
          - None; swaps in-memory maps under lock.
        """

        if not self._endpoints:
            return

        new_v4: dict[str, list[str]] = {}
        new_v6: dict[str, list[str]] = {}
        new_reverse: dict[str, str] = {}
        new_ttl_v4: dict[str, int] = {}
        new_ttl_v6: dict[str, int] = {}
        new_ttl_ptr: dict[str, int] = {}
        new_txt: dict[str, list[str]] = {}
        new_ttl_txt: dict[str, int] = {}
        guests_meta: list[dict[str, object]] = []

        loaded = False
        last_error: Exception | None = None

        for endpoint in self._endpoints:
            url = str(endpoint["url"])
            client = self._get_client(endpoint)
            if client is None:
                continue
            try:
                resources = self._fetch_cluster_vms(client)
                self._note_condition_ok(
                    f"endpoint:{url}",
                    "ProxmoxHosts: endpoint %s is reachable again",
                    url,
                )
            except Exception as exc:
                last_error = exc
                self._note_condition_failure(
                    f"endpoint:{url}",
                    "ProxmoxHosts: failed listing VMs on %s: %s",
                    url,
                    exc,
                )
                continue

            ep_ttl_override = endpoint.get("ttl")
            try:
                ep_ttl = (
                    int(ep_ttl_override)
                    if ep_ttl_override is not None
                    else int(self._ttl)
                )
            except Exception:
                ep_ttl = int(self._ttl)

            ep_suffix = str(endpoint.get("suffix") or "") or self._suffix
            host_ipv4 = endpoint.get("host_ipv4")
            host_ipv6 = endpoint.get("host_ipv6")

            # Filter guests first.
            selected: list[dict[str, Any]] = []
            for guest in resources:
                gtype = str(guest.get("type") or "").lower()
                if gtype not in self._include_types:
                    continue
                if not self._include_templates and int(guest.get("template") or 0) == 1:
                    continue
                status = str(guest.get("status") or "").strip().lower()
                if self._status_allowlist and status not in self._status_allowlist:
                    continue
                selected.append(guest)

            def _work(
                g: dict[str, Any],
            ) -> tuple[dict[str, Any], list[str], list[str], str | None]:
                v4, v6, ahn = self._resolve_guest_addresses(client, g)
                return g, v4, v6, ahn

            results: list[tuple[dict[str, Any], list[str], list[str], str | None]] = []
            workers = min(self._max_workers, max(1, len(selected)))
            if selected:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futs = [pool.submit(_work, g) for g in selected]
                    for fut in as_completed(futs):
                        try:
                            results.append(fut.result())
                        except Exception as exc:
                            logger.debug("ProxmoxHosts: guest worker failed: %s", exc)

            for guest, v4_list, v6_list, agent_hn in results:
                if host_ipv4 is not None:
                    v4_list = [str(host_ipv4)]
                if host_ipv6 is not None:
                    v6_list = [str(host_ipv6)]
                if not v4_list and not v6_list:
                    logger.debug(
                        "ProxmoxHosts: no IPs for %s (vmid=%s); skipping",
                        guest.get("name"),
                        guest.get("vmid"),
                    )
                    continue

                canonical, names = self._names_for_guest(guest, agent_hn, ep_suffix)
                for key in names:
                    if v4_list:
                        existing = new_v4.setdefault(key, [])
                        for ip in v4_list:
                            if ip not in existing:
                                existing.append(ip)
                        new_ttl_v4[key] = ep_ttl
                    if v6_list:
                        existing6 = new_v6.setdefault(key, [])
                        for ip in v6_list:
                            if ip not in existing6:
                                existing6.append(ip)
                        new_ttl_v6[key] = ep_ttl

                for ip in list(v4_list) + list(v6_list):
                    try:
                        ptr_name = ipaddress.ip_address(ip).reverse_pointer
                    except ValueError:
                        continue
                    new_reverse.setdefault(ptr_name, canonical)
                    new_ttl_ptr[ptr_name] = ep_ttl

                line = (
                    f"name={guest.get('name')} type={guest.get('type')} "
                    f"vmid={guest.get('vmid')} node={guest.get('node')} "
                    f"status={guest.get('status')} "
                    f"ans4={','.join(v4_list) if v4_list else '-'} "
                    f"ans6={','.join(v6_list) if v6_list else '-'}"
                )
                for owner in names:
                    new_txt.setdefault(owner, []).append(line)
                    new_ttl_txt[owner] = ep_ttl

                if self._discovery:
                    guests_owner = f"_guests.{ep_suffix}" if ep_suffix else "_guests"
                    new_txt.setdefault(guests_owner, []).append(line)
                    new_ttl_txt[guests_owner] = int(self._ttl)

                guests_meta.append(
                    {
                        "name": str(guest.get("name") or canonical),
                        "canonical": canonical,
                        "aliases": list(names),
                        "type": str(guest.get("type") or ""),
                        "vmid": guest.get("vmid"),
                        "node": str(guest.get("node") or ""),
                        "status": str(guest.get("status") or ""),
                        "ipv4": list(v4_list),
                        "ipv6": list(v6_list),
                    }
                )

            if self._discovery:
                nodes = self._fetch_cluster_nodes(client)
                nodes_owner = f"_nodes.{ep_suffix}" if ep_suffix else "_nodes"
                for node in nodes:
                    nline = (
                        f"node={node.get('node') or node.get('name')} "
                        f"status={node.get('status')} "
                        f"id={node.get('id')}"
                    )
                    new_txt.setdefault(nodes_owner, []).append(nline)
                    new_ttl_txt[nodes_owner] = int(self._ttl)

            loaded = True
            # First successful endpoint wins for this cycle (cluster-wide view).
            break

        if not loaded:
            if last_error is not None:
                self._note_condition_failure(
                    "cluster-reload",
                    "ProxmoxHosts: all endpoints failed; keeping previous mappings: %s",
                    last_error,
                )
            return

        if not new_v4 and not new_v6:
            self._note_condition_failure(
                "no-guest-ip-mappings",
                "ProxmoxHosts: reload succeeded but no guest "
                "hostname/IP mappings were added",
            )
        else:
            self._note_condition_ok("no-guest-ip-mappings")
            self._note_condition_ok("cluster-reload")

        if new_txt:
            for owner, lines in new_txt.items():
                if owner.startswith("_nodes"):
                    lines.insert(0, f"nodes={len(lines)}")
                elif owner.startswith("_guests"):
                    lines.insert(0, f"guests={len(lines)}")
                else:
                    lines.insert(0, f"records={len(lines)}")

        with self._lock:
            self._forward_v4 = new_v4
            self._forward_v6 = new_v6
            self._reverse = new_reverse
            self._ttl_v4 = new_ttl_v4
            self._ttl_v6 = new_ttl_v6
            self._ttl_ptr = new_ttl_ptr
            self._aggregate_txt = new_txt
            self._ttl_txt = new_ttl_txt
            self._guests_meta = guests_meta

        logger.info(
            "ProxmoxHosts: loaded %d guests (%d A, %d AAAA, %d PTR names)",
            len(guests_meta),
            len(new_v4),
            len(new_v6),
            len(new_reverse),
        )

    def get_admin_pages(self) -> list[AdminPageSpec]:
        """Brief: Describe the ProxmoxHosts admin page.

        Inputs:
          - None.
        Outputs:
          - list[AdminPageSpec].
        """

        return [
            AdminPageSpec(
                slug="proxmox-hosts",
                title="Proxmox",
                description=(
                    "Guests discovered by the ProxmoxHosts plugin "
                    "(uses /api/v1/plugins/{name}/proxmox_hosts for data)."
                ),
                layout="one_column",
                kind="proxmox_hosts",
            )
        ]

    def get_admin_ui_descriptor(self) -> dict[str, object]:
        """Brief: Generic admin UI descriptor for Proxmox guests.

        Inputs:
          - None.
        Outputs:
          - dict with snapshot endpoint and table layout.
        """

        plugin_name = getattr(self, "name", "proxmox")
        title = f"Proxmox ({plugin_name})" if plugin_name else "Proxmox"
        snapshot_url = f"/api/v1/plugins/{plugin_name}/proxmox_hosts"
        layout: dict[str, object] = {
            "sections": [
                {
                    "id": "summary",
                    "title": "Summary",
                    "type": "kv",
                    "path": "summary",
                    "rows": [
                        {"key": "total_guests", "label": "Guests"},
                        {"key": "suffix", "label": "Domain"},
                        {"key": "reload_interval", "label": "Reload interval (s)"},
                    ],
                },
                {
                    "id": "endpoints",
                    "title": "Endpoints",
                    "type": "table",
                    "path": "summary.endpoints",
                    "columns": [
                        {"key": "url", "label": "URL"},
                        {"key": "interval", "label": "Interval (s)"},
                        {"key": "suffix", "label": "Suffix"},
                    ],
                },
                {
                    "id": "guests",
                    "title": "Guests",
                    "type": "table",
                    "path": "guests",
                    "columns": [
                        {"key": "name", "label": "Name"},
                        {"key": "type", "label": "Type"},
                        {"key": "vmid", "label": "VMID"},
                        {"key": "node", "label": "Node"},
                        {"key": "status", "label": "Status"},
                        {"key": "ipv4", "label": "IPv4", "join": ", "},
                        {"key": "ipv6", "label": "IPv6", "join": ", "},
                    ],
                },
            ]
        }
        return {
            "name": str(plugin_name),
            "title": str(title),
            "order": 55,
            "endpoints": {"snapshot": snapshot_url},
            "layout": layout,
        }

    def get_http_snapshot(self) -> dict[str, object]:
        """Brief: JSON-safe snapshot of current Proxmox guest mappings.

        Inputs:
          - None.
        Outputs:
          - dict with summary and guests list.
        """

        with self._lock:
            guests = [dict(g) for g in self._guests_meta]
            endpoints_view = []
            for ep in getattr(self, "_endpoints", []):
                if not isinstance(ep, dict):
                    continue
                endpoints_view.append(
                    {
                        "url": str(ep.get("url", "")),
                        "interval": float(ep.get("interval", 0.0) or 0.0),
                        "suffix": ep.get("suffix") or self._suffix or None,
                        "host_ipv4": ep.get("host_ipv4"),
                        "host_ipv6": ep.get("host_ipv6"),
                    }
                )
            summary = {
                "total_guests": len(guests),
                "endpoints": endpoints_view,
                "reload_interval": float(getattr(self, "_reload_interval", 0.0) or 0.0),
                "suffix": self._suffix or None,
            }
        return {"summary": summary, "guests": guests}

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> PluginDecision | None:
        """Brief: Answer A/AAAA/PTR/TXT from Proxmox guest maps.

        Inputs:
          - qname: Queried name.
          - qtype: DNS type.
          - req: Wire request.
          - ctx: Plugin context.
        Outputs:
          - PluginDecision(override) or None.
        """

        if not self.targets(ctx):
            return None

        name = qname.strip(".").lower()

        if qtype == QTYPE.A:
            with self._lock:
                addrs = list(self._forward_v4.get(name, []))
                ttl = int(self._ttl_v4.get(name, self._ttl))
                txts = list(self._aggregate_txt.get(name, []))
                txt_ttl = int(self._ttl_txt.get(name, self._ttl))
            if not addrs and not txts:
                return None
            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("ProxmoxHosts: parse failure for A %s: %s", qname, exc)
                return None
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            for ipaddr in addrs:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=ttl,
                        rdata=A(ipaddr),
                    )
                )
            if self._expose_txt_in_additional:
                for line in txts:
                    reply.add_ar(
                        RR(
                            rname=request.q.qname,
                            rtype=QTYPE.TXT,
                            rclass=1,
                            ttl=txt_ttl,
                            rdata=TXT([self._sanitize_txt_chunk(str(line))]),
                        )
                    )
                try:
                    if len(reply.pack()) > 512:
                        reply.ar = []
                        reply.header.tc = 1
                except Exception:
                    reply.ar = []
                    reply.header.tc = 1
            return PluginDecision(action="override", response=reply.pack())

        if qtype == QTYPE.AAAA:
            with self._lock:
                addrs = list(self._forward_v6.get(name, []))
                ttl = int(self._ttl_v6.get(name, self._ttl))
                txts = list(self._aggregate_txt.get(name, []))
                txt_ttl = int(self._ttl_txt.get(name, self._ttl))
            if not addrs and not txts:
                return None
            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning(
                    "ProxmoxHosts: parse failure for AAAA %s: %s", qname, exc
                )
                return None
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            for ipaddr in addrs:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.AAAA,
                        rclass=1,
                        ttl=ttl,
                        rdata=AAAA(ipaddr),
                    )
                )
            if self._expose_txt_in_additional:
                for line in txts:
                    reply.add_ar(
                        RR(
                            rname=request.q.qname,
                            rtype=QTYPE.TXT,
                            rclass=1,
                            ttl=txt_ttl,
                            rdata=TXT([self._sanitize_txt_chunk(str(line))]),
                        )
                    )
                try:
                    if len(reply.pack()) > 512:
                        reply.ar = []
                        reply.header.tc = 1
                except Exception:
                    reply.ar = []
                    reply.header.tc = 1
            return PluginDecision(action="override", response=reply.pack())

        if qtype == QTYPE.TXT:
            with self._lock:
                txts = list(self._aggregate_txt.get(name, []))
                txt_ttl = int(self._ttl_txt.get(name, self._ttl))
                a_candidates = list(self._forward_v4.get(name, []))
                a_ttl = int(self._ttl_v4.get(name, self._ttl))
                aaaa_candidates = list(self._forward_v6.get(name, []))
                aaaa_ttl = int(self._ttl_v6.get(name, self._ttl))
            if not txts and not a_candidates and not aaaa_candidates:
                return None
            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("ProxmoxHosts: parse failure for TXT %s: %s", qname, exc)
                return None
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            for line in txts:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.TXT,
                        rclass=1,
                        ttl=txt_ttl,
                        rdata=TXT([self._sanitize_txt_chunk(str(line))]),
                    )
                )
            for ipaddr in a_candidates:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=a_ttl,
                        rdata=A(ipaddr),
                    )
                )
            for ipaddr in aaaa_candidates:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.AAAA,
                        rclass=1,
                        ttl=aaaa_ttl,
                        rdata=AAAA(ipaddr),
                    )
                )
            return PluginDecision(action="override", response=reply.pack())

        if qtype == QTYPE.PTR:
            with self._lock:
                hostname = self._reverse.get(name)
                ttl = int(self._ttl_ptr.get(name, self._ttl))
            if not hostname:
                return None
            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("ProxmoxHosts: parse failure for PTR %s: %s", qname, exc)
                return None
            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.PTR,
                    rclass=1,
                    ttl=ttl,
                    rdata=PTR(hostname),
                )
            )
            return PluginDecision(action="override", response=reply.pack())

        return None
