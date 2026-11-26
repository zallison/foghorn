"""UnifiHosts plugin: resolve client/device hostnames via UniFi Network API.

Brief:
  - Polls one or more UniFi Network Integration API endpoints (local console or
    Site Manager cloud connector) and builds in-memory A/AAAA/PTR (+ optional
    TXT) maps from connected clients and adopted devices.
  - Auth is X-API-KEY only (no legacy cookie/CSRF session API).
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from pydantic import BaseModel, ConfigDict, Field, model_validator

from foghorn.plugins.resolve.base import (
    AdminPageSpec,
    plugin_aliases,
)
from foghorn.plugins.resolve.hosts_common import (
    DynamicHostsPlugin,
    apply_address_limit,
    discovery_owner,
    endpoint_label,
    fold_tls_aliases,
    get_sni_session,
    ip_passes_cidr_filters,
    is_valid_dns_hostname,
    normalize_publishable_hostname,
    normalize_suffix,
    note_insecure_tls,
    parse_cidr_list,
    parse_str_list,
    resolve_plugin_tls_path,
    sanitize_txt_chunk,
)
from foghorn.utils import condition_logging as condition_log

logger = logging.getLogger(__name__)

# Strip characters that UniFi free-text names often include (MAC tails, etc.).
_NON_DNS_RE = re.compile(r"[^a-z0-9._-]+")
_MULTI_DOT_RE = re.compile(r"\.{2,}")
_MAC_RE = re.compile(r"[^0-9a-f]", re.IGNORECASE)

_INTEGRATION_SUFFIX = "/proxy/network/integration"


class UnifiEndpointConfig(BaseModel):
    """Brief: Per-endpoint UniFi Network Integration API settings.

    Inputs:
      - url: Console origin (https://udm.lan) or full integration base URL.
      - api_key: Integration / Site Manager API key (string or secret ref).
      - console_id: Optional; when set with a bare api.ui.com host, builds the
        cloud connector path.
      - verify_tls: Verify HTTPS certificates (default True).
      - tls_ca: Optional CA bundle path.
      - tls_server_name: SNI / expected cert hostname (aliases: tls_name, server_name).
      - use_ipv4 / use_ipv6: Optional host IP overrides for all published names.
      - ttl / suffix / reload_interval_second: Per-endpoint overrides.
      - site_ids: Optional site UUID allowlist for this endpoint.

    Outputs:
      - UnifiEndpointConfig instance.
    """

    url: str
    api_key: str | dict[str, object] | None = None
    console_id: str | None = None
    verify_tls: bool = True
    tls_ca: str | None = None
    tls_server_name: str | None = None
    use_ipv4: str | None = None
    use_ipv6: str | None = None
    ttl: int | None = Field(default=None, ge=0)
    suffix: str | None = None
    reload_interval_second: float | None = Field(default=None, ge=0)
    site_ids: list[str] = Field(default_factory=list)
    id: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _coerce_tls_aliases(cls, data: Any) -> Any:
        """Brief: Map tls_name/server_name onto tls_server_name.

        Inputs:
          - data: Raw endpoint mapping or other value.
        Outputs:
          - Mapping with SNI aliases folded, or the original value.
        """

        return fold_tls_aliases(
            data,
            pairs=(
                ("tls_name", "tls_server_name"),
                ("server_name", "tls_server_name"),
            ),
        )


class UnifiHostsConfig(BaseModel):
    """Brief: Typed configuration for UnifiHosts.

    Inputs:
      - endpoints: UniFi API endpoints (failover order).
      - ttl / reload_interval_second: Defaults for answers and polling.
      - include_clients / include_devices: Resource kinds to publish (bool shortcuts).
      - include_kinds / exclude_kinds: client/device kind filters (overrides bools when set).
      - include_types / exclude_types: Client connection types (wired, wireless, vpn, …).
      - device_states / include_states / exclude_states: Device (and optional client) state filters.
      - site_ids / site_names / exclude_site_*: Site filters after listing sites.
      - include_names / exclude_names: DHCP/display name globs (case-insensitive).
      - include_macs / exclude_macs: MAC allow/block (colon-insensitive).
      - include_networks / exclude_networks: Network name or id filters.
      - include_vlans / exclude_vlans: VLAN id filters (matched via networks inventory).
      - filter: Optional server-side Integration filter DSL string.
      - publish_mac: Publish host-<mac> aliases when true.
      - include_cidrs / exclude_cidrs / address_limit: Address filters.
      - discovery / expose_txt_in_additional / suffix: Shared DynamicHosts options.

    Outputs:
      - UnifiHostsConfig instance.
    """

    endpoints: list[UnifiEndpointConfig] = Field(default_factory=list)
    ttl: int = Field(default=60, ge=0)
    reload_interval_second: float = Field(default=120.0, ge=0)
    include_clients: bool = True
    include_devices: bool = True
    include_kinds: list[str] = Field(default_factory=list)
    exclude_kinds: list[str] = Field(default_factory=list)
    include_types: list[str] = Field(default_factory=list)
    exclude_types: list[str] = Field(default_factory=list)
    device_states: list[str] = Field(default_factory=lambda: ["ONLINE"])
    include_states: list[str] = Field(default_factory=list)
    exclude_states: list[str] = Field(default_factory=list)
    site_ids: list[str] = Field(default_factory=list)
    site_names: list[str] = Field(default_factory=list)
    exclude_site_ids: list[str] = Field(default_factory=list)
    exclude_site_names: list[str] = Field(default_factory=list)
    include_names: list[str] = Field(default_factory=list)
    exclude_names: list[str] = Field(default_factory=list)
    include_macs: list[str] = Field(default_factory=list)
    exclude_macs: list[str] = Field(default_factory=list)
    include_networks: list[str] = Field(default_factory=list)
    exclude_networks: list[str] = Field(default_factory=list)
    include_vlans: list[str | int] = Field(default_factory=list)
    exclude_vlans: list[str | int] = Field(default_factory=list)
    filter: str | None = None
    publish_mac: bool = False
    include_cidrs: list[str] = Field(default_factory=list)
    exclude_cidrs: list[str] = Field(default_factory=list)
    address_limit: int = Field(default=0, ge=0)
    discovery: bool = False
    expose_txt_in_additional: bool = False
    suffix: str | None = None

    model_config = ConfigDict(extra="allow")


def normalize_integration_base_url(
    url: str,
    *,
    console_id: str | None = None,
) -> str:
    """Brief: Normalize a console or integration URL to the Integration API root.

    Inputs:
      - url: Bare origin (https://udm.lan), partial path, or full integration root.
      - console_id: Optional Site Manager console id when url is api.ui.com.

    Outputs:
      - Base URL ending at .../proxy/network/integration (no trailing slash,
        no /v1). Paths under /v1 are appended by the client.

    Example:
      normalize_integration_base_url("https://udm.lan")
        -> "https://udm.lan/proxy/network/integration"
      normalize_integration_base_url(
          "https://api.ui.com", console_id="ABC"
        ) -> "https://api.ui.com/v1/connector/consoles/ABC/proxy/network/integration"
    """

    text = str(url or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = "https://" + text
    parsed = urlparse(text)
    path = (parsed.path or "").rstrip("/")

    # Already a full integration root (with or without /v1).
    if "/proxy/network/integration" in path:
        # Drop trailing /v1 so client can join v1/... consistently.
        path = path.removesuffix("/v1")
        base = urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/"), "", "", ""))
        return base.rstrip("/")

    # Cloud Site Manager host + console_id → connector path.
    host = (parsed.netloc or "").lower()
    cid = str(console_id or "").strip()
    if cid and ("api.ui.com" in host or host.endswith("ui.com")):
        path = f"/v1/connector/consoles/{cid}{_INTEGRATION_SUFFIX}"
        base = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
        return base.rstrip("/")

    # Bare console origin (or other path): append integration mount.
    path = (path or "") + _INTEGRATION_SUFFIX
    # Collapse accidental double slashes in path only.
    while "//" in path:
        path = path.replace("//", "/")
    base = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
    return base.rstrip("/")


def sanitize_unifi_name(raw: object) -> str:
    """Brief: Turn a UniFi free-text name into a publishable DNS hostname.

    Inputs:
      - raw: Client/device name from the API (may include spaces, MAC tails).

    Outputs:
      - Normalized hostname suitable for is_valid_dns_hostname, or "".

    Example:
      sanitize_unifi_name("Ryan's Laptop 00:FF") -> "ryan-s-laptop-00-ff"
    """

    text = str(raw or "").strip().lower()
    if not text:
        return ""
    # Prefer shared normalizer first (underscore → hyphen, strip dots).
    candidate = normalize_publishable_hostname(text)
    if candidate and is_valid_dns_hostname(candidate):
        return candidate
    # Aggressive cleanup for free-text UniFi labels.
    cleaned = _NON_DNS_RE.sub("-", text)
    cleaned = cleaned.replace("_", "-")
    cleaned = _MULTI_DOT_RE.sub(".", cleaned)
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    cleaned = cleaned.strip(".-")
    candidate = normalize_publishable_hostname(cleaned)
    if candidate and is_valid_dns_hostname(candidate):
        return candidate
    # Last resort: first label only after cleanup.
    first = cleaned.split(".", 1)[0].strip("-")
    if first and is_valid_dns_hostname(first):
        return first
    return ""


def mac_to_host_alias(mac: object) -> str:
    """Brief: Build a host-<hex> alias from a MAC address.

    Inputs:
      - mac: MAC string (colon/dash/plain).

    Outputs:
      - \"host-<12 hex chars>\" or \"\" when MAC is unusable.
    """

    hex_only = _MAC_RE.sub("", str(mac or "")).lower()
    if len(hex_only) < 12:
        return ""
    hex_only = hex_only[:12]
    if any(c not in "0123456789abcdef" for c in hex_only):
        return ""
    return f"host-{hex_only}"


def normalize_mac_key(mac: object) -> str:
    """Brief: Normalize a MAC to lowercase hex-only for comparisons.

    Inputs:
      - mac: MAC string with optional separators.
    Outputs:
      - Hex-only lowercase string (may be empty).
    """

    return _MAC_RE.sub("", str(mac or "")).lower()


def glob_list_match(value: str, patterns: list[str]) -> bool:
    """Brief: Case-insensitive fnmatch any-of against patterns.

    Inputs:
      - value: Candidate string.
      - patterns: Glob patterns (already lowercased preferred).
    Outputs:
      - True when patterns empty is NOT implied — caller checks emptiness.
        Returns True if any pattern matches value.
    """

    text = str(value or "").strip().lower()
    for pat in patterns:
        p = str(pat or "").strip().lower()
        if not p:
            continue
        if fnmatch.fnmatchcase(text, p):
            return True
    return False


class _UnifiClient:
    """Brief: Thin UniFi Network Integration API client (X-API-KEY).

    Inputs:
      - base_url, api_key, TLS settings from endpoint config.

    Outputs:
      - JSON helpers via get_json() / list_paginated().
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        verify: bool | str,
        tls_server_name: str | None = None,
        timeout: float = 15.0,
        page_limit: int = 200,
        label: str | None = None,
    ) -> None:
        root = str(base_url or "").rstrip("/") + "/"
        self.base_url = root
        self.api_key = str(api_key or "").strip()
        self.verify = verify
        self.timeout = timeout
        self.page_limit = max(1, min(200, int(page_limit)))
        sni = str(tls_server_name or "").strip() or None
        self.tls_server_name = sni
        self._session = get_sni_session(sni)
        self._session.verify = verify
        if verify is False:
            # Prefer configured endpoint id over the integration URL in notices.
            note_insecure_tls(
                str(label or "").strip() or self.base_url,
                log=logger,
            )

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

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Brief: GET an Integration API path and return parsed JSON.

        Inputs:
          - path: Absolute or relative path (e.g. ``v1/sites`` or ``/v1/sites``).
          - params: Optional query parameters.

        Outputs:
          - Parsed JSON body (dict/list/scalar).

        Raises:
          - requests.HTTPError on non-2xx responses.
          - RuntimeError when api_key is missing.
        """

        if not self.api_key:
            raise RuntimeError("UniFi endpoint needs api_key")
        path = str(path or "").lstrip("/")
        if not path.startswith("v1/") and path != "v1":
            path = f"v1/{path}"
        url = urljoin(self.base_url, path)
        headers = {
            "X-API-KEY": self.api_key,
            "Accept": "application/json",
        }
        resp = self._session.get(
            url,
            params=params,
            headers=headers,
            verify=self.verify,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        return resp.json()

    def list_paginated(
        self,
        path: str,
        *,
        extra_params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Brief: Fetch all pages from a list endpoint (offset/limit).

        Inputs:
          - path: List path under the API (e.g. ``sites/{id}/clients``).
          - extra_params: Optional extra query params (e.g. filter).

        Outputs:
          - Flat list of item dicts from successive ``data`` arrays.
        """

        out: list[dict[str, Any]] = []
        offset = 0
        while True:
            params: dict[str, Any] = {
                "offset": offset,
                "limit": self.page_limit,
            }
            if extra_params:
                params.update(extra_params)
            body = self.get_json(path, params=params)
            if not isinstance(body, dict):
                # Some builds may return a bare list.
                if isinstance(body, list):
                    for item in body:
                        if isinstance(item, dict):
                            out.append(item)
                break
            data = body.get("data")
            if not isinstance(data, list):
                data = []
            for item in data:
                if isinstance(item, dict):
                    out.append(item)
            total = body.get("totalCount")
            count = body.get("count", len(data))
            try:
                total_i = int(total) if total is not None else None
            except (TypeError, ValueError):
                total_i = None
            try:
                count_i = int(count)
            except (TypeError, ValueError):
                count_i = len(data)
            offset += max(count_i, 0)
            if not data:
                break
            if total_i is not None and offset >= total_i:
                break
            if count_i < self.page_limit:
                break
            # Safety: avoid infinite loops on broken totalCount.
            if offset > 100_000:
                logger.warning(
                    "pagination safety stop at offset=%s for %s", offset, path
                )
                break
        return out


@plugin_aliases("unifi_hosts", "unifi-hosts", "unifi", "ubiquiti")
class UnifiHosts(DynamicHostsPlugin):
    """Resolve UniFi Network client and device names via the Integration API.

    Brief:
      - setup() connects to configured endpoints, loads site/client/device
        inventory, and builds forward/reverse maps with a background refresher.
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
          - UnifiHostsConfig class.
        """

        return UnifiHostsConfig

    def _reload_maps(self) -> None:
        """Brief: Reload maps from UniFi (DynamicHostsPlugin poller hook).

        Inputs:
          - None.
        Outputs:
          - None.
        """

        self._reload_from_unifi()

    def _accept_ip(self, ip_text: str) -> bool:
        """Brief: Apply usable-IP + include/exclude CIDR filters.

        Inputs:
          - ip_text: Address string.
        Outputs:
          - True when the address should be published.
        """

        return ip_passes_cidr_filters(
            ip_text,
            include_cidrs=getattr(self, "_include_cidrs", None),
            exclude_cidrs=getattr(self, "_exclude_cidrs", None),
        )

    def setup(self) -> None:
        """Brief: Initialize UnifiHosts and build the initial inventory mapping.

        Inputs:
          - Plugin config keys (endpoints, ttl, suffix, filters, …).
        Outputs:
          - None; populates maps and starts the poller when interval > 0.
        """

        self._init_dynamic_hosts_state(default_ttl=int(self.config.get("ttl", 60)))
        self._suffix = normalize_suffix(self.config.get("suffix"))
        self._discovery = bool(self.config.get("discovery", False))
        self._expose_txt_in_additional = bool(
            self.config.get("expose_txt_in_additional", False)
        )
        self._include_clients = bool(self.config.get("include_clients", True))
        self._include_devices = bool(self.config.get("include_devices", True))
        self._publish_mac = bool(self.config.get("publish_mac", False))
        self._api_filter = str(self.config.get("filter") or "").strip() or None
        self._include_cidrs = parse_cidr_list(
            self.config.get("include_cidrs"), option_name="include_cidrs"
        )
        self._exclude_cidrs = parse_cidr_list(
            self.config.get("exclude_cidrs"), option_name="exclude_cidrs"
        )
        try:
            self._address_limit = max(0, int(self.config.get("address_limit", 0)))
        except (TypeError, ValueError):
            logger.warning(
                "invalid address_limit %r; using 0 (unlimited)",
                self.config.get("address_limit"),
            )
            self._address_limit = 0

        self._include_kinds = {
            k for k in parse_str_list(self.config.get("include_kinds")) if k
        }
        self._exclude_kinds = {
            k for k in parse_str_list(self.config.get("exclude_kinds")) if k
        }
        self._include_types = parse_str_list(self.config.get("include_types"))
        self._exclude_types = parse_str_list(self.config.get("exclude_types"))

        # States: include_states wins over legacy device_states when set.
        raw_inc_states = self.config.get("include_states")
        if raw_inc_states is None or raw_inc_states == []:
            raw_states = self.config.get("device_states")
            if raw_states is None:
                state_items = ["ONLINE"]
            elif isinstance(raw_states, str):
                state_items = [raw_states]
            elif isinstance(raw_states, list):
                state_items = [str(x) for x in raw_states]
            else:
                state_items = [str(raw_states)]
            self._include_states = [
                s.strip().upper() for s in state_items if str(s).strip()
            ] or ["ONLINE"]
        else:
            self._include_states = [
                s.upper() for s in parse_str_list(raw_inc_states, lower=False) if s
            ]
        self._exclude_states = {
            s.upper()
            for s in parse_str_list(self.config.get("exclude_states"), lower=False)
            if s
        }

        self._site_ids = {
            str(x).strip()
            for x in (self.config.get("site_ids") or [])
            if str(x).strip()
        }
        self._site_names = {
            str(x).strip().lower()
            for x in (self.config.get("site_names") or [])
            if str(x).strip()
        }
        self._exclude_site_ids = {
            str(x).strip()
            for x in (self.config.get("exclude_site_ids") or [])
            if str(x).strip()
        }
        self._exclude_site_names = {
            str(x).strip().lower()
            for x in (self.config.get("exclude_site_names") or [])
            if str(x).strip()
        }
        self._include_names = parse_str_list(
            self.config.get("include_names"), lower=False
        )
        self._exclude_names = parse_str_list(
            self.config.get("exclude_names"), lower=False
        )
        self._include_macs = {
            normalize_mac_key(x)
            for x in (self.config.get("include_macs") or [])
            if normalize_mac_key(x)
        }
        self._exclude_macs = {
            normalize_mac_key(x)
            for x in (self.config.get("exclude_macs") or [])
            if normalize_mac_key(x)
        }
        self._include_networks = parse_str_list(
            self.config.get("include_networks"), lower=False
        )
        self._exclude_networks = parse_str_list(
            self.config.get("exclude_networks"), lower=False
        )
        self._include_vlans = {
            str(x).strip()
            for x in (self.config.get("include_vlans") or [])
            if str(x).strip() != ""
        }
        self._exclude_vlans = {
            str(x).strip()
            for x in (self.config.get("exclude_vlans") or [])
            if str(x).strip() != ""
        }
        # Need network inventory when VLAN/network filters are configured.
        self._need_networks = bool(
            self._include_networks
            or self._exclude_networks
            or self._include_vlans
            or self._exclude_vlans
        )

        self._endpoints = self._parse_endpoints(self.config.get("endpoints") or [])
        self._hosts_meta: list[dict[str, object]] = []
        self._clients: dict[str, _UnifiClient] = {}
        if self._endpoints:
            logger.info(
                "configured %d endpoint(s); inventory via first healthy console",
                len(self._endpoints),
            )
        else:
            logger.warning("no usable endpoints configured; plugin will stay empty")

        positive = [
            float(ep["interval"]) for ep in self._endpoints if float(ep["interval"]) > 0
        ]
        if positive:
            self._reload_interval = min(positive)
        else:
            try:
                self._reload_interval = float(
                    self.config.get("reload_interval_second", 120.0) or 0.0
                )
            except (TypeError, ValueError):
                self._reload_interval = 120.0
            if self._reload_interval < 0:
                self._reload_interval = 0.0

        logger.info("reload interval %.1fs", float(self._reload_interval))
        self._reload_from_unifi()
        self._start_reload_loop(thread_name="UnifiHostsPoller")

    def _parse_endpoints(self, raw_endpoints: object) -> list[dict[str, object]]:
        """Brief: Normalize endpoints list from plugin config.

        Inputs:
          - raw_endpoints: Config endpoints value (usually a list).
        Outputs:
          - List of normalized endpoint dicts (may be empty).
        """

        endpoints_cfg: list[dict[str, object]] = []
        for raw_item in raw_endpoints or []:
            if not isinstance(raw_item, dict):
                logger.warning("ignoring non-mapping endpoint %r", raw_item)
                continue
            item = fold_tls_aliases(
                raw_item,
                pairs=(
                    ("tls_name", "tls_server_name"),
                    ("server_name", "tls_server_name"),
                ),
            )
            url_raw = str(item.get("url") or "").strip()
            ep_id = str(item.get("id") or "").strip() or None
            if not url_raw:
                logger.warning(
                    "endpoint %s missing url; skipping",
                    ep_id or item,
                )
                continue

            console_id = str(item.get("console_id") or "").strip() or None
            base_url = normalize_integration_base_url(url_raw, console_id=console_id)
            ep_label = endpoint_label(endpoint_id=ep_id, url=base_url or url_raw)
            if not base_url:
                logger.warning(
                    "endpoint %s url empty after normalize; skipping",
                    ep_label or item,
                )
                continue

            api_key_raw = item.get("api_key")
            if api_key_raw is None:
                # Allow common aliases.
                api_key_raw = item.get("token") or item.get("token_secret")
            if isinstance(api_key_raw, dict):
                try:
                    from foghorn.plugins.secrets.resolve import resolve_secret_string

                    api_key = resolve_secret_string(
                        api_key_raw, prefer=("token", "secret", "api_key", "key")
                    )
                except Exception:
                    api_key = None
            else:
                api_key = (
                    str(api_key_raw).strip() if api_key_raw is not None else None
                ) or None
            if not api_key:
                logger.warning("endpoint %s needs api_key", ep_label)
                continue

            if (
                "reload_interval_second" in item
                and item.get("reload_interval_second") is not None
            ):
                interval_raw = item.get("reload_interval_second")
            else:
                interval_raw = self.config.get("reload_interval_second", 120.0)
            try:
                interval = float(interval_raw)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                interval = float(
                    self.config.get("reload_interval_second", 120.0) or 120.0
                )
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
                        logger.warning("use_ipv4=%r is not IPv4", raw_v4)
                except ValueError:
                    logger.warning("invalid use_ipv4 %r", raw_v4)
            raw_v6 = item.get("use_ipv6")
            if raw_v6:
                try:
                    ip_obj = ipaddress.ip_address(str(raw_v6))
                    if ip_obj.version == 6:
                        host_ipv6 = str(ip_obj)
                    else:
                        logger.warning("use_ipv6=%r is not IPv6", raw_v6)
                except ValueError:
                    logger.warning("invalid use_ipv6 %r", raw_v6)

            ttl_override = None
            ttl_raw = item.get("ttl")
            if ttl_raw is not None:
                try:
                    ttl_val = int(ttl_raw)
                    ttl_override = ttl_val if ttl_val >= 0 else None
                except (TypeError, ValueError):
                    logger.warning("invalid ttl %r for %s", ttl_raw, ep_label)

            verify_tls = bool(item.get("verify_tls", True))
            # Also accept tls_verify alias (k8s/docker style).
            if "tls_verify" in item and "verify_tls" not in item:
                verify_tls = bool(item.get("tls_verify"))
            tls_ca = (
                str(item.get("tls_ca") or item.get("ca_cert") or "").strip() or None
            )
            if tls_ca:
                tls_ca = resolve_plugin_tls_path(tls_ca)
            verify: bool | str
            if not verify_tls:
                verify = False
            elif tls_ca:
                verify = tls_ca
            else:
                verify = True

            tls_server_name = str(item.get("tls_server_name") or "").strip() or None
            ep_suffix = (
                normalize_suffix(item.get("suffix")) if item.get("suffix") else ""
            )
            ep_site_ids = [
                str(x).strip() for x in (item.get("site_ids") or []) if str(x).strip()
            ]

            endpoints_cfg.append(
                {
                    "id": ep_id,
                    "url": base_url,
                    "api_key": api_key,
                    "verify": verify,
                    "tls_server_name": tls_server_name,
                    "interval": interval,
                    "host_ipv4": host_ipv4,
                    "host_ipv6": host_ipv6,
                    "ttl": ttl_override,
                    "suffix": ep_suffix,
                    "site_ids": ep_site_ids,
                }
            )
        return endpoints_cfg

    def _get_client(self, endpoint: dict[str, object]) -> _UnifiClient | None:
        """Brief: Return or create an API client for an endpoint.

        Inputs:
          - endpoint: Normalized endpoint mapping.
        Outputs:
          - _UnifiClient or None on failure.
        """

        label = self._endpoint_label(endpoint)
        client = self._clients.get(label)
        if client is not None:
            return client
        try:
            client = _UnifiClient(
                base_url=str(endpoint["url"]),
                api_key=str(endpoint["api_key"]),
                verify=endpoint["verify"],  # type: ignore[arg-type]
                tls_server_name=endpoint.get("tls_server_name"),  # type: ignore[arg-type]
                label=label,
            )
        except Exception as exc:
            # Condition keys stay on URL for stability; log text prefers id.
            condition_log.note_condition_failure(
                self,
                f"endpoint:{endpoint.get('url')}",
                "failed to create client for %s: %s",
                label,
                exc,
            )
            return None
        self._clients[label] = client
        logger.info("using endpoint %s", label)
        return client

    def _endpoint_label(self, endpoint: dict[str, object]) -> str:
        """Brief: Compact display label for an endpoint.

        Inputs:
          - endpoint: Normalized endpoint mapping.
        Outputs:
          - id when set, else URL (same preference as Docker/K8s hosts plugins).
        """

        return endpoint_label(endpoint)

    def _split_ip(self, ip_text: str) -> tuple[list[str], list[str]]:
        """Brief: Classify one address string into v4/v6 lists after filters.

        Inputs:
          - ip_text: Address from UniFi ipAddress field.
        Outputs:
          - (ipv4_list, ipv6_list); empty when rejected.
        """

        text = str(ip_text or "").strip()
        if not text or not self._accept_ip(text):
            return [], []
        try:
            ip_obj = ipaddress.ip_address(text)
        except ValueError:
            return [], []
        if ip_obj.version == 4:
            return [text], []
        return [], [text]

    def _names_for_row(
        self,
        *,
        name: str,
        mac: str,
        suffix: str,
    ) -> tuple[str, list[str]]:
        """Brief: Build canonical + alias published DNS names for one row.

        Inputs:
          - name: Sanitized primary hostname (may be empty).
          - mac: Raw MAC for optional host- alias.
          - suffix: Effective DNS suffix (may be empty).

        Outputs:
          - (canonical, names_for_mapping). Empty names when nothing publishable.
        """

        bases: list[str] = []
        primary = sanitize_unifi_name(name) if name else ""
        if primary:
            bases.append(primary)
        if self._publish_mac:
            mac_alias = mac_to_host_alias(mac)
            if mac_alias and mac_alias not in bases:
                bases.append(mac_alias)
        if not bases:
            # Recover via MAC when name was unusable and publish_mac is off —
            # still skip unless publish_mac (plan: never bare UUID; MAC only when
            # enabled). Exception: if name empty and publish_mac true, mac already
            # added. Nothing left.
            return "", []

        if suffix:
            names = [f"{b}.{suffix}" for b in bases]
        else:
            names = list(bases)
        # Validate full hostnames after suffix.
        valid = [n for n in names if is_valid_dns_hostname(n)]
        if not valid:
            return "", []
        return valid[0], valid

    def _kind_allowed(self, kind: str) -> bool:
        """Brief: Whether resource kind client/device may be published.

        Inputs:
          - kind: "client" or "device".
        Outputs:
          - True when kind passes include/exclude_kinds and bool shortcuts.
        """

        key = str(kind or "").strip().lower()
        exclude = getattr(self, "_exclude_kinds", None) or set()
        if key in exclude:
            return False
        include = getattr(self, "_include_kinds", None) or set()
        if include:
            return key in include
        if key == "client":
            return bool(getattr(self, "_include_clients", True))
        if key == "device":
            return bool(getattr(self, "_include_devices", True))
        return True

    def _client_type_allowed(self, raw_type: object) -> bool:
        """Brief: Whether a client type passes include/exclude_types.

        Inputs:
          - raw_type: API type string (WIRED, WIRELESS, …).
        Outputs:
          - True when type is allowed.
        """

        key = str(raw_type or "").strip().lower()
        exclude = getattr(self, "_exclude_types", None) or []
        if exclude and key in exclude:
            return False
        allow = getattr(self, "_include_types", None) or []
        if not allow:
            return True
        return key in allow

    def _state_allowed(self, raw_state: object, *, kind: str) -> bool:
        """Brief: Whether a row state passes include/exclude_states.

        Inputs:
          - raw_state: API state string (may be empty for clients).
          - kind: client or device.
        Outputs:
          - True when state is allowed. Empty client state is allowed unless
            exclude_states matches empty (rare).
        """

        key = str(raw_state or "").strip().upper()
        exclude = getattr(self, "_exclude_states", None) or set()
        if key and key in exclude:
            return False
        allow = getattr(self, "_include_states", None) or []
        # Devices historically required ONLINE; clients often have no state.
        if kind == "client" and not key:
            return True
        if not allow:
            return True
        if not key:
            return False
        return key in allow

    def _name_allowed(self, raw_name: object) -> bool:
        """Brief: DHCP/display name include/exclude glob filters.

        Inputs:
          - raw_name: UniFi name field.
        Outputs:
          - True when name is allowed.
        """

        name = str(raw_name or "").strip()
        exclude = getattr(self, "_exclude_names", None) or []
        if exclude and glob_list_match(name, exclude):
            return False
        include = getattr(self, "_include_names", None) or []
        if not include:
            return True
        return glob_list_match(name, include)

    def _mac_allowed(self, mac: object) -> bool:
        """Brief: MAC allow/block filters (separator-insensitive).

        Inputs:
          - mac: Raw MAC string.
        Outputs:
          - True when MAC is allowed. Empty MAC fails only when include_macs set.
        """

        key = normalize_mac_key(mac)
        exclude = getattr(self, "_exclude_macs", None) or set()
        if key and key in exclude:
            return False
        include = getattr(self, "_include_macs", None) or set()
        if not include:
            return True
        return bool(key) and key in include

    def _network_meta_from_row(self, row: dict[str, Any]) -> dict[str, str]:
        """Brief: Best-effort network/vlan fields from a client/device row.

        Inputs:
          - row: Integration API object (may include undocumented extras).
        Outputs:
          - dict with optional keys: network_id, network_name, vlan.
        """

        out: dict[str, str] = {}
        for key in ("networkId", "network_id", "network"):
            val = row.get(key)
            if val is not None and str(val).strip():
                text = str(val).strip()
                # bare network id vs name: store both candidates under id/name.
                if key in ("networkId", "network_id"):
                    out["network_id"] = text
                else:
                    out.setdefault("network_name", text)
                    out.setdefault("network_id", text)
                break
        for key in ("networkName", "network_name", "lan_name"):
            val = row.get(key)
            if val is not None and str(val).strip():
                out["network_name"] = str(val).strip()
                break
        for key in ("vlanId", "vlan_id", "vlan"):
            val = row.get(key)
            if val is not None and str(val).strip() != "":
                out["vlan"] = str(val).strip()
                break
        return out

    def _networks_for_site(
        self, client: _UnifiClient, site_id: str
    ) -> list[dict[str, str]]:
        """Brief: List site networks as {id,name,vlan} dicts.

        Inputs:
          - client: UniFi API client.
          - site_id: Site UUID.
        Outputs:
          - Normalized network rows (best-effort; empty on failure).
        """

        try:
            raw = client.list_paginated(f"sites/{site_id}/networks")
        except Exception as exc:
            logger.debug("networks list failed for site %s: %s", site_id, exc)
            return []
        out: list[dict[str, str]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            nid = str(item.get("id") or "").strip()
            name = str(item.get("name") or "").strip()
            vlan = item.get("vlanId")
            if vlan is None:
                vlan = item.get("vlan")
            vlan_s = (
                str(vlan).strip()
                if vlan is not None and str(vlan).strip() != ""
                else ""
            )
            if not (nid or name or vlan_s):
                continue
            out.append({"id": nid, "name": name, "vlan": vlan_s})
        return out

    def _network_allowed(
        self,
        *,
        row_meta: dict[str, str],
        networks: list[dict[str, str]],
        ip_text: str,
    ) -> bool:
        """Brief: Apply include/exclude network name/id and VLAN filters.

        Inputs:
          - row_meta: network_id/name/vlan extracted from the row.
          - networks: Site network inventory (may be empty).
          - ip_text: Client/device IP (reserved for future CIDR match).
        Outputs:
          - True when network/vlan filters pass (or none configured).
        """

        _ = ip_text  # reserved; Integration overview has no stable subnet today
        inc_net = getattr(self, "_include_networks", None) or []
        exc_net = getattr(self, "_exclude_networks", None) or []
        inc_vlan = getattr(self, "_include_vlans", None) or set()
        exc_vlan = getattr(self, "_exclude_vlans", None) or set()
        if not (inc_net or exc_net or inc_vlan or exc_vlan):
            return True

        # Resolve row network against inventory by id/name when possible.
        rid = (row_meta.get("network_id") or "").strip()
        rname = (row_meta.get("network_name") or "").strip()
        rvlan = (row_meta.get("vlan") or "").strip()
        matched: list[dict[str, str]] = []
        for net in networks:
            nid = net.get("id") or ""
            nname = net.get("name") or ""
            if rid and rid == nid:
                matched.append(net)
            elif rname and rname.lower() == nname.lower():
                matched.append(net)
        if not matched and (rid or rname or rvlan):
            matched.append({"id": rid, "name": rname, "vlan": rvlan})
        # If filters require network identity but row has none, fail closed on
        # include lists; exclude-only still allows unknown rows.
        if not matched:
            if inc_net or inc_vlan:
                return False
            return True

        def _net_tokens(net: dict[str, str]) -> list[str]:
            return [
                t
                for t in (
                    net.get("id") or "",
                    net.get("name") or "",
                    (net.get("name") or "").lower(),
                )
                if t
            ]

        if exc_net:
            for net in matched:
                for tok in _net_tokens(net):
                    if any(
                        tok.lower() == str(p).strip().lower()
                        or fnmatch.fnmatchcase(tok.lower(), str(p).strip().lower())
                        for p in exc_net
                        if str(p).strip()
                    ):
                        return False
        if exc_vlan:
            for net in matched:
                vlan = (net.get("vlan") or "").strip()
                if vlan and vlan in exc_vlan:
                    return False

        if inc_net:
            ok = False
            for net in matched:
                for tok in _net_tokens(net):
                    if any(
                        tok.lower() == str(p).strip().lower()
                        or fnmatch.fnmatchcase(tok.lower(), str(p).strip().lower())
                        for p in inc_net
                        if str(p).strip()
                    ):
                        ok = True
                        break
                if ok:
                    break
            if not ok:
                return False
        if inc_vlan:
            ok = False
            for net in matched:
                vlan = (net.get("vlan") or "").strip()
                if vlan and vlan in inc_vlan:
                    ok = True
                    break
            if not ok:
                return False
        return True

    def _site_allowed(
        self,
        site: dict[str, Any],
        *,
        endpoint_site_ids: list[str] | None = None,
    ) -> bool:
        """Brief: Whether a site passes plugin and endpoint site filters.

        Inputs:
          - site: Site overview dict with id/name.
          - endpoint_site_ids: Optional per-endpoint UUID allowlist.
        Outputs:
          - True when the site should be inventoried.
        """

        sid = str(site.get("id") or "").strip()
        sname = str(site.get("name") or site.get("internalName") or "").strip().lower()
        ep_ids = {str(x).strip() for x in (endpoint_site_ids or []) if str(x).strip()}
        if ep_ids and sid not in ep_ids:
            return False
        if sid in (getattr(self, "_exclude_site_ids", None) or set()):
            return False
        if sname and sname in (getattr(self, "_exclude_site_names", None) or set()):
            return False
        plugin_ids = getattr(self, "_site_ids", None) or set()
        plugin_names = getattr(self, "_site_names", None) or set()
        if plugin_ids and sid not in plugin_ids:
            return False
        if plugin_names and sname not in plugin_names:
            return False
        return True

    def _format_txt_line(
        self,
        *,
        kind: str,
        canonical: str,
        v4: list[str],
        v6: list[str],
        mac: str,
        row_type: str,
        site_name: str,
        model: str = "",
        state: str = "",
        endpoint_label: str = "",
    ) -> str:
        """Brief: Build a compact TXT summary line for one host.

        Inputs:
          - kind/canonical/addresses/mac/type/site/model/state/endpoint.
        Outputs:
          - Sanitized single TXT character-string.
        """

        parts: list[str] = [f"kind={kind}"]
        display = canonical.split(".", 1)[0] if canonical else ""
        if display:
            parts.append(f"name={display}")
        if v4:
            parts.append(f"ans4={','.join(v4[:4])}")
        if v6:
            parts.append(f"ans6={','.join(v6[:4])}")
        if mac:
            parts.append(f"mac={mac}")
        if row_type:
            parts.append(f"type={row_type}")
        if state:
            parts.append(f"state={state}")
        if model:
            parts.append(f"model={model}")
        if site_name:
            parts.append(f"site={site_name}")
        if endpoint_label:
            parts.append(f"endpoint={endpoint_label}")
        return sanitize_txt_chunk(" ".join(parts))

    def _publish_row(
        self,
        *,
        kind: str,
        row: dict[str, Any],
        site: dict[str, Any],
        endpoint: dict[str, object],
        ep_ttl: int,
        ep_suffix: str,
        ep_label: str,
        new_v4: dict[str, list[str]],
        new_v6: dict[str, list[str]],
        new_reverse: dict[str, str],
        new_ttl_v4: dict[str, int],
        new_ttl_v6: dict[str, int],
        new_ttl_ptr: dict[str, int],
        new_txt: dict[str, list[str]],
        new_ttl_txt: dict[str, int],
        hosts_meta: list[dict[str, object]],
    ) -> bool:
        """Brief: Map one client/device row into DNS maps when usable.

        Inputs:
          - kind: \"client\" or \"device\".
          - row/site/endpoint and mutable map accumulators.
        Outputs:
          - True when at least one name was published.
        """

        raw_name = str(row.get("name") or "").strip()
        mac = str(row.get("macAddress") or row.get("mac") or "").strip()
        row_type = str(row.get("type") or kind).strip()
        state = str(row.get("state") or "").strip()
        model = str(row.get("model") or "").strip()
        site_name = str(site.get("name") or site.get("internalName") or "").strip()
        site_id = str(site.get("id") or "").strip()
        networks = list(endpoint.get("_networks") or [])  # type: ignore[arg-type]

        if not self._kind_allowed(kind):
            return False
        if kind == "client" and not self._client_type_allowed(row_type):
            return False
        if not self._state_allowed(state, kind=kind):
            return False
        if not self._name_allowed(raw_name):
            return False
        if not self._mac_allowed(mac):
            return False

        ip_raw = str(row.get("ipAddress") or row.get("ip") or "").strip()
        net_meta = self._network_meta_from_row(row)
        if not self._network_allowed(
            row_meta=net_meta, networks=networks, ip_text=ip_raw
        ):
            return False
        v4, v6 = self._split_ip(ip_raw) if ip_raw else ([], [])
        host_v4 = endpoint.get("host_ipv4")
        host_v6 = endpoint.get("host_ipv6")
        if host_v4 is not None:
            v4 = [str(host_v4)]
        if host_v6 is not None:
            v6 = [str(host_v6)]
        v4, v6 = apply_address_limit(v4, v6, getattr(self, "_address_limit", 0))
        if not v4 and not v6:
            return False

        canonical, names = self._names_for_row(name=raw_name, mac=mac, suffix=ep_suffix)
        if not names:
            logger.debug(
                "skipping %s with no usable DNS name (raw=%r mac=%r)",
                kind,
                raw_name,
                mac,
            )
            return False

        for key in names:
            new_ttl_v4.setdefault(key, ep_ttl)
            new_ttl_v6.setdefault(key, ep_ttl)
            if v4:
                existing = new_v4.setdefault(key, [])
                for ip in v4:
                    if ip not in existing:
                        existing.append(ip)
                    try:
                        ptr = ipaddress.ip_address(ip).reverse_pointer
                        new_reverse.setdefault(ptr, canonical)
                        new_ttl_ptr[ptr] = ep_ttl
                    except ValueError:
                        continue
            if v6:
                existing = new_v6.setdefault(key, [])
                for ip in v6:
                    if ip not in existing:
                        existing.append(ip)
                    try:
                        ptr = ipaddress.ip_address(ip).reverse_pointer
                        new_reverse.setdefault(ptr, canonical)
                        new_ttl_ptr[ptr] = ep_ttl
                    except ValueError:
                        continue

        line = self._format_txt_line(
            kind=kind,
            canonical=canonical,
            v4=v4,
            v6=v6,
            mac=mac,
            row_type=row_type,
            site_name=site_name,
            model=model,
            state=state,
            endpoint_label=ep_label,
        )
        for owner in names:
            new_txt.setdefault(owner, []).append(line)
            new_ttl_txt[owner] = ep_ttl

        if self._discovery:
            disc = discovery_owner(
                "_clients" if kind == "client" else "_devices",
                ep_suffix,
            )
            new_txt.setdefault(disc, []).append(line)
            new_ttl_txt[disc] = int(self._ttl)

        hosts_meta.append(
            {
                "kind": kind,
                "name": canonical,
                "display_name": raw_name or canonical,
                "ipv4": list(v4),
                "ipv6": list(v6),
                "mac": mac or None,
                "type": row_type or None,
                "state": state or None,
                "model": model or None,
                "site": site_name or None,
                "site_id": site_id or None,
                "network": net_meta.get("network_name")
                or net_meta.get("network_id")
                or None,
                "vlan": net_meta.get("vlan") or None,
                "endpoint": ep_label,
                "ttl": ep_ttl,
            }
        )
        return True

    def _reload_from_unifi(self) -> None:
        """Brief: Rebuild host maps from the first healthy UniFi endpoint.

        Inputs:
          - None (uses self._endpoints).
        Outputs:
          - None; updates forward/reverse/TXT maps under lock on success.
        """

        new_v4: dict[str, list[str]] = {}
        new_v6: dict[str, list[str]] = {}
        new_reverse: dict[str, str] = {}
        new_ttl_v4: dict[str, int] = {}
        new_ttl_v6: dict[str, int] = {}
        new_ttl_ptr: dict[str, int] = {}
        new_txt: dict[str, list[str]] = {}
        new_ttl_txt: dict[str, int] = {}
        hosts_meta: list[dict[str, object]] = []

        loaded = False
        last_error: Exception | None = None
        reload_stats: dict[str, object] = {}

        for endpoint in self._endpoints:
            ep_url = str(endpoint.get("url") or "")
            ep_key = f"endpoint:{ep_url}"
            ep_label = self._endpoint_label(endpoint)
            client = self._get_client(endpoint)
            if client is None:
                continue

            try:
                # Health / version probe.
                try:
                    client.get_json("info")
                except Exception as exc:
                    # Some builds may 404 info; still try sites.
                    logger.debug("info probe failed for %s: %s", ep_label, exc)

                sites_raw = client.list_paginated("sites")
                sites = [
                    s
                    for s in sites_raw
                    if self._site_allowed(
                        s, endpoint_site_ids=list(endpoint.get("site_ids") or [])
                    )
                ]
                if not sites and sites_raw:
                    logger.warning(
                        "endpoint %s: %d site(s) listed but none matched filters",
                        ep_label,
                        len(sites_raw),
                    )

                ep_ttl_override = endpoint.get("ttl")
                try:
                    ep_ttl = (
                        int(ep_ttl_override)
                        if ep_ttl_override is not None
                        else int(self._ttl)
                    )
                except Exception:
                    ep_ttl = int(self._ttl)

                ep_suffix = str(
                    endpoint.get("suffix") or getattr(self, "_suffix", "") or ""
                )
                if ep_suffix:
                    ep_suffix = normalize_suffix(ep_suffix)

                extra: dict[str, Any] = {}
                if self._api_filter:
                    extra["filter"] = self._api_filter

                if self._discovery and sites:
                    sites_owner = discovery_owner("_sites", ep_suffix)
                    for site in sites:
                        sid = str(site.get("id") or "").strip()
                        sname = str(
                            site.get("name") or site.get("internalName") or ""
                        ).strip()
                        line = sanitize_txt_chunk(
                            f"site={sname or sid} id={sid} endpoint={ep_label}"
                        )
                        new_txt.setdefault(sites_owner, []).append(line)
                    new_ttl_txt[sites_owner] = int(self._ttl)

                scanned = 0
                published = 0
                for site in sites:
                    site_id = str(site.get("id") or "").strip()
                    if not site_id:
                        continue
                    # Stash per-site network inventory on the endpoint dict for
                    # row filters (VLAN/network name matching).
                    if getattr(self, "_need_networks", False):
                        endpoint["_networks"] = self._networks_for_site(client, site_id)
                    else:
                        endpoint["_networks"] = []

                    if self._kind_allowed("client"):
                        clients = client.list_paginated(
                            f"sites/{site_id}/clients",
                            extra_params=extra or None,
                        )
                        for row in clients:
                            scanned += 1
                            if self._publish_row(
                                kind="client",
                                row=row,
                                site=site,
                                endpoint=endpoint,
                                ep_ttl=ep_ttl,
                                ep_suffix=ep_suffix,
                                ep_label=ep_label,
                                new_v4=new_v4,
                                new_v6=new_v6,
                                new_reverse=new_reverse,
                                new_ttl_v4=new_ttl_v4,
                                new_ttl_v6=new_ttl_v6,
                                new_ttl_ptr=new_ttl_ptr,
                                new_txt=new_txt,
                                new_ttl_txt=new_ttl_txt,
                                hosts_meta=hosts_meta,
                            ):
                                published += 1
                    if self._kind_allowed("device"):
                        devices = client.list_paginated(
                            f"sites/{site_id}/devices",
                            extra_params=extra or None,
                        )
                        for row in devices:
                            scanned += 1
                            if self._publish_row(
                                kind="device",
                                row=row,
                                site=site,
                                endpoint=endpoint,
                                ep_ttl=ep_ttl,
                                ep_suffix=ep_suffix,
                                ep_label=ep_label,
                                new_v4=new_v4,
                                new_v6=new_v6,
                                new_reverse=new_reverse,
                                new_ttl_v4=new_ttl_v4,
                                new_ttl_v6=new_ttl_v6,
                                new_ttl_ptr=new_ttl_ptr,
                                new_txt=new_txt,
                                new_ttl_txt=new_ttl_txt,
                                hosts_meta=hosts_meta,
                            ):
                                published += 1

                condition_log.note_condition_ok(
                    self,
                    ep_key,
                    "endpoint %s is reachable again",
                    ep_label,
                )
                # Stash reload stats for the post-swap summary log.
                reload_stats = {
                    "ep_label": ep_label,
                    "sites": len(sites),
                    "scanned": scanned,
                    "published": published,
                    "skipped": max(0, scanned - published),
                }
                loaded = True
                # Failover model: stop after first healthy endpoint.
                break
            except Exception as exc:
                last_error = exc
                condition_log.note_condition_failure(
                    self,
                    ep_key,
                    "failed to load inventory from %s: %s",
                    ep_label,
                    exc,
                )
                continue

        if not loaded:
            if last_error is not None:
                condition_log.note_condition_failure(
                    self,
                    "unifi-inventory",
                    "all UniFi endpoints failed; keeping previous mappings: %s",
                    last_error,
                )
            else:
                condition_log.note_condition_failure(
                    self,
                    "unifi-inventory",
                    "no UniFi endpoints available; keeping previous mappings",
                )
            return

        if not new_v4 and not new_v6:
            condition_log.note_condition_failure(
                self,
                "no-hostname-ip-mappings",
                "UniFi inventory loaded but no hostname/IP mappings were published",
            )
        else:
            condition_log.note_condition_ok(self, "unifi-inventory")
            condition_log.note_condition_ok(self, "no-hostname-ip-mappings")

        if new_txt:
            for owner, lines in new_txt.items():
                if owner.startswith("_sites"):
                    lines.insert(0, f"sites={len(lines)}")
                elif owner.startswith("_devices"):
                    lines.insert(0, f"devices={len(lines)}")
                elif owner.startswith("_clients"):
                    lines.insert(0, f"clients={len(lines)}")
                else:
                    lines.insert(0, f"hosts={len(lines)}")

        hosts_meta.sort(
            key=lambda r: (
                str(r.get("kind") or ""),
                str(r.get("site") or ""),
                str(r.get("name") or ""),
            )
        )

        new_names = {
            str(h.get("name") or "").strip()
            for h in hosts_meta
            if str(h.get("name") or "").strip()
        }
        n_clients = sum(1 for h in hosts_meta if h.get("kind") == "client")
        n_devices = sum(1 for h in hosts_meta if h.get("kind") == "device")

        with self._lock:
            prev_names = {
                str(h.get("name") or "").strip()
                for h in getattr(self, "_hosts_meta", [])
                if str(h.get("name") or "").strip()
            }
            added = new_names - prev_names
            dropped = prev_names - new_names
            host_churn = bool(added or dropped)

            self._forward_v4 = new_v4
            self._forward_v6 = new_v6
            self._reverse = new_reverse
            self._ttl_v4 = new_ttl_v4
            self._ttl_v6 = new_ttl_v6
            self._ttl_ptr = new_ttl_ptr
            self._aggregate_txt = new_txt
            self._ttl_txt = new_ttl_txt
            self._hosts_meta = hosts_meta

        # INFO only when host membership changes; quiet unchanged periodic polls.
        msg = (
            "loaded %d hosts (%d clients, %d devices; %d A, %d AAAA, %d PTR names) "
            "from %s (sites=%d scanned=%d published=%d skipped=%d"
            "%s)"
        )
        churn_bit = ""
        if host_churn:
            churn_bit = f"; added={len(added)} dropped={len(dropped)}"
        args = (
            len(hosts_meta),
            n_clients,
            n_devices,
            len(new_v4),
            len(new_v6),
            len(new_reverse),
            str(reload_stats.get("ep_label") or ""),
            int(reload_stats.get("sites") or 0),
            int(reload_stats.get("scanned") or 0),
            int(reload_stats.get("published") or 0),
            int(reload_stats.get("skipped") or 0),
            churn_bit,
        )
        if host_churn:
            logger.info(msg, *args)
        else:
            logger.debug(msg, *args)

    def get_admin_pages(self) -> list[AdminPageSpec]:
        """Brief: Describe the UnifiHosts admin page for the web UI.

        Inputs:
          - None.
        Outputs:
          - list[AdminPageSpec] with a single UniFi hosts page.
        """

        return [
            AdminPageSpec(
                slug="unifi-hosts",
                title="UniFi",
                description=(
                    "Clients and devices discovered by the UnifiHosts plugin "
                    "(uses /api/v1/plugins/{name}/unifi_hosts for data)."
                ),
                layout="one_column",
                kind="unifi_hosts",
            )
        ]

    def get_admin_ui_descriptor(self) -> dict[str, object]:
        """Brief: Describe UnifiHosts admin UI using a generic snapshot layout.

        Inputs:
          - None.
        Outputs:
          - dict with name, title, order, endpoints, layout.
        """

        plugin_name = getattr(self, "name", "unifi")
        try:
            pages = self.get_admin_pages()
        except Exception:
            pages = []
        page = pages[0] if pages else None
        base_title = getattr(page, "title", None) or "UniFi"
        if plugin_name:
            title = f"{base_title} ({plugin_name})"
        else:
            title = base_title

        snapshot_url = f"/api/v1/plugins/{plugin_name}/unifi_hosts"
        layout: dict[str, object] = {
            "sections": [
                {
                    "id": "summary",
                    "title": "Summary",
                    "type": "kv",
                    "path": "summary",
                    "rows": [
                        {"key": "total_hosts", "label": "Hosts"},
                        {"key": "total_clients", "label": "Clients"},
                        {"key": "total_devices", "label": "Devices"},
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
                        {"key": "id", "label": "ID"},
                        {"key": "url", "label": "URL"},
                        {"key": "interval", "label": "Interval (s)"},
                        {"key": "host_ipv4", "label": "Host IPv4"},
                        {"key": "host_ipv6", "label": "Host IPv6"},
                        {"key": "suffix", "label": "Suffix"},
                    ],
                },
                {
                    "id": "hosts",
                    "title": "Hosts",
                    "type": "table",
                    "path": "hosts",
                    "columns": [
                        {"key": "name", "label": "Name"},
                        {"key": "kind", "label": "Kind"},
                        {"key": "ipv4", "label": "IPv4", "join": ", "},
                        {"key": "type", "label": "Type"},
                        {"key": "state", "label": "State"},
                        {"key": "mac", "label": "MAC"},
                        {"key": "network", "label": "Network"},
                        {"key": "vlan", "label": "VLAN"},
                        {"key": "site", "label": "Site"},
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
        """Brief: Summarize current UnifiHosts mappings for the admin web UI.

        Inputs:
          - None (uses in-memory maps under a lock).
        Outputs:
          - dict with summary and hosts list (JSON-safe).
        """

        with self._lock:
            hosts = [dict(row) for row in getattr(self, "_hosts_meta", [])]
            endpoints_view: list[dict[str, object]] = []
            for ep in getattr(self, "_endpoints", []):
                if not isinstance(ep, dict):
                    continue
                endpoints_view.append(
                    {
                        "id": ep.get("id"),
                        "url": str(ep.get("url", "")),
                        "interval": float(ep.get("interval", 0.0) or 0.0),
                        "host_ipv4": ep.get("host_ipv4"),
                        "host_ipv6": ep.get("host_ipv6"),
                        "suffix": ep.get("suffix") or None,
                    }
                )
            n_clients = sum(1 for h in hosts if h.get("kind") == "client")
            n_devices = sum(1 for h in hosts if h.get("kind") == "device")
            plugin_suffix = str(getattr(self, "_suffix", "") or "")
            summary: dict[str, object] = {
                "total_hosts": len(hosts),
                "total_clients": n_clients,
                "total_devices": n_devices,
                "endpoints": endpoints_view,
                "reload_interval": float(getattr(self, "_reload_interval", 0.0) or 0.0),
                "suffix": plugin_suffix or None,
            }
        return {"summary": summary, "hosts": hosts}

    def shutdown(self) -> None:
        """Brief: Stop the poller and close HTTP clients.

        Inputs:
          - None.
        Outputs:
          - None.
        """

        try:
            super().shutdown()
        except Exception as exc:
            logger.debug("UnifiHosts super.shutdown failed: %s", exc)
        for client in list(getattr(self, "_clients", {}).values()):
            try:
                client.close()
            except Exception as exc:
                logger.debug("UnifiHosts client close failed: %s", exc)
                continue
        self._clients = {}
