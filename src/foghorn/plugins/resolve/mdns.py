from __future__ import annotations

import ipaddress
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from dnslib import A, AAAA, PTR, QTYPE, RR, SRV, TXT, DNSHeader, DNSRecord
from pydantic import BaseModel, Field, validator

from cachetools import TTLCache  # type: ignore[import]
from foghorn.utils.register_caches import registered_cached

from foghorn.plugins.resolve.base import (
    AdminPageSpec,
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

logger = logging.getLogger(__name__)

# Default service types to browse when `service_types` is omitted from the
# MdnsBridge config. This mirrors the curated list shipped in
# `config/config.yaml` so that, in the common case, users can omit the
# field and still get rich discovery.
DEFAULT_MDNS_SERVICE_TYPES: List[str] = [
    "_services._dns-sd._udp.local",  # Everything
    "_services._dns-sd._tcp.local",  # Everything (non-standard)
    "_1password._tcp.local",
    "_a-d-sync._tcp.local",
    "_adb-tls-pairing._tcp.local",
    "_addressbook._tcp.local",
    "_adpro-setup._tcp.local",
    "_aecoretech._tcp.local",
    "_aeroflex._tcp.local",
    "_afpovertcp._tcp.local",
    "_airplay._tcp.local",
    "_airport._tcp.local",
    "_apple-sasl-2._tcp.local",
    "_apple-sasl._tcp.local",
    "_appletv-v2._tcp.local",
    "_appletv-v3._tcp.local",
    "_axis-video._tcp.local",
    "_bacnet._ip.local",
    "_bond._tcp.local",
    "_cups._tcp.local",
    "_daap._tcp.local",
    "_dhcp._udp.local",
    "_dns-sd._udp.local",
    "_elg._tcp.local",
    "_eppc._tcp.local",
    "_esxi._tcp.local",
    "_gameport._tcp.local",
    "_googlecast._tcp.local",
    "_hap._tcp.local",
    "_hap._udp.local",
    "_homekit._tcp.local",
    "_http-alt._tcp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_ipp-usb._tcp.local",
    "_ipp._tcp.local",
    "_jedilib._tcp.local",
    "_kftp._tcp.local",
    "_khttp._tcp.local",
    "_khttps._tcp.local",
    "_kshell._tcp.local",
    "_ldap._tcp.local",
    "_macstadium._tcp.local",
    "_matlab-http._tcp.local",
    "_matter._tcp.local",
    "_matterc._udp.local",
    "_mediaremotetv._tcp.local",
    "_microsoft-ds._tcp.local",
    "_mobilinux._tcp.local",
    "_nchan._tcp.local",
    "_netware._ip.local",
    "_nfs._tcp.local",
    "_ni-virtins._tcp.local",
    "_ni-visa._tcp.local",
    "_nut._tcp.local",
    "_obex._tcp.local",
    "_pdl-datastream._tcp.local",
    "_pdl-service._tcp.local",
    "_presence._tcp.local",
    "_presence._ucp.local",
    "_printer._tcp.local",
    "_ps._tcp.local",
    "_qsync._tcp.local",
    "_raop._tcp.local",
    "_rdm._tcp.local",
    "_rtspu._udp.local",
    "_sane._tcp.local",
    "_services._dns-sd._udp.local",
    "_sips._tcp.local",
    "_slp._udp.local",
    "_smb._tcp.local",
    "_spotify-connect._tcp.local",
    "_ssh._tcp.local",
    "_stun-behavior._udp.local",
    "_stun-tls._tcp.local",
    "_stun._udp.local",
    "_sub._tcp.local",
    "_targus._tcp.local",
    "_telnet._tcp.local",
    "_tftp._udp.local",
    "_time._tcp.local",
    "_touch-able._tcp.local",
    "_upnp._tcp.local",
    "_uscan._tcp.local",
    "_vnc._tcp.local",
    "_vscp._tcp.local",
    "_waste._tcp.local",
    "_webdav._tcp.local",
    "_webdavs._tcp.local",
    "_webex._tcp.local",
    "_wled._tcp.local",
    "_workstation._tcp.local",
    "_xbox._tcp.local",
    "_xserveraid._tcp.local",
    "_zenginkyo-1._tcp.local",
]

# Maximum number of PTR targets for which we will synthesize additional
# host A/AAAA glue records. When a PTR response has more than this many
# targets, the answer will contain only PTRs to avoid overly large
# responses and surprising behavior.
PTR_ADDITIONAL_HOST_LIMIT = 2

# Short-lived caches for hot, pure-ish helper methods. These are strictly
# internal to the plugin and do not affect resolver statistics semantics.
_MDNS_NORMALIZE_OWNER_CACHE: TTLCache = TTLCache(maxsize=4096, ttl=3600)
_MDNS_MIRROR_SUFFIXES_CACHE: TTLCache = TTLCache(maxsize=4096, ttl=3600)
_MDNS_SANITIZE_QNAME_CACHE: TTLCache = TTLCache(maxsize=2048, ttl=3600)


class MdnsBridgeConfig(BaseModel):
    """Brief: Typed configuration model for MdnsBridge.

    Inputs:
      - domain: str DNS domain suffix to treat as the mDNS namespace (default: `.local`).
      - ttl: int DNS TTL to apply to synthesized answers.
      - network_enabled: bool controlling whether the plugin starts active
        zeroconf browsing and uses `get_service_info()` to fetch ServiceInfo. When
        False, the plugin still initializes internal state but does not touch the
        network (useful for tests).
      - include_ipv4: bool controlling whether A records are synthesized.
      - include_ipv6: bool controlling whether AAAA records are synthesized.
      - info_timeout_ms: int timeout in milliseconds for fetching ServiceInfo.
      - zeroconf_interfaces: Which interfaces Zeroconf should bind to.
        Accepts: "default" | "all" | list[str] of interface IPs.
      - zeroconf_ip_version: Which IP versions Zeroconf should use.
        Accepts: "v4" | "v6" | "all".
      - zeroconf_unicast: bool passed to Zeroconf(unicast=...).
      - service_types: Optional list[str] of service types to browse directly
        (e.g., `_http._tcp.local.`). Useful when `_services._dns-sd._udp.local.`
        is not advertised on the network.

    Outputs:
      - MdnsBridgeConfig instance.
    """

    domain: str = Field(default=".local")
    ttl: int = Field(default=300, ge=0)
    zeroconf_interfaces: object = Field(default="default")
    zeroconf_ip_version: Optional[str] = Field(default=None)
    zeroconf_unicast: bool = False
    service_types: List[str] = Field(default_factory=list)

    @validator("domain", pre=True)
    def _normalize_domain(cls, v):  # type: ignore[no-untyped-def]  # pragma: nocover config normalization
        """Brief: Normalize the configured mDNS domain suffix.

        Inputs:
          - v: Domain string (e.g. `.local`, `local`, `.example`).

        Outputs:
          - str: Domain with a leading dot and no trailing dot.

        Example:
          - `local` -> `.local`
          - `.local.` -> `.local`
        """

        s = str(v or ".local").strip()
        if not s:
            s = ".local"
        if not s.startswith("."):
            s = "." + s
        return s.rstrip(".")

    @validator("zeroconf_interfaces", pre=True)
    def _normalize_zeroconf_interfaces(cls, v):  # type: ignore[no-untyped-def]  # pragma: nocover config normalization
        """Brief: Normalize zeroconf_interfaces into a supported representation.

        Inputs:
          - v: "default" | "all" | list of interface IP strings.

        Outputs:
          - object: Normalized value passed to Zeroconf(interfaces=...).
        """

        if v is None:
            return "default"
        if isinstance(v, str):
            s = v.strip().lower()
            if s in {"default", "all"}:
                return s
            # A single IP string.
            return [s]
        if isinstance(v, (list, tuple)):
            out = []
            for item in v:
                if item is None:
                    continue
                s = str(item).strip()
                if s:
                    out.append(s)
            return out
        return v

    @validator("zeroconf_ip_version", pre=True)
    def _normalize_zeroconf_ip_version(cls, v):  # type: ignore[no-untyped-def]  # pragma: nocover config normalization
        """Brief: Normalize zeroconf_ip_version.

        Inputs:
          - v: "v4" | "v6" | "all" (case-insensitive), or None.

        Outputs:
          - Optional[str]: Normalized string or None.
        """

        if v is None:
            return None
        s = str(v).strip().lower()
        if not s:
            return None
        if s in {"v4", "v4only", "ipv4", "4"}:
            return "v4"
        if s in {"v6", "v6only", "ipv6", "6"}:
            return "v6"
        if s in {"all", "both"}:
            return "all"
        return s

    network_enabled: bool = True
    include_ipv4: bool = True
    include_ipv6: bool = True
    info_timeout_ms: int = Field(default=1500, ge=0)

    class Config:
        extra = "allow"


@dataclass(frozen=True)
class _SrvValue:
    """Brief: Internal SRV value.

    Inputs:
      - priority: SRV priority.
      - weight: SRV weight.
      - port: SRV port.
      - target: SRV target hostname (FQDN with trailing dot recommended).

    Outputs:
      - _SrvValue instance.
    """

    priority: int
    weight: int
    port: int
    target: str


@dataclass
class _ServiceState:
    """Brief: Track last-seen timestamps, status, host, and uptime for mDNS services.

    Inputs:
      - status: Current status string (for example, ``"up"`` or ``"down"``).
      - last_seen: ISO 8601 UTC timestamp for the most recent event affecting
        the service.
      - host: Last observed SRV target hostname for this service instance
        (normalized, lowercased, no trailing dot). This is used so that the
        admin UI can continue to show which host a service was last seen on
        even after it goes down.
      - up_since: ISO 8601 UTC timestamp marking the start of the current
        "up" period. When status is ``"up"``, uptime is derived as
        ``now - up_since``; when status is ``"down"``, this field is
        preserved but not directly surfaced.

    Outputs:
      - _ServiceState instance.
    """

    status: str
    last_seen: str
    host: str = ""
    up_since: str = ""


@plugin_aliases("mdns", "zeroconf", "dns_sd", "dnssd", "bonjour")
class MdnsBridge(BasePlugin):
    """Brief: Expose mDNS/DNS-SD (zeroconf) data as DNS records.

    Inputs:
      - name: Optional plugin label.
      - **config: MdnsBridgeConfig-compatible fields.

    Outputs:
      - Plugin instance that can answer PTR/SRV/TXT/A/AAAA for discovered
        services under the configured mDNS domain.

    Notes:
      - mDNS discovery only works on the local L2 network segment. When running
        Foghorn inside Docker, the container must share the host network (for
        example, using `--net=host`) or the mDNS browser will not see any
        services.
      - This plugin is intentionally best-effort: when a query is not known it
        returns None to allow normal upstream resolution.
    """

    @classmethod
    def get_config_model(cls):  # pragma: nocover simple accessor
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - MdnsBridgeConfig class.
        """

        return MdnsBridgeConfig

    def setup(
        self,
    ) -> (
        None
    ):  # pragma: nocover network/zeroconf initialization (covered via integration tests)
        """Brief: Initialize internal record caches and start zeroconf browsing.

        Inputs:
          - domain (str): DNS suffix under which to *serve* discovered mDNS data.
          - ttl (int): TTL for synthesized answers.
          - network_enabled (bool): When True, start background zeroconf browsing.
          - include_ipv4 (bool): When True, synthesize A records.
          - include_ipv6 (bool): When True, synthesize AAAA records.
          - info_timeout_ms (int): Timeout in milliseconds for fetching ServiceInfo.

        Outputs:
          - None.
        """

        self._lock = threading.RLock()

        # Validate/normalize config once for the setup lifecycle.
        self._config_model = MdnsBridgeConfig(**(self.config or {}))

        # Prefer per-plugin logger when available.
        log = getattr(self, "logger", logger)
        log.info(
            "MdnsBridge setup: dns_domain=%s mdns_domain=%s network_enabled=%s include_ipv4=%s include_ipv6=%s ttl=%s info_timeout_ms=%s",
            str(getattr(self._config_model, "domain", ".local")),
            ".local",
            bool(getattr(self._config_model, "network_enabled", True)),
            bool(getattr(self._config_model, "include_ipv4", True)),
            bool(getattr(self._config_model, "include_ipv6", True)),
            int(getattr(self._config_model, "ttl", 300) or 0),
            int(getattr(self._config_model, "info_timeout_ms", 1500) or 0),
        )

        # mDNS itself always uses `.local`, but we may *serve* the discovered data
        # under one or more DNS suffixes.
        self._mdns_domain = ".local"

        # Primary DNS domain is stored normalized as ".suffix" with no trailing dot.
        self._dns_domain = str(self._config_model.domain or ".local")

        # Optional: allow additional DNS domains via config key `domains`, which may
        # be a string or list of strings. Each value is normalized to ".suffix".
        dns_domains: Set[str] = {self._dns_domain}
        extra_domains = getattr(self._config_model, "domains", None)
        if isinstance(extra_domains, str):
            extra_domains = [extra_domains]
        if isinstance(extra_domains, (list, tuple, set)):
            for dom in extra_domains:
                s = str(dom or "").strip()
                if not s:
                    continue
                if not s.startswith("."):
                    s = "." + s
                s = s.rstrip(".")
                dns_domains.add(s)
        self._dns_domains: Set[str] = dns_domains

        # For safety, require an explicit opt-in before serving answers under
        # `.local` as the DNS domain. This prevents accidental shadowing of the
        # host's own mDNS namespace.

        # Records are stored keyed by *lowercased* owner name without trailing dot.
        self._ptr: Dict[str, Set[str]] = {}
        self._srv: Dict[str, _SrvValue] = {}
        self._txt: Dict[str, List[str]] = {}
        self._a: Dict[str, Set[str]] = {}
        self._aaaa: Dict[str, Set[str]] = {}
        self._service_state: Dict[str, _ServiceState] = {}

        self._ttl = int(self._config_model.ttl or 0)
        self._include_ipv4 = bool(self._config_model.include_ipv4)
        self._include_ipv6 = bool(self._config_model.include_ipv6)
        self._info_timeout_ms = int(self._config_model.info_timeout_ms or 0)

        self._zc = None
        self._browsers = []
        self._type_browsers: Dict[str, object] = {}

        if not bool(self._config_model.network_enabled):
            log.info(
                "MdnsBridge: network_enabled=false; skipping zeroconf initialization"
            )
            return

        try:
            from zeroconf import (
                IPVersion,
                InterfaceChoice,
                ServiceBrowser,
                ServiceInfo,
                ServiceStateChange,
                Zeroconf,
            )
        except Exception as exc:
            raise RuntimeError(
                'MdnsBridge requires the "zeroconf" package. Install it or disable this plugin.'
            ) from exc

        self._ServiceBrowser = ServiceBrowser
        self._ServiceInfo = ServiceInfo
        self._ServiceStateChange = ServiceStateChange

        # Provide knobs to avoid permission errors on some systems where binding
        # mDNS sockets on all interfaces or enabling IPv6 multicast can fail.
        interfaces_cfg = self._config_model.zeroconf_interfaces
        log.debug(
            "MdnsBridge: zeroconf config interfaces=%r ip_version=%r unicast=%r",
            interfaces_cfg,
            self._config_model.zeroconf_ip_version,
            bool(self._config_model.zeroconf_unicast),
        )
        if isinstance(interfaces_cfg, str):
            if interfaces_cfg == "default":
                interfaces = InterfaceChoice.Default
            else:
                interfaces = InterfaceChoice.All
        elif isinstance(interfaces_cfg, (list, tuple)):
            parsed = []
            for x in interfaces_cfg:
                try:
                    s = str(x).strip()
                    if not s:
                        continue
                    parsed.append(ipaddress.ip_address(s))
                except Exception:
                    continue
            interfaces = parsed
        else:
            interfaces = interfaces_cfg

        ip_version_cfg = (self._config_model.zeroconf_ip_version or "").lower()
        ip_version = None
        if ip_version_cfg == "v4":
            ip_version = IPVersion.V4Only
        elif ip_version_cfg == "v6":
            ip_version = IPVersion.V6Only
        elif ip_version_cfg == "all":
            ip_version = IPVersion.All

        try:
            self._zc = Zeroconf(
                interfaces=interfaces,
                unicast=bool(self._config_model.zeroconf_unicast),
                ip_version=ip_version,
            )
            log.info("MdnsBridge: Zeroconf initialized successfully")
        except PermissionError as exc:
            log.error(
                "MdnsBridge: Zeroconf failed to bind mDNS sockets (EPERM). interfaces=%r ip_version=%r unicast=%r",
                interfaces_cfg,
                self._config_model.zeroconf_ip_version,
                bool(self._config_model.zeroconf_unicast),
                exc_info=True,
            )
            raise RuntimeError(
                "MdnsBridge: Zeroconf failed to bind mDNS sockets (permission error). "
                "Try setting zeroconf_interfaces=default and/or zeroconf_ip_version=v4."
            ) from exc
        except OSError as exc:
            # Some systems report multicast/bind failures as generic OSError.
            log.error(
                "MdnsBridge: Zeroconf failed to initialize mDNS sockets: %s (interfaces=%r ip_version=%r unicast=%r)",
                exc,
                interfaces_cfg,
                self._config_model.zeroconf_ip_version,
                bool(self._config_model.zeroconf_unicast),
                exc_info=True,
            )
            raise RuntimeError(
                f"MdnsBridge: Zeroconf failed to initialize mDNS sockets: {exc}. "
                "Try setting zeroconf_interfaces=default and/or zeroconf_ip_version=v4."
            ) from exc

        # Discover all service types, then browse each type for instances.
        # Note: Some environments do not advertise `_services._dns-sd._udp.local.`.
        # In that case, configure `service_types` to browse known types directly.
        try:
            browse_name = f"_services._dns-sd._udp{self._mdns_domain}."
            log.debug("MdnsBridge: starting ServiceBrowser for %s", browse_name)
            self._browsers.append(
                ServiceBrowser(
                    self._zc,
                    browse_name,
                    handlers=[self._on_service_type_event],
                )
            )
            log.debug("MdnsBridge: ServiceBrowser started")
        except PermissionError as exc:
            log.error(
                "MdnsBridge: ServiceBrowser failed with EPERM while starting mDNS browsing",
                exc_info=True,
            )
            raise RuntimeError(
                "MdnsBridge: ServiceBrowser failed with EPERM while starting mDNS browsing. "
                "This is commonly caused by VPN/tunnel interfaces. Try setting zeroconf_interfaces to a "
                "specific LAN interface IP (e.g. your Wi-Fi/Ethernet address) and zeroconf_ip_version=v4."
            ) from exc
        except OSError as exc:
            log.error(
                "MdnsBridge: ServiceBrowser failed while starting mDNS browsing: %s",
                exc,
                exc_info=True,
            )
            raise RuntimeError(
                f"MdnsBridge: ServiceBrowser failed while starting mDNS browsing: {exc}. "
                "Try setting zeroconf_interfaces to a specific LAN interface IP and zeroconf_ip_version=v4."
            ) from exc

        # Optional: directly browse configured service types. When no list is
        # provided, fall back to a curated default set so users can omit the
        # field entirely with sane defaults.
        configured_types = list(getattr(self._config_model, "service_types", []) or [])
        effective_service_types = configured_types
        if not effective_service_types:
            try:
                from foghorn.plugins.mdns import (
                    DEFAULT_MDNS_SERVICE_TYPES,
                )  # local import to avoid cycles
            except Exception:  # pragma: no cover - defensive fallback
                DEFAULT_MDNS_SERVICE_TYPES = []  # type: ignore[assignment]
            effective_service_types = list(DEFAULT_MDNS_SERVICE_TYPES)

        for service_type in effective_service_types:
            try:
                self._start_type_browser(str(service_type))
            except Exception:
                log.debug(
                    "MdnsBridge: failed to start explicit service type browser for %r",
                    service_type,
                    exc_info=True,
                )

    @registered_cached(cache=_MDNS_NORMALIZE_OWNER_CACHE)
    def _normalize_owner(
        self, name: str
    ) -> str:  # pragma: nocover defensive normalization
        """Brief: Normalize a DNS owner name for internal dict keys.

        Inputs:
          - name: Domain name (may include trailing dot, any case).

        Outputs:
          - str: Lowercased name without trailing dot.
        """

        try:
            return str(name).rstrip(".").lower()
        except Exception:
            return str(name).lower().rstrip(".")

    def _to_dns_domain(self, fqdn: str) -> str:  # pragma: nocover suffix rewrite helper
        """Brief: Map a `.local` mDNS name to the configured DNS suffix.

        Inputs:
          - fqdn: FQDN (may or may not end with a trailing dot).

        Outputs:
          - str: Lowercased name without trailing dot. If the name ends with the
            mDNS suffix (`.local`), it is rewritten to end with the configured DNS
            suffix.

        Example:
          - `printer._ipp._tcp.local.` with dns domain `.example` ->
            `printer._ipp._tcp.example`
        """

        base = self._normalize_owner(fqdn)
        if base.endswith(self._mdns_domain):
            return base[: -len(self._mdns_domain)] + self._dns_domain
        return base

    @registered_cached(cache=_MDNS_MIRROR_SUFFIXES_CACHE)
    def _mirror_suffixes(
        self, fqdn: str
    ) -> List[str]:  # pragma: nocover suffix mapping helper
        """Brief: Map an mDNS/DNS-SD name into the configured DNS domain(s).

        Inputs:
          - fqdn: FQDN (may or may not end with a trailing dot).

        Outputs:
          - list[str]: A single normalized name (without trailing dot) suitable
            for use as an internal dict key and for answers under the configured
            DNS suffix.

        Notes:
          - mDNS discovery always happens under `.local`, but this bridge only
            *serves* records under the configured DNS domain (`self._dns_domain`).
          - `.local` never appears in synthesized answers unless
            `self._dns_domain` is explicitly configured as `.local`.
        """

        base = self._normalize_owner(fqdn)

        primary_dom = str(getattr(self, "_dns_domain", ".local") or ".local").lower()
        if not primary_dom.startswith("."):
            primary_dom = "." + primary_dom
        primary_dom = primary_dom.rstrip(".")

        dns_doms = getattr(self, "_dns_domains", {primary_dom}) or {primary_dom}
        dns_doms = {d.lower() for d in dns_doms}

        if base.endswith(".local") and any(d != ".local" for d in dns_doms):
            out: List[str] = []
            for d in sorted(dns_doms):
                if d == ".local":
                    out.append(base)
                else:
                    out.append(base[: -len(".local")] + d)
            return out

        # If the name is already using one of the configured DNS suffixes, keep it.
        for d in dns_doms:
            if d != ".local" and base.endswith(d):
                return [base]

        # For all other names (including when every configured domain is `.local`),
        # return the normalized base unchanged.
        return [base]

    def _ptr_add(self, owner: str, target: str) -> None:
        """Brief: Add a PTR mapping (owner -> target) under both suffix variants.

        Inputs:
          - owner: owner name.
          - target: target name.

        Outputs:
          - None.

        Notes:
          - Logs at DEBUG include the effective owner/target pairs added so
            operators can verify DNS-SD enumeration behavior.
        """

        owners = self._mirror_suffixes(owner)
        targets = self._mirror_suffixes(target)

        log = getattr(self, "logger", logger)
        log.debug(
            "MdnsBridge: PTR add owner=%s target=%s owners=%s targets=%s",
            self._normalize_owner(owner),
            self._normalize_owner(target),
            owners,
            targets,
        )

        for o in owners:
            s = self._ptr.setdefault(o, set())
            for t in targets:
                s.add(t)

    def _ptr_remove(
        self, owner: str, target: str
    ) -> None:  # pragma: nocover defensive cleanup path
        """Brief: Remove a PTR mapping under both suffix variants.

        Inputs:
          - owner: owner name.
          - target: target name.

        Outputs:
          - None.
        """

        owners = self._mirror_suffixes(owner)
        targets = self._mirror_suffixes(target)
        for o in owners:
            s = self._ptr.get(o)
            if not s:
                continue
            for t in targets:
                s.discard(t)
            if not s:
                self._ptr.pop(o, None)

    def _service_node_name(
        self, service_type: str, host: str
    ) -> str:  # pragma: nocover helper naming logic
        """Brief: Build a host-qualified service node name.

        Inputs:
          - service_type: Service type name (e.g., `_spotify-connect._tcp.local.`).
          - host: Hostname (e.g., `Macbook-Pro.local.`).

        Outputs:
          - str: Name of the form `<service>.<proto>.<host>.<suffix>`.

        Notes:
          - This is a Foghorn-specific convenience namespace used by `_services.<suffix>`.
          - The returned name is normalized (lowercase, no trailing dot).
        """

        st = self._normalize_owner(service_type)
        h = self._normalize_owner(host)

        # Prefer `.local` as the canonical base.
        if st.endswith(".local"):
            st_prefix = st[: -len(".local")]
        elif self._dns_domain != ".local" and st.endswith(self._dns_domain):
            st_prefix = st[: -len(self._dns_domain)]
        else:
            st_prefix = st

        return f"{st_prefix}.{h}"

    def _index_ptrs_for_service_host(
        self, *, service_type: str, host: str
    ) -> None:  # pragma: nocover index maintenance helper
        """Brief: Maintain host-related PTR indexes for mDNS-discovered services.

        Inputs:
          - service_type: Service type name (e.g., `_spotify-connect._tcp.local.`).
          - host: Hostname from ServiceInfo.server (e.g., `Macbook-Pro.local.`).

        Outputs:
          - None.

        Behavior:
          - PTR `_mdns.<suffix>` -> `<host>.<suffix>`
          - PTR `_services.<suffix>` -> `<service_type>.<host>.<suffix>`

        Notes:
          - Service type PTRs themselves are primarily mapped to synthetic
            instance names; host mappings are exposed via `_mdns` and
            `_services` helper namespaces.
        """

        st_norm = self._normalize_owner(service_type)
        host_norm = self._normalize_owner(host)
        if not st_norm or not host_norm:
            return

        # Only index mDNS-discovered `.local` names.
        if not st_norm.endswith(".local"):
            return
        if not host_norm.endswith(".local"):
            return

        service_node = self._service_node_name(st_norm, host_norm)
        self._ptr_add("_services.local", service_node)
        self._ptr_add("_services._dns-sd._udp.local", service_node)

    def _update_service_state(
        self, instance_name: str, status: str, host: Optional[str] = None
    ) -> None:
        """Brief: Update last-seen timestamp, status, and optional host.

        Inputs:
          - instance_name: Canonical instance owner name (any case, optional dot).
          - status: New status string (for example, ``"up"`` or ``"down"``).
          - host: Optional hostname (any case, optional trailing dot). When
            provided, this value is normalized and recorded as the last host
            where the service was seen. When omitted or empty, any previously
            recorded host is preserved.

        Outputs:
          - None; internal `_service_state` mapping is updated in-place.
        """

        try:
            base_name = self._normalize_owner(instance_name)
        except Exception:
            base_name = str(instance_name or "").rstrip(".").lower()

        if not base_name:
            return

        try:
            ts = datetime.now(timezone.utc).isoformat()
        except Exception:
            ts = ""

        host_norm = ""
        if host is not None:
            try:
                host_norm = self._normalize_owner(host)
            except Exception:
                host_norm = str(host or "").rstrip(".").lower()

        variants = self._mirror_suffixes(base_name)
        with self._lock:
            for key in variants:
                prev = self._service_state.get(key)
                prev_host = getattr(prev, "host", "") if prev is not None else ""
                prev_up_since = (
                    getattr(prev, "up_since", "") if prev is not None else ""
                )
                new_host = host_norm or prev_host

                status_norm = str(status).lower()
                if status_norm == "up":
                    # Preserve existing up_since when remaining up; start a new
                    # up period only when transitioning from a non-up state.
                    new_up_since = prev_up_since or ts
                else:
                    new_up_since = prev_up_since

                self._service_state[key] = _ServiceState(
                    status=str(status),
                    last_seen=ts,
                    host=new_host,
                    up_since=new_up_since,
                )

    def _start_type_browser(
        self, service_type: str
    ) -> None:  # pragma: nocover zeroconf browser wiring
        """Brief: Start a ServiceBrowser for a specific mDNS service type.

        Inputs:
          - service_type: Service type name (e.g., `_http._tcp.local.`). May be
            provided without a trailing dot.

        Outputs:
          - None. Registers browser into self._browsers and self._type_browsers.

        Notes:
          - This is a best-effort helper used for explicit `service_types`.
          - mDNS browsing always happens under `.local` regardless of the DNS
            suffix this plugin serves under.
        """

        log = getattr(self, "logger", logger)
        if self._zc is None:
            return

        t = str(service_type or "").strip()
        if not t:
            return
        if not t.endswith("."):
            t = t + "."

        key = self._normalize_owner(t)
        with self._lock:
            if key in self._type_browsers:
                return
            browser = self._ServiceBrowser(
                self._zc,
                t,
                handlers=[self._on_instance_event],
            )
            self._type_browsers[key] = browser
            self._browsers.append(browser)

        log.debug("MdnsBridge: started explicit ServiceBrowser for %s", t)

    def _on_service_type_event(self, zeroconf, service_type: str, name: str, state_change) -> None:  # type: ignore[no-untyped-def]  # pragma: nocover callback from zeroconf
        """Brief: Handle PTR events for `_services._dns-sd._udp.<domain>.`.

        Inputs:
          - zeroconf: Zeroconf instance.
          - service_type: Browsed type (always `_services._dns-sd._udp.local.`).
          - name: Service type name discovered (e.g. `_http._tcp.local.`).
          - state_change: ServiceStateChange value.

        Outputs:
          - None.
        """

        _ = service_type
        log = getattr(self, "logger", logger)
        with self._lock:
            if getattr(state_change, "name", "") == "Removed":
                log.debug(
                    "MdnsBridge: service type removed: %s (mdns_domain=%s)",
                    name,
                    self._mdns_domain,
                )
                self._ptr_remove(
                    f"_services._dns-sd._udp{self._mdns_domain}.",
                    name,
                )
                # Best-effort: stop tracking per-type browser state.
                key = self._normalize_owner(name)
                self._type_browsers.pop(key, None)
                return

            log.debug(
                "MdnsBridge: service type added/updated: %s (mdns_domain=%s)",
                name,
                self._mdns_domain,
            )
            self._ptr_add(f"_services._dns-sd._udp{self._mdns_domain}.", name)

            key = self._normalize_owner(name)
            if key in self._type_browsers:
                return

            if self._zc is None:
                return

            browser = self._ServiceBrowser(
                self._zc,
                name,
                handlers=[self._on_instance_event],
            )
            self._type_browsers[key] = browser
            self._browsers.append(browser)

    def _on_instance_event(self, zeroconf, service_type: str, name: str, state_change) -> None:  # type: ignore[no-untyped-def]  # pragma: nocover callback from zeroconf
        """Brief: Handle instance add/update/remove for a specific service type.

        Inputs:
          - zeroconf: Zeroconf instance.
          - service_type: Service type being browsed (e.g. `_http._tcp.local.`).
          - name: Full service instance name.
          - state_change: ServiceStateChange value.

        Outputs:
          - None.
        """

        log = getattr(self, "logger", logger)

        # Derive the canonical instance name used internally for SRV/TXT keys so
        # that we can keep status tracking and cache cleanup consistent across
        # add/update and remove events.
        canonical_instance: Optional[str]
        try:
            safe_label = self._sanitize_qname(name)
            st_norm = self._normalize_owner(service_type)
            canonical_instance = f"{safe_label}.{st_norm}"
        except Exception:
            canonical_instance = None

        with self._lock:
            if getattr(state_change, "name", "") == "Removed":
                log.debug(
                    "MdnsBridge: instance removed: %s (type=%s)",
                    name,
                    service_type,
                )
                # Best-effort: we do not currently attempt to remove any
                # host/service PTR index entries here, because other instances
                # may still be active on the same host.
                for k in self._mirror_suffixes(name):
                    self._srv.pop(k, None)
                    self._txt.pop(k, None)
                if canonical_instance is not None:
                    for k in self._mirror_suffixes(canonical_instance):
                        self._srv.pop(k, None)
                        self._txt.pop(k, None)
                try:
                    if canonical_instance is not None:
                        # Preserve the last known host by omitting the host
                        # argument on down transitions.
                        self._update_service_state(canonical_instance, status="down")
                except Exception:
                    log.debug(
                        "MdnsBridge: failed to update service state for removal: %s (type=%s)",
                        name,
                        service_type,
                        exc_info=True,
                    )
                return

            # Record the instance event (PTRs are updated after we fetch ServiceInfo
            # so we can map service types to hostnames).
            log.debug(
                "MdnsBridge: instance added/updated: %s (type=%s)",
                name,
                service_type,
            )

        try:
            info = zeroconf.get_service_info(
                service_type, name, timeout=self._info_timeout_ms
            )
        except Exception:
            log.debug(
                "MdnsBridge: get_service_info raised for %s (type=%s)",
                name,
                service_type,
                exc_info=True,
            )
            info = None

        if info is None:
            log.debug(
                "MdnsBridge: get_service_info returned None for %s (type=%s)",
                name,
                service_type,
            )
            return

        host = None
        port = None
        try:
            host = getattr(info, "server", None)
            port = getattr(info, "port", None)
        except Exception:
            host = None
            port = None

        log.debug(
            "MdnsBridge: ingesting ServiceInfo for %s (type=%s host=%s port=%s)",
            name,
            service_type,
            host,
            port,
        )

        # Update PTR indexes based on the SRV target host.
        try:
            self._index_ptrs_for_service_host(
                service_type=service_type, host=str(host or "")
            )
        except Exception:
            log.debug(
                "MdnsBridge: failed to index PTRs for service_type=%s host=%s",
                service_type,
                host,
                exc_info=True,
            )

        # Additionally, maintain a more traditional DNS-SD style index that maps
        # service types to *instance* names using a DNS-safe, synthetic label
        # derived from the instance name. This allows callers to follow the
        # usual PTR -> SRV/TXT chain with names like
        # "roku_ultra._airplay._tcp.zaa" instead of raw mDNS instance labels.
        try:
            if canonical_instance is None:
                safe_label = self._sanitize_qname(name)
                st_norm = self._normalize_owner(service_type)
                canonical_instance = f"{safe_label}.{st_norm}"
            self._ptr_add(service_type, canonical_instance)
        except Exception:
            log.debug(
                "MdnsBridge: failed to index PTR for service_type=%s instance=%s",
                service_type,
                name,
                exc_info=True,
            )

        self._ingest_service_info(info, canonical_instance_name=canonical_instance)

        try:
            key_for_state = canonical_instance or getattr(info, "name", name)
            self._update_service_state(key_for_state, status="up", host=host)
        except Exception:
            log.debug(
                "MdnsBridge: failed to update service state for %s (type=%s)",
                name,
                service_type,
                exc_info=True,
            )

    @registered_cached(cache=_MDNS_SANITIZE_QNAME_CACHE)
    def _sanitize_qname(
        self, name: str
    ) -> str:  # pragma: nocover string sanitization helper
        """Brief: Derive a DNS-safe, synthetic hostname from an mDNS instance.

        Inputs:
          - name: Raw instance name (e.g., "[LG] Living Room TV._airplay._tcp.local").

        Outputs:
          - str: Lowercased name derived from the instance label (portion before
            the first dot) where any character outside ``[A-Za-z0-9]`` is
            replaced with ``_``, and multiple consecutive ``_`` are collapsed to
            a single ``_``. A leading ``_`` will naturally appear only when the
            original first character is invalid.

        Example:
          - "[LG] Living Room TV._airplay._tcp.local" -> "_LG_LIVING_ROOM_TV".
        """

        try:
            s = str(name).rstrip(".")
        except Exception:
            s = repr(name)

        # Only consider the instance label, not the service type suffix.
        label = s.split(".", 1)[0]

        # Normalize to lower-case and replace invalid characters.
        out_chars: list[str] = []
        for ch in label.lower():
            if "a" <= ch <= "z" or "0" <= ch <= "9":
                out_chars.append(ch)
            else:
                out_chars.append("_")

        # Collapse multiple underscores and trim leading/trailing ones.
        collapsed: list[str] = []
        prev_us = False
        for ch in out_chars:
            if ch == "_":
                if prev_us:
                    continue
                prev_us = True
                collapsed.append(ch)
            else:
                prev_us = False
                collapsed.append(ch)

        # Strip leading/trailing underscores; if the instance label was entirely
        # invalid, fall back to a single underscore.
        core = "".join(collapsed).strip("_")
        if not core:
            return "_"
        return core

    def _ingest_service_info(self, info, canonical_instance_name: Optional[str] = None) -> None:  # type: ignore[no-untyped-def]  # pragma: nocover network-derived data path
        """Brief: Convert a zeroconf ServiceInfo into DNS RRset caches.

        Inputs:
          - info: zeroconf.ServiceInfo instance.

        Outputs:
          - None.

        Notes:
          - Logs include the SRV target host (info.server) so operators can
            correlate discovered instances to hostnames.
        """

        try:
            raw_instance_name = getattr(info, "name", None)
            instance_name = canonical_instance_name or raw_instance_name
            server = getattr(info, "server", None)
            port = int(getattr(info, "port", 0) or 0)
            priority = int(getattr(info, "priority", 0) or 0)
            weight = int(getattr(info, "weight", 0) or 0)
        except Exception:
            return

        if not instance_name or not server:
            return

        log = getattr(self, "logger", logger)
        log.debug(
            "MdnsBridge: caching instance=%s host=%s port=%d ttl=%d",
            str(instance_name).rstrip("."),
            str(server).rstrip("."),
            int(port or 0),
            int(getattr(self, "_ttl", 0) or 0),
        )

        # TXT properties are bytes->bytes; synthesize key=value strings.
        txt_values: List[str] = []
        try:
            props = getattr(info, "properties", None) or {}
            if isinstance(props, dict):
                for k, v in props.items():
                    try:
                        kk = (
                            k.decode("utf-8", errors="replace")
                            if isinstance(k, (bytes, bytearray))
                            else str(k)
                        )
                        vv = (
                            v.decode("utf-8", errors="replace")
                            if isinstance(v, (bytes, bytearray))
                            else str(v)
                        )
                        txt_values.append(f"{kk}={vv}")
                    except Exception:
                        continue
        except Exception:
            txt_values = []

        # Addresses: handle common zeroconf APIs.
        ips: List[str] = []
        for attr in ("parsed_addresses", "addresses"):
            if not hasattr(info, attr):
                continue
            try:
                raw = getattr(info, attr)
                if callable(raw):
                    vals = raw()
                else:
                    vals = raw
            except Exception:
                continue

            if attr == "parsed_addresses":
                try:
                    for s in list(vals or []):
                        ips.append(str(s))
                except Exception:
                    pass
            else:
                # `addresses` is usually a list of packed bytes.
                try:
                    for b in list(vals or []):
                        if isinstance(b, (bytes, bytearray)):
                            try:
                                ips.append(str(ipaddress.ip_address(bytes(b))))
                            except Exception:
                                continue
                except Exception:
                    pass

        with self._lock:
            host_variants = self._mirror_suffixes(server)

            # Also synthesize a "friendly" host name derived from the instance
            # label (e.g. `epson_wf_4830_series.zaa`) that shares the same
            # addresses as the underlying mDNS host (e.g. `epson977fa9.zaa`).
            friendly_hosts: Set[str] = set()
            try:
                safe_label = self._sanitize_qname(raw_instance_name or instance_name)
                for hv in host_variants:
                    parts = hv.split(".", 1)
                    if len(parts) == 2 and parts[1]:
                        friendly_hosts.add(f"{safe_label}.{parts[1]}")
            except Exception:
                friendly_hosts = set()

            # Additionally, build "service-node" names of the form
            # `<service>.<proto>.<host>.<suffix>` that correspond to the
            # `_services` index entries (e.g. `_airplay._tcp.yj006n170656.zaa`).
            # These will share TXT and A/AAAA with the underlying host so that a
            # PTR answer from `_services` can be followed directly to useful
            # metadata and addresses.
            service_nodes: Set[str] = set()
            try:
                service_type = getattr(info, "type", None)
                st_norm = self._normalize_owner(service_type or "")
                host_norm = self._normalize_owner(server)
                if st_norm.endswith(".local") and host_norm.endswith(".local"):
                    service_node_local = self._service_node_name(st_norm, host_norm)
                    for sn in self._mirror_suffixes(service_node_local):
                        service_nodes.add(sn)
            except Exception:
                service_nodes = set()

            for inst in self._mirror_suffixes(instance_name):
                # Pick an SRV target that matches the instance's suffix.
                target_host = (
                    host_variants[0] if host_variants else self._normalize_owner(server)
                )
                if inst.endswith(".local"):
                    for hv in host_variants:
                        if hv.endswith(".local"):
                            target_host = hv
                            break
                elif self._dns_domain != ".local" and inst.endswith(self._dns_domain):
                    for hv in host_variants:
                        if hv.endswith(self._dns_domain):
                            target_host = hv
                            break

                self._srv[inst] = _SrvValue(
                    priority=priority,
                    weight=weight,
                    port=port,
                    target=target_host + ".",
                )
                if txt_values:
                    self._txt[inst] = list(txt_values)
                else:
                    self._txt.pop(inst, None)

            # Attach TXT (when present) to each service-node name as well so that
            # callers following `_services` PTRs can read metadata directly.
            if txt_values:
                for sn in service_nodes:
                    self._txt[sn] = list(txt_values)
            else:
                for sn in service_nodes:
                    self._txt.pop(sn, None)

            # Host addresses for the SRV target, plus any friendly hostnames
            # derived from the instance label, plus the service-node labels
            # used in `_services`.
            all_hosts: Set[str] = set(self._mirror_suffixes(server))
            all_hosts.update(friendly_hosts)
            all_hosts.update(service_nodes)

            for host in all_hosts:
                if self._include_ipv4:
                    v4 = self._a.setdefault(host, set())
                    for ip in ips:
                        try:
                            if ipaddress.ip_address(ip).version == 4:
                                v4.add(ip)
                        except Exception:
                            continue
                    if not v4:
                        self._a.pop(host, None)

                if self._include_ipv6:
                    v6 = self._aaaa.setdefault(host, set())
                    for ip in ips:
                        try:
                            if ipaddress.ip_address(ip).version == 6:
                                v6.add(ip)
                        except Exception:
                            continue
                    if not v6:
                        self._aaaa.pop(host, None)

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[
        PluginDecision
    ]:  # pragma: nocover complex answer synthesis (covered via higher-level tests)
        """Brief: Answer configured mDNS-domain queries from the mDNS cache when possible.

        Inputs:
          - qname: Queried domain name.
          - qtype: Numeric QTYPE code.
          - req: Raw DNS request bytes.
          - ctx: Plugin context.

        Outputs:
          - PluginDecision('override') with a synthesized response when this plugin
            can answer; otherwise None to fall through.
        """

        if not self.targets(ctx):
            return None

        name_norm = self._normalize_owner(qname)

        # Serve only the configured DNS suffix(es) (e.g. `.example`, `.mdns`, `.tld`).
        allowed_suffixes = getattr(self, "_dns_domains", {self._dns_domain})

        if not any(name_norm.endswith(suf) for suf in allowed_suffixes):
            return None

        try:
            request = DNSRecord.parse(req)
        except Exception:
            return None

        qtype_int = int(qtype)
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )
        owner_wire = request.q.qname

        def _added_any() -> bool:
            return len(reply.rr) > 0

        def _append_host_additionals(host_name: str) -> None:
            """Brief: Add A/AAAA additionals for a given host when cached.

            Inputs:
              - host_name: Normalized owner name for the host (no trailing dot).

            Outputs:
              - None; conditionally appends A/AAAA RRs to `reply`.
            """

            if not host_name:
                return
            # Only append if the host is inside one of the configured suffixes; this
            # avoids surprising cross-domain glue.
            allowed_suffixes = getattr(self, "_dns_domains", {self._dns_domain})
            if not any(host_name.endswith(suf) for suf in allowed_suffixes):
                return

            if self._include_ipv4:
                ips4 = self._a.get(host_name)
                if ips4:
                    for ip in sorted(ips4):
                        reply.add_answer(
                            RR(
                                rname=host_name + ".",
                                rtype=QTYPE.A,
                                rclass=1,
                                ttl=self._ttl,
                                rdata=A(ip),
                            ),
                        )

            if self._include_ipv6:
                ips6 = self._aaaa.get(host_name)
                if ips6:
                    for ip in sorted(ips6):
                        reply.add_answer(
                            RR(
                                rname=host_name + ".",
                                rtype=QTYPE.AAAA,
                                rclass=1,
                                ttl=self._ttl,
                                rdata=AAAA(ip),
                            ),
                        )

        def _service_node_host_name(owner: str) -> Optional[str]:
            """Brief: Infer the underlying host name from a service-node owner.

            Inputs:
              - owner: Normalized owner name (no trailing dot).

            Outputs:
              - Optional[str]: Host owner name (no trailing dot) or None.
            """

            if not owner:
                return None

            allowed_suffixes = getattr(self, "_dns_domains", {self._dns_domain})
            matched_suffix: Optional[str] = None
            for suf in sorted(allowed_suffixes, key=len, reverse=True):
                if owner.endswith(suf):
                    matched_suffix = suf
                    break

            if not matched_suffix:
                return None

            base = owner[: -len(matched_suffix)]
            if base.endswith("."):
                base = base[:-1]

            labels = base.split(".")
            if (
                len(labels) < 3
                or not labels[0].startswith("_")
                or labels[1] not in {"_tcp", "_udp"}
            ):
                return None

            host_label = labels[2]
            if not host_label:
                return None

            return f"{host_label}{matched_suffix}"

        with self._lock:
            service_node_host = _service_node_host_name(name_norm)
            # PTR
            if qtype_int in {int(QTYPE.PTR), int(QTYPE.ANY)}:
                ptr_targets = self._ptr.get(name_norm)
                host_additionals: Set[str] = set()

                # When querying a service type like `_app._proto.tld`, only return
                # PTR targets that live under the *same* configured suffix as the
                # owner (so `.zaa` does not return `.local` targets and vice versa).
                owner_suffix: Optional[str] = None
                allowed_suffixes = getattr(self, "_dns_domains", {self._dns_domain})
                if ptr_targets:
                    for suf in allowed_suffixes:
                        if name_norm.endswith(suf):
                            owner_suffix = suf
                            break
                    if owner_suffix:
                        filtered = {t for t in ptr_targets if t.endswith(owner_suffix)}
                        if filtered:
                            ptr_targets = filtered

                if ptr_targets:
                    for t in sorted(ptr_targets):
                        reply.add_answer(
                            RR(
                                rname=owner_wire,
                                rtype=QTYPE.PTR,
                                rclass=1,
                                ttl=self._ttl,
                                rdata=PTR(t + "."),
                            ),
                        )

                    # Rule #2: when there are relatively few PTR targets, attempt to
                    # infer the corresponding host(s) and include their A/AAAA as
                    # additional records.
                    if (
                        0 < len(ptr_targets) <= PTR_ADDITIONAL_HOST_LIMIT
                        and owner_suffix
                    ):
                        for target in ptr_targets:
                            # If we have TXT for the PTR target (e.g. an instance
                            # name like `roku_ultra._airplay._tcp.zaa`), include it
                            # as an additional so a single PTR query can reveal
                            # both the instance metadata and the host addresses.
                            txts_for_target = self._txt.get(target)
                            if txts_for_target:
                                reply.add_answer(
                                    RR(
                                        rname=target + ".",
                                        rtype=QTYPE.TXT,
                                        rclass=1,
                                        ttl=self._ttl,
                                        rdata=TXT(list(txts_for_target)),
                                    ),
                                )

                            # Patterns we understand for mapping PTR target ->
                            # host name:
                            #   - host._service._proto.<suffix>
                            #   - host.<suffix>
                            labels = target.split(".")
                            if not target.endswith(owner_suffix):
                                continue
                            # Strip the matched suffix (and any dot before it) to
                            # get the prefix labels.
                            base = target[: -len(owner_suffix)]
                            if base.endswith("."):
                                base = base[:-1]
                            if not base:
                                continue
                            labels = base.split(".")
                            if len(labels) >= 2:
                                # host._service._proto.<suffix> -> host.<suffix>
                                host_label = labels[0]
                                host_additionals.add(f"{host_label}{owner_suffix}")
                            else:
                                # host.<suffix>
                                host_additionals.add(target)

                for host_name in sorted(host_additionals):
                    _append_host_additionals(host_name)

            # SRV
            if qtype_int in {int(QTYPE.SRV), int(QTYPE.ANY)}:
                srv = self._srv.get(name_norm)
                if srv is not None:
                    reply.add_answer(
                        RR(
                            rname=owner_wire,
                            rtype=QTYPE.SRV,
                            rclass=1,
                            ttl=self._ttl,
                            rdata=SRV(
                                srv.priority,
                                srv.weight,
                                srv.port,
                                srv.target,
                            ),
                        ),
                    )

            # TXT
            if qtype_int in {int(QTYPE.TXT), int(QTYPE.ANY)}:
                txts = self._txt.get(name_norm)
                if txts:
                    reply.add_answer(
                        RR(
                            rname=owner_wire,
                            rtype=QTYPE.TXT,
                            rclass=1,
                            ttl=self._ttl,
                            rdata=TXT(list(txts)),
                        ),
                    )

                    # Rule #1: TXT on a service-node like
                    # `<service>.<proto>.<host>.<suffix>`. When such a name is
                    # queried, also include `host.<suffix>` A/AAAA as
                    # additionals when present so callers can get addresses
                    # alongside metadata.
                    if service_node_host:
                        _append_host_additionals(service_node_host)

            # A / AAAA
            if self._include_ipv4 and qtype_int in {int(QTYPE.A), int(QTYPE.ANY)}:
                ips4 = self._a.get(name_norm)
                if ips4:
                    for ip in sorted(ips4):
                        reply.add_answer(
                            RR(
                                rname=owner_wire,
                                rtype=QTYPE.A,
                                rclass=1,
                                ttl=self._ttl,
                                rdata=A(ip),
                            )
                        )
                elif qtype_int == int(QTYPE.A):
                    # Allow service-type A queries (e.g. `_http._tcp.example`) to
                    # behave like PTR lookups when we have cached PTR data for the
                    # same owner. This helps clients that mistakenly issue A
                    # queries for `_service._proto` names discover available
                    # instances.
                    labels = name_norm.split(".")
                    if (
                        len(labels) >= 3
                        and labels[0].startswith("_")
                        and labels[1] in {"_tcp", "_udp"}
                    ):
                        ptr_targets = self._ptr.get(name_norm)
                        if ptr_targets:
                            for t in sorted(ptr_targets):
                                reply.add_answer(
                                    RR(
                                        rname=owner_wire,
                                        rtype=QTYPE.PTR,
                                        rclass=1,
                                        ttl=self._ttl,
                                        rdata=PTR(t + "."),
                                    ),
                                )

                if qtype_int == int(QTYPE.A) and service_node_host:
                    # When querying A for a service-node name, also return TXT
                    # for the service itself and the underlying host A/AAAA as
                    # additionals so callers get both metadata and addresses
                    # via a single lookup.
                    txts_for_service = self._txt.get(name_norm)
                    if txts_for_service:
                        reply.add_answer(
                            RR(
                                rname=owner_wire,
                                rtype=QTYPE.TXT,
                                rclass=1,
                                ttl=self._ttl,
                                rdata=TXT(list(txts_for_service)),
                            ),
                        )
                    _append_host_additionals(service_node_host)

            if self._include_ipv6 and qtype_int in {int(QTYPE.AAAA), int(QTYPE.ANY)}:
                ips6 = self._aaaa.get(name_norm)
                if ips6:
                    for ip in sorted(ips6):
                        reply.add_answer(
                            RR(
                                rname=owner_wire,
                                rtype=QTYPE.AAAA,
                                rclass=1,
                                ttl=self._ttl,
                                rdata=AAAA(ip),
                            )
                        )
                elif qtype_int == int(QTYPE.AAAA):
                    # Same behavior for AAAA queries to service-type names.
                    labels = name_norm.split(".")
                    if (
                        len(labels) >= 3
                        and labels[0].startswith("_")
                        and labels[1] in {"_tcp", "_udp"}
                    ):
                        ptr_targets = self._ptr.get(name_norm)
                        if ptr_targets:
                            for t in sorted(ptr_targets):
                                reply.add_answer(
                                    RR(
                                        rname=owner_wire,
                                        rtype=QTYPE.PTR,
                                        rclass=1,
                                        ttl=self._ttl,
                                        rdata=PTR(t + "."),
                                    ),
                                )

        if not _added_any():
            return None

        return PluginDecision(action="override", response=reply.pack())

    def get_admin_pages(self) -> List[AdminPageSpec]:
        """Brief: Describe the MdnsBridge admin page for the web UI.

        Inputs:
          - None; uses the plugin instance name for routing and data lookups.

        Outputs:
          - list[AdminPageSpec]: A single page descriptor for mDNS / DNS-SD
            discovery state.
        """

        return [
            AdminPageSpec(
                slug="mdns",
                title="mDNS",
                description=(
                    "Services and hosts discovered by the MdnsBridge. "
                    "Intended to be paired with JSON data from a future "
                    "/api/v1/plugins/{name}/mdns endpoint."
                ),
                layout="one_column",
                kind="mdns",
            )
        ]

    def get_admin_ui_descriptor(self) -> Dict[str, object]:
        """Brief: Describe mDNS admin UI using a generic snapshot layout.

        Inputs:
          - None (uses the plugin instance name for routing).

        Outputs:
          - dict with keys:
              * name: Effective plugin instance name.
              * title: Human-friendly tab title.
              * order: Integer ordering hint among plugin tabs.
              * endpoints: Mapping with at least a "snapshot" URL.
              * layout: Generic section/column description for the frontend.
        """

        plugin_name = getattr(self, "name", "mdns")
        snapshot_url = f"/api/v1/plugins/{plugin_name}/mdns"
        base_title = "mDNS"
        title = f"{base_title} ({plugin_name})" if plugin_name else base_title
        layout: Dict[str, object] = {
            "sections": [
                {
                    "id": "summary",
                    "title": "Summary",
                    "type": "kv",
                    "path": "summary",
                    "rows": [
                        {"key": "total_services", "label": "Services"},
                        {"key": "total_hosts", "label": "Hosts"},
                        {"key": "domains", "label": "Domains", "join": ", "},
                    ],
                },
                {
                    "id": "services",
                    "title": "Services",
                    "type": "table",
                    "path": "services",
                    "columns": [
                        {"key": "instance", "label": "Instance"},
                        {"key": "type", "label": "Type"},
                        {"key": "host", "label": "Host"},
                        {"key": "ipv4", "label": "IPv4", "join": ", "},
                        {"key": "ipv6", "label": "IPv6", "join": ", "},
                        {"key": "uptime_human", "label": "Uptime", "align": "right"},
                    ],
                },
                {
                    "id": "services_down",
                    "title": "Down services",
                    "type": "table",
                    "path": "down_services",
                    "columns": [
                        {"key": "instance", "label": "Instance"},
                        {"key": "type", "label": "Type"},
                        {"key": "host", "label": "Host"},
                        {"key": "last_seen", "label": "Last seen"},
                    ],
                },
            ]
        }

        return {
            "name": str(plugin_name),
            "title": str(title),
            "order": 60,
            "endpoints": {"snapshot": snapshot_url},
            "layout": layout,
        }

    def _format_uptime_human(self, seconds: int) -> str:
        """Brief: Format a duration in seconds into a concise human-readable string.

        Inputs:
          - seconds: Non-negative number of seconds.

        Outputs:
          - str: Duration like "2d 3h 4m 5s", "4h 2m", or "45s". Zero renders as "0s".
        """

        try:
            s = max(0, int(seconds))
        except Exception:
            s = 0
        days, rem = divmod(s, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        parts: List[str] = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        # Always include seconds, even when zero, if no larger unit was emitted.
        if secs or not parts:
            parts.append(f"{secs}s")
        return " ".join(parts)

    def get_http_snapshot(self) -> Dict[str, object]:
        """Brief: Summarize current mDNS services and hosts for the admin web UI.

        Inputs:
          - None (uses in-memory SRV/A/AAAA caches under a lock).

        Outputs:
          - dict with keys:
              * summary: High-level counts for total services and hosts.
              * services: List of objects for currently up services. Each entry
                includes ``uptime`` (seconds, int) and ``uptime_human``
                (human‑readable string) derived from the per-service
                ``up_since`` timestamp when available.
              * down_services: List of objects for services marked down.
        """

        services_up: List[Dict[str, object]] = []
        services_down: List[Dict[str, object]] = []
        hosts_seen: set[str] = set()

        # Capture a single reference time so uptime calculations within this
        # snapshot are consistent across all services.
        now_utc = datetime.now(timezone.utc)

        with self._lock:
            # Snapshot SRV, address mappings, and service state so callers get a
            # consistent view.
            srv_items = list(self._srv.items())
            a_map = {k: set(v) for k, v in self._a.items()}
            aaaa_map = {k: set(v) for k, v in self._aaaa.items()}
            dns_doms = getattr(self, "_dns_domains", {self._dns_domain}) or {
                self._dns_domain
            }
            state_snapshot: Dict[str, _ServiceState] = dict(self._service_state)

        # Build a unified set of service owners limited to the `.local` mDNS
        # namespace so the admin view remains focused on what the plugin is
        # *discovering*, not every DNS suffix it might be serving under.
        srv_by_owner: Dict[str, _SrvValue] = {}
        all_owner_names: Set[str] = set()
        for owner, srv in srv_items:
            owner_name = str(owner or "").strip().lower()
            if owner_name and owner_name.endswith(".local"):
                srv_by_owner[owner_name] = srv
                all_owner_names.add(owner_name)
        for owner in state_snapshot.keys():
            owner_name = str(owner or "").strip().lower()
            if owner_name and owner_name.endswith(".local"):
                all_owner_names.add(owner_name)

        for owner_name in sorted(all_owner_names):
            srv = srv_by_owner.get(owner_name)

            # Derive a human-friendly service type by dropping the first label
            # (synthetic instance label) when possible.
            parts = owner_name.split(".")
            if len(parts) > 1:
                service_type = ".".join(parts[1:])
            else:  # pragma: nocover defensive: owner_name always contains at least one dot (".local")
                service_type = ""

            # Present a cleaner service type to the admin UI by stripping the
            # mDNS suffix; the discovery namespace is already implied.
            if service_type.endswith(".local"):
                service_type = service_type[: -len(".local")]

            state = state_snapshot.get(owner_name)
            raw_last_seen = state.last_seen if state is not None else ""

            # Present last_seen in the local timezone and rounded to whole
            # seconds so operators see human-friendly timestamps rather than raw
            # UTC with sub-second precision.
            last_seen = raw_last_seen
            if raw_last_seen:
                try:
                    s = str(raw_last_seen)
                    # Support ISO timestamps with trailing 'Z' by normalizing
                    # to an explicit UTC offset that datetime.fromisoformat
                    # reliably understands across Python versions.
                    if s.endswith("Z"):
                        s = s[:-1] + "+00:00"
                    dt = datetime.fromisoformat(s)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    local_dt = dt.astimezone()
                    # Drop sub-second precision and render as "YYYY-MM-DD HH:MM:SS".
                    local_dt = local_dt.replace(microsecond=0)
                    last_seen = local_dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    last_seen = raw_last_seen

            host_name = ""
            ipv4_list: List[str] = []
            ipv6_list: List[str] = []
            if srv is not None:
                internal_host = (
                    str(getattr(srv, "target", "") or "").rstrip(".").lower()
                )
                # Only report host entries that remain in the `.local` namespace to
                # keep the view consistent with the service filter above.
                if internal_host and not internal_host.endswith(".local"):
                    internal_host = ""

                if internal_host:
                    hosts_seen.add(internal_host)
                    v4 = a_map.get(internal_host) or set()
                    v6 = aaaa_map.get(internal_host) or set()
                    ipv4_list = sorted(str(ip) for ip in v4)
                    ipv6_list = sorted(str(ip) for ip in v6)

                    # Preserve the full mDNS hostname (including `.local`) so
                    # callers can easily correlate with underlying mDNS records.
                    host_name = internal_host

            # When SRV data is no longer present (for example, a service has been
            # removed from the network), fall back to the last recorded host from
            # the per-instance service state so that the admin UI can still show
            # where the service was last seen.
            if not host_name and state is not None:
                saved_host = getattr(state, "host", "") or ""
                if saved_host:
                    # When falling back to the last recorded host, preserve the
                    # full hostname (including `.local`) for consistency with
                    # the live SRV-derived path above.
                    host_name = saved_host

            if state is not None:
                status = state.status
            else:
                # When no explicit state exists, treat cached SRV data as "up" and
                # absent SRV data as "down" so callers can distinguish cases.
                status = "up" if srv is not None else "down"

            record: Dict[str, object] = {
                "instance": owner_name,
                "type": service_type,
                "host": host_name,
                "ipv4": ipv4_list,
                "ipv6": ipv6_list,
                "last_seen": last_seen,
                "status": status,
            }

            # Provide the raw ISO-8601 timestamp for frontend formatting in the
            # user's browser timezone and for tooltips.
            if raw_last_seen:
                record["_lastSeenRaw"] = str(raw_last_seen)
                record["_lastSeenTooltip"] = str(raw_last_seen)

            # Derive an uptime (in whole seconds) for services that are currently
            # up, based on the per-instance "up_since" timestamp when available.
            if str(status).lower() == "up" and state is not None:
                # Use the raw UTC timestamp for uptime math so that local
                # formatting of last_seen does not affect calculations.
                up_since_raw = getattr(state, "up_since", "") or raw_last_seen
                try:
                    s_up = str(up_since_raw)
                    if s_up.endswith("Z"):
                        s_up = s_up[:-1] + "+00:00"
                    up_since_dt = datetime.fromisoformat(s_up)
                except Exception:
                    up_since_dt = None  # type: ignore[assignment]
                if up_since_dt is not None:
                    try:
                        uptime_seconds = (now_utc - up_since_dt).total_seconds()
                        if uptime_seconds < 0:
                            uptime_seconds = 0.0
                        seconds_int = int(uptime_seconds)
                        # Preserve numeric uptime for potential sorting/aggregation
                        # and also include a human-readable string.
                        record["uptime"] = seconds_int
                        record["uptime_human"] = self._format_uptime_human(seconds_int)
                    except Exception:
                        pass

            if str(status).lower() == "down":
                # Down hosts are reported without addresses for clarity in the UI.
                record["ipv4"] = []
                record["ipv6"] = []
                services_down.append(record)
            else:
                services_up.append(record)

        # Summarize counts plus the configured DNS domains this plugin is
        # serving under so that operators can see both the discovery namespace
        # (.local) and any mapped DNS suffixes (for example, .zaa).
        domains_list = sorted({str(d) for d in dns_doms})

        summary: Dict[str, object] = {
            "total_services": len(services_up) + len(services_down),
            "total_hosts": len(hosts_seen) if hosts_seen else 0,
            "domains": domains_list,
        }

        return {
            "summary": summary,
            "services": services_up,
            "down_services": services_down,
        }

    def close(self) -> None:  # pragma: nocover best-effort shutdown
        """Brief: Best-effort shutdown for zeroconf resources.

        Inputs:
          - None.

        Outputs:
          - None.

        Notes:
          - Foghorn core does not currently call plugin close hooks, but this is
            useful for tests or future lifecycle management.
        """

        log = getattr(self, "logger", logger)
        log.info("MdnsBridge: closing zeroconf resources")

        zc = getattr(self, "_zc", None)
        if zc is not None:
            try:
                zc.close()
            except Exception:
                pass
            self._zc = None

    def _test_seed_records(
        self,
        *,
        ptr: Optional[Dict[str, List[str]]] = None,
        srv: Optional[Dict[str, Tuple[int, int, int, str]]] = None,
        txt: Optional[Dict[str, List[str]]] = None,
        a: Optional[Dict[str, List[str]]] = None,
        aaaa: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """Brief: Seed internal caches for unit tests without network activity.

        Inputs:
          - ptr: Mapping owner -> list of PTR target names.
          - srv: Mapping owner -> (priority, weight, port, target).
          - txt: Mapping owner -> list of TXT strings.
          - a: Mapping owner -> list of IPv4 addresses.
          - aaaa: Mapping owner -> list of IPv6 addresses.

        Outputs:
          - None.

        Notes:
          - This is intentionally prefixed to discourage production use.
        """

        with self._lock:
            if ptr:
                for o, targets in ptr.items():
                    for t in targets:
                        self._ptr_add(o, t)
            if srv:
                for o, (prio, w, port, target) in srv.items():
                    for oo in self._mirror_suffixes(o):
                        self._srv[oo] = _SrvValue(
                            priority=int(prio),
                            weight=int(w),
                            port=int(port),
                            target=str(target).rstrip(".") + ".",
                        )
            if txt:
                for o, vals in txt.items():
                    for oo in self._mirror_suffixes(o):
                        self._txt[oo] = list(vals)
            if a:
                for o, ips in a.items():
                    for oo in self._mirror_suffixes(o):
                        self._a[oo] = set(ips)
            if aaaa:
                for o, ips in aaaa.items():
                    for oo in self._mirror_suffixes(o):
                        self._aaaa[oo] = set(ips)
