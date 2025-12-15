from __future__ import annotations

import ipaddress
import logging
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from dnslib import A, AAAA, PTR, QTYPE, RR, SRV, TXT, DNSHeader, DNSRecord
from pydantic import BaseModel, Field, validator

from foghorn.plugins.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

logger = logging.getLogger(__name__)


class MdnsBridgeConfig(BaseModel):
    """Brief: Typed configuration model for MdnsBridgePlugin.

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
    # Default to "default" rather than "all" to avoid attempting multicast
    # operations on non-standard interfaces (VPN/tunnels/containers) which can
    # yield EPERM on some systems.
    zeroconf_interfaces: object = Field(default="default")
    zeroconf_ip_version: Optional[str] = Field(default=None)
    zeroconf_unicast: bool = False
    service_types: List[str] = Field(default_factory=list)

    @validator("domain", pre=True)
    def _normalize_domain(cls, v):  # type: ignore[no-untyped-def]
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
    def _normalize_zeroconf_interfaces(cls, v):  # type: ignore[no-untyped-def]
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
    def _normalize_zeroconf_ip_version(cls, v):  # type: ignore[no-untyped-def]
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


@plugin_aliases("mdns", "zeroconf", "dns_sd", "dnssd", "bonjour")
class MdnsBridgePlugin(BasePlugin):
    """Brief: Expose mDNS/DNS-SD (zeroconf) data as DNS records.

    Inputs:
      - name: Optional plugin label.
      - **config: MdnsBridgeConfig-compatible fields.

    Outputs:
      - Plugin instance that can answer PTR/SRV/TXT/A/AAAA for discovered
        services under the configured mDNS domain.

    Notes:
      - This plugin is intentionally best-effort: when a query is not known it
        returns None to allow normal upstream resolution.
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - MdnsBridgeConfig class.
        """

        return MdnsBridgeConfig

    def setup(self) -> None:
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
            "MdnsBridgePlugin setup: dns_domain=%s mdns_domain=%s network_enabled=%s include_ipv4=%s include_ipv6=%s ttl=%s info_timeout_ms=%s",
            str(getattr(self._config_model, "domain", ".local")),
            ".local",
            bool(getattr(self._config_model, "network_enabled", True)),
            bool(getattr(self._config_model, "include_ipv4", True)),
            bool(getattr(self._config_model, "include_ipv6", True)),
            int(getattr(self._config_model, "ttl", 300) or 0),
            int(getattr(self._config_model, "info_timeout_ms", 1500) or 0),
        )

        # mDNS itself always uses `.local`, but we may *serve* the discovered data
        # under a different DNS suffix.
        self._mdns_domain = ".local"

        # domain is stored normalized as ".suffix" with no trailing dot.
        self._dns_domain = str(self._config_model.domain or ".local")

        # Records are stored keyed by *lowercased* owner name without trailing dot.
        self._ptr: Dict[str, Set[str]] = {}
        self._srv: Dict[str, _SrvValue] = {}
        self._txt: Dict[str, List[str]] = {}
        self._a: Dict[str, Set[str]] = {}
        self._aaaa: Dict[str, Set[str]] = {}

        self._ttl = int(self._config_model.ttl or 0)
        self._include_ipv4 = bool(self._config_model.include_ipv4)
        self._include_ipv6 = bool(self._config_model.include_ipv6)
        self._info_timeout_ms = int(self._config_model.info_timeout_ms or 0)

        self._zc = None
        self._browsers = []
        self._type_browsers: Dict[str, object] = {}

        if not bool(self._config_model.network_enabled):
            log.info(
                "MdnsBridgePlugin: network_enabled=false; skipping zeroconf initialization"
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
                'MdnsBridgePlugin requires the "zeroconf" package. Install it or disable this plugin.'
            ) from exc

        self._ServiceBrowser = ServiceBrowser
        self._ServiceInfo = ServiceInfo
        self._ServiceStateChange = ServiceStateChange

        # Provide knobs to avoid permission errors on some systems where binding
        # mDNS sockets on all interfaces or enabling IPv6 multicast can fail.
        interfaces_cfg = self._config_model.zeroconf_interfaces
        log.debug(
            "MdnsBridgePlugin: zeroconf config interfaces=%r ip_version=%r unicast=%r",
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
            log.info("MdnsBridgePlugin: Zeroconf initialized successfully")
        except PermissionError as exc:
            log.error(
                "MdnsBridgePlugin: Zeroconf failed to bind mDNS sockets (EPERM). interfaces=%r ip_version=%r unicast=%r",
                interfaces_cfg,
                self._config_model.zeroconf_ip_version,
                bool(self._config_model.zeroconf_unicast),
                exc_info=True,
            )
            raise RuntimeError(
                "MdnsBridgePlugin: Zeroconf failed to bind mDNS sockets (permission error). "
                "Try setting zeroconf_interfaces=default and/or zeroconf_ip_version=v4."
            ) from exc
        except OSError as exc:
            # Some systems report multicast/bind failures as generic OSError.
            log.error(
                "MdnsBridgePlugin: Zeroconf failed to initialize mDNS sockets: %s (interfaces=%r ip_version=%r unicast=%r)",
                exc,
                interfaces_cfg,
                self._config_model.zeroconf_ip_version,
                bool(self._config_model.zeroconf_unicast),
                exc_info=True,
            )
            raise RuntimeError(
                f"MdnsBridgePlugin: Zeroconf failed to initialize mDNS sockets: {exc}. "
                "Try setting zeroconf_interfaces=default and/or zeroconf_ip_version=v4."
            ) from exc

        # Discover all service types, then browse each type for instances.
        # Note: Some environments do not advertise `_services._dns-sd._udp.local.`.
        # In that case, configure `service_types` to browse known types directly.
        try:
            browse_name = f"_services._dns-sd._udp{self._mdns_domain}."
            log.info("MdnsBridgePlugin: starting ServiceBrowser for %s", browse_name)
            self._browsers.append(
                ServiceBrowser(
                    self._zc,
                    browse_name,
                    handlers=[self._on_service_type_event],
                )
            )
            log.info("MdnsBridgePlugin: ServiceBrowser started")
        except PermissionError as exc:
            log.error(
                "MdnsBridgePlugin: ServiceBrowser failed with EPERM while starting mDNS browsing",
                exc_info=True,
            )
            raise RuntimeError(
                "MdnsBridgePlugin: ServiceBrowser failed with EPERM while starting mDNS browsing. "
                "This is commonly caused by VPN/tunnel interfaces. Try setting zeroconf_interfaces to a "
                "specific LAN interface IP (e.g. your Wi-Fi/Ethernet address) and zeroconf_ip_version=v4."
            ) from exc
        except OSError as exc:
            log.error(
                "MdnsBridgePlugin: ServiceBrowser failed while starting mDNS browsing: %s",
                exc,
                exc_info=True,
            )
            raise RuntimeError(
                f"MdnsBridgePlugin: ServiceBrowser failed while starting mDNS browsing: {exc}. "
                "Try setting zeroconf_interfaces to a specific LAN interface IP and zeroconf_ip_version=v4."
            ) from exc

        # Optional: directly browse configured service types.
        for service_type in list(
            getattr(self._config_model, "service_types", []) or []
        ):
            try:
                self._start_type_browser(str(service_type))
            except Exception:
                log.debug(
                    "MdnsBridgePlugin: failed to start explicit service type browser for %r",
                    service_type,
                    exc_info=True,
                )

    def _normalize_owner(self, name: str) -> str:
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

    def _to_dns_domain(self, fqdn: str) -> str:
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

    def _mirror_suffixes(self, fqdn: str) -> List[str]:
        """Brief: Return internal key variants for a name.

        Inputs:
          - fqdn: FQDN (may or may not end with a trailing dot).

        Outputs:
          - list[str]: One or more names (without trailing dot) suitable for use as
            internal dict keys.

        Notes:
          - mDNS discovery happens under `.local`.
          - When serving discovered mDNS data under a configured DNS domain
            (e.g., `.example`), we also serve the same records under the
            canonical `.local` namespace.
            So for mDNS names, this returns variants for:
              - `.local`
              - the configured dns domain (self._dns_domain)
        """

        base = self._normalize_owner(fqdn)

        dns_dom = str(getattr(self, "_dns_domain", ".local") or ".local").lower()
        if not dns_dom.startswith("."):
            dns_dom = "." + dns_dom
        dns_dom = dns_dom.rstrip(".")

        def _add_unique(out: list[str], item: str) -> None:
            if item in out:
                return
            out.append(item)

        local_base: str | None = None
        input_is_dns = False

        if base.endswith(".local"):
            local_base = base
        elif dns_dom != ".local" and base.endswith(dns_dom):
            input_is_dns = True
            local_base = base[: -len(dns_dom)] + ".local"

        if local_base is not None:
            dns_variant = local_base
            if dns_dom != ".local":
                dns_variant = local_base[: -len(".local")] + dns_dom

            out: list[str] = []
            if input_is_dns:
                _add_unique(out, dns_variant)
                _add_unique(out, local_base)
            else:
                _add_unique(out, local_base)
                _add_unique(out, dns_variant)

            return out

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
            "MdnsBridgePlugin: PTR add owner=%s target=%s owners=%s targets=%s",
            self._normalize_owner(owner),
            self._normalize_owner(target),
            owners,
            targets,
        )

        for o in owners:
            s = self._ptr.setdefault(o, set())
            for t in targets:
                s.add(t)

    def _ptr_remove(self, owner: str, target: str) -> None:
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

    def _service_node_name(self, service_type: str, host: str) -> str:
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

    def _index_ptrs_for_service_host(self, *, service_type: str, host: str) -> None:
        """Brief: Maintain PTR indexes that map service types to hostnames.

        Inputs:
          - service_type: Service type name (e.g., `_spotify-connect._tcp.local.`).
          - host: Hostname from ServiceInfo.server (e.g., `Macbook-Pro.local.`).

        Outputs:
          - None.

        Behavior:
          - PTR `<service_type>.<suffix>` -> `<host>.<suffix>`
          - PTR `_hosts.<suffix>` -> `<host>.<suffix>`
          - PTR `_services.<suffix>` -> `<service_type>.<host>.<suffix>`

        Notes:
          - This intentionally returns hostnames (not instance names) for PTR
            queries on service types.
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

        # Ensure we index the canonical `.local` form and the configured DNS domain form.
        # `_ptr_add()` uses `_mirror_suffixes()` to create both suffix variants.
        self._ptr_add(st_norm, host_norm)
        self._ptr_add("_hosts.local", host_norm)

        service_node = self._service_node_name(st_norm, host_norm)
        self._ptr_add("_services.local", service_node)

    def _start_type_browser(self, service_type: str) -> None:
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

        # Browsing happens under `.local`.
        tl = t.lower()
        if tl.endswith(".mdns."):
            log.warning(
                "MdnsBridgePlugin: service_types should use .local; normalizing %s -> .local",
                t,
            )
            t = t[: -len(".mdns.")] + ".local."

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

        log.debug("MdnsBridgePlugin: started explicit ServiceBrowser for %s", t)

    def _on_service_type_event(self, zeroconf, service_type: str, name: str, state_change) -> None:  # type: ignore[no-untyped-def]
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
                    "MdnsBridgePlugin: service type removed: %s (mdns_domain=%s)",
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
                "MdnsBridgePlugin: service type added/updated: %s (mdns_domain=%s)",
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

    def _on_instance_event(self, zeroconf, service_type: str, name: str, state_change) -> None:  # type: ignore[no-untyped-def]
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
        with self._lock:
            if getattr(state_change, "name", "") == "Removed":
                log.debug(
                    "MdnsBridgePlugin: instance removed: %s (type=%s)",
                    name,
                    service_type,
                )
                # Best-effort: we do not currently attempt to remove any
                # host/service PTR index entries here, because other instances
                # may still be active on the same host.
                for k in self._mirror_suffixes(name):
                    self._srv.pop(k, None)
                    self._txt.pop(k, None)
                return

            # Record the instance event (PTRs are updated after we fetch ServiceInfo
            # so we can map service types to hostnames).
            log.debug(
                "MdnsBridgePlugin: instance added/updated: %s (type=%s)",
                name,
                service_type,
            )

        try:
            info = zeroconf.get_service_info(
                service_type, name, timeout=self._info_timeout_ms
            )
        except Exception:
            log.debug(
                "MdnsBridgePlugin: get_service_info raised for %s (type=%s)",
                name,
                service_type,
                exc_info=True,
            )
            info = None

        if info is None:
            log.debug(
                "MdnsBridgePlugin: get_service_info returned None for %s (type=%s)",
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
            "MdnsBridgePlugin: ingesting ServiceInfo for %s (type=%s host=%s port=%s)",
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
                "MdnsBridgePlugin: failed to index PTRs for service_type=%s host=%s",
                service_type,
                host,
                exc_info=True,
            )

        self._ingest_service_info(info)

    def _ingest_service_info(self, info) -> None:  # type: ignore[no-untyped-def]
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
            instance_name = getattr(info, "name", None)
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
            "MdnsBridgePlugin: caching instance=%s host=%s port=%d ttl=%d",
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

            # Host addresses for the SRV target.
            for host in self._mirror_suffixes(server):
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
    ) -> Optional[PluginDecision]:
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

        # Serve both the canonical `.local` namespace and the configured DNS
        # suffix (e.g. `.example`).
        allowed_suffixes = {self._dns_domain, ".local"}

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

        with self._lock:
            # PTR
            if qtype_int in {int(QTYPE.PTR), int(QTYPE.ANY)}:
                targets = self._ptr.get(name_norm)
                if targets:
                    for t in sorted(targets):
                        reply.add_answer(
                            RR(
                                rname=owner_wire,
                                rtype=QTYPE.PTR,
                                rclass=1,
                                ttl=self._ttl,
                                rdata=PTR(t + "."),
                            )
                        )

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
                        )
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
                        )
                    )

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

        if not _added_any():
            return None

        return PluginDecision(action="override", response=reply.pack())

    def close(self) -> None:
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
        log.info("MdnsBridgePlugin: closing zeroconf resources")

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
