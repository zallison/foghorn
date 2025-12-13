from __future__ import annotations

import ipaddress
import logging
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from dnslib import A, AAAA, PTR, SRV, TXT, QTYPE, RR, DNSHeader, DNSRecord
from pydantic import BaseModel, Field

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
      - ttl: int DNS TTL to apply to synthesized answers.
      - network_enabled: bool controlling whether the plugin starts zeroconf
        browsing threads. When False, the plugin still initializes internal
        state but does not touch the network (useful for tests).
      - include_ipv4: bool controlling whether A records are synthesized.
      - include_ipv6: bool controlling whether AAAA records are synthesized.
      - info_timeout_ms: int timeout in milliseconds for fetching ServiceInfo.

    Outputs:
      - MdnsBridgeConfig instance.
    """

    ttl: int = Field(default=60, ge=0)
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
        services in `.local` and `.mdns`.

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
          - ttl (int): TTL for synthesized answers.
          - network_enabled (bool): When True, start background zeroconf browsing.
          - include_ipv4 (bool): When True, synthesize A records.
          - include_ipv6 (bool): When True, synthesize AAAA records.
          - info_timeout_ms (int): Timeout in milliseconds for fetching ServiceInfo.

        Outputs:
          - None.
        """

        self._lock = threading.RLock()

        # Records are stored keyed by *lowercased* owner name without trailing dot.
        self._ptr: Dict[str, Set[str]] = {}
        self._srv: Dict[str, _SrvValue] = {}
        self._txt: Dict[str, List[str]] = {}
        self._a: Dict[str, Set[str]] = {}
        self._aaaa: Dict[str, Set[str]] = {}

        self._ttl = int(self.config.get("ttl", 60) or 0)
        self._include_ipv4 = bool(self.config.get("include_ipv4", True))
        self._include_ipv6 = bool(self.config.get("include_ipv6", True))
        self._info_timeout_ms = int(self.config.get("info_timeout_ms", 1500) or 0)

        self._zc = None
        self._browsers = []
        self._type_browsers: Dict[str, object] = {}

        if not bool(self.config.get("network_enabled", True)):
            return

        try:
            from zeroconf import (
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

        self._zc = Zeroconf()

        # Discover all service types, then browse each type for instances.
        self._browsers.append(
            ServiceBrowser(
                self._zc,
                "_services._dns-sd._udp.local.",
                handlers=[self._on_service_type_event],
            )
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

    def _mirror_suffixes(self, fqdn: str) -> List[str]:
        """Brief: Return equivalent names under `.local` and `.mdns`.

        Inputs:
          - fqdn: FQDN (may or may not end with a trailing dot).

        Outputs:
          - list[str]: List of one or two names (without trailing dot), always
            including the original normalized name.

        Notes:
          - `.mdns` is treated as an alias for `.local`.
        """

        base = self._normalize_owner(fqdn)
        out = [base]
        if base.endswith(".local"):
            out.append(base[:-6] + ".mdns")
        elif base.endswith(".mdns"):
            out.append(base[:-5] + ".local")
        # De-dupe while preserving order.
        return list(dict.fromkeys(out))

    def _ptr_add(self, owner: str, target: str) -> None:
        """Brief: Add a PTR mapping (owner -> target) under both suffix variants.

        Inputs:
          - owner: owner name.
          - target: target name.

        Outputs:
          - None.
        """

        owners = self._mirror_suffixes(owner)
        targets = self._mirror_suffixes(target)
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

    def _on_service_type_event(self, zeroconf, service_type: str, name: str, state_change) -> None:  # type: ignore[no-untyped-def]
        """Brief: Handle PTR events for `_services._dns-sd._udp.local.`.

        Inputs:
          - zeroconf: Zeroconf instance.
          - service_type: Browsed type (always `_services._dns-sd._udp.local.`).
          - name: Service type name discovered (e.g. `_http._tcp.local.`).
          - state_change: ServiceStateChange value.

        Outputs:
          - None.
        """

        _ = zeroconf
        with self._lock:
            if getattr(state_change, "name", "") == "Removed":
                self._ptr_remove("_services._dns-sd._udp.local.", name)
                # Best-effort: stop tracking per-type browser state.
                key = self._normalize_owner(name)
                self._type_browsers.pop(key, None)
                return

            self._ptr_add("_services._dns-sd._udp.local.", name)

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

        with self._lock:
            if getattr(state_change, "name", "") == "Removed":
                self._ptr_remove(service_type, name)
                for k in self._mirror_suffixes(name):
                    self._srv.pop(k, None)
                    self._txt.pop(k, None)
                return

            # Record PTR from type -> instance.
            self._ptr_add(service_type, name)

        try:
            info = zeroconf.get_service_info(
                service_type, name, timeout=self._info_timeout_ms
            )
        except Exception:
            info = None

        if info is None:
            return

        self._ingest_service_info(info)

    def _ingest_service_info(self, info) -> None:  # type: ignore[no-untyped-def]
        """Brief: Convert a zeroconf ServiceInfo into DNS RRset caches.

        Inputs:
          - info: zeroconf.ServiceInfo instance.

        Outputs:
          - None.
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
            for inst in self._mirror_suffixes(instance_name):
                self._srv[inst] = _SrvValue(
                    priority=priority,
                    weight=weight,
                    port=port,
                    target=self._mirror_suffixes(server)[0] + ".",
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
        """Brief: Answer `.local`/`.mdns` queries from the mDNS cache when possible.

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
        if not (name_norm.endswith(".local") or name_norm.endswith(".mdns")):
            # mDNS lives under .local, and .mdns is treated as an alias.
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
