"""DockerHosts plugin: resolve container hostnames and reverse IPs via Docker.

Brief:
  - Discovers containers from one or more Docker endpoints using the Docker SDK.
  - Extracts container hostnames plus IPv4/IPv6 addresses and serves them from
    an in-memory map.
  - Answers pre_resolve queries for matching hostnames (A/AAAA) and in-addr.arpa
    / ip6.arpa-style reverse names (PTR) derived from those addresses.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from typing import Dict, Iterable, List, Optional, Tuple

from dnslib import AAAA, PTR, QTYPE, RR, A, DNSHeader, DNSRecord
from pydantic import BaseModel, Field

from foghorn.plugins.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

try:  # docker SDK is optional at import time; plugin degrades gracefully.
    import docker
    from docker.errors import DockerException
except Exception:  # pragma: no cover - environment without docker SDK installed
    docker = None  # type: ignore[assignment]

    class DockerException(Exception):  # type: ignore[no-redef]
        """Fallback DockerException used when docker SDK is unavailable."""

        pass


logger = logging.getLogger(__name__)


class DockerEndpointConfig(BaseModel):
    """Brief: Per-endpoint configuration for DockerHosts.

    Inputs:
      - url: Docker endpoint URL (e.g. "unix:///var/run/docker.sock",
        "tcp://127.0.0.1:2375").
      - reload_interval_second: Interval in seconds between background refreshes
        for this endpoint. When set to 0, the endpoint is only refreshed at
        startup (or when other endpoints cause a global refresh).
      - use_ipv4: Optional IPv4 address to use in answers instead of
        per-container IPv4 addresses discovered from this endpoint.
      - use_ipv6: Optional IPv6 address to use in answers instead of
        per-container IPv6 addresses discovered from this endpoint.
      - ttl: Optional TTL override for answers derived from this endpoint; when
        omitted, the plugin-level ttl is used.

    Outputs:
      - DockerEndpointConfig instance with normalized field types.
    """

    url: str
    reload_interval_second: float = Field(default=60.0, ge=0)
    use_ipv4: Optional[str] = None
    use_ipv6: Optional[str] = None
    ttl: Optional[int] = Field(default=None, ge=0)


class DockerHostsConfig(BaseModel):
    """Brief: Typed configuration model for DockerHosts plugin.

    Inputs:
      - endpoints: List of endpoint dictionaries.
        Each entry must contain:
          - url: Docker endpoint URL (e.g. "unix:///var/run/docker.sock",
            "tcp://127.0.0.1:2375").
        and may contain:
          - reload_interval_second: float seconds between refreshes for that
            endpoint.
          - use_ipv4: Optional IPv4 address to use instead of per-container
            IPv4 addresses for containers discovered via that endpoint.
          - use_ipv6: Optional IPv6 address to use instead of per-container
            IPv6 addresses for containers discovered via that endpoint.
          - ttl: Optional TTL override (seconds) for answers derived from that
            endpoint.
      - ttl: Plugin-level DNS answer TTL in seconds used when an endpoint does
        not specify its own ttl.

    Outputs:
      - DockerHostsConfig instance with normalized field types.
    """

    endpoints: List[DockerEndpointConfig] = Field(default_factory=list)
    ttl: int = Field(default=300, ge=0)

    class Config:
        extra = "allow"


@plugin_aliases("docker-hosts", "docker_hosts", "docker")
class DockerHosts(BasePlugin):
    """Resolve container hostnames and reverse IPs via Docker inspect.

    Brief:
      - On setup(), shell out to the Docker CLI for each configured endpoint,
        inspect all containers, and build a mapping from hostname -> IPv4/IPv6
        plus reverse pointer names (in-addr.arpa/ip6.arpa) -> hostname.
      - During pre_resolve(), answer matching A/AAAA queries with container
        addresses and PTR queries for matching reverse names.
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - DockerHostsConfig class for use by the core config loader.
        """

        return DockerHostsConfig

    def setup(self) -> None:
        """Brief: Initialize DockerHosts and build the initial container mapping.

        Inputs:
          - endpoints: Optional list of Docker endpoints in the plugin config.
          - docker_binary: Optional Docker CLI path or name.
          - ttl: Optional DNS TTL for answers.

        Outputs:
          - None; populates in-memory forward and reverse maps based on current
            Docker containers for all configured endpoints.
        """

        # Runtime configuration
        self._ttl = int(self.config.get("ttl", 300))

        # Optional default suffix applied to container names when no
        # per-endpoint suffix is provided, e.g. "docker.mycorp" so that a
        # container named "web" is published as "web.docker.mycorp".
        suffix_raw = self.config.get("suffix")
        if suffix_raw:
            base_suffix = str(suffix_raw).strip().strip(".")
            self._suffix = base_suffix.lower() if base_suffix else ""
        else:
            self._suffix = ""

        raw_endpoints = self.config.get("endpoints") or []
        endpoints_cfg: List[Dict[str, object]] = []

        # Normalize endpoint mappings; each must be a dict with a "url" key.
        for item in raw_endpoints:
            if not isinstance(item, dict):
                logger.warning(
                    "DockerHosts: ignoring non-mapping endpoint definition %r", item
                )
                continue
            url_raw = item.get("url")
            if not url_raw:
                logger.warning(
                    "DockerHosts: endpoint missing 'url'; skipping entry %r", item
                )
                continue
            url = str(url_raw).strip()
            if not url:
                logger.warning(
                    "DockerHosts: endpoint has empty 'url'; skipping entry %r", item
                )
                continue

            # Per-endpoint reload interval
            interval_raw = item.get("reload_interval_second", 60.0)
            try:
                interval = float(interval_raw)
            except (TypeError, ValueError):
                interval = 60.0
            if interval < 0:
                interval = 0.0

            # Per-endpoint host IP overrides
            host_ipv4: Optional[str] = None
            host_ipv6: Optional[str] = None
            raw_v4 = item.get("use_ipv4")
            if raw_v4:
                try:
                    ip_obj = ipaddress.ip_address(str(raw_v4))
                    if ip_obj.version == 4:
                        host_ipv4 = str(ip_obj)
                    else:
                        logger.warning(
                            "DockerHosts: use_ipv4=%r is not IPv4; ignoring", raw_v4
                        )
                except ValueError:
                    logger.warning("DockerHosts: invalid use_ipv4 %r; ignoring", raw_v4)
            raw_v6 = item.get("use_ipv6")
            if raw_v6:
                try:
                    ip_obj = ipaddress.ip_address(str(raw_v6))
                    if ip_obj.version == 6:
                        host_ipv6 = str(ip_obj)
                    else:
                        logger.warning(
                            "DockerHosts: use_ipv6=%r is not IPv6; ignoring", raw_v6
                        )
                except ValueError:
                    logger.warning("DockerHosts: invalid use_ipv6 %r; ignoring", raw_v6)

            # Per-endpoint TTL override
            ttl_override: Optional[int]
            ttl_raw = item.get("ttl")
            if ttl_raw is None:
                ttl_override = None
            else:
                try:
                    ttl_val = int(ttl_raw)
                    ttl_override = ttl_val if ttl_val >= 0 else None
                except (TypeError, ValueError):
                    logger.warning(
                        "DockerHosts: invalid ttl %r for endpoint %s; ignoring override",
                        ttl_raw,
                        url,
                    )
                    ttl_override = None

            # Optional per-endpoint suffix; when absent, we fall back to the
            # plugin-level suffix stored in self._suffix.
            ep_suffix_raw = item.get("suffix")
            if ep_suffix_raw:
                ep_suffix_base = str(ep_suffix_raw).strip().strip(".")
                ep_suffix = ep_suffix_base.lower() if ep_suffix_base else ""
            else:
                ep_suffix = ""

            endpoints_cfg.append(
                {
                    "url": url,
                    "interval": interval,
                    "host_ipv4": host_ipv4,
                    "host_ipv6": host_ipv6,
                    "ttl": ttl_override,
                    "suffix": ep_suffix,
                }
            )

        if not endpoints_cfg:
            endpoints_cfg.append(
                {
                    "url": "unix:///var/run/docker.sock",
                    "interval": 60.0,
                    "host_ipv4": None,
                    "host_ipv6": None,
                    "ttl": None,
                }
            )

        self._endpoints: List[Dict[str, object]] = endpoints_cfg

        # Shared state protected by a re-entrant lock so future refresh hooks can
        # safely update mappings.
        self._lock = threading.RLock()
        self._forward_v4: Dict[str, List[str]] = {}
        self._forward_v6: Dict[str, List[str]] = {}
        self._reverse: Dict[str, str] = {}
        # Per-name TTL maps populated by _reload_from_docker.
        self._ttl_v4: Dict[str, int] = {}
        self._ttl_v6: Dict[str, int] = {}
        self._ttl_ptr: Dict[str, int] = {}

        # Docker clients per endpoint URL (when docker SDK is available)
        self._clients: Dict[str, object] = {}
        if docker is not None:
            for ep in self._endpoints:
                url = str(ep["url"])
                try:
                    client = docker.DockerClient(base_url=url)
                except DockerException as exc:
                    logger.warning(
                        "DockerHosts: failed to create client for %s: %s", url, exc
                    )
                    continue
                self._clients[url] = client
        else:
            logger.warning(
                "DockerHosts: docker SDK is not installed; plugin will be inert until it is available"
            )

        # Compute global reload interval as the minimum positive endpoint interval
        positive_intervals = [
            float(ep["interval"]) for ep in self._endpoints if float(ep["interval"]) > 0
        ]
        self._reload_interval = min(positive_intervals) if positive_intervals else 0.0

        # Initial population from Docker.
        self._reload_from_docker()

        # Shared state protected by a re-entrant lock so future refresh hooks can
        # safely update mappings.
        self._lock = threading.RLock()
        self._forward_v4: Dict[str, List[str]] = {}
        self._forward_v6: Dict[str, List[str]] = {}
        self._reverse: Dict[str, str] = {}

        # Initial population from Docker.
        self._reload_from_docker()

        # Optionally start a background refresher to keep mappings up to date
        # without relying on signals. When reload_interval is 0 or negative, the
        # periodic loop is disabled and only the initial snapshot is used.
        if self._reload_interval > 0:
            t = threading.Thread(
                target=self._reload_loop,
                name="DockerHostsPoller",
                daemon=True,
            )
            t.start()

    def _reload_loop(self) -> None:
        """Brief: Periodically refresh container mappings on a fixed interval.

        Inputs:
          - None (uses self._reload_interval and _reload_from_docker()).

        Outputs:
          - None; runs in a background daemon thread until process exit.
        """

        import time as _time

        # Simple loop: sleep for the configured interval, then attempt a reload.
        # Any unexpected exceptions are logged and do not terminate the thread.
        interval = float(getattr(self, "_reload_interval", 0.0))
        if interval <= 0:
            return

        while True:
            _time.sleep(interval)
            try:
                self._reload_from_docker()
            except Exception:  # pragma: no cover - defensive logging
                logger.warning(
                    "DockerHosts: error during periodic reload; keeping previous mappings",
                    exc_info=True,
                )

    def _iter_containers_for_endpoint(
        self, endpoint: Dict[str, object]
    ) -> Iterable[Dict]:
        """Brief: Yield docker inspect-style dicts for containers on an endpoint.

        Inputs:
          - endpoint: Normalized endpoint mapping with "url".

        Outputs:
          - Iterable of container inspection dicts (equivalent to docker
            inspect results).
        """

        url = str(endpoint["url"])
        client = self._clients.get(url)
        if client is None:
            return []

        try:
            # Only consider running containers; stopped ones are ignored.
            containers = client.containers.list()
        except DockerException as exc:
            logger.warning(
                "DockerHosts: failed to list containers for %s: %s", url, exc
            )
            return []

        return [c.attrs for c in containers]

    def _reload_from_docker(self) -> None:
        """Brief: Rebuild in-memory host/IP maps by inspecting all containers.

        Inputs:
          - None (uses self._endpoints and Docker CLI).

        Outputs:
          - None; updates self._forward_v4/self._forward_v6/self._reverse.
        """

        new_v4: Dict[str, List[str]] = {}
        new_v6: Dict[str, List[str]] = {}
        new_reverse: Dict[str, str] = {}
        new_ttl_v4: Dict[str, int] = {}
        new_ttl_v6: Dict[str, int] = {}
        new_ttl_ptr: Dict[str, int] = {}

        total_containers = 0
        mapped_containers = 0

        for endpoint in self._endpoints:
            containers = self._iter_containers_for_endpoint(endpoint)
            containers = list(containers)
            if not containers:
                continue

            # Determine the effective TTL for records sourced from this endpoint.
            ep_ttl_override = endpoint.get("ttl")
            try:
                ep_ttl = (
                    int(ep_ttl_override)
                    if ep_ttl_override is not None
                    else int(self._ttl)
                )
            except Exception:
                ep_ttl = int(self._ttl)

            total_containers += len(containers)
            for container in containers:
                hostname, v4_list, v6_list = self._extract_container_network_data(
                    container
                )

                # When configured, prefer the host's IPs over per-container
                # addresses for that family so that all traffic for container
                # hostnames is directed at the host.
                host_ipv4 = endpoint.get("host_ipv4")
                host_ipv6 = endpoint.get("host_ipv6")
                if host_ipv4 is not None:
                    v4_list = [str(host_ipv4)]
                if host_ipv6 is not None:
                    v6_list = [str(host_ipv6)]

                # Preserve legacy behaviour: warn and skip when no hostname is
                # available at all, even if IPs exist. This matches the
                # original "warning if there's no hostname or ip found" user
                # requirement and existing tests.
                if not hostname:
                    cid = container.get("Id", "<unknown>")
                    logger.warning(
                        "DockerHosts: container %s has no hostname; skipping", cid
                    )
                    continue

                if not v4_list and not v6_list:
                    cid = container.get("Id", "<unknown>")
                    logger.warning(
                        "DockerHosts: container %s (%s) has no IPv4/IPv6; skipping",
                        cid,
                        hostname,
                    )
                    continue

                # Determine all hostnames we should map for this container:
                # - Docker Name (without leading '/')
                # - Config.Hostname (from _extract)
                # - Container ID as a last-resort alias
                raw_name = str(container.get("Name") or "").strip()
                if raw_name.startswith("/"):
                    raw_name = raw_name[1:]
                container_id = str(container.get("Id") or "").strip()

                candidate_names: List[str] = []
                if raw_name:
                    candidate_names.append(raw_name)
                if hostname and hostname != raw_name:
                    candidate_names.append(hostname)
                if container_id:
                    candidate_names.append(container_id)

                normalized_names: List[str] = []
                seen: set[str] = set()
                for n in candidate_names:
                    key = n.rstrip(".").lower()
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    normalized_names.append(key)

                if not normalized_names:
                    # No usable names even though we have IPs; fall back to
                    # container ID if possible, otherwise skip.
                    if container_id:
                        key = container_id.lower()
                        normalized_names = [key]
                    else:
                        logger.warning(
                            "DockerHosts: container %s has IPs but no usable name/ID; skipping",
                            container.get("Id", "<unknown>"),
                        )
                        continue

                # Apply any configured suffix at the endpoint or plugin level so
                # that published names become e.g. "name.suffix".
                ep_suffix = endpoint.get("suffix") or getattr(self, "_suffix", "")
                if ep_suffix:
                    # When a suffix is configured (either at the endpoint or
                    # plugin level), publish only suffixed names for this
                    # instance. Tests expect that unsuffixed hostnames are not
                    # exposed in forward mappings when a suffix is present.
                    ep_suffix = str(ep_suffix).strip().strip(".").lower()
                    names_for_mapping = [f"{n}.{ep_suffix}" for n in normalized_names]
                else:
                    # No suffix configured: publish raw normalized names.
                    names_for_mapping = list(normalized_names)

                # Choose the canonical name for reverse PTRs: prefer the Docker
                # Name, then the extracted hostname, then the container ID, and
                # apply the same suffix (if any).
                if raw_name:
                    base_canonical = raw_name.rstrip(".").lower()
                elif hostname:
                    base_canonical = str(hostname).rstrip(".").lower()
                else:
                    base_canonical = container_id or normalized_names[0]

                if ep_suffix:
                    ptr_canonical = f"{base_canonical}.{ep_suffix}"
                else:
                    ptr_canonical = base_canonical

                mapped_containers += 1

                # Record per-name TTLs for this endpoint; later endpoints win on
                # conflicts, mirroring how address lists are merged.
                for key in names_for_mapping:
                    new_ttl_v4.setdefault(key, ep_ttl)
                    new_ttl_v6.setdefault(key, ep_ttl)

                # Build forward maps and reverse PTRs.
                if v4_list:
                    for key in names_for_mapping:
                        existing_v4 = new_v4.setdefault(key, [])
                        for ip in v4_list:
                            if ip not in existing_v4:
                                existing_v4.append(ip)
                            try:
                                ptr_name = ipaddress.ip_address(ip).reverse_pointer
                                new_reverse.setdefault(ptr_name, ptr_canonical)
                                new_ttl_ptr[ptr_name] = ep_ttl
                            except ValueError:
                                logger.warning(
                                    "DockerHosts: invalid IPv4 address %r for %s; skipping",
                                    ip,
                                    ptr_canonical,
                                )

                if v6_list:
                    for key in names_for_mapping:
                        existing_v6 = new_v6.setdefault(key, [])
                        for ip in v6_list:
                            if ip not in existing_v6:
                                existing_v6.append(ip)
                            try:
                                ptr_name = ipaddress.ip_address(ip).reverse_pointer
                                new_reverse.setdefault(ptr_name, ptr_canonical)
                                new_ttl_ptr[ptr_name] = ep_ttl
                            except ValueError:
                                logger.warning(
                                    "DockerHosts: invalid IPv6 address %r for %s; skipping",
                                    ip,
                                    ptr_canonical,
                                )

                # Debug: show the effective mapping for this container after
                # per-endpoint overrides have been applied.
                if v4_list or v6_list:
                    logger.debug(
                        "DockerHosts: %s -> v4=%s v6=%s (ttl=%s)",
                        ",".join(names_for_mapping),
                        v4_list or [],
                        v6_list or [],
                        ep_ttl,
                    )

        if total_containers and not mapped_containers:
            logger.warning(
                "DockerHosts: inspected %d containers but none had usable hostname/IP",
                total_containers,
            )
        elif not new_v4 and not new_v6:
            logger.warning(
                "DockerHosts: no hostname/IP mappings were added from any endpoint (no running containers or all were skipped)",
            )

        # Swap mappings under lock so readers always see a consistent view.
        with self._lock:
            self._forward_v4 = new_v4
            self._forward_v6 = new_v6
            self._reverse = new_reverse
            self._ttl_v4 = new_ttl_v4
            self._ttl_v6 = new_ttl_v6
            self._ttl_ptr = new_ttl_ptr

    @staticmethod
    def _extract_container_network_data(
        container: Dict,
    ) -> Tuple[Optional[str], List[str], List[str]]:
        """Brief: Extract hostname and IP addresses from a docker inspect record.

        Inputs:
          - container: Mapping parsed from docker inspect JSON.

        Outputs:
          - (hostname, ipv4_list, ipv6_list):
            - hostname is the preferred DNS name for the container, chosen as:
              1) container["Name"] with any leading '/' stripped, if present
              2) Config.Hostname when Name is not set or empty
            - IP lists contain unique IPv4/IPv6 address strings.
        """

        cfg = container.get("Config") or {}

        # Prefer the Docker container Name (e.g. "/web") over Config.Hostname,
        # which is often the container ID. This makes mappings line up with the
        # names operators expect to query.
        raw_name = str(container.get("Name") or "").strip()
        if raw_name.startswith("/"):
            raw_name = raw_name[1:]

        cfg_hostname = str(cfg.get("Hostname") or "").strip()

        hostname = raw_name or cfg_hostname or ""
        if hostname:
            hostname = hostname.strip()
        if not hostname:
            hostname = None

        nets = (container.get("NetworkSettings") or {}).get("Networks") or {}

        v4_set: List[str] = []
        v6_set: List[str] = []

        def _add_ip(target: List[str], value: Optional[str]) -> None:
            if not value:
                return
            text = str(value).strip()
            if text and text not in target:
                target.append(text)

        for net in nets.values():
            _add_ip(v4_set, net.get("IPAddress"))
            _add_ip(v6_set, net.get("GlobalIPv6Address"))

        # Fallback to legacy top-level fields if present.
        net_settings = container.get("NetworkSettings") or {}
        _add_ip(v4_set, net_settings.get("IPAddress"))
        _add_ip(v6_set, net_settings.get("GlobalIPv6Address"))

        return hostname, v4_set, v6_set

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Answer A/AAAA/PTR queries using Docker hostname/IP mappings.

        Inputs:
          - qname: The queried domain name.
          - qtype: DNS query type (A, AAAA, PTR, etc.).
          - req: Raw DNS request wire bytes.
          - ctx: PluginContext for the client request.

        Outputs:
          - PluginDecision("override") when a matching container mapping is
            found; otherwise None to allow normal resolution.
        """

        if not self.targets(ctx):
            return None

        name = qname.rstrip(".").lower()

        if qtype == QTYPE.A:
            with self._lock:
                candidates = list(self._forward_v4.get(name, []))
                ttl = int(self._ttl_v4.get(name, self._ttl))
            if not candidates:
                return None
            wire = self._make_ip_response(qname, QTYPE.A, req, candidates, ttl)
            return PluginDecision(action="override", response=wire)

        if qtype == QTYPE.AAAA:
            with self._lock:
                candidates = list(self._forward_v6.get(name, []))
                ttl = int(self._ttl_v6.get(name, self._ttl))
            if not candidates:
                return None
            wire = self._make_ip_response(qname, QTYPE.AAAA, req, candidates, ttl)
            return PluginDecision(action="override", response=wire)

        if qtype == QTYPE.PTR:
            with self._lock:
                hostname = self._reverse.get(name)
                ttl = int(self._ttl_ptr.get(name, self._ttl))
            if not hostname:
                return None

            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("DockerHosts: parse failure for PTR %s: %s", qname, exc)
                return PluginDecision(action="override", response=None)

            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.PTR,
                    rclass=1,
                    ttl=ttl,
                    rdata=PTR(str(hostname).rstrip(".") + "."),
                )
            )
            return PluginDecision(action="override", response=reply.pack())

        return None

    def _make_ip_response(
        self,
        qname: str,
        query_type: int,
        raw_req: bytes,
        ipaddrs: List[str],
        ttl: int,
    ) -> Optional[bytes]:
        """Brief: Build an A/AAAA response with a specific TTL.

        Inputs:
          - qname: Queried name (unused; kept for symmetry).
          - query_type: QTYPE.A or QTYPE.AAAA.
          - raw_req: Original DNS request wire.
          - ipaddrs: List of IPv4/IPv6 strings to place in the answer.
          - ttl: TTL to apply to the answer records.

        Outputs:
          - Packed DNS response bytes containing one RR per IP, or None on
            parse failure.
        """

        try:
            request = DNSRecord.parse(raw_req)
        except Exception as exc:
            logger.warning("DockerHosts: parse failure building response: %s", exc)
            return None

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        if query_type == QTYPE.A:
            for ipaddr in ipaddrs:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=ttl,
                        rdata=A(ipaddr),
                    )
                )
        elif query_type == QTYPE.AAAA:
            for ipaddr in ipaddrs:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.AAAA,
                        rclass=1,
                        ttl=ttl,
                        rdata=AAAA(ipaddr),
                    )
                )

        return reply.pack()
