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

from dnslib import AAAA, PTR, QTYPE, RR, A, DNSHeader, DNSRecord, TXT
from pydantic import BaseModel, Field

try:  # cachetools is an optional dependency; fall back to no-op cache when missing.
    from cachetools import TTLCache, cached  # type: ignore[import]
except Exception:  # pragma: no cover - defensive optional dependency handling

    class TTLCache(dict):  # type: ignore[override]
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401 - simple shim
            """Lightweight TTLCache shim when cachetools is unavailable."""
            super().__init__()

    def cached(*, cache, **kwargs):  # type: ignore[no-redef]
        """No-op cached decorator used when cachetools is unavailable."""

        def decorator(func):
            return func

        return decorator


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

# Short-lived caches for suffix owner helpers. These are pure string transforms
# used during periodic reload and do not affect resolver statistics semantics.
_DOCKER_AGG_OWNER_CACHE: TTLCache = TTLCache(maxsize=1024, ttl=30)
_DOCKER_HOSTS_OWNER_CACHE: TTLCache = TTLCache(maxsize=1024, ttl=30)


class DockerEndpointConfig(BaseModel):
    """Brief: Per-endpoint configuration for DockerHosts.

    In addition to full container names and IDs, DockerHosts also exposes a
    short container ID alias (the first 12 hex characters) for convenience.

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
      - health: List of acceptable container health/status values. Supported:
        "starting", "healthy", "running", "unhealthy". Default:
        ["healthy", "running"].
      - discovery: When true, publish a TXT record at
        "_containers.<suffix>" (or "_containers" when no suffix is configured)
        containing container summary lines, plus a host-level summary under
        "_hosts.<suffix>" (or "_hosts").

    Outputs:
      - DockerHostsConfig instance with normalized field types.
    """

    endpoints: List[DockerEndpointConfig] = Field(default_factory=list)
    ttl: int = Field(default=300, ge=0)
    health: List[str] = Field(default_factory=lambda: ["healthy", "running"])
    discovery: bool = Field(default=False)

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
          - ttl: Optional DNS TTL for answers.
          - health: Optional list of acceptable container health/status values.
          - discovery: Optional bool to publish a "_docker" TXT record.

        Outputs:
          - None; populates in-memory forward/reverse maps and (optionally)
            aggregate TXT entries based on current Docker containers.
        """

        # Runtime configuration
        self._ttl = int(self.config.get("ttl", 300))

        # Health/status allowlist. Containers whose effective health/status is
        # not in this list are skipped.
        raw_health = self.config.get("health")
        if raw_health is None:
            health_items: List[str] = ["healthy", "running"]
        elif isinstance(raw_health, str):
            health_items = [raw_health]
        elif isinstance(raw_health, list):
            health_items = [str(x) for x in raw_health]
        else:
            health_items = [str(raw_health)]

        allowed = {"starting", "healthy", "running", "unhealthy"}
        health_norm: List[str] = []
        for item in health_items:
            key = str(item).strip().lower()
            if not key:
                continue
            if key not in allowed:
                logger.warning(
                    "DockerHosts: ignoring unsupported health status %r (supported: %s)",
                    item,
                    ",".join(sorted(allowed)),
                )
                continue
            if key not in health_norm:
                health_norm.append(key)
        self._health_allowlist = health_norm

        # When true, publish a TXT record at _containers.<suffix> (or
        # _containers when no suffix is set) plus a host-level summary at
        # _hosts.<suffix> (or _hosts).
        self._discovery = bool(self.config.get("discovery", False))

        # Optional default suffix applied to container names when no
        # per-endpoint suffix is provided, e.g. "docker.mycorp" so that a
        # container named "web" is published as "web.docker.mycorp".
        suffix_raw = self.config.get("suffix")
        if suffix_raw:
            base_suffix = str(suffix_raw).strip().strip(".")
            if base_suffix:
                # Normalize any internal runs of dots and remove empty labels so
                # values like "docker..zaa" become "docker.zaa".
                parts = [p for p in base_suffix.split(".") if p]
                self._suffix = ".".join(parts).lower() if parts else ""
            else:
                self._suffix = ""
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
                if ep_suffix_base:
                    parts = [p for p in ep_suffix_base.split(".") if p]
                    ep_suffix = ".".join(parts).lower() if parts else ""
                else:
                    ep_suffix = ""
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
        self._aggregate_txt: Dict[str, List[str]] = {}
        self._ttl_txt: Dict[str, int] = {}

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

        # Lazily create a client for this endpoint so that connection failures
        # during setup do not permanently disable refreshes. Each reload cycle
        # can retry endpoints that were previously unreachable.
        if client is None and docker is not None:
            try:
                client = docker.DockerClient(base_url=url)
            except DockerException as exc:  # pragma: no cover - connection errors
                logger.warning(
                    "DockerHosts: failed to create client for %s during reload: %s",
                    url,
                    exc,
                )
                return []
            else:
                self._clients[url] = client
        elif client is None:
            # docker SDK is unavailable; nothing to do for this endpoint.
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
          - None (uses self._endpoints).

        Outputs:
          - None; updates self._forward_v4/self._forward_v6/self._reverse and
            (optionally) self._aggregate_txt.
        """

        new_v4: Dict[str, List[str]] = {}
        new_v6: Dict[str, List[str]] = {}
        new_reverse: Dict[str, str] = {}
        new_ttl_v4: Dict[str, int] = {}
        new_ttl_v6: Dict[str, int] = {}
        new_ttl_ptr: Dict[str, int] = {}
        new_txt: Dict[str, List[str]] = {}
        new_ttl_txt: Dict[str, int] = {}

        total_containers = 0
        mapped_containers = 0

        for endpoint in self._endpoints:
            containers = self._iter_containers_for_endpoint(endpoint)
            containers = list(containers)
            if not containers:
                # If we cannot reach the endpoint or there are no running
                # containers, avoid publishing any _hosts TXT for it this
                # cycle so that unreachable hosts disappear from discovery
                # results. Next reload will retry the connection.
                continue

            # When discovery is enabled and we have successfully listed
            # containers for this endpoint, emit a host-level TXT summary for
            # the endpoint under _hosts.<suffix> (or _hosts).
            if self._discovery:
                ep_suffix = endpoint.get("suffix") or getattr(self, "_suffix", "")
                record_owner = self._hosts_owner_for_suffix(
                    str(ep_suffix or "").strip()
                )
                host_ipv4 = endpoint.get("host_ipv4") or ""
                host_ipv6 = endpoint.get("host_ipv6") or ""
                parts: List[str] = []
                url = str(endpoint.get("url"))
                if url:
                    parts.append(f"endpoint={url}")
                if host_ipv4:
                    parts.append(f"ans4={host_ipv4}")
                if host_ipv6:
                    parts.append(f"ans6={host_ipv6}")
                line = " ".join(parts)
                if line:
                    new_txt.setdefault(record_owner, []).append(line)
                    new_ttl_txt[record_owner] = int(self._ttl)

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
                # Filter by configured container health/status.
                effective_health = self._container_effective_health(container)
                if (
                    self._health_allowlist
                    and effective_health not in self._health_allowlist
                ):
                    continue

                hostname, internal_v4, internal_v6 = (
                    self._extract_container_network_data(container)
                )

                # When configured, prefer the host's IPs over per-container
                # addresses for that family so that all traffic for container
                # hostnames is directed at the host.
                v4_list = list(internal_v4)
                v6_list = list(internal_v6)
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
                # - Optional project name label (when distinct from name/image)
                raw_name = str(container.get("Name") or "").strip()
                if raw_name.startswith("/"):
                    raw_name = raw_name[1:]
                container_id = str(container.get("Id") or "").strip()

                cfg = container.get("Config") or {}
                labels = cfg.get("Labels") if isinstance(cfg, dict) else None
                if not isinstance(labels, dict):
                    labels = {}

                project_name_raw = labels.get(
                    "com.docker.compose.project"
                ) or labels.get("io.kubernetes.pod.namespace")
                project_name = str(project_name_raw).strip() if project_name_raw else ""

                image_raw = ""
                if isinstance(cfg, dict):
                    image_raw = str(cfg.get("Image") or "").strip()
                image_norm = image_raw.lower()
                image_repo = image_norm.split("@")[0].split(":")[0]

                def _norm_ident(value: str) -> str:
                    # Normalize identifiers used as DNS labels so they never
                    # begin or end with a dot and are case-insensitive.
                    return str(value).strip().strip(".").lower()

                candidate_names: List[str] = []
                if raw_name:
                    candidate_names.append(raw_name)
                if hostname and hostname != raw_name:
                    candidate_names.append(hostname)
                if project_name:
                    pn = _norm_ident(project_name)
                    rn = _norm_ident(raw_name)
                    hn = _norm_ident(hostname or "")
                    if pn and pn not in {rn, hn} and pn not in {image_norm, image_repo}:
                        candidate_names.append(project_name)
                if container_id:
                    # Include both short and full IDs so lookups by abbreviated
                    # container ID work when rendered into hosts-style records
                    # or when querying via PTR names generated from these labels.
                    candidate_names.append(container_id[:12])
                    candidate_names.append(container_id)

                normalized_names: List[str] = []
                seen: set[str] = set()
                for n in candidate_names:
                    # Ensure normalized names do not retain any leading or
                    # trailing dots so we never publish names that begin with
                    # ".".
                    key = n.strip(".").lower()
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    normalized_names.append(key)

                if (
                    not normalized_names
                ):  # pragma: no cover - unreachable (container_id or hostname always yields at least one name)
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
                    raw_suffix = str(ep_suffix).strip().strip(".")
                    parts = [p for p in raw_suffix.split(".") if p]
                    ep_suffix = ".".join(parts).lower() if parts else ""
                    if ep_suffix:
                        names_for_mapping = [
                            f"{n}.{ep_suffix}" for n in normalized_names
                        ]
                    else:
                        names_for_mapping = list(normalized_names)
                else:
                    # No suffix configured: publish raw normalized names.
                    names_for_mapping = list(normalized_names)

                # Choose the canonical name for reverse PTRs: prefer the Docker
                # Name, then the extracted hostname, then the container ID, and
                # apply the same suffix (if any).
                if raw_name:
                    base_canonical = raw_name.strip(".").lower()
                elif hostname:
                    base_canonical = str(hostname).strip(".").lower()
                else:  # pragma: no cover - unreachable because containers without hostname are skipped above
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

                # Build a summary line for this container.
                line = self._format_aggregate_line(
                    container=container,
                    canonical=ptr_canonical,
                    aliases=names_for_mapping,
                    endpoint_url=str(endpoint.get("url")),
                    effective_health=effective_health,
                    project_name=project_name,
                    internal_v4=internal_v4,
                    internal_v6=internal_v6,
                    answer_v4=v4_list,
                    answer_v6=v6_list,
                )

                # Per-container TXT records: publish a TXT record at each
                # published hostname containing the same information that would
                # appear in the aggregate _containers TXT, but scoped to this
                # container.
                for owner in names_for_mapping:
                    new_txt.setdefault(owner, []).append(line)
                    new_ttl_txt[owner] = ep_ttl

                # Optional aggregate TXT record (_containers.<suffix>) that
                # summarizes all containers.
                if self._discovery:
                    record_owner = self._aggregate_owner_for_suffix(
                        str(ep_suffix or "").strip()
                    )
                    new_txt.setdefault(record_owner, []).append(line)
                    new_ttl_txt[record_owner] = int(self._ttl)

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

        # Prepend a header line to each TXT record collection (if enabled).
        if new_txt:
            for owner, lines in new_txt.items():
                # For container- and aggregate-level owners, containers==len(lines).
                # For host-level owners (_hosts.*), use hosts==len(lines).
                if owner.startswith("_hosts"):
                    lines.insert(0, f"hosts={len(lines)}")
                else:
                    lines.insert(0, f"containers={len(lines)}")

        # Swap mappings under lock so readers always see a consistent view.
        with self._lock:
            self._forward_v4 = new_v4
            self._forward_v6 = new_v6
            self._reverse = new_reverse
            self._ttl_v4 = new_ttl_v4
            self._ttl_v6 = new_ttl_v6
            self._ttl_ptr = new_ttl_ptr
            self._aggregate_txt = new_txt
            self._ttl_txt = new_ttl_txt

    @staticmethod
    def _container_effective_health(container: Dict) -> str:
        """Brief: Determine the effective health/status string for a container.

        Inputs:
          - container: Docker inspect-style dict.

        Outputs:
          - One of: "starting", "healthy", "unhealthy", "running".

        Notes:
          - If Docker health checks are present, this prefers
            container["State"]["Health"]["Status"].
          - Otherwise it falls back to container["State"]["Status"], and then to
            "running" when status is missing.
        """

        state = container.get("State") or {}
        if isinstance(state, dict):
            health = state.get("Health") or {}
            if isinstance(health, dict):
                hs = health.get("Status")
                if hs:
                    return str(hs).strip().lower()
            s = state.get("Status")
            if s:
                return str(s).strip().lower()
        return "running"

    @staticmethod
    @cached(cache=_DOCKER_AGG_OWNER_CACHE)
    def _aggregate_owner_for_suffix(suffix: str) -> str:
        """Brief: Build the container aggregate TXT owner name for a suffix.

        Inputs:
          - suffix: DNS suffix (may be empty, may contain trailing dots).

        Outputs:
          - Normalized owner name for the aggregate TXT record.
            - With suffix: "_containers.<suffix>"
            - Without suffix: "_containers"
        """

        # Normalize suffix so that it never begins or ends with a dot and
        # collapse any repeated dots (e.g. "docker..zaa" -> "docker.zaa").
        raw = str(suffix).strip().strip(".")
        parts = [p for p in raw.split(".") if p]
        suf = ".".join(parts).lower()
        if suf:
            return f"_containers.{suf}"
        return "_containers"

    @staticmethod
    @cached(cache=_DOCKER_HOSTS_OWNER_CACHE)
    def _hosts_owner_for_suffix(suffix: str) -> str:
        """Brief: Build the host-level TXT owner name for a suffix.

        Inputs:
          - suffix: DNS suffix (may be empty, may contain trailing dots).

        Outputs:
          - Normalized owner name for the host summary TXT record.
            - With suffix: "_hosts.<suffix>"
            - Without suffix: "_hosts"
        """

        raw = str(suffix).strip().strip(".")
        parts = [p for p in raw.split(".") if p]
        suf = ".".join(parts).lower()
        if suf:
            return f"_hosts.{suf}"
        return "_hosts"

    @staticmethod
    def _format_aggregate_line(
        *,
        container: Dict,
        canonical: str,
        aliases: List[str],
        endpoint_url: str,
        effective_health: str,
        project_name: str,
        internal_v4: List[str],
        internal_v6: List[str],
        answer_v4: List[str],
        answer_v6: List[str],
        max_len: int = 240,
    ) -> str:
        """Brief: Build a compact, single-string summary for the aggregate TXT record.

        Inputs:
          - container: Docker inspect-style dict.
          - canonical: Canonical published name for PTRs.
          - aliases: All published aliases for the container.
          - endpoint_url: Docker endpoint URL for this container.
          - effective_health: Effective health/status string.
          - project_name: Project/stack name (best-effort label-derived string).
          - internal_v4/internal_v6: Container IPs discovered from inspect.
          - answer_v4/answer_v6: IPs that DockerHosts will actually answer with
            (after host overrides).
          - max_len: Maximum length for the returned TXT chunk.

        Outputs:
          - A string suitable for inclusion as one TXT "character-string".
        """

        cfg = container.get("Config") or {}
        labels = cfg.get("Labels") if isinstance(cfg, dict) else None
        if not isinstance(labels, dict):
            labels = {}

        svc = labels.get("com.docker.compose.service") or labels.get(
            "io.kubernetes.container.name"
        )
        proj = str(project_name).strip() if project_name else ""

        def _join(items: List[str], limit: int = 4) -> str:
            vals = [str(x) for x in items if str(x).strip()]
            if len(vals) > limit:
                return ",".join(vals[:limit]) + f"+{len(vals) - limit}"
            return ",".join(vals)

        def _is_full_container_id(name: str) -> bool:
            # Docker container IDs are typically 64 hex characters.
            token = str(name).strip().split(".", 1)[0].lower()
            if len(token) != 64:
                return False
            return all(c in "0123456789abcdef" for c in token)

        # Filter aliases for aggregate TXT: omit full container IDs.
        filtered_aliases = [a for a in aliases if a and not _is_full_container_id(a)]

        # Collect HostPorts (bindings) for a compact summary.
        ports = (container.get("NetworkSettings") or {}).get("Ports") or {}
        hostports: List[str] = []
        if isinstance(ports, dict):
            for _port_key, bindings in ports.items():
                if not bindings:
                    continue
                if isinstance(bindings, list):
                    for b in bindings:
                        if not isinstance(b, dict):
                            continue
                        hp = str(b.get("HostPort") or "").strip()
                        if hp and hp not in hostports:
                            hostports.append(hp)

        # Additional network summaries (best-effort; keep short).
        nets = (container.get("NetworkSettings") or {}).get("Networks") or {}
        net_parts: List[str] = []
        if isinstance(nets, dict):
            for net_name, net in nets.items():
                if not isinstance(net, dict):
                    continue
                ip4 = str(net.get("IPAddress") or "").strip()
                ip6 = str(net.get("GlobalIPv6Address") or "").strip()
                if not ip4 and not ip6:
                    continue
                seg = f"{net_name}:{ip4 or '-'}"
                if ip6:
                    seg += f"/{ip6}"
                net_parts.append(seg)

        # Ordering requested:
        # name, ans4/ans6, endpoint, HostPorts used, then everything else.
        pieces: List[str] = []
        if canonical:
            pieces.append(f"name={canonical}")
        if answer_v4:
            pieces.append(f"ans4={_join(answer_v4)}")
        if answer_v6:
            pieces.append(f"ans6={_join(answer_v6)}")
        if endpoint_url:
            pieces.append(f"endpoint={endpoint_url}")
        if hostports:
            pieces.append(f"hostports={_join(hostports)}")

        # Remaining fields (omit empties).
        if effective_health:
            pieces.append(f"health={effective_health}")
        if proj:
            pieces.append(f"project-name={proj}")
        if svc:
            pieces.append(f"service={svc}")
        if filtered_aliases:
            pieces.append(f"aliases={_join(filtered_aliases, limit=3)}")
        if internal_v4:
            pieces.append(f"int4={_join(internal_v4)}")
        if internal_v6:
            pieces.append(f"int6={_join(internal_v6)}")
        if net_parts:
            pieces.append(f"nets={_join(net_parts, limit=3)}")

        s = " ".join(pieces)
        if len(s) > max_len:
            return s[: max_len - 3] + "..."
        return s

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

    def _make_ip_response(
        self,
        qname: str,
        qtype: int,
        req: bytes,
        addrs: List[str],
        ttl: int,
    ) -> Optional[bytes]:
        """Brief: Build a minimal A/AAAA DNS response for a single owner.

        Inputs:
          - qname: Owner name for the DNS question (as a string).
          - qtype: Numeric QTYPE (typically QTYPE.A or QTYPE.AAAA).
          - req: Raw DNS request wire bytes.
          - addrs: List of IP address strings to include as answers.
          - ttl: Integer TTL (seconds) to apply to each answer RR.

        Outputs:
          - Optional[bytes]: Packed DNS response bytes on success, or None when
            the incoming packet cannot be parsed.

        Notes:
          - This helper is used by tests to exercise parse-failure behaviour and
            keeps the response-building logic in one place.
        """

        try:
            request = DNSRecord.parse(req)
        except Exception as exc:
            log = getattr(self, "logger", logger)
            log.warning(
                "DockerHosts: parse failure building response for %s %s: %s",
                qname,
                QTYPE.get(qtype, str(qtype)),
                exc,
            )
            return None

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        if not addrs:
            return reply.pack()

        for ipaddr in addrs:
            if qtype == QTYPE.AAAA:
                rdata = AAAA(ipaddr)
                rtype = QTYPE.AAAA
            else:
                # Default to A for unknown/other qtypes; callers only use A/AAAA.
                rdata = A(ipaddr)
                rtype = QTYPE.A

            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=rtype,
                    rclass=1,
                    ttl=int(ttl),
                    rdata=rdata,
                )
            )

        return reply.pack()

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Answer A/AAAA/PTR (and optional TXT) queries using Docker mappings.

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

        # Normalize queried name: trim leading/trailing dots and lowercase so
        # that stray leading dots do not prevent lookups (e.g. ".foo.example").
        name = qname.strip(".").lower()

        if qtype == QTYPE.A:
            # For docker hostnames, answer A queries and also include any
            # per-host TXT summaries in the same reply.
            with self._lock:
                a_candidates = list(self._forward_v4.get(name, []))
                a_ttl = int(self._ttl_v4.get(name, self._ttl))
                txts = list(self._aggregate_txt.get(name, []))
                txt_ttl = int(self._ttl_txt.get(name, self._ttl))

            if not a_candidates and not txts:
                return None

            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("DockerHosts: parse failure for A %s: %s", qname, exc)
                return PluginDecision(action="override", response=None)

            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
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

            for line in txts:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.TXT,
                        rclass=1,
                        ttl=txt_ttl,
                        rdata=TXT([str(line)]),
                    )
                )

            return PluginDecision(action="override", response=reply.pack())

        if qtype == QTYPE.AAAA:
            # For docker hostnames, answer AAAA queries and also include any
            # per-host TXT summaries in the same reply.
            with self._lock:
                aaaa_candidates = list(self._forward_v6.get(name, []))
                aaaa_ttl = int(self._ttl_v6.get(name, self._ttl))
                txts = list(self._aggregate_txt.get(name, []))
                txt_ttl = int(self._ttl_txt.get(name, self._ttl))

            if not aaaa_candidates and not txts:
                return None

            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("DockerHosts: parse failure for AAAA %s: %s", qname, exc)
                return PluginDecision(action="override", response=None)

            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
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

            for line in txts:
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.TXT,
                        rclass=1,
                        ttl=txt_ttl,
                        rdata=TXT([str(line)]),
                    )
                )

            return PluginDecision(action="override", response=reply.pack())

        if qtype == QTYPE.TXT:
            # When TXT is requested for a docker host, also include any A/AAAA
            # records for that host in the same response.
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
                logger.warning("DockerHosts: parse failure for TXT %s: %s", qname, exc)
                return PluginDecision(action="override", response=None)

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
                        rdata=TXT([str(line)]),
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
