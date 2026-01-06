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

try:  # cachetools is an optional dependency; fall back to shim when missing.
    from cachetools import TTLCache  # type: ignore[import]
    from foghorn.utils.register_caches import registered_cached
except (
    Exception
):  # pragma: nocover defensive: optional cachetools dependency may be absent in some environments

    class TTLCache(dict):  # type: ignore[override]
        def __init__(self, *args, **kwargs) -> None:  # noqa: D401 - simple shim
            """Lightweight TTLCache shim when cachetools is unavailable."""
            super().__init__()

    def registered_cached(*, cache, **kwargs):  # type: ignore[no-redef]
        """No-op registered_cached decorator used when cachetools is unavailable."""

        def decorator(func):
            return func

        return decorator


from foghorn.plugins.resolve.base import (
    AdminPageSpec,
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

try:  # docker SDK is optional at import time; plugin degrades gracefully.
    import docker
    from docker.errors import DockerException
except (
    Exception
):  # pragma: nocover defensive: allow import in environments without docker SDK installed
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

        # Optional per-container TXT customisation driven by docker inspect
        # JSONPath-like expressions. When txt_fields is provided, each entry
        # must be a mapping with at least:
        #   - name: field name used in TXT output (e.g. "image").
        #   - path: JSONPath-like expression evaluated against the container
        #           inspect dict (e.g. "Config.Image").
        #
        # When txt_fields_replace is true and at least one custom field
        # resolves for a container, only those custom fields are emitted in the
        # TXT line; otherwise they are appended to the default summary.
        raw_txt_fields = self.config.get("txt_fields") or []
        txt_fields: List[Tuple[str, str]] = []
        if isinstance(raw_txt_fields, list):
            for item in raw_txt_fields:
                if not isinstance(item, dict):
                    logger.warning(
                        "DockerHosts: ignoring non-mapping txt_fields entry %r", item
                    )
                    continue
                name_val = str(item.get("name") or "").strip()
                path_val = str(item.get("path") or "").strip()
                if not name_val or not path_val:
                    logger.warning(
                        "DockerHosts: ignoring txt_fields entry missing name/path: %r",
                        item,
                    )
                    continue
                txt_fields.append((name_val, path_val))
        elif raw_txt_fields:
            logger.warning(
                "DockerHosts: txt_fields must be a list when set; got %r",
                type(raw_txt_fields),
            )

        self._txt_fields: List[Tuple[str, str]] = txt_fields
        self._txt_fields_replace: bool = bool(
            self.config.get("txt_fields_replace", False)
        )

        # Optional: when txt_fields_replace is true, preserve a subset of the
        # built-in TXT summary keys (for example "ans4", "endpoint"). Any
        # listed keys are only kept when they exist for the container; missing
        # ones are silently ignored.
        raw_txt_keep = self.config.get("txt_fields_keep") or []
        txt_fields_keep: List[str] = []
        if isinstance(raw_txt_keep, list):
            for item in raw_txt_keep:
                text = str(item or "").strip()
                if not text:
                    continue
                txt_fields_keep.append(text)
        elif raw_txt_keep:
            logger.warning(
                "DockerHosts: txt_fields_keep must be a list when set; got %r",
                type(raw_txt_keep),
            )

        self._txt_fields_keep: List[str] = txt_fields_keep

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
        # Per-host exported ports (hostports) for admin UI display.
        self._hostports: Dict[str, List[str]] = {}

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
            except (
                Exception
            ) as exc:  # pragma: nocover defensive: periodic reload failures are logged but not worth fragile tests
                # Avoid emitting a full stack trace for periodic reload failures so
                # that transient Docker connectivity issues do not flood logs.
                logger.warning(
                    "DockerHosts: error during periodic reload; keeping previous mappings: %s",
                    exc,
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
            except (
                Exception
            ) as exc:  # pragma: nocover defensive: connection and auth errors depend on external Docker daemon state
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
            # Accessing container.attrs also performs a Docker API query, so
            # treat any exception raised there as a connection/query failure for
            # this endpoint and drop all containers from this host until the
            # next interval so that stale mappings disappear when a host is
            # unreachable.
            containers = client.containers.list()
            return [c.attrs for c in containers]
        except Exception as exc:
            logger.warning(
                "DockerHosts: failed to list containers for %s: %s", url, exc
            )
            return []

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
        new_hostports: Dict[str, List[str]] = {}

        total_containers = 0
        mapped_containers = 0

        # Accumulate aliases per canonical container name so that containers
        # sharing the same canonical name end up with a single unified alias
        # set in TXT/Info (front-end groups by TXT).
        canonical_aliases: Dict[str, set[str]] = {}

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
                    # For display, shorten tcp://host:port endpoints to just
                    # the host name so TXT/Info stays compact. Other schemes
                    # (e.g. unix://) are left as-is.
                    if url.startswith("tcp://"):
                        disp = url[len("tcp://") :]
                        # Strip :port when present.
                        host_only = disp.split(":", 1)[0]
                        parts.append(f"endpoint={host_only}")
                    else:
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

                if isinstance(cfg, dict):
                    _ = str(cfg.get("Image") or "").strip()

                def _strip_env_domain(value: str) -> str:
                    # Best-effort: strip compose-style domain placeholder suffixes
                    # like "${DOMAIN}" or ".${DOMAIN}" from names before using
                    # them as DNS labels.
                    s = str(value or "").strip()
                    if not s:
                        return s
                    for suf in (".${DOMAIN}", "${DOMAIN}"):
                        if s.endswith(suf):
                            s = s[: -len(suf)]
                            break
                    return s

                def _norm_ident(value: str) -> str:
                    # Normalize identifiers used as DNS labels so they never
                    # begin or end with a dot and are case-insensitive.
                    return _strip_env_domain(str(value)).strip().strip(".").lower()

                # Apply ${DOMAIN} stripping to primary docker names as well.
                raw_name = _strip_env_domain(raw_name)
                hostname = _strip_env_domain(hostname) if hostname else hostname

                candidate_names: List[str] = []
                if raw_name:
                    candidate_names.append(raw_name)
                if hostname and hostname != raw_name:
                    candidate_names.append(hostname)
                # Note: project-name is no longer used as a DNS label source; it is
                # retained only for metadata in TXT/Info summaries.
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
                ):  # pragma: nocover defensive: unreachable under normal docker inspect data (hostname or Id always yields at least one name)
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
                else:  # pragma: nocover defensive: unreachable because containers without hostname are skipped earlier in _reload_from_docker
                    base_canonical = container_id or normalized_names[0]

                if ep_suffix:
                    ptr_canonical = f"{base_canonical}.{ep_suffix}"
                else:
                    ptr_canonical = base_canonical

                # Merge aliases for this canonical name across all containers so
                # that TXT/Info can present a single record per name.
                alias_set = canonical_aliases.setdefault(ptr_canonical, set())
                for n in names_for_mapping:
                    alias_set.add(n)

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

                # Build a summary line for this container and capture hostports
                # for admin display. Aliases passed here are the union for the
                # canonical name, not just this specific instance.
                line, hostports = self._format_aggregate_line(
                    container=container,
                    canonical=ptr_canonical,
                    aliases=sorted(canonical_aliases.get(ptr_canonical, set())),
                    endpoint_url=str(endpoint.get("url")),
                    effective_health=effective_health,
                    project_name=project_name,
                    internal_v4=internal_v4,
                    internal_v6=internal_v6,
                    answer_v4=v4_list,
                    answer_v6=v6_list,
                    extra_txt_fields=getattr(self, "_txt_fields", []),
                    replace_default_txt=bool(
                        getattr(self, "_txt_fields_replace", False)
                    ),
                    txt_fields_keep=getattr(self, "_txt_fields_keep", []),
                )

                # Per-container TXT records: publish a TXT record at each
                # published hostname containing the same information that would
                # appear in the aggregate _containers TXT, but scoped to this
                # container.
                for owner in names_for_mapping:
                    new_txt.setdefault(owner, []).append(line)
                    new_ttl_txt[owner] = ep_ttl
                    # Track hostports per exported owner for admin UI; a later
                    # container with the same owner will overwrite, which is fine
                    # since they share the same mapping.
                    new_hostports[owner] = list(hostports)

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
            self._hostports = new_hostports

    def get_admin_pages(self) -> List[AdminPageSpec]:
        """Brief: Describe the DockerHosts admin page for the web UI.

        Inputs:
          - None; uses the plugin instance name for routing.

        Outputs:
          - list[AdminPageSpec]: A single page descriptor for Docker hosts.
        """

        return [
            AdminPageSpec(
                slug="docker-hosts",
                title="Docker",
                description=(
                    "Containers and hosts discovered by the DockerHosts plugin "
                    "(uses /api/v1/plugins/{name}/docker_hosts for data)."
                ),
                layout="one_column",
                kind="docker_hosts",
            )
        ]

    def get_admin_ui_descriptor(self) -> Dict[str, object]:
        """Brief: Describe DockerHosts admin UI using a generic snapshot layout.

        Inputs:
          - None (uses the plugin instance name and admin page spec for routing).

        Outputs:
          - dict with keys:
              * name: Effective plugin instance name.
              * title: Human-friendly tab title.
              * order: Integer ordering hint among plugin tabs.
              * endpoints: Mapping with at least a "snapshot" URL.
              * layout: Generic section/column description for the frontend.
        """

        plugin_name = getattr(self, "name", "docker")
        try:
            pages = self.get_admin_pages()
        except Exception:
            pages = []
        page = pages[0] if pages else None
        base_title = getattr(page, "title", None) or "Docker"
        # When multiple DockerHosts instances are configured, include the
        # instance name in the tab title so operators can distinguish them.
        if plugin_name:
            title = f"{base_title} ({plugin_name})"
        else:
            title = base_title

        snapshot_url = f"/api/v1/plugins/{plugin_name}/docker_hosts"
        layout: Dict[str, object] = {
            "sections": [
                {
                    "id": "summary",
                    "title": "Summary",
                    "type": "kv",
                    "path": "summary",
                    "rows": [
                        {"key": "total_containers", "label": "Containers"},
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
                        {"key": "host_ipv4", "label": "Host IPv4"},
                        {"key": "host_ipv6", "label": "Host IPv6"},
                        {"key": "suffix", "label": "Suffix"},
                    ],
                },
                {
                    "id": "containers",
                    "title": "Containers",
                    "type": "table",
                    "path": "containers",
                    "columns": [
                        {"key": "name", "label": "Name"},
                        {"key": "ipv4", "label": "IPv4", "join": ", "},
                        {"key": "ports", "label": "Ports", "join": ", "},
                        {"key": "txt", "label": "TXT / Info", "html": True},
                    ],
                    # Frontend hint: expose a checkbox to hide hash-like
                    # hostnames (full/short container IDs) in the table.
                    "filters": [
                        {"id": "hide_hash_like", "label": "Hide hash-like hostnames"}
                    ],
                    # Frontend style hint: group rows by identical TXT summaries
                    # and render canonical name plus aliases.
                    "style": "docker_group_by_txt",
                },
            ]
        }

        return {
            "name": str(plugin_name),
            "title": str(title),
            "order": 50,
            "endpoints": {"snapshot": snapshot_url},
            "layout": layout,
        }

    def get_http_snapshot(self) -> Dict[str, object]:
        """Brief: Summarize current DockerHosts mappings for the admin web UI.

        Inputs:
          - None (uses in-memory forward/reverse maps under a lock).

        Outputs:
          - dict with keys:
              * summary: high-level counts and endpoint metadata.
              * containers: list of per-name mappings including IPs and TXT lines.

        Notes:
          - This helper is intentionally read-only and JSON-safe so that it can
            be exposed directly via the admin HTTP API without additional
            transformation.
        """

        with self._lock:
            containers: List[Dict[str, object]] = []
            # Use the union of v4/v6 keys so names with only one family are included.
            all_names = set(self._forward_v4.keys()) | set(self._forward_v6.keys())
            hostports_map = {k: list(v) for k, v in self._hostports.items()}

            def _is_sha1_like(label: str) -> bool:
                """Return True for hash-like labels (12–64 hex characters).

                Inputs:
                  - label: Hostname or owner name; only the left-most label is
                    inspected so "<hash>.example" still counts as hash-like.

                Outputs:
                  - bool: True when the first label looks like a short/long hash.

                Notes:
                  - This covers docker short IDs (12 hex), sha1-style names
                    (40 hex), and longer hex-ish labels that may have been
                    truncated when rendered in UIs.
                """

                token = str(label).split(".", 1)[0].lower().strip()
                if not token:
                    return False
                # Treat any 12–64 character all-hex label as hash-like so
                # truncated or extended hashes (e.g. HSTS pins) are pushed to
                # the bottom of admin snapshots.
                if len(token) < 12 or len(token) > 64:
                    return False
                for ch in token:
                    if ch not in "0123456789abcdef":
                        return False
                return True

            def _sort_key(name: str) -> tuple[int, str]:
                # Regular, human-readable names (non-hash) should come first;
                # sha1/short-hash style names are pushed to the bottom while still
                # being sorted alphabetically within their group.
                return (1 if _is_sha1_like(name) else 0, str(name))

            # For display, strip a shared plugin-level suffix from container
            # names so that "calibre.docker.zaa" becomes "calibre" in the
            # table, while the full owner names remain unchanged in the
            # underlying resolver maps.
            plugin_suffix = str(getattr(self, "_suffix", "") or "")
            dot_suffix = None
            if plugin_suffix:
                # Normalise suffix used for matching so that leading/trailing
                # dots in configuration do not affect detection.
                parts = [p for p in plugin_suffix.strip().strip(".").split(".") if p]
                if parts:
                    dot_suffix = "." + ".".join(parts).lower()

            for name in sorted(all_names, key=_sort_key):
                v4_list = list(self._forward_v4.get(name, []))
                txts = list(self._aggregate_txt.get(name, []))
                ttl_v4 = int(self._ttl_v4.get(name, self._ttl))
                ttl_v6 = int(self._ttl_v6.get(name, self._ttl))
                ports_list = hostports_map.get(name, [])

                display_name = str(name)
                if dot_suffix and display_name.lower().endswith(dot_suffix):
                    display_name = display_name[: -len(dot_suffix)] or display_name

                containers.append(
                    {
                        "name": display_name,
                        "ipv4": v4_list,
                        "ports": ports_list,
                        "ttl_v4": ttl_v4,
                        "ttl_v6": ttl_v6,
                        "txt": txts,
                    }
                )

            # Summarize endpoint configuration for quick inspection.
            endpoints_view: List[Dict[str, object]] = []
            for ep in getattr(self, "_endpoints", []):
                if not isinstance(ep, dict):
                    continue
                endpoints_view.append(
                    {
                        "url": str(ep.get("url", "")),
                        "interval": float(ep.get("interval", 0.0) or 0.0),
                        "host_ipv4": ep.get("host_ipv4"),
                        "host_ipv6": ep.get("host_ipv6"),
                        "suffix": ep.get("suffix"),
                    }
                )

            # Compute the number of effective backends as the number of unique
            # human-readable hostnames. Hash-like labels (short/full container
            # IDs) are treated as aliases and do not contribute additional
            # container slots to the summary count.
            readable_names: set[str] = set()
            for row in containers:
                try:
                    name_val = str(row.get("name", "")).strip()
                except Exception:
                    continue
                if not name_val:
                    continue
                if _is_sha1_like(name_val):
                    # Treat hash-like labels as aliases for display purposes.
                    continue
                readable_names.add(name_val)

            # Fallback: if every row looks hash-like (for example, when Docker
            # assigns only IDs and no human-friendly names), fall back to the raw
            # row count so that operators still see a non-zero container total.
            total_containers = (
                len(readable_names) if readable_names else len(containers)
            )

            # Plugin-level DNS suffix (domain) used when no per-endpoint suffix
            # is configured. This is exposed in the summary so that container
            # display names can omit the common domain while still making it
            # visible to operators.
            plugin_suffix = str(getattr(self, "_suffix", "") or "")

            summary: Dict[str, object] = {
                "total_containers": total_containers,
                "endpoints": endpoints_view,
                "reload_interval": float(getattr(self, "_reload_interval", 0.0) or 0.0),
                "suffix": plugin_suffix or None,
            }

        return {"summary": summary, "containers": containers}

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
    @registered_cached(cache=_DOCKER_AGG_OWNER_CACHE)
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
    @registered_cached(cache=_DOCKER_HOSTS_OWNER_CACHE)
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
        extra_txt_fields: Optional[List[Tuple[str, str]]] = None,
        replace_default_txt: bool = False,
        txt_fields_keep: Optional[List[str]] = None,
        max_len: int = 240,
    ) -> Tuple[str, List[str]]:
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
          - extra_txt_fields: Optional list of (name, path) pairs for custom TXT fields.
          - replace_default_txt: When true, emit only custom fields unless
            txt_fields_keep is set.
          - txt_fields_keep: Optional list of built-in TXT keys (for example
            "ans4", "endpoint") to preserve even when replace_default_txt is
            true, provided those keys are present for the container.
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

        def _strip_domain_suffix(label: str) -> str:
            """Return the left-most DNS label, dropping any domain suffix.

            This keeps TXT/Info names compact (e.g. "calibre-web.docker.zaa" ->
            "calibre-web") while the full domain is shown separately in the
            summary table.
            """

            s = str(label or "").strip().strip(".")
            if not s:
                return s
            return s.split(".", 1)[0]

        # Collect HostPorts (bindings) for a compact summary. Prefer
        # NetworkSettings.Ports host bindings; when none are present, fall back
        # to Config.ExposedPorts so that exposed-but-unbound container ports are
        # still visible in TXT/Info.
        ports = (container.get("NetworkSettings") or {}).get("Ports") or {}
        base_pieces: List[str] = []
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
            if hostports:
                base_pieces.append(f"ports={_join(hostports)}")

        if not hostports and isinstance(cfg, dict):
            # Fallback: use Config.ExposedPorts keys when present. Keys are
            # typically of the form "80/tcp"; we display the numeric port and
            # preserve protocol when available.
            exposed = cfg.get("ExposedPorts") or {}
            if isinstance(exposed, dict):
                for key in exposed.keys():
                    text = str(key or "").strip()
                    if not text:
                        continue
                    # Extract "port" or "port/proto" into a compact string.
                    port_part = text.split("/", 1)[0]
                    if port_part and port_part not in hostports:
                        hostports.append(f"{port_part}")
            if hostports:
                base_pieces.append(f"ports=exposed:{_join(hostports)}")

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

        def _walk_json_path(root: object, expr: str) -> List[str]:
            """Resolve a minimal JSONPath-like expression against a mapping.

            Supported forms (best-effort, intentionally small subset):
              - "Config.Image" -> root["Config"]["Image"]
              - "State.Health.Status" -> nested dict lookups
              - "Networks.bridge.IPAddress" -> dict-of-dicts lookups
              - Leading "$." is ignored when present.
              - When indexing lists, integer path segments are treated as indices;
                non-integer segments are applied to each element when it is a
                mapping.

            If the resolved value for a path is a dict, the returned list
            contains its keys (as strings) rather than recursing into values so
            that callers can expose available subkeys in TXT output.

            Any exception while walking a path results in an empty list so that
            the caller can safely skip this field and move on to the next.
            """

            s = str(expr or "").strip()
            if not s:
                return []

            try:
                # Normalise away a leading JSONPath root ("$" or "$."), then
                # special-case Docker label keys that contain dots so that callers
                # can use paths like "Config.Labels.com.docker.compose.project".
                if s.startswith("$"):
                    s = s[1:]
                    if s.startswith("."):
                        s = s[1:]

                # Config.Labels.<label-key-with-dots>
                label_prefix = "Config.Labels."
                if s.startswith(label_prefix):
                    label_key = s[len(label_prefix) :]
                    cfg_obj = container.get("Config") or {}
                    lbl_obj = (
                        cfg_obj.get("Labels") if isinstance(cfg_obj, dict) else None
                    )
                    if isinstance(lbl_obj, dict):
                        if label_key in lbl_obj:
                            val = lbl_obj[label_key]
                            # Delegate to the normal flattener below.
                            flat: List[str] = []

                            def _flatten_label(obj: object) -> None:
                                if isinstance(obj, (list, tuple, set)):
                                    for item in obj:
                                        _flatten_label(item)
                                elif isinstance(obj, dict):
                                    for k in obj.keys():
                                        text = str(k).strip()
                                        if text:
                                            flat.append(text)
                                elif isinstance(obj, (str, int, float, bool)):
                                    text = str(obj).strip()
                                    if text:
                                        flat.append(text)

                            _flatten_label(val)
                            seen_l: set[str] = set()
                            out_l: List[str] = []
                            for text in flat:
                                if text in seen_l:
                                    continue
                                seen_l.add(text)
                                out_l.append(text)
                            return out_l
                    return []

                parts = [p for p in s.split(".") if p]
                if not parts:
                    return []

                values: List[object] = [root]
                for part in parts:
                    next_vals: List[object] = []
                    for val in values:
                        if isinstance(val, dict) and part in val:
                            next_vals.append(val[part])
                        elif isinstance(val, list):
                            # Integer index: use as list index when valid.
                            try:
                                idx = int(part)
                            except ValueError:
                                # Non-integer: treat as key lookup on each element
                                # when elements are mappings.
                                for elem in val:
                                    if isinstance(elem, dict) and part in elem:
                                        next_vals.append(elem[part])
                            else:
                                if 0 <= idx < len(val):
                                    next_vals.append(val[idx])
                    if not next_vals:
                        values = []
                        break
                    values = next_vals

                flat: List[str] = []

                def _flatten(obj: object) -> None:
                    if isinstance(obj, (list, tuple, set)):
                        for item in obj:
                            _flatten(item)
                    elif isinstance(obj, dict):
                        # When the terminal value is a dict, surface its keys as
                        # the result so callers see a comma-separated list of
                        # available subkeys.
                        for k in obj.keys():
                            text = str(k).strip()
                            if text:
                                flat.append(text)
                    elif isinstance(obj, (str, int, float, bool)):
                        text = str(obj).strip()
                        if text:
                            flat.append(text)

                for v in values:
                    _flatten(v)

                # Deduplicate while preserving order.
                seen: set[str] = set()
                out: List[str] = []
                for text in flat:
                    if text in seen:
                        continue
                    seen.add(text)
                    out.append(text)
                return out
            except Exception:
                # Any error while walking the path results in no values; the
                # caller will skip this field and continue.
                return []

        # For display, drop domain suffixes so TXT names stay short. The full
        # domain is already shown in the summary table.
        display_name = _strip_domain_suffix(canonical) if canonical else ""

        if display_name:
            base_pieces.append(f"name={display_name}")

        # Include a short ID (first 12 hex characters) when the container Id
        # looks hash-like so operators can correlate TXT/Info entries with
        # docker CLI output without exposing the full ID in the record.
        raw_id = str(container.get("Id") or "").strip()
        short_id = raw_id[:12]
        if short_id and all(c in "0123456789abcdefABCDEF" for c in short_id):
            base_pieces.append(f"id={short_id.lower()}")

        # Include both IPv4 and IPv6 answers so that TXT/Info reflects the
        # effective reply addresses, including any use_ipv4/use_ipv6 overrides
        # configured for the endpoint.
        if answer_v4:
            base_pieces.append(f"ans4={_join(answer_v4)}")
        if answer_v6:
            base_pieces.append(f"ans6={_join(answer_v6)}")

        # Include host listening ports derived from NetworkSettings.Ports.
        # if hostports:
        #  base_pieces.append(f"ports={_join(hostports)}")

        # Remaining fields (omit empties), keeping endpoint= last.
        if effective_health:
            base_pieces.append(f"health={effective_health}")
        if proj:
            base_pieces.append(f"project-name={proj}")
        if svc:
            base_pieces.append(f"service={svc}")
        if internal_v4:
            base_pieces.append(f"int4={_join(internal_v4)}")
        if internal_v6:
            base_pieces.append(f"int6={_join(internal_v6)}")
        if net_parts:
            base_pieces.append(f"nets={_join(net_parts, limit=3)}")
        if endpoint_url:
            # For display, shorten tcp://host:port endpoints to just the host
            # name so TXT/Info stays compact.
            disp_endpoint = endpoint_url
            if endpoint_url.startswith("tcp://"):
                disp = endpoint_url[len("tcp://") :]
                disp_endpoint = disp.split(":", 1)[0]
            base_pieces.append(f"endpoint={disp_endpoint}")

        # Helper to clamp an individual "key=value" segment to a maximum
        # length; when truncated, the last three characters are "...".
        def _trim_kv_segment(segment: str, max_len_kv: int = 128) -> str:
            if len(segment) <= max_len_kv:
                return segment
            if max_len_kv <= 3:
                return "..."[:max_len_kv]
            return segment[: max_len_kv - 3] + "..."

        # Map of built-in TXT keys to their "key=value" segments so that
        # txt_fields in replace mode can fall back to these when a custom
        # JSONPath does not resolve for a container.
        base_by_key: Dict[str, str] = {}
        for part in base_pieces:
            key = part.split("=", 1)[0]
            if key and key not in base_by_key:
                base_by_key[key] = part

        custom_pieces: List[str] = []
        # Track which keys have fallen back to built-in values so that
        # txt_fields_keep does not re-add them later and cause duplicates.
        fallback_keys: set[str] = set()
        if extra_txt_fields:
            for field_name, expr in extra_txt_fields:
                name_s = str(field_name or "").strip()
                if not name_s:
                    continue
                values = _walk_json_path(container, expr)
                # When no custom value resolves for this key and we are in
                # replace_default_txt mode, fall back to the built-in TXT
                # segment with the same key (when present) instead of omitting
                # the key entirely.
                if not values and replace_default_txt:
                    builtin_seg = base_by_key.get(name_s)
                    if builtin_seg:
                        custom_pieces.append(_trim_kv_segment(builtin_seg))
                        fallback_keys.add(name_s)
                    continue
                if not values:
                    continue
                # Normalise container-style names for custom fields keyed as
                # "name" so that values like "/foghorn" become "foghorn" in
                # TXT/Info output. This keeps UI display and DNS labels
                # consistent even when callers point txt_fields at
                # docker-specific paths such as "Name".
                if name_s.lower() == "name":
                    norm_vals: List[str] = []
                    for v in values:
                        text = str(v or "").strip()
                        if text.startswith("/"):
                            text = text[1:]
                        if text:
                            norm_vals.append(text)
                    values = norm_vals
                    if not values:
                        # In non-replace mode, base_pieces still carries the
                        # built-in name. In replace mode, fall back to the
                        # built-in name segment when available.
                        if replace_default_txt:
                            builtin_seg = base_by_key.get("name")
                            if builtin_seg:
                                custom_pieces.append(_trim_kv_segment(builtin_seg))
                                fallback_keys.add("name")
                        continue
                seg = f"{name_s}={_join(values)}"
                custom_pieces.append(_trim_kv_segment(seg))

        pieces: List[str]
        if replace_default_txt and custom_pieces:
            # In replace mode, only emit custom fields by default. When
            # txt_fields_keep is configured, preserve a subset of base_pieces
            # whose keys are explicitly listed and that are present for this
            # container (for example "ans4", "endpoint").
            keep_keys = {k.strip() for k in (txt_fields_keep or []) if k.strip()}
            if keep_keys:
                kept: List[str] = []
                for part in base_pieces:
                    key = part.split("=", 1)[0]
                    # Skip keys that have already fallen back to built-in
                    # values via txt_fields so we do not emit duplicates.
                    if key in keep_keys and key not in fallback_keys:
                        kept.append(part)
                # Place kept built-in keys at the end of the TXT record so
                # custom fields remain visually grouped together.
                pieces = custom_pieces + kept
            else:
                pieces = custom_pieces
        else:
            pieces = base_pieces + custom_pieces

        s = " ".join(pieces)
        if len(s) > max_len:
            s = s[: max_len - 3] + "..."
        return s, hostports

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
                # TXT summaries for docker hosts are ancillary metadata for A
                # answers and belong in the ADDITIONAL section rather than the
                # ANSWER section so that A responses remain strictly address-only
                # from a DNS semantics perspective.
                reply.add_ar(
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
                # TXT summaries for docker hosts are ancillary metadata for AAAA
                # answers and belong in the ADDITIONAL section rather than the
                # ANSWER section so that AAAA responses remain strictly
                # address-only from a DNS semantics perspective.
                reply.add_ar(
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
