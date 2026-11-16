"""KubernetesHosts plugin: resolve Service/Pod hostnames via the Kubernetes API.

Brief:
  - Polls one or more Kubernetes API endpoints (in-cluster SA, kubeconfig, or
    explicit api_server + token) and builds in-memory A/AAAA/PTR maps.
  - Answers pre_resolve queries for matching hostnames and reverse names.
  - Uses ``requests`` only (no official kubernetes client dependency).
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from requests.adapters import HTTPAdapter

from foghorn.plugins.resolve.base import (
    AdminPageSpec,
    plugin_aliases,
)
from foghorn.plugins.resolve.hosts_common import (
    DynamicHostsPlugin,
    add_forward_records,
    fold_tls_aliases,
    join_host_suffix,
    merge_list_map,
    normalize_host_label,
    normalize_suffix,
    resolve_plugin_tls_path,
)

logger = logging.getLogger(__name__)


class _SNIAdapter(HTTPAdapter):
    """HTTPAdapter that forces a TLS server_hostname (SNI / cert name)."""

    def __init__(self, server_hostname: str | None = None, **kwargs: Any) -> None:
        """Brief: Create adapter with optional SNI override.

        Inputs:
          - server_hostname: Hostname sent in SNI and used for cert matching.
          - kwargs: Passed to HTTPAdapter.

        Outputs:
          - None.
        """

        self._server_hostname = (
            str(server_hostname).strip() if server_hostname else None
        )
        super().__init__(**kwargs)

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        """Brief: Initialize urllib3 pool with server_hostname when set.

        Inputs:
          - connections / maxsize / block: Pool sizing flags.
          - pool_kwargs: Extra urllib3 pool kwargs.

        Outputs:
          - None.
        """

        if self._server_hostname:
            pool_kwargs["server_hostname"] = self._server_hostname
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


_IN_CLUSTER_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_IN_CLUSTER_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
_IN_CLUSTER_API = "https://kubernetes.default.svc"
_DEFAULT_KUBECONFIG_PATHS = (
    os.environ.get("KUBECONFIG"),
    str(Path.home() / ".kube" / "config"),
)


class KubernetesEndpointConfig(BaseModel):
    """Per-endpoint (or cluster) connection and scope settings.

    Inputs (fields):
      - api_server: Explicit API base URL (https://...).
      - kubeconfig: Path to kubeconfig file.
      - in_cluster: Use in-cluster service account files when True.
      - token / token_file: Bearer token material.
      - client_cert / client_key (aliases tls_cert / tls_key): mTLS client PEM paths.
      - ca_cert (alias tls_ca) / tls_verify: TLS trust settings.
      - tls_server_name (alias tls_name): SNI / expected certificate hostname.
      - namespaces: Namespace allowlist (empty = all / cluster scope).
      - label_selector / field_selector: List filter query params.
      - include_services / include_pods: Resource kinds to index.
      - suffix / use_ipv4 / use_ipv6 / ttl / reload_interval_seconds: DNS overrides.

    Outputs:
      - Validated endpoint config (extra keys allowed).
    """

    api_server: str | None = None
    kubeconfig: str | None = None
    in_cluster: bool = False
    token: str | None = None
    token_file: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    ca_cert: str | None = None
    tls_verify: bool = True
    tls_server_name: str | None = None
    # Docker-style aliases accepted via model_validator (tls_ca/tls_cert/tls_key/tls_name).
    namespaces: list[str] = Field(default_factory=list)
    namespace: str | None = None
    label_selector: str | None = None
    field_selector: str | None = None
    include_services: bool | None = None
    include_pods: bool | None = None
    suffix: str | None = None
    use_ipv4: bool | None = None
    use_ipv6: bool | None = None
    ttl: int | None = Field(default=None, ge=0)
    reload_interval_seconds: float | None = Field(default=None, ge=0)

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="before")
    @classmethod
    def _coerce_tls_aliases(cls, data: Any) -> Any:
        """Brief: Map tls_* aliases onto canonical TLS field names.

        Inputs:
          - data: Raw mapping or other value passed to the model.

        Outputs:
          - Same value, with tls_ca/tls_cert/tls_key/tls_name folded in when set.
        """

        return fold_tls_aliases(data)


class KubernetesHostsConfig(BaseModel):
    """Plugin-level configuration for KubernetesHosts.

    Inputs (fields):
      - endpoints: Optional list of cluster endpoints; empty uses top-level
        connection fields as a single implicit endpoint.
      - ttl / suffix / use_ipv4 / use_ipv6: DNS defaults.
      - include_services / include_pods / namespaces / label_selector: scope defaults.
      - poll_interval_seconds: Background reload interval (0 disables).
      - expose_txt_in_additional: Attach TXT metadata on A/AAAA answers.
      - api_server / kubeconfig / in_cluster / token* / client_cert /
        client_key / ca_cert / tls_verify / tls_server_name: Default connection
        when endpoints is empty. Docker-style aliases tls_ca/tls_cert/tls_key/
        tls_name are also accepted.

    Outputs:
      - Validated plugin config (extra keys allowed).
    """

    endpoints: list[KubernetesEndpointConfig] = Field(default_factory=list)
    ttl: int = Field(default=300, ge=0)
    suffix: str | None = None
    use_ipv4: bool = True
    use_ipv6: bool = True
    include_services: bool = True
    include_pods: bool = True
    namespaces: list[str] = Field(default_factory=list)
    label_selector: str | None = None
    field_selector: str | None = None
    poll_interval_seconds: float = Field(default=30.0, ge=0)
    # Hard caps on API list amplification (0 disables a given cap).
    max_list_pages: int = Field(default=50, ge=0)
    max_list_items: int = Field(default=20000, ge=0)
    expose_txt_in_additional: bool = False
    api_server: str | None = None
    kubeconfig: str | None = None
    in_cluster: bool = False
    token: str | None = None
    token_file: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    ca_cert: str | None = None
    tls_verify: bool = True
    tls_server_name: str | None = None

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="before")
    @classmethod
    def _coerce_tls_aliases(cls, data: Any) -> Any:
        """Brief: Map tls_* aliases onto canonical TLS field names.

        Inputs:
          - data: Raw mapping or other value passed to the model.

        Outputs:
          - Same value, with tls_ca/tls_cert/tls_key/tls_name folded in when set.
        """

        return fold_tls_aliases(data)


def _read_text_file(path: str | None) -> str | None:
    """Brief: Read a UTF-8 text file if path is set and readable.

    Inputs:
      - path: Filesystem path or None.

    Outputs:
      - File contents stripped, or None.
    """

    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except Exception:
        return None


def _write_temp_pem(data_b64: str, *, prefix: str, suffix: str) -> str | None:
    """Brief: Decode base64 PEM material to a temp file path.

    Inputs:
      - data_b64: Base64-encoded PEM bytes from kubeconfig *-data fields.
      - prefix / suffix: tempfile name parts.

    Outputs:
      - Absolute temp file path, or None on failure.
    """

    import base64
    import tempfile

    try:
        pem = base64.b64decode(str(data_b64)).decode("utf-8")
        fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=suffix)
        os.close(fd)
        Path(tmp).write_text(pem, encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except Exception:  # pragma: no cover - best-effort permissions
            pass
        return str(tmp)
    except Exception:
        return None


def _parse_kubeconfig(path: str) -> dict[str, Any]:
    """Brief: Load kubeconfig YAML into a dict of connection hints.

    Inputs:
      - path: Kubeconfig filesystem path.

    Outputs:
      - Dict with optional keys: api_server, token, token_file, ca_cert,
        client_cert, client_key, tls_verify, and _temp_files (list of temps).

    Notes:
      - Supports current-context cluster/user token and client-cert auth.
      - Inline *-data fields are written to temp PEM files listed in _temp_files.
    """

    raw = Path(path).read_text(encoding="utf-8")
    doc = yaml.safe_load(raw) or {}
    if not isinstance(doc, dict):
        return {}

    current = str(doc.get("current-context") or "")
    contexts = {
        str(c.get("name")): c.get("context") or {}
        for c in (doc.get("contexts") or [])
        if isinstance(c, dict) and c.get("name")
    }
    clusters = {
        str(c.get("name")): c.get("cluster") or {}
        for c in (doc.get("clusters") or [])
        if isinstance(c, dict) and c.get("name")
    }
    users = {
        str(u.get("name")): u.get("user") or {}
        for u in (doc.get("users") or [])
        if isinstance(u, dict) and u.get("name")
    }

    ctx = contexts.get(current) if current else None
    if not isinstance(ctx, dict) and contexts:
        ctx = next(iter(contexts.values()))
    if not isinstance(ctx, dict):
        return {}

    cluster = clusters.get(str(ctx.get("cluster") or ""), {})
    user = users.get(str(ctx.get("user") or ""), {})
    if not isinstance(cluster, dict):
        cluster = {}
    if not isinstance(user, dict):
        user = {}

    out: dict[str, Any] = {}
    temps: list[str] = []
    server = cluster.get("server")
    if server:
        out["api_server"] = str(server).rstrip("/")
    if cluster.get("insecure-skip-tls-verify"):
        out["tls_verify"] = False
    ca_path = cluster.get("certificate-authority")
    if ca_path:
        out["ca_cert"] = str(ca_path)
    ca_data = cluster.get("certificate-authority-data")
    if ca_data and not out.get("ca_cert"):
        tmp = _write_temp_pem(str(ca_data), prefix="foghorn-k8s-ca-", suffix=".crt")
        if tmp:
            out["ca_cert"] = tmp
            temps.append(tmp)

    token = user.get("token")
    if token:
        out["token"] = str(token)
    token_file = user.get("tokenFile") or user.get("token-file")
    if token_file and not out.get("token"):
        out["token_file"] = str(token_file)

    # Client certificate authentication (path or inline data).
    cert_path = user.get("client-certificate")
    if cert_path:
        out["client_cert"] = str(cert_path)
    cert_data = user.get("client-certificate-data")
    if cert_data and not out.get("client_cert"):
        tmp = _write_temp_pem(
            str(cert_data), prefix="foghorn-k8s-client-", suffix=".crt"
        )
        if tmp:
            out["client_cert"] = tmp
            temps.append(tmp)

    key_path = user.get("client-key")
    if key_path:
        out["client_key"] = str(key_path)
    key_data = user.get("client-key-data")
    if key_data and not out.get("client_key"):
        tmp = _write_temp_pem(
            str(key_data), prefix="foghorn-k8s-client-", suffix=".key"
        )
        if tmp:
            out["client_key"] = tmp
            temps.append(tmp)

    if temps:
        out["_temp_files"] = temps
    return out


@plugin_aliases("k8s-hosts", "kubernetes-hosts", "k8s", "k8s_hosts")
class KubernetesHosts(DynamicHostsPlugin):
    """Resolve Service/Pod hostnames and reverse IPs via Kubernetes API."""

    @classmethod
    def get_config_model(cls) -> type[BaseModel]:
        """Brief: Return the Pydantic config model for this plugin.

        Inputs:
          - cls: Plugin class.

        Outputs:
          - KubernetesHostsConfig type.
        """

        return KubernetesHostsConfig

    def _shutdown_resources(self) -> None:
        """Brief: Remove temp CA/client PEM files created from kubeconfig data.

        Inputs:
          - None.
        Outputs:
          - None.
        """

        for path in list(getattr(self, "_temp_ca_files", []) or []):
            try:
                if path and os.path.isfile(path):
                    os.remove(path)
            except Exception:  # pragma: no cover
                pass

    def setup(self) -> None:
        """Brief: Build maps from K8s API and start optional poller.

        Inputs:
          - None (uses self.config).

        Outputs:
          - None.
        """

        self._typed = self._coerce_config()
        self._init_dynamic_hosts_state(default_ttl=int(self._typed.ttl))
        self._expose_txt_in_additional = bool(self._typed.expose_txt_in_additional)
        self._suffix = normalize_suffix(self._typed.suffix)
        self._last_reload_ts = 0.0
        self._last_error: str | None = None
        self._entry_sources: dict[str, str] = {}
        self._temp_ca_files: list[str] = []
        self._reload_interval = float(self._typed.poll_interval_seconds or 0.0)

        self._reload_maps()
        self._start_reload_loop(thread_name=f"K8sHostsPoller-{self.name}")
        logger.info(
            "[%s]: setup complete (%s forward names)",
            self.name,
            self._forward_count(),
        )

    def _coerce_config(self) -> KubernetesHostsConfig:
        """Brief: Validate self.config into KubernetesHostsConfig.

        Inputs:
          - None.

        Outputs:
          - KubernetesHostsConfig instance.
        """

        cfg = self.config if isinstance(self.config, dict) else {}
        if isinstance(self.config, KubernetesHostsConfig):
            return self.config
        try:
            return KubernetesHostsConfig.model_validate(cfg)
        except Exception as exc:
            logger.warning(
                "[%s]: config validation failed (%s); using defaults",
                getattr(self, "name", "?"),
                exc,
            )
            return KubernetesHostsConfig()

    def _effective_endpoints(self) -> list[KubernetesEndpointConfig]:
        """Brief: Resolve endpoint list, synthesizing one from top-level fields.

        Inputs:
          - None.

        Outputs:
          - Non-empty list of endpoint configs when connection is implied.
        """

        typed = self._typed
        if typed.endpoints:
            return list(typed.endpoints)

        # Implicit single endpoint from plugin-level connection fields.
        return [
            KubernetesEndpointConfig(
                api_server=typed.api_server,
                kubeconfig=typed.kubeconfig,
                in_cluster=bool(typed.in_cluster),
                token=typed.token,
                token_file=typed.token_file,
                client_cert=typed.client_cert,
                client_key=typed.client_key,
                ca_cert=typed.ca_cert,
                tls_verify=bool(typed.tls_verify),
                tls_server_name=typed.tls_server_name,
                namespaces=list(typed.namespaces or []),
                label_selector=typed.label_selector,
                field_selector=typed.field_selector,
                include_services=typed.include_services,
                include_pods=typed.include_pods,
                suffix=typed.suffix,
                use_ipv4=typed.use_ipv4,
                use_ipv6=typed.use_ipv6,
                ttl=typed.ttl,
                reload_interval_seconds=typed.poll_interval_seconds,
            )
        ]

    def _resolve_connection(self, endpoint: KubernetesEndpointConfig) -> dict[str, Any]:
        """Brief: Resolve API URL, auth, and TLS settings for an endpoint.

        Inputs:
          - endpoint: Endpoint configuration.

        Outputs:
          - Dict: api_server, token (optional), cert (optional requests cert),
            verify (bool|path), headers.

        Notes:
          - Auth is either Bearer token and/or mTLS client certificate pair.
          - At least one of token or (client_cert + client_key) is required.
        """

        api_server = (endpoint.api_server or "").rstrip("/") or None
        token = endpoint.token
        ca_cert = endpoint.ca_cert
        client_cert = endpoint.client_cert
        client_key = endpoint.client_key
        tls_server_name = endpoint.tls_server_name
        verify: bool | str = bool(endpoint.tls_verify)
        temps: list[str] = []

        if endpoint.in_cluster or (
            not api_server
            and not endpoint.kubeconfig
            and not client_cert
            and Path(_IN_CLUSTER_TOKEN).is_file()
        ):
            api_server = api_server or _IN_CLUSTER_API
            token = token or _read_text_file(endpoint.token_file or _IN_CLUSTER_TOKEN)
            ca_cert = ca_cert or endpoint.ca_cert or _IN_CLUSTER_CA
        elif endpoint.kubeconfig or (
            not api_server and not token and not (client_cert and client_key)
        ):
            kc_path = endpoint.kubeconfig
            if not kc_path:
                for candidate in _DEFAULT_KUBECONFIG_PATHS:
                    if candidate and Path(str(candidate).split(":")[0]).is_file():
                        kc_path = str(candidate).split(":")[0]
                        break
            if kc_path and Path(kc_path).is_file():
                try:
                    hints = _parse_kubeconfig(kc_path)
                    api_server = api_server or hints.get("api_server")
                    token = token or hints.get("token")
                    if hints.get("token_file") and not token:
                        token = _read_text_file(str(hints["token_file"]))
                    ca_cert = ca_cert or hints.get("ca_cert")
                    client_cert = client_cert or hints.get("client_cert")
                    client_key = client_key or hints.get("client_key")
                    if "tls_verify" in hints:
                        verify = bool(hints["tls_verify"])
                    for tmp in hints.get("_temp_files") or []:
                        temps.append(str(tmp))
                    # Back-compat if older parse left _ca_temp alone.
                    if hints.get("_ca_temp"):
                        temps.append(str(hints["_ca_temp"]))
                except Exception as exc:
                    logger.warning(
                        "[%s]: kubeconfig parse failed: %s",
                        self.name,
                        exc,
                    )

        if endpoint.token_file and not token:
            token = _read_text_file(endpoint.token_file)
        if not token and endpoint.token:
            token = endpoint.token

        # TLS trust: explicit false wins; otherwise ca_cert path becomes verify=.
        if endpoint.tls_verify is False:
            verify = False
        elif ca_cert:
            ca_path = str(ca_cert)
            if (
                not ca_path.startswith("/")
                and "://" not in ca_path
                or ca_path.startswith("/")
                or ca_path.startswith("~")
            ):
                ca_path = resolve_plugin_tls_path(ca_path)
            verify = ca_path

        if temps:
            self._temp_ca_files.extend(temps)

        if not api_server:
            raise RuntimeError(
                "no Kubernetes api_server (set api_server, kubeconfig, or in_cluster)"
            )

        cert: tuple[str, str] | str | None = None
        if client_cert and client_key:
            c_path = resolve_plugin_tls_path(str(client_cert))
            k_path = resolve_plugin_tls_path(str(client_key))
            cert = (c_path, k_path)
        elif client_cert and not client_key:
            raise RuntimeError(
                "client_cert set without client_key (both required for mTLS)"
            )
        elif client_key and not client_cert:
            raise RuntimeError(
                "client_key set without client_cert (both required for mTLS)"
            )

        if not token and cert is None:
            raise RuntimeError(
                "no Kubernetes auth (set token/token_file, client_cert+client_key, "
                "kubeconfig, or in_cluster)"
            )

        headers: dict[str, str] = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        sni = str(tls_server_name).strip() if tls_server_name else None
        return {
            "api_server": str(api_server).rstrip("/"),
            "token": str(token) if token else None,
            "cert": cert,
            "verify": verify,
            "tls_server_name": sni or None,
            "headers": headers,
        }

    def _k8s_get(
        self,
        conn: dict[str, Any],
        path: str,
        *,
        params: dict[str, str] | None = None,
        timeout: float = 15.0,
    ) -> dict[str, Any]:
        """Brief: GET a Kubernetes API path and return JSON object.

        Inputs:
          - conn: Connection dict from _resolve_connection.
          - path: API path beginning with /api/...
          - params: Optional query string mapping.
          - timeout: Request timeout seconds.

        Outputs:
          - Parsed JSON object (dict).

        Raises:
          - requests.HTTPError / RuntimeError on failure.
        """

        url = urljoin(conn["api_server"] + "/", path.lstrip("/"))
        req_kwargs: dict[str, Any] = {
            "headers": conn["headers"],
            "params": params or {},
            "verify": conn["verify"],
            "timeout": timeout,
        }
        cert = conn.get("cert")
        if cert is not None:
            req_kwargs["cert"] = cert

        sni = conn.get("tls_server_name")
        if sni:
            session = requests.Session()
            try:
                adapter = _SNIAdapter(server_hostname=str(sni))
                session.mount("https://", adapter)
                resp = session.get(url, **req_kwargs)
            finally:
                session.close()
        else:
            resp = requests.get(url, **req_kwargs)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"unexpected K8s response type for {path}")
        return data

    def _list_namespaced(
        self,
        conn: dict[str, Any],
        resource: str,
        namespace: str | None,
        *,
        label_selector: str | None,
        field_selector: str | None,
    ) -> list[dict[str, Any]]:
        """Brief: List Service or Pod objects for one namespace or all.

        Inputs:
          - conn: API connection.
          - resource: 'services' or 'pods'.
          - namespace: Namespace or None for all-namespaces.
          - label_selector / field_selector: Optional filters.

        Outputs:
          - List of item dicts from the API list response.
        """

        params: dict[str, str] = {}
        if label_selector:
            params["labelSelector"] = label_selector
        if field_selector:
            params["fieldSelector"] = field_selector

        if namespace:
            path = f"/api/v1/namespaces/{namespace}/{resource}"
        else:
            path = f"/api/v1/{resource}"

        items: list[dict[str, Any]] = []
        cont: str | None = None
        pages = 0
        typed = getattr(self, "_typed", None)
        try:
            max_pages = int(getattr(typed, "max_list_pages", 50) or 0)
        except Exception:
            max_pages = 50
        try:
            max_items = int(getattr(typed, "max_list_items", 20000) or 0)
        except Exception:
            max_items = 20000
        while True:
            pages += 1
            if max_pages > 0 and pages > max_pages:
                raise RuntimeError(
                    f"k8s list pagination exceeded max_list_pages={max_pages} "
                    f"for {resource} ns={namespace or '*'}"
                )
            page_params = dict(params)
            if cont:
                page_params["continue"] = cont
            data = self._k8s_get(conn, path, params=page_params)
            for it in data.get("items") or []:
                if isinstance(it, dict):
                    items.append(it)
                    if max_items > 0 and len(items) > max_items:
                        raise RuntimeError(
                            f"k8s list exceeded max_list_items={max_items} "
                            f"for {resource} ns={namespace or '*'}"
                        )
            meta = (
                data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            )
            cont = meta.get("continue") if isinstance(meta, dict) else None
            if not cont:
                break
        return items

    def _endpoint_namespaces(
        self, endpoint: KubernetesEndpointConfig
    ) -> list[str | None]:
        """Brief: Namespace list for an endpoint (None means all-namespaces).

        Inputs:
          - endpoint: Endpoint config.

        Outputs:
          - List containing None (cluster-wide) or one-or-more namespace names.
        """

        names: list[str] = []
        if endpoint.namespace:
            names.append(str(endpoint.namespace))
        for ns in endpoint.namespaces or []:
            if ns and str(ns) not in names:
                names.append(str(ns))
        for ns in self._typed.namespaces or []:
            if ns and str(ns) not in names:
                names.append(str(ns))
        if not names:
            return [None]
        return names  # type: ignore[return-value]

    def _names_for_resource(
        self,
        *,
        name: str,
        namespace: str,
        kind: str,
        suffix: str | None,
        single_ns: bool,
    ) -> list[str]:
        """Brief: Build hostname variants for a Service or Pod.

        Inputs:
          - name / namespace / kind: Resource identity (kind: service|pod).
          - suffix: Optional DNS suffix.
          - single_ns: When True, also publish short name without namespace.

        Outputs:
          - List of unique hostnames (with suffix applied).
        """

        base = normalize_host_label(name)
        ns = normalize_host_label(namespace)
        kind_l = kind.lower()
        raws = [
            f"{base}.{ns}",
            f"{base}.{ns}.{kind_l}",
        ]
        if kind_l == "service":
            raws.append(f"{base}.{ns}.svc")
        if single_ns:
            raws.append(base)
        out: list[str] = []
        seen: set[str] = set()
        for r in raws:
            full = join_host_suffix(r, suffix)
            if full and full not in seen:
                seen.add(full)
                out.append(full)
        return out

    def _collect_endpoint(self, endpoint: KubernetesEndpointConfig) -> tuple[
        dict[str, list[str]],
        dict[str, list[str]],
        dict[str, int],
        dict[str, int],
        dict[str, str],
        dict[str, int],
        dict[str, list[str]],
        dict[str, int],
        dict[str, str],
    ]:
        """Brief: Fetch and map resources for one endpoint.

        Inputs:
          - endpoint: Endpoint configuration.

        Outputs:
          - Tuple of forward/reverse/txt/source maps for merge.
        """

        forward_v4: dict[str, list[str]] = {}
        forward_v6: dict[str, list[str]] = {}
        ttl_v4: dict[str, int] = {}
        ttl_v6: dict[str, int] = {}
        reverse: dict[str, str] = {}
        ttl_ptr: dict[str, int] = {}
        aggregate_txt: dict[str, list[str]] = {}
        ttl_txt: dict[str, int] = {}
        entry_sources: dict[str, str] = {}

        conn = self._resolve_connection(endpoint)
        ttl = int(endpoint.ttl if endpoint.ttl is not None else self._typed.ttl)
        use_v4 = (
            self._typed.use_ipv4
            if endpoint.use_ipv4 is None
            else bool(endpoint.use_ipv4)
        )
        use_v6 = (
            self._typed.use_ipv6
            if endpoint.use_ipv6 is None
            else bool(endpoint.use_ipv6)
        )
        include_services = (
            self._typed.include_services
            if endpoint.include_services is None
            else bool(endpoint.include_services)
        )
        include_pods = (
            self._typed.include_pods
            if endpoint.include_pods is None
            else bool(endpoint.include_pods)
        )
        if endpoint.suffix is not None:
            suffix = normalize_suffix(endpoint.suffix) or None
        else:
            suffix = self._suffix or None
        label_selector = endpoint.label_selector or self._typed.label_selector
        field_selector = endpoint.field_selector or self._typed.field_selector
        namespaces = self._endpoint_namespaces(endpoint)
        single_ns = len([n for n in namespaces if n]) == 1

        for ns in namespaces:
            if include_services:
                try:
                    services = self._list_namespaced(
                        conn,
                        "services",
                        ns,
                        label_selector=label_selector,
                        field_selector=field_selector,
                    )
                except Exception as exc:
                    msg = str(exc)
                    if "max_list_pages" in msg or "max_list_items" in msg:
                        raise
                    logger.warning(
                        "[%s]: list services failed (ns=%s): %s",
                        self.name,
                        ns or "*",
                        exc,
                    )
                    services = []
                for svc in services:
                    meta = (
                        svc.get("metadata")
                        if isinstance(svc.get("metadata"), dict)
                        else {}
                    )
                    spec = svc.get("spec") if isinstance(svc.get("spec"), dict) else {}
                    sname = str(meta.get("name") or "")
                    sns = str(meta.get("namespace") or ns or "")
                    if not sname or not sns:
                        continue
                    cluster_ip = str(spec.get("clusterIP") or "")
                    if not cluster_ip or cluster_ip.lower() == "none":
                        continue
                    ips = [cluster_ip]
                    # Also publish any explicit external IPs.
                    for ext in spec.get("externalIPs") or []:
                        if ext:
                            ips.append(str(ext))
                    names = self._names_for_resource(
                        name=sname,
                        namespace=sns,
                        kind="service",
                        suffix=suffix,
                        single_ns=single_ns,
                    )
                    txt = [
                        "k8s=service",
                        f"ns={sns}",
                        f"name={sname}",
                        f"type={spec.get('type') or ''}",
                    ]
                    add_forward_records(
                        names=names,
                        ips=ips,
                        ttl=ttl,
                        use_v4=use_v4,
                        use_v6=use_v6,
                        source=f"service/{sns}/{sname}",
                        txt_lines=txt,
                        forward_v4=forward_v4,
                        forward_v6=forward_v6,
                        ttl_v4=ttl_v4,
                        ttl_v6=ttl_v6,
                        reverse=reverse,
                        ttl_ptr=ttl_ptr,
                        aggregate_txt=aggregate_txt,
                        ttl_txt=ttl_txt,
                        entry_sources=entry_sources,
                    )

            if include_pods:
                try:
                    pods = self._list_namespaced(
                        conn,
                        "pods",
                        ns,
                        label_selector=label_selector,
                        field_selector=field_selector,
                    )
                except Exception as exc:
                    msg = str(exc)
                    if "max_list_pages" in msg or "max_list_items" in msg:
                        raise
                    logger.warning(
                        "[%s]: list pods failed (ns=%s): %s",
                        self.name,
                        ns or "*",
                        exc,
                    )
                    pods = []
                for pod in pods:
                    meta = (
                        pod.get("metadata")
                        if isinstance(pod.get("metadata"), dict)
                        else {}
                    )
                    status = (
                        pod.get("status") if isinstance(pod.get("status"), dict) else {}
                    )
                    pname = str(meta.get("name") or "")
                    pns = str(meta.get("namespace") or ns or "")
                    if not pname or not pns:
                        continue
                    phase = str(status.get("phase") or "")
                    if phase and phase.lower() not in ("running", "succeeded", ""):
                        # Still index Running primarily; allow empty phase.
                        if phase.lower() not in ("running",):
                            continue
                    ips: list[str] = []
                    pod_ip = status.get("podIP")
                    if pod_ip:
                        ips.append(str(pod_ip))
                    for pip in status.get("podIPs") or []:
                        if isinstance(pip, dict) and pip.get("ip"):
                            ip_s = str(pip["ip"])
                            if ip_s not in ips:
                                ips.append(ip_s)
                    if not ips:
                        continue
                    names = self._names_for_resource(
                        name=pname,
                        namespace=pns,
                        kind="pod",
                        suffix=suffix,
                        single_ns=single_ns,
                    )
                    txt = ["k8s=pod", f"ns={pns}", f"name={pname}", f"phase={phase}"]
                    add_forward_records(
                        names=names,
                        ips=ips,
                        ttl=ttl,
                        use_v4=use_v4,
                        use_v6=use_v6,
                        source=f"pod/{pns}/{pname}",
                        txt_lines=txt,
                        forward_v4=forward_v4,
                        forward_v6=forward_v6,
                        ttl_v4=ttl_v4,
                        ttl_v6=ttl_v6,
                        reverse=reverse,
                        ttl_ptr=ttl_ptr,
                        aggregate_txt=aggregate_txt,
                        ttl_txt=ttl_txt,
                        entry_sources=entry_sources,
                    )

        return (
            forward_v4,
            forward_v6,
            ttl_v4,
            ttl_v6,
            reverse,
            ttl_ptr,
            aggregate_txt,
            ttl_txt,
            entry_sources,
        )

    def _reload_maps(self) -> None:
        """Brief: Refresh in-memory DNS maps from all endpoints.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        forward_v4: dict[str, list[str]] = {}
        forward_v6: dict[str, list[str]] = {}
        ttl_v4: dict[str, int] = {}
        ttl_v6: dict[str, int] = {}
        reverse: dict[str, str] = {}
        ttl_ptr: dict[str, int] = {}
        aggregate_txt: dict[str, list[str]] = {}
        ttl_txt: dict[str, int] = {}
        entry_sources: dict[str, str] = {}
        errors: list[str] = []

        cap_exceeded = False
        for endpoint in self._effective_endpoints():
            try:
                (
                    e_v4,
                    e_v6,
                    e_ttl4,
                    e_ttl6,
                    e_rev,
                    e_ttl_ptr,
                    e_txt,
                    e_ttl_txt,
                    e_src,
                ) = self._collect_endpoint(endpoint)
            except Exception as exc:
                msg = str(exc)
                errors.append(msg)
                if "max_list_pages" in msg or "max_list_items" in msg:
                    cap_exceeded = True
                self._note_condition_failure(
                    f"endpoint-collect:{getattr(endpoint, 'api_server', None) or id(endpoint)}",
                    "[%s]: endpoint collect failed: %s",
                    self.name,
                    exc,
                )
                continue
            merge_list_map(forward_v4, e_v4)
            merge_list_map(forward_v6, e_v6)
            ttl_v4.update(e_ttl4)
            ttl_v6.update(e_ttl6)
            for k, v in e_rev.items():
                reverse.setdefault(k, v)
            ttl_ptr.update(e_ttl_ptr)
            merge_list_map(aggregate_txt, e_txt)
            ttl_txt.update(e_ttl_txt)
            entry_sources.update(e_src)

        # Cap hit: keep previous maps so a hostile/buggy API cannot wipe or
        # OOM-amplify state via unbounded continue tokens.
        if cap_exceeded:
            with self._lock:
                self._last_reload_ts = time.time()
                self._last_error = "; ".join(errors) if errors else "list cap exceeded"
            self._note_condition_failure(
                "cluster-reload",
                "[%s]: reload aborted (list cap exceeded); keeping previous maps: %s",
                self.name,
                self._last_error,
            )
            return

        with self._lock:
            self._forward_v4 = forward_v4
            self._forward_v6 = forward_v6
            self._ttl_v4 = ttl_v4
            self._ttl_v6 = ttl_v6
            self._reverse = reverse
            self._ttl_ptr = ttl_ptr
            self._aggregate_txt = aggregate_txt
            self._ttl_txt = ttl_txt
            self._entry_sources = entry_sources
            self._last_reload_ts = time.time()
            self._last_error = "; ".join(errors) if errors else None
        if errors:
            self._note_condition_failure(
                "cluster-reload",
                "[%s]: reload completed with errors: %s",
                self.name,
                self._last_error,
            )
        else:
            self._note_condition_ok(
                "cluster-reload",
                "[%s]: reload recovered",
                self.name,
            )

    def _forward_count(self) -> int:
        """Brief: Count distinct forward hostnames.

        Inputs:
          - None.

        Outputs:
          - Integer count.
        """

        with self._lock:
            return len(set(self._forward_v4) | set(self._forward_v6))

    def get_admin_pages(self) -> list[AdminPageSpec]:
        """Brief: Admin page specs for the web UI.

        Inputs:
          - None.

        Outputs:
          - List with Kubernetes Hosts page spec.
        """

        return [
            AdminPageSpec(
                slug="k8s-hosts",
                title="Kubernetes",
                description=(
                    "Services and pods discovered by KubernetesHosts "
                    "(uses /api/v1/plugins/{name}/k8s_hosts for data)."
                ),
                layout="one_column",
                kind="k8s_hosts",
            )
        ]

    def get_admin_ui_descriptor(self) -> dict[str, object]:
        """Brief: Generic snapshot layout descriptor for the admin UI.

        Inputs:
          - None.

        Outputs:
          - Dict with name, title, order, endpoints, layout.
        """

        plugin_name = getattr(self, "name", "k8s")
        title = f"Kubernetes ({plugin_name})" if plugin_name else "Kubernetes"
        snapshot_url = f"/api/v1/plugins/{plugin_name}/k8s_hosts"
        layout: dict[str, object] = {
            "sections": [
                {
                    "id": "summary",
                    "title": "Summary",
                    "type": "kv",
                    "path": "summary",
                    "rows": [
                        {"key": "total_entries", "label": "Entries"},
                        {"key": "services", "label": "Service names"},
                        {"key": "pods", "label": "Pod names"},
                        {"key": "last_reload", "label": "Last reload (unix)"},
                        {"key": "last_error", "label": "Last error"},
                    ],
                },
                {
                    "id": "entries",
                    "title": "Entries",
                    "type": "table",
                    "path": "entries",
                    "columns": [
                        {"key": "name", "label": "Name"},
                        {"key": "ipv4", "label": "IPv4", "join": ", "},
                        {"key": "ipv6", "label": "IPv6", "join": ", "},
                        {"key": "source", "label": "Source"},
                        {"key": "txt", "label": "TXT", "join": " | "},
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
        """Brief: JSON-safe snapshot of current K8s host mappings for admin UI.

        Inputs:
          - None.

        Outputs:
          - Dict with summary and entries lists.
        """

        with self._lock:
            names = sorted(set(self._forward_v4) | set(self._forward_v6))
            entries: list[dict[str, object]] = []
            services = 0
            pods = 0
            for name in names:
                src = str(self._entry_sources.get(name) or "")
                if src.startswith("service/"):
                    services += 1
                elif src.startswith("pod/"):
                    pods += 1
                entries.append(
                    {
                        "name": name,
                        "ipv4": list(self._forward_v4.get(name, [])),
                        "ipv6": list(self._forward_v6.get(name, [])),
                        "source": src,
                        "txt": list(self._aggregate_txt.get(name, [])),
                        "ttl_v4": int(self._ttl_v4.get(name, self._ttl)),
                        "ttl_v6": int(self._ttl_v6.get(name, self._ttl)),
                    }
                )
            summary = {
                "total_entries": len(names),
                "services": services,
                "pods": pods,
                "last_reload": float(self._last_reload_ts or 0.0),
                "last_error": self._last_error,
                "suffix": self._suffix,
                "poll_interval_seconds": float(
                    self._typed.poll_interval_seconds or 0.0
                ),
            }
        return {"summary": summary, "entries": entries}
