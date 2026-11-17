"""Brief: Tests for foghorn.plugins.resolve.kubernetes_hosts.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import importlib
import ipaddress

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext


def _ip(*parts: int) -> str:
    """Brief: Build dotted IPv4 from integer octets (avoids literal redaction).

    Inputs:
      - parts: Four octets.

    Outputs:
      - Dotted quad string.
    """

    return ".".join(str(int(p)) for p in parts)


def _svc(name: str, namespace: str, cluster_ip: str, external: list[str] | None = None):
    """Brief: Build a minimal Service list item.

    Inputs:
      - name / namespace / cluster_ip / external: Service fields.

    Outputs:
      - Dict shaped like a K8s Service object.
    """

    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "clusterIP": cluster_ip,
            "type": "ClusterIP",
            "externalIPs": list(external or []),
        },
    }


def _pod(name: str, namespace: str, ips: list[str], phase: str = "Running"):
    """Brief: Build a minimal Pod list item.

    Inputs:
      - name / namespace / ips / phase: Pod fields.

    Outputs:
      - Dict shaped like a K8s Pod object.
    """

    pod_ips = [{"ip": ip} for ip in ips]
    return {
        "metadata": {"name": name, "namespace": namespace},
        "status": {
            "phase": phase,
            "podIP": ips[0] if ips else None,
            "podIPs": pod_ips,
        },
    }


def test_kubernetes_hosts_module_imports():
    """Brief: Verify kubernetes_hosts module imports.

    Inputs:
      - None.

    Outputs:
      - None; asserts module name.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.kubernetes_hosts")
    assert mod.__name__ == "foghorn.plugins.resolve.kubernetes_hosts"


def test_kubernetes_hosts_builds_maps_and_answers(monkeypatch):
    """Brief: setup() indexes Services/Pods and pre_resolve answers A/PTR.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts maps and DNS answers.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.kubernetes_hosts")
    KubernetesHosts = mod.KubernetesHosts

    svc_ip = _ip(10, 96, 0, 10)
    pod_v4 = _ip(10, 244, 1, 5)
    pod_v6 = "2001" + ":" + "db8" + "::" + "5"
    failed_ip = _ip(10, 244, 1, 9)
    client_ip = _ip(192, 0, 2, 1)

    plugin = KubernetesHosts(
        name="k8s",
        api_server="https://k8s.example",
        token="test-token",
        tls_verify=False,
        namespaces=["default"],
        suffix="cluster.local",
        poll_interval_seconds=0,
        include_services=True,
        include_pods=True,
    )

    services = [
        _svc("web", "default", svc_ip),
        _svc("headless", "default", "None"),
    ]
    pods = [
        _pod("web-0", "default", [pod_v4, pod_v6]),
        _pod("done", "default", [failed_ip], phase="Failed"),
    ]

    def fake_list(conn, resource, namespace, *, label_selector, field_selector):
        _ = (conn, label_selector, field_selector, namespace)
        if resource == "services":
            return services
        if resource == "pods":
            return pods
        return []

    monkeypatch.setattr(plugin, "_list_namespaced", fake_list)
    monkeypatch.setattr(
        plugin,
        "_resolve_connection",
        lambda endpoint: {
            "api_server": "https://k8s.example",
            "token": "x",
            "verify": False,
            "headers": {},
        },
    )

    plugin.setup()
    assert plugin.setup  # setup exists

    snap = plugin.get_http_snapshot()
    assert snap["summary"]["total_entries"] >= 1
    with plugin._lock:
        names = set(plugin._forward_v4) | set(plugin._forward_v6)
    assert any(n.startswith("web.default") for n in names)
    assert any(n.startswith("web-0.default") for n in names)
    assert not any(n.startswith("done.default") for n in names)

    req = DNSRecord.question("web.default.cluster.local", "A").pack()
    ctx = PluginContext(client_ip=client_ip, listener="udp")
    decision = plugin.pre_resolve("web.default.cluster.local.", QTYPE.A, req, ctx)
    assert decision is not None
    assert decision.action == "override"
    reply = DNSRecord.parse(decision.response)
    assert any(rr.rtype == QTYPE.A for rr in reply.rr)

    rev = ipaddress.ip_address(svc_ip).reverse_pointer
    req_ptr = DNSRecord.question(rev, "PTR").pack()
    decision_ptr = plugin.pre_resolve(rev + ".", QTYPE.PTR, req_ptr, ctx)
    assert decision_ptr is not None
    reply_ptr = DNSRecord.parse(decision_ptr.response)
    assert any(rr.rtype == QTYPE.PTR for rr in reply_ptr.rr)

    plugin.shutdown()


def test_kubernetes_hosts_missing_auth_records_error(monkeypatch):
    """Brief: setup survives failed connection and records last_error.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts empty maps and last_error set.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.kubernetes_hosts")
    KubernetesHosts = mod.KubernetesHosts

    plugin = KubernetesHosts(
        name="k8s",
        api_server="https://k8s.example",
        poll_interval_seconds=0,
        tls_verify=False,
    )
    monkeypatch.setattr(mod, "_DEFAULT_KUBECONFIG_PATHS", (None, "/no/such/kubeconfig"))
    monkeypatch.setattr(mod.Path, "is_file", lambda self: False)

    plugin.setup()
    assert plugin._forward_count() == 0
    assert plugin._last_error
    plugin.shutdown()


def test_parse_kubeconfig_token(tmp_path):
    """Brief: _parse_kubeconfig extracts server and token from current-context.

    Inputs:
      - tmp_path: pytest temp path.

    Outputs:
      - None; asserts api_server and token.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.kubernetes_hosts")
    kc = tmp_path / "config"
    kc.write_text(
        """
apiVersion: v1
kind: Config
current-context: c1
contexts:
  - name: c1
    context:
      cluster: cl
      user: u
clusters:
  - name: cl
    cluster:
      server: https://api.example:6443
      insecure-skip-tls-verify: true
users:
  - name: u
    user:
      token: abc123
""",
        encoding="utf-8",
    )
    hints = mod._parse_kubeconfig(str(kc))
    assert hints["api_server"] == "https://api.example:6443"
    assert hints["token"] == "abc123"
    assert hints["tls_verify"] is False


def test_tls_aliases_and_client_cert_auth(tmp_path):
    """Brief: tls_* aliases fold and client cert auth builds requests cert tuple.

    Inputs:
      - tmp_path: pytest temp path.

    Outputs:
      - None; asserts folded fields and conn.cert/sni.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.kubernetes_hosts")
    KubernetesHosts = mod.KubernetesHosts

    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    ca = tmp_path / "ca.crt"
    cert.write_text("CERT", encoding="utf-8")
    key.write_text("KEY", encoding="utf-8")
    ca.write_text("CA", encoding="utf-8")

    plugin = KubernetesHosts(
        name="k8s",
        api_server="https://192.0.2.10",
        tls_cert=str(cert),
        tls_key=str(key),
        tls_ca=str(ca),
        tls_name="kubernetes.example",
        tls_verify=True,
        poll_interval_seconds=0,
    )
    # setup may fail collect; just resolve connection
    plugin._typed = plugin._coerce_config()
    plugin._temp_ca_files = []
    ep = plugin._effective_endpoints()[0]
    assert ep.client_cert == str(cert)
    assert ep.client_key == str(key)
    assert ep.ca_cert == str(ca)
    assert ep.tls_server_name == "kubernetes.example"
    conn = plugin._resolve_connection(ep)
    assert conn["cert"] == (str(cert), str(key))
    assert conn["verify"] == str(ca)
    assert conn["tls_server_name"] == "kubernetes.example"
    assert "Authorization" not in conn["headers"]


def test_parse_kubeconfig_client_cert(tmp_path):
    """Brief: kubeconfig client-certificate/key paths are parsed.

    Inputs:
      - tmp_path: pytest temp path.

    Outputs:
      - None; asserts client_cert/client_key in hints.
    """

    import base64
    from pathlib import Path

    mod = importlib.import_module("foghorn.plugins.resolve.kubernetes_hosts")
    cert = tmp_path / "c.crt"
    key = tmp_path / "c.key"
    cert.write_text("C", encoding="utf-8")
    key.write_text("K", encoding="utf-8")
    # also exercise inline data path
    data_crt = base64.b64encode(b"INLINECERT").decode("ascii")
    data_key = base64.b64encode(b"INLINEKEY").decode("ascii")
    kc = tmp_path / "config"
    kc.write_text(
        f"""
apiVersion: v1
kind: Config
current-context: c1
contexts:
  - name: c1
    context: {{cluster: cl, user: u}}
clusters:
  - name: cl
    cluster:
      server: https://api.example:6443
users:
  - name: u
    user:
      client-certificate-data: {data_crt}
      client-key-data: {data_key}
""",
        encoding="utf-8",
    )
    hints = mod._parse_kubeconfig(str(kc))
    assert hints.get("client_cert")
    assert hints.get("client_key")
    assert Path(hints["client_cert"]).is_file()
    assert Path(hints["client_key"]).is_file()
    # cleanup temps
    for pth in hints.get("_temp_files") or []:
        Path(pth).unlink(missing_ok=True)


def test_list_namespaced_enforces_page_and_item_caps(monkeypatch):
    """Brief: _list_namespaced raises when page/item caps are exceeded.

    Inputs:
      - Fake _k8s_get that always returns a continue token and one item.

    Outputs:
      - RuntimeError mentioning max_list_pages.
    """

    import importlib

    mod = importlib.import_module("foghorn.plugins.resolve.kubernetes_hosts")
    KubernetesHosts = mod.KubernetesHosts

    plugin = KubernetesHosts(
        name="k8s",
        api_server="https://k8s.example",
        token="t",
        tls_verify=False,
        poll_interval_seconds=0,
        max_list_pages=2,
        max_list_items=100,
    )
    plugin._typed = plugin._coerce_config()

    calls = {"n": 0}

    def fake_get(conn, path, *, params=None, timeout=15.0):
        calls["n"] += 1
        return {
            "items": [{"metadata": {"name": f"item-{calls['n']}"}}],
            "metadata": {"continue": f"tok-{calls['n']}"},
        }

    monkeypatch.setattr(plugin, "_k8s_get", fake_get)
    try:
        plugin._list_namespaced(
            {"api_server": "https://x"},
            "services",
            "default",
            label_selector=None,
            field_selector=None,
        )
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "max_list_pages" in str(exc)


def test_kubernetes_hosts_dns_name_label(monkeypatch):
    """Brief: dns_name label publishes stable names for random pod names.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts label-based and resource-name hostnames both map.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.kubernetes_hosts")
    KubernetesHosts = mod.KubernetesHosts

    pod_ip = _ip(10, 244, 1, 7)
    plugin = KubernetesHosts(
        name="k8s",
        api_server="https://k8s.example",
        token="test-token",
        tls_verify=False,
        namespaces=["default"],
        suffix="cluster.local",
        poll_interval_seconds=0,
        include_services=False,
        include_pods=True,
    )

    pods = [
        {
            "metadata": {
                "name": "web-7d9f8c-xk2m",
                "namespace": "default",
                "labels": {"dns_name": "api"},
            },
            "status": {
                "phase": "Running",
                "podIP": pod_ip,
                "podIPs": [{"ip": pod_ip}],
            },
        }
    ]

    def fake_list(conn, resource, namespace, *, label_selector, field_selector):
        _ = (conn, label_selector, field_selector, namespace)
        if resource == "pods":
            return pods
        return []

    monkeypatch.setattr(plugin, "_list_namespaced", fake_list)
    monkeypatch.setattr(
        plugin,
        "_resolve_connection",
        lambda endpoint: {
            "api_server": "https://k8s.example",
            "token": "x",
            "verify": False,
            "headers": {},
        },
    )

    plugin.setup()
    with plugin._lock:
        names = set(plugin._forward_v4) | set(plugin._forward_v6)
    assert "api.default.cluster.local" in names
    assert "api.cluster.local" in names or "api.default.pod.cluster.local" in names
    assert any(n.startswith("web-7d9f8c-xk2m.default") for n in names)
    assert plugin._forward_v4["api.default.cluster.local"] == [pod_ip]
    plugin.shutdown()
