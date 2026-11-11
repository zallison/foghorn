"""Brief: Tests for foghorn.plugins.resolve.proxmox_hosts ProxmoxHosts.

Inputs:
  - None (uses mocks).

Outputs:
  - None; pytest assertions.
"""

from __future__ import annotations

import importlib
import ipaddress

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext

# RFC 5737 / 3849 documentation addresses (safe in tests).
WEB_V4 = "192.0.2.10"
WEB_V6 = "2001:db8::10"
DB_V4 = "192.0.2.20"
OK_V4 = "192.0.2.30"
LOOP_V4 = "127.0.0.1"
STATIC_V4 = "192.0.2.50"
STATIC_V6 = "2001:db8::50"
CLIENT_IP = "192.0.2.1"


def _guest_rows():
    """Brief: Sample cluster/resources VM rows.

    Inputs:
      - None.
    Outputs:
      - list[dict] of qemu resource rows.
    """

    return [
        {
            "node": "pve1",
            "vmid": 100,
            "name": "web",
            "type": "qemu",
            "status": "running",
            "template": 0,
            "tags": "edge;prod",
        },
        {
            "node": "pve2",
            "vmid": 101,
            "name": "db_primary",
            "type": "qemu",
            "status": "running",
            "template": 0,
        },
        {
            "node": "pve1",
            "vmid": 200,
            "name": "tmpl",
            "type": "qemu",
            "status": "stopped",
            "template": 1,
        },
    ]


def _agent_payload(ipv4: str, ipv6: str | None = None):
    """Brief: Build a guest-agent network-get-interfaces payload.

    Inputs:
      - ipv4: IPv4 address string.
      - ipv6: Optional IPv6 address string.
    Outputs:
      - dict matching PVE agent response shape.
    """

    addrs = [
        {"ip-address": LOOP_V4, "ip-address-type": "ipv4", "prefix": 8},
        {"ip-address": ipv4, "ip-address-type": "ipv4", "prefix": 24},
    ]
    if ipv6:
        addrs.append({"ip-address": ipv6, "ip-address-type": "ipv6", "prefix": 64})
    return {
        "result": [
            {"name": "lo", "ip-addresses": addrs[:1]},
            {"name": "eth0", "ip-addresses": addrs[1:]},
        ]
    }


class _FakeClient:
    """Brief: In-memory stand-in for _PveClient used by unit tests.

    Inputs:
      - routes: mapping path -> payload (or callable).
    Outputs:
      - get_json responses.
    """

    def __init__(self, routes: dict):
        self.routes = routes
        self.closed = False

    def get_json(self, path: str, params=None):
        """Brief: Return a canned API payload for path.

        Inputs:
          - path: API path.
          - params: Optional query params.
        Outputs:
          - Canned data.
        """

        key = path
        if params:
            t = params.get("type")
            if t:
                key = f"{path}?type={t}"
        if key not in self.routes and path in self.routes:
            key = path
        val = self.routes.get(key)
        if callable(val):
            return val(path, params)
        if val is None and key.startswith("nodes/"):
            raise RuntimeError(f"missing route {key}")
        return val

    def close(self) -> None:
        """Brief: Mark client closed.

        Inputs:
          - None.
        Outputs:
          - None.
        """

        self.closed = True


def test_proxmox_hosts_module_imports():
    """Brief: Verify proxmox_hosts module imports.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    assert mod.__name__ == "foghorn.plugins.resolve.proxmox_hosts"


def test_extract_agent_ips_filters_loopback():
    """Brief: Agent IP extractor drops loopback and keeps guest IPs.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    v4, v6 = mod.ProxmoxHosts._extract_agent_ips(_agent_payload(WEB_V4, WEB_V6))
    assert v4 == [WEB_V4]
    assert v6 == [WEB_V6]


def test_proxmox_hosts_builds_maps_and_answers(monkeypatch):
    """Brief: setup builds maps; pre_resolve answers A/AAAA/PTR.

    Inputs:
      - monkeypatch: pytest fixture.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    ProxmoxHosts = mod.ProxmoxHosts

    routes = {
        "cluster/resources?type=vm": _guest_rows(),
        "nodes/pve1/qemu/100/agent/network-get-interfaces": _agent_payload(
            WEB_V4, WEB_V6
        ),
        "nodes/pve2/qemu/101/agent/network-get-interfaces": _agent_payload(DB_V4),
    }
    fake = _FakeClient(routes)

    plugin = ProxmoxHosts(
        endpoints=[
            {
                "url": "https://pve.example:8006",
                "token_id": "foghorn@pve!dns",
                "token_secret": "secret",
                "verify_tls": False,
            }
        ],
        suffix="pve.example",
        reload_interval_second=0,
        publish_tags=True,
    )

    def fake_get_client(endpoint):
        return fake

    monkeypatch.setattr(plugin, "_get_client", fake_get_client)
    monkeypatch.setattr(mod, "_PveClient", lambda **kwargs: fake)

    plugin.setup()

    assert "web.pve.example" in plugin._forward_v4
    assert plugin._forward_v4["web.pve.example"] == [WEB_V4]
    assert plugin._forward_v6["web.pve.example"] == [WEB_V6]
    assert "db-primary.pve.example" in plugin._forward_v4
    assert "edge.pve.example" in plugin._forward_v4
    assert not any("tmpl" in k for k in plugin._forward_v4)

    ptr = ipaddress.ip_address(WEB_V4).reverse_pointer
    assert plugin._reverse[ptr] == "web.pve.example"

    ctx = PluginContext(client_ip=CLIENT_IP)
    q_a = DNSRecord.question("web.pve.example", "A")
    dec = plugin.pre_resolve("web.pve.example", QTYPE.A, q_a.pack(), ctx)
    assert dec is not None and dec.action == "override"
    resp = DNSRecord.parse(dec.response)
    assert str(resp.rr[0].rdata) == WEB_V4

    q_aaaa = DNSRecord.question("web.pve.example", "AAAA")
    dec6 = plugin.pre_resolve("web.pve.example", QTYPE.AAAA, q_aaaa.pack(), ctx)
    assert dec6 is not None
    assert str(DNSRecord.parse(dec6.response).rr[0].rdata) == WEB_V6

    q_ptr = DNSRecord.question(ptr, "PTR")
    dec_ptr = plugin.pre_resolve(ptr, QTYPE.PTR, q_ptr.pack(), ctx)
    assert dec_ptr is not None
    assert "web.pve.example" in str(DNSRecord.parse(dec_ptr.response).rr[0].rdata)

    snap = plugin.get_http_snapshot()
    assert snap["summary"]["total_guests"] == 2
    plugin.shutdown()


def test_proxmox_hosts_endpoint_failover(monkeypatch):
    """Brief: Second endpoint is used when the first fails listing VMs.

    Inputs:
      - monkeypatch: pytest fixture.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    ProxmoxHosts = mod.ProxmoxHosts

    class BoomClient(_FakeClient):
        def get_json(self, path: str, params=None):
            raise RuntimeError("down")

    good = _FakeClient(
        {
            "cluster/resources?type=vm": [
                {
                    "node": "pve2",
                    "vmid": 1,
                    "name": "ok",
                    "type": "qemu",
                    "status": "running",
                    "template": 0,
                }
            ],
            "nodes/pve2/qemu/1/agent/network-get-interfaces": _agent_payload(OK_V4),
        }
    )
    bad = BoomClient({})

    plugin = ProxmoxHosts(
        endpoints=[
            {
                "url": "https://bad.example:8006",
                "token_id": "foghorn@pve!dns",
                "token_secret": "x",
                "verify_tls": False,
            },
            {
                "url": "https://good.example:8006",
                "token_id": "foghorn@pve!dns",
                "token_secret": "x",
                "verify_tls": False,
            },
        ],
        reload_interval_second=0,
    )

    def fake_get_client(endpoint):
        url = str(endpoint["url"])
        return bad if "bad" in url else good

    monkeypatch.setattr(plugin, "_get_client", fake_get_client)
    monkeypatch.setattr(mod, "_PveClient", lambda **kwargs: bad)

    plugin.setup()
    assert plugin._forward_v4.get("ok") == [OK_V4]
    plugin.shutdown()


def test_ipconfig_static_parse():
    """Brief: Parse cloud-init ipconfig static addresses; skip dhcp.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    v4, v6 = mod.ProxmoxHosts._extract_ipconfig_ips(
        {
            "ipconfig0": f"ip={STATIC_V4}/24,gw=192.0.2.1",
            "ipconfig1": "ip=dhcp",
            "ipconfig2": f"ip6={STATIC_V6}/64",
        }
    )
    assert v4 == [STATIC_V4]
    assert v6 == [STATIC_V6]
