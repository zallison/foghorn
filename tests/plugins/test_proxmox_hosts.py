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


def _bare_plugin(**config):
    """Brief: Build a ProxmoxHosts instance without contacting endpoints.

    Inputs:
      - config: Extra plugin config kwargs.
    Outputs:
      - ProxmoxHosts with filter attrs initialized (no setup poll).
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    plugin = mod.ProxmoxHosts(endpoints=[], reload_interval_second=0, **config)
    plugin._include_cidrs = plugin._parse_cidr_list(
        config.get("include_cidrs"), option_name="include_cidrs"
    )
    plugin._exclude_cidrs = plugin._parse_cidr_list(
        config.get("exclude_cidrs"), option_name="exclude_cidrs"
    )
    plugin._include_interfaces = plugin._parse_name_list(
        config.get("include_interfaces")
    )
    try:
        plugin._address_limit = max(0, int(config.get("address_limit", 0)))
    except (TypeError, ValueError):
        plugin._address_limit = 0
    plugin._merge_addresses = bool(config.get("merge_addresses", False))
    return plugin


def test_extract_agent_ips_filters_loopback():
    """Brief: Agent IP extractor drops loopback and keeps guest IPs.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _bare_plugin()
    v4, v6 = plugin._extract_agent_ips(_agent_payload(WEB_V4, WEB_V6))
    assert v4 == [WEB_V4]
    assert v6 == [WEB_V6]


def test_extract_agent_ips_include_exclude_cidrs_and_interfaces():
    """Brief: CIDR and interface filters drop docker/bridge addresses.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    lan = WEB_V4
    docker = str(ipaddress.IPv4Address(0xAC110002))
    docker_cidr = str(ipaddress.ip_network((0xAC100000, 12)))
    payload = {
        "result": [
            {
                "name": "eth0",
                "ip-addresses": [
                    {"ip-address": lan, "ip-address-type": "ipv4", "prefix": 24},
                ],
            },
            {
                "name": "docker0",
                "ip-addresses": [
                    {"ip-address": docker, "ip-address-type": "ipv4", "prefix": 16},
                ],
            },
        ]
    }

    # include_cidrs keeps only LAN (/32 of WEB_V4).
    plugin = _bare_plugin(include_cidrs=[f"{lan}/32"])
    v4, _ = plugin._extract_agent_ips(payload)
    assert v4 == [lan]

    # exclude_cidrs drops docker pool.
    plugin = _bare_plugin(exclude_cidrs=[docker_cidr])
    v4, _ = plugin._extract_agent_ips(payload)
    assert v4 == [lan]

    # include_interfaces keeps eth0 only.
    plugin = _bare_plugin(include_interfaces=["ETH0"])
    v4, _ = plugin._extract_agent_ips(payload)
    assert v4 == [lan]

    plugin = _bare_plugin(include_interfaces=["docker0"])
    v4, _ = plugin._extract_agent_ips(payload)
    assert v4 == [docker]


def test_apply_address_limit_per_family():
    """Brief: address_limit truncates each address family independently.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _bare_plugin(address_limit=1)
    v4, v6 = plugin._apply_address_limit(
        [WEB_V4, DB_V4, OK_V4],
        [WEB_V6, STATIC_V6],
    )
    assert v4 == [WEB_V4]
    assert v6 == [WEB_V6]

    plugin = _bare_plugin(address_limit=0)
    v4, v6 = plugin._apply_address_limit([WEB_V4, DB_V4], [WEB_V6])
    assert v4 == [WEB_V4, DB_V4]
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

    plugin = _bare_plugin()
    # Keep gw value as in original test fixture style.
    gw = ".".join(STATIC_V4.split(".")[:-1] + ["1"])
    v4, v6 = plugin._extract_ipconfig_ips(
        {
            "ipconfig0": f"ip={STATIC_V4}/24,gw={gw}",
            "ipconfig1": "ip=dhcp",
            "ipconfig2": f"ip6={STATIC_V6}/64",
        }
    )
    assert v4 == [STATIC_V4]
    assert v6 == [STATIC_V6]


def test_proxmox_hosts_address_filters_end_to_end(monkeypatch):
    """Brief: setup applies include_cidrs + address_limit to published maps.

    Inputs:
      - monkeypatch: pytest fixture.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    ProxmoxHosts = mod.ProxmoxHosts

    docker_ip = str(ipaddress.IPv4Address(0xAC110002))
    docker_cidr = str(ipaddress.ip_network((0xAC100000, 12)))
    payload = {
        "result": [
            {
                "name": "eth0",
                "ip-addresses": [
                    {
                        "ip-address": WEB_V4,
                        "ip-address-type": "ipv4",
                        "prefix": 24,
                    },
                    {
                        "ip-address": docker_ip,
                        "ip-address-type": "ipv4",
                        "prefix": 16,
                    },
                ],
            }
        ]
    }
    routes = {
        "cluster/resources?type=vm": [
            {
                "node": "pve1",
                "vmid": 100,
                "name": "web",
                "type": "qemu",
                "status": "running",
                "template": 0,
            }
        ],
        "nodes/pve1/qemu/100/agent/network-get-interfaces": payload,
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
        exclude_cidrs=[docker_cidr],
        include_interfaces=["eth0"],
        address_limit=1,
    )
    monkeypatch.setattr(plugin, "_get_client", lambda endpoint: fake)
    monkeypatch.setattr(mod, "_PveClient", lambda **kwargs: fake)
    plugin.setup()

    assert plugin._forward_v4["web.pve.example"] == [WEB_V4]
    plugin.shutdown()


def test_pve_client_suppresses_insecure_tls_warning(caplog):
    """Brief: verify=False suppresses urllib3 flood; one compact log per URL.

    Inputs:
      - caplog: pytest fixture.
    Outputs:
      - None.
    """

    import logging
    import warnings

    import urllib3

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    # Reset module one-shot state for isolation.
    mod._INSECURE_TLS_NOTICES.clear()
    mod._INSECURE_WARNING_FILTER_INSTALLED = False

    with caplog.at_level(logging.WARNING, logger=mod.logger.name):
        c1 = mod._PveClient(
            base_url="https://pve-insecure.example:8006",
            token_id="u@pve!t",
            token_secret="s",
            user=None,
            password=None,
            verify=False,
        )
        c2 = mod._PveClient(
            base_url="https://pve-insecure.example:8006",
            token_id="u@pve!t",
            token_secret="s",
            user=None,
            password=None,
            verify=False,
        )
        c1.close()
        c2.close()

    msgs = [
        r.getMessage()
        for r in caplog.records
        if "TLS verify disabled" in r.getMessage()
    ]
    assert len(msgs) == 1
    assert "pve-insecure.example" in msgs[0]

    assert mod._INSECURE_WARNING_FILTER_INSTALLED is True
    # Global filters should ignore InsecureRequestWarning (urllib3 flood).
    assert any(
        f[0] == "ignore" and f[2] is urllib3.exceptions.InsecureRequestWarning
        for f in warnings.filters
    )


def test_reload_interval_plugin_level_not_shadowed(monkeypatch):
    """Brief: plugin-level reload_interval_second is not overridden by endpoint default.

    Inputs:
      - monkeypatch: pytest fixture.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    ProxmoxHosts = mod.ProxmoxHosts

    # Simulate pydantic model_dump where endpoint reload_interval_second is None
    # (inherit) rather than a hard-coded 30.
    dumped = mod.ProxmoxHostsConfig.model_validate(
        {
            "reload_interval_second": 300,
            "endpoints": [
                {
                    "url": "https://pve.example:8006",
                    "token_id": "foghorn@pve!dns",
                    "token_secret": "secret",
                    "verify_tls": False,
                }
            ],
        }
    ).model_dump()

    assert dumped["endpoints"][0]["reload_interval_second"] is None

    routes = {
        "cluster/resources?type=vm": [],
    }
    fake = _FakeClient(routes)

    plugin = ProxmoxHosts(**dumped)
    monkeypatch.setattr(plugin, "_get_client", lambda endpoint: fake)
    monkeypatch.setattr(mod, "_PveClient", lambda **kwargs: fake)
    plugin.setup()
    assert plugin._reload_interval == 300.0
    plugin.shutdown()


def test_reload_interval_endpoint_override(monkeypatch):
    """Brief: explicit per-endpoint reload_interval_second overrides plugin level.

    Inputs:
      - monkeypatch: pytest fixture.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    ProxmoxHosts = mod.ProxmoxHosts
    fake = _FakeClient({"cluster/resources?type=vm": []})
    plugin = ProxmoxHosts(
        reload_interval_second=300,
        endpoints=[
            {
                "url": "https://pve.example:8006",
                "token_id": "foghorn@pve!dns",
                "token_secret": "secret",
                "verify_tls": False,
                "reload_interval_second": 90,
            }
        ],
    )
    monkeypatch.setattr(plugin, "_get_client", lambda endpoint: fake)
    monkeypatch.setattr(mod, "_PveClient", lambda **kwargs: fake)
    plugin.setup()
    assert plugin._reload_interval == 90.0
    plugin.shutdown()


def test_reload_logs_only_when_maps_change(monkeypatch, caplog):
    """Brief: unchanged reload is silent; map changes log once.

    Inputs:
      - monkeypatch, caplog: pytest fixtures.
    Outputs:
      - None.
    """

    import logging

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    ProxmoxHosts = mod.ProxmoxHosts

    routes = {
        "cluster/resources?type=vm": [
            {
                "node": "pve1",
                "vmid": 100,
                "name": "web",
                "type": "qemu",
                "status": "running",
                "template": 0,
            }
        ],
        "nodes/pve1/qemu/100/agent/network-get-interfaces": _agent_payload(WEB_V4),
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
        reload_interval_second=0,
    )
    monkeypatch.setattr(plugin, "_get_client", lambda endpoint: fake)
    monkeypatch.setattr(mod, "_PveClient", lambda **kwargs: fake)

    with caplog.at_level(logging.INFO, logger=mod.logger.name):
        plugin.setup()
    first = [r for r in caplog.records if "loaded " in r.getMessage()]
    assert len(first) == 1

    caplog.clear()
    with caplog.at_level(logging.INFO, logger=mod.logger.name):
        plugin._reload_from_proxmox()
    second = [r for r in caplog.records if "loaded " in r.getMessage()]
    assert second == []

    # Change inventory → log again.
    routes["nodes/pve1/qemu/100/agent/network-get-interfaces"] = _agent_payload(DB_V4)
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=mod.logger.name):
        plugin._reload_from_proxmox()
    third = [r for r in caplog.records if "loaded " in r.getMessage()]
    assert len(third) == 1
    plugin.shutdown()


def test_default_reload_interval_is_300():
    """Brief: ProxmoxHostsConfig defaults reload_interval_second to 300.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.proxmox_hosts")
    cfg = mod.ProxmoxHostsConfig()
    assert cfg.reload_interval_second == 300.0
