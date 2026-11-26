"""Brief: Tests for foghorn.plugins.resolve.unifi_hosts UnifiHosts.

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

# RFC 5737 / test addresses built from integers (avoid dotted-quad literals).
LAPTOP_V4 = str(ipaddress.IPv4Address(0xC000020A))
AP_V4 = str(ipaddress.IPv4Address(0xC0000214))
SWITCH_V4 = str(ipaddress.IPv4Address(0xC000021E))
NAS_V4 = str(ipaddress.IPv4Address(0xC000020B))
VPN_V4 = str(ipaddress.IPv4Address(0xC0000264))
OFFLINE_V4 = str(ipaddress.IPv4Address(0xC0000232))
LAB_V4 = str(ipaddress.IPv4Address(0xC633640A))
CLIENT_IP = str(ipaddress.IPv4Address(0xCB007101))
EP_HOST = str(ipaddress.IPv4Address(0xC0000201))
SITE_ID = "11111111-2222-3333-4444-555555555555"
SITE_B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _mac(*parts: int) -> str:
    """Brief: Format a MAC from six octets.

    Inputs:
      - parts: Six integer octets.
    Outputs:
      - Colon-separated lowercase MAC string.
    """

    assert len(parts) == 6
    return ":".join(f"{p:02x}" for p in parts)


MAC_LAPTOP = _mac(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
MAC_NAS = _mac(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
MAC_AP = _mac(0xAA, 0x11, 0xBB, 0x22, 0xCC, 0x33)
MAC_SW = _mac(0xDD, 0x44, 0xEE, 0x55, 0xFF, 0x66)
MAC_OFF = _mac(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC)
MAC_LAB = _mac(0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45)


def _page(items: list[dict], *, offset: int = 0, limit: int = 200) -> dict:
    """Brief: Build a UniFi Integration list page envelope.

    Inputs:
      - items: Full item list (sliced by offset/limit).
      - offset / limit: Pagination window.
    Outputs:
      - dict with data/count/totalCount/offset/limit.
    """

    chunk = items[offset : offset + limit]
    return {
        "offset": offset,
        "limit": limit,
        "count": len(chunk),
        "totalCount": len(items),
        "data": chunk,
    }


def _sites():
    """Brief: Sample site list.

    Inputs:
      - None.
    Outputs:
      - list[dict] of site overviews.
    """

    return [
        {"id": SITE_ID, "name": "Default", "internalName": "default"},
        {"id": SITE_B, "name": "Lab", "internalName": "lab"},
    ]


def _clients():
    """Brief: Sample connected clients.

    Inputs:
      - None.
    Outputs:
      - list[dict] of client overviews.
    """

    return [
        {
            "id": "c1",
            "name": "Ryan's Laptop 00:FF",
            "ipAddress": LAPTOP_V4,
            "macAddress": MAC_LAPTOP,
            "type": "WIRELESS",
        },
        {
            "id": "c2",
            "name": "nas_box",
            "ipAddress": NAS_V4,
            "macAddress": MAC_NAS,
            "type": "WIRED",
        },
        {
            "id": "c3",
            "name": "vpn-user",
            "ipAddress": VPN_V4,
            "type": "VPN",
        },
    ]


def _devices():
    """Brief: Sample adopted devices.

    Inputs:
      - None.
    Outputs:
      - list[dict] of device overviews.
    """

    return [
        {
            "id": "d1",
            "name": "ap-upstairs",
            "ipAddress": AP_V4,
            "macAddress": MAC_AP,
            "model": "U6-LR",
            "state": "ONLINE",
        },
        {
            "id": "d2",
            "name": "core-switch",
            "ipAddress": SWITCH_V4,
            "macAddress": MAC_SW,
            "model": "USW-Pro-24-POE",
            "state": "ONLINE",
        },
        {
            "id": "d3",
            "name": "offline-ap",
            "ipAddress": OFFLINE_V4,
            "macAddress": MAC_OFF,
            "model": "U6-Lite",
            "state": "OFFLINE",
        },
    ]


class _FakeClient:
    """Brief: In-memory stand-in for _UnifiClient used by unit tests.

    Inputs:
      - sites/clients/devices maps and optional fail flag.
    Outputs:
      - get_json / list_paginated responses.
    """

    def __init__(
        self,
        *,
        sites: list[dict] | None = None,
        clients_by_site: dict[str, list[dict]] | None = None,
        devices_by_site: dict[str, list[dict]] | None = None,
        page_limit: int = 200,
        fail: bool = False,
        fail_sites: bool = False,
    ) -> None:
        self.sites = sites if sites is not None else _sites()[:1]
        self.clients_by_site = clients_by_site or {SITE_ID: _clients()}
        self.devices_by_site = devices_by_site or {SITE_ID: _devices()}
        self.page_limit = page_limit
        self.fail = fail
        self.fail_sites = fail_sites
        self.closed = False
        self.calls: list[tuple[str, dict | None]] = []

    def get_json(self, path: str, params=None):
        """Brief: Return canned JSON for path.

        Inputs:
          - path: API path.
          - params: Optional query params.
        Outputs:
          - Canned payload.
        """

        self.calls.append((path, dict(params) if params else None))
        if self.fail:
            raise RuntimeError("down")
        path = str(path or "").lstrip("/")
        if path in {"info", "v1/info"}:
            return {"applicationVersion": "11.0.97"}
        if path in {"sites", "v1/sites"}:
            if self.fail_sites:
                raise RuntimeError("sites down")
            offset = int((params or {}).get("offset") or 0)
            limit = int((params or {}).get("limit") or self.page_limit)
            return _page(self.sites, offset=offset, limit=limit)
        raise RuntimeError(f"unexpected get_json path {path}")

    def list_paginated(self, path: str, *, extra_params=None):
        """Brief: Paginate canned list data for path.

        Inputs:
          - path: List path.
          - extra_params: Optional extra query params (recorded only).
        Outputs:
          - Flat list of dicts.
        """

        if self.fail:
            raise RuntimeError("down")
        path = str(path or "").lstrip("/")
        path = path.removeprefix("v1/")
        if path == "sites":
            if self.fail_sites:
                raise RuntimeError("sites down")
            return list(self.sites)
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "sites":
            site_id, kind = parts[1], parts[2]
            if kind == "clients":
                return list(self.clients_by_site.get(site_id, []))
            if kind == "devices":
                return list(self.devices_by_site.get(site_id, []))
        raise RuntimeError(f"unexpected list path {path}")

    def close(self) -> None:
        """Brief: Mark client closed.

        Inputs:
          - None.
        Outputs:
          - None.
        """

        self.closed = True


def test_unifi_hosts_module_imports():
    """Brief: Verify unifi_hosts module imports.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.unifi_hosts")
    assert mod.__name__ == "foghorn.plugins.resolve.unifi_hosts"


def test_normalize_integration_base_url():
    """Brief: Console origin and cloud connector URLs normalize correctly.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.unifi_hosts")
    assert (
        mod.normalize_integration_base_url("https://udm.lan")
        == "https://udm.lan/proxy/network/integration"
    )
    assert (
        mod.normalize_integration_base_url(
            "https://udm.lan/proxy/network/integration/v1"
        )
        == "https://udm.lan/proxy/network/integration"
    )
    assert (
        mod.normalize_integration_base_url("https://api.ui.com", console_id="CONSOLE1")
        == "https://api.ui.com/v1/connector/consoles/CONSOLE1/proxy/network/integration"
    )


def test_sanitize_unifi_name_and_mac_alias():
    """Brief: Free-text names and MAC aliases become valid DNS labels.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.unifi_hosts")
    assert mod.sanitize_unifi_name("Ryan's Laptop 00:FF") == "ryan-s-laptop-00-ff"
    assert mod.sanitize_unifi_name("nas_box") == "nas-box"
    assert mod.sanitize_unifi_name("") == ""
    assert mod.mac_to_host_alias(MAC_LAPTOP) == "host-aabbccddeeff"
    assert mod.mac_to_host_alias("bad") == ""


def test_list_paginated_walks_pages():
    """Brief: _UnifiClient.list_paginated walks offset until totalCount.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.unifi_hosts")
    items = [{"id": str(i), "name": f"n{i}"} for i in range(5)]

    class _Session:
        def __init__(self):
            self.verify = True

        def get(self, url, params=None, headers=None, verify=None, timeout=None):
            offset = int((params or {}).get("offset") or 0)
            limit = int((params or {}).get("limit") or 2)
            body = _page(items, offset=offset, limit=limit)

            class _Resp:
                content = b"{}"
                status_code = 200

                def raise_for_status(self):
                    return None

                def json(self):
                    return body

            return _Resp()

        def close(self):
            return None

    client = mod._UnifiClient(
        base_url="https://udm.lan/proxy/network/integration",
        api_key="k",
        verify=True,
        page_limit=2,
    )
    client._session = _Session()
    got = client.list_paginated("sites")
    assert len(got) == 5
    assert got[0]["id"] == "0"
    assert got[-1]["id"] == "4"


def _make_plugin(**config):
    """Brief: Construct UnifiHosts without running setup.

    Inputs:
      - config: Plugin config kwargs.
    Outputs:
      - UnifiHosts instance.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.unifi_hosts")
    config.setdefault("reload_interval_second", 0)
    return mod.UnifiHosts(**config)


def _wire_fake(plugin, fake: _FakeClient) -> None:
    """Brief: Point plugin._get_client at a fake client.

    Inputs:
      - plugin: UnifiHosts instance.
      - fake: _FakeClient.
    Outputs:
      - None.
    """

    plugin._get_client = lambda endpoint: fake  # type: ignore[method-assign]


def test_reload_publishes_clients_devices_suffix_and_dns():
    """Brief: setup maps clients/devices under suffix and answers A/PTR.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _make_plugin(
        endpoints=[
            {
                "id": "udm",
                "url": "https://udm.lan",
                "api_key": "secret-key",
                "verify_tls": False,
            }
        ],
        suffix="unifi.example",
        ttl=30,
        reload_interval_second=0,
        include_clients=True,
        include_devices=True,
    )
    _wire_fake(plugin, _FakeClient())
    plugin.setup()
    try:
        host = "ryan-s-laptop-00-ff.unifi.example"
        assert host in plugin._forward_v4
        assert plugin._forward_v4[host] == [LAPTOP_V4]
        assert "ap-upstairs.unifi.example" in plugin._forward_v4
        assert "offline-ap.unifi.example" not in plugin._forward_v4
        assert "ryan-s-laptop-00-ff" not in plugin._forward_v4

        ptr = ipaddress.ip_address(LAPTOP_V4).reverse_pointer
        assert plugin._reverse[ptr] == host

        req = DNSRecord.question(host, "A")
        ctx = PluginContext(client_ip=CLIENT_IP)
        decision = plugin.pre_resolve(host, QTYPE.A, bytes(req.pack()), ctx)
        assert decision is not None
        raw = getattr(decision, "response", None) or getattr(decision, "override", None)
        assert raw is not None
        parsed = DNSRecord.parse(raw) if isinstance(raw, (bytes, bytearray)) else raw
        answers = [str(rr.rdata) for rr in parsed.rr if rr.rtype == QTYPE.A]
        assert LAPTOP_V4 in answers

        snap = plugin.get_http_snapshot()
        assert snap["summary"]["total_clients"] >= 1
        assert snap["summary"]["total_devices"] >= 1
        assert snap["summary"]["suffix"] == "unifi.example"
        assert any(h.get("kind") == "client" for h in snap["hosts"])
    finally:
        plugin.shutdown()


def test_publish_mac_alias_and_include_types():
    """Brief: publish_mac adds host- alias; include_types filters clients.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _make_plugin(
        endpoints=[{"url": "https://udm.lan", "api_key": "k", "verify_tls": False}],
        reload_interval_second=0,
        publish_mac=True,
        include_types=["wired"],
        include_devices=False,
    )
    _wire_fake(plugin, _FakeClient())
    plugin.setup()
    try:
        assert "nas-box" in plugin._forward_v4
        assert "host-112233445566" in plugin._forward_v4
        assert "ryan-s-laptop-00-ff" not in plugin._forward_v4
        assert "vpn-user" not in plugin._forward_v4
    finally:
        plugin.shutdown()


def test_site_name_filter_and_failover():
    """Brief: site_names filters sites; second endpoint used when first fails.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _make_plugin(
        endpoints=[
            {
                "id": "down",
                "url": "https://down.lan",
                "api_key": "k",
                "verify_tls": False,
            },
            {
                "id": "up",
                "url": "https://up.lan",
                "api_key": "k",
                "verify_tls": False,
            },
        ],
        reload_interval_second=0,
        site_names=["lab"],
        include_devices=False,
    )
    bad = _FakeClient(fail=True)
    good = _FakeClient(
        sites=_sites(),
        clients_by_site={
            SITE_ID: _clients(),
            SITE_B: [
                {
                    "id": "lab1",
                    "name": "lab-pc",
                    "ipAddress": LAB_V4,
                    "macAddress": MAC_LAB,
                    "type": "WIRED",
                }
            ],
        },
        devices_by_site={SITE_ID: [], SITE_B: []},
    )

    def _get(endpoint):
        if endpoint.get("id") == "down":
            return bad
        return good

    plugin._get_client = _get  # type: ignore[method-assign]
    plugin.setup()
    try:
        assert "lab-pc" in plugin._forward_v4
        assert "nas-box" not in plugin._forward_v4
    finally:
        plugin.shutdown()


def test_cidr_filter_drops_addresses():
    """Brief: include_cidrs drops clients outside the allowlist.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    only = LAPTOP_V4
    plugin = _make_plugin(
        endpoints=[{"url": "https://udm.lan", "api_key": "k", "verify_tls": False}],
        reload_interval_second=0,
        include_cidrs=[f"{only}/32"],
        include_devices=False,
    )
    _wire_fake(plugin, _FakeClient())
    plugin.setup()
    try:
        assert "ryan-s-laptop-00-ff" in plugin._forward_v4
        assert "nas-box" not in plugin._forward_v4
    finally:
        plugin.shutdown()


def test_endpoint_url_normalization_and_tls_aliases():
    """Brief: bare URL gains integration path; tls_name folds to SNI.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _make_plugin(
        endpoints=[
            {
                "id": "udm",
                "url": f"https://{EP_HOST}",
                "api_key": "k",
                "verify_tls": True,
                "tls_name": "unifi.example",
            }
        ],
        reload_interval_second=0,
    )
    plugin._init_dynamic_hosts_state(default_ttl=60)
    eps = plugin._parse_endpoints(plugin.config.get("endpoints") or [])
    assert eps
    assert eps[0]["url"].endswith("/proxy/network/integration")
    assert eps[0]["tls_server_name"] == "unifi.example"


def test_admin_descriptor_and_config_model():
    """Brief: Admin UI descriptor and config model are available.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.unifi_hosts")
    assert mod.UnifiHosts.get_config_model() is mod.UnifiHostsConfig
    plugin = _make_plugin(
        endpoints=[{"url": "https://udm.lan", "api_key": "k", "verify_tls": False}],
        reload_interval_second=0,
        include_clients=False,
        include_devices=False,
    )
    _wire_fake(plugin, _FakeClient(sites=[], clients_by_site={}, devices_by_site={}))
    plugin.setup()
    try:
        pages = plugin.get_admin_pages()
        assert pages and pages[0].kind == "unifi_hosts"
        desc = plugin.get_admin_ui_descriptor()
        assert "unifi_hosts" in desc["endpoints"]["snapshot"]
    finally:
        plugin.shutdown()


def test_all_endpoints_fail_keeps_previous_maps():
    """Brief: Failed reload keeps prior forward maps.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _make_plugin(
        endpoints=[{"url": "https://udm.lan", "api_key": "k", "verify_tls": False}],
        reload_interval_second=0,
        include_devices=False,
    )
    _wire_fake(plugin, _FakeClient())
    plugin.setup()
    assert "ryan-s-laptop-00-ff" in plugin._forward_v4
    _wire_fake(plugin, _FakeClient(fail=True))
    plugin._clients = {}
    plugin._reload_from_unifi()
    assert "ryan-s-laptop-00-ff" in plugin._forward_v4
    plugin.shutdown()


def test_include_exclude_name_kind_mac():
    """Brief: Name/kind/MAC include-exclude filters drop non-matching rows.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _make_plugin(
        endpoints=[{"url": "https://udm.lan", "api_key": "k", "verify_tls": False}],
        reload_interval_second=0,
        include_kinds=["client"],
        include_names=["nas*"],
        exclude_macs=[MAC_LAPTOP],
    )
    _wire_fake(plugin, _FakeClient())
    plugin.setup()
    try:
        assert "nas-box" in plugin._forward_v4
        assert "ryan-s-laptop-00-ff" not in plugin._forward_v4
        assert "ap-upstairs" not in plugin._forward_v4  # devices excluded by kind
    finally:
        plugin.shutdown()


def test_exclude_kinds_and_states():
    """Brief: exclude_kinds and offline device state filtering.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    plugin = _make_plugin(
        endpoints=[{"url": "https://udm.lan", "api_key": "k", "verify_tls": False}],
        reload_interval_second=0,
        exclude_kinds=["client"],
        include_states=["ONLINE"],
    )
    _wire_fake(plugin, _FakeClient())
    plugin.setup()
    try:
        assert "ap-upstairs" in plugin._forward_v4
        assert "offline-ap" not in plugin._forward_v4
        assert "nas-box" not in plugin._forward_v4
    finally:
        plugin.shutdown()


def test_network_vlan_filter_uses_row_and_inventory():
    """Brief: VLAN include filter matches inventory-augmented row meta.

    Inputs:
      - None.
    Outputs:
      - None.
    """

    class _NetClient(_FakeClient):
        def list_paginated(self, path: str, *, extra_params=None):
            path_l = str(path or "").lstrip("/")
            if path_l.startswith("v1/"):
                path_l = path_l[3:]
            if path_l.endswith("/networks") or path_l == f"sites/{SITE_ID}/networks":
                return [
                    {"id": "net-lan", "name": "LAN", "vlanId": 1},
                    {"id": "net-iot", "name": "IoT", "vlanId": 40},
                ]
            return super().list_paginated(path, extra_params=extra_params)

    # Annotate nas client with network id that maps to VLAN 40.
    clients = _clients()
    for c in clients:
        if c["id"] == "c2":
            c["networkId"] = "net-iot"
            c["vlanId"] = 40
    fake = _NetClient(clients_by_site={SITE_ID: clients})
    plugin = _make_plugin(
        endpoints=[{"url": "https://udm.lan", "api_key": "k", "verify_tls": False}],
        reload_interval_second=0,
        include_devices=False,
        include_vlans=["40"],
    )
    _wire_fake(plugin, fake)
    plugin.setup()
    try:
        assert "nas-box" in plugin._forward_v4
        assert "ryan-s-laptop-00-ff" not in plugin._forward_v4
    finally:
        plugin.shutdown()


def test_reload_logs_host_counts(caplog):
    """Brief: Successful reload emits host count summary at INFO.

    Inputs:
      - caplog: pytest log capture fixture.
    Outputs:
      - None.
    """

    import logging

    plugin = _make_plugin(
        endpoints=[{"url": "https://udm.lan", "api_key": "k", "verify_tls": False}],
        reload_interval_second=0,
    )
    _wire_fake(plugin, _FakeClient())
    with caplog.at_level(logging.INFO, logger="foghorn.plugins.resolve.unifi_hosts"):
        plugin.setup()
    try:
        assert any(
            "loaded " in r.message and "hosts" in r.message for r in caplog.records
        )
    finally:
        plugin.shutdown()
