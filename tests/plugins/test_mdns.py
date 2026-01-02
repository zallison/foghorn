import ipaddress

import pytest
from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext


def _make_query(name: str, qtype: int) -> bytes:
    """Brief: Create minimal DNS query bytes for unit tests.

    Inputs:
      - name: DNS name.
      - qtype: Numeric DNS qtype.

    Outputs:
      - bytes: Packed DNS query.
    """

    qtype_name = QTYPE.get(qtype, str(qtype))
    return DNSRecord.question(name, qtype=qtype_name).pack()


def test_mdns_bridge_answers_dns_sd_records() -> None:
    """Brief: MdnsBridgePlugin can answer PTR/SRV/TXT/A/AAAA under a DNS suffix.
    @@
        Outputs:
          - Asserts override responses include expected RR types.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        ttl=120,
        domain=".mdns",
    )
    plugin.setup()

    suffix = "mdns"
    service_type = f"_http._tcp.{suffix}"
    instance = f"My Service._http._tcp.{suffix}"
    host = f"myhost.{suffix}"

    service_node = f"_http._tcp.{host}"  # service type prefix + host

    plugin._test_seed_records(
        ptr={
            # DNS-SD meta-enumeration (service types)
            f"_services._dns-sd._udp.{suffix}": [service_type],
            # Service type -> hostnames (Foghorn behavior)
            service_type: [host],
            # Foghorn convenience indexes
            f"_hosts.{suffix}": [host],
            f"_services.{suffix}": [service_node],
        },
        srv={
            instance: (0, 0, 8080, host),
        },
        txt={
            instance: ["path=/", "version=1"],
        },
        a={
            host: ["192.0.2.10"],
        },
        aaaa={
            host: ["2001:db8::10"],
        },
    )

    ctx = PluginContext(client_ip="127.0.0.1")

    # PTR: enumerate service types
    req = _make_query(f"_services._dns-sd._udp.{suffix}", int(QTYPE.PTR))
    decision = plugin.pre_resolve(
        f"_services._dns-sd._udp.{suffix}", int(QTYPE.PTR), req, ctx
    )
    assert decision is not None
    assert decision.action == "override"
    resp = DNSRecord.parse(decision.response)
    assert any(rr.rtype == QTYPE.PTR for rr in resp.rr)

    # PTR: service type -> hostnames
    req = _make_query(service_type, int(QTYPE.PTR))
    decision = plugin.pre_resolve(service_type, int(QTYPE.PTR), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert any(rr.rtype == QTYPE.PTR for rr in resp.rr)
    assert any(
        str(rr.rdata).rstrip(".") == host for rr in resp.rr if rr.rtype == QTYPE.PTR
    )

    # PTR: list all hosts
    req = _make_query(f"_hosts.{suffix}", int(QTYPE.PTR))
    decision = plugin.pre_resolve(f"_hosts.{suffix}", int(QTYPE.PTR), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert any(
        str(rr.rdata).rstrip(".") == host for rr in resp.rr if rr.rtype == QTYPE.PTR
    )

    # PTR: list host-qualified services
    req = _make_query(f"_services.{suffix}", int(QTYPE.PTR))
    decision = plugin.pre_resolve(f"_services.{suffix}", int(QTYPE.PTR), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert any(
        str(rr.rdata).rstrip(".") == service_node
        for rr in resp.rr
        if rr.rtype == QTYPE.PTR
    )

    # SRV
    req = _make_query(instance, int(QTYPE.SRV))
    decision = plugin.pre_resolve(instance, int(QTYPE.SRV), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert any(rr.rtype == QTYPE.SRV for rr in resp.rr)

    # TXT
    req = _make_query(instance, int(QTYPE.TXT))
    decision = plugin.pre_resolve(instance, int(QTYPE.TXT), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert any(rr.rtype == QTYPE.TXT for rr in resp.rr)

    # A / AAAA
    req = _make_query(host, int(QTYPE.A))
    decision = plugin.pre_resolve(host, int(QTYPE.A), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert any(rr.rtype == QTYPE.A for rr in resp.rr)

    req = _make_query(host, int(QTYPE.AAAA))
    decision = plugin.pre_resolve(host, int(QTYPE.AAAA), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert any(rr.rtype == QTYPE.AAAA for rr in resp.rr)


def test_mdns_bridge_service_node_a_and_txt_returned_together() -> None:
    """Brief: Service-node A/TXT queries return both metadata and host addresses.
    @@
        Outputs:
          - Asserts that A or TXT queries for a service-node name include TXT for the
            service and A/AAAA for the underlying host.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        ttl=120,
        domain=".mdns",
    )
    plugin.setup()

    suffix = "mdns"
    host = f"myhost.{suffix}"
    service_node = f"_http._tcp.{host}"

    plugin._test_seed_records(
        txt={
            service_node: ["path=/", "version=1"],
        },
        a={
            host: ["192.0.2.10"],
        },
    )

    ctx = PluginContext(client_ip="127.0.0.1")

    # A query for the service-node should return TXT for the service-node and
    # A/AAAA for the underlying host.
    req = _make_query(service_node, int(QTYPE.A))
    decision = plugin.pre_resolve(service_node, int(QTYPE.A), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)

    assert any(rr.rtype == QTYPE.TXT for rr in resp.rr)
    assert any(
        rr.rtype == QTYPE.A and str(rr.rname).rstrip(".") == host for rr in resp.rr
    )

    # TXT query for the service-node should similarly include host A/AAAA.
    req = _make_query(service_node, int(QTYPE.TXT))
    decision = plugin.pre_resolve(service_node, int(QTYPE.TXT), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)

    assert any(rr.rtype == QTYPE.TXT for rr in resp.rr)
    assert any(
        rr.rtype == QTYPE.A and str(rr.rname).rstrip(".") == host for rr in resp.rr
    )


def test_mdns_bridge_service_type_a_aaaa_return_ptr() -> None:
    """Brief: A/AAAA queries for `_service._proto` names return PTR data when cached.
    @@
        Outputs:
          - Asserts A/AAAA queries for service-type owners yield PTR RRs using cached targets.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        ttl=120,
        domain=".mdns",
    )
    plugin.setup()

    suffix = "mdns"
    service_type = f"_http._tcp.{suffix}"
    host = f"myhost.{suffix}"

    # Seed only PTR data for the service type; there are no host A/AAAA caches.
    plugin._test_seed_records(
        ptr={
            # Service type -> hostnames (Foghorn behavior)
            service_type: [host],
        },
    )

    ctx = PluginContext(client_ip="127.0.0.1")

    # A query for a service-type name should fall back to PTR data.
    req = _make_query(service_type, int(QTYPE.A))
    decision = plugin.pre_resolve(service_type, int(QTYPE.A), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    ptr_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.PTR]
    assert ptr_rrs
    assert any(str(rr.rdata).rstrip(".") == host for rr in ptr_rrs)

    # AAAA behaves the same way.
    req = _make_query(service_type, int(QTYPE.AAAA))
    decision = plugin.pre_resolve(service_type, int(QTYPE.AAAA), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    ptr_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.PTR]
    assert ptr_rrs
    assert any(str(rr.rdata).rstrip(".") == host for rr in ptr_rrs)


def test_mdns_bridge_falls_through_when_unknown() -> None:
    """Brief: Unknown names fall through (no override).

    Inputs:
      - None.

    Outputs:
      - Asserts plugin returns None.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        domain=".local",
        yes_i_really_mean_local=True,
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req = _make_query("unknown.local", int(QTYPE.A))
    assert plugin.pre_resolve("unknown.local", int(QTYPE.A), req, ctx) is None


def test_mdns_bridge_mirror_suffixes_roundtrip() -> None:
    """Brief: `_mirror_suffixes` maps `.local` names into the DNS suffix.

    Inputs:
      - None.

    Outputs:
      - None; asserts suffix normalization behavior.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False, domain=".mdns")
    plugin.setup()

    # `.local` mDNS names are rewritten into the configured DNS suffix.
    assert plugin._mirror_suffixes("Foo.Local.") == ["foo.mdns"]
    # Non-mDNS names pass through unchanged.
    assert plugin._mirror_suffixes("example.com") == ["example.com"]


def test_mdns_bridge_ptr_add_and_remove_mirrors_suffixes() -> None:
    """Brief: PTR add/remove stores keys under the DNS suffix.

    Inputs:
      - None.

    Outputs:
      - None; asserts `_ptr` cache contains/clears `.local` entries.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False, domain=".mdns")
    plugin.setup()

    plugin._ptr_add("_http._tcp.local.", "myhost.local.")

    # `.local` inputs are mapped into the configured DNS suffix.
    assert "_http._tcp.mdns" in plugin._ptr
    assert "myhost.mdns" in plugin._ptr["_http._tcp.mdns"]

    plugin._ptr_remove("_http._tcp.local.", "myhost.local.")

    assert "_http._tcp.mdns" not in plugin._ptr


def test_mdns_bridge_ptr_glue_hosts_match_owner_suffix() -> None:
    """Brief: PTR A/AAAA glue uses the same suffix as the queried owner.

    Inputs:
      - None.

    Outputs:
      - None; asserts that PTR glue A records for `_service._proto` only
        include hosts under the same suffix as the queried service type.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        ttl=120,
        domain=".zaa",
        domains=[".local"],
    )
    plugin.setup()

    # Seed a service type and instance under `.local`; this will be mirrored
    # into both `.local` and `.zaa` suffixes by `_mirror_suffixes`.
    plugin._test_seed_records(
        ptr={
            "_airplay._tcp.local.": ["roku_ultra._airplay._tcp.local."],
        },
        a={
            "roku_ultra.local.": ["192.0.2.10"],
        },
    )

    ctx = PluginContext(client_ip="127.0.0.1")

    # Query the `.local` service type; PTR targets should be `.local` only and
    # the synthesized host A glue should also use `.local`, not `.zaa`.
    qname = "_airplay._tcp.local"
    req = _make_query(qname, int(QTYPE.PTR))
    decision = plugin.pre_resolve(qname, int(QTYPE.PTR), req, ctx)
    assert decision is not None

    resp = DNSRecord.parse(decision.response)

    ptr_targets = {str(rr.rdata).rstrip(".") for rr in resp.rr if rr.rtype == QTYPE.PTR}
    assert ptr_targets == {"roku_ultra._airplay._tcp.local"}

    a_hosts = {str(rr.rname).rstrip(".") for rr in resp.rr if rr.rtype == QTYPE.A}
    assert "roku_ultra.local" in a_hosts
    assert "roku_ultra.zaa" not in a_hosts


@pytest.mark.parametrize(
    "include_ipv4,include_ipv6",
    [
        (True, True),
        (False, True),
        (True, False),
    ],
)
def test_mdns_bridge_ingest_service_info_populates_caches(
    include_ipv4: bool, include_ipv6: bool
) -> None:
    """Brief: `_ingest_service_info` builds SRV/TXT and optional A/AAAA caches.

    Inputs:
      - include_ipv4: whether A records are enabled.
      - include_ipv6: whether AAAA records are enabled.

    Outputs:
      - None; asserts internal caches are populated as expected.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    class DummyInfo:
        def __init__(self) -> None:
            self.name = "myservice._http._tcp.local."
            self.server = "myhost.local."
            self.port = 8080
            self.priority = 0
            self.weight = 0
            self.properties = {b"path": b"/", b"version": b"1"}
            self.addresses = [
                ipaddress.ip_address("192.0.2.10").packed,
                ipaddress.ip_address("2001:db8::10").packed,
            ]

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        include_ipv4=include_ipv4,
        include_ipv6=include_ipv6,
        domain=".local",
        yes_i_really_mean_local=True,
    )
    plugin.setup()

    plugin._ingest_service_info(DummyInfo())

    # Instance has SRV and TXT under the `.local` suffix.
    assert "myservice._http._tcp.local" in plugin._srv
    assert "myservice._http._tcp.local" in plugin._txt

    txt_set = set(plugin._txt["myservice._http._tcp.local"])
    assert txt_set == {"path=/", "version=1"}

    # Host has optional A/AAAA records.
    if include_ipv4:
        assert "myhost.local" in plugin._a
        assert "192.0.2.10" in plugin._a["myhost.local"]
    else:
        assert "myhost.local" not in plugin._a

    if include_ipv6:
        assert "myhost.local" in plugin._aaaa
        assert "2001:db8::10" in plugin._aaaa["myhost.local"]
    else:
        assert "myhost.local" not in plugin._aaaa


def test_mdns_bridge_pre_resolve_returns_none_for_untargeted_client() -> None:
    """Brief: pre_resolve respects BasePlugin targets() filtering.

    Inputs:
      - None.

    Outputs:
      - None; asserts untargeted clients do not receive overrides.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(
        network_enabled=False, targets=["10.0.0.0/8"], domain=".mdns"
    )
    plugin.setup()

    plugin._test_seed_records(a={"myhost.mdns": ["192.0.2.10"]})

    ctx = PluginContext(client_ip="192.0.2.1")
    req = _make_query("myhost.mdns", int(QTYPE.A))
    assert plugin.pre_resolve("myhost.mdns", int(QTYPE.A), req, ctx) is None


def test_mdns_bridge_pre_resolve_returns_none_for_invalid_dns_request() -> None:
    """Brief: pre_resolve returns None when the raw DNS request cannot be parsed.

    Inputs:
      - None.

    Outputs:
      - None; asserts parse errors fall through.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False, domain=".mdns")
    plugin.setup()

    plugin._test_seed_records(a={"myhost.mdns": ["192.0.2.10"]})

    ctx = PluginContext(client_ip="127.0.0.1")
    assert (
        plugin.pre_resolve("myhost.mdns", int(QTYPE.A), b"not-a-dns-packet", ctx)
        is None
    )


def test_mdns_bridge_pre_resolve_uses_configured_ttl() -> None:
    """Brief: Synthesized answers use the plugin `ttl` config.

    Inputs:
      - None.

    Outputs:
      - None; asserts TTL in answer RRs matches configured value.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False, ttl=123, domain=".mdns")
    plugin.setup()

    plugin._test_seed_records(a={"myhost.mdns": ["192.0.2.10"]})

    ctx = PluginContext(client_ip="127.0.0.1")
    req = _make_query("myhost.mdns", int(QTYPE.A))
    decision = plugin.pre_resolve("myhost.mdns", int(QTYPE.A), req, ctx)
    assert decision is not None

    resp = DNSRecord.parse(decision.response)
    answers = [rr for rr in resp.rr if rr.rtype == QTYPE.A]
    assert len(answers) == 1
    assert answers[0].ttl == 123


def test_mdns_bridge_get_admin_pages_descriptor() -> None:
    """Brief: get_admin_pages returns a single mDNS admin page spec.

    Inputs:
      - None.

    Outputs:
      - None; asserts slug, title, and layout/kind fields.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False, domain=".mdns")
    plugin.setup()

    pages = plugin.get_admin_pages()
    assert len(pages) == 1
    page = pages[0]
    assert page.slug == "mdns"
    assert page.title == "mDNS"
    assert page.layout == "one_column"
    assert page.kind == "mdns"


def test_mdns_bridge_get_admin_ui_descriptor_shape() -> None:
    """Brief: get_admin_ui_descriptor describes the snapshot admin UI.

    Inputs:
      - None.

    Outputs:
      - None; asserts descriptor keys, snapshot endpoint, and layout sections.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False, domain=".mdns")
    plugin.setup()

    desc = plugin.get_admin_ui_descriptor()

    # Name and title should be strings; name should reflect the plugin name
    # when present, falling back to "mdns".
    plugin_name = getattr(plugin, "name", "mdns")
    assert desc["name"] == str(plugin_name)
    assert isinstance(desc["title"], str)

    endpoints = desc["endpoints"]
    assert isinstance(endpoints, dict)
    assert endpoints.get("snapshot") == f"/api/v1/plugins/{plugin_name}/mdns"

    layout = desc["layout"]
    assert isinstance(layout, dict)
    sections = layout.get("sections")
    assert isinstance(sections, list) and sections

    summary_section = next(s for s in sections if s["id"] == "summary")
    assert summary_section["type"] == "kv"
    services_section = next(s for s in sections if s["id"] == "services")
    assert services_section["type"] == "table"


def test_mdns_bridge_get_http_snapshot_summarizes_services_and_hosts() -> None:
    """Brief: get_http_snapshot reports counts and per-service host addresses.

    Inputs:
      - None.

    Outputs:
      - None; asserts summary totals and services entries reflect cached data.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        domain=".local",
        yes_i_really_mean_local=True,
    )
    plugin.setup()

    # Seed a single service instance and host with both IPv4 and IPv6.
    instance = "myservice._http._tcp.local."
    host = "myhost.local."
    plugin._test_seed_records(
        srv={instance: (0, 0, 8080, host)},
        a={host: ["192.0.2.10"]},
        aaaa={host: ["2001:db8::10"]},
    )

    # Ensure the plugin also has an explicit DNS domain configured for summary.
    plugin._dns_domains = {".zaa"}

    snap = plugin.get_http_snapshot()

    summary = snap["summary"]
    services = snap["services"]

    assert summary["total_services"] == 1
    assert summary["total_hosts"] == 1
    # Domains list should include the configured DNS domain.
    assert ".zaa" in summary["domains"]

    assert len(services) == 1
    svc = services[0]
    assert svc["instance"].endswith(".local")
    # Service type should be derived from the owner name and strip `.local`.
    assert svc["type"].endswith("_http._tcp")
    assert svc["host"].endswith(".local")
    assert "192.0.2.10" in svc["ipv4"]
    assert "2001:db8::10" in svc["ipv6"]


def test_mdns_bridge_update_service_state_preserves_host_and_up_since() -> None:
    """Brief: _update_service_state normalizes names and preserves uptime periods.

    Inputs:
      - None.

    Outputs:
      - None; asserts host and up_since are preserved across repeated "up" events.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        domain=".local",
        yes_i_really_mean_local=True,
    )
    plugin.setup()

    instance = "MyService._http._tcp.local."
    host = "MyHost.Local."

    # First transition to "up" with a host should set host and up_since.
    plugin._update_service_state(instance, status="up", host=host)
    key = "myservice._http._tcp.local"
    state1 = plugin._service_state[key]
    assert state1.host.endswith(".local")
    assert state1.status == "up"
    assert state1.up_since

    # Second "up" event without a host should keep the original host and up_since.
    plugin._update_service_state(instance, status="up")
    state2 = plugin._service_state[key]
    assert state2.host == state1.host
    assert state2.up_since == state1.up_since


def test_mdns_bridge_format_uptime_human_variants() -> None:
    """Brief: _format_uptime_human handles normal and invalid inputs.

    Inputs:
      - None.

    Outputs:
      - None; asserts formatting for several representative durations.
    """

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False, domain=".mdns")
    plugin.setup()

    assert plugin._format_uptime_human(0) == "0s"
    assert plugin._format_uptime_human(59) == "59s"
    # Minutes/hours omit trailing zero seconds.
    assert plugin._format_uptime_human(60) == "1m"
    assert plugin._format_uptime_human(3661) == "1h 1m 1s"
    # Non-numeric input should be treated as 0.
    assert plugin._format_uptime_human("bad") == "0s"  # type: ignore[arg-type]


def test_mdns_bridge_get_http_snapshot_uses_state_for_host_last_seen_and_uptime() -> (
    None
):
    """Brief: get_http_snapshot folds service state into host, last_seen, and uptime.

    Inputs:
      - None.

    Outputs:
      - None; asserts up and down services reflect _service_state and caches.
    """

    from datetime import datetime, timezone

    from foghorn.plugins.resolve.mdns import MdnsBridgePlugin, _ServiceState

    plugin = MdnsBridgePlugin(
        network_enabled=False,
        domain=".local",
        yes_i_really_mean_local=True,
    )
    plugin.setup()

    # Seed SRV and address data for one "up" service.
    up_instance = "upsvc._http._tcp.local."
    up_host = "uphost.local."
    plugin._test_seed_records(
        srv={up_instance: (0, 0, 8080, up_host)},
        a={up_host: ["192.0.2.10"]},
        aaaa={up_host: ["2001:db8::10"]},
    )

    # Seed state for the up service with a stable last_seen and up_since.
    now_str = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"
    key_up = "upsvc._http._tcp.local"
    plugin._service_state[key_up] = _ServiceState(
        status="up",
        last_seen=now_str,
        host="uphost.local",
        up_since=now_str,
    )

    # Seed a "down" service that has no SRV data but a remembered host.
    down_instance_key = "downsvc._http._tcp.local"
    plugin._service_state[down_instance_key] = _ServiceState(
        status="down",
        last_seen=now_str,
        host="downhost.local",
        up_since="",
    )

    snap = plugin.get_http_snapshot()

    services = snap["services"]
    down_services = snap["down_services"]

    # Up service should appear in services with host/addresses and uptime fields.
    up_records = [r for r in services if r["instance"] == key_up]
    assert up_records
    up_rec = up_records[0]
    assert up_rec["host"] == "uphost.local"
    assert "192.0.2.10" in up_rec["ipv4"]
    assert "2001:db8::10" in up_rec["ipv6"]
    assert "_lastSeenRaw" in up_rec and "_lastSeenTooltip" in up_rec
    # Uptime is best-effort; when present it should be an int with a human string.
    if "uptime" in up_rec:
        assert isinstance(up_rec["uptime"], int)
        assert "uptime_human" in up_rec and isinstance(up_rec["uptime_human"], str)

    # Down service should appear in down_services with host but no addresses.
    down_records = [r for r in down_services if r["instance"] == down_instance_key]
    assert down_records
    down_rec = down_records[0]
    assert down_rec["host"] == "downhost.local"
    assert down_rec["status"] == "down"
    assert down_rec["ipv4"] == []
    assert down_rec["ipv6"] == []
