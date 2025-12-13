import pytest
from dnslib import QTYPE, DNSRecord

from foghorn.plugins.base import PluginContext


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


@pytest.mark.parametrize(
    "suffix",
    ["local", "mdns"],
)
def test_mdns_bridge_answers_dns_sd_records(suffix: str) -> None:
    """Brief: MdnsBridgePlugin can answer PTR/SRV/TXT/A/AAAA under .local and .mdns.

    Inputs:
      - suffix: zone suffix to test (.local or .mdns).

    Outputs:
      - Asserts override responses include expected RR types.
    """

    from foghorn.plugins.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False, ttl=120)
    plugin.setup()

    service_type = f"_http._tcp.{suffix}"
    instance = f"My Service._http._tcp.{suffix}"
    host = f"myhost.{suffix}"

    plugin._test_seed_records(
        ptr={
            f"_services._dns-sd._udp.{suffix}": [service_type],
            service_type: [instance],
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

    # PTR: enumerate instances
    req = _make_query(service_type, int(QTYPE.PTR))
    decision = plugin.pre_resolve(service_type, int(QTYPE.PTR), req, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)
    assert any(rr.rtype == QTYPE.PTR for rr in resp.rr)

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


def test_mdns_bridge_falls_through_when_unknown() -> None:
    """Brief: Unknown names fall through (no override).

    Inputs:
      - None.

    Outputs:
      - Asserts plugin returns None.
    """

    from foghorn.plugins.mdns import MdnsBridgePlugin

    plugin = MdnsBridgePlugin(network_enabled=False)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    req = _make_query("unknown.local", int(QTYPE.A))
    assert plugin.pre_resolve("unknown.local", int(QTYPE.A), req, ctx) is None
