"""
Brief: Tests for foghorn.plugins.docker-hosts DockerHosts plugin.

Inputs:
  - None

Outputs:
  - None
"""

import importlib
import ipaddress

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.base import PluginContext


def _make_example_containers():
    """Brief: Build example docker inspect records for tests.

    Inputs:
      - None.

    Outputs:
      - List of container-like dicts with hostname and IP data.
    """

    return [
        {
            "Id": "c1",
            "Config": {"Hostname": "web"},
            "NetworkSettings": {
                "Networks": {
                    "bridge": {
                        "IPAddress": "172.17.0.5",
                        "GlobalIPv6Address": "2001:db8::5",
                    }
                }
            },
        }
    ]


def test_docker_hosts_module_imports():
    """Brief: Verify docker-hosts module imports correctly.

    Inputs:
      - None.

    Outputs:
      - None; asserts module name.
    """

    mod = importlib.import_module("foghorn.plugins.docker-hosts")
    assert mod.__name__ == "foghorn.plugins.docker-hosts"


def test_docker_hosts_builds_mappings_from_inspect(monkeypatch):
    """Brief: DockerHosts.setup() builds forward and reverse maps from inspect.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts hostname and reverse mappings are populated.
    """

    mod = importlib.import_module("foghorn.plugins.docker-hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    containers = _make_example_containers()

    def fake_iter(endpoint):  # noqa: ARG001
        return containers

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    plugin.setup()

    # Forward mappings
    assert "web" in plugin._forward_v4  # type: ignore[attr-defined]
    assert plugin._forward_v4["web"] == ["172.17.0.5"]  # type: ignore[index]
    assert "web" in plugin._forward_v6  # type: ignore[attr-defined]
    assert plugin._forward_v6["web"] == ["2001:db8::5"]  # type: ignore[index]

    # Reverse mapping exists for IPv4 and IPv6.
    ptr_v4 = ipaddress.ip_address("172.17.0.5").reverse_pointer
    ptr_v6 = ipaddress.ip_address("2001:db8::5").reverse_pointer

    assert plugin._reverse[ptr_v4] == "web"  # type: ignore[index]
    assert plugin._reverse[ptr_v6] == "web"  # type: ignore[index]


def test_docker_hosts_pre_resolve_a_aaaa_ptr(monkeypatch):
    """Brief: pre_resolve answers A/AAAA/PTR queries from Docker mappings.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts override decisions and expected DNS answers.
    """

    mod = importlib.import_module("foghorn.plugins.docker-hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    containers = _make_example_containers()

    def fake_iter(endpoint):  # noqa: ARG001
        return containers

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    # A record
    q_a = DNSRecord.question("web", "A")
    dec_a = plugin.pre_resolve("web", QTYPE.A, q_a.pack(), ctx)
    assert dec_a is not None
    assert dec_a.action == "override"
    assert dec_a.response is not None
    resp_a = DNSRecord.parse(dec_a.response)
    assert str(resp_a.rr[0].rdata) == "172.17.0.5"

    # AAAA record
    q_aaaa = DNSRecord.question("web", "AAAA")
    dec_aaaa = plugin.pre_resolve("web", QTYPE.AAAA, q_aaaa.pack(), ctx)
    assert dec_aaaa is not None
    assert dec_aaaa.action == "override"
    assert dec_aaaa.response is not None
    resp_aaaa = DNSRecord.parse(dec_aaaa.response)
    assert str(resp_aaaa.rr[0].rdata) == "2001:db8::5"

    # PTR record for IPv4
    ptr_v4 = ipaddress.ip_address("172.17.0.5").reverse_pointer
    q_ptr = DNSRecord.question(ptr_v4, "PTR")
    dec_ptr = plugin.pre_resolve(ptr_v4, QTYPE.PTR, q_ptr.pack(), ctx)
    assert dec_ptr is not None
    assert dec_ptr.action == "override"
    assert dec_ptr.response is not None
    resp_ptr = DNSRecord.parse(dec_ptr.response)
    assert str(resp_ptr.rr[0].rdata) == "web."


def test_docker_hosts_use_host_ip_override(monkeypatch):
    """Brief: DockerHosts can answer using host IPs instead of container IPs.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that host_ipv4/host_ipv6 override container addresses
        for both forward and reverse lookups.
    """

    mod = importlib.import_module("foghorn.plugins.docker-hosts")
    DockerHosts = mod.DockerHosts

    host_v4 = "192.0.2.10"
    host_v6 = "2001:db8::10"

    plugin = DockerHosts(  # type: ignore[arg-type]
        endpoints=[
            {
                "url": "unix:///var/run/docker.sock",
                "use_ipv4": host_v4,
                "use_ipv6": host_v6,
            }
        ],
    )

    containers = _make_example_containers()

    def fake_iter(endpoint):  # noqa: ARG001
        return containers

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    # Forward mappings now point at host IPs
    assert plugin._forward_v4["web"] == [host_v4]  # type: ignore[attr-defined,index]
    assert plugin._forward_v6["web"] == [host_v6]  # type: ignore[attr-defined,index]

    # Reverse mappings
    ptr_v4 = ipaddress.ip_address(host_v4).reverse_pointer
    ptr_v6 = ipaddress.ip_address(host_v6).reverse_pointer
    assert plugin._reverse[ptr_v4] == "web"  # type: ignore[attr-defined,index]
    assert plugin._reverse[ptr_v6] == "web"  # type: ignore[attr-defined,index]

    # A record uses host IPv4
    q_a = DNSRecord.question("web", "A")
    dec_a = plugin.pre_resolve("web", QTYPE.A, q_a.pack(), ctx)
    assert dec_a is not None and dec_a.response is not None
    resp_a = DNSRecord.parse(dec_a.response)
    assert str(resp_a.rr[0].rdata) == host_v4

    # AAAA record uses host IPv6
    q_aaaa = DNSRecord.question("web", "AAAA")
    dec_aaaa = plugin.pre_resolve("web", QTYPE.AAAA, q_aaaa.pack(), ctx)
    assert dec_aaaa is not None and dec_aaaa.response is not None
    resp_aaaa = DNSRecord.parse(dec_aaaa.response)
    assert str(resp_aaaa.rr[0].rdata) == host_v6

    # PTR record for host IPv4 resolves to hostname
    q_ptr = DNSRecord.question(ptr_v4, "PTR")
    dec_ptr = plugin.pre_resolve(ptr_v4, QTYPE.PTR, q_ptr.pack(), ctx)
    assert dec_ptr is not None and dec_ptr.response is not None
    resp_ptr = DNSRecord.parse(dec_ptr.response)
    assert str(resp_ptr.rr[0].rdata) == "web."


def test_docker_hosts_warns_on_missing_hostname_or_ip(monkeypatch, caplog):
    """Brief: setup() warns when containers lack hostname or IPs.

    Inputs:
      - monkeypatch/caplog fixtures.

    Outputs:
      - None; asserts warning messages and empty mappings.
    """

    mod = importlib.import_module("foghorn.plugins.docker-hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    containers = [
        {"Id": "c1", "Config": {"Hostname": ""}, "NetworkSettings": {}},
        {
            "Id": "c2",
            "Config": {"Hostname": "noip"},
            "NetworkSettings": {"Networks": {}},
        },
    ]

    def fake_iter(endpoint):  # noqa: ARG001
        return containers

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    caplog.set_level("WARNING", logger=mod.__name__)

    plugin.setup()

    # No usable mappings created.
    assert plugin._forward_v4 == {}  # type: ignore[attr-defined]
    assert plugin._forward_v6 == {}  # type: ignore[attr-defined]
    assert plugin._reverse == {}  # type: ignore[attr-defined]

    messages = [r.getMessage() for r in caplog.records]
    assert any("has no hostname" in m for m in messages)
    assert any("has no IPv4/IPv6" in m for m in messages)
    assert any("none had usable hostname/IP" in m for m in messages)


def test_docker_hosts_suffix_per_instance(monkeypatch):
    """Brief: Instance-level suffix appends to container names in mappings.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that forward and reverse mappings include the suffix and
        that unsuffixed names are not published.
    """

    mod = importlib.import_module("foghorn.plugins.docker-hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(  # type: ignore[arg-type]
        suffix="docker.mycorp",
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )

    containers = _make_example_containers()

    def fake_iter(endpoint):  # noqa: ARG001
        return containers

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    plugin.setup()

    # Forward mappings use suffixed names
    assert "web.docker.mycorp" in plugin._forward_v4  # type: ignore[attr-defined]
    assert "web" not in plugin._forward_v4  # type: ignore[attr-defined]

    # Reverse mapping points at suffixed name
    ptr_v4 = ipaddress.ip_address("172.17.0.5").reverse_pointer
    assert plugin._reverse[ptr_v4] == "web.docker.mycorp"  # type: ignore[attr-defined,index]


def test_docker_hosts_suffix_per_endpoint(monkeypatch):
    """Brief: Endpoint-level suffix overrides instance suffix for that endpoint.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that endpoint suffix is applied to mappings when set.
    """

    mod = importlib.import_module("foghorn.plugins.docker-hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(  # type: ignore[arg-type]
        suffix="default.suffix",
        endpoints=[
            {
                "url": "unix:///var/run/docker.sock",
                "suffix": "endpoint.suffix",
            }
        ],
    )

    containers = _make_example_containers()

    def fake_iter(endpoint):  # noqa: ARG001
        return containers

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    plugin.setup()

    # Forward mappings use the endpoint-level suffix
    assert "web.endpoint.suffix" in plugin._forward_v4  # type: ignore[attr-defined]
    assert "web.default.suffix" not in plugin._forward_v4  # type: ignore[attr-defined]

    # Reverse mapping points at the endpoint-level suffixed name
    ptr_v4 = ipaddress.ip_address("172.17.0.5").reverse_pointer
    assert plugin._reverse[ptr_v4] == "web.endpoint.suffix"  # type: ignore[attr-defined,index]


def test_docker_hosts_multiple_ips_in_answer(monkeypatch):
    """Brief: When multiple IPs are mapped for a name, all appear in the answer.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that pre_resolve returns multiple A records for a name
        with more than one IPv4 address.
    """

    mod = importlib.import_module("foghorn.plugins.docker-hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    containers = [
        {
            "Id": "c1",
            "Config": {"Hostname": "web"},
            "NetworkSettings": {
                "Networks": {
                    "bridge": {
                        "IPAddress": "172.17.0.5",
                    }
                }
            },
        },
        {
            "Id": "c2",
            "Config": {"Hostname": "web"},
            "NetworkSettings": {
                "Networks": {
                    "bridge": {
                        "IPAddress": "172.17.0.6",
                    }
                }
            },
        },
    ]

    def fake_iter(endpoint):  # noqa: ARG001
        return containers

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    q_a = DNSRecord.question("web", "A")
    dec_a = plugin.pre_resolve("web", QTYPE.A, q_a.pack(), ctx)
    assert dec_a is not None and dec_a.response is not None
    resp_a = DNSRecord.parse(dec_a.response)

    answers = sorted(str(rr.rdata) for rr in resp_a.rr)
    assert answers == ["172.17.0.5", "172.17.0.6"]
