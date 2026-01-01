"""
Brief: Tests for foghorn.plugins.docker_hosts DockerHosts plugin.

Inputs:
  - None

Outputs:
  - None
"""

import importlib
import ipaddress
import types

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

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    assert mod.__name__ == "foghorn.plugins.docker_hosts"


def test_docker_hosts_builds_mappings_from_inspect(monkeypatch):
    """Brief: DockerHosts.setup() builds forward and reverse maps from inspect.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts hostname and reverse mappings are populated.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
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

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
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

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
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

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
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

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
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

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
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

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
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

    # Only consider A records; responses may also include TXT metadata.
    answers = sorted(str(rr.rdata) for rr in resp_a.rr if rr.rtype == QTYPE.A)
    assert answers == ["172.17.0.5", "172.17.0.6"]


def test_docker_hosts_txt_for_a_and_aaaa_in_additional_section(monkeypatch):
    """Brief: TXT metadata for A/AAAA responses is placed in the ADDITIONAL section.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts TXT RRs for A/AAAA replies appear only in ADDITIONAL, not
        ANSWER.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    containers = _make_example_containers()

    def fake_iter(endpoint):  # noqa: ARG001
        return containers

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    plugin.setup()
    ctx = PluginContext(client_ip="127.0.0.1")

    # A query: TXT records should be in ADDITIONAL, not ANSWER.
    q_a = DNSRecord.question("web", "A")
    dec_a = plugin.pre_resolve("web", QTYPE.A, q_a.pack(), ctx)
    assert dec_a is not None and dec_a.response is not None
    resp_a = DNSRecord.parse(dec_a.response)
    assert all(rr.rtype != QTYPE.TXT for rr in resp_a.rr)
    assert any(rr.rtype == QTYPE.TXT for rr in resp_a.ar)

    # AAAA query: same behaviour for IPv6 answers.
    q_aaaa = DNSRecord.question("web", "AAAA")
    dec_aaaa = plugin.pre_resolve("web", QTYPE.AAAA, q_aaaa.pack(), ctx)
    assert dec_aaaa is not None and dec_aaaa.response is not None
    resp_aaaa = DNSRecord.parse(dec_aaaa.response)
    assert all(rr.rtype != QTYPE.TXT for rr in resp_aaaa.rr)
    assert any(rr.rtype == QTYPE.TXT for rr in resp_aaaa.ar)


def test_docker_hosts_get_config_model_returns_pydantic_model():
    """Brief: DockerHosts.get_config_model() returns DockerHostsConfig.

    Inputs:
      - None.

    Outputs:
      - None; asserts returned model class name.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    model = DockerHosts.get_config_model()
    assert model.__name__ == "DockerHostsConfig"


def test_docker_hosts_setup_normalizes_endpoints_and_falls_back_default(caplog):
    """Brief: setup() warns for invalid endpoint entries and adds default endpoint.

    Inputs:
      - caplog: pytest caplog fixture.

    Outputs:
      - None; asserts warning messages and that a default unix socket endpoint is used.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    # All endpoint entries are invalid -> triggers default endpoint insertion.
    plugin = DockerHosts(  # type: ignore[arg-type]
        endpoints=[
            "not-a-dict",
            {},
            {"url": "   "},
        ],
    )

    # Prevent background thread (interval computed from endpoints); and avoid Docker calls.
    caplog.set_level("WARNING", logger=mod.__name__)

    # setup() calls _reload_from_docker() which will no-op because docker client map is empty.
    plugin.setup()

    assert isinstance(plugin._endpoints, list)  # type: ignore[attr-defined]
    assert len(plugin._endpoints) == 1  # type: ignore[attr-defined]
    assert plugin._endpoints[0]["url"] == "unix:///var/run/docker.sock"  # type: ignore[attr-defined,index]

    messages = [r.getMessage() for r in caplog.records]
    assert any("ignoring non-mapping endpoint definition" in m for m in messages)
    assert any("endpoint missing 'url'" in m for m in messages)
    assert any("endpoint has empty 'url'" in m for m in messages)


def test_docker_hosts_setup_parses_endpoint_fields_and_logs_warnings(caplog):
    """Brief: setup() normalizes interval/ip/ttl fields and warns on invalid values.

    Inputs:
      - caplog: pytest caplog fixture.

    Outputs:
      - None; asserts that invalid intervals/IPs/TTLs are handled.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(  # type: ignore[arg-type]
        endpoints=[
            {
                "url": "unix:///var/run/docker.sock",
                "reload_interval_second": "not-a-float",
                "use_ipv4": "2001:db8::1",  # not IPv4
                "use_ipv6": "192.0.2.1",  # not IPv6
                "ttl": "not-an-int",
            },
            {
                "url": "tcp://127.0.0.1:2375",
                "reload_interval_second": -5,
                "use_ipv4": "bad-ip",
                "use_ipv6": "bad-ip",
                "ttl": -1,
            },
        ],
    )

    caplog.set_level("WARNING", logger=mod.__name__)
    plugin.setup()

    # Endpoint normalization.
    ep1 = plugin._endpoints[0]  # type: ignore[attr-defined,index]
    assert ep1["interval"] == 60.0
    assert ep1["host_ipv4"] is None
    assert ep1["host_ipv6"] is None
    assert ep1["ttl"] is None

    ep2 = plugin._endpoints[1]  # type: ignore[attr-defined,index]
    assert ep2["interval"] == 0.0
    assert ep2["host_ipv4"] is None
    assert ep2["host_ipv6"] is None
    assert ep2["ttl"] is None

    messages = [r.getMessage() for r in caplog.records]
    assert any("use_ipv4" in m and "not IPv4" in m for m in messages)
    assert any("use_ipv6" in m and "not IPv6" in m for m in messages)
    assert any("invalid use_ipv4" in m for m in messages)
    assert any("invalid use_ipv6" in m for m in messages)
    assert any("invalid ttl" in m for m in messages)


def test_docker_hosts_iter_containers_returns_empty_when_no_client(monkeypatch):
    """Brief: _iter_containers_for_endpoint returns [] when no client exists.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts empty iterable when the docker SDK is unavailable and no
        client can be created for the endpoint.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    # Simulate an environment without the docker SDK so that
    # _iter_containers_for_endpoint sees client is None *and* docker is None and
    # returns an empty list without ever talking to a real Docker daemon.
    monkeypatch.setattr(mod, "docker", None, raising=True)

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    # Avoid any docker-dependent reload behaviour in setup.
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)
    plugin.setup()

    # Ensure _clients is empty for this URL.
    plugin._clients = {}  # type: ignore[attr-defined]

    items = list(
        plugin._iter_containers_for_endpoint({"url": "unix:///var/run/docker.sock"})
    )
    assert items == []


def test_docker_hosts_iter_containers_logs_and_returns_empty_on_exception(caplog):
    """Brief: _iter_containers_for_endpoint swallows DockerException and returns [].

    Inputs:
      - caplog: pytest caplog fixture.

    Outputs:
      - None; asserts warning log and empty return.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    plugin.setup()

    class DummyDockerExc(Exception):
        pass

    class BadContainers:
        def list(self):  # noqa: D401
            """Always raise to exercise error path."""

            raise DummyDockerExc("boom")

    bad_client = types.SimpleNamespace(containers=BadContainers())

    # Replace the exception type and install the bad client.
    mod.DockerException = DummyDockerExc  # type: ignore[attr-defined]
    plugin._clients = {"unix:///var/run/docker.sock": bad_client}  # type: ignore[attr-defined]

    caplog.set_level("WARNING", logger=mod.__name__)
    items = list(
        plugin._iter_containers_for_endpoint({"url": "unix:///var/run/docker.sock"})
    )
    assert items == []

    assert any("failed to list containers" in r.getMessage() for r in caplog.records)


def test_docker_hosts_reload_from_docker_logs_when_no_containers(monkeypatch, caplog):
    """Brief: _reload_from_docker logs a warning when no endpoints yield containers.

    Inputs:
      - monkeypatch/caplog: pytest fixtures.

    Outputs:
      - None; asserts warning log and empty mappings.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")

    # Avoid talking to a real Docker daemon: force the module-level docker SDK
    # reference to None so setup() and _iter_containers_for_endpoint() never
    # attempt a real connection.
    monkeypatch.setattr(mod, "docker", None, raising=True)

    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    plugin.setup()

    def fake_iter(_endpoint):
        return []

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", fake_iter)

    caplog.set_level("WARNING", logger=mod.__name__)
    plugin._reload_from_docker()

    assert plugin._forward_v4 == {}  # type: ignore[attr-defined]
    assert plugin._forward_v6 == {}  # type: ignore[attr-defined]
    assert any(
        "no hostname/IP mappings were added" in r.getMessage() for r in caplog.records
    )


def test_docker_hosts_reload_from_docker_ttl_cast_fallback_and_invalid_reverse_ptr(
    monkeypatch, caplog
):
    """Brief: _reload_from_docker falls back TTL cast and logs invalid reverse pointers.

    Inputs:
      - monkeypatch/caplog: pytest fixtures.

    Outputs:
      - None; asserts warnings for invalid IP reverse pointers and that forward mappings still include the raw strings.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    plugin.setup()

    # Force an endpoint-level TTL override that will fail int() to hit fallback branch.
    plugin._ttl = 123  # type: ignore[attr-defined]
    plugin._endpoints = [
        {
            "url": "unix:///var/run/docker.sock",
            "interval": 0.0,
            "host_ipv4": None,
            "host_ipv6": None,
            "ttl": "not-int",
            "suffix": "",
        }
    ]  # type: ignore[attr-defined]

    containers = [
        {
            "Id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "Name": "/web",
            "Config": {"Hostname": "web"},
            "NetworkSettings": {
                "Networks": {
                    "bridge": {"IPAddress": "bad-ip", "GlobalIPv6Address": "bad-ipv6"}
                }
            },
        }
    ]

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: containers)

    caplog.set_level("WARNING", logger=mod.__name__)
    plugin._reload_from_docker()

    # Leading '/' stripped from Name in mapping key.
    assert "web" in plugin._forward_v4  # type: ignore[attr-defined]
    assert plugin._forward_v4["web"] == ["bad-ip"]  # type: ignore[attr-defined,index]
    assert plugin._forward_v6["web"] == ["bad-ipv6"]  # type: ignore[attr-defined,index]

    messages = [r.getMessage() for r in caplog.records]
    assert any("invalid IPv4 address" in m for m in messages)
    assert any("invalid IPv6 address" in m for m in messages)


def test_docker_hosts_pre_resolve_returns_none_when_not_targeted(monkeypatch):
    """Brief: pre_resolve returns None when ctx is not in targets.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts None decision.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    # Target only 192.0.2.0/24; ctx uses 127.0.0.1.
    plugin = DockerHosts(targets=["192.0.2.0/24"], endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    # Avoid docker calls.
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    q = DNSRecord.question("web", "A")
    assert plugin.pre_resolve("web", QTYPE.A, q.pack(), ctx) is None


def test_docker_hosts_pre_resolve_missing_mappings_and_parse_failure(
    monkeypatch, caplog
):
    """Brief: pre_resolve returns None when mappings missing; PTR parse failure yields override(None).

    Inputs:
      - monkeypatch/caplog: pytest fixtures.

    Outputs:
      - None; asserts None for missing mappings and override decision with None response on parse failure.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # No mappings -> A/AAAA/PTR should return None.
    q_a = DNSRecord.question("missing", "A")
    assert plugin.pre_resolve("missing", QTYPE.A, q_a.pack(), ctx) is None

    q_aaaa = DNSRecord.question("missing", "AAAA")
    assert plugin.pre_resolve("missing", QTYPE.AAAA, q_aaaa.pack(), ctx) is None

    # PTR parse failure path: create a reverse mapping but provide invalid wire bytes.
    with plugin._lock:  # type: ignore[attr-defined]
        plugin._reverse["1.0.0.127.in-addr.arpa"] = "web"  # type: ignore[attr-defined,index]

    caplog.set_level("WARNING", logger=mod.__name__)
    dec = plugin.pre_resolve(
        "1.0.0.127.in-addr.arpa",
        QTYPE.PTR,
        b"not-a-dns-packet",
        ctx,
    )
    assert dec is not None
    assert dec.action == "override"
    assert dec.response is None
    assert any("parse failure for PTR" in r.getMessage() for r in caplog.records)


def test_docker_hosts_make_ip_response_returns_none_on_parse_failure(
    monkeypatch, caplog
):
    """Brief: _make_ip_response returns None when DNSRecord.parse fails.

    Inputs:
      - monkeypatch/caplog: pytest fixtures.

    Outputs:
      - None; asserts return None and warning log.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)
    plugin.setup()

    caplog.set_level("WARNING", logger=mod.__name__)
    assert plugin._make_ip_response("web", QTYPE.A, b"bad", ["192.0.2.1"], 60) is None
    assert any(
        "parse failure building response" in r.getMessage() for r in caplog.records
    )


def test_docker_hosts_setup_logs_when_docker_sdk_missing(monkeypatch, caplog):
    """Brief: setup() logs a warning when docker SDK is unavailable.

    Inputs:
      - monkeypatch/caplog: pytest fixtures.

    Outputs:
      - None; asserts missing-SDK warning is logged.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    monkeypatch.setattr(mod, "docker", None, raising=True)

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    # Avoid docker-dependent reload.
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)

    caplog.set_level("WARNING", logger=mod.__name__)
    plugin.setup()
    assert any("docker SDK is not installed" in r.getMessage() for r in caplog.records)


def test_docker_hosts_setup_handles_docker_client_creation_failure(monkeypatch, caplog):
    """Brief: setup() logs warning and skips endpoint when DockerClient init fails.

    Inputs:
      - monkeypatch/caplog: pytest fixtures.

    Outputs:
      - None; asserts warning about Docker client creation failure.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    class DummyDockerExc(Exception):
        pass

    class FakeDockerModule:
        def DockerClient(self, base_url: str):  # noqa: N802
            raise DummyDockerExc(f"cannot connect to {base_url}")

    monkeypatch.setattr(mod, "docker", FakeDockerModule(), raising=True)
    monkeypatch.setattr(mod, "DockerException", DummyDockerExc, raising=True)

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    # Avoid reload using docker state.
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)

    caplog.set_level("WARNING", logger=mod.__name__)
    plugin.setup()

    assert any("failed to create client" in r.getMessage() for r in caplog.records)


def test_docker_hosts_reload_loop_executes_reload_once(monkeypatch):
    """Brief: _reload_loop sleeps then calls _reload_from_docker in a loop.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts _reload_from_docker called at least once.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    # Keep setup() minimal.
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)
    plugin.setup()

    calls = {"reload": 0, "sleep": 0}

    def fake_reload() -> None:
        calls["reload"] += 1

    def fake_sleep(_seconds: float) -> None:
        calls["sleep"] += 1
        # Allow first sleep, then escape loop on the next iteration.
        if calls["sleep"] >= 2:
            raise KeyboardInterrupt

    plugin._reload_interval = 0.0001  # type: ignore[attr-defined]
    monkeypatch.setattr(plugin, "_reload_from_docker", fake_reload)

    import time

    monkeypatch.setattr(time, "sleep", fake_sleep)

    try:
        plugin._reload_loop()
    except KeyboardInterrupt:
        pass

    assert calls["reload"] == 1
    assert calls["sleep"] >= 2


def test_docker_hosts_health_filter_default_skips_unhealthy(monkeypatch):
    """Brief: Default health allowlist excludes containers marked unhealthy.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts unhealthy containers are skipped by default.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    containers = [
        {
            "Id": "c1",
            "Config": {"Hostname": "healthy"},
            "State": {"Status": "running", "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.5"}}},
        },
        {
            "Id": "c2",
            "Config": {"Hostname": "unhealthy"},
            "State": {"Status": "running", "Health": {"Status": "unhealthy"}},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.6"}}},
        },
        {
            "Id": "c3",
            "Config": {"Hostname": "nohealth"},
            # No State.Health -> treated as running.
            "State": {"Status": "running"},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.7"}}},
        },
    ]

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: containers)
    plugin.setup()

    assert "healthy" in plugin._forward_v4  # type: ignore[attr-defined]
    assert "nohealth" in plugin._forward_v4  # type: ignore[attr-defined]
    assert "unhealthy" not in plugin._forward_v4  # type: ignore[attr-defined]


def test_docker_hosts_health_filter_can_include_unhealthy(monkeypatch):
    """Brief: health config can allow unhealthy containers.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts unhealthy containers are included when configured.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(  # type: ignore[arg-type]
        health=["unhealthy"],
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )

    containers = [
        {
            "Id": "c2",
            "Config": {"Hostname": "unhealthy"},
            "State": {"Status": "running", "Health": {"Status": "unhealthy"}},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.6"}}},
        },
        {
            "Id": "c3",
            "Config": {"Hostname": "nohealth"},
            "State": {"Status": "running"},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.7"}}},
        },
    ]

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: containers)
    plugin.setup()

    assert "unhealthy" in plugin._forward_v4  # type: ignore[attr-defined]
    assert "nohealth" not in plugin._forward_v4  # type: ignore[attr-defined]


def test_docker_hosts_unreachable_endpoint_omits_hosts_txt(monkeypatch, caplog):
    """Brief: Endpoints that raise DockerException do not emit _hosts.* TXT, and are retried.

    Inputs:
      - monkeypatch/caplog: pytest fixtures.

    Outputs:
      - None; asserts that _hosts.<suffix> TXT is not created when an endpoint
        repeatedly fails with a DockerException, while still logging the
        connection failure.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    # Use discovery so that _hosts.<suffix> TXT would normally be published.
    plugin = DockerHosts(  # type: ignore[arg-type]
        suffix="docker.mycorp",
        discovery=True,
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )

    # Force _iter_containers_for_endpoint to simulate an unreachable endpoint
    # by returning an empty iterable every time.
    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: [])

    caplog.set_level("WARNING", logger=mod.__name__)
    plugin.setup()

    # After setup + reload, no _hosts.* TXT records should exist because the
    # endpoint never yielded any containers.
    assert plugin._aggregate_txt == {}  # type: ignore[attr-defined]

    # Now simulate a DockerException path inside _iter_containers_for_endpoint by
    # using a dummy client whose containers.list() always raises.
    class DummyDockerExc(Exception):
        pass

    class BadContainers:
        def list(self):  # noqa: D401
            """Always raise to exercise the DockerException path."""

            raise DummyDockerExc("boom")

    bad_client = types.SimpleNamespace(containers=BadContainers())

    monkeypatch.setattr(mod, "DockerException", DummyDockerExc, raising=True)
    plugin._clients = {"unix:///var/run/docker.sock": bad_client}  # type: ignore[attr-defined]

    # Trigger another reload; even when the endpoint client raises an error,
    # we should still avoid publishing any _hosts.* TXT owners for it.
    plugin._reload_from_docker()

    assert plugin._aggregate_txt == {}  # type: ignore[attr-defined]


def test_docker_hosts_discovery_publishes_txt(monkeypatch):
    """Brief: discovery publishes a _docker.<suffix> TXT record.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts a TXT query is answered, has expected ordering, and does not
        include full container IDs in TXT text.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(  # type: ignore[arg-type]
        suffix="docker.mycorp",
        discovery=True,
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )

    full_id = "deadbeef" * 8  # 64 hex chars
    short_id = full_id[:12]

    containers = [
        {
            "Id": full_id,
            "Name": "/web",
            "Config": {
                "Hostname": "web",
                "Image": "nginx:latest",
                "Labels": {
                    "com.docker.compose.service": "web",
                    "com.docker.compose.project": "myproj",
                },
            },
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
                "Ports": {
                    "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
                    "443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8443"}],
                },
            },
        }
    ]

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: containers)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    owner = "_containers.docker.mycorp"
    q_txt = DNSRecord.question(owner, "TXT")
    dec = plugin.pre_resolve(owner, QTYPE.TXT, q_txt.pack(), ctx)
    assert dec is not None and dec.response is not None

    resp = DNSRecord.parse(dec.response)
    txt_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]
    assert len(txt_rrs) >= 2  # header + at least one container

    # Find the container line (skip header)
    container_txt = None
    for rr in txt_rrs:
        s = str(rr.rdata)
        if "name=" in s and "endpoint=" in s:
            container_txt = s
            break
    assert container_txt is not None

    # Ordering: name first, endpoint last; metadata fields appear in between.
    assert container_txt.find("name=") != -1
    assert container_txt.find("endpoint=") != -1
    assert container_txt.find("name=") < container_txt.find("endpoint=")

    assert "name=web" in container_txt
    assert f"id={short_id}" in container_txt
    assert "int4=172.17.0.5" in container_txt
    assert "nets=bridge:172.17.0.5" in container_txt
    assert "endpoint=unix:///var/run/docker.sock" in container_txt
    assert "health=running" in container_txt
    assert "project-name=myproj" in container_txt
    # Host listening ports should be included in the TXT summary.
    assert "ports=8080,8443" in container_txt

    # Full container ID should not appear in aggregate TXT.
    assert full_id not in container_txt


def test_docker_hosts_uses_exposed_ports_when_no_host_bindings(monkeypatch):
    """Brief: When no host bindings exist, ports come from Config.ExposedPorts.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that exposed container ports are reflected in the TXT
        "ports=" field when NetworkSettings.Ports has no host bindings.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(  # type: ignore[arg-type]
        suffix="docker.mycorp",
        discovery=True,
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )

    full_id = "deadbeef" * 8

    containers = [
        {
            "Id": full_id,
            "Name": "/web",
            "Config": {
                "Hostname": "web",
                "Image": "nginx:latest",
                "ExposedPorts": {
                    "80/tcp": {},
                    "443/tcp": {},
                },
            },
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
                # No host Port bindings -> exercise ExposedPorts fallback.
                "Ports": {},
            },
        }
    ]

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: containers)
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    owner = "_containers.docker.mycorp"
    q_txt = DNSRecord.question(owner, "TXT")
    dec = plugin.pre_resolve(owner, QTYPE.TXT, q_txt.pack(), ctx)
    assert dec is not None and dec.response is not None

    resp = DNSRecord.parse(dec.response)
    txt_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]
    assert len(txt_rrs) >= 2

    container_txt = None
    for rr in txt_rrs:
        s = str(rr.rdata)
        if "name=" in s and "ports=" in s:
            container_txt = s
            break
    assert container_txt is not None
    # Exposed ports should be visible as container ports when no host bindings exist.
    # Ports that originate only from Config.ExposedPorts are prefixed with "E:".
    assert "ports=E:80" in container_txt
    assert "E:443" in container_txt


def test_docker_hosts_txt_fields_append_and_replace(monkeypatch):
    """Brief: txt_fields appends extra key/value pairs or replaces defaults.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that txt_fields values are appended in default mode and
        replace the built-in summary when txt_fields_replace is true.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    # Shared container used for both append and replace variants.
    base_container = {
        "Id": "deadbeef" * 8,
        "Name": "/web",
        "Config": {
            "Hostname": "web",
            "Image": "nginx:latest",
            "Labels": {
                "com.docker.compose.service": "web",
                "com.docker.compose.project": "myproj",
            },
        },
        "State": {"Status": "running"},
        "NetworkSettings": {
            "Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
        },
    }

    # Append mode: custom fields should appear alongside built-in summary keys.
    plugin_append = DockerHosts(  # type: ignore[arg-type]
        suffix="docker.mycorp",
        discovery=True,
        txt_fields=[
            {"name": "image", "path": "Config.Image"},
            {
                "name": "svc",
                "path": "Config.Hostname",
            },
        ],
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )
    monkeypatch.setattr(
        plugin_append, "_iter_containers_for_endpoint", lambda _ep: [base_container]
    )
    plugin_append.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    owner = "_containers.docker.mycorp"
    q_txt = DNSRecord.question(owner, "TXT")
    dec = plugin_append.pre_resolve(owner, QTYPE.TXT, q_txt.pack(), ctx)
    assert dec is not None and dec.response is not None
    resp = DNSRecord.parse(dec.response)
    txt_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]

    container_txt = None
    for rr in txt_rrs:
        s = str(rr.rdata)
        if "name=" in s and "image=" in s:
            container_txt = s
            break
    assert container_txt is not None
    assert "name=web" in container_txt
    assert "image=nginx:latest" in container_txt
    assert "svc=web" in container_txt

    # Replace mode: when txt_fields_replace is true, only custom fields should
    # be present (aside from the header line inserted separately).
    plugin_replace = DockerHosts(  # type: ignore[arg-type]
        suffix="docker.mycorp",
        discovery=True,
        txt_fields=[{"name": "image", "path": "Config.Image"}],
        txt_fields_replace=True,
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )
    monkeypatch.setattr(
        plugin_replace, "_iter_containers_for_endpoint", lambda _ep: [base_container]
    )
    plugin_replace.setup()

    dec2 = plugin_replace.pre_resolve(owner, QTYPE.TXT, q_txt.pack(), ctx)
    assert dec2 is not None and dec2.response is not None
    resp2 = DNSRecord.parse(dec2.response)
    txt_rrs2 = [rr for rr in resp2.rr if rr.rtype == QTYPE.TXT]

    container_txt2 = None
    for rr in txt_rrs2:
        s = str(rr.rdata)
        # Skip the containers=<n> header line which has no '='-separated keys
        # other than the initial count.
        if s.startswith('"containers='):
            continue
        if "image=" in s:
            container_txt2 = s
            break
    assert container_txt2 is not None
    assert "image=nginx:latest" in container_txt2
    # Built-in keys should be absent when in replace mode.
    assert "name=" not in container_txt2
    assert "ans4=" not in container_txt2
    assert "health=" not in container_txt2
    assert "project-name=" not in container_txt2


def test_docker_hosts_txt_fields_keep_preserves_selected_builtins(monkeypatch):
    """Brief: txt_fields_keep preserves specific built-in TXT keys in replace mode.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that when txt_fields_replace is true, configured keys such
        as "ans4" and "endpoint" are still present alongside custom fields.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    base_container = {
        "Id": "deadbeef" * 8,
        "Name": "/web",
        "Config": {
            "Hostname": "web",
            "Image": "nginx:latest",
            "Labels": {
                "com.docker.compose.service": "web",
                "com.docker.compose.project": "myproj",
            },
        },
        "State": {"Status": "running"},
        "NetworkSettings": {
            "Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
        },
    }

    plugin_keep = DockerHosts(  # type: ignore[arg-type]
        suffix="docker.mycorp",
        discovery=True,
        txt_fields=[{"name": "image", "path": "Config.Image"}],
        txt_fields_replace=True,
        txt_fields_keep=["ans4", "endpoint"],
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )
    monkeypatch.setattr(
        plugin_keep, "_iter_containers_for_endpoint", lambda _ep: [base_container]
    )
    plugin_keep.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    owner = "_containers.docker.mycorp"
    q_txt = DNSRecord.question(owner, "TXT")
    dec = plugin_keep.pre_resolve(owner, QTYPE.TXT, q_txt.pack(), ctx)
    assert dec is not None and dec.response is not None
    resp = DNSRecord.parse(dec.response)
    txt_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]

    container_txt = None
    for rr in txt_rrs:
        s = str(rr.rdata)
        if s.startswith('"containers='):
            continue
        if "image=" in s:
            container_txt = s
            break
    assert container_txt is not None

    # Custom field still present.
    assert "image=nginx:latest" in container_txt
    # Selected built-in keys should be preserved when they exist for the container.
    assert "ans4=172.17.0.5" in container_txt
    assert "endpoint=unix:///var/run/docker.sock" in container_txt


def test_docker_hosts_txt_fields_label_with_dots(monkeypatch):
    """Brief: txt_fields can read Config.Labels keys that contain dots.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that a dotted label key is resolved via
        Config.Labels.<key-with-dots>.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    base_container = {
        "Id": "c1",
        "Name": "/git",
        "Config": {
            "Hostname": "git",
            "Labels": {
                "com.docker.compose.project": "gitea",
            },
        },
        "State": {"Status": "running"},
        "NetworkSettings": {
            "Networks": {"gitea_default": {"IPAddress": "172.19.0.2"}},
        },
    }

    plugin = DockerHosts(  # type: ignore[arg-type]
        suffix="docker.mycorp",
        discovery=True,
        txt_fields=[
            {
                "name": "project",
                "path": "Config.Labels.com.docker.compose.project",
            }
        ],
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )
    monkeypatch.setattr(
        plugin, "_iter_containers_for_endpoint", lambda _ep: [base_container]
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    owner = "_containers.docker.mycorp"
    q_txt = DNSRecord.question(owner, "TXT")
    dec = plugin.pre_resolve(owner, QTYPE.TXT, q_txt.pack(), ctx)
    assert dec is not None and dec.response is not None
    resp = DNSRecord.parse(dec.response)
    txt_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]

    container_txt = None
    for rr in txt_rrs:
        s = str(rr.rdata)
        if "project=" in s:
            container_txt = s
            break
    assert container_txt is not None
    assert "project=gitea" in container_txt


def test_docker_hosts_http_snapshot_counts_unique_human_names(monkeypatch):
    """Brief: get_http_snapshot summary counts human-readable names once.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that total_containers reflects unique non-hash names, not
        hash-like aliases.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    # Two containers with human-friendly names plus hash-like ID aliases.
    containers = [
        {
            "Id": "deadbeef" * 8,  # 64 hex chars -> full container ID
            "Name": "/web",
            "Config": {"Hostname": "web"},
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Networks": {"bridge": {"IPAddress": "172.17.0.5"}},
            },
        },
        {
            "Id": "cafebabe" * 8,
            "Name": "/db",
            "Config": {"Hostname": "db"},
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Networks": {"bridge": {"IPAddress": "172.17.0.6"}},
            },
        },
    ]

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: containers)
    plugin.setup()

    snapshot = plugin.get_http_snapshot()
    summary = snapshot["summary"]
    rows = snapshot["containers"]

    # Sanity: the table should include both human names and hash-like aliases.
    names = {str(row["name"]) for row in rows}
    assert "web" in names
    assert "db" in names
    # At least one alias should look hash-like (12+ hex characters).
    assert any(
        len(n) >= 12 and all(c in "0123456789abcdef" for c in n.lower()) for n in names
    )

    # total_containers should count only the distinct human-readable names.
    assert summary["total_containers"] == 2
    # And it should be less than the number of rows when aliases exist.
    assert summary["total_containers"] < len(rows)


def test_docker_hosts_project_name_publishes_a_record(monkeypatch):
    """Brief: DockerHosts keeps project name as metadata, not a separate label.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts project name becomes a forward-mapped alias.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    containers = [
        {
            "Id": "c1",
            "Name": "/web",
            "Config": {
                "Hostname": "web",
                "Image": "nginx:latest",
                "Labels": {"com.docker.compose.project": "myproj"},
            },
            "State": {"Status": "running"},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.5"}}},
        }
    ]

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: containers)
    plugin.setup()

    assert "web" in plugin._forward_v4  # type: ignore[attr-defined]
    # Project name is now used only in TXT/Info metadata and should not publish
    # a separate DNS label.
    assert "myproj" not in plugin._forward_v4  # type: ignore[attr-defined]


def test_docker_hosts_project_name_not_added_when_same_as_image(monkeypatch):
    """Brief: Project name is not added when it matches the container image.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts project name alias is omitted for image-equal project names.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]

    containers = [
        {
            "Id": "c1",
            "Name": "/web",
            "Config": {
                "Hostname": "web",
                "Image": "nginx:latest",
                "Labels": {"com.docker.compose.project": "nginx"},
            },
            "State": {"Status": "running"},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.5"}}},
        }
    ]

    monkeypatch.setattr(plugin, "_iter_containers_for_endpoint", lambda _ep: containers)
    plugin.setup()

    assert "web" in plugin._forward_v4  # type: ignore[attr-defined]
    assert "nginx" not in plugin._forward_v4  # type: ignore[attr-defined]


def test_docker_hosts_admin_pages_and_ui_descriptor_shape():
    """Brief: get_admin_pages and get_admin_ui_descriptor describe Docker UI.

    Inputs:
      - None.

    Outputs:
      - None; asserts slug/title and snapshot endpoint/layout shape.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    # Avoid contacting Docker during setup.
    plugin._reload_from_docker = lambda: None  # type: ignore[assignment]
    plugin.setup()

    pages = plugin.get_admin_pages()
    assert len(pages) == 1
    page = pages[0]
    assert page.slug == "docker-hosts"
    assert page.title == "Docker"

    desc = plugin.get_admin_ui_descriptor()
    assert desc["name"] == str(getattr(plugin, "name", "docker"))
    assert isinstance(desc["title"], str)
    endpoints = desc["endpoints"]
    assert isinstance(endpoints, dict)
    assert "snapshot" in endpoints
    layout = desc["layout"]
    assert isinstance(layout, dict)
    sections = layout.get("sections")
    assert isinstance(sections, list) and sections
    assert any(s.get("id") == "summary" for s in sections)
    assert any(s.get("id") == "containers" for s in sections)


def test_docker_hosts_owner_helpers_normalize_suffixes():
    """Brief: _aggregate_owner_for_suffix and _hosts_owner_for_suffix normalize suffixes.

    Inputs:
      - None.

    Outputs:
      - None; asserts various suffix forms map to expected owner names.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")

    agg = mod.DockerHosts._aggregate_owner_for_suffix  # type: ignore[attr-defined]
    hosts = mod.DockerHosts._hosts_owner_for_suffix  # type: ignore[attr-defined]

    assert agg("") == "_containers"
    assert agg(" docker.mycorp ") == "_containers.docker.mycorp"
    assert agg(".docker..mycorp.") == "_containers.docker.mycorp"

    assert hosts("") == "_hosts"
    assert hosts(" docker.mycorp ") == "_hosts.docker.mycorp"
    assert hosts(".docker..mycorp.") == "_hosts.docker.mycorp"


def test_docker_hosts_make_ip_response_success_a_and_aaaa(monkeypatch):
    """Brief: _make_ip_response builds A/AAAA answers for valid DNS queries.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that responses contain the expected RR types and TTLs.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)
    plugin.setup()

    # Build a valid A query and have _make_ip_response add a single A RR.
    q_a = DNSRecord.question("web", "A")
    resp_bytes = plugin._make_ip_response("web", QTYPE.A, q_a.pack(), ["192.0.2.1"], 42)
    assert resp_bytes is not None
    resp = DNSRecord.parse(resp_bytes)
    a_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.A]
    assert len(a_rrs) == 1
    assert str(a_rrs[0].rdata) == "192.0.2.1"
    assert a_rrs[0].ttl == 42

    # AAAA variant.
    q_aaaa = DNSRecord.question("web", "AAAA")
    resp_bytes_v6 = plugin._make_ip_response(
        "web", QTYPE.AAAA, q_aaaa.pack(), ["2001:db8::1"], 99
    )
    assert resp_bytes_v6 is not None
    resp_v6 = DNSRecord.parse(resp_bytes_v6)
    aaaa_rrs = [rr for rr in resp_v6.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa_rrs) == 1
    assert str(aaaa_rrs[0].rdata) == "2001:db8::1"
    assert aaaa_rrs[0].ttl == 99

    # Empty addrs returns a response with header/question only.
    resp_bytes_empty = plugin._make_ip_response("web", QTYPE.A, q_a.pack(), [], 60)
    assert resp_bytes_empty is not None
    resp_empty = DNSRecord.parse(resp_bytes_empty)
    assert resp_empty.rr == []


def test_docker_hosts_reload_loop_returns_immediately_when_interval_non_positive(
    monkeypatch,
):
    """Brief: _reload_loop returns immediately when _reload_interval <= 0.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts that no reloads occur when interval is non-positive.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(endpoints=[{"url": "unix:///var/run/docker.sock"}])  # type: ignore[arg-type]
    monkeypatch.setattr(plugin, "_reload_from_docker", lambda: None)
    plugin.setup()

    # Force interval to zero so _reload_loop should hit the early return path.
    plugin._reload_interval = 0.0  # type: ignore[attr-defined]

    calls = {"reload": 0}

    def fake_reload() -> None:
        calls["reload"] += 1

    plugin._reload_from_docker = fake_reload  # type: ignore[assignment]

    # No need to monkeypatch time.sleep because the function should return
    # before entering the loop when interval <= 0.
    plugin._reload_loop()
    assert calls["reload"] == 0


def test_docker_hosts_invalid_txt_fields_and_keep_types_log_warnings(caplog):
    """Brief: setup() logs warnings for invalid txt_fields and txt_fields_keep types.

    Inputs:
      - caplog: pytest caplog fixture.

    Outputs:
      - None; asserts that non-list txt_fields and txt_fields_keep produce warnings.
    """

    mod = importlib.import_module("foghorn.plugins.docker_hosts")
    DockerHosts = mod.DockerHosts

    plugin = DockerHosts(  # type: ignore[arg-type]
        txt_fields="not-a-list",
        txt_fields_keep="also-not-a-list",
        endpoints=[{"url": "unix:///var/run/docker.sock"}],
    )

    # Avoid docker-dependent reload.
    plugin._reload_from_docker = lambda: None  # type: ignore[assignment]

    caplog.set_level("WARNING", logger=mod.__name__)
    plugin.setup()

    messages = [r.getMessage() for r in caplog.records]
    assert any("txt_fields must be a list" in m for m in messages)
    assert any("txt_fields_keep must be a list" in m for m in messages)
