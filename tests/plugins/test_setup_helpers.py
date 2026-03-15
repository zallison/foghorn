from __future__ import annotations

import logging
import socket
import sys
import types
from types import SimpleNamespace
from typing import Any, List

import pytest
from dnslib import AAAA, QTYPE, RR, A, DNSRecord

import foghorn.plugins.setup as setup_mod
from foghorn.plugins.resolve.base import BasePlugin


class _Decision:
    """Brief: Minimal decision object used to mock plugin pre_resolve results."""

    def __init__(self, action: str, response: bytes | None = None) -> None:
        self.action = action
        self.response = response


def _make_override_wire(name: str, qtype: int, value: str) -> bytes:
    """Brief: Build a packed DNS override response with one A/AAAA answer.

    Inputs:
      - name: Query owner name.
      - qtype: QTYPE.A or QTYPE.AAAA.
      - value: IP address text for the answer.

    Outputs:
      - Packed DNS response bytes.
    """

    qname_type = "A" if int(qtype) == int(QTYPE.A) else "AAAA"
    req = DNSRecord.question(name, qname_type)
    reply = req.reply()
    if int(qtype) == int(QTYPE.A):
        reply.add_answer(RR(name, QTYPE.A, rdata=A(value), ttl=60))
    else:
        reply.add_answer(RR(name, QTYPE.AAAA, rdata=AAAA(value), ttl=60))
    return reply.pack()


def test_setup_helper_defaults_and_parse_paths() -> None:
    """Brief: Setup helper parsers handle defaults, malformed values, and coercions.

    Inputs:
      - BasePlugin subclasses/instances with varied config and priorities.

    Outputs:
      - None; asserts helper return values across edge cases.
    """

    class Plain(BasePlugin):
        pass

    class WithSetup(BasePlugin):
        def setup(self) -> None:  # type: ignore[override]
            return None

    class _BadInt:
        def __int__(self) -> int:
            raise ValueError("bad int")

    plain = Plain()
    with_setup = WithSetup()

    assert setup_mod._is_setup_plugin(plain) is False
    assert setup_mod._is_setup_plugin(with_setup) is True
    assert setup_mod._is_setup_plugin(object()) is False

    assert setup_mod._setup_priority_for(plain) == 100
    plain.setup_priority = _BadInt()  # type: ignore[assignment]
    assert setup_mod._setup_priority_for(plain) == 100

    assert setup_mod._setup_abort_on_failure(plain) is True
    no_abort = Plain(abort_on_failure=False)
    assert setup_mod._setup_abort_on_failure(no_abort) is False

    assert setup_mod._setup_dns_fallback_to_system(plain) is True
    assert (
        setup_mod._setup_dns_fallback_to_system(
            Plain(setup_dns_fallback_to_system=False)
        )
        is False
    )
    assert (
        setup_mod._setup_dns_fallback_to_system(Plain(setup_dns_fallback_to_system=0))
        is False
    )
    assert (
        setup_mod._setup_dns_fallback_to_system(Plain(setup_dns_fallback_to_system=2))
        is True
    )
    assert (
        setup_mod._setup_dns_fallback_to_system(
            Plain(setup_dns_fallback_to_system="off")
        )
        is False
    )
    assert (
        setup_mod._setup_dns_fallback_to_system(
            Plain(setup_dns_fallback_to_system="on")
        )
        is True
    )
    assert (
        setup_mod._setup_dns_fallback_to_system(
            Plain(setup_dns_fallback_to_system="unexpected")
        )
        is True
    )


def test_extract_rr_addresses_handles_parse_and_filter_cases(monkeypatch) -> None:
    """Brief: _extract_rr_addresses filters by type/version and handles invalid records.

    Inputs:
      - Monkeypatched DNSRecord.parse to produce synthetic RR objects.

    Outputs:
      - None; asserts only valid addresses for the requested qtype are returned.
    """

    assert setup_mod._extract_rr_addresses(b"not-wire", int(QTYPE.A)) == []

    fake_msg = SimpleNamespace(
        rr=[
            SimpleNamespace(rtype=int(QTYPE.TXT), rdata="skip-mismatch"),
            SimpleNamespace(rtype=int(QTYPE.A), rdata=""),
            SimpleNamespace(rtype=int(QTYPE.A), rdata="not-an-ip"),
            SimpleNamespace(rtype=int(QTYPE.A), rdata="2001:db8::1"),
            SimpleNamespace(rtype=int(QTYPE.A), rdata="1.2.3.4"),
            SimpleNamespace(rtype=int(QTYPE.AAAA), rdata="127.0.0.1"),
            SimpleNamespace(rtype=int(QTYPE.AAAA), rdata="2001:db8::10"),
        ]
    )
    monkeypatch.setattr(setup_mod.DNSRecord, "parse", lambda _wire: fake_msg)

    assert setup_mod._extract_rr_addresses(b"x", int(QTYPE.A)) == ["1.2.3.4"]
    assert setup_mod._extract_rr_addresses(b"x", int(QTYPE.AAAA)) == ["2001:db8::10"]


def test_resolve_with_providers_filters_and_dedupes(monkeypatch) -> None:
    """Brief: Provider resolver path handles exceptions/invalid decisions and dedupes results.

    Inputs:
      - Setup DNS context with providers that emit varied decisions.

    Outputs:
      - None; asserts filtering and deduplication behavior.
    """

    class _ProviderRaises:
        def pre_resolve(self, *_args: Any, **_kwargs: Any) -> _Decision:
            raise RuntimeError("provider failure")

    class _ProviderNone:
        def pre_resolve(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    class _ProviderNonOverride:
        def pre_resolve(self, *_args: Any, **_kwargs: Any) -> _Decision:
            return _Decision("allow")

    class _ProviderNonBytes:
        def pre_resolve(self, *_args: Any, **_kwargs: Any) -> _Decision:
            return _Decision("override", response=None)

    wire = _make_override_wire("example.test", int(QTYPE.A), "1.2.3.4")

    class _ProviderGood:
        def pre_resolve(self, *_args: Any, **_kwargs: Any) -> _Decision:
            return _Decision("override", response=wire)

    ctx = setup_mod._SetupDNSResolverContext(
        providers=[
            _ProviderRaises(),  # type: ignore[list-item]
            _ProviderNone(),  # type: ignore[list-item]
            _ProviderNonOverride(),  # type: ignore[list-item]
            _ProviderNonBytes(),  # type: ignore[list-item]
            _ProviderGood(),  # type: ignore[list-item]
            _ProviderGood(),  # type: ignore[list-item]
        ],
        upstreams=[],
        timeout_ms=1000,
        resolver_mode="forward",
        upstream_max_concurrent=1,
        fallback_to_system=True,
        logger_obj=logging.getLogger("tests.setup"),
    )

    assert ctx._resolve_with_providers("example.test", socket.AF_UNIX) == []
    assert ctx._resolve_with_providers("", socket.AF_INET) == []
    assert ctx._resolve_with_providers("example.test", socket.AF_INET) == ["1.2.3.4"]

    monkeypatch.setattr(
        setup_mod.DNSRecord,
        "question",
        lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("bad question")),
    )
    assert ctx._resolve_with_providers("example.test", socket.AF_INET) == []


def test_resolve_with_upstreams_import_and_runtime_paths(monkeypatch) -> None:
    """Brief: Upstream resolver path covers mode/family/host guards and error fallbacks.

    Inputs:
      - Monkeypatches for DNSRecord.question, module import, and failover sender.

    Outputs:
      - None; asserts the helper returns [] on guarded/error paths and addresses on success.
    """

    logger = logging.getLogger("tests.setup")

    recursive_ctx = setup_mod._SetupDNSResolverContext(
        providers=[],
        upstreams=[{"host": "1.1.1.1", "port": 53}],
        timeout_ms=1000,
        resolver_mode="recursive",
        upstream_max_concurrent=1,
        fallback_to_system=True,
        logger_obj=logger,
    )
    assert recursive_ctx._resolve_with_upstreams("example.test", socket.AF_INET) == []

    no_upstream_ctx = setup_mod._SetupDNSResolverContext(
        providers=[],
        upstreams=[],
        timeout_ms=1000,
        resolver_mode="forward",
        upstream_max_concurrent=1,
        fallback_to_system=True,
        logger_obj=logger,
    )
    assert no_upstream_ctx._resolve_with_upstreams("example.test", socket.AF_INET) == []
    assert no_upstream_ctx._resolve_with_upstreams("example.test", socket.AF_UNIX) == []
    assert no_upstream_ctx._resolve_with_upstreams("", socket.AF_INET) == []

    ctx = setup_mod._SetupDNSResolverContext(
        providers=[],
        upstreams=[{"host": "1.1.1.1", "port": 53}],
        timeout_ms=1000,
        resolver_mode="forward",
        upstream_max_concurrent=2,
        fallback_to_system=True,
        logger_obj=logger,
    )
    assert ctx._resolve_with_upstreams("example.test", socket.AF_UNIX) == []
    assert ctx._resolve_with_upstreams("  . ", socket.AF_INET) == []

    original_question = setup_mod.DNSRecord.question
    monkeypatch.setattr(
        setup_mod.DNSRecord,
        "question",
        lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("bad question")),
    )
    assert ctx._resolve_with_upstreams("bad host", socket.AF_INET) == []

    monkeypatch.setattr(setup_mod.DNSRecord, "question", original_question)

    missing_sender_module = types.ModuleType("foghorn.servers.server")
    monkeypatch.setitem(sys.modules, "foghorn.servers.server", missing_sender_module)
    assert ctx._resolve_with_upstreams("example.test", socket.AF_INET) == []

    module_raises = types.ModuleType("foghorn.servers.server")

    def _raise_sender(*_args: Any, **_kwargs: Any) -> tuple[None, None, None]:
        raise RuntimeError("sender failed")

    module_raises.send_query_with_failover = _raise_sender  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "foghorn.servers.server", module_raises)
    assert ctx._resolve_with_upstreams("example.test", socket.AF_INET) == []

    module_empty = types.ModuleType("foghorn.servers.server")
    module_empty.send_query_with_failover = (  # type: ignore[attr-defined]
        lambda *_a, **_kw: (None, None, None)
    )
    monkeypatch.setitem(sys.modules, "foghorn.servers.server", module_empty)
    assert ctx._resolve_with_upstreams("example.test", socket.AF_INET) == []

    module_ok = types.ModuleType("foghorn.servers.server")
    module_ok.send_query_with_failover = (  # type: ignore[attr-defined]
        lambda *_a, **_kw: (b"wire", {"host": "1.1.1.1"}, None)
    )
    monkeypatch.setitem(sys.modules, "foghorn.servers.server", module_ok)
    monkeypatch.setattr(
        setup_mod,
        "_extract_rr_addresses",
        lambda _wire, qtype: (
            ["2001:db8::20"] if qtype == int(QTYPE.AAAA) else ["9.9.9.9"]
        ),
    )

    assert ctx._resolve_with_upstreams("example.test", socket.AF_INET) == ["9.9.9.9"]
    assert ctx._resolve_with_upstreams("example.test", socket.AF_INET6) == [
        "2001:db8::20"
    ]


def test_resolve_for_family_and_as_getaddrinfo_paths() -> None:
    """Brief: Family resolver and getaddrinfo conversion handle precedence, failures, and dedupe.

    Inputs:
      - Setup DNS context with monkeypatched provider/upstream and origin resolver behavior.

    Outputs:
      - None; asserts provider precedence, upstream fallback, and deduped tuples.
    """

    ctx = setup_mod._SetupDNSResolverContext(
        providers=[],
        upstreams=[],
        timeout_ms=1000,
        resolver_mode="forward",
        upstream_max_concurrent=1,
        fallback_to_system=True,
        logger_obj=logging.getLogger("tests.setup"),
    )

    ctx._resolve_with_providers = lambda _host, _family: ["1.1.1.1"]  # type: ignore[assignment]
    ctx._resolve_with_upstreams = lambda _host, _family: (_ for _ in ()).throw(AssertionError("upstream should not be used"))  # type: ignore[assignment]
    assert ctx._resolve_for_family("example.test", socket.AF_INET) == ["1.1.1.1"]

    ctx._resolve_with_providers = lambda _host, _family: []  # type: ignore[assignment]
    ctx._resolve_with_upstreams = lambda _host, _family: ["2.2.2.2"]  # type: ignore[assignment]
    assert ctx._resolve_for_family("example.test", socket.AF_INET) == ["2.2.2.2"]

    ctx._resolve_with_upstreams = lambda _host, _family: []  # type: ignore[assignment]
    assert ctx._resolve_for_family("example.test", socket.AF_INET) == []

    def _fake_resolve_for_family(_host: str, family: int) -> List[str]:
        if family == socket.AF_INET:
            return ["1.1.1.1", "1.1.1.1", "2.2.2.2"]
        return []

    def _fake_orig_getaddrinfo(host: str, port: int, *_rest: Any) -> list[tuple]:
        if host == "1.1.1.1":
            raise OSError("resolve fail")
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port)),
        ]

    ctx._resolve_for_family = _fake_resolve_for_family  # type: ignore[assignment]
    ctx._orig_getaddrinfo = _fake_orig_getaddrinfo  # type: ignore[assignment]
    resolved = ctx._as_getaddrinfo("example.test", 53, socket.AF_UNSPEC, 0, 0, 0)
    assert resolved == [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("2.2.2.2", 53))]
    assert ctx._as_getaddrinfo("example.test", 53, socket.AF_UNIX, 0, 0, 0) == []

    called_families: list[int] = []

    def _capture_family(_host: str, family: int) -> List[str]:
        called_families.append(family)
        return ["3.3.3.3"] if family == socket.AF_INET else []

    ctx._resolve_for_family = _capture_family  # type: ignore[assignment]
    ctx._orig_getaddrinfo = lambda host, port, *_rest: [  # type: ignore[assignment]
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))
    ]
    assert ctx._as_getaddrinfo("example.test", 443, socket.AF_INET, 0, 0, 0) == [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("3.3.3.3", 443))
    ]
    assert called_families == [socket.AF_INET]


def test_context_enter_exit_patches_and_restores_socket() -> None:
    """Brief: Setup DNS context patches socket resolvers and restores originals on exit.

    Inputs:
      - Setup DNS contexts with fallback enabled and disabled.

    Outputs:
      - None; asserts host resolution behavior for synthetic, fallback, and error paths.
    """

    original_getaddrinfo = socket.getaddrinfo
    original_gethostbyname = socket.gethostbyname
    original_gethostbyname_ex = socket.gethostbyname_ex

    try:
        ctx = setup_mod._SetupDNSResolverContext(
            providers=[],
            upstreams=[],
            timeout_ms=1000,
            resolver_mode="forward",
            upstream_max_concurrent=1,
            fallback_to_system=True,
            logger_obj=logging.getLogger("tests.setup"),
        )

        synthetic_getaddrinfo: list[tuple] = [("synthetic",)]
        resolve_ips: list[str] = ["9.9.9.9"]

        ctx._orig_getaddrinfo = lambda host, port, *_rest: [("orig", host, port)]  # type: ignore[assignment]
        ctx._orig_gethostbyname = lambda host: f"orig-{host}"  # type: ignore[assignment]
        ctx._orig_gethostbyname_ex = lambda host: (host, [], [f"orig-{host}"])  # type: ignore[assignment]
        ctx._as_getaddrinfo = lambda *_args, **_kwargs: list(synthetic_getaddrinfo)  # type: ignore[assignment]
        ctx._resolve_for_family = lambda *_args, **_kwargs: list(resolve_ips)  # type: ignore[assignment]

        with ctx:
            assert socket.getaddrinfo(None, 80) == [("orig", None, 80)]
            assert socket.getaddrinfo("1.2.3.4", 80) == [("orig", "1.2.3.4", 80)]
            assert socket.getaddrinfo("example.test", 80) == [("synthetic",)]
            synthetic_getaddrinfo.clear()
            assert socket.getaddrinfo("example.test", 80) == [
                ("orig", "example.test", 80)
            ]

            assert socket.gethostbyname("1.2.3.4") == "orig-1.2.3.4"
            resolve_ips[:] = ["8.8.8.8"]
            assert socket.gethostbyname("example.test") == "8.8.8.8"
            resolve_ips.clear()
            assert socket.gethostbyname("example.test") == "orig-example.test"

            resolve_ips[:] = ["7.7.7.7"]
            assert socket.gethostbyname_ex("example.test") == (
                "example.test",
                [],
                ["7.7.7.7"],
            )
            resolve_ips.clear()
            assert socket.gethostbyname_ex("1.2.3.4") == (
                "1.2.3.4",
                [],
                ["orig-1.2.3.4"],
            )
            assert socket.gethostbyname_ex("example.test") == (
                "example.test",
                [],
                ["orig-example.test"],
            )

        assert socket.getaddrinfo is ctx._orig_getaddrinfo
        assert socket.gethostbyname is ctx._orig_gethostbyname
        assert socket.gethostbyname_ex is ctx._orig_gethostbyname_ex

        socket.getaddrinfo = original_getaddrinfo
        socket.gethostbyname = original_gethostbyname
        socket.gethostbyname_ex = original_gethostbyname_ex

        ctx_no_fallback = setup_mod._SetupDNSResolverContext(
            providers=[],
            upstreams=[],
            timeout_ms=1000,
            resolver_mode="forward",
            upstream_max_concurrent=1,
            fallback_to_system=False,
            logger_obj=logging.getLogger("tests.setup"),
        )
        ctx_no_fallback._orig_getaddrinfo = lambda host, port, *_rest: [("orig", host, port)]  # type: ignore[assignment]
        ctx_no_fallback._orig_gethostbyname = lambda host: f"orig-{host}"  # type: ignore[assignment]
        ctx_no_fallback._orig_gethostbyname_ex = lambda host: (host, [], [f"orig-{host}"])  # type: ignore[assignment]
        ctx_no_fallback._as_getaddrinfo = lambda *_args, **_kwargs: []  # type: ignore[assignment]
        ctx_no_fallback._resolve_for_family = lambda *_args, **_kwargs: []  # type: ignore[assignment]

        with ctx_no_fallback:
            with pytest.raises(socket.gaierror):
                socket.getaddrinfo("example.test", 53)
            with pytest.raises(socket.gaierror):
                socket.gethostbyname("example.test")
            with pytest.raises(socket.gaierror):
                socket.gethostbyname_ex("example.test")
    finally:
        socket.getaddrinfo = original_getaddrinfo
        socket.gethostbyname = original_gethostbyname
        socket.gethostbyname_ex = original_gethostbyname_ex


def test_run_setup_plugins_failure_paths() -> None:
    """Brief: run_setup_plugins aborts or continues based on abort_on_failure setting.

    Inputs:
      - Setup-aware plugins with successful and failing setup hooks.

    Outputs:
      - None; asserts RuntimeError for aborting plugins and continuation otherwise.
    """

    calls: list[str] = []

    class _BadAbort(BasePlugin):
        def __init__(self) -> None:
            super().__init__(abort_on_failure=True)

        def setup(self) -> None:  # type: ignore[override]
            raise RuntimeError("boom")

    class _BadContinue(BasePlugin):
        def __init__(self) -> None:
            super().__init__(abort_on_failure=False)

        def setup(self) -> None:  # type: ignore[override]
            raise RuntimeError("boom")

    class _Good(BasePlugin):
        def setup(self) -> None:  # type: ignore[override]
            calls.append("good")

    with pytest.raises(RuntimeError, match="Setup for plugin _BadAbort failed"):
        setup_mod.run_setup_plugins([_BadAbort()])

    setup_mod.run_setup_plugins([_BadContinue(), _Good()])
    assert calls == ["good"]
