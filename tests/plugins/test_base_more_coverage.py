"""Brief: Additional branch coverage for foghorn.plugins.resolve.base.

Inputs:
  - None.

Outputs:
  - None.
"""

import logging

import foghorn.plugins.resolve.base as base_mod
from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision
from foghorn.plugins.resolve.base import logger as base_logger


def test_plugin_decision_post_init_short_circuits(monkeypatch) -> None:
    """Brief: PluginDecision.__post_init__ returns early when plugin+label set.

    Inputs:
      - monkeypatch: used to ensure inspect.stack is not consulted.

    Outputs:
      - None; asserts decision retains provided plugin metadata.
    """

    def boom():  # type: ignore[no-untyped-def]
        raise AssertionError("inspect.stack should not be called")

    monkeypatch.setattr(base_mod.inspect, "stack", boom)

    d = PluginDecision(action="allow", plugin=BasePlugin, plugin_label="x")
    assert d.plugin is BasePlugin
    assert d.plugin_label == "x"


def test_normalize_qtype_list_handles_none_and_invalid_types(caplog) -> None:
    """Brief: _normalize_qtype_list returns wildcard for None/invalid values.

    Inputs:
      - caplog: captures warning for invalid type.

    Outputs:
      - None.
    """
    assert BasePlugin._normalize_qtype_list(None) == ["*"]

    caplog.set_level(logging.WARNING, logger=base_logger.name)
    assert BasePlugin._normalize_qtype_list(123) == ["*"]
    assert "invalid target_qtypes" in caplog.text.lower()

    # String input path + blank entry skip.
    assert BasePlugin._normalize_qtype_list(" ") == ["*"]


def test_normalize_domain_targets_parses_domains_and_modes(caplog) -> None:
    """Brief: _normalize_domain_targets normalizes raw domains + mode aliases.

    Inputs:
      - caplog: captures warnings for invalid domains/mode.

    Outputs:
      - None.
    """
    caplog.set_level(logging.WARNING, logger=base_logger.name)

    domains, mode = BasePlugin._normalize_domain_targets("Example.COM.", mode="EQ")
    assert domains == ["example.com"]
    assert mode == "exact"

    # Empty domain entries are skipped.
    domains2, mode2 = BasePlugin._normalize_domain_targets(
        ["", "Example.COM."],
        mode="sub",
    )
    assert domains2 == ["example.com"]
    assert mode2 == "suffix"

    domains3, mode3 = BasePlugin._normalize_domain_targets(123, mode="any")
    assert domains3 == []
    assert mode3 == "any"
    assert "invalid targets_domains" in caplog.text.lower()

    domains4, mode4 = BasePlugin._normalize_domain_targets(
        ["example.com"], mode="weird"
    )
    assert domains4 == ["example.com"]
    assert mode4 == "any"
    assert "unknown targets_domains_mode" in caplog.text.lower()


def test_normalize_domain_targets_mode_str_failure_falls_back_to_any() -> None:
    """Brief: Non-stringable mode values fall back to 'any'.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    class BadMode:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    domains, mode = BasePlugin._normalize_domain_targets(
        ["example.com"], mode=BadMode()
    )
    assert domains == ["example.com"]
    assert mode == "any"


def test_normalize_listener_target_covers_tokens_and_warnings(caplog) -> None:
    """Brief: _normalize_listener_target handles any/empty/unknown/list entries.

    Inputs:
      - caplog: captures warnings.

    Outputs:
      - None.
    """
    caplog.set_level(logging.WARNING, logger=base_logger.name)

    assert BasePlugin._normalize_listener_target(" ") == set()

    # Concrete listener token
    assert BasePlugin._normalize_listener_target("udp") == {"udp"}

    # any clears the set
    assert BasePlugin._normalize_listener_target(["udp", "any"]) == set()

    assert BasePlugin._normalize_listener_target("wat") == set()
    assert "unknown targets_listener" in caplog.text.lower()

    class BadStr:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    assert BasePlugin._normalize_listener_target([BadStr()]) == set()
    assert "ignoring non-string targets_listener entry" in caplog.text.lower()

    assert BasePlugin._normalize_listener_target(123) == set()
    assert "invalid targets_listener" in caplog.text.lower()


def test_targets_domain_filter_requires_qname_and_matches_modes() -> None:
    """Brief: targets() enforces domain filters for exact/suffix modes.

    Inputs:
      - None.

    Outputs:
      - None.
    """
    p_exact = BasePlugin(targets_domains=["example.com"], targets_domains_mode="exact")
    p_exact.setup()

    ctx = PluginContext(client_ip="192.0.2.1")
    assert p_exact.targets(ctx) is False

    ctx.qname = ""
    assert p_exact.targets(ctx) is False

    ctx.qname = "other.com"
    assert p_exact.targets(ctx) is False

    ctx.qname = "EXAMPLE.COM."
    assert p_exact.targets(ctx) is True

    p_suffix = BasePlugin(
        targets_domains=["example.com"],
        targets_domains_mode="suffix",
    )
    p_suffix.setup()

    ctx2 = PluginContext(client_ip="192.0.2.2")
    ctx2.qname = "foo.other.com"
    assert p_suffix.targets(ctx2) is False

    ctx2.qname = "www.example.com."
    assert p_suffix.targets(ctx2) is True


def test_cache_counter_assignment_failures_are_tolerated() -> None:
    """Brief: targets() tolerates exceptions when updating cache counters.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    class CounterRaises:
        """Brief: Dict-like cache with counters that raise on set."""

        def __init__(self, *, cached: bytes | None) -> None:
            self._cached = cached
            self._store: dict[tuple[str, int], bytes] = {}
            self._calls_total = 0
            self._cache_hits = 0
            self._cache_misses = 0

        @property
        def calls_total(self) -> int:
            return self._calls_total

        @calls_total.setter
        def calls_total(self, value: int) -> None:
            raise RuntimeError("nope")

        @property
        def cache_hits(self) -> int:
            return self._cache_hits

        @cache_hits.setter
        def cache_hits(self, value: int) -> None:
            raise RuntimeError("nope")

        @property
        def cache_misses(self) -> int:
            return self._cache_misses

        @cache_misses.setter
        def cache_misses(self, value: int) -> None:
            raise RuntimeError("nope")

        def get(self, key):  # type: ignore[no-untyped-def]
            return self._cached

        def __setitem__(self, key, value):  # type: ignore[no-untyped-def]
            self._store[key] = value

    p = BasePlugin(targets=["10.0.0.0/8"])
    p.setup()

    # Cache-hit path -> exercises calls_total and cache_hits set failures.
    p._targets_cache = CounterRaises(cached=b"1")  # type: ignore[assignment]
    assert p.targets(PluginContext(client_ip="10.1.2.3")) is True

    # Cache-miss path -> exercises cache_misses set failure.
    p._targets_cache = CounterRaises(cached=None)  # type: ignore[assignment]
    assert p.targets(PluginContext(client_ip="10.1.2.3")) is True


def test_qtype_name_normalizes_str() -> None:
    """Brief: qtype_name uppercases mnemonic strings.

    Inputs:
      - None.

    Outputs:
      - None.
    """
    assert BasePlugin.qtype_name("mx") == "MX"


def test_normalize_opcode_list_and_targets_opcode(caplog, monkeypatch) -> None:
    """Brief: target_opcodes normalization and targets_opcode() matching.

    Inputs:
      - caplog: captures warnings for invalid normalization input.
      - monkeypatch: used to force defensive branches.

    Outputs:
      - None.
    """
    caplog.set_level(logging.WARNING, logger=base_logger.name)

    assert BasePlugin._normalize_opcode_list(None) == ["QUERY"]
    assert BasePlugin._normalize_opcode_list("NOTIFY") == ["NOTIFY"]
    assert BasePlugin._normalize_opcode_list(["*", "STATUS"]) == ["*"]
    assert BasePlugin._normalize_opcode_list([4, "status", " "]) == [4, "STATUS"]

    assert BasePlugin._normalize_opcode_list({"bad": "type"}) == ["QUERY"]
    assert "invalid target_opcodes" in caplog.text.lower()

    p = BasePlugin(target_opcodes=[4, "STATUS"])
    p.setup()

    assert p.targets_opcode(4) is True
    assert p.targets_opcode(2) is True
    assert p.targets_opcode(0) is False

    # Defensive: _target_opcodes exists but is non-iterable.
    p._target_opcodes = object()  # type: ignore[assignment]
    assert p.targets_opcode(0) is True

    # Defensive: OPCODE.get raises.
    class BadOpcodeMap:
        def get(self, key, default=None):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

    monkeypatch.setattr(base_mod, "OPCODE", BadOpcodeMap())
    p._target_opcodes = [123]  # type: ignore[assignment]
    assert p.targets_opcode(123) is True

    p._target_opcodes = []  # type: ignore[assignment]
    assert p.targets_opcode(4) is False

    p._target_opcodes = ["*"]  # type: ignore[assignment]
    assert p.targets_opcode(123) is True


def test_handle_opcode_default_noop() -> None:
    """Brief: handle_opcode() default implementation returns None.

    Inputs:
      - None.

    Outputs:
      - None.
    """
    p = BasePlugin()
    p.setup()
    ctx = PluginContext(client_ip="192.0.2.1")
    assert p.handle_opcode(4, "example.com", 1, b"", ctx) is None


def test_normalize_qname_and_base_domain_and_admin_descriptor() -> None:
    """Brief: Smoke tests for normalize_qname/base_domain/admin descriptor.

    Inputs:
      - None.

    Outputs:
      - None.
    """
    assert BasePlugin.normalize_qname("Example.COM.", lower=True) == "example.com"
    assert BasePlugin.normalize_qname("Example.COM.", lower=False) == "Example.COM"

    assert BasePlugin.base_domain("a.b.example.com.") == "example.com"
    assert BasePlugin.base_domain("example.com.", base_labels=10) == "example.com"
    assert BasePlugin.base_domain("") == ""

    p = BasePlugin()
    p.setup()
    assert p.get_admin_ui_descriptor() is None


def test_init_instance_logger_removes_handlers_and_syslog_non_dict(monkeypatch) -> None:
    """Brief: _init_instance_logger removes pre-existing handlers and supports syslog.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None.
    """

    class DummySysLogHandler(logging.Handler):
        LOG_USER = object()

        def __init__(self, address=None, facility=None):  # type: ignore[no-untyped-def]
            super().__init__()
            self.address = address
            self.facility = facility

    monkeypatch.setattr(base_mod.logging.handlers, "SysLogHandler", DummySysLogHandler)

    plugin_logger = logging.getLogger("foghorn.plugins.resolve.base")
    orig_handlers = list(plugin_logger.handlers)
    orig_level = plugin_logger.level
    orig_propagate = plugin_logger.propagate

    try:
        old_handler = logging.NullHandler()
        plugin_logger.addHandler(old_handler)

        cfg = {
            "level": "info",
            "stderr": False,
            "syslog": True,
        }
        p = BasePlugin(logging=cfg)
        p.setup()

        assert old_handler not in p.logger.handlers
        assert any(isinstance(h, DummySysLogHandler) for h in p.logger.handlers)
    finally:
        plugin_logger.handlers = orig_handlers
        plugin_logger.setLevel(orig_level)
        plugin_logger.propagate = orig_propagate
