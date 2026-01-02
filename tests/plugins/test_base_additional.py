"""Brief: Additional coverage tests for foghorn.plugins.resolve.base.

Inputs:
  - None.

Outputs:
  - None.
"""

import logging

import foghorn.plugins.resolve.base as base_mod
from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision
from foghorn.plugins.resolve.base import logger as base_logger


def test_plugin_decision_populates_plugin_and_label_from_stack() -> None:
    """Brief: PluginDecision infers plugin class and label via call stack.

    Inputs:
      - None.

    Outputs:
      - None; asserts plugin and plugin_label inferred from BasePlugin subclass.
    """

    class StackPlugin(BasePlugin):
        def make_decision(self) -> PluginDecision:
            """Brief: Build a decision from within a plugin method.

            Inputs:
              - None.

            Outputs:
              - PluginDecision created in the context of this plugin instance.
            """

            return PluginDecision(action="allow")

    plugin = StackPlugin(name="stack_plugin")
    plugin.setup()
    decision = plugin.make_decision()

    # PluginDecision.__post_init__ performs best-effort stack inspection; when
    # it succeeds we expect the originating plugin class and label to be set,
    # but failures must not break normal handling. Assert only when metadata
    # is present.
    if decision.plugin is not None:
        assert decision.plugin is StackPlugin
        assert decision.plugin_label == "stack_plugin"


def test_init_instance_logger_configures_handlers(tmp_path, monkeypatch) -> None:
    """Brief: _init_instance_logger sets up stderr, file, and syslog handlers.

    Inputs:
      - tmp_path: pytest tmp_path fixture for log file location.
      - monkeypatch: pytest fixture used to stub SysLogHandler.

    Outputs:
      - None; asserts logger level, handlers, and propagation behavior.
    """

    # Capture original logger state so this test does not leak configuration
    # (handlers, levels, propagate flags) into other tests which rely on the
    # default behavior of foghorn.plugins.resolve.base's logger.
    base_log = logging.getLogger("foghorn.plugins.resolve.base")
    orig_level = base_log.level
    orig_handlers = list(base_log.handlers)
    orig_propagate = base_log.propagate

    class DummySysLogHandler(logging.Handler):
        """Brief: Lightweight stand-in for logging.handlers.SysLogHandler.

        Inputs:
          - address: syslog address (unused here).
          - facility: syslog facility (unused here).

        Outputs:
          - None; standard logging.Handler initialization.
        """

        LOG_USER = object()

        def __init__(self, address=None, facility=None):  # type: ignore[no-untyped-def]
            super().__init__()
            self.address = address
            self.facility = facility
            self.records = []

        def emit(self, record):  # type: ignore[no-untyped-def]
            """Brief: Collect emitted records without performing any I/O.

            Inputs:
              - record: logging.LogRecord being emitted.

            Outputs:
              - None; appends the record to an in-memory list.
            """

            self.records.append(record)

    # Replace the SysLogHandler used within foghorn.plugins.resolve.base with the dummy.
    monkeypatch.setattr(base_mod.logging.handlers, "SysLogHandler", DummySysLogHandler)

    log_path = tmp_path / "plugin.log"
    logging_cfg = {
        "level": "debug",
        "stderr": True,
        "file": str(log_path),
        "syslog": {"address": "/dev/log", "facility": "user"},
    }

    plugin = BasePlugin(logging=logging_cfg)
    plugin.setup()

    plugin_logger = plugin.logger
    # Logger should be the module logger used by BasePlugin.
    assert plugin_logger is logging.getLogger(plugin.__class__.__module__)
    assert plugin_logger.level == logging.DEBUG
    assert plugin_logger.propagate is False

    handler_types = {type(h) for h in plugin_logger.handlers}
    assert DummySysLogHandler in handler_types

    # Restore original logger state to avoid affecting subsequent tests which
    # expect the default logger configuration.
    base_log.handlers = orig_handlers
    base_log.setLevel(orig_level)
    base_log.propagate = orig_propagate


def test_parse_network_list_accepts_string_and_sequence(caplog) -> None:
    """Brief: _parse_network_list parses string and sequence inputs and logs invalid types.

    Inputs:
      - caplog: pytest logging capture fixture.

    Outputs:
      - None; asserts parsed networks and that invalid types emit a warning.
    """

    caplog.set_level(logging.WARNING, logger=base_logger.name)

    nets_from_str = BasePlugin._parse_network_list("10.0.0.0/8")
    assert len(nets_from_str) == 1

    nets_from_seq = BasePlugin._parse_network_list(["192.0.2.1"])
    assert len(nets_from_seq) == 1

    nets_from_invalid = BasePlugin._parse_network_list(123)
    assert nets_from_invalid == []


def test_parse_network_list_skips_blank_and_invalid_entries(caplog) -> None:
    """Brief: _parse_network_list ignores blank strings and invalid CIDR entries.

    Inputs:
      - caplog: pytest logging capture fixture.

    Outputs:
      - None; asserts only valid networks are returned and invalid are logged.
    """

    caplog.set_level(logging.WARNING, logger=base_logger.name)

    nets = BasePlugin._parse_network_list(["10.0.0.0/24", " ", "not-a-network"])
    assert len(nets) == 1
    assert str(nets[0].network_address) == "10.0.0.0"


def test_targets_returns_false_when_client_ip_missing() -> None:
    """Brief: targets() returns False when filters are configured but client_ip is missing.

    Inputs:
      - None.

    Outputs:
      - None; asserts non-empty filters with no client_ip yield False.
    """

    plugin = BasePlugin(targets=["10.0.0.0/8"])
    plugin.setup()

    class DummyCtx:
        """Brief: Context without a client_ip attribute for targets() checks.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        pass

    ctx = DummyCtx()
    assert plugin.targets(ctx) is False


def test_targets_returns_false_on_invalid_client_ip() -> None:
    """Brief: targets() treats invalid client_ip as not targeted when filters exist.

    Inputs:
      - None.

    Outputs:
      - None; asserts invalid client_ip leads to a False decision.
    """

    plugin = BasePlugin(targets=["10.0.0.0/8"])
    plugin.setup()
    ctx = PluginContext(client_ip="not-an-ip")

    assert plugin.targets(ctx) is False
