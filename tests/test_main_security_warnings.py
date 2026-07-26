"""Security-warning tests for foghorn.main startup paths."""

from __future__ import annotations

import argparse

import foghorn.main as main_mod


def test_log_startup_security_warnings_emits_expected_messages(caplog) -> None:
    """Brief: Startup security helper emits warnings for risky config choices.

    Inputs:
      - caplog fixture.

    Outputs:
      - None; asserts warnings for DoH plaintext exposure, AXFR openness,
        DoT verify=false, and ACL default=allow.
    """

    cfg = {
        "plugins": [
            {
                "type": "acl",
                "config": {"default": "allow"},
            }
        ]
    }
    upstreams = [
        {
            "host": "1.1.1.1",
            "port": 853,
            "transport": "dot",
            "tls": {"verify": False},
        }
    ]
    doh_cfg = {"enabled": True, "host": "0.0.0.0"}

    with caplog.at_level("WARNING", logger="foghorn.main"):
        main_mod._log_startup_security_warnings(
            logger=main_mod.logging.getLogger("foghorn.main"),
            cfg=cfg,
            resolver_mode="forward",
            upstreams=upstreams,
            doh_cfg=doh_cfg,
            axfr_enabled=True,
            axfr_allow_clients=[],
        )

    messages = [record.getMessage() for record in caplog.records]
    assert any("DoH listener is enabled on non-loopback host" in m for m in messages)
    assert any(
        "AXFR/IXFR is enabled without server.axfr.allow_clients" in m for m in messages
    )
    assert any("has tls.verify=false" in m for m in messages)
    assert any("ACL plugin at plugins[0] uses default=allow" in m for m in messages)


def test_configure_dnssec_validation_resolver_warns_when_deps_missing(
    monkeypatch, caplog
) -> None:
    """Brief: Local DNSSEC validation logs warning/error when imports fail.

    Inputs:
      - monkeypatch and caplog fixtures.

    Outputs:
      - None; asserts function returns False and warning is logged.
    """

    import builtins

    original_import = builtins.__import__

    def fake_import(
        name, globals=None, locals=None, fromlist=(), level=0
    ):  # noqa: ANN001, ANN201
        if name == "foghorn.dnssec.dnssec_validate":
            raise ImportError("missing dependency")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with caplog.at_level("WARNING", logger="foghorn.main"):
        ok = main_mod._configure_dnssec_validation_resolver(
            logger=main_mod.logging.getLogger("foghorn.main"),
            dnssec_mode="validate",
            dnssec_validation="local",
            resolver_mode="forward",
            upstreams=[{"host": "1.1.1.1"}],
        )

    assert ok is False
    assert any(
        "DNSSEC local validation requested but dependencies are unavailable"
        in rec.getMessage()
        for rec in caplog.records
    )


def test_initialize_statistics_subsystem_warns_without_retention_limits(
    monkeypatch, caplog
) -> None:
    """Brief: Stats subsystem warns when persistence lacks retention limits.

    Inputs:
      - monkeypatch and caplog fixtures.

    Outputs:
      - None; asserts warning is emitted while initialization succeeds.
    """

    class DummyStore:
        """Brief: Minimal persistence store stub for stats initialization tests.

        Inputs:
          - None.

        Outputs:
          - DummyStore instance supporting required startup methods.
        """

        def rebuild_counts_if_needed(
            self, force_rebuild: bool, logger_obj
        ) -> None:  # noqa: ANN001, ARG002
            return None

        def close(self) -> None:
            return None

    class DummyReporter:
        """Brief: Minimal reporter stub to avoid background threads in tests.

        Inputs:
          - collector/log options from stats initialization.

        Outputs:
          - DummyReporter with start/stop no-op behavior.
        """

        def __init__(
            self,
            *,
            collector,  # noqa: ANN001, ARG002
            interval_seconds: int,
            reset_on_log: bool,  # noqa: ARG002
            log_level: str,  # noqa: ARG002
            persistence_store,  # noqa: ANN001, ARG002
        ) -> None:
            self.interval_seconds = interval_seconds

        def start(self) -> None:
            return None

        def stop(self) -> None:
            return None

    monkeypatch.setattr(main_mod, "load_stats_store_backend", lambda _cfg: DummyStore())
    monkeypatch.setattr(main_mod, "StatsReporter", DummyReporter)

    cfg = {
        "logging": {"backends": [{"backend": "sqlite"}]},
        "stats": {"enabled": True},
    }
    args = argparse.Namespace(rebuild=False)

    with caplog.at_level("WARNING", logger="foghorn.main"):
        stats_collector, stats_reporter, stats_store = (
            main_mod._initialize_statistics_subsystem(
                cfg=cfg,
                logging_cfg=cfg["logging"],
                args=args,
                logger=main_mod.logging.getLogger("foghorn.main"),
            )
        )

    assert stats_collector is not None
    assert stats_reporter is not None
    assert stats_store is not None
    assert any(
        "Statistics persistence is enabled without query_log retention limits"
        in rec.getMessage()
        for rec in caplog.records
    )
