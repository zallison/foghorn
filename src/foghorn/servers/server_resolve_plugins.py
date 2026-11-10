"""Pre/post plugin execution for the shared DNS resolve pipeline."""

from __future__ import annotations

import logging
from typing import Any

from dnslib import RCODE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext, PluginDecision

from .plugin_telemetry import (
    log_plugin_telemetry,
    plugin_telemetry_enabled,
    time_plugin_call,
)
from .server_opcode import _ResolveCoreResult
from .server_response_utils import (
    _attach_ede_option,
    _echo_client_edns,
    _set_response_id,
)

logger = logging.getLogger("foghorn.server")


def _run_pre_plugins(
    *,
    data: bytes,
    req: object,
    client_ip: str,
    listener: str | None,
    secure: bool | None,
    qname: str,
    qtype: object,
    trusted_inbound_ecs: dict[str, Any] | None,
    effective_target_ip: str,
    handler: object,
    snap: object | None,
    stats: object | None,
    t0: float | None,
    request_result_meta: dict[str, Any],
    get_ordered_plugins,
    resolve_plugin_label,
    qtype_label_fn,
    record_suppressed_query_log_drop_candidate,
    classify_dnssec_status_for_response,
    apply_dnssec_ad_bit,
    is_signed_authoritative_response,
) -> tuple[list[object], list[object], _ResolveCoreResult | None]:
    """Brief: Run ordered pre_resolve plugins; may short-circuit drop/deny.

    Inputs:
      - data/req/client_ip/listener/secure: Request identity.
      - qname/qtype: Effective question.
      - trusted_inbound_ecs/effective_target_ip: Plugin targeting context.
      - handler/snap/stats/t0/request_result_meta: Runtime and metrics.
      - get_ordered_plugins/resolve_plugin_label/qtype_label_fn/
        record_suppressed_query_log_drop_candidate: Injected helpers.

    Outputs:
      - (pre_plugins, post_plugins, optional early _ResolveCoreResult).
    """

    _get_ordered_plugins = get_ordered_plugins
    _resolve_plugin_label = resolve_plugin_label
    _qtype_label_for_stats = qtype_label_fn
    _record_suppressed_query_log_drop_candidate = (
        record_suppressed_query_log_drop_candidate
    )
    _classify_dnssec_status_for_response = classify_dnssec_status_for_response
    _apply_dnssec_ad_bit = apply_dnssec_ad_bit
    _is_signed_authoritative_response = is_signed_authoritative_response
    rcode_name = "UNKNOWN"

    # Pre plugins
    ctx = PluginContext(client_ip=client_ip, listener=listener, secure=secure)
    # Attach qname so BasePlugin domain-targeting helpers can use it.
    try:
        ctx.qname = qname
    except Exception:  # pragma: no cover - defensive
        pass
    try:
        ctx.ecs = dict(trusted_inbound_ecs) if trusted_inbound_ecs is not None else None
        ctx.effective_target_ip = str(effective_target_ip or client_ip or "")
        ctx.source_ip = str(client_ip or "")
    except Exception:  # pragma: no cover - defensive
        pass
    plugins_list = list(getattr(handler, "plugins", []) or [])
    if snap is not None and hasattr(snap, "generation"):
        pre_plugins, post_plugins = _get_ordered_plugins(
            plugins=plugins_list,
            token_kind="snap",
            token=int(getattr(snap, "generation", 0) or 0),
        )
    else:
        pre_plugins, post_plugins = _get_ordered_plugins(
            plugins=plugins_list,
            token_kind="state",
            token=id(getattr(handler, "plugins", plugins_list)),
        )

    record_plugin_timing = plugin_telemetry_enabled(logger)
    pre_telemetry: list = []
    for p in pre_plugins:
        # Skip plugins that do not target this qtype when they opt in via
        # BasePlugin.target_qtypes.
        try:
            if hasattr(p, "targets_qtype") and not p.targets_qtype(
                qtype
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                continue
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            # On failure, fall back to running the plugin to avoid hiding
            # errors behind targeting decisions.
            pass

        try:
            decision = time_plugin_call(
                pre_telemetry,
                type(p).__name__,
                lambda p=p: p.pre_resolve(qname, qtype, data, ctx),
                record=record_plugin_timing,
            )
        except Exception:
            logger.error(
                "pre_resolve failed for plugin %s", type(p).__name__, exc_info=True
            )
            decision = None
        if isinstance(decision, PluginDecision):
            if decision.action == "drop":
                if stats is not None:
                    try:
                        from foghorn.servers.resolve_telemetry import (
                            ResolveEvent,
                            ResolveEventKind,
                            telemetry_from_stats,
                        )

                        telemetry_from_stats(stats).emit(
                            ResolveEvent(
                                kind=ResolveEventKind.PRE_PLUGIN_DECISION,
                                action="drop",
                                client_ip=client_ip,
                                qname=qname,
                                t0=t0,
                            )
                        )
                    except Exception:
                        _record_suppressed_query_log_drop_candidate(
                            stats,
                            rcode="DROP",
                            status="drop",
                        )
                # Pre-plugin timeout/drop: return sentinel empty wire so UDP
                # handlers and othefoghorn.servers.transports can choose not to reply.
                log_plugin_telemetry(logger, "pre", qname, pre_telemetry)
                return (
                    pre_plugins,
                    post_plugins,
                    _ResolveCoreResult(
                        wire=b"",
                        dnssec_status=None,
                        upstream_id=None,
                        rcode_name="DROP",
                    ),
                )
            if decision.action == "deny":
                # NXDOMAIN deny path
                r = req.reply()
                r.header.rcode = RCODE.NXDOMAIN
                # Echo client EDNS(0) OPT, when present, into synthetic NXDOMAIN
                # and, when enabled, attach an EDE option describing the
                # policy-based deny.
                _echo_client_edns(req, r)
                # Allow plugins to override the EDE info-code/text via
                # optional PluginDecision.ede_code / ede_text attributes,
                # falling back to a default mapping based on stat when
                # they are not provided.
                try:
                    ede_code_hint = getattr(
                        decision, "ede_code", None
                    )  # pragma: no cover - defensive/metrics path excluded from coverage
                except (
                    Exception
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    ede_code_hint = None
                try:
                    ede_text_hint = getattr(
                        decision, "ede_text", None
                    )  # pragma: no cover - defensive/metrics path excluded from coverage
                except (
                    Exception
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    ede_text_hint = None
                if ede_code_hint is not None:
                    ede_code = int(ede_code_hint)
                    ede_text = (
                        str(ede_text_hint)
                        if ede_text_hint is not None
                        else "policy deny"
                    )
                else:
                    try:
                        stat_label = getattr(
                            decision, "stat", None
                        )  # pragma: no cover - defensive/metrics path excluded from coverage
                    except (
                        Exception
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        stat_label = None
                    # Use "Not Ready" (14) for explicit rate limiting when
                    # decision.stat == "rate_limit"; otherwise treat this as a
                    # generic policy block (15).
                    if stat_label == "rate_limit":
                        ede_code = 14  # Not Ready
                        ede_text = "rate limit exceeded"
                    else:
                        ede_code = 15  # Blocked
                        ede_text = "blocked by policy"
                _attach_ede_option(req, r, ede_code, ede_text)
                wire = _set_response_id(r.pack(), req.header.id)
                if stats is not None:
                    try:
                        from foghorn.servers.resolve_telemetry import (
                            ResolveEvent,
                            ResolveEventKind,
                            telemetry_from_stats,
                        )

                        qtype_name = _qtype_label_for_stats(qtype)
                        short = _resolve_plugin_label(decision, p)
                        try:
                            stat_label = getattr(decision, "stat", None)
                        except Exception:
                            stat_label = None
                        telemetry_from_stats(stats).emit(
                            ResolveEvent(
                                kind=ResolveEventKind.PRE_PLUGIN_DECISION,
                                action="deny",
                                client_ip=client_ip,
                                qname=qname,
                                qtype_label=qtype_name,
                                t0=t0,
                                request_result_meta=dict(request_result_meta),
                                plugin_label=short,
                                stat_label=str(stat_label) if stat_label else None,
                                suppress_query_log=bool(
                                    getattr(decision, "suppress_query_log", False)
                                ),
                                ede_code=int(ede_code),
                                ede_text=str(ede_text),
                            )
                        )
                    except (
                        Exception
                    ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                        pass
                log_plugin_telemetry(logger, "pre", qname, pre_telemetry)
                return (
                    pre_plugins,
                    post_plugins,
                    _ResolveCoreResult(
                        wire=wire,
                        dnssec_status=None,
                        upstream_id=None,
                        rcode_name="NXDOMAIN",
                    ),
                )
            if decision.action == "override" and decision.response is not None:
                # Allow plugins to supply a full wire response, but ensure we
                # still echo client EDNS(0) when the override does not carry
                # its own OPT record.
                resp_wire = decision.response
                try:
                    override_msg = DNSRecord.parse(resp_wire)
                    _echo_client_edns(req, override_msg)
                    resp_wire = override_msg.pack()
                except Exception:  # pragma: no cover - defensive: parse failure
                    pass
                dnssec_status = _classify_dnssec_status_for_response(
                    handler=handler,
                    qname=qname,
                    qtype=qtype,
                    response_wire=resp_wire,
                )
                dnssec_status_for_stats = dnssec_status
                try:
                    dnssec_mode = str(getattr(handler, "dnssec_mode", "ignore")).lower()
                except Exception:
                    dnssec_mode = "ignore"
                if (
                    dnssec_mode == "validate"
                    and dnssec_status in (None, "dnssec_unsigned", "dnssec_bogus")
                    and _is_signed_authoritative_response(resp_wire)
                ):
                    dnssec_status = "dnssec_zone_secure"
                resp_wire = _apply_dnssec_ad_bit(
                    handler=handler,
                    dnssec_status=dnssec_status,
                    response_wire=resp_wire,
                )
                wire = _set_response_id(resp_wire, req.header.id)
                rcode_name = "UNKNOWN"
                if stats is not None:
                    try:
                        from foghorn.servers.resolve_telemetry import (
                            ResolveEvent,
                            ResolveEventKind,
                            build_answers_from_parsed,
                            telemetry_from_stats,
                        )

                        parsed = DNSRecord.parse(wire)
                        rcode_name = RCODE.get(
                            parsed.header.rcode, str(parsed.header.rcode)
                        )
                        answers, first = build_answers_from_parsed(parsed)
                        short = _resolve_plugin_label(decision, p)
                        try:
                            stat_label = getattr(decision, "stat", None)
                        except Exception:
                            stat_label = None
                        telemetry_from_stats(stats).emit(
                            ResolveEvent(
                                kind=ResolveEventKind.PRE_PLUGIN_DECISION,
                                action="override",
                                client_ip=client_ip,
                                qname=qname,
                                qtype_label=_qtype_label_for_stats(qtype),
                                t0=t0,
                                request_result_meta=dict(request_result_meta),
                                plugin_label=short,
                                stat_label=str(stat_label) if stat_label else None,
                                suppress_query_log=bool(
                                    getattr(decision, "suppress_query_log", False)
                                ),
                                rcode_name=rcode_name,
                                answers=answers,
                                first=first,
                                dnssec_status=dnssec_status_for_stats,
                            )
                        )
                    except (
                        Exception
                    ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                        pass
                log_plugin_telemetry(logger, "pre", qname, pre_telemetry)
                return (
                    pre_plugins,
                    post_plugins,
                    _ResolveCoreResult(
                        wire=wire,
                        dnssec_status=dnssec_status,
                        upstream_id=None,
                        rcode_name=rcode_name,
                    ),
                )
            if decision.action == "allow":
                # Explicit allow: stop evaluating further pre plugins but
                # continue normal resolution (cache/upstream).
                break

    log_plugin_telemetry(logger, "pre", qname, pre_telemetry)
    return pre_plugins, post_plugins, None


def _run_post_plugins(
    *,
    reply: bytes,
    req: object,
    client_ip: str,
    listener: str | None,
    secure: bool | None,
    qname: str,
    qtype: object,
    trusted_inbound_ecs: dict[str, Any] | None,
    effective_target_ip: str,
    post_plugins: list[object],
    upstream_id: str | None,
    stats: object | None,
    record_suppressed_query_log_drop_candidate,
) -> tuple[bytes, _ResolveCoreResult | None]:
    """Brief: Run ordered post_resolve plugins; may drop or rewrite wire.

    Inputs:
      - reply: Upstream/cache-miss response wire.
      - req and client identity/context fields for PluginContext.
      - post_plugins: Ordered post plugin list.
      - upstream_id/stats: Metrics context.
      - record_suppressed_query_log_drop_candidate: Injected helper.

    Outputs:
      - (out_wire, optional early _ResolveCoreResult for drop).
    """

    _record_suppressed_query_log_drop_candidate = (
        record_suppressed_query_log_drop_candidate
    )

    # Post plugins
    ctx2 = PluginContext(client_ip=client_ip, listener=listener, secure=secure)
    try:
        ctx2.qname = qname
    except Exception:  # pragma: no cover - defensive
        pass
    try:
        ctx2.ecs = (
            dict(trusted_inbound_ecs) if trusted_inbound_ecs is not None else None
        )
        ctx2.effective_target_ip = str(effective_target_ip or client_ip or "")
        ctx2.source_ip = str(client_ip or "")
    except Exception:  # pragma: no cover - defensive
        pass
    out = reply
    record_plugin_timing = plugin_telemetry_enabled(logger)
    post_telemetry: list = []
    for p in post_plugins:
        # Skip plugins that do not target this qtype when they opt in via
        # BasePlugin.target_qtypes.
        try:
            if hasattr(p, "targets_qtype") and not p.targets_qtype(
                qtype
            ):  # pragma: no cover - defensive/metrics path excluded from coverage
                continue
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            pass

        try:
            decision = time_plugin_call(
                post_telemetry,
                type(p).__name__,
                lambda p=p, out=out: p.post_resolve(qname, qtype, out, ctx2),
                record=record_plugin_timing,
            )
        except Exception:
            logger.error(
                "post_resolve failed for plugin %s", type(p).__name__, exc_info=True
            )
            decision = None
        if isinstance(decision, PluginDecision):
            if decision.action == "drop":
                if stats is not None:
                    try:
                        from foghorn.servers.resolve_telemetry import (
                            ResolveEvent,
                            ResolveEventKind,
                            telemetry_from_stats,
                        )

                        telemetry_from_stats(stats).emit(
                            ResolveEvent(
                                kind=ResolveEventKind.POST_PLUGIN_DECISION,
                                action="drop",
                                client_ip=client_ip,
                                qname=qname,
                                upstream_id=upstream_id,
                            )
                        )
                    except Exception:
                        _record_suppressed_query_log_drop_candidate(
                            stats,
                            rcode="DROP",
                            status="drop",
                        )
                # Post-plugin timeout/drop: do not send a response.
                log_plugin_telemetry(logger, "post", qname, post_telemetry)
                return b"", _ResolveCoreResult(
                    wire=b"",
                    dnssec_status=None,
                    upstream_id=upstream_id,
                    rcode_name="DROP",
                )
            if decision.action == "deny":
                r = req.reply()
                r.header.rcode = RCODE.NXDOMAIN
                # Echo client EDNS(0) OPT into post-plugin NXDOMAIN replies
                # and, when enabled, attach an EDE option describing the
                # post-resolve policy deny.
                _echo_client_edns(req, r)
                # Allow plugins to override the EDE info-code/text via
                # optional PluginDecision.ede_code / ede_text attributes,
                # falling back to a default mapping based on stat when
                # they are not provided.
                try:
                    ede_code_hint = getattr(
                        decision, "ede_code", None
                    )  # pragma: no cover - defensive/metrics path excluded from coverage
                except (
                    Exception
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    ede_code_hint = None
                try:
                    ede_text_hint = getattr(
                        decision, "ede_text", None
                    )  # pragma: no cover - defensive/metrics path excluded from coverage
                except (
                    Exception
                ):  # pragma: no cover - defensive/metrics path excluded from coverage
                    ede_text_hint = None
                if ede_code_hint is not None:
                    ede_code = int(ede_code_hint)
                    ede_text = (
                        str(ede_text_hint)
                        if ede_text_hint is not None
                        else "policy deny"
                    )
                else:
                    try:
                        stat_label = getattr(
                            decision, "stat", None
                        )  # pragma: no cover - defensive/metrics path excluded from coverage
                    except (
                        Exception
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        stat_label = None
                    if (
                        stat_label == "rate_limit"
                    ):  # pragma: no cover - defensive/metrics path excluded from coverage
                        ede_code = 14  # Not Ready  # pragma: no cover - defensive/metrics path excluded from coverage
                        ede_text = "rate limit exceeded"
                    else:
                        ede_code = 15  # Blocked
                        ede_text = "blocked by policy"
                _attach_ede_option(req, r, ede_code, ede_text)
                out = r.pack()
                break
            if decision.action == "override" and decision.response is not None:
                # Allow plugins to override the wire response while still
                # echoing client EDNS(0) when the override does not carry an
                # OPT RR of its own.
                resp_wire = decision.response
                try:
                    override_msg = DNSRecord.parse(resp_wire)
                    _echo_client_edns(req, override_msg)
                    out = override_msg.pack()
                except Exception:  # pragma: no cover - defensive: parse failure
                    out = resp_wire
                break  # pragma: no cover - defensive/metrics path excluded from coverage
            if decision.action == "allow":
                # Explicit allow: stop evaluating further post plugins but
                # leave the upstream response unchanged.
                break

    log_plugin_telemetry(logger, "post", qname, post_telemetry)
    return out, None
