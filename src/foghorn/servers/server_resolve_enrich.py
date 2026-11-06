"""Query enrichment: search-domain qualification and ECS processing."""

from __future__ import annotations

from typing import Any

from .edns_utils import (
    parse_ecs_from_request,
    strip_ecs_options_from_request,
    upsert_ecs_option,
)


def _apply_search_domain_qualification(
    *,
    qname: str,
    qtype: object,
    snap: object | None,
    excluded_qtypes: frozenset[int],
) -> str:
    """Brief: Optionally qualify qname with configured search domain.

    Inputs:
      - qname: Normalized owner name without trailing dot.
      - qtype: Query type value.
      - snap: Runtime snapshot or None.
      - excluded_qtypes: QTYPEs that skip search qualification (DNSSEC).

    Outputs:
      - str: Possibly qualified qname.
    """

    try:
        if snap is None:
            return qname
        _search = str(getattr(snap, "search_domain", "") or "")
        if _search:
            try:
                _qtype_num = int(qtype)
            except Exception:
                _qtype_num = int(qtype or 0)
            if _qtype_num in excluded_qtypes:
                _search = ""
        if _search:
            from foghorn.utils.dns_names import qualify_name, should_qualify

            _qual = should_qualify(
                qname,
                qualify_single_label=bool(getattr(snap, "qualify_single_label", True)),
                qualify_non_proper_tld=getattr(snap, "qualify_non_proper_tld", False),
                non_proper_tld_mode=str(
                    getattr(snap, "non_proper_tld_mode", "suffix") or "suffix"
                ),
            )
            if _qual:
                _qualified = qualify_name(qname, _search)
                if _qualified is not None:
                    qname = _qualified
    except (
        Exception
    ):  # pragma: no cover - defensive: qualification failure is non-fatal
        pass
    return qname


def _apply_ecs_processing(
    *,
    req: object,
    handler: object,
    client_ip: str,
    listener: str | None,
    secure: bool | None,
    is_listener_trusted_for_ecs,
    is_source_ip_trusted_for_ecs,
    synthesize_ecs_for_source_ip,
    build_request_result_meta,
) -> tuple[
    dict[str, Any] | None,
    bool,
    dict[str, Any] | None,
    dict[str, Any] | None,
    str,
    bool,
    dict[str, Any],
]:
    """Brief: Parse/trust/synthesize ECS and rebuild request_result_meta.

    Inputs:
      - req: Parsed DNS request (may be mutated).
      - handler: Runtime handler-like object.
      - client_ip: Transport source IP.
      - listener: Optional listener label.
      - secure: Optional secure transport flag.
      - is_listener_trusted_for_ecs: Trust predicate for listeners.
      - is_source_ip_trusted_for_ecs: Trust predicate for source IPs.
      - synthesize_ecs_for_source_ip: ECS synthesis helper.
      - build_request_result_meta: Metadata builder.

    Outputs:
      - (inbound_ecs, inbound_ecs_trusted, trusted_inbound_ecs, outbound_ecs,
         effective_target_ip, ecs_cache_bypass, request_result_meta)
    """

    ecs_enabled = bool(getattr(handler, "ecs_enabled", False))
    ecs_forward_inbound = bool(getattr(handler, "ecs_forward_inbound", False))
    ecs_synthesize_from_client_ip = bool(
        getattr(handler, "ecs_synthesize_from_client_ip", False)
    )
    ecs_source_prefix_v4 = max(
        0,
        min(32, int(getattr(handler, "ecs_source_prefix_v4", 24))),
    )
    ecs_source_prefix_v6 = max(
        0,
        min(128, int(getattr(handler, "ecs_source_prefix_v6", 56))),
    )
    ecs_scope_prefix_v4 = max(
        0,
        min(32, int(getattr(handler, "ecs_scope_prefix_v4", 0))),
    )
    ecs_scope_prefix_v6 = max(
        0,
        min(128, int(getattr(handler, "ecs_scope_prefix_v6", 0))),
    )
    ecs_trusted_listeners = list(getattr(handler, "ecs_trusted_listeners", []) or [])
    ecs_trusted_client_cidrs = list(
        getattr(handler, "ecs_trusted_client_cidrs", []) or []
    )
    ecs_use_for_plugin_targeting = bool(
        getattr(handler, "ecs_use_for_plugin_targeting", False)
    )

    inbound_ecs: dict[str, Any] | None = None
    inbound_ecs_trusted = False
    trusted_inbound_ecs: dict[str, Any] | None = None
    outbound_ecs: dict[str, Any] | None = None
    effective_target_ip = str(client_ip or "")

    resolver_mode_for_ecs = str(getattr(handler, "resolver_mode", "forward")).lower()
    if resolver_mode_for_ecs == "none":
        resolver_mode_for_ecs = "master"

    if ecs_enabled:
        inbound_ecs = parse_ecs_from_request(req)
        if inbound_ecs is not None:
            inbound_ecs_trusted = bool(
                is_listener_trusted_for_ecs(
                    listener=listener,
                    secure=secure,
                    trusted_listeners=ecs_trusted_listeners,
                )
                or is_source_ip_trusted_for_ecs(
                    client_ip=client_ip,
                    trusted_cidrs=ecs_trusted_client_cidrs,
                )
            )
            if inbound_ecs_trusted:
                trusted_inbound_ecs = dict(inbound_ecs)

        if (
            resolver_mode_for_ecs == "forward"
            and ecs_forward_inbound
            and trusted_inbound_ecs is not None
        ):
            outbound_ecs = dict(trusted_inbound_ecs)
        elif resolver_mode_for_ecs == "forward" and ecs_synthesize_from_client_ip:
            outbound_ecs = synthesize_ecs_for_source_ip(
                client_ip=client_ip,
                source_prefix_v4=ecs_source_prefix_v4,
                source_prefix_v6=ecs_source_prefix_v6,
                scope_prefix_v4=ecs_scope_prefix_v4,
                scope_prefix_v6=ecs_scope_prefix_v6,
            )

        if resolver_mode_for_ecs == "forward" and inbound_ecs is not None:
            try:
                strip_ecs_options_from_request(req)
            except Exception:
                pass

        if outbound_ecs is not None:
            try:
                if not upsert_ecs_option(
                    req,
                    outbound_ecs,
                    create_opt_if_missing=False,
                    edns_udp_payload=int(getattr(handler, "edns_udp_payload", 1232)),
                    preserve_do_bit=True,
                ):
                    outbound_ecs = None
            except Exception:
                outbound_ecs = None

        if ecs_use_for_plugin_targeting and trusted_inbound_ecs is not None:
            target_ip = str(trusted_inbound_ecs.get("address") or "").strip()
            if target_ip:
                effective_target_ip = target_ip

    if not effective_target_ip:
        effective_target_ip = str(client_ip or "")
    ecs_cache_bypass = bool(
        outbound_ecs is not None or effective_target_ip != str(client_ip or "")
    )
    request_result_meta = build_request_result_meta(
        source_ip=str(client_ip or ""),
        effective_target_ip=str(effective_target_ip or client_ip or ""),
        listener=listener,
        secure=secure,
        inbound_ecs=inbound_ecs,
        inbound_ecs_trusted=inbound_ecs_trusted,
        outbound_ecs=outbound_ecs,
        ecs_cache_bypass=ecs_cache_bypass,
    )
    return (
        inbound_ecs,
        inbound_ecs_trusted,
        trusted_inbound_ecs,
        outbound_ecs,
        effective_target_ip,
        ecs_cache_bypass,
        request_result_meta,
    )
