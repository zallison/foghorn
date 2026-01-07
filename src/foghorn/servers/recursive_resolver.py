from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from foghorn.utils.current_cache import get_current_namespaced_cache, module_namespace

from dnslib import QTYPE, RCODE, DNSRecord

from . import (
    recursive_resolver as _recursive_module,  # Self-import to honour test monkeypatching.
)
from foghorn.servers.transports.tcp import tcp_query as _tcp_transport_query
from foghorn.servers.transports.udp import udp_query as _udp_transport_query

"""Iterative recursive resolver for Foghorn.

This module implements a minimal but functional recursive resolver that can walk
from the DNS root down to authoritative servers using root hints and the
existing UDP/TCP transport helpers. It is intentionally conservative and
primarily aimed at being exercised under tests via monkeypatchefoghorn.servers.transports.
"""


logger = logging.getLogger("foghorn.recursive")

# QNAME minimisation tuning knobs inspired by RFC 9156-style guidance. These are
# deliberately simple and internal; if operators need to tune them later they
# can be promoted to configuration options.
#
# - _MAX_MINIMISE_COUNT limits how many intermediate "minimised" queries we
#   will send per resolution (queries that use shortened QNAMEs).
# - _MINIMISE_ONE_LAB ensures that we still walk label-by-label for the last
#   few suffixes near the leaf, even if we have already hit the global
#   minimisation budget.
_MAX_MINIMISE_COUNT = 10
_MINIMISE_ONE_LAB = 2


def udp_query(host: str, port: int, wire: bytes, *, timeout_ms: int = 2000) -> bytes:
    """Brief: DNS-over-UDP helper used by RecursiveResolver and tests.

    Inputs:
      - host: Upstream authority host/IP.
      - port: Upstream UDP port.
      - wire: Wire-format DNS query bytes.
      - timeout_ms: Per-query timeout in milliseconds.

    Outputs:
      - bytes: Wire-format DNS response bytes.
    """

    return _udp_transport_query(host, int(port), wire, timeout_ms=timeout_ms)


def tcp_query(
    host: str,
    port: int,
    wire: bytes,
    *,
    connect_timeout_ms: int = 1000,
    read_timeout_ms: int = 1500,
) -> bytes:
    """Brief: DNS-over-TCP helper used by RecursiveResolver and tests.

    Inputs:
      - host: Upstream authority host/IP.
      - port: Upstream TCP port.
      - wire: Wire-format DNS query bytes.
      - connect_timeout_ms: TCP connect timeout in milliseconds.
      - read_timeout_ms: TCP read timeout in milliseconds.

    Outputs:
      - bytes: Wire-format DNS response bytes.
    """

    return _tcp_transport_query(
        host,
        int(port),
        wire,
        connect_timeout_ms=connect_timeout_ms,
        read_timeout_ms=read_timeout_ms,
    )


@dataclass
class _Server:
    """Brief: Simple container for an authoritative server target.

    Inputs:
      - host: IP address string
      - port: TCP/UDP port (default 53)

    Outputs:
      - _Server instances used internally by RecursiveResolver.
    """

    host: str
    port: int = 53


def _default_root_hints() -> List[_Server]:
    """Brief: Return a baked-in list of root server IPv4 addresses.

    Inputs:
      - None

    Outputs:
      - List of _Server entries for root name servers (IPv4 only).

    Notes:
      - This is intentionally small and static; operators can override via
        configuration in future steps if needed.
    """

    # A small subset of the current root servers; this is sufficient for
    # real-world use and deterministic tests that monkeypatcfoghorn.servers.transports.
    # Source: IANA root hints (IPv4 only).
    return [
        _Server("198.41.0.4", 53),  # a.root-servers.net
        _Server("199.9.14.201", 53),  # b.root-servers.net
        _Server("192.33.4.12", 53),  # c.root-servers.net
        _Server("199.7.91.13", 53),  # d.root-servers.net
        _Server("192.203.230.10", 53),  # e.root-servers.net
    ]


class RecursiveResolver:
    """Brief: Minimal iterative recursive resolver for Foghorn.

    Inputs (constructor):
      - cache: FoghornTTLCache instance used for shared DNS caching (optional).
      - stats: Optional StatsCollector for recording upstream results.
      - max_depth: Maximum number of delegation/referral hops per query.
      - timeout_ms: Overall timeout budget per query (best effort).
      - per_try_timeout_ms: Per-authority query timeout in milliseconds.

    Outputs:
      - Instances able to resolve a DNSRecord request via resolve().
    """

    def __init__(
        self,
        *,
        cache,
        stats,
        max_depth: int = 16,
        timeout_ms: int = 2000,
        per_try_timeout_ms: int = 2000,
    ) -> None:
        # `cache` is the currently configured DNS cache plugin. We derive a
        # separate namespaced TTL cache from it (when backed by sqlite) to store
        # recursive minimization/referral results without colliding with the
        # primary DNS response cache table.
        self._cache = cache
        self._ns_cache = get_current_namespaced_cache(
            namespace=module_namespace(__file__),
            cache_plugin=cache,
        )

        self._stats = stats
        self._max_depth = max(1, int(max_depth or 1))
        self._timeout_ms = int(timeout_ms or 2000)
        self._per_try_timeout_ms = int(per_try_timeout_ms or self._timeout_ms)

    def _query_single(self, server: _Server, wire: bytes) -> Optional[bytes]:
        """Brief: Send a single query to an authority over UDP with TCP fallback.

        Inputs:
          - server: _Server(host, port)
          - wire: DNS query wire bytes (RD bit already set/cleared as desired).

        Outputs:
          - DNS response wire bytes, or None on timeout/transport failure.
        """

        try:
            # Import via this module alias so tests which monkeypatch
            # foghorn.servers.recursive_resolver.udp_query see the effect here.
            resp = _recursive_module.udp_query(
                server.host,
                int(server.port),
                wire,
                timeout_ms=self._per_try_timeout_ms,
            )
        except (
            Exception
        ) as exc:  # pragma: nocover defensive: UDP transport failures are network/environment dependent and hard to exercise deterministically in tests
            logger.debug("UDP query to %s:%d failed: %s", server.host, server.port, exc)
            return None

        # If TC=1, retry over TCP for a full answer.
        try:
            parsed = DNSRecord.parse(resp)
        except (
            Exception
        ) as exc:  # pragma: nocover defensive: parse failures indicate corrupt upstream packets and are already exercised via higher-level tests
            logger.debug(
                "Failed to parse UDP response from %s:%d: %s",
                server.host,
                server.port,
                exc,
            )
            return None

        if getattr(parsed.header, "tc", 0):
            try:
                # Likewise, use the module alias for tcp_query so tests can
                # safely stub it via monkeypatch without hitting the network.
                resp = _recursive_module.tcp_query(
                    server.host,
                    int(server.port),
                    wire,
                    connect_timeout_ms=self._per_try_timeout_ms,
                    read_timeout_ms=self._per_try_timeout_ms,
                )
            except (
                Exception
            ) as exc:  # pragma: nocover defensive: TCP fallback failures are rare network issues and not worth brittle tests
                logger.debug(
                    "TCP follow-up to %s:%d failed: %s", server.host, server.port, exc
                )
                return None

        return resp

    def _choose_initial_servers(self) -> List[_Server]:
        # Shuffle slightly to avoid always hammering the same root.
        servers = _default_root_hints()
        try:
            random.shuffle(servers)
        except (
            Exception
        ):  # pragma: nocover defensive: random.shuffle failure would indicate interpreter corruption and is not practical to test
            pass
        return servers

    @staticmethod
    def _ttl_from_response(resp: DNSRecord, *, default_ttl: int = 60) -> int:
        """Brief: Best-effort TTL to use when caching a response.

        Inputs:
          - resp: Parsed DNSRecord.
          - default_ttl: Fallback TTL seconds when no TTLs are present.

        Outputs:
          - int: TTL seconds (>= 1).
        """

        try:
            ttls: list[int] = []
            for section in (
                getattr(resp, "rr", None) or [],
                getattr(resp, "auth", None) or [],
                getattr(resp, "ar", None) or [],
            ):
                for rr in section:
                    try:
                        ttl = int(getattr(rr, "ttl", 0) or 0)
                    except (
                        Exception
                    ):  # pragma: nocover defensive: malformed TTL fields are extremely rare and low value to fuzz explicitly
                        ttl = 0
                    if ttl > 0:
                        ttls.append(ttl)
            if ttls:
                return max(1, int(min(ttls)))
        except (
            Exception
        ):  # pragma: nocover defensive: unexpected structure in resp is already exercised via higher-level resolver tests
            pass
        return max(1, int(default_ttl))

    def _extract_next_servers(self, resp: DNSRecord) -> List[_Server]:
        """Brief: Derive next-hop authority servers from an NS referral.

        Inputs:
          - resp: Parsed DNSRecord response from an authority.

        Outputs:
          - List of _Server objects for the next hop, derived from NS records
            and in-message glue (A/AAAA in the additional section).
        """

        auth = getattr(resp, "auth", None) or []
        addl = getattr(resp, "ar", None) or []

        ns_names: List[str] = [
            str(rr.rdata.label) for rr in auth if rr.rtype == QTYPE.NS
        ]
        if not ns_names:
            return []

        # Build a simple glue map from additional A/AAAA records.
        glue: Dict[str, List[_Server]] = {}
        for rr in addl:
            if rr.rtype not in (QTYPE.A, QTYPE.AAAA):
                continue
            name = str(rr.rname).rstrip(".")
            try:
                host = str(rr.rdata)
            except (
                Exception
            ):  # pragma: nocover defensive: bad glue rdata formatting is an upstream data bug and not worth dedicated tests
                continue
            glue.setdefault(name.lower(), []).append(_Server(host, 53))

        servers: List[_Server] = []
        for ns_name in ns_names:
            key = ns_name.rstrip(".").lower()
            servers.extend(glue.get(key, []))

        return servers

    def resolve(self, req: DNSRecord) -> Tuple[bytes, Optional[str]]:
        """Brief: Resolve a single DNSRecord via iterative recursion.

        Inputs:
          - req: DNSRecord representing the original client query.

        Outputs:
          - (wire, upstream_id):
              - wire: Final DNS response bytes.
              - upstream_id: Optional string describing the last authority used
                ("host:port"), suitable for upstream stats.

        Notes:
          - Implements QNAME minimization (RFC 7816/RFC 9156 style) by querying
            for progressively longer suffixes of the QNAME (e.g. "com.",
            "example.com.") before finally querying the full owner name for the
            requested RR type. A simple threshold-based optimisation limits the
            number of minimised queries, and names with leading underscore
            labels (e.g. _service._proto.example.com) are treated with a
            heuristic that skips those underscore-only suffixes when
            minimising.
        """

        q = req.questions[0]
        qname = str(q.qname).rstrip(".")
        qtype = q.qtype

        # Precompute suffixes used for QNAME minimization. For
        # "www.foo.example.com" this yields:
        #   ["www.foo.example.com.", "foo.example.com.", "example.com.", "com."]
        labels = qname.split(".") if qname else []
        if labels:
            suffixes = [".".join(labels[i:]) + "." for i in range(len(labels))]
        else:
            suffixes = ["."]
        zone_index = len(labels) - 1 if labels else 0

        # Count of how many minimised queries (shortened QNAMEs) we have sent so
        # far for this resolution. This is compared against
        # _MAX_MINIMISE_COUNT, but we still allow fine-grained minimisation for
        # the last _MINIMISE_ONE_LAB suffixes near the leaf.
        minimise_count = 0

        # Heuristic: detect a run of leading underscore-prefixed labels (common
        # in SRV-style names such as _service._proto.example.com). We avoid
        # sending separate minimised queries for suffixes that still include
        # only underscore labels before the effective zone, since they tend to
        # be service metadata rather than delegation cut points.
        underscore_prefix = 0
        for lbl in labels:
            if lbl.startswith("_"):
                underscore_prefix += 1
            else:
                break

        servers = self._choose_initial_servers()
        visited: set[Tuple[str, str]] = set()  # (stage_qname, host)
        deadline = time.time() + (self._timeout_ms / 1000.0)

        last_upstream: Optional[str] = None

        for depth in range(self._max_depth):
            if not servers:
                break

            now = time.time()
            if now >= deadline:
                break

            server = servers[0]
            servers = servers[1:]

            # Decide whether to perform a minimised query at this stage. We
            # minimise only when:
            #   - we are not yet at the full QNAME (zone_index > 0),
            #   - we still have a suffix for this index,
            #   - either we have not yet exhausted the global minimisation
            #     budget (_MAX_MINIMISE_COUNT) or we are within the last
            #     _MINIMISE_ONE_LAB suffixes near the leaf, and
            #   - the suffix is not entirely within the leading underscore
            #     prefix (so we do not minimise "_service._proto.example.com"
            #     through the underscore-only suffixes).
            allow_minimise_budget = (
                minimise_count < _MAX_MINIMISE_COUNT or zone_index <= _MINIMISE_ONE_LAB
            )
            allow_minimise_underscore = zone_index >= underscore_prefix

            do_minimise = (
                zone_index > 0
                and suffixes
                and zone_index < len(suffixes)
                and allow_minimise_budget
                and allow_minimise_underscore
            )

            if do_minimise:
                stage_qname = suffixes[zone_index]
                # For compatibility, we keep using NS for these minimisation
                # queries; the answers are only used to discover delegations via
                # authority NS + glue.
                stage_qtype = QTYPE.NS
                is_final = False
            else:
                stage_qname = (
                    qname + "." if qname and not qname.endswith(".") else qname or "."
                )
                stage_qtype = qtype
                is_final = True

            key = (stage_qname.lower(), server.host)
            if key in visited:
                continue
            visited.add(key)

            # Build a stage-specific query with RD=0 as we are the resolver.
            try:
                # dnslib.DNSRecord.question in our version expects the qtype as a
                # string name (e.g. "A", "NS"), not a numeric code. Convert any
                # integer QTYPE values to their textual representation so tests
                # which monkeypatch udp_query see valid wire queries.
                stage_qtype_name = (
                    QTYPE[stage_qtype] if isinstance(stage_qtype, int) else stage_qtype
                )
                stage_req = DNSRecord.question(stage_qname, stage_qtype_name)
            except (
                Exception
            ) as exc:  # pragma: nocover defensive: protects against unexpected dnslib API changes or bad input types
                logger.debug(
                    "Failed to build stage query %s %s: %s",
                    stage_qname,
                    stage_qtype,
                    exc,
                )
                continue
            stage_req.header.rd = 0
            wire = stage_req.pack()

            if not is_final:
                minimise_count += 1

            # For minimization stages (NS lookups), consult the current
            # namespaced cache first. This can reduce repeated root/TLD queries in
            # recursive mode while keeping the final answer flow and upstream_id
            # semantics unchanged.
            resp_wire = None
            if not is_final:
                try:
                    cached = self._ns_cache.get((stage_qname.lower(), int(stage_qtype)))
                    if isinstance(cached, (bytes, bytearray, memoryview)):
                        resp_wire = bytes(cached)
                except (
                    Exception
                ):  # pragma: nocover defensive: cache backend failures should not break resolution and are hard to reproduce portably
                    resp_wire = None

            # Perform the upstream query directly here so that tests which
            # monkeypatch foghorn.servers.recursive_resolver.udp_query/tcp_query can
            # reliably intercept all network operations.
            if resp_wire is None:
                try:
                    resp_wire = _recursive_module.udp_query(
                        server.host,
                        int(server.port),
                        wire,
                        timeout_ms=self._per_try_timeout_ms,
                    )
                except (
                    Exception
                ) as exc:  # pragma: nocover defensive: network/transport failures are highly environment-dependent
                    logger.debug(
                        "UDP query to %s:%d failed: %s", server.host, server.port, exc
                    )
                    continue

            # If TC=1, retry over TCP for a full answer.
            try:
                parsed = DNSRecord.parse(resp_wire)
            except (
                Exception
            ) as exc:  # pragma: nocover defensive: protects against corrupt upstream packets and dnslib quirks
                logger.debug(
                    "Failed to parse UDP response from %s:%d: %s",
                    server.host,
                    server.port,
                    exc,
                )
                continue

            if getattr(parsed.header, "tc", 0):
                try:
                    resp_wire = _recursive_module.tcp_query(
                        server.host,
                        int(server.port),
                        wire,
                        connect_timeout_ms=self._per_try_timeout_ms,
                        read_timeout_ms=self._per_try_timeout_ms,
                    )
                except (
                    Exception
                ) as exc:  # pragma: nocover defensive: TCP fallback network failures are not deterministic enough for stable tests
                    logger.debug(
                        "TCP follow-up to %s:%d failed: %s",
                        server.host,
                        server.port,
                        exc,
                    )
                    continue

            last_upstream = f"{server.host}:{server.port}"

            try:
                resp = DNSRecord.parse(resp_wire)
            except (
                Exception
            ) as exc:  # pragma: nocover defensive: guards against unexpected parse issues in edge cases
                logger.debug(
                    "Failed to parse recursive response from %s: %s", last_upstream, exc
                )
                continue

            # Cache minimization-stage (NS referral) responses in the namespaced
            # cache. Final answers are cached by the outer resolver pipeline.
            if not is_final:
                try:
                    ttl = self._ttl_from_response(resp)
                    self._ns_cache.set(
                        (stage_qname.lower(), int(stage_qtype)), ttl, resp_wire
                    )
                except (
                    Exception
                ):  # pragma: nocover defensive: cache backend write failures should not break recursion and are difficult to force portably
                    pass

            rcode = resp.header.rcode
            has_answer = bool(resp.rr)
            auth = getattr(resp, "auth", None) or []

            if is_final:
                # Final answers: NOERROR with answers, NXDOMAIN, or
                # NOERROR+SOA NODATA.
                if rcode == RCODE.NOERROR and has_answer:
                    return resp_wire, last_upstream
                if rcode == RCODE.NXDOMAIN:
                    return resp_wire, last_upstream
                if rcode == RCODE.NOERROR and not has_answer:
                    has_soa = any(rr.rtype == QTYPE.SOA for rr in auth)
                    if has_soa:
                        return resp_wire, last_upstream

                # Otherwise, try to follow delegations via NS + glue.
                next_servers = self._extract_next_servers(resp)
                if next_servers:
                    servers.extend(next_servers)
                    # Stay in final stage; subsequent queries will keep using
                    # the full QNAME/QTYPE but against more specific
                    # authorities.
                    continue

                # No useful delegation information; fall back to returning this
                # response as-is.
                return resp_wire, last_upstream

            # Minimization stage: only use responses to discover delegations; do
            # not treat rcode directly as the final answer for the original
            # question.
            next_servers = self._extract_next_servers(resp)
            if next_servers:
                servers.extend(next_servers)
                if zone_index > 0:
                    zone_index -= 1
                continue

            # No delegation discovered at this stage. Assume we are already
            # talking to the closest available authority for this branch and
            # switch to the final query (full QNAME + original QTYPE) using the
            # same server set.
            servers.insert(0, server)
            zone_index = 0
            continue

        # If we exhaust depth/timeout/servers, synthesize SERVFAIL.
        r = req.reply()
        r.header.rcode = RCODE.SERVFAIL
        return r.pack(), last_upstream
