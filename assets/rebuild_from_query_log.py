#!/usr/bin/env python3
"""
Rebuild the SQLite `counts` table from the `query_log` table for Foghorn statistics.

Inputs:
    - SQLite database path containing `counts` and `query_log` tables.

Outputs:
    - None on success; process exit code 0.
    - Non-zero exit code on failure (error logged to stderr).

Behavior:
    - Acquires an EXCLUSIVE transaction lock for the duration of the rebuild,
      preventing concurrent writers while it runs.
    - Clears the existing `counts` table.
        - Re-aggregates statistics from all rows in `query_log`, including upstream
      outcome and rcode information in the `upstreams` scope keys:
      "upstream_id|outcome|rcode", and per-upstream qtype information in the
      `upstream_qtypes` scope keys: "upstream_id|qtype".
"""

import argparse
import logging
import sqlite3
import sys
from typing import Iterable, Optional

logger = logging.getLogger(__name__)


def normalize_domain(domain: str) -> str:
    """Brief: Normalize domain name for aggregation.

    Inputs:
        domain: Raw domain string (may have trailing dot, mixed case, etc.).

    Outputs:
        str: Lowercase domain without trailing dot.
    """
    return (domain or "").rstrip(".").lower()


def increment_local(
    conn: sqlite3.Connection,
    sql: str,
    scope: str,
    key: str,
    delta: int = 1,
) -> None:
    """Brief: Increment an aggregate counter row in `counts`.

    Inputs:
        conn: Open sqlite3.Connection, inside an explicit transaction.
        sql:  Prepared SQL string using INSERT ... ON CONFLICT ... DO UPDATE.
        scope: Logical scope name (e.g. "totals", "qtypes", "upstreams").
        key:   Counter key string within the scope.
        delta: Increment value (integer, may be negative if needed).

    Outputs:
        None; executes a single SQL statement against `counts`.
    """
    if not scope or not key:
        return
    conn.execute(sql, (scope, key, int(delta)))


def rebuild_counts_from_query_log(conn: sqlite3.Connection) -> None:
    """Brief: Rebuild `counts` by aggregating all rows from `query_log`.

    Inputs:
        conn: sqlite3.Connection with an active transaction.

    Outputs:
        None; mutates the `counts` table in-place.

    Notes:
        - Assumes `BEGIN EXCLUSIVE` (or other write transaction) has already been
          executed on the connection.
        - Clears `counts` before recomputing.
        - Aggregation logic mirrors Foghorn's in-process behavior:
          * totals.total_queries
          * totals.cache_hits / totals.cache_misses
          * qtypes.<qtype>
          * clients.<client_ip>
          * sub_domains.<full_domain>, domains.<base_domain>
          * rcodes.<rcode>
          * upstreams."upstream_id|outcome|rcode"
          * qtype_qnames."qtype|normalized_qname" for all observed qtypes
    """
    # Clear existing counts to start from a clean slate.
    conn.execute("DELETE FROM counts")

    # Single prepared statement reused for all increments.
    insert_sql = (
        "INSERT INTO counts (scope, key, value) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT(scope, key) DO UPDATE SET value = counts.value + excluded.value"
    )

    cur = conn.execute(
        """
        SELECT
            client_ip,
            name,
            qtype,
            upstream_id,
            rcode,
            status,
            error
        FROM query_log
        """
    )

    for (
        client_ip,
        name,
        qtype,
        upstream_id,
        rcode,
        status,
        error,  # noqa: F841  (error is unused but kept for parity)
    ) in cur:  # type: ignore[misc]
        # Normalize domain and compute base domain (last two labels).
        domain = normalize_domain(name or "")
        parts = domain.split(".") if domain else []
        base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        # Total queries
        increment_local(conn, insert_sql, "totals", "total_queries", 1)

        # Cache hits/misses/cache_null (best-effort approximation).
        # These semantics mirror the live StatsCollector behavior:
        # - "cache_hit" rows are treated as cache hits.
        # - Pre-plugin deny/override rows ("deny_pre"/"override_pre")
        #   are treated as "cache_null" since no cache lookup occurs.
        # - All other statuses are treated as cache misses.

        upstream_str: Optional[str] = None
        if upstream_id:
            upstream_str = str(upstream_id)

        status_str = str(status) if status is not None else None
        if status_str == "cache_hit":
            increment_local(conn, insert_sql, "totals", "cache_hits", 1)
        elif status_str in ("deny_pre", "override_pre"):
            increment_local(conn, insert_sql, "totals", "cache_null", 1)
            increment_local(conn, insert_sql, "cache_null", status_str, 1)
        else:
            increment_local(conn, insert_sql, "totals", "cache_misses", 1)

        # Per-outcome cache-domain aggregates using base domains when
        # available so that warm-loaded top lists align with the
        # in-process StatsCollector tracking.
        if base:
            if status_str == "cache_hit":
                increment_local(conn, insert_sql, "cache_hit_domains", base, 1)
                if domain and domain != base:
                    increment_local(
                        conn,
                        insert_sql,
                        "cache_hit_subdomains",
                        base,
                        1,
                    )
            elif status_str not in ("deny_pre", "override_pre"):
                if domain and domain != base:
                    increment_local(
                        conn,
                        insert_sql,
                        "cache_miss_subdomains",
                        base,
                        1,
                    )
                increment_local(conn, insert_sql, "cache_miss_domains", base, 1)

        # Qtype breakdown
        if qtype:
            increment_local(conn, insert_sql, "qtypes", str(qtype), 1)

        # Clients
        if client_ip:
            increment_local(conn, insert_sql, "clients", str(client_ip), 1)

        # Domains and subdomains
        if domain:
            increment_local(conn, insert_sql, "sub_domains", domain, 1)
            if base:
                increment_local(conn, insert_sql, "domains", base, 1)

        # Per-qtype domain counters for all qtypes.
        if domain and qtype:
            key = f"{qtype}|{domain}"
            increment_local(conn, insert_sql, "qtype_qnames", key, 1)

        # Rcodes
        if rcode:
            increment_local(conn, insert_sql, "rcodes", str(rcode), 1)
            if base:
                key = f"{rcode}|{base}"
                increment_local(conn, insert_sql, "rcode_domains", key, 1)
                if domain and domain != base:
                    increment_local(
                        conn,
                        insert_sql,
                        "rcode_subdomains",
                        key,
                        1,
                    )

        # Upstreams: include outcome and rcode in the key, and track qtype.
        if upstream_id:
            upstream_str = str(upstream_id)

            # Approximate outcome classification from status/rcode.
            rcode_str = str(rcode) if rcode is not None else "UNKNOWN"
            outcome = "success"
            if rcode_str != "NOERROR" or (
                status_str and status_str not in ("ok", "cache_hit")
            ):
                outcome = status_str or "fatalError"

            upstream_key = f"{upstream_str}|{outcome}|{rcode_str}"
            increment_local(conn, insert_sql, "upstreams", upstream_key, 1)

            # Per-upstream qtype breakdown: "upstream_id|qtype".
            if qtype:
                upstream_qtype_key = f"{upstream_str}|{qtype}"
                increment_local(
                    conn, insert_sql, "upstream_qtypes", upstream_qtype_key, 1
                )


def run_rebuild(db_path: str) -> None:
    """Brief: Open the SQLite DB, lock it, and rebuild counts.

    Inputs:
        db_path: Filesystem path to the SQLite stats database file.

    Outputs:
        None; raises on failure.

    Behavior:
        - Connects in autocommit mode (isolation_level=None).
        - Applies PRAGMA journal_mode=WAL on a best-effort basis.
        - Executes BEGIN EXCLUSIVE to lock the database for writes while
          rebuilding.
        - Commits on success, rolls back on any exception.
    """
    # isolation_level=None puts the connection in autocommit mode so we can
    # manage transactions manually with explicit BEGIN/COMMIT/ROLLBACK.
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:
            # Best-effort; do not fail the rebuild if PRAGMA is unsupported.
            logger.debug("Failed to set journal_mode=WAL", exc_info=True)

        # Acquire an exclusive write transaction; this effectively locks the DB
        # while we rebuild counts.
        conn.execute("BEGIN EXCLUSIVE TRANSACTION")
        try:
            rebuild_counts_from_query_log(conn)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    """Brief: Parse CLI arguments for the rebuild script.

    Inputs:
        argv: Optional iterable of argument strings; defaults to sys.argv[1:].

    Outputs:
        argparse.Namespace with at least:
            - db_path: Path to SQLite stats DB file.
    """
    parser = argparse.ArgumentParser(
        description="Rebuild Foghorn statistics `counts` table from `query_log` "
        "with upstream outcome+rcode aggregation."
    )
    parser.add_argument(
        "--db",
        "--db-path",
        dest="db_path",
        metavar="PATH",
        default="./config/var/stats.db",
        help="Path to the Foghorn stats SQLite database "
        "(default: ./config/var/stats.db)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging to stderr.",
    )
    return parser.parse_args(list(argv) if argv is not None else sys.argv[1:])


def main(argv: Optional[Iterable[str]] = None) -> int:
    """Brief: CLI entrypoint for counts-table rebuild.

    Inputs:
        argv: Optional iterable of CLI argument strings.

    Outputs:
        int: Exit code (0 on success, non-zero on error).
    """
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    logger.info("Starting counts rebuild for database: %s", args.db_path)
    try:
        run_rebuild(args.db_path)
    except Exception as exc:
        logger.error("Counts rebuild failed: %s", exc, exc_info=True)
        return 1

    logger.info("Counts rebuild completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
