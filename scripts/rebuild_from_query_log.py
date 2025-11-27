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
import sys
from typing import Iterable, Optional

from foghorn.stats import StatsSQLiteStore

logger = logging.getLogger(__name__)


def run_rebuild(db_path: str) -> None:
    """Brief: Rebuild counts by delegating to StatsSQLiteStore helper.

    Inputs:
        db_path: Filesystem path to the SQLite stats database file.

    Outputs:
        None; raises on failure.

    Behavior:
        - Opens the stats database using StatsSQLiteStore.
        - Invokes StatsSQLiteStore.rebuild_counts_from_query_log so the script
          uses the same aggregation logic as the live server.
        - Ensures the underlying connection is closed on completion.
    """
    store = StatsSQLiteStore(db_path=db_path)
    try:
        store.rebuild_counts_from_query_log(logger_obj=logger)
    finally:
        store.close()


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
