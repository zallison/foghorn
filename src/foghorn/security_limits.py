"""Security-related limits and helpers.

Brief:
  Centralizes conservative bounds used to reduce DoS/DDoS impact from oversized
  DNS and DoH requests, as well as helper functions used to detect potentially
  risky listener exposure.

Inputs/Outputs:
  - Provides integer size limits (bytes) and small helper functions.

Notes:
  - These are intentionally internal. Configuration plumbing can override them
    in higher-level modules when needed.
"""

from __future__ import annotations

import ipaddress
import math
from typing import Optional

# DNS-over-TCP maximum message size.
#
# RFC 7766 uses a 16-bit length prefix, so the protocol max is 65535 bytes.
# Keeping this at the protocol max preserves compatibility, while callers may
# choose to enforce a lower operational ceiling.
MAX_DNS_TCP_MESSAGE_BYTES: int = 65535

# DNS message size accepted via DoH (GET/POST).
MAX_DOH_DNS_MESSAGE_BYTES: int = 65535

# Maximum decoded size for the DoH GET "dns=" query parameter.
# This should match MAX_DOH_DNS_MESSAGE_BYTES, but is kept separate to allow
# tuning if desired.
MAX_DOH_QUERY_PARAM_BYTES: int = 65535

# AXFR is length-prefixed DNS over TCP. Keep protocol max by default.
MAX_AXFR_FRAME_BYTES: int = 65535
# Maximum number of buckets allowed for query-log aggregate APIs.
# This bounds memory and CPU used by dense zero-filled bucket responses.
MAX_QUERY_LOG_AGG_BUCKETS: int = 20000
# Maximum number of grouped rows allowed for query-log aggregate APIs.
# This bounds memory and CPU used by high-cardinality sparse grouped responses.
MAX_QUERY_LOG_AGG_GROUPED_RESULTS: int = 50000
# Maximum JSON body size accepted by admin config/restart POST endpoints.
MAX_ADMIN_JSON_BODY_BYTES: int = 5_000_000


def is_loopback_host(host: str) -> bool:
    """Brief: Return True when *host* is loopback-only.

    Inputs:
      - host: Listener bind host string.

    Outputs:
      - bool: True for 127.0.0.0/8 and ::1 and common loopback aliases.

    Notes:
      - Treats empty host as non-loopback (conservative).
      - Treats 'localhost' as loopback.
    """

    if not host:
        return False

    text = str(host).strip().lower()
    if text in {"localhost"}:
        return True

    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False

    return bool(addr.is_loopback)


def clamp_positive_int(value: object, *, default: int, minimum: int = 1) -> int:
    """Brief: Parse an integer config value and clamp to >= minimum.

    Inputs:
      - value: Raw object from config.
      - default: Fallback integer when parsing *value* fails (must be int-castable).
      - minimum: Inclusive minimum value (must be int-castable).

    Outputs:
      - int: Parsed integer clamped to >= minimum.

    Notes:
      - If *default* or *minimum* are not int-castable, conversion exceptions
        propagate to the caller.
    """

    try:
        out = int(value)  # type: ignore[arg-type]
    except Exception:
        out = int(default)
    if out < int(minimum):
        return int(minimum)
    return int(out)


def maybe_parse_content_length(value: Optional[str]) -> int:
    """Brief: Parse Content-Length header safely.

    Inputs:
      - value: Raw header string or None.

    Outputs:
      - int: Parsed positive integer length; returns 0 for missing, invalid, or
        non-positive values.
    """

    if value is None:
        return 0
    try:
        ln = int(str(value).strip())
    except Exception:
        return 0
    return ln if ln > 0 else 0


def compute_query_log_aggregate_bucket_count(
    start_ts: object,
    end_ts: object,
    interval_seconds: object,
) -> int:
    """Brief: Compute the expected number of aggregate buckets for query-log APIs.

    Inputs:
      - start_ts: Inclusive window start timestamp (float-like Unix seconds).
      - end_ts: Exclusive window end timestamp (float-like Unix seconds).
      - interval_seconds: Bucket size in seconds (int-like).

    Outputs:
      - int: Non-negative bucket count. Returns 0 for invalid inputs or
        non-positive/empty windows.
    """

    try:
        start_f = float(start_ts)  # type: ignore[arg-type]
        end_f = float(end_ts)  # type: ignore[arg-type]
    except Exception:
        return 0

    try:
        interval_i = int(interval_seconds)  # type: ignore[arg-type]
    except Exception:
        return 0

    if interval_i <= 0 or end_f <= start_f:
        return 0

    try:
        count = int(math.ceil((end_f - start_f) / float(interval_i)))
    except Exception:
        return 0

    return count if count > 0 else 0


def enforce_query_log_aggregate_bucket_limit(
    start_ts: object,
    end_ts: object,
    interval_seconds: object,
    *,
    max_buckets: int = MAX_QUERY_LOG_AGG_BUCKETS,
) -> int:
    """Brief: Validate and cap aggregate bucket requests to prevent DoS.

    Inputs:
      - start_ts: Inclusive window start timestamp (float-like Unix seconds).
      - end_ts: Exclusive window end timestamp (float-like Unix seconds).
      - interval_seconds: Bucket size in seconds (int-like).
      - max_buckets: Maximum allowed bucket count.

    Outputs:
      - int: Computed bucket count (0 for invalid/empty windows).

    Raises:
      - ValueError: When computed bucket count exceeds max_buckets.
    """

    count = compute_query_log_aggregate_bucket_count(start_ts, end_ts, interval_seconds)

    try:
        max_i = int(max_buckets)
    except Exception:
        max_i = int(MAX_QUERY_LOG_AGG_BUCKETS)
    if max_i < 1:
        max_i = int(MAX_QUERY_LOG_AGG_BUCKETS)

    if count > max_i:
        raise ValueError(
            f"requested bucket count ({count}) exceeds maximum allowed ({max_i}); "
            "reduce the time range or increase interval"
        )

    return count


def enforce_query_log_aggregate_grouped_result_limit(
    grouped_result_count: object,
    *,
    max_grouped_results: int = MAX_QUERY_LOG_AGG_GROUPED_RESULTS,
) -> int:
    """Brief: Validate grouped aggregate result size to prevent DoS.

    Inputs:
      - grouped_result_count: Number of grouped aggregate rows (int-like).
      - max_grouped_results: Maximum allowed grouped row count.

    Outputs:
      - int: Computed grouped row count (0 for invalid inputs).

    Raises:
      - ValueError: When grouped_result_count exceeds max_grouped_results.
    """

    try:
        count = int(grouped_result_count)  # type: ignore[arg-type]
    except Exception:
        count = 0
    if count < 0:
        count = 0

    try:
        max_i = int(max_grouped_results)
    except Exception:
        max_i = int(MAX_QUERY_LOG_AGG_GROUPED_RESULTS)
    if max_i < 1:
        max_i = int(MAX_QUERY_LOG_AGG_GROUPED_RESULTS)

    if count > max_i:
        raise ValueError(
            f"requested grouped result count ({count}) exceeds maximum allowed ({max_i}); "
            "reduce the time range, increase interval, or use a lower-cardinality group_by"
        )

    return count
