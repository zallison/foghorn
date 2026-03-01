from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from functools import lru_cache
from typing import Optional, Tuple

from dnslib import QTYPE, RCODE, DNSRecord
from pydantic import BaseModel, Field

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)
from foghorn.utils.current_cache import get_current_namespaced_cache, module_namespace

logger = logging.getLogger(__name__)


@lru_cache(maxsize=16384)
def _psl_registrable_domain(qname: str) -> str | None:
    """Brief: Return the PSL registrable domain (a.k.a. eTLD+1) for qname.

    Inputs:
      - qname: Domain name string; may include a trailing dot.

    Outputs:
      - str | None: Registrable domain (e.g. 'example.co.uk', 'user.github.io')
        or None when it cannot be determined.

    Notes:
      - Uses the Public Suffix List via publicsuffix2.
      - Returns None for empty input.
    """

    s = str(qname).strip().rstrip(".").lower()
    if not s:
        return None

    try:
        from publicsuffix2 import get_sld

        # get_sld() returns the registrable domain (eTLD+1) when possible.
        out = get_sld(s)
        if out:
            return str(out).strip().rstrip(".").lower()
        return None
    except Exception:
        # Defensive: on any import/runtime error, fall back to non-PSL behavior
        # in the caller.
        return None


class RateLimitConfig(BaseModel):
    """Brief: Typed configuration model for RateLimit.

    Inputs:
      - mode: 'per_client' (default), 'per_client_domain', or 'per_domain'
        controlling how rate profiles are keyed.
      - window_seconds: Measurement window size in seconds (>= 1).
      - warmup_windows: Number of completed windows to observe before enforcing.
      - alpha: EWMA smoothing factor when the new RPS is >= the learned average
        (controls how quickly we ramp *up*).
      - alpha_down: Optional EWMA factor when the new RPS is < the learned
        average (controls how quickly we ramp *down*). Defaults to alpha when
        omitted.
      - burst_factor: Allowed multiplier over learned average RPS when enforcing.
      - min_enforce_rps: Minimum RPS threshold for enforcement.
      - global_max_rps: Hard upper bound on allowed RPS per key (0 disables).
      - db_path: Path to sqlite3 database storing learned profiles.

      - max_profiles: Maximum number of rows permitted in rate_profiles (>= 1).
      - profile_ttl_seconds: Best-effort TTL for profiles; rows older than this
        are pruned during periodic maintenance (0 disables TTL pruning).
      - prune_interval_seconds: Minimum seconds between prune passes (>= 0).

      - udp_keying: Keying override applied when ctx.listener == 'udp' and the
        request is not secure. Options:
          - 'cidr' (default): bucket client IPs into /udp_client_prefix_v4 or
            /udp_client_prefix_v6 to reduce spoofed-IP cardinality.
          - 'domain': ignore client identity and key only by base domain.
      - udp_client_prefix_v4: IPv4 prefix length used for udp_keying='cidr'.
      - udp_client_prefix_v6: IPv6 prefix length used for udp_keying='cidr'.

      - deny_response: Policy for limited queries ('nxdomain', 'refused', 'servfail',
        'noerror_empty'/'nodata', or 'ip'). Defaults to 'refused'.
      - deny_response_ip4 / deny_response_ip6: Optional IPs used when deny_response=='ip'.
      - ttl: Optional TTL used when synthesizing IP responses.

    Outputs:
      - RateLimitConfig instance with normalized field types.
    """

    mode: str = Field(default="per_client")
    window_seconds: int = Field(default=10, ge=1)
    warmup_windows: int = Field(default=6, ge=0)
    alpha: float = Field(default=0.2, ge=0.0, le=1.0)
    alpha_down: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    burst_factor: float = Field(default=3.0, ge=1.0)
    min_enforce_rps: float = Field(default=50.0, ge=0.0)
    global_max_rps: float = Field(default=5000.0, ge=0.0)
    db_path: str = Field(default="./config/var/rate_limit.db")

    max_profiles: int = Field(default=10000, ge=1)
    profile_ttl_seconds: int = Field(default=7 * 24 * 60 * 60, ge=0)
    prune_interval_seconds: int = Field(default=60, ge=0)

    udp_keying: str = Field(default="cidr")
    udp_client_prefix_v4: int = Field(default=24, ge=0, le=32)
    udp_client_prefix_v6: int = Field(default=56, ge=0, le=128)

    deny_response: str = Field(default="refused")
    deny_response_ip4: Optional[str] = None
    deny_response_ip6: Optional[str] = None
    ttl: int = Field(default=60, ge=0)

    class Config:
        extra = "allow"


@lru_cache(maxsize=16384)
def _to_base_domain(qname: str, base_labels: int = 2) -> str:
    """Brief: Extract a stable base domain for qname (PSL-aware when available).

    Inputs:
      - qname: Fully-qualified domain name string; trailing dot allowed.
      - base_labels: Legacy fallback number of rightmost labels to use when PSL
        parsing is unavailable or inconclusive.

    Outputs:
      - str: Base/registrable domain such as:
          - 'example.com' for 'a.b.example.com.'
          - 'example.co.uk' for 'a.b.example.co.uk.'
          - 'user.github.io' for 'a.user.github.io.'
        When PSL parsing cannot determine a registrable domain, falls back to
        joining the last N labels.

    Notes:
      - This is used by RateLimit keying for per-domain modes, so PSL-awareness
        helps prevent attackers from evading limits by exploiting multi-label
        public suffixes (e.g. *.co.uk).
    """

    psl = _psl_registrable_domain(qname)
    if psl:
        return psl

    # Fallback: last-N labels (previous behavior).
    s = str(qname).rstrip(".").lower()
    labels = [p for p in s.split(".") if p]
    if len(labels) >= base_labels:
        return ".".join(labels[-base_labels:])
    return s


@plugin_aliases("rate_limit", "ratelimit", "rate")
class RateLimit(BasePlugin):
    """Brief: Learning rate limiting plugin with sqlite3-backed per-key baselines.

    Plugins using RateLimit can prevent abusive spikes while allowing
    legitimate sustained high-volume traffic. The plugin learns a per-key
    baseline requests-per-second (RPS) and only enforces when the current
    window rate is a clear outlier relative to the learned average.
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - RateLimitConfig class for use by the core config loader.
        """

        return RateLimitConfig

    def setup(self) -> None:
        """Brief: Initialize caches, configuration, and sqlite3 profile database.

        Inputs:
          - None (reads configuration from self.config set by BasePlugin).

        Outputs:
          - None (sets up window cache, DB connection, and parsed thresholds).
        """

        # Parse mode
        raw_mode = str(self.config.get("mode", "per_client")).strip().lower()
        if raw_mode not in {"per_client", "per_client_domain", "per_domain"}:
            logger.warning("RateLimit: invalid mode %r; using 'per_client'", raw_mode)
            raw_mode = "per_client"
        self.mode = raw_mode

        # Spoofing-aware keying for UDP (best-effort).
        raw_udp_keying = str(self.config.get("udp_keying", "cidr") or "cidr").lower()
        if raw_udp_keying not in {"cidr", "domain"}:
            logger.warning(
                "RateLimit: invalid udp_keying %r; using 'cidr'",
                raw_udp_keying,
            )
            raw_udp_keying = "cidr"
        self.udp_keying = raw_udp_keying

        self.udp_client_prefix_v4 = self._parse_int_config(
            "udp_client_prefix_v4",
            24,
            minimum=0,
        )
        self.udp_client_prefix_v6 = self._parse_int_config(
            "udp_client_prefix_v6",
            56,
            minimum=0,
        )
        # Clamp prefix bounds explicitly.
        self.udp_client_prefix_v4 = max(0, min(32, int(self.udp_client_prefix_v4)))
        self.udp_client_prefix_v6 = max(0, min(128, int(self.udp_client_prefix_v6)))

        # sqlite bounds / pruning knobs.
        self.max_profiles = self._parse_int_config("max_profiles", 10000, minimum=1)
        self.profile_ttl_seconds = self._parse_int_config(
            "profile_ttl_seconds",
            7 * 24 * 60 * 60,
            minimum=0,
        )
        self.prune_interval_seconds = self._parse_int_config(
            "prune_interval_seconds",
            60,
            minimum=0,
        )
        self._last_prune_ts: int = 0

        # Numeric configuration with defensive parsing
        self.window_seconds = self._parse_int_config("window_seconds", 10, minimum=1)
        self.warmup_windows = self._parse_int_config("warmup_windows", 6, minimum=0)
        self.alpha = self._parse_float_config("alpha", 0.2, minimum=0.0, maximum=1.0)
        # Separate alpha for downward adjustments; default to alpha when not set.
        self.alpha_down = self._parse_float_config(
            "alpha_down", self.alpha, minimum=0.0, maximum=1.0
        )
        self.burst_factor = self._parse_float_config("burst_factor", 3.0, minimum=1.0)
        self.min_enforce_rps = self._parse_float_config(
            "min_enforce_rps", 50.0, minimum=0.0
        )
        self.global_max_rps = self._parse_float_config(
            "global_max_rps", 5000.0, minimum=0.0
        )

        # Deny policy configuration
        deny_resp = str(
            self.config.get("deny_response", "refused") or "refused"
        ).lower()
        valid_deny = {
            "nxdomain",
            "refused",
            "servfail",
            "noerror_empty",
            "nodata",
            "ip",
        }
        if deny_resp not in valid_deny:
            logger.warning(
                "RateLimit: unknown deny_response %r; defaulting to 'refused'",
                deny_resp,
            )
            deny_resp = "refused"
        self.deny_response: str = deny_resp
        self.deny_response_ip4: Optional[str] = self.config.get("deny_response_ip4")
        self.deny_response_ip6: Optional[str] = self.config.get("deny_response_ip6")

        # TTL for synthetic IP responses when deny_response == 'ip'
        try:
            self._ttl = int(self.config.get("ttl", 60))
        except (
            TypeError,
            ValueError,
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            self._ttl = 60

        # Per-key rolling window counters (key -> "window_id:count")
        self._window_cache = get_current_namespaced_cache(
            namespace=module_namespace(__file__),
            cache_plugin=self.config.get("cache"),
        )

        # SQLite-backed learned profiles
        cfg_db_path = self.config.get("db_path", "./config/var/rate_limit.db")
        self.db_path: str = str(cfg_db_path or "./config/var/rate_limit.db")
        self._db_lock = threading.Lock()
        self._db_init()

    def _parse_int_config(self, key: str, default: int, minimum: int = 0) -> int:
        """Brief: Parse integer configuration with clamping and logging.

        Inputs:
          - key: Name of the configuration key.
          - default: Fallback value when parsing fails.
          - minimum: Inclusive minimum allowed value.

        Outputs:
          - int: Parsed and clamped integer value.
        """

        raw = self.config.get(key, default)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            logger.warning("RateLimit: %s non-integer %r; using %d", key, raw, default)
            return default
        if value < minimum:
            logger.warning(
                "RateLimit: %s below minimum %d (%d); clamping",
                key,
                minimum,
                value,
            )
            return minimum
        return value

    def _parse_float_config(
        self,
        key: str,
        default: float,
        minimum: float = 0.0,
        maximum: Optional[float] = None,
    ) -> float:
        """Brief: Parse float configuration with range clamping and logging.

        Inputs:
          - key: Configuration key name.
          - default: Fallback value when parsing fails.
          - minimum: Inclusive minimum allowed value.
          - maximum: Optional inclusive maximum allowed value.

        Outputs:
          - float: Parsed and clamped float value.
        """

        raw = self.config.get(key, default)
        try:
            value = float(raw)
        except (TypeError, ValueError):
            logger.warning("RateLimit: %s non-float %r; using %s", key, raw, default)
            return default
        if value < minimum:
            logger.warning(
                "RateLimit: %s below minimum %s (%s); clamping",
                key,
                minimum,
                value,
            )
            value = minimum
        if maximum is not None and value > maximum:
            logger.warning(
                "RateLimit: %s above maximum %s (%s); clamping",
                key,
                maximum,
                value,
            )
            value = maximum
        return value

    def _db_init(self) -> None:
        """Brief: Initialize sqlite3 database for learned rate profiles.

        Inputs:
          - None

        Outputs:
          - None (creates self._conn and the rate_profiles table).

        Notes:
          - The database is bounded via best-effort pruning in _maybe_prune_db().
        """

        dir_path = os.path.dirname(self.db_path)
        if dir_path:
            try:
                os.makedirs(dir_path, exist_ok=True)
            except Exception as exc:  # pragma: no cover - defensive: log-only path
                logger.warning(
                    "RateLimit: failed to create directory for db_path %s: %s",
                    self.db_path,
                    exc,
                )

        with self._db_lock:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS rate_profiles ("
                "key TEXT PRIMARY KEY, "
                "avg_rps REAL NOT NULL, "
                "max_rps REAL NOT NULL, "
                "samples INTEGER NOT NULL, "
                "last_update INTEGER NOT NULL"
                ")"
            )
            # Index to support efficient pruning and stats inspection.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rate_profiles_last_update "
                "ON rate_profiles(last_update)"
            )
            self._conn.commit()

    def _db_get_profile(self, key: str) -> Optional[Tuple[float, float, int]]:
        """Brief: Load (avg_rps, max_rps, samples) for a key from sqlite.

        Inputs:
          - key: Normalized profile key string.

        Outputs:
          - Optional (avg_rps, max_rps, samples) tuple; None when no profile or row is malformed.
        """

        with self._db_lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT avg_rps, max_rps, samples FROM rate_profiles WHERE key=?",
                (key,),
            )
            row = cur.fetchone()
        if not row:
            return None
        try:
            if row[0] is None or row[1] is None or row[2] is None:
                raise TypeError("RateLimit: NULL fields in rate_profiles row")
            return float(row[0]), float(row[1]), int(row[2])
        except Exception as exc:  # pragma: no cover - defensive: malformed DB rows
            logger.warning(
                "RateLimit: ignoring malformed rate_profiles row for %s: %s",
                key,
                exc,
            )
            return None

    def _maybe_prune_db(self, *, now_ts: int) -> None:
        """Brief: Best-effort pruning to bound sqlite3 growth.

        Inputs:
          - now_ts: Current epoch seconds used for TTL comparisons.

        Outputs:
          - None. May delete old rows and/or cap the total row count.

        Notes:
          - Pruning is intentionally best-effort and must never raise.
          - TTL pruning is controlled via profile_ttl_seconds (0 disables).
          - Row-count bounding is controlled via max_profiles.
          - prune_interval_seconds throttles how often this runs.
        """

        try:
            if int(self.prune_interval_seconds) > 0 and int(now_ts) - int(
                getattr(self, "_last_prune_ts", 0) or 0
            ) < int(self.prune_interval_seconds):
                return
        except Exception:
            # If throttling fails, err on the side of skipping pruning.
            return

        with self._db_lock:
            cur = self._conn.cursor()

            # TTL-based pruning.
            try:
                ttl = int(getattr(self, "profile_ttl_seconds", 0) or 0)
            except Exception:
                ttl = 0
            if ttl > 0:
                try:
                    cutoff = int(now_ts) - ttl
                    cur.execute(
                        "DELETE FROM rate_profiles WHERE last_update < ?",
                        (int(cutoff),),
                    )
                except Exception:
                    pass

            # Row-count bound.
            try:
                max_rows = int(getattr(self, "max_profiles", 10000) or 10000)
            except Exception:
                max_rows = 10000
            if max_rows < 1:
                max_rows = 1

            try:
                cur.execute("SELECT COUNT(*) FROM rate_profiles")
                row = cur.fetchone()
                total = int(row[0]) if row and row[0] is not None else 0
            except Exception:
                total = 0

            if total > max_rows:
                try:
                    excess = int(total - max_rows)
                    # Delete the oldest rows first.
                    cur.execute(
                        "DELETE FROM rate_profiles WHERE key IN ("
                        "SELECT key FROM rate_profiles ORDER BY last_update ASC LIMIT ?"
                        ")",
                        (int(excess),),
                    )
                except Exception:
                    pass

            try:
                self._conn.commit()
            except Exception:
                pass

        try:
            self._last_prune_ts = int(now_ts)
        except Exception:
            self._last_prune_ts = 0

    def _db_update_profile(self, key: str, rps: float, now_ts: int) -> None:
        """Brief: Update or insert the learned profile for a key.

        Inputs:
          - key: Normalized key string.
          - rps: Observed requests-per-second in the completed window.
          - now_ts: Epoch seconds of the update time.

        Outputs:
          - None (persists updated avg_rps, max_rps, and samples).
        """

        with self._db_lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT avg_rps, max_rps, samples FROM rate_profiles WHERE key=?",
                (key,),
            )
            row = cur.fetchone()
            if not row or row[0] is None or row[1] is None or row[2] is None:
                # Treat missing or partially-null rows as if they do not exist,
                # resetting the profile based on the current observation.
                cur.execute(
                    "INSERT OR REPLACE INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (key, float(rps), float(rps), 1, int(now_ts)),
                )
            else:
                try:
                    avg_rps, max_rps, samples = (
                        float(row[0]),
                        float(row[1]),
                        int(row[2]),
                    )
                except Exception:
                    # Malformed existing row; reset it using the current observation.
                    cur.execute(
                        "INSERT OR REPLACE INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (key, float(rps), float(rps), 1, int(now_ts)),
                    )
                else:
                    # Use asymmetric smoothing so we can ramp up and down at different rates.
                    if float(rps) >= avg_rps:
                        alpha = float(self.alpha)
                    else:
                        alpha = float(getattr(self, "alpha_down", self.alpha))
                    new_avg = (1.0 - alpha) * avg_rps + alpha * float(rps)
                    new_max = max(max_rps, float(rps))
                    new_samples = samples + 1
                    cur.execute(
                        "UPDATE rate_profiles SET avg_rps=?, max_rps=?, samples=?, last_update=? "
                        "WHERE key=?",
                        (new_avg, new_max, new_samples, int(now_ts), key),
                    )
            self._conn.commit()

        # Best-effort pruning outside of the DB lock critical path.
        try:
            self._maybe_prune_db(now_ts=int(now_ts))
        except Exception:
            pass

    def _client_ip_bucket(self, client_ip: str) -> str:
        """Brief: Bucket a client IP into a CIDR prefix to reduce key cardinality.

        Inputs:
          - client_ip: Client IP string (IPv4 or IPv6).

        Outputs:
          - str: Canonical CIDR string like '192.0.2.0/24' or '2001:db8::/56'.

        Notes:
          - This is best-effort. On parse failures it returns the original client_ip.
        """

        try:
            import ipaddress

            ip_obj = ipaddress.ip_address(str(client_ip).strip())
            if ip_obj.version == 4:
                prefix = int(getattr(self, "udp_client_prefix_v4", 24) or 24)
            else:
                prefix = int(getattr(self, "udp_client_prefix_v6", 56) or 56)
            prefix = max(0, min(32 if ip_obj.version == 4 else 128, prefix))
            net = ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False)
            return str(net)
        except Exception:
            return str(client_ip)

    def _make_key(self, qname: str, ctx: PluginContext) -> str:
        """Brief: Build the profiling key according to the configured mode.

        Inputs:
          - qname: Queried domain name.
          - ctx: PluginContext providing client_ip.

        Outputs:
          - str: Normalized key string (e.g., '1.2.3.4' or '1.2.3.0/24|example.com').

        Notes:
          - When ctx.listener == 'udp' and ctx.secure is falsey, the keying can be
            overridden via udp_keying to reduce spoofed-source cardinality.
        """

        client_ip = getattr(ctx, "client_ip", "") or "unknown"
        listener = str(getattr(ctx, "listener", "") or "").lower()
        secure = bool(getattr(ctx, "secure", False))

        # Spoofing-aware UDP overrides.
        if listener == "udp" and not secure:
            udp_keying = str(getattr(self, "udp_keying", "cidr") or "cidr").lower()
            if udp_keying == "domain":
                # Ignore client identity entirely for UDP.
                return _to_base_domain(qname)
            # Default: bucket client IP.
            client_ip = self._client_ip_bucket(str(client_ip))

        if self.mode == "per_client_domain":
            base = _to_base_domain(qname)
            return f"{client_ip}|{base}"
        if self.mode == "per_domain":
            return _to_base_domain(qname)
        return str(client_ip)

    def _increment_window(
        self, key: str, now: Optional[float] = None
    ) -> Tuple[int, int]:
        """Brief: Increment per-key counter for the current window and update profile.

        Inputs:
          - key: Normalized key string.
          - now: Optional current time override (epoch seconds).

        Outputs:
          - (window_id, count): Tuple of current window identifier and count after increment.
        """

        if now is None:
            now = time.time()
        window_id = int(now // float(self.window_seconds))
        cache_key = (key, 0)

        raw = self._window_cache.get(cache_key)
        prev_window_id: Optional[int] = None
        prev_count: Optional[int] = None

        if raw is None:
            # First observation for this key.
            count = 1
        else:
            try:
                text = raw.decode()
                stored_window_str, stored_count_str = text.split(":", 1)
                stored_window_id = int(stored_window_str)
                stored_count = int(stored_count_str)
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                stored_window_id = window_id
                stored_count = 0

            if stored_window_id == window_id:
                count = stored_count + 1
            else:
                # Completed window; update profile from the previous window before
                # starting a new one.
                prev_window_id = stored_window_id
                prev_count = stored_count
                count = 1

        # Persist the updated window counter with a TTL slightly larger than a single window.
        ttl = max(self.window_seconds * 2, self.window_seconds + 1)
        try:
            payload = f"{window_id}:{count}".encode()
            self._window_cache.set(cache_key, int(ttl), payload)
        except Exception:  # pragma: no cover - defensive logging only
            logger.debug("RateLimit: failed updating window cache for %s", key)

        # If we have a completed window, update the learned profile in sqlite.
        if prev_window_id is not None and prev_count is not None and prev_count > 0:
            rps = float(prev_count) / float(self.window_seconds)
            now_ts = int(now)
            try:
                self._db_update_profile(key, rps, now_ts)
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                logger.warning("RateLimit: failed to update profile for %s", key)

        return window_id, count

    def _build_deny_decision(
        self,
        qname: str,
        qtype: int,
        raw_req: bytes,
        ctx: PluginContext,
    ) -> PluginDecision:
        """Brief: Build a PluginDecision for a rate-limited query.

        Inputs:
          - qname: Queried domain name.
          - qtype: DNS query type integer.
          - raw_req: Raw DNS request wire bytes.
          - ctx: PluginContext for the request.

        Outputs:
          - PluginDecision with action 'deny' or 'override' based on configuration.
        """

        mode = (getattr(self, "deny_response", "refused") or "refused").lower()
        if mode == "nxdomain":
            return PluginDecision(action="deny", stat="rate_limit")

        if mode in {"refused", "servfail", "noerror_empty", "nodata"}:
            try:
                req = DNSRecord.parse(raw_req)
            except (
                Exception
            ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                logger.warning(
                    "RateLimit: failed to parse request while building deny response: %s",
                    exc,
                )
                return PluginDecision(action="deny")

            reply = req.reply()
            if mode == "refused":
                reply.header.rcode = RCODE.REFUSED
            elif mode == "servfail":
                reply.header.rcode = RCODE.SERVFAIL
            else:
                reply.header.rcode = RCODE.NOERROR
                # Produce NOERROR with no answers (NODATA-style response)
                reply.rr = []
            return PluginDecision(
                action="override",
                response=reply.pack(),
                stat="rate_limit",
            )

        if mode == "ip":
            ipaddr: Optional[str] = None
            if qtype == QTYPE.A and self.deny_response_ip4:
                ipaddr = str(self.deny_response_ip4)
            elif qtype == QTYPE.AAAA and self.deny_response_ip6:
                ipaddr = str(self.deny_response_ip6)
            elif self.deny_response_ip4 or self.deny_response_ip6:
                ipaddr = str(self.deny_response_ip4 or self.deny_response_ip6)

            if ipaddr:
                wire = self._make_a_response(qname, qtype, raw_req, ctx, ipaddr)
                if wire is not None:
                    return PluginDecision(
                        action="override",
                        response=wire,
                        stat="rate_limit",
                    )

        # Fallback: simple deny (refused by default)
        return PluginDecision(action="deny", stat="rate_limit")

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Apply learning rate limits before DNS resolution.

        Inputs:
          - qname: Queried domain name.
          - qtype: DNS query type integer.
          - req: Raw DNS request wire bytes.
          - ctx: PluginContext with client_ip and metadata.

        Outputs:
          - PluginDecision when current RPS is a clear outlier above the learned
            baseline and exceeds global thresholds; otherwise None.
        """

        if not self.targets(ctx):
            return None

        client_ip = getattr(ctx, "client_ip", None)
        if not client_ip:
            # Without a usable client identity, do not attempt to rate-limit.
            return None

        key = self._make_key(qname, ctx)
        now = time.time()

        # Update per-window counters and learn from the previous window if complete.
        _, count = self._increment_window(key, now=now)
        current_rps = float(count) / float(self.window_seconds)

        profile = None
        try:
            profile = self._db_get_profile(key)
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.warning(
                "RateLimit: failed to load profile for %s: %s",
                key,
                exc,
                exc_info=True,
            )

        if not profile:
            # No baseline yet; learning-only phase.
            return None

        avg_rps, _max_rps, samples = profile

        # Require at least warmup_windows completed windows before enforcing.
        if samples < int(self.warmup_windows):
            return None

        # Derive allowed RPS from learned average plus configured caps.
        allowed_rps = max(
            avg_rps * float(self.burst_factor), float(self.min_enforce_rps)
        )
        if self.global_max_rps > 0.0:
            allowed_rps = min(allowed_rps, float(self.global_max_rps))

        if current_rps <= allowed_rps:
            return None

        logger.info(
            "RateLimit: limiting key=%s current_rps=%.2f avg_rps=%.2f allowed_rps=%.2f",
            key,
            current_rps,
            avg_rps,
            allowed_rps,
        )
        return self._build_deny_decision(qname, qtype, req, ctx)
