from __future__ import annotations

import logging
import math
import os
import sqlite3
import threading
import time
from typing import Mapping, Optional, Tuple

from dnslib import QTYPE, RCODE, DNSRecord
from pydantic import BaseModel, Field, ConfigDict, model_validator
from foghorn.plugins.resolve.admin_ui import config_to_items
from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache
from foghorn.plugins.cache.none import NullCache

from foghorn.plugins.resolve.base import (
    AdminPageSpec,
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)
from foghorn.utils.current_cache import (
    TTLCacheAdapter,
    get_current_namespaced_cache,
    module_namespace,
)
from foghorn.utils import dns_names, ip_networks
from foghorn.utils.register_caches import registered_lru_cache

logger = logging.getLogger(__name__)
_GLOBAL_RPS_DB_KEY = "global"


@registered_lru_cache(maxsize=16384)
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

    s = dns_names.normalize_name(qname)
    if not s:
        return None

    try:
        from publicsuffix2 import get_sld

        # get_sld() returns the registrable domain (eTLD+1) when possible.
        out = get_sld(s)
        if out:
            return dns_names.normalize_name(out)
        return None
    except Exception:
        # Defensive: on any import/runtime error, fall back to non-PSL behavior
        # in the caller.
        return None


def _psl_is_available() -> bool:
    """Brief: Return True when publicsuffix2 PSL extraction is available.

    Inputs:
      - None.

    Outputs:
      - bool: True when publicsuffix2 imports and get_sld is callable.
    """

    try:
        from publicsuffix2 import get_sld  # noqa: F401

        return True
    except Exception:
        return False


def _normalize_prefix_length_value(value: object) -> object:
    """Brief: Normalize optional CIDR-style slash prefix strings.

    Inputs:
      - value: Raw configuration value that may be a string like '/32' or '32'.

    Outputs:
      - object: Normalized value with one leading slash removed for string inputs;
        non-string values are returned unchanged.
    """

    if not isinstance(value, str):
        return value

    text = value.strip()
    if text.startswith("/"):
        return text[1:].strip()
    return text


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
      - burst_windows: Number of consecutive burst windows allowed before the
        burst factor is disabled (0 means unlimited).
      - burst_reset_windows: Number of consecutive completed windows at or below
        threshold required to reset burst state back to zero.
      - min_enforce_rps: Minimum RPS threshold for enforcement.
      - min_burst_threshold: Minimum burst-threshold floor used when deriving
        avg_rps * burst_factor; defaults to min_boot_rps/min_boost_rps when
        provided, otherwise defaults to min_enforce_rps.
      - min_boot_rps: Deprecated alias for min_burst_threshold.
      - min_boost_rps: Deprecated alias for min_burst_threshold.
      - max_enforce_rps: Hard upper bound on allowed RPS per key (0 disables).
      - global_max_rps: Optional hard upper bound on total RPS across all keys
        (0 disables).
      - db_path: Path to sqlite3 database storing learned profiles.

      - max_profiles: Maximum number of rows permitted in rate_profiles (>= 1).
      - active_window_max_keys: Maximum number of keys tracked in-memory for the
        currently active request window (>= 1). This bounds request-path memory
        overhead for admin snapshot visibility and rollover flush handling.
      - profile_ttl_seconds: Best-effort TTL for profiles; rows older than this
        are pruned during periodic maintenance (0 disables TTL pruning).
      - prune_interval_seconds: Minimum seconds between prune passes (>= 0).

      - assume_udp_when_listener_missing: When True, treat missing/unknown
        listener values on insecure transports as UDP for spoofing mitigation.
      - bucket_network_prefix_v4: IPv4 prefix length used for UDP client-IP
        bucketing on insecure transports.
      - bucket_network_prefix_v6: IPv6 prefix length used for UDP client-IP
        bucketing on insecure transports.
      - limit_recalc_windows: Number of completed windows between per-bucket
        allowed-RPS recalculations. Default 10 windows.
      - warmup_max_rps: Optional hard RPS cap enforced during warmup
        (0 disables).
      - bootstrap_rps: Optional baseline RPS used to seed profiles when
        no historical samples exist. When omitted, defaults to global_max_rps
        when explicitly set; otherwise defaults to 50. Set to 0 to disable
        bootstrap seeding.

      - deny_response: Policy for limited queries ('nxdomain', 'refused', 'servfail',
        'noerror_empty'/'nodata', 'ip', or 'drop'). Defaults to 'nxdomain'.
      - deny_response_ip4 / deny_response_ip6: Optional IPs used when deny_response=='ip'.
      - ttl: Optional TTL used when synthesizing IP responses.
      - stats_log_interval_seconds: Interval for periodic rate-limit summary logs
        (0 disables).
      - stats_window_seconds: Optional lookback window in seconds applied when
        computing periodic summary avg/max values (0 uses all profiles).
      - deny_log_interval_seconds: Minimum seconds between per-key deny log
        messages (0 logs every deny; default 60).  Suppressed denies are
        counted and the total is included in the next emitted message.
      - deny_log_first_n: Number of denied queries to write a persistent
        query-log row for at the start of each blocked episode per key.
        After this many logged denies the query-log row is suppressed for the
        remainder of the episode; counting resets when the key's rate drops
        back below the allowed threshold.  0 suppresses all query-log rows
        for rate-limited queries (previous behavior).  Default 3.
      - psl_strict: When True, fail startup if PSL extraction is unavailable
        in domain-based modes.

    Outputs:
      - RateLimitConfig instance with normalized field types.
    """

    mode: str = Field(default="per_client")
    window_seconds: int = Field(default=10, ge=1)
    warmup_windows: int = Field(default=6, ge=0)
    alpha: float = Field(default=0.2, ge=0.0, le=1.0)
    alpha_down: Optional[float] = Field(default=0.2, ge=0.0, le=1.0)
    burst_factor: float = Field(default=3.0, ge=1.0)
    burst_windows: int = Field(default=6, ge=0)
    burst_reset_windows: int = Field(default=20, ge=1)
    min_enforce_rps: float = Field(default=50.0, ge=0.0)
    min_burst_threshold: Optional[float] = Field(default=None, ge=0.0)
    max_enforce_rps: float = Field(default=5000.0, ge=0.0)
    global_max_rps: float = Field(default=0.0, ge=0.0)
    db_path: str = Field(default="./config/var/dbs/rate_limit.db")

    max_profiles: int = Field(default=10000, ge=1)
    active_window_max_keys: int = Field(default=2048, ge=1)
    profile_ttl_seconds: int = Field(default=7 * 24 * 60 * 60, ge=0)
    prune_interval_seconds: int = Field(default=60, ge=0)

    assume_udp_when_listener_missing: bool = Field(default=True)
    bucket_network_prefix_v4: int = Field(default=24, ge=0, le=32)
    bucket_network_prefix_v6: int = Field(default=56, ge=0, le=128)
    limit_recalc_windows: int = Field(default=10, ge=1)
    warmup_max_rps: float = Field(default=0.0, ge=0.0)
    bootstrap_rps: float = Field(default=50.0, ge=0.0)

    deny_response: str = Field(default="nxdomain")
    deny_response_ip4: Optional[str] = None
    deny_response_ip6: Optional[str] = None
    ttl: int = Field(default=60, ge=0)
    stats_log_interval_seconds: int = Field(default=3600, ge=0)
    stats_window_seconds: int = Field(default=0, ge=0)
    deny_log_interval_seconds: int = Field(default=60, ge=0)
    deny_log_first_n: int = Field(default=3, ge=0)
    psl_strict: bool = Field(default=False)

    @model_validator(mode="before")
    @classmethod
    def _normalize_min_boot_rps_alias(cls, data: object) -> object:
        """Brief: Map deprecated min_boot_rps/min_boost_rps to min_burst_threshold.

        Inputs:
          - data: Raw configuration payload before field validation.

        Outputs:
          - object: Configuration payload with min_burst_threshold populated
            from min_boot_rps/min_boost_rps when min_burst_threshold is unset.
        """

        if not isinstance(data, Mapping):
            return data
        if "min_burst_threshold" in data:
            return data
        if "min_boot_rps" not in data and "min_boost_rps" not in data:
            return data

        out = dict(data)
        out["min_burst_threshold"] = data.get("min_boot_rps", data.get("min_boost_rps"))
        return out

    @model_validator(mode="before")
    @classmethod
    def _reject_client_prefix_keys(cls, data: object) -> object:
        """Brief: Reject removed RateLimit config keys.

        Inputs:
          - data: Raw configuration payload before field validation.

        Outputs:
          - object: Unmodified data when no removed keys are present.
        """

        if isinstance(data, Mapping):
            disallowed = [
                key
                for key in ("client_prefix_v4", "client_prefix_v6", "udp_keying")
                if key in data
            ]
            if disallowed:
                keys = ", ".join(f"'{key}'" for key in disallowed)
                raise ValueError(
                    f"unsupported config key(s) {keys}; "
                    "use UDP prefix bucketing via "
                    "'bucket_network_prefix_v4' and/or "
                    "'bucket_network_prefix_v6'."
                )
        return data

    @model_validator(mode="before")
    @classmethod
    def _normalize_bucket_network_prefix_v4(cls, data: object) -> object:
        """Brief: Accept '/N' form for bucket_network_prefix_v4.

        Inputs:
          - data: Raw configuration payload before field validation.

        Outputs:
          - object: Configuration payload with bucket_network_prefix_v4 normalized.
        """

        if not isinstance(data, Mapping):
            return data
        if "bucket_network_prefix_v4" not in data:
            return data

        out = dict(data)
        out["bucket_network_prefix_v4"] = _normalize_prefix_length_value(
            data.get("bucket_network_prefix_v4")
        )
        return out

    @model_validator(mode="after")
    def _default_dynamic_thresholds(self) -> "RateLimitConfig":
        """Brief: Populate dependent defaults from already-parsed fields.

        Inputs:
          - self: Fully parsed RateLimitConfig model instance.

        Outputs:
          - RateLimitConfig: Model with dependent defaults populated when unset.
        """

        if "bootstrap_rps" not in self.model_fields_set:
            if "global_max_rps" in self.model_fields_set:
                self.bootstrap_rps = float(self.global_max_rps)
            else:
                self.bootstrap_rps = 50.0
        if "min_burst_threshold" not in self.model_fields_set:
            self.min_burst_threshold = float(self.min_enforce_rps)
        return self

    model_config = ConfigDict(extra="allow")


@registered_lru_cache(maxsize=16384)
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
    s = dns_names.normalize_name(qname)
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

    Notes:
      - Listener-level transport limits (for example max_in_flight) are
        enforced outside this plugin and can apply before RateLimit thresholds.
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
            logger.warning("invalid mode configured; using 'per_client'")
            raw_mode = "per_client"
        self.mode = raw_mode
        # PSL availability guard for domain-based modes.
        self._psl_available = bool(_psl_is_available())
        if self.mode in {"per_client_domain", "per_domain"} and not self._psl_available:
            psl_strict = self._parse_bool_config("psl_strict", False)
            msg = (
                "publicsuffix2 not available; domain-based mode "
                f"{self.mode!r} is unsafe for multi-label public suffixes."
            )
            if psl_strict:
                raise RuntimeError(msg)
            logger.warning("%s Switching mode to 'per_client'.", msg)
            self.mode = "per_client"

        # Spoofing-aware keying for UDP (best-effort).
        self.assume_udp_when_listener_missing = self._parse_bool_config(
            "assume_udp_when_listener_missing",
            True,
        )
        self._missing_listener_warned = False

        cfg_map = dict(self.config or {})
        disallowed_client_prefix = [
            key
            for key in ("client_prefix_v4", "client_prefix_v6", "udp_keying")
            if key in cfg_map
        ]
        if disallowed_client_prefix:
            keys = ", ".join(f"'{key}'" for key in disallowed_client_prefix)
            raise ValueError(
                f"unsupported config key(s) {keys}; "
                "use UDP prefix bucketing via "
                "'bucket_network_prefix_v4' and/or "
                "'bucket_network_prefix_v6'."
            )

        self.bucket_network_prefix_v4 = self._parse_int_config(
            "bucket_network_prefix_v4",
            24,
            minimum=0,
        )
        self.bucket_network_prefix_v6 = self._parse_int_config(
            "bucket_network_prefix_v6",
            56,
            minimum=0,
        )
        # Clamp prefix bounds explicitly.
        self.bucket_network_prefix_v4 = max(
            0, min(32, int(self.bucket_network_prefix_v4))
        )
        self.bucket_network_prefix_v6 = max(
            0, min(128, int(self.bucket_network_prefix_v6))
        )
        self.limit_recalc_windows = self._parse_int_config(
            "limit_recalc_windows",
            10,
            minimum=1,
        )

        # sqlite bounds / pruning knobs.
        self.max_profiles = self._parse_int_config("max_profiles", 10000, minimum=1)
        active_window_default = min(int(self.max_profiles), 2048)
        self.active_window_max_keys = self._parse_int_config(
            "active_window_max_keys",
            int(active_window_default),
            minimum=1,
        )
        if int(self.active_window_max_keys) > int(self.max_profiles):
            logger.warning(
                "active_window_max_keys (%d) exceeds max_profiles (%d); clamping",
                int(self.active_window_max_keys),
                int(self.max_profiles),
            )
        self._active_window_max_keys = max(
            1,
            min(int(self.active_window_max_keys), int(self.max_profiles)),
        )
        self.active_window_max_keys = int(self._active_window_max_keys)
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
        self.burst_windows = self._parse_int_config("burst_windows", 6, minimum=0)
        self.burst_reset_windows = self._parse_int_config(
            "burst_reset_windows",
            20,
            minimum=1,
        )
        self.min_enforce_rps = self._parse_float_config(
            "min_enforce_rps", 50.0, minimum=0.0
        )
        min_boot_rps = self._parse_float_config(
            "min_boot_rps",
            float(self.min_enforce_rps),
            minimum=0.0,
        )
        min_boost_rps = self._parse_float_config(
            "min_boost_rps",
            float(min_boot_rps),
            minimum=0.0,
        )
        self.min_burst_threshold = self._parse_float_config(
            "min_burst_threshold",
            float(min_boost_rps),
            minimum=0.0,
        )
        self.warmup_max_rps = self._parse_float_config(
            "warmup_max_rps", 0.0, minimum=0.0
        )
        self.max_enforce_rps = self._parse_float_config(
            "max_enforce_rps", 5000.0, minimum=0.0
        )
        self.global_max_rps = self._parse_float_config(
            "global_max_rps", 0.0, minimum=0.0
        )
        bootstrap_default = (
            float(self.global_max_rps) if "global_max_rps" in self.config else 50.0
        )
        self.bootstrap_rps = self._parse_float_config(
            "bootstrap_rps",
            float(bootstrap_default),
            minimum=0.0,
        )
        self.stats_log_interval_seconds = self._parse_int_config(
            "stats_log_interval_seconds",
            3600,
            minimum=0,
        )
        self.stats_window_seconds = self._parse_int_config(
            "stats_window_seconds",
            0,
            minimum=0,
        )
        self._last_stats_log_ts: float = 0.0
        # Serialize stats log cadence checks so concurrent resolver threads
        # cannot emit duplicate periodic summaries in the same interval.
        self._stats_log_lock = threading.Lock()

        # Deny-log throttle: per-key last-logged timestamp and suppressed count
        # to prevent per-deny logging from becoming a DoS vector itself.
        self.deny_log_interval_seconds = self._parse_int_config(
            "deny_log_interval_seconds", 60, minimum=0
        )
        self._deny_log_ts: dict[str, float] = {}
        self._deny_log_suppressed: dict[str, int] = {}
        self._deny_log_lock = threading.Lock()

        # Per-key blocked-episode query-log counter.  Tracks how many deny
        # decisions have been given a visible query-log row in the current
        # blocked episode.  Resets when the key's rate drops below threshold.
        self.deny_log_first_n = self._parse_int_config("deny_log_first_n", 3, minimum=0)
        self._deny_episode_count: dict[str, int] = {}
        self._deny_episode_lock = threading.Lock()

        # Deny policy configuration
        deny_resp = str(
            self.config.get("deny_response", "nxdomain") or "nxdomain"
        ).lower()
        valid_deny = {
            "nxdomain",
            "refused",
            "servfail",
            "noerror_empty",
            "nodata",
            "ip",
            "drop",
        }
        if deny_resp not in valid_deny:
            logger.warning(
                "unknown deny_response %r; defaulting to 'nxdomain'",
                deny_resp,
            )
            deny_resp = "nxdomain"
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

        # Per-key rolling window counters (key -> "window_id:count").
        # Rate-limit counters must remain stateful even when DNS response cache
        # is disabled (cache: none), otherwise each request appears as a
        # first-in-window request and limits never trigger.
        cache_namespace = module_namespace(__file__)
        self._window_cache = get_current_namespaced_cache(
            namespace=cache_namespace,
            cache_plugin=self.config.get("cache"),
        )
        window_cache_backend = getattr(self._window_cache, "_backend", None)
        if isinstance(window_cache_backend, NullCache):
            logger.warning(
                "cache backend %s disables stateful counters; "
                "using internal in-memory counter cache.",
                type(window_cache_backend).__name__,
            )
            self._window_cache = TTLCacheAdapter(
                FoghornTTLCache(namespace=cache_namespace)
            )
        self._window_locks = [threading.Lock() for _ in range(256)]
        # Best-effort in-memory snapshot of current-window key counters for
        # admin visibility. This is independent of sqlite profile persistence,
        # so keys that are active in the current window can be surfaced even
        # before a completed window writes a rate_profiles row. Tracking is
        # bounded by active_window_max_keys to avoid unbounded per-window
        # memory growth under high-cardinality traffic.
        self._active_window_counts: dict[str, tuple[int, int]] = {}
        self._active_window_id: Optional[int] = None
        self._active_window_lock = threading.Lock()
        self._cached_bucket_limits: dict[str, tuple[int, float, float]] = {}
        self._bucket_limit_lock = threading.Lock()
        self._last_limit_recalc_epoch: Optional[int] = None
        self._warn_on_limit_precedence_conflicts()

        # SQLite-backed learned profiles
        cfg_db_path = self.config.get("db_path", "./config/var/dbs/rate_limit.db")
        self.db_path: str = str(cfg_db_path or "./config/var/dbs/rate_limit.db")
        self._db_lock = threading.Lock()
        self._db_init()

    def _warn_on_limit_precedence_conflicts(self) -> None:
        """Brief: Warn when configured limits are likely to trigger sooner than others.

        Inputs:
          - None (uses parsed setup() attributes).

        Outputs:
          - None (emits startup warning logs for potentially surprising precedence).
        """

        warmup_cap = float(getattr(self, "warmup_max_rps", 0.0) or 0.0)
        hard_cap = float(getattr(self, "max_enforce_rps", 0.0) or 0.0)
        bootstrap = float(getattr(self, "bootstrap_rps", 0.0) or 0.0)
        global_cap = float(getattr(self, "global_max_rps", 0.0) or 0.0)
        min_enforce = float(getattr(self, "min_enforce_rps", 0.0) or 0.0)

        if warmup_cap > 0.0 and hard_cap > 0.0 and warmup_cap > hard_cap:
            logger.warning(
                "warmup_max_rps=%.2f exceeds max_enforce_rps=%.2f; "
                "warmup enforcement will be clamped by max_enforce_rps.",
                warmup_cap,
                hard_cap,
            )

        if bootstrap > 0.0 and hard_cap > 0.0 and bootstrap > hard_cap:
            logger.warning(
                "bootstrap_rps=%.2f exceeds max_enforce_rps=%.2f; "
                "bootstrap behavior will clamp to max_enforce_rps.",
                bootstrap,
                hard_cap,
            )

        if min_enforce > 0.0 and hard_cap > 0.0 and hard_cap < min_enforce:
            logger.warning(
                "max_enforce_rps=%.2f is below min_enforce_rps=%.2f; "
                "hard-cap enforcement may trigger before learned-threshold enforcement.",
                hard_cap,
                min_enforce,
            )

        if global_cap > 0.0 and warmup_cap > 0.0 and global_cap < warmup_cap:
            logger.warning(
                "global_max_rps=%.2f is below warmup_max_rps=%.2f; "
                "global limiting may trigger before warmup per-key limits.",
                global_cap,
                warmup_cap,
            )

        if global_cap > 0.0 and hard_cap > 0.0 and global_cap < hard_cap:
            logger.warning(
                "global_max_rps=%.2f is below max_enforce_rps=%.2f; "
                "global limiting may trigger before per-key limits.",
                global_cap,
                hard_cap,
            )

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
        if key == "bucket_network_prefix_v4":
            raw = _normalize_prefix_length_value(raw)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value_type = type(raw).__name__
            logger.warning(
                "%s non-integer value (type=%s); using %d",
                key,
                value_type,
                default,
            )
            return default
        if value < minimum:
            logger.warning(
                "%s below minimum %d (%d); clamping",
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
            value_type = type(raw).__name__
            logger.warning(
                "%s non-float value (type=%s); using %s",
                key,
                value_type,
                default,
            )
            return default
        if value < minimum:
            logger.warning(
                "%s below minimum %s (%s); clamping",
                key,
                minimum,
                value,
            )
            value = minimum
        if maximum is not None and value > maximum:
            logger.warning(
                "%s above maximum %s (%s); clamping",
                key,
                maximum,
                value,
            )
            value = maximum
        return value

    def _parse_bool_config(self, key: str, default: bool) -> bool:
        """Brief: Parse boolean configuration values.

        Inputs:
          - key: Configuration key name.
          - default: Fallback boolean value on parse failure.

        Outputs:
          - bool: Parsed boolean value.
        """

        raw = self.config.get(key, default)
        if isinstance(raw, bool):
            return raw
        if raw is None:
            return bool(default)
        text = str(raw).strip().lower()
        if text in {"1", "true", "yes", "y", "on"}:
            return True
        if text in {"0", "false", "no", "n", "off"}:
            return False
        value_type = type(raw).__name__
        logger.warning(
            "%s non-boolean value (type=%s); using %s",
            key,
            value_type,
            default,
        )
        return bool(default)

    def _db_init(self) -> None:
        """Brief: Initialize sqlite3 database for learned rate profiles.

        Inputs:
          - None

        Outputs:
          - None (creates self._conn and the rate_profiles table).

        Notes:
          - Creates a secondary window-sample table used for true
            stats_window_seconds summary aggregation.
          - The database is bounded via best-effort pruning in _maybe_prune_db().
        """

        dir_path = os.path.dirname(self.db_path)
        if dir_path:
            try:
                os.makedirs(dir_path, exist_ok=True)
            except Exception as exc:  # pragma: no cover - defensive: log-only path
                logger.warning(
                    "failed to create directory for db_path %s: %s",
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
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS rate_profile_windows ("
                "key TEXT NOT NULL, "
                "rps REAL NOT NULL, "
                "last_update INTEGER NOT NULL"
                ")"
            )
            # Index to support efficient pruning and stats inspection.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rate_profiles_last_update "
                "ON rate_profiles(last_update)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rate_profile_windows_last_update "
                "ON rate_profile_windows(last_update)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rate_profile_windows_key "
                "ON rate_profile_windows(key)"
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
            if (  # pragma: no cover - defensive: tolerate malformed/partially-null persisted rows
                row[0] is None or row[1] is None or row[2] is None
            ):
                raise TypeError("NULL fields in rate_profiles row")
            return float(row[0]), float(row[1]), int(row[2])
        except Exception as exc:  # pragma: no cover - defensive: malformed DB rows
            logger.warning(
                "ignoring malformed rate_profiles row for %s: %s",
                key,
                exc,
            )
            return None

    def _cap_non_global_samples(
        self,
        cursor: sqlite3.Cursor,
        profile_key: str,
        sample_count: int,
    ) -> int:
        """Brief: Cap non-global sample_count to current global samples.

        Inputs:
          - cursor: sqlite cursor on the rate-limit profile DB.
          - profile_key: Profile key being updated.
          - sample_count: Candidate sample count for this profile update.

        Outputs:
          - int: Possibly capped sample count.
        """

        bounded_samples = int(sample_count)
        if str(profile_key) == str(_GLOBAL_RPS_DB_KEY):
            return int(bounded_samples)
        try:
            cursor.execute(
                "SELECT samples FROM rate_profiles WHERE key=?",
                (str(_GLOBAL_RPS_DB_KEY),),
            )
            global_row = cursor.fetchone()
            global_samples = (
                int(global_row[0]) if global_row and global_row[0] is not None else None
            )
        except Exception:
            global_samples = None
        if (
            global_samples is not None
            and int(global_samples) >= 0
            and int(bounded_samples) > int(global_samples)
        ):
            return int(global_samples)
        return int(bounded_samples)

    def _db_get_profile_last_update(self, key: str) -> Optional[int]:
        """Brief: Return last_update epoch seconds for a profile key.

        Inputs:
          - key: Normalized profile key string.

        Outputs:
          - Optional[int]: last_update epoch seconds, or None if missing/malformed.
        """

        with self._db_lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT last_update FROM rate_profiles WHERE key=?",
                (key,),
            )
            row = cur.fetchone()
        if not row or row[0] is None:
            return None
        try:
            return int(row[0])
        except Exception:
            return None

    def _ensure_global_profile_floor(
        self,
        cursor: sqlite3.Cursor,
        *,
        floor_avg_rps: float,
        floor_max_rps: float,
        floor_samples: int,
        now_ts: int,
        window_rps: Optional[float] = None,
    ) -> None:
        """Brief: Ensure non-global writes cannot outrun the global DB row.

        Inputs:
          - cursor: sqlite cursor on the rate-limit profile DB.
          - floor_avg_rps: Avg-RPS value used when synthesizing a missing
            global profile row.
          - floor_max_rps: Minimum max_rps the global row must expose.
          - floor_samples: Minimum samples count the global row must expose.
          - now_ts: Epoch seconds for last_update / optional window sample time.
          - window_rps: Optional window RPS floor to persist for the global
            rate_profile_windows row at now_ts.

        Outputs:
          - None. Creates or updates the global profile/window rows so a
            non-global key cannot persist stronger history than the global key.
        """

        try:
            avg_floor = max(0.0, float(floor_avg_rps))
        except Exception:
            avg_floor = 0.0
        try:
            max_floor = max(0.0, float(floor_max_rps))
        except Exception:
            max_floor = 0.0
        try:
            sample_floor = max(0, int(floor_samples))
        except Exception:
            sample_floor = 0
        try:
            now_i = int(now_ts)
        except Exception:
            now_i = 0

        cursor.execute(
            "SELECT avg_rps, max_rps, samples, last_update FROM rate_profiles WHERE key=?",
            (str(_GLOBAL_RPS_DB_KEY),),
        )
        row = cursor.fetchone()
        if (
            not row
            or row[0] is None
            or row[1] is None
            or row[2] is None
            or row[3] is None
        ):
            cursor.execute(
                "INSERT OR REPLACE INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    str(_GLOBAL_RPS_DB_KEY),
                    float(avg_floor),
                    float(max_floor),
                    int(sample_floor),
                    int(now_i),
                ),
            )
        else:
            try:
                global_max = float(row[1])
                global_samples = int(row[2])
                global_last_update = int(row[3])
            except Exception:
                cursor.execute(
                    "INSERT OR REPLACE INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        str(_GLOBAL_RPS_DB_KEY),
                        float(avg_floor),
                        float(max_floor),
                        int(sample_floor),
                        int(now_i),
                    ),
                )
            else:
                new_global_max = max(float(global_max), float(max_floor))
                new_global_samples = max(int(global_samples), int(sample_floor))
                new_global_last_update = max(int(global_last_update), int(now_i))
                if (
                    float(new_global_max) != float(global_max)
                    or int(new_global_samples) != int(global_samples)
                    or int(new_global_last_update) != int(global_last_update)
                ):
                    cursor.execute(
                        "UPDATE rate_profiles SET max_rps=?, samples=?, last_update=? "
                        "WHERE key=?",
                        (
                            float(new_global_max),
                            int(new_global_samples),
                            int(new_global_last_update),
                            str(_GLOBAL_RPS_DB_KEY),
                        ),
                    )

        if window_rps is None:
            return

        try:
            window_floor = max(0.0, float(window_rps))
        except Exception:
            window_floor = 0.0
        cursor.execute(
            "SELECT MAX(rps) FROM rate_profile_windows WHERE key=? AND last_update=?",
            (str(_GLOBAL_RPS_DB_KEY), int(now_i)),
        )
        row = cursor.fetchone()
        existing_window_rps = float(row[0]) if row and row[0] is not None else None
        if existing_window_rps is None:
            cursor.execute(
                "INSERT INTO rate_profile_windows (key, rps, last_update) "
                "VALUES (?, ?, ?)",
                (str(_GLOBAL_RPS_DB_KEY), float(window_floor), int(now_i)),
            )
        elif float(existing_window_rps) < float(window_floor):
            cursor.execute(
                "UPDATE rate_profile_windows SET rps=? WHERE key=? AND last_update=?",
                (
                    float(window_floor),
                    str(_GLOBAL_RPS_DB_KEY),
                    int(now_i),
                ),
            )

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
            try:
                history_ttl = max(
                    int(getattr(self, "profile_ttl_seconds", 0) or 0),
                    int(getattr(self, "stats_window_seconds", 0) or 0),
                )
            except Exception:
                history_ttl = 0
            if history_ttl > 0:
                try:
                    history_cutoff = int(now_ts) - int(history_ttl)
                    cur.execute(
                        "DELETE FROM rate_profile_windows WHERE last_update < ?",
                        (int(history_cutoff),),
                    )
                except Exception:
                    pass

            # Row-count bound.
            try:
                max_rows = int(getattr(self, "max_profiles", 10000) or 10000)
            except Exception:
                max_rows = 10000
            if (
                max_rows < 1
            ):  # pragma: no cover - defensive: config model already enforces >=1
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
          - None (persists updated avg_rps, max_rps, samples, and optional
            per-window sample rows used by stats_window_seconds summaries;
            global window samples are always persisted for admin runtime metrics).
        """

        with self._db_lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT avg_rps, max_rps, samples FROM rate_profiles WHERE key=?",
                (key,),
            )
            row = cur.fetchone()
            global_row_present = True
            global_max_rps: Optional[float] = None
            global_samples: Optional[int] = None
            if str(key) != str(_GLOBAL_RPS_DB_KEY):
                try:
                    cur.execute(
                        "SELECT avg_rps, max_rps, samples, last_update FROM rate_profiles WHERE key=?",
                        (str(_GLOBAL_RPS_DB_KEY),),
                    )
                    global_row = cur.fetchone()
                except Exception:
                    global_row_present = False
                else:
                    global_row_present = bool(
                        global_row
                        and global_row[0] is not None
                        and global_row[1] is not None
                        and global_row[2] is not None
                        and global_row[3] is not None
                    )
                    if global_row_present:
                        global_max_rps = float(global_row[1])
                        global_samples = int(global_row[2])
            global_floor_samples = 0
            can_preseed_global = not global_row_present
            if (
                str(key) != str(_GLOBAL_RPS_DB_KEY)
                and not can_preseed_global
                and row
                and row[1] is not None
                and row[2] is not None
                and global_max_rps is not None
                and global_samples is not None
            ):
                try:
                    can_preseed_global = (
                        int(global_samples) == int(row[2])
                        and abs(float(global_max_rps) - float(row[1])) < 1e-9
                    )
                except Exception:
                    can_preseed_global = False
            if str(key) != str(_GLOBAL_RPS_DB_KEY) and can_preseed_global:
                proposed_samples = 1
                if row and row[2] is not None:
                    try:
                        proposed_samples = max(1, int(row[2]) + 1)
                    except Exception:
                        proposed_samples = 1
                self._ensure_global_profile_floor(
                    cur,
                    floor_avg_rps=float(rps),
                    floor_max_rps=float(rps),
                    floor_samples=int(proposed_samples),
                    now_ts=int(now_ts),
                    window_rps=(
                        float(rps)
                        if int(getattr(self, "stats_window_seconds", 0) or 0) > 0
                        else None
                    ),
                )
            if not row or row[0] is None or row[1] is None or row[2] is None:
                # Treat missing or partially-null rows as if they do not exist,
                # resetting the profile based on the current observation.
                capped_samples = self._cap_non_global_samples(cur, str(key), 1)
                global_floor_samples = int(capped_samples)
                cur.execute(
                    "INSERT OR REPLACE INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (key, float(rps), float(rps), int(capped_samples), int(now_ts)),
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
                    capped_samples = self._cap_non_global_samples(cur, str(key), 1)
                    global_floor_samples = int(capped_samples)
                    cur.execute(
                        "INSERT OR REPLACE INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (key, float(rps), float(rps), int(capped_samples), int(now_ts)),
                    )
                else:
                    # Use asymmetric smoothing so we can ramp up and down at different rates.
                    if float(rps) >= avg_rps:
                        alpha = float(self.alpha)
                    else:
                        alpha = float(getattr(self, "alpha_down", self.alpha))
                    new_avg = (1.0 - alpha) * avg_rps + alpha * float(rps)
                    new_max = max(max_rps, float(rps))
                    new_samples = self._cap_non_global_samples(
                        cur, str(key), int(samples + 1)
                    )
                    global_floor_samples = int(new_samples)
                    cur.execute(
                        "UPDATE rate_profiles SET avg_rps=?, max_rps=?, samples=?, last_update=? "
                        "WHERE key=?",
                        (new_avg, new_max, new_samples, int(now_ts), key),
                    )
            if str(key) != str(_GLOBAL_RPS_DB_KEY):
                self._ensure_global_profile_floor(
                    cur,
                    floor_avg_rps=float(rps),
                    floor_max_rps=float(rps),
                    floor_samples=int(global_floor_samples),
                    now_ts=int(now_ts),
                    window_rps=(
                        float(rps)
                        if int(getattr(self, "stats_window_seconds", 0) or 0) > 0
                        else None
                    ),
                )
            # Always write per-key RPS to rate_profile_windows for historical aggregation
            # (e.g., computing 1m/5m/10m averages in the admin UI).
            cur.execute(
                "INSERT INTO rate_profile_windows (key, rps, last_update) "
                "VALUES (?, ?, ?)",
                (key, float(rps), int(now_ts)),
            )
            self._conn.commit()

        # Best-effort pruning outside of the DB lock critical path.
        try:
            self._maybe_prune_db(now_ts=int(now_ts))
        except Exception:
            pass

    def _db_apply_zero_windows(self, key: str, windows: int, now_ts: int) -> None:
        """Brief: Apply missed windows as zero-RPS samples for an existing profile.

        Inputs:
          - key: Normalized profile key string.
          - windows: Number of consecutive missed windows to apply.
          - now_ts: Epoch seconds used as the profile last_update timestamp.

        Outputs:
          - None (decays avg_rps using alpha_down and increments samples).
        """

        try:
            missed_windows = int(windows)
        except Exception:
            return
        if missed_windows <= 0:
            return

        with self._db_lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT avg_rps, max_rps, samples FROM rate_profiles WHERE key=?",
                (key,),
            )
            row = cur.fetchone()
            if (  # pragma: no cover - defensive: profile may be missing/pruned between checks
                not row or row[0] is None or row[1] is None or row[2] is None
            ):
                return

            try:
                avg_rps = float(row[0])
                max_rps = float(row[1])
                samples = int(row[2])
            except Exception:
                return

            alpha_down = float(getattr(self, "alpha_down", self.alpha))
            if alpha_down <= 0.0:
                new_avg = avg_rps
            elif alpha_down >= 1.0:
                new_avg = 0.0
            else:
                new_avg = avg_rps * ((1.0 - alpha_down) ** missed_windows)
            new_samples = int(samples + missed_windows)
            if str(key) != str(_GLOBAL_RPS_DB_KEY):
                try:
                    cur.execute(
                        "SELECT samples FROM rate_profiles WHERE key=?",
                        (str(_GLOBAL_RPS_DB_KEY),),
                    )
                    global_row = cur.fetchone()
                    global_samples = (
                        int(global_row[0])
                        if global_row and global_row[0] is not None
                        else None
                    )
                except Exception:
                    global_samples = None
                if (
                    global_samples is not None
                    and int(global_samples) >= 0
                    and int(new_samples) > int(global_samples)
                ):
                    new_samples = int(global_samples)
                self._ensure_global_profile_floor(
                    cur,
                    floor_avg_rps=float(new_avg),
                    floor_max_rps=float(max_rps),
                    floor_samples=int(new_samples),
                    now_ts=int(now_ts),
                )

            cur.execute(
                "UPDATE rate_profiles SET avg_rps=?, max_rps=?, samples=?, last_update=? "
                "WHERE key=?",
                (
                    float(new_avg),
                    float(max_rps),
                    int(new_samples),
                    int(now_ts),
                    key,
                ),
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

            ip_obj = ip_networks.parse_ip(client_ip)
            if ip_obj is None:
                return str(client_ip)
            if ip_obj.version == 4:
                prefix = int(getattr(self, "bucket_network_prefix_v4", 24) or 24)
            else:
                prefix = int(getattr(self, "bucket_network_prefix_v6", 56) or 56)
            prefix = max(0, min(32 if ip_obj.version == 4 else 128, prefix))
            if ip_obj.version == 4 and int(prefix) == 32:
                return str(ip_obj)
            net = ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False)
            return str(net)
        except Exception:
            return str(client_ip)

    def _window_lock_for_key(self, key: str) -> threading.Lock:
        """Brief: Return a stripe lock for the given key to protect window updates.

        Inputs:
          - key: Normalized profile key string.

        Outputs:
          - threading.Lock instance used to serialize window cache updates.
        """

        locks = getattr(self, "_window_locks", None)
        if not locks:
            return threading.Lock()
        return locks[hash(key) % len(locks)]

    def _should_apply_udp_bucketing(self, listener: str, secure: bool) -> bool:
        """Brief: Decide whether to apply UDP spoofing mitigation bucketing.

        Inputs:
          - listener: Normalized listener string.
          - secure: Boolean security flag for the transport.

        Outputs:
          - bool: True when UDP bucketed keying should be applied.
        """

        if listener == "udp":
            return not secure
        known = {"udp", "tcp", "dot", "doh"}
        if listener and listener in known:
            return False
        if secure:
            return False
        return bool(getattr(self, "assume_udp_when_listener_missing", True))

    def _warn_missing_listener(self) -> None:
        """Brief: Log a one-time warning when listener metadata is missing.

        Inputs:
          - None.

        Outputs:
          - None (logs a warning at most once per plugin instance).
        """

        if bool(getattr(self, "_missing_listener_warned", False)):
            return
        logger.warning(
            "listener metadata missing; applying UDP prefix bucketing fallback."
        )
        self._missing_listener_warned = True

    def _seed_profile(self, key: str, rps: float, now_ts: int, samples: int) -> None:
        """Brief: Seed a rate profile with a bootstrap baseline.

        Inputs:
          - key: Normalized profile key string.
          - rps: Baseline requests-per-second to seed.
          - now_ts: Current epoch seconds for last_update.
          - samples: Initial samples count to persist.

        Outputs:
          - None (writes a baseline row into sqlite).
        """

        with self._db_lock:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO rate_profiles (key, avg_rps, max_rps, samples, last_update) "
                "VALUES (?, ?, ?, ?, ?)",
                (key, float(rps), float(rps), int(samples), int(now_ts)),
            )
            self._conn.commit()

    def _make_key(self, qname: str, ctx: PluginContext) -> str:
        """Brief: Build the profiling key according to the configured mode.

        Inputs:
          - qname: Queried domain name.
          - ctx: PluginContext providing client_ip.

        Outputs:
          - str: Normalized key string (e.g., '1.2.3.4' or '1.2.3.0/24|example.com').

        Notes:
          - On insecure UDP transports, client identity uses CIDR bucketing via
            bucket_network_prefix_v4/bucket_network_prefix_v6.
        """

        raw_client_ip = str(getattr(ctx, "client_ip", "") or "unknown")
        client_ip = raw_client_ip
        listener = str(getattr(ctx, "listener", "") or "").lower()
        secure = bool(getattr(ctx, "secure", False))

        # Spoofing-aware UDP overrides.
        if self._should_apply_udp_bucketing(listener, secure):
            if not listener:
                self._warn_missing_listener()
            client_ip = self._client_ip_bucket(raw_client_ip)

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

        prev_window_id: Optional[int] = None
        prev_count: Optional[int] = None
        cache_miss = False
        missed_windows = 0
        lock = self._window_lock_for_key(key)
        with lock:
            raw = self._window_cache.get(cache_key)
            if raw is None:
                # First observation for this key.
                cache_miss = True
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
                    missed_windows = max(int(window_id) - int(stored_window_id) - 1, 0)
                    count = 1

            # Persist the updated window counter with a TTL slightly larger than a single window.
            ttl = max(self.window_seconds * 2, self.window_seconds + 1)
            try:
                payload = f"{window_id}:{count}".encode()
                self._window_cache.set(cache_key, int(ttl), payload)
            except Exception:  # pragma: no cover - defensive logging only
                logger.debug("failed updating window cache for %s", key)
        # If the cache entry expired for an existing profile, infer missed windows
        # from the profile timestamp and apply them as zero-RPS samples.
        if cache_miss and prev_window_id is None and prev_count is None:
            try:
                last_update_ts = self._db_get_profile_last_update(key)
            except Exception:
                last_update_ts = None
            if last_update_ts is not None:
                last_update_window = int(last_update_ts // float(self.window_seconds))
                missed_windows = max(int(window_id) - int(last_update_window) - 1, 0)

        now_ts = int(now)
        # If we have a completed window, update the learned profile in sqlite.
        if prev_window_id is not None and prev_count is not None:
            if prev_count > 0:
                rps = float(prev_count) / float(self.window_seconds)
                try:
                    self._db_update_profile(key, rps, now_ts)
                    self._update_burst_counter(key, rps)
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.warning("failed to update profile for %s", key)
        if missed_windows > 0:
            try:
                self._db_apply_zero_windows(key, missed_windows, now_ts)
                try:
                    profile = self._db_get_profile(key)
                except Exception:
                    profile = None
                if not profile:
                    self._reset_burst_state(key)
                else:
                    avg_rps, _max_rps, samples = profile
                    if int(samples) < int(self.warmup_windows):
                        self._reset_burst_state(key)
                    elif float(avg_rps) < float(self.min_enforce_rps):
                        self._reset_burst_state(key)
                    else:
                        self._advance_burst_reset_counter(key, int(missed_windows))
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                logger.warning(
                    "failed applying zero-RPS windows for %s",
                    key,
                )
        # Record a best-effort in-memory snapshot of active current-window
        # counters so admin views can include keys before profile persistence
        # catches up at the next window rollover.
        #
        # Skip global key tracking here: global is surfaced via
        # _get_current_window_rps('global') and tracking it in the active-window
        # rollover path can flush stale per-key entries before their own update
        # path runs, which can skew per-key missed-window sample backfill.
        if str(key) != str(_GLOBAL_RPS_DB_KEY):
            self._record_active_window_count(str(key), int(window_id), int(count))

        return window_id, count

    def _record_active_window_count(self, key: str, window_id: int, count: int) -> None:
        """Brief: Track per-key request count for the currently active window.

        Inputs:
          - key: Rate profile key (for example client IP or client|domain).
          - window_id: Integer window identifier (epoch/window_seconds).
          - count: Current request count observed for this key in window_id.

        Outputs:
          - None. Updates in-memory active-window counters used by admin views.
        """

        key_text = str(key)
        if (
            not key_text
        ):  # pragma: no cover - defensive: key is always populated by internal callers
            return
        count_i = int(count)
        if (
            count_i <= 0
        ):  # pragma: no cover - defensive: internal counter increments are positive
            return
        window_i = int(window_id)
        stale_entries: list[tuple[str, int]] = []
        rollover_happened = False
        with self._active_window_lock:
            # Keep only the active window to avoid unbounded growth under
            # high-cardinality traffic.
            #
            # IMPORTANT: Only advance _active_window_id forward, never regress.
            # Late-arriving threads from older windows must not reset the window
            # ID backwards, as this causes stale entry collection to incorrectly
            # include entries from the current (newer) window, leading to
            # duplicate or inconsistent profile updates.
            if self._active_window_id is not None and int(window_i) < int(
                self._active_window_id
            ):
                # Stale data from a late-arriving thread; skip tracking entirely
                # to avoid corrupting the active window state.
                return
            if self._active_window_id is None or int(self._active_window_id) < window_i:
                previous_window_id = self._active_window_id
                self._active_window_id = int(window_i)
                rollover_happened = previous_window_id is not None
                stale_keys = [
                    stale_key
                    for stale_key, (
                        stale_window,
                        _,
                    ) in self._active_window_counts.items()
                    if int(stale_window) != int(window_i)
                ]
                for stale_key in stale_keys:
                    stale_window_id, stale_count = self._active_window_counts.pop(
                        stale_key,
                        (None, 0),
                    )
                    if (
                        stale_window_id is not None
                        and previous_window_id is not None
                        and int(stale_window_id) == int(previous_window_id)
                    ):
                        stale_entries.append((str(stale_key), int(stale_count)))
            existing_entry = self._active_window_counts.get(key_text)
            max_active_keys = max(
                int(
                    getattr(
                        self,
                        "_active_window_max_keys",
                        getattr(self, "max_profiles", 10000),
                    )
                    or 1
                ),
                1,
            )
            if existing_entry is not None or len(self._active_window_counts) < int(
                max_active_keys
            ):
                self._active_window_counts[key_text] = (int(window_i), int(count_i))

        if rollover_happened:
            self._flush_completed_active_window_keys(
                stale_entries=stale_entries,
                exclude_keys={str(key_text), str(_GLOBAL_RPS_DB_KEY)},
            )

    def _flush_completed_active_window_keys(
        self,
        *,
        stale_entries: list[tuple[str, int]],
        exclude_keys: set[str],
    ) -> None:
        """Brief: Persist completed-window active key counts that were not self-flushed.

        Inputs:
          - stale_entries: list of (profile_key, request_count) for the
            previous active window.
          - exclude_keys: Keys to skip because their rollover is handled by the
            normal per-key _increment_window path (for example current key and
            the global key).

        Outputs:
          - None. Best-effort profile updates are written to sqlite.
        """

        if not stale_entries:
            return
        window_seconds = int(getattr(self, "window_seconds", 10) or 10)
        if (
            window_seconds <= 0
        ):  # pragma: no cover - defensive: config model enforces >=1
            return
        now_ts = int(time.time())
        current_window_id = int(now_ts // float(window_seconds))
        window_counter_ttl = max(window_seconds * 2, window_seconds + 1)
        skipped_keys = {str(k) for k in set(exclude_keys or set())}

        for stale_key, stale_count in stale_entries:
            key_text = str(stale_key)
            if not key_text or key_text in skipped_keys:
                continue
            count_i = int(stale_count)
            if count_i <= 0:
                continue
            should_flush = True
            lock = self._window_lock_for_key(key_text)
            with lock:
                raw = self._window_cache.get((key_text, 0))
                stored_window_id: Optional[int] = None
                if raw is not None:
                    try:
                        text = raw.decode()
                        stored_window_str, _stored_count_str = text.split(":", 1)
                        stored_window_id = int(stored_window_str)
                    except Exception:
                        stored_window_id = None

                # If this key already rolled into the current window (for example
                # via a concurrent self-request), skip flush to avoid duplicate
                # sample writes for the same completed window.
                if stored_window_id is not None and int(stored_window_id) >= int(
                    current_window_id
                ):
                    should_flush = False
                else:
                    try:
                        payload = f"{current_window_id}:0".encode()
                        self._window_cache.set(
                            (key_text, 0),
                            int(window_counter_ttl),
                            payload,
                        )
                    except Exception:  # pragma: no cover - defensive
                        logger.debug(
                            "failed updating rollover marker for %s",
                            key_text,
                        )
            if not should_flush:
                continue
            rps = float(count_i) / float(window_seconds)
            try:
                self._db_update_profile(key_text, rps, now_ts)
                self._update_burst_counter(key_text, rps)
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                logger.warning(
                    "failed to flush completed active window for %s",
                    key_text,
                )

    def _get_current_window_rps_snapshot(self, limit: int = 500) -> dict[str, float]:
        """Brief: Return a snapshot of per-key RPS for the active request window.

        Inputs:
          - limit: Maximum number of keys to include (<=0 disables truncation).

        Outputs:
          - dict[str, float]: Mapping of key -> current-window RPS for keys with
            observed traffic in the currently active window.
        """

        window_seconds = int(getattr(self, "window_seconds", 10) or 10)
        if (
            window_seconds <= 0
        ):  # pragma: no cover - defensive: config model enforces >=1
            return {}

        current_window_id = int(time.time() // float(window_seconds))
        with self._active_window_lock:
            active_window_id = getattr(self, "_active_window_id", None)
            if active_window_id is None or int(active_window_id) != int(
                current_window_id
            ):
                self._active_window_id = int(current_window_id)
                stale_keys = [
                    stale_key
                    for stale_key, (
                        stale_window,
                        _,
                    ) in self._active_window_counts.items()
                    if int(stale_window) != int(current_window_id)
                ]
                for stale_key in stale_keys:
                    self._active_window_counts.pop(stale_key, None)

            rows = [
                (key_text, int(count))
                for key_text, (window_id, count) in self._active_window_counts.items()
                if int(window_id) == int(current_window_id) and int(count) > 0
            ]

        if int(limit) > 0 and len(rows) > int(limit):
            rows.sort(key=lambda row: int(row[1]), reverse=True)
            rows = rows[: int(limit)]

        return {
            str(key_text): float(int(count)) / float(window_seconds)
            for key_text, count in rows
        }

    def _get_current_window_rps(self, key: str) -> float:
        """Brief: Return active in-progress window RPS for a profile key.

        Inputs:
          - key: Normalized profile key string.

        Outputs:
          - float: Current-window requests-per-second for the key, or 0.0 when
            no active current-window counter exists.
        """

        window_seconds = int(getattr(self, "window_seconds", 10) or 10)
        if window_seconds <= 0:
            return 0.0

        raw = self._window_cache.get((key, 0))
        if raw is None:
            return 0.0

        try:
            text = raw.decode()
            stored_window_str, stored_count_str = text.split(":", 1)
            stored_window_id = int(stored_window_str)
            stored_count = int(stored_count_str)
        except Exception:
            return 0.0
        if stored_count <= 0:
            return 0.0

        current_window_id = int(time.time() // float(window_seconds))
        if stored_window_id != current_window_id:
            return 0.0
        return float(stored_count) / float(window_seconds)

    def _get_burst_count(self, key: str) -> int:
        """Brief: Return the current burst window count for a key.

        Inputs:
          - key: Normalized profile key string.

        Outputs:
          - int: Current burst window count (0 when unset or malformed).
        """

        raw = self._window_cache.get((key, 1))
        if raw is None:
            return 0
        try:
            return int(raw.decode())
        except Exception:
            return 0

    def _set_burst_count(self, key: str, count: int) -> None:
        """Brief: Store burst window count in the window cache.

        Inputs:
          - key: Normalized profile key string.
          - count: Burst window count to persist.

        Outputs:
          - None.
        """

        if int(getattr(self, "burst_windows", 0) or 0) <= 0:
            return
        ttl = max(
            self.window_seconds * (max(int(self.burst_windows), 1) + 2),
            self.window_seconds * 2,
        )
        try:
            payload = str(int(count)).encode()
            self._window_cache.set((key, 1), int(ttl), payload)
        except Exception:  # pragma: no cover - defensive
            logger.debug("failed updating burst window cache for %s", key)

    def _get_burst_reset_count(self, key: str) -> int:
        """Brief: Return the in-progress burst reset cooldown window count.

        Inputs:
          - key: Normalized profile key string.

        Outputs:
          - int: Consecutive below-threshold completed windows observed since the
            last burst window for this key (0 when unset or malformed).
        """

        raw = self._window_cache.get((key, 2))
        if raw is None:
            return 0
        try:
            return int(raw.decode())
        except Exception:
            return 0

    def _set_burst_reset_count(self, key: str, count: int) -> None:
        """Brief: Persist burst reset cooldown progress in the window cache.

        Inputs:
          - key: Normalized profile key string.
          - count: Consecutive below-threshold completed windows observed.

        Outputs:
          - None.
        """

        if int(getattr(self, "burst_windows", 0) or 0) <= 0:
            return
        ttl = max(
            self.window_seconds
            * (max(int(getattr(self, "burst_reset_windows", 20) or 20), 1) + 2),
            self.window_seconds * 2,
        )
        try:
            payload = str(int(count)).encode()
            self._window_cache.set((key, 2), int(ttl), payload)
        except Exception:  # pragma: no cover - defensive
            logger.debug("failed updating burst reset cache for %s", key)

    def _reset_burst_state(self, key: str) -> None:
        """Brief: Reset burst counters for a key to a neutral state.

        Inputs:
          - key: Normalized profile key string.

        Outputs:
          - None (sets burst count and burst reset count to zero).
        """

        self._set_burst_count(key, 0)
        self._set_burst_reset_count(key, 0)

    def _advance_burst_reset_counter(self, key: str, completed_windows: int) -> None:
        """Brief: Advance below-threshold cooldown windows for burst reset.

        Inputs:
          - key: Normalized profile key string.
          - completed_windows: Number of consecutive completed windows at or
            below threshold since the previous update.

        Outputs:
          - None (resets burst count when cooldown reaches burst_reset_windows).
        """

        if int(getattr(self, "burst_windows", 0) or 0) <= 0:
            return
        try:
            windows = int(completed_windows)
        except Exception:
            return
        if windows <= 0:
            return

        burst_count = self._get_burst_count(key)
        if burst_count <= 0:
            self._set_burst_reset_count(key, 0)
            return

        reset_windows = int(getattr(self, "burst_reset_windows", 20) or 20)
        if reset_windows <= 1:
            self._reset_burst_state(key)
            return

        cooldown_count = self._get_burst_reset_count(key) + windows
        if cooldown_count >= reset_windows:
            self._reset_burst_state(key)
            return
        self._set_burst_reset_count(key, cooldown_count)

    def _update_burst_counter(self, key: str, rps: float) -> None:
        """Brief: Update burst window counter based on the last completed window.

        Inputs:
          - key: Normalized profile key string.
          - rps: Observed requests-per-second for the completed window.

        Outputs:
          - None (updates cached burst count).
        """

        if int(getattr(self, "burst_windows", 0) or 0) <= 0:
            return

        try:
            profile = self._db_get_profile(key)
        except Exception:
            profile = None
        if not profile:
            return
        avg_rps, _max_rps, samples = profile
        if int(samples) < int(self.warmup_windows):
            self._reset_burst_state(key)
            return
        if float(avg_rps) < float(self.min_enforce_rps):
            self._reset_burst_state(key)
            return

        threshold = float(avg_rps) * float(self.burst_factor)
        threshold = max(threshold, float(self.min_burst_threshold))
        if self.max_enforce_rps > 0.0:
            threshold = min(threshold, float(self.max_enforce_rps))

        if float(rps) > float(threshold):
            count = self._get_burst_count(key)
            if count < int(self.burst_windows):
                count += 1
            else:
                count = int(self.burst_windows)
            self._set_burst_count(key, count)
            self._set_burst_reset_count(key, 0)
            return
        self._advance_burst_reset_counter(key, 1)

    def _compute_allowed_rps_thresholds(self, avg_rps: float) -> tuple[float, float]:
        """Brief: Compute burst and baseline allowed-RPS thresholds from avg_rps.

        Inputs:
          - avg_rps: Learned baseline requests-per-second for the bucket.

        Outputs:
          - tuple[float, float]:
              * burst_allowed_rps: avg_rps * burst_factor (floored by
                min_burst_threshold, then clamped by max_enforce_rps).
              * baseline_allowed_rps: avg_rps (clamped by max_enforce_rps).
        """

        burst_allowed_rps = float(avg_rps) * float(self.burst_factor)
        burst_allowed_rps = max(burst_allowed_rps, float(self.min_burst_threshold))
        baseline_allowed_rps = float(avg_rps)
        if float(self.max_enforce_rps) > 0.0:
            burst_allowed_rps = min(burst_allowed_rps, float(self.max_enforce_rps))
            baseline_allowed_rps = min(
                baseline_allowed_rps,
                float(self.max_enforce_rps),
            )
        return float(burst_allowed_rps), float(baseline_allowed_rps)

    def _maybe_recalculate_all_bucket_limits(self, now: float) -> int:
        """Brief: Refresh cached limits for all known buckets on recalc cadence.

        Inputs:
          - now: Current epoch seconds used to derive window/recalc epochs.

        Outputs:
          - int: Current request window identifier.

        Notes:
          - This performs a global recalc every limit_recalc_windows windows for
            all persisted buckets, including buckets not seen in the current
            interval.
        """

        window_seconds = int(getattr(self, "window_seconds", 10) or 10)
        if window_seconds <= 0:
            return 0
        window_id = int(float(now) // float(window_seconds))
        recalc_windows = max(
            1,
            int(getattr(self, "limit_recalc_windows", 10) or 10),
        )
        recalc_epoch = int(window_id // int(recalc_windows))

        with self._bucket_limit_lock:
            if self._last_limit_recalc_epoch == recalc_epoch:
                return int(window_id)
            self._last_limit_recalc_epoch = int(recalc_epoch)

        rows: list[tuple[str, float]] = []
        try:
            with self._db_lock:
                cur = self._conn.cursor()
                cur.execute("SELECT key, avg_rps FROM rate_profiles")
                raw_rows = cur.fetchall()
            for key_text, avg_rps in raw_rows:
                try:
                    rows.append((str(key_text), float(avg_rps or 0.0)))
                except Exception:
                    continue
        except Exception:
            return int(window_id)

        if not rows:
            return int(window_id)

        with self._bucket_limit_lock:
            for key_text, avg_rps in rows:
                burst_allowed_rps, baseline_allowed_rps = (
                    self._compute_allowed_rps_thresholds(float(avg_rps))
                )
                self._cached_bucket_limits[str(key_text)] = (
                    int(window_id),
                    float(burst_allowed_rps),
                    float(baseline_allowed_rps),
                )
        return int(window_id)

    def _get_recalculated_allowed_rps(
        self,
        key: str,
        avg_rps: float,
        samples: int,
        now: Optional[float] = None,
    ) -> tuple[float, float]:
        """Brief: Return per-bucket allowed-RPS thresholds with interval refresh.

        Inputs:
          - key: Normalized profile key string.
          - avg_rps: Learned baseline requests-per-second for this bucket.
          - samples: Number of completed windows observed for this bucket.
          - now: Optional current time override used for window/recalc epochs.

        Outputs:
          - tuple[float, float]:
              * burst_allowed_rps: Burst threshold for the bucket.
              * baseline_allowed_rps: Non-burst threshold for the bucket.

        Notes:
          - Buckets seen in the current interval are recalculated once per
            window interval.
          - Every limit_recalc_windows windows, all persisted buckets are
            globally refreshed, including buckets not seen in the interval.
        """
        try:
            int(samples)
        except Exception:
            pass

        if now is None:
            now = time.time()
        current_window_id = self._maybe_recalculate_all_bucket_limits(float(now))

        with self._bucket_limit_lock:
            cached = self._cached_bucket_limits.get(str(key))
            if cached is not None:
                cached_window_id, cached_burst, cached_baseline = cached
                if int(cached_window_id) == int(current_window_id):
                    return float(cached_burst), float(cached_baseline)

            burst_allowed_rps, baseline_allowed_rps = (
                self._compute_allowed_rps_thresholds(float(avg_rps))
            )
            self._cached_bucket_limits[str(key)] = (
                int(current_window_id),
                float(burst_allowed_rps),
                float(baseline_allowed_rps),
            )

            max_cached_keys = (
                max(int(getattr(self, "max_profiles", 10000) or 10000), 1) * 2
            )
            if len(self._cached_bucket_limits) > int(max_cached_keys):
                self._cached_bucket_limits.clear()

        return float(burst_allowed_rps), float(baseline_allowed_rps)

    def _maybe_log_stats(self, now: float) -> None:
        """Brief: Periodically log rate-limit summary statistics.

        Inputs:
          - now: Current epoch seconds.

        Outputs:
          - None (logs info when activity is present and interval has elapsed).

        Notes:
          - When stats_window_seconds > 0, stats are logged every
            stats_window_seconds.
          - When stats_window_seconds > 0, summary aggregates include only
            per-window samples with last_update within that lookback window.
        """
        stats_window_seconds = int(getattr(self, "stats_window_seconds", 0) or 0)
        if stats_window_seconds > 0:
            interval = int(stats_window_seconds)
        else:
            interval = int(getattr(self, "stats_log_interval_seconds", 0) or 0)
        if interval <= 0:
            return
        stats_log_lock = getattr(self, "_stats_log_lock", None)
        if stats_log_lock is None:
            stats_log_lock = threading.Lock()
            self._stats_log_lock = stats_log_lock
        with stats_log_lock:
            last_ts = float(getattr(self, "_last_stats_log_ts", 0.0) or 0.0)
            if now - last_ts < float(interval):
                return
            try:
                self._last_stats_log_ts = float(now)
            except Exception:
                self._last_stats_log_ts = 0.0

        buckets = 0
        avg_rps = 0.0
        max_rps = 0.0
        max_bucket_avg_rps = 0.0
        try:
            with self._db_lock:
                cur = self._conn.cursor()
                if stats_window_seconds > 0:
                    cutoff = int(now) - int(stats_window_seconds)
                    cur.execute(
                        "DELETE FROM rate_profile_windows WHERE last_update < ?",
                        (int(cutoff),),
                    )
                    cur.execute(
                        "SELECT COUNT(*), AVG(avg_rps), MAX(max_rps), MAX(avg_rps) "
                        + "FROM ("
                        + "SELECT key, AVG(rps) AS avg_rps, MAX(rps) AS max_rps "
                        + "FROM rate_profile_windows "
                        + "WHERE key != ? AND last_update >= ? "
                        + "GROUP BY key"
                        + ")",
                        (_GLOBAL_RPS_DB_KEY, int(cutoff)),
                    )
                    try:
                        self._conn.commit()
                    except Exception:
                        pass
                else:
                    cur.execute(
                        "SELECT COUNT(*), AVG(avg_rps), MAX(max_rps), MAX(avg_rps) "
                        "FROM rate_profiles WHERE key != ?",
                        (_GLOBAL_RPS_DB_KEY,),
                    )
                row = cur.fetchone()
            if (
                row
            ):  # pragma: no cover - defensive: sqlite aggregate fetches should return a row
                buckets = int(row[0] or 0)
                avg_rps = float(row[1] or 0.0)
                max_rps = float(row[2] or 0.0)
                max_bucket_avg_rps = float(row[3] or 0.0)
        except Exception:  # pragma: no cover - defensive
            buckets = 0

        if buckets <= 0 or avg_rps <= 0.0:
            # If no stats are available yet, avoid suppressing checks for the
            # full interval after an empty probe; retry after one request window.
            retry_seconds = min(
                int(interval),
                max(1, int(getattr(self, "window_seconds", 10) or 10)),
            )
            with stats_log_lock:
                current_last = float(getattr(self, "_last_stats_log_ts", 0.0) or 0.0)
                if (
                    current_last
                    == float(  # pragma: no cover - defensive: expected to match now under the same stats lock
                        now
                    )
                ):
                    try:
                        self._last_stats_log_ts = (
                            float(now) - float(interval) + float(retry_seconds)
                        )
                    except Exception:
                        self._last_stats_log_ts = 0.0
            return

        plugin_name = str(getattr(self, "name", "rate_limit") or "rate_limit")
        logger.info(
            "RateLimit stats name=%s avg_rps=%.2f max_rps=%.2f buckets=%d "
            + "max_bucket_avg_rps=%.2f stats_window_seconds=%d",
            plugin_name,
            avg_rps,
            max_rps,
            buckets,
            max_bucket_avg_rps,
            stats_window_seconds,
        )

    def _prune_deny_log_state(
        self, now: float, interval: int, keep_key: Optional[str] = None
    ) -> None:
        """Brief: Prune deny-log throttle maps to bound in-memory key growth.

        Inputs:
          - now: Current epoch seconds used for staleness checks.
          - interval: deny_log_interval_seconds throttle window.
          - keep_key: Optional key to preserve during this prune pass so
            throttled flush accounting can be emitted for the current key.

        Outputs:
          - None; removes stale and overflow keys from deny-log tracking maps.
        """

        cutoff = float(now) - float(interval)
        stale_keys = [
            stale_key
            for stale_key, ts in self._deny_log_ts.items()
            if float(ts) <= float(cutoff) and stale_key != keep_key
        ]
        for stale_key in stale_keys:
            self._deny_log_ts.pop(stale_key, None)
            self._deny_log_suppressed.pop(stale_key, None)
        orphan_suppressed_keys = [
            suppressed_key
            for suppressed_key in self._deny_log_suppressed.keys()
            if suppressed_key not in self._deny_log_ts
        ]
        for suppressed_key in orphan_suppressed_keys:
            self._deny_log_suppressed.pop(suppressed_key, None)

        try:
            max_profiles = int(getattr(self, "max_profiles", 10000) or 10000)
        except Exception:
            max_profiles = 10000
        max_keys = max(1, int(max_profiles)) * 2
        overflow = len(self._deny_log_ts) - int(max_keys)
        if overflow <= 0:
            return
        oldest_keys = sorted(
            self._deny_log_ts.items(),
            key=lambda key_ts: float(key_ts[1] or 0.0),
        )[: int(overflow)]
        for old_key, _old_ts in oldest_keys:
            self._deny_log_ts.pop(old_key, None)
            self._deny_log_suppressed.pop(old_key, None)

    def _throttled_deny_log(self, key: str, msg: str, *args: object) -> None:
        """Brief: Emit a rate-limited deny log message.

        Inputs:
          - key: Rate-limit bucket key used for per-key throttling.
          - msg: Log format string.
          - *args: Format arguments for msg.

        Outputs:
          - None; logs at most once per key per deny_log_interval_seconds.
            Suppressed entries are counted and included in the next message.
        """

        interval = int(getattr(self, "deny_log_interval_seconds", 60) or 60)
        if interval <= 0:
            logger.info(msg, *args)
            return

        now = time.time()
        with self._deny_log_lock:
            self._prune_deny_log_state(
                now=float(now), interval=int(interval), keep_key=str(key)
            )
            last = self._deny_log_ts.get(key, 0.0)
            if now - last < float(interval):
                self._deny_log_suppressed[key] = (
                    self._deny_log_suppressed.get(key, 0) + 1
                )
                return
            suppressed = self._deny_log_suppressed.pop(key, 0)
            self._deny_log_ts[key] = now
            self._prune_deny_log_state(
                now=float(now), interval=int(interval), keep_key=str(key)
            )

        if suppressed > 0:
            logger.info(
                msg + " (suppressed %d similar in last %ds)",
                *args,
                suppressed,
                interval,
            )
        else:
            logger.info(msg, *args)

    def _episode_suppress(self, key: str) -> bool:
        """Brief: Track a denied query for key; return whether to suppress query log.

        Inputs:
          - key: Rate-limit bucket key for this request.

        Outputs:
          - bool: True when the persistent query-log row should be suppressed.
            Returns False for the first deny_log_first_n denies in an episode
            so those queries are visible in the log, then True for the rest.
            When deny_log_first_n is 0, always returns True (suppress all).

        Notes:
          - The episode counter resets via _episode_reset() when the key's rate
            drops below the allowed threshold, so the next blocked episode
            starts fresh with another deny_log_first_n visible rows.
        """

        first_n = int(getattr(self, "deny_log_first_n", 3) or 0)
        if first_n == 0:
            return True
        with self._deny_episode_lock:
            count = self._deny_episode_count.get(key, 0) + 1
            self._deny_episode_count[key] = count
        return count > first_n

    def _episode_reset(self, key: str) -> None:
        """Brief: Reset the deny-episode counter for key.

        Inputs:
          - key: Rate-limit bucket key.

        Outputs:
          - None; removes the key from the episode counter so the next blocked
            episode starts fresh with deny_log_first_n visible query-log rows.

        Notes:
          - Called from pre_resolve whenever a request is NOT denied, signalling
            that the key's rate has returned to an acceptable level.
        """

        with self._deny_episode_lock:
            self._deny_episode_count.pop(key, None)

    def _build_deny_decision(
        self,
        qname: str,
        qtype: int,
        raw_req: bytes,
        ctx: PluginContext,
        suppress_query_log: bool = True,
    ) -> PluginDecision:
        """Brief: Build a PluginDecision for a rate-limited query.

        Inputs:
          - qname: Queried domain name.
          - qtype: DNS query type integer.
          - raw_req: Raw DNS request wire bytes.
          - ctx: PluginContext for the request.
          - suppress_query_log: When True (default), instructs the core resolver
            to skip the persistent query-log row for this deny.  Callers
            should pass False for the first deny_log_first_n denies per episode
            so that the offending client is visible in query logs.

        Outputs:
          - PluginDecision with action 'deny', 'override', or 'drop' based on
            configuration.  The suppress_query_log value is forwarded to all
            returned decisions.
        """

        mode = (getattr(self, "deny_response", "nxdomain") or "nxdomain").lower()
        if mode == "drop":
            # Drop responses are never logged (no response is sent to the client).
            return self._decision(
                action="drop", stat="rate_limit", suppress_query_log=True
            )
        if mode == "nxdomain":
            return self._decision(
                action="deny",
                stat="rate_limit",
                suppress_query_log=suppress_query_log,
            )

        if mode in {"refused", "servfail", "noerror_empty", "nodata"}:
            try:
                req = DNSRecord.parse(raw_req)
            except (
                Exception
            ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                logger.warning(
                    "failed to parse request while building deny response: %s",
                    exc,
                )
                return self._decision(
                    action="deny", stat="rate_limit", suppress_query_log=True
                )

            reply = req.reply()
            if mode == "refused":
                reply.header.rcode = RCODE.REFUSED
            elif mode == "servfail":
                reply.header.rcode = RCODE.SERVFAIL
            else:
                reply.header.rcode = RCODE.NOERROR
                # Produce NOERROR with no answers (NODATA-style response)
                reply.rr = []

            # Add EDE message for rate limit (code 17) when enable_ede is true
            try:
                from foghorn.servers.server import (
                    _echo_client_edns,
                    _attach_ede_option,
                )
                from foghorn.servers.dns_runtime_state import DNSRuntimeState

                if getattr(DNSRuntimeState, "enable_ede", False):
                    _echo_client_edns(req, reply)
                    _attach_ede_option(
                        req,
                        reply,
                        17,
                        "Rate-Limited",
                    )
            except Exception as exc:
                logger.debug("failed to attach EDE option: %s", exc)

            return self._decision(
                action="override",
                response=reply.pack(),
                stat="rate_limit",
                suppress_query_log=suppress_query_log,
            )

        if mode == "ip":
            if qtype not in {QTYPE.A, QTYPE.AAAA}:
                return self._decision(
                    action="deny",
                    stat="rate_limit",
                    suppress_query_log=suppress_query_log,
                )
            ipaddr: Optional[str] = None
            if qtype == QTYPE.A and self.deny_response_ip4:
                ipaddr = str(self.deny_response_ip4)
            elif qtype == QTYPE.AAAA and self.deny_response_ip6:
                ipaddr = str(self.deny_response_ip6)

            if ipaddr:
                wire = self._make_a_response(qname, qtype, raw_req, ctx, ipaddr)
                if wire is not None:
                    return self._decision(
                        action="override",
                        response=wire,
                        stat="rate_limit",
                        suppress_query_log=suppress_query_log,
                    )

        # Fallback: simple deny (nxdomain by default)
        return self._decision(
            action="deny",
            stat="rate_limit",
            suppress_query_log=suppress_query_log,
        )

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

        Notes:
          - Listener/transport concurrency controls (for example max_in_flight)
            are checked elsewhere and may reduce traffic before these RPS
            thresholds are reached.
        """

        if not self.targets(ctx):
            return None

        client_ip = getattr(ctx, "client_ip", None)
        if not client_ip:
            # Without a usable client identity, do not attempt to rate-limit.
            return None

        key = self._make_key(qname, ctx)
        now = time.time()

        # Update per-window counters and learn from the previous window if
        # complete. We increment the global key first so an abrupt interruption
        # between the two updates cannot leave per-key samples ahead of global
        # samples over time.
        _, global_count = self._increment_window(_GLOBAL_RPS_DB_KEY, now=now)
        global_rps = float(global_count) / float(self.window_seconds)
        _, count = self._increment_window(key, now=now)
        current_rps = float(count) / float(self.window_seconds)
        self._maybe_log_stats(now)

        if float(getattr(self, "global_max_rps", 0.0) or 0.0) > 0.0:
            global_allowed_rps = float(self.global_max_rps)
            if global_rps > global_allowed_rps:
                self._throttled_deny_log(
                    key,
                    "limiting key=%s current_rps=%.2f global_rps=%.2f "
                    "global_allowed_rps=%.2f",
                    key,
                    current_rps,
                    global_rps,
                    global_allowed_rps,
                )
                _suppress = self._episode_suppress(key)
                return self._build_deny_decision(
                    qname, qtype, req, ctx, suppress_query_log=_suppress
                )

        profile = None
        profile_is_bootstrap = False
        try:
            profile = self._db_get_profile(key)
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.warning(
                "failed to load profile for %s: %s",
                key,
                exc,
                exc_info=True,
            )

        if not profile:
            bootstrap_rps = float(getattr(self, "bootstrap_rps", 0.0) or 0.0)
            if bootstrap_rps > 0.0:
                # Bootstrap is a transient baseline for enforcement decisions
                # and should not be persisted as learned profile data. Treat it
                # as warmup-complete so configured bootstrap limits can enforce
                # immediately (instead of waiting warmup_windows windows).
                profile = (bootstrap_rps, bootstrap_rps, int(self.warmup_windows))
                profile_is_bootstrap = True
            if not profile:
                warmup_cap = float(getattr(self, "warmup_max_rps", 0.0) or 0.0)
                if warmup_cap > 0.0:
                    allowed_rps = warmup_cap
                    if self.max_enforce_rps > 0.0:
                        allowed_rps = min(allowed_rps, float(self.max_enforce_rps))
                    if current_rps > allowed_rps:
                        _suppress = self._episode_suppress(key)
                        return self._build_deny_decision(
                            qname, qtype, req, ctx, suppress_query_log=_suppress
                        )
                # No baseline yet; learning-only phase.
                self._episode_reset(key)
                return None

        avg_rps, _max_rps, samples = profile

        # Require at least warmup_windows completed windows before enforcing.
        if samples < int(self.warmup_windows):
            warmup_cap = float(getattr(self, "warmup_max_rps", 0.0) or 0.0)
            if warmup_cap > 0.0:
                allowed_rps = warmup_cap
                if self.max_enforce_rps > 0.0:
                    allowed_rps = min(allowed_rps, float(self.max_enforce_rps))
                if current_rps > allowed_rps:
                    _suppress = self._episode_suppress(key)
                    return self._build_deny_decision(
                        qname, qtype, req, ctx, suppress_query_log=_suppress
                    )
            self._episode_reset(key)
            return None
        if float(avg_rps) < float(self.min_enforce_rps):
            hard_cap_rps = float(getattr(self, "max_enforce_rps", 0.0) or 0.0)
            if hard_cap_rps > 0.0 and current_rps > hard_cap_rps:
                self._throttled_deny_log(
                    key,
                    "limiting key=%s current_rps=%.2f avg_rps=%.2f "
                    "hard_cap_rps=%.2f min_enforce_rps=%.2f",
                    key,
                    current_rps,
                    avg_rps,
                    hard_cap_rps,
                    float(self.min_enforce_rps),
                )
                _suppress = self._episode_suppress(key)
                return self._build_deny_decision(
                    qname, qtype, req, ctx, suppress_query_log=_suppress
                )
            self._episode_reset(key)
            return None

        # Derive allowed RPS from learned average and refresh thresholds at the
        # configured recalculation cadence.
        if profile_is_bootstrap:
            # During bootstrap, enforce the configured bootstrap baseline directly
            # without applying burst-factor amplification.
            baseline_allowed_rps = float(avg_rps)
            if self.max_enforce_rps > 0.0:
                baseline_allowed_rps = min(
                    float(baseline_allowed_rps),
                    float(self.max_enforce_rps),
                )
            burst_allowed_rps = float(baseline_allowed_rps)
        else:
            burst_allowed_rps, baseline_allowed_rps = (
                self._get_recalculated_allowed_rps(
                    key=str(key),
                    avg_rps=float(avg_rps),
                    samples=int(samples),
                    now=float(now),
                )
            )

        if int(getattr(self, "burst_windows", 0) or 0) > 0:
            burst_count = self._get_burst_count(key)
            if int(burst_count) >= int(self.burst_windows):
                allowed_rps = baseline_allowed_rps
            else:
                allowed_rps = burst_allowed_rps
        else:
            allowed_rps = burst_allowed_rps

        if current_rps <= allowed_rps:
            self._episode_reset(key)
            return None

        self._throttled_deny_log(
            key,
            "limiting key=%s current_rps=%.2f avg_rps=%.2f allowed_rps=%.2f",
            key,
            current_rps,
            avg_rps,
            allowed_rps,
        )
        _suppress = self._episode_suppress(key)
        return self._build_deny_decision(
            qname, qtype, req, ctx, suppress_query_log=_suppress
        )

    def get_admin_pages(self) -> list[AdminPageSpec]:
        """Brief: Describe the RateLimit admin page for the web UI.

        Inputs:
          - None; uses the plugin instance name for routing.

        Outputs:
          - list[AdminPageSpec]: A single page descriptor for rate limiting config.
        """

        return [
            AdminPageSpec(
                slug="rate-limit",
                title="Rate Limit",
                description=(
                    "Rate limiting configuration and derived settings for this RateLimit instance."
                ),
                layout="one_column",
                kind="rate_limit",
            )
        ]

    def get_admin_ui_descriptor(self) -> dict[str, object]:
        """Brief: Describe RateLimit admin UI using a generic snapshot layout.

        Inputs:
          - None (uses the plugin instance name for routing).

        Outputs:
          - dict with keys:
              * name: Effective plugin instance name.
              * title: Human-friendly tab title.
              * order: Integer ordering hint among plugin tabs.
              * endpoints: Mapping with at least a "snapshot" URL.
              * layout: Generic section/column description for the frontend.
        """

        plugin_name = getattr(self, "name", "rate_limit")
        snapshot_url = f"/api/v1/plugins/{plugin_name}/rate_limit"
        base_title = "Rate Limit"
        title = f"{base_title} ({plugin_name})" if plugin_name else base_title

        layout: dict[str, object] = {
            "sections": [
                {
                    "id": "settings",
                    "title": "Settings",
                    "type": "kv",
                    "path": "settings",
                    "rows": [
                        {"key": "mode", "label": "Mode"},
                        {"key": "window_seconds", "label": "Window (s)"},
                        {
                            "key": "limit_recalc_windows",
                            "label": "Limit recalc interval (windows)",
                        },
                        {"key": "warmup_windows", "label": "Warmup windows"},
                        {"key": "warmup_max_rps", "label": "Warmup max RPS"},
                        {"key": "burst_factor", "label": "Burst factor"},
                        {"key": "burst_windows", "label": "Burst windows"},
                        {
                            "key": "burst_reset_windows",
                            "label": "Burst reset windows",
                        },
                        {"key": "bootstrap_rps", "label": "Bootstrap RPS"},
                        {"key": "min_enforce_rps", "label": "Min enforce RPS"},
                        {
                            "key": "min_burst_threshold",
                            "label": "Min burst threshold",
                        },
                        {
                            "key": "max_enforce_rps",
                            "label": "Per-bucket max RPS",
                        },
                        {"key": "global_max_rps", "label": "Global max RPS"},
                        {"key": "current_rps", "label": "Current RPS"},
                        {"key": "rps_1m", "label": "RPS (1m)"},
                        {"key": "rps_5m", "label": "RPS (5m)"},
                        {"key": "rps_10m", "label": "RPS (10m)"},
                        {
                            "key": "stats_log_interval_seconds",
                            "label": "Stats log interval (s)",
                        },
                        {
                            "key": "stats_window_seconds",
                            "label": "Stats window (s)",
                        },
                        {
                            "key": "total_avg_rps",
                            "label": "Average RPS (total)",
                        },
                        {
                            "key": "total_max_rps",
                            "label": "Max RPS (total)",
                        },
                        {
                            "key": "window_avg_rps",
                            "label": "Average RPS (last stats_window_seconds)",
                        },
                        {
                            "key": "window_max_rps",
                            "label": "Max RPS (last stats_window_seconds)",
                        },
                        {
                            "key": "bucket_network_prefix_v4",
                            "label": "Bucket network prefix v4",
                        },
                        {
                            "key": "bucket_network_prefix_v6",
                            "label": "Bucket network prefix v6",
                        },
                        {
                            "key": "assume_udp_when_listener_missing",
                            "label": "Assume UDP when listener missing",
                        },
                        {"key": "db_path", "label": "DB path"},
                        {"key": "psl_available", "label": "PSL available"},
                    ],
                },
                {
                    "id": "config",
                    "title": "Config",
                    "type": "table",
                    "path": "config_items",
                    "columns": [
                        {"key": "key", "label": "Key"},
                        {"key": "value", "label": "Value"},
                    ],
                },
            ]
        }

        return {
            "name": str(plugin_name),
            "title": str(title),
            "order": 40,
            "endpoints": {"snapshot": snapshot_url},
            "layout": layout,
        }

    def get_http_snapshot(self) -> dict[str, object]:
        """Brief: Summarize RateLimit configuration and derived runtime settings.

        Inputs:
          - None (reads runtime-parsed attributes when setup() has run).

        Outputs:
          - dict with keys:
              * summary/config_items (from BasePlugin.get_http_snapshot)
              * settings: derived settings used for enforcement and keying
        """

        snapshot = super().get_http_snapshot()
        try:
            snapshot["config_items"] = config_to_items(dict(self.config or {}))
        except Exception:  # pragma: no cover - defensive snapshot normalization
            pass

        db_path = str(getattr(self, "db_path", self.config.get("db_path", "")) or "")
        rps_snapshot = self._get_snapshot_rps_stats()
        recent_rps_1m = float(self._get_recent_global_rps(60))
        recent_rps_5m = float(self._get_recent_global_rps(5 * 60))
        recent_rps_10m = float(self._get_recent_global_rps(10 * 60))
        snapshot["settings"] = {
            "mode": str(getattr(self, "mode", self.config.get("mode", "per_client"))),
            "window_seconds": int(
                getattr(self, "window_seconds", self.config.get("window_seconds", 10))
                or 10
            ),
            "limit_recalc_windows": int(
                getattr(
                    self,
                    "limit_recalc_windows",
                    self.config.get("limit_recalc_windows", 10),
                )
                or 10
            ),
            "warmup_windows": int(
                getattr(self, "warmup_windows", self.config.get("warmup_windows", 6))
                or 0
            ),
            "warmup_max_rps": float(
                getattr(self, "warmup_max_rps", self.config.get("warmup_max_rps", 0.0))
                or 0.0
            ),
            "alpha": float(
                getattr(self, "alpha", self.config.get("alpha", 0.2)) or 0.0
            ),
            "alpha_down": float(
                getattr(
                    self,
                    "alpha_down",
                    self.config.get("alpha_down", getattr(self, "alpha", 0.2)),
                )
                or 0.0
            ),
            "burst_factor": float(
                getattr(self, "burst_factor", self.config.get("burst_factor", 3.0))
                or 0.0
            ),
            "burst_windows": int(
                getattr(self, "burst_windows", self.config.get("burst_windows", 6)) or 0
            ),
            "burst_reset_windows": int(
                getattr(
                    self,
                    "burst_reset_windows",
                    self.config.get("burst_reset_windows", 20),
                )
                or 0
            ),
            "bootstrap_rps": float(
                getattr(self, "bootstrap_rps", self.config.get("bootstrap_rps", 0.0))
                or 0.0
            ),
            "min_enforce_rps": float(
                getattr(
                    self, "min_enforce_rps", self.config.get("min_enforce_rps", 50.0)
                )
                or 0.0
            ),
            "min_burst_threshold": float(
                getattr(
                    self,
                    "min_burst_threshold",
                    self.config.get(
                        "min_burst_threshold",
                        getattr(self, "min_enforce_rps", 50.0),
                    ),
                )
                or 0.0
            ),
            "max_enforce_rps": float(
                getattr(
                    self, "max_enforce_rps", self.config.get("max_enforce_rps", 5000.0)
                )
                or 0.0
            ),
            "global_max_rps": float(
                getattr(self, "global_max_rps", self.config.get("global_max_rps", 0.0))
                or 0.0
            ),
            "current_rps": float(self._get_current_window_rps(_GLOBAL_RPS_DB_KEY)),
            "rps_1m": float(recent_rps_1m),
            "rps_5m": float(recent_rps_5m),
            "rps_10m": float(recent_rps_10m),
            "stats_log_interval_seconds": int(
                getattr(
                    self,
                    "stats_log_interval_seconds",
                    self.config.get("stats_log_interval_seconds", 900),
                )
                or 0
            ),
            "stats_window_seconds": int(
                getattr(
                    self,
                    "stats_window_seconds",
                    self.config.get("stats_window_seconds", 0),
                )
                or 0
            ),
            "assume_udp_when_listener_missing": bool(
                getattr(
                    self,
                    "assume_udp_when_listener_missing",
                    self.config.get("assume_udp_when_listener_missing", True),
                )
            ),
            "bucket_network_prefix_v4": int(
                getattr(
                    self,
                    "bucket_network_prefix_v4",
                    self.config.get("bucket_network_prefix_v4", 24),
                )
                or 0
            ),
            "bucket_network_prefix_v6": int(
                getattr(
                    self,
                    "bucket_network_prefix_v6",
                    self.config.get("bucket_network_prefix_v6", 56),
                )
                or 0
            ),
            "deny_response": str(
                getattr(
                    self, "deny_response", self.config.get("deny_response", "nxdomain")
                )
            ),
            "psl_available": bool(getattr(self, "_psl_available", False)),
            "db_path": db_path,
            "max_profiles": int(
                getattr(self, "max_profiles", self.config.get("max_profiles", 10000))
                or 0
            ),
            "profile_ttl_seconds": int(
                getattr(
                    self,
                    "profile_ttl_seconds",
                    self.config.get("profile_ttl_seconds", 7 * 24 * 60 * 60),
                )
                or 0
            ),
            "prune_interval_seconds": int(
                getattr(
                    self,
                    "prune_interval_seconds",
                    self.config.get("prune_interval_seconds", 60),
                )
                or 0
            ),
            "total_avg_rps": float(rps_snapshot.get("total_avg_rps", 0.0) or 0.0),
            "total_max_rps": float(rps_snapshot.get("total_max_rps", 0.0) or 0.0),
            "window_avg_rps": float(rps_snapshot.get("window_avg_rps", 0.0) or 0.0),
            "window_max_rps": float(rps_snapshot.get("window_max_rps", 0.0) or 0.0),
        }

        # Keep the snapshot JSON-safe for admin UI transport.
        return snapshot

    def _get_recent_global_rps(self, lookback_seconds: int) -> float:
        """Brief: Return average global RPS over recent completed windows.

        Inputs:
          - lookback_seconds: Lookback window size in seconds.

        Outputs:
          - float: Average global RPS from rate_profile_windows over the
            lookback window, or 0.0 when unavailable.
        Notes:
          - Uses zero-fill averaging across expected completed windows in the
            lookback interval so idle periods naturally decay toward 0.0.
        """

        try:
            lookback = int(lookback_seconds)
        except Exception:
            return 0.0
        if lookback <= 0:
            return 0.0
        try:
            window_seconds = int(getattr(self, "window_seconds", 10) or 10)
        except Exception:
            window_seconds = 10
        if window_seconds <= 0:
            window_seconds = 10
        expected_windows = max(
            1,
            int(math.ceil(float(lookback) / float(window_seconds))),
        )

        conn = getattr(self, "_conn", None)
        if conn is None:
            return 0.0

        cutoff = int(time.time()) - int(lookback)
        with self._db_lock:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT COALESCE(SUM(rps), 0.0) FROM rate_profile_windows "
                    "WHERE key = ? AND last_update >= ?",
                    (_GLOBAL_RPS_DB_KEY, int(cutoff)),
                )
                row = cur.fetchone()
            except Exception:
                return 0.0
        if not row:
            return 0.0
        try:
            return float(row[0] or 0.0) / float(expected_windows)
        except Exception:
            return 0.0

    def _get_snapshot_rps_stats(self) -> dict[str, float]:
        """Brief: Compute total and windowed RPS aggregates for admin snapshots.

        Inputs:
          - None (uses sqlite profile tables and current stats_window_seconds).

        Outputs:
          - dict with:
              * total_avg_rps: Mean of learned avg_rps across all profile keys.
              * total_max_rps: Maximum learned max_rps across all profile keys.
              * window_avg_rps: Mean avg_rps over keys in the last
                stats_window_seconds (or total_avg_rps when disabled).
              * window_max_rps: Maximum max_rps over keys in the last
                stats_window_seconds (or total_max_rps when disabled).
        """

        stats: dict[str, float] = {
            "total_avg_rps": 0.0,
            "total_max_rps": 0.0,
            "window_avg_rps": 0.0,
            "window_max_rps": 0.0,
        }
        conn = getattr(self, "_conn", None)
        if conn is None:
            return stats

        stats_window_seconds = int(getattr(self, "stats_window_seconds", 0) or 0)
        with self._db_lock:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT AVG(avg_rps), MAX(max_rps) FROM rate_profiles WHERE key != ?",
                    (_GLOBAL_RPS_DB_KEY,),
                )
                row_total = cur.fetchone()
                if (
                    row_total
                ):  # pragma: no cover - defensive: sqlite aggregate fetches should always return a row
                    stats["total_avg_rps"] = float(row_total[0] or 0.0)
                    stats["total_max_rps"] = float(row_total[1] or 0.0)
            except Exception:
                return stats

            if stats_window_seconds <= 0:
                stats["window_avg_rps"] = float(stats["total_avg_rps"])
                stats["window_max_rps"] = float(stats["total_max_rps"])
                return stats

            cutoff = int(time.time()) - int(stats_window_seconds)
            try:
                cur.execute(
                    "SELECT AVG(avg_rps), MAX(max_rps) "
                    "FROM ("
                    "SELECT key, AVG(rps) AS avg_rps, MAX(rps) AS max_rps "
                    "FROM rate_profile_windows WHERE key != ? AND last_update >= ? "
                    "GROUP BY key"
                    ")",
                    (_GLOBAL_RPS_DB_KEY, int(cutoff)),
                )
                row_window = cur.fetchone()
                if (
                    row_window
                ):  # pragma: no cover - defensive: sqlite aggregate fetches should always return a row
                    stats["window_avg_rps"] = float(row_window[0] or 0.0)
                    stats["window_max_rps"] = float(row_window[1] or 0.0)
            except Exception:
                stats["window_avg_rps"] = 0.0
                stats["window_max_rps"] = 0.0
        return stats

    def shutdown(self) -> None:
        """Brief: Close sqlite3 connection on shutdown/reload.

        Inputs:
          - None.

        Outputs:
          - None (closes db connection if present).
        """

        try:
            conn = getattr(self, "_conn", None)
        except Exception:
            conn = None
        if conn is not None:
            with self._db_lock:
                try:
                    conn.close()
                except Exception:
                    pass
                self._conn = None
        super().shutdown()
