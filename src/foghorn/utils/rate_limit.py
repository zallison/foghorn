import time
import threading
from typing import Any, Dict


class RateLimiter:
    def __init__(self):
        # State for token bucket (AXFR transfers)
        # key -> (last_seen, tokens)
        self._token_buckets: Dict[str, tuple[float, float]] = {}
        self._token_buckets_last_sweep = 0.0

        # State for window counters (DNS UPDATEs)
        # key -> {"start": float, "count": int}
        self._window_counters: Dict[str, Dict[str, Any]] = {}

        # State for concurrent transfers
        self._concurrent_transfers = 0

        self._lock = threading.Lock()

    def _get_token_bucket_idle_ttl(self, rate: float, burst: float) -> float:
        if rate <= 0.0:
            return 0.0
        refill_window = max(1.0, burst / rate)
        return max(60.0, refill_window * 4.0)

    def check_token_bucket(self, key: str, rate: float, burst: float) -> bool:
        """
        Implements token bucket rate limiting with automatic sweeping of stale entries.
        Returns True if limited, False otherwise.
        """
        now = time.monotonic()
        idle_ttl = self._get_token_bucket_idle_ttl(rate, burst)

        if rate <= 0.0:
            return False

        if not key:
            return True

        with self._lock:
            # Sweep stale entries
            if idle_ttl > 0.0 and (now - self._token_buckets_last_sweep) >= min(
                max(5.0, idle_ttl / 2.0), 60.0
            ):
                stale_before = now - idle_ttl
                stale_keys = [
                    k
                    for k, (last_seen, _) in self._token_buckets.items()
                    if float(last_seen) < stale_before
                ]
                for k in stale_keys:
                    self._token_buckets.pop(k, None)
                self._token_buckets_last_sweep = now

            # Get or initialize state
            state = self._token_buckets.get(key, (now, burst))
            last_ts, tokens = state

            elapsed = max(0.0, now - float(last_ts))
            tokens = min(burst, float(tokens) + elapsed * rate)

            if tokens < 1.0:
                self._token_buckets[key] = (now, tokens)
                return True

            self._token_buckets[key] = (now, tokens - 1.0)
            return False

    def check_window_counter(self, key: str, limit: int) -> bool:
        """
        Implements fixed-window rate limiting (1-second window).
        Returns True if limited, False otherwise.
        """
        now = time.monotonic()
        with self._lock:
            state = self._window_counters.get(key)
            if state is None:
                state = {"start": now, "count": 0}
                self._window_counters[key] = state

            if now - state["start"] >= 1.0:
                state["start"] = now
                state["count"] = 0

            if state["count"] >= limit:
                return True

            state["count"] += 1
            return False

    def acquire_concurrent_slot(self, limit: int) -> bool:
        """
        Attempts to acquire a slot for a concurrent transfer.
        Returns True if successful, False if limit reached.
        """
        with self._lock:
            if self._concurrent_transfers >= limit:
                return False
            self._concurrent_transfers += 1
            return True

    def release_concurrent_slot(self) -> None:
        """Releases a concurrent transfer slot."""
        with self._lock:
            self._concurrent_transfers = max(0, self._concurrent_transfers - 1)

    def get_concurrent_transfers_count(self) -> int:
        with self._lock:
            return self._concurrent_transfers

    def get_token_buckets_keys(self) -> list[str]:
        with self._lock:
            return list(self._token_buckets.keys())

    def clear(self):
        with self._lock:
            self._token_buckets.clear()
            self._token_buckets_last_sweep = 0.0
            self._window_counters.clear()
            self._concurrent_transfers = 0

    def get_token_buckets_count(self) -> int:
        with self._lock:
            return len(self._token_buckets)


# Global instance for shared use
# We use a singleton approach to allow both plugins to share the same rate limiting state
# as requested for the update_processor window counters.
# For token buckets, if we want isolation, we'd need separate instances,
# but for now, a single instance handles everything.
_GLOBAL_LIMITER = RateLimiter()


def check_token_bucket(key: str, rate: float, burst: float) -> bool:
    return _GLOBAL_LIMITER.check_token_bucket(key, rate, burst)


def check_window_counter(key: str, limit: int) -> bool:
    return _GLOBAL_LIMITER.check_window_counter(key, limit)


def acquire_concurrent_slot(limit: int) -> bool:
    return _GLOBAL_LIMITER.acquire_concurrent_slot(limit)


def release_concurrent_slot() -> None:
    _GLOBAL_LIMITER.release_concurrent_slot()


def clear() -> None:
    _GLOBAL_LIMITER.clear()


def get_token_buckets_count() -> int:
    return _GLOBAL_LIMITER.get_token_buckets_count()


def get_concurrent_transfers_count() -> int:
    return _GLOBAL_LIMITER.get_concurrent_transfers_count()


def get_token_buckets_keys() -> list[str]:
    return _GLOBAL_LIMITER.get_token_buckets_keys()
