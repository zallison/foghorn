from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from cachetools import TTLCache, cached
from cachetools.keys import hashkey
from functools import lru_cache


# In-process registry of functions/methods decorated with cachetools.cached
# via registered_cached(). This is best-effort and intended for diagnostics in
# the admin UI rather than as a hard configuration API.
_REGISTERED_CACHED_FUNCS: List[Dict[str, Any]] = []


def _make_counter_entry(func: Callable[..., Any]) -> Dict[str, Any]:
    """Create a base registry entry with shared counter fields.

    This helper is used by both registered_cached and registered_lru_cached so
    that the decorated caches table can treat them uniformly.
    """

    return {
        "module": getattr(func, "__module__", None) or "",
        "qualname": getattr(func, "__qualname__", getattr(func, "__name__", "")),
        "cache_args": [],
        "cache_kwargs": {},
        "calls_total": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "backend": None,
    }


def registered_cached(
    *c_args: Any, **c_kwargs: Any
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Brief: Wrap cachetools.cached and record decorated functions for admin UI.

    Inputs:
      - *c_args, **c_kwargs: Positional/keyword args forwarded to cachetools.cached.

    Outputs:
      - Decorator that applies cachetools.cached and records metadata about the
        wrapped function in a process-local registry.
    """

    def _outer(func: Callable[..., Any]) -> Callable[..., Any]:
        # Install the underlying cachetools decorator first.
        wrapped = cached(*c_args, **c_kwargs)(func)

        # Registry entry describing this decorated function. The counters are
        # updated in the wrapper below so that admin snapshots can expose live
        # hit/miss metrics without having to introspect the cache object.
        entry: Dict[str, Any] = _make_counter_entry(func)
        entry["cache_args"] = list(c_args) if c_args else []
        entry["cache_kwargs"] = dict(c_kwargs) if c_kwargs else {}
        entry["backend"] = "ttlcache"

        # Best-effort: when a TTLCache instance is passed as the "cache"
        # argument, record its ttl/maxsize so admin UI can display them without
        # having to introspect live objects.
        cache_obj: Optional[Any] = None
        if "cache" in c_kwargs:
            cache_obj = c_kwargs.get("cache")
        elif c_args:  # positional cache argument
            cache_obj = c_args[0]

        if isinstance(cache_obj, TTLCache):
            try:
                ttl_val = getattr(cache_obj, "ttl", None)
                maxsize_val = getattr(cache_obj, "maxsize", None)
                if isinstance(ttl_val, (int, float)):
                    entry["ttl"] = int(ttl_val)
                if isinstance(maxsize_val, int):
                    entry["maxsize"] = maxsize_val
            except Exception:  # pragma: nocover defensive cache introspection
                # Never let registry introspection affect normal behavior.
                pass

        # Retain a non-serialized reference to the underlying cache object so we
        # can compute dynamic metrics (like current size) in get_registered_cached.
        if cache_obj is not None:
            entry["_cache_ref"] = cache_obj

        # Determine the cache key function used by cachetools.cached so we can
        # best-effort distinguish hits from misses.
        key_func: Callable[..., Tuple[Any, ...]]
        if "key" in c_kwargs and callable(c_kwargs["key"]):
            key_func = c_kwargs["key"]  # type: ignore[assignment]
        else:
            key_func = hashkey

        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            # Update total call counter.
            try:
                entry["calls_total"] += 1
            except Exception:  # pragma: nocover defensive counter update
                pass

            # Attempt to classify this call as a cache hit or miss by checking
            # membership before and after invocation. This is approximate but
            # sufficient for operator-facing diagnostics.
            had_key: Optional[bool] = None
            if cache_obj is not None:
                try:
                    cache_key = key_func(*args, **kwargs)
                    had_key = cache_key in cache_obj  # type: ignore[operator]
                except Exception:  # pragma: nocover defensive key computation
                    had_key = None

            result = wrapped(*args, **kwargs)

            if cache_obj is not None:
                try:
                    cache_key_after = key_func(*args, **kwargs)
                    has_now = cache_key_after in cache_obj  # type: ignore[operator]
                except Exception:  # pragma: nocover defensive key computation
                    has_now = None

                try:
                    if had_key is True:
                        entry["cache_hits"] += 1
                    elif had_key is False and has_now:
                        entry["cache_misses"] += 1
                except Exception:  # pragma: nocover defensive counter update
                    pass

            return result

        # Preserve the underlying cache attribute so tests and callers that
        # rely on func.cache continue to function.
        try:
            cache_attr = getattr(wrapped, "cache", None)
            if cache_attr is not None:
                setattr(_wrapper, "cache", cache_attr)
        except Exception:  # pragma: nocover defensive cache attribute preservation
            pass

        try:
            _REGISTERED_CACHED_FUNCS.append(entry)
        except Exception:  # pragma: nocover defensive registry append
            # Best-effort only: registry failures must not affect normal behavior.
            pass

        return _wrapper

    return _outer


def registered_lru_cached(
    *lru_args: Any, **lru_kwargs: Any
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Brief: Wrap functools.lru_cache and record decorated functions for admin UI.

    Inputs:
      - *lru_args, **lru_kwargs: Positional/keyword args forwarded to
        functools.lru_cache.

    Outputs:
      - Decorator that applies lru_cache and records metadata and lightweight
        counters in the registry.
    """

    def _outer(func: Callable[..., Any]) -> Callable[..., Any]:
        wrapped = lru_cache(*lru_args, **lru_kwargs)(func)

        entry: Dict[str, Any] = _make_counter_entry(func)
        entry["cache_args"] = list(lru_args) if lru_args else []
        entry["cache_kwargs"] = dict(lru_kwargs) if lru_kwargs else {}
        entry["backend"] = "lru_cache"

        # Attempt to retain a reference to the underlying cache mapping so that
        # size_current can be computed in get_registered_cached(). For CPython's
        # lru_cache, the wrapper exposes cache_parameters() and clear() but not
        # the internal dict, so we fall back to hits/misses only.
        cache_ref: Optional[Any] = None
        try:
            cache_ref = getattr(wrapped, "cache", None)
        except Exception:  # pragma: nocover defensive cache_ref lookup
            cache_ref = None
        if cache_ref is not None:
            entry["_cache_ref"] = cache_ref

        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                entry["calls_total"] += 1
            except Exception:  # pragma: nocover defensive counter update
                pass

            # Best-effort: use lru_cache statistics when available to derive
            # hit/miss counts. functools.lru_cache provides cache_info() with
            # hits and misses aggregated across the wrapper.
            before_hits = before_misses = None
            try:
                info = wrapped.cache_info()
                before_hits = getattr(info, "hits", None)
                before_misses = getattr(info, "misses", None)
            except Exception:  # pragma: nocover defensive cache_info read
                pass

            result = wrapped(*args, **kwargs)

            try:
                info2 = wrapped.cache_info()
                after_hits = getattr(info2, "hits", None)
                after_misses = getattr(info2, "misses", None)
            except Exception:  # pragma: nocover defensive cache_info read
                after_hits = after_misses = None

            try:
                if (
                    isinstance(before_hits, int)
                    and isinstance(after_hits, int)
                    and after_hits > before_hits
                ):
                    entry["cache_hits"] += after_hits - before_hits
                if (
                    isinstance(before_misses, int)
                    and isinstance(after_misses, int)
                    and after_misses > before_misses
                ):
                    entry["cache_misses"] += after_misses - before_misses
            except Exception:  # pragma: nocover defensive counter update
                pass

            return result

        # Preserve lru_cache helpers where possible so callers/tests that rely on
        # them continue to work.
        for attr in ("cache_info", "cache_clear", "cache_parameters", "clear"):
            try:
                val = getattr(wrapped, attr, None)
                if val is not None:
                    setattr(_wrapper, attr, val)
            except Exception:  # pragma: nocover defensive attribute preservation
                continue

        try:
            _REGISTERED_CACHED_FUNCS.append(entry)
        except Exception:  # pragma: nocover defensive registry append
            pass

        return _wrapper

    return _outer


def get_registered_cached() -> List[Dict[str, Any]]:
    """Brief: Return a snapshot of all functions decorated with registered_cached.

    Inputs:
      - None.

    Outputs:
      - List[dict]: One entry per decorated function with module/qualname,
        decorator arguments, and lightweight runtime metrics. Dynamic fields
        include:

          * size_current: best-effort ``len(cache)`` when the cache exposes
            ``__len__``.
    """

    snapshot: List[Dict[str, Any]] = []
    for entry in _REGISTERED_CACHED_FUNCS:
        try:
            copy: Dict[str, Any] = dict(entry)
        except Exception:  # pragma: nocover defensive snapshot copy
            continue

        cache_ref = copy.pop("_cache_ref", None)
        if cache_ref is not None:
            try:
                cur_size = len(cache_ref)  # type: ignore[arg-type]
                copy["size_current"] = int(cur_size)
            except Exception:  # pragma: nocover defensive size computation
                # size_current is best-effort only.
                pass

        snapshot.append(copy)

    return snapshot
