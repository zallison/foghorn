from __future__ import annotations

import importlib
import logging
from functools import lru_cache
from typing import Any, Callable, Dict, List, Optional, Tuple

from cachetools import TTLCache, LFUCache, RRCache, cached
from cachetools.keys import hashkey


# In-process registry of functions/methods decorated with cache-aware helpers
# (registered_cached / registered_lru_cached / registered_foghorn_ttl /
# registered_sqlite_ttl). This is best-effort and intended for diagnostics in
# the admin UI rather than as a hard configuration API.
_REGISTERED_CACHED_FUNCS: List[Dict[str, Any]] = []

_logger = logging.getLogger("foghorn.utils.register_caches")


class _LruProxy:
    """Brief: Indirection wrapper so lru_cache backends can be swapped at runtime.

    Inputs:
      - target: Initial functools.lru_cache wrapper.

    Outputs:
      - _LruProxy instance exposing a mutable ``target`` attribute.
    """

    __slots__ = ("target",)

    def __init__(self, target: Callable[..., Any]) -> None:
        self.target = target


def _make_counter_entry(func: Callable[..., Any]) -> Dict[str, Any]:
    """Create a base registry entry with shared counter fields.

    This helper is used by both registered_cached and registered_lru_cached so
    that the decorated caches table can treat them uniformly.
    """

    return {
        "module": getattr(func, "__module__", None) or "",
        "name": getattr(func, "__name__", getattr(func, "__name__", "")),
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

        # Best-effort: when a cache instance is passed as the "cache" argument,
        # record its type so that backend-specific overrides (ttlcache,
        # lru_cache, foghorn_ttl, sqlite_ttl, lfu_cache, rr_cache) can be
        # targeted in config.
        cache_obj: Optional[Any] = None
        if "cache" in c_kwargs:
            cache_obj = c_kwargs.get("cache")
        elif c_args:  # positional cache argument
            cache_obj = c_args[0]

        backend_name = None
        if isinstance(cache_obj, TTLCache):
            backend_name = "ttlcache"
        elif isinstance(cache_obj, LFUCache):
            backend_name = "lfu_cache"
        elif isinstance(cache_obj, RRCache):
            backend_name = "rr_cache"
        if backend_name is not None:
            entry["backend"] = backend_name

        if isinstance(cache_obj, TTLCache):
            try:
                ttl_val = getattr(cache_obj, "ttl", None)
                maxsize_val = getattr(cache_obj, "maxsize", None)
                if isinstance(ttl_val, (int, float)):
                    entry["ttl"] = int(ttl_val)
                if isinstance(maxsize_val, int):
                    entry["maxsize"] = int(maxsize_val)
            except Exception:  # pragma: nocover defensive cache introspection
                # Never let registry introspection affect normal behavior.
                pass
        else:
            # Non-TTL cachetools backends (e.g., LFUCache, RRCache) expose
            # "maxsize" but no TTL. Record maxsize when available so that admin
            # UI and overrides can surface it.
            try:
                maxsize_generic = getattr(cache_obj, "maxsize", None)
                if isinstance(maxsize_generic, int):
                    entry["maxsize"] = int(maxsize_generic)
            except Exception:  # pragma: nocover defensive generic maxsize read
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
        # Underlying functools.lru_cache wrapper. This may be replaced at
        # runtime by apply_decorated_cache_overrides, but callers always invoke
        # the stable _wrapper closure below.
        wrapped = lru_cache(*lru_args, **lru_kwargs)(func)
        proxy = _LruProxy(wrapped)

        entry: Dict[str, Any] = _make_counter_entry(func)
        entry["cache_args"] = list(lru_args) if lru_args else []
        entry["cache_kwargs"] = dict(lru_kwargs) if lru_kwargs else {}
        entry["backend"] = "lru_cache"

        # Retain references so overrides and snapshots can see the live wrapper
        # and original function.
        entry["_lru_wrapper_ref"] = wrapped
        entry["_lru_proxy"] = proxy
        entry["_lru_orig_func"] = getattr(wrapped, "__wrapped__", func)

        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            target = proxy.target
            try:
                entry["calls_total"] += 1
            except Exception:  # pragma: nocover defensive counter update
                pass

            # Best-effort: use lru_cache statistics when available to derive
            # hit/miss counts. functools.lru_cache provides cache_info() with
            # hits and misses aggregated across the wrapper.
            before_hits = before_misses = None
            try:
                info = target.cache_info()  # type: ignore[call-arg]
                before_hits = getattr(info, "hits", None)
                before_misses = getattr(info, "misses", None)
            except Exception:  # pragma: nocover defensive cache_info read
                pass

            result = target(*args, **kwargs)

            try:
                info2 = target.cache_info()  # type: ignore[call-arg]
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
        # them continue to work. Helpers are forwarded through the proxy so
        # runtime overrides continue to respect maxsize and typed.
        def _make_forward(attr_name: str) -> Callable[..., Any]:
            def _forward(*args: Any, **kwargs: Any) -> Any:
                target = proxy.target
                fn = getattr(target, attr_name, None)
                if not callable(fn):  # pragma: nocover defensive attribute lookup
                    raise AttributeError(attr_name)
                return fn(*args, **kwargs)

            return _forward

        for attr in ("cache_info", "cache_clear", "cache_parameters", "clear"):
            try:
                if getattr(wrapped, attr, None) is not None:
                    setattr(_wrapper, attr, _make_forward(attr))
            except Exception:  # pragma: nocover defensive attribute preservation
                continue

        # Preserve __wrapped__ so introspection and tools like functools.wraps
        # continue to work as expected.
        try:
            setattr(_wrapper, "__wrapped__", getattr(wrapped, "__wrapped__", func))
        except Exception:  # pragma: nocover defensive attribute preservation
            pass

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
      - List[dict]: One entry per decorated function with module/name,
        decorator arguments, and lightweight runtime metrics. Dynamic fields
        include:

          * size_current: best-effort ``len(cache)`` when the cache exposes
            ``__len__`` or, for ``functools.lru_cache``,
            ``cache_info().currsize`` via the wrapper.
    """

    snapshot: List[Dict[str, Any]] = []
    for entry in _REGISTERED_CACHED_FUNCS:
        try:
            copy: Dict[str, Any] = dict(entry)
        except Exception:  # pragma: nocover defensive snapshot copy
            continue

        backend = copy.get("backend")
        cache_ref = copy.pop("_cache_ref", None)
        lru_wrapper = copy.pop("_lru_wrapper_ref", None)

        # TTLCache and other mapping-like backends where we have the cache
        # object itself: use len(cache).
        if cache_ref is not None:
            try:
                cur_size = len(cache_ref)  # type: ignore[arg-type]
                copy["size_current"] = int(cur_size)
            except Exception:  # pragma: nocover defensive size computation
                # size_current is best-effort only.
                pass

        # functools.lru_cache wrappers: derive current size from
        # cache_info().currsize when a live wrapper reference is available.
        if backend == "lru_cache" and lru_wrapper is not None:
            try:
                info = lru_wrapper.cache_info()  # type: ignore[call-arg]
                curr = getattr(info, "currsize", None)
                if isinstance(curr, int):
                    copy["size_current"] = curr
            except Exception:  # pragma: nocover defensive lru size computation
                pass

        snapshot.append(copy)

    return snapshot


def _apply_lru_override_for_entry(
    *,
    entry: Dict[str, Any],
    maxsize_val: Optional[int],
    ttl_val: Optional[int],
    module: str,
    name: str,
) -> None:
    """Brief: Apply maxsize/ttl overrides to a single lru_cache-backed entry.

    Inputs:
      - entry: Registry entry for a decorated lru_cache helper.
      - maxsize_val: Optional new maxsize (>= 0) or None.
      - ttl_val: Optional TTL override (ignored for lru_cache; logged only).
      - module: Module name for logging.
      - name: Function name for logging.

    Outputs:
      - None; best-effort mutation of the underlying functools.lru_cache wrapper.
    """

    if maxsize_val is None and ttl_val is None:
        return

    proxy = entry.get("_lru_proxy")
    lru_wrapper = entry.get("_lru_wrapper_ref")
    if proxy is None or lru_wrapper is None:
        return

    # TTL has no meaning for functools.lru_cache; log once per override.
    if ttl_val is not None:
        _logger.debug(
            "apply_decorated_cache_overrides: ttl override for lru_cache %s.%s "
            "is ignored (no TTL concept for functools.lru_cache)",
            module,
            name,
        )

    if maxsize_val is None:
        return

    try:
        params = lru_wrapper.cache_parameters()  # type: ignore[call-arg]
    except Exception:  # pragma: nocover defensive cache_parameters read
        params = {}

    current_max = params.get("maxsize")
    if isinstance(current_max, int) and current_max == maxsize_val:
        # Keep registry metadata in sync even when no wrapper swap is needed.
        entry["maxsize"] = int(maxsize_val)
        return

    # Rebuild the lru_cache wrapper with the new maxsize while preserving the
    # original function and the typed flag when available.
    orig_func = entry.get("_lru_orig_func") or getattr(lru_wrapper, "__wrapped__", None)
    if orig_func is None:
        _logger.debug(
            "apply_decorated_cache_overrides: missing original function for lru_cache %s.%s",
            module,
            name,
        )
        return

    typed_flag = bool(params.get("typed", False))

    try:
        new_wrapper = lru_cache(maxsize=maxsize_val, typed=typed_flag)(orig_func)
    except Exception:  # pragma: nocover defensive wrapper rebuild
        _logger.debug(
            "apply_decorated_cache_overrides: failed to rebuild lru_cache wrapper for %s.%s",
            module,
            name,
            exc_info=True,
        )
        return

    # Best-effort: clear the old wrapper so memory can be reclaimed when no
    # external references remain.
    try:
        clear_fn = getattr(lru_wrapper, "cache_clear", None) or getattr(
            lru_wrapper, "clear", None
        )
        if callable(clear_fn):
            clear_fn()
    except Exception:  # pragma: nocover defensive cache_clear
        _logger.debug(
            "apply_decorated_cache_overrides: failed to clear old lru_cache wrapper for %s.%s",
            module,
            name,
            exc_info=True,
        )

    # Point the proxy and registry at the new wrapper so subsequent calls and
    # snapshots use the updated configuration.
    try:
        proxy.target = new_wrapper
    except Exception:  # pragma: nocover defensive proxy update
        _logger.debug(
            "apply_decorated_cache_overrides: failed to update lru_cache proxy for %s.%s",
            module,
            name,
            exc_info=True,
        )

    entry["_lru_wrapper_ref"] = new_wrapper
    entry["maxsize"] = int(maxsize_val)


def registered_foghorn_ttl(
    *,
    cache: Any,
    ttl: Optional[int] = None,
    maxsize: Optional[int] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Brief: Register a helper cached via FoghornTTLCache for admin overrides.

    Inputs:
      - cache: FoghornTTLCache instance used to store helper results.
      - ttl: Optional default TTL (seconds) for stored entries (>= 0).
      - maxsize: Optional logical maxsize knob recorded in the registry. This is
        not enforced by FoghornTTLCache itself but can be used by callers.

    Outputs:
      - Decorator that applies FoghornTTLCache-based memoization and records
        metadata and lightweight counters in the registry.
    """

    base_ttl: Optional[int] = None
    if isinstance(ttl, int) and ttl >= 0:
        base_ttl = ttl

    base_maxsize: Optional[int] = None
    if isinstance(maxsize, int) and maxsize >= 0:
        base_maxsize = maxsize

    def _outer(func: Callable[..., Any]) -> Callable[..., Any]:
        entry: Dict[str, Any] = _make_counter_entry(func)
        entry["backend"] = "foghorn_ttl"
        if base_ttl is not None:
            entry["ttl"] = base_ttl
        if base_maxsize is not None:
            entry["maxsize"] = base_maxsize
        entry["_cache_ref"] = cache

        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                entry["calls_total"] += 1
            except Exception:  # pragma: nocover defensive counter update
                pass

            before_hits = before_misses = None
            try:
                before_hits = getattr(cache, "cache_hits", None)
                before_misses = getattr(cache, "cache_misses", None)
            except Exception:  # pragma: nocover defensive counter read
                pass

            key = hashkey(*args, **kwargs)
            value = cache.get(key)
            cache_miss_local = False
            if value is not None:
                # Backend counters handle hit accounting; when unavailable, fall
                # back to local counters.
                if before_hits is None:
                    try:
                        entry["cache_hits"] += 1
                    except Exception:  # pragma: nocover defensive counter update
                        pass
                return value

            cache_miss_local = before_misses is None
            result = func(*args, **kwargs)

            try:
                eff_ttl_obj = entry.get("ttl", base_ttl)
                eff_ttl = int(eff_ttl_obj) if eff_ttl_obj is not None else 0
                if eff_ttl < 0:
                    eff_ttl = 0  # pragma: nocover negative TTL guard (defensive)
            except Exception:  # pragma: nocover defensive ttl coercion
                eff_ttl = 0

            try:
                cache.set(key, eff_ttl, result)
            except Exception:  # pragma: nocover defensive cache set
                _logger.debug(
                    "registered_foghorn_ttl: failed to set cache entry for %s.%s",
                    entry.get("module"),
                    entry.get("name"),
                    exc_info=True,
                )

            try:
                after_hits = getattr(cache, "cache_hits", None)
                after_misses = getattr(cache, "cache_misses", None)
            except Exception:  # pragma: nocover defensive counter read
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
                if cache_miss_local and after_misses is None:
                    entry["cache_misses"] += 1
            except Exception:  # pragma: nocover defensive counter update
                pass

            return result

        try:
            _REGISTERED_CACHED_FUNCS.append(entry)
        except Exception:  # pragma: nocover defensive registry append

            pass

        return _wrapper

    return _outer


def registered_sqlite_ttl(
    *,
    cache: Any,
    ttl: Optional[int] = None,
    maxsize: Optional[int] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Brief: Register a helper cached via SQLite3TTLCache for admin overrides.

    Inputs:
      - cache: SQLite3TTLCache instance used to store helper results.
      - ttl: Optional default TTL (seconds) for stored entries (>= 0).
      - maxsize: Optional logical maxsize knob recorded in the registry. This is
        not enforced by SQLite3TTLCache itself but can be used by callers.

    Outputs:
      - Decorator that applies SQLite3TTLCache-based memoization and records
        metadata and lightweight counters in the registry.
    """

    base_ttl: Optional[int] = None
    if isinstance(ttl, int) and ttl >= 0:
        base_ttl = ttl

    base_maxsize: Optional[int] = None
    if isinstance(maxsize, int) and maxsize >= 0:
        base_maxsize = maxsize

    def _outer(func: Callable[..., Any]) -> Callable[..., Any]:
        entry: Dict[str, Any] = _make_counter_entry(func)
        entry["backend"] = "sqlite_ttl"
        if base_ttl is not None:
            entry["ttl"] = base_ttl
        if base_maxsize is not None:
            entry["maxsize"] = base_maxsize
        entry["_cache_ref"] = cache

        def _wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                entry["calls_total"] += 1
            except Exception:  # pragma: nocover defensive counter update
                pass

            before_hits = before_misses = None
            try:
                before_hits = getattr(cache, "cache_hits", None)
                before_misses = getattr(cache, "cache_misses", None)
            except Exception:  # pragma: nocover defensive counter read
                pass

            key = hashkey(*args, **kwargs)
            value = cache.get(key)
            cache_miss_local = False
            if value is not None:
                if before_hits is None:
                    try:
                        entry["cache_hits"] += 1  # pragma: nocover mirrored fallback from Foghorn TTL
                    except Exception:  # pragma: nocover defensive counter update
                        pass
                return value  # pragma: nocover mirrored fallback from Foghorn TTL

            cache_miss_local = before_misses is None
            result = func(*args, **kwargs)

            try:
                eff_ttl_obj = entry.get("ttl", base_ttl)
                eff_ttl = int(eff_ttl_obj) if eff_ttl_obj is not None else 0
                if eff_ttl < 0:
                    eff_ttl = 0  # pragma: nocover negative TTL guard (defensive)
            except Exception:  # pragma: nocover defensive ttl coercion
                eff_ttl = 0

            try:
                cache.set(key, eff_ttl, result)
            except Exception:  # pragma: nocover defensive cache set
                _logger.debug(
                    "registered_sqlite_ttl: failed to set cache entry for %s.%s",
                    entry.get("module"),
                    entry.get("name"),
                    exc_info=True,
                )

            try:
                after_hits = getattr(cache, "cache_hits", None)
                after_misses = getattr(cache, "cache_misses", None)
            except Exception:  # pragma: nocover defensive counter read
                after_hits = after_misses = None

            try:
                if (
                    isinstance(before_hits, int)
                    and isinstance(after_hits, int)
                    and after_hits > before_hits
                ):
                    entry["cache_hits"] += after_hits - before_hits  # pragma: nocover mirrored aggregator from Foghorn TTL
                if (
                    isinstance(before_misses, int)
                    and isinstance(after_misses, int)
                    and after_misses > before_misses
                ):
                    entry["cache_misses"] += after_misses - before_misses
                if cache_miss_local and after_misses is None:
                    entry["cache_misses"] += 1  # pragma: nocover mirrored aggregator from Foghorn TTL
            except Exception:  # pragma: nocover defensive counter update
                pass

            return result

        try:
            _REGISTERED_CACHED_FUNCS.append(entry)
        except Exception:  # pragma: nocover defensive registry append
            pass

        return _wrapper

    return _outer


def apply_decorated_cache_overrides(overrides: List[Dict[str, Any]]) -> None:
    """Brief: Apply config-driven overrides to decorated caches.

    Inputs:
      - overrides: List of mapping objects describing per-cache overrides. Each
        override may contain:

          * module: Fully-qualified module name of the decorated function.
          * name: Function ``__name__`` used in the registry.
          * backend: Optional backend filter ("ttlcache" or "lru_cache").
          * maxsize: Optional integer max size override (>= 0).
          * ttl: Optional integer TTL override in seconds (>= 0, ttlcache only).
          * reset_on_ttl_change: Optional bool controlling whether a TTL change
            clears the underlying cache when the TTL value actually changes.

    Outputs:
      - None. Mutates live cache objects and registry entries where applicable.
    """

    if not overrides:
        return

    for raw in overrides:
        if not isinstance(raw, dict):
            continue

        module = raw.get("module")
        # Accept either the newer "name" field or the legacy "name" for
        # compatibility with existing configs.
        name = raw.get("name", raw.get("name"))
        if not isinstance(module, str) or not module:
            continue
        if not isinstance(name, str) or not name:
            continue

        backend_filter_obj = raw.get("backend")
        backend_filter: Optional[str]
        if isinstance(backend_filter_obj, str) and backend_filter_obj:
            backend_filter = backend_filter_obj
        else:
            backend_filter = None

        maxsize_raw = raw.get("maxsize")
        ttl_raw = raw.get("ttl")
        reset_on_ttl_change = bool(raw.get("reset_on_ttl_change", False))

        maxsize_val: Optional[int] = None
        if isinstance(maxsize_raw, int):
            if maxsize_raw >= 0:
                maxsize_val = maxsize_raw
        elif maxsize_raw is not None:
            try:
                v = int(maxsize_raw)
                if v >= 0:
                    maxsize_val = v
            except Exception:  # pragma: nocover defensive int coercion
                pass

        ttl_val: Optional[int] = None
        if isinstance(ttl_raw, int):
            if ttl_raw >= 0:
                ttl_val = ttl_raw
        elif ttl_raw is not None:
            try:
                v = int(ttl_raw)
                if v >= 0:
                    ttl_val = v
            except Exception:  # pragma: nocover defensive int coercion
                pass

        # Import the target module best-effort so that its decorated functions
        # are registered before we walk the registry.
        try:
            importlib.import_module(module)
        except Exception:  # pragma: nocover defensive import
            # If the module cannot be imported, fallback to whatever is already
            # in the registry; this keeps behaviour best-effort.
            pass

        for entry in _REGISTERED_CACHED_FUNCS:
            try:
                emod = str(entry.get("module", "")).strip()
                eqn = str(entry.get("name", "")).strip()
                ebackend = entry.get("backend")
            except Exception:  # pragma: nocover defensive registry read
                continue

            if emod != module or eqn != name:
                continue

            if backend_filter is not None and str(ebackend) != backend_filter:
                continue

            # TTLCache-backed caches: adjust maxsize/ttl as requested.
            if ebackend == "ttlcache":
                cache_ref = entry.get("_cache_ref")
                if not isinstance(cache_ref, TTLCache):
                    continue

                old_ttl = getattr(cache_ref, "ttl", None)

                if maxsize_val is not None:
                    try:
                        cache_ref.maxsize = int(maxsize_val)
                        entry["maxsize"] = int(maxsize_val)
                    except Exception:  # pragma: nocover defensive maxsize update
                        _logger.debug(
                            "apply_decorated_cache_overrides: failed to set maxsize "
                            "for %s.%s",
                            emod,
                            eqn,
                            exc_info=True,
                        )

                if ttl_val is not None:
                    try:
                        cache_ref.ttl = int(ttl_val)
                        entry["ttl"] = int(ttl_val)

                        if (
                            reset_on_ttl_change
                            and isinstance(old_ttl, (int, float))
                            and int(old_ttl) != int(ttl_val)
                        ):
                            try:
                                cache_ref.clear()
                            except Exception:  # pragma: nocover defensive clear
                                _logger.debug(
                                    "apply_decorated_cache_overrides: failed to clear cache "
                                    "for %s.%s after TTL change",
                                    emod,
                                    eqn,
                                    exc_info=True,
                                )
                    except Exception:  # pragma: nocover defensive ttl update
                        _logger.debug(
                            "apply_decorated_cache_overrides: failed to set ttl for %s.%s",
                            emod,
                            eqn,
                            exc_info=True,
                        )

                # Nothing more to do for this entry.
                continue

            # lru_cache-backed entries: rebuild the underlying functools.lru_cache
            # wrapper with a new maxsize when requested. TTL is ignored but
            # logged for operator visibility.
            if ebackend == "lru_cache":
                _apply_lru_override_for_entry(
                    entry=entry,
                    maxsize_val=maxsize_val,
                    ttl_val=ttl_val,
                    module=emod,
                    name=eqn,
                )
                continue

            # FoghornTTLCache / SQLite3TTLCache-backed decorated caches: there is
            # no global maxsize knob on the backend itself, but we still allow
            # TTL overrides to update the registry entry so that wrapper logic
            # that consults entry["ttl"] can honor the new value.
            if ebackend in {"foghorn_ttl", "sqlite_ttl"}:
                if maxsize_val is not None:
                    try:
                        entry["maxsize"] = int(maxsize_val)
                    except Exception:  # pragma: nocover defensive maxsize record
                        _logger.debug(
                            "apply_decorated_cache_overrides: failed to record maxsize for %s.%s",
                            emod,
                            eqn,
                            exc_info=True,
                        )

                if ttl_val is not None:
                    try:
                        entry["ttl"] = int(ttl_val)
                    except Exception:  # pragma: nocover defensive ttl record
                        _logger.debug(
                            "apply_decorated_cache_overrides: failed to record ttl for %s.%s",
                            emod,
                            eqn,
                            exc_info=True,
                        )

                continue

            # LFUCache / RRCache backends from cachetools: support maxsize
            # overrides and treat ttl as a no-op with a debug log.
            if ebackend in {"lfu_cache", "rr_cache"}:
                cache_ref = entry.get("_cache_ref")
                if maxsize_val is not None and cache_ref is not None:
                    try:
                        # cachetools.LFUCache/RRCache expose ``maxsize`` as a
                        # read-only property backed by a private ``_Cache__maxsize``
                        # attribute. Updating the private field is the only way to
                        # adjust the limit at runtime.
                        setattr(cache_ref, "_Cache__maxsize", int(maxsize_val))
                        entry["maxsize"] = int(maxsize_val)
                    except Exception:  # pragma: nocover defensive maxsize update
                        _logger.debug(
                            "apply_decorated_cache_overrides: failed to set maxsize for %s.%s (backend=%s)",
                            emod,
                            eqn,
                            ebackend,
                            exc_info=True,
                        )

                if ttl_val is not None:
                    _logger.debug(
                        "apply_decorated_cache_overrides: ttl override for %s backend %s.%s "
                        "is ignored (no TTL concept for cachetools %s)",
                        ebackend,
                        emod,
                        eqn,
                        ebackend,
                    )

                continue
