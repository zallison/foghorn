from __future__ import annotations

from typing import Any, Optional, Tuple


def cache_aliases(*aliases: str):
    """Brief: Decorator to set aliases on a cache plugin class for discovery.

    Inputs:
      - *aliases: Variable number of alias strings.

    Outputs:
      - Callable that applies the aliases to a CachePlugin subclass and returns it.

    Example:
      >>> from foghorn.plugins.cache.base import CachePlugin, cache_aliases
      >>> @cache_aliases('none', 'null')
      ... class NullCache(CachePlugin):
      ...     pass
      >>> NullCache.aliases
      ('none', 'null')
    """

    def _wrap(cls: type) -> type:
        cls.aliases = tuple(aliases)
        return cls

    return _wrap


class CachePlugin:
    """Base class for DNS response caches.

    Brief:
      CachePlugin provides a stable public interface for caching DNS responses.
      Subclasses must implement all methods.

    Inputs:
      - None.

    Outputs:
      - CachePlugin instance.
    """

    aliases: tuple[str, ...] = ()

    def get_admin_ui_descriptor(self) -> Optional[dict[str, object]]:
        """Brief: Describe this cache plugin's admin web UI surface (if any).

        Inputs:
          - None.

        Outputs:
          - Optional[dict]: Minimal metadata describing this cache plugin's
            admin UI, or None when the cache does not contribute any admin UI.

        Notes:
          - Cache plugins that expose admin web pages should override this
            method and return a JSON-serializable mapping.

          - The returned mapping follows the same conventions as
            foghorn.plugins.resolve.base.BasePlugin.get_admin_ui_descriptor(), with
            common keys including:

              * name (str): Effective instance name used for routing and
                tab selection.
              * title (str): Human-friendly tab title for the admin UI.
              * kind (str): Short identifier used by the frontend to pick a
                renderer when needed.
              * order (int): Optional ordering hint (lower appears earlier).
              * endpoints (dict): Optional mapping of logical endpoint names to
                URLs (for example, {"snapshot": "/api/v1/cache"}).

          - The base implementation returns None so cache implementations
            without admin UI do not appear in generic discovery responses.
        """

        return None

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Lookup a cached entry.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - Any | None: Cached value if present; otherwise None.
        """

        raise NotImplementedError("CachePlugin.get() must be implemented by a subclass")

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        raise NotImplementedError(
            "CachePlugin.get_with_meta() must be implemented by a subclass"
        )

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: Store a value under key with a TTL.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).
          - ttl: int time-to-live in seconds.
          - value: Cached value.

        Outputs:
          - None.
        """

        raise NotImplementedError("CachePlugin.set() must be implemented by a subclass")

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).
        """

        raise NotImplementedError(
            "CachePlugin.purge() must be implemented by a subclass"
        )
