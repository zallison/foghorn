from __future__ import annotations

from typing import Any, Optional, Tuple

from .base import CachePlugin, cache_aliases


@cache_aliases("none", "off", "disabled", "no_cache")
class NullCache(CachePlugin):
    """Null cache plugin that never stores anything.

    Brief:
      This implementation disables caching while keeping the resolver pipeline
      unchanged.

    Inputs:
      - **config: Ignored.

    Outputs:
      - NullCache instance.

    Example:
      cache:
        module: null
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize a NullCache.

        Inputs:
          - **config: Ignored.

        Outputs:
          - None.
        """

        _ = config

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Always return None.

        Inputs:
          - key: Tuple[str, int] cache key.

        Outputs:
          - None.
        """

        _ = key
        return None

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Always return (None, None, None).

        Inputs:
          - key: Tuple[str, int] cache key.

        Outputs:
          - (None, None, None)
        """

        _ = key
        return None, None, None

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: No-op set.

        Inputs:
          - key: Tuple[str, int] cache key.
          - ttl: int seconds.
          - value: cached payload.

        Outputs:
          - None.
        """

        _ = (key, ttl, value)
        return None

    def purge(self) -> int:
        """Brief: No-op purge.

        Inputs:
          - None.

        Outputs:
          - int: Always 0.
        """

        return 0
