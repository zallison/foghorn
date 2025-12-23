from __future__ import annotations

from typing import Any, Optional, Tuple

from .base import CachePlugin, cache_aliases


@cache_aliases("none", "off", "disabled", "no_cache", "null")
class NullCache(CachePlugin):
    """Null cache plugin that never stores anything.

    Brief:
      This implementation disables caching while keeping the resolver pipeline
      unchanged.

    Example:
      cache:
        module: none
    """

    def __init__(self, **config: object) -> None:
        pass

    def get(self, key: Tuple[str, int]) -> Any | None:
        return None

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        return None, None, None

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        return None

    def purge(self) -> int:
        return 0
