from __future__ import annotations

from typing import Dict, List, Tuple


TOPK_CAPACITY_FACTOR = 100
TOPK_MIN_CAPACITY = 1024


class TopK:
    """
    Approximate top-K heavy hitters tracker with bounded memory.

    Inputs (constructor):
        capacity: Target number of top items to track (K)
        prune_factor: Multiplier for pruning threshold (default 4)

    Outputs:
        TopK instance for adding keys and exporting top N

    Uses a counter dict that is pruned when size exceeds prune_factor * capacity.
    Provides O(1) amortized insertion and bounded memory.

    Example:
        >>> tracker = TopK(capacity=3, prune_factor=2)
        >>> for _ in range(10):
        ...     tracker.add('example.com')
        >>> for _ in range(5):
        ...     tracker.add('google.com')
        >>> top = tracker.export(2)
        >>> top[0][0]
        'example.com'
    """

    def __init__(self, capacity: int = 10, prune_factor: int = 4) -> None:
        """
        Initialize TopK tracker.

        Inputs:
            capacity: Target top-K size
            prune_factor: Pruning multiplier (prune when size > capacity * prune_factor)

        Outputs:
            None
        """
        self.capacity = max(1, capacity)
        self.prune_factor = max(2, prune_factor)
        self.counts: Dict[str, int] = {}

    def add(self, key: str) -> None:
        """
        Increment count for a key.

        Inputs:
            key: String key to track

        Outputs:
            None

        Example:
            >>> tracker = TopK(capacity=5)
            >>> tracker.add('example.com')
            >>> tracker.add('example.com')
        """
        self.counts[key] = self.counts.get(key, 0) + 1

        # Occasional pruning to bound memory
        if len(self.counts) > self.capacity * self.prune_factor:
            self._prune()

    def export(self, n: int) -> List[Tuple[str, int]]:
        """
        Export top N items sorted by count descending.

        Inputs:
            n: Number of top items to return

        Outputs:
            List of (key, count) tuples sorted by count descending

        Example:
            >>> tracker = TopK(capacity=5)
            >>> tracker.add('a')
            >>> tracker.add('a')
            >>> tracker.add('b')
            >>> tracker.export(2)
            [('a', 2), ('b', 1)]
        """
        items = sorted(self.counts.items(), key=lambda x: x[1], reverse=True)
        return items[:n]

    def _prune(self) -> None:
        """
        Prune to top capacity items by count.

        Inputs:
            None

        Outputs:
            None
        """
        if len(self.counts) <= self.capacity:
            return  # pragma: no cover - trivial early-exit guard

        items = sorted(self.counts.items(), key=lambda x: x[1], reverse=True)
        self.counts = dict(items[: self.capacity])
