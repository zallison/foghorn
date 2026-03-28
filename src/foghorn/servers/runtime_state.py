"""Shared runtime state and ring buffer helpers.

Brief:
  This module provides small, FastAPI-free building blocks that are useful both
  in the core DNS server startup path and in optional HTTP components:
    - RingBuffer: a thread-safe fixed-size buffer used for recent log-like items
    - RuntimeState: thread-safe listener readiness state used by /ready endpoints

Inputs:
  - None (library module)

Outputs:
  - RingBuffer and RuntimeState classes.

Notes:
  - These types were intentionally moved out of foghorn.servers.webserver so
    that a minimal/headless build can import foghorn.main without pulling in
    FastAPI/uvicorn.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from foghorn.utils.register_caches import registered_ttl_cache


class RingBuffer:
    """Brief: Thread-safe fixed-size ring buffer of arbitrary items.

    Inputs (constructor):
      - capacity: Maximum number of items to retain (int, >= 1)

    Outputs:
      - RingBuffer instance with push() and snapshot() helpers.

    Example:
      >>> buf = RingBuffer(capacity=2)
      >>> buf.push('a')
      >>> buf.push('b')
      >>> buf.snapshot()
      ['a', 'b']
      >>> buf.push('c')
      >>> buf.snapshot()
      ['b', 'c']
    """

    def __init__(self, capacity: int = 500) -> None:
        if capacity <= 0:
            capacity = 1

        self._capacity = int(capacity)
        self._items: List[Any] = []
        self._lock = threading.Lock()

    def push(self, item: Any) -> None:
        """Brief: Append an item, evicting the oldest when capacity is exceeded.

        Inputs:
          - item: Any JSON-serializable value.

        Outputs:
          - None.
        """

        with self._lock:
            self._items.append(item)
            if len(self._items) > self._capacity:
                overflow = len(self._items) - self._capacity
                if overflow > 0:
                    self._items = self._items[overflow:]

    @registered_ttl_cache(maxsize=1, ttl=10)
    def snapshot(self, limit: Optional[int] = None) -> List[Any]:
        """Brief: Return a copy of buffered items, optionally truncated to newest N.

        Inputs:
          - limit: Optional int maximum number of items to return (newest last).

        Outputs:
          - list[Any]: Items suitable for JSON serialization.
        """

        with self._lock:
            data = list(self._items)
        if limit is not None and limit >= 0:
            data = data[-limit:]
        return data


@dataclass
class _ListenerRuntime:
    """Brief: Track the runtime state of a single listener for readiness checks.

    Inputs (fields):
      - name: Logical listener name (e.g. 'udp', 'tcp', 'dot', 'doh', 'webserver').
      - enabled: Whether this listener is expected to be running.
      - thread: Optional thread-like object that may implement is_alive() or
        is_running().
      - error: Optional string describing a startup/runtime error.

    Outputs:
      - _ListenerRuntime instance used inside RuntimeState.
    """

    name: str
    enabled: bool
    thread: Any | None = None
    error: str | None = None


def _thread_is_alive(obj: Any | None) -> bool:
    """Brief: Best-effort check whether a thread/handle is alive.

    Inputs:
      - obj: Thread-like object (may implement is_alive() or is_running()) or None.

    Outputs:
      - bool: True when obj appears to be running; False otherwise.
    """

    if obj is None:
        return False
    try:
        fn = getattr(obj, "is_alive", None)
        if callable(fn):
            return bool(fn())
    except Exception:
        return False

    try:
        fn = getattr(obj, "is_running", None)
        if callable(fn):
            return bool(fn())
    except Exception:
        return False

    return False


class RuntimeState:
    """Brief: Shared, thread-safe runtime state used by /ready endpoints.

    Inputs (constructor):
      - startup_complete: Optional bool indicating whether main startup has completed.

    Outputs:
      - RuntimeState instance whose snapshot() returns a JSON-safe mapping
        describing listener readiness.

    Example:
      >>> state = RuntimeState()
      >>> state.set_listener('udp', enabled=True, thread=None)
      >>> state.mark_startup_complete()
      >>> bool(state.snapshot().get('startup_complete'))
      True
    """

    def __init__(self, startup_complete: bool = False) -> None:
        self._lock = threading.Lock()
        self._startup_complete = bool(startup_complete)
        self._listeners: Dict[str, _ListenerRuntime] = {}

    def mark_startup_complete(self) -> None:
        """Brief: Mark the process as having completed startup.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        with self._lock:
            self._startup_complete = True

    def set_listener(self, name: str, *, enabled: bool, thread: Any | None) -> None:
        """Brief: Register or update a listener entry.

        Inputs:
          - name: Listener name string.
          - enabled: Whether the listener is expected to be running.
          - thread: Optional thread/handle object.

        Outputs:
          - None.
        """

        if not name:
            return
        with self._lock:
            current = self._listeners.get(name)
            error = current.error if current is not None else None
            self._listeners[name] = _ListenerRuntime(
                name=str(name),
                enabled=bool(enabled),
                thread=thread,
                error=error,
            )

    def set_listener_error(self, name: str, exc: Exception | str) -> None:
        """Brief: Attach an error message to a listener entry.

        Inputs:
          - name: Listener name string.
          - exc: Exception instance or error string.

        Outputs:
          - None.
        """

        if not name:
            return
        msg = str(exc)
        with self._lock:
            current = self._listeners.get(name)
            enabled = current.enabled if current is not None else True
            thread = current.thread if current is not None else None
            self._listeners[name] = _ListenerRuntime(
                name=str(name),
                enabled=bool(enabled),
                thread=thread,
                error=msg,
            )

    @registered_ttl_cache(maxsize=1, ttl=10)
    def snapshot(self) -> Dict[str, Any]:
        """Brief: Return a JSON-safe snapshot of current runtime state.

        Inputs:
          - None.

        Outputs:
          - dict with keys:
              * startup_complete: bool
              * listeners: mapping of listener name -> {enabled, running, error}
        """

        with self._lock:
            listeners = {
                name: {
                    "enabled": entry.enabled,
                    "running": _thread_is_alive(entry.thread),
                    "error": entry.error,
                }
                for name, entry in self._listeners.items()
            }
            return {
                "startup_complete": bool(self._startup_complete),
                "listeners": listeners,
            }
