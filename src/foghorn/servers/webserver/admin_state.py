"""Shared in-memory admin runtime state for webserver action APIs.

This module provides a thread-safe state container used by both:
- FastAPI handlers (via app.state), and
- the threaded fallback handler (via _AdminHTTPServer attributes).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class AdminRuntimeState:
    """Brief: Thread-safe runtime state used by admin action routes.

    Inputs:
      - audit_max_entries: Maximum number of in-memory audit events retained.

    Outputs:
      - AdminRuntimeState instance storing:
          * last config verification payload
          * restart scheduling metadata
          * bounded admin action audit events
    """

    audit_max_entries: int = 500

    def __post_init__(self) -> None:
        """Brief: Initialize synchronization primitives and in-memory fields.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        self._lock = threading.RLock()
        self._last_config_verify: Dict[str, Any] | None = None
        self._restart_pending: Dict[str, Any] | None = None
        self._audit_events: List[Dict[str, Any]] = []

    def set_last_config_verify(self, payload: Dict[str, Any]) -> None:
        """Brief: Store last config verify result payload.

        Inputs:
          - payload: Verify result dictionary.

        Outputs:
          - None.
        """

        with self._lock:
            self._last_config_verify = dict(payload or {})

    def get_last_config_verify(self) -> Dict[str, Any] | None:
        """Brief: Return a copy of the last config verify payload.

        Inputs:
          - None.

        Outputs:
          - Optional verification payload copy.
        """

        with self._lock:
            if self._last_config_verify is None:
                return None
            return dict(self._last_config_verify)

    def set_restart_pending(
        self,
        *,
        delay_seconds: float,
        reason: str | None = None,
        signal_name: str = "SIGHUP",
    ) -> Dict[str, Any]:
        """Brief: Record restart scheduling metadata.

        Inputs:
          - delay_seconds: Scheduled restart delay.
          - reason: Optional human-readable reason.
          - signal_name: Signal identifier used to restart process.

        Outputs:
          - Recorded restart metadata payload.
        """

        now_ts = float(time.time())
        payload: Dict[str, Any] = {
            "scheduled": True,
            "signal": str(signal_name),
            "delay_seconds": float(delay_seconds),
            "scheduled_at_ts": now_ts,
            "expected_at_ts": now_ts + float(delay_seconds),
            "reason": (str(reason) if reason is not None else None),
        }
        with self._lock:
            self._restart_pending = dict(payload)
        return payload

    def get_restart_pending(self) -> Dict[str, Any] | None:
        """Brief: Return a copy of currently recorded restart metadata.

        Inputs:
          - None.

        Outputs:
          - Optional restart metadata payload copy.
        """

        with self._lock:
            if self._restart_pending is None:
                return None
            return dict(self._restart_pending)

    def add_audit_event(
        self,
        *,
        action: str,
        target: str,
        ok: bool,
        details: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Brief: Append an admin action audit event to the bounded ring.

        Inputs:
          - action: Action name (for example 'query_log.clear').
          - target: Action target identifier.
          - ok: Whether the action succeeded.
          - details: Optional compact metadata for the event.

        Outputs:
          - Stored audit event payload.
        """

        event: Dict[str, Any] = {
            "ts": float(time.time()),
            "action": str(action or ""),
            "target": str(target or ""),
            "ok": bool(ok),
            "details": dict(details or {}),
        }
        with self._lock:
            self._audit_events.append(event)
            max_entries = max(1, int(self.audit_max_entries or 500))
            if len(self._audit_events) > max_entries:
                del self._audit_events[: len(self._audit_events) - max_entries]
        return dict(event)

    def list_audit_events(
        self,
        *,
        limit: int = 100,
        action: str | None = None,
    ) -> List[Dict[str, Any]]:
        """Brief: Return recent audit events, newest-first.

        Inputs:
          - limit: Maximum number of events to return.
          - action: Optional exact action filter.

        Outputs:
          - List of audit event payload copies.
        """

        lim = max(1, min(int(limit or 100), 1000))
        action_text = str(action).strip() if action is not None else ""
        with self._lock:
            events = list(self._audit_events)
        if action_text:
            events = [it for it in events if str(it.get("action", "")) == action_text]
        events = list(reversed(events))
        return [dict(it) for it in events[:lim]]

    def clear_audit_events(self) -> int:
        """Brief: Remove all retained audit events.

        Inputs:
          - None.

        Outputs:
          - Number of removed events.
        """

        with self._lock:
            count = len(self._audit_events)
            self._audit_events.clear()
        return int(count)
