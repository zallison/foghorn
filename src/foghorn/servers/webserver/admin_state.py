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
        self._temporary_records: Dict[str, Dict[str, Any]] = {}
        self._tasks: List[Dict[str, Any]] = []

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

    def upsert_temporary_record(
        self,
        *,
        key: str,
        target: str,
        plugin: str,
        payload: Dict[str, Any] | None = None,
        ttl_seconds: int = 300,
        persist: bool = False,
    ) -> Dict[str, Any]:
        """Brief: Insert or update one temporary record tracking entry.

        Inputs:
          - key: Stable unique key for the tracked record.
          - target: Record target namespace (for example etc_hosts/zone_records).
          - plugin: Plugin instance name.
          - payload: Optional compact record payload.
          - ttl_seconds: Requested temporary lifetime in seconds.
          - persist: Whether this record is persisted to disk.

        Outputs:
          - Stored temporary-record tracking payload.
        """

        now_ts = float(time.time())
        ttl_i = max(1, int(ttl_seconds or 300))
        expires_at_ts = now_ts + float(ttl_i)
        item: Dict[str, Any] = {
            "key": str(key),
            "target": str(target),
            "plugin": str(plugin),
            "persist": bool(persist),
            "ttl_seconds": int(ttl_i),
            "created_at_ts": now_ts,
            "updated_at_ts": now_ts,
            "expires_at_ts": expires_at_ts,
            "payload": dict(payload or {}),
        }
        with self._lock:
            prior = self._temporary_records.get(str(key))
            if isinstance(prior, dict):
                item["created_at_ts"] = float(prior.get("created_at_ts", now_ts) or now_ts)
            self._temporary_records[str(key)] = dict(item)
        return dict(item)

    def remove_temporary_record(self, *, key: str) -> bool:
        """Brief: Remove one temporary-record tracking entry by key.

        Inputs:
          - key: Stable record-tracking key.

        Outputs:
          - True when an entry was removed, else False.
        """

        with self._lock:
            existed = str(key) in self._temporary_records
            self._temporary_records.pop(str(key), None)
        return bool(existed)

    def list_temporary_records(
        self,
        *,
        target: str | None = None,
        plugin: str | None = None,
        include_expired: bool = True,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Brief: Return tracked temporary records with optional filters.

        Inputs:
          - target: Optional target filter.
          - plugin: Optional plugin-name filter.
          - include_expired: Whether expired records are included.
          - limit: Maximum number of records returned.

        Outputs:
          - List of temporary-record payload copies.
        """

        target_text = str(target).strip() if target is not None else ""
        plugin_text = str(plugin).strip() if plugin is not None else ""
        lim = max(1, min(int(limit or 500), 5000))
        now_ts = float(time.time())
        with self._lock:
            items = [dict(v) for v in self._temporary_records.values() if isinstance(v, dict)]
        out: List[Dict[str, Any]] = []
        for item in items:
            if target_text and str(item.get("target", "")) != target_text:
                continue
            if plugin_text and str(item.get("plugin", "")) != plugin_text:
                continue
            expires_at_ts = float(item.get("expires_at_ts", 0.0) or 0.0)
            expired = bool(expires_at_ts > 0.0 and expires_at_ts <= now_ts)
            item["expired"] = bool(expired)
            if not include_expired and expired:
                continue
            out.append(item)
        out.sort(key=lambda it: float(it.get("updated_at_ts", 0.0) or 0.0), reverse=True)
        return out[:lim]

    def purge_expired_temporary_records(self, *, now_ts: float | None = None) -> List[Dict[str, Any]]:
        """Brief: Remove and return all currently expired temporary records.

        Inputs:
          - now_ts: Optional timestamp override.

        Outputs:
          - List of removed temporary-record payloads.
        """

        now_f = float(now_ts) if now_ts is not None else float(time.time())
        removed: List[Dict[str, Any]] = []
        with self._lock:
            keys = list(self._temporary_records.keys())
            for key in keys:
                item = self._temporary_records.get(key)
                if not isinstance(item, dict):
                    continue
                expires_at_ts = float(item.get("expires_at_ts", 0.0) or 0.0)
                if expires_at_ts <= 0.0 or expires_at_ts > now_f:
                    continue
                removed.append(dict(item))
                self._temporary_records.pop(key, None)
        return removed

    def add_task(
        self,
        *,
        task_type: str,
        status: str,
        details: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Brief: Append an admin task/event record for observability.

        Inputs:
          - task_type: Task category (for example query_log.export).
          - status: Task status text.
          - details: Optional task details mapping.

        Outputs:
          - Stored task payload.
        """

        now_ts = float(time.time())
        item: Dict[str, Any] = {
            "id": f"task-{int(now_ts * 1000)}-{len(self._tasks) + 1}",
            "task_type": str(task_type or "unknown"),
            "status": str(status or "done"),
            "created_at_ts": now_ts,
            "details": dict(details or {}),
        }
        with self._lock:
            self._tasks.append(item)
            max_entries = max(1, int(self.audit_max_entries or 500))
            if len(self._tasks) > max_entries:
                del self._tasks[: len(self._tasks) - max_entries]
        return dict(item)

    def list_tasks(
        self,
        *,
        limit: int = 100,
        task_type: str | None = None,
        status: str | None = None,
    ) -> List[Dict[str, Any]]:
        """Brief: Return recent admin task/event records, newest-first.

        Inputs:
          - limit: Maximum task records to return.
          - task_type: Optional task-type filter.
          - status: Optional status filter.

        Outputs:
          - List of task payload copies.
        """

        lim = max(1, min(int(limit or 100), 1000))
        task_type_text = str(task_type).strip() if task_type is not None else ""
        status_text = str(status).strip() if status is not None else ""
        with self._lock:
            items = list(self._tasks)
        if task_type_text:
            items = [it for it in items if str(it.get("task_type", "")) == task_type_text]
        if status_text:
            items = [it for it in items if str(it.get("status", "")) == status_text]
        items = list(reversed(items))
        return [dict(it) for it in items[:lim]]
