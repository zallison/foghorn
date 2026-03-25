"""Brief: Watchdog and polling infrastructure for file changes.

Inputs/Outputs:
  - File change detection, debounced reload scheduling, periodic stat-based polling.
"""

from __future__ import annotations

import logging
import os
import pathlib
import threading
import time
from typing import Iterable, Optional


def _iter_watched_record_files(plugin: object) -> list[str]:
    """Brief: Collect all record source files that should trigger reload.

    Inputs:
      - plugin: ZoneRecords instance.

    Outputs:
      - list[str]: Concrete filesystem paths from both:
          - plugin.file_paths (Foghorn pipe-delimited records files)
          - plugin.bind_paths (BIND/RFC-1035 zone files)

    Notes:
      - bind_paths entries may be strings, dicts with a 'path' key, or typed
        objects with a .path attribute.
      - Returned paths are de-duplicated while preserving order.
    """

    paths: list[str] = []

    # Pipe-delimited records files.
    for fp in list(getattr(plugin, "file_paths", []) or []):
        try:
            text = str(fp)
        except Exception:
            continue
        if text:
            paths.append(text)

    # BIND-style zone files.
    for entry in list(getattr(plugin, "bind_paths", []) or []):
        path_val = None
        if isinstance(entry, dict):
            path_val = entry.get("path")
        elif hasattr(entry, "path"):
            path_val = getattr(entry, "path", None)
        else:
            path_val = entry

        if path_val is None:
            continue

        try:
            text = str(path_val)
        except Exception:
            continue
        if text:
            paths.append(text)

    # De-duplicate while preserving order.
    return list(dict.fromkeys(paths))


try:  # watchdog is used for cross-platform file watching
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover - defensive fallback when watchdog is unavailable
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def _path_has_parent_reference(path_text: str) -> bool:
    """Brief: Return True when a path contains explicit parent traversal.

    Inputs:
      - path_text: Raw path string from configuration.

    Outputs:
      - bool: True when ``..`` appears as a concrete path segment.
    """
    try:
        parts = pathlib.PurePath(path_text).parts
    except Exception:
        return True
    return ".." in parts


def _path_is_within_prefixes(
    candidate: pathlib.Path, prefixes: Iterable[pathlib.Path]
) -> bool:
    """Brief: Return True when a candidate path resolves under allowed prefixes.

    Inputs:
      - candidate: Resolved path to validate.
      - prefixes: Iterable of resolved directory prefixes.

    Outputs:
      - bool: True when candidate is under at least one configured prefix.
    """
    for prefix in prefixes:
        try:
            candidate.relative_to(prefix)
            return True
        except Exception:
            continue
    return False


def _resolve_watched_record_paths(plugin: object) -> list[pathlib.Path]:
    """Brief: Resolve and validate record file paths used by watchers/polling.

    Inputs:
      - plugin: ZoneRecords instance with watcher validation settings.

    Outputs:
      - list[pathlib.Path]: De-duplicated list of validated absolute file paths.

    Notes:
      - Paths with explicit ``..`` traversal segments are rejected.
      - Absolute paths may be rejected based on plugin configuration.
      - When watcher allowlist prefixes are configured, only files under those
        prefixes are accepted.
      - Maximum watched file count is enforced.
    """
    raw_paths = _iter_watched_record_files(plugin)
    allowed_prefixes = list(getattr(plugin, "_watchdog_path_allowlist", []) or [])
    reject_absolute = bool(getattr(plugin, "_watchdog_reject_absolute_paths", False))
    max_files = int(getattr(plugin, "_watchdog_max_files", 4096) or 4096)
    max_files = max(1, max_files)

    validated: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for raw in raw_paths:
        text = str(raw).strip()
        if not text:
            continue
        if _path_has_parent_reference(text):
            logger.warning(
                "Skipping records watch path %s: parent traversal ('..') is not allowed",
                text,
            )
            continue
        expanded = pathlib.Path(text).expanduser()
        if reject_absolute and expanded.is_absolute():
            logger.warning(
                "Skipping records watch path %s: absolute paths are not allowed",
                text,
            )
            continue
        try:
            resolved = expanded.resolve()
        except Exception:
            logger.warning(
                "Skipping records watch path %s: unable to resolve path", text
            )
            continue
        if allowed_prefixes and not _path_is_within_prefixes(
            resolved, allowed_prefixes
        ):
            logger.warning(
                "Skipping records watch path %s: path is outside configured watcher directories",
                resolved,
            )
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        validated.append(resolved)
        if len(validated) >= max_files:
            logger.warning(
                "Truncating watched record file list to %d entries (configured max)",
                max_files,
            )
            break
    return validated


class WatchdogHandler(FileSystemEventHandler):
    """Brief: Internal watchdog handler that reloads records on file changes.

    Inputs:
      - plugin: ZoneRecords instance to notify on changes.
      - watched_files: Iterable of concrete records file paths to track.

    Outputs:
      - None (invokes plugin._reload_records_from_watchdog when a watched path changes).
    """

    def __init__(
        self,
        plugin: object,
        watched_files: list[pathlib.Path],
    ) -> None:
        super().__init__()
        self._plugin = plugin
        self._watched = {p.resolve() for p in watched_files}

    def _should_reload(
        self, src_path: Optional[str], dest_path: Optional[str] = None
    ) -> bool:
        if not src_path and not dest_path:
            return False

        candidates = []
        if src_path:
            candidates.append(src_path)
        if dest_path:
            candidates.append(dest_path)

        for raw in candidates:
            try:
                p = pathlib.Path(raw).resolve()
            except Exception:  # pragma: no cover - extremely defensive
                continue
            if p in self._watched:
                return True
        return False

    def on_any_event(self, event) -> None:  # type: ignore[override]
        # Ignore directory-level events; we only care about concrete file writes.
        if getattr(event, "is_directory", False):
            return

        # Treat these event types as "writes". Many editors perform atomic
        # saves via create+move rather than in-place modification, so we
        # include "created" and "moved" in addition to "modified".
        event_type = getattr(event, "event_type", None)
        if event_type not in {"modified", "created", "moved"}:
            return

        src = getattr(event, "src_path", None)
        dest = getattr(event, "dest_path", None)
        if self._should_reload(src, dest):
            self._plugin._reload_records_from_watchdog()


def start_watchdog(plugin: object) -> None:
    """Brief: Start a watchdog observer to reload records files on change.

    Inputs:
      - plugin: ZoneRecords instance with file_paths and bind_paths.

    Outputs:
      - None
    """
    if Observer is None:
        logger.warning(
            "watchdog is not available; automatic ZoneRecords reload disabled",
        )
        plugin._observer = None
        return

    watched_files = _resolve_watched_record_paths(plugin)
    max_directories = int(getattr(plugin, "_watchdog_max_directories", 256) or 256)
    max_directories = max(1, max_directories)
    directories = list(dict.fromkeys([p.parent.resolve() for p in watched_files]))
    if len(directories) > max_directories:
        logger.warning(
            "Truncating watched directories from %d to %d (configured max)",
            len(directories),
            max_directories,
        )
        directories = directories[:max_directories]

    if not directories:
        plugin._observer = None
        return

    handler = WatchdogHandler(plugin, watched_files)
    observer = Observer()
    for directory in directories:
        try:
            observer.schedule(handler, str(directory), recursive=False)
            logger.debug("Watching %s", directory)
        except Exception as exc:  # pragma: no cover - log and continue
            logger.warning("Failed to watch directory %s: %s", directory, exc)
    observer.daemon = True
    observer.start()
    plugin._observer = observer


def start_polling(plugin: object) -> None:
    """Brief: Start a stat-based polling loop to detect records file changes.

    Inputs:
      - plugin: ZoneRecords instance with file_paths/bind_paths and _poll_interval.

    Outputs:
      - None

    Example:
      Called from setup() when ``watchdog_poll_interval_seconds`` is > 0.
    """
    poll_interval = getattr(plugin, "_poll_interval", 0.0)
    if poll_interval <= 0.0:
        return

    stop_event = getattr(plugin, "_poll_stop", None)
    if stop_event is None:
        # If no stop event is configured, do not start polling to avoid
        # leaking an unmanaged thread.
        return

    # Establish a baseline snapshot before the polling thread starts so the
    # first tick does not immediately trigger a redundant reload.
    try:
        _ = have_files_changed(plugin)
    except Exception:  # pragma: no cover - defensive logging only
        logger.debug("failed to establish polling baseline", exc_info=True)

    thread = threading.Thread(
        target=_poll_loop, args=(plugin,), name="CustomRecordsPoller"
    )
    thread.daemon = True
    thread.start()
    plugin._poll_thread = thread


def _poll_loop(plugin: object) -> None:
    """Brief: Background loop that periodically checks for file changes.

    Inputs:
      - plugin: ZoneRecords instance.

    Outputs:
      - None
    """
    stop_event = getattr(plugin, "_poll_stop", None)
    interval = getattr(plugin, "_poll_interval", 0.0)
    if stop_event is None or interval <= 0.0:
        return

    while not stop_event.is_set():
        try:
            if have_files_changed(plugin):
                plugin._reload_records_from_watchdog()
        except Exception:  # pragma: no cover - defensive logging
            logger.warning("Error during records polling loop", exc_info=True)

        # Wait with wakeup on stop event or timeout.
        stop_event.wait(interval)


def have_files_changed(plugin: object) -> bool:
    """Brief: Detect whether any configured records files have changed on disk.

    Inputs:
      - plugin: ZoneRecords instance with file_paths/bind_paths and _last_stat_snapshot.

    Outputs:
      - bool: True if the current stat snapshot differs from the last one.

    Example:
      First invocation records a baseline snapshot; subsequent calls only return
      True when a file's inode, size, or mtime changes.
    """
    file_paths = _resolve_watched_record_paths(plugin)
    max_entries = int(getattr(plugin, "_watchdog_snapshot_max_entries", 4096) or 4096)
    max_entries = max(1, max_entries)
    snapshot = []
    for fp in file_paths:
        fp_text = str(fp)
        try:
            st = os.stat(fp_text)
        except FileNotFoundError:
            snapshot.append((fp_text, None))
        except OSError:
            # Other OS-level errors are logged but do not crash the poller.
            logger.warning("Failed to stat records file %s", fp_text, exc_info=True)
            snapshot.append((fp_text, None))
        else:
            snapshot.append((fp_text, (st.st_ino, st.st_size, st.st_mtime)))
        if len(snapshot) >= max_entries:
            logger.warning(
                "Truncating records stat snapshot to %d entries (configured max)",
                max_entries,
            )
            break

    last = getattr(plugin, "_last_stat_snapshot", None)
    if last is None or snapshot != last:
        plugin._last_stat_snapshot = snapshot
        return True
    return False


def schedule_debounced_reload(plugin: object, delay: float) -> None:
    """Brief: Schedule a one-shot deferred reload after a minimum interval.

    Inputs:
      - plugin: ZoneRecords instance with _reload_debounce_timer.
      - delay: Seconds to wait before attempting the reload.

    Outputs:
      - None

    Example:
      Called internally when multiple watchdog events arrive within
      ``watchdog_min_interval_seconds``; coalesces them into a single
      reload instead of dropping later changes.
    """
    if delay <= 0.0:
        # If there is effectively no delay, fall back to an immediate
        # reload attempt.
        plugin._reload_records_from_watchdog()
        return

    lock = getattr(plugin, "_reload_timer_lock", None)
    if lock is None:
        # During teardown ``close()`` may have removed timer state;
        # in that case we simply avoid scheduling new work.
        return

    with lock:
        timer = getattr(plugin, "_reload_debounce_timer", None)
        if timer is not None:
            # Replace any pending timer so rapid events collapse into one
            # deferred reload at the latest requested deadline.
            try:
                timer.cancel()
            except Exception:  # pragma: no cover - defensive
                logger.debug("failed to cancel prior debounce timer", exc_info=True)

        def _timer_cb() -> None:
            # Re-enter the normal reload path; by the time this fires the
            # minimum interval will have elapsed, so the reload will be
            # performed.
            with lock:
                plugin._reload_debounce_timer = None
            try:
                plugin._reload_records_from_watchdog()
            except Exception:  # pragma: no cover - defensive logging
                logger.warning(
                    "Error during deferred records reload from watchdog",
                    exc_info=True,
                )

        timer = threading.Timer(delay, _timer_cb)
        timer.daemon = True
        plugin._reload_debounce_timer = timer
    timer.start()


def reload_records_from_watchdog(
    plugin: object,
) -> None:
    """Brief: Safely reload records mapping in response to watchdog events.

    Inputs:
      - plugin: ZoneRecords instance.

    Outputs:
      - None

    Notes:
      - Applies a minimum interval between reloads (configurable via
        ``watchdog_min_interval_seconds``) to avoid continuous reload
        loops when the act of reading the records file itself generates
        further filesystem events.
      - When multiple events arrive within the minimum interval, schedules
        a single deferred reload instead of dropping the later events.
    """
    from . import helpers, notify

    now = time.time()
    last_ts = getattr(plugin, "_last_watchdog_reload_ts", 0.0)
    min_interval = getattr(plugin, "_watchdog_min_interval", 1.0)
    elapsed = now - last_ts

    # Fast path: if we reloaded very recently, schedule a deferred reload
    # instead of skipping outright. This coalesces rapid events while still
    # ensuring that at least one reload happens after the interval.
    if elapsed < min_interval:
        remaining = max(min_interval - elapsed, 0.0)
        logger.debug(
            "Deferring records reload for %.3fs; last reload was %.3fs ago",
            remaining,
            elapsed,
        )
        schedule_debounced_reload(plugin, remaining)
        return

    # Snapshot pre-reload state so we can detect which zones changed once
    # the new records have been loaded.
    lock = getattr(plugin, "_records_lock", None)
    if lock is None:
        old_name_index = dict(getattr(plugin, "_name_index", {}) or {})
        old_zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})
    else:
        with lock:
            old_name_index = dict(getattr(plugin, "_name_index", {}) or {})
            old_zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})

    plugin._last_watchdog_reload_ts = now
    logger.info("Reloading records mapping due to filesystem change")
    try:
        plugin._load_records()
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("Failed to reload records from watchdog event: %s", exc)
        return

    # After a successful reload, compute which authoritative zones changed
    # and send DNS NOTIFY for each updated zone apex.
    if lock is None:
        new_name_index = dict(getattr(plugin, "_name_index", {}) or {})
        new_zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})
    else:
        with lock:
            new_name_index = dict(getattr(plugin, "_name_index", {}) or {})
            new_zone_soa = dict(getattr(plugin, "_zone_soa", {}) or {})

    try:
        changed_zones = helpers.compute_changed_zones(
            old_name_index,
            old_zone_soa,
            new_name_index,
            new_zone_soa,
        )
    except Exception:  # pragma: no cover - defensive logging only
        logger.warning(
            "failed to compute changed zones after reload",
            exc_info=True,
        )
        return

    try:
        notify.send_notify_for_zones(plugin, changed_zones)
    except Exception:  # pragma: no cover - defensive logging only
        logger.warning(
            "failed to send NOTIFY after records reload",
            exc_info=True,
        )
