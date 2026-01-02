from __future__ import annotations

import logging
import os
import pathlib
import threading
import time
from typing import Dict, Iterable, List, Optional

from dnslib import AAAA, PTR, QTYPE, RR, A, DNSHeader, DNSRecord
from pydantic import BaseModel, Field

try:  # watchdog is used for cross-platform file watching
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover - defensive fallback when watchdog is unavailable
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None  # type: ignore[assignment]

from foghorn.plugins.resolve.base import (
    AdminPageSpec,
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

logger = logging.getLogger(__name__)


class EtcHostsConfig(BaseModel):
    """Brief: Typed configuration model for EtcHosts.

    Inputs:
      - file_path: Legacy single hosts file path.
      - file_paths: Preferred list of hosts file paths.
      - watchdog_enabled: Enable watchdog-based reloads.
      - watchdog_min_interval_seconds: Minimum seconds between reloads.
      - watchdog_poll_interval_seconds: Optional polling interval.
      - ttl: Response TTL in seconds.

    Outputs:
      - EtcHostsConfig instance with normalized field types.
    """

    file_path: Optional[str] = None
    file_paths: Optional[List[str]] = None
    watchdog_enabled: Optional[bool] = None
    watchdog_min_interval_seconds: float = Field(default=1.0, ge=0)
    watchdog_poll_interval_seconds: float = Field(default=0.0, ge=0)
    ttl: int = Field(default=300, ge=0)

    class Config:
        extra = "allow"


@plugin_aliases("hosts", "hostfile", "etc-hosts", "etc_hosts", "etchosts", "/etc/hosts")
class EtcHosts(BasePlugin):
    """
    Brief: Resolve A/AAAA/PTR queries from one or more hosts files.

    Load IPs and hostnames from /etc/hosts or other host files. Supports reading
    multiple files; when the same hostname appears in more than one file, entries
    from later files override earlier ones. IPv4 entries also seed in-addr.arpa
    reverse mappings so PTR lookups for those addresses can be answered locally.
    """

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - EtcHostsConfig class for use by the core config loader.
        """

        return EtcHostsConfig

    def setup(self) -> None:
        """
        Brief: Initialize the plugin, load host mappings, and configure watchers.

        Inputs:
          - file_paths (list[str], optional): List of hosts file paths
            to load and merge in order (later overrides earlier). When omitted,
            defaults to ["/etc/hosts"].
          - watchdog_enabled (bool, optional): When True (default), start a
            watchdog-based observer to reload files automatically on change.
          - watchdog_poll_interval_seconds (float, optional): When greater than
            zero, enable a stat-based polling loop to detect changes even when
            filesystem events are not delivered (for example in some container
            or read-only bind-mount setups).

        Outputs:
          - None

        Example:
          Multiple files:
            EtcHosts(file_paths=["/etc/hosts", "/etc/hosts.d/extra"], watchdog_enabled=True)
        """

        # Normalize configuration into a list of paths. Default to /etc/hosts.
        provided = self.config.get("file_paths")
        self.file_paths: List[str] = self._normalize_paths(provided, None)

        # Internal synchronization and state
        self._hosts_lock = threading.RLock()
        self.hosts: Dict[str, str] = {}
        # Optional per-entry source tracking for admin snapshots: name -> file path.
        self._entry_sources: Dict[str, str] = {}
        self._observer = None

        # Watchdog reload debouncing: avoid tight reload loops when a single
        # change event causes additional filesystem notifications (e.g. from
        # our own reload reads).
        self._watchdog_min_interval = float(
            self.config.get("watchdog_min_interval_seconds", 1.0)
        )
        self._last_watchdog_reload_ts = 0.0
        # Timer used to coalesce multiple rapid watchdog events into a single
        # deferred reload while still guaranteeing that no change is lost.
        self._reload_debounce_timer = None
        self._reload_timer_lock = threading.Lock()

        # Polling-based fallback reload behaviour (useful when filesystem
        # events are not delivered, such as in certain container or bind-mount
        # environments).
        self._poll_interval = float(
            self.config.get("watchdog_poll_interval_seconds", 0.0)
        )
        self._last_stat_snapshot = None
        self._poll_stop = None
        self._poll_thread = None

        # Initial load
        self._load_hosts()

        self._ttl = self.config.get("ttl", 300)

        # Optionally start watchdog-based reloads
        watchdog_cfg = self.config.get("watchdog_enabled")
        if watchdog_cfg is not None:
            watchdog_enabled = bool(watchdog_cfg)
        else:
            watchdog_enabled = True

        if watchdog_enabled:
            self._start_watchdog()

        # Optional polling-based fallback for environments where filesystem
        # events are not reliably delivered (for example some Docker or
        # network filesystems). When enabled, this runs alongside watchdog and
        # is further rate-limited by the reload debouncing in
        # _reload_hosts_from_watchdog.
        if self._poll_interval > 0.0:
            logger.warning(
                "Watchdog falling back to polling every {self._poll_interval}"
            )
            self._poll_stop = threading.Event()
            self._start_polling()

    def _normalize_paths(
        self, file_paths: Optional[Iterable[str]], legacy: Optional[str]
    ) -> List[str]:
        """
        Brief: Coerce provided file path inputs into an ordered, de-duplicated list.

        Inputs:
          - file_paths: iterable of file path strings (may be None)
          - legacy: single legacy file path string (may be None)

        Outputs:
          - list[str]: Non-empty list of unique paths (order preserved). Defaults
            to ["/etc/hosts"]. If both file_paths and legacy file_path are given,
            the legacy path is included in the set of file paths.

        Example:
          _normalize_paths(["/a", "/b"], None) -> ["/a", "/b"]
          _normalize_paths(["/a", "/b"], "/a") -> ["/a", "/b"]
          _normalize_paths(None, "/a") -> ["/a"]
          _normalize_paths(None, None) -> ["/etc/hosts"]
        """
        paths: List[str] = []
        if file_paths:
            for p in file_paths:
                paths.append(os.path.expanduser(str(p)))
        if legacy:
            # Include legacy file_path in the set of file paths
            paths.append(os.path.expanduser(str(legacy)))
        if not paths:
            paths = [
                "/etc/hosts"
            ]  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        # De-duplicate while preserving order
        paths = list(dict.fromkeys(paths))
        return paths

    def _load_hosts(self) -> None:
        """
        Brief: Read hosts files and build a mapping of domain -> IP (and sources).

        - Supports comments beginning with '#', including inline comments.
        - Requires at least one hostname after the IP on each non-comment line.
        - Multiple hostnames per line are supported and mapped to the same IP.
        - When multiple files are provided, later files override earlier ones on
          conflicts for the same hostname.

        Inputs:
          - None (uses self.file_paths)
        Outputs:
          - None (populates self.hosts: Dict[str, str])
        """
        mapping: Dict[str, str] = {}
        entry_sources: Dict[str, str] = {}

        for fp in self.file_paths:
            logging.debug(f"reading hostfile: {fp}")
            hosts_path = pathlib.Path(fp)
            with hosts_path.open("r", encoding="utf-8") as f:
                for raw_line in f:
                    # Remove inline comments and surrounding whitespace
                    line = raw_line.split("#", 1)[0].strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        raise ValueError(
                            f"File {hosts_path} malformed line: {raw_line}"
                        )

                    ip = parts[0]

                    # When adding an IPv4 address, also create the corresponding
                    # in-addr.arpa reverse mapping so reverse lookups can be
                    # resolved from the same hosts data.
                    reverse_name: Optional[str] = None
                    if ":" not in ip and "." in ip:
                        octets = ip.split(".")
                        if len(octets) == 4 and all(o.isdigit() for o in octets):
                            try:
                                if all(0 <= int(o) <= 255 for o in octets):
                                    reverse_name = (
                                        ".".join(reversed(octets)) + ".in-addr.arpa"
                                    )
                            except ValueError:
                                reverse_name = None

                    for domain in parts[1:]:
                        # Later entries override earlier ones by assignment
                        mapping[domain] = ip
                        entry_sources[domain] = fp
                        if reverse_name:
                            mapping[reverse_name] = domain
                            entry_sources[reverse_name] = fp

        lock = getattr(self, "_hosts_lock", None)
        if lock is None:
            self.hosts = mapping
            self._entry_sources = entry_sources
        else:
            with lock:
                self.hosts = mapping
                self._entry_sources = entry_sources

    def get_http_snapshot(self) -> Dict[str, object]:
        """Brief: Summarize current EtcHosts mappings for the admin web UI.

        Inputs:
          - None (uses in-memory hosts mapping under a lock).

        Outputs:
          - dict with keys:
              * summary: high-level counts.
              * entries: list of per-host mappings including IPv4/IPv6 classification
                and, when available, the source file path for each entry.
        """

        lock = getattr(self, "_hosts_lock", None)
        if lock is None:
            mapping = dict(self.hosts or {})
            src_map = dict(getattr(self, "_entry_sources", {}) or {})
        else:
            with lock:
                mapping = dict(self.hosts or {})
                src_map = dict(getattr(self, "_entry_sources", {}) or {})

        entries: List[Dict[str, object]] = []
        v4_count = 0
        v6_count = 0
        ptr_count = 0

        # Sort entries so that forward records appear first and reverse
        # (PTR-style) names are pushed to the bottom of the admin view.
        def _sort_key(item: tuple[str, str]) -> tuple[int, str]:
            n, _v = item
            is_ptr = n.endswith(".in-addr.arpa") or n.endswith(".ip6.arpa")
            return (1 if is_ptr else 0, n)

        for name, value in sorted(mapping.items(), key=_sort_key):
            ip = str(value)
            source_path = src_map.get(name)
            is_ptr = name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa")
            is_v6 = ":" in ip
            is_v4 = "." in ip and not is_v6
            if is_ptr:
                ptr_count += 1
            elif is_v6:
                v6_count += 1
            elif is_v4:
                v4_count += 1

            entries.append(
                {
                    "name": name,
                    "value": ip,
                    "is_reverse": bool(is_ptr),
                    "family": "ipv6" if is_v6 else "ipv4" if is_v4 else "other",
                    "source": str(source_path) if source_path is not None else None,
                }
            )

        summary: Dict[str, object] = {
            "total_entries": len(entries),
            "ipv4_entries": v4_count,
            "ipv6_entries": v6_count,
            "reverse_entries": ptr_count,
        }

        return {"summary": summary, "entries": entries}

    def get_admin_pages(self) -> List[AdminPageSpec]:
        """Brief: Describe the EtcHosts admin page for the web UI.

        Inputs:
          - None; uses the plugin instance name for routing and data lookups.

        Outputs:
          - list[AdminPageSpec]: A single page descriptor for hosts mappings.
        """

        return [
            AdminPageSpec(
                slug="etc-hosts",
                title=f"Hosts {self.name}",
                description=(
                    "Static host mappings loaded by the EtcHosts plugin "
                    "(mirrors /etc/hosts-style files)."
                ),
                layout="one_column",
                kind="etc_hosts",
            )
        ]

    def get_admin_ui_descriptor(self) -> Dict[str, object]:
        """Brief: Describe EtcHosts admin UI using a generic snapshot layout.

        Inputs:
          - None (uses the plugin instance name for routing).

        Outputs:
          - dict with keys:
              * name: Effective plugin instance name.
              * title: Human-friendly tab title.
              * order: Integer ordering hint among plugin tabs.
              * endpoints: Mapping with at least a "snapshot" URL.
              * layout: Generic section/column description for the frontend.
        """

        plugin_name = getattr(self, "name", "etc_hosts")
        snapshot_url = f"/api/v1/plugins/{plugin_name}/etc_hosts"
        base_title = "Hosts"
        title = f"{base_title} ({plugin_name})" if plugin_name else base_title
        layout: Dict[str, object] = {
            "sections": [
                {
                    "id": "summary",
                    "title": "Summary",
                    "type": "kv",
                    "path": "summary",
                    "rows": [
                        {"key": "total_entries", "label": "Total entries"},
                        {"key": "ipv4_entries", "label": "IPv4 entries"},
                        {"key": "ipv6_entries", "label": "IPv6 entries"},
                        {"key": "reverse_entries", "label": "Reverse entries"},
                    ],
                },
                {
                    "id": "entries",
                    "title": "Entries",
                    "type": "table",
                    "path": "entries",
                    "columns": [
                        {"key": "name", "label": "Name"},
                        {"key": "value", "label": "Value"},
                        {"key": "family", "label": "Family"},
                        {"key": "is_reverse", "label": "Reverse"},
                        {"key": "source", "label": "Source"},
                    ],
                },
            ]
        }

        return {
            "name": str(plugin_name),
            "title": str(title),
            "order": 70,
            "endpoints": {"snapshot": snapshot_url},
            "layout": layout,
        }

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Brief: Return an override decision for A/AAAA/PTR when qname exists in hosts.

        Inputs:
            qname: Queried domain name (may include a trailing dot).
            qtype: DNS record type.
            req: Raw DNS request bytes.
            ctx: Plugin context.
        Outputs:
            PluginDecision("override") when domain is mapped and type is A/AAAA
            (using the stored IP) or PTR (using the stored hostname), otherwise
            None.

        """
        if not self.targets(ctx):
            return None

        qname = qname.rstrip(".")

        # Safe concurrent read from the hosts mapping when a watcher may be
        # reloading it in the background.
        lock = getattr(self, "_hosts_lock", None)
        if lock is None:
            value = self.hosts.get(qname)
        else:
            with lock:
                value = self.hosts.get(qname)

        if not value:
            return None

        # Handle reverse lookups using the precomputed in-addr.arpa entries.
        if qtype == QTYPE.PTR:
            hostname = str(value).rstrip(".") + "."
            try:
                request = DNSRecord.parse(req)
            except Exception as exc:
                logger.warning("EtcHosts: parse failure for PTR %s: %s", qname, exc)
                return PluginDecision(action="override", response=None)

            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.PTR,
                    rclass=1,
                    ttl=self._ttl,
                    rdata=PTR(hostname),
                )
            )
            return PluginDecision(action="override", response=reply.pack())

        # Only A/AAAA lookups use the stored IP value.
        if qtype not in (QTYPE.A, QTYPE.AAAA):
            return None

        ip = value

        # If the requested type doesn't match the IP version we have, let normal
        # resolution continue (avoid constructing invalid AAAA from IPv4, etc.).
        is_v6 = ":" in ip
        is_v4 = "." in ip
        if qtype == QTYPE.AAAA and is_v4 and not is_v6:
            return None
        if qtype == QTYPE.A and is_v6 and not is_v4:
            return None

        # Build a proper DNS response with the same TXID
        wire = self._make_a_response(qname, qtype, req, ctx, ip)
        return PluginDecision(action="override", response=wire)

    def _make_a_response(
        self,
        qname: str,
        query_type: int,
        raw_req: bytes,
        ctx: PluginContext,
        ipaddr: str,
    ) -> Optional[bytes]:
        try:
            request = DNSRecord.parse(raw_req)
        except Exception as e:
            logger.warning("parse failure: %s", e)
            return None

        # Normalize domain
        # qname = str(request.q.qname).rstrip(".")

        ip = ipaddr
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        if query_type == QTYPE.A:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.A,
                    rclass=1,
                    ttl=self._ttl,
                    rdata=A(ip),
                )
            )
        elif query_type == QTYPE.AAAA:
            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.AAAA,
                    rclass=1,
                    ttl=60,
                    rdata=AAAA(ip),
                )
            )

        return reply.pack()

    class _WatchdogHandler(FileSystemEventHandler):
        """Brief: Internal watchdog handler that reloads hosts on file changes.

        Inputs:
          - plugin: EtcHosts instance to notify on changes.
          - watched_files: Iterable of concrete hosts file paths to track.

        Outputs:
          - None (invokes plugin._reload_hosts_from_watchdog when a watched path changes).
        """

        def __init__(
            self,
            plugin: "EtcHosts",
            watched_files: Iterable[pathlib.Path],
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
                self._plugin._reload_hosts_from_watchdog()

    def _start_watchdog(self) -> None:
        """Brief: Start a watchdog observer to reload hosts files on change.

        Inputs:
          - None (uses self.file_paths)
        Outputs:
          - None
        """

        if Observer is None:
            logger.warning(
                "watchdog is not available; automatic /etc/hosts reload disabled",
            )
            self._observer = None
            return

        host_paths = [pathlib.Path(p).expanduser() for p in self.file_paths]
        watched_files = [p.resolve() for p in host_paths]
        directories = {p.parent.resolve() for p in host_paths}

        if not directories:
            self._observer = None
            return

        handler = self._WatchdogHandler(self, watched_files)
        observer = Observer()
        for directory in directories:
            try:
                observer.schedule(handler, str(directory), recursive=False)
                logger.debug("Watching %s", directory)
            except Exception as exc:  # pragma: no cover - log and continue
                logger.warning("Failed to watch directory %s: %s", directory, exc)

        observer.daemon = True
        observer.start()
        self._observer = observer

    def _start_polling(self) -> None:
        """Brief: Start a stat-based polling loop to detect hosts file changes.

        Inputs:
          - None (uses self.file_paths and self._poll_interval)
        Outputs:
          - None

        Example:
          Called from setup() when ``watchdog_poll_interval_seconds`` is > 0.
        """
        if self._poll_interval <= 0.0:
            return

        stop_event = getattr(self, "_poll_stop", None)
        if stop_event is None:
            # If no stop event is configured, do not start polling to avoid
            # leaking an unmanaged thread.
            return

        thread = threading.Thread(target=self._poll_loop, name="EtcHostsPoller")
        thread.daemon = True
        thread.start()
        self._poll_thread = thread

    def _poll_loop(self) -> None:
        """Brief: Background loop that periodically checks for file changes.

        Inputs:
          - None
        Outputs:
          - None
        """
        stop_event = getattr(self, "_poll_stop", None)
        interval = getattr(self, "_poll_interval", 0.0)
        if stop_event is None or interval <= 0.0:
            return

        while not stop_event.is_set():
            try:
                if self._have_files_changed():
                    self._reload_hosts_from_watchdog()
            except Exception:  # pragma: no cover - defensive logging
                logger.warning("Error during hosts polling loop", exc_info=True)

            # Wait with wakeup on stop event or timeout.
            stop_event.wait(interval)

    def _have_files_changed(self) -> bool:
        """Brief: Detect whether any configured hosts files have changed on disk.

        Inputs:
          - None (uses self.file_paths)
        Outputs:
          - bool: True if the current stat snapshot differs from the last one.

        Example:
          First invocation after setup() returns True and records baseline
          snapshot; subsequent calls only return True when a file's inode,
          size, or mtime changes.
        """
        snapshot = []
        for fp in self.file_paths:
            try:
                st = os.stat(fp)
            except FileNotFoundError:
                snapshot.append((fp, None))
            except OSError:
                # Other OS-level errors are logged but do not crash the poller.
                logger.warning("Failed to stat hosts file %s", fp, exc_info=True)
                snapshot.append((fp, None))
            else:
                snapshot.append((fp, (st.st_ino, st.st_size, st.st_mtime)))

        last = getattr(self, "_last_stat_snapshot", None)
        if last is None or snapshot != last:
            self._last_stat_snapshot = snapshot
            return True
        return False

    def _schedule_debounced_reload(self, delay: float) -> None:
        """Brief: Schedule a one-shot deferred reload after a minimum interval.

        Inputs:
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
            self._reload_hosts_from_watchdog()
            return

        lock = getattr(self, "_reload_timer_lock", None)
        if lock is None:
            # During teardown ``close()`` may have removed timer state;
            # in that case we simply avoid scheduling new work.
            return

        with lock:
            timer = getattr(self, "_reload_debounce_timer", None)
            if timer is not None and getattr(timer, "is_alive", lambda: False)():
                # A timer is already scheduled; let it perform the reload.
                return

            def _timer_cb() -> None:
                # Re-enter the normal reload path; by the time this fires the
                # minimum interval will have elapsed, so the reload will be
                # performed.
                try:
                    self._reload_hosts_from_watchdog()
                except Exception:  # pragma: no cover - defensive logging
                    logger.warning(
                        "Error during deferred hosts reload from watchdog",
                        exc_info=True,
                    )

            timer = threading.Timer(delay, _timer_cb)
            timer.daemon = True
            self._reload_debounce_timer = timer
            timer.start()

    def _reload_hosts_from_watchdog(self) -> None:
        """Brief: Safely reload hosts mapping in response to watchdog events.

        Inputs:
          - None
        Outputs:
          - None

        Notes:
          - Applies a minimum interval between reloads (configurable via
            ``watchdog_min_interval_seconds``) to avoid continuous reload
            loops when the act of reading the hosts file itself generates
            further filesystem events.
          - When multiple events arrive within the minimum interval, schedules
            a single deferred reload instead of dropping the later events.
        """
        now = time.time()
        last_ts = getattr(self, "_last_watchdog_reload_ts", 0.0)
        min_interval = getattr(self, "_watchdog_min_interval", 1.0)
        elapsed = now - last_ts

        # Fast path: if we reloaded very recently, schedule a deferred reload
        # instead of skipping outright. This coalesces rapid events while still
        # ensuring that at least one reload happens after the interval.
        if elapsed < min_interval:
            remaining = max(min_interval - elapsed, 0.0)
            logger.debug(
                "Deferring hosts reload for %.3fs; last reload was %.3fs ago",
                remaining,
                elapsed,
            )
            self._schedule_debounced_reload(remaining)
            return

        self._last_watchdog_reload_ts = now
        logger.info("Reloading hosts mapping due to filesystem change")
        try:
            self._load_hosts()
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Failed to reload hosts from watchdog event: %s", exc)

    def close(self) -> None:
        """
        Brief: Stop any background watchers and release resources.

        Inputs:
          - None
        Outputs:
          - None
        """
        observer = getattr(self, "_observer", None)
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=2.0)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
            self._observer = None

        # Stop polling loop, if configured.
        stop_event = getattr(self, "_poll_stop", None)
        if stop_event is not None:
            try:
                stop_event.set()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

        poll_thread = getattr(self, "_poll_thread", None)
        if poll_thread is not None:
            try:
                poll_thread.join(timeout=2.0)
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
            self._poll_thread = None

        # Cancel any outstanding deferred reload timer so it does not fire
        # after resources have been torn down.
        timer = getattr(self, "_reload_debounce_timer", None)
        if timer is not None:
            try:
                timer.cancel()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
            self._reload_debounce_timer = None
