from __future__ import annotations

import logging
import os
import pathlib
import threading
import time
from typing import Dict, Iterable, List, Optional, Tuple

from dnslib import QTYPE, RCODE, RR, DNSHeader, DNSRecord
from pydantic import BaseModel, Field

try:  # watchdog is used for cross-platform file watching
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover - defensive fallback when watchdog is unavailable
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None  # type: ignore[assignment]

from foghorn.plugins.resolve.base import (
    BasePlugin,
    PluginContext,
    PluginDecision,
    plugin_aliases,
)

logger = logging.getLogger(__name__)


class ZoneRecordsConfig(BaseModel):
    """Brief: Typed configuration model for ZoneRecords.

    Inputs:
      - file_path: Legacy single records file path.
      - file_paths: Preferred list of records file paths.
      - records: Optional list of inline records using
        ``<domain>|<qtype>|<ttl>|<value>`` format.
      - watchdog_enabled: Enable watchdog-based reloads.
      - watchdog_min_interval_seconds: Minimum seconds between reloads.
      - watchdog_poll_interval_seconds: Optional polling interval.
      - ttl: Default TTL in seconds.

    Outputs:
      - ZoneRecordsConfig instance with normalized field types.
    """

    file_path: Optional[str] = None
    file_paths: Optional[List[str]] = None
    records: Optional[List[str]] = None
    watchdog_enabled: Optional[bool] = None
    watchdog_min_interval_seconds: float = Field(default=1.0, ge=0)
    watchdog_poll_interval_seconds: float = Field(default=0.0, ge=0)
    ttl: int = Field(default=300, ge=0)

    class Config:
        extra = "allow"


@plugin_aliases("zone", "zone_records", "custom", "records")
class ZoneRecords(BasePlugin):

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - ZoneRecordsConfig class for use by the core config loader.
        """

        return ZoneRecordsConfig

    def setup(self) -> None:
        """
        Brief: Initialize the plugin, load record mappings, and configure watchers.

        Inputs:
          - file_paths (list[str], optional): List of records file paths
            to load and merge in order (later overrides earlier).
          - file_path (str, optional): Legacy single records file path.
          - records (list[str], optional): Inline records using
            ``<domain>|<qtype>|<ttl>|<value>`` format; merged after any
            file-backed records.
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
            ZoneRecords(file_paths=["/foghorn/conf/var/records.txt", "/etc/records.d/extra.txt"], watchdog_enabled=True)
        """

        # Normalize configuration into a list of paths, allowing either
        # file_paths or legacy file_path. When neither is provided but inline
        # records are configured, file-backed paths remain empty.
        provided_paths = self.config.get("file_paths")
        legacy_path = self.config.get("file_path")
        inline_records_cfg = self.config.get("records")

        if provided_paths is not None or legacy_path is not None:
            self.file_paths = self._normalize_paths(provided_paths, legacy_path)
        elif inline_records_cfg:
            # Inline-only configuration; no file-backed records.
            self.file_paths = []
        else:
            # Preserve historical behaviour: fail fast when no sources are set.
            self.file_paths = self._normalize_paths(None, None)

        # Cache inline records (if any) for use by _load_records().
        try:
            self._inline_records = list(inline_records_cfg or [])
        except Exception:  # pragma: no cover - defensive: config may be non-iterable
            self._inline_records = []

        # Internal synchronization and state
        self._records_lock = threading.RLock()
        # Mapping of (domain, qtype) -> (ttl, ordered list of unique values)
        self.records: Dict[Tuple[str, int], Tuple[int, List[str]]] = {}
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
        self._load_records()

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
        # _reload_records_from_watchdog.
        if self._poll_interval > 0.0:
            logger.warning(
                "ZoneRecords Watchdog falling back to polling every {self._poll_interval}"
            )
            self._poll_stop = threading.Event()
            self._start_polling()

    def _normalize_paths(
        self, file_paths: Optional[Iterable[str]], legacy: Optional[str]
    ) -> List[str]:
        """Brief: Coerce provided file path inputs into an ordered, de-duplicated list.

        Inputs:
          - file_paths: iterable of file path strings (may be None)
          - legacy: single legacy file path string (may be None)

        Outputs: - list[str]: Non-empty list of unique paths (order preserved).
        If both file_paths and legacy file_path are given, the legacy path is included in the set of file paths.

        Example:
          _normalize_paths(["/a", "/b"], None) -> ["/a", "/b"]
          _normalize_paths(["/a", "/b"], "/a") -> ["/a", "/b"]
          _normalize_paths(None, "/a") -> ["/a"]
          _normalize_paths(None, None) -> []

        """
        paths: List[str] = []
        if file_paths:
            for p in file_paths:
                paths.append(os.path.expanduser(str(p)))
        if legacy:
            # legacy is kept only for the internal API; external configs must use
            # file_paths and should never set legacy.
            paths.append(os.path.expanduser(str(legacy)))
        if not paths:
            raise ValueError(f"No paths given {self.config}")
        # De-duplicate while preserving order
        paths = list(dict.fromkeys(paths))
        return paths

    def _load_records(self) -> None:
        """Brief: Read custom records files and build lookup structures.

        Inputs:
          - None (uses self.file_paths and any inline records from config).

        Outputs:
          - None (populates:
              - self.records: Dict[(domain, qtype), (ttl, [values])]
              - self._name_index: Dict[domain, Dict[qtype, (ttl, [values])]]
              - self._zone_soa: Dict[zone_apex, (ttl, [soa_values])]
            )
        """
        # Build fresh mappings so that reloads are atomic when swapped in.
        #
        # For each (domain, qtype) key we:
        #   - preserve the order in which values appear across files
        #   - de-duplicate values, keeping the first occurrence
        #   - keep the TTL from the first occurrence (later duplicates are
        #     ignored entirely)
        mapping: Dict[Tuple[str, int], Tuple[int, List[str]]] = {}
        name_index: Dict[str, Dict[int, Tuple[int, List[str]]]] = {}
        zone_soa: Dict[str, Tuple[int, List[str]]] = {}

        # Resolve the SOA type code using getattr with a safe default and fall
        # back to QTYPE.get so that tests which monkeypatch QTYPE continue to
        # work as expected, without relying on QTYPE.SOA being present.
        try:
            raw = getattr(QTYPE, "SOA", None)
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            raw = None
        if raw is None:
            try:
                raw = QTYPE.get("SOA", None)
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                raw = None
        try:
            soa_code: Optional[int] = int(raw) if raw is not None else None
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            soa_code = None

        def _process_line(raw_line: str, source_label: str, lineno: int) -> None:
            """Brief: Parse a single record line and merge it into mappings.

            Inputs:
              - raw_line: Original line text including any comments.
              - source_label: Human-readable source identifier (file path or
                inline config label).
              - lineno: 1-based line number within the source.

            Outputs:
              - None; updates mapping, name_index, and zone_soa in-place.
            """
            # Remove inline comments and surrounding whitespace
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                return

            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 4:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"expected <domain>|<qtype>|<ttl>|<value>, got {raw_line!r}"
                )

            domain_raw, qtype_raw, ttl_raw, value_raw = parts
            if not domain_raw or not qtype_raw or not ttl_raw or not value_raw:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"empty field in {raw_line!r}"
                )

            domain = domain_raw.rstrip(".").lower()

            # Parse qtype as number or mnemonic (e.g., "A", "AAAA").
            qtype_code: Optional[int]
            if qtype_raw.isdigit():
                qtype_code = int(qtype_raw)
            else:
                name = qtype_raw.upper()
                try:
                    qtype_code = int(getattr(QTYPE, name))
                except AttributeError:
                    qtype_val = QTYPE.get(name, None)
                    qtype_code = int(qtype_val) if isinstance(qtype_val, int) else None
            if qtype_code is None:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"unknown qtype {qtype_raw!r}"
                )

            try:
                ttl = int(ttl_raw)
            except ValueError as exc:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"invalid ttl {ttl_raw!r}"
                ) from exc
            if ttl < 0:
                raise ValueError(
                    f"Source {source_label} malformed line {lineno}: "
                    f"negative ttl {ttl}"
                )

            value = value_raw

            key = (domain, int(qtype_code))
            existing = mapping.get(key)

            if existing is None:
                # First occurrence for this (domain, qtype): start a new
                # ordered list of values and remember its TTL.
                stored_ttl = ttl
                values: List[str] = []
            else:
                # Subsequent occurrences: extend the list, but only with
                # values we have not seen before. The TTL from the first
                # occurrence is retained and later duplicates are
                # dropped entirely.
                stored_ttl, values = existing

            if value not in values:
                values.append(value)

            mapping[key] = (stored_ttl, values)

            # Populate per-name index for authoritative semantics.
            per_name = name_index.setdefault(domain, {})
            per_name[int(qtype_code)] = (stored_ttl, values)

            # Track SOA records as zone apexes for authoritative zones.
            if (
                soa_code is not None
                and int(qtype_code) == int(soa_code)
                and domain not in zone_soa
            ):
                zone_soa[domain] = (stored_ttl, values)

        # First, process any configured records files.
        for fp in self.file_paths:
            logger.debug("reading recordfile: %s", fp)
            records_path = pathlib.Path(fp)
            with records_path.open("r", encoding="utf-8") as f:
                for lineno, raw_line in enumerate(f, start=1):
                    _process_line(raw_line, str(records_path), lineno)

        # Next, merge any inline records from plugin configuration.
        inline_records = getattr(self, "_inline_records", None) or []
        for lineno, raw_line in enumerate(inline_records, start=1):
            try:
                text = str(raw_line)
            except Exception as exc:  # pragma: no cover - defensive: log and skip
                logger.warning(
                    "Skipping non-string inline record at index %d: %r (%s)",
                    lineno,
                    raw_line,
                    exc,
                )
                continue
            _process_line(text, "inline-config-records", lineno)

        lock = getattr(self, "_records_lock", None)

        if lock is None:
            self.records = mapping
            self._name_index = name_index
            self._zone_soa = zone_soa
        else:
            with lock:
                self.records = mapping
                self._name_index = name_index
                self._zone_soa = zone_soa

    def _find_zone_for_name(self, name: str) -> Optional[str]:
        """Brief: Find the longest-matching authoritative zone apex for a name.

        Inputs:
          - name: Lowercased domain name without trailing dot.

        Outputs:
          - The matching zone apex string, or None when no authoritative zone
            covers this name.

        Example:
          Given zones {"example.com", "sub.example.com"}:
            _find_zone_for_name("www.sub.example.com") -> "sub.example.com"
            _find_zone_for_name("other.example.com") -> "example.com"
            _find_zone_for_name("example.org") -> None
        """
        zones = getattr(self, "_zone_soa", None) or {}
        best: Optional[str] = None
        for apex in zones.keys():
            if name == apex or name.endswith("." + apex):
                if best is None or len(apex) > len(best):
                    best = apex
        return best

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """Brief: Decide whether to override resolution for a query.

        Inputs:
          - qname: Queried domain name.
          - qtype: DNS record type (numeric code).
          - req: Raw DNS request bytes.
          - ctx: Plugin context.

        Outputs:
          - PluginDecision("override") with an authoritative DNS response when
            this plugin should answer the query, or None to allow normal cache
            and upstream processing.

        Behaviour:
          - For names inside an authoritative zone (identified by SOA records
            in the records files), act as an authoritative server: apply
            correct CNAME and QTYPE.ANY semantics and synthesize NODATA and
            NXDOMAIN responses with SOA in the authority section.
          - For names outside any authoritative zone, preserve the historical
            behaviour and only answer when there is an exact (name, qtype)
            entry, falling through to upstreams otherwise.
        """
        # Normalize domain to a consistent lookup key.
        try:
            name = str(qname).rstrip(".").lower()
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            name = str(qname).lower()

        qtype_int = int(qtype)
        type_name = QTYPE.get(qtype_int, str(qtype_int))
        logger.debug("pre-resolve zone-records %s %s", name, type_name)

        # Safe concurrent read from mappings when a watcher may be reloading.
        lock = getattr(self, "_records_lock", None)
        if lock is None:
            records = getattr(self, "records", {})
            name_index = getattr(self, "_name_index", {})
            zone_soa = getattr(self, "_zone_soa", {})
        else:
            with lock:
                records = dict(getattr(self, "records", {}))
                name_index = dict(getattr(self, "_name_index", {}))
                zone_soa = dict(getattr(self, "_zone_soa", {}))

        zone_apex = self._find_zone_for_name(name)

        # Helper to build RRs from a single RRset.
        def _add_rrset(
            reply: DNSRecord,
            owner_name: str,
            rr_qtype: int,
            ttl: int,
            values: List[str],
        ) -> bool:
            added_any = False
            rr_type_name = QTYPE.get(rr_qtype, str(rr_qtype))
            for value in values:
                zone_line = f"{owner_name} {ttl} IN {rr_type_name} {value}"
                try:
                    rrs = RR.fromZone(zone_line)
                except Exception as exc:  # pragma: no cover - invalid record value
                    logger.warning(
                        "ZoneRecords invalid value %r for qtype %s: %s",
                        value,
                        rr_type_name,
                        exc,
                    )
                    continue
                for rr in rrs:
                    reply.add_answer(rr)
                    added_any = True
            return added_any

        # If this name is not covered by any authoritative zone, preserve the
        # legacy exact-match override behaviour keyed by (name, qtype).
        if zone_apex is None:
            key = (name, qtype_int)
            entry = records.get(key)
            if not entry:
                return None

            ttl, values = entry
            logger.info(
                "ZoneRecords got entry for %s %s -> %s", name, type_name, values
            )

            try:
                request = DNSRecord.parse(req)
            except Exception as e:  # pragma: no cover - defensive parsing
                logger.warning("ZoneRecords parse failure: %s", e)
                return None

            reply = DNSRecord(
                DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
            )
            owner = str(request.q.qname).rstrip(".") + "."

            added = _add_rrset(reply, owner, qtype_int, ttl, list(values))
            if not added:
                return None

            return PluginDecision(action="override", response=reply.pack())

        # Authoritative path: name is inside a zone managed by this plugin.
        try:
            request = DNSRecord.parse(req)
        except Exception as e:  # pragma: no cover - defensive parsing
            logger.warning("ZoneRecords parse failure (authoritative path): %s", e)
            return None

        owner = str(request.q.qname).rstrip(".") + "."
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        rrsets = name_index.get(name, {})
        cname_code = int(QTYPE.CNAME)

        # CNAME at owner name: always answer with CNAME regardless of qtype.
        if cname_code in rrsets:
            ttl_cname, cname_values = rrsets[cname_code]
            # Ignore any other RRsets at this name to avoid illegal CNAME
            # coexistence; log once if there are extras.
            if len(rrsets) > 1:
                logger.warning(
                    "CustomRecords zone %s has CNAME and other RRsets at %s; "
                    "answering with CNAME only",
                    zone_apex,
                    name,
                )
            added = _add_rrset(reply, owner, cname_code, ttl_cname, list(cname_values))
            if not added:
                return None
            return PluginDecision(action="override", response=reply.pack())

        # No CNAME at this owner; distinguish positive, NODATA, and NXDOMAIN.
        if rrsets:
            # Positive answers for specific qtypes.
            if qtype_int == int(QTYPE.ANY):
                added_any = False
                for rr_qtype, (ttl_rr, values_rr) in rrsets.items():
                    if _add_rrset(reply, owner, rr_qtype, ttl_rr, list(values_rr)):
                        added_any = True
                if not added_any:
                    return None
                return PluginDecision(action="override", response=reply.pack())

            if qtype_int in rrsets:
                ttl_rr, values_rr = rrsets[qtype_int]
                if not _add_rrset(reply, owner, qtype_int, ttl_rr, list(values_rr)):
                    return None
                return PluginDecision(action="override", response=reply.pack())

            # NODATA: name exists in zone but requested type is absent.
            reply.header.rcode = RCODE.NOERROR
            # Add SOA from the authoritative zone, when available.
            soa_entry = zone_soa.get(zone_apex)
            if soa_entry is not None:
                soa_ttl, soa_values = soa_entry
                soa_owner = zone_apex.rstrip(".") + "."
                for value in list(soa_values):
                    zone_line = f"{soa_owner} {soa_ttl} IN SOA {value}"
                    try:
                        rrs = RR.fromZone(zone_line)
                    except (
                        Exception
                    ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                        logger.warning(
                            "ZoneRecords invalid SOA value %r for zone %s: %s",
                            value,
                            zone_apex,
                            exc,
                        )
                        continue
                    for rr in rrs:
                        reply.add_auth(rr)

            return PluginDecision(action="override", response=reply.pack())

        # NXDOMAIN: no RRsets at this owner name within the authoritative zone.
        reply.header.rcode = RCODE.NXDOMAIN
        soa_entry = zone_soa.get(zone_apex)
        if soa_entry is not None:
            soa_ttl, soa_values = soa_entry
            soa_owner = zone_apex.rstrip(".") + "."
            for value in list(soa_values):
                zone_line = f"{soa_owner} {soa_ttl} IN SOA {value}"
                try:
                    rrs = RR.fromZone(zone_line)
                except (
                    Exception
                ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    logger.warning(
                        "ZoneRecords invalid SOA value %r for zone %s: %s",
                        value,
                        zone_apex,
                        exc,
                    )
                    continue
                for rr in rrs:
                    reply.add_auth(rr)

        return PluginDecision(action="override", response=reply.pack())

    class _WatchdogHandler(FileSystemEventHandler):
        """Brief: Internal watchdog handler that reloads records on file changes.

        Inputs:
          - plugin: CustomRecords instance to notify on changes.
          - watched_files: Iterable of concrete records file paths to track.

        Outputs:
          - None (invokes plugin._reload_records_from_watchdog when a watched path changes).
        """

        def __init__(
            self,
            plugin: "ZoneRecords",
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
                self._plugin._reload_records_from_watchdog()

    def _start_watchdog(self) -> None:
        """Brief: Start a watchdog observer to reload records files on change.

        Inputs:
          - None (uses self.file_paths)
        Outputs:
          - None
        """

        if Observer is None:
            logger.warning(
                "watchdog is not available; automatic ZoneRecords reload disabled",
            )
            self._observer = None
            return

        record_paths = [pathlib.Path(p).expanduser() for p in self.file_paths]
        watched_files = [p.resolve() for p in record_paths]
        directories = {p.parent.resolve() for p in record_paths}

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
        """Brief: Start a stat-based polling loop to detect records file changes.

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

        thread = threading.Thread(target=self._poll_loop, name="CustomRecordsPoller")
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
                    self._reload_records_from_watchdog()
            except Exception:  # pragma: no cover - defensive logging
                logger.warning("Error during records polling loop", exc_info=True)

            # Wait with wakeup on stop event or timeout.
            stop_event.wait(interval)

    def _have_files_changed(self) -> bool:
        """Brief: Detect whether any configured records files have changed on disk.

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
                logger.warning("Failed to stat records file %s", fp, exc_info=True)
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
            self._reload_records_from_watchdog()
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
                    self._reload_records_from_watchdog()
                except Exception:  # pragma: no cover - defensive logging
                    logger.warning(
                        "Error during deferred records reload from watchdog",
                        exc_info=True,
                    )

            timer = threading.Timer(delay, _timer_cb)
            timer.daemon = True
            self._reload_debounce_timer = timer
            timer.start()

    def _reload_records_from_watchdog(self) -> None:
        """Brief: Safely reload records mapping in response to watchdog events.

        Inputs:
          - None
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
                "Deferring records reload for %.3fs; last reload was %.3fs ago",
                remaining,
                elapsed,
            )
            self._schedule_debounced_reload(remaining)
            return

        self._last_watchdog_reload_ts = now
        logger.info("Reloading records mapping due to filesystem change")
        try:
            self._load_records()
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Failed to reload records from watchdog event: %s", exc)

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
