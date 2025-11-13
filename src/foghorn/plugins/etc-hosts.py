from __future__ import annotations
import logging
import os
import pathlib
import sys
import threading
import time

from dnslib import DNSRecord, QTYPE, A, AAAA, QR, RR, DNSHeader
from typing import Dict, Optional, Iterable, List, Set

from foghorn.plugins.base import PluginDecision, PluginContext
from foghorn.plugins.base import BasePlugin, plugin_aliases

try:
    import pyinotify

    _HAVE_PYINOTIFY = True
except Exception:  # pragma: no cover
    _HAVE_PYINOTIFY = False

logger = logging.getLogger(__name__)


class _HostsEventHandler(object if not _HAVE_PYINOTIFY else pyinotify.ProcessEvent):
    """
    Brief: Inotify event handler that triggers host file reloads.

    Inputs:
      - reload_callback: callable with no args, performs an immediate reload.
      - target_paths: set of absolute paths to files we care about.
      - lock: threading.RLock used to serialize reload.

    Outputs:
      - None (side-effects: calls reload_callback on file events).
    """

    def __init__(self, reload_callback, target_paths: Set[str], lock: threading.RLock):
        if _HAVE_PYINOTIFY:
            super().__init__()
        self._reload_callback = reload_callback
        self._target_paths = {pathlib.Path(p).resolve() for p in target_paths}
        self._lock = lock

    def _maybe_reload(self, event):
        """
        Brief: Check if event pathname is a target file and trigger reload if so.

        Inputs:
          - event: pyinotify event object

        Outputs:
          - None (may call _reload_callback)
        """
        try:
            changed = pathlib.Path(getattr(event, "pathname", "")).resolve()
        except Exception:
            return
        if changed in self._target_paths:
            with self._lock:
                self._reload_callback()

    def process_IN_CLOSE_WRITE(self, event):  # noqa: N802
        """Handle close after write event."""
        self._maybe_reload(event)

    def process_IN_MODIFY(self, event):  # noqa: N802
        """Handle modify event."""
        self._maybe_reload(event)

    def process_IN_MOVED_TO(self, event):  # noqa: N802
        """Handle move-to event (atomic replace pattern)."""
        self._maybe_reload(event)

    def process_IN_ATTRIB(self, event):  # noqa: N802
        """Handle attribute change event."""
        self._maybe_reload(event)


@plugin_aliases("hosts", "etc-hosts", "/etc/hosts")
class EtcHosts(BasePlugin):
    """
    Brief: Resolve A/AAAA queries from one or more hosts files.

    Load IPs and hostnames from /etc/hosts or other host files. Supports reading
    multiple files; when the same hostname appears in more than one file, entries
    from later files override earlier ones.
    """

    def __init__(
        self,
        file_paths: Optional[List[str]] = None,
        file_path: Optional[str] = None,
        inotify_enabled: Optional[bool] = None,
        **config,
    ) -> None:
        """
        Brief: Initialize the plugin and load host mappings with optional inotify reloading.

        Inputs:
          - file_paths (list[str], optional): List of hosts file paths
            to load and merge in order (later overrides earlier)
          - file_path (str, optional): Single hosts file path (legacy, preserved)
          - inotify_enabled (bool, optional): Enable background reloading via inotify.
            Defaults to True on Linux when pyinotify is available.
          - **config: Additional plugin configuration

        Outputs:
          - None

        Example:
          Legacy single file:
            EtcHosts(file_path="/custom/hosts")

          Multiple files (preferred):
            EtcHosts(file_paths=["/etc/hosts", "/etc/hosts.d/extra"])

          With inotify explicitly disabled:
            EtcHosts(file_paths=["/etc/hosts"], inotify_enabled=False)
        """
        super().__init__(**config)

        # Thread safety lock
        self._lock = threading.RLock()

        # Normalize configuration into a list of paths. Default to /etc/hosts
        provided = file_paths or self.config.get("file_paths")
        legacy = file_path or self.config.get("file_path")
        self.file_paths: List[str] = self._normalize_paths(provided, legacy)

        # Host mappings
        self.hosts: Dict[str, str] = {}

        # Inotify state
        self._watch_manager: Optional[object] = None
        self._notifier: Optional[object] = None

        # Determine if inotify should be enabled
        if inotify_enabled is None:
            inotify_enabled = _HAVE_PYINOTIFY and (
                os.name == "posix" and sys.platform.startswith("linux")
            )
        self._inotify_enabled = bool(inotify_enabled)

        # Initial load
        self._load_hosts()

        # Start background watcher if enabled
        if self._inotify_enabled:
            self._start_inotify()

    def _start_inotify(self) -> None:
        """
        Brief: Start a background ThreadedNotifier to watch host files for changes.

        Inputs:
          - None (uses self.file_paths)

        Outputs:
          - None

        Example:
          self._start_inotify()
        """
        if not _HAVE_PYINOTIFY:
            return

        try:
            wm = pyinotify.WatchManager()
            mask = (
                pyinotify.IN_CLOSE_WRITE
                | pyinotify.IN_MODIFY
                | pyinotify.IN_MOVED_TO
                | pyinotify.IN_ATTRIB
                | pyinotify.IN_CREATE
            )
            abs_paths = [str(pathlib.Path(p).resolve()) for p in self.file_paths]
            handler = _HostsEventHandler(self._load_hosts, set(abs_paths), self._lock)
            notifier = pyinotify.ThreadedNotifier(wm, default_proc_fun=handler)
            notifier.daemon = True

            # Watch both each file and its parent directory (to catch atomic replace)
            for path in abs_paths:
                parent = pathlib.Path(path).parent
                try:
                    wm.add_watch(str(parent), mask, rec=False, auto_add=False)
                    logger.debug(f"Added inotify watch for directory {parent}")
                except Exception as e:
                    logger.debug(f"Failed to watch directory {parent}: {e}")

                try:
                    if pathlib.Path(path).exists():
                        wm.add_watch(path, mask, rec=False, auto_add=False)
                        logger.debug(f"Added inotify watch for file {path}")
                except Exception as e:
                    logger.debug(f"Failed to watch file {path}: {e}")

            notifier.start()
            self._watch_manager = wm
            self._notifier = notifier
            logger.debug("Started inotify ThreadedNotifier for hosts files")
        except Exception as e:
            logger.warning(f"Failed to start inotify watcher: {e}")
            self._inotify_enabled = False

    def _stop_inotify(self) -> None:
        """
        Brief: Stop the inotify notifier and release resources.

        Inputs:
          - None

        Outputs:
          - None
        """
        n = self._notifier
        self._notifier = None
        try:
            if n is not None:
                n.stop()
                logger.debug("Stopped inotify ThreadedNotifier")
        except Exception as e:
            logger.debug(f"Error stopping notifier: {e}")
        finally:
            wm = self._watch_manager
            self._watch_manager = None
            if wm is not None:
                try:
                    wm.close()
                except Exception as e:
                    logger.debug(f"Error closing watch manager: {e}")

    def close(self) -> None:
        """
        Brief: Close the plugin and stop background watchers.

        Inputs:
          - None

        Outputs:
          - None

        Example:
          plugin.close()
        """
        self._stop_inotify()

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
            paths = ["/etc/hosts"]  # pragma: no cover
        # De-duplicate while preserving order
        paths = list(dict.fromkeys(paths))
        return paths

    def _load_hosts(self) -> None:
        """
        Brief: Read hosts files and build a mapping of domain -> IP.

        - Supports comments beginning with '#', including inline comments.
        - Requires at least one hostname after the IP on each non-comment line.
        - Multiple hostnames per line are supported and mapped to the same IP.
        - When multiple files are provided, later files override earlier ones on
          conflicts for the same hostname.
        - Thread-safe: acquires self._lock to ensure no leftover data from previous calls.

        Inputs:
          - None (uses self.file_paths)
        Outputs:
          - None (populates self.hosts: Dict[str, str])
        """
        with self._lock:
            # Ensure no data is left over from previous calls.
            mapping: Dict[str, str] = {}

            for fp in self.file_paths:
                hosts_path = pathlib.Path(fp)
                try:
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
                            for domain in parts[1:]:
                                # Later files override earlier ones by assignment
                                mapping[domain] = ip
                except FileNotFoundError:
                    # File may not exist yet or may be deleted; skip it
                    pass
            self.hosts = mapping

    def pre_resolve(
        self, qname: str, qtype: int, req: bytes, ctx: PluginContext
    ) -> Optional[PluginDecision]:
        """
        Brief: Return an override decision if qname exists in loaded hosts.

        Inputs:
            qname: Queried domain name.
            qtype: DNS record type.
            req: Raw DNS request bytes.
            ctx: Plugin context.
        Outputs:
            PluginDecision("override") when domain is mapped (and type matches),
            otherwise None.

        """
        if qtype not in (QTYPE.A, QTYPE.AAAA):
            return None

        qname = qname.rstrip(".")

        with self._lock:
            ip = self.hosts.get(qname)

        if not ip:
            return None

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
        qname = str(request.q.qname).rstrip(".")

        ip = ipaddr
        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        if query_type == QTYPE.A:
            reply.add_answer(
                RR(rname=request.q.qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A(ip))
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
