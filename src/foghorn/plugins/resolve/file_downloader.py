from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import tempfile
import threading
import time
from datetime import datetime
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, Field, ConfigDict

from .base import BasePlugin

logger = logging.getLogger(__name__)

ONE_DAY_SECONDS = 24 * 60 * 60
MAX_DOMAIN_LIST_LINE_LENGTH = 2048
FAILURE_BACKOFF_BASE_SECONDS = 30
FAILURE_BACKOFF_MAX_SECONDS = 15 * 60


class FileDownloaderConfig(BaseModel):
    """Brief: Typed configuration model for FileDownloader.

    Inputs:
      - download_path: Directory where list files are written.
      - urls: Explicit list of HTTP(S) URLs to download. Each entry may be either
        a bare URL string or an object with keys:
          - url (str): The URL to download.
          - hash_filenames (bool | None): When True, use hashed filenames;
            when False, derive filenames directly from the URL; when None in a
            per-URL object, fall back to the plugin-level default.
          - add_comment (bool | None): When True, prepend a timestamped comment
            line to the downloaded file; when False or None, no comment is
            written for that URL.
      - url_files: Paths to files containing one URL per line.
      - interval_days: Optional number of days between refreshes (>= 0).
      - interval_seconds: Optional legacy seconds-based interval (>= 0).
      - add_comment: Plugin-level default for whether to add a comment header
        line to downloaded files (default: False).
      - hash_filenames: Plugin-level default for whether filenames should
        include a URL hash (default: False).
      - allow_private_hosts: When True, allow loopback/link-local/RFC1918 targets.
      - allowlist_hosts: Optional list of hostnames or domain suffixes to allow.
      - head_check: When to issue upstream HEAD requests ('always', 'half_age',
        'stale', or 'never').

    Outputs:
      - FileDownloaderConfig instance with normalized field types.
    """

    download_path: str = Field(default="./config/var/lists")
    urls: List[object] = Field(default_factory=list)
    url_files: List[str] = Field(default_factory=list)
    interval_days: Optional[float] = Field(default=None, ge=0)
    interval_seconds: Optional[int] = Field(default=None, ge=0)
    add_comment: Optional[bool] = Field(default=False)
    hash_filenames: bool = Field(default=False)
    allow_private_hosts: bool = Field(default=False)
    allowlist_hosts: Optional[List[str]] = Field(default=None)
    head_check: str = Field(default="stale")

    model_config = ConfigDict(extra="allow")


class FileDownloader(BasePlugin):
    """
    Periodically download domain-only blocklists to local files so Filter can load them.

    Inputs (config):
      - urls (List[str]): HTTP(S) URLs to domain-per-line lists (comments with '#').
      - url_files (List[str], optional): File paths containing one URL per line ('#' comments allowed).
      - download_path (str): Directory to store downloaded files (default: './config/var/lists').
      - interval_days (float|int|None): If set, re-check and update no more often than
        this many days (legacy 'interval_seconds' is still accepted as a deprecated
        alias).
      - allow_private_hosts (bool): When True, allow loopback/link-local/RFC1918 targets.
      - allowlist_hosts (List[str]|None): Optional hostnames or suffixes to allow.
      - head_check (str): When to issue upstream HEAD requests ('always', 'half_age',
        'stale', or 'never').

    Outputs:
      - Writes one file per URL under download_path, named as '{base}-{sha256(url)[:12]}{ext}'.
        If the URL path has no extension, no extension is added (e.g., 'base-<hash>').
        The first line of each file is a timestamped header: '# YYYY-MM-DD HH:MM - url'.

    Example usage:
        plugins:
          - module: file_downloader
            pre_priority: 15
            config:
              download_path: ./config/var/lists
              cache_days: 7
              urls:
                - https://v.firebog.net/hosts/AdguardDNS.txt
                - https://v.firebog.net/hosts/Easylist.txt
              url_files:
                - ./config/url-sources/community.txt
    """

    aliases = ("file_downloader", "lists")
    setup_requires_dns = True

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - FileDownloaderConfig class for use by the core config loader.
        """

        return FileDownloaderConfig

    def __init__(self, **config):
        """Brief: Initialize FileDownloader configuration and merge URL sources.

        Inputs:
          - **config: Arbitrary keyword configuration, typically including
            'download_path', 'urls', 'url_files', and interval settings, plus
            optional 'add_comment' and 'hash_filenames' flags.

        Outputs:
          - None; populates instance attributes such as download_path, urls,
            url_files, and interval_seconds.
        """

        super().__init__(**config)
        self.download_path: str = str(
            self.config.get("download_path", "./config/var/lists")
        )

        # Global defaults for per-URL options. add_comment may be None to
        # indicate "no header"; headers are only written when the effective
        # value is True.
        self._default_add_comment: Optional[bool] = self.config.get(
            "add_comment", False
        )
        self._default_hash_filenames: bool = bool(
            self.config.get("hash_filenames", False)
        )
        self._allow_private_hosts: bool = bool(
            self.config.get("allow_private_hosts", False)
        )
        raw_allowlist = self.config.get("allowlist_hosts")
        self._allowlist_hosts: List[str] = [
            str(host).strip().lower()
            for host in (raw_allowlist or [])
            if str(host).strip()
        ]
        self._head_check: str = str(self.config.get("head_check", "stale")).lower()

        # Public, string-only URL list preserved for backwards compatibility and
        # tests. Per-URL options are tracked separately in _url_options.
        self.urls: List[str] = []
        self._url_options: dict[str, dict[str, Optional[bool] | bool]] = {}

        raw_urls = self.config.get("urls", []) or []
        self._init_urls_with_options(raw_urls)

        self.url_files: List[str] = list(self.config.get("url_files", []) or [])
        # interval_days is the primary public setting; interval_seconds remains an
        # internal, seconds-based representation. The legacy config key
        # 'interval_seconds' is still accepted as a deprecated alias.
        interval_days_cfg = self.config.get("interval_days")
        legacy_interval_seconds = self.config.get("interval_seconds")
        self.interval_seconds: int | None
        if interval_days_cfg is not None:
            try:
                days = float(interval_days_cfg)
                self.interval_seconds = int(days * ONE_DAY_SECONDS)
            except (TypeError, ValueError):
                logger.warning(
                    "FileDownloader interval_days %r is invalid; disabling periodic refresh",
                    interval_days_cfg,
                )
                self.interval_seconds = None
        elif legacy_interval_seconds is not None:
            try:
                self.interval_seconds = int(legacy_interval_seconds)
            except (TypeError, ValueError):
                logger.warning(
                    "FileDownloader interval_seconds %r is invalid; disabling periodic refresh",
                    legacy_interval_seconds,
                )
                self.interval_seconds = None
        else:
            self.interval_seconds = None
        self._last_run: float = 0.0
        self._failure_state: dict[str, dict[str, float | int]] = {}
        self._validated_list_meta: dict[str, dict[str, float | int]] = {}
        self._stop_event: threading.Event | None = None
        self._background_thread: threading.Thread | None = None

        # Merge URLs from url_files early so callers see a unified, sorted list
        # immediately after construction.
        self._merge_urls_from_files()

    def _merge_urls_from_files(self) -> None:
        """Brief: Merge URLs from url_files into self.urls and log additions.

        Inputs:
          - None; uses self.url_files and self.urls.

        Outputs:
          - None; updates self.urls in-place to a sorted list of unique URLs and
            ensures per-URL options are populated (using defaults for
            url_files-derived entries).

        Example:
          >>> dl = FileDownloader(download_path="./config/var/lists", urls=["https://one"], url_files=[])
          >>> dl.urls  # doctest: +ELLIPSIS
          ['https://one']
        """

        if not self.url_files:
            return

        try:
            urls_from_files = self._read_url_files(self.url_files)
            if not urls_from_files:
                return

            merged: Set[str] = set(self.urls)
            before_count = len(merged)
            merged.update(urls_from_files)
            added_count = len(merged) - before_count

            # Ensure all new URLs have option records using plugin defaults.
            for url in urls_from_files:
                if url not in self._url_options:
                    self._url_options[url] = {
                        "hash_filenames": self._default_hash_filenames,
                        "add_comment": self._default_add_comment,
                    }

            self.urls = sorted(merged)
            if added_count:
                logger.debug("FileDownloader added %d URLs from url_files", added_count)
        except Exception as exc:  # pragma: no cover - defensive logging only
            logger.warning("Failed reading url_files: %s", exc)

    # Run early in the setup phase so files exist before Filter runs
    setup_priority = 15

    def setup(self) -> None:
        """Perform initial downloads and start optional periodic refresh.

        Inputs:
          - None (uses plugin configuration stored on self).
        Outputs:
          - None

        Brief: Creates the download directory, performs an initial update of
        all configured lists, and, when interval_days is set, starts a
        background thread that periodically refreshes the lists.

        Example use:
          >>> from foghorn.plugins.file_downloader import FileDownloader
          >>> dl = FileDownloader(download_path="./config/var/lists", urls=[], url_files=[])
          >>> dl.setup()  # doctest: +SKIP
        """

        # Merge URLs from url_files
        if self.url_files:
            try:
                urls_from_files = self._read_url_files(self.url_files)
                merged: Set[str] = set(self.urls)
                merged.update(urls_from_files)

                # Ensure all new URLs have option records using plugin defaults.
                for url in urls_from_files:
                    if url not in self._url_options:
                        self._url_options[url] = {
                            "hash_filenames": self._default_hash_filenames,
                            "add_comment": self._default_add_comment,
                        }

                self.urls = sorted(merged)
                logger.debug(
                    "FileDownloader added %d URLs from url_files", len(urls_from_files)
                )
            except (
                Exception
            ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                logger.warning("Failed reading url_files: %s", e)

        os.makedirs(self.download_path, exist_ok=True)
        # Initial fetch at startup; failures propagate to caller so that
        # abort_on_failure semantics can be enforced by the setup runner.
        if self._should_delay_startup_check():
            self._start_delayed_startup_check()
        else:
            self._maybe_run(force=True)

        # Optional periodic refresh while the process runs
        if self.interval_seconds is None:
            return
        try:
            interval = int(self.interval_seconds)
        except (
            TypeError,
            ValueError,
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.warning(
                "FileDownloader interval configuration %r is invalid; disabling periodic refresh",
                self.interval_seconds,
            )
            return
        if interval <= 0:
            return

        if self._stop_event is not None:
            # Already started
            return

        self._stop_event = threading.Event()

        def _loop() -> None:
            """Background loop to refresh lists on a fixed interval.

            Inputs:
              - None (captures self and configuration).
            Outputs:
              - None

            The loop calls _maybe_run(force=False) and then waits for the
            configured interval; any exceptions during refresh are logged but
            do not stop the loop.
            """
            assert self._stop_event is not None
            while not self._stop_event.is_set():
                try:
                    self._maybe_run(force=False)
                except (
                    Exception
                ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                    logger.warning("FileDownloader periodic update failed: %s", exc)
                # Wait for the interval or until stop is requested
                self._stop_event.wait(interval)

        t = threading.Thread(
            target=_loop,
            name="FileDownloader-refresh",
            daemon=True,
        )
        logger.info("FileDownloader starting background refresh thread")
        t.start()
        self._background_thread = t

    # Internal helpers
    def _maybe_run(self, force: bool) -> None:
        now = time.time()
        if not force and self.interval_seconds is not None:
            if (now - self._last_run) < int(self.interval_seconds):
                return
        try:
            self._download_all(self.urls)
            self._last_run = now
        except (
            Exception
        ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.warning("FileDownloader update failed: %s", e)

    def _should_delay_startup_check(self) -> bool:
        """Brief: Decide whether startup refresh should be delayed.

        Inputs:
          - None (uses current urls, download_path, and interval settings).

        Outputs:
          - True when all local files exist and are still within their fresh
            window; False otherwise.
        """
        if not self.urls:
            return False
        min_age = ONE_DAY_SECONDS
        if self.interval_seconds is not None:
            try:
                min_age = max(0, int(self.interval_seconds))
            except (TypeError, ValueError):
                min_age = ONE_DAY_SECONDS
        now = time.time()
        for url in self.urls:
            hash_filenames, _ = self._get_effective_url_options(url)
            if hash_filenames:
                fname = self._make_hashed_filename(url)
            else:
                fname = self._make_plain_filename(url)
            fpath = os.path.join(self.download_path, fname)
            if not os.path.exists(fpath):
                return False
            try:
                local_mtime = os.path.getmtime(fpath)
            except OSError:
                return False
            if (now - local_mtime) >= min_age:
                return False
        return True

    def _start_delayed_startup_check(self) -> None:
        """Brief: Run startup refresh in a background thread after a short delay.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        def _delayed() -> None:
            time.sleep(10)
            try:
                self._maybe_run(force=False)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("FileDownloader delayed startup update failed: %s", exc)

        t = threading.Thread(
            target=_delayed,
            name="FileDownloader-startup-check",
            daemon=True,
        )
        logger.info("FileDownloader starting delayed startup check thread")
        t.start()

    def _download_all(self, urls: Iterable[str]) -> None:
        """Brief: Download and validate all provided URLs using per-URL options.

        Inputs:
          - urls: Iterable of URL strings to process.

        Outputs:
          - None; files are written under download_path and validated.

        Behavior:
          - For each URL, derives a filename using either a hashed or
            non-hashed scheme depending on the effective hash_filenames
            setting for that URL.
          - The _fetch helper consults the effective add_comment setting to
            decide whether to prepend a header line.
        """

        path_to_url: dict[str, str] = {}
        planned: list[tuple[str, str, str]] = []
        for url in urls:
            hash_filenames, _ = self._get_effective_url_options(url)
            if hash_filenames:
                fname = self._make_hashed_filename(url)
            else:
                fname = self._make_plain_filename(url)

            fpath = os.path.join(self.download_path, fname)
            prior = path_to_url.get(fpath)
            if prior and prior != url:
                raise ValueError(
                    f"Filename collision for {fpath}: {prior} vs {url} (enable hash_filenames)"
                )
            path_to_url[fpath] = url
            planned.append((url, fpath, fname))

        for url, fpath, fname in planned:
            logger.info("checking for updates: %s", url)
            # Try HEAD for last-modified; fall back to GET
            if self._needs_update(url, fpath):
                logger.info("Downloading list %s to %s", url, fpath)
                temp_path = self._fetch(url, fpath)
                try:
                    if not self._validate_domain_list(temp_path):
                        raise ValueError(
                            f"Invalid content in {fname} ({url}): expected domain-per-line list"
                        )
                    os.replace(temp_path, fpath)
                    self._validated_list_meta[fpath] = self._file_stat_snapshot(fpath)
                    self._clear_failure_state(url)
                finally:
                    if os.path.exists(temp_path):
                        try:
                            os.remove(temp_path)
                        except OSError:
                            logger.warning(
                                "FileDownloader failed cleaning temp file %s", temp_path
                            )
            if not self._is_validation_current(fpath):
                if not self._validate_domain_list(fpath):
                    raise ValueError(
                        f"Invalid content in {fname} ({url}): expected domain-per-line list"
                    )
                self._validated_list_meta[fpath] = self._file_stat_snapshot(fpath)

    def _needs_update(self, url: str, filepath: str) -> bool:
        """Brief: Decide whether the local list file should be refreshed.

        Inputs:
          - url (str): Source URL for the list.
          - filepath (str): Path to the local list file.

        Outputs:
          - (bool): True if the caller should download, False to reuse the file.

        Behavior:
          - If the file is missing, always returns True.
          - If the file is younger than the configured interval (``interval_days``
            converted to seconds) when set, returns False without a network call.
          - If no interval is configured, files younger than one day are treated
            as fresh and also return False.
          - Otherwise, consults the remote Last-Modified header when configured
            to do so and returns True only when the remote copy is newer, falling
            back to a backoff cooldown on parsing or network errors.
        """
        if not os.path.exists(filepath):
            return True
        now = time.time()
        if self._is_failure_cooldown_active(url, now):
            return False

        # Do not update files that are younger than the configured interval_days
        # (when present) or younger than one day by default; during setup this
        # prevents recently-created list files from being rewritten unnecessarily.
        try:
            local_mtime = os.path.getmtime(filepath)
            min_age = ONE_DAY_SECONDS
            if self.interval_seconds is not None:
                try:
                    min_age = max(0, int(self.interval_seconds))
                except (
                    TypeError,
                    ValueError,
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    min_age = ONE_DAY_SECONDS
            age_seconds = now - local_mtime
            if self._head_check == "never":
                return age_seconds >= min_age
            if self._head_check not in {"always", "half_age", "stale"}:
                logger.warning(
                    "FileDownloader head_check %r is invalid; defaulting to 'half_age'",
                    self._head_check,
                )
                self._head_check = "half_age"
            if self._head_check == "stale" and age_seconds < min_age:
                return False
            if self._head_check == "half_age" and age_seconds < (min_age / 2):
                return False
        except OSError:
            # If we cannot stat the file, fall back to remote checks.
            pass

        try:
            logger.info("FileDownloader checking upstream (HEAD) for %s", url)
            res = requests.head(url, timeout=10)
            lm = res.headers.get("Last-Modified")
            if lm:
                try:
                    remote_mtime = time.mktime(
                        time.strptime(lm, "%a, %d %b %Y %H:%M:%S GMT")
                    )
                    local_mtime = os.path.getmtime(filepath)
                    return remote_mtime > local_mtime
                except Exception:
                    self._record_failure(url, now)
                    return False
        except requests.RequestException:
            self._record_failure(url, now)
            return False
        return True

    @staticmethod
    def _file_stat_snapshot(path: str) -> dict[str, float | int]:
        """Brief: Capture file size and timestamps for validation caching.

        Inputs:
          - path: File path to stat.

        Outputs:
          - dict with 'size', 'mtime', and 'ctime' values.
        """
        st = os.stat(path)
        return {
            "size": int(st.st_size),
            "mtime": float(st.st_mtime),
            "ctime": float(st.st_ctime),
        }

    def _is_validation_current(self, path: str) -> bool:
        """Brief: Check whether a file's validation cache matches current stats.

        Inputs:
          - path: File path to check.

        Outputs:
          - True if validation is current, False otherwise.
        """
        cached = self._validated_list_meta.get(path)
        if not cached:
            return False
        try:
            snap = self._file_stat_snapshot(path)
        except OSError:
            return False
        return (
            int(cached.get("size", -1)) == int(snap["size"])
            and float(cached.get("mtime", -1)) == float(snap["mtime"])
            and float(cached.get("ctime", -1)) == float(snap["ctime"])
        )

    # --- Helpers for filenames, per-URL options, and url files ---
    def _init_urls_with_options(self, raw_urls: Iterable[object]) -> None:
        """Brief: Populate self.urls and per-URL options from raw config values.

        Inputs:
          - raw_urls: Iterable from the validated config['urls'] field. Each
            entry may be a string URL or a mapping with keys 'url',
            'hash_filenames', and 'add_comment'.

        Outputs:
          - None; updates self.urls and _url_options in-place.
        """

        sentinel = object()
        for entry in raw_urls:
            if isinstance(entry, str):
                url = self._validate_and_normalize_url(entry, source="urls")
                use_hashed = self._default_hash_filenames
                add_comment = self._default_add_comment
            elif isinstance(entry, dict):
                url = str(entry.get("url", ""))
                if not url:
                    logger.warning(
                        "FileDownloader skipping urls entry without 'url': %r", entry
                    )
                    continue
                url = self._validate_and_normalize_url(url, source="urls")
                raw_use_hashed = entry.get("hash_filenames", sentinel)
                if raw_use_hashed is sentinel:
                    use_hashed = self._default_hash_filenames
                else:
                    use_hashed = bool(raw_use_hashed)
                if "add_comment" in entry:
                    add_comment = entry.get("add_comment")
                else:
                    add_comment = self._default_add_comment
            else:
                logger.warning(
                    "FileDownloader skipping unsupported urls entry %r (expected str or mapping)",
                    entry,
                )
                continue

            self.urls.append(url)
            # Preserve the last configuration seen for a given URL so users can
            # override earlier entries.
            self._url_options[url] = {
                "hash_filenames": use_hashed,
                "add_comment": add_comment,
            }

        # Keep urls list stable and sorted for callers/tests that inspect it.
        if self.urls:
            self.urls = sorted({u: None for u in self.urls}.keys())

    def _get_effective_url_options(self, url: str) -> tuple[bool, Optional[bool]]:
        """Brief: Resolve per-URL options for hash_filenames and add_comment.

        Inputs:
          - url: URL string to look up.

        Outputs:
          - (hash_filenames, add_comment):
              - hash_filenames (bool): Whether to use hashed filenames.
              - add_comment (bool | None): When True, _fetch will prepend a
                header line; when False or None, no header is written.
        """

        opts = self._url_options.get(url)
        if not opts:
            return self._default_hash_filenames, self._default_add_comment

        use_hashed = bool(opts.get("hash_filenames", self._default_hash_filenames))
        add_comment = opts.get("add_comment", self._default_add_comment)
        return use_hashed, add_comment

    def _url_hash12(self, url: str) -> str:
        """
        Brief: Return first 12 hex chars of sha256 over the full URL.

        Inputs:
          - url (str): The full URL string used to download.
        Outputs:
          - (str): 12-character lowercase hex digest.
        """
        h = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return h[:12]

    def _derive_base_and_ext(self, url: str) -> tuple[str, str]:
        """
        Brief: Derive a safe base name and extension from a URL path.

        Inputs:
          - url (str): The full URL.
        Outputs:
          - (base, ext): base without extension, ext including leading '.' or empty string.

        Notes:
          - If URL has no path component, fall back to netloc.
          - If the path basename has no extension, ext is ''.

        Example usage:
            >>> FileDownloader()._derive_base_and_ext('https://x/y/AdguardDNS.txt?z=1')
            ('AdguardDNS', '.txt')
        """
        p = urlparse(url)
        basename = os.path.basename(p.path)
        if not basename:
            base = p.netloc or "list"
            return base, ""
        base, ext = os.path.splitext(basename)
        base = base or (p.netloc or "list")
        return base, ext

    def _make_hashed_filename(self, url: str, base_name: str | None = None) -> str:
        """
        Brief: Build '{base}-{sha256[:12]}{ext}' using URL-derived or provided base.

        Inputs:
          - url (str): The full URL.
          - base_name (str|None): Optional preferred base name (without extension).
        Outputs:
          - (str): File name suitable for local storage.

        Behavior:
          - If URL provides an extension, preserve it; otherwise, omit extension entirely.
          - If no extension, result is 'base-<hash>' (no trailing dot).
        """
        url_hash = self._url_hash12(url)
        if base_name:
            base = base_name
            _, ext = self._derive_base_and_ext(url)
        else:
            base, ext = self._derive_base_and_ext(url)
        # sanitize base (keep common safe characters)
        safe = []
        for ch in base:
            if ch.isalnum() or ch in ("-", "_", "."):
                safe.append(ch)
            else:
                safe.append("_")
        base_safe = "".join(safe) or "list"
        return f"{base_safe}-{url_hash}{ext}"

    def _make_plain_filename(self, url: str, base_name: str | None = None) -> str:
        """Brief: Build '{base}{ext}' using URL-derived or provided base.

        Inputs:
          - url (str): The full URL.
          - base_name (str|None): Optional preferred base name (without extension).

        Outputs:
          - (str): File name suitable for local storage when hashing is
            disabled.

        Behavior:
          - When hashing is disabled via hash_filenames=False, filenames are
            derived directly from the URL path (or netloc when no path) without
            any hash or dash suffix.
        """
        if base_name:
            base = base_name
            _, ext = self._derive_base_and_ext(url)
        else:
            base, ext = self._derive_base_and_ext(url)
        safe = []
        for ch in base:
            if ch.isalnum() or ch in ("-", "_", "."):
                safe.append(ch)
            else:
                safe.append("_")
        base_safe = "".join(safe) or "list"
        return f"{base_safe}{ext}"

    def _read_url_files(self, paths: List[str]) -> Set[str]:
        """
        Brief: Read one-URL-per-line files and return a set of URLs.

        Inputs:
          - paths (List[str]): File paths to parse.
        Outputs:
          - (Set[str]): Unique URLs collected from all files.

        Parsing rules:
          - Lines starting with '#' are comments and ignored.
          - Blank or whitespace-only lines are ignored.
        """
        urls: Set[str] = set()
        for path in paths:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        s = raw.strip()
                        if not s or s.startswith("#"):
                            continue
                        try:
                            url = self._validate_and_normalize_url(
                                s, source=f"url_files:{path}"
                            )
                            urls.add(url)
                        except ValueError as exc:
                            logger.warning("Skipping invalid URL in %s: %s", path, exc)
            except FileNotFoundError:
                logger.warning("url_files entry not found: %s", path)
        return urls

    def _make_header_line(self, url: str, now: datetime | None = None) -> str:
        """
        Brief: Produce header line '# YYYY-MM-DD HH:MM - url'.

        Inputs:
          - url (str): Source URL.
          - now (datetime|None): Optional timestamp for deterministic tests.
        Outputs:
          - (str): Header line (without trailing newline).
        """
        ts = now or datetime.now()
        return f"# {ts.strftime('%Y-%m-%d %H:%M')} - {url}"

    def _fetch(self, url: str, filepath: str) -> str:
        """Brief: Download a single URL to a temp file, honoring add_comment option.

        Inputs:
          - url: Source URL to fetch.
          - filepath: Final destination path for the downloaded content.

        Outputs:
          - (str): Path to the temp file containing the downloaded content.

        Behavior:
          - When the effective add_comment option for the URL is True, a
            timestamped header line is written as the first line in the file.
          - When add_comment is False or None, only the body is written.
        """

        now = time.time()
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
        except requests.RequestException:
            self._record_failure(url, now)
            raise
        _, add_comment = self._get_effective_url_options(url)
        body = r.text
        temp_dir = os.path.dirname(filepath) or "."
        fd, temp_path = tempfile.mkstemp(
            prefix=".file_downloader.", dir=temp_dir, text=True
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="ignore") as f:
                if add_comment is True:
                    header = self._make_header_line(url)
                    f.write(header)
                    f.write("\n")
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning("FileDownloader failed cleaning temp file %s", temp_path)
            self._record_failure(url, now)
            raise
        return temp_path

    def _validate_domain_list(self, filepath: str) -> bool:
        """Brief: Validate that a file contains domain-per-line entries.

        Inputs:
          - filepath (str): Path to the downloaded list file.
        Outputs:
          - (bool): True if all non-comment lines are valid domains.

        Behavior:
          - Validates the entire file.
          - Rejects oversized lines, control characters, or invalid labels.
        """
        try:
            seen = 0
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    if len(raw) > MAX_DOMAIN_LIST_LINE_LENGTH:
                        return False
                    line = raw.strip()
                    # Treat both '#' and '!' as comment prefixes to support
                    # AdGuard/Adblock-style lists where '!' starts a comment.
                    if (
                        not line
                        or line.startswith("#")
                        or line.startswith("!")
                        or line.startswith("[")
                    ):
                        continue
                    # Strip any trailing comment introduced by '#' or '!' on
                    # the same line, then re-trim.
                    line = line.split("#", 1)[0].split("!", 1)[0].strip()
                    if not line:
                        continue
                    adguard_token, adguard_matched = self._extract_adguard_domain_token(
                        line
                    )
                    if adguard_matched:
                        if not adguard_token:
                            # Recognized AdGuard syntax that does not encode a
                            # DNS domain token for Filter (e.g. cosmetic rule).
                            continue
                        line = adguard_token
                    if not self._is_valid_domain_token(line):
                        return False
                    seen += 1
            return seen > 0
        except Exception:
            return False

    @staticmethod
    def _extract_adguard_domain_token(line: str) -> tuple[str, bool]:
        """Brief: Extract a DNS domain token from an AdGuard/Adblock rule line.

        Inputs:
          - line (str): Candidate non-comment list line.
        Outputs:
          - (domain_token, matched):
              - domain_token: Parsed domain token (empty if none present).
              - matched: True when line is recognized as AdGuard-style syntax.
        """
        text = str(line).strip()
        if not text:
            return "", False

        if text.startswith("@@"):
            text = text[2:].lstrip()

        # Cosmetic rules are valid AdGuard syntax but do not provide DNS
        # domains for this plugin's domain list semantics.
        if any(marker in text for marker in ("##", "#@#", "#?#", "#$#")):
            return "", True

        if not text.startswith("||"):
            return "", False

        token = text[2:].strip()
        if "^" in token:
            token = token.split("^", 1)[0]
        if "$" in token:
            token = token.split("$", 1)[0]
        if "/" in token:
            token = token.split("/", 1)[0]

        return token.strip().strip("."), True

    def _validate_and_normalize_url(self, url: str, source: str) -> str:
        """Brief: Validate URL scheme/host and enforce allowlist/private rules.

        Inputs:
          - url (str): Raw URL string to validate.
          - source (str): Origin of the URL for error messages.
        Outputs:
          - (str): Normalized URL string.

        Behavior:
          - Allows only http/https schemes.
          - Rejects loopback/link-local/RFC1918 targets unless configured.
        """
        candidate = str(url).strip()
        if not candidate:
            raise ValueError(f"{source} entry is empty")
        parsed = urlparse(candidate)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"{source} entry has invalid scheme: {candidate}")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"{source} entry missing hostname: {candidate}")
        host_lc = hostname.lower().rstrip(".")
        if self._allowlist_hosts and self._is_allowlisted_host(host_lc):
            return candidate
        if self._is_private_host(host_lc) and not self._allow_private_hosts:
            raise ValueError(f"{source} entry points to private host: {candidate}")
        return candidate

    def _is_allowlisted_host(self, host: str) -> bool:
        """Brief: Check if host matches configured allowlist entries.

        Inputs:
          - host (str): Lowercased hostname without trailing dot.
        Outputs:
          - (bool): True if host matches an allowlist entry.

        Behavior:
          - Exact matches are allowed.
          - Entries starting with '.' allow subdomain suffix matches.
        """
        for entry in self._allowlist_hosts:
            if entry.startswith("."):
                suffix = entry.lstrip(".")
                if host == suffix or host.endswith(f".{suffix}"):
                    return True
            elif host == entry:
                return True
        return False

    def _is_private_host(self, host: str) -> bool:
        """Brief: Determine if a hostname is loopback/link-local/RFC1918.

        Inputs:
          - host (str): Lowercased hostname without trailing dot.
        Outputs:
          - (bool): True if host is private/loopback/link-local/etc.
        """
        if host in ("localhost",):
            return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    def _is_valid_domain_token(self, token: str) -> bool:
        """Brief: Validate a single domain token from a list file.

        Inputs:
          - token (str): Raw token string after comment stripping.
        Outputs:
          - (bool): True if token is a valid DNS-style domain name.

        Behavior:
          - Rejects whitespace, control chars, or overly long names.
          - Enforces label length and character rules.
        """
        from foghorn.utils import dns_names

        return dns_names.is_list_domain_token(token)

    def _record_failure(self, url: str, now: float) -> None:
        """Brief: Record a URL failure and update backoff state.

        Inputs:
          - url (str): URL that failed.
          - now (float): Current timestamp.
        Outputs:
          - None; updates internal backoff state.
        """
        state = self._failure_state.get(url, {"count": 0, "last_failure": 0.0})
        count = int(state.get("count", 0)) + 1
        self._failure_state[url] = {"count": count, "last_failure": now}

    def _clear_failure_state(self, url: str) -> None:
        """Brief: Clear failure backoff state after a successful download.

        Inputs:
          - url (str): URL that succeeded.
        Outputs:
          - None.
        """
        self._failure_state.pop(url, None)

    def _is_failure_cooldown_active(self, url: str, now: float) -> bool:
        """Brief: Determine if a URL is in failure backoff cooldown.

        Inputs:
          - url (str): URL to check.
          - now (float): Current timestamp.
        Outputs:
          - (bool): True if still in cooldown window.
        """
        state = self._failure_state.get(url)
        if not state:
            return False
        count = int(state.get("count", 0))
        last_failure = float(state.get("last_failure", 0.0))
        backoff = min(
            FAILURE_BACKOFF_MAX_SECONDS,
            FAILURE_BACKOFF_BASE_SECONDS * (2 ** max(0, count - 1)),
        )
        return (now - last_failure) < backoff
