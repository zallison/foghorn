from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from datetime import datetime
from typing import Iterable, List, Optional, Set
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, Field

from .base import BasePlugin

logger = logging.getLogger(__name__)

ONE_DAY_SECONDS = 24 * 60 * 60


class ListDownloaderConfig(BaseModel):
    """Brief: Typed configuration model for ListDownloader.

    Inputs:
      - download_path: Directory where list files are written.
      - urls: Explicit list of HTTP(S) URLs to download.
      - url_files: Paths to files containing one URL per line.
      - interval_days: Optional number of days between refreshes (>= 0).
      - interval_seconds: Optional legacy seconds-based interval (>= 0).

    Outputs:
      - ListDownloaderConfig instance with normalized field types.
    """

    download_path: str = Field(default="./config/var/lists")
    urls: List[str] = Field(default_factory=list)
    url_files: List[str] = Field(default_factory=list)
    interval_days: Optional[float] = Field(default=None, ge=0)
    interval_seconds: Optional[int] = Field(default=None, ge=0)

    class Config:
        extra = "allow"


class ListDownloader(BasePlugin):
    """
    Periodically download domain-only blocklists to local files so Filter can load them.

    Inputs (config):
      - urls (List[str]): HTTP(S) URLs to domain-per-line lists (comments with '#').
      - url_files (List[str], optional): File paths containing one URL per line ('#' comments allowed).
      - download_path (str): Directory to store downloaded files (default: './config/var/lists').
      - interval_days (float|int|None): If set, re-check and update no more often than
        this many days (legacy 'interval_seconds' is still accepted as a deprecated
        alias).

    Outputs:
      - Writes one file per URL under download_path, named as '{base}-{sha1(url)[:12]}{ext}'.
        If the URL path has no extension, no extension is added (e.g., 'base-<hash>').
        The first line of each file is a timestamped header: '# YYYY-MM-DD HH:MM - url'.

    Example usage:
        plugins:
          - module: list_downloader
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

    aliases = ("list_downloader", "lists")

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - ListDownloaderConfig class for use by the core config loader.
        """

        return ListDownloaderConfig

    def __init__(self, **config):
        """Brief: Initialize ListDownloader configuration and merge URL sources.

        Inputs:
          - **config: Arbitrary keyword configuration, typically including
            'download_path', 'urls', 'url_files', and interval settings.

        Outputs:
          - None; populates instance attributes such as download_path, urls,
            url_files, and interval_seconds.
        """

        super().__init__(**config)
        self.download_path: str = str(
            self.config.get("download_path", "./config/var/lists")
        )
        self.urls: List[str] = list(self.config.get("urls", []) or [])
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
                    "ListDownloader interval_days %r is invalid; disabling periodic refresh",
                    interval_days_cfg,
                )
                self.interval_seconds = None
        elif legacy_interval_seconds is not None:
            try:
                self.interval_seconds = int(legacy_interval_seconds)
            except (TypeError, ValueError):
                logger.warning(
                    "ListDownloader interval_seconds %r is invalid; disabling periodic refresh",
                    legacy_interval_seconds,
                )
                self.interval_seconds = None
        else:
            self.interval_seconds = None
        self._last_run: float = 0.0
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
          - None; updates self.urls in-place to a sorted list of unique URLs.

        Example:
          >>> dl = ListDownloader(download_path="./config/var/lists", urls=["https://one"], url_files=[])
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
            self.urls = sorted(merged)
            if added_count:
                logger.debug("ListDownloader added %d URLs from url_files", added_count)
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
          >>> from foghorn.plugins.list_downloader import ListDownloader
          >>> dl = ListDownloader(download_path="./config/var/lists", urls=[], url_files=[])
          >>> dl.setup()  # doctest: +SKIP
        """

        # Merge URLs from url_files
        if self.url_files:
            try:
                urls_from_files = self._read_url_files(self.url_files)
                merged: Set[str] = set(self.urls)
                merged.update(urls_from_files)
                self.urls = sorted(merged)
                logger.debug(
                    "ListDownloader added %d URLs from url_files", len(urls_from_files)
                )
            except (
                Exception
            ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                logger.warning("Failed reading url_files: %s", e)

        os.makedirs(self.download_path, exist_ok=True)
        # Initial fetch at startup; failures propagate to caller so that
        # abort_on_failure semantics can be enforced by the setup runner.
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
                "ListDownloader interval configuration %r is invalid; disabling periodic refresh",
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
                    logger.warning("ListDownloader periodic update failed: %s", exc)
                # Wait for the interval or until stop is requested
                self._stop_event.wait(interval)

        t = threading.Thread(
            target=_loop,
            name="ListDownloader-refresh",
            daemon=True,
        )
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
            logger.warning("ListDownloader update failed: %s", e)

    def _download_all(self, urls: Iterable[str]) -> None:
        for url in urls:
            fname = self._make_hashed_filename(url)
            fpath = os.path.join(self.download_path, fname)
            logger.debug("ListDownloader checking: %s", url)
            # Try HEAD for last-modified; fall back to GET
            if self._needs_update(url, fpath):
                logger.info(f"Downloading list {url} to {fpath}")
                self._fetch(url, fpath)

            if not self._validate_domain_list(fpath):
                raise ValueError(
                    f"Invalid content in {fname}: expected domain-per-line list"
                )

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
          - Otherwise, consults the remote Last-Modified header when available and
            returns True only when the remote copy is newer, falling back to True
            on parsing or network errors.
        """
        if not os.path.exists(filepath):
            return True

        # Do not update files that are younger than the configured interval_days
        # (when present) or younger than one day by default; during setup this
        # prevents recently-created list files from being rewritten unnecessarily.
        try:
            now = time.time()
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
            if (now - local_mtime) < min_age:
                return False
        except OSError:
            # If we cannot stat the file, fall back to remote checks.
            pass

        try:
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
                    return True
        except requests.RequestException:
            return True
        return True

    # --- Helpers for filenames and url files ---
    def _url_hash12(self, url: str) -> str:
        """
        Brief: Return first 12 hex chars of sha1 over the full URL.

        Inputs:
          - url (str): The full URL string used to download.
        Outputs:
          - (str): 12-character lowercase hex digest.

        Example usage:
            >>> ListDownloader()._url_hash12('https://example.com/a.txt')
            '0a1b2c3d4e5f'
        """
        h = hashlib.sha1(url.encode("utf-8")).hexdigest()
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
            >>> ListDownloader()._derive_base_and_ext('https://x/y/AdguardDNS.txt?z=1')
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
        Brief: Build '{base}-{sha1[:12]}{ext}' using URL-derived or provided base.

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
                        urls.add(s)
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

    def _fetch(self, url: str, filepath: str) -> None:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        header = self._make_header_line(url)
        body = r.text
        with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
            f.write(header)
            f.write("\n")
            f.write(body)

    def _validate_domain_list(self, filepath: str) -> bool:
        try:
            seen = 0
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
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
                    # Reject typical hosts-format entries (start with an IP) or
                    # lines lacking a dot or containing whitespace.
                    if " " in line or "\t" in line or "." not in line:
                        return False
                    seen += 1
                    if seen >= 5:
                        return True
            return False
        except Exception:
            return False
