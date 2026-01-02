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

    class Config:
        extra = "allow"


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

    Outputs:
      - Writes one file per URL under download_path, named as '{base}-{sha1(url)[:12]}{ext}'.
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

        for url in urls:
            hash_filenames, _ = self._get_effective_url_options(url)
            if hash_filenames:
                fname = self._make_hashed_filename(url)
            else:
                fname = self._make_plain_filename(url)

            fpath = os.path.join(self.download_path, fname)
            logger.debug("FileDownloader checking: %s", url)
            # Try HEAD for last-modified; fall back to GET
            if self._needs_update(url, fpath):
                logger.info("Downloading list %s to %s", url, fpath)
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
            if (now - local_mtime) < (
                min_age / 2
            ):  # If we're over halfway to needing to reload it, reload it.
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
                url = entry
                use_hashed = self._default_hash_filenames
                add_comment = self._default_add_comment
            elif isinstance(entry, dict):
                url = str(entry.get("url", ""))
                if not url:
                    logger.warning(
                        "FileDownloader skipping urls entry without 'url': %r", entry
                    )
                    continue
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
        Brief: Return first 12 hex chars of sha1 over the full URL.

        Inputs:
          - url (str): The full URL string used to download.
        Outputs:
          - (str): 12-character lowercase hex digest.

        Example usage:
            >>> FileDownloader()._url_hash12('https://example.com/a.txt')
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
        """Brief: Download a single URL to filepath, honoring add_comment option.

        Inputs:
          - url: Source URL to fetch.
          - filepath: Destination path for the downloaded content.

        Outputs:
          - None; writes the downloaded body (and optional header) to filepath.

        Behavior:
          - When the effective add_comment option for the URL is True, a
            timestamped header line is written as the first line in the file.
          - When add_comment is False or None, only the body is written.
        """

        r = requests.get(url, timeout=20)
        r.raise_for_status()
        _, add_comment = self._get_effective_url_options(url)
        body = r.text
        with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
            if add_comment is True:
                header = self._make_header_line(url)
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
