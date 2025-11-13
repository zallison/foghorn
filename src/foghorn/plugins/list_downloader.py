from __future__ import annotations
import logging
import os
import time
import hashlib
from datetime import datetime
from typing import Iterable, List, Set
from urllib.parse import urlparse

import requests

from .base import BasePlugin

logger = logging.getLogger(__name__)


class ListDownloader(BasePlugin):
    """
    Periodically download domain-only blocklists to local files so Filter can load them.

    Inputs (config):
      - urls (List[str]): HTTP(S) URLs to domain-per-line lists (comments with '#').
      - url_files (List[str], optional): File paths containing one URL per line ('#' comments allowed).
      - download_path (str): Directory to store downloaded files (default: './var/lists').
      - cache_days (int): Skip re-download if local file is newer than this many days.
      - interval_seconds (int|None): If set, re-check and update no more often than this.

    Outputs:
      - Writes one file per URL under download_path, named as '{base}-{sha1(url)[:12]}{ext}'.
        If the URL path has no extension, no extension is added (e.g., 'base-<hash>').
        The first line of each file is a timestamped header: '# YYYY-MM-DD HH:MM - url'.

    Example usage:
        plugins:
          - module: list_downloader
            pre_priority: 15
            config:
              download_path: ./var/lists
              cache_days: 7
              urls:
                - https://v.firebog.net/hosts/AdguardDNS.txt
                - https://v.firebog.net/hosts/Easylist.txt
              url_files:
                - ./config/url-sources/community.txt
    """

    aliases = ("list_downloader", "lists")

    def __init__(self, **config):
        super().__init__(**config)
        self.download_path: str = str(self.config.get("download_path", "./var/lists"))
        self.cache_days: int = int(self.config.get("cache_days", 7))
        self.urls: List[str] = list(self.config.get("urls", []) or [])
        self.url_files: List[str] = list(self.config.get("url_files", []) or [])
        self.interval_seconds: int | None = self.config.get("interval_seconds")
        self._last_run: float = 0.0

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
            except Exception as e:  # pragma: no cover
                logger.warning("Failed reading url_files: %s", e)

        os.makedirs(self.download_path, exist_ok=True)
        # Perform an initial fetch at startup
        self._maybe_run(force=True)

    # Run early so files exist before Filter runs
    pre_priority = 15

    def pre_resolve(self, qname, qtype, req, ctx):  # noqa: D401
        """No decision; opportunistically refresh lists on interval."""
        self._maybe_run(force=False)
        return None

    # Internal helpers
    def _maybe_run(self, force: bool) -> None:
        now = time.time()
        if not force and self.interval_seconds is not None:
            if (now - self._last_run) < int(self.interval_seconds):
                return
        try:
            self._download_all(self.urls)
            self._last_run = now
        except Exception as e:  # pragma: no cover
            logger.warning("ListDownloader update failed: %s", e)

    def _download_all(self, urls: Iterable[str]) -> None:
        for url in urls:
            fname = self._make_hashed_filename(url)
            fpath = os.path.join(self.download_path, fname)

            if self._should_skip_cache(fpath):
                continue

            # Try HEAD for last-modified; fall back to GET
            if self._needs_update(url, fpath):
                self._fetch(url, fpath)

            if not self._validate_domain_list(fpath):
                raise ValueError(
                    f"Invalid content in {fname}: expected domain-per-line list"
                )

    def _should_skip_cache(self, filepath: str) -> bool:
        if not os.path.exists(filepath):
            return False
        mtime = os.path.getmtime(filepath)
        return (time.time() - mtime) < (self.cache_days * 86400)

    def _needs_update(self, url: str, filepath: str) -> bool:
        if not os.path.exists(filepath):
            return True
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
                    if not line or line.startswith("#"):
                        continue
                    # Reject typical hosts-format entries (start with an IP)
                    if line[0].isdigit():
                        return False
                    if " " in line or "\t" in line or "." not in line:
                        return False
                    seen += 1
                    if seen >= 5:
                        return True
            return False
        except Exception:
            return False
