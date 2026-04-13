"""
Brief: Tests for foghorn.plugins.resolve.file_downloader.FileDownloader covering helper logic,
interval handling, and download/validation behavior.

Inputs:
  - None directly; uses pytest fixtures such as tmp_path and monkeypatch.

Outputs:
  - None; assertions validate FileDownloader helper functions and side effects.
"""

import os
import time
from datetime import datetime

import pytest
import requests

import foghorn.plugins.resolve.file_downloader as file_downloader_mod
from foghorn.plugins.resolve.file_downloader import FileDownloader


def _setup_downloader_for_tests(dl: FileDownloader) -> None:
    """Brief: Call setup with a no-op _maybe_run to avoid network activity.

    Inputs:
      - dl (FileDownloader): Downloader instance to prepare.
    Outputs:
      - None; calls setup() after stubbing _maybe_run.
    """

    dl._maybe_run = lambda force: None
    dl.setup()


@pytest.fixture
def downloader(tmp_path):
    """Brief: Construct FileDownloader with a temporary download path and no URLs.

    Inputs:
      - tmp_path (pathlib.Path): Pytest-provided temporary directory.

    Outputs:
      - FileDownloader: Instance configured with empty urls/url_files and temp path.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    return dl


def test_url_hash12_length_and_stability(downloader):
    """Brief: _url_hash12 returns a stable 12-char lowercase hex digest.

    Inputs:
      - downloader: FileDownloader fixture.

    Outputs:
      - None; asserts digest length, stability, and hex characters.
    """

    h1 = downloader._url_hash12("https://example.com/a.txt")
    h2 = downloader._url_hash12("https://example.com/a.txt")
    assert len(h1) == 12
    assert h1 == h2
    assert all(c in "0123456789abcdef" for c in h1)


def test_derive_base_and_ext_various_shapes(downloader):
    """Brief: _derive_base_and_ext handles paths, no paths, and no extensions.

    Inputs:
      - downloader: FileDownloader fixture.

    Outputs:
      - None; asserts derived (base, ext) tuples for several URL forms.
    """

    base, ext = downloader._derive_base_and_ext("https://x/y/AdguardDNS.txt?z=1")
    assert base == "AdguardDNS"
    assert ext == ".txt"

    base2, ext2 = downloader._derive_base_and_ext("https://example.com/path/noext")
    assert base2 == "noext"
    assert ext2 == ""

    base3, ext3 = downloader._derive_base_and_ext("https://example.com")
    assert base3 == "example.com"
    assert ext3 == ""

    # Hidden file-like basename without explicit extension
    base4, ext4 = downloader._derive_base_and_ext("https://example.com/.hidden")
    assert base4 == ".hidden"
    assert ext4 == ""


def test_make_hashed_filename_uses_sanitized_base_and_ext(downloader):
    """Brief: _make_hashed_filename preserves extension and sanitizes base name.

    Inputs:
      - downloader: FileDownloader fixture.

    Outputs:
      - None; asserts filename pattern and sanitization.
    """

    url = "https://example.com/lists/My List!.txt"
    fname = downloader._make_hashed_filename(url)
    base, ext = os.path.splitext(fname)
    # Base should be "My_List_-<hash>" and extension .txt
    assert base.startswith("My_List_-")
    assert len(base.split("-", 1)[1]) == 12
    assert ext == ".txt"


def test_make_hashed_filename_with_custom_base(downloader):
    """Brief: _make_hashed_filename respects base_name override and URL-derived ext.

    Inputs:
      - downloader: FileDownloader fixture.

    Outputs:
      - None; asserts filename uses custom base with URL extension.
    """

    url = "https://example.com/file.data"
    fname = downloader._make_hashed_filename(url, base_name="custom")
    base, ext = os.path.splitext(fname)
    assert base.startswith("custom-")
    assert len(base.split("-", 1)[1]) == 12
    assert ext == ".data"


def test_read_url_files_parses_and_logs_missing(tmp_path, caplog):
    """Brief: _read_url_files collects URLs and logs missing files.

    Inputs:
      - tmp_path: Temporary directory for URL list files.
      - caplog: Pytest logging capture fixture.

    Outputs:
      - None; asserts returned URLs and presence of missing-file warning.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f1 = tmp_path / "urls1.txt"
    f1.write_text("# comment\n\nhttps://one.example\n  https://two.example  \n")
    missing = tmp_path / "missing.txt"

    caplog.set_level("WARNING")
    urls = dl._read_url_files([str(f1), str(missing)])
    assert urls == {"https://one.example", "https://two.example"}
    assert any(
        "url_files entry not found" in rec.getMessage() for rec in caplog.records
    )


def test_init_merges_url_files_and_logs_debug(tmp_path, caplog):
    """Brief: __init__ merges urls and url_files and logs debug for added URLs.

    Inputs:
      - tmp_path: Temporary directory for download_path and url_files.
      - caplog: Pytest logging capture fixture.

    Outputs:
      - None; asserts merged/sorted URLs and presence of debug log.
    """

    url_file = tmp_path / "urls.txt"
    url_file.write_text("# header\nhttps://b.example\nhttps://a.example\n")

    caplog.set_level("DEBUG")
    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=["https://c.example"],
        url_files=[str(url_file)],
        interval_days=None,
    )

    # URLs should be merged and sorted
    assert dl.urls == [
        "https://a.example",
        "https://b.example",
        "https://c.example",
    ]
    # Debug message about added URLs is logged
    assert any("FileDownloader added" in rec.getMessage() for rec in caplog.records)
    _setup_downloader_for_tests(dl)


def test_make_header_line_uses_supplied_datetime(downloader):
    """Brief: _make_header_line uses provided datetime for deterministic output.

    Inputs:
      - downloader: FileDownloader fixture.

    Outputs:
      - None; asserts formatted timestamp and URL.
    """

    dt = datetime(2024, 1, 2, 3, 4)
    line = downloader._make_header_line("https://example.com", now=dt)
    assert line == "# 2024-01-02 03:04 - https://example.com"


def test_validate_and_normalize_url_rejects_non_http(tmp_path):
    """Brief: _validate_and_normalize_url rejects non-http/https schemes.

    Inputs:
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts ValueError for unsupported schemes.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    with pytest.raises(ValueError):
        dl._validate_and_normalize_url("ftp://example.com/list.txt", source="urls")


def test_validate_and_normalize_url_rejects_private_host(tmp_path):
    """Brief: _validate_and_normalize_url rejects private hosts by default.

    Inputs:
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts ValueError for private targets.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    with pytest.raises(ValueError):
        dl._validate_and_normalize_url("http://127.0.0.1/list.txt", source="urls")


def test_validate_and_normalize_url_allows_private_with_flag(tmp_path):
    """Brief: _validate_and_normalize_url allows private hosts when enabled.

    Inputs:
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts private host URLs are accepted with allow_private_hosts.
    """

    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=[],
        url_files=[],
        allow_private_hosts=True,
    )
    _setup_downloader_for_tests(dl)
    url = dl._validate_and_normalize_url("http://127.0.0.1/list.txt", source="urls")
    assert url == "http://127.0.0.1/list.txt"


def test_validate_and_normalize_url_allows_allowlisted_host(tmp_path):
    """Brief: _validate_and_normalize_url allows hosts on allowlist.

    Inputs:
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts allowlisted hosts bypass private checks.
    """

    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=[],
        url_files=[],
        allowlist_hosts=["localhost"],
    )
    _setup_downloader_for_tests(dl)
    url = dl._validate_and_normalize_url("http://localhost/list.txt", source="urls")
    assert url == "http://localhost/list.txt"


def test_validate_and_normalize_url_rejects_hostname_resolving_private(
    monkeypatch, tmp_path
):
    """Brief: _validate_and_normalize_url rejects hostnames resolving to private IPs.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts ValueError when hostname DNS resolves to 127.0.0.1.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)

    def fake_getaddrinfo(host, port, type=None):  # noqa: ANN001, ARG001
        assert host == "public.example"
        return [
            (
                file_downloader_mod.socket.AF_INET,
                file_downloader_mod.socket.SOCK_STREAM,
                6,
                "",
                ("127.0.0.1", 0),
            )
        ]

    monkeypatch.setattr(file_downloader_mod.socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="private host"):
        dl._validate_and_normalize_url(
            "http://public.example/list.txt",
            source="urls",
        )


def test_request_with_safe_redirects_rejects_private_redirect_target(
    monkeypatch, tmp_path
):
    """Brief: _request_with_safe_redirects rejects redirects into private targets.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts ValueError when redirect Location points to 127.0.0.1.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    calls = {"count": 0, "closed": 0}

    class RedirectResp:
        status_code = 302
        headers = {"Location": "http://127.0.0.1/blocked.txt"}

        def close(self) -> None:
            calls["closed"] += 1

    def fake_get(url, stream, timeout, allow_redirects):
        calls["count"] += 1
        assert url == "https://example.com/list.txt"
        assert stream is True
        assert timeout == 20
        assert allow_redirects is False
        return RedirectResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    with pytest.raises(ValueError, match="private host"):
        dl._request_with_safe_redirects(
            method="GET",
            url="https://example.com/list.txt",
            timeout=20,
            stream=True,
            source="download",
        )

    assert calls["count"] == 1
    assert calls["closed"] == 1


def test_request_with_safe_redirects_enforces_redirect_hop_limit(monkeypatch, tmp_path):
    """Brief: _request_with_safe_redirects enforces max redirect hops.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts ValueError when redirects exceed configured hop limit.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    calls = {"count": 0, "closed": 0}

    class RedirectResp:
        status_code = 302
        headers = {"Location": "/next"}

        def close(self) -> None:
            calls["closed"] += 1

    def fake_get(url, stream, timeout, allow_redirects):
        calls["count"] += 1
        assert stream is True
        assert timeout == 20
        assert allow_redirects is False
        return RedirectResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    with pytest.raises(ValueError, match="exceeded max redirect hops"):
        dl._request_with_safe_redirects(
            method="GET",
            url="https://example.com/list.txt",
            timeout=20,
            stream=True,
            source="download",
            max_redirect_hops=1,
        )

    assert calls["count"] == 2
    assert calls["closed"] == 2


def test_read_url_files_skips_invalid_urls(tmp_path, caplog):
    """Brief: _read_url_files skips invalid or private URLs and logs warnings.

    Inputs:
      - tmp_path: Temporary directory for URL list files.
      - caplog: Pytest logging capture fixture.

    Outputs:
      - None; asserts only valid URLs are returned.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f1 = tmp_path / "urls1.txt"
    f1.write_text(
        "ftp://bad.example/list.txt\nhttp://127.0.0.1/list.txt\nhttps://ok.example\n"
    )

    caplog.set_level("WARNING")
    urls = dl._read_url_files([str(f1)])
    assert urls == {"https://ok.example"}
    assert any("Skipping invalid URL" in rec.getMessage() for rec in caplog.records)


def test_needs_update_respects_failure_backoff(monkeypatch, tmp_path):
    """Brief: _needs_update suppresses retries during backoff window.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts RequestException triggers cooldown.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "list.txt"
    f.write_text("# header\n")

    def failing_head(url, timeout, allow_redirects=False):  # noqa: ARG001
        assert allow_redirects is False
        raise requests.RequestException("boom")

    monkeypatch.setattr(file_downloader_mod.requests, "head", failing_head)
    assert dl._needs_update("https://example.com/a.txt", str(f)) is False

    def should_not_call(
        url, timeout, allow_redirects=False
    ):  # pragma: no cover - backoff short-circuits
        assert allow_redirects is False
        raise AssertionError("requests.head should not be called during backoff")

    monkeypatch.setattr(file_downloader_mod.requests, "head", should_not_call)
    assert dl._needs_update("https://example.com/a.txt", str(f)) is False


def test_download_all_detects_plain_filename_collisions(tmp_path):
    """Brief: _download_all raises on filename collisions when hashing is disabled.

    Inputs:
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts ValueError on collisions.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    urls = ["https://a.example/list.txt", "https://b.example/list.txt"]

    with pytest.raises(ValueError):
        dl._download_all(urls)


def test_needs_update_true_for_missing_file(tmp_path):
    """Brief: _needs_update returns True when local file does not exist.

    Inputs:
      - tmp_path: Temporary directory path.

    Outputs:
      - None; asserts True for nonexistent file.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    missing = tmp_path / "missing.txt"
    assert dl._needs_update("https://example.com/a.txt", str(missing)) is True


def test_needs_update_uses_last_modified_header(monkeypatch, tmp_path):
    """Brief: _needs_update compares remote Last-Modified to local mtime.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts True when remote is newer and False when older.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "list.txt"
    f.write_text("# header\n")

    # Set local mtime to a fixed epoch
    local_mtime = 1_700_000_000
    os.utime(f, (local_mtime, local_mtime))

    class DummyResp:
        status_code = 200
        headers = {"Last-Modified": "Sun, 05 Feb 2034 01:23:45 GMT"}

        def close(self) -> None:  # pragma: no cover - trivial
            return None

    calls = {}

    def fake_head(url, timeout, allow_redirects=False):
        calls["args"] = (url, timeout, allow_redirects)
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "head", fake_head)

    # Remote newer than local -> True
    assert dl._needs_update("https://example.com/a.txt", str(f)) is True
    assert calls["args"][0] == "https://example.com/a.txt"
    assert calls["args"][2] is False

    # Remote older than local -> False
    DummyResp.headers = {"Last-Modified": "Sun, 05 Feb 2000 01:23:45 GMT"}
    assert dl._needs_update("https://example.com/a.txt", str(f)) is False


def test_needs_update_false_on_bad_last_modified(monkeypatch, tmp_path):
    """Brief: _needs_update returns False when Last-Modified is unparsable.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts False when time.strptime raises inside _needs_update.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "list.txt"
    f.write_text("# header\n")
    os.utime(f, (1_700_000_000, 1_700_000_000))

    class DummyResp:
        status_code = 200
        headers = {"Last-Modified": "not-a-date"}

        def close(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_head(url, timeout, allow_redirects=False):  # noqa: ARG001
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is False


def test_needs_update_false_on_request_exception(monkeypatch, tmp_path):
    """Brief: _needs_update returns False when requests.head raises RequestException.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts False when RequestException is raised.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "list.txt"
    f.write_text("# header\n")
    os.utime(f, (1_700_000_000, 1_700_000_000))

    def fake_head(url, timeout, allow_redirects=False):  # noqa: ARG001
        raise requests.RequestException("boom")

    monkeypatch.setattr(file_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is False


def test_needs_update_true_when_no_last_modified(monkeypatch, tmp_path):
    """Brief: _needs_update returns True when Last-Modified header is absent.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts True when response has no Last-Modified header.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "list.txt"
    f.write_text("# header\n")
    os.utime(f, (1_700_000_000, 1_700_000_000))

    class DummyResp:
        status_code = 200
        headers = {}

        def close(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_head(url, timeout, allow_redirects=False):  # noqa: ARG001
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is True


def test_needs_update_false_for_recent_file(monkeypatch, tmp_path):
    """Brief: _needs_update returns False when local file is younger than default.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts False and avoids calling requests.head when file is fresh.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "list.txt"
    f.write_text("# header\n")

    # Make the file appear fresh: mtime within the last hour.
    now = time.time()
    fresh_mtime = now - 3600
    os.utime(f, (fresh_mtime, fresh_mtime))

    def fake_head(
        url, timeout, allow_redirects=False
    ):  # pragma: no cover - should not be called
        assert allow_redirects is False
        raise AssertionError("requests.head should not be called for fresh files")

    monkeypatch.setattr(file_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is False


def test_needs_update_uses_interval_days_for_min_age(monkeypatch, tmp_path):
    """Brief: _needs_update uses interval_days to decide file freshness.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts False and avoids network when file is newer than interval.
    """

    dl = FileDownloader(
        download_path=str(tmp_path), urls=[], url_files=[], interval_days=7
    )
    _setup_downloader_for_tests(dl)
    f = tmp_path / "list.txt"
    f.write_text("# header\n")

    # File age is 3 days, which is less than interval_days=7 -> treated as fresh.
    now = time.time()
    three_days = 3 * file_downloader_mod.ONE_DAY_SECONDS
    fresh_mtime = now - three_days
    os.utime(f, (fresh_mtime, fresh_mtime))

    def fake_head(
        url, timeout, allow_redirects=False
    ):  # pragma: no cover - should not be called
        assert allow_redirects is False
        raise AssertionError(
            "requests.head should not be called when file is newer than interval_days"
        )

    monkeypatch.setattr(file_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is False


def test_validate_domain_list_accepts_good_domain_only_list(tmp_path):
    """Brief: _validate_domain_list returns True for valid domain-per-line lists.

    Inputs:
      - tmp_path: Temporary directory for domain list file.

    Outputs:
      - None; asserts True when at least one valid domain line exists.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "domains.txt"
    lines = [
        "# header",
        "",
        "one.example",
    ]
    f.write_text("\n".join(lines))

    assert dl._validate_domain_list(str(f)) is True


def test_validate_domain_list_ignores_bang_comment_lines(tmp_path):
    """Brief: _validate_domain_list skips lines starting with '!' as comments.

    Inputs:
      - tmp_path: Temporary directory for domain list file.

    Outputs:
      - None; asserts AdGuard-style '!' comments do not cause rejection.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "adguard.txt"
    lines = [
        "# header",
        "! AdGuard comment line",
        "one.example",
    ]
    f.write_text("\n".join(lines))

    assert dl._validate_domain_list(str(f)) is True


def test_validate_domain_list_rejects_hosts_and_bad_lines(tmp_path):
    """Brief: _validate_domain_list rejects hosts-format and malformed lines.

    Inputs:
      - tmp_path: Temporary directory for malformed list files.

    Outputs:
      - None; asserts False for hosts-style and invalid content.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)

    # Hosts-style file: IP followed by hostname -> reject
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("127.0.0.1 bad.example\n")
    assert dl._validate_domain_list(str(hosts)) is False

    # Line without dot or with spaces/tabs -> reject
    bad = tmp_path / "bad.txt"
    bad.write_text("notadomain\nfoo bar\n")
    assert dl._validate_domain_list(str(bad)) is False


def test_validate_domain_list_false_when_no_valid_lines(tmp_path):
    """Brief: _validate_domain_list returns False when no valid domains exist.

    Inputs:
      - tmp_path: Temporary directory for short list file.

    Outputs:
      - None; asserts False when valid domain count is below threshold.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    short = tmp_path / "short.txt"
    short.write_text("# header\n! comment\n")
    assert dl._validate_domain_list(str(short)) is False


def test_fetch_writes_header_and_body(monkeypatch, tmp_path):
    """Brief: _fetch writes a header line followed by response body when enabled.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for the output file.

    Outputs:
      - None; asserts header content and body lines written.
    """

    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=["https://example.com/list.txt"],
        url_files=[],
        add_comment=True,
    )
    _setup_downloader_for_tests(dl)
    url = "https://example.com/list.txt"
    out = tmp_path / "out.txt"

    class DummyResp:
        def __init__(self, text: str) -> None:
            self._body = text.encode("utf-8")
            self.status_code = 200
            self.headers = {"Content-Length": str(len(self._body))}

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

        def iter_content(self, chunk_size: int = 1):  # noqa: ARG002
            yield self._body

        def close(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(u, timeout, stream, allow_redirects=False):
        assert u == url
        assert timeout == 20
        assert stream is True
        assert allow_redirects is False
        return DummyResp("line1\nline2\n")

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)
    monkeypatch.setattr(
        dl,
        "_make_header_line",
        lambda src_url, now=None: f"# HEADER {src_url}",
    )

    temp_path = dl._fetch(url, str(out))
    with open(temp_path, "r", encoding="utf-8") as handle:
        content = handle.read()
    os.remove(temp_path)
    lines = content.splitlines()
    assert lines[0] == f"# HEADER {url}"
    assert lines[1:] == ["line1", "line2"]


def test_fetch_rejects_response_with_oversized_content_length(monkeypatch, tmp_path):
    """Brief: _fetch rejects responses whose Content-Length exceeds the max cap.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for output path checks.

    Outputs:
      - None; asserts ValueError is raised before body iteration.
    """

    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=["https://example.com/list.txt"],
        url_files=[],
        add_comment=False,
    )
    _setup_downloader_for_tests(dl)
    url = "https://example.com/list.txt"
    out = tmp_path / "out.txt"

    calls = {"iter": 0, "closed": 0}

    class DummyResp:
        status_code = 200
        headers = {
            "Content-Length": str(file_downloader_mod.MAX_DOWNLOAD_RESPONSE_BYTES + 1)
        }

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

        def iter_content(self, chunk_size: int = 1):  # noqa: ARG002
            calls["iter"] += 1
            yield b"one.example\n"

        def close(self) -> None:
            calls["closed"] += 1

    def fake_get(u, timeout, stream, allow_redirects=False):
        assert u == url
        assert timeout == 20
        assert stream is True
        assert allow_redirects is False
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    with pytest.raises(ValueError, match="exceeds max allowed size"):
        dl._fetch(url, str(out))
    assert calls["iter"] == 0
    assert calls["closed"] == 1
    assert url in dl._failure_state


def test_fetch_rejects_stream_when_total_bytes_exceed_limit(monkeypatch, tmp_path):
    """Brief: _fetch rejects streamed responses that exceed max bytes mid-download.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for output path checks.

    Outputs:
      - None; asserts streamed overflow raises and temp file is cleaned up.
    """

    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=["https://example.com/list.txt"],
        url_files=[],
        add_comment=False,
    )
    _setup_downloader_for_tests(dl)
    url = "https://example.com/list.txt"
    out = tmp_path / "out.txt"

    monkeypatch.setattr(file_downloader_mod, "MAX_DOWNLOAD_RESPONSE_BYTES", 8)
    monkeypatch.setattr(file_downloader_mod, "DOWNLOAD_STREAM_CHUNK_BYTES", 4)

    calls = {"closed": 0}

    class DummyResp:
        status_code = 200
        headers = {"Content-Length": "0"}

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

        def iter_content(self, chunk_size: int = 1):
            assert chunk_size == 4
            yield b"abcd"
            yield b"efgh"
            yield b"i"

        def close(self) -> None:
            calls["closed"] += 1

    def fake_get(u, timeout, stream, allow_redirects=False):
        assert u == url
        assert timeout == 20
        assert stream is True
        assert allow_redirects is False
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    with pytest.raises(ValueError, match="exceeded max allowed size"):
        dl._fetch(url, str(out))
    assert calls["closed"] == 1
    assert url in dl._failure_state
    assert out.exists() is False
    assert list(tmp_path.glob(".file_downloader.*")) == []


def test_download_all_fetches_and_validates(monkeypatch, tmp_path):
    """Brief: _download_all fetches lists when needed and validates them.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for downloaded file.

    Outputs:
      - None; asserts fetch invocation and file validation succeeds.
    """

    dl = FileDownloader(
        download_path=str(tmp_path), urls=[], url_files=[], add_comment=True
    )
    _setup_downloader_for_tests(dl)
    url = "https://example.com/list.txt"

    # Deterministic filename in tmp_path
    monkeypatch.setattr(dl, "_make_hashed_filename", lambda _url: "list.txt")
    monkeypatch.setattr(dl, "_needs_update", lambda _url, _path: True)

    def fake_fetch(src_url, _fpath):
        assert src_url == url
        header = dl._make_header_line(src_url, now=datetime(2024, 1, 2, 3, 4))
        body = "one.example\ntwo.example\nthree.example\nfour.example\nfive.example\n"
        temp_path = tmp_path / "temp.txt"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(header + "\n" + body)
        return str(temp_path)

    monkeypatch.setattr(dl, "_fetch", fake_fetch)

    dl._download_all([url])
    out = tmp_path / "list.txt"
    assert out.exists()
    assert dl._validate_domain_list(str(out)) is True


def test_download_all_skips_when_no_update_needed(monkeypatch, tmp_path):
    """Brief: _download_all skips fetching when _needs_update returns False.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for downloaded file.

    Outputs:
      - None; asserts _fetch is not called and validation fails when file is missing.
    """

    dl = FileDownloader(
        download_path=str(tmp_path), urls=[], url_files=[], add_comment=True
    )
    _setup_downloader_for_tests(dl)
    url = "https://example.com/list.txt"

    monkeypatch.setattr(dl, "_make_hashed_filename", lambda _url: "list.txt")

    called = {"needs_update": False, "fetch": False}

    def fake_needs_update(_url, _path):
        called["needs_update"] = True
        return False

    def fake_fetch(_url, _path):  # pragma: no cover - should not be called
        called["fetch"] = True

    monkeypatch.setattr(dl, "_needs_update", fake_needs_update)
    monkeypatch.setattr(dl, "_fetch", fake_fetch)

    # File does not exist, so _validate_domain_list will return False and raise.
    with pytest.raises(ValueError):
        dl._download_all([url])

    assert called["needs_update"] is True
    assert called["fetch"] is False


def test_download_all_raises_on_invalid_content(monkeypatch, tmp_path):
    """Brief: _download_all raises ValueError when validation fails.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for computed path.

    Outputs:
      - None; asserts ValueError when _validate_domain_list returns False.
    """

    dl = FileDownloader(
        download_path=str(tmp_path), urls=[], url_files=[], add_comment=True
    )
    _setup_downloader_for_tests(dl)
    url = "https://example.com/list.txt"

    monkeypatch.setattr(dl, "_make_hashed_filename", lambda _url: "list.txt")
    monkeypatch.setattr(dl, "_needs_update", lambda _url, _path: False)

    # Leave file missing so _validate_domain_list returns False
    with pytest.raises(ValueError):
        dl._download_all([url])


def test_maybe_run_respects_interval(monkeypatch, tmp_path):
    """Brief: _maybe_run respects the configured interval when force is False.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for FileDownloader path.

    Outputs:
      - None; asserts _download_all is skipped when within interval.
    """

    # Avoid real network calls from the initial __init__-triggered _maybe_run by
    # stubbing out requests.get at the module level before constructing the
    # downloader.
    class DummyResp:
        text = ""

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(url, timeout, allow_redirects=False):  # noqa: ARG001
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    dl = FileDownloader(
        download_path=str(tmp_path), urls=["https://example.com/a.txt"], url_files=[]
    )
    dl.interval_seconds = 60
    dl._last_run = 0.0

    calls = []

    def fake_download(urls):
        calls.append(list(urls))

    monkeypatch.setattr(dl, "_download_all", fake_download)

    times = [100.0, 120.0, 200.0]

    def fake_time():
        return times.pop(0)

    monkeypatch.setattr(file_downloader_mod.time, "time", fake_time)

    dl._maybe_run(force=False)  # t=100 -> should run
    dl._maybe_run(force=False)  # t=120 -> within 60s, skip
    dl._maybe_run(force=False)  # t=200 -> after 60s, run

    assert len(calls) == 2
    assert calls[0] == ["https://example.com/a.txt"]


def test_maybe_run_force_ignores_interval(monkeypatch, tmp_path):
    """Brief: _maybe_run with force=True bypasses the configured interval.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for FileDownloader path.

    Outputs:
      - None; asserts _download_all runs even within interval when forced.
    """

    # Avoid real network calls from the initial __init__-triggered _maybe_run by
    # stubbing out requests.get at the module level before constructing the
    # downloader.
    class DummyResp:
        text = ""

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(url, timeout, allow_redirects=False):  # noqa: ARG001
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    dl = FileDownloader(
        download_path=str(tmp_path), urls=["https://example.com/a.txt"], url_files=[]
    )
    dl.interval_seconds = 300
    dl._last_run = 1000.0

    calls = []

    def fake_download(urls):
        calls.append(list(urls))

    monkeypatch.setattr(dl, "_download_all", fake_download)
    monkeypatch.setattr(file_downloader_mod.time, "time", lambda: 1100.0)

    dl._maybe_run(force=True)
    assert len(calls) == 1
    assert calls[0] == ["https://example.com/a.txt"]


def test_setup_calls_maybe_run_and_returns_none(monkeypatch, tmp_path):
    """Brief: setup delegates to _maybe_run(force=True) and returns None.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for FileDownloader path.

    Outputs:
      - None; asserts _maybe_run is called with force=True and return is None.
    """

    # Avoid real network calls by stubbing out requests.get at the module level
    # before constructing the downloader.
    class DummyResp:
        text = ""

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(url, timeout, allow_redirects=False):  # noqa: ARG001
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    dl = FileDownloader(
        download_path=str(tmp_path), urls=["https://example.com/a.txt"], url_files=[]
    )

    called = {"force": None}

    def fake_maybe_run(force: bool):
        called["force"] = force

    monkeypatch.setattr(dl, "_maybe_run", fake_maybe_run)

    result = dl.setup()
    assert result is None
    assert called["force"] is True


def test_setup_defers_startup_check_until_post_setup(monkeypatch, tmp_path):
    """Brief: setup defers delayed startup check until post_setup is called.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for downloader files.

    Outputs:
      - None; asserts delayed startup check is triggered only from post_setup().
    """

    url = "https://example.com/list.txt"
    dl = FileDownloader(download_path=str(tmp_path), urls=[url], url_files=[])

    # Ensure startup-delay condition is met: a fresh local file already exists.
    existing = tmp_path / "list.txt"
    existing.write_text("one.example\n")
    now = time.time()
    os.utime(existing, (now, now))

    called = {"count": 0}

    def fake_start_delayed_startup_check() -> None:
        called["count"] += 1

    monkeypatch.setattr(
        dl,
        "_start_delayed_startup_check",
        fake_start_delayed_startup_check,
    )

    dl.setup()
    assert dl._run_startup_check_on_post_setup is True
    assert called["count"] == 0

    dl.post_setup()
    assert dl._run_startup_check_on_post_setup is False
    assert called["count"] == 1


def test_post_setup_noop_when_no_deferred_startup_check(monkeypatch, tmp_path):
    """Brief: post_setup is a no-op when setup did not defer startup checks.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for downloader files.

    Outputs:
      - None; asserts no delayed startup check is started.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    called = {"count": 0}

    def fake_start_delayed_startup_check() -> None:
        called["count"] += 1

    monkeypatch.setattr(
        dl,
        "_start_delayed_startup_check",
        fake_start_delayed_startup_check,
    )

    dl.post_setup()
    assert called["count"] == 0


def test_init_invalid_interval_days_disables_periodic_refresh(tmp_path, caplog):
    """Brief: Invalid interval_days value logs a warning and disables refresh.

    Inputs:
      - tmp_path: Temporary directory for download_path.
      - caplog: Pytest logging capture fixture.

    Outputs:
      - None; asserts interval_seconds is None and warning mentions interval_days.
    """

    caplog.set_level("WARNING")
    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=[],
        url_files=[],
        interval_days="not-a-number",
    )

    assert dl.interval_seconds is None
    assert any("interval_days" in rec.getMessage() for rec in caplog.records)


def test_init_invalid_legacy_interval_seconds_disables_periodic_refresh(
    tmp_path, caplog
):
    """Brief: Invalid legacy interval_seconds logs a warning and disables refresh.

    Inputs:
      - tmp_path: Temporary directory for download_path.
      - caplog: Pytest logging capture fixture.

    Outputs:
      - None; asserts interval_seconds is None and warning mentions interval_seconds.
    """

    caplog.set_level("WARNING")
    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=[],
        url_files=[],
        interval_days=None,
        interval_seconds="bad",
    )

    assert dl.interval_seconds is None
    assert any("interval_seconds" in rec.getMessage() for rec in caplog.records)


def test_merge_urls_from_files_returns_early_when_no_urls(tmp_path, monkeypatch):
    """Brief: _merge_urls_from_files returns early when url_files produce no URLs.

    Inputs:
      - tmp_path: Temporary directory for download_path.
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts _read_url_files is called and urls remain unchanged.
    """

    called = {"paths": None}

    def fake_read_url_files(self, paths):  # noqa: D401
        """Stub that records paths and returns an empty set."""

        called["paths"] = list(paths)
        return set()

    monkeypatch.setattr(
        FileDownloader, "_read_url_files", fake_read_url_files, raising=False
    )

    dl = FileDownloader(
        download_path=str(tmp_path),
        urls=["https://existing.example"],
        url_files=["ignored.txt"],
    )

    assert called["paths"] == ["ignored.txt"]
    assert dl.urls == ["https://existing.example"]


def test_setup_merges_url_files_and_logs_debug(monkeypatch, tmp_path, caplog):
    """Brief: setup merges url_files into urls and logs a debug message.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for download_path.
      - caplog: Pytest logging capture fixture.

    Outputs:
      - None; asserts _read_url_files is invoked and merged URLs are logged.
    """

    # Avoid real network calls by stubbing _maybe_run and requests.get.
    class DummyResp:
        text = ""

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(url, timeout, allow_redirects=False):  # noqa: ARG001
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    dl = FileDownloader(
        download_path=str(tmp_path), urls=["https://base.example"], url_files=[]
    )
    dl.url_files = ["urls1.txt"]

    read_calls = {"paths": None}

    def fake_read_url_files(paths):
        read_calls["paths"] = list(paths)
        return {"https://fromfile.example"}

    monkeypatch.setattr(dl, "_read_url_files", fake_read_url_files)

    called_maybe = {"force": None}

    def fake_maybe_run(force: bool) -> None:
        called_maybe["force"] = force

    monkeypatch.setattr(dl, "_maybe_run", fake_maybe_run)

    caplog.set_level("DEBUG")
    dl.setup()

    assert read_calls["paths"] == ["urls1.txt"]
    assert "https://fromfile.example" in dl.urls
    assert called_maybe["force"] is True
    assert any("FileDownloader added" in rec.getMessage() for rec in caplog.records)


def test_setup_invalid_interval_configuration_disables_refresh(
    monkeypatch, tmp_path, caplog
):
    """Brief: setup logs a warning and skips refresh thread for bad interval_seconds.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for download_path.
      - caplog: Pytest logging capture fixture.

    Outputs:
      - None; asserts warning logged and no background thread created.
    """

    class DummyResp:
        text = ""

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(url, timeout, allow_redirects=False):  # noqa: ARG001
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])

    called_maybe = {"force": None}

    def fake_maybe_run(force: bool) -> None:
        called_maybe["force"] = force

    monkeypatch.setattr(dl, "_maybe_run", fake_maybe_run)

    dl.interval_seconds = "n/a"  # triggers invalid interval branch

    caplog.set_level("WARNING")
    dl.setup()

    assert called_maybe["force"] is True
    assert dl._stop_event is None
    assert dl._background_thread is None
    assert any("interval configuration" in rec.getMessage() for rec in caplog.records)


def test_setup_starts_background_thread_with_valid_interval(monkeypatch, tmp_path):
    """Brief: setup creates stop event and background thread when interval is valid.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for download_path.

    Outputs:
      - None; asserts _stop_event and _background_thread are set and loop runs once.
    """

    class DummyResp:
        text = ""

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(url, timeout, allow_redirects=False):  # noqa: ARG001
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.requests, "get", fake_get)

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])

    call_count = {"maybe_run": 0, "forces": []}

    def fake_maybe_run(force: bool) -> None:
        call_count["maybe_run"] += 1
        call_count["forces"].append(force)

    monkeypatch.setattr(dl, "_maybe_run", fake_maybe_run)

    class DummyEvent:
        """Brief: Event stub that allows a single loop iteration then stops.

        Inputs:
          - None

        Outputs:
          - None; is_set() is False initially and True after wait().
        """

        def __init__(self) -> None:
            self._set = False

        def is_set(self) -> bool:
            return self._set

        def set(self) -> None:
            self._set = True

        def wait(self, timeout: float) -> None:  # noqa: ARG002
            self._set = True

    class DummyThread:
        """Brief: Thread stub that runs the target synchronously once.

        Inputs:
          - target: Callable to run.

        Outputs:
          - None; start() invokes target() immediately.
        """

        def __init__(self, target=None, name=None, daemon=None) -> None:
            self._target = target
            self.name = name
            self.daemon = daemon
            self.started = False

        def start(self) -> None:
            self.started = True
            if self._target is not None:
                self._target()

    monkeypatch.setattr(file_downloader_mod.threading, "Event", DummyEvent)
    monkeypatch.setattr(file_downloader_mod.threading, "Thread", DummyThread)

    dl.interval_seconds = 60
    dl.setup()

    assert isinstance(dl._stop_event, DummyEvent)
    assert isinstance(dl._background_thread, DummyThread)
    assert dl._background_thread.name == "FileDownloader-refresh"
    assert dl._background_thread.daemon is True
    # One call from the initial forced update, one from the background loop.
    assert call_count["maybe_run"] == 2
    assert call_count["forces"] == [True, False]


def test_needs_update_ignores_stat_oserror_and_uses_remote(monkeypatch, tmp_path):
    """Brief: _needs_update falls back to remote checks when stat raises OSError.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts True is returned when getmtime raises OSError.
    """

    dl = FileDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    _setup_downloader_for_tests(dl)
    f = tmp_path / "list.txt"
    f.write_text("# header\n")

    def fake_getmtime(path):  # noqa: ARG001
        raise OSError("stat-fail")

    class DummyResp:
        status_code = 200
        headers = {}

        def close(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_head(url, timeout, allow_redirects=False):  # noqa: ARG001
        assert allow_redirects is False
        return DummyResp()

    monkeypatch.setattr(file_downloader_mod.os.path, "getmtime", fake_getmtime)
    monkeypatch.setattr(file_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is True
