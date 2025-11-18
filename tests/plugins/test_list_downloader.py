"""
Brief: Tests for foghorn.plugins.list_downloader.ListDownloader covering helper logic,
interval handling, and download/validation behavior.

Inputs:
  - None directly; uses pytest fixtures such as tmp_path and monkeypatch.

Outputs:
  - None; assertions validate ListDownloader helper functions and side effects.
"""

import os
import time
from datetime import datetime

import pytest
import requests

import foghorn.plugins.list_downloader as list_downloader_mod
from foghorn.plugins.list_downloader import ListDownloader


@pytest.fixture
def downloader(tmp_path):
    """Brief: Construct ListDownloader with a temporary download path and no URLs.

    Inputs:
      - tmp_path (pathlib.Path): Pytest-provided temporary directory.

    Outputs:
      - ListDownloader: Instance configured with empty urls/url_files and temp path.
    """

    return ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])


def test_url_hash12_length_and_stability(downloader):
    """Brief: _url_hash12 returns a stable 12-char lowercase hex digest.

    Inputs:
      - downloader: ListDownloader fixture.

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
      - downloader: ListDownloader fixture.

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
      - downloader: ListDownloader fixture.

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
      - downloader: ListDownloader fixture.

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

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
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
    dl = ListDownloader(
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
    assert any("ListDownloader added" in rec.getMessage() for rec in caplog.records)


def test_make_header_line_uses_supplied_datetime(downloader):
    """Brief: _make_header_line uses provided datetime for deterministic output.

    Inputs:
      - downloader: ListDownloader fixture.

    Outputs:
      - None; asserts formatted timestamp and URL.
    """

    dt = datetime(2024, 1, 2, 3, 4)
    line = downloader._make_header_line("https://example.com", now=dt)
    assert line == "# 2024-01-02 03:04 - https://example.com"


def test_needs_update_true_for_missing_file(tmp_path):
    """Brief: _needs_update returns True when local file does not exist.

    Inputs:
      - tmp_path: Temporary directory path.

    Outputs:
      - None; asserts True for nonexistent file.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
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

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    f = tmp_path / "list.txt"
    f.write_text("# header\n")

    # Set local mtime to a fixed epoch
    local_mtime = 1_700_000_000
    os.utime(f, (local_mtime, local_mtime))

    class DummyResp:
        headers = {"Last-Modified": "Sun, 05 Feb 2034 01:23:45 GMT"}

    calls = {}

    def fake_head(url, timeout):
        calls["args"] = (url, timeout)
        return DummyResp()

    monkeypatch.setattr(list_downloader_mod.requests, "head", fake_head)

    # Remote newer than local -> True
    assert dl._needs_update("https://example.com/a.txt", str(f)) is True
    assert calls["args"][0] == "https://example.com/a.txt"

    # Remote older than local -> False
    DummyResp.headers = {"Last-Modified": "Sun, 05 Feb 2000 01:23:45 GMT"}
    assert dl._needs_update("https://example.com/a.txt", str(f)) is False


def test_needs_update_true_on_bad_last_modified(monkeypatch, tmp_path):
    """Brief: _needs_update returns True when Last-Modified is unparsable.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts True when time.strptime raises inside _needs_update.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    f = tmp_path / "list.txt"
    f.write_text("# header\n")
    os.utime(f, (1_700_000_000, 1_700_000_000))

    class DummyResp:
        headers = {"Last-Modified": "not-a-date"}

    def fake_head(url, timeout):
        return DummyResp()

    monkeypatch.setattr(list_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is True


def test_needs_update_true_on_request_exception(monkeypatch, tmp_path):
    """Brief: _needs_update returns True when requests.head raises RequestException.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts True when RequestException is raised.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    f = tmp_path / "list.txt"
    f.write_text("# header\n")
    os.utime(f, (1_700_000_000, 1_700_000_000))

    def fake_head(url, timeout):
        raise requests.RequestException("boom")

    monkeypatch.setattr(list_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is True


def test_needs_update_true_when_no_last_modified(monkeypatch, tmp_path):
    """Brief: _needs_update returns True when Last-Modified header is absent.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts True when response has no Last-Modified header.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    f = tmp_path / "list.txt"
    f.write_text("# header\n")
    os.utime(f, (1_700_000_000, 1_700_000_000))

    class DummyResp:
        headers = {}

    def fake_head(url, timeout):
        return DummyResp()

    monkeypatch.setattr(list_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is True


def test_needs_update_false_for_recent_file(monkeypatch, tmp_path):
    """Brief: _needs_update returns False when local file is younger than one day.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for local file.

    Outputs:
      - None; asserts False and avoids calling requests.head when file is fresh.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    f = tmp_path / "list.txt"
    f.write_text("# header\n")

    # Make the file appear fresh: mtime within the last hour.
    now = time.time()
    fresh_mtime = now - 3600
    os.utime(f, (fresh_mtime, fresh_mtime))

    def fake_head(url, timeout):  # pragma: no cover - should not be called
        raise AssertionError("requests.head should not be called for fresh files")

    monkeypatch.setattr(list_downloader_mod.requests, "head", fake_head)

    assert dl._needs_update("https://example.com/a.txt", str(f)) is False


def test_validate_domain_list_accepts_good_domain_only_list(tmp_path):
    """Brief: _validate_domain_list returns True for valid domain-per-line lists.

    Inputs:
      - tmp_path: Temporary directory for domain list file.

    Outputs:
      - None; asserts True when at least 5 valid domain lines exist.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    f = tmp_path / "domains.txt"
    lines = [
        "# header",
        "",
        "one.example",
        "two.example",
        "three.example",
        "four.example",
        "five.example",
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

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])

    # Hosts-style file: IP followed by hostname -> reject
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("127.0.0.1 bad.example\n")
    assert dl._validate_domain_list(str(hosts)) is False

    # Line without dot or with spaces/tabs -> reject
    bad = tmp_path / "bad.txt"
    bad.write_text("notadomain\nfoo bar\n")
    assert dl._validate_domain_list(str(bad)) is False


def test_validate_domain_list_false_when_insufficient_valid_lines(tmp_path):
    """Brief: _validate_domain_list returns False when fewer than 5 valid domains.

    Inputs:
      - tmp_path: Temporary directory for short list file.

    Outputs:
      - None; asserts False when valid domain count is below threshold.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    short = tmp_path / "short.txt"
    short.write_text("one.example\ntwo.example\nthree.example\nfour.example\n")
    assert dl._validate_domain_list(str(short)) is False


def test_fetch_writes_header_and_body(monkeypatch, tmp_path):
    """Brief: _fetch writes a header line followed by response body.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for the output file.

    Outputs:
      - None; asserts header content and body lines written.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    url = "https://example.com/list.txt"
    out = tmp_path / "out.txt"

    class DummyResp:
        def __init__(self, text: str) -> None:
            self.text = text

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(u, timeout):
        assert u == url
        assert timeout == 20
        return DummyResp("line1\nline2\n")

    monkeypatch.setattr(list_downloader_mod.requests, "get", fake_get)
    monkeypatch.setattr(
        dl,
        "_make_header_line",
        lambda src_url, now=None: f"# HEADER {src_url}",
    )

    dl._fetch(url, str(out))
    content = out.read_text(encoding="utf-8")
    lines = content.splitlines()
    assert lines[0] == f"# HEADER {url}"
    assert lines[1:] == ["line1", "line2"]


def test_download_all_fetches_and_validates(monkeypatch, tmp_path):
    """Brief: _download_all fetches lists when needed and validates them.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for downloaded file.

    Outputs:
      - None; asserts fetch invocation and file validation succeeds.
    """

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
    url = "https://example.com/list.txt"

    # Deterministic filename in tmp_path
    monkeypatch.setattr(dl, "_make_hashed_filename", lambda _url: "list.txt")
    monkeypatch.setattr(dl, "_needs_update", lambda _url, _path: True)

    def fake_fetch(src_url, fpath):
        assert src_url == url
        header = dl._make_header_line(src_url, now=datetime(2024, 1, 2, 3, 4))
        body = "one.example\ntwo.example\nthree.example\nfour.example\nfive.example\n"
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(header + "\n" + body)

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

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
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

    dl = ListDownloader(download_path=str(tmp_path), urls=[], url_files=[])
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
      - tmp_path: Temporary directory for ListDownloader path.

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

    def fake_get(url, timeout):
        return DummyResp()

    monkeypatch.setattr(list_downloader_mod.requests, "get", fake_get)

    dl = ListDownloader(
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

    monkeypatch.setattr(list_downloader_mod.time, "time", fake_time)

    dl._maybe_run(force=False)  # t=100 -> should run
    dl._maybe_run(force=False)  # t=120 -> within 60s, skip
    dl._maybe_run(force=False)  # t=200 -> after 60s, run

    assert len(calls) == 2
    assert calls[0] == ["https://example.com/a.txt"]


def test_maybe_run_force_ignores_interval(monkeypatch, tmp_path):
    """Brief: _maybe_run with force=True bypasses the configured interval.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for ListDownloader path.

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

    def fake_get(url, timeout):
        return DummyResp()

    monkeypatch.setattr(list_downloader_mod.requests, "get", fake_get)

    dl = ListDownloader(
        download_path=str(tmp_path), urls=["https://example.com/a.txt"], url_files=[]
    )
    dl.interval_seconds = 300
    dl._last_run = 1000.0

    calls = []

    def fake_download(urls):
        calls.append(list(urls))

    monkeypatch.setattr(dl, "_download_all", fake_download)
    monkeypatch.setattr(list_downloader_mod.time, "time", lambda: 1100.0)

    dl._maybe_run(force=True)
    assert len(calls) == 1
    assert calls[0] == ["https://example.com/a.txt"]


def test_setup_calls_maybe_run_and_returns_none(monkeypatch, tmp_path):
    """Brief: setup delegates to _maybe_run(force=True) and returns None.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.
      - tmp_path: Temporary directory for ListDownloader path.

    Outputs:
      - None; asserts _maybe_run is called with force=True and return is None.
    """

    # Avoid real network calls by stubbing out requests.get at the module level
    # before constructing the downloader.
    class DummyResp:
        text = ""

        def raise_for_status(self) -> None:  # pragma: no cover - trivial
            return None

    def fake_get(url, timeout):
        return DummyResp()

    monkeypatch.setattr(list_downloader_mod.requests, "get", fake_get)

    dl = ListDownloader(
        download_path=str(tmp_path), urls=["https://example.com/a.txt"], url_files=[]
    )

    called = {"force": None}

    def fake_maybe_run(force: bool):
        called["force"] = force

    monkeypatch.setattr(dl, "_maybe_run", fake_maybe_run)

    result = dl.setup()
    assert result is None
    assert called["force"] is True
