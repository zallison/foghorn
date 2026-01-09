import importlib
import os

from dnslib import QTYPE, DNSRecord

from foghorn.plugins.resolve.base import PluginContext


def _make_txt_query(name: str) -> bytes:
    """Brief: Build a minimal TXT DNS query for name.

    Inputs:
      - name: Domain name to query.

    Outputs:
      - Raw DNS query bytes suitable for passing to FileOverDns.pre_resolve.
    """

    q = DNSRecord.question(name, qtype="TXT")
    return q.pack()


def test_file_over_dns_module_imports() -> None:
    """Brief: Ensure file_over_dns module imports correctly.

    Inputs:
      - None.

    Outputs:
      - Asserts module name matches expected path.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.file_over_dns")
    assert mod.__name__ == "foghorn.plugins.resolve.examples.file_over_dns"


def test_parse_qname_basic_and_swap() -> None:
    """Brief: _parse_file_over_dns_qname parses labels and swaps X/Y when needed.

    Inputs:
      - None (uses hard-coded qname strings).

    Outputs:
      - Asserts parsed (name, start, end) and swap behaviour.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.file_over_dns")
    parse = mod._parse_file_over_dns_qname

    assert parse("crazy_file.0.10.example.com") == ("crazy_file", 0, 10)
    # Swap when X > Y
    assert parse("crazy_file.10.0.example.com") == ("crazy_file", 0, 10)
    # Too few labels -> None
    assert parse("too.short") is None
    # Non-integers -> None
    assert parse("crazy_file.x.y.example.com") is None


def test_read_file_segment_bounds_and_limits(tmp_path) -> None:
    """Brief: _read_file_segment clamps bounds and enforces max_chunk_bytes.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - Asserts start/end clamping, empty slice beyond EOF, and chunk limiting.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.file_over_dns")
    read_seg = mod._read_file_segment

    fpath = tmp_path / "data.bin"
    # Write 32 bytes 0..31 for deterministic checks.
    payload = bytes(range(32))
    fpath.write_bytes(payload)

    # In-range slice.
    data, s, e, total = read_seg(str(fpath), 4, 12, 32)
    assert total == 32
    assert (s, e) == (4, 12)
    assert data == payload[4:12]

    # Enforce max_chunk_bytes smaller than requested span.
    data2, s2, e2, total2 = read_seg(str(fpath), 0, 31, 8)
    assert total2 == 32
    assert (s2, e2) == (0, 8)
    assert data2 == payload[0:8]

    # Start beyond EOF -> empty slice at EOF.
    data3, s3, e3, total3 = read_seg(str(fpath), 64, 128, 16)
    assert total3 == 32
    assert (s3, e3) == (32, 32)
    assert data3 == b""


def test_file_over_dns_pre_resolve_basic_flow(tmp_path) -> None:
    """Brief: FileOverDns answers TXT queries with data and metadata records.

    Inputs:
      - tmp_path: pytest temporary directory for the backing file.

    Outputs:
      - Asserts that pre_resolve returns an override decision containing two
        TXT answers with expected base64 data and metadata fields.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.file_over_dns")
    FileOverDns = mod.FileOverDns

    data_path = tmp_path / "file.txt"
    content = b"abcdefghijklmnopqrstuvwxyz"  # 26 bytes
    data_path.write_bytes(content)

    plugin = FileOverDns(
        files=[{"file_path": str(data_path), "name": "crazy_file"}],
        ttl=123,
        max_chunk_bytes=8,
    )
    # BasePlugin defines setup(); call it per project convention, even though
    # FileOverDns does not override it.
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # Request bytes [2:10) -> 8-byte chunk, clamped by max_chunk_bytes.
    qname = "crazy_file.2.10.example.test"
    req_bytes = _make_txt_query(qname)

    decision = plugin.pre_resolve(qname, int(QTYPE.TXT), req_bytes, ctx)
    assert decision is not None
    assert decision.action == "override"
    assert decision.response is not None

    resp = DNSRecord.parse(decision.response)
    txt_answers = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]
    # Expect data + metadata; small payload should fit one data TXT.
    assert len(txt_answers) == 2

    data_txt = str(txt_answers[0].rdata).strip("\"")
    meta_txt = str(txt_answers[1].rdata).strip("\"")

    # First TXT record should be base64 of the requested slice.
    import base64

    expected_slice = content[2:10]
    expected_b64 = base64.b64encode(expected_slice).decode("ascii")
    assert data_txt == expected_b64

    # Metadata must contain filename, start/end, total, and sha1 over base64.
    assert f"filename={data_path}" in meta_txt
    assert "start=2" in meta_txt
    assert "end=10" in meta_txt
    assert "total=26" in meta_txt
    assert "sha1=" in meta_txt


def test_file_over_dns_pre_resolve_non_matching_or_missing_file(tmp_path) -> None:
    """Brief: FileOverDns falls back to None for non-matching names and missing files.

    Inputs:
      - tmp_path: pytest temporary directory for creating then removing a file.

    Outputs:
      - Asserts that pre_resolve returns None when name is unknown or the
        configured file is missing.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.file_over_dns")
    FileOverDns = mod.FileOverDns

    data_path = tmp_path / "file.txt"
    data_path.write_bytes(b"0123456789")

    plugin = FileOverDns(
        files=[{"file_path": str(data_path), "name": "crazy_file"}],
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    # Name not in mapping -> None
    qname = "other.0.5.example"
    req_bytes = _make_txt_query(qname)
    assert plugin.pre_resolve(qname, int(QTYPE.TXT), req_bytes, ctx) is None

    # Remove file so lookup fails.
    os.remove(data_path)
    qname2 = "crazy_file.0.5.example"
    req_bytes2 = _make_txt_query(qname2)
    assert plugin.pre_resolve(qname2, int(QTYPE.TXT), req_bytes2, ctx) is None


def test_file_over_dns_pre_resolve_raw_and_chunking(tmp_path) -> None:
    """Brief: FileOverDns supports raw format and splits payload into 180-byte TXT chunks.

    Inputs:
      - tmp_path: pytest temporary directory for the backing file.

    Outputs:
      - Asserts that raw bytes are emitted without base64 and that long
        payloads are split into multiple TXT records of at most 180 bytes.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.file_over_dns")
    FileOverDns = mod.FileOverDns

    # Build a payload with newlines and large enough to require multiple
    # 180-byte TXT chunks. Newlines should terminate individual TXT records
    # in raw mode.
    data_path = tmp_path / "file.txt"
    content = (b"line1\n" + b"Y" * 190 + b"\nline2\n" + b"Z" * 190 + b"\n")
    data_path.write_bytes(content)

    plugin = FileOverDns(
        files=[{"file_path": str(data_path), "name": "crazy_file"}],
        format="raw",
        max_chunk_bytes=400,
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")
    qname = "crazy_file.0.400.example.test"
    req_bytes = _make_txt_query(qname)

    decision = plugin.pre_resolve(qname, int(QTYPE.TXT), req_bytes, ctx)
    assert decision is not None
    resp = DNSRecord.parse(decision.response)

    txt_answers = [rr for rr in resp.rr if rr.rtype == QTYPE.TXT]
    # Last record is metadata; preceding ones are payload chunks.
    assert len(txt_answers) >= 3

    data_chunks = [str(rr.rdata).strip('"') for rr in txt_answers[:-1]]
    meta_txt = str(txt_answers[-1].rdata).strip('"')

    # Each chunk should be at most 180 bytes long.
    for chunk in data_chunks:
        encoded = chunk.encode("latin1")
        assert len(encoded) <= 180
        # Raw mode should end chunks on newlines when present.
        assert encoded.endswith(b"\n") or b"\n" not in encoded

    # Metadata should still contain filename and sha1.
    assert f"filename={data_path}" in meta_txt
    assert "sha1=" in meta_txt


def test_file_over_dns_pre_resolve_respects_targets(tmp_path) -> None:
    """Brief: FileOverDns honours BasePlugin targets configuration.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that pre_resolve returns None when client_ip is not targeted.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.file_over_dns")
    FileOverDns = mod.FileOverDns

    data_path = tmp_path / "file.txt"
    data_path.write_bytes(b"abcdef")

    plugin = FileOverDns(
        files=[{"file_path": str(data_path), "name": "crazy_file"}],
        targets=["10.0.0.0/8"],
    )
    plugin.setup()

    # Client outside targets -> plugin should not apply.
    ctx = PluginContext(client_ip="192.0.2.1")
    qname = "crazy_file.0.4.example"
    req_bytes = _make_txt_query(qname)

    assert plugin.pre_resolve(qname, int(QTYPE.TXT), req_bytes, ctx) is None


def test_file_over_dns_ignores_non_txt_qtypes(tmp_path) -> None:
    """Brief: FileOverDns only responds to TXT queries.

    Inputs:
      - tmp_path: pytest temporary directory.

    Outputs:
      - Asserts that pre_resolve returns None for non-TXT qtypes.
    """

    mod = importlib.import_module("foghorn.plugins.resolve.examples.file_over_dns")
    FileOverDns = mod.FileOverDns

    data_path = tmp_path / "file.txt"
    data_path.write_bytes(b"abcdef")

    plugin = FileOverDns(
        files=[{"file_path": str(data_path), "name": "crazy_file"}],
    )
    plugin.setup()

    ctx = PluginContext(client_ip="127.0.0.1")

    qname = "crazy_file.0.4.example"
    q = DNSRecord.question(qname, qtype="A")
    assert plugin.pre_resolve(qname, int(QTYPE.A), q.pack(), ctx) is None
