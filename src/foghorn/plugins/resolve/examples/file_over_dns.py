from __future__ import annotations

import base64
import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from typing_extensions import Literal

from dnslib import QTYPE, RR, TXT, DNSHeader, DNSRecord
from pydantic import BaseModel, Field

from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision
from foghorn.utils.register_caches import registered_lru_cached

logger = logging.getLogger(__name__)


@dataclass
class FileMapping:
    """Brief: In-memory mapping from short name to file path.

    Inputs (fields):
      - name: Short identifier used in DNS labels (case-insensitive).
      - file_path: Absolute or relative filesystem path to the source file.

    Outputs:
      - FileMapping instances are used by FileOverDns for quick lookup.
    """

    name: str
    file_path: str


class FileOverDnsConfigEntry(BaseModel):
    """Brief: Single file/name entry for FileOverDns configuration.

    Inputs:
      - file_path: Path to the file whose contents will be exposed over DNS.
      - name: Short identifier used in qnames (e.g. "crazy_file").

    Outputs:
      - FileOverDnsConfigEntry instance.
    """

    file_path: str
    name: str


class FileOverDnsConfig(BaseModel):
    """Brief: Typed configuration model for FileOverDns.

    Inputs:
      - files: List of objects each containing:
          * file_path (str): Path to a readable file.
          * name (str): Short identifier used in DNS labels.
      - ttl: TTL in seconds for TXT responses (default 300, >= 0).
      - max_chunk_bytes: Maximum raw byte span (Y - X) to serve per query
        before encoding, clamped to [1, 4096].
      - format: Output format for TXT records; "base64" (default) or "raw".

    Outputs:
      - FileOverDnsConfig instance with normalized field types.
    """

    files: List[FileOverDnsConfigEntry] = Field(default_factory=list)
    ttl: int = Field(default=300, ge=0)
    max_chunk_bytes: int = Field(default=4096, ge=1, le=4096)
    format: Literal["base64", "raw"] = Field(default="base64")

    class Config:
        extra = "allow"


@registered_lru_cached(maxsize=16_384)
def _parse_file_over_dns_qname(qname: str) -> Optional[Tuple[str, int, int]]:
    """Brief: Parse qname into (name, start, end) for FileOverDns queries.

    Inputs:
      - qname: Full DNS name string, e.g. "crazy_file.0.512.example.com".

    Outputs:
      - (name, start, end) tuple when the pattern matches; None otherwise.

    Behaviour:
      - Expected pattern: <name>.<start>.<end>.<rest-of-domain>.
      - start and end are interpreted as integer byte offsets.
      - When start > end, the values are swapped.
    """

    if not qname:
        return None

    text = str(qname).rstrip(".")
    labels = text.split(".")
    if len(labels) < 4:
        return None

    name_label = labels[0].strip()
    if not name_label:
        return None

    try:
        start = int(labels[1])
        end = int(labels[2])
    except ValueError:
        return None

    # Normalise negative inputs to zero to avoid confusing slices.
    if start < 0:
        start = 0
    if end < 0:
        end = 0

    if start > end:
        start, end = end, start

    return name_label.lower(), start, end


@registered_lru_cached(maxsize=16_384)
def _read_file_segment(
    file_path: str,
    start: int,
    end: int,
    max_chunk_bytes: int,
) -> Tuple[bytes, int, int, int]:
    """Brief: Read a clamped [start, end) byte segment from file_path.

    Inputs:
      - file_path: Path to the file to read (opened in binary mode).
      - start: Requested inclusive start byte offset.
      - end: Requested exclusive end byte offset.
      - max_chunk_bytes: Maximum allowed span (end - start) before clamping.

    Outputs:
      - (data, actual_start, actual_end, total_size):
          * data (bytes): File slice after bounds and size clamping.
          * actual_start (int): Effective start offset used.
          * actual_end (int): Effective end offset used (<= total_size).
          * total_size (int): Total file size in bytes.

    Behaviour:
      - Negative offsets are treated as zero.
      - When start > end, the values are swapped before clamping.
      - (actual_end - actual_start) is limited to max_chunk_bytes.
      - When actual_start >= total_size, data is b"" and actual_end == total_size.
    """

    if max_chunk_bytes <= 0:
        max_chunk_bytes = 1

    start = max(0, int(start))
    end = max(0, int(end))
    if start > end:
        start, end = end, start

    # First, determine total file size.
    with open(file_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        total_size = f.tell()

        if total_size <= 0:
            return b"", 0, 0, 0

        if start >= total_size:
            return b"", total_size, total_size, total_size

        # Clamp end to file size and max_chunk_bytes.
        span = min(max_chunk_bytes, max(0, end - start))
        if span <= 0:
            span = min(max_chunk_bytes, total_size - start)

        actual_start = start
        actual_end = min(total_size, actual_start + span)

        f.seek(actual_start, os.SEEK_SET)
        data = f.read(actual_end - actual_start)

    return data, actual_start, actual_end, total_size


class FileOverDns(BasePlugin):
    """Brief: Serve file slices over TXT DNS queries.

    Inputs (config):
      - files: List of {"file_path", "name"} objects mapping friendly names
        to filesystem paths.
      - ttl: Optional TTL in seconds for TXT answers (default 300).
      - max_chunk_bytes: Optional maximum raw bytes to return per query
        (default 512, clamped to [1, 4096]).
      - format: Output format for TXT records; "base64" (default) or "raw".

    Behaviour:
      - Answers TXT queries of the form ``<name>.<X>.<Y>.<rest>`` when ``name``
        matches a configured entry.
      - Interprets X and Y as byte offsets [X, Y); swaps when X > Y and clamps
        the span to max_chunk_bytes and file size.
      - The file slice is encoded as one or more TXT records, each limited
        to 180 bytes of payload. In "base64" mode the payload is base64
        text; in "raw" mode bytes are emitted directly.
      - A final TXT record contains metadata: filename, effective start/end,
        total file size, and SHA1 of the emitted payload.
    """

    # Restrict this plugin to TXT qtypes by default.
    target_qtypes = ("TXT",)

    @classmethod
    def get_config_model(cls):
        """Brief: Return the Pydantic model used to validate plugin configuration.

        Inputs:
          - None.

        Outputs:
          - FileOverDnsConfig class for use by the core config loader.
        """

        return FileOverDnsConfig

    def __init__(self, **config):
        """Brief: Initialize FileOverDns and normalise configuration.

        Inputs:
          - **config: Arbitrary keyword configuration compatible with
            FileOverDnsConfig (typically provided via YAML/JSON).

        Outputs:
          - None; populates in-memory name -> path mapping and TTL settings.
        """

        super().__init__(**config)

        cfg_model = FileOverDnsConfig(**self.config)
        self._ttl = int(cfg_model.ttl)
        self._max_chunk_bytes = int(cfg_model.max_chunk_bytes)
        self._format = str(cfg_model.format)

        mappings: Dict[str, FileMapping] = {}
        for entry in cfg_model.files:
            raw_path = os.path.expanduser(entry.file_path)
            mappings[entry.name.lower()] = FileMapping(
                name=entry.name.lower(),
                file_path=raw_path,
            )
        self._files_by_name: Dict[str, FileMapping] = mappings

    def pre_resolve(
        self,
        qname: str,
        qtype: int,
        req: bytes,
        ctx: PluginContext,
    ) -> Optional[PluginDecision]:
        """Brief: Intercept and answer matching TXT queries with file slices.

        Inputs:
          - qname: Full query name from the DNS request.
          - qtype: Numeric DNS qtype code.
          - req: Raw DNS request bytes.
          - ctx: PluginContext instance for this request.

        Outputs:
          - PluginDecision("override") with a packed DNS response when this
            plugin serves the query, or None to fall back to normal handling.
        """

        if not self.targets(ctx):
            return None

        # Only TXT queries are supported.
        try:
            if int(qtype) != int(QTYPE.TXT):
                return None
        except Exception:  # pragma: no cover - defensive conversion
            return None

        parsed = _parse_file_over_dns_qname(str(qname))
        if not parsed:
            return None

        name_label, start, end = parsed
        mapping = self._files_by_name.get(name_label)
        if mapping is None:
            return None

        file_path = mapping.file_path
        if not os.path.isfile(file_path):
            logger.warning(
                "FileOverDns: file not found for name %s: %s", name_label, file_path
            )
            return None

        try:
            data, actual_start, actual_end, total_size = _read_file_segment(
                file_path,
                start,
                end,
                self._max_chunk_bytes,
            )
        except OSError as exc:
            logger.warning(
                "FileOverDns: failed reading %s [%d:%d]: %s",
                file_path,
                start,
                end,
                exc,
            )
            return None

        # Encode the slice according to configured format and compute SHA1.
        if self._format == "raw":
            payload_bytes = data
            # Use latin-1 to preserve byte values 0-255 in TXT string form.
            payload_text = payload_bytes.decode("latin1") if payload_bytes else ""
        else:
            b64_bytes = base64.b64encode(data)
            payload_bytes = b64_bytes
            payload_text = b64_bytes.decode("ascii") if b64_bytes else ""

        sha1_hex = hashlib.sha1(payload_bytes).hexdigest()

        # Build a DNS TXT response reusing the transaction ID from the request.
        try:
            request = DNSRecord.parse(req)
        except Exception as exc:  # pragma: no cover - defensive parsing
            logger.warning(
                "FileOverDns: failed to parse request for %s: %s", qname, exc
            )
            return None

        reply = DNSRecord(
            DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q
        )

        # Emit data as one or more TXT answers.
        # - In "base64" mode: fixed-size chunks up to 180 bytes.
        # - In "raw" mode: prefer to end chunks on newlines, still respecting
        #   a hard limit of 180 bytes per TXT payload.
        max_txt_len = 180
        if self._format == "raw":
            # Stream bytes into TXT records; whenever we see a newline or we
            # hit 180 bytes, flush the current record and start a new one.
            data_bytes = payload_bytes
            chunk: bytearray = bytearray()
            for b in data_bytes:
                chunk.append(b)
                # If we've just added a newline, or we hit size limit, flush.
                if b == 0x0A or len(chunk) >= max_txt_len:
                    chunk_text = chunk.decode("latin1")
                    reply.add_answer(
                        RR(
                            rname=request.q.qname,
                            rtype=QTYPE.TXT,
                            rclass=1,
                            ttl=self._ttl,
                            rdata=TXT(chunk_text),
                        )
                    )
                    chunk.clear()

            # Flush any remaining bytes that did not end with a newline.
            if chunk:
                chunk_text = chunk.decode("latin1")
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.TXT,
                        rclass=1,
                        ttl=self._ttl,
                        rdata=TXT(chunk_text),
                    )
                )
        else:
            for i in range(0, len(payload_text), max_txt_len):
                chunk = payload_text[i : i + max_txt_len]
                reply.add_answer(
                    RR(
                        rname=request.q.qname,
                        rtype=QTYPE.TXT,
                        rclass=1,
                        ttl=self._ttl,
                        rdata=TXT(chunk),
                    )
                )

        # Final TXT record with metadata.
        meta = (
            f"filename={file_path};start={actual_start};end={actual_end};"
            f"total={total_size};sha1={sha1_hex}"
        )
        reply.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.TXT,
                rclass=1,
                ttl=self._ttl,
                rdata=TXT(meta),
            )
        )

        return PluginDecision(action="override", response=reply.pack())
