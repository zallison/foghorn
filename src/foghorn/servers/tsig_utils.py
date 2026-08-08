"""Shared DNS TSIG (RFC 2845) helpers for QUERY and zone-management paths.

Brief:
  Centralize algorithm normalization, keyring construction, request verification,
  response signing, TSIG stripping for cache hygiene, and error responses.

Inputs:
  - Raw DNS wire bytes and key config dicts (name/secret/algorithm).

Outputs:
  - Verification results, signed/stripped wire bytes, and error responses.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.tsig
import dns.tsigkeyring

from foghorn.utils import dns_names

logger = logging.getLogger(__name__)

# Timestamp skew fudge (seconds). BIND and dnspython default to 300.
DEFAULT_TSIG_MAX_FUDGE_SECONDS = 300


def normalize_tsig_algorithm(alg: object) -> str:
    """Brief: Normalize a TSIG algorithm name to a short canonical form.

    Inputs:
      - alg: Algorithm text (e.g. 'hmac-sha256.', 'HMAC-SHA512').

    Outputs:
      - str: Canonical short name (e.g. 'hmac-sha256').
    """

    a = str(alg or "").rstrip(".").lower()
    if "hmac-sha512" in a:
        return "hmac-sha512"
    if "hmac-sha384" in a:
        return "hmac-sha384"
    if "hmac-sha256" in a:
        return "hmac-sha256"
    if "hmac-sha1" in a:
        return "hmac-sha1"
    if "hmac-md5" in a:
        return "hmac-md5"
    return a or "hmac-sha256"


def normalize_key_name(name: object) -> str:
    """Brief: Normalize a TSIG key DNS name for comparison.

    Inputs:
      - name: Key name with or without trailing dot.

    Outputs:
      - str: Lowercased name without trailing dot.
    """

    return dns_names.normalize_name(name)


def wire_may_contain_tsig(data: bytes | bytearray | memoryview | None) -> bool:
    """Brief: Cheap ARCOUNT-based hint that additional RRs (possibly TSIG) exist.

    Inputs:
      - data: Raw DNS message bytes.

    Outputs:
      - bool: True when header ARCOUNT > 0 (or wire too short to tell safely False).
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        return False
    raw = bytes(data)
    if len(raw) < 12:
        return False
    arcount = int.from_bytes(raw[10:12], "big")
    return arcount > 0


def build_tsig_keyring(
    key_configs: Sequence[dict] | None,
) -> Tuple[Optional[object], Dict[str, dict]]:
    """Brief: Build a dnspython keyring and name->config map from key configs.

    Inputs:
      - key_configs: Iterable of dicts with name/secret[/algorithm].

    Outputs:
      - (keyring, by_name): keyring or None; map of normalized name -> config dict.
    """

    textring: Dict[str, str] = {}
    by_name: Dict[str, dict] = {}
    for cfg in key_configs or []:
        if not isinstance(cfg, dict):
            continue
        name = cfg.get("name")
        secret = cfg.get("secret")
        if not name or not secret:
            continue
        n = normalize_key_name(name)
        textring[str(name)] = str(secret)
        by_name[n] = dict(cfg)
    if not textring:
        return None, {}
    try:
        keyring = dns.tsigkeyring.from_text(textring)
    except Exception:
        return None, {}
    return keyring, by_name


@dataclass(frozen=True)
class TsigVerifyResult:
    """Brief: Result of verifying a TSIG-signed DNS request.

    Inputs:
      - Constructed by verify_request_tsig.

    Outputs:
      - Immutable verification outcome fields for hot-path / UPDATE callers.
    """

    ok: bool
    error_code: Optional[str]
    error_text: Optional[str]
    key_config: Optional[dict]
    keyname: Optional[str]
    algorithm: Optional[str]
    had_tsig: bool
    request_msg: Any = None


def verify_request_tsig(
    request_data: bytes,
    key_configs: Sequence[dict] | None,
    *,
    max_fudge_seconds: int = DEFAULT_TSIG_MAX_FUDGE_SECONDS,
) -> TsigVerifyResult:
    """Brief: Verify TSIG authentication (RFC 2845) using dnspython.

    Inputs:
      - request_data: Raw DNS message bytes.
      - key_configs: Configured TSIG keys (name/secret/algorithm).
      - max_fudge_seconds: Maximum accepted TSIG fudge (default 300).

    Outputs:
      - TsigVerifyResult with ok/error_code/key metadata and optional request_msg.
    """

    configs = [c for c in (key_configs or []) if isinstance(c, dict)]
    if not configs:
        return TsigVerifyResult(
            ok=False,
            error_code="no_keys",
            error_text="No TSIG keys configured",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=False,
            request_msg=None,
        )

    keyring, by_name = build_tsig_keyring(configs)
    if keyring is None:
        return TsigVerifyResult(
            ok=False,
            error_code="no_keys",
            error_text="No usable TSIG keys configured",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=False,
            request_msg=None,
        )

    try:
        msg = dns.message.from_wire(request_data, keyring=keyring)
    except dns.tsig.PeerBadKey as exc:
        return TsigVerifyResult(
            ok=False,
            error_code="badkey",
            error_text=f"Unknown TSIG key: {exc}",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=True,
            request_msg=None,
        )
    except dns.tsig.BadSignature:
        return TsigVerifyResult(
            ok=False,
            error_code="badsig",
            error_text="TSIG signature verification failed",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=True,
            request_msg=None,
        )
    except dns.tsig.PeerBadTime:
        return TsigVerifyResult(
            ok=False,
            error_code="badtime",
            error_text="TSIG time verification failed",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=True,
            request_msg=None,
        )
    except dns.message.UnknownTSIGKey as exc:
        return TsigVerifyResult(
            ok=False,
            error_code="badkey",
            error_text=f"Unknown TSIG key: {exc}",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=True,
            request_msg=None,
        )
    except dns.exception.DNSException as exc:
        return TsigVerifyResult(
            ok=False,
            error_code="dns",
            error_text=f"TSIG verification error: {exc}",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=True,
            request_msg=None,
        )
    except Exception as exc:
        return TsigVerifyResult(
            ok=False,
            error_code="dns",
            error_text=f"TSIG verification error: {exc}",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=True,
            request_msg=None,
        )

    if not getattr(msg, "had_tsig", False):
        return TsigVerifyResult(
            ok=False,
            error_code="no_tsig",
            error_text="No TSIG present",
            key_config=None,
            keyname=None,
            algorithm=None,
            had_tsig=False,
            request_msg=msg,
        )

    try:
        tsig_rr = msg.tsig[0]
        fudge = int(getattr(tsig_rr, "fudge", 0) or 0)
    except Exception:
        fudge = 0

    max_fudge = int(max_fudge_seconds or DEFAULT_TSIG_MAX_FUDGE_SECONDS)
    if max_fudge < 0:
        max_fudge = DEFAULT_TSIG_MAX_FUDGE_SECONDS
    if fudge and fudge > max_fudge:
        return TsigVerifyResult(
            ok=False,
            error_code="badfudge",
            error_text=f"TSIG fudge too large ({fudge}s)",
            key_config=None,
            keyname=normalize_key_name(getattr(msg, "keyname", "")),
            algorithm=normalize_tsig_algorithm(getattr(msg, "keyalgorithm", "")),
            had_tsig=True,
            request_msg=msg,
        )

    keyname = normalize_key_name(getattr(msg, "keyname", ""))
    keyalgorithm = normalize_tsig_algorithm(getattr(msg, "keyalgorithm", ""))
    cfg = by_name.get(keyname)
    if cfg is None:
        # Fall back to linear scan for non-normalized name variants.
        for candidate in configs:
            if normalize_key_name(candidate.get("name", "")) == keyname:
                cfg = candidate
                break
    if cfg is None:
        return TsigVerifyResult(
            ok=False,
            error_code="badkey",
            error_text="TSIG key not configured",
            key_config=None,
            keyname=keyname,
            algorithm=keyalgorithm,
            had_tsig=True,
            request_msg=msg,
        )

    expected_alg = normalize_tsig_algorithm(cfg.get("algorithm", "hmac-sha256"))
    if expected_alg and expected_alg != keyalgorithm:
        return TsigVerifyResult(
            ok=False,
            error_code="badalg",
            error_text=(
                f"TSIG algorithm mismatch (expected {expected_alg}, got {keyalgorithm})"
            ),
            key_config=None,
            keyname=keyname,
            algorithm=keyalgorithm,
            had_tsig=True,
            request_msg=msg,
        )

    return TsigVerifyResult(
        ok=True,
        error_code=None,
        error_text=None,
        key_config=dict(cfg),
        keyname=keyname,
        algorithm=keyalgorithm,
        had_tsig=True,
        request_msg=msg,
    )


def strip_tsig_from_wire(wire: bytes | bytearray | memoryview | None) -> bytes:
    """Brief: Remove TSIG RRs from a DNS message wire payload.

    Inputs:
      - wire: Response or request wire bytes.

    Outputs:
      - bytes: Wire without TSIG when parseable; original bytes on failure.
    """

    if not isinstance(wire, (bytes, bytearray, memoryview)):
        return b""
    raw = bytes(wire)
    if not raw:
        return raw
    try:
        msg = dns.message.from_wire(raw, ignore_trailing=True)
    except Exception:
        try:
            msg = dns.message.from_wire(raw, continue_on_error=True)
        except Exception:
            return raw
    try:
        if getattr(msg, "tsig", None):
            msg.tsig = []
        # Some dnspython versions keep mac context; clear best-effort.
        for attr in ("mac", "keyname", "keyalgorithm", "tsig_error"):
            if hasattr(msg, attr):
                try:
                    setattr(msg, attr, None)
                except Exception:
                    pass
        return msg.to_wire()
    except Exception:
        return raw


def sign_response_tsig(
    response_wire: bytes,
    *,
    key_configs: Sequence[dict] | None,
    keyname: object,
    algorithm: object | None = None,
    request_msg: Any = None,
) -> bytes:
    """Brief: Attach a TSIG signature to a response wire using the request key.

    Inputs:
      - response_wire: Unsigned response bytes.
      - key_configs: Key configs used to build the keyring.
      - keyname: TSIG key name from the verified request.
      - algorithm: Optional algorithm override.
      - request_msg: Optional verified request message for context.

    Outputs:
      - bytes: Signed response wire, or original wire on failure.
    """

    raw = bytes(response_wire or b"")
    if not raw or not keyname:
        return raw
    keyring, _by = build_tsig_keyring(key_configs)
    if keyring is None:
        return raw
    try:
        resp = dns.message.from_wire(raw, ignore_trailing=True)
    except Exception:
        return raw
    # Drop any existing TSIG before re-signing.
    try:
        resp.tsig = []
    except Exception:
        pass
    alg = normalize_tsig_algorithm(
        algorithm or getattr(request_msg, "keyalgorithm", None) or "hmac-sha256"
    )
    try:
        kn = str(keyname)
        if not kn.endswith("."):
            kn = kn + "."
        resp.use_tsig(
            keyring=keyring,
            keyname=kn,
            algorithm=alg,
            original_id=getattr(request_msg, "id", None),
        )
        return resp.to_wire()
    except Exception as exc:
        logger.debug("TSIG response signing failed: %s", exc)
        return raw


def build_tsig_error_response(
    request_data: bytes,
    *,
    rcode: int = dns.rcode.NOTAUTH,
    key_configs: Sequence[dict] | None = None,
    keyname: object | None = None,
    algorithm: object | None = None,
    sign: bool = True,
) -> bytes:
    """Brief: Build a QR=1 error response, optionally TSIG-signed.

    Inputs:
      - request_data: Original request wire.
      - rcode: DNS RCODE (default NOTAUTH).
      - key_configs: Keys for optional signing.
      - keyname/algorithm: Key identity when signing.
      - sign: When True and key material present, attempt TSIG on the error.

    Outputs:
      - bytes: Response wire.
    """

    recovered: Any = None
    try:
        recovered = dns.message.from_wire(request_data, continue_on_error=True)
    except Exception:
        recovered = None

    if recovered is not None:
        try:
            resp = dns.message.make_response(recovered)
            resp.set_rcode(int(rcode))
            wire = resp.to_wire()
            if sign and keyname and key_configs:
                return sign_response_tsig(
                    wire,
                    key_configs=key_configs,
                    keyname=keyname,
                    algorithm=algorithm,
                    request_msg=recovered,
                )
            return wire
        except Exception:
            pass

    try:
        mid = int.from_bytes(request_data[0:2], "big") if len(request_data) >= 2 else 0
        flags = (
            int.from_bytes(request_data[2:4], "big") if len(request_data) >= 4 else 0
        )
        opcode = int((flags >> 11) & 0xF)
    except Exception:
        mid = 0
        opcode = 0
    resp = dns.message.Message(id=int(mid))
    resp.flags |= dns.flags.QR
    try:
        resp.set_opcode(opcode)
    except Exception:
        pass
    resp.set_rcode(int(rcode))
    try:
        return resp.to_wire()
    except Exception:
        # Last-resort minimal header.
        try:
            hdr = bytearray(12)
            hdr[0:2] = int(mid).to_bytes(2, "big")
            # QR=1, copy opcode, RCODE low nibble
            fl = 0x8000 | ((opcode & 0xF) << 11) | (int(rcode) & 0xF)
            hdr[2:4] = int(fl).to_bytes(2, "big")
            return bytes(hdr)
        except Exception:
            return b""


def resolve_features_tsig_keys(tsig_cfg: dict | None) -> List[dict]:
    """Brief: Resolve server.features.tsig keys using shared UPDATE key loaders.

    Inputs:
      - tsig_cfg: Mapping that may contain keys / key_sources.

    Outputs:
      - list[dict]: Normalized key config dicts.
    """

    if not isinstance(tsig_cfg, dict):
        return []
    try:
        from foghorn.plugins.resolve.zone_records import update_helpers
    except Exception:
        # Fallback: inline keys only.
        keys = tsig_cfg.get("keys") or []
        return [dict(k) for k in keys if isinstance(k, dict)]
    zone_like = {"tsig": tsig_cfg}
    try:
        return list(
            update_helpers.resolve_tsig_key_configs(zone_like, source_loaders=None)
            or []
        )
    except Exception:
        return []
