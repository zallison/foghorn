import base64
import logging
import threading
import time
from typing import Any, Final

try:  # Ensure required crypto backend is present before enabling DNSSEC logic.
    import importlib.util as _importlib_util

    if _importlib_util.find_spec("cryptography") is None:
        raise ImportError(
            "No module named 'cryptography'"
        )  # pragma: no cover - depends on runtime environment
except (
    ImportError
) as exc:  # pragma: no cover - exercised only when dependency is missing at runtime
    _log = logging.getLogger("foghorn.dnssec")
    _log.critical(
        "The 'cryptography' package is required for DNSSEC validation but is not installed: %s",
        exc,
    )
    raise SystemExit(1)

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

from foghorn.utils.register_caches import registered_ttl_cache


def _parse_resolv_conf_nameservers(path: str = "/etc/resolv.conf") -> list[str]:
    """Brief: Best-effort parse of nameserver entries from a resolv.conf file.

    Inputs:
      - path: Filesystem path to a resolv.conf-format file.

    Outputs:
      - List of nameserver IP strings in the order encountered. Returns an empty
        list when the file cannot be read or contains no nameserver entries.

    Notes:
      - This intentionally ignores search/domain directives. Some environments
        may contain invalid search suffixes (e.g. leading dots) that cause
        dnspython's strict parser to raise; we only need nameservers here.
    """

    servers: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.split("#", 1)[0].strip()
                if not raw:
                    continue
                parts = raw.split()
                if len(parts) >= 2 and parts[0].lower() == "nameserver":
                    servers.append(parts[1])
    except Exception:  # pragma: no cover - depends on host environment
        return []
    return servers


logger = logging.getLogger("foghorn.dnssec")

# Optional override for the nameservers used by the local DNSSEC validator.
# When None, the system resolver configuration is used (as provided by
# dnspython). When set to a non-empty list of IP strings, all validation
# lookups (_resolver) will send queries directly to those nameservers.
#
# When configured via an empty list ("[]"), validation lookups are performed
# using Foghorn's own RecursiveResolver instead of any external resolvers.
_VALIDATION_NAMESERVERS: Final[list[str] | None] = None
_VALIDATION_VIA_RECURSIVE: Final[bool] = False


def configure_dnssec_resolver(nameservers: list[str] | None) -> None:
    """Configure nameservers for DNSSEC validation lookups.

    Inputs:
      - nameservers: Optional list of IP address strings.
        - None: validation uses the system resolver configuration.
        - [] (empty list): validation performs all lookups via Foghorn's own
          RecursiveResolver (no system resolver, no external stub resolvers).
        - Non-empty list: validation lookups bypass the system config and talk
          directly to these servers.

    Outputs:
      - None; updates module-level configuration used by _resolver().
    """

    global _VALIDATION_NAMESERVERS, _VALIDATION_VIA_RECURSIVE

    # Sentinel semantics:
    #   - nameservers is None: use system resolver configuration.
    #   - nameservers is an empty list: use Foghorn's own RecursiveResolver for
    #     all validation lookups (no system resolver, no external stub).
    #   - nameservers is a non-empty list: talk directly to those IPs.
    if nameservers is None:
        _VALIDATION_NAMESERVERS = None
        _VALIDATION_VIA_RECURSIVE = False
    elif isinstance(nameservers, list) and len(nameservers) == 0:
        _VALIDATION_NAMESERVERS = []
        _VALIDATION_VIA_RECURSIVE = True
    else:
        # Store a shallow copy so callers cannot mutate our internal list.
        _VALIDATION_NAMESERVERS = list(nameservers)
        _VALIDATION_VIA_RECURSIVE = False


# RFC 5011-style trust anchor configuration (wired in by the application
# config loader). Defaults keep existing static behavior.
_TRUST_ANCHOR_MODE: str = "static"  # "static" or "rfc5011"
_TRUST_ANCHOR_STORE_PATH: str | None = None
_TRUST_ANCHOR_HOLD_ADD_DAYS: int = 2
_TRUST_ANCHOR_HOLD_REMOVE_DAYS: int = 2
# zone_text (absolute, trailing-dot) -> DNSKEY rdatas from operator config
_CUSTOM_DNSKEY_ANCHORS: dict[str, list] = {}
# zone_text -> DS rdatas from operator config (islands of trust)
_CUSTOM_DS_ANCHORS: dict[str, list] = {}
_TRUST_ANCHOR_STORE_LOCK = threading.Lock()


def _normalize_zone_text(zone: str | None) -> str:
    """Brief: Normalize a zone name to absolute text with trailing dot.

    Inputs:
      - zone: Zone name string (e.g. '.', 'example.com').

    Outputs:
      - Absolute zone text ending with '.'; root is '.'.
    """

    text = str(zone or ".").strip() or "."
    try:
        return dns.name.from_text(text).to_text()
    except Exception:
        if not text.endswith("."):
            text = text + "."
        return text


def _clear_trust_anchor_caches() -> None:
    """Brief: Drop cached root anchors and chain results after TA changes.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    for fn in (_root_dnskey_rrset, _validate_chain_cached, _find_zone_apex_cached):
        clear_fn = getattr(fn, "cache_clear", None) or getattr(
            getattr(fn, "cache", None), "clear", None
        )
        if callable(clear_fn):
            try:
                clear_fn()
            except Exception:
                pass


def _parse_custom_trust_anchor_entries(
    entries: list | None,
) -> tuple[dict[str, list], dict[str, list]]:
    """Brief: Parse operator trust_anchors list into DNSKEY/DS maps.

    Inputs:
      - entries: Optional list of mapping objects from config.

    Outputs:
      - (dnskey_by_zone, ds_by_zone) maps of zone_text -> list[rdata].

    Entry shapes:
      - DNSKEY: {zone, algorithm, public_key[, flags, protocol]}
      - DS: {zone, key_tag, algorithm, digest_type, digest}
      - type: optional "dnskey"|"ds" discriminator when both forms possible
    """

    dnskey_by_zone: dict[str, list] = {}
    ds_by_zone: dict[str, list] = {}
    if not isinstance(entries, list):
        return dnskey_by_zone, ds_by_zone

    import dns.rdata
    import dns.rdataclass

    for raw in entries:
        if not isinstance(raw, dict):
            continue
        zone = _normalize_zone_text(raw.get("zone") or raw.get("name") or ".")
        kind = str(raw.get("type") or raw.get("kind") or "").strip().lower()
        digest = raw.get("digest")
        public_key = raw.get("public_key") or raw.get("public_key_b64")
        if not kind:
            if digest is not None:
                kind = "ds"
            elif public_key is not None:
                kind = "dnskey"
            else:
                continue
        try:
            if kind == "ds":
                key_tag = int(raw.get("key_tag"))
                algorithm = int(raw.get("algorithm"))
                digest_type = int(raw.get("digest_type") or raw.get("digest_alg") or 2)
                digest_text = str(digest or "").strip()
                if not digest_text:
                    continue
                rdata = dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.DS,
                    f"{key_tag} {algorithm} {digest_type} {digest_text}",
                )
                ds_by_zone.setdefault(zone, []).append(rdata)
            elif kind in {"dnskey", "key"}:
                algorithm = int(raw.get("algorithm"))
                pub = str(public_key or "").strip()
                if not pub:
                    continue
                flags = int(raw.get("flags", 257) or 257)
                protocol = int(raw.get("protocol", 3) or 3)
                rdata = dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.DNSKEY,
                    f"{flags} {protocol} {algorithm} {pub}",
                )
                dnskey_by_zone.setdefault(zone, []).append(rdata)
        except Exception as exc:
            logger.warning("Ignoring invalid trust_anchors entry %r: %s", raw, exc)
            continue
    return dnskey_by_zone, ds_by_zone


def configure_trust_anchors(
    mode: str = "static",
    store_path: str | None = None,
    hold_down_add_days: int = 2,
    hold_down_remove_days: int = 2,
    custom_anchors: list | None = None,
) -> None:
    """Configure DNSSEC trust-anchor management mode.

    Inputs:
      - mode: 'static' to use baked-in/custom root keys, or 'rfc5011' to enable
        RFC 5011-style automated trust anchor management (requires store_path).
      - store_path: Optional filesystem path to the JSON trust anchor store.
      - hold_down_add_days: Days a new key must remain present before promotion.
      - hold_down_remove_days: Days a missing key must remain absent before drop.
      - custom_anchors: Optional operator trust_anchors list (DNSKEY and/or DS).

    Outputs:
      - None; updates module-level configuration used by validation helpers.
    """
    global _TRUST_ANCHOR_MODE, _TRUST_ANCHOR_STORE_PATH
    global _TRUST_ANCHOR_HOLD_ADD_DAYS, _TRUST_ANCHOR_HOLD_REMOVE_DAYS
    global _CUSTOM_DNSKEY_ANCHORS, _CUSTOM_DS_ANCHORS

    mode_norm = (mode or "static").lower()
    if mode_norm not in {"static", "rfc5011"}:
        mode_norm = "static"
    _TRUST_ANCHOR_MODE = mode_norm
    _TRUST_ANCHOR_STORE_PATH = store_path if store_path else None
    _TRUST_ANCHOR_HOLD_ADD_DAYS = max(0, int(hold_down_add_days or 0))
    _TRUST_ANCHOR_HOLD_REMOVE_DAYS = max(0, int(hold_down_remove_days or 0))
    dnskeys, ds_map = _parse_custom_trust_anchor_entries(custom_anchors)
    _CUSTOM_DNSKEY_ANCHORS = dnskeys
    _CUSTOM_DS_ANCHORS = ds_map
    if _TRUST_ANCHOR_MODE == "rfc5011" and not _TRUST_ANCHOR_STORE_PATH:
        logger.warning(
            "dnssec.trust_anchor_mode=rfc5011 without trust_anchor_store_path; "
            "falling back to static anchors (no automated key management)"
        )
    _clear_trust_anchor_caches()


def configure_trust_anchors_from_dnssec_cfg(
    dnssec_cfg: dict[str, Any] | None,
    *,
    enforce_data_root: bool = True,
) -> None:
    """Brief: Apply server.dnssec trust-anchor knobs from a config mapping.

    Inputs:
      - dnssec_cfg: server.dnssec mapping (or None).
      - enforce_data_root: When True, resolve store_path under server.data_root.

    Outputs:
      - None. Raises ValueError when store_path escapes data_root.

    Example:
      >>> configure_trust_anchors_from_dnssec_cfg({
      ...     "trust_anchor_mode": "rfc5011",
      ...     "trust_anchor_store_path": "/var/lib/foghorn/ta.json",
      ... })
    """

    cfg = dnssec_cfg if isinstance(dnssec_cfg, dict) else {}
    ta_mode = str(
        cfg.get("trust_anchor_mode") or cfg.get("trust_anchors_mode") or "static"
    ).lower()
    raw_store = (
        cfg.get("trust_anchor_store_path")
        or cfg.get("store_path")
        or cfg.get("trust_anchors_path")
    )
    store_path = None
    if raw_store is not None and str(raw_store).strip():
        if enforce_data_root:
            from foghorn.utils.safe_paths import enforce_data_root_path

            store_path = enforce_data_root_path(
                raw_store, kind="DNSSEC trust_anchor_store_path"
            )
        else:
            store_path = str(raw_store).strip()
    try:
        hold_add = int(cfg.get("hold_down_add_days", 2) or 2)
    except Exception:
        hold_add = 2
    try:
        hold_remove = int(cfg.get("hold_down_remove_days", 2) or 2)
    except Exception:
        hold_remove = 2
    custom = cfg.get("trust_anchors")
    if custom is None:
        custom = cfg.get("anchors")
    configure_trust_anchors(
        mode=ta_mode,
        store_path=store_path,
        hold_down_add_days=hold_add,
        hold_down_remove_days=hold_remove,
        custom_anchors=custom if isinstance(custom, list) else None,
    )


def apply_dnssec_validation_runtime(
    *,
    dnssec_cfg: dict[str, Any] | None,
    dnssec_mode: str,
    dnssec_validation: str,
    resolver_mode: str,
    upstream_hosts: list[str] | None = None,
    enforce_data_root: bool = True,
) -> None:
    """Brief: Apply trust-anchor + validation-resolver settings together.

    Inputs:
      - dnssec_cfg: server.dnssec mapping.
      - dnssec_mode / dnssec_validation / resolver_mode: Effective runtime knobs.
      - upstream_hosts: Forward-mode upstream IP/host strings for local validation.
      - enforce_data_root: Path containment for the trust-anchor store.

    Outputs:
      - None. Raises ValueError on bad store paths.
    """

    configure_trust_anchors_from_dnssec_cfg(
        dnssec_cfg, enforce_data_root=enforce_data_root
    )
    mode = str(dnssec_mode or "ignore").lower()
    validation = str(dnssec_validation or "upstream_ad").lower()
    if mode == "validate" and validation in {"local", "local_extended"}:
        if str(resolver_mode or "").lower() == "forward":
            hosts = [str(h) for h in (upstream_hosts or []) if str(h).strip()]
            configure_dnssec_resolver(hosts or None)
        else:
            # Empty list => RecursiveResolver-backed validation lookups.
            configure_dnssec_resolver([])
    else:
        configure_dnssec_resolver(None)


# Root trust anchor (KSK-2017) as DNSKEY public key (RFC 7958) in presentation form.
# Source: https://data.iana.org/root-anchors/root-anchors.xml (KeyDigest id=Klajeyz)
# key id 20326, algorithm 8 (RSASHA256), DS SHA-256:
#   E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
ROOT_DNSKEY_STR = (
    ". 0 IN DNSKEY 257 3 8 "
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq"
    "7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI"
    "DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb"
    "9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId"
    "sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qih"
    "ylGa8subX2Nn6UwNR1AkUTV74bU="
)


class _RecursiveAnswer:
    """Minimal Answer-like object for RecursiveResolver-backed lookups.

    Inputs:
      - rrset: The RRset corresponding to the queried name/type (or None).
      - response: Full dns.message.Message parsed from wire.

    Outputs:
      - Instances exposing .rrset and .response attributes compatible with the
        subset of dnspython's Answer API used by this module.
    """

    def __init__(self, rrset, response):
        self.rrset = rrset
        self.response = response


class _RecursiveValidationResolver:
    """Resolver shim that routes DNSSEC helper queries via RecursiveResolver.

     This class implements the small subset of the dnspython Resolver API that
    foghorn.dnssec.dnssec_validate relies on: a ``resolve(name, rdtype, raise_on_no_answer)``
     method returning an object with ``rrset`` and ``response`` attributes.

     It sends its queries using Foghorn's RecursiveResolver and never consults
     the system resolver configuration or external stub resolvers.
    """

    def __init__(self, payload_size: int = 1232) -> None:
        self._payload_size = int(payload_size or 1232)

    def resolve(self, name, rdtype, raise_on_no_answer: bool = True):
        """Resolve a single qname/rdtype using RecursiveResolver."""

        # Local imports to avoid introducing hard module-level dependencies or
        # import cycles when DNSSEC is disabled.
        from dnslib import EDNS0, DNSRecord

        from foghorn.servers.recursive_resolver import RecursiveResolver

        # Normalise name and rdtype to text for dnslib.
        qname_text = getattr(name, "to_text", lambda: str(name))()
        if isinstance(rdtype, str):
            rdtype_text = rdtype
        else:
            rdtype_text = dns.rdatatype.to_text(rdtype)

        # Build a DNS query with EDNS(0) + DO bit set so that upstream
        # authorities can return DNSSEC material when available.
        q = DNSRecord.question(qname_text, rdtype_text)
        try:
            q.add_ar(EDNS0(payload=self._payload_size, flags=dns.flags.DO))
        except Exception:  # pragma: no cover - defensive: EDNS helper failure
            pass

        resolver = RecursiveResolver(
            cache=None,
            stats=None,
            max_depth=16,
            timeout_ms=2000,
            per_try_timeout_ms=2000,
        )
        wire, _ = resolver.resolve(q)
        resp = dns.message.from_wire(wire)

        # Locate the RRset for the requested owner/type in the answer section.
        wanted_type = dns.rdatatype.from_text(rdtype_text)
        owner = dns.name.from_text(qname_text)
        rrset = None
        for rr in resp.answer:
            if rr.name == owner and rr.rdtype == wanted_type:
                rrset = rr
                break

        if rrset is None and raise_on_no_answer:
            raise dns.resolver.NoAnswer(f"No RRset for {owner} {rdtype_text}")

        return _RecursiveAnswer(rrset, resp)


def _resolver(payload_size: int = 1232):
    """Return a resolver object configured for DNSSEC validation.

    The resolver always enables EDNS(0) with the DO bit set when using the
    system or explicit nameserver configuration. When validation is configured
    to run via Foghorn's RecursiveResolver, a small shim object is returned
    instead that issues its queries through that engine.
    """

    # When validation is configured to run via Foghorn's RecursiveResolver,
    # return a small shim that issues its queries through that engine instead of
    # using any system or stub resolvers.
    if _VALIDATION_VIA_RECURSIVE:
        return _RecursiveValidationResolver(payload_size=payload_size)

    # When explicit nameservers are configured for validation, construct a
    # resolver without loading system configuration and point it at those
    # addresses. Otherwise, fall back to dnspython's default behavior.
    if _VALIDATION_NAMESERVERS:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = list(_VALIDATION_NAMESERVERS)
    else:
        # Prefer dnspython's default behavior (read system resolver config). Some
        # host environments ship malformed resolv.conf search/domain directives
        # (e.g. leading dots) which can make dnspython raise during parsing.
        # In that case, fall back to a minimal nameserver-only parse.
        try:
            r = dns.resolver.Resolver(configure=True)
        except Exception as exc:  # pragma: no cover - environment specific
            logger.warning(
                "DNSSEC resolver could not parse system resolv.conf; falling back to nameserver-only config: %s",
                exc,
            )
            r = dns.resolver.Resolver(configure=False)
            ns = _parse_resolv_conf_nameservers()
            if ns:
                r.nameservers = ns

    r.use_edns(edns=0, ednsflags=dns.flags.DO, payload=payload_size)
    r.lifetime = 2.0
    return r


def _fetch(r: dns.resolver.Resolver, name: dns.name.Name, rdtype: str):
    return r.resolve(name, rdtype, raise_on_no_answer=True)


@registered_ttl_cache(maxsize=17, ttl=86400)
def _baked_in_root_dnskey_rrset() -> dns.rrset.RRset:
    """Brief: Parse the constant IANA root KSK into a DNSKEY RRset.

    Inputs:
      - None.

    Outputs:
      - dns.rrset.RRset for '.' containing ROOT_DNSKEY_STR.
    """

    name = dns.name.from_text(".")
    txt = ROOT_DNSKEY_STR.replace("\n", " ")
    rrset = dns.rrset.from_text_list(
        name,
        0,
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        [txt.split(" DNSKEY ")[1]],
    )
    rrset.name = name
    return rrset


def _merge_dnskey_rrset(
    base: dns.rrset.RRset | None, extra: list | None
) -> dns.rrset.RRset | None:
    """Brief: Merge extra DNSKEY rdatas into a copy of base.

    Inputs:
      - base: Existing DNSKEY RRset (or None).
      - extra: Iterable of DNSKEY rdatas to add.

    Outputs:
      - Combined RRset, or None when empty.
    """

    if not extra and base is None:
        return None
    name = dns.name.from_text(".") if base is None else base.name
    out = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    seen: set[tuple[object, ...]] = set()
    for src in (list(base or []), list(extra or [])):
        for rd in src:
            ident = _dnskey_material_key(rd)
            if ident is not None and ident in seen:
                continue
            if ident is not None:
                seen.add(ident)
            try:
                out.add(rd)
            except Exception:
                continue
    return out if len(out) else None


def _dnskey_rrset_for_zone(zone: str) -> dns.rrset.RRset | None:
    """Brief: Build a DNSKEY trust-anchor RRset for a zone.

    Inputs:
      - zone: Zone name text (normalized or not).

    Outputs:
      - DNSKEY RRset of trusted anchors for the zone, or None.
    """

    zone_text = _normalize_zone_text(zone)
    custom = list(_CUSTOM_DNSKEY_ANCHORS.get(zone_text) or [])
    if zone_text != ".":
        if not custom:
            return None
        name = dns.name.from_text(zone_text)
        rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        for rd in custom:
            try:
                rrset.add(rd)
            except Exception:
                continue
        return rrset if len(rrset) else None

    # Root: store / baked-in plus any custom root DNSKEY anchors.
    from . import trust_anchors as _ta  # local import to avoid cycles

    base: dns.rrset.RRset | None = None
    use_store = _TRUST_ANCHOR_MODE == "rfc5011" and bool(_TRUST_ANCHOR_STORE_PATH)
    if use_store:
        store = _ta.load_store(_TRUST_ANCHOR_STORE_PATH or "")
        anchors = _ta.anchors_for_zone(store, ".")
        if not anchors:
            base = _baked_in_root_dnskey_rrset()
            store = _ta.bootstrap_from_rrset(store, ".", base)
            with _TRUST_ANCHOR_STORE_LOCK:
                _ta.save_store(_TRUST_ANCHOR_STORE_PATH or "", store)
        else:
            name = dns.name.from_text(".")
            base = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
            for rdata in anchors:
                try:
                    base.add(rdata)
                except Exception:
                    continue
    else:
        base = _baked_in_root_dnskey_rrset()
    return _merge_dnskey_rrset(base, custom)


@registered_ttl_cache(maxsize=16, ttl=300)
def _root_dnskey_rrset() -> dns.rrset.RRset | None:
    """Return the current root trust anchor DNSKEY RRset.

    Static mode uses the baked-in KSK plus any custom root DNSKEY anchors.
    RFC 5011 mode loads trusted keys from the on-disk store (bootstrapping from
    the baked-in key when empty), then merges custom root anchors.
    """
    try:
        return _dnskey_rrset_for_zone(".")
    except Exception as e:  # pragma: no cover - defensive around store handling
        logger.warning("Failed to construct root trust anchor: %s", e)
        return None


def _maybe_rfc5011_update_from_live_dnskey(
    zone: str, live_dnskey: dns.rrset.RRset
) -> None:
    """Brief: Feed an authenticated live DNSKEY set into the RFC 5011 store.

    Inputs:
      - zone: Zone name text (typically '.').
      - live_dnskey: DNSKEY RRset already authenticated by current anchors.

    Outputs:
      - None. Persists store and clears TA caches when the store changes.

    Notes:
      - No-op unless trust_anchor_mode=rfc5011 and store_path is configured.
      - Only call after RRSIG(DNSKEY) validation against current trust anchors.
    """

    if _TRUST_ANCHOR_MODE != "rfc5011" or not _TRUST_ANCHOR_STORE_PATH:
        return
    from . import trust_anchors as _ta

    zone_text = _normalize_zone_text(zone)
    changed = False
    try:
        with _TRUST_ANCHOR_STORE_LOCK:
            store = _ta.load_store(_TRUST_ANCHOR_STORE_PATH)
            changed = bool(
                _ta.update_from_dnskey_rrset(
                    store,
                    zone_text,
                    live_dnskey,
                    hold_down_add_days=_TRUST_ANCHOR_HOLD_ADD_DAYS,
                    hold_down_remove_days=_TRUST_ANCHOR_HOLD_REMOVE_DAYS,
                )
            )
            if changed:
                _ta.save_store(_TRUST_ANCHOR_STORE_PATH, store)
                logger.info(
                    "RFC 5011 trust-anchor store updated for zone %s at %s",
                    zone_text,
                    _TRUST_ANCHOR_STORE_PATH,
                )
        if changed:
            _clear_trust_anchor_caches()
    except Exception as exc:
        logger.warning("RFC 5011 trust-anchor update failed for %s: %s", zone_text, exc)


def _closest_custom_dnskey_anchor_zone(apex: dns.name.Name) -> dns.name.Name | None:
    """Brief: Deepest ancestor of apex (incl. apex) with custom DNSKEY anchors.

    Inputs:
      - apex: Zone apex being validated.

    Outputs:
      - dns.name.Name of the closest custom-TA zone, or None (use root path).
    """

    cur = apex
    while True:
        text = cur.to_text()
        if _CUSTOM_DNSKEY_ANCHORS.get(text):
            return cur
        if cur == dns.name.root:
            return None
        cur = cur.parent()


def _ds_matches_dnskey(
    child: dns.name.Name, ds_rrset: dns.rrset.RRset, child_dnskey: dns.rrset.RRset
) -> bool:
    """Brief: True when any DS in ds_rrset matches a child DNSKEY.

    Inputs:
      - child: Child zone name.
      - ds_rrset: DS RRset (parent or custom).
      - child_dnskey: Child DNSKEY RRset.

    Outputs:
      - bool.
    """

    for dnskey in child_dnskey:
        try:
            for algorithm in (dns.dnssec.DSDigest.SHA256, dns.dnssec.DSDigest.SHA1):
                computed = dns.dnssec.make_ds(child, dnskey, algorithm)
                if any(
                    x.digest == computed.digest and x.key_tag == computed.key_tag
                    for x in ds_rrset
                ):
                    return True
        except Exception:
            continue
    return False


def _find_zone_apex(
    r: dns.resolver.Resolver, qname: dns.name.Name
) -> dns.name.Name | None:
    """Return the closest zone apex that publishes a DNSKEY for qname.

    Inputs:
      - r: Resolver configured with DO and appropriate EDNS payload size.
      - qname: dns.name.Name to locate the apex for.

    Outputs:
      - dns.name.Name representing the apex (may be "."), or None on error.
    """
    n = qname
    while True:
        try:
            _ = _fetch(r, n, "DNSKEY")
            return n
        except Exception:
            if n == dns.name.root:
                return dns.name.root
            n = n.parent()


# DNSKEY/DS caches keyed by owner name with per-entry TTLs derived from RRset
# TTLs, clamped to a maximum lifetime.
_MAX_KEY_CACHE_TTL_SECONDS = 4 * 3600  # 4 hours
_MAX_KEY_CACHE_ENTRIES = 4096
_DNSKEY_CACHE: dict[str, tuple[dns.rrset.RRset, float]] = {}
_DS_CACHE: dict[str, tuple[dns.rrset.RRset, float]] = {}


def _evict_expired_cache_entries(
    cache: dict[str, tuple[dns.rrset.RRset, float]], now: float
) -> None:
    """Evict cache entries whose expiration timestamp has passed.

    Inputs:
      - cache: Mapping of owner-name key to (rrset, expires_at_epoch_seconds).
      - now: Current epoch time to compare against entry expiry.

    Outputs:
      - None
    """
    expired_keys = [
        key for key, (_rrset, expires_at) in cache.items() if now >= expires_at
    ]
    for key in expired_keys:
        cache.pop(key, None)


def _enforce_cache_entry_limit(
    cache: dict[str, tuple[dns.rrset.RRset, float]], max_entries: int
) -> None:
    """Ensure a cache dictionary does not exceed a configured maximum size.

    Inputs:
      - cache: Mapping of owner-name key to (rrset, expires_at_epoch_seconds).
      - max_entries: Maximum number of entries to retain in the cache.

    Outputs:
      - None
    """
    overage = len(cache) - max_entries
    if overage <= 0:
        return
    keys_by_expiry = sorted(cache.keys(), key=lambda cache_key: cache[cache_key][1])
    for key in keys_by_expiry[:overage]:
        cache.pop(key, None)


def _fetch_dnskey_cached(
    r: dns.resolver.Resolver, name: dns.name.Name
) -> dns.rrset.RRset:
    """Fetch and cache the DNSKEY RRset for name.

    Cache lifetime is based on the RRset TTL, clamped to
    _MAX_KEY_CACHE_TTL_SECONDS.
    """
    key = name.to_text()
    now = time.time()
    _evict_expired_cache_entries(_DNSKEY_CACHE, now)
    cached_entry = _DNSKEY_CACHE.get(key)
    if cached_entry is not None:
        rrset, expires_at = cached_entry
        if now < expires_at:
            return rrset
        _DNSKEY_CACHE.pop(key, None)
        # Expired entry; fall through to refresh.
    rr = _fetch(r, name, "DNSKEY").rrset
    ttl = getattr(rr, "ttl", _MAX_KEY_CACHE_TTL_SECONDS)
    ttl = max(0, min(int(ttl), _MAX_KEY_CACHE_TTL_SECONDS))
    _DNSKEY_CACHE[key] = (rr, now + ttl)
    _enforce_cache_entry_limit(_DNSKEY_CACHE, _MAX_KEY_CACHE_ENTRIES)
    return rr


def _fetch_ds_cached(r: dns.resolver.Resolver, name: dns.name.Name) -> dns.rrset.RRset:
    """Fetch and cache the DS RRset for name.

    Cache lifetime is based on the RRset TTL, clamped to
    _MAX_KEY_CACHE_TTL_SECONDS.
    """
    key = name.to_text()
    now = time.time()
    _evict_expired_cache_entries(_DS_CACHE, now)
    cached_entry = _DS_CACHE.get(key)
    if cached_entry is not None:
        rrset, expires_at = cached_entry
        if now < expires_at:
            return rrset
        _DS_CACHE.pop(key, None)
    rr = _fetch(r, name, "DS").rrset
    ttl = getattr(rr, "ttl", _MAX_KEY_CACHE_TTL_SECONDS)
    ttl = max(0, min(int(ttl), _MAX_KEY_CACHE_TTL_SECONDS))
    _DS_CACHE[key] = (rr, now + ttl)
    _enforce_cache_entry_limit(_DS_CACHE, _MAX_KEY_CACHE_ENTRIES)
    return rr


def _dnskey_material_key(rdata: object) -> tuple[object, ...] | None:
    """Brief: Stable identity tuple for a DNSKEY rdata.

    Inputs:
      - rdata: dnspython DNSKEY rdata (or compatible object).

    Outputs:
      - (algorithm, flags, protocol, key_bytes) when extractable, else None.
    """
    try:
        key = getattr(rdata, "key", None)
        if key is None:
            return None
        if isinstance(key, (bytes, bytearray)):
            key_bytes = bytes(key)
        else:
            key_bytes = bytes(key)
        return (
            int(getattr(rdata, "algorithm", 0) or 0),
            int(getattr(rdata, "flags", 0) or 0),
            int(getattr(rdata, "protocol", 0) or 0),
            key_bytes,
        )
    except Exception:
        return None


def _rrset_contains_any_dnskey(
    haystack: dns.rrset.RRset | None, needles: dns.rrset.RRset | None
) -> bool:
    """Brief: True when any DNSKEY in needles appears in haystack.

    Inputs:
      - haystack: Live DNSKEY RRset (e.g. fetched root keys).
      - needles: Trust-anchor DNSKEY RRset.

    Outputs:
      - bool: True when at least one anchor key is present in haystack.
    """
    if haystack is None or needles is None:
        return False
    live: set[tuple[object, ...]] = set()
    for rd in haystack:
        ident = _dnskey_material_key(rd)
        if ident is not None:
            live.add(ident)
    if not live:
        return False
    for rd in needles:
        ident = _dnskey_material_key(rd)
        if ident is not None and ident in live:
            return True
    return False


def _fetch_rrset_and_rrsig(
    r: dns.resolver.Resolver,
    name: dns.name.Name,
    rdtype: str,
    covered_type: int,
) -> tuple[dns.rrset.RRset, dns.rrset.RRset | None]:
    """Brief: Fetch an RRset and its covering RRSIG from one DO query.

    Inputs:
      - r: Resolver configured with DO.
      - name: Owner name to query.
      - rdtype: Query type text (e.g. "DNSKEY", "DS").
      - covered_type: dns.rdatatype constant the RRSIG must cover.

    Outputs:
      - (rrset, rrsig_rrset_or_None).

    Raises:
      - Exception when the primary RRset is missing from the answer.
    """
    ans = r.resolve(name, rdtype, raise_on_no_answer=True)
    resp = ans.response
    primary: dns.rrset.RRset | None = None
    sig_rrset: dns.rrset.RRset | None = None
    wanted = int(covered_type)
    for rrset in resp.answer:
        if rrset.rdtype == wanted:
            primary = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            try:
                covered = rrset[0].type_covered
            except Exception:
                continue
            if covered == wanted:
                sig_rrset = rrset
    if primary is None:
        raise Exception(f"No {rdtype} RRset found in answer for {name}")
    return primary, sig_rrset


def _fetch_dnskey_and_rrsig(
    r: dns.resolver.Resolver, name: dns.name.Name
) -> tuple[dns.rrset.RRset, dns.rrset.RRset | None]:
    """Fetch DNSKEY RRset and its covering RRSIG(DNSKEY) for the given owner.

    Inputs:
      - r: Resolver configured with DO.
      - name: Owner name to query.

    Outputs:
      - (dnskey_rrset, rrsig_rrset_or_None).
    """
    return _fetch_rrset_and_rrsig(r, name, "DNSKEY", dns.rdatatype.DNSKEY)


def _fetch_ds_and_rrsig(
    r: dns.resolver.Resolver, name: dns.name.Name
) -> tuple[dns.rrset.RRset, dns.rrset.RRset | None]:
    """Fetch DS RRset and its covering RRSIG(DS) for the given owner.

    Inputs:
      - r: Resolver configured with DO.
      - name: Child owner name whose DS is published at the parent.

    Outputs:
      - (ds_rrset, rrsig_rrset_or_None).
    """
    return _fetch_rrset_and_rrsig(r, name, "DS", dns.rdatatype.DS)


def _validate_chain(
    r: dns.resolver.Resolver, apex: dns.name.Name
) -> (
    dns.rrset.RRset | None
):  # pragma: no cover - networked DNSSEC chain validation exercised via higher-level tests
    """
    Validates the DNSKEY rrset at apex back to a trust anchor.

    Inputs:
      - r: Resolver (with DO)
      - apex: zone apex dns.name.Name
    Outputs:
      - dnskey_rrset if validated, else None

    Brief:
      Starts at root (or a closer custom DNSKEY trust anchor). Root: require
      live DNSKEY to contain the trust anchor, verify RRSIG(DNSKEY) against
      anchor keys only, then optionally feed the live set into RFC 5011.
      For each child: verify RRSIG(DS) with parent DNSKEY (or accept a custom
      DS trust anchor), DS matches child DNSKEY, and child DNSKEY self-sig.
    """
    try:
        # Prefer the deepest operator DNSKEY trust anchor on the apex path
        # (island of trust); otherwise start from the root anchors.
        custom_start = _closest_custom_dnskey_anchor_zone(apex)
        if custom_start is not None and custom_start != dns.name.root:
            parent = custom_start
            anchor_keys = _dnskey_rrset_for_zone(parent.to_text())
            if anchor_keys is None:
                logger.debug(
                    "_validate_chain: missing custom DNSKEY anchors for %s", parent
                )
                return None
            try:
                parent_dnskey, parent_dnskey_sig = _fetch_dnskey_and_rrsig(r, parent)
            except Exception as e:
                logger.debug(
                    "_validate_chain: custom-TA DNSKEY/RRSIG fetch failed for %s: %s",
                    parent,
                    e,
                )
                return None
            if not _rrset_contains_any_dnskey(parent_dnskey, anchor_keys):
                logger.warning(
                    "_validate_chain: live DNSKEY at %s does not contain custom trust anchor",
                    parent,
                )
                return None
            if parent_dnskey_sig is None:
                logger.debug(
                    "_validate_chain: missing RRSIG(DNSKEY) at custom TA %s", parent
                )
                return None
            try:
                dns.dnssec.validate(
                    parent_dnskey, parent_dnskey_sig, {parent: anchor_keys}
                )
            except Exception as e:
                logger.warning(
                    "_validate_chain: custom-TA DNSKEY RRSIG validation failed for %s: %s",
                    parent,
                    e,
                )
                return None
        else:
            root_keys = _root_dnskey_rrset()
            if root_keys is None:
                logger.debug("_validate_chain: no root_keys available")
                return None
            parent = dns.name.root
            try:
                parent_dnskey, parent_dnskey_sig = _fetch_dnskey_and_rrsig(r, parent)
            except Exception as e:
                logger.debug("_validate_chain: root DNSKEY/RRSIG fetch failed: %s", e)
                return None
            logger.debug(
                "_validate_chain: starting at parent=%s with %d DNSKEY records",
                parent,
                len(parent_dnskey or []),
            )
            # Fail closed: live root DNSKEY must contain our trust anchor material.
            if not _rrset_contains_any_dnskey(parent_dnskey, root_keys):
                logger.warning(
                    "_validate_chain: live root DNSKEY does not contain trust anchor"
                )
                return None
            if parent_dnskey_sig is None:
                logger.debug("_validate_chain: missing RRSIG(DNSKEY) at root")
                return None
            try:
                # Validate using anchor keys only so a forged self-consistent root
                # set (attacker ZSK + included public KSK) cannot pass.
                dns.dnssec.validate(
                    parent_dnskey, parent_dnskey_sig, {dns.name.root: root_keys}
                )
            except Exception as e:
                logger.warning(
                    "_validate_chain: root DNSKEY RRSIG validation failed: %s", e
                )
                return None
            # Authenticated live root set may drive RFC 5011 store updates.
            _maybe_rfc5011_update_from_live_dnskey(".", parent_dnskey)

        # Seed DNSKEY cache with the authenticated trust-start set.
        try:
            now = time.time()
            ttl = getattr(parent_dnskey, "ttl", _MAX_KEY_CACHE_TTL_SECONDS)
            ttl = max(0, min(int(ttl), _MAX_KEY_CACHE_TTL_SECONDS))
            _DNSKEY_CACHE[parent.to_text()] = (parent_dnskey, now + ttl)
            _enforce_cache_entry_limit(_DNSKEY_CACHE, _MAX_KEY_CACHE_ENTRIES)
        except Exception:
            pass

        # Walk down from parent to apex (skip labels at/above the trust start).
        labels = []
        cur = apex
        while cur != parent and cur != dns.name.root:
            labels.append(cur)
            cur = cur.parent()
        if cur != parent and parent != dns.name.root:
            # apex is not under the chosen custom TA
            logger.debug(
                "_validate_chain: apex %s is not under trust start %s", apex, parent
            )
            return None
        for child in reversed(labels):
            logger.debug(
                "_validate_chain: descending to child=%s from parent=%s", child, parent
            )
            child_text = child.to_text()
            custom_ds_list = list(_CUSTOM_DS_ANCHORS.get(child_text) or [])
            ds = None
            used_custom_ds = False
            if custom_ds_list:
                ds = dns.rrset.RRset(child, dns.rdataclass.IN, dns.rdatatype.DS)
                for rd in custom_ds_list:
                    try:
                        ds.add(rd)
                    except Exception:
                        continue
                used_custom_ds = len(ds) > 0
            if not used_custom_ds:
                # DS at the child owner must be signed by the already-authenticated
                # parent DNSKEY set (RRSIG(DS) required).
                try:
                    ds, ds_sig = _fetch_ds_and_rrsig(r, child)
                except Exception as e:
                    # No DS for this child — treat the delegation as insecure and
                    # stop strict validation.
                    logger.debug(
                        "_validate_chain: DS fetch failed for %s: %s", child, e
                    )
                    return None
                if ds_sig is None:
                    logger.debug("_validate_chain: missing RRSIG(DS) for %s", child)
                    return None
                try:
                    dns.dnssec.validate(ds, ds_sig, {parent: parent_dnskey})
                except Exception as e:
                    logger.warning(
                        "_validate_chain: RRSIG(DS) validation failed for %s: %s",
                        child,
                        e,
                    )
                    return None
            # Cache authenticated DS.
            try:
                now = time.time()
                ttl = getattr(ds, "ttl", _MAX_KEY_CACHE_TTL_SECONDS)
                ttl = max(0, min(int(ttl), _MAX_KEY_CACHE_TTL_SECONDS))
                _DS_CACHE[child_text] = (ds, now + ttl)
                _enforce_cache_entry_limit(_DS_CACHE, _MAX_KEY_CACHE_ENTRIES)
            except Exception:
                pass

            # Fetch child DNSKEY and its RRSIG(DNSKEY) in one query so we do not
            # depend on separate RRSIG lookups that many resolvers do not
            # support as standalone qtypes.
            try:
                child_dnskey, child_dnskey_sig = _fetch_dnskey_and_rrsig(r, child)
            except Exception as e:
                logger.debug(
                    "_validate_chain: DNSKEY/RRSIG fetch failed for %s: %s", child, e
                )
                return None
            if not _ds_matches_dnskey(child, ds, child_dnskey):
                logger.debug("_validate_chain: no DS/DNSKEY match for %s", child)
                return None
            # Validate child DNSKEY RRset self-signature (requires RRSIG).
            if child_dnskey_sig is None:
                logger.debug("_validate_chain: missing RRSIG(DNSKEY) for %s", child)
                return None
            try:
                dns.dnssec.validate(
                    child_dnskey, child_dnskey_sig, {child: child_dnskey}
                )
            except Exception as e:
                # If missing/invalid, fail
                logger.warning(
                    "_validate_chain: DNSKEY self-signature validation failed for %s: %s",
                    child,
                    e,
                )
                return None
            # Advance parent
            parent = child
            parent_dnskey = child_dnskey
        logger.debug("_validate_chain: successfully validated chain to apex %s", apex)
        return parent_dnskey
    except Exception as e:
        logger.debug("_validate_chain: unexpected error for apex %s: %s", apex, e)
        return None


@registered_ttl_cache(maxsize=1024, ttl=120)
def _find_zone_apex_cached(
    qname_text: str, udp_payload_size: int
) -> dns.name.Name | None:
    """Resolve and cache the DNSSEC apex for a given qname/UDP payload size.

    Inputs:
      - qname_text: Query name as text.
      - udp_payload_size: EDNS payload size used when probing for DNSKEY.

    Outputs:
      - dns.name.Name apex when a DNSKEY RRset is found, or None on error.
    """
    try:
        r = _resolver(payload_size=udp_payload_size)
        qname = dns.name.from_text(qname_text)
        return _find_zone_apex(r, qname)
    except Exception:
        return None


@registered_ttl_cache(maxsize=4096, ttl=900)
def _validate_chain_cached(
    apex_text: str, udp_payload_size: int
) -> dns.rrset.RRset | None:
    """Validate and cache the DNSKEY rrset at apex back to the root anchor.

    Inputs:
      - apex_text: Apex name in text form (e.g. "example.com.").
      - udp_payload_size: EDNS payload size for validation fetches.

    Outputs:
      - dns.rrset.RRset when the chain validates, or None on error.
    """
    try:
        r = _resolver(payload_size=udp_payload_size)
        apex = dns.name.from_text(apex_text)
        return _validate_chain(r, apex)
    except Exception:
        return None


def validate_response_local(
    qname_text: str,
    qtype_num: int,
    response_wire: bytes,
    *,
    udp_payload_size: int = 1232,
) -> bool:
    """
    Perform local DNSSEC validation of an upstream response.

    Inputs:
      - qname_text: Query name as text
      - qtype_num: Numeric qtype (e.g., 1=A, 28=AAAA)
      - response_wire: Raw wire-format DNS response
      - udp_payload_size: EDNS payload size for any validation fetches
    Outputs:
      - bool: True if validated, False otherwise

    Example:
      >>> ok = validate_response_local('example.com', 1, wire)
    """
    try:
        msg = dns.message.from_wire(response_wire)
        qname = dns.name.from_text(qname_text)
        rdtype = (
            dns.rdatatype.from_text(str(qtype_num))
            if isinstance(qtype_num, str)
            else qtype_num
        )

        # Attempt to locate a positive answer RRset, following a simple CNAME
        # chain when present. This returns the final owner name plus the list
        # of RRsets (and their signatures) that must validate.
        chain = _collect_positive_rrsets(msg, qname, rdtype)

        if chain is not None:
            final_owner, rrsets, sig_rrsets = chain

            # Resolve the DNSSEC apex using the final owner name so that
            # cross-name CNAME targets under the same zone are validated using
            # the correct DNSKEY rrset.
            apex = _find_zone_apex_cached(final_owner.to_text(), udp_payload_size)
            if apex is None:
                return False

            # Validate the key chain for the apex via a cached helper; this
            # avoids repeated DNSKEY/DS fetches and signature checks for
            # popular zones.
            zone_dnskey = _validate_chain_cached(apex.to_text(), udp_payload_size)
            if zone_dnskey is None:
                return False

            try:
                for rrset, sig_rrset in zip(rrsets, sig_rrsets):
                    dns.dnssec.validate(rrset, sig_rrset, {apex: zone_dnskey})
                # With the answer chain validated, also sanity-check any
                # DNSKEY/DS/NS/SOA RRsets in the authority section that are
                # covered by this zone and carry signatures.
                if not _validate_authority_rrsets(
                    msg, qname, rdtype, apex, zone_dnskey
                ):
                    return False
                return True
            except Exception:
                return False

        # No positive RRset (or chain) to validate; attempt negative answer
        # validation. This covers NXDOMAIN and NODATA proofs via NSEC only.
        apex = _find_zone_apex_cached(qname_text, udp_payload_size)
        if apex is None:
            return False
        zone_dnskey = _validate_chain_cached(apex.to_text(), udp_payload_size)
        if zone_dnskey is None:
            return False

        rcode = msg.rcode()
        if rcode not in (dns.rcode.NXDOMAIN, dns.rcode.NOERROR):
            # Not a standard negative response we know how to validate
            return False

        if not _validate_negative_response(msg, qname, rdtype, apex, zone_dnskey):
            return False
        # For negative answers, also validate any signed authority RRsets for
        # this zone so that inconsistent NS/SOA/DS/DNSKEY data cannot slip
        # through even when the NSEC proof itself is valid.
        if not _validate_authority_rrsets(msg, qname, rdtype, apex, zone_dnskey):
            return False
        return True
    except Exception:
        return False


def _collect_positive_rrsets(
    msg: dns.message.Message,
    qname: dns.name.Name,
    rdtype: int,
) -> tuple[dns.name.Name, list[dns.rrset.RRset], list[dns.rrset.RRset]] | None:
    """Collect RRsets and signatures forming a positive answer chain.

    Inputs:
      - msg: Parsed dns.message.Message from the upstream.
      - qname: Original query name as dns.name.Name.
      - rdtype: Numeric RR type being queried.

    Outputs:
      - (final_owner, rrsets, sig_rrsets) when a positive answer is found,
        where final_owner is the owner name of the terminal RRset, rrsets is
        the ordered list of RRsets to validate (e.g. CNAME hop(s) followed by
        the final answer), and sig_rrsets is the corresponding list of
        RRSIG RRsets.
      - None when no suitable positive chain can be found.

    Notes:
      - Follows CNAME and DNAME chains. For DNAME, the function synthesizes a
        new owner name by replacing the DNAME owner suffix on the current
        qname with the DNAME target suffix.
    """
    try:
        # Index answer RRsets by (name, rdtype) for quick lookup and keep a
        # mapping of RRSIG RRsets by owner name.
        by_name_type: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        rrsig_by_name: dict[dns.name.Name, dns.rrset.RRset] = {}
        for rrset in msg.answer:
            key = (rrset.name, rrset.rdtype)
            by_name_type[key] = rrset
            if rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_by_name[rrset.name] = rrset

        current = qname
        rrsets: list[dns.rrset.RRset] = []
        sig_rrsets: list[dns.rrset.RRset] = []

        # Follow a small bounded chain to avoid pathological messages.
        for _ in range(8):
            direct = by_name_type.get((current, rdtype))
            if direct is not None:
                sig = rrsig_by_name.get(current)
                if sig is None:
                    return None
                rrsets.append(direct)
                sig_rrsets.append(sig)
                return current, rrsets, sig_rrsets

            # Try a direct CNAME at the current name.
            cname_rrset = by_name_type.get((current, dns.rdatatype.CNAME))
            if cname_rrset is not None:
                cname_sig = rrsig_by_name.get(current)
                if cname_sig is None:
                    return None
                rrsets.append(cname_rrset)
                sig_rrsets.append(cname_sig)
                try:
                    target = cname_rrset[0].target
                except Exception:
                    return None
                current = target
                continue

            # Try a DNAME at or above the current name. We search for the
            # closest ancestor that has a DNAME RRset and synthesize the new
            # owner name from the current qname.
            dname_owner = current
            dname_rrset = None
            while True:
                cand = by_name_type.get((dname_owner, dns.rdatatype.DNAME))
                if cand is not None:
                    dname_rrset = cand
                    break
                if dname_owner == dns.name.root:
                    break
                dname_owner = dname_owner.parent()

            if dname_rrset is None:
                # No CNAME or DNAME to follow; give up on a positive chain.
                return None

            dname_sig = rrsig_by_name.get(dname_owner)
            if dname_sig is None:
                return None

            rrsets.append(dname_rrset)
            sig_rrsets.append(dname_sig)

            try:
                # dnspython DNAME has .target for the new suffix.
                target_suffix = dname_rrset[0].target
            except Exception:
                return None

            # current = <prefix>.dname_owner; replace the owner suffix with
            # target_suffix.
            if not current.is_subdomain(dname_owner):
                return None  # pragma: no cover - defensive: dname_owner is derived from current and its parents
            prefix_labels = current.labels[: -len(dname_owner.labels)]
            new_labels = prefix_labels + target_suffix.labels
            current = dns.name.Name(new_labels)

        # Chain too long or cyclic.
        return None
    except Exception:
        return None


def _validate_negative_response(
    msg: dns.message.Message,
    qname: dns.name.Name,
    rdtype: int,
    apex: dns.name.Name,
    zone_dnskey: dns.rrset.RRset,
) -> bool:
    """Validate a DNSSEC negative response using NSEC/NSEC3.

    This implements a conservative subset of RFC 4035/5155 sufficient to
    distinguish securely proven negative answers from unsigned or ambiguous
    ones. Classic NSEC proofs are preferred when present; when only NSEC3
    records are available, a simplified NSEC3-based proof is attempted.

    Inputs:
      - msg: Parsed dns.message.Message from the upstream.
      - qname: Query name as a dns.name.Name.
      - rdtype: Numeric query type.
      - apex: Validated zone apex name.
      - zone_dnskey: Validated DNSKEY RRset for the apex.

    Outputs:
      - bool: True if the negative answer is cryptographically proven
        (secure), False otherwise. Unsupported or malformed proofs are
        treated as insecure rather than bogus here; callers may layer
        stricter policy if desired.
    """
    try:
        # Collect NSEC/NSEC3 and corresponding RRSIGs from the authority
        # section. We validate signatures using the already-validated
        # zone_dnskey set.
        nsec_rrsets = []
        nsec3_rrsets = []
        rrsig_by_name = {}

        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_by_name[rrset.name] = rrset
            elif rrset.rdtype == dns.rdatatype.NSEC:
                nsec_rrsets.append(rrset)
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                nsec3_rrsets.append(rrset)

        # First ensure all NSEC and NSEC3 RRsets are properly signed.
        for rrset in list(nsec_rrsets) + list(nsec3_rrsets):
            sig = rrsig_by_name.get(rrset.name)
            if sig is None:
                return False
            try:
                dns.dnssec.validate(rrset, sig, {apex: zone_dnskey})
            except Exception:
                return False

        rcode = msg.rcode()

        # Prefer classic NSEC proofs when present.
        if nsec_rrsets:
            if rcode == dns.rcode.NXDOMAIN:
                return _nsec_proves_nxdomain(qname, nsec_rrsets)
            if rcode == dns.rcode.NOERROR and not msg.answer:
                return _nsec_proves_nodata(qname, rdtype, nsec_rrsets)
            return False

        # Fall back to NSEC3-based proofs when no NSEC is available.
        if nsec3_rrsets:
            if rcode == dns.rcode.NXDOMAIN:
                return _nsec3_proves_nxdomain(qname, nsec3_rrsets)
            if rcode == dns.rcode.NOERROR and not msg.answer:
                return _nsec3_proves_nodata(qname, rdtype, nsec3_rrsets)
            return False

        # No usable proof available.
        return False
    except Exception:  # pragma: no cover - defensive: unexpected authority structure
        return False


def _nsec_proves_nxdomain(
    qname: dns.name.Name,
    nsec_rrsets: list[dns.rrset.RRset],
) -> bool:
    """Return True if the provided NSEC RRsets prove NXDOMAIN for qname.

    This is a conservative implementation: if we cannot clearly prove
    non-existence using standard NSEC ordering semantics, we return False.

    Inputs:
      - qname: Name being queried.
      - nsec_rrsets: List of NSEC RRsets from the authority section.

    Outputs:
      - bool: True when the NSEC chain convincingly proves the name does
        not exist, False otherwise.
    """
    try:
        # Build a map from owner name to its "next domain" target.
        nsec_map: dict[dns.name.Name, dns.name.Name] = {}
        for rrset in nsec_rrsets:
            if not rrset:
                continue
            rdata = rrset[0]
            if not hasattr(rdata, "next"):  # dnspython stores next name here
                continue
            nsec_map[rrset.name] = rdata.next

        if not nsec_map:
            return False

        # Find any NSEC whose interval covers qname: owner <= qname < next,
        # taking DNSSEC canonical ordering into account.
        for owner, nxt in nsec_map.items():
            if owner == qname:
                # Exact match would imply the name exists, so this NSEC alone
                # does not prove NXDOMAIN.
                continue
            # Treat qname subdomains of the owner as covered when the interval
            # spans past the owner label in canonical order.
            if owner < qname < nxt or (qname.is_subdomain(owner) and owner < nxt):
                return True
            # Handle the wrap-around case where the last NSEC covers up to
            # the apex of the space.
            if owner > nxt and (qname > owner or qname < nxt):
                return True
        return False
    except Exception:  # pragma: no cover - defensive: malformed NSEC RDATA
        return False


def _nsec_proves_nodata(
    qname: dns.name.Name,
    rdtype: int,
    nsec_rrsets: list[dns.rrset.RRset],
) -> bool:
    """Return True if NSEC RRsets prove that qname exists but rdtype does not.

    Inputs:
      - qname: Name being queried.
      - rdtype: Numeric RR type being queried.
      - nsec_rrsets: NSEC RRsets from the authority section.

    Outputs:
      - bool: True when there is an NSEC whose owner is qname and whose type
        bitmap does not include rdtype, False otherwise.
    """
    try:
        for rrset in nsec_rrsets:
            if rrset.name != qname or not rrset:
                continue
            rdata = rrset[0]
            try:
                # Prefer structured type sets when present (future dnspython).
                if hasattr(rdata, "types"):
                    raw_types = set(rdata.types)
                    types = {
                        (dns.rdatatype.to_text(t) if isinstance(t, int) else str(t))
                        for t in raw_types
                    }
                elif hasattr(rdata, "to_text"):
                    # NSEC presentation: "next.name. TYPE1 TYPE2 ..."
                    # Index 0 is the next name; types start at index 1.
                    parts = rdata.to_text().split()
                    types = set(parts[1:]) if len(parts) > 1 else set()
                else:
                    # Very conservative fallback: assume NODATA cannot be
                    # proven without a richer view of the bitmap.
                    return False
                if dns.rdatatype.to_text(rdtype) not in types:
                    return True
            except Exception:
                return False
        return False
    except Exception:  # pragma: no cover - defensive: malformed NSEC bitmap
        return False


def _nsec3_common_params(
    nsec3_rrsets: list[dns.rrset.RRset],
) -> tuple[dns.name.Name, int, int, bytes] | None:
    """Extract common NSEC3 parameters (origin, algorithm, iterations, salt)."""
    try:
        if not nsec3_rrsets:
            return None
        first = nsec3_rrsets[0]
        if not first:
            return None
        rdata = first[0]
        origin = first.name.parent()
        algorithm = getattr(rdata, "algorithm", None)
        iterations = getattr(rdata, "iterations", None)
        salt = getattr(rdata, "salt", None)
        if algorithm is None or iterations is None or salt is None:
            return None
        for rrset in nsec3_rrsets[1:]:
            if not rrset:
                return None
            r = rrset[0]
            if (
                getattr(r, "algorithm", None) != algorithm
                or getattr(r, "iterations", None) != iterations
                or getattr(r, "salt", None) != salt
            ):
                return None
        return origin, algorithm, iterations, salt
    except Exception:
        return None


def _nsec3_proves_nxdomain(
    qname: dns.name.Name,
    nsec3_rrsets: list[dns.rrset.RRset],
) -> bool:
    """Return True if the provided NSEC3 RRsets prove NXDOMAIN for qname."""
    try:
        params = _nsec3_common_params(nsec3_rrsets)
        if params is None:
            return False
        origin, algorithm, iterations, salt = params

        digest = dns.dnssec.nsec3_hash(qname, algorithm, iterations, salt)
        hash_label = base64.b32encode(digest).decode("ascii").strip("=").lower()
        hashed_qname = dns.name.from_text(f"{hash_label}.{origin}")

        nsec_map: dict[dns.name.Name, dns.name.Name] = {}
        for rrset in nsec3_rrsets:
            if not rrset:
                continue
            rdata = rrset[0]
            next_hash = getattr(rdata, "next", None)
            if next_hash is None:
                continue
            next_name = dns.name.Name(next_hash.labels + origin.labels)
            nsec_map[rrset.name] = next_name

        if not nsec_map:
            return False

        for owner, nxt in nsec_map.items():
            if owner == hashed_qname:
                continue
            if owner < hashed_qname < nxt:
                return True
            if owner > nxt and (hashed_qname > owner or hashed_qname < nxt):
                return True
        return False
    except Exception:
        return False


def _nsec3_proves_nodata(
    qname: dns.name.Name,
    rdtype: int,
    nsec3_rrsets: list[dns.rrset.RRset],
) -> bool:
    """Return True if NSEC3 RRsets prove that qname exists but rdtype does not."""
    try:
        params = _nsec3_common_params(nsec3_rrsets)
        if params is None:
            return False
        origin, algorithm, iterations, salt = params

        digest = dns.dnssec.nsec3_hash(qname, algorithm, iterations, salt)
        hash_label = base64.b32encode(digest).decode("ascii").strip("=").lower()
        hashed_qname = dns.name.from_text(f"{hash_label}.{origin}")

        for rrset in nsec3_rrsets:
            if rrset.name != hashed_qname or not rrset:
                continue
            rdata = rrset[0]
            try:
                if hasattr(rdata, "types"):
                    types = set(rdata.types)
                else:
                    parts = rdata.to_text().split()
                    types = set(parts[5:]) if len(parts) > 5 else set()
                if dns.rdatatype.to_text(rdtype) not in types:
                    return True
            except Exception:
                return False
        return False
    except Exception:
        return False


def _validate_authority_rrsets(
    msg: dns.message.Message,
    qname: dns.name.Name,
    rdtype: int,
    apex: dns.name.Name,
    zone_dnskey: dns.rrset.RRset,
) -> bool:
    """Validate signed authority RRsets that can affect the current answer.

    Inputs:
      - msg: Parsed dns.message.Message from the upstream.
      - qname: Query name as dns.name.Name.
      - rdtype: Numeric RR type being queried.
      - apex: Validated zone apex name.
      - zone_dnskey: Validated DNSKEY RRset for the apex.

    Outputs:
      - bool: True if all relevant authority RRsets are either absent or
        validate successfully, False otherwise.

    Notes:
      - This is intentionally conservative: any authority RRset of type
        DNSKEY/DS/NS/SOA that appears under the validated apex must carry a
        corresponding RRSIG RRset and must validate under zone_dnskey. A
        mismatched apex DNSKEY RRset is treated as an error even if the
        separate chain validation previously succeeded.
    """

    try:
        # Index RRSIG RRsets by owner name; dnspython will match covered types
        # inside dns.dnssec.validate.
        rrsig_by_name: dict[dns.name.Name, dns.rrset.RRset] = {}
        for rrset in getattr(msg, "authority", []) or []:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                rrsig_by_name[rrset.name] = rrset

        for rrset in getattr(msg, "authority", []) or []:
            if rrset.rdtype in (
                dns.rdatatype.NSEC,
                dns.rdatatype.NSEC3,
                dns.rdatatype.RRSIG,
            ):
                # Handled separately by negative validation.
                continue

            # Only consider RRsets that live in or below the validated apex.
            if not rrset.name.is_subdomain(apex):
                continue

            # Sanity-check apex DNSKEY RRsets against the validated keyset.
            if rrset.rdtype == dns.rdatatype.DNSKEY and rrset.name == apex:
                expected = {r.to_text() for r in (zone_dnskey or [])}
                got = {r.to_text() for r in rrset}
                if expected and got and expected != got:
                    return False

            if rrset.rdtype not in (
                dns.rdatatype.DNSKEY,
                dns.rdatatype.DS,
                dns.rdatatype.NS,
                dns.rdatatype.SOA,
            ):
                # Other authority types (e.g., glue-like A/AAAA) are ignored
                # here; they are not considered security-critical in this
                # validator.
                continue

            sig_rrset = rrsig_by_name.get(rrset.name)
            if sig_rrset is None:
                # Signed zone data in the authority section without an
                # accompanying RRSIG is treated as insecure.
                return False
            try:
                dns.dnssec.validate(rrset, sig_rrset, {apex: zone_dnskey})
            except Exception:
                return False

        return True
    except (
        Exception
    ):  # pragma: no cover - defensive: unexpected authority parsing error
        # Treat any unexpected failure while inspecting authority data as a
        # reason to downgrade the response security.
        return False


def _message_has_dnssec_rr(msg: dns.message.Message) -> bool:
    """Return True if the message carries any DNSSEC-related RR types.

    Inputs:
      - msg: Parsed dns.message.Message instance.

    Outputs:
      - bool: True when any RRset in answer/authority is DNSKEY/DS/RRSIG/NSEC/NSEC3.
    """

    for rrset in getattr(msg, "answer", []) or []:
        if rrset.rdtype in (
            dns.rdatatype.DNSKEY,
            dns.rdatatype.DS,
            dns.rdatatype.RRSIG,
            dns.rdatatype.NSEC,
            dns.rdatatype.NSEC3,
        ):
            return True
    for rrset in getattr(msg, "authority", []) or []:
        if rrset.rdtype in (
            dns.rdatatype.DNSKEY,
            dns.rdatatype.DS,
            dns.rdatatype.RRSIG,
            dns.rdatatype.NSEC,
            dns.rdatatype.NSEC3,
        ):
            return True
    return False


def _classify_dnssec_local(
    qname_text: str,
    qtype_num: int,
    response_wire: bytes,
    udp_payload_size: int,
) -> str | None:
    """Baseline local DNSSEC classification used by 'local' and 'local_extended'.

    This inspects only the DNSSEC material present in the provided response and
    does not perform any extra upstream lookups.
    """

    try:
        msg = dns.message.from_wire(response_wire)
        has_dnssec_rr = _message_has_dnssec_rr(msg)

        validated = bool(
            validate_response_local(
                qname_text,
                qtype_num,
                response_wire,
                udp_payload_size=udp_payload_size,
            )
        )

        if validated:
            return "dnssec_secure"
        # If the response carried any DNSSEC material but validation failed,
        # treat it as explicitly bogus. Otherwise it is simply unsigned.
        return "dnssec_bogus" if has_dnssec_rr else "dnssec_unsigned"
    except Exception as e:  # pragma: no cover - defensive logging only
        logger.debug("Local DNSSEC classification error: %s", e)
        return None


def _classify_dnssec_local_extended(
    qname_text: str,
    qtype_num: int,
    response_wire: bytes,
    udp_payload_size: int,
) -> str | None:
    """Extended local DNSSEC classification.

    This first applies the baseline local classification and, when the result is
    'dnssec_unsigned' and the original response contains no DNSSEC material, it
    issues an extra DO=1 query via the configured resolver to obtain a
    DNSSEC-rich response and re-runs validation on that enriched message.
    """

    # Step 1: baseline local classification on the original response.
    base_status = _classify_dnssec_local(
        qname_text, qtype_num, response_wire, udp_payload_size
    )
    if base_status in {"dnssec_secure", "dnssec_bogus"} or base_status is None:
        # Already have a strong or indeterminate verdict; do not second-guess it.
        return base_status

    # Only attempt to extend when we believe the response is effectively unsigned
    # and carries no DNSSEC material at all.
    try:
        original_msg = dns.message.from_wire(response_wire)
    except Exception:
        return base_status

    if _message_has_dnssec_rr(original_msg):
        # There is DNSSEC material but baseline validation treated it as
        # unsigned; for now, keep the baseline classification.
        return base_status

    # Step 2: validate the DNSKEY/DS chain for the zone apex using DO=1
    # lookups, even if the original response carried no DNSSEC records.
    try:
        apex = _find_zone_apex_cached(qname_text, udp_payload_size)
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("Extended local DNSSEC: failed to find apex: %s", e)
        apex = None

    if apex is None:
        return base_status

    try:
        zone_dnskey = _validate_chain_cached(apex.to_text(), udp_payload_size)
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("Extended local DNSSEC: chain validation error: %s", e)
        zone_dnskey = None

    if zone_dnskey is None:
        # Could not validate the zone's DNSKEY/DS chain; cannot claim any
        # additional security beyond the baseline decision.
        return base_status

    # At this point the zone's DNSKEY/DS chain is validated. Attempt to obtain a
    # DNSSEC-rich answer for the specific qname/qtype so we can decide whether
    # the RRset itself is signed.
    try:
        r = _resolver(payload_size=udp_payload_size)
        rdtype = (
            qtype_num
            if isinstance(qtype_num, int)
            else dns.rdatatype.from_text(str(qtype_num))
        )
        qname = dns.name.from_text(qname_text)
        answer = _fetch(r, qname, dns.rdatatype.to_text(rdtype))
        enriched_msg = answer.response
    except Exception as e:  # pragma: no cover - defensive networking path
        logger.debug("Extended local DNSSEC: fetch of RRset failed: %s", e)
        # Could not obtain an enriched response; without a signed RRset,
        # keep the baseline unsigned/bogus classification.
        return base_status

    # Look for a matching RRset and its covering RRSIG in the enriched answer.
    try:
        # Find the answer RRset for the queried name/type.
        rrset = None
        sig_rrset = None
        for rr in enriched_msg.answer:
            if rr.rdtype == rdtype and rr.name == qname:
                rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG and rr.name == qname:
                sig_rrset = rr
        if rrset is not None and sig_rrset is not None:
            try:
                dns.dnssec.validate(rrset, sig_rrset, {apex: zone_dnskey})
                # Extended path: we obtained and validated an RRSIG for the
                # RRset, upgrading an otherwise unsigned-looking response.
                return "dnssec_zone_secure"
            except Exception:
                # The RRset is claimed to be signed but does not validate.
                return "dnssec_bogus"
    except Exception as e:  # pragma: no cover - defensive
        logger.debug(
            "Extended local DNSSEC: error while inspecting enriched RRset: %s", e
        )
        # Fall back to the baseline classification if inspection fails.

    # No usable RRSIG for the specific RRset; even though the zone's
    # DNSKEY/DS chain is valid, we treat the answer as effectively unsigned.
    return base_status


def classify_dnssec_status(
    dnssec_mode: str,
    dnssec_validation: str,
    qname_text: str,
    qtype_num: int,
    response_wire: bytes,
    *,
    udp_payload_size: int = 1232,
) -> str | None:
    """Classify a DNS response as DNSSEC "secure", "unsigned", or "bogus".

    Inputs:
      - dnssec_mode: DNSSEC mode string (e.g. 'ignore', 'passthrough', 'validate').
      - dnssec_validation: Validation strategy ('upstream_ad', 'local', or
        'local_extended').
      - qname_text: Query name as text.
      - qtype_num: Numeric qtype (e.g., 1=A, 28=AAAA).
      - response_wire: Raw DNS response bytes.
      - udp_payload_size: EDNS payload size for any local validation fetches.

    Outputs:
      - 'dnssec_secure' when the specific RRset (or negative response) has been
        fully validated using DNSSEC, including an appropriate RRSIG from the
        original upstream response.
      - 'dnssec_zone_secure' when extended local validation (mode
        'local_extended') performs an extra DO=1 lookup, obtains an RRSIG for
        the RRset, and successfully validates it even though the original
        response appeared unsigned.
      - 'dnssec_unsigned' when the response appears to come from an unsigned
        context (no DNSSEC material available and/or no validated chain).
      - 'dnssec_bogus' when the response carries DNSSEC material that fails
        validation under the current trust anchors.
      - None when dnssec_mode is not 'validate' or classification cannot be
        determined due to errors.
    """
    try:
        mode = str(dnssec_mode).lower()
        if mode != "validate":
            return None

        strategy = str(dnssec_validation or "upstream_ad").lower()

        if strategy == "local":
            return _classify_dnssec_local(
                qname_text, qtype_num, response_wire, udp_payload_size
            )

        if strategy == "local_extended":
            return _classify_dnssec_local_extended(
                qname_text, qtype_num, response_wire, udp_payload_size
            )
        # For upstream_ad we rely on the AD bit only and cannot
        # reliably distinguish unsigned from bogus. Treat AD=1 as
        # 'secure' and AD=0 as 'unsigned'.
        try:
            from dnslib import DNSRecord as _DNSRecord  # local import

            parsed = _DNSRecord.parse(response_wire)
            ad_set = getattr(parsed.header, "ad", 0) == 1
            return "dnssec_secure" if ad_set else "dnssec_unsigned"
        except Exception as e:  # pragma: no cover - defensive logging only
            logger.debug("Upstream AD check failed: %s", e)
            return None
    except Exception:  # pragma: no cover - defensive: low-value edge case
        logger.debug("DNSSEC classification failed; leaving status unset")
        return None
