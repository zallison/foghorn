from __future__ import annotations

import logging
import pathlib
from typing import Dict, List, Optional, Tuple

from dnslib import QTYPE, RR

logger = logging.getLogger(__name__)


def auto_sign_zones(
    mapping: Dict[Tuple[str, int], Tuple[int, List[str]]],
    name_index: Dict[str, Dict[int, Tuple[int, List[str]]]],
    zone_soa: Dict[str, Tuple[int, List[str]]],
    dnssec_cfg_raw: dict,
    log: Optional[logging.Logger] = None,
) -> None:
    """Brief: Perform DNSSEC auto-signing for authoritative zones.

    Inputs:
      - mapping: (owner, qtype) -> (ttl, [values]) mapping to receive DNSKEY/
        RRSIG material.
      - name_index: owner -> qtype -> (ttl, [values]) index updated with
        auto-signed RRsets.
      - zone_soa: zone apex -> (ttl, [soa_values]) mapping.
      - dnssec_cfg_raw: dnssec_signing configuration dict.
      - log: Optional logger; when omitted, uses this module's logger.

    Outputs:
      - None; mutates mapping and name_index in place by adding DNSKEY/RRSIG
        RRsets for each auto-signed zone.
    """

    log = log or logger

    try:
        import datetime as _dt

        import dns.name as _dns_name
        import dns.rdata as _dns_rdata
        import dns.rdataclass as _dns_rdataclass
        import dns.rdatatype as _dns_rdatatype
        import dns.rrset as _dns_rrset
        import dns.zone as _dns_zone

        from foghorn.dnssec import zone_signer as _zs

        keys_dir_cfg = dnssec_cfg_raw.get("keys_dir")
        algorithm = dnssec_cfg_raw.get("algorithm") or "ECDSAP256SHA256"
        generate_policy = dnssec_cfg_raw.get("generate") or "maybe"
        validity_days = int(dnssec_cfg_raw.get("validity_days") or 30)

        try:
            dnskey_code_all = int(QTYPE.DNSKEY)
        except Exception:  # pragma: no cover - defensive
            dnskey_code_all = 48
        try:
            rrsig_code_all = int(QTYPE.RRSIG)
        except Exception:  # pragma: no cover - defensive
            rrsig_code_all = 46

        for apex_owner in list(zone_soa.keys()):
            origin_text = apex_owner.rstrip(".").lower() + "."
            origin = _dns_name.from_text(origin_text)

            zone_obj = _dns_zone.Zone(origin)

            for owner, rrsets in name_index.items():
                try:
                    owner_norm = str(owner).rstrip(".").lower()
                except Exception:  # pragma: no cover - defensive
                    owner_norm = str(owner).lower()

                if owner_norm != apex_owner and not owner_norm.endswith(
                    "." + apex_owner
                ):
                    continue

                owner_name = _dns_name.from_text(owner_norm + ".")
                node_obj = zone_obj.find_node(owner_name, create=True)

                for qtype_code, (ttl_val, vals) in rrsets.items():
                    if int(qtype_code) == int(rrsig_code_all):
                        continue
                    if int(qtype_code) == int(dnskey_code_all):
                        continue

                    rr_type_name = QTYPE.get(qtype_code, str(qtype_code))
                    try:
                        rdtype = _dns_rdatatype.from_text(str(rr_type_name))
                    except Exception:  # pragma: no cover - defensive
                        continue

                    rrset_obj = _dns_rrset.RRset(
                        owner_name,
                        _dns_rdataclass.IN,
                        rdtype,
                    )
                    for v in list(vals):
                        try:
                            rdata_obj = _dns_rdata.from_text(
                                _dns_rdataclass.IN, rdtype, str(v)
                            )
                        except Exception:  # pragma: no cover - defensive
                            continue
                        rrset_obj.add(rdata_obj, int(ttl_val))

                    node_obj.replace_rdataset(rrset_obj)

            if keys_dir_cfg is not None:
                keys_dir_path = pathlib.Path(str(keys_dir_cfg)).expanduser()
            else:
                keys_dir_path = pathlib.Path(".")

            try:
                (
                    ksk_private,
                    zsk_private,
                    ksk_dnskey,
                    zsk_dnskey,
                ) = _zs.ensure_zone_keys(
                    origin_text,
                    keys_dir_path,
                    algorithm=algorithm,
                    generate_policy=generate_policy,
                )
            except Exception as exc:  # pragma: no cover - defensive
                # Keep the existing log message used by ZoneRecords so callers
                # relying on it continue to see the same text.
                log.warning(
                    "ZoneRecords DNSSEC auto-sign skipped for %s: %s",
                    apex_owner,
                    exc,
                )
                continue

            now = _dt.datetime.utcnow()
            inception = now - _dt.timedelta(hours=1)
            expiration = now + _dt.timedelta(days=validity_days)
            alg_enum = _zs.ALGORITHM_MAP[algorithm][0]

            _zs.sign_zone(
                zone_obj,
                origin,
                ksk_private,
                zsk_private,
                ksk_dnskey,
                zsk_dnskey,
                alg_enum,
                inception,
                expiration,
            )

            for owner_name, node_obj in zone_obj.items():
                try:
                    if isinstance(owner_name, _dns_name.Name):
                        owner_abs = owner_name
                    else:
                        owner_abs = _dns_name.from_text(str(owner_name))
                    if not owner_abs.is_absolute():
                        owner_abs = owner_abs.derelativize(origin)
                    owner_norm = owner_abs.to_text().rstrip(".").lower()
                except Exception:  # pragma: no cover - defensive
                    owner_norm = str(owner_name).rstrip(".").lower()

                for rdataset in node_obj:
                    if rdataset.rdtype not in (
                        _dns_rdatatype.DNSKEY,
                        _dns_rdatatype.RRSIG,
                    ):
                        continue

                    if rdataset.rdtype == _dns_rdatatype.DNSKEY:
                        qcode = int(dnskey_code_all)
                    else:
                        qcode = int(rrsig_code_all)

                    key = (owner_norm, qcode)
                    existing = mapping.get(key)
                    if existing is None:
                        stored_ttl = int(getattr(rdataset, "ttl", 0) or 0)
                        vals_list: List[str] = []
                    else:
                        stored_ttl, vals_list = existing

                    for rdata_obj in list(rdataset):
                        try:
                            value_text = rdata_obj.to_text()
                        except Exception:  # pragma: no cover - defensive
                            continue
                        if value_text not in vals_list:
                            vals_list.append(value_text)

                    mapping[key] = (stored_ttl, vals_list)
                    per_name = name_index.setdefault(owner_norm, {})
                    per_name[qcode] = (stored_ttl, vals_list)

    except Exception:  # pragma: no cover - defensive logging only
        log.warning(
            "ZoneRecords: DNSSEC auto-signing failed; leaving zones unsigned",
            exc_info=True,
        )


def build_dnssec_helper_mapping(
    mapping: Dict[Tuple[str, int], Tuple[int, List[str]]],
    log: Optional[logging.Logger] = None,
) -> Dict[int, Dict[str, List[RR]]]:
    """Brief: Build qtype->owner->RR helper mapping including RRSIGs.

    Inputs:
      - mapping: (owner, qtype) -> (ttl, [values]) mapping.
      - log: Optional logger; when omitted, uses this module's logger.

    Outputs:
      - mapping_by_qtype: qtype -> owner -> list[RR] structure used by
        plugins at query time to attach base RRsets and their signatures.
    """

    log = log or logger

    try:
        try:
            rrsig_code_idx = int(QTYPE.RRSIG)
        except Exception:  # pragma: no cover - defensive
            rrsig_code_idx = 46

        rrsig_cover: Dict[Tuple[str, int], List[str]] = {}
        for (owner_name_idx, qcode_idx), (ttl_idx, vals_idx) in mapping.items():
            if int(qcode_idx) != int(rrsig_code_idx):
                continue
            owner_norm_idx = str(owner_name_idx).rstrip(".").lower()
            for v_idx in list(vals_idx):
                try:
                    parts = str(v_idx).split()
                except Exception:  # pragma: no cover - defensive
                    continue
                if not parts:
                    continue
                covered_name = parts[0].upper()
                covered_code: Optional[int] = None
                try:
                    attr_val = getattr(QTYPE, covered_name)
                except Exception:
                    attr_val = None
                if isinstance(attr_val, int):
                    covered_code = int(attr_val)
                else:
                    try:
                        qval = QTYPE.get(covered_name, None)
                    except Exception:
                        qval = None
                    if isinstance(qval, int):
                        covered_code = int(qval)
                if covered_code is None:
                    continue
                key_idx = (owner_norm_idx, covered_code)
                bucket = rrsig_cover.setdefault(key_idx, [])
                bucket.append(str(v_idx))

        mapping_by_qtype: Dict[int, Dict[str, List[RR]]] = {}
        for (owner_name_idx, qcode_idx), (ttl_idx, vals_idx) in mapping.items():
            owner_norm_idx = str(owner_name_idx).rstrip(".").lower()
            qcode_int = int(qcode_idx)

            if qcode_int == int(rrsig_code_idx):
                continue

            rr_type_name_idx = QTYPE.get(qcode_int, str(qcode_int))
            rr_list: List[RR] = []

            for v_idx in list(vals_idx):
                zone_line_idx = (
                    f"{owner_norm_idx}. {int(ttl_idx)} IN {rr_type_name_idx} {v_idx}"
                )
                try:
                    built = RR.fromZone(zone_line_idx)
                except Exception:  # pragma: no cover - defensive
                    continue
                rr_list.extend(built)

            sig_entries = rrsig_cover.get((owner_norm_idx, qcode_int), [])
            for v_sig in sig_entries:
                ttl_sig = int(ttl_idx) or 300
                zone_line_sig = f"{owner_norm_idx}. {ttl_sig} IN RRSIG {v_sig}"
                try:
                    built_sig = RR.fromZone(zone_line_sig)
                except Exception:  # pragma: no cover - defensive
                    continue
                rr_list.extend(built_sig)

            if not rr_list:
                continue

            by_name = mapping_by_qtype.setdefault(qcode_int, {})
            by_name[owner_norm_idx] = rr_list
    except Exception:  # pragma: no cover - defensive logging only
        log.warning(
            "ZoneRecords: failed to build DNSSEC helper mapping; falling back to per-query construction",
            exc_info=True,
        )
        mapping_by_qtype = {}

    return mapping_by_qtype
