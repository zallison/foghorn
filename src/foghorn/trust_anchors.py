import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype


@dataclass
class TrustAnchorKey:
    """Single trust-anchor key entry.

    Inputs/fields:
      - key_tag: Numeric key ID (dns.dnssec.key_id).
      - algorithm: DNSKEY algorithm number.
      - public_key_b64: Base64-encoded public key field from DNSKEY.
      - status: 'trusted', 'pending_add', or 'pending_remove'.
      - first_seen: ISO 8601 timestamp when we first saw this key.
      - last_seen: ISO 8601 timestamp when we last saw this key in DNSKEY.
      - promoted_at: ISO 8601 timestamp when we promoted to trusted (optional).
    Outputs:
      - Instances are stored in a JSON-serializable dict via asdict().
    """

    key_tag: int
    algorithm: int
    public_key_b64: str
    status: str
    first_seen: str
    last_seen: str
    promoted_at: Optional[str] = None


Store = Dict[str, Dict[str, List[Dict]]]


def _now_utc() -> datetime:
    """Return current UTC time.

    Outputs:
      - timezone-aware datetime in UTC.
    """

    return datetime.now(timezone.utc)


def load_store(path: str) -> Store:
    """Load trust anchor store from JSON file.

    Inputs:
      - path: Filesystem path where the store JSON is located.

    Outputs:
      - dict mapping zone name to structure with 'keys' list. Returns an empty
        store when the file does not exist or is invalid.
    """

    if not path:
        return {}
    try:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def save_store(path: str, store: Store) -> None:
    """Persist trust anchor store to disk.

    Inputs:
      - path: Filesystem path where the JSON should be written.
      - store: Store dictionary to serialize.

    Outputs:
      - None; best-effort write with simple replace.
    """

    if not path:
        return
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, sort_keys=True)
    os.replace(tmp_path, path)


def _zone_bucket(store: Store, zone: str) -> Dict:
    """Return bucket for a given zone, creating it if needed."""

    zone = zone or "."
    bucket = store.get(zone)
    if bucket is None:
        bucket = {"keys": []}
        store[zone] = bucket
    return bucket


def anchors_for_zone(store: Store, zone: str) -> List[dns.rdata.Rdata]:
    """Return trusted DNSKEY RDATAs for a zone.

    Inputs:
      - store: Trust anchor store dict.
      - zone: Zone name (e.g. '.').

    Outputs:
      - List of dns.rdata.Rdata DNSKEY objects for entries with status 'trusted'.
    """

    bucket = _zone_bucket(store, zone)
    out: List[dns.rdata.Rdata] = []
    for entry in bucket.get("keys", []):
        if entry.get("status") != "trusted":
            continue
        try:
            alg = int(entry["algorithm"])
            pub_b64 = entry["public_key_b64"]
            # Construct DNSKEY rdata from text form to leverage dnspython parsing.
            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DNSKEY,
                f"257 3 {alg} {pub_b64}",
            )
            rdata = rdata
            out.append(rdata)
        except Exception:
            continue
    return out


def bootstrap_from_rrset(store: Store, zone: str, rrset: dns.rrset.RRset) -> Store:
    """Seed the store for a zone from a DNSKEY rrset.

    Inputs:
      - store: Existing trust anchor store.
      - zone: Zone name string.
      - rrset: DNSKEY rrset containing at least one SEP (KSK).

    Outputs:
      - Updated store with trusted keys bootstrapped from the rrset.
    """

    now = _now_utc().isoformat()
    bucket = _zone_bucket(store, zone)
    keys = []
    for rdata in rrset:
        try:
            # Only consider KSKs (SEP bit set in the DNSKEY flags field).
            if not getattr(rdata, "flags", 0) & int(getattr(dns.dnssec.Flag, "SEP", 0)):
                continue
            key_tag = dns.dnssec.key_id(rdata)
            pub_b64 = rdata.to_text().split()[-1]
            keys.append(
                asdict(
                    TrustAnchorKey(
                        key_tag=key_tag,
                        algorithm=int(rdata.algorithm),
                        public_key_b64=pub_b64,
                        status="trusted",
                        first_seen=now,
                        last_seen=now,
                        promoted_at=now,
                    )
                )
            )
        except Exception:
            continue
    if keys:
        bucket["keys"] = keys
    return store


def update_from_dnskey_rrset(
    store: Store,
    zone: str,
    rrset: dns.rrset.RRset,
    *,
    now: Optional[datetime] = None,
    hold_down_add_days: int = 2,
    hold_down_remove_days: int = 2,
) -> bool:
    """Update trust-anchor state for a zone from a live DNSKEY rrset.

    Inputs:
      - store: Trust anchor store.
      - zone: Zone name string.
      - rrset: Live DNSKEY rrset for the zone.
      - now: Optional override of current time (UTC) for tests.
      - hold_down_add_days: Days a new key must remain present before promotion.
      - hold_down_remove_days: Days a missing/revoked key must remain absent.

    Outputs:
      - bool: True if the store was modified and should be saved.
    """

    if now is None:
        now = _now_utc()
    bucket = _zone_bucket(store, zone)
    changed = False

    # Index live DNSKEYs (only KSKs, i.e., SEP bit set).
    live_by_tag = {}
    for rdata in rrset:
        try:
            # Restrict to KSKs (SEP bit) when deriving trust anchors.
            if not getattr(rdata, "flags", 0) & int(getattr(dns.dnssec.Flag, "SEP", 0)):
                continue
            tag = dns.dnssec.key_id(rdata)
            live_by_tag[tag] = rdata
        except Exception:
            continue

    # Existing entries.
    entries: List[Dict] = bucket.get("keys", [])
    by_tag = {e.get("key_tag"): e for e in entries}

    # Mark presence and last_seen.
    for tag, entry in by_tag.items():
        if tag in live_by_tag:
            entry["last_seen"] = now.isoformat()

    # Add new candidates.
    for tag, rdata in live_by_tag.items():
        if tag in by_tag:
            continue
        try:
            pub_b64 = rdata.to_text().split()[-1]
            new = TrustAnchorKey(
                key_tag=tag,
                algorithm=int(rdata.algorithm),
                public_key_b64=pub_b64,
                status="pending_add",
                first_seen=now.isoformat(),
                last_seen=now.isoformat(),
                promoted_at=None,
            )
            entries.append(asdict(new))
            changed = True
        except Exception:
            continue

    hold_add = timedelta(days=max(hold_down_add_days, 0))
    hold_remove = timedelta(days=max(hold_down_remove_days, 0))

    # Promotion and removal.
    for entry in list(entries):
        try:
            status = entry.get("status", "trusted")
            tag = entry.get("key_tag")
            first_seen = datetime.fromisoformat(entry["first_seen"])

            if status == "pending_add":
                if tag in live_by_tag and now - first_seen >= hold_add:
                    entry["status"] = "trusted"
                    entry["promoted_at"] = now.isoformat()
                    changed = True

            elif status == "trusted":
                if tag not in live_by_tag:
                    # Begin removal hold-down.
                    entry["status"] = "pending_remove"
                    entry["first_seen"] = now.isoformat()
                    entry["last_seen"] = now.isoformat()
                    changed = True

            elif status == "pending_remove":
                if tag not in live_by_tag and now - first_seen >= hold_remove:
                    entries.remove(entry)
                    changed = True
        except Exception:
            continue

    bucket["keys"] = entries
    return changed
