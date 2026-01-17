# ZoneRecords resolve plugin

## Overview

The `zone_records` resolve plugin serves custom DNS records from one or more
zone-style files and/or inline configuration. It understands:

- a simple pipe-delimited records format specific to Foghorn, and
- standard BIND-style zone files (RFC 1035) via `bind_paths`.

It supports automatic reloads using `watchdog` and/or polling, with atomic
updates so that readers always see a consistent set of records.

Typical use cases:

- Hosting small internal zones or overrides without running a full authoritative server.
- Serving ACME TXT challenges or other short-lived records alongside existing zones.
- Overlaying custom records on top of external zones for testing or migration.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: custom-zone
	type: zone_records
	hooks:
	  pre_resolve: { priority: 60 }
	config:
	  file_paths:
		- ./config/var/records.txt    # Foghorn pipe-delimited format
	  ttl: 300
```

Example `records.txt` line (pipe-delimited):

```text path=null start=null
www.example.com|A|300|192.0.2.10
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: zone-advanced
	type: zone_records
	hooks:
	  pre_resolve: { priority: 60 }
	config:
	  # BasePlugin targeting + logging
	  targets: [ 0.0.0.0/0 ]
	  targets_listener: any
	  target_qtypes: [ '*' ]
	  logging:
		level: info
		stderr: true

	  # Pipe-delimited records files (Foghorn format)
	  file_paths:
		- ./config/var/records.txt
		- ./config/var/extra-records.txt

	  # Standard BIND-style zone files
	  bind_paths:
		- ./config/var/example.com.zone
		- ./config/var/0.0.10.in-addr.arpa.zone

	  # Inline records (appended after files; later entries win)
	  records:
		- 'www.example.com|A|300|192.0.2.10'
		- 'mail.example.com|MX|600|10 mail.example.com.'
		- '_acme-challenge.example.com|TXT|60|xyz-token'

	  # Automatic reload control
	  watchdog_enabled: true
	  watchdog_min_interval_seconds: 1.0
	  watchdog_poll_interval_seconds: 0.0

	  # Default TTL when a record omits TTL
	  ttl: 300

	  # Optional AXFR-backed zones fetched at startup
	  axfr_zones:
		- zone: example.com
		  upstreams:
			- host: 192.0.2.10
			  port: 53
			  timeout_ms: 5000
```

## DNSSEC Support

ZoneRecords supports serving DNSSEC-signed zones when clients advertise EDNS(0)
with the DO (DNSSEC OK) bit set.

### Static DNSSEC Signing

DNSSEC signatures can be pre-generated offline using the provided helper script:

```bash path=null start=null
# Generate keys and sign a zone file
python scripts/generate_zone_dnssec.py \
  --zone example.com. \
  --input zones/example.com.zone \
  --output zones/example.com.signed.zone \
  --keys-dir keys/
```

The signed zone file contains DNSKEY and RRSIG records that ZoneRecords serves
automatically when clients request DNSSEC.

### Optional DNSSEC Auto-Signing

When the `dnssec_signing.enabled` config flag is set to true, ZoneRecords will
attempt to synthesize DNSKEY and RRSIG records for authoritative zones at
load/reload time using the same primitives as the helper script. Example:

```yaml path=null start=null
plugins:
  - type: zone_records
    hooks:
      pre_resolve: { priority: 60 }
    config:
      file_paths:
        - ./config/var/example.com.txt
      dnssec_signing:
        enabled: true
        keys_dir: ./keys
        algorithm: ECDSAP256SHA256
        generate: maybe   # yes | no | maybe
        validity_days: 30
```

Keys are stored per-zone under `keys_dir` using the same naming convention as
`scripts/generate_zone_dnssec.py`. The `generate` policy controls how keys are
managed:

- `yes`: always generate new keys for the zone (overwriting any existing files).
- `no`: never generate; existing keys must already be present.
- `maybe`: reuse keys when present; generate new keys only when missing.

If DNSSEC auto-signing fails for a zone (for example, missing dependencies or
invalid records), ZoneRecords logs a warning and leaves that zone unsigned.

### Client DO Bit Detection

When a client query includes EDNS(0) with DO=1, ZoneRecords:

1. Returns RRSIG records alongside the requested RRsets.
2. At the zone apex, also includes DNSKEY records.

Clients without DO=1 receive only the base RRsets without signatures.

### Scope and Limitations

- NSEC/NSEC3 negative proofs are **not** generated automatically.
- Foghorn does not validate its own ZoneRecords responses.
- DNSSEC is static – re-run the signing script when zone data changes.

## Options

### Plugin-specific options (`ZoneRecordsConfig`)

- `file_paths: list[str] | null`
  - Hosts Foghorn's simple pipe-delimited record format. Each non-comment line
	is `"<domain>|<qtype>|<ttl>|<value>"`.
- `file_path: str | null`
  - Legacy single records file path; merged into `file_paths` when both are set.
  - Prefer `file_paths` for new configurations.
- `bind_paths: list[str] | null`
  - Paths to standard BIND zone files (RFC 1035). These are parsed into the same
  internal mapping.
- `records: list[str] | null`
  - Inline pipe-delimited records with the same syntax as `file_paths` entries.
  - Processed after file-backed records so they can override entries from files.
- `axfr_zones: list[object] | null`
  - Optional list of zones fetched via AXFR at startup. Each entry should include:
    - `zone: str` – zone apex (e.g. `"example.com"`, `"0.0.10.in-addr.arpa"`).
    - `upstreams: list[object]` – authoritative servers to AXFR from; each upstream supports at least `host`, `port` (default `53`), `timeout_ms` (default `5000`), and optional DoT fields (`transport`, `server_name`, `verify`, `ca_file`).
    - `allow_no_dnssec: bool` – hint for future DNSSEC policies. Currently all zones are
      loaded regardless of DNSSEC state; Foghorn classifies each AXFR-backed
      zone as having `dnssec_state=present|partial|none` and logs a warning when
      DNSKEY/RRSIG data is missing or incomplete, especially when
      `allow_no_dnssec` is `false`.
  - AXFR-backed zones are loaded once during initial setup; subsequent reloads come from local files/inline records.
- `watchdog_enabled: bool | null`
  - When `true`, and `watchdog` is present, start filesystem watchers for
	configured files and reload on change.
  - When `false`, no watchdog is started.
  - `null` defaults to `true`.
- `watchdog_min_interval_seconds: float`
  - Minimum seconds between reloads to avoid tight loops when each reload causes
	further filesystem events.
- `watchdog_poll_interval_seconds: float`
  - When `> 0`, start a stat-based polling loop that periodically checks for
	changes (useful where filesystem events are unreliable).
- `ttl: int`
  - Default TTL in seconds. Used when an individual record omits its own TTL.

### Behaviour

- Records from `axfr_zones`, `records`, `file_paths` and `bind_paths` are merged
  into an internal mapping of `(domain, qtype) -> (ttl, [values])`.
- Reloads are atomic: new mappings are built off-thread and swapped in under a
  lock so readers never see partial state.
- Zone apex SOA records are tracked separately for SOA queries and are used to
  build proper NOERROR/NODATA and NXDOMAIN authority sections for names inside
  authoritative zones.
- Zone transfers (AXFR/IXFR) are fetched via the optional `axfr_zones` config at
  startup; subsequent reloads only use local files and inline records.
- When a zone apex carries an SOA record (from any source), ZoneRecords marks
  that apex as authoritative. The core server exposes a simple AXFR/IXFR server
  for such zones over DNS-over-TCP and DoT: AXFR/IXFR queries are answered by
  streaming the zone contents provided by `iter_zone_rrs_for_transfer()`,
  bounded by matching SOA records. IXFR is currently implemented as a full
  AXFR-style transfer (no deltas).

#### Precedence

When multiple sources define the same owner/qtype, ZoneRecords applies this
policy order:

1. `records` – inline records define local policy and TTLs.
2. `axfr_zones` – AXFR-backed records extend the inline view.
3. `file_paths` – custom pipe-delimited files further extend the view.
4. `bind_paths` – BIND-style zone files are merged last.

Within this merge:

- The first source to introduce a given `(domain, qtype)` determines its TTL.
- Later sources only add new, distinct values to the RRset; duplicates are
  ignored.
- The first SOA for a given owner defines that zone apex; later SOAs for the
  same owner are ignored.

### Common BasePlugin options

ZoneRecords supports full BasePlugin targeting and logging; see the full
configuration example for typical usage.
