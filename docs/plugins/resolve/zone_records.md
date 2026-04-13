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

## DNS UPDATE defaults quick reference

ZoneRecords supports dynamic updates through `config.dns_update`. The full key
map is documented in `docs/plugins/resolve/zone_update.md`. Key default blocks:

- `dns_update.enabled`: `false`
- `dns_update.zones`: `null`
- `dns_update.persistence`: `null`
- `dns_update.replication`: `null`
- `dns_update.security`: `null`

When the optional nested blocks are provided, defaults are:

- `dns_update.persistence`
  - `enabled: true`
  - `state_dir: null`
  - `fsync_mode: interval`
  - `fsync_interval_ms: 5000`
  - `max_journal_bytes: 10485760`
  - `max_journal_entries: 10000`
  - `compact_interval_seconds: 3600`
  - `compact_tombstone_ratio: 0.5`
- `dns_update.replication`
  - `role: primary`
  - `zone_owner_node_id: null`
  - `notify_on_update: true`
  - `node_id: null`
  - `reject_direct_update_on_replica: false`
- `dns_update.security`
  - `max_updates_per_message: 100`
  - `max_rr_values_per_rrset: 100`
  - `max_owner_length: 255`
  - `max_rdata_length: 65535`
  - `max_ttl_range: 86400`
  - `max_transaction_bytes: 1048576`
  - `rate_limit_per_client: 10`
  - `rate_limit_per_key: 100`

Also see:
- `example_configs/plugin_zone_update_all_options.yaml`

## Basic configuration

```yaml path=null start=null
plugins:
  - id: custom-zone
	type: zone_records
	hooks:
	  pre_resolve: 60
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
	  pre_resolve: 60
	config:
	  # BasePlugin targeting + logging
	  targets:
        ips: [0.0.0.0/0 ]
	    listeners: any
	    qtypes: [ '*' ]
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
	  watchdog_poll_interval_seconds: 60.0  # set to 0 to disable
      watchdog_data_directories:
        - ./config/var
      watchdog_reject_absolute_paths: false
      watchdog_max_files: 4096
      watchdog_max_directories: 256
      watchdog_snapshot_max_entries: 4096

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

When the `dnssec_signing` block is present, ZoneRecords treats auto-signing as
enabled by default and will attempt to synthesize DNSKEY and RRSIG records for
authoritative zones at load/reload time using the same primitives as the
helper script. Set `dnssec_signing.enabled: false` to disable. Example:

```yaml path=null start=null
plugins:
  - type: zone_records
    hooks:
      pre_resolve: 60
    config:
      file_paths:
        - ./config/var/example.com.txt
      dnssec_signing:
        enabled: true
        keys_dir: ./keys
        algorithm: ECDSAP256SHA256
        generate: maybe   # yes | no | maybe
        validity_days: 30
        nsec3:
          # NSEC3 salt in zonefile presentation form: '-' for empty salt, else hex.
          salt: '-'
          iterations: 10
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

- When `dnssec_signing` is configured (or `dnssec_signing.enabled` is set to
  `true`), ZoneRecords generates **NSEC3PARAM** and **NSEC3** records for
  authoritative zones so that NXDOMAIN/NODATA responses can include
  authenticated denial of existence when clients set DO=1.
- NSEC (non-hashed) negative proofs are not generated.
- Foghorn does not validate its own ZoneRecords responses.
- DNSSEC is static – re-run the signing script when zone data changes.

## Options

### Plugin-specific options (`ZoneRecordsConfig`)

- `file_paths: list[str] | null`
  - Hosts Foghorn's simple pipe-delimited record format. Each non-comment line
	is `"<domain>|<qtype>|<ttl>|<value>"`.
- `path_allowlist: list[str] | null`
  - Optional list of allowed directory prefixes for `file_paths` and `bind_paths`.
  - Paths outside these prefixes are ignored with a warning.
  - Paths containing explicit `..` segments are rejected.
  - Protect the config file; without this allowlist, any readable path can be used.
- `file_path: str | null`
  - Legacy single records file path; merged into `file_paths` when both are set.
  - Prefer `file_paths` for new configurations.
- `bind_paths: list[str | object] | null`
  - Paths (or per-file objects) for standard BIND zone files (RFC 1035). Each
    entry may be either:
    - `./path/to/zonefile.zone`, or
    - `{ path: ./path/to/zonefile.zone, origin: example.com., ttl: 300 }`
  - When `origin` is set, any `$ORIGIN` line found in the file is ignored (with a warning).
  - When `ttl` is set, any `$TTL` line found in the file is ignored (with a warning).
- `records: list[str] | null`
  - Inline pipe-delimited records with the same syntax as `file_paths` entries.
  - Processed after file-backed records so they can override entries from files.
- `load_mode: str`
  - `merge` (default) preserves any existing in-memory records and overlays newly
    loaded records on top (no deletions).
  - `replace` rebuilds the in-memory mapping on each load/reload.
  - `first` uses the first configured source group in this order:
    records (inline) → axfr_zones → file_paths → bind_paths, and ignores the others.
- `merge_policy: str`
  - `add` (default) appends unique values into an existing RRset.
  - `overwrite` replaces an existing RRset when a later source defines the same
    `(domain, qtype)`.
  - When `overwrite` overwrites any owners, ZoneRecords logs a single warning
    summarizing how many owners were overwritten per source.
- `max_file_size_bytes: int`
  - Maximum allowed size (bytes) for each configured file in `file_paths` and
    `bind_paths`. Files larger than this are rejected during load.
  - Default: `16777216` (16 MiB).
- `max_records: int`
  - Maximum total record values accepted in one load pass.
  - Applies across inline records, `file_paths`, and `bind_paths`.
  - Default: `500000`.
- `max_record_value_length: int`
  - Maximum allowed character length for each record value (rdata text).
  - Oversized values are rejected during load.
  - Default: `4096`.
- `auto_ptr_enabled: bool`
  - Enables/disables automatic PTR synthesis from loaded A/AAAA records.
  - Default: `true`.
- `max_auto_ptr_records: int`
  - Maximum number of PTR values auto-generated in one load pass.
  - Default: `100000`.
- `soa_synthesis_enabled: bool`
  - Enables/disables fallback SOA synthesis from inferred common suffixes when
    no SOA is explicitly present.
  - Default: `true`.
- `axfr_zones: list[object] | null`
  - Optional list of zones fetched via AXFR at startup. Each entry should include:
    - `zone: str` – zone apex (e.g. `"example.com"`, `"0.0.10.in-addr.arpa"`).
    - `upstreams: list[object]` – authoritative servers to AXFR from; each upstream supports at least `host`, `port` (default `53`), `timeout_ms` (default `5000`), optional DoT fields (`transport`, `server_name`, `verify`, `ca_file`), and optional TSIG (`tsig.name`, `tsig.secret`, `tsig.algorithm`).
    - `allow_no_dnssec: bool` – hint for future DNSSEC policies. Currently all zones are
      loaded regardless of DNSSEC state; Foghorn classifies each AXFR-backed
      zone as having `dnssec_state=present|partial|none` and logs a warning when
      DNSKEY/RRSIG data is missing or incomplete, especially when
      `allow_no_dnssec` is `false`.
    - `allow_private_upstreams: bool` – allow upstreams that resolve to
      non-public IPs (private/loopback/link-local). Defaults to `true`; set to
      `false` to block private upstreams.
    - `allow_public_upstreams: bool` – allow upstreams that resolve to public
      IPs. Defaults to `true`; set to `false` to block public upstreams.
    - `minimum_reload_time: float` – minimum seconds between AXFR reloads.
    - `max_rrs_per_zone: int | null` – optional cap on total RRs per transfer.
    - `max_bytes_per_zone: int | null` – optional cap on total response bytes
      per transfer.
    - `max_retries_per_zone: int | null` – optional cap on consecutive failed
      AXFR attempts before giving up.
    - `failure_backoff_initial_seconds: float` – initial backoff delay after a
      failed transfer (0 disables backoff).
    - `failure_backoff_max_seconds: float` – maximum backoff delay (0 disables
      the cap).
    - `poll_interval_seconds: int | null` – optional polling interval (seconds)
      for periodic AXFR refreshes; clamped to `axfr_poll_min_interval_seconds`
      (hard floor of 10 seconds).
  - AXFR-backed zones are loaded once during initial setup; subsequent reloads come from local files/inline records.
- `axfr_poll_min_interval_seconds: float`
  - Minimum polling interval enforced for AXFR polling. Defaults to `60.0`.
  - Values below the hard floor are clamped to `10.0`.
- `axfr_notify: list[object] | null`
  - Optional static list of downstream NOTIFY recipients. Each entry supports:
    - `host`, `port`, `timeout_ms`
    - `transport` (`tcp` or `dot`)
    - `server_name`, `verify`, `ca_file` for DoT.
  - Only configured targets are used; AXFR clients are not auto-learned.
- `axfr_notify_allow_private_targets: bool`
  - Default: `false`.
  - When `false`, NOTIFY targets resolving to private/loopback/link-local/
    multicast/reserved addresses are blocked.
- `axfr_notify_target_allowlist: list[str] | null`
  - Optional outbound NOTIFY target allowlist.
  - Entries may be hostnames, IP literals, or CIDR ranges.
  - When set, each NOTIFY target must match the hostname allowlist directly or
    resolve only to allowlisted IP/CIDR addresses.
- `axfr_notify_min_interval_seconds: float`
  - Default: `1.0`.
  - Minimum elapsed seconds between sends to the same NOTIFY target.
- `axfr_notify_rate_limit_per_target_per_minute: int`
  - Default: `60`.
  - Maximum sends to the same target within a rolling 60-second window.
- `axfr_notify_scheduled: int | null`
  - Deprecated compatibility field; retained for config stability.
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
  - Default: `60.0` (set to `0.0` to disable).
- `watchdog_data_directories: list[str] | null`
  - Optional directory prefixes used to constrain watchdog/polling filesystem
    operations.
  - When omitted, `path_allowlist` is reused.
  - Paths outside these prefixes are skipped with warnings.
- `watchdog_reject_absolute_paths: bool`
  - Default: `false`.
  - When `true`, absolute paths in watched record sources are skipped.
- `watchdog_max_files: int`
  - Maximum record files considered by watchdog/polling.
  - Default: `4096`.
- `watchdog_max_directories: int`
  - Maximum parent directories scheduled in watchdog.
  - Default: `256`.
- `watchdog_snapshot_max_entries: int`
  - Maximum polling stat snapshot entries retained in memory.
  - Default: `4096`.
- `ttl: int`
  - Default TTL in seconds. Used when an individual record omits its own TTL.
- `nxdomain_zones: list[str] | null`
  - Optional list of zone suffixes where ZoneRecords should return NXDOMAIN/NODATA
    for names under that suffix which are not present in its internal mapping,
    instead of falling through to upstream resolution.

### Behaviour

- Records from `axfr_zones`, `records`, `file_paths` and `bind_paths` are merged
  into an internal mapping of `(domain, qtype) -> (ttl, [values])`.
- Reloads are atomic: new mappings are built off-thread and swapped in under a
  lock so readers never see partial state.
- Watchdog observes parent directories (non-recursive) for configured files and
  then filters events down to concrete target files.
- To reduce filesystem disclosure/scope, use `watchdog_data_directories`,
  `path_allowlist`, and the watcher size limits in production.
- Zone apex SOA records are tracked separately for SOA queries and are used to
  build proper NOERROR/NODATA and NXDOMAIN authority sections for names inside
  authoritative zones.
- A and AAAA RRsets automatically synthesize reverse PTR records whose
  owners follow `ipaddress.ip_address(...).reverse_pointer` semantics and
  whose targets point back to the forward owner name. Explicit PTR records
  retain precedence: they define the TTL and are not overwritten.
- Zone transfers (AXFR/IXFR) are fetched via the optional `axfr_zones` config at
  startup; subsequent reloads only use local files and inline records.
- When a zone apex carries an SOA record (from any source), ZoneRecords marks
  that apex as authoritative. The core server exposes a simple AXFR/IXFR server
  for such zones over DNS-over-TCP and DoT when `server.axfr.enabled` is true:
  AXFR/IXFR queries are answered by streaming the zone contents provided by
  `iter_zone_rrs_for_transfer()`, bounded by matching SOA records. IXFR is
  currently implemented as a full AXFR-style transfer (no deltas).
- AXFR/IXFR returns the full zone contents (including DNSSEC material when
  present). Only explicitly allowlisted clients should be permitted.
- Transfer attempts and completed transfers are logged with client IP, zone
  apex, RR count, message count, transfer bytes, and duration for auditing.

#### Wildcard semantics

ZoneRecords wildcard matching intentionally differs from RFC 4592 for leading
`*` labels: a leading `*` matches **one or more** labels (any depth). For
example, `*.example.org` matches `a.example.org` and `a.b.example.org`.

#### Operational guidance

- For production deployments, keep authoritative zone apex counts to roughly
  **1,000 zones per instance** unless you have benchmarked higher counts.

#### Precedence

When multiple sources define the same owner/qtype, ZoneRecords applies this
policy order from highest to lowest precedence:

1. `records` – inline records define local policy and TTLs.
2. `axfr_zones` – AXFR-backed records extend the inline view.
3. `file_paths` – custom pipe-delimited files further extend the view.
4.  `bind_paths` – BIND-style zone files are merged last.

Within this merge:

- The first source to introduce a given `(domain, qtype)` determines its TTL.
- Later sources only add new, distinct values to the RRset; duplicates are
  ignored.
- The first SOA for a given owner defines that zone apex; later SOAs for the
  same owner are ignored.

#### AXFR Reload Timing

AXFR-backed zones can be reloaded on subsequent plugin loads based on the
`minimum_reload_time` configuration field in `axfr_zones` entries:

- `minimum_reload_time: float` – Minimum seconds between AXFR reloads. Reloads only
  after this time has elapsed since the initial load or since the last NOTIFY was
  received for the zone. A value of 0 (default) reloads on every load.

#### AXFR Failure Backoff and Limits

AXFR transfers can be constrained and retried with backoff on failure:

- `max_rrs_per_zone` and `max_bytes_per_zone` cap the size of an AXFR transfer.
- `max_retries_per_zone` caps consecutive failures before giving up.
- `failure_backoff_initial_seconds` and `failure_backoff_max_seconds` implement
  exponential backoff between failed attempts.

This allows balancing between keeping zones up-to-date and avoiding excessive transfer
load on upstream servers.

#### AXFR Serve-Side Limits (`server.axfr`)

When serving AXFR/IXFR to downstream clients (TCP/DoT listeners), hardening is
configured under `server.axfr`:

- `enabled: bool` – enable/disable serving AXFR/IXFR.
- `allow_clients: list[str]` – required client CIDR/IP allowlist.
- `require_tsig: bool` – require TSIG on inbound AXFR/IXFR requests.
- `tsig_keys: list[object]` – accepted TSIG keys (`name`, `secret`, optional `algorithm`).
- `max_zone_rrs: int | null` – optional cap on transfer RR count per zone.
- `max_concurrent_transfers: int` – global limit for concurrent transfers.
- `rate_limit_per_client_per_second: float` – per-client request token refill
  rate (`0` disables this limiter).
- `rate_limit_burst: float` – per-client request burst tokens.
- `max_transfer_rate_bytes_per_second: int | null` – optional best-effort
  transfer pacing cap.
- `message_max_bytes: int` – maximum packed DNS message size per AXFR frame.

The `load_mode=replace` mode always forces a reload when the plugin starts up.

#### Dynamic DNS Support

ZoneRecords currently supports Dynamic DNS updates (RFC 2136) when
`dns_update.enabled` is true and the queried zone matches a configured
`dns_update.zones[]` entry.

In the active UPDATE request path, request authorization is TSIG-based.

### Common BasePlugin options

ZoneRecords supports full BasePlugin targeting and logging; see the full
configuration example for typical usage.
