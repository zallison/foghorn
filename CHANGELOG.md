# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
### Recent incremental updates
- Hardened external cache backends against untrusted-data deserialization by replacing pickle-based payload decoding with a safe JSON/tagged codec in Redis, Memcached, MongoDB, SQLite, MySQL, and PostgreSQL cache paths; legacy pickle-encoded cache entries now fail closed as cache misses (with best-effort cleanup), and persisted key encoding updates in SQLite/MySQL/PostgreSQL may invalidate previously stored entries until repopulated.
- Added query-log flood hardening controls across runtime/config/backends: global `logging.max_logging_queue`, retention byte caps (`max_bytes`), prune cadence controls (`prune_interval_seconds`, `prune_every_n_inserts`), pre-persistence sampling (`query_log_sampling`) and dedupe (`query_log_dedupe`) options, plus backend maintenance knobs (SQLite/PostgreSQL vacuum, MySQL optimize, MongoDB native TTL index support, SQLite auto-vacuum mode).
- Runtime stats initialization now propagates global logging retention defaults into backend configs (with per-backend override precedence) and passes query-log sampling/dedupe settings into `StatsCollector` so persistent query-log writes can be throttled before backend insert.
- Hardened ZoneRecords file/transfer behavior by keeping BIND path reads pinned to the validated resolved path (even if CWD changes mid-load) and pruning stale AXFR per-client rate-limit buckets after idle TTL expiry.
- Retuned built-in RateLimit profile presets in `rate_limit_profiles.yaml` (`slow`, `medium`, `fast`, `localhost`, `home`/`lan`, `smb`, `enterprise`) and updated profile resolution tests to match the new defaults.
- Refined internal naming in stats composition helpers from `*Mixin` to `*Utils` (collector and sqlite_store helper classes) while preserving runtime behavior.
- Expanded README hardening guidance with a new query-log flood hardening section, including recommended logging controls and backend-specific maintenance options.
- Server response handling now strips upstream DNS COOKIE options before caching and rebinds COOKIE on each response to the active client request (removing stale COOKIE data when the request has no cookie).
- Resolver DNSSEC handling now classifies pre-plugin override and forwarded responses consistently, applies AD-bit updates in validate mode, and treats signed authoritative local responses as zone-secure when classification would otherwise be unsigned/bogus.
- Search-domain qualification now excludes DNSSEC RR types, and ZoneRecords now synthesizes search-alias CNAME responses (plus target RRsets when present) for qualified positive and NODATA authoritative answers.
- SSHFP scan tooling now supports reverse PTR hostname expansion for IP targets (enabled by default, configurable via `--reverse-ptr` / `--no-reverse-ptr`) and emits PTR-derived SSHFP owners in both standard and zone-record output modes.
- ZoneRecords NOTIFY sender resolution/rate-limit helper state now uses bounded TTL caches to prevent unbounded in-memory growth under long-running traffic.
- Added shared DNS/IP helper modules (`dns_names`, `ip_networks`) and adopted them across resolver, server, querylog, stats, and ZoneRecords paths to standardize normalization and network parsing.
- Added resolver search-domain qualification controls (`server.resolver.search`) and applied qualification before cache keys, plugin dispatch, stats recording, and upstream forwarding.
- Expanded DNS-name helper coverage with qualification heuristics (`is_single_label`, `has_proper_tld`, `qualify_name`, `should_qualify`) and focused tests for suffix/exact non-proper-TLD modes.
- Extended RateLimit deny visibility controls with `deny_log_first_n` per blocked episode and updated `deny_log_interval_seconds` default to `60` seconds.
- Updated RateLimit schema/docs examples to describe deny-episode query-log visibility behavior and the new deny logging defaults.
- Migrated several hot-path/helper constants to `typing.Final` and refreshed selected helper caches (including MdnsBridge helper methods) to explicit `registered_lru_cached` sizing.
- Hardened resolver plugins with stricter list/file parsing, safer validation, cache/pruning controls, and improved policy enforcement in Filter, FileDownloader, mDNS, SSH Keys, and related host-source/access-control paths.
- Expanded RateLimit behavior and configuration with bootstrap/warmup controls and PSL strictness options, and improved built-in profile loading fallback behavior.
- Updated plugin test coverage and plugin documentation/schema content to reflect the new parsing, normalization, and policy semantics.
- Added a post-setup plugin lifecycle hook (`post_setup`) so deferred background tasks can start after setup ordering completes; FileDownloader now uses this hook for startup freshness checks.
- Hardened ZoneRecords load/notify safety with path traversal rejection, source file/record/value budget limits, optional SOA/PTR synthesis controls, and outbound NOTIFY target allowlist/throttling/private-address policy controls.
- Added a local Docker Compose observability stack (`docker/`) provisioning InfluxDB + Grafana with a prebuilt Foghorn query-log dashboard and datasource wiring.
- Improved config-diagram rendering efficiency by skipping PNG re-renders when generated DOT content is unchanged.
- Expanded AXFR/IXFR hardening with configurable `server.axfr` policy controls (TSIG requirements/keys, per-client rate limiting, concurrent transfer caps, transfer pacing, and per-message sizing limits), plus runtime snapshot/config-dump exposure for these settings.
- Added TSIG support for ZoneRecords AXFR upstream pulls (`axfr_zones[*].upstreams[*].tsig`) and TSIG-validated/signed downstream AXFR/IXFR serving, including transport plumbing updates for TCP/DoT request-wire verification.
- Hardened ZoneRecords watchdog/polling file handling with optional watcher path-prefix constraints, parent-traversal rejection, optional absolute-path rejection, capped watched-file/directory counts, and capped polling snapshot sizes.
- Improved RateLimit enforcement and observability: bootstrap profiles now enforce immediately when configured, per-key hard caps apply even below `min_enforce_rps`, burst reset timing is configurable via `burst_reset_windows`, and admin snapshots include effective per-bucket limits plus interval/overall RPS views.
- Updated built-in RateLimit profiles (`slow`/`medium`/`fast`/`localhost`/`home`/`lan`/`smb`/`enterprise`) and profile resolution paths so profile-backed settings are consistently available in plugin loading and admin/stat helpers.
- Improved admin usability with richer query-log drilldowns/filter controls, enhanced rate-limit profile rendering, and plugin/cache section ordering updates; upstream status payloads now redact sensitive config keys and truncate oversized error strings.
- Reworked RateLimit bucket enforcement and profile tuning with `limit_recalc_windows`, per-window active-key tracking, and explicit UDP network prefix bucketing (`bucket_network_prefix_v4` / `bucket_network_prefix_v6`) replacing legacy UDP keying behavior.
- Expanded admin/API RateLimit observability to include current per-bucket RPS snapshots, burst thresholds, and enforcement-active state in both runtime stats payloads and the web UI tables.
- Extended PTR-domain targeting for resolve plugins so `EtcHosts` and `ZoneRecords` can evaluate reverse PTR owners against configured domain targets before applying plugin decisions.
- Added `PluginDecision.suppress_query_log` support in server decision handling and removed the legacy minimal DoH server module/tests that are no longer used by the current server stack.
- Added shared query-log aggregate bucket enforcement (`MAX_QUERY_LOG_AGG_BUCKETS=20000`) and wired it through admin logic, API routes, and all query-log store backends to reject oversized dense aggregate requests safely.
- Added capped unique-client/unique-domain tracking in StatsCollector (`max_unique_clients`, `max_unique_domains`), including warm-load truncation handling and dropped-count visibility in snapshot totals.
- Hardened threaded admin request body handling with strict Content-Length parsing/caps for config save and diagram upload paths, and aligned aggregate/query snapshot handlers to surface AdminLogic HTTP errors consistently.
- Added config backup retention helpers and pruning in webserver config persistence so timestamped config backups are automatically bounded (`DEFAULT_CONFIG_BACKUP_RETENTION_COUNT=20`).
- Improved DNS UPDATE safety by cloning record maps for isolated mutation, adding stale-snapshot conflict detection on commit, and expanding branch coverage for concurrent conflict handling.
- Improved transport resilience/observability across DoT/TCP/UDP paths with explicit expected-disconnect handling and richer exception logging context in resolver/server code.
- Expanded use of registered cache decorators and cache sizes in hot paths (AccessControl, RateLimit, ZoneRecords DNSSEC/name normalization helpers) to improve throughput under load.
- Updated admin UI dark-theme button visibility so button controls render with clearer accent outlines, and refreshed README coverage badges from 87% to 85%.

### Breaking Changes

- ZoneRecords plugin source precedence order has been **revised** to match documentation: inline records (highest) → AXFR zones → file_paths → bind_paths (lowest). Previously the order was the reverse of this.
  - This changes which source wins when the same `(domain, qtype)` is defined by multiple sources.
  - `load_mode=first` order has been updated to reflect the new precedence: inline → axfr → file_paths → bind_paths.
- AXFR zones now enforce `minimum_reload_time` timing on reload, preventing excessive upstream load. Previously, AXFR was only loaded once at startup.
- The `minimum_reload_time` field in `axfr_zones` entries now triggers reloads only after the configured seconds have elapsed since initial load or last NOTIFY receipt (default 0 = reload on every load).
- Threaded UDP/TCP listeners now refuse to start on non-loopback bind hosts unless `server.limits.allow_unsafe_threaded_listeners=true` is set. Prefer asyncio listeners for exposed interfaces.
- UDP listener now defaults to asyncio everywhere (including localhost). Threaded fallback only allowed on localhost or when explicitly permitted via `allow_unsafe_threaded_listeners`.
- Extended DNS Errors (RFC 8914) now enabled by default for improved error diagnostics across DNS resolvers, rate limiting, and access control.
- Rate limit plugin now adds EDE messages (code 17 "Rate-Limited") when rate limiting, providing better visibility into why queries were rejected.
- ZoneRecords no longer learns NOTIFY destinations from AXFR clients via `axfr_notify_all`; outbound NOTIFY now uses configured `axfr_notify` targets only (`axfr_notify_all` is deprecated and ignored).

### Added
- Admin API: added `/api/v1/config/schema` and `/config/schema` endpoints (FastAPI and threaded admin server) to return the active JSON config schema document.
- UDP listener: added `server.listen.udp.max_query_bytes` (default 4096) to cap accepted UDP query payload size; packets smaller than a DNS header (12 bytes) or larger than the cap are dropped silently.
- ZoneRecords DNS UPDATE TSIG config now supports pluggable external key loading via `tsig.key_sources` (default `type: file` loader).
- ZoneRecords DNS UPDATE now supports optional persistence, replication, and security config blocks under `dns_update`:
  - `dns_update.persistence` (journal fsync/size/compaction controls),
  - `dns_update.replication` (role/node/NOTIFY routing controls),
  - `dns_update.security` (message/rrset/owner/rdata/ttl limits and update rate limits).
- ZoneRecords DNS UPDATE persistence now includes durable per-zone journal files, startup replay, and journal compaction primitives.
- Upstreams: support backup upstream endpoints via `upstreams.backup.endpoints` (normalized alongside primary endpoints).
- Upstreams: added `upstreams.health` tuning config (health thresholds/probes) and surfaced it in admin upstream status payloads.
- Upstreams: added `upstreams.health.profile` to apply built-in upstream health preset bundles from `upstreams_health_profiles.yaml`.
- Admin UI: added AccessControl and RateLimit plugin snapshot endpoints and UI descriptors.
- Plugins: added `targets.rcodes` support for post-resolve plugin targeting.

- Rate limit configuration warning: Foghorn now warns at startup when listeners bind to non-loopback addresses without a rate_limit plugin configured. This provides operators guidance for DoS protection on exposed deployments.
- Tooling: added `scripts/dump_effective_config.py` and `foghorn.config.config_dump` helpers to render an "effective" config (variables expanded + core runtime defaults made explicit) as YAML or JSON for debugging.
- Runtime: added a dedicated bounded background executor controlled by `server.limits.bg_executor_workers` for non-resolver background tasks.
- Plugins/config: added plugin profile preset loading helpers plus built-in RateLimit profile presets (default/single/lan/smb/enterprise) and an example configuration demonstrating profile selection and per-field overrides.
- Plugins/config: include built-in `*_profiles.yaml` in installed distributions so presets can be loaded via package resources.
- ZoneRecords: added `path_allowlist` support for `file_paths`/`bind_paths`, plus zone suffix and NSEC3 owner indexes to speed authoritative lookups and DNSSEC negative-proof matching.
- ZoneRecords AXFR: added polling controls (`poll_interval_seconds`, `axfr_poll_min_interval_seconds`) plus transfer safety limits (`max_rrs_per_zone`, `max_bytes_per_zone`, retry/backoff controls, and public/private upstream gating).
- AXFR transport: added hard per-transfer caps (`max_rrs`, `max_total_bytes`) with explicit transfer errors when exceeded.
- RateLimit: added `stats_window_seconds` to support window-scoped periodic summary logging and aggregation.
- Tests: added focused coverage for AXFR size caps, ZoneRecords helpers/journal edge paths, DNS name helpers, and background executor behavior.

- ZoneRecords plugin: Implemented DNS UPDATE (RFC 2136) with full RFC 2136 support:
  - Prerequisite evaluation checks for RRset existence/nonexistence and name in use.
  - Update operations: ADD/DELETE/REPLACE semantics for RRs and RRsets with atomic commits.
  - Per-key (TSIG) and per-token (PSK) scopes: allow/block updated names and allow/block A/AAAA values.
  - TSIG authentication enforcement with algorithm and fudge validation.
  - Name/value authorization checks against configured allow/block lists.
  - Client IP authorization via `allow_clients` and `allow_clients_files`.
  - Zone-boundary checks: all operations confined to configured zone apex.
  - Tooling: `make gen-tsig-key` and `make gen-psk-token` to generate secrets and config snippets.
  - Documentation: added DNS UPDATE docs and an example plugin config.
- Config validation: strip top-level `templates` after variable expansion so YAML authoring helpers don’t trip schema validation.
- ZoneRecords plugin: Added `minimum_reload_time` field to `axfr_zones` entries to control when AXFR zones can be reloaded, allowing load balancing between staying current and avoiding excessive upstream transfer load while still honoring NOTIFY events.
- DoS hardening:
  - Added a shared, bounded resolver executor for asyncio servers (`server.limits.resolver_executor_workers`).
  - Added asyncio TCP/DoT connection limits (`max_connections`, `max_connections_per_ip`), per-connection query caps (`max_queries_per_connection`), and idle timeouts (`idle_timeout_seconds`).
  - Added asyncio UDP listener support with in-flight caps (`server.listen.udp.use_asyncio`, `max_inflight`, `max_inflight_per_ip`, and `max_inflight_by_cidr`) and optional response ceiling (`max_response_bytes`).
  - Added DoH request size caps (GET param decode and POST body) returning HTTP 413 for oversized requests.
  - Added TCP DNS and AXFR frame size caps (length-prefixed max 65535 bytes).
  - Added recursive resolver referral-processing caps (NS names, glue records scanned, and next-hop server list).
  - Added `allow_threaded_fallback` knobs for DoH (`server.listen.doh.allow_threaded_fallback`) and the admin web UI (`server.http.allow_threaded_fallback`).
  - Added DoH parameter size validation before base64 decoding to prevent processing oversized payloads.
  - Added automated upstream health cleanup to prevent unbounded memory growth in `upstream_health` dict.
  - Reduced default recursive `max_depth` from 16 to 12 for better DoS resistance (fully configurable via `server.resolver.max_depth`).
- Config schema generation now allows optional `comment` and `id` metadata fields on object mappings, with runtime validation enforcing string type and max length (254).
- RateLimit plugin now supports `burst_windows` to cap consecutive burst windows and `stats_log_interval_seconds` for periodic summary logs.
- Resolver runtime: added `servers/dns_runtime_state.py` as a shared runtime/config state holder used across UDP handler and shared resolver/helper paths.
- Resolver pipeline: non-QUERY opcodes can now be handled by resolve plugins via `handle_opcode()` so plugins can explicitly drop, deny, or override those requests.
- Caching:
  - InMemoryTTLCache and SQLite3Cache can reserve capacity for NXDOMAIN responses (`max_size`, `pct_nxdomain`) to avoid NXDOMAIN floods evicting positive entries.
- Stats/query log:
  - Stats backends now support bounded async queues with backpressure metrics and optional `max_logging_queue` configuration.
- AXFR:
  - Added `axfr_enabled` and `axfr_allow_clients` policy gates for zone transfers.

### Changed
- ZoneRecords resolver now prioritizes UPDATE-managed RRsets over static source RRsets for the same owner, so dynamic DNS UPDATE answers win during query resolution.
- ZoneRecords resolver now refuses QTYPE=ANY by default, applies RRset/record caps with TC on oversized responses, fails closed on targets() errors, avoids per-query map copies by holding the records lock, and no longer sets AD by default on authoritative replies.
- ZoneRecords NOTIFY handling now validates per-zone upstream authorization, rate-limits senders, and coalesces AXFR refresh scheduling to reduce duplicate reloads.
- Non-QUERY opcode handling now enforces size/rate limits, validates TSIG for signed UPDATE/NOTIFY requests, and applies NOTIFY allowlist checks before plugin dispatch.
- Recursive resolver now uses the full IPv4 root hint set, validates response TXID/question matches, filters out-of-bailiwick glue, and refines per-try timeouts.
- Server response helpers now clamp cache TTLs to a max value, clamp EDNS payload sizes, and avoid mutating client OPT records while attaching EDE options.
- DockerHosts now supports TLS configuration for TCP endpoints, validates container DNS names (normalizing underscores), and optionally exposes TXT metadata in ADDITIONAL when enabled.
- Filter plugin now supports strict file loading, safe regex compilation, domain length/label caps, and deny-response fallbacks for non-A/AAAA queries.
- Admin UI config rendering now redacts URL userinfo, expands redact key matching, and uses a safe fallback sanitizer when webserver helpers are unavailable.
- Config diagram generation now expands variables prior to schema validation to match runtime parsing behavior.
- DNS UPDATE internals now track source metadata in committed RRsets and rebuild the name index after atomic update commits to keep resolver lookups in sync.
- DNS UPDATE processing now supports persisted journal replay during ZoneRecords load/reload cycles, with per-zone sequence tracking and replay metrics in plugin snapshots.
- DNS UPDATE post-commit behavior now bumps zone SOA serials and can emit NOTIFY according to replication settings.
- DNS UPDATE request handling now enforces replication role policy gates (including optional direct-update rejection on replicas) and bounded security/rate-limit controls.
- ZoneRecords NOTIFY fanout now skips local listener endpoints to prevent self-loop NOTIFY storms.
- ZoneRecords DNSSEC auto-signing now defaults to enabled when a `dnssec_signing` block is present (unless `dnssec_signing.enabled: false` is set).
- Runtime lifecycle: `main()` now runs best-effort shutdown hooks for loaded resolver plugins, cache backends, and query-log/statistics backends via `run_shutdown_plugins`.
- Plugin lifecycle: setup() now supports DNS-aware provider-first orchestration via `setup_provides_dns` / `setup_requires_dns`, allowing setup consumers to resolve hostnames using earlier resolver plugins (optionally falling back to system DNS).
- Resolver forwarding: when `forward_local` is disabled, RFC1918 IPv4 reverse PTR (`in-addr.arpa`) queries are now treated like `.local` and are not forwarded upstream.
- Upstream failover concurrency now uses a rolling bounded in-flight window (`max_concurrent`) and stops scheduling additional upstream attempts after the first successful response.
- UDP asyncio CIDR in-flight bucketing now selects the most-specific matching CIDR (largest prefixlen) rather than the strictest/smallest `max_inflight` among matches.
- RateLimit profile presets were retuned and expanded (`home`, `lan`, `smb`, `enterprise`, `localhost`), with `default` now pointing at the `lan` preset.
- RateLimit built-in profile defaults were further retuned in `rate_limit_profiles.yaml` (including `home`, `smb`, and `enterprise` thresholds), and profile resolution tests were updated to match the active defaults.
- Admin UI dark-theme form controls now use higher-contrast input/select/textarea backgrounds for search and query-log panes.
- Plugin priorities: `hooks.priority` and per-hook priorities now accept either an integer or `{priority: <int>}` shorthand; legacy `*_priority` fields remain supported.
- Plugin targeting: configuration now prefers a nested `targets` object with `ips`, `ignore_ips`, `listeners`, `domains`, `domains_mode`, `qtypes`, `opcodes`, and `rcodes` (legacy flat keys still accepted).
- Admin upstream status now reads from runtime snapshots, including backup upstreams when present.
- Upstreams health config:
  - Added `upstreams.health.profile` (preset bundles).
  - `probe_min_percent` now has a non-zero floor (0.5) to ensure unhealthy upstreams are eventually retried.
  - Removed deprecated `success_recovery` / `failure_cap` keys from the schema.

- AXFR-backed zones now respect `minimum_reload_time` and reload only when enough time has elapsed since initial load or last NOTIFY reception, or when `load_mode=replace` forces a full reload.
- ZoneRecords now owns inbound DNS NOTIFY handling through plugin opcode dispatch; server-level NOTIFY branching was removed in favor of generic non-QUERY opcode routing.
- Server NOTIFY helper names (`_resolve_notify_sender_upstream`, `_schedule_notify_axfr_refresh`) remain as compatibility wrappers and now delegate to ZoneRecords-owned implementations.
- Resolver server internals are now split into focused modules: failover transport logic moved to `servers/server_failover.py` and response/EDNS/EDE helper logic moved to `servers/server_response_utils.py`, while `servers/server.py` keeps compatibility wrapper exports.
- Resolver server internals now also extract opcode handling, upstream health payload shaping, and UDP runtime wiring into `servers/server_opcode.py`, `servers/server_upstream_health.py`, and `servers/server_runtime.py`, while preserving `servers/server.py` compatibility imports/exports.
- Config validation cleanup: removed an unreachable trailing `return None` in `config.validate_config` with no functional behavior change.
- AXFR/IXFR policy checks and transfer message construction now live in `resolve.zone_records.transfer`; server-level AXFR entry points remain as compatibility delegations to ZoneRecords-owned implementations.
- Upstreams: failover now validates upstream responses (TXID + question) and skips mismatched replies.
- Transports: UDP upstream queries now ignore unexpected response peers (best-effort defense against off-path injection).
- Cache: in-memory and SQLite caches can reserve separate capacity for NXDOMAIN responses to prevent cache pollution under NXDOMAIN floods.
- RateLimit: base-domain extraction is now Public Suffix List aware (eTLD+1) when `publicsuffix2` is available.
- RateLimit: sqlite `rate_profiles` storage is now bounded and pruned (TTL + max rows) via `max_profiles`, `profile_ttl_seconds`, and `prune_interval_seconds`.
- RateLimit: UDP keying can be made spoofing-robust via `udp_keying` (default `cidr`) and `bucket_network_prefix_v4`/`bucket_network_prefix_v6` bucketing.
- UpstreamRouter: `_forward_with_failover` now delegates to the hardened core `send_query_with_failover` implementation (TXID/question validation, transport support), avoiding inconsistent forwarding behavior.
- Stats/query log: async queue is now bounded; under sustained overload some stats operations may be dropped with DEBUG/INFO visibility via queue metrics.
- Query log stats pressure messages are now suppressed until the queue exceeds 5% utilization.
- Config dump tooling now normalizes key resolver/dnssec/http/upstream values to match runtime interpretation in effective-config output.
- Admin config reload APIs now return HTTP 409 for restart-required changes on reload-only paths rather than scheduling restart behavior.
- Performance: added LRU caches to hot-path helpers used during resolution and admin polling (ZoneRecords wildcard parsing, RateLimit base-domain extraction, AccessControl IP parsing, DoH/DoT SSL context creation, stats ignore-filter IP parsing, and webserver UTC datetime parsing).
- Admin UI: diagram rendering now prefers a light/dark PNG that matches the selected UI theme.
- Admin UI: when the config diagram PNG is unavailable, the UI now preserves the normal two-pane layout and shows Graphviz dot source in the diagram pane.
- Admin UI: light theme success messages (e.g. config save) now use higher-contrast colors.
- Admin UI: plugin snapshot groups can now include optional `className` styling, and RateLimit snapshots render dedicated configuration and profile tables (including scroll handling for larger profile sets).
- Logging: upstream skip de-duplication messages are now logged at WARNING (de-duplicated; emitted once per upstream key until a success clears the warned state).
- Logging: added ANSI-highlighted console rendering (timestamps, levels, key/value tokens, IP/port, plugin markers, quoted/path-like values) with a top-level `color` toggle while file/syslog output remains non-colored.
- Logging: BracketLevelFormatter now highlights bracketed SHA1-style values (short+long forms) alongside existing bracketed container-id rendering.
- Diagrams: config diagram source and PNG rendering now use Graphviz (`dot`) (replacing Mermaid/mmdc).
- Diagrams: added a dark-theme diagram PNG endpoint.
- Diagrams: dot output styling now defaults to a sans font, uses a Graphviz colorscheme, and applies light/dark-aware shading for resolver/upstream/plugin clusters.
- Docker image: install `graphviz` (`dot`) to support diagram rendering.
- Docker image: install `publicsuffix2` to support PSL-aware RateLimit base-domain extraction in container builds.
- Config: variable names now allow mixed-case identifier keys (`[A-Za-z_][A-Za-z0-9_]*`) instead of only all-caps keys.
- Config: upstream TLS `ca_file` paths are now validated at startup (existence/readability/CA bundle validity), with `abort_on_fail` / `abort_on_failure` controlling fatal vs warning behavior.
- Config: `server.listen.host` / `server.listen.port` and `server.listen.dns.udp` / `server.listen.dns.tcp` are now rejected as obsolete; use `server.listen.dns.host` / `server.listen.dns.port` plus per-listener sections.
- Runtime internals: refactored `foghorn.main` startup/shutdown flow into focused helper functions (argument parsing, listener normalization, resolver/upstream parsing, cache/stats initialization, runtime snapshot setup, DNSSEC resolver wiring, and signal-handler install) while preserving `main()` behavior and public wrappers.
- Runtime/config parity: listener default host/port handling is now aligned across startup, effective-config dump output, rate-limit exposure checks, and config-diagram extraction.
- Config CLI/runtime: added `--skip-schema-validation` (unsafe) to allow explicit startup without JSON Schema checks while preserving config normalization.
- Config validation: startup now fails closed when the JSON schema file cannot be found/parsed or `jsonschema` is unavailable (unless schema validation is explicitly skipped).
- Logging/transport diagnostics: DoT and admin TLS failure warnings now include richer certificate/key/CA context with likely-cause hints.
- Failover diagnostics: upstream skip/failure logging now includes stable upstream identity labels and health context summaries.
- Upstream failover connection-refused warnings are now throttled under sustained failures to reduce repetitive log noise.
- Admin UI: plugin table rendering now supports client-side searchable sections, and rate-limit snapshots include config item details.
- Resolver forward-local gating now uses a cached helper for `.local` and RFC1918 PTR block checks in the hot path.
- Config interpolation now ignores non-ALL_CAPS keys defined in top-level `variables`/`vars` (allowing mixed-case entries to be used as YAML anchors without interpolation effects).
- Startup banner logging now includes a stable config-file fingerprint (`config_sha256`) derived from config file contents, with a safe fallback to `unknown` when file hashing fails.
- Plugin signals: startup/runtime signal dispatch now prefers a unified `handle_sigusr(sig_label)` hook while retaining legacy compatibility paths.
- Makefile `docker-run` now exports `LISTEN` and `LISTEN_PORT` environment variables into the runtime container.
- RateLimit defaults now use `./config/var/dbs/rate_limit.db` for profile storage across runtime helpers, examples, and API output.
- Server EDNS behavior now preserves client EDNS/DO-bit intent and avoids synthesizing OPT records when the request did not include EDNS.
- Upstream selection now uses backup upstreams only when all primaries are degraded, with updated failover logging thresholds to reduce noisy warnings.
- FileDownloader now supports configurable upstream HEAD-check policies (`always`, `half_age`, `stale`, `never`) and delayed startup refresh when list files are still fresh.
- Filter list loading now uses persistent file metadata/fingerprint tracking so unchanged allow/block files are skipped across reloads.
- ZoneRecords AXFR polling now clamps configured intervals to a minimum floor and coordinates reload contention via a reload lock.
- Logging formatter now shortens `foghorn.*` logger names in console output, and Influx query-log writes now validate session/timeout/timestamp inputs more defensively.

### Fixed
- Upstream failover: fixed a crash in the connection-refused warning path when upstream-health data was missing/malformed.
- Upstream failover: hardened response validation to reject upstream replies with an empty question section.
- UDP listener overload shedding: worst-case SERVFAIL fallback now constructs a minimal 12-byte DNS header response without parsing the query (preserving TXID when possible).

- DNS UPDATE TSIG parse/verification failures now return protocol-correct UPDATE responses with `NOTAUTH` (instead of malformed opcode handling), including improved TSIG failure diagnostics.
- DNS UPDATE authorization now enforces per-key/per-token `allow_names` and `allow_update_ips` scope (combined with zone-level policy), preventing out-of-scope updates from being accepted.
- ZoneRecords DNS UPDATE now rebuilds wildcard-owner indexes after update commits, so wildcard UPDATE owners (for example `*.foo.dyn.zaa`) are immediately used during resolution.

- ZoneRecords DNSSEC: improved NSEC3 denial-of-existence handling so NODATA responses only include relevant NSEC3 proofs.
- Diagrams: upstream routes now handle template variable hosts (e.g., `${host}`) by showing placeholder when host is a template variable and transport/port are present.
- Diagrams: endpoint protocol tracking now correctly classifies dot/doh/tcp/udp for security styling, defaulting to insecure when protocols cannot be determined.
- Diagrams: config diagram endpoints now expose `.dot` source consistently.
- Diagrams: routed upstreams now render as color-coded nodes inside the upstreams cluster based on security level (secure vs insecure), with dashed connections from plugins to their routed upstreams.
- Diagrams: deny and override edge labels now use multi-line format (e.g., `deny\nIP`, `override\nwire reply`) with proper DOT escaping.
- Diagrams: listener extraction now treats an explicitly present listener block (`udp`/`tcp`/`dot`/`doh`) as implicitly enabled unless `enabled: false` is set.
- ZoneRecords DNSSEC negative-response helpers now handle source-aware RRset entries `(ttl, values, sources)` to avoid tuple-unpacking errors.
- Server internals: migrated remaining shared runtime attribute access away from `DNSUDPHandler` class state to `DNSRuntimeState`, reducing transport coupling and improving helper/test isolation.
- DNSSEC: `ensure_zone_keys` now searches fallback relative key directories (including `config/.config` cwd patterns) before concluding keys are missing when generation is disabled.
- Main signal handling: fixed SIGUSR reset-flag comparisons so `sigusr1_resets_stats` / `sigusr2_resets_stats` gating is evaluated correctly.
- Makefile `run` and `docker-run` now pass `LISTEN_PORT` correctly (fixing `docker-run` mistakenly reusing `LISTEN`).
- Logging formatter bracket-highlighting now more reliably identifies SHA1-style IDs and bracketed container IDs.
- ZoneRecords journal persistence now hardens zone-name normalization, actor/action validation, entry-size limits, and manifest sequence tracking to reduce replay/compaction corruption risk.

### Tests
- Added ZoneRecords TSIG update tests covering pluggable `key_sources` resolution paths.
- Added ZoneRecords DNS UPDATE persistence tests for journal append/replay/compaction and restart replay behavior.
- Added Docker-marked cluster-oriented tests for single-writer shared journal convergence and replica direct-write refusal.
- Added web/admin route coverage asserting `/api/v1/config/schema` and `/config/schema` return matching schema payloads in both FastAPI and threaded modes.
- Added DNS UPDATE regression tests for TSIG bad-key handling, TSIG algorithm mismatch responses, and key-scoped `allow_names` enforcement (including wildcard scope matches).
- Added DNS UPDATE regression coverage for wildcard-owner index rebuilds after update commits.
- Added lifecycle tests for `run_shutdown_plugins()` and main-loop shutdown hook invocation.
- Added failover concurrency regression coverage to verify bounded in-flight scheduling and no unnecessary later-upstream attempts after early success.

- Updated upstream failover coverage to assert DEBUG-level (de-duplicated) skip logs for malformed upstream responses.
- Added NOTIFY regression coverage to ensure local self-loop targets are skipped.
- Added DNSSEC regression coverage to assert NXDOMAIN authority output when auto-signing is explicitly disabled.
- Added branch-coverage tests for ZoneRecords UPDATE/TSIG branches, asyncio UDP CIDR inflight limits, web admin config/diagram edge paths, and config/security helper normalization behavior.
- Updated ZoneRecords resolver and server EDE-path tests to assert plugin-owned NOTIFY behavior and explicit ZoneRecords plugin loading for NOTIFY opcode coverage.
- Added targeted branch tests for server opcode handling fallback paths, DNSServer runtime wiring/defensive defaults, upstream-health payload shaping, and expanded DoT server branch coverage.
- Added regression coverage for obsolete listener-key validation, listener default normalization consistency, and relative DNSSEC key-dir fallback lookup behavior.
- Updated `tests/test_main_additional_coverage.py` fixtures to use `server.listen.dns.host` / `server.listen.dns.port` so startup-path tests no longer rely on obsolete `server.listen.host` / `server.listen.port` keys.
- Added config schema validation tests covering accepted/rejected `comment` and `id` metadata values (type and length constraints).

### Documentation
- Updated README and plugin docs/examples to reflect the nested `targets` config and hook priority shorthands.

- Updated ZoneRecords docs to clarify source precedence order and AXFR reload timing behavior.
- Added Graphviz `dot` rendering instructions for config diagrams.
- Documented DEBUG-level upstream skip/failover logs and de-duplication behavior in the README.
- Updated rate-limit README/docs/examples/API references for `burst_windows`, `stats_log_interval_seconds`, and the new default DB path.

----

Note: v0.6.5 was pulled due to a breaking bug.

> Release notes for changes between **v0.6.4** and **v0.6.5**.

### Added

- Added `foghorn.stats` package providing a thread-safe `StatsCollector`, a SQLite-backed `StatsSQLiteStore`, and a background `StatsReporter`.
- Added generic resolve-plugin admin UI snapshots via `BasePlugin.get_http_snapshot()`.
- Added ZoneRecords admin snapshot payload (`ZoneRecords.get_http_snapshot()`) including per-record source labels.
- Added `scripts/generate_config_diagram.py` to generate a Graphviz dot diagram of plugin ordering and short-circuit behavior from a config file.
- `scripts/generate_config_diagram.py`: added diagram rendering knobs (`--direction`, `--font-size`, `--node-spacing`, `--rank-spacing`, `--no-init`) and config-derived listener/upstream summaries.
- Admin web UI: added a config diagram PNG generated on startup (when possible) and served at `/api/v1/config/diagram.png`.
- Admin web UI: added a Graphviz dot source endpoint for the config diagram at `/api/v1/config/diagram.dot`.
- Admin web UI: added a config diagram upload endpoint at `POST /api/v1/config/diagram.png`.
- Admin web UI: updated the "JSON & Config" tab to show the config diagram (left) and config YAML (right).
- Admin web UI: added server-side paginated table data for stats via `/api/v1/stats/table/{table_id}` (supports paging, sorting, and search).
- Admin web UI: added server-side paginated table data for cache via `/api/v1/cache/table/{table_id}`.
- Admin web UI: added server-side paginated table data for plugin admin tables via `/api/v1/plugins/{plugin_name}/table/{table_id}`.
- Config diagram generation now splits listeners and upstream endpoints into individual nodes, and highlights secure transports (DoT/DoH) vs insecure (UDP/TCP).
- Filter plugin: added `deny_response: drop` to allow silently dropping denied queries (no reply).
- ZoneRecords (`zone`) now supports configurable reload semantics via `load_mode` and conflict handling via `merge_policy`.
- ZoneRecords now supports wildcard owner patterns (`*` labels) in record sources, selecting a single best match based on leading-wildcard depth.
- ZoneRecords can now be configured with `load_mode=first` to select the first configured source group (files, BIND zonefiles, AXFR, or inline) and ignore the others.
- BIND zonefile entries under `bind_paths` can now override `$ORIGIN` and `$TTL` via per-entry `origin`/`ttl` settings; in-file `$ORIGIN`/`$TTL` directives are ignored with a warning when overridden.
- Added `nxdomain_zones` to force NXDOMAIN/NODATA under selected suffixes when a name is not present in ZoneRecords, instead of falling through to upstream.
- Added `example_configs/plugin_zone.yaml` and expanded `example_configs/kitchen_sink.yaml` to demonstrate ZoneRecords options.

### Changed

- `server.resolver.mode: none` is now treated as an alias for authoritative-only operation (master mode): queries do not recurse/forward.
- Filter plugin now normalizes domain keys (case/trailing-dot) for consistent allow/deny and record handling.
- Resolve Echo plugin class renamed from `EchoPlugin` to `Echo`.
- Refactored `scripts/generate_config_diagram.py` to use shared library code under `foghorn.utils.config_diagram`.
- MySQL/MariaDB cache and stats backends now support explicit driver selection and fallback policy (`driver`, `driver_fallback`).
- `EtcHosts.watchdog_poll_interval_seconds` now defaults to `60.0` to enable a stat-based reload fallback when filesystem events are unreliable.
- Regenerated `assets/config-schema.json` (via `scripts/generate_foghorn_schema.py`) to reflect updated resolver options and plugin config models.
- Refactored ZoneRecords implementation into `foghorn.plugins.resolve.zone_records` package modules for clearer separation of loader/resolver/watchdog/AXFR helpers.
- Refactored `cache.postgres_cache` to delegate to the `PostgresTTLCache` backend, with a more explicit key/TTL/value API and stable key hashing for non-bytes keys.
- Packaging now includes the built-in admin web UI assets in installed distributions.
- Foghorn can now start in minimal/headless environments without importing FastAPI or dnspython at module import time. DNSSEC local validation, DoH, and the admin web UI are imported only when enabled in configuration.
- Resolve plugin discovery skips plugins with missing optional dependencies by default (with improved error messages). Set `abort_on_failure: true` in a plugin's config to make missing dependencies fatal, or set `FOGHORN_STRICT_PLUGIN_DISCOVERY=1` for strict discovery.

### Fixed

- Filter allow/deny behavior is now consistent across mixed-case names and trailing-dot variants.
- Authoritative-only resolver behavior now returns REFUSED with an EDE explanation instead of attempting upstream resolution.
- Reduced log spam in upstream failover by emitting upstream skip warnings once per upstream target.
- The admin config diagram endpoint now attempts on-demand generation/refresh (when `dot` is available) if the PNG is missing or stale.
- Config diagram PNG generation now uses an atomic replace to avoid leaving partially-written files on render failure.
- The admin `/config` endpoint now supports `server.http.redact_keys` as a compatibility fallback when `webserver.redact_keys` is not set.
- Redacted YAML output now quotes the placeholder (`'***'`) to ensure redacted config output remains parseable.
- Fixed config diagram generation when resolver mode is `master` (authoritative-only / no forwarding).

### Tests

- Updated echo/filter tests to match the rename and domain normalization.
- Added tests asserting plugin/ZoneRecords admin snapshots are JSON-safe.
- Added pipeline tests for master/none authoritative-only behavior.
- Extended ZoneRecords test coverage for merge/overwrite behavior, first-mode semantics, BIND override warnings, and `nxdomain_zones`.
- Added ZoneRecords wildcard matching tests, including ensuring blank names do not match `*`.
- Added focused unit tests for ZoneRecords AXFR polling, NOTIFY helpers, and transfer snapshot helpers.
- Added cache backend tests covering stable key hashing, bytes vs pickle storage, and the updated `PostgresCache` API.
- Hardened MySQL/MariaDB backend tests against environments where the `mariadb` driver is installed.
- Updated webserver tests for config diagram generation/refresh and redact-key compatibility (`server.http.redact_keys`).
- Added additional branch-coverage tests for DNSSEC validation helpers and resolve plugin targeting/echo behavior.

### Documentation

- Updated Filter plugin docs to include `deny_response: drop`.
- Updated ZoneRecords plugin docs and README examples to document the new options.
- Updated the README test/coverage badges.
- Added developer documentation note about regenerating `assets/config-schema.json` when plugin config models change.

## [0.6.4] - 2026-02-05

> Release notes for changes between **v0.6.3** and **v0.6.4**.

### Added

- Added `forward_local` server configuration option to control whether `.local` queries are forwarded to upstream resolvers. When disabled (default), `.local` queries return NXDOMAIN with an RFC 6762 EDE note unless answered by a plugin like MdnsBridge.
- Extended MdnsBridge plugin to synthesize service-type PTR records from the SRV cache when explicit PTRs are missing, enabling DNS-SD enumeration for discovered services.
- Added browse-name aliasing in MdnsBridge to map `_dns_sd._tcp.<suffix>` and `_tcp.<suffix>` queries to their RFC 6763 equivalents.
- Added AXFR NOTIFY configuration options for the `resolve.zone_records` plugin, plus example configuration for AXFR client/server usage.
- Added `dnssec.zone_helpers` module and an AXFR/DNSSEC overlay for the `resolve.zone_records` plugin so signed zones from AXFR-aware upstreams and tooling can be consumed and served with DNSSEC data.
- Added shared DNS-over-HTTPS parsing and validation logic for the DoH API.
- Added a debugging plugin `echo` (config + tests).  It returns a `TXT` record of the qname and qtype.
- HTTP webserver implementations split into core (asyncio) server, threaded server, runtime, routing, and helper modules.

### Tests

- Added tests for `forward_local` behavior in the query resolution pipeline, covering blocked and allowed `.local` forwarding scenarios.
- Added comprehensive tests for MdnsBridge DNS-SD aliasing and PTR fallback enumeration from SRV cache.
- Added unit tests for the `ssh_keyscan` utility module covering key fetch, error handling, and SSHFP record generation.
- Added tests covering AXFR NOTIFY behavior in ZoneRecords, including ensuring NOTIFY sends the expected AXFR.
- Extended `tests/plugins/test_zone_records.py` to cover reload-triggered NOTIFY behavior and ensure both static and learned NOTIFY targets are exercised.

### Changed

- Refactored the `resolve.zone_records` plugin to snapshot zone state across reloads, compute changed zones, and send DNS NOTIFY only for zones that changed, including DNSSEC-aware helpers for serving signed RRsets.
- Migrated the webserver runtime and routes to the new core implementation and removed the legacy `_core` module.
- Threaded `client_ip` through AXFR iterators.

### Fixed

- DNSSEC is now only applied when requested and enabled.
- Routed DoH API parsing through shared parsing/validation logic to keep behavior consistent.

### Documentation

- Updated README configuration examples and the test coverage badge.

## [0.6.3] - 2026-01-19

> Release notes for changes between **v0.6.2** and **v0.6.3**.

### Added

- Added configurable DNSSEC signing for zones via a new `ZoneDnssecSigningConfig` block, including algorithm selection, keys directory, enable/disable flag, and validity controls.
- Introduced enhanced DNSSEC-aware behavior in the `resolve.zone_records` plugin, including precomputed mappings for RRsets and RRSIGs and DO-bit-aware responses.
- Added automatic PTR record generation from A/AAAA records in `resolve.zone_records` when configured.
- Added an `sshfp_scan` helper script and `ssh_keyscan` utility module for generating SSHFP records from remote hosts.
- Marked authoritative responses from `resolve.zone_records` as authenticated (AD=1) when they come from signed zones, so DNSSEC-aware stub resolvers and tools like OpenSSH (when combined with `trust-ad`) can rely on them.

### Changed

- Updated the DNSSEC zone signer helper to normalize zone origins, ensure apex nodes exist, and consistently construct DNSKEY and RRSIG RRsets for signed zones.
- Refined `resolve.zone_records` DNSSEC handling so RRSIG and DNSKEY data is surfaced only when appropriate and existing behavior is preserved when DNSSEC helpers are unavailable.
- Improved `resolve.zone_records` DNSSEC answer construction so that, where possible, RRSIGs are attached directly alongside their covered RRsets in the ANSWER section with sensible TTLs.

### Fixed

- Allowed BasePlugin-level options such as `targets`, `targets_domains`, and per-plugin `logging` to flow through the typed `ZoneRecordsConfig` by relaxing its `extra` handling, fixing validation failures for common configs.
- Fixed SOA synthesis and apex inference for SSHFP-only or partial zones so that `resolve.zone_records` can infer a reasonable zone apex and behave authoritatively (including DNSSEC auto-signing) even when no explicit SOA is present.
- Normalized DNSSEC owner names for apex DNSKEY/RRSIG RRsets so that signed material is stored under the real zone apex instead of BIND-style `@` owners, ensuring later lookups can find and serve DNSSEC data correctly.
- Corrected `resolve.zone_records` DNSSEC answer paths so RRSIG records for A/SSHFP and other RRsets are returned in the ANSWER section alongside their covered records and inherit the RRset TTL by default.
- Updated `resolve.zone_records.pre_resolve` to honor BasePlugin client, listener, and domain targeting helpers (`targets`, `targets_listener`, and `targets_domains`), so zone data is only applied to matching queries.

### Tests

- Extended `tests/plugins/test_zone_records.py` to cover DNSSEC mappings, DO-bit behavior, SOA synthesis, automatic PTR generation, and the new targeting/normalization behaviors.
- Added tests for the new `sshfp_scan` script and `ssh_keyscan` utility under `tests/scripts`, validating SSHFP output and error handling.

### Documentation

- Updated Makefile documentation to match current targets and DNSSEC/tooling helpers.
- Refreshed `zone_records` plugin documentation to describe DNSSEC, PTR auto-generation, targeting, and SSHFP interactions.
- Updated Pihole and RFC-style documentation to reflect the new DNSSEC tooling and behavior.
- Documented glibc `trust-ad` behavior in `README.md`, including how to configure `/etc/resolv.conf` so glibc-based applications such as OpenSSH can accept the AD bit from a validating Foghorn instance.

## [0.6.2] - 2026-01-17

> Release notes for changes between **v0.6.1** and **v0.6.2**.

### Added

- Introduced a shared `dnssec.zone_signer` helper module that centralizes DNSKEY/key management, zone signing, and DS record generation for tools and plugins.
- Added optional DNSSEC auto-signing support to the `resolve.zone_records` plugin via a `dnssec_signing` configuration block.
- Extended top-level Makefile targets to drive DNSSEC key and zone signing workflows.
- Added RFC8914 Extended DNS Errors (EDE) support throughout the resolver, controlled by a new `server.enable_ede` flag, and wired into stats snapshots and the admin UI.
- Added AXFR and IXFR support, including a TCP/DoT AXFR transport client, ZoneRecords AXFR integration, and example configs/tests for full-zone transfers.
- Added SSH host key utilities and resolver plugin, SSHFP/OPENPGPKEY record support in zones.
- Added DNSSEC-aware AXFR upstream helpers and signing automation for BIND-style zones consumed by `resolve.zone_records`.

### Changed

- Refactored the `scripts/generate_zone_dnssec.py` into `dnssec.zone_signer`, now it's just a wrapper.
- Tightened DNS server failover, EDNS handling, and DNSSEC validation logging to make error behavior and diagnostics more robust.
- Treated TCP connection resets as short reads in the network stack to reduce spurious errors when clients close connections abruptly.
- Updated packaging metadata, Makefile helpers, and coverage settings to support the new DNSSEC, EDE, and AXFR tooling while keeping CI artifacts out of the tree.

### Documentation

- Updated DNSSEC and zone plugin documentation to describe the new signing helpers and configuration options.
- Documented RFC8914 EDE behavior, how to enable it in configuration, and how it appears in stats and the admin UI.
- Expanded AXFR/IXFR documentation, including examples for ZoneRecords participation in full-zone transfers and DNSSEC-aware AXFR upstreams.
  - IXFR requests are answered with AXFR.
  - No client support for IXFR yet.
- Documented new OpenSSL/SSHFP helpers and resolver plugins, refreshed DNS RFC compliance notes, and updated screenshots and BMC imagery.
- Tweaked README status badges and coverage badge styling.

## [0.6.1] - 2026-01-09

> Release notes for changes between **v0.6.0** and **v0.6.1**.

### Added

- Listener and security context (`listener`, `secure`) are now threaded through the resolve pipeline and exposed in recorded query results and stats.
- Resolve plugins can now target specific listeners (for example, `udp`, `tcp`, `dot`, `doh`) using `targets_listener`, including convenient aliases such as `secure` and `unsecure`.
- Resolve plugins can optionally target specific domains using `targets_domains` with exact and suffix matching modes, and new example configuration has been added to demonstrate these options.
- The MDNS resolver now exposes richer snapshot information, including instance HTML/URLs and refined columns in the admin web UI.
- New example resolve plugins ("file over DNS" and "finger") were added under `foghorn.plugins.resolve.examples`, along with tests.
- The `zone` records plugin can now load RFC‑1035 style BIND zonefiles via `bind_paths` and merge them with inline and file-based records into a single authoritative view.

### Changed

- EDNS and DO-bit handling for UDP responses was tightened to respect DNSSEC mode, clamp payload sizes to server limits, and synthesize OPT records when appropriate.
- Large non-EDNS UDP responses now set the TC flag instead of silently truncating without signaling the client.
- SERVFAIL responses created when no upstreams are available now preserve client EDNS OPT records where possible.
- MDNS plugin behavior around default service types and domain suffix handling was refined for more predictable snapshots.
- Latency histogram buckets were expanded to give more resolution across slower queries.
- Example plugin filter configuration was updated to use the new targeting options and defaults.
- TTL cache behavior was refined across the in-memory, SQLite, and Foghorn TTL backends to keep expiry and registry semantics consistent.

### Fixed

- Fixed several edge cases where EDNS OPT records or DO bits could be lost or misapplied in error and SERVFAIL paths.
- Corrected UDP handling for large answers without EDNS so that clients reliably see TC=1 and can retry over TCP.
- Hardened cache, resolver, server, and transport test coverage, especially where EDNS and cache behavior interact, to catch more edge cases.

### Documentation

- Updated the top-level README and developer documentation to describe listener/security context, plugin targeting options, EDNS behavior, and the new zone/BIND zonefile support.
- Refreshed RFC-style notes to match the current resolver and transport behavior.
- Regenerated and expanded the JSON configuration schema with per-field type and default annotations to match the new options.

## [0.6.0] - 2026-01-07

> Release notes for changes between **v0.5.4** and **v0.6.0**.

### Breaking

- **Configuration files from v0.5.x (including v0.5.4) will not work as-is.** The configuration schema and layout were completely reorganized so that related settings (logging, stats, cache, plugins, etc.) live together more logically. Existing configs must be updated to the new structure before Foghorn will start.
- Internal modules, classes, and helper functions were moved and renamed for consistency. Any code that imports Foghorn internals or provides out-of-tree plugins must be updated to use the new module paths and class/function names.
- Example resolver filters (such as DNS prefetch, example rewrites, greylist, and new-domain WHOIS filters) were moved under `foghorn.plugins.resolve.examples` and are no longer wired into a running server by default. Configurations that referenced these example plugins must be updated and explicitly wired in.
- The legacy plain-text `CHANGELOG` file was removed in favor of this Markdown changelog.

For high-level migration guidance, see the **"Upgrading from 0.5.x to 0.6.0"** section in `README.md`.

### Added

- **Backend-based stats and query-log persistence**
  - Introduced a unified backend model for statistics and query logging, driven by the `logging.backends` and `stats` configuration blocks.
  - Added database-backed statistics and query-log backends, including support for relational stores and other persistent targets.
  - Added a JSON query-log backend for file-based query logging.
  - Added an MQTT-backed query-log/statistics backend for shipping DNS metrics and events over MQTT.

- **Background async logging and stats workers**
  - Introduced an async worker and `MultiStatsStore` fan-out for stats backends.
  - Controlled by the new `logging.async` toggle; when enabled, writes to stats/query-log backends happen in the background so request handling stays fast.
  - Tests and configuration validation were updated to cover the async worker model and its error handling.

- **New cache backends and controls**
  - Added MongoDB and Memcached TTL cache backends, alongside existing memory/SQLite/Redis options.
  - Introduced decorated cache overrides and standardized cache registry names.
  - Exposed new cache controls (including decorated overrides and helper cache knobs) in the admin web UI.

- **Tooling and assets**
  - Added Makefile helpers for generating TLS keys and certificates used by DNS-over-TLS / DoH listeners and upstreams.
  - Added query-flow assets and scripts to help visualize how requests move through listeners, caches, plugins, and upstreams.
  - Expanded and refreshed example configurations for caches, logging/stats, and listeners.

### Changed

- **Logging and stats configuration**
  - Reworked logging and statistics configuration around the new backend model, so both the process-wide Python logger and persistent stats/query-log backends are configured under `logging` and `stats`.
  - Updated the configuration schema and documentation so that logging, stats, and persistence options are grouped together and share consistent naming.
  - Refreshed developer documentation and README sections to match the new model.

- **Configuration schema and validation**
  - Regenerated and hardened the combined JSON config schema, adding stricter validation and internal invariants for stats, logging, and cache configuration.
  - Improved error messages and robustness when loading the schema, including better handling of cache override rules and invalid configurations.

- **Core server layout and transports**
  - Refactored recursive resolver and transport abstractions, moving them into a more consistent layout (e.g., under `foghorn.servers.transports`).
  - Tightened wiring between UDP/TCP/DoT/DoH listeners, caches, and the resolver.
  - Updated DNSSEC validation and related tests to work with the new resolver/transport structure.

- **Plugins and examples**
  - Normalized plugin names and improved resolve plugin defaults and aliases (no functional change in most cases, but configuration and imports are now more consistent).
  - Moved resolver example plugins into a dedicated `resolve.examples` namespace and documented their usage as opt-in examples.
  - Tuned several plugins (such as DockerHosts and Filter) to work cleanly with the updated stats and cache semantics.
  - Modernized plugin example configurations throughout the docs and examples.

### Fixed

- Corrected LRU cache registry size accounting and tightened cache registry handling.
- Hardened server response ID handling for non-bytes input.
- Fixed UDP/TCP listener derivation from the `server.listen.dns` configuration.
- Hardened error handling paths in resolver plugins and transports.
- Stabilized stats backend tests around async workers and updated signal-handling tests for the new stats lifecycle.
- Added additional test coverage for config schema invariants, etc-hosts configuration, snapshots, and admin helpers.

### Documentation

- Documented the new logging/stats backend model, including examples for SQLite, MQTT, and other backends.
- Updated README and developer documentation to describe decorated cache overrides, cache registry naming, and new cache backends.
- Documented TLS key and certificate Makefile helpers and refreshed listener/upstream examples.
- Added an "Upgrading from 0.5.x to 0.6.0" section to `README.md` with concrete guidance on migrating existing deployments.

---

Older versions prior to v0.6.0 did not use this Markdown changelog; see git history for details if needed.
