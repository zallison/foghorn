# Changelog

All notable changes to this project will be documented in this file.

## [0.6.1] - 2026-01-09

> Release notes for changes between **v0.6.0** and **v0.6.1**.

### Breaking

- The zone records resolver no longer accepts a single `file_path` option; configurations must use the `file_paths` list instead.

### Added

- Listener and security context (`listener`, `secure`) are now threaded through the resolve pipeline and exposed in recorded query results and stats.
- Resolve plugins can now target specific listeners (for example, `udp`, `tcp`, `dot`, `doh`) using `targets_listener`, including convenient aliases such as `secure` and `unsecure`.
- Resolve plugins can optionally target specific domains using `targets_domains` with exact and suffix matching modes, and new example configuration has been added to demonstrate these options.
- The MDNS resolver now exposes richer snapshot information, including instance HTML/URLs and refined columns in the admin web UI.
- New example resolve plugins ("file over DNS" and "finger") were added under `foghorn.plugins.resolve.examples`, along with tests.

### Changed

- EDNS and DO-bit handling for UDP responses was tightened to respect DNSSEC mode, clamp payload sizes to server limits, and synthesize OPT records when appropriate.
- Large non-EDNS UDP responses now set the TC flag instead of silently truncating without signaling the client.
- SERVFAIL responses created when no upstreams are available now preserve client EDNS OPT records where possible.
- MDNS plugin behavior around default service types and domain suffix handling was refined for more predictable snapshots.
- Latency histogram buckets were expanded to give more resolution across slower queries.
- Example plugin filter configuration was updated to use the new targeting options and defaults.

### Fixed

- Fixed several edge cases where EDNS OPT records or DO bits could be lost or misapplied in error and SERVFAIL paths.
- Corrected UDP handling for large answers without EDNS so that clients reliably see TC=1 and can retry over TCP.
- Hardened cache-path test coverage and related server paths where EDNS and cache behavior interact.

### Documentation

- Updated the top-level README and developer documentation to describe listener/security context, plugin targeting options, and EDNS behavior.
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