# Changelog

## [0.6.0] - 2026-01-06

> This is a major, **breaking** release. Configuration files written for v0.5.x (including v0.5.4) will **not** validate or run unmodified on v0.6.0.
>
> Start from the updated examples in the README or regenerate your configuration instead of trying to reuse an old file as‑is.

### Breaking changes
- **Configuration schema fully redesigned.** The JSON schema and YAML layout were reorganized so related settings live together. Sections such as `logging`, `stats`, cache configuration, and plugin wiring now use a more regular structure.
- **Old configuration keys removed or moved.** Many fields that existed under earlier `logging`/`stats`/cache blocks were renamed or relocated. Configs that worked in v0.5.4 will fail validation until updated to the new layout.
- **Module and API reshuffle.** Transports, recursive resolver components, and helper utilities (such as cache helpers) were moved into a more consistent package layout. Several classes, functions, and registry names were normalized; any out‑of‑tree plugins or integrations that import internals from v0.5.x will need to be updated.
- **Plugin and cache registry naming normalized.** Internal and documented plugin/cache identifiers were cleaned up for consistency. Existing configs should be checked against the new names and examples.

### Added
- **Background asynchronous logging pipeline.** Stats and query‑log backends can now be driven by a background worker, controlled via the `logging.async` flag. This keeps request handling fast even with slower persistence backends.
- **Pluggable stats and query‑log backends.** The new `logging.backends` + `stats.source_backend` model supports multiple persistence mechanisms (for example SQLite, MariaDB/MySQL, PostgreSQL, MQTT, Influx, etc.) and fan‑out to more than one backend.
- **Additional cache backends.** New TTL cache implementations were added (including Memcached and MongoDB‑backed variants) alongside the existing in‑memory and SQLite options.
- **Query‑log statistics enhancements.** A dedicated MQTT‑backed query‑log statistics backend was introduced, and the default MQTT stats logging QoS was tightened for more reliable delivery.
- **Web admin and API improvements.** The admin UI and HTTP API gained controls for the new stats and logging layout, including selection of stats source backend and visibility into cache/logging configuration.
- **TLS key and certificate Makefile helpers.** New `make ssl-*` targets generate a small test CA and server certificates/keys for local TLS and DoT/DoH experimentation.
- **Developer tooling and CI.** GitHub CI workflows were added/updated, along with helper scripts and assets for visualizing query flow and keeping the generated schema up to date.

### Changed
- **Config examples and docs refreshed.** All example configurations were updated to the new schema, including listener, stats, cache, and plugin examples. The README and developer docs now describe the new logging/stats model and cache override options.
- **Transport and resolver internals refactored.** TCP/UDP transports and the recursive resolver abstraction were reorganized for clearer wiring and better test coverage, without changing intended external behaviour.
- **Plugin loading and cache injection improved.** Plugin initialization, cache registration, and default behaviour were tightened so plugins interact more predictably with the core resolver and cache.
- **Statistics semantics clarified.** The lifecycle of statistics collection and persistence was simplified, and the web/admin endpoints were aligned with the new model.

### Fixed
- Hardened DNSSEC validation and associated tests.
- More robust handling of malformed or non‑bytes server response IDs.
- Improved validation of internal config schema invariants and error messages when loading configs.
- Correct derivation of UDP/TCP listeners from DNS listen settings.
- Numerous smaller fixes across resolver plugins, transports, cache size accounting, and signal handling.