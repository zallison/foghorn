# Foghorn Developer Guide

This document is aimed at contributors and integrators who want to understand how Foghorn is wired internally: where key pieces of code live, how plugins and caches are registered, how statistics backends work, and how to regenerate the configuration schema.

## Table of Contents

- [1. High-level architecture](#1-high-level-architecture)
- [2. Code layout](#2-code-layout)
- [3. Configuration, schema and validation](#3-configuration-schema-and-validation)
  - [3.1 Base schema and generator](#31-base-schema-and-generator)
  - [3.2 How plugins contribute config schemas](#32-how-plugins-contribute-config-schemas)
- [4. Plugin systems](#4-plugin-systems)
  - [4.1 Resolve plugins](#41-resolve-plugins)
  - [4.2 Cache plugins](#42-cache-plugins)
  - [4.3 Statistics/query-log backends](#43-statisticsquery-log-backends)
- [5. DNS cache vs function caches](#5-dns-cache-vs-function-caches)
- [6. Implementing new plugins](#6-implementing-new-plugins)
  - [6.1 New resolve plugin](#61-new-resolve-plugin)
  - [6.2 New cache plugin](#62-new-cache-plugin)
  - [6.3 New stats/query-log backend](#63-new-statsquery-log-backend)
- [7. Updating the schema generator](#7-updating-the-schema-generator)
- [8. Makefile and common workflows](#8-makefile-and-common-workflows)

---

## 1. High-level architecture

The main entry point is `src/foghorn/main.py`. It is responsible for:

- Parsing CLI arguments and loading the YAML configuration via `foghorn.config.config_parser`.
- Initializing logging (`foghorn.config.logging_config.init_logging`).
- Normalizing upstreams (`normalize_upstream_config`) and loading plugins (`load_plugins`).
- Applying cache overrides for helper functions (`apply_decorated_cache_overrides`).
- Creating statistics collectors/reporters and wiring a `BaseStatsStore` backend.
- Starting listeners (UDP, TCP, DoT, DoH) and the admin webserver.

DNS resolution itself is handled by `foghorn.servers.server.DNSServer` and helpers under `src/foghorn/servers`. Resolve plugins sit around that core and can short‑circuit, modify, or observe queries.

---

## 2. Code layout

Important directories and modules:

- `src/foghorn/main.py`
  - Process entry point; orchestrates config, plugins, cache, stats, and listeners.
- `src/foghorn/config/`
  - `config_parser.py`: reads YAML, applies `vars`, validates against JSON Schema, normalizes shapes into the `server`, `upstreams`, `logging`, `stats`, and `plugins` blocks consumed by the rest of the code.
  - `logging_config.py`: logging setup and per-plugin logger helpers.
- `src/foghorn/plugins/resolve/`
  - `base.py`: `BasePlugin`, `PluginContext`, and shared helpers; owns the global `DNS_CACHE` reference by default.
  - `registry.py`: discovers resolve plugins and resolves aliases.
  - `*.py`: concrete plugins such as access control, filters, mDNS bridge, etc.
- `src/foghorn/plugins/cache/`
  - `base.py`: `CachePlugin` and `cache_aliases` decorator.
  - `registry.py`: discovers cache plugins and resolves aliases; provides `load_cache_plugin`.
  - `in_memory_ttl.py`, `sqlite_cache.py`, `redis_cache.py`, `memcached_cache.py`, `mongodb_cache.py`, `none.py`: built‑in DNS cache backends.
  - `backends/foghorn_ttl.py`, `backends/sqlite_ttl.py`: reusable TTL cache primitives.
- `src/foghorn/plugins/querylog/`
  - `base.py`: `BaseStatsStore` and `StatsStoreBackendConfig`.
  - `registry.py`: discovers stats backends and resolves aliases; provides `discover_stats_backends` and `get_stats_backend_class`.
  - `sqlite.py`, `mysql_mariadb.py`, `postgresql.py`, `mongodb.py`, `influxdb.py`, `mqtt_logging.py`: built‑in stats/query-log backends.
- `src/foghorn/utils/register_caches.py`
  - Registers decorated helper functions (`registered_cached`, `registered_lru_cached`, `registered_foghorn_ttl`, `registered_sqlite_ttl`) and applies config‑driven overrides (`apply_decorated_cache_overrides`).
- `src/foghorn/stats.py`
  - Higher-level statistics collector and reporter built on top of `BaseStatsStore`.
- `src/foghorn/servers/`
  - `server.py`: core resolver loop, UDP handler glue and adapter for plugins.
  - `udp_server.py`, `doh_api.py`, and related transport implementations.
  - `webserver.py`: admin HTTP API and UI, plus `RuntimeState` and log buffer.

---

## 3. Configuration, schema and validation

### 3.1 Base schema and generator

Foghorn validates configuration using a JSON Schema document in `assets/config-schema.json`. This file must not be edited directly in code or by hand.

Instead, the project uses a generator script:

- `scripts/generate_foghorn_schema.py`
  - Loads the existing base schema from `assets/config-schema.json`.
  - Discovers resolve plugins via `foghorn.plugins.resolve.registry.discover_plugins()`.
  - For each plugin, obtains a configuration model or explicit schema and attaches it under `$defs.PluginConfigs`.
  - Normalizes top-level layout (`vars`, `server`, `upstreams`, `logging`, `stats`, `plugins`) and ensures helper definitions such as `DecoratedCacheOverride`, `PluginInstance`, `upstream_host`, and `upstream_doh` are present.

When you make changes that affect configuration shape, regenerate the schema with either:

```bash
# From the project root
./scripts/generate_foghorn_schema.py -o assets/config-schema.json
# or
make schema
```

### 3.2 How plugins contribute config schemas

Plugins can participate in schema generation in two ways:

1. **Typed config model**
   - Implement a `get_config_model()` `@classmethod` that returns a Pydantic `BaseModel` subclass.
   - The generator calls `model_json_schema()` (Pydantic v2) or `schema()` (v1) and embeds the result.

2. **Raw JSON Schema**
   - Implement a `get_config_schema()` `@classmethod` that returns a `dict` JSON Schema.

The generator prefers `get_config_model()` when present, then falls back to `get_config_schema()`.

---

## 4. Plugin systems

### 4.1 Resolve plugins

Resolve plugins live under `src/foghorn/plugins/resolve` and subclass `BasePlugin`.

Key pieces:

- `BasePlugin` in `resolve/base.py`:
  - Handles per-instance name, logging, and priorities (`pre_priority`, `post_priority`, `setup_priority`).
  - Implements client targeting via `targets()` using CIDR lists (`targets` and `targets_ignore`).
  - Implements qtype targeting via `targets_qtype()`.
  - Provides hook methods:
    - `pre_resolve(qname, qtype, req, ctx)`
    - `post_resolve(qname, qtype, response_wire, ctx)`
    - `setup()`, `handle_sigusr2()`, and optional admin UI descriptor.
- `plugin_aliases()` decorator in `resolve/base.py` assigns short aliases used in configuration.
- `resolve/registry.py`:
  - Walks the `foghorn.plugins` package using `pkgutil.walk_packages`.
  - Registers each `BasePlugin` subclass under a default alias derived from its class name plus any explicit `aliases` attribute.
  - `get_plugin_class()` resolves identifiers either as aliases or dotted import paths.

Built‑in resolve plugins include (by alias only):

- `acl`, `prefetch`, `docker`, `hosts`, `examples`, `lists`, `filter`, `flaky`, `greylist_example`, `mdns`, `new_domain`, `rate`, `router`, `zone`.

### 4.2 Cache plugins

Cache plugins live under `src/foghorn/plugins/cache` and subclass `CachePlugin`.

- `CachePlugin` in `cache/base.py` defines the DNS cache interface:
  - `get(key)`, `get_with_meta(key)`, `set(key, ttl, value)`, `purge()`.
- `cache_aliases()` decorator assigns short aliases used in configuration.
- `cache/registry.py`:
  - Walks `foghorn.plugins.cache` and registers each `CachePlugin` subclass under a default alias plus explicit aliases.
  - `load_cache_plugin()` accepts `None`, a string alias/path, or a small mapping and returns a configured cache instance.

Built‑in DNS cache plugins include aliases such as:

- `memory` (in-memory TTL cache)
- `sqlite` / `sqlite3`
- `redis` / `valkey`
- `memcached` / `memcache`
- `mongodb` / `mongo`
- `none` / `null` / `off` / `disabled` / `no_cache`

### 4.3 Statistics/query-log backends

Statistics and query-log backends live under `src/foghorn/plugins/querylog` and subclass `BaseStatsStore`.

- `BaseStatsStore` in `querylog/base.py` defines the contract used by `StatsCollector` and the web UI.
- `querylog/registry.py`:
  - Walks `foghorn.plugins.querylog` and registers each `BaseStatsStore` subclass under a default alias plus explicit aliases.
  - `get_stats_backend_class()` resolves aliases or dotted import paths.
  - `load_stats_store_backend()` builds one or more backends from the `stats.persistence` config and wraps multiple backends in a `MultiStatsStore` when needed.

Built‑in backends include aliases such as:

- `sqlite`, `sqlite3`
- `mysql`, `mariadb`
- `postgres`, `postgresql`, `pg`
- `mongo`, `mongodb`
- `influx`, `influxdb` (logging‑only)
- `mqtt`, `broker` (logging‑only)

---

## 5. DNS cache vs function caches

There are two distinct caching layers in Foghorn:

1. **DNS response cache** (configured via `server.cache`)
   - Implemented by `CachePlugin` subclasses.
   - Used by the resolver to cache full DNS responses keyed by `(qname, qtype)`.
   - Backends such as the in-memory TTL cache, SQLite, Redis, Memcached, and MongoDB share the same interface.

2. **Function/helper caches** (configured via `server.cache.modify` / `decorated_overrides` / `func_caches`)
   - Implemented in `foghorn.utils.register_caches`.
   - Helpers such as `registered_cached`, `registered_lru_cached`, `registered_foghorn_ttl`, and `registered_sqlite_ttl` wrap individual functions or methods.
   - Each decorated function creates a registry entry containing module, name, backend type (`ttlcache`, `lru_cache`, `foghorn_ttl`, `sqlite_ttl`, `lfu_cache`, `rr_cache`), TTL and maxsize hints, and hit/miss counters.
   - `apply_decorated_cache_overrides()` reads an array of overrides from configuration and can adjust TTL or maxsize at runtime without code changes.

The JSON Schema exposes a `DecoratedCacheOverride` definition and adds two array properties under `server.cache`:

- `decorated_overrides`: legacy name for overrides.
- `modify`: preferred name; both share the same item schema.

Example override snippet:

```yaml
server:
  cache:
    modify:
      - module: foghorn.dnssec.dnssec_validate
        name: dnssec_validate
        backend: ttlcache          # ttlcache | lru_cache | foghorn_ttl | sqlite_ttl | lfu_cache | rr_cache
        ttl: 300
        maxsize: 1024
        reset_on_ttl_change: true
```

---

## 6. Implementing new plugins

### 6.1 New resolve plugin

Minimal steps to add a new resolve plugin:

1. Create a module under `src/foghorn/plugins/resolve`, for example `my_feature.py`.
2. Subclass `BasePlugin` and assign aliases using `plugin_aliases`.
3. Implement one or more hooks: `pre_resolve`, `post_resolve`, and optionally `setup`.
4. Optionally provide a typed config model or JSON Schema for better validation.

Sketch:

```python
from foghorn.plugins.resolve.base import BasePlugin, PluginContext, PluginDecision, plugin_aliases

@plugin_aliases('my_feature')
class MyFeature(BasePlugin):
    def pre_resolve(self, qname: str, qtype: int, req: bytes, ctx: PluginContext) -> PluginDecision | None:
        # Insert logic here
        return None
```

The registry will pick the plugin up automatically as long as it lives under `foghorn.plugins.resolve`. Users can then configure:

```yaml
plugins:
  - type: my_feature
    config:
      # your fields here
```

To integrate with the schema generator, add:

- `@classmethod get_config_model(cls) -> BaseModel` returning a Pydantic model, or
- `@classmethod get_config_schema(cls) -> dict` returning a JSON Schema mapping.

### 6.2 New cache plugin

Steps:

1. Create a module under `src/foghorn/plugins/cache`, for example `my_cache.py`.
2. Subclass `CachePlugin`.
3. Decorate the class with `cache_aliases` to declare configuration aliases.
4. Implement `get`, `get_with_meta`, `set`, and `purge`.

Example:

```python
from foghorn.plugins.cache.base import CachePlugin, cache_aliases

@cache_aliases('my_cache')
class MyCache(CachePlugin):
    def __init__(self, **config: object) -> None:
        # store config, open connections, etc.
        ...

    def get(self, key):
        ...

    def get_with_meta(self, key):
        ...

    def set(self, key, ttl, value):
        ...

    def purge(self) -> int:
        ...
```

The cache registry will discover this automatically. Operators can then select it via:

```yaml
server:
  cache:
    module: my_cache
    config:
      # backend-specific config
```

### 6.3 New stats/query-log backend

Steps:

1. Create a module under `src/foghorn/plugins/querylog`, for example `my_backend.py`.
2. Subclass `BaseStatsStore` and implement all required methods.
3. Provide a short alias tuple, for example `aliases = ('my_backend',)`.
4. Optionally define a `default_config` mapping used by the loader.

The registry will pick the backend up automatically. A configuration entry might look like:

```yaml
stats:
  persistence:
    backends:
      - backend: my_backend
        config:
          # backend-specific settings
```

`load_stats_store_backend()` converts `stats.persistence` into either a single backend or a `MultiStatsStore` depending on how many backends are configured.

---

## 7. Updating the schema generator

When you introduce new top-level configuration fields or change important structures (for example, adding new properties under `stats.persistence` or `server.cache`), you may need to update `scripts/generate_foghorn_schema.py`.

Typical changes include:

- Extending `_augment_statistics_persistence_schema()` when new persistence options are added so they appear under `stats.persistence` in the schema.
- Extending `_build_v2_root_schema()` when you want to add or rearrange top-level properties (for example, introducing a new block under `server`).
- Adjusting how plugin definitions are copied into `$defs.PluginConfigs` when plugin metadata changes.

Workflow:

1. Modify the generator code.
2. Run the generator:

   ```bash
   ./scripts/generate_foghorn_schema.py -o assets/config-schema.json
   ```

3. Review the diff to ensure only the intended parts of the schema changed.
4. Run tests and, if present, any editor tooling that relies on the schema.

Remember: `assets/config-schema.json` is generated output; never hand-edit it.

---

## 8. Makefile and common workflows

The `Makefile` in the project root provides shortcuts for common tasks. Important targets:

- `make env`
  - Create a virtual environment in `./venv` and install the package.
- `make env-dev`
  - As above, but install in editable mode with development extras (`.[dev]`).
- `make build`
  - Ensure `venv` exists and the `foghorn` entrypoint is installed.
- `make run`
  - Activate the venv, create `var/` if needed, and run `foghorn --config config/config.yaml`.
- `make schema`
  - Run `scripts/generate_foghorn_schema.py` and refresh `assets/config-schema.json`.
- `make test`
  - Run pytest with coverage over `src`, reusing the dev environment if present.
- `make clean`
  - Remove `venv`, `var`, build artifacts, and common Python cache files.
- `make docker-build`, `make docker-run`, `make docker-clean`, `make docker-logs`
  - Build and run the Docker image and follow container logs.
- `make package-build`, `make package-publish`, `make package-publish-dev`
  - Build and publish Python packages to PyPI or TestPyPI.

A typical developer loop:

```bash
# One-time setup
make env-dev

# Edit code and tests

# Run tests
make test

# Regenerate schema when config-related code changes
make schema
```

With this overview you should be able to navigate the codebase, introduce new plugins and backends, and keep the schema and tooling in sync with runtime behaviour.