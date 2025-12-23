# Foghorn

<img src="html/logo.png" width="300px" alt="Foghorn Logo, a stylized alarm horn" />

Foghorn is a modern, programmable DNS proxy and validating caching resolver focused on correctness, observability, and extensibility. It provides hardened DNSSEC validation, including RFC5011-style trust anchors and NSEC3 support, along with an in‑memory caching layer and pluggable policy engine. Foghorn operates as a caching forwarder to upstream resolvers rather than a fully standalone recursive server, making it well-suited as a secure validating front-end to upstream DNS providers.

Operators can tune upstream strategy, concurrency, and health behavior directly from configuration, while monitoring real-time upstream status and response codes via a versioned `/api/v1` admin API and associated UI. Foghorn exposes rich statistics for DNSSEC, rate limiting, upstream health, and more, with both snapshot and persistent storage options.

A plugin architecture enables advanced behaviors without forking core code. Built-in plugins like `AccessControlPlugin`, `EtcHosts`, `FilterPlugin`, `RateLimitPlugin`, `UpstreamRouterPlugin`, `ZoneRecords`, `FileDownloader`, `DockerHosts`, and `FlakyServer` cover access control, /etc-hosts mapping, domain/IP filtering, adaptive rate limiting, upstream routing, zone records, list downloads, Docker-aware name resolution, and chaos testing. Per-plugin logging and strict registry semantics help catch misconfiguration early.

With special thanks to Fiona Weatherwax for their contributions and inspiration.

For developer documentation (architecture, transports, plugin internals, testing), see README-DEV.md.

----

[Jump to Documentation Index](#index)

----

## [0.5.0] - 2025-12-22

### Added
- Introduced core admin web UI primitives and backend endpoints for management pages.
- Added frontend admin UI scaffolding for plugin and cache pages.
- Added admin page and HTTP snapshot endpoints for the mDNS plugin.
- Added admin snapshots and UI descriptors for cache plugins.
- Added DockerHosts HTTP snapshot helper and admin UI integration.
- Added DockerHosts admin UI page and bumped version as part of 0.5.0 beta releases.
- Introduced a cache registry and wired it into the server TTL cache.
- Added per-backend cache hit/miss counters and cache statistics.
- Added webserver build-info caching and exposed cache metrics.
- Extended `BasePlugin` helper APIs to support richer plugin behaviors.
- Added support for inline zone records in plugin configuration.
- Introduced a default set of mDNS services to browse.
- Added the ability to override the DNS listen address via the `LISTEN` Makefile variable.
- Added utilities and scripts around pruning branches and other development tooling.

### Changed
- Modernized the DockerHosts plugin implementation and aligned associated tests.
- Refactored the EtcHosts plugin and updated its tests.
- Consolidated the config parser into a single module and added a CLI helper for configuration.
- Normalized the `git prune-branches` script naming.
- Wired plugins into the admin webserver and exposed the DockerHosts API.
- Aligned webserver enablement defaults with configuration values.
- Wired DNSSEC validation into the cache registry and renamed zone-secure status representation.
- Adjusted default DNS port settings (e.g., defaulting to 5335 to better align with unbound usage).
- Performed multiple version and dependency bumps across the admin UI, cache registry, and plugins during the 0.5.0 beta cycle.

### Fixed
- Improved error handling when binding the DNS UDP socket.
- Hardened DockerHosts endpoint handling and container discovery.
- Refined web UI stats layout and configuration warnings.
- Removed a duplicate dependency from the project.

### Documentation
- Documented mDNS networking requirements, including Docker host-networking needs for discovery.
- Clarified Docker/mDNS behavior and configuration expectations in the docs.
- Updated documentation around configuration, admin UI features, and new cache behavior where relevant.

## v0.4.7 (2025-12-12)

Release includes **55 commits** from `v0.4.6` (2025-12-07) to `v0.4.7` (2025-12-12).

### Highlights
- Added a full **recursive resolver mode** (iterative recursion with QNAME minimization) and wired it through UDP/TCP/DoT/DoH.
- Introduced a **cache plugin system** (including a `none` cache plugin) and began moving caching to a shared, pluggable cache interface.
- Expanded **DNSSEC validation** with a new `local_extended` strategy plus DNSSEC counters exposed in stats and the admin UI.
- Added new plugins: **mDNS bridge** and **DNS prefetch**.

---

## Added

### Resolver / core pipeline
- **Recursive resolver mode** (`resolver.mode: recursive`) with:
  - Iterative recursion with QNAME minimization.
  - UDP queries with TCP fallback.
  - Max depth and timeout budgeting (overall + per-try).
- Support for a plugin **`drop` action** in the resolution pipeline (used to intentionally produce client-side timeouts by not responding).

### Caching
- New **cache plugin framework**:
  - Cache plugin registry/loader supporting aliases, dotted paths, and `{module, config}` objects.
  - New cache plugins under `src/foghorn/cache_plugins/` (including a **`none` cache** implementation).
- Cache entries now expose TTL metadata via a new cache API helper (`get_with_meta()`), enabling richer cache behavior.
- Server caching moved toward a shared global cache (`foghorn.plugins.base.DNS_CACHE`) rather than per-handler caches.

### DNSSEC
- New DNSSEC validation strategy: **`local_extended`** (in addition to `upstream_ad` and `local`).
- DNSSEC validation can now route its internal lookups through:
  - configured forward upstreams (forward mode), or
  - Foghorn’s own recursive resolver (recursive mode).
- New DNSSEC status accounting: stats track totals for:
  - `dnssec_secure`, `dnssec_zone_secure`, `dnssec_unsigned`, `dnssec_bogus`, `dnssec_indeterminate`.

### Plugins
- **MdnsBridgePlugin**: bridges zeroconf/mDNS into standard DNS answering (PTR/SRV/TXT/A/AAAA), with example config added.
  - **Networking requirement:** mDNS only works on the local L2 network. When running Foghorn in Docker and using this plugin, the container **must** use host networking (for example, `--net=host`); bridged Docker networks will not see mDNS traffic.
- **DnsPrefetchPlugin**: background worker that prefetches hot domains (based on stats) to keep cache entries warm.
- **EtcHosts plugin**: added PTR reverse-lookup support.
- **DockerHosts plugin**: added support for a short container ID alias (first 12 chars) as an additional candidate name.

### Observability / admin
- `/stats`, `/api/v1/stats`, `/traffic`, `/api/v1/traffic` now accept a **`top`** query parameter to limit returned Top-N list sizes.
- Admin dashboard updated to show DNSSEC counters.

### Tooling
- New generated JSON schema: `assets/config-schema.json` (replaces the old `assets/config-yaml.schema`).
- New script: `scripts/generate_foghorn_schema.py` to generate a combined schema including plugin schemas.

---

## Changed

### Configuration / schema
- Schema file rename & format change:
  - Removed: `assets/config-yaml.schema` and `html/config-yaml.schema`
  - Added: `assets/config-schema.json` and `html/config-schema.json`
  - Admin UI now fetches `/config-schema.json` and validates with Ajv.
- Cache config is now modeled as a top-level `cache:` configuration (and `min_cache_ttl` moved under `cache.config` in examples/docs).

### Plugins
- Default plugin priority values increased from **50 → 100** (pre/post/setup), affecting ordering when priorities are omitted.

### Stats behavior
- Added an `include_in_stats` toggle for ignore filters, allowing ignored traffic to be excluded from aggregation while still being logged.
- Increased internal Top-K capacity (keeps more candidates internally; truncation is applied at response time via the `top` query param).

### DoH behavior & dependencies
- DoH FastAPI usage is now more defensive:
  - FastAPI imports are deferred; if unavailable, DoH starts in a threaded fallback mode.
  - Empty resolver responses are treated as timeouts (e.g., FastAPI path returns HTTP 504; other paths effectively time out).

---

## Fixed / Hardening
- DNSSEC local validation now fails fast with a clear error when `cryptography` is missing (instead of silently misbehaving).
- Transport handlers (UDP/TCP/DoT) now consistently treat “no response” from the resolver as “don’t reply” (client timeout), aligning with the new drop/timeout semantics.

---

## Dependencies / Packaging
- Added `cryptography` dependency (required for DNSSEC local validation).
- Docker image install list updated to include `cryptography`.
- JSON Schema validation is now optional at runtime (skips validation if `jsonschema` is not installed).

---

## Documentation
- Updated docs and examples to reflect:
  - new cache config layout (`cache.module`, `cache.config.min_cache_ttl`)
  - new plugins (`dns_prefetch`, `mdns`)
  - schema generation + using `assets/config-schema.json`

---

## Tests
- Added/expanded coverage for:
  - recursive resolver behavior (including transport helpers and QNAME minimization)
  - DNSSEC extended local validation and trust anchor behavior
  - new plugins (mDNS, DNS prefetch) and updated plugin behaviors
  - cache plugin behavior (including the `none` cache)

---

## Notable PRs
- Merged PR: **#20**

---

**Full Changelog:** `https://github.com/zallison/foghorn/compare/v0.4.6...v0.4.7`

----

## Index

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Docker](#docker)
  - [DNSSEC modes](#dnssec-modes)
- [Configuration](#configuration)
  - [`listen`](#listen)
  - [`upstreams`](#upstreams)
  - [`plugins`](#plugins)
	- [AccessControlPlugin](#accesscontrolplugin)
	- [NewDomainFilterPlugin](#newdomainfilterplugin)
	- [RateLimitPlugin](#ratelimitplugin)
	- [UpstreamRouterPlugin](#upstreamrouterplugin)
	- [FilterPlugin](#filterplugin)
	- [FileDownloader plugin](#listdownloader-plugin)
	- [ZoneRecords plugin](#zonerecords-plugin)
	- [DnsPrefetchPlugin](#dnsprefetchplugin)
  - [Complete `config.yaml` Example](#complete-configyaml-example)
- [Logging](#logging)
- [License](#license)

## Features

*   **DNS Caching and Prefetch:** Speeds up DNS resolution by caching responses from upstream servers, with optional cache prefetch / stale‑while‑revalidate and a dns_prefetch plugin that keeps hot entries warm using statistics.
*   **Extensible Plugin System:** Easily add custom logic to control DNS resolution.
*   **Flexible Configuration:** Configure listeners, upstream resolvers (UDP/TCP/DoT/DoH), and plugins using YAML.
*   **Built-in Plugins:**
  *   **Access Control:** CIDR-based allow/deny (allowlist/blocklist terminology in docs).
  *   **EtcHosts:** Answer queries based on host file(s).
  *   **Filter:** Filter by domain patterns/keywords IPs.
  *   **Rate Limit**: Adaptive or static rate limiting, by client, domain, or client-domain
  *   **Upstream Router:** Route queries to different upstream servers by domain/suffix.
  *   **ZoneRecords** Serve static DNS records and authoritative zones from one or more files, with optional live reload on change.
  *   **DockerHosts**: Answer A/AAAA/PTR queries for Docker container hostnames and reverse IPs by inspecting Docker endpoints.
* **Examples**:
  *   **Examples:** Showcase of simple policies and rewrites.
  *   **New Domain Filter:** Block recently registered domains.
  *   **Greylist:** Temporarily block newly seen domains.


## Installation

Use a virtual environment named `venv`:

```bash
python3 -m venv venv
source venv/bin/activate
pip install .
# Optional for development:
pip install -e '.[dev]'
```

## Usage

Create a `config.yaml`, then run:

```bash
foghorn --config config.yaml
```

Alternatively, run as a module:

```bash
python -m foghorn.main --config config.yaml
```

The server will start listening for DNS queries on the configured host and port.

### Docker

Foghorn is available on Docker Hub at `zallison/foghorn:latest`.

> **Note about mDNS / MdnsBridgePlugin**
> The mDNS bridge plugin (`MdnsBridgePlugin`, alias `mdns`) relies on multicast
> DNS on the local layer‑2 network. When you run Foghorn inside Docker and want
> mDNS discovery to work, the container **must** share the host network (for
> example, `--net=host` on Linux). If you use the default bridged Docker
> network, mDNS traffic will not be visible to the container and the plugin will
> not see any services.

**Using the pre-built image:**

```bash
docker run -d -p 5335:5335/udp \
  -v /path/to/your/config/:/foghorn/config/ \
  zallison/foghorn:latest
```

**Building locally:**

```bash
[cp /path/to/your/config.yaml ./config/config.yaml] # Optional
docker build -t my/foghorn .
docker run -d -p 5353:5353/udp my/foghorn
```

**Important:** Mount your `config.yaml` to `/foghorn/config/config.yaml` inside the container unless you've built your own image that contains your config.

If you need to expose additional listeners (TCP/DoT/DoH), add the corresponding port mappings:

```bash
docker run -d \
  -p 5353:5353/udp \
  -p 5353:5353/tcp \
  -p 8853:8853/tcp \
  -p 5380:5380/tcp \
  -v /path/to/your/config.yaml:/foghorn/config/config.yaml \
  zallison/foghorn:latest
```

### DNSSEC modes

```yaml
dnssec:
  mode: passthrough            # ignore | passthrough | validate
  validation: upstream_ad      # upstream_ad | local   (local = experimental)
  udp_payload_size: 1232
```
- ignore: do not advertise DO; DNSSEC data not requested.
- passthrough: advertise DO and return DNSSEC records; forward AD bit if upstream set it.
- validate:
  - upstream_ad: require upstream AD bit (recommended for now)
  - local (experimental): perform local DNSSEC validation.

## Configuration

Configuration is handled through a `config.yaml` file. The primary top-level sections are `listen`, `upstreams`, `cache`, `foghorn`, and `plugins`.

The `cache` section selects the DNS response cache implementation (default: in-memory TTL):

```yaml
cache:
  module: in_memory_ttl
  config: {}
```

The `foghorn` section also exposes optional cache prefetch / stale‑while‑revalidate knobs that work together with the shared resolver, and you can enable the `dns_prefetch` plugin to use statistics to keep frequently requested domains warm in cache.

------

## `listen`

You can enable one or more `listener`s. `UDP` is enabled by default; `TCP`, `DoT`, and `DoH` are optional and supported.

The default ports (UDP/TCP 5333, DoT 8853, DoH 5380, admin webserver 5380) are chosen to be above 1024 so that Foghorn can be run as a non-root user without special capabilities.

```yaml
listen:
  udp:
	enabled: true
	host: 127.0.0.1
	port: 5353
  tcp:
	enabled: false
	host: 127.0.0.1
	port: 5353
  dot:
	enabled: false
	host: 127.0.0.1
	port: 8853
	cert_file: /path/to/cert.pem
	key_file: /path/to/key.pem
  doh:
	enabled: false
	host: 127.0.0.1
	port: 5380
	# Optional TLS
	# cert_file: /path/to/cert.pem
	# key_file: /path/to/key.pem
```

Note: The DoH listener is served by a dedicated FastAPI app using uvicorn in a
single background thread. TLS is applied via `cert_file`/`key_file`. Behavior is
RFC 8484‑compatible and unchanged from previous releases; only the runtime
implementation has changed.

----

## `upstreams`

You can mix transports per upstream. If `transport` is omitted it defaults to UDP.

```yaml
upstreams:
  - host: 1.1.1.1
	port: 853
	transport: dot
	tls:
	  server_name: cloudflare-dns.com
	  verify: true
	pool:
	  max_connections: 64
	  idle_timeout_ms: 30000
  - host: 8.8.8.8
	port: 53
	# transport: udp (default)
	pool:
	  max_connections: 32
	  idle_timeout_ms: 15000
  - transport: doh
	url: https://dns.google/dns-query
	method: POST   # or GET
	headers:
	  user-agent: foghorn
	tls:
	  verify: true
	  # ca_file: /etc/ssl/certs/ca-certificates.crt
```

----

## `plugins`

This section is a list of plugins to load. Each plugin has a `module` and a `config` section. You can also specify a plugin as a short string alias.

You can use short aliases instead of full dotted paths:
- access_control or acl -> foghorn.plugins.access_control.AccessControlPlugin
- new_domain_filter or new_domain -> foghorn.plugins.new_domain_filter.NewDomainFilterPlugin
- upstream_router or router -> foghorn.plugins.upstream_router.UpstreamRouterPlugin
- filter -> foghorn.plugins.filter.FilterPlugin
- rate_limit or ratelimit -> foghorn.plugins.rate_limit.RateLimitPlugin
- docker-hosts, docker_hosts or docker -> foghorn.plugins.docker-hosts.DockerHosts

Examples of plugin entries:
- As a dict with module/config: `{ module: acl, config: {...} }`
- As a plain alias string: `acl` (no config)

#### Base plugin targeting (targets / targets_ignore)

All plugins that inherit from `BasePlugin` support optional, shared client‑targeting
knobs in their `config` block:

- `targets` (optional): list of CIDR/IP strings (or a single string) specifying
  which client networks this plugin should apply to.
- `targets_ignore` (optional): list of CIDR/IP strings to exclude from
  targeting, even when they match `targets`.
- `targets_cache_ttl_seconds` (optional, default 300): TTL in seconds for an
  in‑memory cache of per‑client targeting decisions; longer values reduce CPU
  when many queries arrive from the same clients.

Semantics:

- When **neither** `targets` nor `targets_ignore` is set, the plugin applies to
  **all** clients (default behavior).
- When **only** `targets` is set, the plugin applies **only** to clients whose
  IP is contained in at least one listed CIDR/IP.
- When **only** `targets_ignore` is set, the plugin applies to **all clients
  except** those in `targets_ignore` (inverted logic).
- When **both** are set, `targets_ignore` wins: clients in that list are
  skipped even if they match an entry in `targets`.

These knobs are honored by core plugins such as AccessControl, Filter,
Greylist, NewDomainFilter, UpstreamRouter, FlakyServer, Examples, and
EtcHosts. See `example_configs/` (for example `kitchen_sink.yaml` and
`plugin_rate_limit.yaml`) for usage patterns.

A minimal plugin entry using all common BasePlugin-wide options looks like:

```yaml
plugins:
  - module: foghorn.plugins.filter.FilterPlugin
	name: example_filter
	enabled: true
	comment: "Demo plugin using common BasePlugin options"
	pre_priority: 40
	post_priority: 60
	setup_priority: 50
	config:
	  # BasePlugin-wide options
	  logging:
		level: debug
		stderr: true
		file: ./logs/example_filter.log
		syslog:
		  address: /dev/log
		  facility: user

	  targets:
		- 10.0.0.0/8
		- 192.0.2.1
	  targets_ignore:
		- 10.0.5.0/24
	  targets_cache_ttl_seconds: 600

	  target_qtypes:
		- A
		- AAAA

	  abort_on_failure: true  # used by some plugins during setup()

	  # Plugin-specific options (FilterPlugin here)
	  default: deny
	  cache_ttl_seconds: 600
```

#### Plugin priorities and `setup_priority`

Plugins support three priority knobs in their config (all optional, integers 1–255):

- `pre_priority`: controls the order of `pre_resolve` hooks; lower values run first.
- `post_priority`: controls the order of `post_resolve` hooks; lower values run first.
- `setup_priority`: controls the order of one-time `setup()` calls during startup; lower values run first.

`setup_priority` is only used for plugins that override `BasePlugin.setup`. Its value is resolved as:

- Use the explicit `setup_priority` from config if provided.
- Otherwise, reuse the config’s `pre_priority` value for setup-aware plugins.
- Otherwise, fall back to the plugin’s class-level default (50).

This lets you, for example, have a FileDownloader plugin run its setup early (to download lists) and a Filter plugin run slightly later to load those lists from disk.

------

### AccessControlPlugin

This plugin provides access control based on the client's IP address.

**Configuration:**

*   `default`: The default action to take if no rule matches (`allow` or `deny`).
*   `allow`: A list of CIDR ranges to allow.
*   `deny`: A list of CIDR ranges to deny. Deny rules take precedence over allow rules.

**Example (full path):**

```yaml
plugins:
  - module: foghorn.plugins.access_control.AccessControlPlugin
	config:
	  default: allow
	  allow:
		- "192.168.0.0/16"
		- "10.0.0.0/8"
	  deny:
		- "203.0.113.0/24"
```

**Example (short alias):**

```yaml
plugins:
  - module: acl
	config:
	  default: allow
	  allow:
		- "192.168.0.0/16"
```

------

### NewDomainFilterPlugin

This plugin blocks domains that were registered recently by checking the domain's creation date using `whois`.

**Configuration:**

*   `threshold_days`: The minimum age of a domain in days. Domains younger than this will be blocked.
*   `timeout_ms`: The timeout in milliseconds for `whois` queries.

**Example (full path):**

```yaml
plugins:
  - module: foghorn.plugins.new_domain_filter.NewDomainFilterPlugin
	config:
	  threshold_days: 7
	  timeout_ms: 2000
```

**Example (short alias):**

```yaml
plugins:
  - module: new_domain
	config:
	  threshold_days: 14
```

------

### RateLimitPlugin

This plugin provides adaptive or fixed per-key DNS rate limiting, backed by a
sqlite database. It can key profiles by client IP, client+domain, or domain
only, and it learns a baseline requests-per-second (RPS) for each key.

**Configuration (subset):**

* `mode`: `per_client`, `per_client_domain`, or `per_domain`.
* `window_seconds`: measurement window length in seconds.
* `warmup_windows`: number of completed windows to observe before enforcing.
* `alpha`: EWMA factor when the new window's RPS is >= the current average
  (ramp-up speed).
* `alpha_down`: optional EWMA factor when the new window's RPS is < the current
  average (ramp-down speed). If omitted, it defaults to `alpha`.
* `burst_factor`: multiplier over the learned average when computing
  `allowed_rps`.
* `min_enforce_rps`: lower bound on `allowed_rps`.
* `global_max_rps`: optional hard upper bound on `allowed_rps` (0 disables).
* `db_path`: sqlite file storing learned profiles.
* `deny_response`: how to answer when a query is rate-limited (mirrors
  FilterPlugin: `nxdomain`, `refused`, `servfail`, `noerror_empty`/`nodata`, or
  `ip`).

To make the limiter behave like a "dumb" fixed-rate limiter, set
`min_enforce_rps` and `global_max_rps` to the same value; in that case the
learned average no longer affects the enforcement threshold.

See `example_configs/plugin_rate_limit.yaml` for concrete profiles (solo user,
home network, SMB) and notes on static vs adaptive behavior.

------

### UpstreamRouterPlugin

This plugin routes queries to different upstream DNS servers based on the queried domain.

**Configuration:**

*   `routes`: A list of routing rules. Each rule can have a `domain` (for exact matches) or a `suffix` (for suffix matches) and a list of `upstreams` servers to route to.

**Example (full path):**

```yaml
plugins:
  - module: foghorn.plugins.upstream_router.UpstreamRouterPlugin
	config:
	  routes:
		- domain: "internal.corp.com"
		  upstreams:
			- host: 10.0.0.1
			  port: 53
		- suffix: ".dev.example.com"
		  upstreams:
			- host: 192.168.1.1
			  port: 53
```

**Example (short alias):**

```yaml
plugins:
  - module: router
	config:
	  routes:
		- suffix: "corp"
		  upstreams:
			- host: 10.0.0.53
			  port: 53
```

------

### FilterPlugin

This plugin provides flexible filtering of DNS queries based on domain names, patterns, keywords, and response IPs.

**Configuration:**

- blocked_domains: list of exact domain names to block.
- blocked_patterns: list of regular expressions to match against the domain name.
- blocked_keywords: list of keywords to block if they appear anywhere in the domain name.
- blocked_ips: list of IP addresses or CIDR ranges to control post‑resolution behavior; each entry supports action deny, remove, or replace (with replace_with).

File-backed inputs (support globs):
- allowed_domains_files, blocked_domains_files
- blocked_patterns_files
- blocked_keywords_files
- blocked_ips_files

Formats supported per file (auto-detected line-by-line):
- Plain text (default): a single value per line; blank lines and lines starting with '#' are ignored
- JSON Lines (JSONL): one JSON object per line with the following schemas
  - Domains: {"domain": "example.com", "mode": "allow|deny"} (mode optional; defaults to the file-level mode implied by which key you used)
  - Patterns: {"pattern": "^ads\\.", "flags": ["IGNORECASE"]} (flags optional; defaults to IGNORECASE)
  - Keywords: {"keyword": "tracker"}
  - IPs: {"ip": "203.0.113.0/24", "action": "deny|remove|replace", "replace_with": "IP"}

Note: JSONL is only supported in FilterPlugin file-backed inputs (the *_files keys above). The core YAML config does not accept JSONL.

Load order and precedence for domains (last write wins):
1) allowed_domains_files
2) blocked_domains_files
3) inline allowed_domains
4) inline blocked_domains

**Example (short alias):**

```yaml
plugins:
  - module: filter
	config:
	  # Pre-resolve (domain) filtering
	  blocked_domains:
		- "malware.com"
		- "phishing-site.org"

	  blocked_patterns:
		- ".*\\.porn\\..*"

	  blocked_keywords:
		- "gambling"

	  # Post-resolve (IP) filtering
	  blocked_ips:
		- ip: "1.2.3.4"
		  action: "deny" # Deny the whole response
		- ip: "8.8.8.0/24"
		  action: "remove" # Remove just this A/AAAA record

	  # File-backed examples (globs allowed)
	  allowed_domains_files:
		- config/allow.txt
		- config/allow.d/*.list
	  blocked_domains_files:
		- config/block.txt
		- config/block.d/*.txt
	  blocked_patterns_files:
		- config/patterns/*.re
	  blocked_keywords_files:
		- config/keywords.txt
	  blocked_ips_files:
		- config/ips.txt
		- config/ips.d/*.csv
```

#### JSON Lines examples for files

- Domains (allowed_domains_files or blocked_domains_files):

```json
{"domain": "good.com", "mode": "allow"}
{"domain": "bad.com", "mode": "deny"}
{"domain": "neutral.com"}
```

- Patterns (blocked_patterns_files):

```json
{"pattern": "^ads\\.", "flags": ["IGNORECASE"]}
{"pattern": "^track\\.", "flags": []}
```

- Keywords (blocked_keywords_files):

```json
{"keyword": "tracker"}
{"keyword": "analytics"}
```

- IPs (blocked_ips_files):

```json
{"ip": "192.0.2.1", "action": "deny"}
{"ip": "198.51.100.0/24", "action": "remove"}
{"ip": "203.0.113.5", "action": "replace", "replace_with": "127.0.0.1"}
```

Notes:
- Plain-text lines continue to work alongside JSON Lines within the same file.
- Unknown actions default to deny (logged). Invalid JSON/regex/IP lines are logged and skipped.

------

### FileDownloader plugin

Download domain-only blocklists from well-known sources to local files so the Filter plugin can load them.

Notes:
- Works with domain-per-line lists (e.g., Firebog "just domains"). Hosts-formatted lists (with IPs) are not supported without preprocessing.
- Runs early (pre_priority 15) so files are present before Filter executes.

**Configuration:**

* `urls`: List of HTTP(S) URLs to domain-only lists (comments with `#` allowed).
* `url_files`: List of file paths, each containing one URL per line (supports `#` comments and blank lines).
* `download_path`: Directory to write files (default `./config/var/lists`).
* `interval_days`: Optional periodic refresh interval (in days) while the server runs.

Filenames are unique and stable per-URL: `{base}-{sha1(url)[:12]}{ext}`. If the URL has no extension, none is added (`{base}-{hash}`). Each file begins with a header line: `# YYYY-MM-DD HH:MM - URL`.

**Example:**

```yaml
plugins:
  - module: file_downloader
	pre_priority: 15
	config:
	  download_path: ./config/var/lists
	  interval_days: 1
	  urls:
		- https://v.firebog.net/hosts/AdguardDNS.txt
		- https://v.firebog.net/hosts/Easylist.txt
		- https://v.firebog.net/hosts/Prigent-Ads.txt
		- https://v.firebog.net/hosts/Prigent-Malware.txt

  - module: filter
	pre_priority: 20
	config:
	  default: deny
	  blocklist_files:
		- ./config/var/lists/AdguardDNS-*.txt
		- ./config/var/lists/Easylist-*.txt
		- ./config/var/lists/Prigent-Ads-*.txt
		- ./config/var/lists/Prigent-Malware-*.txt
```

------

### DockerHosts plugin

The `DockerHosts` plugin answers selected queries directly from Docker metadata.
It discovers containers via the Docker CLI on one or more endpoints, extracts
hostnames plus IPv4/IPv6 addresses, and serves forward and reverse entries from
an in-memory map that is periodically refreshed.

**Configuration keys**

```yaml
plugins:
  - module: docker-hosts
	config:
	  # Optional: list of Docker endpoints; defaults to the local Unix socket
	  endpoints:
		- unix:///var/run/docker.sock
		# Example TCP endpoints (remote Docker daemons or proxies):
		# - tcp://127.0.0.1:2375
		# - tcp://docker-host.internal:2375
		# - tcp://10.0.0.10:2376

	  # Optional: docker CLI binary; defaults to "docker"
	  docker_binary: docker

	  # TTL for A/AAAA/PTR answers served by this plugin (seconds; default 300)
	  ttl: 300

	  # Background refresh interval in seconds. When set to 0, only the
	  # initial mapping from setup() is used and no periodic refresh occurs.
	  reload_interval_seconds: 60

	  # Optional per-family host IP overrides. When set, these are used in
	  # place of per-container addresses so that clients reach the host even
	  # if container networks are not routable.
	  # use_ipv4: 192.0.2.10
	  # use_ipv6: 2001:db8::10
```

`module` may be any of:

- Full dotted path: `foghorn.plugins.docker-hosts.DockerHosts`
- Alias: `docker-hosts`, `docker_hosts`, or `docker`

DockerHosts inspects all containers on each endpoint, building:

- forward maps from hostname (case-insensitive) to IPv4/IPv6 addresses
- reverse maps from both IPv4 and IPv6 addresses to hostnames using
  RFC-compliant in-addr.arpa and ip6.arpa reverse names

During `pre_resolve`, the plugin:

- answers A queries from the IPv4 map (`QTYPE.A`)
- answers AAAA queries from the IPv6 map (`QTYPE.AAAA`)
- answers PTR queries when the reverse lookup matches a known address

If a container is missing a hostname or has no usable IP addresses, DockerHosts
logs a warning and skips that container. If no containers across all endpoints
have usable hostname/IP combinations, it logs a summary warning after reload.

------

### ZoneRecords plugin

The `ZoneRecords` plugin answers selected queries directly from one or more
local files, and can act as an authoritative server for configured zones while
still bypassing upstream resolvers and the cache for those names.

**Record file format**

Each non-empty, non-comment line in a records file must be:

`<domain>|<qtype>|<ttl>|<value>`

- `domain`: hostname (with or without trailing dot); stored and matched case-insensitively.
- `qtype`: mnemonic (for example `A`, `AAAA`, `TXT`, `CNAME`) or numeric type code.
- `ttl`: non-negative integer TTL in seconds.
- `value`: RDATA for the given type (for example an IP for `A`/`AAAA`, a target
  name for `CNAME`, the text for `TXT`, and so on).

Lines beginning with `#` (after stripping leading whitespace), or that are
empty after removing inline `#` comments, are ignored.

When the same `(domain, qtype)` appears multiple times (even across multiple
files), the first TTL is kept and values are de-duplicated while preserving
first-seen ordering. This ordering is reflected in the final DNS answer.

**Configuration keys**

```yaml
plugins:
  - module: zone
	config:
	  # Provide one or more records files; lines use:
	  #   <domain>|<qtype>|<ttl>|<value>
	  # example.com|A|300|192.0.2.10
	  file_paths:
		- ./config/custom-records.txt
		- ./config/custom-records-extra.txt

	  # Optional: add or override entries directly in config using the same
	  # line format; these are merged after file-backed records with
	  # first-TTL-wins and de-duplicated values.
	  # records:
	  #   - example.com|A|300|192.0.2.20
	  #   - www.example.com|CNAME|300|example.com.

	  # Optional: control how filesystem changes are detected
	  watchdog_enabled: true                        # default true when omitted
	  watchdog_min_interval_seconds: 1.0            # minimum time between reloads
	  watchdog_poll_interval_seconds: 0.0           # >0 enables stat-based polling
```

`module` may be any of:

- Full dotted path: `foghorn.plugins.zone-records.ZoneRecords`
- Alias: `zone`, `zone_records`, `custom`, or `records`

When `watchdog_enabled` is true and the optional `watchdog` dependency is
installed, the plugin watches the parent directories of all configured records
files and reloads them when changed. When
`watchdog_poll_interval_seconds > 0`, a lightweight polling loop supplements
filesystem events, which is useful in some container or network filesystem
setups where file change notifications are unreliable.

------

### DnsPrefetchPlugin

The `DnsPrefetchPlugin` runs a background worker that periodically inspects
statistics (primarily `cache_hit_domains`, with `top_domains` as a fallback) and
issues synthetic DNS queries for the hottest domains and qtypes so that cache
entries stay warm.

**Configuration keys**

```yaml
plugins:
  - module: dns_prefetch
	config:
	  interval_seconds: 60        # how often to run a prefetch cycle
	  prefetch_top_n: 100         # max domains considered each cycle
	  max_consecutive_misses: 5   # stop prefetching if no hits are ever seen
	  qtypes: ["A", "AAAA"]       # record types to prefetch
```

Notes:
- The plugin never modifies individual client queries; it only issues
  background prefetches.
- Statistics must be enabled for the plugin to be effective (see
  `example_configs/prefetch.yaml` for a minimal example).

------

## Cache plugins
Foghorn caches DNS responses via a configurable *cache plugin* under the top-level `cache:` key.

Built-in cache plugins:
- `in_memory_ttl` (default): in-process TTL cache
- `sqlite3`: persistent on-disk TTL cache (SQLite)
- `redis` / `valkey`: Redis-compatible remote cache (requires the optional Python dependency `redis`)
- `none`: disables caching

Examples (complete runnable configs) are available in:
- `example_configs/cache_in_memory_ttl.yaml`
- `example_configs/cache_sqlite3.yaml`
- `example_configs/cache_redis.yaml`
- `example_configs/cache_none.yaml`

Minimal config snippets:

`in_memory_ttl` (default):

```yaml
cache:
  module: in_memory_ttl
  config:
	min_cache_ttl: 60
```

`sqlite3` (persistent on-disk cache):

```yaml
cache:
  module: sqlite3
  config:
	db_path: ./config/var/dbs/dns_cache.db
	namespace: dns_cache
	min_cache_ttl: 60
```

`redis` / `valkey` (remote cache):

```yaml
cache:
  module: redis
  config:
	url: redis://127.0.0.1:6379/0
	namespace: foghorn:dns_cache:
	min_cache_ttl: 60
```

`none` (disable caching):

```yaml
cache:
  module: none
```

Notes:
- `min_cache_ttl` is a cache-expiry floor used by the resolver; it does not rewrite TTLs inside DNS answers.

## Complete `config.yaml` Example

Here is a complete `config.yaml` file that uses the modern configuration format and shows how plugin priorities (including `setup_priority`) work:

```yaml
# Example configuration for the DNS caching server
listen:
  # Modern listener config; UDP is enabled by default.
  udp:
	enabled: true
	host: 127.0.0.1
	port: 5333
  tcp:
	enabled: false
	host: 127.0.0.1
	port: 5333
  dot:
	enabled: false
	host: 127.0.0.1
	port: 8853
	# cert_file: /path/to/cert.pem
	# key_file: /path/to/key.pem
  doh:
	enabled: false
	host: 127.0.0.1
	port: 5380
	# Optional TLS for DoH
	# cert_file: /path/to/cert.pem
	# key_file: /path/to/key.pem

# Multiple upstream DNS servers with automatic failover.
# All upstreams share a single timeout (foghorn.timeout_ms) per attempt).
upstreams:
  - host: 8.8.8.8
	port: 53
	transport: udp
  - host: 1.1.1.1
	port: 853
	transport: dot
	tls:
	  server_name: cloudflare-dns.com
	  verify: true
	  # ca_file: /etc/ssl/certs/ca-certificates.crt
  - transport: doh
	url: https://dns.google/dns-query
	method: POST
	headers:
	  user-agent: foghorn
	tls:
	  verify: true
	  # ca_file: /etc/ssl/certs/ca-certificates.crt

# Global timeout and upstream behaviour knobs
foghorn:
  timeout_ms: 2000
  upstream_strategy: failover
  upstream_max_concurrent: 1
  use_asyncio: true
# Cache configuration
cache:
  module: in_memory_ttl
  config:
	# Minimum cache TTL (in seconds) applied to ***all*** cached responses.
	# - For NOERROR with answers: cache TTL = max(min(answer TTLs), min_cache_ttl)
	# - For NOERROR with no answers, NXDOMAIN, and SERVFAIL: cache TTL = min_cache_ttl
	# Note: TTL field in the DNS response is not rewritten; this controls cache expiry only.
	min_cache_ttl: 60

# Optional DNSSEC configuration
# dnssec:
#   mode: passthrough            # ignore | passthrough | validate
#   validation: upstream_ad      # upstream_ad | local (local is experimental)
#   udp_payload_size: 1232

# Logging configuration
logging:
  level: debug            # Available levels: debug, info, warn, error, crit
  stderr: true            # Log to stderr (default: true)
  file: /tmp/foghorn.log  # Optional: also log to this file
  syslog: false           # Optional: also log to syslog

# Statistics (optional)
statistics:
  enabled: false
  interval_seconds: 10
  reset_on_log: false
  include_qtype_breakdown: true
  include_top_clients: true
  include_top_domains: true
  top_n: 10
  track_latency: true
  # When true, either SIGUSR1 or SIGUSR2 will reset in-memory statistics before
  # notifying plugins.
  # sigusr2_resets_stats: true
  # Optional display-only ignore filters for top lists. These do not affect
  # totals or persisted aggregates; they only hide entries from the
  # top_clients/top_domains/top_subdomains sections exposed via /stats.
  # ignore:
  #   # IPs/CIDRs to hide from top_clients only.
  #   top_clients:
  #     - 192.168.0.0/16
  #     - 10.0.0.0/8
  #
  #   # Base domains to hide from top_domains and, when subdomains list is
  #   # empty, from top_subdomains as well. Matching is exact by default.
  #   top_domains:
  #     - example.internal
  #   # Matching mode for top_domains: "exact" (default) or "suffix".
  #   # In suffix mode, a base domain D is ignored when D == value or
  #   # D ends with "." + value.
  #   top_domains_mode: suffix
  #
  #   # Full qnames to hide from top_subdomains. When this list is empty,
  #   # the values from top_domains are reused as the ignore set.
  #   top_subdomains:
  #     - dev.example.internal
  #   # Matching mode for top_subdomains: "exact" (default) or "suffix".
  #   # In suffix mode, a subdomain name N is ignored when N == value or
  #   # N ends with "." + value.
  #   top_subdomains_mode: suffix

plugins:
  # New-domain filter: simple pre-resolve policy plugin.
  - module: new_domain
	config:
	  threshold_days: 14

  # Greylist plugin.
  - module: greylist
	config:
	  duration_seconds: 60
	  # duration_hours: 1  # Only if duration_seconds isn't provided
	  # db_path: ./greylist.db

  # Upstream router: route queries to specific upstreams by suffix.
  # Uses the modern "upstreams" list format only.
  - module: router
	config:
	  routes:
		- suffix: ".mylan"
		  upstreams:
			- host: 192.168.1.1
			  port: 53
		- suffix: "corp.internal"
		  upstreams:
			- host: 10.0.0.1
			  port: 53
			- host: 10.0.0.2
			  port: 53

  # FileDownloader: runs early in the setup phase to download blocklists
  # that the Filter plugin will read from disk.
  - module: file_downloader
	config:
	  # setup_priority controls when setup() runs relative to other plugins.
	  # Lower numbers run earlier. FileDownloader defaults to 15.
	  setup_priority: 15
	  download_path: ./config/var/lists
	  interval_seconds: 3600
	  urls:
		- https://v.firebog.net/hosts/AdguardDNS.txt
		- https://v.firebog.net/hosts/Easylist.txt
		- https://v.firebog.net/hosts/Prigent-Ads.txt
		- https://v.firebog.net/hosts/Prigent-Malware.txt

  # Filter plugin: loads domain lists and applies domain/IP filtering.
  - module: filter
	  # pre_priority for setupable plugins, or to the class default (50).
	  setup_priority: 20

	  # Pre-resolve (domain) filtering
	  blocked_domains:
		- "malware.com"
		- "phishing-site.org"
		- "spam.example"

	  blocked_patterns:
		- ".*\\.porn\\..*"      # Block any domain with "porn" in subdomain
		- "casino[0-9]+\\..*"   # Block casino1.com, casino2.net, etc.
		- ".*adult.*"           # Block domains containing "adult"

	  blocked_keywords:
		- "porn"
		- "gambling"
		- "casino"
		- "malware"
		- "phishing"

	  # Optional: file-backed allow/block inputs (globs allowed)
	  # allowed_domains_files:
	  #   - config/allow.txt
	  #   - config/allow.d/*.list
	  # blocked_domains_files:
	  #   - config/block.txt
	  #   - config/block.d/*.txt
	  # blocked_patterns_files:
	  #   - config/patterns/*.re
	  # blocked_keywords_files:
	  #   - config/keywords.txt
	  # blocked_ips_files:
	  #   - config/ips.txt

	  # Post-resolve (IP) filtering with per-IP actions
	  blocked_ips:
		# Remove just the matching IP(s)
		- ip: "23.220.75.245/16"
		  action: "remove"
		# Deny entire response if any returned IPs are found
		- ip: "1.2.3.4"
		  action: "deny"

  # Examples plugin: demonstrates additional policies and rewrites.
  - module: foghorn.plugins.examples.ExamplesPlugin
	config:
	  # Pre-resolve policy
	  max_subdomains: 5
	  max_length_no_dots: 50
	  base_labels: 2

	  # Post-resolve IP rewrite rules
	  rewrite_first_ipv4:
		- apply_to_qtypes: ["A"]
		  ip_override: 127.0.0.1
		- apply_to_qtypes: ["AAAA"]
		  ip_override: ::1

```

------

## Logging

Foghorn includes configurable logging with bracketed level tags and UTC timestamps. Example output:

```
2025-10-24T05:56:01Z [info] foghorn.main: Starting Foghorn on 127.0.0.1:5354
2025-10-24T05:56:01Z [debug] foghorn.server: Query from 127.0.0.1: example.com 1
2025-10-24T05:56:02Z [warn] foghorn.plugins.new_domain_filter: Domain example-new.com blocked (age: 3 days, threshold: 7)
```

See README-DEV.md for advanced logging and statistics options.

## License

MIT, see LICENSE file.
