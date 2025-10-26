# Foghorn: Technical Project Overview

## Component Interactions & Data Flow

```
CLI/Config → main.py
    ↓
normalize_upstream_config() → (upstreams, timeout_ms)
load_plugins() → [plugin_instances]
init_logging() → Logger setup
    ↓
DNSServer.__init__() → ThreadingUDPServer created, plugins injected into handler class vars
    ↓
DNSServer.serve_forever() → Listens for UDP queries
    ↓
DNSUDPHandler.handle() per query:
    ├─ Parse query (DNSRecord)
    ├─ Instantiate PluginContext(client_ip)
    ├─ For each plugin: pre_resolve() → PluginDecision
    ├─ Cache lookup by (qname, qtype)
    ├─ send_query_with_failover(upstream_candidates or global upstreams)
    ├─ For each plugin: post_resolve() → PluginDecision
    ├─ Cache response (if NOERROR + has answers)
    └─ Send response to client
```


## Core Components

### 1. Main Entry Point (`foghorn/main.py`)
- **Purpose**: Parses CLI arguments, loads YAML configuration, initializes logging and plugins, and starts the DNS server
- **Key Functions**:
  - `normalize_upstream_config()`: Normalizes upstream DNS server configuration (supports both legacy single upstream and new multi-upstream list format with automatic failover)
  - `load_plugins()`: Dynamically loads plugins using importlib; supports both full dotted paths and short aliases
  - `main()`: Orchestrates server initialization

### 2. DNS Server (`foghorn/server.py`)
- **Core Class**: `DNSServer` - Initializes a ThreadingUDPServer for concurrent UDP request handling
- **Request Handler**: `DNSUDPHandler` - Processes individual DNS queries with the following pipeline:
  1. **Parse Query**: Extracts qname and qtype from DNSRecord
  2. **Pre-resolve Plugin Phase**: Plugins can deny (NXDOMAIN), override, or allow queries
  3. **Cache Lookup**: Returns cached response if hit (cache key: (qname_lowercase, qtype))
  4. **Upstream Forwarding**: Sends query to upstream servers with automatic failover
  5. **Post-resolve Plugin Phase**: Plugins can modify responses
  6. **Cache Storage**: Caches NOERROR responses using minimum TTL from answer RRs (excludes SERVFAIL and NXDOMAIN)
  7. **Response**: Sends final response to client

- **Failover Logic** (`send_query_with_failover()`):
  - Tries each upstream in sequence
  - Triggers failover on: network errors, timeouts, SERVFAIL responses, parse exceptions
  - Does NOT failover on valid responses (NXDOMAIN, NOERROR)
  - Returns `(response_wire, used_upstream, reason)` tuple

### 3. Caching Layer (`foghorn/cache.py`)
- **Class**: `TTLCache` - Thread-safe, in-memory cache with TTL support
- **Data Structure**: Dictionary mapping `(qname_lowercase, qtype)` → `(expiry_epoch, wire_packet)`
- **Synchronization**: Uses `threading.RLock()` for thread safety
- **TTL Management**: Opportunistic expired-entry purging on get/set operations
- **API**:
  - `get(key)`: Retrieves cached data if not expired
  - `set(key, ttl, data)`: Stores data with TTL in seconds
  - `purge_expired()`: Manual cleanup of expired entries

### 4. Logging (`foghorn/logging_config.py`)
- **Formatter**: `BracketLevelFormatter` - Custom format with UTC ISO-8601 timestamps and bracketed level tags
- **Handlers**: Supports stderr, file, and syslog simultaneously
- **Configuration**: YAML-based with log level control (debug, info, warn, error, crit)
- **Features**: Auto-creates parent directories for file logging; gracefully falls back on syslog unavailability

## Plugin System Architecture (`foghorn/plugins/`)

### Base Plugin Framework (`base.py`)
- **`BasePlugin`**: Abstract base class for all plugins with:
  - `pre_resolve(qname, qtype, req, ctx)`: Hook before upstream query (can deny/override)
  - `post_resolve(qname, qtype, response_wire, ctx)`: Hook after upstream response (can deny/override)
  - `PluginDecision`: Dataclass with `action` ("allow"/"deny"/"override") and optional `response` bytes
  - `PluginContext`: Carries request context including `client_ip`, `upstream_candidates` (list override), and `upstream_override` (legacy)

### Plugin Discovery (`registry.py`)
- **Dynamic Loading**: Automatically discovers and imports plugin modules under `foghorn.plugins`
- **Alias Resolution**: Supports both full dotted paths (`foghorn.plugins.module.ClassName`) and short aliases
- **Default Aliasing**: Auto-generates default aliases from class names (CamelCase → snake_case)
- **Decorator**: `@plugin_aliases()` allows plugins to declare multiple aliases
- **Validation**: Raises on duplicate aliases; provides helpful suggestions on unknown aliases

### Built-in Plugins

#### 1. AccessControlPlugin (`access_control.py`)
- **Aliases**: `acl`, `access_control`
- **Function**: CIDR-based IP allow/deny lists with configurable default policy
- **Hook**: `pre_resolve()` - Denies/allows based on client IP
- **Config**: `default` (allow/deny), `allow` (list of CIDR ranges), `deny` (list of CIDR ranges)

#### 2. UpstreamRouterPlugin (`upstream_router.py`)
- **Aliases**: `upstream_router`, `router`, `upstream`
- **Function**: Routes queries to different upstreams based on domain suffix/exact match with failover
- **Hook**: `pre_resolve()` - Sets `ctx.upstream_candidates` to matched upstream list
- **Config**: `routes` list with `domain`/`suffix` matchers and `upstream`/`upstreams` targets
- **Failover**: Implements retry logic on network errors and SERVFAIL responses

#### 3. NewDomainFilterPlugin (`new_domain_filter.py`)
- **Aliases**: `new_domain`, `new_domain_filter`, `ndf`
- **Function**: Blocks domains registered recently (WHOIS query-based)
- **Hook**: `pre_resolve()` - Denies domains newer than threshold
- **Config**: `threshold_days` (minimum domain age), `timeout_ms` (WHOIS query timeout)

#### 4. FilterPlugin (`filter.py`)
- **Aliases**: `filter`
- **Function**: Multi-faceted filtering (domains and IPs)
- **Pre-resolve**: Blocks by exact domain match, regex patterns, or keywords
- **Post-resolve**: Blocks/removes/replaces IP addresses in responses (per-IP action: "deny", "remove", "replace")
- **Config**: `blocked_domains`, `blocked_patterns` (regex), `blocked_keywords`, `blocked_ips` (with per-IP actions)

#### 5. ExamplesPlugin (`examples.py`)
- **Function**: Demonstrates pre- and post-resolve hooks
- **Pre-resolve**: Denies excessively deep subdomains or long domain names
- **Post-resolve**: Rewrites first IPv4/IPv6 RR in responses (configurable per qtype)
- **Config**: `max_subdomains`, `max_length_no_dots`, `base_labels`, `rewrite_first_ipv4` rules

### Plugin Integration Points
- Plugins receive `PluginContext` which they can mutate (e.g., `upstream_router` sets `upstream_candidates`)
- Pre-resolve plugins can bypass upstream queries entirely via "override" action
- Post-resolve plugins can modify or deny responses before caching/sending
- All plugin decisions are logged with plugin class name for traceability

## Deployment Architecture

### Dependencies (installed via pip)
- `dnslib`: DNS protocol handling
- `pyyaml`: YAML configuration parsing
- `requests`: HTTP library (indirectly via plugins)
- `whois`: Domain registration lookup (for NewDomainFilterPlugin)
  Optional: use system `whois` commmand.

### Configuration (YAML format)
- **listen**: Host/port to bind
- **upstream**: Single dict or list of {host, port} (with optional legacy timeout_ms per upstream)
- **timeout_ms**: Global timeout in milliseconds (applied per upstream attempt)
- **logging**: Level, output destinations (stderr, file, syslog)
- **plugins**: List of plugin specs (module path + config, or short alias + config)

### Installation
- Python 3.7+ required
- Virtual environment recommended: `python3 -m venv venv && source venv/bin/activate`
- Install: `pip install -e ".[dev]"` (includes development dependencies)

### Runtime
- Listen port 5353 by default (port 53 requires elevated privileges)
- Single process with daemon thread pool for request handling
- Signal handling: `KeyboardInterrupt` (Ctrl+C) for graceful shutdown

## Runtime Behavior

### 1. Initialization
- Loads YAML config
- Initializes logging system (UTC timestamps, bracketed level tags)
- Normalizes upstream config (legacy vs. new format)
- Dynamically loads and instantiates plugins (via registry)
- Creates ThreadingUDPServer and injects config into handler class variables

### 2. Request Handling (per UDP packet)
- Parse DNS query (dnslib)
- Execute pre-resolve plugin chain (early exit on deny/override)
- Lookup cache (exact match on normalized qname + qtype)
- If cache miss: forward to upstream(s) with timeout and failover
- Execute post-resolve plugin chain (can modify/deny response)
- Cache response (TTL from min RR TTL, excludes SERVFAIL)
- Send response (with original request ID preserved)

### 3. Error Handling
- Upstream timeout → Try next upstream (or SERVFAIL if all fail)
- SERVFAIL from upstream → Try next upstream (failover trigger)
- Parse errors → Log and return SERVFAIL
- Plugin exceptions → Logged; query continues (no abort)

### 4. Caching Behavior
- Cache key: `(qname.lower(), qtype)`
- Cache hit: Return cached bytes with original query ID
- Cache population: Only NOERROR responses with answer RRs
- TTL: Minimum of all answer RRs (or default 300s)
- Eviction: Opportunistic on get/set; expired entries auto-purged
- No caching of SERVFAIL (allows retry on next request)
- No caching of NXDOMAIN (existing behavior preserved)

### 5. Logging Output
- Format: `<UTC_timestamp> <[level]> <logger_name>: <message>`
- Example: `2025-10-24T05:56:01Z [info] foghorn.main: Starting Foghorn on 127.0.0.1:5353`
- Configurable level per logger (debug → error → crit)
- Multiple output channels (stderr, file, syslog) simultaneously
