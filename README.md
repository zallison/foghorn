# Foghorn

![Foghorn Logo](html/logo.png)

Foghorn is a lightweight, caching DNS server built with Python (3.10+). It's designed to be fast and extensible, featuring a pluggable policy system that allows you to customize its behavior to fit your needs.

With special thanks to Fiona Weatherwax for their contributions and inspiration.

For developer documentation (architecture, transports, plugin internals, testing), see README-DEV.md.

## Features

*   **DNS Caching:** Speeds up DNS resolution by caching responses from upstream servers.
*   **Extensible Plugin System:** Easily add custom logic to control DNS resolution.
*   **Flexible Configuration:** Configure listeners, upstream resolvers (UDP/TCP/DoT/DoH), and plugins using YAML.
*   **Built-in Plugins:**
    *   **Access Control:** CIDR-based allow/deny (allowlist/blocklist terminology in docs).
    *   **EtcHosts:** Answer queries based on host file(s).
    *   **Greylist:** Temporarily block newly seen domains.
    *   **New Domain Filter:** Block recently registered domains.
    *   **Upstream Router:** Route queries to different upstream servers by domain/suffix.
    *   **Filter:** Filter by domain patterns/keywords IPs.
    *   **Examples:** Showcase of simple policies and rewrites.

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

**Using the pre-built image:**

```bash
docker run -d -p 5353:5353/udp \
  -v /path/to/your/config.yaml:/foghorn/config.yaml \
  zallison/foghorn:latest
```

**Building locally:**

```bash
[cp /path/to/your/config.yaml .] # Optional
docker build -t my/foghorn .
docker run -d -p 5353:5353/udp my/foghorn
```

**Important:** Mount your `config.yaml` to `/foghorn/config.yaml` inside the container unless you've built your own image that contains your config.

If you need to expose additional listeners (TCP/DoT/DoH), add the corresponding port mappings:

```bash
docker run -d \
  -p 5353:5353/udp \
  -p 5353:5353/tcp \
  -p 8853:8853/tcp \
  -p 8053:8053/tcp \
  -v /path/to/your/config.yaml:/foghorn/config.yaml \
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

Configuration is handled through a `config.yaml` file. The file has three main sections: `listen`, `upstream`, and `plugins`.

### `listen`

You can enable one or more listeners. UDP is enabled by default; TCP, DoT, and DoH are optional and supported.

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
    port: 8053
    # Optional TLS
    # cert_file: /path/to/cert.pem
    # key_file: /path/to/key.pem

Note: The DoH listener is served by a dedicated FastAPI app using uvicorn in a
single background thread. TLS is applied via `cert_file`/`key_file`. Behavior is
RFC 8484‑compatible and unchanged from previous releases; only the runtime
implementation has changed.
```

### `upstream`

You can mix transports per upstream. If `transport` is omitted it defaults to UDP.

```yaml
upstream:
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

### `plugins`

This section is a list of plugins to load. Each plugin has a `module` and a `config` section. You can also specify a plugin as a short string alias.

You can use short aliases instead of full dotted paths:
- access_control or acl -> foghorn.plugins.access_control.AccessControlPlugin
- new_domain_filter or new_domain -> foghorn.plugins.new_domain_filter.NewDomainFilterPlugin
- upstream_router or router -> foghorn.plugins.upstream_router.UpstreamRouterPlugin
- filter -> foghorn.plugins.filter.FilterPlugin

Examples of plugin entries:
- As a dict with module/config: `{ module: acl, config: {...} }`
- As a plain alias string: `acl` (no config)

#### Plugin priorities and `setup_priority`

Plugins support three priority knobs in their config (all optional, integers 1–255):

- `pre_priority`: controls the order of `pre_resolve` hooks; lower values run first.
- `post_priority`: controls the order of `post_resolve` hooks; lower values run first.
- `setup_priority`: controls the order of one-time `setup()` calls during startup; lower values run first.

`setup_priority` is only used for plugins that override `BasePlugin.setup`. Its value is resolved as:

- Use the explicit `setup_priority` from config if provided.
- Otherwise, reuse the config’s `pre_priority` value for setup-aware plugins.
- Otherwise, fall back to the plugin’s class-level default (50).

This lets you, for example, have a ListDownloader plugin run its setup early (to download lists) and a Filter plugin run slightly later to load those lists from disk.

#### AccessControlPlugin

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

#### NewDomainFilterPlugin

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

#### UpstreamRouterPlugin

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

#### FilterPlugin

This plugin provides flexible filtering of DNS queries based on domain names, patterns, keywords, and response IPs.

**Configuration:**

- blocked_domains: list of exact domain names to block.
- blocked_patterns: list of regular expressions to match against the domain name.
- blocked_keywords: list of keywords to block if they appear anywhere in the domain name.
- blocked_ips: list of IP addresses or CIDR ranges to control post‑resolution behavior; each entry supports action deny, remove, or replace (with replace_with).

File-backed inputs (support globs):
- allowed_domains_files, blocked_domains_files (aliases also supported: allowlist_files, blocklist_files)
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
1) allowed_domains_files/allowlist_files
2) blocked_domains_files/blocklist_files
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

##### JSON Lines examples for files

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

#### ListDownloader plugin

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
  - module: list_downloader
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
    port: 8053
    # Optional TLS for DoH
    # cert_file: /path/to/cert.pem
    # key_file: /path/to/key.pem

# Multiple upstream DNS servers with automatic failover.
# All upstreams share a single timeout (timeout_ms) per attempt.
upstream:
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

# Global timeout applies to each upstream attempt
timeout_ms: 2000

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
  # reset_on_sigusr1: true
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

  # ListDownloader: runs early in the setup phase to download blocklists
  # that the Filter plugin will read from disk.
  - module: list_downloader
    config:
      # setup_priority controls when setup() runs relative to other plugins.
      # Lower numbers run earlier. ListDownloader defaults to 15.
      setup_priority: 15
      download_path: ./config/var/lists
      interval_seconds: 3600
      urls:
        - https://v.firebog.net/hosts/AdguardDNS.txt
        - https://v.firebog.net/hosts/Easylist.txt

  # Filter plugin: loads allowlists/blocklists and applies domain/IP filtering.
  - module: filter
    config:
      # setup_priority controls when setup() runs. When omitted, it falls back to
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

      # Optional: file-backed allowlist/blocklist inputs (globs allowed)
      # allowlist_files:
      #   - config/allow.txt
      #   - config/allow.d/*.list
      # blocklist_files:
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

## Logging

Foghorn includes configurable logging with bracketed level tags and UTC timestamps. Example output:

```
2025-10-24T05:56:01Z [info] foghorn.main: Starting Foghorn on 127.0.0.1:5354
2025-10-24T05:56:01Z [debug] foghorn.server: Query from 127.0.0.1: example.com 1
2025-10-24T05:56:02Z [warn] foghorn.plugins.new_domain_filter: Domain example-new.com blocked (age: 3 days, threshold: 7)
```

See README-DEV.md for advanced logging and statistics options.

## License

MIT
