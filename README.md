# Foghorn

Foghorn is a lightweight, caching DNS server built with Python (3.10+). It's designed to be fast and extensible, featuring a pluggable policy system that allows you to customize its behavior to fit your needs.

With special thanks to Fiona Weatherwax for their contributions.

For developer documentation (architecture, transports, plugin internals, testing), see README-DEV.md.

## Features

*   **DNS Caching:** Speeds up DNS resolution by caching responses from upstream servers.
*   **Extensible Plugin System:** Easily add custom logic to control DNS resolution.
*   **Flexible Configuration:** Configure listeners, upstream resolvers (UDP/TCP/DoT/DoH), and plugins using YAML.
*   **Built-in Plugins:**
    *   **Access Control:** CIDR-based allow/deny (allowlist/blocklist terminology in docs).
    *   **Greylist:** Temporarily block newly seen domains.
    *   **New Domain Filter:** Block recently registered domains.
    *   **Upstream Router:** Route queries to different upstream servers by domain/suffix.
    *   **Filter:** Filter by domain patterns/keywords and by response IPs.
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
          upstream:
            host: 10.0.0.1
            port: 53
        - suffix: ".dev.example.com"
          upstream:
            host: 192.168.1.1
            port: 53
```

**Example (short alias):**

```yaml
plugins:
  - module: router
    config:
      routes:
        - suffix: "corp"
          upstream:
            host: 10.0.0.53
            port: 53
```

#### FilterPlugin

This plugin provides flexible filtering of DNS queries based on domain names, patterns, keywords, and response IPs.

**Configuration:**

*   `blocked_domains`: A list of exact domain names to block.
*   `blocked_patterns`: A list of regular expressions to match against the domain name.
*   `blocked_keywords`: A list of keywords to block if they appear anywhere in the domain name.
*   `blocked_ips`: A list of IP addresses or CIDR ranges to block in the response. You can specify an `action` for each (`deny` or `remove`).

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
        - ip: "8.8.8.8/24"
          action: "remove" # Remove just this A/AAAA record
```

## Complete `config.yaml` Example

Here is a complete `config.yaml` file that uses all the available features:

```yaml
# Example configuration for the DNS caching server
listen:
  host: 127.0.0.1
  port: 5300

# Multiple upstream DNS servers with automatic failover
upstream:
  - host: 8.8.8.8
    port: 53
  - host: 1.1.1.1
    port: 53

# Global timeout applies to each upstream attempt
timeout_ms: 2000

# Minimum cache TTL (in seconds) applied to ***all*** cached responses.
# - For NOERROR with answers: cache TTL = max(min(answer TTLs), min_cache_ttl)
# - For NOERROR with no answers, NXDOMAIN, and SERVFAIL: cache TTL = min_cache_ttl
# Note: TTL field in the DNS response is not rewritten; this controls cache expiry only.
min_cache_ttl: 60

# Logging configuration
logging:
  level: debug            # Available levels: debug, info, warn, error, crit
  stderr: true            # Log to stderr (default: true)
  file: /tmp/foghorn.log  # Optional: also log to this file
  syslog: false           # Optional: also log to syslog

plugins:
  - module: new_domain
    config:
      threshold_days: 14

  - module: greylist
    config:
      duration_seconds: 60
  #     # duration_hours: 1 # Only if duration_seconds isn't provided
  #     # db_path: ./greylist.db

  - module: router
    config:
      routes:
        # Single upstream (legacy format)
        - suffix: ".mylan"
          upstream:
            host: 192.168.1.1
            port: 53
        # Multiple upstreams with failover (new format)
        - suffix: "corp.internal"
          upstreams:
            - host: 10.0.0.1
              port: 53
            - host: 10.0.0.2
              port: 53

  - module: filter
    config:
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

      # Post-resolve (IP) filtering with per-IP actions
      blocked_ips:
        # Remove just the matching IP(s)
        - ip: "23.220.75.245/16"
          action: "remove"
        # Deny entire response if any returned IPs are found
        - ip: "1.2.3.4"
          action: "deny"

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
