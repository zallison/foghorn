# Foghorn

Foghorn is a lightweight, caching DNS server built with Python. It's designed to be fast and extensible, featuring a pluggable policy system that allows you to customize its behavior to fit your needs.

With special thanks to Fiona Weatherwax for their contributions.

## Features

*   **DNS Caching:** Speeds up DNS resolution by caching responses from upstream servers.
*   **Extensible Plugin System:** Easily add custom logic to control DNS resolution.
*   **Flexible Configuration:** Configure the server, upstream resolvers, and plugins using a simple YAML file.
*   **Built-in Plugins:** Comes with a set of useful plugins to get you started:
    *   **Access Control:** Filter DNS queries based on the client's IP address (CIDR-based allow/deny).
    *   **Greylist:** Block domains for a set amount of time after they are first requested.
    *   **New Domain Filter:** Block domains that were registered recently.
    *   **Upstream Router:** Route queries to different upstream servers based on the domain name.
    *   **Filter:** Block queries based on domain names, keywords, and IP addresses in responses.
    *   **Examples:** Misc examples, replace the first entry of every record to localhost, limit the length of the domain name, or the depth of domain names.



## Installation

1.  **Create a virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2.  **Install the package with development dependencies:**

    ```bash
    pip install .
    ```

    To install the project in editable mode, along with all runtime and development dependencies.

    ```bash
    pip install -e ".[dev]"
    ```

## Usage

To run the server, you first need a `config.yaml` file. Then, you can start the server with the `foghorn` command:

```bash
foghorn --config config.yaml
```
Alternatively, you can run it as a module:
```bash
python -m foghorn.main --config config.yaml
```

The server will start listening for DNS queries on the configured host and port.

## Testing

To run the test suite, use `pytest`:

```bash
pytest
```

## Code Formatting

This project uses `black` for code formatting. To format the code, run:

```bash
black src tests
```

## Configuration

Configuration is handled through a `config.yaml` file. The file has three main sections: `listen`, `upstream`, and `plugins`.

### `listen`

This section defines the host and port the server will listen on.

```yaml
listen:
  host: 127.0.0.1
  port: 5353
```

### `upstream`

This section specifies the upstream DNS servers to which queries will be forwarded. You can provide a list of servers, and they will be tried in order.

```yaml
upstream:
  - host: 1.1.1.1
    port: 53
    timeout_ms: 2000
  - host: 8.8.8.8
    port: 53
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

Foghorn includes configurable logging with bracketed level tags and UTC timestamps. Log output includes the timestamp, level tag, logger name, and message:

```
2025-10-24T05:56:01Z [info] foghorn.main: Starting Foghorn on 127.0.0.1:5354
2025-10-24T05:56:01Z [debug] foghorn.server: Query from 127.0.0.1: example.com 1
2025-10-24T05:56:02Z [warn] foghorn.plugins.new_domain_filter: Domain example-new.com blocked (age: 3 days, threshold: 7)
```

### Configuration

Add a `logging` section to your `config.yaml`:

```yaml
logging:
  level: info          # Available levels: debug, info, warn, error, crit
  stderr: true         # Log to stderr (default: true)
  file: ./foghorn.log  # Optional: also log to this file
  syslog: true         # Optional: also log to syslog (default: false)
```

To configure syslog with custom options:

```yaml
logging:
  level: info
  syslog:
    address: /dev/log  # Unix socket (default: /dev/log) or ("hostname", port) for network syslog
    facility: USER     # Syslog facility (default: USER; others: LOCAL0-LOCAL7, DAEMON, etc.)
```

### Available Levels

*   **debug**: Detailed diagnostic information including each query, cache hits/misses, plugin decisions
*   **info**: General information about server startup, configuration, and important events
*   **warn**: Warning conditions like denied queries, upstream timeouts, plugin errors
*   **error**: Error conditions that don't stop the server
*   **crit**: Critical errors that may cause the server to stop

### File Logging

When `file` is specified, Foghorn will:
*   Create parent directories automatically if they don't exist
*   Log to both stderr and the file (if `stderr: true`)
*   Append to the file (it won't overwrite existing content)
*   Use UTF-8 encoding

### Plugin Logging

Plugin authors can use Python's standard `logging` module and will inherit the same bracketed format:

```python
import logging

logger = logging.getLogger(__name__)
logger.warning("Custom plugin warning: %s", some_value)
```

## Plugin Development

You can extend Foghorn by creating your own plugins. A plugin is a Python class that inherits from `BasePlugin` and implements one or both of the following methods:

*   `pre_resolve(self, qname, qtype, ctx)`: This method is called before a query is resolved. It can return a `PluginDecision` to `allow`, `deny`, or `override` the query.
*   `post_resolve(self, qname, qtype, response_wire, ctx)`: This method is called after a query has been resolved. It can also return a `PluginDecision` to modify the response.
