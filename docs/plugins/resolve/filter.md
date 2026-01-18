# Filter resolve plugin

## Overview

The `filter` resolve plugin provides flexible domain and IP filtering. It has
both:

- **pre-resolve** logic to allow/deny queries based on domain lists, patterns
  and keywords; and
- **post-resolve** logic to inspect A/AAAA answers and remove, deny or replace
  specific IPs or subnets.

It supports large list files (often fed by `file_downloader`) using an internal
SQLite database and an in-memory TTL cache for decisions.

Typical use cases:

- Ad-blocking or privacy filtering for home and lab networks.
- Security filtering for known malware, phishing, or tracking domains.
- Enforcing simple policy allow/deny rules for specific domains or IP ranges.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: adblock-filter
    type: filter
    hooks:
      pre_resolve:  { priority: 25 }
      post_resolve: { priority: 25 }
    config:
      default: allow                 # allow everything unless blocked
      ttl: 300                       # TTL for synthetic IP responses
      deny_response: ip              # deny via synthetic IPs
      deny_response_ip4: 0.0.0.0
      deny_response_ip6: ::1

      blocked_domains_files:
        - ./config/var/lists/*      # domain-per-line lists
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: filter-advanced
    type: filter
    hooks:
      pre_resolve:  { priority: 25 }
      post_resolve: { priority: 25 }
    config:
      # BasePlugin targeting + logging
      targets: [ 0.0.0.0/0 ]
      targets_listener: any
      target_qtypes: [ '*' ]          # apply to all qtypes logically supported
      logging:
        level: info
        stderr: true

      # Core behaviour
      cache_ttl_seconds: 600          # TTL for domain decision cache
      db_path: ./config/var/filter.db # when empty => per-instance in-memory DB
      default: deny                   # default decision when not matched
      ttl: 300                        # TTL for synthetic IP answers

      # What to send when a query is denied in pre/post phases
      deny_response: nxdomain         # nxdomain|refused|servfail|noerror_empty|ip
      deny_response_ip4: 0.0.0.0      # used when deny_response == 'ip'
      deny_response_ip6: ::1

      # Optional qtype-level policy
      allow_qtypes: [ 'A', 'AAAA' ]   # only allow A/AAAA; everything else denied
      deny_qtypes:  [ 'ANY' ]         # or explicitly deny certain types

      # Domain allow/block lists
      allowed_domains_files:
        - ./config/allowlists/*.txt
      blocked_domains_files:
        - ./config/blocklists/*.txt

      allowed_domains:
        - www.example.com
      blocked_domains:
        - ads.example.com
        - tracker.example.net

      # Regex and keyword filters
      blocked_patterns:
        - '.*\\.adult\\.'
        - '(^|\\.)casino[0-9]*\\.'
      blocked_patterns_files:
        - ./config/patterns/*.txt

      blocked_keywords:
        - 'gambling'
        - 'malware'
      blocked_keywords_files:
        - ./config/keywords/*.txt

      # IP / subnet rules for post-resolve filtering
      blocked_ips:
        # Simple form: all use default action 'deny'
        - '203.0.113.5'
        - '198.51.100.0/24'

        # Detailed form with per-entry action
        - ip: '192.0.2.1'
          action: deny
        - ip: '203.0.113.99'
          action: remove
        - ip: '2001:db8::/32'
          action: deny
        - ip: '203.0.113.10'
          action: replace
          replace_with: '127.0.0.1'

      blocked_ips_files:
        - ./config/ip-blocks/*.txt
```

## Options

### Domain-side options (`FilterConfig`)

- `cache_ttl_seconds: int`
  - TTL (seconds) for entries in the in-memory domain decision cache.
- `db_path: str | null`
  - SQLite database path for storing allow/deny lists. When omitted or empty,
    an in-memory DB is used per Filter instance.
- `default: str`
  - Default policy when no list/pattern/keyword match exists: `"allow"` or
    `"deny"` (default: `"deny"`).
- `ttl: int`
  - TTL for synthesized IP answers when `deny_response == 'ip'`.
- `deny_response: str`
  - Policy for denied queries:
    - `"nxdomain"` (default): server synthesizes NXDOMAIN.
    - `"refused"` / `"servfail"`.
    - `"noerror_empty"` / `"nodata"`: NOERROR with empty answer.
    - `"ip"`: synthesize A/AAAA answers using `deny_response_ip4`/`deny_response_ip6`.
- `deny_response_ip4: str | null`, `deny_response_ip6: str | null`
  - Replacement IPs used when `deny_response == 'ip'`.
- `clear: int`
  - When non-zero (default `1`), drop and recreate the internal `blocked_domains` table on startup so it reflects current files and inline config.
  - Set to `0` to preserve existing rows across restarts (for example when pre-populating the database).

- `allowed_domains_files`, `blocked_domains_files: list[str]`
  - Paths (globs allowed) to domain-per-line files imported into the DB.
- `allowed_domains`, `blocked_domains: list[str]`
  - Inline domains to allow/deny.
- `blocked_patterns`, `blocked_patterns_files`
  - Regex patterns applied to the FQDN.
- `blocked_keywords`, `blocked_keywords_files`
  - Simple substring matches inside the FQDN.

### IP-side options

- `blocked_ips: list[str | object]`
  - Each entry is either:
    - a string IP or CIDR (defaults to `action: "deny"`), or
    - a mapping with keys:
      - `ip: str` – IP or CIDR string.
      - `action: "remove" | "deny" | "replace"`.
      - `replace_with: str` (required when `action == "replace"`).
- `blocked_ips_files: list[str]`
  - Files containing one JSON or simple text rule per line (see code/docs for
    exact formats); loaded additively.

### Qtype policy options

- `allow_qtypes: list[str]`, `deny_qtypes: list[str]`
  - Converted to dnslib QTYPE integers. When `allow_qtypes` is non-empty, any
    qtype not in that set is immediately denied. When `deny_qtypes` contains the
    qtype, it is also denied even if otherwise allowed.

### Behaviour

- Pre-resolve:
  1. Enforce qtype policy.
  2. Consult cache by `(domain, qtype)` / `(domain, 0)` key.
  3. Check exact allow/deny lists.
  4. Check keyword and regex patterns.
  5. Cache and return either `PluginDecision(action="skip")` (allowed) or a
     deny decision according to `deny_response`.
- Post-resolve:
  - Only A/AAAA records are inspected. For each address, the best-matching
    `blocked_ips` or `blocked_networks` entry is applied. Actions:
    - `deny` → entire response denied according to `deny_response`.
    - `remove` → record removed; if all are removed, response is denied.
    - `replace` → rdata changed to `replace_with` (same IP family required).

### Common BasePlugin options

Filter supports all BasePlugin targeting and logging options as shown in the
full configuration example above.
