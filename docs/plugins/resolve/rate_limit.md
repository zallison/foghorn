# RateLimit resolve plugin

## Overview

The `rate_limit` resolve plugin implements adaptive, learning rate limiting
backed by sqlite3. It tracks request rates per key (client, client+domain, or
base domain) over sliding windows, learns a baseline requests-per-second (RPS)
for each key, and only starts enforcing when current traffic is a clear outlier.

It can respond to limited queries with NXDOMAIN, REFUSED, SERVFAIL, NOERROR
(empty), or synthetic IP answers, depending on configuration.

Typical use cases:

- Protecting upstream resolvers and shared infrastructure from abusive or buggy clients.
- Throttling automated scanners, misconfigured services, or runaway scripts without hard per-IP limits.
- Detecting and dampening sudden spikes for specific domains or clients while allowing normal bursts.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: rl-per-client
    type: rate_limit
    hooks:
      pre_resolve: { priority: 50 }
    config:
      mode: per_client
      window_seconds: 10
      warmup_windows: 6
      burst_factor: 3.0
      min_enforce_rps: 50.0
      db_path: ./config/var/rate_limit.db
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: rl-advanced
    type: rate_limit
    hooks:
      pre_resolve: { priority: 50 }
    config:
      # BasePlugin targeting + logging
      targets: [ 0.0.0.0/0 ]
      targets_listener: any
      target_qtypes: [ '*' ]
      logging:
        level: info
        stderr: true

      # How to key rate limits
      mode: per_client_domain        # per_client|per_client_domain|per_domain

      # Window and learning parameters
      window_seconds: 10             # length of measurement window
      warmup_windows: 6              # no enforcement until N complete windows
      alpha: 0.2                     # EWMA factor when new >= average
      alpha_down: 0.1                # EWMA when new < average (optional)

      # Enforcement thresholds
      burst_factor: 3.0              # allow up to 3x learned average
      min_enforce_rps: 50.0          # do not enforce on low-traffic keys
      global_max_rps: 5000.0         # hard ceiling per key (0 => disabled)

      # Persistence
      db_path: ./config/var/rate_limit.db

      # Deny behaviour
      deny_response: nxdomain        # nxdomain|refused|servfail|noerror_empty|ip
      deny_response_ip4: 0.0.0.0
      deny_response_ip6: ::1
      ttl: 60                        # TTL for synthetic IP answers when using 'ip'
```

## Options

### Plugin-specific options (`RateLimitConfig`)

- `mode: str`
  - How to identify a key for rate limiting:
    - `"per_client"` (default): key is client IP.
    - `"per_client_domain"`: key is `(client IP, base domain)`.
    - `"per_domain"`: key is base domain only.
- `window_seconds: int`
  - Sliding window size in seconds (>= 1).
- `warmup_windows: int`
  - Number of *completed* windows to observe before enforcing. During warmup,
    counters are learned but no queries are blocked.
- `alpha: float`, `alpha_down: float | null`
  - EWMA smoothing factors for the learned baseline RPS.
  - `alpha` applies when the new rate is >= the baseline; `alpha_down` (or
    `alpha` if omitted) applies when the new rate is < baseline.
- `burst_factor: float`
  - Multiplier over the learned average RPS that defines the soft ceiling. For
    example, with baseline 100 RPS and `burst_factor=3.0`, enforcement starts
    above ~300 RPS.
- `min_enforce_rps: float`
  - Minimum baseline RPS required before enforcement is considered; protects
    low-traffic keys from being throttled by a few extra queries.
- `global_max_rps: float`
  - Hard upper bound on allowed RPS per key. `0` disables this cap.
- `db_path: str`
  - sqlite3 file path used to persist learned profiles across restarts.
- `deny_response: str`
  - Policy for limited queries (same semantics as Filter):
    - `"nxdomain"` (default), `"refused"`, `"servfail"`, `"noerror_empty"`/`"nodata"`, `"ip"`.
- `deny_response_ip4: str | null`, `deny_response_ip6: str | null`
  - Replacement IPs used when `deny_response == 'ip'`.
- `ttl: int`
  - TTL for synthetic IP answers when `deny_response == 'ip'`.

### Behaviour

- For each request, RateLimit computes a key based on `mode` and updates a
  per-key window counter in an in-memory cache plus a sqlite-backed profile.
- Once a key has at least `warmup_windows` completed windows and a baseline
  above `min_enforce_rps`, new windows are evaluated against:
  - `burst_factor * baseline`, and
  - `global_max_rps` (if non-zero).
- When the current window's RPS exceeds allowed thresholds, the plugin returns a
  deny decision according to `deny_response`; otherwise it returns `None` and
  allows normal processing.

### Common BasePlugin options

RateLimit supports all BasePlugin targeting and logging options as shown in the
full configuration example.
