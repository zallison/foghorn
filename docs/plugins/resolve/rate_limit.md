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

## Important: protections that run before this plugin

The `rate_limit` plugin runs in the resolver pipeline. Some listener/transport
guardrails execute **before** a query reaches plugin hooks, so those requests
will not be counted or denied by `rate_limit`.

Key pre-plugin protections:

- UDP listener inflight shedding (`server.listen.udp.max_inflight`,
  `server.listen.udp.max_inflight_per_ip`, `server.listen.udp.max_inflight_by_cidr`)
  can shed traffic before resolver/plugin execution.
- UDP query-size gate (`server.listen.udp.max_query_bytes`) drops undersized or
  oversized packets before plugin execution.
- TCP/DoT connection limits (`server.listen.tcp.max_connections`,
  `server.listen.tcp.max_connections_per_ip`, and DoT equivalents) can reject
  connections before the query reaches the plugin.
- TCP/DoT per-connection caps (`max_queries_per_connection`,
  `idle_timeout_seconds`) can close connections before additional queries reach
  plugin hooks.
- TCP/DoT frame-size protections (oversized DNS-over-TCP frames) close/break
  before resolver/plugin execution.
- DoH request-size protections reject oversized DoH requests (HTTP 413) before
  resolver/plugin execution.

Overload response policy for listener-level shedding/rejection is controlled by:

- Global default: `server.listen.overload_response`
- Per-listener override:
  - `server.listen.udp.overload_response`
  - `server.listen.tcp.overload_response`
  - `server.listen.dot.overload_response`

Allowed values are `servfail`, `refused`, `drop`.

If `server.listen.overload_response` is not set, backward-compatible defaults are:

- UDP: `servfail`
- TCP/DoT: `drop`

DoH currently relies on HTTP-level protections (for example 413 size checks and
timeout/close behavior) rather than the DNS overload-response policy above.

Practical implication: under heavy load you may observe transport-level
SERVFAIL/REFUSED/drop behavior that occurs before `rate_limit` policy evaluation.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: rl-per-client
	type: rate_limit
	hooks:
	  pre_resolve: 50
	config:
	  mode: per_client
	  window_seconds: 10
	  warmup_windows: 6
	  burst_factor: 3.0
	  burst_windows: 6
	  min_enforce_rps: 50.0
	  stats_log_interval_seconds: 900
	  db_path: ./config/var/dbs/rate_limit.db
```

## Configuration profiles (presets)

RateLimit ships with a small set of preset configuration bundles (profiles)
stored in an external YAML file:

- `src/foghorn/plugins/resolve/rate_limit_profiles.yaml`

These are loaded by `foghorn.config.plugin_profiles.load_builtin_profiles('rate_limit')`
(and are intended to be merged with explicit config in higher-level config logic).

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: rl-advanced
	type: rate_limit
	hooks:
	  pre_resolve: 50
	config:
	  # BasePlugin targeting + logging
	  targets:
		ips: [ 0.0.0.0/0 ]
		listeners: any
		qtypes: [ '*' ]
		opcodes: [ 'QUERY' ]
	  logging:
		level: info
		stderr: true

	  # How to key rate limits
	  mode: per_client_domain        # per_client|per_client_domain|per_domain

	  # Window and learning parameters
	  window_seconds: 10             # length of measurement window
	  warmup_windows: 6              # no enforcement until N complete windows
	  warmup_max_rps: 0.0            # optional hard cap during warmup (0 disables)
	  alpha: 0.2                     # EWMA factor when new >= average
	  alpha_down: 0.1                # EWMA when new < average (optional)
	  bootstrap_rps: 0.0             # optional bootstrap baseline (0 disables)

	  # Enforcement thresholds
	  burst_factor: 3.0              # allow up to 3x learned average
	  burst_windows: 6               # consecutive burst windows before disabling
	  burst_reset_windows: 20        # consecutive below-threshold windows before reset
	  limit_recalc_windows: 10       # recalculate per-bucket limits every N windows
	  min_enforce_rps: 50.0          # do not enforce on low-traffic keys
	  max_enforce_rps: 5000.0         # hard ceiling per key (0 => disabled)

	  # Persistence
	  db_path: ./config/var/dbs/rate_limit.db

	  # Deny behaviour
	  deny_response: nxdomain        # nxdomain|refused|servfail|noerror_empty|ip
	  deny_response_ip4: 0.0.0.0
	  deny_response_ip6: ::1
	  ttl: 60                        # TTL for synthetic IP answers when using 'ip'
	  assume_udp_when_listener_missing: true  # apply UDP prefix bucketing when listener is unknown
	  bucket_network_prefix_v4: 24   # CIDR prefix used for insecure UDP client buckets
	  bucket_network_prefix_v6: 56   # CIDR prefix used for insecure UDP client buckets
	  psl_strict: false              # fail startup if PSL extraction is unavailable
	  stats_log_interval_seconds: 900  # periodic summary logging fallback when stats_window_seconds is 0
	  stats_window_seconds: 3600       # logs every 3600s and summarizes only the last 3600s

	  # Deny-event visibility
	  deny_log_interval_seconds: 60    # min seconds between per-bucket server log messages (0 = always)
	  deny_log_first_n: 3              # write query-log rows for first N denies per episode; 0 = suppress all
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
- `warmup_max_rps: float`
  - Optional hard RPS cap enforced during warmup windows. `0` disables.
- `alpha: float`, `alpha_down: float | null`
  - EWMA smoothing factors for the learned baseline RPS.
  - `alpha` applies when the new rate is >= the baseline; `alpha_down` (or
	`alpha` if omitted) applies when the new rate is < baseline.
- `burst_factor: float`
  - Multiplier over the learned average RPS that defines the soft ceiling. For
	example, with baseline 100 RPS and `burst_factor=3.0`, enforcement starts
	above ~300 RPS.
- `burst_windows: int`
  - Number of consecutive windows where the current RPS exceeds
	`max(avg_rps * burst_factor, min_enforce_rps)` before the burst factor is
	disabled. `0` keeps the existing unlimited burst behavior.
- `burst_reset_windows: int`
  - Number of consecutive completed windows at or below the burst threshold
	required before burst state resets back to zero (default `20`).
- `limit_recalc_windows: int`
  - Number of completed windows between recalculations of per-bucket allowed
	RPS thresholds derived from the learned average (default `10`).
- `bootstrap_rps: float`
  - Optional baseline RPS used to seed a profile when no historical data exists.
	When set, enforcement can occur immediately instead of waiting for warmup.
- `min_enforce_rps: float`
  - Minimum baseline RPS required before enforcement is considered; protects
	low-traffic keys from being throttled by a few extra queries.
- `max_enforce_rps: float`
  - Hard upper bound on allowed RPS per key. `0` disables this cap.
- `db_path: str`
  - sqlite3 file path used to persist learned profiles across restarts.
- `deny_response: str`
  - Policy for limited queries (same semantics as Filter):
	- `"nxdomain"` (default), `"refused"`, `"servfail"`, `"noerror_empty"`/`"nodata"`, `"ip"`.
- `deny_response_ip4: str | null`, `deny_response_ip6: str | null`
  - Replacement IPs used when `deny_response == 'ip'` for A/AAAA queries.
- `assume_udp_when_listener_missing: bool`
  - When `true`, missing/unknown listener metadata on insecure transports
	uses UDP CIDR prefix bucketing as a spoofing fallback.
- `ttl: int`
  - TTL for synthetic IP answers when `deny_response == 'ip'`.
- `stats_log_interval_seconds: int`
  - Periodic summary log interval in seconds used when
	`stats_window_seconds == 0`. When both are `0`, summary logging is
	disabled. Logs only when `avg_rps > 0`.
- `stats_window_seconds: int`
  - Optional lookback window (seconds) for periodic summary log aggregates.
	When greater than `0`, stats are logged every `stats_window_seconds` and
	only per-window samples with `last_update >= now - window` are included.
	This keeps `avg_rps`/`max_rps` calculations window-scoped instead of
	lifetime-scoped. `0` uses all stored profiles and defers cadence to
	`stats_log_interval_seconds`.
- `deny_log_interval_seconds: int`
  - Minimum seconds between per-key deny log messages. `0` logs every denial;
	the default `10` throttles messages with suppressed counts reported in the
	next emitted message.
- `deny_log_first_n: int`
  - Number of denied queries for which a persistent query-log row is written at
	the start of each blocked episode per key. After this many logged denies the
	query-log row is suppressed for the remainder of the episode. The counter
	resets when the key's rate drops back below the allowed threshold, so the
	next blocked episode again produces up to `deny_log_first_n` visible rows.
	`0` suppresses all query-log rows for rate-limited queries. Default `3`.
	This gives offending clients visibility in the query log without flooding it.
- `psl_strict: bool`
  - When `true`, fail startup if PSL extraction is unavailable while using
	`per_domain`/`per_client_domain` modes.

### Behaviour

- For each request, RateLimit computes a key based on `mode` and updates a
  per-key window counter in an in-memory cache plus a sqlite-backed profile.
- Once a key has at least `warmup_windows` completed windows and a baseline
  above `min_enforce_rps`, new windows are evaluated against:
  - a recalculated burst threshold (`burst_factor * baseline`) refreshed every
	`limit_recalc_windows` windows, and
  - `max_enforce_rps` (if non-zero).
- When `warmup_max_rps` is set, the plugin enforces that cap even during warmup
  or before any profile exists.
- When `bootstrap_rps` is set, the plugin seeds a baseline to reduce the
  first-window blind spot.
- When `burst_windows > 0`, the burst factor is disabled after the configured
  number of consecutive burst windows.
- Burst state resets only after `burst_reset_windows` consecutive completed
  windows at or below threshold.
- When the current window's RPS exceeds allowed thresholds, the plugin returns a
  deny decision according to `deny_response`; otherwise it returns `None` and
  allows normal processing.
- For the first `deny_log_first_n` denied queries in a blocked episode, the
  decision carries `suppress_query_log=False` so the core resolver writes a
  persistent query-log row. Subsequent denies in the same episode suppress
  the query-log row to avoid flooding. The episode counter resets when the
  key is next seen below its allowed threshold. Server-log deny messages are
  separately throttled by `deny_log_interval_seconds`.

### Common BasePlugin options

RateLimit supports all BasePlugin targeting and logging options as shown in the
full configuration example.
