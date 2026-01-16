# UpstreamRouter resolve plugin

## Overview

The `upstream_router` resolve plugin routes queries to different upstream DNS
servers based on the queried domain name. It does not answer queries itself;
instead, it sets per-request upstream candidates on the `PluginContext`, which
the core resolver then uses to forward the query with failover.

Typical uses:

- Send all `*.corp` queries to on-prem resolvers while everything else goes to
  public resolvers.
- Route certain SaaS domains through special filtering or logging resolvers.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: corp-router
    type: upstream_router
    hooks:
      pre_resolve: { priority: 235 }
    config:
      targets: [ 192.168.0.0/16 ]
      routes:
        - suffix: corp
          upstreams:
            - host: 10.0.0.2
              port: 53
            - host: 10.0.0.3
              port: 53
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: router-advanced
    type: upstream_router
    hooks:
      pre_resolve: { priority: 230 }
    config:
      # BasePlugin targeting + logging
      targets:
        - 192.168.0.0/16
      targets_ignore:
        - 192.168.1.100/32
      targets_listener: any
      targets_domains:
        - example.com
      targets_domains_mode: suffix
      target_qtypes: [ 'A', 'AAAA' ]
      logging:
        level: info
        stderr: true

      # Route definitions
      routes:
        # Exact match: only 'internal.example.com'
        - domain: internal.example.com
          upstreams:
            - host: 10.1.0.10
              port: 53

        # Suffix match: any name ending in '.corp' or equal to 'corp'
        - suffix: corp
          upstreams:
            - host: 10.2.0.20
              port: 53
            - host: 10.2.0.21
              port: 53

        # Another suffix using a FQDN-style suffix
        - suffix: .svc.example
          upstreams:
            - host: 172.16.0.10
              port: 53
```

## Options

### Plugin-specific options

The configuration is described by `UpstreamRouterConfig` and `UpstreamRoute`:

- `routes: list[UpstreamRoute]`
  - Each route is a mapping with keys:

    - `domain: str | null`
      - Exact domain name to match. Compared case-insensitively with the
        trailing dot removed.
    - `suffix: str | null`
      - Domain suffix to match. Stored without a leading dot internally.
      - A query `qname` matches when `qname == suffix` or `qname` ends with
        `"." + suffix`.
    - `upstreams: list[{host, port}]` (required)
      - The upstream candidates to use when the route matches.
      - Each entry has:
        - `host: str` – IP or hostname of the upstream resolver.
        - `port: int` – port number (1–65535).

- Routes without at least one of `domain` or `suffix` or without any valid
  `upstreams` are ignored during normalization.

### Behaviour

- During `pre_resolve`, UpstreamRouter:
  1. Checks BasePlugin targeting (`targets*`, listener/domain filters).
  2. Normalizes `qname` (lowercase, no trailing dot).
  3. Walks routes in order and picks the first match.
  4. When a match is found, sets `ctx.upstream_candidates` to the route's
     `[{"host", "port"}, ...]` and returns `None` so normal processing continues.
- The core resolver is responsible for actually forwarding to the chosen
  upstreams and handling failover. A helper `_forward_with_failover` exists in
  the plugin code but is not used directly by configuration.

### Common BasePlugin options

UpstreamRouter supports all BasePlugin options for client, listener and
qtype/domain targeting, as well as per-plugin logging. The full configuration
example above demonstrates typical usage.
