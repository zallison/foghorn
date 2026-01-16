# MdnsBridge resolve plugin

## Overview

The `mdns_bridge` resolve plugin exposes mDNS / DNS-SD (zeroconf) services from
your local network as regular DNS records under a configurable DNS suffix.

It discovers services using the Python `zeroconf` library and then answers
queries for PTR, SRV, TXT, A and AAAA records based on what it has learned.

Typical use cases:

- Make devices that advertise mDNS services (printers, Chromecasts, HomeKit,
  etc.) discoverable via plain DNS under a corporate or lab domain.
- Inspect local services via DNS queries (e.g. `_services._dns-sd._udp.example`).

## Basic configuration

```yaml path=null start=null
plugins:
  - id: mdns-default
    type: mdns_bridge
    hooks:
      pre_resolve: { priority: 200 }
    config:
      # Serve mDNS data under your main domain
      targets: [ 192.168.0.0/16 ]
      domain: .zaa
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: mdns-advanced
    type: mdns_bridge
    hooks:
      pre_resolve: { priority: 200 }
    config:
      # BasePlugin targeting + logging
      targets: [ 192.168.0.0/16, 10.0.0.0/8 ]
      targets_listener: secure         # only DoT/DoH queries
      target_qtypes: [ 'PTR', 'SRV', 'TXT', 'A', 'AAAA' ]
      logging:
        level: info
        stderr: true

      # Primary DNS suffix under which to *serve* mDNS data
      domain: .mdns.example

      # Optional additional DNS suffixes (all mirror the same mDNS data)
      # domains:
      #   - .mdns.example
      #   - .lan

      # TTL applied to synthesized records
      ttl: 300

      # Zeroconf network options
      zeroconf_interfaces: default    # 'default', 'all', or list of IPs
      zeroconf_ip_version: v4         # 'v4', 'v6', or 'all'
      zeroconf_unicast: false         # pass through to Zeroconf(unicast=...)

      # Service discovery
      # When empty, MdnsBridge uses a large built-in list of common service types.
      service_types:
        - _http._tcp.local
        - _ipps._tcp.local

      # Address synthesis behaviour
      include_ipv4: true
      include_ipv6: true

      # Timeout when fetching ServiceInfo for a service instance (milliseconds)
      info_timeout_ms: 1500

      # Disable all mDNS network access (useful for tests)
      # network_enabled: false
```

## Options

### Plugin-specific options

These fields are defined by `MdnsBridgeConfig` and live under the plugin
`config` block:

- `domain: str`
  - DNS suffix under which the bridge will *serve* discovered data.
  - Normalized to `.suffix` form with no trailing dot; e.g. `"local"`, `.local.`,
    and `.local` all become `.local`.
- `domains: list[str]`
  - Optional additional DNS suffixes that all mirror the same discovered mDNS data (e.g. `.mdns.example` and `.lan`).
  - Each value is normalized to `.suffix` form with no trailing dot.
- `ttl: int`
  - TTL applied to synthesized answers.
  - Default: `300`.
- `network_enabled: bool`
  - When `false`, the plugin initializes internal data structures but does **not**
    create Zeroconf sockets or perform network I/O.
  - Useful for offline testing.
- `include_ipv4: bool`, `include_ipv6: bool`
  - Control whether A and/or AAAA records are synthesized for discovered hosts.
- `info_timeout_ms: int`
  - Timeout in milliseconds for Zeroconf `get_service_info()` calls.
- `zeroconf_interfaces: "default" | "all" | list[str]`
  - Passed through to `Zeroconf(interfaces=...)`.
  - `"default"` (default) lets Zeroconf pick interfaces.
  - `"all"` attempts to bind on all interfaces.
  - A list of IP strings restricts Zeroconf to specific interfaces.
- `zeroconf_ip_version: str | null`
  - Selects IPv4/IPv6 usage for Zeroconf:
    - `"v4"` → `IPVersion.V4Only`
    - `"v6"` → `IPVersion.V6Only`
    - `"all"` → `IPVersion.All`
  - Any other string is passed through as-is.
- `zeroconf_unicast: bool`
  - Passed as `unicast=` to the Zeroconf constructor.
- `service_types: list[str]`
  - Optional list of specific service types to browse directly
    (e.g. `"_http._tcp.local."`). When empty, MdnsBridge first browses
    `_services._dns-sd._udp.local.` and also falls back to a curated default
    list of common types.

### Behaviour

- Discovery always happens in the mDNS namespace `.local`, but MdnsBridge
  rewrites names into one or more configured DNS suffixes (e.g. `.mdns.example`).
- PTR answers for service types and helper namespaces (like `_services` and
  `_mdns`) are augmented with SRV/TXT/A/AAAA where possible so that a single
  query can often reveal instance metadata and host addresses.
- The plugin is read-only with respect to the network; it never advertises
  services, only mirrors what it sees.

### Common BasePlugin options

MdnsBridge supports all BasePlugin options (`targets*`, `targets_listener`,
`targets_domains*`, `target_qtypes`, `logging`, etc.) as shown in the full
configuration example above.
