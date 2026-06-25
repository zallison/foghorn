# DnsRebinding resolve plugin

## Overview
The `dns_rebinding` resolve plugin inspects post-resolve A/AAAA answers and blocks responses that map non-allowlisted names to private address space. This helps reduce DNS rebinding attack exposure for clients that trust your resolver.

When a policy violation is found, the plugin returns `PluginDecision(action="deny")`, and the resolver pipeline synthesizes NXDOMAIN.

## Basic configuration
```yaml path=null start=null
plugins:
  - type: dns_rebinding
    id: dns-rebinding
    hooks:
      post_resolve:
        priority: 40
    config:
      allowlist_domains:
        - printer.example.com
        - .vpn.example.com
        - .mytld
```

## Full configuration
```yaml path=null start=null
plugins:
  - type: dns_rebinding
    id: dns-rebinding-strict
    enabled: true
    hooks:
      post_resolve:
        priority: 40
    config:
      # BasePlugin targeting is supported.
      targets:
        ips:
          - 10.0.0.0/8
        listeners:
          - udp
          - tcp
        qtypes:
          - A
          - AAAA

      # Plugin-specific options.
      allowlist_mode: suffix   # suffix | exact
      allowlist_domains:
        - .my.tld
        - vpn.example.com
      private_cidrs:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 127.0.0.0/8
        - 169.254.0.0/16
        - ::1/128
        - fc00::/7
        - fe80::/10
```

## Options
- `allowlist_domains: list[str]`
  - Domain names allowed to resolve to private IPs.
- `allowlist_mode: 'suffix' | 'exact'`
  - `suffix` (default): `a.b.example.com` matches `example.com`.
  - `exact`: only exact qname matches.
- `private_cidrs: list[str]`
  - CIDR ranges treated as private/rebinding-sensitive.
  - Invalid CIDRs are ignored with warnings.

## Behavior summary
- Runs in `post_resolve`.
- Applies BasePlugin targeting (`targets`, `targets.qtypes`, listener/domain gates, etc.).
- Parses upstream response answers and inspects A/AAAA RDATA values.
- If any returned address is in `private_cidrs` and qname is not allowlisted, returns deny.
