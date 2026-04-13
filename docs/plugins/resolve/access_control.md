# AccessControl resolve plugin

## Overview

The `access_control` resolve plugin enforces simple allow/deny policies based on the client IP address. It runs in `pre_resolve` and can drop or deny queries from disallowed networks before any other resolution occurs.

Typical use cases:

- Only allow LAN clients to query Foghorn.
- Deny specific hosts or subnets while allowing everyone else.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: acl-lan-only
	type: access_control
	hooks:
	  pre_resolve: 10
	config:
	  # Default policy: deny everything not explicitly allowed
	  default: deny
	  # Allow RFC1918 LANs
	  allow:
		- 192.168.0.0/16
		- 172.16.0.0/12
		- 10.0.0.0/8
		- 127.0.0.1/8
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: acl-example
	type: access_control
	hooks:
	  priority: 10
	config:
	  # BasePlugin targeting
	  targets:
		ips:
		  - 0.0.0.0/0          # apply to all clients
		ignore_ips:
		  - 192.0.2.10/32      # but skip this one IP completely
		listeners: any  # udp|tcp|dot|doh|secure|insecure|any
		qtypes: [ '*' ]

	  # BasePlugin logging
	  logging:
		level: info
		stderr: true

	  # AccessControl-specific options
	  # Default decision when a client does not match allow/deny lists.
	  default: allow          # 'allow' (default) or 'deny'

	  # Explicit allow/deny lists of client networks.
	  allow:
		- 192.168.0.0/16
		- 10.0.0.0/8
	  deny:
		- 203.0.113.0/24
		- 198.51.100.23/32
```

## Options

### Plugin-specific options

- `default: str`
  - Default policy when the client IP is not matched by any `allow`/`deny` entry.
  - `"allow"` (default): queries are permitted unless explicitly denied.
  - `"deny"`: queries are blocked unless explicitly allowed.
- `allow: list[str]`
  - List of IPv4/IPv6 CIDR ranges or single IPs that are explicitly allowed.
  - When a client IP is in this list, the plugin always allows the query
	(subject to other plugins).
- `deny: list[str]`
  - List of IPv4/IPv6 CIDR ranges or single IPs that are explicitly denied.
  - Deny rules take precedence over allow rules.
  - When matched, the plugin uses `deny_response` behavior:
    - default `deny_response: refused` returns `PluginDecision(action="override")` with `RCODE.REFUSED`
    - `deny_response: nxdomain` returns `PluginDecision(action="deny")`
    - `deny_response: drop` returns `PluginDecision(action="drop")`
    - other supported values (`servfail`, `noerror_empty`/`nodata`, `ip`) return `action="override"`

### Behaviour

- The plugin only runs when `BasePlugin.targets(ctx)` is true (see base options below).
- Evaluation order:
  1. If client IP matches any entry in `deny`, the query is denied.
  2. Else if client IP matches any entry in `allow`, the plugin returns `None`
	 (request is allowed to continue).
  3. Otherwise the `default` policy is applied.

### Common BasePlugin options

AccessControl supports the standard resolve plugin base options:

- `targets` (nested targeting config with `ips`, `ignore_ips`, `listeners`, `domains`,
  `domains_mode`, `qtypes`, `opcodes`, `rcodes`), and
- per-plugin logging (`logging.level`, `logging.file`, `logging.syslog`, ...).

See the full configuration example above for a concrete use of these fields.
