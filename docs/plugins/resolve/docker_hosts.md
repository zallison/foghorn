# DockerHosts resolve plugin

## Overview

The `docker_hosts` resolve plugin inspects Docker containers from one or more
Docker endpoints and exposes their names and addresses as DNS records. It can:

- answer A/AAAA queries for container names (and optional suffixes),
- answer PTR queries for reverse mappings built from container IPs,
- optionally publish TXT summaries under helper names like `_containers` and
  `_hosts` when `discovery` is enabled.

Typical uses:

- Make containers reachable via DNS (e.g. `web.docker.example`).
- Provide human-readable inventory of containers via TXT lookups.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: docker-lan
	type: docker_hosts
	hooks:
	  pre_resolve: { priority: 40 }
	config:
	  targets: [ 192.168.0.0/16 ]
	  suffix: docker.${DOMAIN}
	  discovery: true
	  endpoints:
		- url: unix:///var/run/docker.sock
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: docker-advanced
	type: docker_hosts
	hooks:
	  pre_resolve: { priority: 40 }
	config:
	  # BasePlugin targeting + logging
	  targets:
		- 192.168.0.0/16
	  targets_listener: any
	  target_qtypes: [ 'A', 'AAAA', 'PTR', 'TXT' ]
	  logging:
		level: info
		stderr: true

	  # Default TTL used when an endpoint does not override it
	  ttl: 300

	  # Only containers whose effective health/status is in this list are
	  # exposed. Valid values: 'starting', 'healthy', 'running', 'unhealthy'.
	  health: [ 'healthy', 'running' ]

	  # When true, publish TXT summaries:
	  #   _containers.<suffix> and _hosts.<suffix>
	  discovery: true

	  # Optional default suffix for container names, e.g. 'web' -> 'web.docker.zaa'
	  suffix: docker.${DOMAIN}

	  # Custom TXT fields derived from docker inspect data
	  txt_fields_replace: true
	  txt_fields_keep: [ 'id', 'ans4', 'endpoint', 'ports' ]
	  txt_fields:
		- name: name
		  path: Name
		- name: image
		  path: Config.Image
		- name: priority
		  path: Config.Labels.com.foghorn.priority

	  # Per-endpoint configuration
	  endpoints:
		- url: unix:///var/run/docker.sock
		  reload_interval_second: 60      # 0 => only at startup
		  # Use host IPs instead of container IPs
		  use_ipv4: 192.168.88.20
		  # use_ipv6: 2001:db8::1
		  ttl: 120                        # override TTL for this endpoint only
		  suffix: docker.${DOMAIN}        # override default suffix for this endpoint

		- url: tcp://docker1.lan:2375     # A front end like haproxy looking for server.docker.lan
		  use_ipv4: 192.168.12.21          # and only receive healthy targets.  If there are no
											   # results then they can look for server.backup.lan
		- url: tcp://docker2.lan:2375
		  use_ipv4: 192.168.12.22

		- url: tcp://backup1.lan:2375
		  use_ipv4: 192.168.13.11
		  suffix: backup.${DOMAIN}

		- url: tcp://backup2.lan:2375
		  use_ipv4: 192.168.13.12
		  suffix: backup.${DOMAIN}

```

## Options

### Plugin-specific options

Top-level `config` keys (described by `DockerHostsConfig`):

- `endpoints: list[DockerEndpointConfig]`
  - Each entry describes how to connect to a Docker daemon and optionally how
	to rewrite addresses and TTLs:

	- `url: str` (required)
	  - Docker endpoint, e.g. `"unix:///var/run/docker.sock"` or
		`"tcp://127.0.0.1:2375"`.
	- `reload_interval_second: float`
	  - Interval between background refreshes for this endpoint. `0` means only
		refresh at startup.
	- `use_ipv4: str | null`, `use_ipv6: str | null`
	  - When set, use this IPv4/IPv6 address for all containers from this
		endpoint instead of their per-container addresses.
	- `ttl: int | null`
	  - TTL override (seconds) for answers derived from this endpoint.
	- `suffix: str | null`
	  - Optional DNS suffix to apply to containers from this endpoint. When
		omitted/empty, the plugin-level `suffix` (if any) is used.

- `ttl: int`
  - Plugin-level default TTL when an endpoint does not define its own.
- `health: list[str]`
  - List of acceptable container health/status values. Supported: `"starting"`,
	`"healthy"`, `"running"`, `"unhealthy"`.
  - Containers whose effective state is not in this list are skipped.
- `discovery: bool`
  - When `true`, publish TXT summaries under special names like
	`_containers.<suffix>` and `_hosts.<suffix>`.
- `suffix: str | null`
  - Default DNS suffix to append to container names, e.g. `docker.zaa`.
  - Container name `web` becomes `web.docker.zaa`.
- `txt_fields: list[{name, path}]`
  - Optional list of JSONPath-like expressions used to construct custom TXT
	fields from docker inspect data. Each entry:
	- `name: str` – key used in TXT output.
	- `path: str` – dotted path into the inspect dict (e.g. `"Config.Image"`).
- `txt_fields_replace: bool`
  - When `true` and at least one `txt_fields` value is present for a container,
	only the custom fields (plus any `txt_fields_keep` keys that exist) are
	emitted. When `false`, custom fields are appended to the default summary.
- `txt_fields_keep: list[str]`
  - When `txt_fields_replace` is `true`, these keys from the built-in TXT summary
	are preserved when present (e.g. `"id"`, `"ans4"`, `"endpoint"`, `"ports"`).

### Behaviour

- On setup, DockerHosts connects to each configured endpoint, inspects
  containers and builds forward/reverse maps plus optional TXT summaries.
- It periodically refreshes those maps at the minimum positive interval across
  endpoints.
- The plugin remains usable even when the `docker` SDK is not installed, but it
  will log a warning and behave as inert until the SDK becomes available.

### Common BasePlugin options

DockerHosts supports the full BasePlugin targeting and logging options. In
practice you typically restrict it with `targets` (e.g. LAN clients only) and
set a per-plugin log level for troubleshooting.
