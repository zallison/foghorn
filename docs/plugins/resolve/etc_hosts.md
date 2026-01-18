# EtcHosts resolve plugin

## Overview

The `etc_hosts` resolve plugin reads one or more `/etc/hosts`-style files and serves A, AAAA and PTR answers directly from them. It merges multiple files in order (later entries override earlier ones) and can watch the files for changes using `watchdog` and/or a stat-based polling loop.

Use this plugin when you want a small, fast, authoritative source of host records that mirrors system host files, without going through upstream resolvers.

Typical use cases:

- Mirror `/etc/hosts` into DNS for a small lab or home network.
- Layer additional host overrides on top of upstream DNS for testing.
- Keep critical infrastructure hostnames resolvable even when upstream resolvers are unavailable.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: lan-hosts
    type: etc_hosts
    hooks:
      pre_resolve: { priority: 30 }
    config:
      # Answer for clients on the LAN only
      targets:
        - 192.168.0.0/16
        - 10.0.0.0/8
      # Default: [/etc/hosts]
      file_paths:
        - /etc/hosts
```

## Full configuration (all plugin + base options)

```yaml path=null start=null
plugins:
  - id: lan-hosts-full
    type: etc_hosts
    hooks:
      pre_resolve:  { priority: 30 }
      post_resolve: { priority: 30 }
    config:
      # BasePlugin targeting
      targets:
        - 192.168.0.0/16
      targets_ignore:
        - 192.168.1.50/32
      targets_listener: secure           # only DoT/DoH listeners
      targets_domains:
        - example.internal
      targets_domains_mode: suffix       # only qnames under example.internal
      target_qtypes: [ 'A', 'AAAA', 'PTR' ]

      # BasePlugin logging
      logging:
        level: debug                     # debug|info|warn|error|crit
        stderr: true
        file: ./config/var/log/etc-hosts.log
        syslog:
          address: /dev/log
          facility: local0

      # EtcHosts-specific options
      file_paths:
        - /etc/hosts
        - /etc/foghorn/extra-hosts
      # legacy single path (discouraged, prefer file_paths)
      # file_path: /etc/hosts

      # Enable/disable automatic reloads using watchdog
      watchdog_enabled: true
      watchdog_min_interval_seconds: 1.0
      # Optional stat-based polling fallback when filesystem events are unreliable
      watchdog_poll_interval_seconds: 0.0

      # TTL applied to synthesized answers (A/AAAA/PTR)
      ttl: 300
```

## Options

### Plugin-specific options

- `file_paths: list[str] | null`
  - Ordered list of host files to load. Later files win on conflicts.
  - When omitted and `file_path` is also omitted, defaults to `["/etc/hosts"]`.
- `file_path: str | null`
  - Legacy single hosts file; merged into `file_paths` when both are set.
- `watchdog_enabled: bool | null`
  - When `true`, and `watchdog` is installed, start a filesystem watcher to reload on change.
  - When `false`, no watchdog is started.
  - When `null` (default), behaves as `true`.
- `watchdog_min_interval_seconds: float`
  - Minimum time between reloads triggered by watchdog events (debounce window).
  - Default: `1.0`.
- `watchdog_poll_interval_seconds: float`
  - When `> 0`, start a background polling thread that periodically stats the files
    and reloads them when metadata changes (useful on filesystems that do not
    generate change events).
  - Default: `0.0` (disabled).
- `ttl: int`
  - TTL in seconds used for synthesized A, AAAA and PTR answers.
  - Default: `300`.

### Common BasePlugin options (via `config`)

These options are shared by all resolve plugins:

- `targets: list[str] | str | null`
  - CIDR/IP list of client networks this plugin should apply to. When omitted and
    `targets_ignore` is empty, all clients are targeted.
- `targets_ignore: list[str] | str | null`
  - CIDR/IP list of clients to exclude. When `targets` is empty and this is
    non-empty, targeting is "everyone except these".
- `targets_listener: str | list[str] | null`
  - Restrict to specific listeners: any of `udp`, `tcp`, `dot`, `doh`.
  - Aliases: `secure` → `dot`+`doh`, `unsecure`/`insecure` → `udp`+`tcp`, `any`/`*` → no restriction.
- `targets_domains: str | list[str] | null`, `targets_domains_mode: str`
  - Optional domain-level targeting. `targets_domains_mode` is one of `any`,
    `exact`, `suffix`.
- `target_qtypes: str | list[str] | null`
  - Restrict plugin to specific qtypes (e.g. `["A", "AAAA"]`). `"*"` or omission
    means all qtypes.
- `targets_cache_ttl_seconds: int`
  - Hints the size/behaviour of the internal LRU cache for targeting decisions.
- `logging: { level, stderr, file, syslog }`
  - Per-plugin logging configuration, matching the top-level `logging.python`
    structure.

The full configuration example above demonstrates typical usage of these base options with `EtcHosts`.
