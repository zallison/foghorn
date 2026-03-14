# SshKeys resolve plugin

## Overview
The `ssh_keys` resolve plugin scans SSH servers and answers DNS `SSHFP`
queries from a local sqlite cache.

It:
- probes configured targets (IPs, CIDRs, hostnames) during setup
- stores discovered SSH public keys in sqlite
- synthesizes SSHFP answers (SHA-1 and SHA-256 fingerprints)

## Basic configuration
```yaml path=null start=null
plugins:
  - id: sshfp-cache
    type: ssh_keys
    hooks:
      setup: { priority: 20 }
      pre_resolve: 60
    config:
      targets:
        - 192.168.1.10
        - 192.168.1.0/24
        - bastion.example.com
```

## Full configuration (all plugin + base options)
```yaml path=null start=null
plugins:
  - id: sshfp-advanced
    type: ssh_keys
    hooks:
      setup: { priority: 20 }
      pre_resolve: 60
    config:
      logging:
        level: info
        stderr: true

      # SshKeysConfig fields
      targets:
        - 192.168.1.10
        - 192.168.1.0/24
        - bastion.example.com
      scan_threads: 4
      ttl: 300
      db_path: ./config/var/ssh_keys.db
      port: 22
      timeout_seconds: 5.0
```

## Options

### Plugin-specific options (`SshKeysConfig`)
- `targets` (list[str], default: `[]`)
  - scan targets; supports IPs, CIDRs, and hostnames
- `scan_threads` (int, default: `4`)
  - max concurrent scan workers
- `ttl` (int, default: `300`)
  - TTL used for synthesized SSHFP answers
- `db_path` (str, default: `./config/var/ssh_keys.db`)
  - sqlite cache file path
- `port` (int, default: `22`)
  - SSH TCP port used for probes
- `timeout_seconds` (float, default: `5.0`)
  - SSH probe timeout

### Behaviour
- SSHFP-only plugin: default qtype target is `SSHFP`.
- On setup, SshKeys performs a best-effort scan and upserts results into sqlite.
- At query time, qname is normalized and looked up in cache; on hit, SSHFP RRs
  are synthesized and returned.

### Common BasePlugin options
`config.logging` works as standard BasePlugin logging.

`config.targets` is used by SshKeys itself for scan targets (IPs/CIDRs/hosts),
so the usual nested BasePlugin client-targeting object is not used for this
plugin.
