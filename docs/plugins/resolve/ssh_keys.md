# SshKeys resolve plugin

## Overview
The `ssh_keys` resolve plugin scans SSH servers and answers DNS `SSHFP`
queries from a local sqlite cache.

It:
- probes configured targets (IPs, CIDRs, hostnames) during setup
- stores discovered SSH public keys in sqlite
- synthesizes SSHFP answers (SHA-256 and optional SHA-1 fingerprints)

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
      # Scan safety controls
      scan_allowlist:
        - 10.0.0.0/8
        - 192.168.0.0/16
      scan_blocklist:
        - 10.0.1.0/24
      allow_public_scan: false
      max_targets: 4096
      max_cidr_hosts: 1024
      lazy_scan: true
      max_lazy_scans: 32
      # Response access controls
      response_allowlist:
        - 10.0.0.0/8
      response_blocklist: []
      allow_public_responses: false
      include_sha1: true
      # DB retention controls
      retention_seconds: 1209600  # 14 days
      max_rows: 50000
      prune_interval_seconds: 300
      db_path_allowlist:
        - ./config/var
        - ./var
        - ./data
```

## Options

### Plugin-specific options (`SshKeysConfig`)
- `targets` (list[str], default: `[]`)
  - scan targets; supports IPs, CIDRs, and hostnames
  - IP/CIDR entries also influence query-time client targeting because
    `pre_resolve()` still calls BasePlugin `targets(ctx)`
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
- `scan_allowlist` (list[str], default: `[]`)
  - CIDR/IP list allowed for scanning; when set, only these targets are scanned
- `scan_blocklist` (list[str], default: `[]`)
  - CIDR/IP list excluded from scanning
- `allow_public_scan` (bool, default: `false`)
  - when false, skip targets that resolve to public IPs unless allowlisted
- `max_targets` (int, default: `4096`)
  - max number of scan targets processed per startup scan
- `max_cidr_hosts` (int, default: `1024`)
  - max host count expanded per CIDR entry
- `lazy_scan` (bool, default: `true`)
  - enable on-demand single-host scans when SSHFP queries hit CIDR targets
- `max_lazy_scans` (int, default: `32`)
  - max concurrent lazy scans
- `response_allowlist` (list[str], default: `[]`)
  - client CIDR/IP list permitted to receive SSHFP responses
- `response_blocklist` (list[str], default: `[]`)
  - client CIDR/IP list excluded from SSHFP responses
- `allow_public_responses` (bool, default: `false`)
  - when false, only non-public client IPs are served unless allowlisted
- `include_sha1` (bool, default: `true`)
  - include legacy SHA-1 SSHFP records (fp_type=1) when true
- `retention_seconds` (float, default: `0.0`)
  - prune entries older than this age (0 disables time-based pruning)
- `max_rows` (int, default: `0`)
  - cap total rows in the DB (0 disables row-count pruning)
- `prune_interval_seconds` (float, default: `300.0`)
  - minimum interval between prune passes
- `db_path_allowlist` (list[str], default: `["./config/var", "./var", "./data", "."]`)
  - allowed base directories for `db_path`

### Behaviour
- SSHFP-only plugin: default qtype target is `SSHFP`.
- On setup, SshKeys performs a best-effort scan and upserts results into sqlite.
- At query time, qname is normalized and looked up in cache; on hit, SSHFP RRs
  are synthesized and returned.

### Common BasePlugin options
`config.logging` works as standard BasePlugin logging.

`config.targets` is used by SshKeys for scan targets (IPs/CIDRs/hosts), and
query handling still calls BasePlugin `targets(ctx)`. In practice, IP/CIDR
entries in `config.targets` therefore also act as client-response filters.
Use `response_allowlist` / `response_blocklist` for explicit response
authorization policy.
