# DNS UPDATE Support in ZoneRecords Plugin

## Overview
ZoneRecords supports RFC 2136 UPDATE handling with:
- TSIG authentication
- per-zone and per-principal allow/block scopes
- persistent journal replay/compaction
- replication and security limit controls

Note: the active UPDATE request authorization flow is currently TSIG-only.
`dns_update.zones[].psk` remains in the config schema but PSK verification is
not currently applied when authorizing UPDATE requests.

This document lists every `dns_update` key and default from the current config model.

## Complete key map with defaults

### `dns_update` (plugin config key: `plugins[].config.dns_update`)
- `enabled` (bool, default: `false`)
- `zones` (list, default: `null`)
- `persistence` (object, default: `null`)
- `replication` (object, default: `null`)
- `security` (object, default: `null`)

### `dns_update.zones[]` (per zone)
- `zone` (str, required)
- `tsig` (object, default: `null`)
- `psk` (object, default: `null`; currently not used by active request authentication path)
- `allow_names` (list[str], default: `null`)
- `allow_names_files` (list[str], default: `null`)
- `block_names` (list[str], default: `null`)
- `block_names_files` (list[str], default: `null`)
- `allow_clients` (list[str], default: `null`)
- `allow_clients_files` (list[str], default: `null`)
- `allow_update_ips` (list[str], default: `null`)
- `allow_update_ips_files` (list[str], default: `null`)
- `block_update_ips` (list[str], default: `null`)
- `block_update_ips_files` (list[str], default: `null`)

### `dns_update.zones[].tsig.keys[]`
- `name` (str, required)
- `algorithm` (str, default: `hmac-sha256`)
- `secret` (str, required; base64)
- `allow_names` (list[str], default: `null`)
- `allow_names_files` (list[str], default: `null`)
- `block_names` (list[str], default: `null`)
- `block_names_files` (list[str], default: `null`)
- `allow_update_ips` (list[str], default: `null`)
- `allow_update_ips_files` (list[str], default: `null`)
- `block_update_ips` (list[str], default: `null`)
- `block_update_ips_files` (list[str], default: `null`)

### `dns_update.zones[].tsig.key_sources[]`
- `type` (str, required by loader; built-in type: `file`)
- For `type: file`:
  - `path` (str, required)

### `dns_update.zones[].psk.tokens[]`
- `token` (str, required; hashed token)
- `allow_names` (list[str], default: `null`)
- `allow_names_files` (list[str], default: `null`)
- `block_names` (list[str], default: `null`)
- `block_names_files` (list[str], default: `null`)
- `allow_update_ips` (list[str], default: `null`)
- `allow_update_ips_files` (list[str], default: `null`)
- `block_update_ips` (list[str], default: `null`)
- `block_update_ips_files` (list[str], default: `null`)

### `dns_update.persistence` (defaults)
- `enabled` (bool, default: `true`)
- `state_dir` (str|null, default: `null`)
- `fsync_mode` (str, default: `interval`) (`always` or `interval`)
- `fsync_interval_ms` (int, default: `5000`)
- `max_journal_bytes` (int, default: `10485760`)
- `max_journal_entries` (int, default: `10000`)
- `compact_interval_seconds` (int, default: `3600`)
- `compact_tombstone_ratio` (float, default: `0.5`)

### `dns_update.replication` (defaults)
- `role` (str, default: `primary`) (`primary` | `replica` | `peer`)
- `zone_owner_node_id` (str|null, default: `null`)
- `notify_on_update` (bool, default: `true`)
- `node_id` (str|null, default: `null`)
- `reject_direct_update_on_replica` (bool, default: `false`)

### `dns_update.security` (defaults)
- `max_updates_per_message` (int, default: `100`)
- `max_rr_values_per_rrset` (int, default: `100`)
- `max_owner_length` (int, default: `255`)
- `max_rdata_length` (int, default: `65535`)
- `max_ttl_range` (int, default: `86400`)
- `max_transaction_bytes` (int, default: `1048576`)
- `rate_limit_per_client` (int, default: `10`)
- `rate_limit_per_key` (int, default: `100`)

## Minimal example
```yaml
plugins:
  - id: zone-with-dynamic-updates
    type: zone_records
    config:
      dns_update:
        enabled: true
        zones:
          - zone: example.com
            tsig:
              keys:
                - name: "key.example.com."
                  algorithm: "hmac-sha256"
                  secret: "base64-secret"
```

## Full example
See:
- `example_configs/plugin_zone_update_all_options.yaml`

## Authentication key generation
```bash
make gen-tsig-key NAME=dynamic-key.example.com
make gen-tsig-key NAME=cdn-key.example.com ALGO=hmac-sha512
make gen-psk-token
./scripts/generate_dns_update_keys.py --tsig --name "key.example.com" --config-snippet
./scripts/generate_dns_update_keys.py --psk --config-snippet
```
PSK token generation commands are kept for schema compatibility and provisioning
workflows, but runtime UPDATE authorization currently validates TSIG keys.
