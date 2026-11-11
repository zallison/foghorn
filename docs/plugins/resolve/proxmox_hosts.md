# ProxmoxHosts resolve plugin

## Overview

The `proxmox_hosts` resolve plugin polls the Proxmox VE REST API and publishes
QEMU VMs and LXC containers as DNS names. Because Proxmox is multi-master, **any
configured cluster node can answer for the whole cluster** — inventory comes
from `/cluster/resources`, not from a single node’s local list.

It can:

- answer A/AAAA for guest names (optional suffix),
- answer PTR for reverse mappings built from guest IPs,
- optionally publish TXT inventory under `_guests.<suffix>` and `_nodes.<suffix>`
  when `discovery` is enabled.

Address sources (first usable wins per family unless `merge_addresses` is true):

1. QEMU guest agent `network-get-interfaces`
2. LXC `/interfaces`
3. status/current fields when present
4. cloud-init `ipconfigN` static addresses
5. optional endpoint `use_ipv4` / `use_ipv6` overrides

Loopback and link-local addresses are dropped.

## Basic configuration

```yaml path=null start=null
plugins:
  - id: pve-lan
    type: proxmox_hosts
    hooks:
      pre_resolve: 40
    config:
      targets:
        ips: [10.0.0.0/8]
      suffix: pve.${DOMAIN}
      ttl: 60
      reload_interval_second: 30
      endpoints:
        - url: https://pve1.lan:8006
          token_id: foghorn@pve!dns
          token_secret: "${PVE_TOKEN_SECRET}"
          verify_tls: true
        - url: https://pve2.lan:8006
          token_id: foghorn@pve!dns
          token_secret: "${PVE_TOKEN_SECRET}"
          verify_tls: true
```

Multiple endpoints are **failover** only. The first healthy node supplies the
full cluster view each reload cycle.

## Options

### Plugin-specific

- `endpoints: list`
  - `url` (required): Base URL, e.g. `https://pve1.lan:8006`
  - `token_id` / `token_secret`: API token (`USER@REALM!TOKENID` + secret)
  - `user` / `password`: Optional ticket auth instead of a token
  - `verify_tls` (default true), `tls_ca`: TLS settings
  - `use_ipv4` / `use_ipv6`: Answer with these host IPs for all guests
  - `ttl`, `suffix`, `reload_interval_second`: Per-endpoint overrides
- `ttl` (default 60)
- `reload_interval_second` (default 30; `0` disables the poller after initial load)
- `status` (default `["running"]`)
- `include_types` (default `["qemu", "lxc"]`)
- `include_templates` (default false)
- `use_guest_agent` (default true)
- `merge_addresses` (default false)
- `publish_vmid` / `publish_tags` (default false)
- `discovery` / `expose_txt_in_additional` (default false)
- `suffix`: DNS suffix, e.g. `pve.example` → `web.pve.example`
- `max_workers` (default 4): Parallel per-guest API fetches

### Behaviour notes

- Names come from the PVE guest name (underscores → hyphens), optional agent
  hostname, optional tags/vmid aliases, then fallback `vm{id}` / `ct{id}`.
- When `suffix` is set, only suffixed names are published (same as DockerHosts).
- Guest-agent failures fall back quietly (DEBUG); guests with no usable IP are
  omitted.
- Endpoint / empty-map failures use sticky logging (warn once, hourly reminder,
  info on recovery).

## Minimum-privilege Proxmox user

Do **not** use `root@pam`. Create a dedicated `@pve` user and a
privilege-separated API token.

### Privileges

- `VM.Audit` on `/vms` (or `/`) — list guests + read config/status/LXC interfaces
- Guest-agent NICs:
  - PVE 9+: `VM.GuestAgent.Audit` on `/vms`
  - PVE 8: `VM.Monitor` on `/vms`
- Optional node TXT inventory: `Sys.Audit` on `/nodes` or `/`

`PVEAuditor` covers audit reads but usually **not** guest-agent; prefer a custom
role.

### CLI setup (order matters)

```bash path=null start=null
# 1) Role (PVE 9+)
pveum role add FoghornDNS --privs "VM.Audit VM.GuestAgent.Audit"
# PVE 8: pveum role add FoghornDNS --privs "VM.Audit VM.Monitor"

# 2) User
pveum user add foghorn@pve --comment "Foghorn DNS inventory"

# 3) User ACL first (privsep token cannot exceed user rights)
pveum acl modify /vms --users foghorn@pve --roles FoghornDNS

# 4) Create token — SAVE the secret UUID (shown once)
pveum user token add foghorn@pve dns --privsep 1
pveum user token list foghorn@pve   # must show tokenid dns

# 5) Token ACL (required when privsep=1)
pveum acl modify /vms --tokens 'foghorn@pve!dns' --roles FoghornDNS

pveum user token permissions foghorn@pve dns
```

If step 5 fails with `no such token 'dns' for user 'foghorn@pve'`, the token was
not created yet — finish step 4 first.

Lab shortcut: `--privsep 0` inherits the user ACL (token ACL optional). Prefer
`privsep=1` in production.

### Verify

```bash path=null start=null
curl -sS -k -H "Authorization: PVEAPIToken=foghorn@pve!dns=SECRET" \
  'https://pve1.lan:8006/api2/json/cluster/resources?type=vm' | jq '.data|length'
# Empty array ⇒ missing user or token ACL.

curl -sS -k -H "Authorization: PVEAPIToken=foghorn@pve!dns=SECRET" \
  'https://pve1.lan:8006/api2/json/nodes/NODE/qemu/VMID/agent/network-get-interfaces'
# 403 ⇒ missing VM.GuestAgent.Audit / VM.Monitor
# agent error ⇒ guest agent not running (plugin falls back)
```

### Security

- Read-only role only (no power/config/console/storage allocate).
- Prefer tokens + TLS verification with the cluster CA.
- Scope ACL to `/pool/...` if only a subset of guests should appear in DNS.
- Keep `discovery` / `expose_txt_in_additional` off on untrusted resolvers.

## Admin UI

ProxmoxHosts exposes a snapshot at `/api/v1/plugins/{name}/proxmox_hosts` with
guest name, type, vmid, node, status, and addresses.
