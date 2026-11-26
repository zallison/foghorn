# UnifiHosts resolve plugin

## Overview

The `unifi_hosts` resolve plugin polls the **official UniFi Network Integration
API** and publishes connected clients and adopted devices as DNS names. It uses
`X-API-KEY` authentication only (no legacy cookie/CSRF controller API).

It can:

- answer A/AAAA for client and device names (optional suffix),
- answer PTR for reverse mappings built from published IPs,
- optionally publish TXT inventory under `_clients.<suffix>`,
  `_devices.<suffix>`, and `_sites.<suffix>` when `discovery` is enabled.

Inventory sources (both on by default):

1. `GET /v1/sites/{siteId}/clients` — **connected** clients only
2. `GET /v1/sites/{siteId}/devices` — adopted UniFi devices

Base URLs:

- Local console: `https://{host}/proxy/network/integration/v1/...`
- Site Manager connector:
  `https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration/v1/...`

Foghorn accepts a bare console origin (`https://udm.lan`) and appends the
integration path automatically.

Loopback and link-local addresses are dropped. See [Include / exclude filters](#include--exclude-filters)
for name, kind, IP, state, MAC, site, network, and VLAN controls.

## Basic configuration

```yaml
plugins:
  - id: unifi-lan
    type: unifi_hosts
    hooks:
      pre_resolve: 40
    config:
      targets:
        ips: [0.0.0.0/0]
      suffix: unifi.${DOMAIN}
      ttl: 60
      reload_interval_second: 120
      include_clients: true
      include_devices: true
      publish_mac: false
      # Example filters (all optional):
      # include_kinds: [client]
      # exclude_names: ["guest*", "*iphone*"]
      # include_cidrs: ["10.0.0.0/8"]
      # include_vlans: [40, 50]
      # exclude_macs: ["aa:bb:cc:dd:ee:ff"]
      endpoints:
        # One healthy console is enough; extras are failover only.
        - id: udm
          url: https://unifi.example
          api_key: "${UNIFI_API_KEY}"
          verify_tls: false
          # Prefer pinning the console CA when possible:
          # verify_tls: true
          # tls_ca: keys/unifi-ca.pem
          # tls_server_name: unifi.lan
```

Multiple endpoints are **failover** only. Foghorn talks to the first healthy
console each reload. For independent consoles you want merged in DNS, configure
**separate plugin instances** (separate keys/sites).

## Load / reload logging

On **setup** and every successful background reload, UnifiHosts logs an INFO
summary of what was inventoried and published, for example:

```text
loaded 42 hosts (30 clients, 12 devices; 40 A, 2 AAAA, 35 PTR names) from udm (sites=1 scanned=50 published=42 skipped=8)
```

Fields:

- **hosts** — rows that made it into DNS maps (after filters)
- **clients / devices** — split of those published hosts by kind
- **A / AAAA / PTR names** — sizes of the forward and reverse maps
- **from** — endpoint id (or URL label)
- **sites** — sites used after site filters
- **scanned** — client+device objects fetched from the API before row filters
- **published** — rows that passed filters and had a usable name+IP
- **skipped** — `scanned - published` (filtered out, no IP, invalid name, etc.)

Failed endpoint attempts use sticky condition logging (warn once, hourly
reminder, info on recovery). If every endpoint fails, previous maps are kept
and no “loaded N hosts” line is emitted for that cycle.

Watch the plugin logger (or Foghorn’s configured python logging) for the
`foghorn.plugins.resolve.unifi_hosts` logger.

## Include / exclude filters

Filters run **per inventory row** after fetch. Empty **include** lists mean “no
restriction” for that dimension (except where noted). **Exclude** always wins
over include for the same dimension.

| Dimension | Include | Exclude | Notes |
|-----------|---------|---------|-------|
| **Kind** | `include_kinds` | `exclude_kinds` | Values: `client`, `device`. When `include_kinds` is non-empty it overrides `include_clients` / `include_devices`. |
| **DHCP / display name** | `include_names` | `exclude_names` | Case-insensitive globs (`fnmatch`) against the UniFi `name` field. |
| **IP** | `include_cidrs` | `exclude_cidrs` | CIDR lists; loopback/link-local always dropped. |
| **State** | `include_states` (or legacy `device_states`) | `exclude_states` | Devices default to `ONLINE` via `device_states` when `include_states` is unset. Clients with empty state are allowed unless excluded. |
| **MAC** | `include_macs` | `exclude_macs` | Separators ignored (`aa:bb:…` == `aabb…`). |
| **Site** | `site_ids`, `site_names` | `exclude_site_ids`, `exclude_site_names` | Applied when listing sites; per-endpoint `endpoints[].site_ids` also apply. |
| **Network** | `include_networks` | `exclude_networks` | Network **name** or **id** (globs ok). Uses row fields when present plus site network inventory. |
| **VLAN** | `include_vlans` | `exclude_vlans` | VLAN ids as string or int. Same inventory/row sources as network. |
| **Client connection type** | `include_types` | `exclude_types` | e.g. `wired`, `wireless`, `vpn` (case-insensitive). |

Also:

- `include_clients` / `include_devices` (default `true`) — bool shortcuts when
  `include_kinds` is empty
- `address_limit` — max addresses per family after CIDR filters (`0` = unlimited)
- `filter` — optional **server-side** Integration API filter DSL on list calls

### Filter example

```yaml
config:
  suffix: unifi.${DOMAIN}
  include_kinds: [client]
  exclude_names:
    - "guest*"
    - "*iphone*"
  include_cidrs:
    - "10.0.0.0/8"
  exclude_cidrs:
    - "10.99.0.0/16"   # guest VLAN subnet if known
  include_vlans: [40, 50]
  exclude_macs:
    - "aa:bb:cc:dd:ee:ff"
  exclude_site_names: [lab]
  include_types: [wired, wireless]
  endpoints:
    - id: udm
      url: https://unifi.example
      api_key: "${UNIFI_API_KEY}"
      verify_tls: false
```

### Network / VLAN caveats

Official **client overview** objects often omit network id / VLAN. UnifiHosts:

1. Reads optional row fields when the controller includes them
   (`networkId`, `networkName`, `vlanId`, and common aliases).
2. When any network/VLAN filter is set, also loads
   `GET /v1/sites/{siteId}/networks` and matches on `id`, `name`, and `vlanId`.

If clients never carry network metadata, **include_vlans / include_networks**
may drop everything. Prefer **name**, **MAC**, or **CIDR** filters in that
case, or confirm your Network Application version populates those fields.

## Options

### Plugin-specific

- `endpoints: list`
  - `id` (optional): Short label preferred in logs and admin UI
  - `url` (required): Console origin or full integration base URL
  - `api_key` (required): Integration / Site Manager API key (string or secret ref)
  - `console_id` (optional): When `url` is `https://api.ui.com`, builds the
    connector path for that console
  - `verify_tls` (default true), `tls_ca` / `ca_cert`: TLS settings
  - `tls_server_name` (aliases `tls_name`, `server_name`): SNI / expected cert hostname
  - `use_ipv4` / `use_ipv6`: Answer with these host IPs for all names from the endpoint
  - `ttl`, `suffix`, `reload_interval_second`: Per-endpoint overrides
  - `site_ids`: Optional per-endpoint site UUID allowlist
- `ttl` (default 60)
- `reload_interval_second` (default 120; `0` disables the poller after initial load)
- `include_clients` / `include_devices` (default true)
- `include_kinds` / `exclude_kinds`: `client` / `device` (when set, overrides the bools)
- `include_types` / `exclude_types`: client connection types
  (`wired`, `wireless`, `vpn`, …; case-insensitive)
- `device_states` (default `["ONLINE"]`) — legacy device state allowlist
- `include_states` / `exclude_states`: preferred state filters (devices; empty
  client state always allowed unless excluded)
- `site_ids` / `site_names` / `exclude_site_ids` / `exclude_site_names`
- `include_names` / `exclude_names`: DHCP/display name globs (case-insensitive)
- `include_macs` / `exclude_macs`: MAC filters (separators ignored)
- `include_networks` / `exclude_networks`: network name or id (globs ok)
- `include_vlans` / `exclude_vlans`: VLAN ids (string or int)
- `filter`: Optional server-side Integration filter DSL string
- `publish_mac` (default false): also publish `host-<12 hex mac>` aliases
- `include_cidrs` / `exclude_cidrs` / `address_limit`
- `discovery` / `expose_txt_in_additional` (default false)
- `suffix`: DNS suffix, e.g. `unifi.example` → `laptop.unifi.example`

### Behaviour notes

- Names come from the UniFi `name` field after aggressive sanitize (spaces and
  punctuation → hyphens; underscores → hyphens). Invalid names are skipped
  unless `publish_mac` provides a usable alias.
- When `suffix` is set, only suffixed names are published (same as DockerHosts /
  ProxmoxHosts).
- Official client list is **connected only**; offline fixed-IP hosts do not
  appear.
- Integration overview objects expose a single `ipAddress` field; A vs AAAA is
  chosen by parsing that value.
- Endpoint / empty-map failures use sticky logging (warn once, hourly reminder,
  info on recovery). Failed reloads keep the previous maps.

## Creating API keys (scoped / least privilege)

### Important limitation

Ubiquiti’s **local Network Integration** key is still coarse:

- Created under the console Integrations UI
- Inherits the **creating account’s** effective rights
- There is **no first-class “read-only clients only” scope** on many Network
  builds; a community “View Only after mint” workaround is version-sensitive
- **Site Manager (cloud) keys** can select application **Network** and
  optionally **specific sites** — that is the closest official scoped key

Prefer **local** console keys when Foghorn is on-LAN (clients are exposed
there). Cloud connector is optional for multi-site estates.

**Do not mix key types:** a local Integrations key will not work on
`api.ui.com`, and a Site Manager key will not work as a local console key.

### Local console key (recommended for clients + devices)

Prereq: UniFi OS console with Network Application supporting Integrations /
Integration API (API-key auth from Network **9.0.114+**; inventory endpoints
need a recent Network 9/10/11).

1. Open the **local** console UI (`https://<console-ip>`), not only
   unifi.ui.com, if you need a local-only key.
2. Sign in as a **dedicated** local admin used only for automation (do not mint
   from your super-admin daily driver if you can avoid it).
3. Go to **Settings → Control Plane → Integrations** (wording may be
   **Settings → Integrations** on some builds).
4. **Create API Key** → name e.g. `foghorn-dns` → optional description →
   expiration as policy allows → **Create**.
5. **Copy the key once**; store in env/secret backend (`UNIFI_API_KEY`). It will
   not be shown again.
6. Least privilege (best-effort today):
   - Create admin `foghorn` with the minimum role that can open Integrations and
     read Network inventory.
   - Mint the key **while signed in as that account**.
   - If your Network build supports it, drop the account to **View Only**
     afterward and **verify writes return 403** while GETs still work
     (community workaround; re-test after upgrades).
   - If View Only cannot mint keys on your version, keep a dedicated full admin
     that is local-only, unused for humans, and rotate keys aggressively.
7. Verify:

```bash
# info
curl -sS ${CURL_K:--k} -H "X-API-KEY: $UNIFI_API_KEY" \
  "https://$UNIFI_HOST/proxy/network/integration/v1/info"

# sites
curl -sS ${CURL_K:--k} -H "X-API-KEY: $UNIFI_API_KEY" \
  "https://$UNIFI_HOST/proxy/network/integration/v1/sites" | jq .

# clients (replace SITE_UUID)
curl -sS ${CURL_K:--k} -H "X-API-KEY: $UNIFI_API_KEY" \
  "https://$UNIFI_HOST/proxy/network/integration/v1/sites/$SITE_ID/clients?limit=200" \
  | jq '.totalCount,.data[0]'
```

TLS: local consoles often use a self-signed cert → either `verify_tls: false`
(sticky insecure notice) or export/trust the console CA via `tls_ca` +
`tls_server_name`.

### Site Manager / cloud connector key (application + site scope)

Use when Foghorn cannot reach the console on LAN, or you manage many consoles
via a UI account.

1. Sign in at https://unifi.ui.com (Site Manager).
2. **Settings → API Keys** (or account API keys UI for your fabric/org).
3. **Create New API Key**:
   - Name: `foghorn-dns`
   - Enable **UniFi Applications** / Network access as presented
   - Under **Applications**, select **Network** only (do not grant
     Protect/Access/etc. unless needed)
   - Under **Sites**, select **specific sites** Foghorn should see (avoid “All”
     when possible)
   - Set expiration
4. Copy secret once → `UNIFI_SM_API_KEY`.
5. Note each console’s **console id** from Site Manager.
6. Endpoint shape in Foghorn:

```yaml
endpoints:
  - id: cloud-udm
    url: https://api.ui.com
    console_id: YOUR_CONSOLE_ID
    api_key: "${UNIFI_SM_API_KEY}"
    verify_tls: true
```

Or set the full connector URL:

```yaml
url: https://api.ui.com/v1/connector/consoles/YOUR_CONSOLE_ID/proxy/network/integration
api_key: "${UNIFI_SM_API_KEY}"
```

7. Verify with the same `/v1/info` and `/v1/sites` paths under that connector
   base.

### What Foghorn requires from the key

Read-only GETs only:

- `GET /v1/info` (health; optional if sites work)
- `GET /v1/sites`
- `GET /v1/sites/{id}/clients` (if `include_clients`)
- `GET /v1/sites/{id}/devices` (if `include_devices`)

No client actions, adopt/unadopt, or network mutations.

### Operator security checklist

- Dedicated automation identity; rotate on compromise or admin departure
- Env/secret plugin refs — never commit raw keys
- Prefer `tls_ca` over `verify_tls: false` on local consoles
- Keep `discovery` / `expose_txt_in_additional` off on untrusted resolvers
  (hostname/MAC leakage)
- Separate Foghorn plugin instances per security domain if one key must not see
  another site’s clients

## Admin UI

UnifiHosts exposes a snapshot at `/api/v1/plugins/{name}/unifi_hosts` (also the
generic `/snapshot` alias). The admin table includes host name, kind
(client/device), IPv4, type/state, MAC, **network**, **VLAN**, and site.

Summary counters in the UI (`total_hosts`, `total_clients`, `total_devices`)
reflect the last successful reload (same basis as the log line).
