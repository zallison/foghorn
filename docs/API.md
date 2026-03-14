# Foghorn Admin HTTP API (Webserver + Resolve plugin integration)

This document lists the HTTP API endpoints implemented under:
- `src/foghorn/servers/webserver/` (FastAPI + threaded fallback)
- `src/foghorn/plugins/resolve/` (endpoints that expose Resolve plugin data via the webserver)

Notes:
- The canonical API is versioned under `/api/v1/...`, with a small set of convenience aliases (for example `/stats`).
- The FastAPI and threaded fallback implementations are intended to expose the same URLs.

## Example placeholders used in this doc
All examples use dummy values; replace them with your real deployment values.

```bash
# Admin webserver (FastAPI) base URL
BASE_URL='http://127.0.0.1:8080'

# DoH listener base URL (separate listener from the admin webserver)
DOH_BASE_URL='https://127.0.0.1:8053'

# Admin auth token (only used when server.http.auth.mode: token)
TOKEN='example-token-123'

# DNS listener address/port (UDP/TCP/DoT depend on your config)
DNS_SERVER='127.0.0.1'
DNS_PORT='53'
DNS_TCP_PORT='53'
```

## Authentication
Authentication is configured via the `server.http.auth` config block.

### Token mode
When `server.http.auth.mode: token` is enabled, protected endpoints require *either*:
- `Authorization: Bearer <token>`
- `X-API-Key: <token>`

Example header:
- `Authorization: Bearer example-token-123`

### No-auth mode
When `server.http.auth.mode` is not `token` (default: `none`), protected endpoints are not enforced.

## Conventions
- Many JSON responses include `server_time` as an ISO-8601 timestamp string.
- Many “optional feature” endpoints return `{"status": "disabled" ...}` when the backing feature is not enabled/configured.

---

# Endpoint reference

## Health / About / Readiness

### GET `/api/v1/health` (alias: `/health`)
Auth: none

Inputs:
- Query: none

Example:
```bash
curl -sS "$BASE_URL/api/v1/health"
```

Example response:
```json
{
  "status": "ok",
  "server_time": "2026-02-24T05:36:03Z"
}
```

### GET `/api/v1/about` (alias: `/about`)
Auth: none

Inputs:
- Query: none

Example:
```bash
curl -sS "$BASE_URL/api/v1/about"
```

Example response (shape varies by build metadata):
```json
{
  "name": "foghorn",
  "version": "0.0.0-example",
  "server_time": "2026-02-24T05:36:03Z",
  "github": "https://github.com/example/foghorn",
  "build": {
    "git_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "built_at": "2026-02-23T12:00:00Z"
  }
}
```

### GET `/api/v1/ready` (alias: `/ready`)
Auth: none

Inputs:
- Query: none

Example:
```bash
curl -sS "$BASE_URL/api/v1/ready"
```

Success response:
- HTTP 200 when ready
- HTTP 503 when not ready

Example response:
```json
{
  "server_time": "2026-02-24T05:36:03Z",
  "ready": true,
  "details": {
    "mode": "forward",
    "expected_listeners": {
      "udp": true,
      "tcp": false,
      "dot": false,
      "doh": false,
      "webserver": true
    },
    "runtime": {
      "startup_complete": true,
      "listeners": {
        "udp": {"enabled": true, "running": true}
      }
    }
  }
}
```

---

## Statistics

### GET `/api/v1/stats` (alias: `/stats`)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Query (optional):
  - `reset` (bool, default: `false`): when true, resets counters after snapshot
  - `top` (int, default: `10`): max entries in top_* lists

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/stats?reset=false&top=10"
```

Disabled response:
```json
{
  "status": "disabled",
  "server_time": "2026-02-24T05:36:03Z"
}
```

### GET `/api/v1/stats/table/{table_id}`
Auth: protected when `server.http.auth.mode: token`

Brief: server-side pagination/sorting/search for known stats lists.

Inputs:
- Path (required):
  - `table_id` (string): one of:
    - `top_clients`
    - `top_domains`
    - `top_subdomains`
    - `cache_hit_domains`
    - `cache_miss_domains`
    - `cache_hit_subdomains`
    - `cache_miss_subdomains`
    - `qtype_qnames` (grouped; requires `group_key`)
    - `rcode_domains` (grouped; requires `group_key`)
    - `rcode_subdomains` (grouped; requires `group_key`)
- Query (optional unless noted):
  - `group_key` (string, required for grouped table_ids): example `A` or `NXDOMAIN`
  - `page` (int, default: `1`)
  - `page_size` (int, default: `50`)
  - `sort_key` (string, example: `count`)
  - `sort_dir` (string, `asc` or `desc`, example: `desc`)
  - `search` (string, example: `example.com`)

Example:
```bash
curl -sS \
  -H "X-API-Key: $TOKEN" \
  "$BASE_URL/api/v1/stats/table/top_domains?page=1&page_size=50&sort_key=count&sort_dir=desc&search=example"
```

Example response:
```json
{
  "server_time": "2026-02-24T05:36:03Z",
  "table_id": "top_domains",
  "total": 2,
  "page": 1,
  "page_size": 50,
  "total_pages": 1,
  "sort_key": "count",
  "sort_dir": "desc",
  "search": "example",
  "items": [
    {"name": "example.com", "count": 123},
    {"name": "example.net", "count": 45}
  ]
}
```

### POST `/api/v1/stats/reset` (alias: `/stats/reset`)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Body: none

Example:
```bash
curl -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/stats/reset"
```

Example response:
```json
{
  "status": "ok",
  "server_time": "2026-02-24T05:36:03Z"
}
```

---

## Traffic

### GET `/api/v1/traffic` (alias: `/traffic`)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Query (optional):
  - `top` (int, default: `10`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/traffic?top=10"
```

---

## Upstreams

### GET `/api/v1/upstream_status`
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Query: none

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/upstream_status"
```

Example response:
```json
{
  "server_time": "2026-02-24T05:36:03Z",
  "strategy": "failover",
  "max_concurrent": 32,
  "items": [
    {
      "id": "udp:1.1.1.1:53",
      "config": {"host": "1.1.1.1", "port": 53, "transport": "udp"},
      "state": "up",
      "fail_count": 0,
      "down_until": 1708750000.0
    }
  ]
}
```

---

## Rate limit stats

### GET `/api/v1/ratelimit`
Auth: protected when `server.http.auth.mode: token`

Brief: derives stats from sqlite `rate_profiles` databases configured by the RateLimit plugin(s).

Inputs:
- Query: none

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/ratelimit"
```

Example response:
```json
{
  "server_time": "2026-02-24T05:36:03Z",
  "databases": [
    {
      "db_path": "./config/var/dbs/rate_limit.db",
      "total_profiles": 3,
      "max_avg_rps": 1.25,
      "max_max_rps": 7.5,
      "profiles": [
        {"key": "192.0.2.10", "avg_rps": 1.25, "max_rps": 7.5, "samples": 120, "last_update": 1708750000}
      ]
    }
  ]
}
```

---

## Configuration

### GET `/api/v1/config` (alias: `/config`)
Auth: protected when `server.http.auth.mode: token`

Outputs:
- `application/x-yaml` (sanitized/redacted)

Inputs:
- Query: none

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/config"
```

### GET `/api/v1/config.json` (alias: `/config.json`)
Auth: protected when `server.http.auth.mode: token`

Outputs:
- JSON object with `config` containing redacted values.

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/config.json"
```

Example response:
```json
{
  "server_time": "2026-02-24T05:36:03Z",
  "config": {
    "server": {
      "http": {"auth": {"token": "***"}},
      "listen": {"udp": {"enabled": true}}
    }
  }
}
```

### GET `/api/v1/config/raw` (alias: `/config/raw`)

Auth: protected when `server.http.auth.mode: token`

Brief: reads the on-disk config YAML file (`app.state.config_path` / server `config_path`).

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/config/raw"
```

### GET `/api/v1/config/raw.json` (alias: `/config/raw.json`)

Auth: protected when `server.http.auth.mode: token`

Outputs:
- JSON object containing both parsed `config` and `raw_yaml` text.

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/config/raw.json"
```

Example response:
```json
{
  "server_time": "2026-02-24T05:36:03Z",
  "config": {
    "server": {"listen": {}},
    "upstreams": {"endpoints": [{"host": "8.8.8.8"}]}
  },
  "raw_yaml": "upstreams:\n  endpoints:\n  - host: 8.8.8.8\nserver:\n  listen: {}\n"
}
```

### POST `/api/v1/config/save` (alias: `/config/save`)
Auth: protected when `server.http.auth.mode: token`

Brief: writes new YAML to the configured config path and validates it.

Notes:
- This endpoint is intentionally side-effect free: it does not reload or restart the process.
- Use `/api/v1/config/reload` to apply a reload-only update when possible.
- Use `/api/v1/restart` (or `/api/v1/config/save_and_restart`) to schedule a SIGHUP restart.

Inputs:
- JSON body (required):
  - `raw_yaml` (string, required): full YAML document text

Example:
```bash
curl -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "raw_yaml": "upstreams:\n  endpoints:\n  - host: 8.8.8.8\nserver:\n  listen: {}\n"
  }' \
  "$BASE_URL/api/v1/config/save"
```

Example response:
```json
{
  "status": "ok",
  "server_time": "2026-02-24T05:36:03Z",
  "path": "/path/to/config.yaml",
  "backed_up_to": "/path/to/config.yaml.bak.2026-02-24T05-36-03+00-00"
}
```

---

## Configuration diagram

### GET `/api/v1/config/diagram.png` (alias: `/config/diagram.png`)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Query (optional):
  - `meta` (int, example: `1`): when non-zero, return an empty 200 with headers only.

Outputs:
- When the diagram exists and `meta` is not set: `image/png`
- When `meta=1`: empty body plus headers:
  - `X-Foghorn-Exists: 1` or `0`
  - `X-Foghorn-Warning: ...` (optional; staleness warning)

Example (meta-only):
```bash
curl -sS -D - \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/config/diagram.png?meta=1" \
  -o /tmp/diagram-meta-body.txt
```

### POST `/api/v1/config/diagram.png` (alias: `/config/diagram.png`)
Auth: protected when `server.http.auth.mode: token`

Brief: upload a custom PNG; saved to `<config_dir>/diagram.png`.

Inputs:
- `multipart/form-data` with field:
  - `file` (required): PNG file upload

Example:
```bash
curl -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -F 'file=@./diagram.png;type=image/png' \
  "$BASE_URL/api/v1/config/diagram.png"
```

Example response:
```json
{
  "status": "ok",
  "server_time": "2026-02-24T05:36:03Z",
  "path": "/path/to/diagram.png",
  "size_bytes": 42137
}
```

### GET `/api/v1/config/diagram-dark.png` (alias: `/config/diagram-dark.png`)
Auth: protected when `server.http.auth.mode: token`

Same inputs/outputs semantics as `diagram.png` (supports `meta=1`).

### GET `/api/v1/config/diagram.dot` (alias: `/config/diagram.dot`)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Query (optional):
  - `meta` (int, example: `1`): when non-zero, return empty body with any warning headers.

Outputs:
- `text/plain` dot graph content.

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/config/diagram.dot"
```

---

## Logs (webserver ring buffer)

### GET `/api/v1/logs` (alias: `/logs`)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Query (optional):
  - `limit` (int, default: `100`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/logs?limit=100"
```

Example response:
```json
{
  "server_time": "2026-02-24T05:36:03Z",
  "entries": [
    {"ts": 1708750000.0, "level": "INFO", "message": "started webserver"}
  ]
}
```

---

## Query log (statistics persistence store)

### GET `/api/v1/query_log` (alias: `/query_log`)
Auth: protected when `server.http.auth.mode: token`

Brief: returns query_log rows from the stats persistence store when enabled.

Inputs:
- Query (all optional):
  - `client_ip` (string, example: `192.0.2.10`)
  - `qtype` (string, example: `A`)
  - `qname` (string, example: `example.com`)
  - `rcode` (string, example: `NOERROR`)
  - `start` (string datetime, example: `2026-02-24T00:00:00Z`)
  - `end` (string datetime, example: `2026-02-24T23:59:59Z`)

Datetime parsing:
- Accepts ISO-8601 (including a trailing `Z`), e.g. `2026-02-24T00:00:00Z`
- Also accepts `YYYY-MM-DD HH:MM:SS` (optionally with fractional seconds), e.g. `2026-02-24 00:00:00`
  - `page` (int, default: `1`, example: `1`)
  - `page_size` (int, default: `100`, clamped to max `1000`, example: `100`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/query_log?client_ip=192.0.2.10&qtype=A&qname=example.com&page=1&page_size=100"
```

Disabled response:
```json
{
  "status": "disabled",
  "server_time": "2026-02-24T05:36:03Z",
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 100,
  "total_pages": 0
}
```

### GET `/api/v1/query_log/aggregate`
Auth: protected when `server.http.auth.mode: token`

Brief: aggregates query_log counts into time buckets.

Inputs:
- Query (required):
  - `interval` (int > 0, example: `60`)
  - `interval_units` (string, one of: `second`, `seconds`, `minute`, `minutes`, `hour`, `hours`, `day`, `days`, example: `minutes`)
  - `start` (string datetime, example: `2026-02-24T00:00:00Z`)
  - `end` (string datetime, example: `2026-02-24T01:00:00Z`)
- Query (optional):
  - `client_ip` (string, example: `192.0.2.10`)
  - `qtype` (string, example: `A`)
  - `qname` (string, example: `example.com`)
  - `rcode` (string, example: `NXDOMAIN`)
  - `group_by` (string, one of: `client_ip`, `qtype`, `qname`, `rcode`, example: `rcode`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/query_log/aggregate?interval=5&interval_units=minutes&start=2026-02-24T00:00:00Z&end=2026-02-24T01:00:00Z&group_by=rcode"
```

Example response:
```json
{
  "server_time": "2026-02-24T05:36:03Z",
  "start": "2026-02-24T00:00:00Z",
  "end": "2026-02-24T01:00:00Z",
  "interval_seconds": 300,
  "items": [
    {
      "bucket_start_ts": 1708732800,
      "bucket_end_ts": 1708733100,
      "bucket_start": "2026-02-24T00:00:00Z",
      "bucket_end": "2026-02-24T00:05:00Z",
      "group": "NOERROR",
      "count": 42
    }
  ]
}
```

---

## Plugins / Resolve integration

These endpoints live under the webserver but primarily expose data produced by plugins, including plugins under `src/foghorn/plugins/resolve/`.

### GET `/api/v1/plugin_pages`
Auth: protected when `server.http.auth.mode: token`

Brief: lists admin pages contributed by plugins (for the web UI).

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/plugin_pages"
```

### GET `/api/v1/plugin_pages/{plugin_name}/{page_slug}`
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Path (required):
  - `plugin_name` (string, example: `docker`)
  - `page_slug` (string, example: `docker-hosts`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/plugin_pages/docker/docker-hosts"
```

### GET `/api/v1/plugins/ui`
Auth: protected when `server.http.auth.mode: token`

Brief: returns “UI descriptors” for plugins (tab title, layout sections, and endpoint URLs). Use this to discover valid `table_id` values for table endpoints.

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/plugins/ui"
```

### GET `/api/v1/cache`
Auth: protected when `server.http.auth.mode: token`

Brief: returns a cache snapshot if the global DNS cache plugin is present and exposes `get_http_snapshot()`.

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/cache"
```

### GET `/api/v1/cache/table/{table_id}`
Auth: protected when `server.http.auth.mode: token`

Brief: server-side table pagination for cache admin UI sections.

Inputs:
- Path (required):
  - `table_id` (string, example: `caches`)
- Query (optional):
  - `page` (int, default: `1`)
  - `page_size` (int, default: `50`)
  - `sort_key` (string, example: `calls_total`)
  - `sort_dir` (string, `asc` or `desc`, example: `desc`)
  - `search` (string, example: `example.com`)
  - `hide_zero_calls` (int flag, example: `1`)
  - `hide_zero_hits` (int flag, example: `1`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/cache/table/caches?page=1&page_size=50&sort_key=calls_total&sort_dir=desc&hide_zero_calls=1"
```

### GET `/api/v1/plugins/{plugin_name}/table/{table_id}`
Auth: protected when `server.http.auth.mode: token`

Brief: server-side table pagination for an individual plugin snapshot.

Inputs:
- Path (required):
  - `plugin_name` (string, example: `docker`)
  - `table_id` (string, example: `containers`)
- Query (optional):
  - `page` (int, default: `1`)
  - `page_size` (int, default: `50`)
  - `sort_key` (string, example: `calls_total`)
  - `sort_dir` (string, `asc` or `desc`, example: `desc`)
  - `search` (string, example: `web`)
  - `hide_hash_like` (int flag, example: `1`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/plugins/docker/table/containers?page=1&page_size=50&search=web&hide_hash_like=1"
```

### GET `/api/v1/plugins/{plugin_name}/docker_hosts` (Resolve plugin: DockerHosts)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Path (required):
  - `plugin_name` (string, example: `docker`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/plugins/docker/docker_hosts"
```

### GET `/api/v1/plugins/{plugin_name}/etc_hosts` (Resolve plugin: EtcHosts)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Path (required):
  - `plugin_name` (string, example: `etc`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/plugins/etc/etc_hosts"
```

### GET `/api/v1/plugins/{plugin_name}/mdns` (Resolve plugin: MdnsBridge)
Auth: protected when `server.http.auth.mode: token`

Inputs:
- Path (required):
  - `plugin_name` (string, example: `mdns`)

Example:
```bash
curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/api/v1/plugins/mdns/mdns"
```

---

## DNS-over-HTTPS (DoH)

The DoH listener implements RFC 8484 at a single path:
- `/dns-query` (GET and POST)

### GET `/dns-query`
Auth: none

Inputs:
- Query (required):
  - `dns` (string, required): base64url (no padding) encoded DNS wire message.
- Headers (recommended):
  - `Accept: application/dns-message`

Example (dummy query for `A example.com.`):
```bash
DNS_QUERY_WIRE_HEX='000101000001000000000000076578616d706c6503636f6d0000010001'
DNS_QUERY_B64URL='AAEBAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'

curl -sS \
  -H 'Accept: application/dns-message' \
  "$DOH_BASE_URL/dns-query?dns=$DNS_QUERY_B64URL" \
  --output /tmp/doh-response.bin
```

Outputs:
- Success: HTTP 200 with `Content-Type: application/dns-message` and a DNS wire-format response body.
- Errors:
  - HTTP 400 for missing/invalid `dns` parameter.
  - FastAPI DoH path: HTTP 504 when the shared resolver returns an empty response (interpreted as drop/timeout).
  - Threaded DoH fallback: when the shared resolver returns an empty response, the server closes the connection without an HTTP response.

### POST `/dns-query`
Auth: none

Inputs:
- Headers (required):
  - `Content-Type: application/dns-message`
  - `Accept: application/dns-message`
- Body (required):
  - Raw DNS query wire bytes.

Example (dummy query for `A example.com.`):
```bash
DNS_QUERY_WIRE_HEX='000101000001000000000000076578616d706c6503636f6d0000010001'
printf '%s' "$DNS_QUERY_WIRE_HEX" | xxd -r -p > /tmp/doh-query.bin

curl -sS -X POST \
  -H 'Content-Type: application/dns-message' \
  -H 'Accept: application/dns-message' \
  --data-binary '@/tmp/doh-query.bin' \
  "$DOH_BASE_URL/dns-query" \
  --output /tmp/doh-response.bin
```

Outputs:
- Success: HTTP 200 with `Content-Type: application/dns-message`.
- Errors:
  - HTTP 415 when `Content-Type` is not `application/dns-message`.
  - FastAPI DoH path: HTTP 504 when the shared resolver returns an empty response (interpreted as drop/timeout).
  - Threaded DoH fallback: when the shared resolver returns an empty response, the server closes the connection without an HTTP response.

---

## Static admin UI (HTML + files)

### GET `/` (alias: `/index.html`)
Auth: none

Notes:
- Controlled by `server.http.index` (defaults to enabled).
- Returns `html/index.html` when present.

Example:
```bash
curl -i "$BASE_URL/"
```

### GET `/{path:path}`
Auth: none

Brief: catch-all route that serves files under the resolved `html/` root when they exist.

Inputs:
- Path (required):
  - `path` (string, example: `static/app.css`)

Example:
```bash
curl -i "$BASE_URL/static/app.css"
```

---

# DNS-level endpoints (Resolve plugins)

This section documents the DNS “endpoints” exposed via resolve plugins under `src/foghorn/plugins/resolve/`.

Conventions:
- Query inputs:
  - `qname`: domain name (case-insensitive; many plugins strip a trailing dot)
  - `qtype`: record type (A, AAAA, PTR, TXT, SRV, SSHFP, AXFR, IXFR, ANY, ...)
  - `client_ip`: client address (affects targeting and policy plugins)
  - `listener`: udp/tcp/dot/doh (affects some behavior like NOTIFY)
- Most examples use `dig`; replace placeholders as needed.

Common DNS example:
```bash
# UDP
DIG_UDP="dig @$DNS_SERVER -p $DNS_PORT"

# TCP (for AXFR/IXFR and for testing)
DIG_TCP="dig @$DNS_SERVER -p $DNS_TCP_PORT +tcp"
```

## Resolve plugin: DockerHosts (`docker_hosts.py`)

DNS endpoints:
- Forward lookups (container owners):
  - `A <container>.<suffix>`
  - `AAAA <container>.<suffix>`
  - `TXT <container>.<suffix>` (also includes A/AAAA in the same response)
  - When answering A/AAAA, the plugin may attach TXT lines as *additional* records.
- Reverse lookups:
  - `PTR <reverse_pointer>.in-addr.arpa`
  - `PTR <reverse_pointer>.ip6.arpa`
- Discovery aggregate TXT records (only when `discovery: true`):
  - `TXT _containers.<suffix>` (or `TXT _containers` when no suffix)
  - `TXT _hosts.<suffix>` (or `TXT _hosts` when no suffix)

Required inputs:
- `qname`: a published container name/alias, a PTR reverse name, or `_containers...` / `_hosts...`.
- `qtype`: one of A/AAAA/TXT/PTR.

Optional inputs/config knobs that change DNS-visible behavior:
- `suffix` (plugin-level and/or per-endpoint): controls whether owners are published as `name.suffix`.
- `discovery` (bool): enables `_containers.*` and `_hosts.*` TXT.
- `ttl` (plugin-level) and per-endpoint `ttl`.
- Per-endpoint `use_ipv4` / `use_ipv6`: forces answers to point at host IPs.

Examples:
```bash
$DIG_UDP web.docker.example A
$DIG_UDP web.docker.example AAAA
$DIG_UDP web.docker.example TXT
$DIG_UDP 10.0.0.127.in-addr.arpa PTR
$DIG_UDP _containers.docker.example TXT
$DIG_UDP _hosts.docker.example TXT
```

## Resolve plugin: EtcHosts (`etc_hosts.py`)

DNS endpoints:
- Forward lookups (from merged hosts files):
  - `A <name>`
  - `AAAA <name>`
- Reverse lookups (only synthesized for IPv4 entries):
  - `PTR <reversed-ipv4>.in-addr.arpa`

Required inputs:
- `qname`: an owner present in the loaded hosts mapping.
- `qtype`: A/AAAA/PTR.

Examples:
```bash
$DIG_UDP myhost.example A
$DIG_UDP myhost.example AAAA
$DIG_UDP 10.0.0.127.in-addr.arpa PTR
```

## Resolve plugin: MdnsBridge (`mdns.py`)

MdnsBridge maps (selected) mDNS/DNS-SD data into one or more configured DNS suffixes.

DNS endpoints (within configured suffixes; default suffix is `.local`):
- Host address lookups:
  - `A <host><suffix>` (when `include_ipv4: true`)
  - `AAAA <host><suffix>` (when `include_ipv6: true`)
- Service instance record lookups:
  - `SRV <instance>.<service>._tcp<suffix>`
  - `SRV <instance>.<service>._udp<suffix>`
  - `TXT <instance>.<service>._tcp<suffix>`
  - `TXT <instance>.<service>._udp<suffix>`
- DNS-SD browsing via PTR:
  - `PTR _services._dns-sd._udp<suffix>` (enumerates service types)
  - `PTR _dns_sd._tcp<suffix>` (alias for `_services._dns-sd._udp<suffix>`)
  - `PTR _tcp<suffix>` and `PTR _udp<suffix>` (enumerate service types for that protocol)
  - `PTR <service>._tcp<suffix>` and `PTR <service>._udp<suffix>` (enumerate instances of that service type)

Required inputs:
- `qname`: must be under one of the configured MdnsBridge DNS suffixes.
- `qtype`: typically PTR/SRV/TXT/A/AAAA/ANY.

Key config options that affect what is visible over DNS:
- `domain`: DNS suffix under which to *serve* discovered mDNS data (stored internally as `.suffix`).
- `domains` (optional): additional DNS suffixes under which to serve the same discovered data.
- `network_enabled`: when false, the plugin does not browse the network.
- `include_ipv4`, `include_ipv6`: whether A/AAAA are synthesized.
- `service_types`: explicit list of service types to browse when `_services._dns-sd._udp.local.` is not available.

Examples:
```bash
# Browse service types
$DIG_UDP _services._dns-sd._udp.local PTR

# Browse instances of a specific service type
$DIG_UDP _http._tcp.local PTR

# Query a specific service instance
$DIG_UDP 'My Printer._ipp._tcp.local' SRV
$DIG_UDP 'My Printer._ipp._tcp.local' TXT

# Query the target host emitted by SRV
$DIG_UDP printer-host.local A
$DIG_UDP printer-host.local AAAA
```

## Resolve plugin: ZoneRecords (`zone_records/`)

ZoneRecords serves authoritative zone data loaded from zone files and/or AXFR, and supports DNSSEC-aware responses.

DNS endpoints:
- Authoritative queries for any owner inside a configured zone, for any RR type present in zone data.
- `ANY <owner>` returns all RRsets at the owner (DNSSEC RRtypes may be suppressed unless the client sets DO=1).
- DNSSEC: when the client sets EDNS(0) DO=1, the plugin may include DNSSEC RRsets/signatures (when present).
- NOTIFY handling:
  - Opcode: NOTIFY (4)
  - Transport: UDP only
  - Sender: must match a configured upstream (otherwise denied)
- Zone transfers (served by the TCP/DoT listeners):
  - `AXFR <zone-apex>` over TCP/DoT
  - `IXFR <zone-apex>` over TCP/DoT (currently streamed as a full AXFR-style transfer)

Required inputs:
- For normal authoritative queries: `qname` inside a configured zone, and an RR type present in that zone.
- For AXFR/IXFR: `qname` must be the zone apex.

Examples:
```bash
# Regular authoritative lookup
$DIG_UDP www.example.com A

# DNSSEC-aware query (DO=1)
$DIG_UDP www.example.com A +dnssec

# Zone transfer (TCP)
$DIG_TCP example.com AXFR
$DIG_TCP example.com IXFR
```

## Resolve plugin: SshKeys (`ssh_keys.py`)

DNS endpoints:
- `SSHFP <subject>` when subject exists in the local sqlite cache.

Required inputs:
- `qtype`: SSHFP
- `qname`: hostname or IP that has been scanned/cached.

Example:
```bash
$DIG_UDP server1.example SSHFP
$DIG_UDP 192.0.2.10 SSHFP
```

## Resolve plugin: Filter (`filter.py`)

Filter is primarily a policy plugin; it affects many (or all) DNS names depending on configuration.

DNS-visible behaviors:
- Pre-resolve:
  - Deny/allow based on exact allow/deny lists, regex patterns, and keyword matches.
  - Optional per-qtype allow/deny via `allow_qtypes` / `deny_qtypes`.
  - Deny response behavior is controlled by `deny_response`:
    - `nxdomain`, `refused`, `servfail`, `noerror_empty`, `nodata`, `ip`, `drop`
- Post-resolve (A/AAAA only):
  - Remove/deny/replace answers based on matching returned IPs or IP subnets.

Required inputs:
- `qname`, `qtype`: any query (post-resolve applies only to A/AAAA).

Example:
```bash
$DIG_UDP ads.example A
$DIG_UDP www.example.com A
```

## Resolve plugin: AccessControl (`access_control.py`)

AccessControl is a policy plugin; it applies to any query from a client that matches its targeting.

DNS-visible behaviors:
- Pre-resolve: returns `deny` when `client_ip` matches a configured deny CIDR/IP.
- Otherwise defaults to `allow` or `deny` based on `default`.

Required inputs:
- `client_ip` (the only meaningful “input” for this plugin).

## Resolve plugin: UpstreamRouter (`upstream_router.py`)

UpstreamRouter influences where queries are forwarded.

DNS-visible behaviors:
- For queries whose `qname` matches a configured exact `domain` or a `suffix`, it sets `ctx.upstream_candidates`.

Required inputs:
- `qname`.

## Resolve plugin: FlakyServer (`flaky_server.py`)

FlakyServer is a testing/degradation plugin.

DNS-visible behaviors (probabilistic):
- Can drop queries (timeout), or override with SERVFAIL/NXDOMAIN/FORMERR/NOERROR-empty.
- Can fuzz responses in post_resolve.

Required inputs:
- `client_ip` and `qtype` (affected by targeting + `apply_to_qtypes`).

## Resolve plugin: Echo (`echo.py`)

Echo is a simple test plugin.

DNS endpoints:
- Answers any targeted query with a single TXT RR containing `"<qname> <qtype>"`.

Example:
```bash
$DIG_UDP anything.example TXT
$DIG_UDP anything.example A
```

## Resolve plugin: RateLimit (`rate_limit.py`)

RateLimit does not expose specific DNS owners; it enforces per-key rate limits on query handling.

## Resolve plugin: FileDownloader (`file_downloader.py`)

FileDownloader does not expose DNS owners; it periodically downloads list files for other plugins (for example Filter).
