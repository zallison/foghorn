# Foghorn Configuration & Operations

Foghorn is a versatile DNS server designed for flexibility and performance. Built on a robust caching forwarder or recursive resolver foundation, it seamlessly integrates with YAML-based configuration and modular plugins to transform into a powerful ad-blocker, local hosts service, kid-safe filter. Fine-tune its capabilities with a Redis backend, InfluxDB logging, and customizable function-cache sizes tailored to your specific needs.

With built-in admin and API server support, Foghorn empowers you to monitor and manage its operations efficiently. Plugins extend its functionality by providing their own status pages, seamlessly integrated into the admin dashboard.

[![Python Tests](https://github.com/zallison/foghorn/actions/workflows/pytest.yml/badge.svg)](https://github.com/zallison/foghorn/actions/workflows/pytest.yml) ![Docker Pulls](https://img.shields.io/docker/pulls/zallison/foghorn)  [![PyPI Downloads](https://static.pepy.tech/personalized-badge/foghorn?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/foghorn)

<img src="https://raw.githubusercontent.com/zallison/foghorn/refs/heads/main/assets/screenshot-1.png" width=300px />



The configuration file is validated against a JSON Schema, but you rarely need to read the schema directly. This guide walks through the main sections (`vars`, `server`, `upstreams`, `logging`, `stats`, and `plugins`), then shows concrete examples for every built‑in plugin.

## Table of Contents

- [1. Quick start: minimal config](#1-quick-start-minimal-config)
- [2. Configuration layout overview](#2-configuration-layout-overview)
  - [2.1 Top-level keys](#21-top-level-keys)
  - [2.2 Server block](#22-server-block)
  - [2.3 Upstreams block](#23-upstreams-block)
  - [2.4 Logging](#24-logging)
  - [2.5 Stats and query log](#25-stats-and-query-log)
  - [2.6 Plugins](#26-plugins)
- [3. Listeners and upstreams by example](#3-listeners-and-upstreams-by-example)
  - [3.1 UDP/TCP listener](#31-udptcp-listener)
  - [3.2 DNS-over-TLS (DoT) upstream](#32-dns-over-tls-dot-upstream)
  - [3.3 DNS-over-HTTPS (DoH) listener with TLS](#33-dns-over-https-doh-listener-with-tls)
  - [3.4 DoH listener behind an HTTP reverse proxy](#34-doh-listener-behind-an-http-reverse-proxy)
- [4. Plugin cookbook](#4-plugin-cookbook)
  - [4.1 Access control (acl)](#41-access-control-acl)
  - [4.2 DNS prefetch (prefetch)](#42-dns-prefetch-prefetch)
  - [4.3 Docker containers (docker)](#43-docker-containers-docker)
  - [4.4 Hosts files (hosts)](#44-hosts-files-hosts)
  - [4.5 Example rewrites EXAMPLE(examples)](#45-example-rewrites-examples)
  - [4.6 List downloader (lists)](#46-list-downloader-lists)
  - [4.7 Domain filter / adblock (filter)](#47-domain-filter--adblock-filter)
  - [4.8 Flaky upstream simulator (flaky)](#48-flaky-upstream-simulator-flaky)
  - [4.9 Greylist new names EXAMPLE (greylist_example)](#49-greylist-new-names-greylist_example)
  - [4.10 mDNS / Bonjour bridge (mdns)](#410-mdns--bonjour-bridge-mdns)
  - [4.11 New-domain WHOIS filter EXAMPLE (new_domain)](#411-new-domain-whois-filter-new_domain)
  - [4.12 Rate limiting (rate)](#412-rate-limiting-rate)
  - [4.13 Per-domain upstream routing (router)](#413-per-domain-upstream-routing-router)
  - [4.14 Inline and file-based records (zone)](#414-inline-and-file-based-records-zone)
- [5. Sample configurations](#5-sample-configurations)
  - [5.1 `local`: workstation config](#51-local-workstation-config)
  - [5.2 `lan`: home LAN with adblock and kid filter](#52-lan-home-lan-with-adblock-and-kid-filter)
  - [5.3 `smb`: small business](#53-smb-small-business)
  - [5.4 `enterprise`: layered caches and rich stats](#54-enterprise-layered-caches-and-rich-stats)

---

## 1. Quick start: minimal config

This example listens on all interfaces for UDP/TCP DNS and forwards to a public DoT resolver. It also enables a simple in-memory cache.

```yaml
# config/config.yaml

vars:
  ENV: prod

server:
  listen:
	dns:
	  udp:
		enabled: true
		host: 0.0.0.0
		port: 53
	  tcp:
		enabled: true
		host: 0.0.0.0
		port: 53
  cache:
	module: memory  # memory | sqlite | redis | memcached | mongodb | none

upstreams:
  strategy: failover        # failover | round_robin | random
  max_concurrent: 1         # 1 | 2 | 4 ...
  endpoints:
	- host: 1.1.1.1
	  port: 853
	  transport: dot        # udp | tcp | dot
	  tls:
		server_name: cloudflare-dns.com

plugins: []
```

You can start Foghorn with:

```bash
foghorn --config config/config.yaml
```

From here you layer in plugins to get adblocking, hosts files, per-user allowlists, and more.

---

## 2. Configuration layout overview

### 2.1 Top-level keys

At the top level the schema defines these keys:

- `vars`: key/value variables for interpolation inside the rest of the file.
- `server`: listener, DNSSEC, resolver, cache, and admin HTTP settings.
- `upstreams`: how outbound DNS queries are sent.
- `logging`: global logging level and outputs.
- `stats`: runtime statistics and query-log persistence.
- `plugins`: the ordered list of plugins that wrap each query.

Conceptually, a request flows like this:

```text
client ---> UDP/TCP/DoH listener
		---> DNS cache (optional)
		---> plugins (pre_resolve chain)
		---> [maybe upstream DNS calls]
		---> plugins (post_resolve chain)
		---> response or deny
```

**Note:** when a pre_resolve plugin returns an `override` decision the generated
response is sent immediately and the post_resolve chain is skipped entirely; a
post_resolve `override` short-circuits any later post_resolve plugins for that
query.

### 2.2 Server block

Key parts of `server`:

- `server.listen`
  - `dns.udp` / `dns.tcp`: classic DNS listeners.
  - `dns.dot`: DNS-over-TLS listener.
  - `doh`: DNS-over-HTTPS listener.
- `server.cache`
  - `module`: which cache plugin to use.
  - `config`: plugin-specific cache settings.
  - `modify` / `decorated_overrides`: optional overrides for internal helper caches.
- `server.dnssec`
  - Mode and DNSSEC validation knobs (e.g., UDP payload size).
- `server.resolver`
  - Timeouts, recursion depth, and whether Foghorn runs as a forwarder or recursive resolver.
- `server.http`
  - Admin web UI listener configuration.

### 2.3 Upstreams block

`upstreams` describes how Foghorn talks to other DNS servers:

- `strategy`: `failover` (try in order), `round_robin`, or `random`.
- `max_concurrent`: maximum simultaneous outstanding upstream queries.
- `endpoints`: list of `upstream_host` definitions.

An `upstream_host` entry:

```yaml
upstreams:
  endpoints:
	- host: 9.9.9.9
	  port: 53        # 853 for DoT
	  transport: udp  # udp | tcp | dot
	  tls:
        server_name: dns.quad9.net
		verify: true  # true | false
```

An `upstream_host` entry: using `DNS-over-HTTP(s)`

```yaml
upstreams:
  endpoints:
	- transport: doh
	  url: https://dns.example.com/dns-query
	  method: POST    # POST | GET
	  tls:
		verify: true  # true | false
		ca_file: /etc/ssl/certs/ca-certificates.crt
```

### 2.4 Logging

`logging` controls the process-wide logger:

```yaml
logging:
  level: info       # debug | info | warn | error | critical
  stderr: true      # true | false
  file: ./var/foghorn.log
  syslog: false     # false | true | {address, facility, tag}
```

Plugins can also override logging per-instance via their own `config.logging` block.

### 2.5 Stats and query log

The `stats` section controls runtime statistics and persistent query-log backends.

Important fields include:

- `logging_only`: when true, only write raw query logs or counters; skip heavy background rebuilds.
- `query_log_only`: when true, do not persist aggregate counts, only the raw query log.
- `persistence.primary_backend`: which backend to treat as primary when several are configured.
- `persistence.backends`: list of backend entries.

Example:

```yaml
stats:
  logging_only: false       # false | true
  query_log_only: false     # false | true
  persistence:
	primary_backend: sqlite # sqlite | mysql | postgres | mongo | influx | mqtt
	backends:
	  - backend: sqlite
		config:
		  db_path: ./config/var/stats.db
	  - backend: influx
		config:
		  write_url: http://127.0.0.1:8086/api/v2/write
		  bucket: dns
		  org: myorg
```

### 2.6 Plugins

In the `plugins` list each entry is a `PluginInstance`:

```yaml
plugins:
  - type: filter
	id: main-filter
	enabled: true
	setup:
	  abort_on_failure: true
	hooks:
``	  pre_resolve:
		enabled: true
		priority: 50
	logging:
	  level: info
	config:
	  # plugin-specific config here
```

You normally care about:

- `type`: short alias for the plugin.
- `id`: optional stable identifier for this plugin instance (surfaced in stats, logs, and admin UI).
- `enabled`: whether it runs.
- `hooks`: per-hook enable/priority overrides (optional).
- `setup`: one-time setup behaviour; `abort_on_failure` controls whether a failing setup() aborts startup.
- `logging`: per-plugin logging overrides (level, file, stderr, syslog) using the same shape as the global `logging` block.
- `config`: the actual configuration for that plugin.

Common plugin‑wide options:

- **Client targeting** (all resolve plugins honor this):
  - `config.targets`: list (or single string) of CIDR/IPs to explicitly target. When set, only matching clients are affected.
  - `config.targets_ignore`: list (or single string) of CIDR/IPs to skip. When only `targets_ignore` is set, all other clients are targeted by default.
- **qtype targeting**:
  - `config.target_qtypes`: list of qtype names or `'*'` for all types, e.g. `['A', 'AAAA']`, `['MX']` or `['*']`.
- **Per-plugin logging**:
  - The `logging` stanza on the plugin instance lets you bump log level or direct output differently from the global logger.

Example with targeting and qtype selection:

```yaml
plugins:
  - type: filter
	id: lan-filter
	enabled: true
	logging:
	  level: debug
	config:
	  targets:
		- 192.168.0.0/16
	  targets_ignore:
		- 192.168.0.10
	  target_qtypes: ['A', 'AAAA']  # '*' | ['A'] | ['A', 'AAAA']
```

---

## 3. Listeners and upstreams by example

### 3.1 UDP/TCP listener

A typical `server.listen.dns` configuration:

```yaml
server:
  listen:
	dns:
	  udp:
		enabled: true
		host: 0.0.0.0
		port: 53
	  tcp:
		enabled: true
		host: 0.0.0.0
		port: 53
```

Turn TCP off if you never want to accept TCP DNS:

```yaml
	  tcp:
		enabled: false  # true | false
```

### 3.2 DNS-over-TLS (DoT) upstream

To talk to an upstream DoT resolver:

```yaml
upstreams:
  strategy: round_robin      # failover | round_robin | random
  endpoints:
	- host: 1.1.1.1
	  port: 853
	  transport: dot
	  tls:
		server_name: cloudflare-dns.com
		verify: true
```

You can mix DoT and plain UDP endpoints in the same list; the `strategy` decides how they are chosen.

### 3.3 DNS-over-HTTPS (DoH) listener with TLS

To expose a DoH listener directly from Foghorn (for example on port 8053 with TLS termination):

```yaml
server:
  listen:
	# ... dns.udp / dns.tcp here ...
	doh:
	  enabled: true
	  host: 0.0.0.0
	  port: 8053
	  cert_file: /etc/foghorn/tls/server.crt
	  key_file: /etc/foghorn/tls/server.key
```

### 3.4 DoH listener behind an HTTP reverse proxy

When Foghorn itself is running behind an HTTP reverse proxy (for example, nginx or Envoy), you typically terminate TLS at the proxy and run the DoH listener as plain HTTP on localhost. The proxy handles `https://` and forwards `/dns-query` to Foghorn:

```yaml
server:
  listen:
	# ... dns.udp / dns.tcp here ...
	doh:
	  enabled: true
	  host: 127.0.0.1
	  port: 8053
	  # No cert_file/key_file here; TLS is terminated at the reverse proxy.
```

Your reverse proxy is then configured to listen on `443` with TLS and proxy requests such as `https://dns.example.com/dns-query` to `http://127.0.0.1:8053/dns-query`.

---

## 4. Plugin cookbook

Below are the built‑in plugins, with short descriptions and minimal configs. All examples assume they live in the shared `plugins:` list.

### 4.1 Access control (`acl`)

IP-based allow/deny control at the edge.

```yaml
plugins:
  - type: acl
	config:
	  default: allow       # allow | deny
	  allow:
		- 192.168.1.1 # Overrides the deny below.
		- 10.0.0.0/8
	  deny:
        - 192.168.0.0/16
		- 172.16.0.0/12
```

### 4.2 Example: DNS prefetch (`prefetch`)

Prefetches the most popular names from statistics to keep the cache warm.  Not very effecient yet, but it shows the concept

```yaml
plugins:
  - type: prefetch
	config:
	  interval_seconds: 60
	  prefetch_top_n: 100
	  max_consecutive_misses: 5
	  qtypes: ['A', 'AAAA']
```

### 4.3 Docker containers (`docker`)

Expose Docker container names as DNS answers.

```yaml
plugins:
  - type: docker
	config:
	  endpoints:
		- url: unix:///var/run/docker.sock
        - url: tcp://my.server.lan:2375
	  ttl: 60
	  health: ['healthy', 'running']
	  discovery: true   # false | true
```

### 4.4 Hosts files (`hosts`)

Serve additional records from one or more hosts-style files.

```yaml
plugins:
  - type: hosts
	config:
	  file_paths:
		- /etc/hosts
		- ./config/hosts.local
	  ttl: 300
	  watchdog_enabled: true   # null | true | false
```

### 4.5 Example rewrites (`examples`)

A playground plugin that can rewrite responses or demonstrate behaviours.

```yaml
plugins:
  - type: examples
	config:
	  base_labels: 2
	  max_subdomains: 5
	  apply_to_qtypes: ['A']
```

### 4.6 List downloader (`lists`)

Fetches remote blocklists/allowlists on a schedule and stores them as files for other plugins.

```yaml
plugins:
  - type: lists
    hooks: # Setup early so other plugins have their files available.
      setup:  { priority: 10 }
	config:
	  download_path: ./config/var/lists
	  interval_days: 1
	  hash_filenames: true # false | true - Multiple "hosts.txt" files easily handled by hashing the URL
	  urls:
		- https://example.com/ads.txt
        - https://example.com/hosts.txt
        - https://serverA/hosts.txt
        - https://serverB/hosts.txt
```

### 4.7 Domain filter / adblock (`filter`)

Flexible domain/IP/pattern filter used to build adblockers and kid-safe DNS.

```yaml
plugins:
  - type: filter
	config:
    hooks:
      pre_resolve:  { priority: 25 } # Run early in block queries so other plugins don't do anything
      post_resolve: { priority: 25 } # if it's blocked.
	  default: aloow  # deny | allow
      targets:
          - 10.0.1.0/24 # Kids subnet
	  ttl: 300
	  deny_response: nxdomain  # nxdomain | refused | servfail | ip | noerror_empty
	  deny_response_ip4: 0.0.0.0
	  blocked_domains_files:
		- ./config/var/lists/*.txt
	  allowed_domains:
		- homework.example.org
      blocked_domains:
        - how-to-cheat.org
        - current-game-obession.io

```

### 4.8 Flaky upstream simulator (`flaky`)

Injects DNS errors and timeouts for testing client behaviour.

```yaml
plugins:
  - type: flaky
	config:
	  servfail_percent: 5
	  nxdomain_percent: 0
	  timeout_percent: 1
	  truncate_percent: 0
	  noerror_empty_percent: 0
	  apply_to_qtypes: ['A', 'AAAA']
```

### 4.9 Greylist new names (`greylist_example`)

Introduces a delay window before new names are allowed.  The origin of the project!  Started as a greylist for security researches working on phishing protection. It would sound an alarm when potential phishing domain names were spotted.  Things like "mycorp.phishing.com".
The idea was most of these phishing domains don't see any traffic before the campagin is active.


```yaml
plugins:
  - type: greylist_example
	config:
	  db_path: ./config/var/greylist.db
	  cache_ttl_seconds: 300
	  duration_hours: 24
```

### 4.10 mDNS / Bonjour bridge (`mdns`)

Expose mDNS / DNS-SD services as normal DNS records.

```yaml
plugins:
  - type: mdns
	config:
	  domain: '.local'
	  ttl: 120
	  include_ipv4: true   # true | false
	  include_ipv6: true   # true | false
	  network_enabled: true
```

### 4.11 New-domain WHOIS filter EXAMPLE (`new_domain`)

Blocks domains that appear too new according to WHOIS data.

```yaml
plugins:
  - type: new_domain
	config:
	  threshold_days: 7
	  whois_db_path: ./config/var/whois_cache.db
	  whois_cache_ttl_seconds: 3600
```

### 4.12 Rate limiting (`rate`)

Adaptive rate limiting per client or per (client,domain).

```yaml
plugins:
  - type: rate
	config:
	  mode: per_client        # per_client | per_client_domain | per_domain
	  window_seconds: 10
	  warmup_windows: 6
	  burst_factor: 3.0
	  min_enforce_rps: 50.0
	  deny_response: nxdomain # nxdomain | refused | servfail | noerror_empty | ip
	  deny_response_ip4: 0.0.0.0
	  db_path: ./config/var/rate_limit.db
```

### 4.13 Per-domain upstream routing (`router`)

Send different domains to different upstreams.

```yaml
upstreams:
  strategy: failover
  endpoints:
	- host: 9.9.9.9
	  port: 53
	  transport: udp

plugins:
  - type: router
	config:
	  routes:
		- domain: internal.example
		  upstreams:
			- host: 10.0.0.53
			  port: 53
		- suffix: corp.local
		  upstreams:
			- host: 192.168.1.1
			  port: 53
```

### 4.14 Inline and file-based records (`zone`)

Define custom records either inline or in zone files.

```yaml
plugins:
  - type: zone
	config:
	  file_paths:
		- ./config/zones.d/internal.zone
	  records:
		- 'printer.lan|A|300|192.168.1.50'
		- 'files.lan|AAAA|300|2001:db8::50'
	  ttl: 300
```

---

## 5. Sample configurations

These sketches show how all the pieces fit together. Adjust paths and IPs to match your environment.

### 5.1 `local`: workstation config

Goals:

- Cache locally for speed.
- Forward to a public DoT resolver.
- No plugins yet.

```yaml
vars:
  PROFILE: local

server:
  listen:
	dns:
	  udp: {enabled: "true", host: "127.0.0.1", port: 5353}
  cache:
	module: memory

upstreams:
  strategy: failover
  endpoints:
	- host: 1.1.1.1
	  port: 853
	  transport: dot
	  tls: {server_name: "cloudflare-dns.com", verify: true}

logging:
  level: info

stats:
  logging_only: true

plugins: []
```

### 5.2 `lan`: home LAN with adblock and kid filter

Goals:

- Listen on all interfaces.
- Use filter+lists to block ads.
- Use a second filter instance as a stricter allowlist for kids.
- Route internal corp domains to a separate upstream.

```yaml
vars:
  PROFILE: lan
  LAN: 192.168.0.0/16
  KIDS: 192.168.2.0/24

server:
  listen:
	dns:
	  udp: {enabled: true, host: 0.0.0.0, port: 53}
  cache:
	module: sqlite
	config:
	  db_path: ./config/var/dns_cache.db

upstreams:
  strategy: round_robin
  endpoints:
	- host: 9.9.9.9
	  port: 53
	  transport: udp
	- host: 1.1.1.1
	  port: 53
	  transport: udp

logging:
  level: info

stats:
  logging_only: false
  persistence:
	primary_backend: sqlite
	backends:
	  - backend: sqlite
		config:
		  db_path: ./config/var/stats_lan.db

plugins:
  - type: lists
	id: blocklists
	config:
	  pre_priority: 20
	  download_path: ./config/var/lists
	  interval_days: 1
	  urls:
		- https://example.com/ads.txt

  - type: filter
	id: adblock  # Ad block for everyone
	config:
	  pre_priority: 40
	  default: allow
	  blocked_domains_files:
		- ./config/var/lists/ads.txt

  - type: filter
	id: kids  # Filter just for the kids.
	config:
	  pre_priority: 50
	  targets: ${KIDS}
	  default: deny
	  allowed_domains:
		- homework.example.org
		- library.example.org
	  deny_response: ip
	  deny_response_ip4: 0.0.0.0

  - type: router
	id: corp-router
	config:
	  pre_priority: 80
	  routes:
		- suffix: corp
		  upstreams:
			- host: 192.168.100.53
			  port: 53
```

### 5.3 `smb`: small business

Goals:

- Persistent DNS cache.
- Local LAN overrides via hosts, mDNS bridge, and zone records.
- Simple access control and rate limiting.
- Query-log persistence in MariaDB/MySQL.

```yaml
vars:
  PROFILE: smb
  LISTEN: "0.0.0.0"
  LAN: 192.168.0.0/16
  FLOOR1: 192.168.10.50
  FLOOR2: 192.168.20.50
  FLOOR1_NET: 192.168.10.0/24
  FLOOR2_NET: 192.168.20.0/24

server:
  listen:
	dns:
	  udp: {enabled: true, host: ${LISTEN}, port: 53}
	  tcp: {enabled: true, host: ${LISTEN}, port: 53}
  cache:
	module: sqlite
	config:
	  db_path: ./config/var/dns_cache.db

upstreams:
  strategy: failover
  endpoints:
	- host: dot1.myisp.example
	  port: 853
	  transport: dot
	  tls: {server_name: dot1.myisp.example, verify: true}
	- host: dot2.myisp.example
	  port: 853
	  transport: dot
	  tls: {server_name: dot2.myisp.example, verify: true}

logging:
  level: info

stats:
  logging_only: false
  persistence:
	primary_backend: mariadb
	backends:
	  - backend: mariadb
		config:
		  host: db.internal
		  port: 3306
		  user: foghorn
		  database: foghorn_stats

plugins:
  - type: acl
	id: lan-only
	config:
	  pre_priority: 10
	  default: deny
	  allow:
		- ${LAN}

  - type: hosts
	id: office-hosts
	config:
	  pre_priority: 20
	  file_paths:
		- /etc/hosts
		- ./config/hosts.office

  - type: mdns
	id: office-mdns
	config:
	  pre_priority: 30
	  domain: 'devices.mycorp'
	  ttl: 120

  - type: zone
	id: printers-floor1
	config:
	  pre_priority: 40
	  targets: ${FLOOR1_NET}
	  records:
		- 'printer.corp|A|300|${FLOOR1}'

  - type: zone
	id: printers-floor2
	config:
	  pre_priority: 41
	  targets: ${FLOOR2_NET}
	  records:
		- 'printer.corp|A|300|${FLOOR2}'

  - type: docker
	id: lan-docker
	config:
	  pre_priority: 50
	  targets: ${LAN}
	  endpoints:
		- url: unix:///var/run/docker.sock
	  ttl: 60

  - type: rate
	id: smb-rate
	config:
	  pre_priority: 90
	  mode: per_client
	  window_seconds: 10
	  min_enforce_rps: 20.0
	  deny_response: servfail
```

### 5.4 `enterprise`: layered caches and rich stats

Goals:

- Redis or Memcached cache for large edge deployments.
- Multiple PostgreSQL statistics backends plus Influx logging.
- Heavy use of plugins (router, filter, docker, mdns, zone).
- Fine-grained client targeting and per-plugin priorities.

```yaml
vars:
  PROFILE: enterprise
  LISTEN: 0.0.0.0
  LAN: 10.0.0.0/16
  OFFICE: 10.10.0.0/16
  OFFICE_REMOTE: 10.20.0.0/16

server:
  listen:
	dns:
	  udp: {enabled: true, host: ${LISTEN}, port: 53}
	  tcp: {enabled: true, host: ${LISTEN}, port: 53}
	  dot:
		enabled: true
		host: ${LISTEN}
		port: 853
		cert_file: /etc/foghorn/tls/server.crt
		key_file: /etc/foghorn/tls/server.key
  cache:
	module: redis # redis | memcached | sqlite | memory | mongodb | none
	config:
	  url: redis://redis-cache.internal:6379/0
	  namespace: foghorn:dns_cache:

upstreams:
  strategy: round_robin
  max_concurrent: 4
  endpoints:
	- host: 10.0.0.53
	  port: 53
	  transport: udp
	  pool:
		max_connections: 64
		idle_timeout_ms: 30000
	- host: 10.0.1.53
	  port: 53
	  transport: udp
	  pool:
		max_connections: 64
		idle_timeout_ms: 30000
	- host: 10.0.2.53
	  port: 853
	  transport: dot
	  tls: {server_name: dns.corp.example, verify: true}
	  pool:
		max_connections: 32
		idle_timeout_ms: 60000

logging:
  level: info

stats:
  logging_only: false
  query_log_only: false
  persistence:
	primary_backend: pg_primary
	backends:
	  - backend: postgres
		name: pg_primary
		config:
		  host: pg-primary.internal
		  port: 5432
		  user: foghorn
		  database: foghorn_stats
		  connect_kwargs:
			application_name: foghorn-primary
	  - backend: postgres
		name: pg_reporting
		config:
		  host: pg-reporting.internal
		  port: 5432
		  user: foghorn_ro
		  database: foghorn_stats
	  - backend: influx
		config:
		  write_url: http://metrics.internal:8086/api/v2/write
		  bucket: dns
		  org: infra

plugins:
  - type: acl
	id: lan-only
	config:
	  pre_priority: 10
	  default: deny
	  allow:
		- ${LAN}

  - type: docker
	id: lan-docker
	config:
	  pre_priority: 20
	  targets: ${LAN}
	  endpoints:
		- url: unix:///var/run/docker.sock
	  ttl: 60

  - type: mdns
	id: enterprise-mdns
	config:
	  pre_priority: 30
	  domain: 'devices.lan'
	  ttl: 120

  - type: zone
	id: zone-1-office
	config:
	  pre_priority: 40
	  targets: ${OFFICE}
	  file_paths:
		- ./config/zones.d/zone-1.zone

  - type: zone
	id: zone-2-remote
	config:
	  pre_priority: 41
	  targets: ${OFFICE_REMOTE}
	  file_paths:
		- ./config/zones.d/zone-2.zone

  - type: router
	id: corp-router
	config:
	  pre_priority: 60
	  routes:
		- suffix: corp.example
		  upstreams:
			- host: 10.1.0.53
			  port: 53

  - type: filter
	id: global-filter
	config:
	  pre_priority: 80
	  default: allow
	  blocked_domains_files:
		- ./config/var/lists/global_block.txt
```

From here you can mix and match plugins, caches, and stats backends to shape Foghorn into exactly the DNS service you need.
