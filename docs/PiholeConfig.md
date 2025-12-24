# Building a Foghorn Config: From Forwarder to Pi-hole-Style DNS

This guide walks through building a Foghorn DNS configuration **incrementally**.
You’ll start with a minimal DNS forwarder and gradually add plugins to achieve a
Pi-hole-like experience: blocklists, local hosts, zone records, and dynamic
sources such as Docker.

---

## 1. Minimal DNS Forwarder

Every Foghorn configuration begins with:

- **Listeners** – where Foghorn accepts DNS queries
- **Upstreams** – DNS servers to forward unresolved queries to

Minimal configuration:

```yaml
listen:
  udp:
	enabled: true
	host: 0.0.0.0
	port: 5335

upstreams:
  - host: 8.8.8.8
	port: 53
	transport: udp
```

### What this does

Foghorn listens on UDP port `5335` and forwards all DNS queries to Google DNS.

```
+--------+    +-----------+    +------------+
| Client | →  | UDP :5335 | -> | 8.8.8.8:53 |
+--------+    +-----------+    +------------+
```

At this stage, Foghorn behaves as a simple caching DNS proxy.  See `CachePlugin`
for more information about caching.

---

## 2. Plugins Overview

Plugins extend Foghorn’s behavior. Each plugin is listed under `plugins` and
configured independently. All plugins support `targets` (and `targets_ignore`),
a list of CIDRs used to decide whether the plugin applies to a given client.

Common plugin categories include:

- **Data sources** – download lists, read files, discover hosts
- **Decision logic** – filter, block, allow, override
- **Authoritative data** – zones, local records, override upstream

To build a Pi-hole-like setup, we start with two core plugins:

- `FileDownloader`
- `Filter`

---

## 3. Downloading Blocklists with FileDownloader

Pi-hole-style blocking relies on regularly updated domain lists. In Foghorn,
this is handled by the `FileDownloader` plugin.

Example configuration:

```yaml
plugins:
  - module: file_downloader
	config:
	  setup_priority: 10 # Run early so files are available for other plugins
	  download_path: ./config/var/lists
	  urls:
		- https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
	  interval_days: 1
	  hash_filenames: true
```

### What this does

- Downloads a hosts-style blocklist
- Refreshes it every 24 hours
- Stores it locally for other plugins to consume
- What if I have multiple files named "hosts.txt"?
  See the option `hash_filenames`, which uses the first 12 digits of the sha1 of the url.
  In our example here the url hashes to `b14d900f67a6.....` so the file will be saved as "hosts-b14d900f67a6.txt"

At this point, no domains are blocked yet; the data is only being fetched.

---

## 4. Blocking Domains with the Filter Plugin

The `Filter` plugin evaluates every DNS query and decides whether it should be
allowed, blocked, or forwarded upstream. Decisions are cached.

Example configuration:

```yaml
plugins:
  - module: filter
	config:
	  # N.B. This could all just be "priority: 20"
	  setup_priority: 20 # Load after the files have been downloaded
	  pre_priority: 20   # Run early, before any other lookups happen
	  post_priority: 20  # Run early in post-resolve to deny/modify responses
	  default: allow
	  deny_response: nxdomain
	  blocked_domains_files:
		./config/var/lists/* # Globs supported
		# If using hashed filenames:
		# - ./config/var/lists/hosts-....-.txt
		# If not using hashed filenames:
		# - ./config/var/lists/hosts.txt
```

### What this does

- Uses an **allow-by-default** policy
- Blocks domains found in the downloaded blocklist(s)
- Returns `NXDOMAIN` for blocked queries (similar to Pi-hole)
- Next:
  - If desired add the `targets` option (available on all plugins).
	This lets you choose which client IPs the filter applies to.
  - Add more filter files or rules

DNS decision flow is now:

```
+-------+   +---------+   +----------+
+ Query | → |  Filter | → | Upstream | → answer
+-------+   +---------+   +----------+
				|
				+--→ Blocked → NXDOMAIN
```

---

## 5. [Optional] Allowing Local Names with EtcHosts

To support local DNS overrides (such as `/etc/hosts`), enable the `EtcHosts`
plugin.

Example configuration:

```yaml
plugins:
  - module: etc-hosts
	config: # Default values below
	  file_paths:
		- /etc/hosts
	  ttl: 300
```

### What this does

- Reads one or more hosts files
- Creates authoritative DNS answers
- Adds PTRs for reverse lookups

```
/etc/hosts
	 |
	 v
+-----------+   +----------+
| EtcHosts  | → | Upstream | → answer
+-----------+   +----------+
	 |
	 +→ Local DNS answers
```

---

## 6. Combined Pi-hole-Style Configuration

The following configuration combines downloading blocklists, local hosts, and
filtering behavior.

```yaml
listen:
  udp:
	enabled: true
	host: 0.0.0.0
	port: 53

upstreams:
  - host: 1.1.1.1
	port: 53
	transport: udp

plugins:
  - module: file_downloader
	config:
	  setup_priority: 10
	  download_path: ./config/var/lists
	  urls:
		- https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
	  interval_days: 1
	  hash_filenames: true

  - module: etc-hosts
	config:
	  pre_priority: 10 # Resolve local names first
	  file_paths:
		- /etc/hosts
	  ttl: 300

  - module: filter
	config:
	  setup_priority: 20
	  pre_priority: 20
	  post_priority: 20
	  default: allow
	  deny_response: nxdomain
	  blocked_domains_files:
		- ./config/var/lists/hosts-*
```

---

## 7. DNS Resolution Flow

With all plugins enabled (and with `EtcHosts` configured to run before `Filter`),
DNS resolution works as follows:

```
 +----------+     +-------------+
 | EtcHosts |     | Block Lists |
 +----------+     +-------------+
		  ↓           ↓
Client → EtcHosts → Filter → Forward Upstream → Answer
		 |            |
		 |            +→ Query Blocked → NXDOMAIN+
		 +→ Answer

```

---

## 8. [optional] Adding Zone Records (Authoritative DNS)

For static internal DNS zones, use the `ZoneRecords` plugin.

Example configuration:

```yaml
plugins: # priorites defaults to 100 (out of 255),
  - module: zone
	config:
	  file_paths:
		- ./config/var/zone-records.txt
	  ttl: 300
```

Example `./config/var/zone-records.txt` entries:

```
router.home|A|300|192.168.1.1
nas.home|A|300|192.168.1.10
30.1.168.192.in-addr.arpa|PTR|server.home
override.some.domain|CNAME|60|my.other.domain
```

```
 +----------+     +-------------+  +--------------------+
 | EtcHosts |     | Block Lists |  | Zone Record / File |
 +----------+     +-------------+  +---------------------
		  ↓           ↓               ↓
Client → EtcHosts → Filter → Zone Records → Forward Upstream → Answer
		 |            |
		 |            +→ Query Blocked → NXDOMAIN
		 +→ Answer
```

---

## 9. [optional] Discovering Hosts from Docker

To automatically generate DNS records for Docker containers, use the
`DockerHosts` plugin.

Example configuration:

```yaml
plugins:
  - module: docker-hosts
	config:
	  # Optional: append a suffix so container "web" becomes "web.docker.local".
	  suffix: docker.lan
	  endpoints:
		- url: unix:///var/run/docker.sock
		  reload_interval_second: 30
	  ttl: 300
```

### What this does

- Watches running Docker containers
- Automatically creates DNS records for them

```
container_name.docker.local → container IP
```

If you want to use a different IP (for example, the host IP instead of the container IP), you can use the `use_ipv4` or `use_ipv6` option per endpoint.

---

## 10. Final Architecture Overview

```
 +-------------+   +------------+  +--------------------+
 | Block Lists |   | /etc/hosts |  | Docker instance(s) |
 +-------------+   +------------+  +--------------------+
		  ↓            ↓             ↓
Client → Filter → EtcHosts → DockerHosts → Upstream → Answer
		  |
		  +→ Blocked → NXDOMAIN
```

---

## 11. Summary

You have built a Pi-hole-style DNS server using Foghorn by:

1. Creating a basic DNS forwarder
2. Downloading blocklists
3. Blocking domains with filters
4. Adding local host overrides
5. Defining authoritative zones
6. Discovering dynamic hosts from Docker

Each step adds functionality while keeping the configuration declarative and
schema-validated.

---

## Next Steps

- Enable logging and metrics
- Add DoT or DoH upstreams for encrypted DNS
- Add TCP, DoT, or DoH downstreams
- Create per-client / subnet filtering policies
