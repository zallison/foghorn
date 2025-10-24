# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Overview
A minimal DNS caching UDP server with a pluggable policy system. Configuration is provided via YAML. No packaging, tests, or lint configuration are present in-repo.

## Common commands
- Install runtime dependencies (from imports in the code):
  - pip install dnslib pyyaml requests
- Run the server (ensure src is on PYTHONPATH):
  - PYTHONPATH=src python -m foghorn.main --config config.yaml
- Run a single test (if you add pytest):
  - pytest tests/test_server.py::test_cache_hit

Notes:
- Default listen port is 5353. Binding to port 53 typically requires elevated privileges.

## Configuration
Create a YAML file (default path: config.yaml) with these keys:
- listen: host, port
- upstream: host, port, timeout_ms (milliseconds)
- plugins: list of plugin specs with module (full dotted class path) and config

Example:
```yaml
listen:
  host: 127.0.0.1
  port: 5353
upstream:
  host: 1.1.1.1
  port: 53
  timeout_ms: 2000
logging:
  level: info          # debug, info, warn, error, crit (default: info if omitted)
  stderr: true         # log to stderr (default: true)
  file: ./foghorn.log  # optional file output
plugins:
  - module: dns_cache_server.plugins.access_control.AccessControlPlugin
    config:
      default: allow   # or deny
      allow: ["192.168.0.0/16", "10.0.0.0/8"]
      deny: ["203.0.113.0/24"]
  - module: dns_cache_server.plugins.new_domain_filter.NewDomainFilterPlugin
    config:
      threshold_days: 7
      rdap_endpoint: https://rdap.org/domain/
      timeout_ms: 2000
```

Note: Logging defaults to stderr at level info if the logging block is omitted.

## Architecture and flow
- Entry point: foghorn.main
  - Parses --config (YAML), builds plugin instances via importlib, starts DNSServer.
- UDP pipeline: foghorn.server
  - DNSUDPHandler.handle:
    1) Parse query via dnslib.DNSRecord
    2) Pre-resolve plugin phase: each plugin may return a PluginDecision
       - deny: respond NXDOMAIN
       - override: send provided wire response
       - allow/None: continue
    3) Cache lookup by (qname.lower(), qtype)
    4) Forward to upstream (DNSRecord.send) with configured timeout
    5) Post-resolve plugin phase: may deny (SERVFAIL/NXDOMAIN logic in code) or override response
    6) Cache response using minimum TTL from answer RRs
- Caching: foghorn.cache.TTLCache
  - In-memory map from (qname, qtype) -> (expiry_epoch, wire_packet)
  - TTL derived from min rr.ttl in the upstream answer set
- Plugin API: foghorn.plugins.base
  - BasePlugin with hooks: pre_resolve(qname, qtype, ctx) and post_resolve(qname, qtype, response_wire, ctx)
  - PluginDecision(action: "allow"|"deny"|"override", response: Optional[bytes])
  - PluginContext(client_ip)
- Built-in plugins:
  - AccessControlPlugin: CIDR-based allow/deny lists with default policy
  - NewDomainFilterPlugin: queries RDAP for domain registration date; denies domains newer than threshold_days

## Developing plugins
- Implement a subclass of BasePlugin and expose it via an importable dotted path.
- Return PluginDecision from pre_resolve/post_resolve to influence handling.
- Add the plugin to config.yaml under plugins with its module path and config.
