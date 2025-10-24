# Foghorn

Foghorn is a lightweight, caching DNS server built with Python. It's designed to be fast and extensible, featuring a pluggable policy system that allows you to customize its behavior to fit your needs.

## Features

*   **DNS Caching:** Speeds up DNS resolution by caching responses from upstream servers.
*   **Extensible Plugin System:** Easily add custom logic to control DNS resolution.
*   **Flexible Configuration:** Configure the server, upstream resolvers, and plugins using a simple YAML file.
*   **Built-in Plugins:** Comes with a set of useful plugins to get you started:
    *   **Access Control:** Filter DNS queries based on the client's IP address (CIDR-based allow/deny).
    *   **New Domain Filter:** Block domains that were registered recently.
    *   **Upstream Router:** Route queries to different upstream servers based on the domain name.

## Installation

1.  **Create a virtual environment:**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2.  **Install the required dependencies:**

    ```bash
    pip install dnslib pyyaml requests
    ```

## Usage

To run the server, you first need a `config.yaml` file. Then, you can start the server with the following command:

```bash
PYTHONPATH=src python -m foghorn.main --config config.yaml
```

The server will start listening for DNS queries on the configured host and port.

## Configuration

Configuration is handled through a `config.yaml` file. The file has three main sections: `listen`, `upstream`, and `plugins`.

### `listen`

This section defines the host and port the server will listen on.

```yaml
listen:
  host: 127.0.0.1
  port: 5353
```

### `upstream`

This section specifies the upstream DNS server to which queries will be forwarded.

```yaml
upstream:
  host: 1.1.1.1
  port: 53
  timeout_ms: 2000
```

### `plugins`

This section is a list of plugins to load. Each plugin has a `module` and a `config` section. You can also specify a plugin as a short string alias.

You can use short aliases instead of full dotted paths:
- access_control or acl -> foghorn.plugins.access_control.AccessControlPlugin
- new_domain_filter or new_domain -> foghorn.plugins.new_domain_filter.NewDomainFilterPlugin
- upstream_router or router -> foghorn.plugins.upstream_router.UpstreamRouterPlugin

Examples of plugin entries:
- As a dict with module/config: `{ module: acl, config: {...} }`
- As a plain alias string: `acl` (no config)

#### AccessControlPlugin

This plugin provides access control based on the client's IP address.

**Configuration:**

*   `default`: The default action to take if no rule matches (`allow` or `deny`).
*   `allow`: A list of CIDR ranges to allow.
*   `deny`: A list of CIDR ranges to deny. Deny rules take precedence over allow rules.

**Example (full path):**

```yaml
plugins:
  - module: foghorn.plugins.access_control.AccessControlPlugin
    config:
      default: allow
      allow:
        - "192.168.0.0/16"
        - "10.0.0.0/8"
      deny:
        - "203.0.113.0/24"
```

**Example (short alias):**

```yaml
plugins:
  - module: acl
    config:
      default: allow
      allow:
        - "192.168.0.0/16"
```

#### NewDomainFilterPlugin

This plugin blocks domains that were registered recently.

**Configuration:**

*   `threshold_days`: The minimum age of a domain in days. Domains younger than this will be blocked.
*   `rdap_endpoint`: The RDAP endpoint to use for domain age lookups.
*   `timeout_ms`: The timeout in milliseconds for RDAP queries.

**Example (full path):**

```yaml
plugins:
  - module: foghorn.plugins.new_domain_filter.NewDomainFilterPlugin
    config:
      threshold_days: 7
      rdap_endpoint: https://rdap.org/domain/
      timeout_ms: 2000
```

**Example (short alias):**

```yaml
plugins:
  - module: new_domain
    config:
      threshold_days: 14
```

#### UpstreamRouterPlugin

This plugin routes queries to different upstream DNS servers based on the queried domain.

**Configuration:**

*   `routes`: A list of routing rules. Each rule can have a `domain` (for exact matches) or a `suffix` (for suffix matches) and an `upstream` server to route to.

**Example (full path):**

```yaml
plugins:
  - module: foghorn.plugins.upstream_router.UpstreamRouterPlugin
    config:
      routes:
        - domain: "internal.corp.com"
          upstream:
            host: 10.0.0.1
            port: 53
        - suffix: ".dev.example.com"
          upstream:
            host: 192.168.1.1
            port: 53
```

**Example (short alias):**

```yaml
plugins:
  - module: router
    config:
      routes:
        - suffix: "corp"
          upstream:
            host: 10.0.0.53
            port: 53
```

## Complete `config.yaml` Example

Here is a complete `config.yaml` file that uses all the available plugins (with short aliases):

```yaml
listen:
  host: 127.0.0.1
  port: 5353
upstream:
  host: 1.1.1.1
  port: 53
  timeout_ms: 2000
plugins:
  - acl
  - module: new_domain
    config:
      threshold_days: 7
      rdap_endpoint: https://rdap.org/domain/
      timeout_ms: 2000
  - module: router
    config:
      routes:
        - domain: "internal.corp.com"
          upstream:
            host: 10.0.0.1
            port: 53
        - suffix: ".dev.example.com"
          upstream:
            host: 192.168.1.1
            port: 53
```

## Plugin Development

You can extend Foghorn by creating your own plugins. A plugin is a Python class that inherits from `BasePlugin` and implements one or both of the following methods:

*   `pre_resolve(self, qname, qtype, ctx)`: This method is called before a query is resolved. It can return a `PluginDecision` to `allow`, `deny`, or `override` the query.
*   `post_resolve(self, qname, qtype, response_wire, ctx)`: This method is called after a query has been resolved. It can also return a `PluginDecision` to modify the response.
