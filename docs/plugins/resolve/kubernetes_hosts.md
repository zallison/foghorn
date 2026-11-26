# KubernetesHosts

Resolve plugin that indexes Kubernetes **Services** and **Pods** into an
in-memory DNS map and answers matching `A` / `AAAA` / `PTR` / `TXT` queries
in `pre_resolve`.

## Auth

One of (or combine token + mTLS):

1. **In-cluster** (`in_cluster: true`) — reads
   `/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt}` and talks to
   `https://kubernetes.default.svc`.
2. **kubeconfig** (`kubeconfig: /path`) — uses `current-context` cluster server
   and user `token` / `tokenFile` and/or `client-certificate` + `client-key`
   (file paths or `*-data` base64 fields).
3. **Explicit** — `api_server` plus either:
   - `token` / `token_file`, and/or
   - `client_cert` + `client_key` (mTLS)

RBAC needs list on `services` and/or `pods` in the configured namespaces
(or cluster-wide).

## TLS options

| Field | Aliases | Meaning |
|-------|---------|---------|
| `tls_verify` | `verify_tls` | Verify server certificate (default true) |
| `ca_cert` | `tls_ca` | CA bundle path used when verifying |
| `client_cert` | `tls_cert` | Client certificate PEM path (mTLS) |
| `client_key` | `tls_key` | Client private key PEM path (mTLS) |
| `tls_server_name` | `tls_name` | SNI / expected hostname (e.g. when `api_server` is an IP) |

Example (IP API server with named cert + client cert auth):

```yaml
config:
  api_server: "https://api.example:6443"
  tls_server_name: kubernetes.default.svc
  tls_ca: /etc/foghorn/k8s-ca.crt
  tls_cert: /etc/foghorn/client.crt
  tls_key: /etc/foghorn/client.key
  tls_verify: true
```

## Names

For each Service/Pod `name` in `namespace`, Foghorn publishes:

- `{name}.{namespace}`
- `{name}.{namespace}.svc` or `{name}.{namespace}.pod`
- `{name}` when exactly one namespace is configured
- optional `suffix` appended (e.g. `cluster.local`)

When metadata label `dns_name` is set (configurable via `dns_name_label`), that
value is also used as a name base with the same variants. Example:
`labels: {dns_name: api}` on pod `web-7d9f8c-xk2m` publishes `api.default…`
in addition to the pod name forms. Values may be comma/whitespace-separated.

Headless Services (`clusterIP: None`) are skipped. Non-Running pods are skipped.

## Config highlights

| Field | Meaning |
|-------|---------|
| `endpoints` | Optional multi-cluster list; empty uses top-level connection fields |
| `endpoints[].id` | Optional short label preferred in logs (falls back to `api_server`) |
| `namespaces` | Limit scope; empty lists all namespaces the token can see |
| `include_services` / `include_pods` | Resource kinds |
| `label_selector` / `field_selector` | K8s list filters |
| `dns_name_label` | Label key for explicit DNS names (default `dns_name`) |
| `poll_interval_seconds` | Reload interval; `0` disables background poll |
| `suffix` | DNS suffix |
| `ttl` | Answer TTL |
| `expose_txt_in_additional` | Attach k8s=… TXT on A/AAAA |

See `example_configs/plugin_kubernetes_hosts.yaml`.

## Admin UI

Snapshot: `GET /api/v1/plugins/{name}/k8s_hosts` (also `/kubernetes_hosts` and
generic `/snapshot`). Requires `get_http_snapshot` on the plugin instance.
