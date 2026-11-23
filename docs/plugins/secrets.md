# Secrets backends

Foghorn can load sensitive material from one or more named secrets backends
instead of (or in addition to) inline config values and ad-hoc file paths.

## What belongs here

| Kind | Contents |
|---|---|
| `tls` | Certificate / key / CA PEMs |
| `tsig` | TSIG key name + base64 secret + algorithm |
| `token` | Opaque API tokens (admin HTTP, plugins) |
| `dnssec` | Zone KSK/ZSK private key PEMs |
| `https` | Reserved for a future backend |
| `gnupg` | Reserved for a future backend |

Public DNSSEC trust anchors stay under `server.dnssec.trust_anchors` (not secrets).

## Config shape

Multi-backend (preferred):

```yaml
secrets:
  backends:
    - id: local-files
      module: file
      config:
        entries:
          - id: admin-api
            kind: token
            value_file: ./keys/admin.token
          - id: admin-tls
            kind: tls
            cert_file: ./keys/admin.crt
            key_file: ./keys/admin.key
    - id: tsig-db
      module: mysql
      config:
        host: db.example
        user: foghorn
        password: ${DB_PASSWORD}
        database: foghorn
        table: secrets
    - id: dnssec-keys
      module: file
      config:
        keys_dir: ./keys/dnssec
```

Single-backend shorthand:

```yaml
secrets:
  module: file
  config:
    entries:
      - id: admin-api
        kind: token
        token: "inline-or-prefer-file"
```

## References

Consumers **must** name both:
- a backend selector: `id` and/or `backend` (secrets backend instance id)
- a lookup key: `key` (secret identifier within that backend)

```yaml
# TLS cert and private key as separate secret keys in the same backend
cert_secret: { id: admin-tls, key: "server1-tls-cert-secret" }
key_secret:  { id: admin-tls, key: "server1-tls-secret" }

# Equivalent with explicit backend field
cert_secret: { backend: admin-tls, key: server1-tls-cert-secret }

server:
  http:
    auth:
      mode: token
      token_secret: { id: local-files, key: admin-api }
```

Bare strings are not accepted for consumer refs.

### TSIG `key_sources`

```yaml
tsig:
  key_sources:
    - type: secrets
      id: tsig-db          # backend instance id
      key: dyn-key-1       # secret lookup key
      # or keys: [k1, k2]
    # still supported:
    - type: file
      path: ./keys/tsig-keys.yaml
```

`type: store` is an alias for `type: secrets`. Shared by DNS UPDATE,
`server.features.tsig`, and `server.axfr.tsig`.

### DNSSEC signing

```yaml
plugins:
  - type: zone_records
    config:
      dnssec_signing:
        secrets:
          backend: dnssec-keys
          # optional explicit ids; default matches kind=dnssec + zone
          # ksk_id: example.com-ksk
          # zsk_id: example.com-zsk
        keys_dir: ./keys/dnssec   # fallback / generate target
        generate: maybe
```

File backends understand the existing `domainkey_<apex>.{ksk,zsk}.key` layout.
`generate: yes|maybe` can persist new keys into writable backends.

## Backends

### `file`

- `entries[]`: catalog of secrets (paths or inline values)
- `keys_dir`: index DNSSEC PEMs from disk
- `root` / `base_dir`: base for relative paths
- Writable `put()` for DNSSEC generate

### `mysql` / `mariadb`

- Standard DB connection knobs (`host`, `port`, `user`, `password`, `database`)
- `table` (default `secrets`)
- `driver` / `driver_fallback` (same as cache MySQL backend)
- Stores TLS/TSIG/token/DNSSEC rows; supports `put()`

## Lifecycle

Secrets backends load early at startup (before plugins/listeners), rebuild on
config reload, and close on process teardown. Per-backend `abort_on_failure`
(default true) controls whether init/probe failures abort startup.
