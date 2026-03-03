# DNS UPDATE Support in ZoneRecords Plugin

## Overview

Foghorn's ZoneRecords plugin includes **experimental scaffolding** for RFC 2136 DNS UPDATE (dynamic DNS).

Update operations and full RFC semantics are still TODO (including prerequisites and atomic update application).

## Configuration

```yaml
plugins:
  - id: zone-with-dynamic-updates
    type: zone_records
    config:
      dns_update:
        enabled: bool
        zones:
          - zone: example.com
            # Authentication (TSIG or PSK)
            tsig:
              keys:
                - name: "keyname"
                  algorithm: "hmac-md5" | "hmac-sha256" | "hmac-sha512"
                  secret: "base64-encoded-secret"
                  # Per-key authorization scopes
                  allow_names:
                    - "specific-host.example.com"
                  allow_names_files:
                    - /path/to/allowed-names.txt
                  block_names:
                    - "protected.example.com"
                  block_names_files:
                    - /path/to/blocked-names.txt
                  allow_update_ips:
                    - "192.0.2.0/24"
                  allow_update_ips_files:
                    - /path/to/allowed-ips.txt
                  block_update_ips:
                    - "10.0.0.0/8"
                  block_update_ips_files:
                    - /path/to/blocked-ips.txt
            psk:
              tokens:
                - token: "hashed-token"
                  # Per-token authorization scopes
                  allow_names:
                    - "specific-host.example.com"
                  allow_names_files:
                    - /path/to/allowed-names.txt
                  block_names:
                    - "protected.example.com"
                  block_names_files:
                    - /path/to/blocked-names.txt
                  allow_update_ips:
                    - "192.0.2.0/24"
                  allow_update_ips_files:
                    - /path/to/allowed-ips.txt
                  block_update_ips:
                    - "10.0.0.0/8"
                  block_update_ips_files:
                    - /path/to/blocked-ips.txt

            # Client restrictions
            allow_clients:
              - "10.0.0.0/8"
            allow_clients_files: /path/to/clients.txt

            # Name restrictions
            allow_names:
              - "*.dyn.example.com"
            block_names:
              - "example.com"

            # Value restrictions (A/AAAA records)
            allow_update_ips:
              - "192.168.1.0/24"
            block_update_ips:
              - "10.0.0.0/8"
```

## Security Enforcement

1. **Client Authorization** (allow_clients): CIDR-based allowlist for UPDATE senders
2. **TSIG** (RFC 2845): HMAC authentication using shared keys (implementation details still evolving)
3. **PSK**: Token authentication restricted to secure listeners (DoT/DoH)
4. **Name Filtering**: Block first, then allow with wildcard support
5. **Value Validation**: Block/allow specific IPs for A/AAAA records

### Per-Key/Token Authorization

Both TSIG keys and PSK tokens can have their own authorization scopes, allowing fine-grained access control:

- **Single Hostname**: Restrict a key/token to update only one specific record (e.g., `home.homelab.net`)
- **Multiple Hostnames**: Allow updates to multiple hosts (e.g., wildcard `*.dyn.example.com`)
- **File-Based Scopes**: Load allowed/blocked names and IPs from external files
- **CDN Scenario**: Block private IPs, allow only public IPs for CDN endpoints
- **Private IP Only**: Restrict updates to RFC1918 addresses only
- **Device-Specific Tokens**: PSK tokens ideal for IoT devices with DoT (single host + private IP)

Authorization checks are performed in this order:
1. Per-key/token block names (highest priority)
2. Per-key/token allow names
3. Zone-level block names (if per-key scopes don't restrict)
4. Zone-level allow names
5. Similar logic for IP values in A/AAAA records

## Message Processing

DNS UPDATE messages are intended to be routed through:
1. Opcode detection (UPDATE = 5)
2. Zone configuration lookup
3. Client authorization check
4. Message parsing and validation
5. Prerequisite checks (TODO)
6. Update operations with atomic rollback (TODO)
7. Response with appropriate RCODEs

## Generating Authentication Secrets

Foghorn provides a Makefile target and script to generate secure TSIG keys and PSK tokens:

```bash
# Generate a TSIG key (default: hmac-sha256)
make gen-tsig-key NAME=dynamic-key.example.com

# Generate a TSIG key with a different algorithm
make gen-tsig-key NAME=cdn-key.example.com ALGO=hmac-sha512

# Generate a PSK token
make gen-psk-token

# Or use the script directly
./scripts/generate_dns_update_keys.py --tsig --name "key.example.com" --config-snippet
./scripts/generate_dns_update_keys.py --psk --config-snippet
```

**TSIG Secrets**: Base64-encoded random secrets, cryptographically secure (secrets.token_bytes). 32 bytes for HMAC-SHA256, 64 bytes for HMAC-SHA512.

**PSK Tokens**: Bcrypt-hashed secrets with salt factor 10, ideal for DoT/DoH clients.

## Notes

- No record persistence (changes are in-memory only)
- GSSAPI not implemented
- Zero-downtime reload for configuration files via watchdog
- TSIG requires careful timestamp skew handling (5 minute fudge default)
- Wildcards and CNAME rules per RFC 2136 section 1.1
