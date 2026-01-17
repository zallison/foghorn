# Creating SSHFP DNS records with `ssh-keyscan -D`

This document shows how to use the OpenSSH `ssh-keyscan` tool with the `-D` flag to generate SSHFP DNS records for use in DNSSEC-enabled zones.

SSHFP (SSH FingerPrint) DNS records allow SSH clients that support DNSSEC to verify a server's host key via DNS, reducing or eliminating interactive host key prompts and helping prevent man-in-the-middle attacks.

## Prerequisites

- OpenSSH client tools installed (for `ssh-keyscan`)
- Access to query or reach the SSH host(s) you care about
- Access to edit DNS records for your domain (either directly or via a DNS admin)
- Optional but recommended: DNSSEC enabled on the zone so that SSHFP records can be validated securely

## Basic usage of `ssh-keyscan -D`

`ssh-keyscan` connects to one or more SSH servers and prints their public host keys. The `-D` flag outputs those keys as SSHFP resource records suitable for direct inclusion in a DNS zone file.

### Example: single host

```sh
ssh-keyscan -D example.com
```

This will print one or more SSHFP records, depending on which host key algorithms the server presents. Example (output format simplified):

```text
example.com IN SSHFP 1 1 <fingerprint>
example.com IN SSHFP 2 1 <fingerprint>
example.com IN SSHFP 4 2 <fingerprint>
```

Each SSHFP record has the form:

```text
<name> IN SSHFP <algorithm> <fp_type> <fingerprint>
```

Where:

- `<name>`: the hostname (e.g., `example.com`)
- `<algorithm>`: numeric code for the key algorithm (e.g., 1 = RSA, 2 = DSA, 3 = ECDSA, 4 = Ed25519, etc.)
- `<fp_type>`: fingerprint type (1 = SHA-1, 2 = SHA-256)
- `<fingerprint>`: the hex-encoded fingerprint

You normally do not need to interpret these numbers manually; you can copy the lines directly into your DNS zone.

### Example: specific port or multiple hosts

If your SSH server is on a non-standard port:

```sh
ssh-keyscan -D -p 2222 host.example.com
```

Scan multiple hosts at once:

```sh
ssh-keyscan -D host1.example.com host2.example.com host3.example.com
```

Or scan from a file containing hostnames:

```sh
ssh-keyscan -D -f hosts.txt
```

Where `hosts.txt` is a newline-separated list of hostnames.

## Adding SSHFP records to DNS

Once you have the SSHFP lines from `ssh-keyscan -D`, you can add them to your DNS configuration. The exact method depends on how you manage DNS.

### Zone file example (BIND-style)

If you manage DNS via a text zone file, paste the records into the relevant zone section. For example, in the `example.com` zone file:

```text
; SSHFP records for SSH host keys
example.com.   IN SSHFP 4 2 <fingerprint-for-ed25519>
example.com.   IN SSHFP 1 2 <fingerprint-for-rsa>
```

Make sure to:

- Include a trailing dot on the FQDN (`example.com.`) if your DNS software expects fully-qualified names
- Keep TTLs consistent with your zone policy (you can optionally add a TTL field before `IN`)
- Reload or re-sign the zone as required by your DNS server (e.g., `rndc reload`)

### Web UI / DNS provider

If you manage DNS through a provider UI:

1. Create a new record.
2. Select type `SSHFP`.
3. Set the name/host (e.g., `@` for the zone apex or `host` for `host.example.com`).
4. Enter the algorithm, fingerprint type, and fingerprint values exactly as printed by `ssh-keyscan -D`.
5. Save and publish changes.

Most modern DNS providers that support SSHFP will expose separate fields for algorithm, fingerprint type, and fingerprint.

## Verifying SSHFP records from a client

After publishing SSHFP records, you can verify them:

### Check that DNS is serving SSHFP

```sh
dig SSHFP example.com +dnssec
```

Look for `SSHFP` records in the answer section. If DNSSEC is enabled and configured, you should also see signatures (RRSIG) and the `ad` (Authenticated Data) flag set in the response.

### Test SSH client behavior

Modern OpenSSH clients can use SSHFP records when `VerifyHostKeyDNS` is enabled:

1. In your `~/.ssh/config` (or the system-wide `ssh_config`), add:

   ```text
   Host example.com
       VerifyHostKeyDNS yes
   ```

2. Connect to the host:

   ```sh
   ssh example.com
   ```

If everything is configured correctly and DNSSEC validates, SSH will treat the SSHFP records as a trusted source of host key information. You should either see no host key prompt, or a prompt indicating that the key was verified via DNS.

## Regenerating SSHFP records after host key changes

Whenever you rotate or add host keys on your SSH server, you must update the SSHFP DNS records.

A simple workflow:

1. After changing host keys on the server, regenerate SSHFP records:

   ```sh
   ssh-keyscan -D 192.168.1.0/24 > sshfp-subnet-example.com.txt
   ```

2. Review the file for correctness.
3. Update your DNS zone or provider configuration with the new values.
4. If using DNSSEC, re-sign or trigger re-signing of the zone.
5. Optionally, verify with `dig SSHFP example.com +dnssec` and a test SSH connection as described above.

## Security considerations

- **Trust model**: SSHFP provides value only if DNS responses are trustworthy. That typically means DNSSEC must be enabled and validated by the client. Without DNSSEC, SSHFP records can still be useful, but they do not provide strong protection against active attackers.
- **Key rotation**: Remember to update SSHFP records whenever host keys change, or clients that rely on DNS validation may fail to connect or raise warnings.
- **Multiple algorithms**: It is common to publish SSHFP records for multiple host key algorithms (e.g., RSA and Ed25519) matching what your server offers, so that clients can validate whichever key they negotiate.

## Summary

- Use `ssh-keyscan -D <host>` to generate SSHFP DNS records directly from an SSH server.
- Copy the resulting lines into your DNS zone or provider's interface as SSHFP records.
- Enable and rely on DNSSEC where possible so SSH clients can securely validate host keys via DNS.
- Regenerate and update SSHFP records whenever you rotate SSH host keys.
