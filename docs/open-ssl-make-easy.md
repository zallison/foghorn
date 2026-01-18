# OpenSSL keys made easy with make

This project includes a small set of `make` targets that hide most of the OpenSSL complexity behind a simple interface. They create a local Certificate Authority (CA) and issue server certificates signed by that CA.

The **fastest way** to get a working server certificate (and the CA certificate to trust it) is:

```bash
make ssl-server-pem CNAME=server
```

This single command:
- Ensures the key directory exists
- Creates a CA private key and CA certificate (if they do not already exist)
- Generates a server private key and certificate signing request (CSR) for `CNAME=server`
- Signs that CSR with the local CA
- Produces a combined `server.pem` file (certificate + private key) suitable for server use
- Produces a PEM-encoded CA certificate you can install as a trust anchor

If you prefer to understand or run the steps individually, the sections below explain each target in detail.

---

## Key locations and variables

The Makefile defines a few key variables that control where things are written:

- `KEYDIR` (default: `./keys`)
  Directory where all keys, CSRs, certificates, and PEM files are stored.

- `CA_KEY` (default: `${KEYDIR}/foghorn_ca.key`)
  Private key for the local Certificate Authority.

- `CA_CERT` (default: `${KEYDIR}/foghorn_ca.crt`)
  X.509 certificate for the local CA, in standard certificate format.

- `CA_PEM` (default: `${KEYDIR}/foghorn_ca.pem`)
  PEM-encoded version of the CA certificate, suitable for installing as a trust anchor.

- `CNAME` (default: system hostname)
  Common Name for the server certificate. You typically override this on the command line, e.g. `CNAME=server` or `CNAME=myservice.local`.

- `SERVER` (default: `${KEYDIR}/foghorn_${CNAME}`)
  Base filename used for the server key, CSR, certificate, and PEM.

- `SERVER_PEM` (default: `${KEYDIR}/${SERVER}.pem`)
  Combined server file containing both the certificate and private key.

These variables are wired into the targets described below.

---

## ssl-key-dir

**Target:** `ssl-key-dir`

**What it does:**
- Ensures the key directory exists.
- Internally runs `mkdir -p ${KEYDIR}`.

**When to use it:**
- Normally you do **not** call this directly; other targets (like `ssl-ca` and `ssl-cert`) depend on it and will create the directory as needed.

---

## ssl-ca

**Target:** `ssl-ca`

**What it does:**
- Depends on `ssl-key-dir` and `${CA_CERT}`.
- If `${CA_KEY}` does not exist, it runs:
  - `openssl genrsa -out ${CA_KEY} 4096` (generate a 4096-bit RSA CA private key).
- If `${CA_CERT}` does not exist, it runs:
  - `openssl req -x509 -new -nodes -key ${CA_KEY} -days 3650 -out ${CA_CERT} -subj "/O=Foghorn/CN=Foghorn CA" -addext "keyUsage = keyCertSign, cRLSign"`

**Key characteristics:**
- **Idempotent:** If the CA key or certificate already exist, it prints a message and skips regenerating them.
- Produces a 10-year self-signed CA certificate (`-days 3650`).
- Sets basic key usage so it can sign certificates and CRLs.

**Resulting files:**
- `${KEYDIR}/foghorn_ca.key`  (CA private key)
- `${KEYDIR}/foghorn_ca.crt`  (CA certificate)

---

## ssl-ca-pem

**Target:** `ssl-ca-pem`

**What it does:**
- Depends on `ssl-ca` and `${CA_PEM}`.
- After ensuring the CA exists, it converts `${CA_CERT}` to PEM format:
  - `openssl x509 -in ${CA_CERT} -out ${CA_PEM} -outform PEM`

**Why this matters:**
- Many tools and operating systems expect CA certificates in PEM format.
- `${CA_PEM}` is what you typically import into a trust store (e.g. browser, OS, or application trust configuration).

**Resulting files:**
- `${KEYDIR}/foghorn_ca.pem`  (PEM-encoded CA certificate)

---

## ssl-cert

**Target:** `ssl-cert`

**What it does:**
- Depends on `ssl-key-dir` and `${SERVER}.crt`.
- To produce `${SERVER}.crt`, it runs the following chain:
  1. Generate a server private key `${SERVER}.key` if needed.
  2. Generate a certificate signing request `${SERVER}.csr` using that key and `CNAME` as the Common Name.
  3. Sign the CSR with the CA key and certificate to produce `${SERVER}.crt`.

Concretely, the steps are:

1. **Server key:**
   - If `${SERVER}.key` does not exist and the CA is available, generate it:
	 - `openssl genrsa -out ${SERVER}.key 2048`

2. **Certificate Signing Request (CSR):**
   - Create a CSR using the server key:
	 - `openssl req -new -key ${SERVER}.key -out ${SERVER}.csr -subj "/O=Foghorn/CN=${CNAME}"`

3. **Server certificate:**
   - Sign the CSR with the CA certificate and key:
	 - `openssl x509 -req -in ${SERVER}.csr -CA ${CA_CERT} -CAkey ${CA_KEY} -CAcreateserial -out ${SERVER}.crt -days 365 -sha256`

**Key characteristics:**
- Binds the server certificate to the Common Name you pass via `CNAME`.
- Issues a **1-year** certificate (`-days 365`).
- Uses SHA-256 for the signature.

**Resulting files:**
- `${KEYDIR}/foghorn_${CNAME}.key`  (server private key)
- `${KEYDIR}/foghorn_${CNAME}.csr`  (certificate signing request)
- `${KEYDIR}/foghorn_${CNAME}.crt`  (server certificate signed by the local CA)

---

## ssl-cert-pem

**Target:** `ssl-cert-pem`

**What it does:**
- Depends on `ssl-cert` and `${SERVER_PEM}`.
- After `${SERVER}.crt` and `${SERVER}.key` exist, it concatenates them into a single `.pem` file:
  - `cat ${SERVER}.crt ${SERVER}.key > ${SERVER}.pem`

**Why this matters:**
- Many TLS servers (or libraries) accept a single PEM file containing both the certificate and private key.
- `${SERVER}.pem` is the file you typically configure in your service.

**Resulting files:**
- `${KEYDIR}/foghorn_${CNAME}.pem`  (combined server certificate + key)

---

## ssl-server-pem (convenience wrapper)

**Target:** `ssl-server-pem`

**What it is intended to do:**
- This is a convenience target that should run the full chain needed for a working server setup:
  1. Ensure the key directory exists.
  2. Create or reuse the CA key and certificate.
  3. Generate a server key and CSR for the given `CNAME`.
  4. Sign the server certificate with the CA.
  5. Produce both the CA PEM and the server PEM.

**How to use it:**

```bash
make ssl-server-pem CNAME=server
```

This is the **recommended fast path**:
- After it completes, you should have:
  - `${KEYDIR}/foghorn_ca.pem` — import this as a trusted CA in your client or system.
  - `${KEYDIR}/foghorn_server.pem` — use this as the server’s TLS certificate/key bundle.

Change `CNAME=server` to any hostname you want to embed in the certificate, e.g. `CNAME=myservice.local`.

---

## ssl-clean-keys

**Target:** `ssl-clean-keys`

**What it does:**
- Removes all generated keys, CSRs, certificates, and serial files in the key directory:
  - `rm -f ${KEYDIR}/*.key ${KEYDIR}/*.csr ${KEYDIR}/*.crt ${KEYDIR}/*.srl`

**When to use it:**
- When you want to start fresh, e.g. to:
  - Rotate the CA and all issued certificates.
  - Regenerate keys/certificates with a different `CNAME`.

**Warning:**
- This **deletes** the CA key and certificates as well as all server keys/certs. Anything previously issued by this CA will no longer be usable once you regenerate new ones.

---

## Typical workflows

### 1. Quick start (recommended)

```bash
make ssl-server-pem CNAME=server
```

After running this:
- Import `${KEYDIR}/foghorn_ca.pem` into your client or OS trust store.
- Configure your server to use `${KEYDIR}/foghorn_server.pem`.
- Additional runs create more keys signed by same CA.

### 2. Step-by-step manual flow

If you want more control or to run the steps individually:

1. Create the CA and its PEM:

   ```bash
   make ssl-ca-pem
   ```

2. Create a server certificate and PEM for a specific name:

   ```bash
   make ssl-cert-pem CNAME=myservice.local
   ```

3. Use the resulting files:
   - Trust: `${KEYDIR}/foghorn_ca.pem`
   - Server: `${KEYDIR}/foghorn_myservice.local.pem`

If you ever need to reset everything, run:

```bash
make ssl-clean-keys
```

and then repeat the quick-start or manual flow.
