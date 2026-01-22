# Makefile reference

This document explains the `Makefile` targets in the Foghorn repository and how to use the key variables.

The `Makefile` lives at the repo root and uses a few configurable variables:

- `VENV` – Path to the Python virtual environment directory (default: `./venv`).
- `PREFIX` – Docker image repository/namespace prefix (default: current `$USER`).
- `CONTAINER_NAME` – Docker image/container base name (default: `foghorn`).
- `TAG` – Docker image tag (default: `latest`).
- `KEYDIR` – Directory where SSL keys and certificates are stored (default: `./keys`).

`make` defaults to the `help` target (`.DEFAULT_GOAL := help`), so running `make` with no arguments prints a summary.

---

## All targets (index)

_Local/dev_
- `env`
- `env-dev`
- `run`
- `schema`

_Testing_
- `test`
- `tests`

_Variable inspection_
- `vars-print-all-all`
- `vars-print-all`
- `var-print-%`
- `vars-header-%`
- `vars-make`
- `vars-docker`
- `vars-ssl`
- `vars-python`

_DNSSEC_
- `dnssec-sign-zone`

_SSL / OpenSSL keys_
- `ssl-key-dir`
- `ssl-ca`
- `ssl-ca-pem`
- `ssl-cert`
- `ssl-cert-pem`
- `ssl-clean-keys`

_Git / GitHub helpers_
- `github-push`
- `create-pr`

_Docker helpers_
- `docker`
- `docker-build`
- `docker-clean`
- `docker-run`
- `docker-run-not-host`
- `docker-logs`
- `docker-ship`

_Packaging_
- `package-build`
- `package-publish`
- `package-publish-dev`

_Misc_
- `help`

---

## Overview

### Local development

The main entry points for local development are:

- Create a virtualenv and install the project (with dev extras):
  ```sh
  make env-dev
  ```
- Run Foghorn locally from the venv:
  ```sh
  make run
  ```
- Run the test suite with coverage:
  ```sh
  make test
  # or
  make tests
  ```

### Docker

To build and run using Docker:

- Build the image:
  ```sh
  make docker-build
  ```
- Run the container and follow logs (host networking):
  ```sh
  make docker
  ```
- Run the container with explicit port mappings instead of `--net=host`:
  ```sh
  make docker-run-not-host
  ```

For production-like deployments, you will typically use `docker-compose.yaml` (or your own orchestration) with the image produced by `docker-build`/`docker-ship`.

---

## Variables

### `VENV`

The `VENV` variable controls where the Python virtual environment is created and used.

- Default: `./venv`
- Used in:
  - `env`
  - `env-dev`
  - `run`
  - `test` / `tests`

You can override it per invocation:

```sh
make VENV=.venv env-dev
```

> Note: Most project tooling and docs assume the default `venv` directory.

### Docker: `PREFIX`, `CONTAINER_NAME`, `TAG`, ports, and data

These variables control Docker image names and runtime behavior:

- `PREFIX` (default: `${USER}`)
  - Acts as the image repository/namespace.
  - For example, if your username is `zack`, the image name becomes `zack/foghorn:latest`.
- `CONTAINER_NAME` (default: `foghorn`)
  - Base name of the image and the running container.
  - The container is run with `--name foghorn` in `docker-run` / `docker-run-not-host`.
- `TAG` (default: `latest`)
  - The Docker image tag.
- `CONTAINER_DATA` (default: `./.docker`)
  - Directory mounted into the container to hold configuration and data.
- `UDPPORT`, `TCPPORT`, `ADMINPORT` (defaults: `53`, `53`, `8053`)
  - Control the host ports used by `docker-run-not-host`.

The full image reference used by Docker targets is:

```text
${PREFIX}/${CONTAINER_NAME}:${TAG}
```

Examples:

- Default:
  - `PREFIX=$USER`, `CONTAINER_NAME=foghorn`, `TAG=latest`
  - Image: `zack/foghorn:latest`
- Custom tag and org:
  - `make TAG=dev PREFIX=myorg docker-build`
  - Image: `myorg/foghorn:dev`

These values are used consistently in:

- `docker-build` – builds the image `${PREFIX}/${CONTAINER_NAME}:${TAG}`
- `docker-clean` – removes the same image
- `docker-ship` – pushes `${PREFIX}/${CONTAINER_NAME}:${TAG}`

### SSL variables

The SSL-related targets use:

- `KEYDIR` (default: `./keys`) – where CA/server keys and certs live.
- `CNAME` – Common Name for the server certificate (defaults to `hostname`).
- `CA_KEY`, `CA_CERT`, `CA_PEM` – paths for the CA key/cert/PEM.
- `SERVER`, `SERVER_PEM` – base path and PEM for the server certificate and key.

You normally do not need to override these; the defaults are suitable for local development.

---

## Targets

Below is a list of all `Makefile` targets, grouped roughly by purpose.

### Local running and environment

- `run`
  - Depends on: `$(VENV)/bin/foghorn`
  - Activates the venv, ensures `var/` exists, then runs:
    ```sh
    foghorn --config config/config.yaml
    ```
- `env`
  - Creates the virtual environment in `$(VENV)` if it does not already exist and installs the package once.
- `env-dev`
  - Depends on: `env`
  - Installs the project in editable mode with dev dependencies (`.[dev]`) into `$(VENV)`.
- `schema`
  - Regenerates `assets/config-schema.json` from the Python schema generator.
  - Implementation detail: runs `./scripts/generate_foghorn_schema.py -o assets/config-schema.json` and then appends a trailing newline.

### DNSSEC

- `dnssec-sign-zone`
  - Depends on: `$(VENV)/bin/foghorn`
  - Signs a zone file and writes a fully DNSSEC-signed output zonefile.
  - Required environment variables:
    - `ZONE` – Zone name (e.g. `example.com.`).
    - `INPUT` – Path to the unsigned zone file.
    - `OUTPUT` – Path to the signed zone file.
  - Optional variables:
    - `KEYS_DIR` – Directory for DNSSEC keys (default: `./keys`).
    - `ALGO` – Signing algorithm (default: `ECDSAP256SHA256`).
    - `VALIDITY_DAYS` – Signature validity period (default: `30`).

Example usage:

```sh
make dnssec-sign-zone \
  ZONE=example.com. \
  INPUT=unsigned.zone \
  OUTPUT=signed.zone \
  KEYS_DIR=./keys \
  ALGO=ECDSAP256SHA256 \
  VALIDITY_DAYS=30
```

### Variable inspection

These targets help you inspect the `Makefile` variables:

- `vars-print-all-all`
  - Prints all make variables (mostly for debugging/introspection).
- `vars-print-all`
  - Prints foghorn-related variables grouped by category (Make, Docker, SSL, Python).
- `var-print-FOO` (pattern: `var-print-%`)
  - Prints flavor and value of a single variable, e.g. `make var-print-VENV`.

There are also internal helper targets used by those commands:

- `vars-header-%` – prints a header for a group of variables.
- `vars-make` – prints Make-related variables.
- `vars-docker` – prints Docker-related variables.
- `vars-ssl` – prints SSL-related variables.
- `vars-python` – prints Python-related variables.

### Testing

- `test`
  - Depends on: `$(VENV)/bin/foghorn`, `env-dev`
  - Activates the venv and runs:
    ```sh
    pytest --cov=src --cov-report=json --ff tests
    ```
  - Updates the coverage badge in `README.md` using the JSON coverage report and prints a short coverage summary.
- `tests`
  - Alias for `test`.

### Cleaning

- `clean`
  - Removes:
    - `$(VENV)`
    - `var/`
    - `build/`
    - `docker-build/`
    - `coverage.json`
    - `schema.json`
    - `dist/`
  - Also removes Python bytecode and common temporary/editor files:
    - `__pycache__/` directories
    - `*.pyc`, `*.tmp`, backup (`*~`, `#*`), and swap (`*.swp`) files.

### SSL / OpenSSL keys

These targets help you create a simple CA and server certificate for local use.

- `ssl-key-dir`
  - Ensures `KEYDIR` exists.
- `ssl-ca`
  - Depends on: `ssl-key-dir`, `$(CA_CERT)`
  - Creates the CA key and certificate if missing.
- `ssl-ca-pem`
  - Depends on: `ssl-ca`, `$(CA_PEM)`
  - Produces a PEM-encoded CA certificate (trust anchor).
- `ssl-cert`
  - Depends on: `ssl-key-dir`, `${SERVER}.crt`
  - Creates a key and certificate for the server (CN=`${CNAME}`).
- `ssl-cert-pem`
  - Depends on: `ssl-cert`, `$(SERVER_PEM)`
  - Produces a combined server PEM containing both certificate and key.
- `ssl-clean-keys`
  - Deletes generated keys, CSRs, certs, and serial files from `KEYDIR`.

### Git / GitHub helpers

- `github-push`
  - Depends on: `clean`, `tests`
  - Ensures the repository is clean (no uncommitted or untracked changes) and then pushes the current branch to `origin`.
- `create-pr`
  - Uses the GitHub API to open a PR for the current branch.
  - Expects a `GITHUB_TOKEN` environment variable (Base64-encoded in this implementation).
  - PR title/body are built from the branch name and recent commits.

> These helpers are opinionated and may need adjustment for your own workflow.

### Docker helpers

- `docker`
  - Depends on: `clean`, `docker-build`, `docker-run`, `docker-logs`
  - Convenience wrapper that cleans, builds the image, runs the container, and then tails logs.
- `docker-build`
  - Syncs a subset of the repo into `docker-build/` (excluding `__pycache__`) and builds the image `${PREFIX}/${CONTAINER_NAME}:${TAG}` from that directory.
- `docker-clean`
  - Removes the image `${PREFIX}/${CONTAINER_NAME}:${TAG}` if it exists and deletes the `docker-build/` directory.
- `docker-run`
  - Depends on: `docker-build`
  - Runs the container with `--net=host`, mounting `${CONTAINER_DATA}` as `/foghorn/config/`, labeling it for discovery, mounting `/etc/hosts`, and using `--restart unless-stopped`.
- `docker-run-not-host`
  - Depends on: `docker-build`
  - Runs the container without `--net=host`, instead mapping:
    - `${UDPPORT}:5333/udp`
    - `${TCPPORT}:5333/tcp`
    - `${ADMINPORT}:8053/tcp`
- `docker-logs`
  - Follows the logs of the `foghorn` container.
- `docker-ship`
  - Depends on: `clean`, `docker-build`
  - Pushes the image `${PREFIX}/${CONTAINER_NAME}:${TAG}` to the configured registry/namespace.

### Packaging

- `package-build`
  - Depends on: `env-dev`
  - Builds the Python package into `dist/` using `python -m build`.
- `package-publish`
  - Depends on: `package-build`
  - Uploads the built distributions to PyPI using `twine upload`.
- `package-publish-dev`
  - Depends on: `package-build`
  - Uploads the built distributions to TestPyPI using `twine upload --repository testpypi`.

---

## `help`

The default `help` target prints a categorized summary of the most important targets and what they do. Running either of the following will show the same output:

```sh
make
# or
make help
```

The `help` text is the authoritative, up-to-date short reference. This document provides the longer description of each target and the variables they use.
