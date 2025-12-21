# Makefile reference

This document explains the `Makefile` targets in the Foghorn repository and how to use the key variables.

The `Makefile` lives at the repo root and uses a few configurable variables:

- `VENV` – Path to the Python virtual environment directory (default: `./venv`).
- `PREFIX` – Docker image repository/namespace prefix (default: current `$USER`).
- `CONTAINER_NAME` – Docker image/container base name (default: `foghorn`).
- `TAG` – Docker image tag (default: `latest`).

`make` defaults to the `help` target (`.DEFAULT_GOAL := help`), so running `make` with no arguments prints a summary.

---

## Overview

### Building

The Makefile supports building and running directly, or via docker. The highlights are:

- Build and run locally
```sh
  make run
```
- Build and run using docker
```sh
  make docker-run
```

#### All targets
```
  run            – Execute foghorn --config config.yaml (depends on build)
  env            – Create virtual environment in ./venv
  build          – Install project in editable mode (with dev dependencies) into ./venv
  test           – Run pytest with coverage
  clean          – Remove venv/, var/, build/, and temp files
  docker         – Clean image, build it, run container, then follow logs
  docker-build   – Build docker image zack/foghorn:latest
  docker-clean   – Remove docker image zack/foghorn:latest
  docker-run     – Run docker container (ports 53, 5380/tcp, 8153/tcp )
  docker-logs    – Follow docker container logs
  docker-dev-ship       – Clean, build, and push docker image to docker hub
```

For real deployments use `docker-compose.yaml` file to manage the container, after it's been built.


## Variables

### `VENV`

The `VENV` variable controls where the Python virtual environment is created and used.

- Default: `./venv`
- Used in:
  - `env`
  - `build`
  - indirectly in `run` and `test` when they create a venv before running commands.

You can override it per invocation:

```sh
make VENV=.venv env
```

> Note: Most project tooling and docs assume the default `venv` directory.

### Docker: `PREFIX`, `CONTAINER_NAME`, and `TAG`

These variables control Docker image names and tags:

- `PREFIX` (default: `${USER}`)
  - Acts as the image repository/namespace.
  - For example, if your username is `zack`, the image name becomes `zack/foghorn:latest`.
  - You can set it to a registry or org, e.g. `PREFIX=my-registry.example.com/foghorn`.
- `CONTAINER_NAME` (default: `foghorn`)
  - Base name of the image and the running container.
  - The container is run with `--name foghorn` in `docker-run`.
- `TAG` (default: `latest`)
  - The Docker image tag.

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
- `dev-ship` – pushes `${PREFIX}/${CONTAINER_NAME}:${TAG}`

---

## Targets

### `run`

```make
run: build
    python -m venv $(VENV) && . ${VENV}/bin/activate || true
    mkdir var 2>/dev/null || true
    foghorn --config config.yaml
```

**Purpose:** Build the project (via `build`), ensure a virtual environment directory exists, create a `var/` directory, and run Foghorn using `config.yaml`.

- Depends on `build`, so it will:
  1. Create/refresh the venv.
  2. Install Foghorn in editable mode with dev extras.
- Then it runs:
  - `foghorn --config config.yaml`

Usage:

```sh
make run
```

### `env`

```make
env:
    @echo "=== Creating virtual environment ==="
    python -m venv $(VENV) || true
```

**Purpose:** Create the Python virtual environment in `$(VENV)` if needed .


Usage:

```sh
make env
```

### `build`

```make
build: env
    @echo "=== Installing project in editable mode ==="
    source ${VENV}/bin/activate
    $(VENV)/bin/pip install -e ".[dev]"
```

**Purpose:** Create the venv (via `env`) and install Foghorn into it in editable mode with development dependencies.

- Calls `pip install -e '.[dev]'` inside `$(VENV)`.
- This is the preferred way to set up your development environment before running tests or the CLI.

Usage:

```sh
make build
```

### `test` / `tests`

```make
.PHONY: test tests
tests: test

test: env
    @echo "=== Running tests (short) ==="
    source ${VENV}/bin/activate
    pytest --cov=foghorn tests
```

**Purpose:** Run the test suite with coverage.

- `tests` is an alias that simply calls `test`.
- `test`:
  - Ensures a virtual environment directory exists (similar pattern to `run`).
  - Runs `pytest --cov=foghorn tests`.

Usage:

```sh
make test
# or
make tests
```

### `clean`

```make
clean:
    @echo "=== Removing virtual environment and var directory ==="
    rm -rf $(VENV) var build
    @echo "=== Removing temporary files and byte‑code ==="
    find . -type d -name "__pycache__" -exec rm -rf {} +;
    find . -type f \
        \( -name '*.pyc' -o -name '*.tmp' -o -name '*~' -o -name '#*' -o -name '*.swp' \) -delete
```

**Purpose:** Remove local build artifacts and temporary files.

- Deletes:
  - The virtualenv directory `$(VENV)`
  - `var/`
  - `build/`
- Cleans up Python and editor artifacts:
  - `__pycache__/`
  - `*.pyc`, `*.tmp`, backup (`*~`, `#*`), and swap (`*.swp`) files.

Usage:

```sh
make clean
```

---

## Docker targets

These targets assume you have Docker installed and that you are comfortable running a container that binds to port 53 on the host.

### Image naming with `PREFIX` and `TAG`

All image-related targets refer to the same image:

```text
${PREFIX}/${CONTAINER_NAME}:${TAG}
```

- `PREFIX` defaults to `${USER}` – you can change it per call:
  - `make PREFIX=myorg TAG=0.2.0 docker-build`
- `TAG` defaults to `latest` but can be set to any tag (e.g. a version or branch name).
- `CONTAINER_NAME` defaults to `foghorn`.

This is used consistently in `docker-build`, `docker-clean`, and `docker-dev-ship`.

### `docker`

```make
.PHONY: docker
docker: docker-build docker-run docker-logs
```

**Purpose:** Convenience target to build an image, run a container, and then follow its logs.

- Runs, in order:
  1. `docker-build`
  2. `docker-run`
  3. `docker-logs`

Usage:

```sh
make docker
```

### `docker-build`

```make
docker-build: docker-clean
    docker build . -t ${PREFIX}/${CONTAINER_NAME}:${TAG}
```

**Purpose:** Build the Foghorn Docker image.

- First calls `docker-clean` to remove any existing image with the same name.
- Then builds a new image from the local `Dockerfile` with tag `${PREFIX}/${CONTAINER_NAME}:${TAG}`.

Examples:

```sh
# Default image, e.g. zack/foghorn:latest
make docker-build

# Custom org / tag
make PREFIX=myorg TAG=0.2.0 docker-build
```

### `docker-clean`

```make
docker-clean:
    docker rmi -f ${PREFIX}/${CONTAINER_NAME}:${TAG} || true
```

**Purpose:** Remove the Docker image used for this project.

- Uses `docker rmi -f` to force removal, ignoring errors (e.g. image missing).
- Targets the same image name as `docker-build` and `docker-dev-ship`.

Usage:

```sh
make docker-clean
```

### `docker-run`

```make
docker-run:
    docker rm -f foghorn 2> /dev/null
    docker run --name foghorn -d \
        -p 53:5335/udp \
        -p 53:53/tcp \
        -p 5380:5380/tcp \
        -v /etc/hosts:/etc/hosts:ro \
        --restart unless-stopped \
        ${PREFIX}/${CONTAINER_NAME}:${TAG}
```

**Purpose:** Run the Foghorn container with useful defaults.

- Removes any existing container named `foghorn`.
- Starts a new detached container named `foghorn` from the image `${PREFIX}/${CONTAINER_NAME}:${TAG}`.
- Port mappings:
  - `-p 53:5335/udp` – host UDP port 53 → container UDP 5335 (DNS listener).
  - `-p 53:53/tcp` – host TCP port 53 → container TCP 53 (TCP DNS, if used).
  - `-p 8053:8053/tcp` – host TCP port 8053 → container TCP 8053 (admin/web server).
- Mounts `/etc/hosts` read-only into the container.
- Uses `--restart unless-stopped` so the container is automatically restarted by Docker.

Usage:

```sh
make docker-run
```

> You may need elevated privileges or appropriate capabilities to bind to port 53 on the host.

### `docker-logs`

```make
docker-logs:
    docker logs -f foghorn
```

**Purpose:** Follow the logs of the running `foghorn` container.

Usage:

```sh
make docker-logs
```

### `docker-dev-ship`

```make
dev-ship: clean docker-build
    docker push ${PREFIX}/${CONTAINER_NAME}:${TAG}
```

**Purpose:** Clean your local environment, rebuild the Docker image, and push it to the configured registry/namespace.

- Runs:
  1. `clean` – remove venv, temp files, etc.
  2. `docker-build` (via dependency)
  3. `docker push ${PREFIX}/${CONTAINER_NAME}:${TAG}`

Typical usage:

```sh
# Push zack/foghorn:latest
make dev-ship

# Push myorg/foghorn:0.2.0
make PREFIX=myorg TAG=0.2.0 dev-ship
```

---

## `help`

```make
help:
    @echo "Makefile targets:"
    @echo "  run            – Execute foghorn --config config.yaml (depends on build)"
    @echo "  env            – Create virtual environment in $(VENV)"
    @echo "  build          – Install project in editable mode (with dev dependencies) into $(VENV)"
    @echo "  test           – Run pytest with coverage"
    @echo "  clean          – Remove venv/, var/, build/, and temp files"
    @echo "  docker         – Clean image, build it, run container, then follow logs"
    @echo "  docker-build   – Build docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
    @echo "  docker-clean   – Remove docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
    @echo "  docker-run     – Run docker container (ports 53/udp, 53/tcp, 5380/tcp)"
    @echo "  docker-logs    – Follow docker container logs"
    @echo "  docker-dev-ship       – Clean, build, and push docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
```

**Purpose:** Default entry point (`make` with no arguments). Prints a one-line description of each supported target, including how Docker image names are derived from `PREFIX`, `CONTAINER_NAME`, and `TAG`.

Usage:

```sh
make
# or
make help
```
