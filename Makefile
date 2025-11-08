# Name of the virtual‑env directory
VENV ?= ./venv
PREFIX ?=  ${USER}
CONFIG_DIR ?= ./config
CONTAINER_NAME ?= foghorn
TAG ?= latest

# Files/folders that should NOT be deleted by `clean`
# (Keep YAML files, so we exclude *.yaml and *.yml from the delete patterns)
IGNORE_EXTS :=  .yaml .yml

# Default goal
.DEFAULT_GOAL := help

# ------------------------------------------------------------
#
# ------------------------------------------------------------
.PHONY: run
run: env build
	mkdir var 2>/dev/null || true
	foghorn --config config.yaml


# ------------------------------------------------------------
# Build the project: create a venv, install the package in editable mode
# ------------------------------------------------------------
.PHONY: env
env:
	@echo "=== Creating virtual environment ==="
	python -m venv $(VENV) && . ${VENV}/bin/activate || . ${VENV}/bin/activate   # ignore error if it already exists

.PHONY: build
build: env
	@echo "=== Installing project in editable mode ==="
	$(VENV)/bin/pip install -e ".[dev]"

# ------------------------------------------------------------
# Run tests
# ------------------------------------------------------------
.PHONY: test tests
tests: test
test:
	@echo "=== Running tests (short) ==="
	python -m venv $(VENV) && . ${VENV}/bin/activate || true   # ignore error if it already exists
	pytest --cov=foghorn tests

# ------------------------------------------------------------
# Clean temporary artefacts
# ------------------------------------------------------------
.PHONY: clean
clean:
	@echo "=== Removing virtual environment and var directory ==="
	rm -rf $(VENV) var build
	@echo "=== Removing temporary files and byte‑code ==="
	# Delete __pycache__ directories
	find . -type d -name "__pycache__" -exec rm -rf {} +;
	# Delete .pyc, .tmp, backup (~) and vim swap files
	find . -type f \
	        \( -name '*.pyc' -o -name '*.tmp' -o -name '*~' -o -name '#*' -o -name '*.swp' \) -delete
        # Keep YAML files – nothing more needed

# ---------------
# Docker
# ---------------
.PHONY: docker
docker: docker-build docker-run docker-logs

.PHONY: docker-build
docker-build: docker-clean
	docker build . -t ${PREFIX}/${CONTAINER_NAME}:${TAG}

.PHONY: docker-clean
docker-clean:
	docker rmi ${PREFIX}/${CONTAINER_NAME}:${TAG} || true

.PHONY: docker-run
docker-run:
	docker rm -f foghorn 2> /dev/null
	docker run --name foghorn -d -p 53:5353/udp -p 53:5353/tcp -v ${CONFIG_DIR}:/foghorn/config -v /etc/hosts:/etc/hosts:ro --restart unless-stopped ${PREFIX}/${CONTAINER_NAME}:${TAG}

.PHONY: docker-logs
docker-logs:
	docker logs -f foghorn

.PHONY: dev-ship
dev-ship: clean docker-build
	docker push ${PREFIX}/${CONTAINER_NAME}:${TAG}

# ------------------------------------------------------------
# Help
# ------------------------------------------------------------
.PHONY: help
help:
	@echo "Makefile targets:"
	@echo "  run            – Execute foghorn --config config.yaml"
	@echo "  env            – Create virtual environment"
	@echo "  build          – Install project in editable mode (with dev dependencies)"
	@echo "  test           – Run pytest with coverage"
	@echo "  clean          – Remove venv/, var/, and temp files"
	@echo "  docker         – Build, run, and follow logs for docker container"
	@echo "  docker-build   – Build docker image"
	@echo "  docker-clean   – Remove docker image"
	@echo "  docker-run     – Run docker container"
	@echo "  docker-logs    – Follow docker container logs"
	@echo "  dev-ship       – Clean, build, and push docker image"
