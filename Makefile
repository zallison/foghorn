# Name of the virtual‑env directory
VENV := venv
IMAGE_PREFIX ?=  my
CONFIG_DIR ?= config
CONTAINER_NAME ?= foghorn

# Files/folders that should NOT be deleted by `clean`
# (Keep YAML files, so we exclude *.yaml and *.yml from the delete patterns)
IGNORE_EXTS :=  .yaml .yml

# Default goal
.DEFAULT_GOAL := help

# ------------------------------------------------------------
#
# ------------------------------------------------------------
.PHONY: run
run: env
	mkdir var 2>/dev/null || true
	foghorn --config config/config.yaml


# ------------------------------------------------------------
# Build the project: create a venv, install the package in editable mode
# ------------------------------------------------------------
.PHONY: env
env:
	@echo "=== Creating virtual environment ==="
	python -m venv $(VENV) && . ${VENV}/bin/activate || . ${VENV}/bin/activate   # ignore error if it already exists

.PHONY: build
build:
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
	rm -rf $(VENV) var
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
.PHONY: docker-build
docker-build:
	docker build . -t ${IMAGE_PREFIX}/${CONTAINER_NAME}:latest

.PHONY: docker-run
docker-run:
	docker rm -f foghorn 2> /dev/null
	docker run --name foghorn -d -p 53:5353/udp -v ${CONFIG_DIR}:/foghorn/config -v /etc/hosts:/etc/hosts:ro --restart unless-stopped ${IMAGE_PREFIX}/${CONTAINER_NAME}:latest

.PHHONY: docker-logs
docker-logs:
	docker logs -f foghorn

# ------------------------------------------------------------
# Help
# ------------------------------------------------------------
.PHONY: help
help:
	@echo "Makefile targets:"
	@echo "  run            – Execute foghorn --config config.yaml"
	@echo "  docker-build   – Create docker image)"
	@echo "  test           – Run pytest"
	@echo "  clean          – Remove venv/, var/, amd temp files"

