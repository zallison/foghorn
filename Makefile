# Name of the virtual‑env directory
VENV ?= ./venv
PREFIX ?= ${USER}
CONTAINER_NAME ?= foghorn
CONTAINER_DATA ?= ./.docker
TAG ?= latest
LISTEN ?= 0.0.0.0
# Default ports
ADMINPORT ?= 8053
UDPPORT ?= 53
TCPPORT ?= 53
# Files/folders that should NOT be deleted by `clean`
# (Keep YAML files, so we exclude *.yaml and *.yml from the delete patterns)
IGNORE_EXTS :=  .yaml .yml

# Default goal
.DEFAULT_GOAL := help

# ------------------------------------------------------------
#
# ------------------------------------------------------------
.PHONY: run
run: $(VENV)/bin/foghorn
	. ${VENV}/bin/activate
	mkdir var 2>/dev/null || true
	LISTEN=${LISTEN} ${VENV}/bin/foghorn --config config/config.yaml


# ------------------------------------------------------------
# Build the project: create a venv, install the package in editable mode
# ------------------------------------------------------------
.PHONY: env
env:
	@echo "=== Creating virtual environment ==="
	[ -d ${VENV} ] || python -m venv $(VENV)

$(VENV)/bin/foghorn: pyproject.toml
	$(MAKE) env
	$(VENV)/bin/pip install -e "."

.PHONY: build
build: $(VENV)/bin/foghorn ./scripts/generate_foghorn_schema.py
	@echo "=== Building schema === "
# Ensure the schema is up to date, only display errors.
	./scripts/generate_foghorn_schema.py -o assets/config-schema.json > /dev/null
# Add newline to end of config
	echo >> assets/config-schema.json

.PHONY: env-dev
env-dev:
	@echo "=== Installing project in editable mode ==="
	$(VENV)/bin/pip install -e ".[dev]"

# ------------------------------------------------------------
# Run tests
# ------------------------------------------------------------
.PHONY: test tests
tests: test
test: $(VENV)/bin/foghorn
	@echo "=== Running tests (short) ==="
	. ${VENV}/bin/activate
	${VENV}/bin/pytest --cov=foghorn --disable-warnings tests


# ------------------------------------------------------------
# Clean temporary artefacts
# ------------------------------------------------------------
.PHONY: clean
clean:
	@echo "=== Removing virtual environment and var directory ==="
	rm -rf $(VENV) var build docker-build
	@echo "=== Removing temporary files and byte‑code ==="
# Delete __pycache__ directories
	find . -type d -name "__pycache__" -exec rm -rf {} +;
# Delete .pyc, .tmp, backup (~) and vim swap files
	find . -type f \
	\( -name '*.pyc' -o -name '*.tmp' -o -name '*~' -o -name '#*' -o -name '*.swp' \) -delete

# ---------------
# Docker
# ---------------
.PHONY: docker
docker: clean docker-build docker-run docker-logs

.PHONY: docker-build
docker-build:
	rsync -qr --exclude='*/__pycache__/*' --delete-during LICENSE.txt ./entrypoint.sh ./src ./pyproject.toml ./Dockerfile ./docker-compose.yaml ./assets ./docs ./scripts docker-build/
	docker build ./docker-build -t ${PREFIX}/${CONTAINER_NAME}:${TAG}

.PHONY: docker-clean
docker-clean:
	docker rmi -f ${PREFIX}/${CONTAINER_NAME}:${TAG} || true
	rm -rf docker-build || true

.PHONY: docker-run
docker-run: docker-build
	docker rm -f foghorn
	docker run -d --privileged --net=host --name foghorn -v ${CONTAINER_DATA}:/foghorn/config/ \
		 -v /etc/hosts:/etc/hosts:ro --restart unless-stopped  ${PREFIX}/${CONTAINER_NAME}:${TAG}

# Port forwarding
.PHONY: docker-run-not-host
docker-run-not-host: docker-build
	docker rm -f foghorn
	docker run -d --privileged --name foghorn -v ${CONTAINER_DATA}:/foghorn/config/ \
		-p 5353:5353 -p ${UDPPORT}:5333/udp -p ${TCPPORT}:5333/tcp -p ${ADMINPORT}:8053/tcp \
	 	-v /etc/hosts:/etc/hosts:ro --restart unless-stopped ${PREFIX}/${CONTAINER_NAME}:${TAG}

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
	@echo "  run	         – Execute foghorn --config config/config.yaml (depends on build)"
	@echo "  env	         – Create virtual environment in $(VENV)"
	@echo "  build          – Install project in editable mode (with dev dependencies) into $(VENV)"
	@echo "  test	         – Run pytest with coverage"
	@echo "  clean	         – Remove venv/, var/, build/, and temp files"
	@echo "  docker         – Clean image, build it, run container, then follow logs"
	@echo "  docker-build   – Build docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  docker-clean   – Remove docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  docker-run     – Run docker container (ports 53/udp, 53/tcp, 8053/tcp)"
	@echo "  docker-logs    – Follow docker container logs"
	@echo "  dev-ship       – Clean, build, and push docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
