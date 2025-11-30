# Name of the virtual‑env directory
VENV ?= ./venv
PREFIX ?= ${USER}
CONTAINER_NAME ?= foghorn
CONTAINER_DATA ?= ./.docker
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
run: build
	. ${VENV}/bin/activate
	mkdir var 2>/dev/null || true
	${VENV}/bin/foghorn --config config/config.yaml


# ------------------------------------------------------------
# Build the project: create a venv, install the package in editable mode
# ------------------------------------------------------------
.PHONY: env
env:
	@echo "=== Creating virtual environment ==="
	[ -d ${VENV} ] || python -m venv $(VENV)

.PHONY: build
build: env
	@echo "=== Installing project witout dev tool (env-dev) ==="
	$(VENV)/bin/pip install -e "."

.PHONY: env-dev
env-dev:
	@echo "=== Installing project in editable mode ==="
	$(VENV)/bin/pip install -e ".[dev]"

# ------------------------------------------------------------
# Run tests
# ------------------------------------------------------------
.PHONY: test tests
tests: test
test: env build
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
docker: clean env docker-build docker-run docker-logs

.PHONY: docker-build
docker-build: build env
	rsync -qr --exclude='*/__pycache__/*' --delete-during ./entrypoint.sh ./*md ./src ./html ./Makefile ./pyproject.toml ./Dockerfile ./docker-compose.yaml ./assets docker-build/
	docker build ./docker-build -t ${PREFIX}/${CONTAINER_NAME}:${TAG}

.PHONY: docker-clean
docker-clean:
	docker rmi -f ${PREFIX}/${CONTAINER_NAME}:${TAG} || true
	rm -rf docker-build || true

.PHONY: docker-run
docker-run: env docker-build
	. ${VENV}/bin/activate
	docker rm -f foghorn
	docker run --name foghorn -v ${CONTAINER_DATA}:/foghorn/config/ -d -p 53:5333/udp -p 53:5333/tcp -p 8053:8053/tcp -p 801:1801/tcp -v /etc/hosts:/etc/hosts:ro --restart unless-stopped  ${PREFIX}/${CONTAINER_NAME}:${TAG}

.PHONY: docker-logs
docker-logs:
	. ${VENV}/bin/activate
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
	@echo "  run	        – Execute foghorn --config config/config.yaml (depends on build)"
	@echo "  env	        – Create virtual environment in $(VENV)"
	@echo "  build          – Install project in editable mode (with dev dependencies) into $(VENV)"
	@echo "  test	        – Run pytest with coverage"
	@echo "  clean	        – Remove venv/, var/, build/, and temp files"
	@echo "  docker	        – Clean image, build it, run container, then follow logs"
	@echo "  docker-build   – Build docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  docker-clean   – Remove docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  docker-run     – Run docker container (ports 53/udp, 53/tcp, 8053/tcp)"
	@echo "  docker-logs    – Follow docker container logs"
	@echo "  dev-ship       – Clean, build, and push docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
