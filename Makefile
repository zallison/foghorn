## Makefile
###########
# Default goal
.DEFAULT_GOAL := help

# Files/folders that should NOT be deleted by `clean`
# (Keep YAML files, so we exclude *.yaml and *.yml from the delete patterns)
IGNORE_EXTS :=  .yaml .yml .pem .key .cert .srl

## Docker
#########
# prefix (default: username) and tag (default: latest).
PREFIX ?= ${USER}
TAG ?= latest
# Name to use for the container
CONTAINER_NAME ?= foghorn
# Location of container config/data.
CONTAINER_DATA ?= ./.docker
# Only used if your config.yaml uses LISTEN as a variable
LISTEN ?= 0.0.0.0
# Label for docker_hosts.py
FH_PRIORITY ?= 100
# Default ports
ADMINPORT ?= 8053
UDPPORT ?= 53
TCPPORT ?= 53

## SSL
######
# Common Name, aka server name
CNAME ?= $(shell hostname)
# Where to store keys
KEYDIR ?=  ./keys
# CA Locations
CA_KEY ?=  ${KEYDIR}/foghorn_ca.key
CA_CERT ?= ${KEYDIR}/foghorn_ca.crt
CA_PEM ?=  ${KEYDIR}/foghorn_ca.pem
# Server keys for CNAME
SERVER :=  ${KEYDIR}/foghorn_${CNAME}
SERVER_PEM ?= ${SERVER}.pem

## Python
#########
# Build the project: create a venv, install the package in editable mode
# Name of the virtual‑env directory
VENV ?= ./venv

## END VARIABLES
################


## Show Variables:
##################
# Print ALL make variables (debug / introspection only)
.PHONY: vars-print-all-all
vars-print-all-all:
	@$(foreach v,$(sort $(.VARIABLES)),$(info $(v) = $($(v))))

# Print Foghorn-related variables by group
.PHONY: vars-print-all
vars-print-all: vars-make vars-docker vars-ssl vars-python

# Print a variable by name: make var-print-FOO
.PHONY: var-print-%
var-print-%:
	@echo "- $* is a $(flavor $*) var set to [$($*)]"

# Header sections
.PHONY: vars-header-%
vars-header-%:
	$(info == Variables for $*)

# Variables for make
.PHONY: vars-make
vars-make: vars-header-Make var-print-IGNORE_EXTS
	@echo

# Variables for Docker
.PHONY: vars-docker
vars-docker: vars-header-Docker var-print-PREFIX var-print-TAG var-print-CONTAINER_DATA var-print-CONTAINER_NAME var-print-LISTEN var-print-FH_PRIORITY var-print-ADMINPORT var-print-TCPPORT var-print-UDPPORT
	@echo

# Variables for openssl
.PHONY: vars-ssl
vars-ssl: vars-header-SSL var-print-CNAME var-print-KEYDIR var-print-CA_KEY var-print-CA_CERT var-print-CA_PEM var-print-SERVER var-print-SERVER_PEM
	@echo

# Variables for Python
.PHONY: vars-python
vars-python: vars-header-Python var-print-VENV
	@echo


## Local running
################
.PHONY: run
run: $(VENV)/bin/foghorn
	. ${VENV}/bin/activate
	mkdir var 2>/dev/null || true
	LISTEN=${LISTEN} ${VENV}/bin/foghorn --config config/config.yaml

.PHONY: env
env:
	@echo "=== Creating virtual environment ==="
	[ -d ${VENV} ] || python -m venv $(VENV)
	$(VENV)/bin/pip install "."

$(VENV)/bin/foghorn: pyproject.toml
	$(MAKE) env-dev

# Ensure the schema is up to date
# Add newline to end of config to make linting happy.
.PHONY: schema
schema:
	./scripts/generate_foghorn_schema.py -o assets/config-schema.json > /dev/null
	echo >> assets/config-schema.json


.PHONY: env-dev
env-dev: env
	@echo "=== Installing project in editable mode ==="
	$(VENV)/bin/pip install -e ".[dev]"


## DNSSEC
#########

# Sign a zonefile and write out a zonefile, with all DNSSEC records (RRSIG, NSSIG)
.PHONY: dnssec-sign-zone
dnssec-sign-zone: $(VENV)/bin/foghorn
	. ${VENV}/bin/activate
	@if [ -z "$$ZONE" ] || [ -z "$$INPUT" ] || [ -z "$$OUTPUT" ]; then \
	  echo "Usage: make dnssec-sign-zone ZONE=example.com. INPUT=unsigned.zone OUTPUT=signed.zone [KEYS_DIR=./keys ALGO=ECDSAP256SHA256 VALIDITY_DAYS=30]"; \
	  exit 1; \
	fi
	ALGO=$${ALGO:-ECDSAP256SHA256}; \
	VALIDITY_DAYS=$${VALIDITY_DAYS:-30}; \
	KEYS_ARG=""; if [ -n "$$KEYS_DIR" ]; then KEYS_ARG="--keys-dir $$KEYS_DIR"; fi; \
	${VENV}/bin/python scripts/generate_zone_dnssec.py \
	  --zone "$$ZONE" \
	  --input "$$INPUT" \
	  --output "$$OUTPUT" \
	  $$KEYS_ARG \
	  --algorithm "$$ALGO" \
	  --validity-days "$$VALIDITY_DAYS"

# ------------------------------------------------------------
# Run tests
# ------------------------------------------------------------
.PHONY: test tests
tests: test
test: $(VENV)/bin/foghorn env-dev
	@echo "=== Running tests (short) ==="
	. ${VENV}/bin/activate
	${VENV}/bin/pytest --cov=src --cov-report=json --ff tests && \
	    export COVERAGE=$$(jq .totals.percent_covered_display < coverage.json | tr -d '\"') && sed -i -e "s|https://img.shields.io/badge/test_coverage-[0-9]*%25-blue|https://img.shields.io/badge/test_coverage-$${COVERAGE}%25-blue|g" README.md && echo -e "Total Test Coverage: $${COVERAGE}%. For full coverage info run: ${VENV}/bin/pytest --cov=src --cov-report=term-missing"


# ------------------------------------------------------------
# Clean temporary artefacts
# ------------------------------------------------------------
.PHONY: clean
clean:
	@echo "=== Removing virtual environment and var directory ==="
	rm -rf $(VENV) var build docker-build coverage.json schema.json dist 2> /dev/null
	@echo "=== Removing temporary files and byte‑code ==="
# Delete __pycache__ directories
	find . -type d -name "__pycache__" -exec rm -rf {} +;
# Delete .pyc, .tmp, backup (~) and vim swap files
	find . -type f \
	\( -name '*.pyc' -o -name '*.tmp' -o -name '*~' -o -name '#*' -o -name '*.swp' \) -delete


# ###############
# ---------------
# OpenSSL Keys
#  - Generates CA
#  - make ssl-cert
# ---------------
# ###############

.PHONY: cert ca key_dir clean_keys ssl-ca-pem ssl-cert-pem

ssl-key-dir:
	mkdir -p ${KEYDIR}

# Build only the CA key and certificate
ssl-ca: ssl-key-dir $(CA_CERT)

# Build a PEM-encoded CA certificate (for use as a trust anchor)
ssl-ca-pem: ssl-ca $(CA_PEM)

# Build CA + server certificate
ssl-cert: ssl-key-dir ${SERVER}.crt

# Build a combined server .pem (certificate + private key)
ssl-cert-pem: ssl-cert $(SERVER_PEM)

$(CA_CERT): ssl-key-dir $(CA_KEY)
	@mkdir -p "$(dir $(CA_CERT))" || true
	@if [ ! -f "$(CA_CERT)" ]; then \
			echo "== Generating CA $(CA_CERT)"; \
			openssl req -x509 -new -nodes -key "$(CA_KEY)" -days 3650 -out "$(CA_CERT)" -subj "/O=Foghorn/CN=Foghorn CA" -addext "keyUsage = keyCertSign, cRLSign"; \
	else \
		echo "Skipping $(CA_CERT) - already exists"; \
	fi

$(CA_KEY): ssl-key-dir
	@if [ ! -f "$(CA_KEY)" ]; then \
		openssl genrsa -out "$(CA_KEY)" 4096; \
	else \
		echo "Skipping $(CA_KEY) - already exists"; \
	fi

# Generate ${SERVER} key, CSR, and sign with CA
${SERVER}.crt: ${SERVER}.csr | $(CA_CERT)
	@echo "== Generating ${SERVER}.crt"
	openssl x509 -req -in ${SERVER}.csr -CA $(CA_CERT) -CAkey $(CA_KEY) -CAcreateserial -out ${SERVER}.crt -days 365 -sha256

${SERVER}.csr: ${SERVER}.key
	@echo "== Generating ${SERVER}.csr"
	openssl req -new -key ${SERVER}.key -out ${SERVER}.csr -subj "/O=Foghorn/CN=${CNAME}"

${SERVER}.key: ${CA_CERT}
	@echo "== Generating ${SERVER}.key"
	openssl genrsa -out ${SERVER}.key 2048

$(CA_PEM): $(CA_CERT)
	@echo "== Generating $(CA_PEM) from $(CA_CERT)"
	openssl x509 -in "$(CA_CERT)" -out "$(CA_PEM)" -outform PEM

$(SERVER_PEM): ${SERVER}.crt ${SERVER}.key
	@echo "== Generating ${SERVER}.pem (cert + key)"
	cat ${SERVER}.crt ${SERVER}.key > ${SERVER}.pem

# Clean up
ssl-clean-keys:
	rm -f ${KEYDIR}/*.key ${KEYDIR}/*.csr ${KEYDIR}/*.crt ${KEYDIR}/*.srl

# ################
# ----------------
# End openssl keys
# ----------------
# ################


# ---------------
# Github Helpers
# ---------------

.PHONY: github-push
github-push: clean tests
	git add -A
	git diff --quiet --cached && git diff --quiet --exit-code && git status --porcelain --ignore-submodules=all | grep -q . || { \
		echo "ERROR: Repository has uncommitted changes or untracked files. Commit or stash them before pushing."; \
		exit 1; \
	}
	git push origin $(shell git rev-parse --abbrev-ref HEAD)


# GitHub PR creation target
create-pr:
	@echo "Creating GitHub PR for $(shell git rev-parse --abbrev-ref HEAD) branch..."
	@PR_BODY="$(shell echo '## Changes\n\n$(shell git log --oneline $(shell git merge-base HEAD origin/$(shell git rev-parse --abbrev-ref HEAD))..HEAD)')"
	@PR_TITLE="$(shell echo '$(shell git rev-parse --abbrev-ref HEAD): $(shell git log -1 --pretty=%s)')"
	@curl -X POST \
		-H "Authorization: token $(shell echo ${GITHUB_TOKEN} | base64)" \
		-H "Accept: application/vnd.github.v3+json" \
		-d "{\"title\": \"$(PR_TITLE)\", \"body\": \"$(PR_BODY)\", \"head\": \"$(shell git rev-parse --abbrev-ref HEAD)\", \"base\": \"main\"}" \
		https://api.github.com/repos/PREFIX/Container_name/pulls



# ---------------
# Docker Helpers
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
		--label "com.foghorn.priority=${FH_PRIORITY}" \
		-v /etc/hosts:/etc/hosts:ro --restart unless-stopped  ${PREFIX}/${CONTAINER_NAME}:${TAG}

# Port forwarding
.PHONY: docker-run-not-host
docker-run-not-host: docker-build
	docker rm -f foghorn
	docker run -d --privileged --name foghorn \
	    -v ${CONTAINER_DATA}:/foghorn/config/ \
		-p ${UDPPORT}:5333/udp \
		-p ${TCPPORT}:5333/tcp \
		-p ${ADMINPORT}:8053/tcp \
	 	-v /etc/hosts:/etc/hosts:ro \
		--restart unless-stopped \
		${PREFIX}/${CONTAINER_NAME}:${TAG}

.PHONY: docker-logs
docker-logs:
	docker logs -f foghorn

.PHONY: docker-ship
docker-ship: clean docker-build
	docker push ${PREFIX}/${CONTAINER_NAME}:${TAG}

# ---------------
# Packaging
# ---------------

.PHONY: package-build
package-build: env-dev
	python -m build

.PHONY: package-publish
package-publish: package-build
	twine upload dist/* --verbose

.PHONY: package-publish-dev
package-publish-dev: package-build
	twine upload --repository testpypi dist/* --verbose


# ----------------------
# end of code, show help
# ----------------------


# ------------------------------------------------------------
# Help
# ------------------------------------------------------------
.PHONY: help
help:
	@echo "Building, testing, and running:"
	@echo "  clean            - Remove venv/, var/, build/, and temp files"
	@echo "  env              - Create virtual environment in $(VENV)"
	@echo "  env-dev          - Install project in editable mode with dev dependencies into $(VENV)"
	@echo "  run              - Execute foghorn --config config/config.yaml using $(VENV)"
	@echo "  schema           - Regenerate assets/config-schema.json"
	@echo "  test             - Run pytest with coverage and update README coverage badge"
	@echo "  dnssec-sign-zone - Sign a DNS zone file with DNSSEC records (see target for ZONE/INPUT/OUTPUT args)"
	@echo "Variable inspection:"
	@echo "  vars-print-all-all - Print all make variables (debug/introspection)"
	@echo "  vars-print-all     - Print grouped Foghorn-related variables (make/docker/SSL/Python)"
	@echo "  var-print-FOO      - Print a single variable named FOO"
	@echo "Build and run containers:"
	@echo "  docker-build     - Build docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  docker-clean     - Remove docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  docker-logs      - Follow docker container logs"
	@echo "  docker-run       - Run docker container (ports 53/udp, 53/tcp, 8053/tcp)"
	@echo "  docker-run-not-host - Run docker container with explicit port mappings instead of --net=host"
	@echo "  docker           - Docker start to finish: clean → build → run → logs"
	@echo "OpenSSL CA and signed certs:"
	@echo "  ssl-ca           - Generate only the CA key and certificate under ${KEYDIR} (.crt)"
	@echo "  ssl-ca-pem       - Generate a PEM-encoded CA certificate ${CA_PEM} for use as a trust anchor"
	@echo "  ssl-cert         - Generate a CA and server certificate/key pair under ${KEYDIR} for CN=${CNAME} (.crt/.key)"
	@echo "  ssl-cert-pem     - Generate a combined server PEM (${SERVER_PEM}) containing cert + key"
	@echo "  ssl-clean-keys   - Remove generated CA and server key/cert files from ${KEYDIR}"
	@echo "Git / GitHub helpers:"
	@echo "  github-push      - Run clean/tests and push current branch, enforcing a clean git state"
	@echo "  create-pr        - Create a GitHub PR for the current branch using the GitHub API"
	@echo "Package targets:"
	@echo "  docker-ship      - Clean, build, and push docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  package-build    - Build the Python package into dist/"
	@echo "  package-publish  - Publish the package to pypi"
	@echo "  package-publish-dev - Publish the package to testpypi"


# EOF
