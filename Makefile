## Makefile
###########
# Default goal
.DEFAULT_GOAL := help

# Files/folders that should NOT be deleted by `clean`
# (Keep YAML files, so we exclude *.yaml and *.yml from the delete patterns)
IGNORE_EXTS :=  .yaml .yml .pem .key .cert .srl

## :Docker:
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
ADMINPORT ?= 5380
UDPPORT ?= 53
TCPPORT ?= 53

## :SSL:
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

## :Python:
#########
# Build the project: create a venv, install the package in editable mode
# Name of the virtual-env directory
VENV ?= ./venv


## :Variables:Helpers:
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
	@printf "%-15s= %s\n" "$*" "$($*)"

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


## :python: running locally
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
	${MAKE} clean
	$(MAKE) env-dev

# :Schema: Ensure the schema is up to date
# Add newline to end of config to make linting happy.
.PHONY: schema
schema:
	./scripts/generate_foghorn_schema.py -o assets/config-schema.json > /dev/null
	echo >> assets/config-schema.json
.PHONY: ui-bundle
ui-bundle:
	python ./scripts/build_admin_ui_bundle.py

.PHONY: ui-bundle-runtime
ui-bundle-runtime:
	python ./scripts/build_admin_ui_bundle.py --runtime-only


.PHONY: env-dev
env-dev: env
	@echo "=== Installing project in editable mode ==="
	$(VENV)/bin/pip install -e ".[dev]"


## :DNSSEC:
#############

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

## :DNS:Update:
##################

# Generate a TSIG key for DNS UPDATE authentication
.PHONY: gen-tsig-key
gen-tsig-key: $(VENV)/bin/foghorn
	. ${VENV}/bin/activate
	@NAME=$${NAME:-dynamic-key.example.com} ; \
	ALGO=$${ALGO:-hmac-sha256} ; \
	echo "Generating TSIG key: $$NAME ($$ALGO)" ; \
	${VENV}/bin/python scripts/generate_dns_update_keys.py \
	  --tsig \
	  --name "$$NAME" \
	  --algorithm "$$ALGO" \
	  --config-snippet

# Generate a PSK token for DNS UPDATE authentication
.PHONY: gen-psk-token
gen-psk-token: $(VENV)/bin/foghorn
	. ${VENV}/bin/activate
	@echo "Generating PSK token" ; \
	${VENV}/bin/python scripts/generate_dns_update_keys.py \
	  --psk \
	  --config-snippet

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
# Clean temporary artifacts
# ------------------------------------------------------------
.PHONY: clean
clean:
	@echo "=== Removing virtual environment and var directory ==="
	rm -rf $(VENV) var build docker-build coverage.json schema.json dist
	@echo "=== Removing temporary files and byte‑code ==="
	find . -type d -name "__pycache__" -exec rm -rf {} +;
	find . -type f \
	\( -name '*.pyc' -o -name '*.tmp' -o -name '*~' -o -name '#*' -o -name '*.swp' \) -delete


# ###############
# ---------------
# :OpenSSL|Keys:
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


# ----------------
# :End| openssl keys:
# ----------------



# ---------------
# :Docker|Helpers:
# ---------------
.PHONY: docker
docker: docker-build docker-run docker-logs

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
	docker run -d --net=host --name foghorn -v ${CONTAINER_DATA}:/foghorn/config/ \
        --privileged \
		--label "com.foghorn.priority=${FH_PRIORITY}" \
		-v /etc/hosts:/etc/hosts:ro \
        --restart unless-stopped \
        ${PREFIX}/${CONTAINER_NAME}:${TAG}

# Port forwarding
.PHONY: docker-run-not-host
docker-run-not-host: docker-build
	docker rm -f foghorn
	docker run -d --name foghorn \
        --privileged \
	    -v ${CONTAINER_DATA}:/foghorn/config/ \
		-p ${UDPPORT}:5335/udp \
		-p ${TCPPORT}:5335/tcp \
		-p ${ADMINPORT}:5380/tcp \
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
# :pypi|Packaging:
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


# -------
# :Help:
# -------
.PHONY: help
help:
	@echo "Building, testing, and running:"
	@echo "  clean            - Remove venv/, var/, build/, and temp files"
	@echo "  env              - Create virtual environment in $(VENV)"
	@echo "  env-dev          - Install project in editable mode with dev dependencies into $(VENV)"
	@echo "  run              - Execute foghorn --config config/config.yaml using $(VENV)"
	@echo "  test             - Run pytest with coverage and update README coverage badge"
	@echo "  schema           - Regenerate assets/config-schema.json"
	@echo "DNSSEC helper:"
	@echo "  dnssec-sign-zone - Sign a DNS zone file with DNSSEC records (see target for ZONE/INPUT/OUTPUT args)"
	@echo "DNS UPDATE helpers:"
	@echo "  gen-tsig-key     - Generate a TSIG key for DNS UPDATE (optional: NAME=dynamic-key.example.com ALGO=hmac-sha256)"
	@echo "  gen-psk-token    - Generate a PSK token for DNS UPDATE"
	@echo "Build and run containers:"
	@echo "  docker-build     - Build docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  docker-clean     - Remove docker image ${PREFIX}/${CONTAINER_NAME}:${TAG}"
	@echo "  docker-logs      - Follow docker container logs"
	@echo "  docker-run       - Run docker container (ports 53/udp, 53/tcp, 5380/tcp)"
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
	@echo "  ui-bundle        - Build embedded single-file admin UI JS bundle for CDN use"
	@echo "  ui-bundle-runtime - Build runtime-only admin UI JS bundle (no embedded HTML/CSS)"
	@echo "Variable inspection:"
	@echo "  vars-print-all-all - Print all make variables (debug/introspection)"
	@echo "  vars-print-all     - Print grouped Foghorn-related variables (make/docker/SSL/Python)"
	@echo "  var-print-FOO      - Print a single variable named FOO"


# EOF
