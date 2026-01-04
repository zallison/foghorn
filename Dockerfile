# Use the latest official Python image
FROM python:latest

# Set working directory inside the container
WORKDIR /foghorn

# Install python3-pip
RUN DEBIAN_FRONTEND=noninteractive apt update && \
	DEBIAN_FRONTEND=noninteractive apt install -y python3-pip libmariadb-dev && \
	DEBIAN_FRONTEND=noninteractive apt clean && \
	rm -rf /var/lib/apt/lists/*

# Pre-install python modules to keep this next smaller for updates
RUN pip3 install --root-user-action=ignore PyYAML>=6.0.1 jsonschema>=4.17.3 cachetools dnslib>=0.9.24 \
	dnspython>=2.6.1 fastapi>=0.111.0 httpx psutil pytest requests>=2.31.0 uvicorn>=0.30.0 watchdog \
	whois coverage docker cryptography mysql-connector-python mariadb zeroconf

# Dev packages and build dependencies
RUN pip3 install --root-user-action=ignore black build coverage isort pytest pytest-cov ruff twine setuptools>=68 wheel

# NB: Use `make docker-build` to get a cleaner build (no .git, etc)
# Copy the current directory contents into the container
COPY . /foghorn

# Ensure dependencies
RUN pip install --root-user-action=ignore --no-build-isolation "."

## Port expose and suggusted mappings
# Normal Port # Comment
# Expose: Internal Port

# 53 # Standard UDP/TCP
EXPOSE 5335/tcp
EXPOSE 5335/udp

# 853  # DNS-over-TLS
EXPOSE 1853

# 443  # DNS-over-HTTP
EXPOSE 8153

# 5380 # Admin / API server (with stats, enabled seperately)
EXPOSE 5380

# Configure container health check hitting the FastAPI /health endpoint.
# The check succeeds only when the JSON body contains "status": "ok".
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD [ \
	"python", \
	"-c", \
	"import json, sys, urllib.request as u; data = json.load(u.urlopen('http://127.0.0.1:5380/health')); sys.exit(0 if data.get('status') == 'ok' else 1)" \
]

# Define the default command to run when the container starts
CMD [ "/foghorn/entrypoint.sh" ]
