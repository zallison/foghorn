# NB: Use `make docker-build` to get a cleaner build (no .git, etc)

# Use the latest official Python image
FROM python
#:slim

# Set working directory inside the container
WORKDIR /foghorn

# Copy the current directory contents into the container
COPY . /foghorn

# Ensure dependencies for databases and diagram rendering in the webui
RUN DEBIAN_FRONTEND=noninteractive apt update && \
	DEBIAN_FRONTEND=noninteractive apt install -y \
	  # build-essential \
	  # gcc \
	  # libmariadb-dev \
	  # postgresql-server-dev-all \
	  graphviz && \
	DEBIAN_FRONTEND=noninteractive apt clean && \
	rm -rf /var/lib/apt/lists/*

# build-essential, gcc, and libmariadb for maraidb support
# build-essential, gcc, and postgresql-server-dev-all for postgres
# graphviz (dot) for rendering config diagrams.

RUN pip install --root-user-action=ignore --upgrade pip \
	&& pip install --root-user-action=ignore "."

## Suggested expose and mappings
# Listens on ports > 1024 by default.
# 53→53353 # Standard UDP/TCP
EXPOSE 5335/tcp
EXPOSE 5335/udp

# 853→1853  # DNS-over-TLS
EXPOSE 1853

# 443 → 8153  # DNS-over-HTTP
EXPOSE 8153

# 5380 → 5380 # Admin / API server (with stats, enabled seperately)
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
