# NB: Use `make docker-build` to get a cleaner build (no .git, etc)

# Use the latest official Python image
FROM python

# Set working directory inside the container
WORKDIR /foghorn

# Enable all the bells and whistles
RUN DEBIAN_FRONTEND=noninteractive apt update \
	&& DEBIAN_FRONTEND=noninteractive apt install -y graphviz \
	&& DEBIAN_FRONTEND=noninteractive apt clean \
	&& rm -rf /var/lib/apt/lists/* \
	&& pip install --root-user-action=ignore --upgrade pip \
	&& pip install --root-user-action=ignore  cachetools dnslib>=0.9.24 jsonschema>=4.17.3 pydantic pyyaml>=6.0.1 requests>=2.31.0 \
		cryptography dnspython>=2.6.1 fastapi>=0.111.0 psutil python-multipart uvicorn>=0.30.0 paramiko docker>=7.0.0 watchdog zeroconf \
		mariadb mysql-connector-python paho-mqtt psycopg2 pymemcache pymongo redis publicsuffix2

# Copy the current directory contents into the container
COPY . /foghorn

RUN pip install --root-user-action=ignore "."

## Suggested expose and mappings
# Listens on ports > 1024 by default.
# 53→5335 # Default UDP/TCP
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
