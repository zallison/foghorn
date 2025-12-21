# Use the latest official Python image
FROM python:latest

# Set working directory inside the container
WORKDIR /foghorn

# Install python3-pip
RUN DEBIAN_FRONTEND=noninteractive apt update && \
	DEBIAN_FRONTEND=noninteractive apt install -y python3-pip && \
	DEBIAN_FRONTEND=noninteractive apt clean && \
	rm -rf /var/lib/apt/lists/*

# Pre-install python modules to keep this layer small

RUN pip3 install --root-user-action=ignore PyYAML>=6.0.1 jsonschema>=4.17.3 cachetools dnslib>=0.9.24 \
	dnspython>=2.6.1 fastapi>=0.111.0 httpx psutil ytest pytest-cov requests>=2.31.0 uvicorn>=0.30.0 \
	watchdog whois coverage docker cryptography

# Copy the current directory contents into the container
# `make docker` gives you a cleaner build
COPY . /foghorn

# Ensure dependencies
RUN pip install --root-user-action=ignore "."

## To prevent or tell which cuda device to use for fastapi
# ENV CUDA_VISIBLE_DEVICES=""

## Port expose and suggusted mappings
# Normal Port # Comment
# Expose: Internal Port

# 53 # Standard UDP/TCP
EXPOSE 5335

# 853  # DNS-over-TLS
EXPOSE 1853

# 443  # DNS-over-HTTP
EXPOSE 8153

# 8053 # Admin / API server (with stats, enabled seperately)
EXPOSE 8053

# Define the default command to run when the container starts
CMD [ "/foghorn/entrypoint.sh" ]
