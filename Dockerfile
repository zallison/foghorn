# Use the latest official Python image
FROM python:latest

# Set working directory inside the container
WORKDIR /foghorn

# Install python3-pip
RUN DEBIAN_FRONTEND=noninteractive apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y python3-pip

# So we can cache this layer.
RUN pip install --root-user-action=ignore -U dnslib requests PyYAML whois lxml httpx dnspython watchdog fastapi uvicorn pytest pytest-cov psutil watchdog cachetools

# Copy the current directory contents into the container
COPY . /foghorn

# Ensure dependencies
RUN pip install --root-user-action=ignore .

# UDP/TCP
EXPOSE 5333
# DNS-over-TLS
EXPOSE 1801
# API server (with frontpage)
EXPOSE 8053

# Define the default command to run when the container starts
CMD [ "/foghorn/entrypoint.sh" ]
