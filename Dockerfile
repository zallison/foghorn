# Use the latest official Python image
FROM python:latest

# Set working directory inside the container
WORKDIR /foghorn

# Install python3-pip
RUN DEBIAN_FRONTEND=noninteractive apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y python3-pip && \
    DEBIAN_FRONTEND=noninteractive apt clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container
COPY . /foghorn

# Ensure dependencies
RUN pip install --root-user-action=ignore ".[dev]"

# UDP/TCP
EXPOSE 5333
# DNS-over-TLS
EXPOSE 1801
# API server (with frontpage)
EXPOSE 8053

# Define the default command to run when the container starts
CMD [ "/foghorn/entrypoint.sh" ]
