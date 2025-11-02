# Use the latest official Python image
FROM python:latest

# Set working directory inside the container
WORKDIR /foghorn

# Copy the current directory contents into the container
COPY . /foghorn

RUN DEBIAN_FRONTEND=noninteractive apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y python3-pip && \
    pip install .

EXPOSE 5353/udp

# Define the default command to run when the container starts
CMD [ "/foghorn/entrypoint.sh" ]
