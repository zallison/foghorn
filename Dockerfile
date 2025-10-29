# Use the latest official Python image
FROM python:latest

# Set working directory inside the container
WORKDIR /foghorn

# Copy the current directory contents into the container
COPY . /foghorn

# Create a virtual environment and install
RUN pip install -e . && \
    pytest

RUN mkdir /config
COPY ./config/config.yaml /config/

# Ensure the virtual environment is used by default
ENV PATH="/foghorn/venv/bin:$PATH"

EXPOSE 5353/udp

# Define the default command to run when the container starts
CMD ["foghorn", "--config", "/config/config.yaml"]
