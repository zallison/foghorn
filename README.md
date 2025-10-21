# Foghorn

A lightweight caching DNS server written in Python with a plugin system for access control.

Included plugins:
- Access Control (CIDR allow/deny)
- New Domain Filter (blocks domains registered less than 7 days ago)

## Quick start

1. Create and activate a virtualenv
2. Install the package in editable mode: `pip install -e .`
3. Edit `config.yaml` as needed
4. Run: `foghorn --config config.yaml`

## Configuration
See `config.yaml` for an example. You can enable/disable plugins and configure upstreams.
