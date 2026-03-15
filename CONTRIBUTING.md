# Contributing to Foghorn

This project aims to keep style/tooling consistent so changes are easy to review and CI stays predictable.

## Development environment
- Python: 3.11+ (see `pyproject.toml`).
- Recommended local setup:
  - `make env-dev`
  - `source ./venv/bin/activate`

Some optional backends require system libraries (for example MariaDB/MySQL drivers). On Debian/Ubuntu you may need:
- `sudo apt install libmariadb3 libmariadb-dev`

## Code style (keep it consistent)
Formatting and linting are enforced by:
- `black` (formatting)
- `isort` (import sorting; profile=black)
- `ruff` (linting)
- `pre-commit` (recommended wrapper)

Run locally before opening a PR:
- `./venv/bin/black .`
- `./venv/bin/isort .`
- `./venv/bin/ruff check .`
- `pre-commit run --all-files`

Conventions used throughout the codebase:
- Naming: `snake_case` for functions/vars, `CamelCase` for classes.
- Plugins: avoid a `Plugin` suffix in class names (prefer `UpstreamRouter`, `MdnsBridge`, etc.).
- Terminology: prefer `allowlist` / `blacklist` (avoid `whitelist` / `blocklist`).
- Prefer specific exceptions; log via stdlib `logging`.

## Tests
Run the main test suite:
- `make test`

By default, pytest opts exclude docker-marked tests. To run docker tests explicitly:
- `./venv/bin/pytest -m docker -v`

### Designing tests (include edge/corner cases)
When adding/changing behavior, tests should cover:
- The happy path.
- At least a couple of edge/corner cases relevant to the change (examples):
  - Empty inputs / missing keys / `None`
  - Boundary values (ttl=0, port=1/65535, max-size=0/1)
  - Case-insensitivity and trailing-dot normalization for DNS names
  - Invalid/malformed config that should fail validation
  - Upstream/network failures and timeouts (keep tests deterministic)

Docker/integration tests:
- Must be marked `@pytest.mark.docker`.
- Prefer random high, unused ports for any bound service.

Plugin tests:
- If a test instantiates a plugin and it defines `setup()`, call `plugin.setup()`.

## Pull requests
All PRs must include:
- Tests that validate the proposed change.
- Example configuration updates showing all available options relevant to the changed feature(s).

## Schema generation
`assets/config-schema.json` is generated output.
- Do not edit it directly.
- After config/schema-affecting changes, regenerate with `make schema` (or `./scripts/generate_foghorn_schema.py -o assets/config-schema.json`).

## Adding/changing dependencies
Use `pyproject.toml`:
- Runtime deps: `[project].dependencies`
- Dev deps: `[project.optional-dependencies].dev`
