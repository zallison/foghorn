# Name of the virtual‑env directory
VENV := venv

# Files/folders that should NOT be deleted by `clean`
# (Keep YAML files, so we exclude *.yaml and *.yml from the delete patterns)
IGNORE_EXTS := .yaml .yml

# Default goal
.DEFAULT_GOAL := help

# ------------------------------------------------------------
#
# ------------------------------------------------------------
.PHONY: run
run: test
	python -m venv $(VENV) && . ${VENV}/bin/activate || true   # ignore error if it already exists
	mkdir var 2>/dev/null || true
	./$(VENV)/bin/foghorn --config config.yaml


# ------------------------------------------------------------
# Build the project: create a venv, install the package in editable mode
# ------------------------------------------------------------
.PHONY: build
build:
	@echo "=== Creating virtual environment ==="
	python -m venv $(VENV) && . ${VENV}/bin/activate || true   # ignore error if it already exists
	@echo "=== Installing project in editable mode ==="
	$(VENV)/bin/pip install -e .

# ------------------------------------------------------------
# Run tests
# ------------------------------------------------------------
.PHONY: test tests
tests: test
test: build
	@echo "=== Running tests (short) ==="
	python -m venv $(VENV) && . ${VENV}/bin/activate || true   # ignore error if it already exists
	${VENV}/bin/pytest

# ------------------------------------------------------------
# Clean temporary artefacts
# ------------------------------------------------------------
.PHONY: clean
clean:
	@echo "=== Removing virtual environment and var directory ==="
	rm -rf $(VENV) var
	@echo "=== Removing temporary files and byte‑code ==="
	# Delete __pycache__ directories
	find . -type d -name "__pycache__" -exec rm -rf {} +;
	# Delete .pyc, .tmp, backup (~) and vim swap files
	find . -type f \
		\( -name '*.pyc' -o -name '*.tmp' -o -name '*~' -o -name '#*' -o -name '*.swp' \) -delete
        # Keep YAML files – nothing more needed

# ------------------------------------------------------------
# Help
# ------------------------------------------------------------
.PHONY: help
help:
	@echo "Makefile targets:"
	@echo "  all           – Execute foghorn --config config.yaml"
	@echo "  build         – Create venv and install package (-e .)"
	@echo "  test          – Run pytest"
	@echo "  clean         – Remove venv/, var/, amd temp files"
