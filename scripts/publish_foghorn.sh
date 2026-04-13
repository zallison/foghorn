#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

TAG=''  # required
PUBLISH_PREFIX='zallison'
CONTAINER_NAME='foghorn'

AMD64_CONTEXT='lemur'
ARMHF_CONTEXT='tacocat'
AMD64_ENV_FILE='./.env1'
ARMHF_ENV_FILE='./.env2'

DRY_RUN=0
SKIP_TESTS=0
SKIP_GIT_CHECKS=0
SKIP_DOCKER=0
PUBLISH_PYPI=0
PYPI_TARGET='pypi'  # pypi | testpypi
ENFORCE_VERSION_MATCH=0
KEEP_DOCKER_BUILD=0

ORIG_DOCKER_CONTEXT=''
REPO_ROOT=''

usage() {
	cat <<'USAGE'
Usage:
  ./publish.sh <tag> [options]

Options:
  --prefix <name>           Image prefix/namespace (default: zallison)
  --container-name <name>   Image name (default: foghorn)

  --amd64-context <name>    Docker context to use for amd64 builds (default: lemur)
  --armhf-context <name>    Docker context to use for armhf builds (default: tacocat)
  --amd64-env <path>        Env file to source before amd64 build/push (default: ./.env1)
  --armhf-env <path>        Env file to source before armhf build/push (default: ./.env2)

  --pypi                    Publish Python package to PyPI
  --testpypi                Publish Python package to TestPyPI
  --enforce-version-match   Fail if tag (stripping leading 'v') doesn't match pyproject.toml version

  --skip-tests              Skip pytest
  --skip-git-checks         Skip git cleanliness checks
  --skip-docker             Skip docker build/push
  --dry-run                 Print commands without executing
  --keep-docker-build        Do not delete docker-build/ on exit
  -h, --help                Show this help

Examples:
  ./publish.sh 0.6.5b1
  ./publish.sh v0.6.5b1 --dry-run
  ./publish.sh 0.6.5b1 --pypi
USAGE
}

die() {
	echo "ERROR: $*" >&2
	exit 1
}

info() {
	echo "== $*"
}

run() {
	if [[ ${DRY_RUN} -eq 1 ]]; then
		echo "+ $*"
		return 0
	fi
	"$@"
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

source_env_file() {
	local file="$1"
	if [[ -z "${file}" ]]; then
		return 0
	fi
	if [[ ! -f "${file}" ]]; then
		return 0
	fi

	# Export variables declared in the env file so child processes (e.g. make/docker) inherit them.
	set -a
	# shellcheck disable=SC1090
	source "${file}"
	set +a
}

ensure_git_repo() {
	git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Not inside a git repository"
	REPO_ROOT=$(git rev-parse --show-toplevel)
	cd "${REPO_ROOT}"
}

ensure_clean_git_tree() {
	local status
	status=$(git status --porcelain --untracked-files=all)
	if [[ -n "${status}" ]]; then
		echo "Git tree is NOT clean. Commit/stash these changes first:" >&2
		echo "${status}" >&2
		return 1
	fi
	return 0
}

read_pyproject_version() {
	if ! command -v python >/dev/null 2>&1; then
		echo ''
		return 0
	fi
	if [[ ! -f pyproject.toml ]]; then
		echo ''
		return 0
	fi
	python - <<'PY'
import re
from pathlib import Path
text = Path('pyproject.toml').read_text(encoding='utf-8')
m = re.search(r'^version\s*=\s*"([^"]+)"\s*$', text, flags=re.MULTILINE)
print(m.group(1) if m else '')
PY
}

check_version_match() {
	local normalized_tag version
	normalized_tag="${TAG#v}"
	version=$(read_pyproject_version)
	if [[ -z "${version}" ]]; then
		info "Could not determine version from pyproject.toml; skipping version check"
		return 0
	fi
	if [[ "${normalized_tag}" != "${version}" ]]; then
		if [[ ${ENFORCE_VERSION_MATCH} -eq 1 ]]; then
			die "Tag '${TAG}' does not match pyproject.toml version '${version}'"
		fi
		echo "WARNING: Tag '${TAG}' does not match pyproject.toml version '${version}'" >&2
	fi
}

ensure_docker_context_exists() {
	local ctx="$1"
	docker context inspect "${ctx}" >/dev/null 2>&1 || die "Docker context not found: ${ctx}"
}

cleanup() {
	if [[ -n "${ORIG_DOCKER_CONTEXT}" ]]; then
		run docker context use "${ORIG_DOCKER_CONTEXT}" >/dev/null
	fi
	if [[ ${KEEP_DOCKER_BUILD} -eq 0 ]] && [[ -d docker-build ]]; then
		run rm -rf docker-build
	fi
}

docker_build_tag_push() {
	local ctx="$1"
	local env_file="$2"
	local build_tag="$3"
	shift 3
	local extra_push_tags=("$@")

	ensure_docker_context_exists "${ctx}"
	source_env_file "${env_file}"

	# Avoid mixing selection mechanisms: DOCKER_HOST overrides docker contexts.
	if [[ -n "${DOCKER_HOST:-}" ]]; then
		echo "WARNING: DOCKER_HOST is set; unsetting it to ensure docker context '${ctx}' is used" >&2
		unset DOCKER_HOST
	fi

	info "Using docker context: ${ctx}"
	run docker context use "${ctx}" >/dev/null

	info "Building image ${PUBLISH_PREFIX}/${CONTAINER_NAME}:${build_tag}"
	run make docker-build PREFIX="${PUBLISH_PREFIX}" CONTAINER_NAME="${CONTAINER_NAME}" TAG="${build_tag}"

	for t in "${extra_push_tags[@]}"; do
		info "Tagging ${PUBLISH_PREFIX}/${CONTAINER_NAME}:${build_tag} -> :${t}"
		run docker tag \
			"${PUBLISH_PREFIX}/${CONTAINER_NAME}:${build_tag}" \
			"${PUBLISH_PREFIX}/${CONTAINER_NAME}:${t}"
	done

	info "Pushing ${PUBLISH_PREFIX}/${CONTAINER_NAME}:${build_tag}"
	run docker push "${PUBLISH_PREFIX}/${CONTAINER_NAME}:${build_tag}"

	for t in "${extra_push_tags[@]}"; do
		info "Pushing ${PUBLISH_PREFIX}/${CONTAINER_NAME}:${t}"
		run docker push "${PUBLISH_PREFIX}/${CONTAINER_NAME}:${t}"
	done
}

publish_pypi() {
	require_cmd python
	if [[ ${PYPI_TARGET} == 'testpypi' ]]; then
		info "Publishing Python package to TestPyPI"
		run make package-publish-dev
	else
		info "Publishing Python package to PyPI"
		run make package-publish
	fi
}

run_tests() {
	info "Setting up venv + running pytest"
	run make env-dev
	run ./venv/bin/pytest -q
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--prefix)
				PUBLISH_PREFIX="$2"; shift 2 ;;
			--container-name)
				CONTAINER_NAME="$2"; shift 2 ;;
			--amd64-context)
				AMD64_CONTEXT="$2"; shift 2 ;;
			--armhf-context)
				ARMHF_CONTEXT="$2"; shift 2 ;;
			--amd64-env)
				AMD64_ENV_FILE="$2"; shift 2 ;;
			--armhf-env)
				ARMHF_ENV_FILE="$2"; shift 2 ;;
			--pypi)
				PUBLISH_PYPI=1; PYPI_TARGET='pypi'; shift 1 ;;
			--testpypi)
				PUBLISH_PYPI=1; PYPI_TARGET='testpypi'; shift 1 ;;
			--enforce-version-match)
				ENFORCE_VERSION_MATCH=1; shift 1 ;;
			--skip-tests)
				SKIP_TESTS=1; shift 1 ;;
			--skip-git-checks)
				SKIP_GIT_CHECKS=1; shift 1 ;;
			--skip-docker)
				SKIP_DOCKER=1; shift 1 ;;
			--dry-run)
				DRY_RUN=1; shift 1 ;;
			--keep-docker-build)
				KEEP_DOCKER_BUILD=1; shift 1 ;;
			-h|--help)
				usage; exit 0 ;;
			--)
				shift; break ;;
			-*)
				die "Unknown option: $1" ;;
			*)
				if [[ -z "${TAG}" ]]; then
					TAG="$1"; shift 1
				else
					die "Unexpected argument: $1"
				fi
				;;
		esac
	done

	if [[ -z "${TAG}" ]]; then
		usage
		die "No TAG provided"
	fi
}

main() {
	parse_args "$@"

	require_cmd git
	require_cmd make
	ensure_git_repo

	# Capture + restore docker context, and optionally clean up docker-build/.
	if command -v docker >/dev/null 2>&1; then
		ORIG_DOCKER_CONTEXT=$(docker context show 2>/dev/null || true)
	fi
	trap cleanup EXIT

	if [[ ${SKIP_GIT_CHECKS} -eq 0 ]]; then
		info "Checking git status"
		ensure_clean_git_tree || exit 1
	fi

	check_version_match

	if [[ ${SKIP_TESTS} -eq 0 ]]; then
		run_tests
	fi

	info "Create PR: https://github.com/zallison/foghorn/compare/"
	info "Merge PR: https://github.com/zallison/foghorn/pulls/"
	info "Make GitHub release: https://github.com/zallison/foghorn/releases/new"

	read -p "Press enter to continue: "
	if [[ ${PUBLISH_PYPI} -eq 1 ]]; then
		publish_pypi
	fi

	if [[ ${SKIP_DOCKER} -eq 0 ]]; then
		require_cmd docker

		info "Building/pushing amd64"
		docker_build_tag_push "${AMD64_CONTEXT}" "${AMD64_ENV_FILE}" "${TAG}" latest

		info "Building/pushing armhf"
		docker_build_tag_push "${ARMHF_CONTEXT}" "${ARMHF_ENV_FILE}" "armhf-${TAG}" armhf
	fi
}

main "$@"
