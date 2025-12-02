#!/usr/bin/env bash
set -euo pipefail

# Delete local and remote branches that are:
#   - merged and older than N days since last commit, or
#   - unmerged and older than 3 * N days since last commit (default N: 14).
#
# Usage:
#   git-prune-branches.sh [--days N] [--dry-run]
#
# Examples:
#   git-prune-branches.sh
#   git-prune-branches.sh --days 30 --dry-run

DAYS=14
DRY_RUN=0

usage() {
	cat <<'EOF'
Usage: git-prune-branches.sh [--days N] [--dry-run]

Delete local and remote branches that are:
  - merged into the default branch and older than N days since last commit, or
  - unmerged (not fully merged) and older than 3 * N days since last commit (default N: 14).

Options:
  --days N   Base days; merged branches use N days, unmerged branches use 3 * N days.
  --dry-run  Show what would be deleted without actually deleting anything.
  -h, --help Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--days)
			if [[ $# -lt 2 ]]; then
				echo 'ERROR: --days requires a numeric argument' >&2
				exit 1
			fi
			DAYS="$2"
			shift 2
			;;
		--dry-run)
			DRY_RUN=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "ERROR: Unknown argument: $1" >&2
			usage
			exit 1
			;;
	esac
done

if ! git rev-parse --git-dir >/dev/null 2>&1; then
	echo 'ERROR: Not inside a git repository' >&2
	exit 1
fi

if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then
	echo 'ERROR: --days must be an integer' >&2
	exit 1
fi

now=$(date +%s)
merged_days=$DAYS
unmerged_days=$(( 3 * DAYS ))
merged_cutoff_ts=$(( now - merged_days * 24 * 60 * 60 ))
unmerged_cutoff_ts=$(( now - unmerged_days * 24 * 60 * 60 ))

# Determine default remote and default branch
default_remote=$(git remote 2>/dev/null | head -n1 || true)
: "${default_remote:=origin}"

# Try to infer the default branch from origin/HEAD (or the chosen remote HEAD)
if default_ref=$(git symbolic-ref --quiet --short "refs/remotes/${default_remote}/HEAD" 2>/dev/null); then
	default_branch="${default_ref#${default_remote}/}"
else
	# Fallback to main if HEAD is not configured
	default_branch='main'
fi

current_branch=$(git rev-parse --abbrev-ref HEAD)

# Protect important long-lived branches from deletion.
# - default branch (usually main)
# - any branch named main
# - any branch starting with dev/ or release/
is_protected_branch() {
	local name="$1"
	[[ "$name" == "$default_branch" ]] && return 0
	[[ "$name" == main ]] && return 0
	[[ "$name" == dev ]] && return 0
	[[ "$name" == testing ]] && return 0
	[[ "$name" == dev/* ]] && return 0
	return 1
}

declare -A local_to_delete=()

# Track which local branches are already merged into the default branch
# so we can later identify branches that are *unmerged*.
declare -A local_merged=()

# Collect local branches that are fully merged into the default branch
while IFS= read -r branch; do
	[[ -z "$branch" ]] && continue
	local_merged["$branch"]=1
done < <(git for-each-ref --format='%(refname:short)' --merged="$default_branch" refs/heads)

# Add local branches that are old enough based on merged/unmerged status
while IFS= read -r branch; do
	[[ -z "$branch" ]] && continue
	[[ "$branch" == "$current_branch" ]] && continue
	if is_protected_branch "$branch"; then
		continue
	fi

	last_commit_ts=$(git log -1 --format=%ct "$branch")
	if [[ -n "${local_merged[$branch]:-}" ]]; then
		# Merged branch: use merged_days cutoff
		if (( last_commit_ts < merged_cutoff_ts )); then
			local_to_delete["$branch"]=1
		fi
	else
		# Unmerged branch: use unmerged_days cutoff
		if (( last_commit_ts < unmerged_cutoff_ts )); then
			local_to_delete["$branch"]=1
		fi
	fi
done < <(git for-each-ref --format='%(refname:short)' refs/heads)

# Collect remote branches for all remotes
declare -A remote_to_delete=()  # key: "<remote> <branch>"

for remote in $(git remote); do
	# Determine this remote's default branch, if configured
	remote_default_ref=$(git symbolic-ref --quiet --short "refs/remotes/${remote}/HEAD" 2>/dev/null || true)
	if [[ -n "$remote_default_ref" ]]; then
		remote_default_branch="${remote_default_ref#${remote}/}"
	else
		remote_default_branch="$default_branch"
	fi

	# Track which remote branches are merged into this remote's default branch
	declare -A remote_merged=()
	merged_remote_branches=$(git for-each-ref --format='%(refname:short)' --merged="${remote}/${remote_default_branch}" "refs/remotes/${remote}" 2>/dev/null || true)

	while IFS= read -r ref; do
		[[ -z "$ref" ]] && continue
		[[ "$ref" == "${remote}/HEAD" ]] && continue
		branch="${ref#${remote}/}"
		remote_merged["$branch"]=1
	done <<< "$merged_remote_branches"

	# Branches that are old enough based on merged/unmerged status on this remote
	while IFS= read -r ref; do
		[[ -z "$ref" ]] && continue
		[[ "$ref" == "${remote}/HEAD" ]] && continue

		branch="${ref#${remote}/}"
		if is_protected_branch "$branch"; then
			continue
		fi

		last_commit_ts=$(git log -1 --format=%ct "$ref")
		if [[ -n "${remote_merged[$branch]:-}" ]]; then
			# Merged remote branch: use merged_days cutoff
			if (( last_commit_ts < merged_cutoff_ts )); then
				remote_to_delete["${remote} ${branch}"]=1
			fi
		else
			# Unmerged remote branch: use unmerged_days cutoff
			if (( last_commit_ts < unmerged_cutoff_ts )); then
				remote_to_delete["${remote} ${branch}"]=1
			fi
		fi
	done < <(git for-each-ref --format='%(refname:short)' "refs/remotes/${remote}")

	# Clear per-remote merged map before next remote
	unset remote_merged

done

printf 'Default remote: %s\n' "$default_remote"
printf 'Default branch: %s\n' "$default_branch"
printf 'Merged branches cutoff:   %s days ago (%s)\n' "$merged_days" "$(date -d "@$merged_cutoff_ts" 2>/dev/null || date -r "$merged_cutoff_ts" 2>/dev/null || echo "timestamp $merged_cutoff_ts")"
printf 'Unmerged branches cutoff: %s days ago (%s)\n' "$unmerged_days" "$(date -d "@$unmerged_cutoff_ts" 2>/dev/null || date -r "$unmerged_cutoff_ts" 2>/dev/null || echo "timestamp $unmerged_cutoff_ts")"
printf '\n'

if (( ${#local_to_delete[@]} == 0 && ${#remote_to_delete[@]} == 0 )); then
	echo 'No branches to delete.'
	exit 0
fi

echo 'Local branches to delete:'
if (( ${#local_to_delete[@]} == 0 )); then
	echo '  (none)'
else
	for branch in "${!local_to_delete[@]}"; do
		echo "  $branch"
	done
fi

echo

echo 'Remote branches to delete:'
if (( ${#remote_to_delete[@]} == 0 )); then
	echo '  (none)'
else
	for key in "${!remote_to_delete[@]}"; do
		read -r remote branch <<< "$key"
		echo "  ${remote}/${branch}"
	done
fi

if (( DRY_RUN )); then
	echo
	echo 'Dry run: no branches deleted.'
	exit 0
fi

# Delete local branches
for branch in "${!local_to_delete[@]}"; do
	echo "Deleting local branch: $branch"
	git branch -D "$branch"
done

# Delete remote branches
for key in "${!remote_to_delete[@]}"; do
	read -r remote branch <<< "$key"
	echo "Deleting remote branch: ${remote}/${branch}"
	git push "$remote" --delete "$branch" || {
		echo "WARNING: Failed to delete remote branch ${remote}/${branch}" >&2
	}
done
