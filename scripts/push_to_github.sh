#!/usr/bin/env bash
# Push the local `master` branch and the version tags that hold their code (v1.7, v2.0) to GitHub.
#
#   scripts/push_to_github.sh              checks, shows what would be pushed, asks, pushes
#   scripts/push_to_github.sh --dry-run    everything except the push itself (git push --dry-run)
#   scripts/push_to_github.sh --skip-checks --no-tags --yes
#
# It never logs in: it never runs `gh auth`, never asks for a user name, password or token, and never
# stores one. It uses only what git on this machine already has (an SSH key loaded in ssh-agent, or a
# credential helper). If git would have to ask for credentials, the push fails with a message instead
# of prompting. It never force-pushes, never pushes another branch (`attack-lab`, the branch `v2.0`),
# and never pushes any tag but v1.7 and v2.0, the tags that hold their versions (docs/progress.md).
set -euo pipefail

REMOTE="${REMOTE:-origin}"
BRANCH="master"
TAGS=(v1.7 v2.0)
DRY_RUN=0
SKIP_CHECKS=0
PUSH_TAGS=1
ASSUME_YES=0

usage() {
	sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY_RUN=1 ;;
	--skip-checks) SKIP_CHECKS=1 ;;
	--no-tags) PUSH_TAGS=0 ;;
	--yes | -y) ASSUME_YES=1 ;;
	-h | --help) usage 0 ;;
	*)
		echo "unknown option: $arg" >&2
		usage 2
		;;
	esac
done

say() { printf '\n== %s\n' "$*"; }
fail() {
	printf '\nSTOPPED: %s\n' "$*" >&2
	exit 1
}

# Never prompt for credentials: fail instead (no login of any kind).
export GIT_TERMINAL_PROMPT=0
export GCM_INTERACTIVE=never
export GIT_ASKPASS=/bin/true
export SSH_ASKPASS=/bin/true
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes}"

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PY="${PY:-$ROOT/.venv/bin/python}"

say "Repository: $ROOT"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not a git repository"

current="$(git rev-parse --abbrev-ref HEAD)"
[ "$current" = "$BRANCH" ] || fail "you are on '$current'; switch to '$BRANCH' first (git switch $BRANCH)"

if [ -n "$(git status --porcelain)" ]; then
	git status --short
	fail "uncommitted changes: commit or stash them first; only committed work is pushed"
fi

url="$(git remote get-url "$REMOTE" 2>/dev/null)" || fail "no remote named '$REMOTE'"
echo "Remote '$REMOTE': $url"

say "Fetching $REMOTE (read only)"
if ! git fetch --quiet "$REMOTE" "refs/heads/$BRANCH:refs/remotes/$REMOTE/$BRANCH"; then
	fail "could not fetch from $url without credentials (network down, or a private repository)"
fi

remote_ref="refs/remotes/$REMOTE/$BRANCH"
if ! git merge-base --is-ancestor "$remote_ref" "refs/heads/$BRANCH"; then
	fail "$REMOTE/$BRANCH has commits that $BRANCH does not have; pull or rebase first. This script never force-pushes."
fi

ahead="$(git rev-list --count "$remote_ref..refs/heads/$BRANCH")"
say "Commits to push ($ahead)"
if [ "$ahead" -gt 0 ]; then
	git log --oneline "$remote_ref..refs/heads/$BRANCH"
else
	echo "(none: $REMOTE/$BRANCH is up to date)"
fi

tag_refs=()
if [ "$PUSH_TAGS" -eq 1 ]; then
	say "Tags"
	remote_tags="$(git ls-remote --tags "$REMOTE" 2>/dev/null || true)"
	for tag in "${TAGS[@]}"; do
		# refs/tags/... explicitly: a local *branch* is also called v2.0
		git rev-parse -q --verify "refs/tags/$tag" >/dev/null || fail "tag $tag does not exist here"
		local_commit="$(git rev-parse "refs/tags/$tag^{commit}")"
		remote_commit="$(printf '%s\n' "$remote_tags" | awk -v t="refs/tags/$tag^{}" '$2 == t {print $1}')"
		if [ -z "$remote_commit" ]; then
			remote_commit="$(printf '%s\n' "$remote_tags" | awk -v t="refs/tags/$tag" '$2 == t {print $1}')"
		fi
		if [ -z "$remote_commit" ]; then
			echo "  $tag -> ${local_commit:0:7}  (new)"
			tag_refs+=("refs/tags/$tag")
		elif [ "$remote_commit" = "$local_commit" ]; then
			echo "  $tag -> ${local_commit:0:7}  (already on $REMOTE, skipped)"
		else
			fail "tag $tag points at ${remote_commit:0:7} on $REMOTE but ${local_commit:0:7} here; not overwriting"
		fi
	done
fi

if [ "$ahead" -eq 0 ] && [ "${#tag_refs[@]}" -eq 0 ]; then
	say "Nothing to push."
	exit 0
fi

if [ "$SKIP_CHECKS" -eq 0 ]; then
	[ -x "$PY" ] || fail "no Python at $PY (run 'make install', or set PY=..., or use --skip-checks)"
	say "Checks: lint"
	make --no-print-directory lint PY="$PY"
	say "Checks: tests (about a minute)"
	make --no-print-directory test PY="$PY"
	say "Checks: publishability (secrets, personal data, raw content)"
	"$PY" scripts/check_publishable.py
	echo
	echo "Note: the commits carry your git author name and e-mail; pushing publishes them."
fi

if [ "$DRY_RUN" -eq 1 ]; then
	say "Dry run: what git would do"
	git push --dry-run --no-follow-tags "$REMOTE" "refs/heads/$BRANCH:refs/heads/$BRANCH" ${tag_refs[@]+"${tag_refs[@]}"}
	echo
	echo "Dry run only: nothing was pushed."
	exit 0
fi

if [ "$ASSUME_YES" -eq 0 ]; then
	printf '\nPush %s commit(s) and %s tag(s) to %s? [y/N] ' "$ahead" "${#tag_refs[@]}" "$url"
	read -r answer
	case "$answer" in
	y | Y | yes | YES) ;;
	*)
		echo "Not pushed."
		exit 0
		;;
	esac
fi

say "Pushing"
if ! git push --no-follow-tags "$REMOTE" "refs/heads/$BRANCH:refs/heads/$BRANCH" ${tag_refs[@]+"${tag_refs[@]}"}; then
	cat >&2 <<EOF

STOPPED: the push was refused. Nothing was force-pushed and nothing was changed locally.
If the message above says authentication failed or a password would be needed: this script never
logs in. git on this machine needs credentials it can use without asking, for example an SSH key in
ssh-agent with the remote set to git@github.com:parsabe/Refmon.git, or a credential helper you set
up yourself. The repository URL now is: $url
EOF
	exit 1
fi

say "Done"
git status -sb | head -1
