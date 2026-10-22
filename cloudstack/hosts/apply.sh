#!/usr/bin/env bash
# apply.sh <commit> [ansible-playbook args]: runs site.yaml exactly as it is in
# <commit>, never from the working tree. What the playbook reads (this
# directory and the compute catalog, in their repository layout) is exported
# from the commit into <repository>/.scratch/rollout/<commit id>/tree, and
# Ansible runs there in the background, detached from this terminal: a run
# through martini takes tens of minutes. The log, next to the tree, ends with
# "EXIT <code>".
#
#   cloudstack/hosts/apply.sh <commit> --limit derby [--check]
#
# ansible-playbook is taken from PATH unless ANSIBLE_PLAYBOOK names it.
# APPLY_DRY_RUN=1 exports the tree and prints the command without running it.
set -euo pipefail
# the log and the export are this user's alone
umask 077

die() {
  echo "apply.sh: $*" >&2
  exit 2
}

[ $# -ge 1 ] || die "usage: apply.sh <commit> [ansible-playbook args]"
commit=$1
shift
case $commit in
  -*) die "the first argument is the commit to apply, not an option: $commit" ;;
esac

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
sha=$(git -C "$root" rev-parse --verify --quiet --end-of-options "$commit^{commit}") ||
  die "$commit is not a commit of $root"

# A commit older than the catalog has playbooks that do not read it.
paths=()
for p in cloudstack/hosts argocd/atrium/cloudstack/compute-catalog.json; do
  if git -C "$root" cat-file -e "$sha:$p" 2>/dev/null; then
    paths+=("$p")
  fi
done
[ "${paths[0]:-}" = cloudstack/hosts ] || die "$sha has no cloudstack/hosts"

playbook=${ANSIBLE_PLAYBOOK:-$(command -v ansible-playbook || true)}
[ -n "$playbook" ] && [ -x "$playbook" ] ||
  die "ansible-playbook not found; put it on PATH or set ANSIBLE_PLAYBOOK"

# A tree exported earlier is used only while it still equals the commit.
# Exports are serialised, and a partial one is removed on any exit.
rollout=$root/.scratch/rollout
dest=$rollout/$sha
mkdir -p "$rollout"
exec 9<"$rollout"
flock -E 75 -w 600 9 || {
  rc=$?
  [ "$rc" != 75 ] || die "another apply.sh has held $rollout for 10 minutes"
  die "cannot lock $rollout (flock exit $rc)"
}
fresh=$(mktemp -d "$rollout/.$sha.XXXXXX")
trap '[ -z "$fresh" ] || rm -rf "$fresh"' EXIT
git -C "$root" archive --format=tar "$sha" -- "${paths[@]}" | tar -x -C "$fresh"
if [ -e "$dest/tree" ]; then
  diff -r -q "$fresh" "$dest/tree" >/dev/null ||
    die "$dest/tree differs from $sha; move it away and run again"
  rm -rf "$fresh"
else
  mkdir -p "$dest"
  mv "$fresh" "$dest/tree"
fi
fresh=
exec 9<&-

hosts=$dest/tree/cloudstack/hosts
cmd=("$playbook" -i inventory.yaml site.yaml --diff -f 1
  -e ansible_ssh_retries=3 -e "ansible_ssh_common_args='-J martini'" "$@")

if [ -n "${APPLY_DRY_RUN:-}" ]; then
  echo "exported $sha into $dest/tree"
  printf 'would run in %s:' "$hosts"
  printf ' %q' "${cmd[@]}"
  echo
  exit 0
fi

log=$dest/apply-$(date +%Y%m%d-%H%M%S).log
{
  echo "commit $sha ($commit)"
  printf '%q ' "${cmd[@]}"
  echo
} >"$log"
cd "$hosts"
setsid nohup bash -c '"$@"; echo "EXIT $?"' apply "${cmd[@]}" </dev/null >>"$log" 2>&1 &
echo "applying $sha in the background; log: $log (ends with EXIT <code>)"
