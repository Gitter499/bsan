#!/usr/bin/env bash
# fetch-dep.sh <dest> <owner/repo> <commit> [patch...]
# Git-based replacement for Bun's tarball fetcher (codeload is not reachable here).
set -euo pipefail
dest=$(realpath -m "$1") repo=$2 commit=$3; shift 3
rm -rf "$dest"; mkdir -p "$dest"; cd "$dest"
git init -q . && git remote add origin "https://github.com/$repo.git"
git fetch -q --depth=1 origin "$commit" && git checkout -q FETCH_HEAD
for p in "$@"; do git apply --whitespace=nowarn "$p"; done
rm -rf .git
echo "fetched $repo@${commit:0:8} -> $dest"
