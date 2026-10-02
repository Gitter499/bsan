#!/usr/bin/env bash
# Populate bun's tarball cache (build/cache/tarballs/<name>-<sha256(url)[:16]>.tar.gz) using git,
# since github archive tarballs (codeload) are blocked by the proxy here. bun's own fetch-cli then
# extracts, patches and stamps them exactly as it would a downloaded archive.
# usage: prefetch-tarballs.sh /home/user/bun-jsc/build/debug/build.ninja /home/user/bun-jsc/build/cache/tarballs
set -euo pipefail
ninja=$1 cache=$2
mkdir -p "$cache"
awk '/[ :]dep_fetch( |$)/{inedge=1; next} inedge && /^  name = /{n=$3} inedge && /^  repo = /{r=$3} inedge && /^  commit = /{c=$3; print n, r, c; inedge=0}' "$ninja" |
while read -r name repo commit; do
  url="https://github.com/$repo/archive/$commit.tar.gz"
  h=$(printf %s "$url" | sha256sum | cut -c1-16)
  out="$cache/$name-$h.tar.gz"
  [ -s "$out" ] && { echo "have $name"; continue; }
  tmp=$(mktemp -d)
  git -C "$tmp" init -q --bare
  git -C "$tmp" fetch -q --depth=1 "https://github.com/$repo.git" "$commit"
  git -C "$tmp" archive --format=tar --prefix="${repo#*/}-$commit/" FETCH_HEAD | gzip -1 > "$out.tmp"
  mv "$out.tmp" "$out"; rm -rf "$tmp"
  echo "fetched $name $repo@${commit:0:8} ($(du -h "$out" | cut -f1))"
done
