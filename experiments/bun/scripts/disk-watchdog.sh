#!/usr/bin/env bash
# Host-side. Stops cargo/rustc in the `bsan` container if free space on / drops below a threshold.
while true; do
  avail=$(df --output=avail -m / | tail -1)
  if [ "$avail" -lt "${MIN_MB:-400}" ]; then
    pids=$(docker exec bsan ps -eo pid,comm | awk '$2 ~ /^(cargo|rustc|cargo-bsan|run-crates.sh|link-loop.sh|bsan-test.sh)$/ {print $1}' | tr '\n' ' ')
    [ -n "$pids" ] && docker exec bsan kill $pids
    echo "$(date +%T) disk watchdog: ${avail}MB free, stopped: $pids" | tee -a "$(dirname "$0")/../logs/notes.txt"
    sleep 60
  fi
  sleep 15
done
