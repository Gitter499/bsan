#!/usr/bin/env bash
# memwatch.sh <secs> <cmd...> — run cmd, print peak RSS (MB) and wall time; kill after <secs>.
lim=$1; shift
"$@" >/tmp/memwatch.out 2>&1 & pid=$!
peak=0; t=0
while kill -0 $pid 2>/dev/null; do
  r=$(awk '/VmRSS/{print int($2/1024)}' /proc/$pid/status 2>/dev/null); [ -n "$r" ] && [ "$r" -gt "$peak" ] && peak=$r
  sleep 0.5; t=$((t+1))
  if [ $t -ge $((lim*2)) ]; then kill $pid; echo "TIMEOUT after ${lim}s"; break; fi
done
wait $pid; rc=$?
echo "rc=$rc peak_rss=${peak}MB wall=$((t/2))s"
