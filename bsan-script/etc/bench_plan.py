#!/usr/bin/env python3
"""
Usage: bench_plan.py <crates.json> <targets.json> --ref-name NAME --sha SHA
                     --main-sha SHA [--main-cache raw.csv]

Print the `bench` job matrix for bench.yml as JSON (`{"include": [...]}`).

On `main`, every crate is benchmarked on every target, with Miri, for the
ratio-over-time dashboard.

On any other branch, the page compares the branch against `main` under
BorrowSanitizer's `full` configuration alone, so Miri and every other
configuration are skipped, and every crate is benchmarked twice: once for the
branch, and once for `main` unless `main`'s raw results (published to gh-pages
by its own runs) already cover that target and crate version. `--main-cache` is that published CSV, if
there is one.

Each entry carries:
  label   `branch` or `main`: which side of the comparison it measures
  ref     the commit whose BorrowSanitizer is built and measured
  target, os, crate
  miri    whether to run the Miri configurations
  modes   space-separated configurations to limit bench.py to; empty for all
"""

import argparse
import csv
import json
import sys
from pathlib import Path

# The only configuration a branch is compared against `main` under.
COMPARISON_MODES = ["full"]


def cached_pairs(path):
    """Return the (target, crate, version) triples that `path` has results for."""
    if path is None or not path.is_file():
        return set()
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        # A cache written before `status` existed cannot be compared against:
        # it has no way to say which of its tests failed.
        if "status" not in (reader.fieldnames or []):
            return set()
        return {(r["target"], r["crate_name"], r["version"]) for r in reader
                if r.get("test_name")}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("crates_json", type=Path)
    ap.add_argument("targets_json", type=Path)
    ap.add_argument("--ref-name", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--main-sha", required=True)
    ap.add_argument("--main-cache", type=Path)
    args = ap.parse_args(argv)

    crates = json.loads(args.crates_json.read_text())
    targets = json.loads(args.targets_json.read_text())

    def entry(label, ref, t, crate, miri, modes=()):
        return {"label": label, "ref": ref, "target": t["target"], "os": t["os"],
                "crate": crate["name"], "miri": miri, "modes": " ".join(modes)}

    include = []
    if args.ref_name == "main":
        for t in targets:
            for c in crates:
                include.append(entry("main", args.sha, t, c, True))
    else:
        have = cached_pairs(args.main_cache)
        for t in targets:
            for c in crates:
                include.append(entry("branch", args.sha, t, c, False, COMPARISON_MODES))
                if (t["target"], c["name"], c["version"]) not in have:
                    include.append(entry("main", args.main_sha, t, c, False,
                                         COMPARISON_MODES))

    for e in include:
        print(f"{e['label']:>6}: {e['crate']} ({e['target']}) @ {e['ref'][:8]}",
              file=sys.stderr)
    print(json.dumps({"include": include}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
