#!/usr/bin/env python3
"""
Usage: bench_plan.py <crates.json> <targets.json> --ref-name NAME --sha SHA
                     --main-sha SHA [--main-cache raw.csv] [--max-jobs N]

Print the `bench` job matrix for bench.yml as JSON (`{"include": [...]}`).

The crates are split into at most `--max-jobs` jobs in total, shared evenly
between the targets. Each job benchmarks a group of crates in one
`bench.py` invocation per side, so the cost of setting up a runner and building
BorrowSanitizer is paid once per group rather than once per crate, and the
matrix stays well under GitHub's 256-job limit however many crates there are.

On `main`, every crate is benchmarked with Miri and every configuration, for
the ratio-over-time dashboard.

On any other branch, the page compares the branch against `main` under
BorrowSanitizer's `full` configuration alone, so Miri and every other
configuration are skipped. Each job benchmarks its crates on the branch, then on
`main` for those that `main`'s raw results (published to gh-pages by its own
runs) do not already cover at that crate version. `--main-cache` is that
published CSV, if there is one. Measuring both sides of a crate in the same job
also puts them on the same runner.

Each entry carries:
  target, os
  group          index of the group within its target, for naming artifacts
  branch_crates  space-separated crates to benchmark on the branch
  main_crates    space-separated crates to benchmark on `main`
  branch_ref     the branch commit to build and measure
  main_ref       the `main` commit to build and measure
  miri           whether to run the Miri configurations
  modes          space-separated configurations to limit bench.py to; empty for all
"""

import argparse
import csv
import json
import sys
from pathlib import Path

# The only configuration a branch is compared against `main` under.
COMPARISON_MODES = ["full"]


def cached_pairs(path):
    """Return the (target, crate, version) triples that `path` has results for.

    A crate that failed to build on `main` counts: its failure is the result,
    and measuring it again would only fail again.
    """
    if path is None or not path.is_file():
        return set()
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        # A cache written before `status` existed cannot be compared against:
        # it has no way to say which of its tests failed.
        if "status" not in (reader.fieldnames or []):
            return set()
        return {(r["target"], r["crate_name"], r["version"]) for r in reader}


def split(work, n):
    """Split [(crate, cost)] into at most `n` groups of roughly equal cost.

    Costliest first, each to the cheapest group so far; groups keep the order
    crates.json lists them in. Without timings to go on, a crate measured on
    both sides counts as twice the work of one measured on one.
    """
    n = max(1, min(n, len(work)))
    groups = [[] for _ in range(n)]
    load = [0] * n
    order = {name: i for i, (name, _) in enumerate(work)}
    for name, cost in sorted(work, key=lambda w: -w[1]):
        i = load.index(min(load))
        groups[i].append(name)
        load[i] += cost
    return [sorted(g, key=order.get) for g in groups if g]


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("crates_json", type=Path)
    ap.add_argument("targets_json", type=Path)
    ap.add_argument("--ref-name", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--main-sha", required=True)
    ap.add_argument("--main-cache", type=Path)
    ap.add_argument("--max-jobs", type=int, default=20,
                    help="Most bench jobs to spawn, across every target (default: 20).")
    args = ap.parse_args(argv)

    crates = json.loads(args.crates_json.read_text())
    targets = json.loads(args.targets_json.read_text())
    per_target = max(1, args.max_jobs // len(targets))
    on_main = args.ref_name == "main"
    have = set() if on_main else cached_pairs(args.main_cache)

    include = []
    for t in targets:
        # {crate: (on the branch?, on main?)}
        sides = {}
        for c in crates:
            if on_main:
                sides[c["name"]] = (False, True)
            else:
                sides[c["name"]] = (True, (t["target"], c["name"], c["version"]) not in have)
        work = [(name, int(b) + int(m)) for name, (b, m) in sides.items()]
        for i, group in enumerate(split(work, per_target)):
            include.append({
                "target": t["target"],
                "os": t["os"],
                "group": i,
                "branch_crates": " ".join(c for c in group if sides[c][0]),
                "main_crates": " ".join(c for c in group if sides[c][1]),
                "branch_ref": "" if on_main else args.sha,
                "main_ref": args.sha if on_main else args.main_sha,
                "miri": on_main,
                "modes": "" if on_main else " ".join(COMPARISON_MODES),
            })

    for e in include:
        print(f"{e['target']} #{e['group']}: branch [{e['branch_crates']}] "
              f"main [{e['main_crates']}]", file=sys.stderr)
    print(json.dumps({"include": include}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
