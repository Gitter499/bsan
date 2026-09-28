#!/usr/bin/env python3
"""
Usage: branch_report.py <output.json> <csv> [csv ...]

Build the dataset behind a per-branch benchmark page from the raw per-test CSVs
`bench.py` writes (target, crate_name, version, test_name, mode, status,
mean_exec_time_seconds).

`main` tracks ratios over time, which needs a baseline and a history. A branch
has neither: what you want there is what the run actually cost and where the
configurations stopped agreeing. So this reports per-crate wall time in seconds,
one series per mode, over a workload every mode completed -- the shape of
`plot_by_crate.py seconds --common-tests --no-calibration`, with no options,
because on a branch there is only ever one thing to ask.

Common tests
    A crate's seconds are the SUM of its tests' mean_s, restricted to tests that
    every mode ran with the SAME status, and where that status is `success`.
    Without the restriction each series covers whatever its mode happened to
    complete, so a mode that lost tests is credited with less work and looks
    faster for it. Statuses come from the CSV, which records a failure per
    (test, mode) rather than aborting the run.

No calibration
    bench.py measures a test binary directly with an `--exact` filter, so there
    is no per-invocation cargo constant to subtract and nothing is clamped --
    every total is a plain sum of means. (`plot_by_crate.py` needs
    `--no-calibration` for this because its datasets carry a `__calibration__`
    row; these do not.)

Everything dropped from the common set is reported in `dropped`, with each
mode's status, so the page can show which tests disagreed rather than only how
many.
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

# Plot order, also the legend order. `native` is first because the crates are
# ordered along the x axis by the first series, and native is the one series
# certain to be present and monotone in crate size.
MODE_ORDER = ["native", "no-op", "full-no-wildcard", "full", "miri-tb"]

# A test counts toward a crate's total only with this status in every mode.
COMPARABLE = "success"


def mode_key(mode):
    return (MODE_ORDER.index(mode) if mode in MODE_ORDER else len(MODE_ORDER), mode)


def read_rows(paths):
    """Load every CSV into {(target, crate, test, mode): row}.

    The last row for a key wins: a crate re-benchmarked into the same file
    should not have both measurements counted.
    """
    required = {"target", "crate_name", "version", "test_name", "mode",
                "status", "mean_exec_time_seconds"}
    rows = {}
    for path in paths:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            missing = required - set(reader.fieldnames or [])
            if missing:
                sys.exit(f"Error: {path} is missing column(s): "
                         f"{', '.join(sorted(missing))}")
            for row in reader:
                if not row.get("test_name"):
                    continue
                crate = f"{row['crate_name']}@{row['version']}"
                rows[(row["target"], crate, row["test_name"], row["mode"])] = row
    if not rows:
        sys.exit("Error: no test rows found in the given CSVs.")
    return rows


def timing(row):
    try:
        v = float(row["mean_exec_time_seconds"])
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


def build_target(rows, modes):
    """Reduce one target's rows to its crate series and dropped tests."""
    # {(crate, test): {mode: row}}
    per_test = {}
    for (crate, test, mode), row in rows.items():
        per_test.setdefault((crate, test), {})[mode] = row

    seconds = {m: {} for m in modes}
    counts = {}
    dropped = []

    for (crate, test), by_mode in sorted(per_test.items()):
        counts.setdefault(crate, {"kept": 0, "total": 0})
        counts[crate]["total"] += 1
        statuses = {m: (by_mode[m]["status"] if m in by_mode else "not run")
                    for m in modes}
        distinct = set(statuses.values())

        if len(distinct) > 1:
            reason = "disagreed"
        elif distinct == {COMPARABLE}:
            reason = None
        elif "not run" in distinct:
            reason = "not run in any mode"
        else:
            reason = f"{distinct.pop()} in every mode"

        if reason is not None:
            dropped.append({"crate": crate, "test": test,
                            "reason": reason, "statuses": statuses})
            continue

        # Every mode succeeded, so every mode has a timing to add.
        means = {m: timing(by_mode[m]) for m in modes}
        if any(v is None for v in means.values()):
            dropped.append({"crate": crate, "test": test,
                            "reason": "success without a timing",
                            "statuses": statuses})
            continue
        for m in modes:
            seconds[m][crate] = seconds[m].get(crate, 0.0) + means[m]
        counts[crate]["kept"] += 1

    # A crate with no comparable test has no point on any series; drop it from
    # all of them so every series covers the same crates.
    keep = {c for c in counts if counts[c]["kept"] > 0}
    for m in modes:
        seconds[m] = {c: v for c, v in seconds[m].items() if c in keep}

    # x ordering: ascending by the first series, like plot_by_crate.
    first = modes[0]
    crates = sorted(keep, key=lambda c: (seconds[first].get(c, float("inf")), c))

    # Most-informative first: a disagreement is a real finding, the rest is
    # usually a test that is simply unsupported everywhere.
    dropped.sort(key=lambda d: (d["reason"] != "disagreed", d["crate"], d["test"]))

    return {
        "crates": crates,
        "seconds": seconds,
        "tests": {c: counts[c] for c in crates},
        "dropped": dropped,
    }


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output", type=Path)
    ap.add_argument("csvs", type=Path, nargs="+")
    ap.add_argument("--branch", default="")
    ap.add_argument("--commit", default="")
    ap.add_argument("--repo-url", default="")
    ap.add_argument("--run-url", default="")
    args = ap.parse_args(argv)

    rows = read_rows(args.csvs)

    targets = sorted({k[0] for k in rows})
    modes = sorted({k[3] for k in rows}, key=mode_key)

    report = {
        "generated": int(time.time() * 1000),
        "branch": args.branch,
        "commit": args.commit,
        "repoUrl": args.repo_url,
        "runUrl": args.run_url,
        "modes": modes,
        "targets": {},
    }
    for target in targets:
        sub = {(c, t, m): row for (tg, c, t, m), row in rows.items() if tg == target}
        report["targets"][target] = build_target(sub, modes)

    args.output.write_text(json.dumps(report, indent=2))

    for target, data in report["targets"].items():
        disagreed = sum(1 for d in data["dropped"] if d["reason"] == "disagreed")
        kept = sum(v["kept"] for v in data["tests"].values())
        print(f"{target}: {len(data['crates'])} crate(s), {kept} comparable test(s), "
              f"{len(data['dropped'])} dropped ({disagreed} disagreed)")
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
