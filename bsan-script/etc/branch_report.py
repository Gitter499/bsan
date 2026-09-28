#!/usr/bin/env python3
"""
Usage: branch_report.py <output.json> --branch-csv CSV [CSV ...]
                        --main-csv CSV [CSV ...]

Build the dataset behind a per-branch benchmark page from the raw per-test CSVs
`bench.py` writes (target, crate_name, version, test_name, mode, status,
mean_exec_time_seconds): one set measured on the branch, one on `main`.

The page answers one question: did this branch make BorrowSanitizer faster or
slower than `main`? So for each target and each mode it reports per-crate wall
time in seconds for both sides, over a workload both sides completed.

Common tests
    For a given target and mode, a crate's seconds are the SUM of its tests'
    means, restricted to tests that succeeded on BOTH `main` and the branch.
    Without the restriction each side covers whatever it happened to complete,
    so a side that lost tests is credited with less work and looks faster for
    it. Statuses come from the CSV, which records a failure per (test, mode)
    rather than aborting the run.

No calibration
    bench.py measures a test binary directly with an `--exact` filter, so there
    is no per-invocation cargo constant to subtract; every total is a plain sum
    of means.

Everything left out of the common set is reported in `dropped` with its status
on each side, and for each failing side the error bench.py found in its output
and a link to the CI log holding that output, so the page can show which tests
changed behaviour, and why, rather than only how many.

When a CSV is given more than once for the same (target, crate, test, mode),
the last row wins, so fresh `main` results listed after a cached copy replace it.
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

# Mode order in the page's selector. `full` is the default selection.
MODE_ORDER = ["full", "full-no-wildcard", "no-op", "native"]

# Modes that do not measure BorrowSanitizer, so comparing them across two of its
# builds says nothing. `main`'s cached results still carry Miri.
IGNORED_MODES = {"miri-tb"}

# A test counts toward a crate's total only with this status on both sides.
COMPARABLE = "success"

REQUIRED = {"target", "crate_name", "version", "test_name", "mode",
            "status", "mean_exec_time_seconds"}


def mode_key(mode):
    return (MODE_ORDER.index(mode) if mode in MODE_ORDER else len(MODE_ORDER), mode)


def read_rows(paths):
    """Load CSVs into {(target, mode, crate, test): row}; the last row wins."""
    rows = {}
    for path in paths:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            missing = REQUIRED - set(reader.fieldnames or [])
            if missing:
                sys.exit(f"Error: {path} is missing column(s): "
                         f"{', '.join(sorted(missing))}")
            for row in reader:
                if not row.get("test_name") or row["mode"] in IGNORED_MODES:
                    continue
                crate = f"{row['crate_name']}@{row['version']}"
                rows[(row["target"], row["mode"], crate, row["test_name"])] = row
    return rows


def timing(row):
    try:
        v = float(row["mean_exec_time_seconds"])
    except (TypeError, ValueError):
        return None
    return v if v > 0 else None


def status(row):
    return row["status"] if row is not None else "not run"


def error(row):
    """The error bench.py extracted from a failing test, or None.

    Results published before bench.py recorded errors have no error columns.
    """
    if row is None or row.get("status") == COMPARABLE:
        return None
    fields = {"message": row.get("error_message") or "",
              "location": row.get("error_location") or "",
              "url": row.get("log_url") or "",
              "detail": row.get("error_detail") or ""}
    return fields if any(fields.values()) else None


def build_mode(main_rows, branch_rows):
    """Compare one (target, mode): {(crate, test): row} on each side."""
    seconds = {"main": {}, "branch": {}}
    counts = {}
    dropped = []

    for crate, test in sorted(set(main_rows) | set(branch_rows)):
        m, b = main_rows.get((crate, test)), branch_rows.get((crate, test))
        counts.setdefault(crate, {"kept": 0, "total": 0})
        counts[crate]["total"] += 1
        sm, sb = status(m), status(b)

        if sm == sb == COMPARABLE:
            tm, tb = timing(m), timing(b)
            if tm is not None and tb is not None:
                seconds["main"][crate] = seconds["main"].get(crate, 0.0) + tm
                seconds["branch"][crate] = seconds["branch"].get(crate, 0.0) + tb
                counts[crate]["kept"] += 1
                continue
            reason = "success without a timing"
        elif sm == "not run" or sb == "not run":
            reason = f"not run on {'main' if sm == 'not run' else 'branch'}"
        elif sm != sb:
            reason = "changed"
        else:
            reason = f"{sm} on both"
        dropped.append({"crate": crate, "test": test, "reason": reason,
                        "main": sm, "branch": sb,
                        "errors": {"main": error(m), "branch": error(b)}})

    # A crate with no comparable test has no point on either line.
    crates = sorted((c for c in counts if counts[c]["kept"] > 0),
                    key=lambda c: (seconds["main"][c], c))

    # A test whose result changed between main and the branch is a real finding;
    # the rest is usually a test that is simply unsupported everywhere.
    dropped.sort(key=lambda d: (d["reason"] != "changed", d["crate"], d["test"]))

    return {
        "crates": crates,
        "main": seconds["main"],
        "branch": seconds["branch"],
        "tests": {c: counts[c] for c in crates},
        "dropped": dropped,
    }


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output", type=Path)
    ap.add_argument("--branch-csv", type=Path, nargs="+", required=True)
    ap.add_argument("--main-csv", type=Path, nargs="+", required=True)
    ap.add_argument("--branch", default="")
    ap.add_argument("--commit", default="")
    ap.add_argument("--main-commit", action="append", default=[],
                    help="A `main` commit the baseline was measured at (repeatable; "
                         "more than one when cached and fresh results are mixed).")
    ap.add_argument("--repo-url", default="")
    ap.add_argument("--run-url", default="")
    args = ap.parse_args(argv)

    branch_rows = read_rows(args.branch_csv)
    main_rows = read_rows(args.main_csv)
    if not branch_rows:
        sys.exit("Error: no test rows found in the branch CSVs.")
    if not main_rows:
        sys.exit("Error: no test rows found in the main CSVs.")

    # Only a target and mode measured on both sides can be compared.
    def keys(rows):
        return {(tg, m) for tg, m, _, _ in rows}
    pairs = keys(branch_rows) & keys(main_rows)
    # `main`'s published results carry every mode, and a branch run measures
    # only the ones it is compared under, so only the reverse is worth a warning.
    for tg, m in sorted(keys(branch_rows) - keys(main_rows)):
        print(f"warning: {m} on {tg} was not measured on main; skipped",
              file=sys.stderr)

    targets = sorted({tg for tg, _ in pairs})
    modes = sorted({m for _, m in pairs}, key=mode_key)

    report = {
        "generated": int(time.time() * 1000),
        "branch": args.branch,
        "commit": args.commit,
        "mainCommits": list(dict.fromkeys(c for c in args.main_commit if c)),
        "repoUrl": args.repo_url,
        "runUrl": args.run_url,
        "modes": modes,
        "targets": {},
    }
    for tg in targets:
        report["targets"][tg] = {}
        for m in modes:
            if (tg, m) not in pairs:
                continue
            side = lambda rows: {(c, t): r for (rtg, rm, c, t), r in rows.items()
                                 if rtg == tg and rm == m}
            branch_side = side(branch_rows)
            # `main`'s published results can cover crates, or crate versions,
            # that this branch no longer benchmarks; those are not a comparison.
            crates = {c for c, _ in branch_side}
            main_side = {k: r for k, r in side(main_rows).items() if k[0] in crates}
            report["targets"][tg][m] = build_mode(main_side, branch_side)

    args.output.write_text(json.dumps(report, indent=2))

    for tg, by_mode in report["targets"].items():
        for m, data in by_mode.items():
            kept = sum(v["kept"] for v in data["tests"].values())
            changed = sum(1 for d in data["dropped"] if d["reason"] == "changed")
            tm = sum(data["main"][c] for c in data["crates"])
            tb = sum(data["branch"][c] for c in data["crates"])
            ratio = f", branch/main = {tb / tm:.3f}x" if tm else ""
            print(f"{tg} {m}: {len(data['crates'])} crate(s), {kept} common test(s), "
                  f"{len(data['dropped'])} dropped ({changed} changed){ratio}")
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
