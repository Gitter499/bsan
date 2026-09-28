# This script calculates BorrowSanitizer's relative execution time
# across all test cases for a crate. It produces two output files:
#
# * A JSON file with relative execution times in a format that is
#   compatible with `github-actions-benchmark`
#
# * A CSV file listing the mean execution times of each mode, including
#   both the baselines and tested configurations.
import argparse
import re
import statistics
import json
import csv
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

RUNS = 3
WARMUP = 1

# Uninstrumented native execution.
NATIVE = {
    "name": "native",
    "cmd": ["cargo", "test", "--lib"],
    "env": {"RUSTFLAGS": "--cfg=bsan --cfg=miri"},
}

# Flags shared by every Miri configuration. These disable most forms of
# checking, and ensure deterministic execution.
MIRI_COMMON_FLAGS = (
    "-Zmiri-mute-stdout-stderr "
    "-Zmiri-disable-data-race-detector -Zmiri-deterministic-concurrency "
    "-Zmiri-disable-alignment-check -Zmiri-ignore-leaks"
)

# Miri with Tree Borrows enabled,and all other checking disabled
# (to the extent possible).
MIRI = {
    "name": "miri-tb",
    "env": {
        "MIRIFLAGS": f"-Zmiri-tree-borrows {MIRI_COMMON_FLAGS}",
    },
}

# Every Miri configuration.
MIRI_CONFIGS = [MIRI]

# BorrowSanitizer configurations.
BSAN_CONFIGS = [
    # Full checking.
    {
        "name": "full",
        "cmd": ["cargo", "bsan", "test", "--lib"],
        "env": {"RUSTFLAGS": "--cfg=miri"},
    },
    # Full, but with wildcard provenance disabled.
    {
        "name": "full-no-wildcard",
        "cmd": ["cargo", "bsan", "test", "--lib"],
        "env": {
            "RUSTFLAGS": "--cfg=miri", 
            "BSAN_OPTIONS": "wildcard=0"
        },
    },
    # No-op checking. Instrumentation is inserted, but
    # all memory access checks, retags, and reference count
    # updates are disabled.
    {
        "name": "no-op",
        "cmd": ["cargo", "bsan", "test", "--nop", "--lib"],
        "env": {"RUSTFLAGS": "--cfg=miri"},
    }
]

# Every configuration that requires compiling a native binary.
ALL_BINARY_CONFIGS = [NATIVE] + BSAN_CONFIGS

# Raw timing results are output as a CSV with these headers.
CSV_HEADERS = [
    'target',
    'crate_name',
    'version',
    'test_name',
    'mode',
    'status',
    'mean_exec_time_seconds',
    # Filled in only for `test_failed`; see `describe_failure`.
    'error_message',
    'error_location',
    'log_url',
    'error_detail',
]

# How much of a failing test's output, from the error onward, is kept.
ERROR_DETAIL_LINES = 40
ERROR_DETAIL_CHARS = 4000

class TestHarnessJSON:
    def __init__(self, txt):
        self.lines = txt.splitlines()
        self.idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        while self.idx < len(self.lines):
            prev = self.idx
            self.idx += 1
            try:
                return json.loads(self.lines[prev])
            except json.JSONDecodeError:
                continue
        raise StopIteration

def _build_env(kwargs: dict) -> dict:
    """Creates a copy of the current environment, merged with an `env` mapping from `kwargs`.

    If a a value is set to `None` in `kwargs`, then the value will be unset from the environment,
    instead of being inherited by the parent process.
    """
    env = os.environ.copy()
    for key, value in (kwargs.pop("env", None) or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env

def run(
    cmd: list[str],
    **kwargs,
) -> subprocess.CompletedProcess:
    """Run a command, raising CalledProcessError on non-zero exit.

    The command inherits the current environment.
    """
    sys.stderr.flush()
    try:
        proc = subprocess.run(cmd, check=True, env=_build_env(kwargs), **kwargs)
    except subprocess.CalledProcessError as exc:
        print(
            f"command failed with exit code {exc.returncode}: {shlex.join(cmd)}",
            file=sys.stderr,
        )
        sys.exit(1)
    return proc

def run_rc(
    cmd: list[str],
    **kwargs,
) -> int:
    """Run a command and return its exit code instead of aborting.

    Used where a non-zero exit is a measurement result rather than an error: a
    test that fails under one configuration is data we want to report, not a
    reason to throw away every other measurement in the job.
    """
    sys.stderr.flush()
    return subprocess.run(cmd, check=False, env=_build_env(kwargs), **kwargs).returncode

def run_capture(
    cmd: list[str],
    **kwargs,
) -> str:
    """Run a command and return stdout as a string.

    The command inherits the current environment.
    """
    proc = subprocess.run(
        cmd, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=_build_env(kwargs),
        **kwargs,
    )
    return proc.stdout

def run_output(cmd: list[str], **kwargs) -> str:
    """Run a command and return its stdout and stderr, interleaved, whatever
    its exit code. Used to see why a test failed after hyperfine has already
    reported that it did."""
    sys.stderr.flush()
    proc = subprocess.run(
        cmd, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
        env=_build_env(kwargs),
        **kwargs,
    )
    return proc.stdout

# `--> src/lib.rs:12:5`, as BorrowSanitizer and Miri print below an error.
ARROW_LOCATION = re.compile(r"^\s*--> (?P<path>[^\s:][^:]*):(?P<line>\d+):(?P<col>\d+)")
# `thread 'x' panicked at src/lib.rs:12:5:`, with the message on the next line.
PANIC_LOCATION = re.compile(r"panicked at (?P<path>[^\s:][^:]*):(?P<line>\d+):(?P<col>\d+):?")
# A dependency's source, as cargo unpacks it from a registry.
REGISTRY_PATH = re.compile(
    r"/registry/src/[^/]+/(?P<name>[A-Za-z0-9_-]+?)-(?P<version>\d[^/]*)/(?P<rest>.+)$")
# The standard library's source, as rustc records it.
RUSTC_PATH = re.compile(r"^/rustc/(?P<hash>[0-9a-f]{40})/(?P<rest>.+)$")

def describe_failure(output: str | None, src_dir: Path, log_url: str) -> dict:
    """Pull the first error out of a failing test's output.

    Returns the CSV's error fields: a one-line message, the `path:line:col` it
    points at (relative to the crate, when it is in the crate), a link to the
    CI log the full output was printed to (see `print_failure`), and the output
    from the error onward. Any of them may be empty: a test can fail without
    printing a location, or without printing at all.

    `output` is None for anything but a failed test, which has no error.
    """
    empty = {"error_message": "", "error_location": "", "log_url": "", "error_detail": ""}
    if output is None:
        return empty
    empty["log_url"] = log_url
    if not output:
        return empty
    lines = output.splitlines()

    start = message = loc = None
    # A sanitizer report is the more specific finding: the test harness only
    # adds a generic panic or abort after it.
    for i, text in enumerate(lines):
        if "Undefined Behavior" in text:
            start, message = i, text.strip()
            for later in lines[i + 1:]:
                if m := ARROW_LOCATION.match(later):
                    loc = m
                    break
            break
    if start is None:
        for i, text in enumerate(lines):
            if m := PANIC_LOCATION.search(text):
                start, loc = i, m
                following = lines[i + 1].strip() if i + 1 < len(lines) else ""
                message = following or text.strip()
                break
    if start is None:
        # Nothing recognisable, e.g. a crash with no report: keep the end of
        # the output, which is where the reason usually is.
        nonblank = [i for i, text in enumerate(lines) if text.strip()]
        if not nonblank:
            return empty
        start = max(0, nonblank[-1] - ERROR_DETAIL_LINES + 1)
        message = lines[nonblank[-1]].strip()

    detail = "\n".join(lines[start:start + ERROR_DETAIL_LINES])[:ERROR_DETAIL_CHARS]
    result = {**empty, "error_message": message[:300], "error_detail": detail}
    if loc:
        path = loc["path"]
        root = str(src_dir) + "/"
        # Show a path the way someone would look it up, not where it happened
        # to be unpacked on the runner.
        if path.startswith(root):
            shown = path[len(root):]
        elif m := REGISTRY_PATH.search(path):
            shown = f"{m['name']}-{m['version']}/{m['rest']}"
        elif m := RUSTC_PATH.match(path):
            shown = m["rest"]
        else:
            shown = path
        result["error_location"] = f"{shown}:{loc['line']}:{loc['col']}"
    return result

def print_failure(mode: str, test: str, output: str | None) -> None:
    """Print a failed test's output to the log, which `log_url` links to.

    In GitHub Actions each failure is a collapsed group, titled so that it can
    be found by searching the log for the test's name.
    """
    if output is None:
        return
    actions = os.environ.get("GITHUB_ACTIONS") == "true"
    print(f"::group::FAILED {mode}: {test}" if actions else f"FAILED {mode}: {test}")
    print(output.rstrip() or "(no output)")
    if actions:
        print("::endgroup::")
    sys.stdout.flush()

def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        sys.exit(f"Error: '{name}' is required but not installed.")

def download_crate(crate: str, version: str, dest_dir: Path) -> Path:
    """Downloads <crate>@<version> from crates.io into dest_dir, extracts it,
    and returns the path to the extracted contents."""
    url = f"https://crates.io/api/v1/crates/{crate}/{version}/download"
    tarball = dest_dir / f"{crate}-{version}.crate"

    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as resp, open(tarball, "wb") as out:
        shutil.copyfileobj(resp, out)

    with tarfile.open(tarball, "r:gz") as tf:
        try:
            tf.extractall(dest_dir, filter="data")
        except TypeError:
            tf.extractall(dest_dir)
    tarball.unlink()

    extracted = dest_dir / f"{crate}-{version}"
    if not extracted.is_dir():
        sys.exit(f"Error: expected extracted directory {extracted} not found.")
    return extracted

def compile_test_binary(config: dict, cwd: Path, out_dir: Path):
    """Compiles the test binary for the given cargo invocation and copies it into
    `out_dir`. Aborts on compile failure or if no executable is created.
    """
    print(f"compiling tests ({config["name"]}): {' '.join(config["cmd"])}",
          file=sys.stderr)
    # We need to parse the output JSON to find the name of the test binary.
    msg_json = run_capture(
        config["cmd"] + ["--no-run", "--message-format=json"],
        cwd=cwd,
        env=config.get("env"),
    )
    for msg in TestHarnessJSON(msg_json):
        exe = msg.get("executable")
        target = msg.get("target") or {}
        if exe and target.get("test"):
            print("done.")
            binary = out_dir / config["name"]
            shutil.copy2(exe, binary)
            binary.chmod(0o755)
            return

    sys.exit(f"Error: could not locate {config["name"]} test binary.")

def miri_binary() -> str:
    """Resolve the real `miri` executable for the active toolchain."""
    return run_capture(["rustup", "which", "miri"]).strip()


# The only way to execute a program in Miri is through Miri's cargo plugin
# (e.g. `cargo miri ...`). This adds additional overhead that is not present
# for natively compiled code. We want our timing measurements to be as accurate
# as possible, so instead of timing `cargo miri test`, we capture Miri's
# environment right before it invokes the actual `miri` binary as an interpreter.
# Then, we create a shell script to recreate that environment and execute `miri`
# directly, bypassing `cargo-miri`.
#
# This happens in two stages. First, we emit the shell script below. This is a one-time
# operation; we reuse it for subsequent invocations. Whenever we execute Miri, we set
# the `MIRI` environment variable to point to this script. Every time that `cargo-miri`
# invokes the `miri` binary, this script will be executed instead. It forwards all
# argument to `miri`, but it also checks to see if it is being invoked as the final call
# to the interpreter. We identify this case if the variable `CARGO_PRIMARY_PACKAGE` is set
# and the flag `--test` is provided. In that situation, we capture the environment and all
# flags, and emit it as an additional shell script. That final shell script, which is
# created per-test, is what gets benchmarked.
#
# This generally saves ~0.1 seconds of overhead, which is small but significant when
# comparing against native execution.
MIRI_WRAPPER_TEMPLATE = """#!/usr/bin/env bash
if [ -n "$CARGO_PRIMARY_PACKAGE" ] && [[ " $* " == *" --test "* ]]; then
    {
        echo '#!/usr/bin/env bash'
        printf 'cd %q || exit 1\\n' "$PWD"
        printf 'exec env -i'
        while IFS= read -r -d '' var; do printf ' %q' "$var"; done < <(env -0)
        printf ' %q' @MIRI_BIN@ "$@"
        echo
    } > "$BSAN_MIRI_REPLAY"
    chmod +x "$BSAN_MIRI_REPLAY"
fi
exec @MIRI_BIN@ "$@"
"""

def ensure_miri_wrapper(scratch: Path) -> Path:
    """Ensure that the wrapper script for capturing Miri invocations is initialized."""
    wrapper = scratch / "miri-wrapper.sh"
    if not wrapper.is_file():
        script = MIRI_WRAPPER_TEMPLATE.replace("@MIRI_BIN@", shlex.quote(miri_binary()))
        wrapper.write_text(script)
        wrapper.chmod(0o755)
    return wrapper

def compile_miri_tests(cwd: Path):
    print("compiling tests (miri)")
    run_capture(
        ["cargo", "miri", "test", "--no-run", "--message-format=json"],
        cwd=cwd,
    )

def run_miri_test(cwd: Path, t: str, config: dict, scratch: Path
                  ) -> tuple[float | None, str, str | None]:
    """Time a single Miri test, excluding `cargo-miri` overhead, by capturing its
    final `miri` invocation as a standalone script.

    Returns `(mean_seconds, status, output)` on the same terms as
    `hyperfine_mean`: a test Miri refuses to run is reported, not fatal.
    """
    replay = scratch / "miri-replay.sh"
    # The wrapper rewrites this for every test. Clear it first so that a failed
    # interception cannot leave the previous test's script in place, which we
    # would then happily time and attribute to this one.
    replay.unlink(missing_ok=True)

    override_env = { **(config.get("env") or {}) }
    override_env["MIRI"] = str(ensure_miri_wrapper(scratch))
    override_env["BSAN_MIRI_REPLAY"] = str(replay)

    # One cargo-miri run generates the replay script for this test's final miri
    # invocation; we then time that script on its own, free of cargo overhead.
    proc = subprocess.run(
        ["cargo", "miri", "test", "-q", "--lib", "--", "--exact", t, "--nocapture"],
        check=False, cwd=cwd, env=_build_env({"env": override_env}),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    if proc.returncode != 0:
        return None, "test_failed", proc.stdout
    if not replay.is_file():
        return None, "bench_failed", None
    return hyperfine_mean(str(replay), config)

def list_tests(cwd: Path, cmd: list[str]) -> list[str]:
    out = run_capture(cmd + [
        # Format the test list as JSON
        "--list", "--format=json",
        # Enable JSON output
        "-Zunstable-options"
        ],
        cwd=cwd
    )
    tests = []
    for obj in TestHarnessJSON(out):
        type = obj.get("type")
        event = obj.get("event")
        name = obj.get("name")
        ignored = obj.get("ignore")
        # every JSON output line had "type" and "event" keys
        if type is not None and event is not None:
            if type == "test" and event == "discovered":
                # the "ignore" flag indicates if the test configured
                # to be ignored under this compilation configuration.
                if name is not None and ignored is not None:
                    if not ignored:
                        tests.append(name)
                    continue
            else:
                continue
        sys.exit(f"Invalid libtest JSON format.")
    return tests

def hyperfine_mean(cmd, config: dict, **kwargs) -> tuple[float | None, str, str | None]:
    """Run hyperfine on a single command and return
    `(mean_seconds, status, output)`.

    A configuration that cannot run a test is a result, not an error: the same
    test usually runs fine under the others, and which configurations disagree
    is exactly what the per-branch report exists to show. So nothing here
    aborts.

      success       hyperfine timed the command and reported a positive mean
      test_failed   the command exited non-zero, so hyperfine has no timing
      bench_failed  hyperfine ran but reported no usable mean

    Only `success` carries a mean; the other two return None, which the CSV
    writes as an empty cell. Only `test_failed` carries output: hyperfine
    discards it, so the command is run once more to see why it failed.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out_json:
        out_path = Path(out_json.name)
    try:
        rc = run_rc(
            [
                "hyperfine",
                "--runs", str(RUNS),
                "--warmup", str(WARMUP),
                "--shell=none",
                "--export-json", str(out_path),
                "--show-output",
                cmd,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **kwargs
        )
        # Without `--ignore-failure` hyperfine exits non-zero as soon as the
        # command under test does, and writes no JSON.
        if rc != 0:
            return None, "test_failed", run_output(shlex.split(cmd), **kwargs)
        try:
            data = json.loads(out_path.read_text())
            mean = float(data["results"][0]["mean"])
        except (OSError, ValueError, KeyError, IndexError):
            return None, "bench_failed", None
        return (mean, "success", None) if mean > 0 else (None, "bench_failed", None)
    finally:
        out_path.unlink(missing_ok=True)

def process_config(
    cfg: dict,
    target: str,
    scratch: Path,
    miri: bool = True,
    binary_configs: list[dict] = ALL_BINARY_CONFIGS,
    log_url: str = "",
) -> list:
    crate = cfg.get("name")
    version = cfg.get("version")
    excluded_tests = set(cfg.get("exclude") or [])

    if not crate or not version:
        sys.exit(f"Error: invalid per-crate config:\n{cfg}")

    bench_name = f"{crate}@{version} - {target}"

    print(f"Running: {bench_name}")
    if excluded_tests:
        print("Excluding:")
        for test_name in excluded_tests:
            print(f"- {test_name}")

    src_dir = download_crate(crate, version, scratch)
    for config in binary_configs:
        compile_test_binary(config, cwd=src_dir, out_dir=scratch)
        try:
            run(["cargo", "clean", "--quiet"], cwd=src_dir)
        except subprocess.CalledProcessError:
            pass

    # Without Miri, list from the first compiled binary instead. Every one is
    # built with `--cfg=miri` too, so `#[cfg_attr(miri, ignore)]` still takes
    # effect.
    if miri:
        all_tests = list_tests(src_dir, ["cargo", "miri", "test", "--lib", "--"])
    else:
        all_tests = list_tests(src_dir, [str(scratch / binary_configs[0]["name"])])

    if not all_tests:
        sys.exit(f"Error: no tests discovered for {bench_name}.")
    else:
        print(f"Found {len(all_tests)} tests for {bench_name}.")

    tests = [t for t in all_tests if t not in excluded_tests]
    if not tests:
        sys.exit(f"Error: every discovered test was excluded for {bench_name}.")

    miri_configs = MIRI_CONFIGS if miri else []
    if miri:
        compile_miri_tests(src_dir)

    # a mapping from (config, baseline) pairs to mean execution times for each test case
    # for example, we would have `ratios[("no-op", "miri-tb")]` map to the list of
    # mean execution times for our no-op mode relative to Miri with tree borrows enabled.
    ratios: dict[tuple[str, str], list[float]] = {}

    # a raw list of execution times per crate, version, test case, and mode
    raw_results: list[tuple] = []
    # measurements that produced no timing, reported once at the end so a run
    # that quietly lost a configuration is visible in the log
    failed = 0
    for t in tests:
        row_start = (target, crate, version, t)
        print(f"  -> {t}")
        # a mapping from each config to its mean execution time; a config that
        # could not run this test has no entry
        per_test_means: dict[str, float] = {}

        # execute every natively-compiled binary and record its mean execution time
        for config in binary_configs:
            binary = scratch / config["name"]
            mean, status, output = hyperfine_mean(f"{binary} --exact {t} --nocapture",
                                                  config, env=config.get("env"))
            if mean is None:
                print(f"    - {config['name']}: {status}")
                failed += 1
            else:
                print(f"    - {config['name']}={round(mean, 8)}s")
                per_test_means[config["name"]] = mean
            print_failure(config["name"], t, output)
            error = describe_failure(output, src_dir, log_url)
            raw_results.append(row_start + (config["name"], status, mean)
                               + tuple(error.values()))

        baselines = {}
        if NATIVE["name"] in per_test_means:
            baselines[NATIVE["name"]] = per_test_means.pop(NATIVE["name"])
        # execute Miri and add each configuration as a baseline for comparison
        for miri_config in miri_configs:
            miri_mean, status, output = run_miri_test(src_dir, t, miri_config, scratch)
            if miri_mean is None:
                print(f"    - {miri_config['name']}: {status}")
                failed += 1
            else:
                print(f"    - {miri_config['name']}={round(miri_mean, 8)}s")
                baselines[miri_config["name"]] = miri_mean
            print_failure(miri_config["name"], t, output)
            error = describe_failure(output, src_dir, log_url)
            raw_results.append(row_start + (miri_config["name"], status, miri_mean)
                               + tuple(error.values()))

        # A ratio needs both of its halves measured on this test, so a config
        # that failed here contributes no ratio and the mean below is taken over
        # the tests that did produce one.
        for mode, mode_mean in per_test_means.items():
            for baseline, baseline_mean in baselines.items():
                ratio = mode_mean / baseline_mean
                ratios.setdefault((mode, baseline), []).append(ratio)
                print(f"    - {mode} vs {baseline} = {round(ratio, 4)}x")

    if failed:
        print(f"{failed} measurement(s) produced no timing for {bench_name}; "
              f"see the status column of the CSV.")

    relative_results = []
    for (mode, baseline), ratio_list in ratios.items():
        relative_results.append({
            "name": bench_name,
            "unit": "Mean Relative Execution Time",
            "value": statistics.mean(ratio_list),
            "extra": json.dumps({
                "mode": mode,
                "baseline": baseline,
                "target": target,
                "version": version,
                "crate": crate,
                "max": max(ratio_list),
                "min": min(ratio_list)
            }),
        })

    all_results = {
        "relative": relative_results,
        "raw": raw_results
    }
    return all_results

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark relative execution time",
        usage=(
            "%(prog)s [--crate NAME ...] <crates> <target> <output_json> <output_csv>"
        ),
    )
    parser.add_argument("crates_json", type=Path)
    parser.add_argument("target", type=str)
    parser.add_argument("output_json", type=Path)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument(
        "--crate",
        action="append",
        dest="only",
        metavar="NAME",
        help="Only benchmark the named crate from <crates> (repeatable). "
             "Used to shard the benchmark suite one crate per CI job.",
    )
    parser.add_argument(
        "--no-miri",
        action="store_false",
        dest="miri",
        help="Skip the Miri configurations. Ratios are then only relative to "
             "native. Used where the comparison of interest is against another "
             "build of BorrowSanitizer rather than against Miri.",
    )
    parser.add_argument(
        "--mode",
        action="append",
        dest="modes",
        metavar="NAME",
        choices=[c["name"] for c in ALL_BINARY_CONFIGS],
        help="Only compile and time the named configuration (repeatable). "
             "Without `native`, no ratios are produced, only raw times. Used "
             "for branch comparisons, which only look at `full`.",
    )

    parser.add_argument(
        "--log-url",
        default="",
        metavar="URL",
        help="Where this run's log can be read, e.g. its CI job. Recorded "
             "against every failed test, whose output is printed to the log.",
    )

    args = parser.parse_args(argv)
    for tool in ["cargo", "hyperfine"]:
        require_tool(tool)

    crates_json = args.crates_json
    if not crates_json.is_file():
        sys.exit(f"Error: invalid config file: {crates_json}")

    binary_configs = ALL_BINARY_CONFIGS
    if args.modes:
        binary_configs = [c for c in ALL_BINARY_CONFIGS if c["name"] in args.modes]

    configs = json.loads(crates_json.read_text())
    if args.only:
        wanted = set(args.only)
        configs = [cfg for cfg in configs if cfg.get("name") in wanted]
        missing = wanted - {cfg.get("name") for cfg in configs}
        if missing:
            sys.exit(f"Error: crate(s) not found in {crates_json}: {', '.join(sorted(missing))}")

    all_results = {}
    with tempfile.TemporaryDirectory() as scratch_str:
        scratch = Path(scratch_str)
        for cfg in configs:
            cfg_results = process_config(cfg, args.target, scratch, miri=args.miri,
                                         binary_configs=binary_configs,
                                         log_url=args.log_url)
            all_results.setdefault("relative", [])
            all_results["relative"] += cfg_results["relative"]
            all_results.setdefault("raw", [])
            all_results["raw"] += cfg_results["raw"]

    args.output_json.write_text(json.dumps(all_results["relative"], indent=4))
    if "raw" in all_results:
        with open(args.output_csv, 'w') as out:
            csv_out=csv.writer(out)
            csv_out.writerow(CSV_HEADERS)
            for row in all_results["raw"]:
                csv_out.writerow(row)

    print(f"Results written to {args.output_json} and {args.output_csv}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
