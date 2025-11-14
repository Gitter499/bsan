#!/bin/bash
            cargo miri run --manifest-path ./programs/Cargo.toml -p programs --bin aliasing -Zmiri-tree-borrows -Zmiri-ignore-leaks -Zmiri-disable-alignment-check -Zmiri-disable-data-race-detector -Zmiri-disable-validation -Zmiri-disable-weak-memory-emulation > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-MIRI/stdout.log" 2> "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-MIRI/stderr.log"
            EXIT_CODE=$?
            echo '{"exit_code": $EXIT_CODE, "stdout": "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-MIRI/stdout.log", "stderr": "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-MIRI/stderr.log"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-MIRI/output.json"
            exit 0
            