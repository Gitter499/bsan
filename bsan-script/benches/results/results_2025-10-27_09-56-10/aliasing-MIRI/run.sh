#!/bin/bash
            cargo miri run --manifest-path ./programs/Cargo.toml -p programs --bin aliasing -Zmiri-tree-borrows -Zmiri-ignore-leaks -Zmiri-disable-alignment-check -Zmiri-disable-data-race-detector -Zmiri-disable-validation -Zmiri-disable-weak-memory-emulation > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-MIRI/stdout.log" 2> "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-MIRI/stderr.log"
            EXIT_CODE=$?
            STDOUT_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-MIRI/stdout.log")
            STDERR_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-MIRI/stderr.log")
            echo '{"exit_code": '$EXIT_CODE', "stdout": "'$STDOUT_CONTENT'", "stderr": "'$STDERR_CONTENT'"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-MIRI/output.json"
            exit 0
            