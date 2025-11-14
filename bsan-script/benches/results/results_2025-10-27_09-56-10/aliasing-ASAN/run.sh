#!/bin/bash
            "/workspaces/bsan/target/release/aliasing-asan" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-ASAN/stdout.log" 2> "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-ASAN/stderr.log"
            EXIT_CODE=$?
            STDOUT_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-ASAN/stdout.log")
            STDERR_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-ASAN/stderr.log")
            echo '{"exit_code": '$EXIT_CODE', "stdout": "'$STDOUT_CONTENT'", "stderr": "'$STDERR_CONTENT'"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-ASAN/output.json"
            exit 0
            