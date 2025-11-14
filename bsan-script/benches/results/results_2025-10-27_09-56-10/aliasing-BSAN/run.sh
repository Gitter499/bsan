#!/bin/bash
            "/workspaces/bsan/target/release/aliasing-bsan" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-BSAN/stdout.log" 2> "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-BSAN/stderr.log"
            EXIT_CODE=$?
            STDOUT_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-BSAN/stdout.log")
            STDERR_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-BSAN/stderr.log")
            echo '{"exit_code": '$EXIT_CODE', "stdout": "'$STDOUT_CONTENT'", "stderr": "'$STDERR_CONTENT'"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-BSAN/output.json"
            exit 0
            