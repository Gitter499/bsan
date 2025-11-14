#!/bin/bash
            "/workspaces/bsan/target/release/aliasing-native" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-Native/stdout.log" 2> "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-Native/stderr.log"
            EXIT_CODE=$?
            STDOUT_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-Native/stdout.log")
            STDERR_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-Native/stderr.log")
            echo '{"exit_code": '$EXIT_CODE', "stdout": "'$STDOUT_CONTENT'", "stderr": "'$STDERR_CONTENT'"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-56-10/aliasing-Native/output.json"
            exit 0
            