#!/bin/bash
            set -e
            echo "Attempting to create stdout.log at: /workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/stdout.log"
            echo "test output" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/stdout.log"
            echo "Attempting to create stderr.log at: /workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/stderr.log"
            echo "test error" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/stderr.log"
            EXIT_CODE=0
            echo "Attempting to read stdout.log from: /workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/stdout.log"
            STDOUT_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/stdout.log")
            echo "Attempting to read stderr.log from: /workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/stderr.log"
            STDERR_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/stderr.log")
            echo '{"exit_code": '$EXIT_CODE', "stdout": "'$STDOUT_CONTENT'", "stderr": "'$STDERR_CONTENT'"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-59-14/aliasing-ASAN/output.json"
            exit 0
            