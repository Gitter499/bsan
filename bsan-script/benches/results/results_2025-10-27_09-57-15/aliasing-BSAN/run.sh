#!/bin/bash
            echo "test output" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-57-15/aliasing-BSAN/stdout.log"
            echo "test error" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-57-15/aliasing-BSAN/stderr.log"
            EXIT_CODE=0
            STDOUT_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-57-15/aliasing-BSAN/stdout.log")
            STDERR_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-57-15/aliasing-BSAN/stderr.log")
            echo '{"exit_code": '$EXIT_CODE', "stdout": "'$STDOUT_CONTENT'", "stderr": "'$STDERR_CONTENT'"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-57-15/aliasing-BSAN/output.json"
            exit 0
            