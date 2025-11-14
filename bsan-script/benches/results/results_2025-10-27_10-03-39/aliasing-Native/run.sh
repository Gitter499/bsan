#!/bin/bash
            echo "Hello from wrapper script" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_10-03-39/aliasing-Native/stdout.log"
            EXIT_CODE=0
            STDOUT_CONTENT=$(cat "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_10-03-39/aliasing-Native/stdout.log")
            STDERR_CONTENT=""
            echo '{"exit_code": '$EXIT_CODE', "stdout": "'$STDOUT_CONTENT'", "stderr": "'$STDERR_CONTENT'"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_10-03-39/aliasing-Native/output.json"
            exit 0
            