#!/bin/bash
            "/workspaces/bsan/target/release/aliasing-asan" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-ASAN/stdout.log" 2> "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-ASAN/stderr.log"
            EXIT_CODE=$?
            echo '{"exit_code": $EXIT_CODE, "stdout": "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-ASAN/stdout.log", "stderr": "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-ASAN/stderr.log"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-ASAN/output.json"
            exit 0
            