#!/bin/bash
            "/workspaces/bsan/target/release/aliasing-bsan" > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-BSAN/stdout.log" 2> "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-BSAN/stderr.log"
            EXIT_CODE=$?
            echo '{"exit_code": $EXIT_CODE, "stdout": "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-BSAN/stdout.log", "stderr": "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-BSAN/stderr.log"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_09-40-28/aliasing-BSAN/output.json"
            exit 0
            