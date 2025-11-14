#!/bin/bash
                        echo "Hello from wrapper script"
                        EXIT_CODE=0
                        STDOUT_CONTENT="Hello from wrapper script"
                        STDERR_CONTENT=""
                        echo '{"exit_code": '$EXIT_CODE', "stdout": "'$STDOUT_CONTENT'", "stderr": "'$STDERR_CONTENT'"}' > "/workspaces/bsan/bsan-script/benches/results/results_2025-10-27_10-04-28/aliasing-MIRI/output.json"
                        exit 0
                        