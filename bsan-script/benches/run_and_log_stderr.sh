#!/bin/bash
# $1: command to run
# $2: stderr log file path

# Execute the command, redirect stderr to a temporary file
# and then append the content of the temporary file to the log file.
# This ensures that each run's stderr is captured.
temp_stderr=$(mktemp)
"$@" 2> "$temp_stderr"
exit_code=$?

# Append stderr to the log file, prefixed with a separator and timestamp
echo "--- $(date) ---" >> "$2"
cat "$temp_stderr" >> "$2"
rm "$temp_stderr"

exit $exit_code
