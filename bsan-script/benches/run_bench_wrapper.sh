#!/bin/bash

COMMAND="{COMMAND}"
STDOUT_LOG_PATH="{STDOUT_LOG_PATH}"
STDERR_LOG_PATH="{STDERR_LOG_PATH}"
OUTPUT_JSON_PATH="{OUTPUT_JSON_PATH}"

# Execute the command and capture its stdout and stderr
$COMMAND > "$STDOUT_LOG_PATH" 2> "$STDERR_LOG_PATH"
EXIT_CODE=$?

# Read stdout and stderr, escaping them for JSON
# jaq -Rs . reads raw string and outputs as JSON string literal
STDOUT_CONTENT=$(cat "$STDOUT_LOG_PATH" | jaq -Rs . || echo ''"") # Default to empty JSON string if jaq fails
STDERR_CONTENT=$(cat "$STDERR_LOG_PATH" | jaq -Rs . || echo ''"") # Default to empty JSON string if jaq fails

# Construct the final JSON output
# Use printf to avoid issues with echo and complex strings
printf '{"exit_code": %d, "stdout": %s, "stderr": %s}\n' "$EXIT_CODE" "$STDOUT_CONTENT" "$STDERR_CONTENT" > "$OUTPUT_JSON_PATH"

exit 0
