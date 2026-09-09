#!/bin/sh
# Output JSON for a key file
# Usage: key_to_json.sh <output_filename> <format> <output_json_file> [password]

OUTPUT_FILENAME="$1"
FORMAT="$2"
OUTPUT_JSON="$3"
PASSWORD="$4"

if [ -n "$PASSWORD" ]; then
  jq -n \
    --arg filename "$OUTPUT_FILENAME" \
    --arg format "$FORMAT" \
    --arg type "key" \
    --arg password "$PASSWORD" \
    '{filename: $filename, format: $format, type: $type, password: $password}' \
    > "$OUTPUT_JSON"
else
  jq -n \
    --arg filename "$OUTPUT_FILENAME" \
    --arg format "$FORMAT" \
    --arg type "key" \
    '{filename: $filename, format: $format, type: $type}' \
    > "$OUTPUT_JSON"
fi
