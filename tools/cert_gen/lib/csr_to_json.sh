#!/bin/sh
# Extract CSR info and output JSON
# Usage: csr_to_json.sh <pem_csr_file> <output_filename> <format> <output_json_file>

PEM_FILE="$1"
OUTPUT_FILENAME="$2"
FORMAT="$3"
OUTPUT_JSON="$4"

SUBJECT=$(openssl req -in "$PEM_FILE" -subject -noout | sed 's/subject=//')

jq -n \
  --arg filename "$OUTPUT_FILENAME" \
  --arg format "$FORMAT" \
  --arg type "csr" \
  --arg subject "$SUBJECT" \
  '{filename: $filename, format: $format, type: $type, subject: $subject}' \
  > "$OUTPUT_JSON"
