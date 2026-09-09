#!/bin/sh
# Extract certificate info and output JSON
# Usage: cert_to_json.sh <pem_cert_file> <output_filename> <format> <output_json_file>

PEM_FILE="$1"
OUTPUT_FILENAME="$2"
FORMAT="$3"
OUTPUT_JSON="$4"

SERIAL=$(openssl x509 -in "$PEM_FILE" -serial -noout | cut -d= -f2)
FINGERPRINT=$(openssl x509 -in "$PEM_FILE" -fingerprint -sha256 -noout | cut -d= -f2)
NOTAFTER=$(openssl x509 -in "$PEM_FILE" -enddate -noout | cut -d= -f2)
SUBJECT=$(openssl x509 -in "$PEM_FILE" -subject -noout | sed 's/subject=//')

jq -n \
  --arg filename "$OUTPUT_FILENAME" \
  --arg format "$FORMAT" \
  --arg type "cert" \
  --arg expiration "$NOTAFTER" \
  --arg serial "$SERIAL" \
  --arg fingerprint "$FINGERPRINT" \
  --arg subject "$SUBJECT" \
  '{filename: $filename, format: $format, type: $type, expiration: $expiration, serial: $serial, fingerprint: $fingerprint, subject: $subject}' \
  > "$OUTPUT_JSON"
