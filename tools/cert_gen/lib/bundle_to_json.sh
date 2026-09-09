#!/bin/sh
# Extract bundle info and output JSON with contents array
# Usage: bundle_to_json.sh <pem_bundle_file> <output_filename> <format> <output_json_file>

PEM_FILE="$1"
OUTPUT_FILENAME="$2"
FORMAT="$3"
OUTPUT_JSON="$4"

TMPDIR=$(mktemp -d)

# Split the bundle into individual certs
csplit -f "$TMPDIR/cert-" -z "$PEM_FILE" '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null || \
  awk '/-----BEGIN CERTIFICATE-----/{n++}{print > "'"$TMPDIR"'/cert-" sprintf("%02d", n)}' "$PEM_FILE"

CONTENTS="[]"
for cert in "$TMPDIR"/cert-*; do
  [ -f "$cert" ] || continue
  # Skip empty files
  [ -s "$cert" ] || continue

  SERIAL=$(openssl x509 -in "$cert" -serial -noout 2>/dev/null | cut -d= -f2) || continue
  [ -z "$SERIAL" ] && continue

  FINGERPRINT=$(openssl x509 -in "$cert" -fingerprint -sha256 -noout | cut -d= -f2)
  NOTAFTER=$(openssl x509 -in "$cert" -enddate -noout | cut -d= -f2)
  SUBJECT=$(openssl x509 -in "$cert" -subject -noout | sed 's/subject=//')

  CERT_JSON=$(jq -n \
    --arg type "cert" \
    --arg expiration "$NOTAFTER" \
    --arg serial "$SERIAL" \
    --arg fingerprint "$FINGERPRINT" \
    --arg subject "$SUBJECT" \
    '{type: $type, expiration: $expiration, serial: $serial, fingerprint: $fingerprint, subject: $subject}')

  CONTENTS=$(echo "$CONTENTS" | jq --argjson cert "$CERT_JSON" '. += [$cert]')
done

rm -rf "$TMPDIR"

echo "$CONTENTS" | jq \
  --arg filename "$OUTPUT_FILENAME" \
  --arg format "$FORMAT" \
  --arg type "bundle" \
  '{filename: $filename, format: $format, type: $type, contents: .}' \
  > "$OUTPUT_JSON"
