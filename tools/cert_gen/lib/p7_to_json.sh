#!/bin/sh
# Extract PKCS7 info and output JSON
# Usage: p7_to_json.sh <p7_file> <inform> <output_filename> <format> <output_json_file>
# inform: DER or PEM

P7_FILE="$1"
INFORM="$2"
OUTPUT_FILENAME="$3"
FORMAT="$4"
OUTPUT_JSON="$5"

TMPDIR=$(mktemp -d)

# Extract certs from PKCS7
openssl pkcs7 -in "$P7_FILE" -inform "$INFORM" -print_certs -out "$TMPDIR/certs.pem" 2>/dev/null

CONTENTS="[]"

if [ -f "$TMPDIR/certs.pem" ] && [ -s "$TMPDIR/certs.pem" ]; then
  # Split certs
  awk '/-----BEGIN CERTIFICATE-----/{n++}{print > "'"$TMPDIR"'/cert-" sprintf("%02d", n) ".pem"}' "$TMPDIR/certs.pem" 2>/dev/null

  for cert in "$TMPDIR"/cert-*.pem; do
    [ -f "$cert" ] || continue
    [ -s "$cert" ] || continue

    SERIAL=$(openssl x509 -in "$cert" -serial -noout 2>/dev/null | cut -d= -f2) || continue
    [ -z "$SERIAL" ] && continue

    FINGERPRINT=$(openssl x509 -in "$cert" -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2)
    NOTAFTER=$(openssl x509 -in "$cert" -enddate -noout 2>/dev/null | cut -d= -f2)
    SUBJECT=$(openssl x509 -in "$cert" -subject -noout 2>/dev/null | sed 's/subject=//')

    CERT_JSON=$(jq -n \
      --arg type "cert" \
      --arg expiration "$NOTAFTER" \
      --arg serial "$SERIAL" \
      --arg fingerprint "$FINGERPRINT" \
      --arg subject "$SUBJECT" \
      '{type: $type, expiration: $expiration, serial: $serial, fingerprint: $fingerprint, subject: $subject}')

    CONTENTS=$(echo "$CONTENTS" | jq --argjson cert "$CERT_JSON" '. += [$cert]')
  done
fi

rm -rf "$TMPDIR"

NUM_CERTS=$(echo "$CONTENTS" | jq 'length')
if [ "$NUM_CERTS" -eq 1 ]; then
  # Single cert - output flat structure
  echo "$CONTENTS" | jq '.[0]' | jq \
    --arg filename "$OUTPUT_FILENAME" \
    --arg format "$FORMAT" \
    --arg type "cert" \
    '{filename: $filename, format: $format, type: $type} + .' \
    > "$OUTPUT_JSON"
else
  # Multiple certs - output with contents array (bundle)
  echo "$CONTENTS" | jq \
    --arg filename "$OUTPUT_FILENAME" \
    --arg format "$FORMAT" \
    --arg type "bundle" \
    '{filename: $filename, format: $format, type: $type, contents: .}' \
    > "$OUTPUT_JSON"
fi
