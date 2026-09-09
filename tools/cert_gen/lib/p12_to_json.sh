#!/bin/sh
# Extract PKCS12 info and output JSON
# Usage: p12_to_json.sh <p12_file> <password> <output_filename> <format> <output_json_file>

P12_FILE="$1"
PASSWORD="$2"
OUTPUT_FILENAME="$3"
FORMAT="$4"
OUTPUT_JSON="$5"
STORE_PASSWORD="$PASSWORD"

TMPDIR=$(mktemp -d)

# Extract certs to PEM
openssl pkcs12 -in "$P12_FILE" -passin "pass:$PASSWORD" -nokeys -out "$TMPDIR/certs.pem" 2>/dev/null

# Check if there's a private key
HAS_KEY=$(openssl pkcs12 -in "$P12_FILE" -passin "pass:$PASSWORD" -nocerts -nodes 2>/dev/null | grep -c "PRIVATE KEY" || true)

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

# Determine type based on key presence
if [ "$HAS_KEY" -gt 0 ]; then
  TYPE="keystore"
else
  TYPE="truststore"
fi

NUM_CERTS=$(echo "$CONTENTS" | jq 'length')
if [ "$NUM_CERTS" -eq 1 ] && [ "$HAS_KEY" -gt 0 ]; then
  # Single cert with key - output flat structure
  echo "$CONTENTS" | jq '.[0]' | jq \
    --arg filename "$OUTPUT_FILENAME" \
    --arg format "$FORMAT" \
    --arg type "keystore" \
    --arg password "$STORE_PASSWORD" \
    '{filename: $filename, format: $format, type: $type, password: $password} + .' \
    > "$OUTPUT_JSON"
else
  # Multiple certs or no key - output with contents array
  echo "$CONTENTS" | jq \
    --arg filename "$OUTPUT_FILENAME" \
    --arg format "$FORMAT" \
    --arg type "$TYPE" \
    --arg password "$STORE_PASSWORD" \
    '{filename: $filename, format: $format, type: $type, password: $password, contents: .}' \
    > "$OUTPUT_JSON"
fi
