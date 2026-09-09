#!/bin/sh
# Extract JKS/JCEKS keystore info and output JSON
# Usage: jks_to_json.sh <keystore_file> <password> <output_filename> <format> <output_json_file>

KEYSTORE="$1"
PASSWORD="$2"
OUTPUT_FILENAME="$3"
FORMAT="$4"
OUTPUT_JSON="$5"
STORE_PASSWORD="$PASSWORD"

TMPDIR=$(mktemp -d)

# List aliases
ALIASES=$(keytool -list -keystore "$KEYSTORE" -storepass "$PASSWORD" -v 2>/dev/null | grep "Alias name:" | sed 's/Alias name: //')

CONTENTS="[]"
HAS_KEYS=false
HAS_CERTS=false

for alias in $ALIASES; do
  # Get entry type
  ENTRY_INFO=$(keytool -list -keystore "$KEYSTORE" -storepass "$PASSWORD" -alias "$alias" -v 2>/dev/null)

  if echo "$ENTRY_INFO" | grep -q "PrivateKeyEntry\|SecretKeyEntry"; then
    HAS_KEYS=true
    ENTRY_TYPE="key"

    if echo "$ENTRY_INFO" | grep -q "SecretKeyEntry"; then
      # Secret key - no cert info
      CERT_JSON=$(jq -n \
        --arg type "secretkey" \
        --arg alias "$alias" \
        '{type: $type, alias: $alias}')
      CONTENTS=$(echo "$CONTENTS" | jq --argjson cert "$CERT_JSON" '. += [$cert]')
      continue
    fi
  else
    ENTRY_TYPE="trustedcert"
  fi

  HAS_CERTS=true

  # Export cert to temp file
  keytool -exportcert -keystore "$KEYSTORE" -storepass "$PASSWORD" -alias "$alias" -file "$TMPDIR/$alias.der" 2>/dev/null
  openssl x509 -inform DER -in "$TMPDIR/$alias.der" -out "$TMPDIR/$alias.pem" 2>/dev/null

  if [ -f "$TMPDIR/$alias.pem" ]; then
    SERIAL=$(openssl x509 -in "$TMPDIR/$alias.pem" -serial -noout 2>/dev/null | cut -d= -f2)
    FINGERPRINT=$(openssl x509 -in "$TMPDIR/$alias.pem" -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2)
    NOTAFTER=$(openssl x509 -in "$TMPDIR/$alias.pem" -enddate -noout 2>/dev/null | cut -d= -f2)
    SUBJECT=$(openssl x509 -in "$TMPDIR/$alias.pem" -subject -noout 2>/dev/null | sed 's/subject=//')

    CERT_JSON=$(jq -n \
      --arg type "$ENTRY_TYPE" \
      --arg alias "$alias" \
      --arg expiration "$NOTAFTER" \
      --arg serial "$SERIAL" \
      --arg fingerprint "$FINGERPRINT" \
      --arg subject "$SUBJECT" \
      '{type: $type, alias: $alias, expiration: $expiration, serial: $serial, fingerprint: $fingerprint, subject: $subject}')

    CONTENTS=$(echo "$CONTENTS" | jq --argjson cert "$CERT_JSON" '. += [$cert]')
  fi
done

rm -rf "$TMPDIR"

# Determine overall type
if [ "$HAS_KEYS" = true ] && [ "$HAS_CERTS" = true ]; then
  TYPE="keystore"
elif [ "$HAS_KEYS" = true ]; then
  TYPE="keystore"
else
  TYPE="truststore"
fi

echo "$CONTENTS" | jq \
  --arg filename "$OUTPUT_FILENAME" \
  --arg format "$FORMAT" \
  --arg type "$TYPE" \
  --arg password "$STORE_PASSWORD" \
  '{filename: $filename, format: $format, type: $type, password: $password, contents: .}' \
  > "$OUTPUT_JSON"
