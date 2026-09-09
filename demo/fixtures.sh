#!/usr/bin/env bash
# Builds the demo certificate set used by the VHS tapes.
#
# Regenerated on every render so the "expires in N days" findings stay true.
# Everything is derived from a private config file, so the recording never
# depends on the operator's ~/.certdiag/certdiag.yaml.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
certdiag="$root/certdiag_app/dist/certdiag"

# Built outside the repo, in a neutral path: certdiag prints absolute paths in
# detail view, and a recording must not show the operator's home directory.
demo="${CERTDIAG_DEMO_DIR:-/tmp/certdiag-demo}"

[ -x "$certdiag" ] || { echo "build first: make build" >&2; exit 1; }

mkdir -p "$demo"
cat > "$demo.yaml" <<'YAML'
kind: certdiag-config
version: "1"
defaults:
  subject:
    organization: ""
passwords:
  common_plaintext:
    - changeit
YAML

export CERTDIAG_CONFIG="$demo.yaml"

cd "$demo"
find . -mindepth 1 -delete

cd_run() { "$certdiag" "$@" >/dev/null 2>&1; }
days_ago() { python3 -c "import datetime,sys;print((datetime.date.today()-datetime.timedelta(days=int(sys.argv[1]))).isoformat())" "$1"; }

# Root CA -> issuing CA, so the scan has a real chain to render.
cd_run create-cert --ca --subject 'CN=Example Root CA,O=Example Corp' --days 3650 \
  --with-key --key-output root-ca.key -o root-ca.crt --no-confirm
cd_run create-cert --ca --path-length 0 --subject 'CN=Example Issuing CA,O=Example Corp' --days 1825 \
  --with-key --key-output intermediate.key --sign-ca root-ca.crt --sign-key root-ca.key \
  -o intermediate.crt --no-confirm

# A healthy leaf with its key alongside.
cd_run create-cert --subject 'CN=api.example.com,O=Example Corp' \
  --san 'DNS:api.example.com,DNS:*.api.example.com' --days 365 \
  --with-key --key-output api.example.com.key \
  --sign-ca intermediate.crt --sign-key intermediate.key -o api.example.com.crt --no-confirm

# Critical: expires in 5 days.
cd_run create-cert --subject 'CN=www.example.com' --san 'DNS:www.example.com,DNS:example.com' \
  --not-before "$(days_ago 360)" --days 365 --with-key --key-output www.key \
  --sign-ca intermediate.crt --sign-key intermediate.key -o www.example.com.crt --no-confirm

# Warning: expires in 20 days.
cd_run create-cert --subject 'CN=mail.example.com' --san 'DNS:mail.example.com' \
  --not-before "$(days_ago 345)" --days 365 --with-key --key-output mail.key \
  --sign-ca intermediate.crt --sign-key intermediate.key -o mail.example.com.crt --no-confirm

# Critical: long expired.
cd_run create-cert --subject 'CN=legacy.example.com' --san 'DNS:legacy.example.com' \
  --not-before 2023-01-01 --days 30 --with-key --key-output legacy.key \
  --sign-ca intermediate.crt --sign-key intermediate.key -o legacy.example.com.crt --no-confirm

# Critical: RSA-1024. certdiag refuses to generate a key this weak, which is the
# point, so openssl makes it. Skipped if openssl is unavailable.
if command -v openssl >/dev/null 2>&1; then
  openssl genrsa -out weak.key 1024 2>/dev/null
  cd_run create-cert --subject 'CN=old-api.example.com' --san 'DNS:old-api.example.com' \
    -k weak.key --days 365 \
    --sign-ca intermediate.crt --sign-key intermediate.key -o old-api.example.com.crt --no-confirm
  rm -f weak.key
fi

# leaf + intermediate, so "verify the chain, not just the leaf" has a happy ending.
cd_run bundle api.example.com.crt intermediate.crt -o fullchain.pem -f pem --no-confirm

# Password-protected stores, so the scan has something locked to open.
cd_run bundle api.example.com.crt api.example.com.key intermediate.crt \
  -o keystore.p12 -f pkcs12 --output-password changeit --alias api --no-confirm
cd_run bundle root-ca.crt intermediate.crt \
  -o truststore.jks -f jks --output-password changeit --alias ca --no-confirm
# An older copy of the trust store, one anchor short, for the store diff demo.
cd_run bundle root-ca.crt \
  -o truststore-old.jks -f jks --output-password changeit --alias ca --no-confirm

# A TLS 1.3 capture plus its session keys, for the pcap demo.
cp "$root/tools/testing/testdata/tls13_keylog.pcap" capture.pcap
cp "$root/tools/testing/testdata/tls13.keylog" capture.keylog

# api.example.com keeps its key pair and the issuing CA keeps its key (the TUI
# renew demo signs with it); the other keys would be noise.
rm -f root-ca.key www.key mail.key legacy.key

echo "demo fixtures -> $demo (config: $demo.yaml)"
