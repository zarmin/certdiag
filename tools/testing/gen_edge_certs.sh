#!/usr/bin/env bash
# Generate the edge-case certificate fixtures used by
# certdiag_app/internal/certlib/edge_fixtures_test.go.
#
#   bash tools/testing/gen_edge_certs.sh
#
# Needs openssl 3.x. Generation-time only: the tests read the committed
# files. They live under internal/certlib/testdata/edge, not under
# tools/testing/edgecases/fixtures, because that tree is gitignored and
# regenerated wholesale by the harness.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=certdiag_app/internal/certlib/testdata/edge
mkdir -p "$OUT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/key.pem"
req() { openssl req -x509 -new -key "$TMP/key.pem" -days 3650 "$@"; }

# (An X.509 v1 certificate is built by hand in the test: OpenSSL 3 always
# adds key identifiers, which makes the result v3.)

# RSA-PSS signature, DSA key, Ed448 key.
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out "$TMP/pss.key" 2>/dev/null
openssl req -x509 -new -key "$TMP/pss.key" -subj /CN=rsa-pss.edge.test -days 3650 -out "$OUT/rsa-pss.crt"
openssl dsaparam -out "$TMP/dsap.pem" 2048 2>/dev/null
openssl gendsa -out "$TMP/dsa.key" "$TMP/dsap.pem" 2>/dev/null
openssl req -x509 -new -key "$TMP/dsa.key" -subj /CN=dsa.edge.test -days 3650 -out "$OUT/dsa.crt"
openssl genpkey -algorithm ed448 -out "$TMP/ed448.key"
openssl req -x509 -new -key "$TMP/ed448.key" -subj /CN=ed448.edge.test -days 3650 -out "$OUT/ed448.crt"

# Extensions Go does not decode: a critical unknown one, and the CT poison.
req -subj /CN=critical-unknown.edge.test -addext "1.2.3.4.5.6=critical,ASN1:UTF8String:certdiag" -out "$OUT/critical-unknown-ext.crt"
req -subj /CN=precert.edge.test -addext "1.3.6.1.4.1.11129.2.4.3=critical,ASN1:NULL" -out "$OUT/precert.crt"

# directoryName constraints need a config section.
cat > "$TMP/dirname.cnf" <<CNF
[req]
distinguished_name = dn
prompt = no
x509_extensions = ext
[dn]
CN = dirname-constraints.edge.test
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
nameConstraints = critical,permitted;dirName:permitted_dn
[permitted_dn]
C = HU
O = Example Org
CNF
req -config "$TMP/dirname.cnf" -out "$OUT/dirname-constraints.crt"

# 300 DNS SANs.
SANS=$(for i in $(seq 1 300); do printf 'DNS:host%03d.many.edge.test,' "$i"; done)
req -subj /CN=many-sans.edge.test -addext "subjectAltName=${SANS%,}" -out "$OUT/many-sans.crt"

# Non-ASCII subject, duplicated SANs, a SAN with a trailing dot.
req -utf8 -subj "/CN=测试.edge.test/O=Zsűri Kft./L=Zürich" -out "$OUT/non-ascii-dn.crt"
req -subj /CN=duplicate-sans.edge.test -addext "subjectAltName=DNS:dup.edge.test,DNS:dup.edge.test,IP:10.0.0.1,IP:10.0.0.1" -out "$OUT/duplicate-sans.crt"
req -subj /CN=trailing-dot.edge.test -addext "subjectAltName=DNS:trailing.edge.test." -out "$OUT/trailing-dot-san.crt"

# Validity far in the future (GeneralizedTime) and a negative serial.
openssl req -new -key "$TMP/key.pem" -subj /CN=notafter-9999.edge.test -out "$TMP/far.csr"
openssl x509 -req -in "$TMP/far.csr" -signkey "$TMP/key.pem" -not_before 20260101000000Z -not_after 99991231235959Z -out "$OUT/notafter-9999.crt" 2>/dev/null
openssl x509 -req -in "$TMP/far.csr" -signkey "$TMP/key.pem" -days 3650 -set_serial -1 -out "$OUT/negative-serial.crt" 2>/dev/null || echo "negative serial: openssl refused, fixture skipped"

ls -1 "$OUT"
