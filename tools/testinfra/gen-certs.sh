#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/certs" && pwd)"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

DAYS_VALID=3650

echo "=== Generating Test CA ==="
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -days $DAYS_VALID \
    -subj "/CN=Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "=== Generating server cert (localhost) ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
cat > server_ext.cnf <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $DAYS_VALID -extfile server_ext.cnf

echo "=== Generating expired cert ==="
openssl genrsa -out expired.key 2048
openssl req -new -key expired.key -out expired.csr -subj "/CN=expired.localhost"
cat > expired_ext.cnf <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:expired.localhost,DNS:localhost,IP:127.0.0.1,IP:::1
EOF

# Try modern openssl flags first, fall back to openssl ca
if openssl x509 -req -in expired.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out expired.crt -extfile expired_ext.cnf \
    -not_before 20200101000000Z -not_after 20200102000000Z 2>/dev/null; then
    echo "  Created expired cert with -not_before/-not_after"
else
    echo "  Using openssl ca fallback for expired cert..."
    mkdir -p demoCA/newcerts
    touch demoCA/index.txt
    echo "01" > demoCA/serial
    cat > ca_expired.cnf <<'CACNF'
[ca]
default_ca = CA_default
[CA_default]
dir = ./demoCA
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
default_md = sha256
policy = policy_anything
copy_extensions = copy
[policy_anything]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
CACNF
    openssl ca -batch -config ca_expired.cnf \
        -cert ca.crt -keyfile ca.key \
        -startdate 20200101000000Z -enddate 20200102000000Z \
        -in expired.csr -out expired.crt -extfile expired_ext.cnf -notext
    rm -rf demoCA ca_expired.cnf
    echo "  Created expired cert with openssl ca"
fi

echo "=== Generating self-signed cert ==="
openssl genrsa -out selfsigned.key 2048
openssl req -new -x509 -key selfsigned.key -out selfsigned.crt -days $DAYS_VALID \
    -subj "/CN=selfsigned.localhost" \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:selfsigned.localhost,DNS:localhost,IP:127.0.0.1,IP:::1"

echo "=== Generating wrong-host cert ==="
openssl genrsa -out wronghost.key 2048
openssl req -new -key wronghost.key -out wronghost.csr -subj "/CN=wrong.example.com"
cat > wronghost_ext.cnf <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:wrong.example.com
EOF
openssl x509 -req -in wronghost.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out wronghost.crt -days $DAYS_VALID -extfile wronghost_ext.cnf

echo "=== Generating client cert (for mTLS) ==="
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=test-client"
cat > client_ext.cnf <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days $DAYS_VALID -extfile client_ext.cnf

echo "=== Generating intermediate CA + leaf-only cert (incomplete chain) ==="
openssl genrsa -out intermediate.key 2048
openssl req -new -key intermediate.key -out intermediate.csr -subj "/CN=Test Intermediate CA"
cat > intermediate_ext.cnf <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
openssl x509 -req -in intermediate.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out intermediate.crt -days $DAYS_VALID -extfile intermediate_ext.cnf

openssl genrsa -out leafonly.key 2048
openssl req -new -key leafonly.key -out leafonly.csr -subj "/CN=leafonly.localhost"
cat > leafonly_ext.cnf <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:leafonly.localhost,DNS:localhost,IP:127.0.0.1,IP:::1
EOF
openssl x509 -req -in leafonly.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
    -out leafonly.crt -days $DAYS_VALID -extfile leafonly_ext.cnf

echo "=== Generating wrong client cert (self-signed, for mTLS rejection test) ==="
openssl genrsa -out wrongclient.key 2048
openssl req -new -x509 -key wrongclient.key -out wrongclient.crt -days $DAYS_VALID \
    -subj "/CN=wrong-client" \
    -addext "basicConstraints=CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=clientAuth"

echo "=== Generating revocable certs + CRL + OCSP index (M24) ==="
# A small CA database driven off the main ca.crt/ca.key, used to issue two leaf
# certs that carry AIA OCSP + CRL Distribution Point URLs pointing at the docker
# services (OCSP responder on :14560, CRL server on :14561). One leaf is revoked.
# The revca/index.txt this produces is what the openssl OCSP responder serves,
# and crl/test.crl is what the CRL server serves. Both are kept (not cleaned up).
REVCA="$CERT_DIR/revca"
rm -rf "$REVCA"
mkdir -p "$REVCA/newcerts" "$CERT_DIR/crl"
touch "$REVCA/index.txt"
echo "1000" > "$REVCA/serial"
echo "1000" > "$REVCA/crlnumber"

cat > revca.cnf <<EOF
[ca]
default_ca = CA_default
[CA_default]
dir = $REVCA
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $CERT_DIR/ca.crt
private_key = $CERT_DIR/ca.key
default_md = sha256
default_days = $DAYS_VALID
default_crl_days = 30
policy = policy_anything
x509_extensions = leaf_exts
copy_extensions = copy
[policy_anything]
commonName = supplied
countryName = optional
stateOrProvinceName = optional
organizationName = optional
organizationalUnitName = optional
emailAddress = optional
[leaf_exts]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
authorityInfoAccess = OCSP;URI:http://localhost:14560
crlDistributionPoints = URI:http://localhost:14561/test.crl
EOF

for name in revocable-good revocable-revoked; do
    openssl genrsa -out "$name.key" 2048
    openssl req -new -key "$name.key" -out "$name.csr" -subj "/CN=$name.localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:$name.localhost,IP:127.0.0.1"
    openssl ca -batch -config revca.cnf -in "$name.csr" -out "$name.crt" -notext
    # nginx must present the issuer so the client can verify OCSP/CRL signatures.
    cat "$name.crt" ca.crt > "$name-chain.crt"
done

openssl ca -batch -config revca.cnf -revoke revocable-revoked.crt -crl_reason keyCompromise
openssl ca -batch -config revca.cnf -gencrl -out "$CERT_DIR/crl/test.crl"

echo "=== Cleanup temp files ==="
rm -f *.csr *.cnf *.srl *.old 2>/dev/null || true

echo "=== Generated certs ==="
ls -la "$CERT_DIR"/*.crt "$CERT_DIR"/*.key
echo ""
echo "=== Verifying certs ==="
for f in ca.crt server.crt expired.crt selfsigned.crt wronghost.crt client.crt intermediate.crt leafonly.crt wrongclient.crt; do
    if [ -f "$f" ]; then
        subject=$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/subject=//')
        echo "  $f: $subject"
    else
        echo "  $f: MISSING"
    fi
done
