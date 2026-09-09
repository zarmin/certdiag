FROM alpine:latest AS generator

RUN apk add --no-cache openssl jq

WORKDIR /certs

RUN mkdir -p /output /scripts

COPY lib/*.sh /scripts/
RUN chmod +x /scripts/*.sh

# Create a certificate chain first
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/root.key \
    -out /certs/root.crt \
    -days 3650 \
    -subj "/C=US/ST=California/O=Example Root CA/CN=Root CA"

RUN openssl req -newkey rsa:2048 -nodes \
    -keyout /certs/intermediate.key \
    -out /certs/intermediate.csr \
    -subj "/C=US/ST=California/O=Example Intermediate CA/CN=Intermediate CA"

RUN openssl x509 -req -in /certs/intermediate.csr \
    -CA /certs/root.crt -CAkey /certs/root.key \
    -CAcreateserial -out /certs/intermediate.crt \
    -days 1825 \
    -extfile /dev/stdin <<EOF
basicConstraints=CA:TRUE
keyUsage=keyCertSign,cRLSign
EOF

RUN openssl req -newkey rsa:2048 -nodes \
    -keyout /certs/leaf.key \
    -out /certs/leaf.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=server.example.com"

RUN openssl x509 -req -in /certs/leaf.csr \
    -CA /certs/intermediate.crt -CAkey /certs/intermediate.key \
    -CAcreateserial -out /certs/leaf.crt \
    -days 365

# 1. PKCS#7 with single certificate (DER format)
RUN openssl crl2pkcs7 -nocrl \
    -certfile /certs/leaf.crt \
    -out /output/single-cert.p7b \
    -outform DER
RUN /scripts/p7_to_json.sh /output/single-cert.p7b DER single-cert.p7b pkcs7 /output/single-cert.json

# 2. PKCS#7 with single certificate (PEM format)
RUN openssl crl2pkcs7 -nocrl \
    -certfile /certs/leaf.crt \
    -out /output/single-cert-pem.p7b \
    -outform PEM
RUN /scripts/p7_to_json.sh /output/single-cert-pem.p7b PEM single-cert-pem.p7b pkcs7 /output/single-cert-pem.json

# 3. PKCS#7 with certificate chain (DER format)
RUN cat /certs/leaf.crt /certs/intermediate.crt /certs/root.crt > /certs/chain.pem

RUN openssl crl2pkcs7 -nocrl \
    -certfile /certs/chain.pem \
    -out /output/cert-chain.p7b \
    -outform DER
RUN /scripts/p7_to_json.sh /output/cert-chain.p7b DER cert-chain.p7b pkcs7 /output/cert-chain.json

# 4. PKCS#7 with certificate chain (PEM format)
RUN openssl crl2pkcs7 -nocrl \
    -certfile /certs/chain.pem \
    -out /output/cert-chain-pem.p7c \
    -outform PEM
RUN /scripts/p7_to_json.sh /output/cert-chain-pem.p7c PEM cert-chain-pem.p7c pkcs7 /output/cert-chain-pem.json

# 5. PKCS#7 with multiple separate certificates (not a chain)
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/cert1.key \
    -out /certs/cert1.crt \
    -days 365 \
    -subj "/C=US/O=Example Corp/CN=cert1.example.com"

RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/cert2.key \
    -out /certs/cert2.crt \
    -days 365 \
    -subj "/C=US/O=Example Corp/CN=cert2.example.com"

RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/cert3.key \
    -out /certs/cert3.crt \
    -days 365 \
    -subj "/C=US/O=Example Corp/CN=cert3.example.com"

RUN cat /certs/cert1.crt /certs/cert2.crt /certs/cert3.crt > /certs/multiple.pem

RUN openssl crl2pkcs7 -nocrl \
    -certfile /certs/multiple.pem \
    -out /output/multiple-certs.p7b \
    -outform DER
RUN /scripts/p7_to_json.sh /output/multiple-certs.p7b DER multiple-certs.p7b pkcs7 /output/multiple-certs.json

# 6. PKCS#7 with CA bundle
RUN cat /certs/intermediate.crt /certs/root.crt > /certs/ca-bundle.pem

RUN openssl crl2pkcs7 -nocrl \
    -certfile /certs/ca-bundle.pem \
    -out /output/ca-bundle.p7b \
    -outform DER
RUN /scripts/p7_to_json.sh /output/ca-bundle.p7b DER ca-bundle.p7b pkcs7 /output/ca-bundle.json

# 7. Signed PKCS#7 (CMS) with data
RUN echo "This is signed data for testing" > /certs/data.txt

RUN openssl smime -sign \
    -in /certs/data.txt \
    -text \
    -signer /certs/leaf.crt \
    -inkey /certs/leaf.key \
    -out /output/signed-data.p7s \
    -outform DER
RUN /scripts/p7_to_json.sh /output/signed-data.p7s DER signed-data.p7s pkcs7 /output/signed-data.json

RUN openssl smime -sign \
    -in /certs/data.txt \
    -text \
    -signer /certs/leaf.crt \
    -inkey /certs/leaf.key \
    -out /output/signed-data-pem.p7s \
    -outform PEM
RUN /scripts/p7_to_json.sh /output/signed-data-pem.p7s PEM signed-data-pem.p7s pkcs7 /output/signed-data-pem.json

FROM scratch
COPY --from=generator /output /
