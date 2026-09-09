FROM alpine:latest AS generator

RUN apk add --no-cache openssl jq

WORKDIR /certs

RUN mkdir -p /output /scripts

COPY lib/*.sh /scripts/
RUN chmod +x /scripts/*.sh

# 1. Simple PKCS#12 with single certificate and key (RSA 2048)
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/simple.key \
    -out /certs/simple.crt \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=simple.example.com"

RUN openssl pkcs12 -export \
    -out /output/simple-rsa2048.p12 \
    -inkey /certs/simple.key \
    -in /certs/simple.crt \
    -name "Simple RSA 2048 Certificate" \
    -passout pass:password123
RUN /scripts/p12_to_json.sh /output/simple-rsa2048.p12 password123 simple-rsa2048.p12 pkcs12 /output/simple-rsa2048.json

# 2. PKCS#12 with certificate chain (RSA 4096)
RUN openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /certs/root.key \
    -out /certs/root.crt \
    -days 3650 \
    -subj "/C=US/ST=California/O=Example Root CA/CN=Root CA"

RUN openssl req -newkey rsa:4096 -nodes \
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

RUN openssl req -newkey rsa:4096 -nodes \
    -keyout /certs/leaf.key \
    -out /certs/leaf.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=chain.example.com"

RUN openssl x509 -req -in /certs/leaf.csr \
    -CA /certs/intermediate.crt -CAkey /certs/intermediate.key \
    -CAcreateserial -out /certs/leaf.crt \
    -days 365

RUN cat /certs/intermediate.crt /certs/root.crt > /certs/ca-bundle.crt

RUN openssl pkcs12 -export \
    -out /output/chain-rsa4096.p12 \
    -inkey /certs/leaf.key \
    -in /certs/leaf.crt \
    -certfile /certs/ca-bundle.crt \
    -name "Certificate with Chain" \
    -passout pass:chainpass456
RUN /scripts/p12_to_json.sh /output/chain-rsa4096.p12 chainpass456 chain-rsa4096.p12 pkcs12 /output/chain-rsa4096.json

# 3. PKCS#12 with ECDSA P-256 certificate
RUN openssl ecparam -name prime256v1 -genkey -noout -out /certs/ecdsa.key

RUN openssl req -new -x509 -key /certs/ecdsa.key \
    -out /certs/ecdsa.crt \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=ecdsa.example.com"

RUN openssl pkcs12 -export \
    -out /output/ecdsa-p256.p12 \
    -inkey /certs/ecdsa.key \
    -in /certs/ecdsa.crt \
    -name "ECDSA P-256 Certificate" \
    -passout pass:ecdsapass
RUN /scripts/p12_to_json.sh /output/ecdsa-p256.p12 ecdsapass ecdsa-p256.p12 pkcs12 /output/ecdsa-p256.json

# 4. PKCS#12 with multiple certificates and friendly names
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/multi1.key \
    -out /certs/multi1.crt \
    -days 365 \
    -subj "/C=US/ST=California/O=Example/CN=multi1.example.com"

RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/multi2.key \
    -out /certs/multi2.crt \
    -days 365 \
    -subj "/C=US/ST=California/O=Example/CN=multi2.example.com"

RUN openssl pkcs12 -export \
    -out /output/multi-cert.p12 \
    -inkey /certs/multi1.key \
    -in /certs/multi1.crt \
    -certfile /certs/multi2.crt \
    -name "Primary Certificate" \
    -passout pass:multipass
RUN /scripts/p12_to_json.sh /output/multi-cert.p12 multipass multi-cert.p12 pkcs12 /output/multi-cert.json

# 5. PKCS#12 with legacy encryption (3DES) for compatibility testing
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/legacy.key \
    -out /certs/legacy.crt \
    -days 365 \
    -subj "/C=US/ST=California/O=Example/CN=legacy.example.com"

RUN openssl pkcs12 -export \
    -out /output/legacy-3des.p12 \
    -inkey /certs/legacy.key \
    -in /certs/legacy.crt \
    -name "Legacy 3DES Certificate" \
    -keypbe PBE-SHA1-3DES \
    -certpbe PBE-SHA1-3DES \
    -passout pass:legacypass
RUN /scripts/p12_to_json.sh /output/legacy-3des.p12 legacypass legacy-3des.p12 pkcs12 /output/legacy-3des.json

# 6. PKCS#12 with modern encryption (AES-256)
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/modern.key \
    -out /certs/modern.crt \
    -days 365 \
    -subj "/C=US/ST=California/O=Example/CN=modern.example.com"

RUN openssl pkcs12 -export \
    -out /output/modern-aes256.p12 \
    -inkey /certs/modern.key \
    -in /certs/modern.crt \
    -name "Modern AES-256 Certificate" \
    -keypbe AES-256-CBC \
    -certpbe AES-256-CBC \
    -passout pass:modernpass
RUN /scripts/p12_to_json.sh /output/modern-aes256.p12 modernpass modern-aes256.p12 pkcs12 /output/modern-aes256.json

# Also export as .pfx extension (same format)
RUN cp /output/simple-rsa2048.p12 /output/simple-rsa2048.pfx
RUN cp /output/simple-rsa2048.json /output/simple-rsa2048.pfx.json && \
    sed -i 's/simple-rsa2048.p12/simple-rsa2048.pfx/g' /output/simple-rsa2048.pfx.json

FROM scratch
COPY --from=generator /output /
