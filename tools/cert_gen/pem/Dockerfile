FROM alpine:latest AS generator

RUN apk add --no-cache openssl jq

WORKDIR /certs

RUN mkdir -p /output /scripts

COPY lib/*.sh /scripts/
RUN chmod +x /scripts/*.sh

# 1. Single certificate (RSA 2048)
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /output/single-rsa2048.key \
    -out /output/single-rsa2048.crt \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=example.com"
RUN /scripts/cert_to_json.sh /output/single-rsa2048.crt single-rsa2048.crt pem /output/single-rsa2048.crt.json
RUN /scripts/key_to_json.sh single-rsa2048.key pem /output/single-rsa2048.key.json

# 2. Certificate chain (RSA 4096) - Root -> Intermediate -> Leaf
RUN openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /certs/root.key \
    -out /output/root-ca.crt \
    -days 3650 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Root CA/CN=Root CA"
RUN /scripts/cert_to_json.sh /output/root-ca.crt root-ca.crt pem /output/root-ca.crt.json

RUN openssl req -newkey rsa:4096 -nodes \
    -keyout /certs/intermediate.key \
    -out /certs/intermediate.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Intermediate CA/CN=Intermediate CA"

RUN openssl x509 -req -in /certs/intermediate.csr \
    -CA /output/root-ca.crt -CAkey /certs/root.key \
    -CAcreateserial -out /output/intermediate-ca.crt \
    -days 1825 \
    -extfile /dev/stdin <<EOF
basicConstraints=CA:TRUE
keyUsage=keyCertSign,cRLSign
EOF
RUN /scripts/cert_to_json.sh /output/intermediate-ca.crt intermediate-ca.crt pem /output/intermediate-ca.crt.json

RUN openssl req -newkey rsa:4096 -nodes \
    -keyout /output/leaf-chain.key \
    -out /certs/leaf.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=secure.example.com"
RUN /scripts/key_to_json.sh leaf-chain.key pem /output/leaf-chain.key.json

RUN openssl x509 -req -in /certs/leaf.csr \
    -CA /output/intermediate-ca.crt -CAkey /certs/intermediate.key \
    -CAcreateserial -out /output/leaf.crt \
    -days 365
RUN /scripts/cert_to_json.sh /output/leaf.crt leaf.crt pem /output/leaf.crt.json

RUN cat /output/leaf.crt /output/intermediate-ca.crt /output/root-ca.crt > /output/full-chain.pem
RUN /scripts/bundle_to_json.sh /output/full-chain.pem full-chain.pem pem /output/full-chain.pem.json

# 3. ECDSA certificate and key
RUN openssl ecparam -name prime256v1 -genkey -noout -out /output/ecdsa-p256.key
RUN /scripts/key_to_json.sh ecdsa-p256.key pem /output/ecdsa-p256.key.json

RUN openssl req -new -x509 -key /output/ecdsa-p256.key \
    -out /output/ecdsa-p256.crt \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=ecdsa.example.com"
RUN /scripts/cert_to_json.sh /output/ecdsa-p256.crt ecdsa-p256.crt pem /output/ecdsa-p256.crt.json

# 4. Encrypted private key (AES-256)
RUN openssl req -x509 -newkey rsa:2048 \
    -keyout /output/encrypted-aes256.key \
    -out /output/encrypted-aes256.crt \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=encrypted.example.com" \
    -passout pass:secretpassword
RUN /scripts/cert_to_json.sh /output/encrypted-aes256.crt encrypted-aes256.crt pem /output/encrypted-aes256.crt.json
RUN /scripts/key_to_json.sh encrypted-aes256.key pem /output/encrypted-aes256.key.json secretpassword

# 5. Multiple concatenated objects (key + cert + chain)
RUN cat /output/leaf-chain.key /output/full-chain.pem > /output/combined-all.pem
RUN /scripts/bundle_to_json.sh /output/combined-all.pem combined-all.pem pem /output/combined-all.pem.json

# 6. Certificate with Subject Alternative Names
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /output/san-cert.key \
    -out /output/san-cert.crt \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=multi.example.com" \
    -extensions v3_req \
    -config /dev/stdin <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = multi.example.com
DNS.2 = www.example.com
DNS.3 = api.example.com
IP.1 = 192.168.1.100
EOF
RUN /scripts/cert_to_json.sh /output/san-cert.crt san-cert.crt pem /output/san-cert.crt.json
RUN /scripts/key_to_json.sh san-cert.key pem /output/san-cert.key.json

FROM scratch
COPY --from=generator /output /
