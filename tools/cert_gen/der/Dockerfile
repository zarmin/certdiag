FROM alpine:latest as generator

RUN apk add --no-cache openssl jq

WORKDIR /certs

RUN mkdir -p /output /scripts

COPY lib/*.sh /scripts/
RUN chmod +x /scripts/*.sh

# 1. RSA 2048 certificate in DER format
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/temp-rsa2048.key \
    -out /certs/temp-rsa2048.pem \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=rsa2048.example.com"

RUN openssl x509 -in /certs/temp-rsa2048.pem -outform DER -out /output/rsa2048.der
RUN openssl rsa -in /certs/temp-rsa2048.key -outform DER -out /output/rsa2048-key.der
RUN /scripts/cert_to_json.sh /certs/temp-rsa2048.pem rsa2048.der der /output/rsa2048.json
RUN /scripts/key_to_json.sh rsa2048-key.der der /output/rsa2048-key.json

# 2. RSA 4096 certificate in DER format
RUN openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /certs/temp-rsa4096.key \
    -out /certs/temp-rsa4096.pem \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=rsa4096.example.com"

RUN openssl x509 -in /certs/temp-rsa4096.pem -outform DER -out /output/rsa4096.der
RUN openssl rsa -in /certs/temp-rsa4096.key -outform DER -out /output/rsa4096-key.der
RUN /scripts/cert_to_json.sh /certs/temp-rsa4096.pem rsa4096.der der /output/rsa4096.json
RUN /scripts/key_to_json.sh rsa4096-key.der der /output/rsa4096-key.json

# 3. ECDSA P-256 certificate in DER format
RUN openssl ecparam -name prime256v1 -genkey -noout -out /certs/temp-ecdsa.key

RUN openssl req -new -x509 -key /certs/temp-ecdsa.key \
    -out /certs/temp-ecdsa.pem \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=ecdsa.example.com"

RUN openssl x509 -in /certs/temp-ecdsa.pem -outform DER -out /output/ecdsa-p256.der
RUN openssl ec -in /certs/temp-ecdsa.key -outform DER -out /output/ecdsa-p256-key.der
RUN /scripts/cert_to_json.sh /certs/temp-ecdsa.pem ecdsa-p256.der der /output/ecdsa-p256.json
RUN /scripts/key_to_json.sh ecdsa-p256-key.der der /output/ecdsa-p256-key.json

# 4. ECDSA P-384 certificate in DER format
RUN openssl ecparam -name secp384r1 -genkey -noout -out /certs/temp-ecdsa384.key

RUN openssl req -new -x509 -key /certs/temp-ecdsa384.key \
    -out /certs/temp-ecdsa384.pem \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=ecdsa384.example.com"

RUN openssl x509 -in /certs/temp-ecdsa384.pem -outform DER -out /output/ecdsa-p384.der
RUN openssl ec -in /certs/temp-ecdsa384.key -outform DER -out /output/ecdsa-p384-key.der
RUN /scripts/cert_to_json.sh /certs/temp-ecdsa384.pem ecdsa-p384.der der /output/ecdsa-p384.json
RUN /scripts/key_to_json.sh ecdsa-p384-key.der der /output/ecdsa-p384-key.json

# 5. Certificate Signing Request in DER format
RUN openssl req -new -newkey rsa:2048 -nodes \
    -keyout /certs/csr-key.pem \
    -out /certs/csr.pem \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=csr.example.com"

RUN openssl req -in /certs/csr.pem -outform DER -out /output/certificate-request.csr.der
RUN /scripts/csr_to_json.sh /certs/csr.pem certificate-request.csr.der der /output/certificate-request.csr.json

FROM scratch
COPY --from=generator /output /
