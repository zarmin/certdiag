FROM eclipse-temurin:11-jre AS generator

RUN apt-get update && apt-get install -y openssl jq && rm -rf /var/lib/apt/lists/*

WORKDIR /certs

RUN mkdir -p /output /scripts

COPY lib/*.sh /scripts/
RUN chmod +x /scripts/*.sh

# 1. Simple JKS with self-signed certificate (RSA 2048)
RUN keytool -genkeypair \
    -alias simple-rsa2048 \
    -keyalg RSA \
    -keysize 2048 \
    -validity 365 \
    -dname "CN=simple.example.com,OU=IT,O=Example Corp,L=San Francisco,ST=California,C=US" \
    -keystore /output/simple-rsa2048.jks \
    -storepass password123 \
    -keypass password123
RUN /scripts/jks_to_json.sh /output/simple-rsa2048.jks password123 simple-rsa2048.jks jks /output/simple-rsa2048.json

# 2. JKS with RSA 4096 certificate
RUN keytool -genkeypair \
    -alias rsa4096-cert \
    -keyalg RSA \
    -keysize 4096 \
    -validity 365 \
    -dname "CN=rsa4096.example.com,OU=IT,O=Example Corp,L=San Francisco,ST=California,C=US" \
    -keystore /output/rsa4096.jks \
    -storepass strongpass456 \
    -keypass strongpass456
RUN /scripts/jks_to_json.sh /output/rsa4096.jks strongpass456 rsa4096.jks jks /output/rsa4096.json

# 3. JKS with multiple entries
RUN keytool -genkeypair \
    -alias web-server \
    -keyalg RSA \
    -keysize 2048 \
    -validity 365 \
    -dname "CN=web.example.com,OU=Web,O=Example Corp,C=US" \
    -keystore /output/multi-entry.jks \
    -storepass multipass789 \
    -keypass multipass789

RUN keytool -genkeypair \
    -alias api-server \
    -keyalg RSA \
    -keysize 2048 \
    -validity 365 \
    -dname "CN=api.example.com,OU=API,O=Example Corp,C=US" \
    -keystore /output/multi-entry.jks \
    -storepass multipass789 \
    -keypass multipass789
RUN /scripts/jks_to_json.sh /output/multi-entry.jks multipass789 multi-entry.jks jks /output/multi-entry.json

# 4. JKS with imported PKCS#12 (create PKCS#12 first, then import)
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/import.key \
    -out /certs/import.crt \
    -days 365 \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=import.example.com"

RUN openssl pkcs12 -export \
    -out /certs/import.p12 \
    -inkey /certs/import.key \
    -in /certs/import.crt \
    -name imported-cert \
    -passout pass:importpass

RUN keytool -importkeystore \
    -srckeystore /certs/import.p12 \
    -srcstoretype PKCS12 \
    -srcstorepass importpass \
    -destkeystore /output/imported-from-pkcs12.jks \
    -deststoretype JKS \
    -deststorepass jksimport123 \
    -destkeypass jksimport123
RUN /scripts/jks_to_json.sh /output/imported-from-pkcs12.jks jksimport123 imported-from-pkcs12.jks jks /output/imported-from-pkcs12.json

# 5. JKS with trusted CA certificates only
RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/ca1.key \
    -out /certs/ca1.crt \
    -days 3650 \
    -subj "/C=US/O=Example Root CA 1/CN=Root CA 1"

RUN openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /certs/ca2.key \
    -out /certs/ca2.crt \
    -days 3650 \
    -subj "/C=US/O=Example Root CA 2/CN=Root CA 2"

RUN keytool -importcert -noprompt \
    -alias root-ca-1 \
    -file /certs/ca1.crt \
    -keystore /output/truststore.jks \
    -storepass trustpass123

RUN keytool -importcert -noprompt \
    -alias root-ca-2 \
    -file /certs/ca2.crt \
    -keystore /output/truststore.jks \
    -storepass trustpass123
RUN /scripts/jks_to_json.sh /output/truststore.jks trustpass123 truststore.jks jks /output/truststore.json

# 6. JKS converted to PKCS#12 (showing migration path)
RUN keytool -importkeystore \
    -srckeystore /output/simple-rsa2048.jks \
    -srcstoretype JKS \
    -srcstorepass password123 \
    -destkeystore /output/jks-to-pkcs12.p12 \
    -deststoretype PKCS12 \
    -deststorepass converted123
RUN /scripts/p12_to_json.sh /output/jks-to-pkcs12.p12 converted123 jks-to-pkcs12.p12 pkcs12 /output/jks-to-pkcs12.p12.json

FROM scratch
COPY --from=generator /output /
