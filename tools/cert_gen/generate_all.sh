#!/usr/bin/env bash

set -euxo pipefail

cd "$(dirname "$0")"
OUTPUT_DIR="./generated"

mkdir -p "${OUTPUT_DIR}"

CERT_TYPES=("pem" "der" "pkcs12" "jks" "pkcs7")

for cert_type in "${CERT_TYPES[@]}"; do
    output_path="${OUTPUT_DIR}/${cert_type}"
    mkdir -p "${output_path}"

    # Build with parent context (.) so lib folder is available
    docker build \
        -f "./${cert_type}/Dockerfile" \
        --output "type=local,dest=${output_path}" \
        .
done
