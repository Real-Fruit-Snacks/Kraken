#!/bin/bash
# Generate certificates for Kraken mTLS
# Usage: ./gen-certs.sh [output_dir]

set -e

OUTPUT_DIR="${1:-./certs}"
mkdir -p "$OUTPUT_DIR"

echo "Generating CA certificate..."
openssl genrsa -out "$OUTPUT_DIR/ca.key" 4096
openssl req -new -x509 -days 3650 -key "$OUTPUT_DIR/ca.key" \
    -out "$OUTPUT_DIR/ca.crt" \
    -subj "/CN=Kraken CA/O=Kraken"

echo "Generating server certificate..."
openssl genrsa -out "$OUTPUT_DIR/server.key" 2048
openssl req -new -key "$OUTPUT_DIR/server.key" \
    -out "$OUTPUT_DIR/server.csr" \
    -subj "/CN=kraken-server/O=Kraken"
openssl x509 -req -days 365 -in "$OUTPUT_DIR/server.csr" \
    -CA "$OUTPUT_DIR/ca.crt" -CAkey "$OUTPUT_DIR/ca.key" \
    -CAcreateserial -out "$OUTPUT_DIR/server.crt"
rm "$OUTPUT_DIR/server.csr"

echo "Generating operator certificate..."
openssl genrsa -out "$OUTPUT_DIR/operator.key" 2048
openssl req -new -key "$OUTPUT_DIR/operator.key" \
    -out "$OUTPUT_DIR/operator.csr" \
    -subj "/CN=operator/O=Kraken"
openssl x509 -req -days 365 -in "$OUTPUT_DIR/operator.csr" \
    -CA "$OUTPUT_DIR/ca.crt" -CAkey "$OUTPUT_DIR/ca.key" \
    -CAcreateserial -out "$OUTPUT_DIR/operator.crt"
rm "$OUTPUT_DIR/operator.csr"

echo "Certificates generated in $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
