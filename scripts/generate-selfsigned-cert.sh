#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# generate-selfsigned-cert.sh
#
# Generates a self-signed TLS certificate for local / private network use.
# The resulting cert enables HTTPS without requiring a public domain or
# internet connectivity.
#
# NOTE: Self-signed certs cause browser warnings. They are appropriate for:
#   • Local development
#   • Air-gapped / private network deployments
#   • Testing and CI
#
# For internet-accessible deployments use Let's Encrypt (docker-compose.https.yml).
#
# Usage:
#   chmod +x scripts/generate-selfsigned-cert.sh
#   ./scripts/generate-selfsigned-cert.sh [hostname]
#
# Examples:
#   ./scripts/generate-selfsigned-cert.sh              # defaults to localhost
#   ./scripts/generate-selfsigned-cert.sh warden.local
#   ./scripts/generate-selfsigned-cert.sh 192.168.1.50
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

HOSTNAME="${1:-localhost}"
SSL_DIR="ssl/selfsigned"
DAYS=3650  # 10-year cert — fine for self-signed internal use

echo "Generating self-signed certificate for: ${HOSTNAME}"
echo "Output directory: ${SSL_DIR}"

mkdir -p "${SSL_DIR}"

# Build SubjectAltName — include both DNS and IP if the arg looks like an IP
SAN="DNS:${HOSTNAME},DNS:localhost"
if [[ "${HOSTNAME}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN="${SAN},IP:${HOSTNAME},IP:127.0.0.1"
fi

openssl req -x509 \
    -nodes \
    -days "${DAYS}" \
    -newkey rsa:4096 \
    -keyout "${SSL_DIR}/key.pem" \
    -out    "${SSL_DIR}/cert.pem" \
    -subj   "/CN=${HOSTNAME}/O=Warden/OU=Self-Signed" \
    -addext "subjectAltName=${SAN}" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

chmod 600 "${SSL_DIR}/key.pem"
chmod 644 "${SSL_DIR}/cert.pem"

echo ""
echo "Certificate generated:"
echo "  Certificate : ${SSL_DIR}/cert.pem"
echo "  Private key : ${SSL_DIR}/key.pem"
echo ""
echo "To start Warden with HTTPS (self-signed):"
echo "  docker compose -f docker-compose.yml -f docker-compose.selfsigned.yml up -d"
echo ""
echo "To trust this certificate in your browser:"
echo "  macOS : sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${SSL_DIR}/cert.pem"
echo "  Linux : sudo cp ${SSL_DIR}/cert.pem /usr/local/share/ca-certificates/warden.crt && sudo update-ca-certificates"
echo "  Or import ${SSL_DIR}/cert.pem manually into your browser's trust store."
