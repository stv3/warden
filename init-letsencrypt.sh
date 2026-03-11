#!/usr/bin/env bash
# ── Warden — Let's Encrypt first-run certificate provisioning ──────────────────
#
# Run this once before starting Warden with HTTPS for the first time.
# After this succeeds, start the stack with:
#
#   docker compose -f docker-compose.yml -f docker-compose.https.yml up -d
#
# Usage:
#   chmod +x init-letsencrypt.sh
#   ./init-letsencrypt.sh
#
# Required environment variables (in .env or exported):
#   WARDEN_DOMAIN   — your domain, e.g. warden.yourdomain.com
#   CERTBOT_EMAIL   — email for expiry notices from Let's Encrypt

set -euo pipefail

# ── Load .env if present ───────────────────────────────────────────────────────
if [ -f .env ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' .env | grep -v '^$' | xargs)
fi

# ── Validate required variables ────────────────────────────────────────────────
if [ -z "${WARDEN_DOMAIN:-}" ]; then
    echo "ERROR: WARDEN_DOMAIN is not set."
    echo "       Add WARDEN_DOMAIN=yourdomain.example.com to your .env file."
    exit 1
fi

if [ -z "${CERTBOT_EMAIL:-}" ]; then
    echo "ERROR: CERTBOT_EMAIL is not set."
    echo "       Add CERTBOT_EMAIL=you@example.com to your .env file."
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Warden — Let's Encrypt certificate setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Domain : $WARDEN_DOMAIN"
echo "  Email  : $CERTBOT_EMAIL"
echo ""

# ── Create required directories ────────────────────────────────────────────────
mkdir -p ./certbot/conf ./certbot/www

# ── Check DNS before hitting Let's Encrypt rate limits ────────────────────────
echo "Checking DNS resolution for $WARDEN_DOMAIN..."
if ! host "$WARDEN_DOMAIN" > /dev/null 2>&1; then
    echo ""
    echo "WARNING: $WARDEN_DOMAIN does not resolve."
    echo "         Make sure your DNS A record points to this server's public IP"
    echo "         before continuing."
    echo ""
    read -rp "Continue anyway? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 1
fi

# ── Start nginx in HTTP-only mode for the ACME challenge ──────────────────────
echo ""
echo "Starting nginx (HTTP only) for ACME domain validation..."
docker compose up -d ui

# Wait for nginx to be ready
sleep 3

# ── Request the certificate ───────────────────────────────────────────────────
echo ""
echo "Requesting certificate from Let's Encrypt..."
docker compose run --rm certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --email "$CERTBOT_EMAIL" \
    --agree-tos \
    --no-eff-email \
    --domain "$WARDEN_DOMAIN"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Certificate obtained successfully!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo ""
echo "  # Bring down the temporary HTTP-only stack"
echo "  docker compose down"
echo ""
echo "  # Start the full HTTPS stack"
echo "  docker compose -f docker-compose.yml -f docker-compose.https.yml up -d"
echo ""
echo "  Warden will be available at: https://$WARDEN_DOMAIN"
echo ""
