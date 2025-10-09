#!/bin/bash

# Production deployment script for Oauth Contacts and calendar exporter (Podman)
set -e

echo "🚀 Oauth Contacts and calendar exporter - Production Deployment (Podman)"
echo "=============================================================="

# Check prerequisites
command -v podman >/dev/null 2>&1 || { echo "❌ Podman is required but not installed. Aborting." >&2; exit 1; }
command -v podman-compose >/dev/null 2>&1 || { echo "❌ Podman Compose is required but not installed. Aborting." >&2; exit 1; }

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "✅ Created .env file from template"
        echo "📝 Please edit .env file with your configuration:"
        echo "   - DOMAIN: your domain name"
        echo "   - ACME_EMAIL: your email for Let's Encrypt"
        echo "   - GOOGLE_ENCRYPTION_KEY: generate using the command below"
        echo ""
        echo "🔑 Generate encryption key:"
        echo "   python3 -c \"from cryptography.fernet import Fernet; print('GOOGLE_ENCRYPTION_KEY=' + Fernet.generate_key().decode())\""
        echo ""
        echo "📋 Then run this script again to deploy"
        exit 1
    else
        echo "❌ .env.example file not found. Please create .env file manually."
        exit 1
    fi
fi

# Source environment variables
source .env

# Validate required environment variables
if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "your-domain.com" ]; then
    echo "❌ Please set DOMAIN in .env file"
    exit 1
fi


if [ -z "$GOOGLE_ENCRYPTION_KEY" ] || [ "$GOOGLE_ENCRYPTION_KEY" = "your-encryption-key-here" ]; then
    echo "❌ Please set GOOGLE_ENCRYPTION_KEY in .env file"
    echo "🔑 Generate one using: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    exit 1
fi

echo "✅ Configuration validated"
echo "🌐 Domain: $DOMAIN"

# Check if services are already running
if podman-compose ps | grep -q "Up"; then
    echo "⚠️  Services are already running"
    read -p "Do you want to restart them? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🔄 Stopping existing services..."
        podman-compose down
    else
        echo "ℹ️  Keeping existing services running"
        exit 0
    fi
fi

# Generate Traefik configuration with environment variables
echo "⚙️  Generating Traefik configuration..."
cat > traefik-dynamic.yml << EOF
# Traefik Dynamic Configuration (Generated)
http:
  routers:
    # Main application router
    contacts:
      rule: "Host(\`${DOMAIN}\`)"
      entryPoints:
        - websecure
        - web
      middlewares:
        - security-headers
      service: contacts
      tls:
        certResolver: letsencrypt

  middlewares:
    # Security headers
    security-headers:
      headers:
        customRequestHeaders:
          X-Forwarded-Proto: "https"
        customResponseHeaders:
          X-Content-Type-Options: "nosniff"
          X-Frame-Options: "DENY"
          X-XSS-Protection: "1; mode=block"
          Strict-Transport-Security: "max-age=31536000; includeSubDomains"

  services:
    contacts:
      loadBalancer:
        servers:
          - url: "http://google-contacts-downloader:8000"
EOF

# Build and start services
echo "🏗️  Building and starting services..."
podman-compose up -d --build

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check service health
echo "🏥 Checking service health..."
for i in {1..30}; do
    if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
        echo "✅ Service is healthy!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Service health check failed after 30 attempts"
        echo "📋 Checking logs..."
        podman-compose logs --tail=20 google-contacts-downloader
        exit 1
    fi
    echo "   Attempt $i/30..."
    sleep 2
done

# Display status
echo ""
echo "🎉 Deployment completed successfully!"
echo "=================================================="
echo "🌍 Application URL: http://localhost:8000 (or https://$DOMAIN:8443 with reverse proxy)"
echo "📊 Health Check: http://localhost:8000/health"
echo "📈 Metrics: http://localhost:8000/metrics"

echo ""
echo "⚠️  Note: Rootless Podman uses non-privileged ports:"
echo "   - HTTP: 8000 (instead of 80)"
echo "   - HTTPS: 8443 (instead of 443)"
echo "   - You may need to set up port forwarding or reverse proxy"

echo ""
echo "📋 Service Status:"
podman-compose ps

echo ""
echo "📖 Useful Commands:"
echo "   View logs: podman-compose logs -f"
echo "   Stop services: podman-compose down"
echo "   Restart: podman-compose restart"
echo "   Update: podman-compose pull && podman-compose up -d --build"

echo ""
echo "⚠️  Don't forget to:"
echo "   1. Backup your encryption key securely"
echo "   2. Set up monitoring for the health endpoint"
echo "   3. Configure regular database backups"