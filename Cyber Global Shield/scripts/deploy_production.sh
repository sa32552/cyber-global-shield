#!/bin/bash
# =============================================================================
# Cyber Global Shield — Production Deployment Script
# =============================================================================
# Usage:
#   chmod +x scripts/deploy_production.sh
#   ./scripts/deploy_production.sh
#
# Prerequisites:
#   - Ubuntu 22.04+ / Debian 12+
#   - Docker & Docker Compose v2 installed
#   - Domain: cyberglobalshield.io (change in .env and nginx.conf)
#   - Ports 80/443 open in firewall
# =============================================================================

set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Cyber Global Shield — Production Deployment            ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Step 1: Check Prerequisites ─────────────────────────────────────────
echo -e "${YELLOW}[1/8] Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found. Installing...${NC}"
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo -e "${GREEN}✓ Docker installed${NC}"
else
    echo -e "${GREEN}✓ Docker $(docker --version)${NC}"
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose not found. Installing...${NC}"
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo -e "${GREEN}✓ Docker Compose installed${NC}"
else
    echo -e "${GREEN}✓ Docker Compose $(docker-compose --version)${NC}"
fi

# ─── Step 2: Create Directory Structure ──────────────────────────────────
echo -e "${YELLOW}[2/8] Creating directory structure...${NC}"

mkdir -p infra/docker/nginx/ssl
mkdir -p infra/docker/nginx/html
mkdir -p backups
mkdir -p data

echo -e "${GREEN}✓ Directories created${NC}"

# ─── Step 3: Configure Environment ───────────────────────────────────────
echo -e "${YELLOW}[3/8] Configuring environment...${NC}"

if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env from .env.example...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}⚠️  Please edit .env with your production credentials!${NC}"
    echo -e "${YELLOW}   Especially: SECRET_KEY, SUPABASE_*, OPENAI_API_KEY${NC}"
else
    echo -e "${GREEN}✓ .env file exists${NC}"
fi

# ─── Step 4: Generate SSL Certificates ───────────────────────────────────
echo -e "${YELLOW}[4/8] Setting up SSL certificates...${NC}"

DOMAIN="${DOMAIN:-cyberglobalshield.io}"

if [ ! -f "infra/docker/nginx/ssl/live/$DOMAIN/fullchain.pem" ]; then
    echo -e "${YELLOW}No SSL certificates found for $DOMAIN${NC}"
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  1) Auto with Let's Encrypt (requires DNS pointing to this server)"
    echo -e "  2) Use self-signed certificates (for testing)"
    echo -e "  3) Skip (will use HTTP only - NOT RECOMMENDED)"
    read -p "Choose [1/2/3]: " ssl_choice

    case $ssl_choice in
        1)
            echo -e "${YELLOW}Obtaining Let's Encrypt certificates...${NC}"
            # Start nginx temporarily for ACME challenge
            docker-compose -f docker-compose.prod.yml up -d nginx certbot
            docker-compose -f docker-compose.prod.yml exec certbot certbot certonly \
                --webroot -w /var/www/certbot \
                -d $DOMAIN -d api.$DOMAIN \
                --email admin@$DOMAIN \
                --agree-tos \
                --non-interactive
            echo -e "${GREEN}✓ SSL certificates obtained${NC}"
            ;;
        2)
            echo -e "${YELLOW}Generating self-signed certificates...${NC}"
            mkdir -p "infra/docker/nginx/ssl/live/$DOMAIN"
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "infra/docker/nginx/ssl/live/$DOMAIN/privkey.pem" \
                -out "infra/docker/nginx/ssl/live/$DOMAIN/fullchain.pem" \
                -subj "/CN=$DOMAIN"
            echo -e "${GREEN}✓ Self-signed certificates generated${NC}"
            ;;
        3)
            echo -e "${YELLOW}⚠️  Skipping SSL. Will use HTTP only!${NC}"
            ;;
    esac
else
    echo -e "${GREEN}✓ SSL certificates found${NC}"
fi

# ─── Step 5: Pull Docker Images ──────────────────────────────────────────
echo -e "${YELLOW}[5/8] Pulling Docker images...${NC}"

docker-compose -f docker-compose.prod.yml pull
echo -e "${GREEN}✓ Images pulled${NC}"

# ─── Step 6: Build Application ───────────────────────────────────────────
echo -e "${YELLOW}[6/8] Building application...${NC}"

docker-compose -f docker-compose.prod.yml build
echo -e "${GREEN}✓ Application built${NC}"

# ─── Step 7: Start Services ──────────────────────────────────────────────
echo -e "${YELLOW}[7/8] Starting services...${NC}"

# Start infrastructure first
echo -e "${YELLOW}  Starting infrastructure (Kafka, ClickHouse, Redis)...${NC}"
docker-compose -f docker-compose.prod.yml up -d zookeeper kafka clickhouse redis

# Wait for infrastructure to be healthy
echo -e "${YELLOW}  Waiting for infrastructure to be healthy...${NC}"
sleep 15

# Start remaining services
echo -e "${YELLOW}  Starting application services...${NC}"
docker-compose -f docker-compose.prod.yml up -d

echo -e "${GREEN}✓ Services started${NC}"

# ─── Step 8: Verify Deployment ───────────────────────────────────────────
echo -e "${YELLOW}[8/8] Verifying deployment...${NC}"

echo -e "${YELLOW}  Waiting for API to be ready...${NC}"
sleep 10

# Check API health
if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API is healthy${NC}"
else
    echo -e "${RED}✗ API health check failed${NC}"
    echo -e "${YELLOW}  Check logs: docker-compose -f docker-compose.prod.yml logs api${NC}"
fi

# Check all services
echo -e "${YELLOW}  Checking all services...${NC}"
docker-compose -f docker-compose.prod.yml ps

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Deployment Complete!                                    ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BLUE}║  API:          https://api.$DOMAIN/docs                     ║${NC}"
echo -e "${BLUE}║  Dashboard:    https://$DOMAIN                              ║${NC}"
echo -e "${BLUE}║  Grafana:      https://$DOMAIN/grafana                      ║${NC}"
echo -e "${BLUE}║  Prometheus:   https://$DOMAIN/prometheus                   ║${NC}"
echo -e "${BLUE}║  Ray Dashboard: http://localhost:8265                        ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BLUE}║  Useful commands:                                           ║${NC}"
echo -e "${BLUE}║  Logs:    docker-compose -f docker-compose.prod.yml logs -f ║${NC}"
echo -e "${BLUE}║  Restart: docker-compose -f docker-compose.prod.yml restart ║${NC}"
echo -e "${BLUE}║  Stop:    docker-compose -f docker-compose.prod.yml down    ║${NC}"
echo -e "${BLUE}║  Update:  docker-compose -f docker-compose.prod.yml up -d   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
