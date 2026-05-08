#!/bin/bash
# =============================================================================
# Cyber Global Shield — Déploiement Automatisé sur Coolify
# =============================================================================
# Prérequis :
#   1. Un serveur VPS (Ubuntu 22.04+ recommandé)
#   2. Coolify installé sur le serveur
#   3. Docker et Docker Compose installés
#   4. Domaine configuré (optionnel)
# =============================================================================

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     🛡️ Cyber Global Shield — Déploiement Coolify           ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# Étape 1 : Vérification des prérequis
# =============================================================================
echo -e "\n${BLUE}[1/6] Vérification des prérequis...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker n'est pas installé. Installation...${NC}"
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose n'est pas installé. Installation...${NC}"
    sudo apt-get update && sudo apt-get install -y docker-compose-plugin
fi

echo -e "${GREEN}✅ Docker $(docker --version)${NC}"
echo -e "${GREEN}✅ Docker Compose $(docker-compose --version)${NC}"

# =============================================================================
# Étape 2 : Configuration de l'environnement
# =============================================================================
echo -e "\n${BLUE}[2/6] Configuration de l'environnement...${NC}"

# Générer les secrets
JWT_SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -hex 16)
CLICKHOUSE_PASSWORD=$(openssl rand -hex 16)
MLFLOW_DB_PASSWORD=$(openssl rand -hex 16)

# Créer le fichier .env
cat > .env << EOF
# =============================================================================
# Cyber Global Shield — Configuration de déploiement
# =============================================================================

# Environnement
ENVIRONMENT=production
LOG_LEVEL=INFO
TAG=latest

# API
JWT_SECRET=${JWT_SECRET}
CORS_ORIGINS=https://*.cyberglobalshield.io
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=60
ENABLE_HTTPS_REDIRECT=true

# Base de données
DATABASE_URL=postgresql://cgs_user:${MLFLOW_DB_PASSWORD}@postgres:5432/cyber_shield

# Cache
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
REDIS_PASSWORD=${REDIS_PASSWORD}

# Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:9092

# ClickHouse
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=cgs_user
CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD}
CLICKHOUSE_DB=cyber_shield

# MLflow
MLFLOW_TRACKING_URI=http://mlflow:5000
MLFLOW_DB_USER=cgs_user
MLFLOW_DB_PASSWORD=${MLFLOW_DB_PASSWORD}
MLFLOW_DB_HOST=postgres
S3_MODELS_BUCKET=cgs-models
S3_ENDPOINT_URL=http://minio:9000
AWS_ACCESS_KEY_ID=cgs_admin
AWS_SECRET_ACCESS_KEY=$(openssl rand -hex 32)

# URLs
API_URL=https://api.cyberglobalshield.io
WS_URL=wss://api.cyberglobalshield.io/ws
EOF

echo -e "${GREEN}✅ Fichier .env créé avec des secrets sécurisés${NC}"

# =============================================================================
# Étape 3 : Création des dossiers de données
# =============================================================================
echo -e "\n${BLUE}[3/6] Création des dossiers de données...${NC}"

mkdir -p data/{clickhouse,redis,postgres,minio,mlflow,vector,grafana,prometheus}
mkdir -p models logs backups

echo -e "${GREEN}✅ Dossiers de données créés${NC}"

# =============================================================================
# Étape 4 : Déploiement des services
# =============================================================================
echo -e "\n${BLUE}[4/6] Déploiement des services Docker...${NC}"

echo -e "${YELLOW}⚠️  Cela peut prendre 5-10 minutes pour le premier déploiement${NC}"

# Arrêter les services existants
docker-compose -f infra/coolify/docker-compose.coolify.yml down 2>/dev/null || true

# Démarrer les services
docker-compose -f infra/coolify/docker-compose.coolify.yml up -d --build

echo -e "${GREEN}✅ Services déployés${NC}"

# =============================================================================
# Étape 5 : Vérification de la santé
# =============================================================================
echo -e "\n${BLUE}[5/6] Vérification de la santé des services...${NC}"

SERVICES=("api:8000" "ml:8001" "soar:8002" "web:80" "clickhouse:8123" "redis:6379" "mlflow:5000")

for service in "${SERVICES[@]}"; do
    NAME="${service%%:*}"
    PORT="${service##*:}"
    
    echo -n "  ⏳ Vérification de $NAME (port $PORT)... "
    
    for i in {1..30}; do
        if curl -sf "http://localhost:$PORT/health" > /dev/null 2>&1 || \
           curl -sf "http://localhost:$PORT/ping" > /dev/null 2>&1 || \
           nc -z localhost "$PORT" 2>/dev/null; then
            echo -e "${GREEN}✅ OK${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}❌ TIMEOUT${NC}"
        fi
        sleep 2
    done
done

# =============================================================================
# Étape 6 : Résumé du déploiement
# =============================================================================
echo -e "\n${BLUE}[6/6] Résumé du déploiement${NC}"
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           🛡️ Cyber Global Shield — DÉPLOYÉ ! 🎉            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  📊 Dashboard SOC:        ${BLUE}http://localhost${NC}"
echo -e "  🔬 Dashboard Quantum:    ${BLUE}http://localhost/transcendent${NC}"
echo -e "  ⚡ API Backend:          ${BLUE}http://localhost:8000${NC}"
echo -e "  🧠 ML Service:          ${BLUE}http://localhost:8001${NC}"
echo -e "  🔐 SOAR Engine:         ${BLUE}http://localhost:8002${NC}"
echo -e "  📈 MLflow:              ${BLUE}http://localhost:5000${NC}"
echo -e "  📊 Grafana:             ${BLUE}http://localhost:3000${NC} (admin/cybershield)"
echo -e "  🗄️  ClickHouse:         ${BLUE}http://localhost:8123${NC}"
echo ""
echo -e "  ${YELLOW}📝 Fichier .env créé avec les secrets${NC}"
echo -e "  ${YELLOW}🔑 JWT Secret: ${JWT_SECRET:0:16}...${NC}"
echo ""
echo -e "  ${GREEN}Pour voir les logs :${NC}"
echo -e "    docker-compose -f infra/coolify/docker-compose.coolify.yml logs -f"
echo ""
echo -e "  ${GREEN}Pour arrêter :${NC}"
echo -e "    docker-compose -f infra/coolify/docker-compose.coolify.yml down"
echo ""
echo -e "  ${GREEN}Pour mettre à jour :${NC}"
echo -e "    docker-compose -f infra/coolify/docker-compose.coolify.yml pull"
echo -e "    docker-compose -f infra/coolify/docker-compose.coolify.yml up -d"
echo ""

# Afficher les conteneurs en cours d'exécution
echo -e "${BLUE}Conteneurs en cours d'exécution :${NC}"
docker-compose -f infra/coolify/docker-compose.coolify.yml ps
