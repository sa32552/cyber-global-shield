# 🛡️ Cyber Global Shield — Déploiement sur Coolify

## 📋 Prérequis

1. **Un compte GitHub** avec le projet Cyber Global Shield
2. **Un serveur VPS** (Ubuntu 22.04+ recommandé) ou **Coolify Cloud**
3. **Coolify installé** sur ton serveur (ou utiliser coolify.io)

---

## 🚀 Étape 1 : Installer Coolify (si self-hosted)

```bash
# Connexion SSH à ton serveur
ssh root@ton-serveur-ip

# Installer Coolify (1 commande)
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash

# Accéder à Coolify
# Ouvre http://TON_IP:8000 dans ton navigateur
```

> **Alternative plus simple :** Utilise [Coolify Cloud](https://coolify.io) — pas besoin de serveur !

---

## 🚀 Étape 2 : Connecter GitHub à Coolify

1. Ouvre Coolify dans ton navigateur
2. Va dans **Settings → Source**
3. Clique sur **"Connect GitHub"**
4. Autorise l'accès à ton repository Cyber Global Shield

---

## 🚀 Étape 3 : Créer le Projet

1. Dans Coolify, clique sur **"New Project"**
2. Nomme-le : `Cyber Global Shield`
3. Clique sur **"New Resource" → "Docker Compose"**
4. Sélectionne ton repository GitHub
5. Dans **"Compose File Path"**, entre : `infra/coolify/docker-compose.coolify.yml`
6. Coolify va détecter automatiquement tous les services :

```
✅ api       → FastAPI Backend (port 8000)
✅ ml        → ML Service (port 8001)
✅ soar      → SOAR Engine (port 8002)
✅ web       → Frontend Nginx (port 80/443)
✅ clickhouse → Analytics Database
✅ redis     → Cache
✅ mlflow    → Model Registry
✅ vector    → Log Aggregator
```

---

## 🚀 Étape 4 : Configurer les Variables d'Environnement

Dans Coolify, pour chaque service, ajoute ces variables :

### Service `api` :
```
ENVIRONMENT=production
JWT_SECRET=<généré automatiquement>
CORS_ORIGINS=https://*.ton-domaine.com
```

### Service `web` :
```
API_URL=https://api.ton-domaine.com
WS_URL=wss://api.ton-domaine.com/ws
```

### Service `clickhouse` :
```
CLICKHOUSE_USER=cgs_user
CLICKHOUSE_PASSWORD=<mot de passe sécurisé>
CLICKHOUSE_DB=cyber_shield
```

### Service `redis` :
```
REDIS_PASSWORD=<mot de passe sécurisé>
```

---

## 🚀 Étape 5 : Déployer !

1. Clique sur **"Deploy"**
2. Coolify va :
   - 🔨 Builder les images Docker
   - 🚀 Démarrer tous les services
   - 🔒 Configurer HTTPS automatiquement (Let's Encrypt)
   - 📊 Activer le monitoring

⏱️ **Premier déploiement :** 5-10 minutes
⏱️ **Déploiements suivants :** 1-2 minutes

---

## ✅ Étape 6 : Vérifier le Déploiement

Une fois déployé, tu auras accès à :

| Service | URL | Description |
|---|---|---|
| 🌐 **Dashboard SOC** | `https://ton-domaine.com` | Interface principale |
| 🔬 **Dashboard Quantum** | `https://ton-domaine.com/transcendent` | Dashboard quantique |
| ⚡ **API Backend** | `https://api.ton-domaine.com` | API REST |
| 🧠 **ML Service** | `https://ml.ton-domaine.com` | Machine Learning |
| 🔐 **SOAR Engine** | `https://soar.ton-domaine.com` | Security Automation |
| 📈 **MLflow** | `https://mlflow.ton-domaine.com` | Model Registry |
| 📊 **Grafana** | `https://grafana.ton-domaine.com` | Monitoring |
| 🗄️ **ClickHouse** | `https://clickhouse.ton-domaine.com` | Analytics DB |

---

## 🔄 Mise à Jour Automatique

Coolify détecte les push GitHub et redéploie automatiquement :

```bash
# 1. Faire les modifications
git add .
git commit -m "fix: correction bug détection"
git push

# 2. Coolify détecte le push et redéploie automatiquement ✅
```

---

## 📊 Monitoring

Coolify fournit :
- ✅ Logs en temps réel
- ✅ Métriques CPU/RAM
- ✅ Alertes de santé
- ✅ Redémarrage automatique en cas de crash

---

## 🎯 Résumé

```
┌─────────────────────────────────────────────┐
│          🛡️ Cyber Global Shield             │
│              DÉPLOYÉ SUR COOLIFY !           │
├─────────────────────────────────────────────┤
│                                             │
│  🌐 https://ton-domaine.com                 │
│     ↓                                       │
│  📦 Coolify (Orchestrateur)                 │
│     ↓                                       │
│  🐳 Docker Compose (18 services)            │
│     ↓                                       │
│  ☁️ VPS / Cloud                             │
│                                             │
└─────────────────────────────────────────────┘
```

---

## 💡 Pro Tips

1. **Domaine personnalisé** : Coolify gère HTTPS automatiquement
2. **Backups** : Active les backups dans Coolify → Settings → Backup
3. **Scaling** : Augmente les ressources dans `docker-compose.coolify.yml`
4. **CI/CD** : Les push GitHub déclenchent le déploiement automatique
5. **Gratuit** : Coolify est open-source et gratuit !
