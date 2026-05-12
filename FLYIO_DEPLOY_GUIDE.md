# 🪰 Déploiement Fly.io — Cyber Global Shield (100% Gratuit)

## Pourquoi Fly.io ?

| Critère | Fly.io | Railway |
|---------|--------|---------|
| **Gratuit** | ✅ 3 apps, toujours actives | ❌ 500h/mois (~20 jours) |
| **Ne dort jamais** | ✅ Oui (configuré) | ❌ Dort après 15min |
| **RAM** | 3GB gratuits | 1GB gratuit |
| **Stockage** | 3GB | 1GB |
| **Carte bancaire** | Requise (mais 0€ facturé) | Non requise |

---

## Architecture sur Fly.io

```
┌──────────────────────────────────────────────────────────────┐
│                         Fly.io                                │
│                                                               │
│  ┌──────────────────────┐    ┌───────────────────────────┐   │
│  │  cyber-shield-api    │    │  cyber-shield-web         │   │
│  │  (Python FastAPI)    │◄──►│  (Next.js)                │   │
│  │  Port 8000           │    │  Port 3000                │   │
│  │  1GB RAM, 1 CPU      │    │  1GB RAM, 1 CPU           │   │
│  └──────────┬───────────┘    └───────────────────────────┘   │
│             │                                                 │
│             ▼                                                 │
│  ┌──────────────────────┐                                     │
│  │  Supabase (externe)  │                                     │
│  │  (déjà créé)         │                                     │
│  └──────────────────────┘                                     │
└──────────────────────────────────────────────────────────────┘
```

---

## 📋 Étape 1 : Installer Fly CLI

### Sur Windows (PowerShell en administrateur)
```powershell
iwr https://fly.io/install.ps1 -useb | iex
```

### Sur macOS/Linux
```bash
curl -L https://fly.io/install.sh | sh
```

### Vérifier l'installation
```bash
fly version
```

---

## 📋 Étape 2 : Se connecter à Fly.io

```bash
fly auth login
```
→ Cela ouvre ton navigateur. Connecte-toi avec GitHub.

---

## 📋 Étape 3 : Déployer le Backend (Python)

```bash
# Aller dans le dossier du backend
cd Cyber Global Shield

# Créer l'app sur Fly.io
fly launch --name cyber-shield-api --no-deploy

# Configurer les variables d'environnement (remplace par TES valeurs Supabase)
fly secrets set SUPABASE_URL=https://ton-projet.supabase.co
fly secrets set SUPABASE_KEY=ton-anon-key
fly secrets set SUPABASE_SERVICE_ROLE_KEY=ton-service-role-key
fly secrets set SUPABASE_JWT_SECRET=ton-jwt-secret
fly secrets set PORT=8000

# Déployer !
fly deploy
```

⏱ **Attends 2-3 minutes** que le build termine.

### Vérifier
```bash
# Tester l'API
fly curl http://cyber-shield-api.fly.dev/health

# Voir les logs
fly logs
```

---

## 📋 Étape 4 : Déployer le Frontend (Next.js)

```bash
# Aller dans le dossier du frontend
cd apps/cyber-shield-web

# Créer l'app sur Fly.io
fly launch --name cyber-shield-web --no-deploy

# Configurer les variables
fly secrets set NEXT_PUBLIC_SUPABASE_URL=https://ton-projet.supabase.co
fly secrets set NEXT_PUBLIC_SUPABASE_ANON_KEY=ton-anon-key
fly secrets set NEXT_PUBLIC_API_URL=https://cyber-shield-api.fly.dev

# Déployer !
fly deploy
```

⏱ **Attends 2-3 minutes.**

---

## 📋 Étape 5 : Vérifier le déploiement

| Service | URL |
|---------|-----|
| Frontend | `https://cyber-shield-web.fly.dev` |
| Backend API | `https://cyber-shield-api.fly.dev` |
| Swagger Docs | `https://cyber-shield-api.fly.dev/docs` |
| Health Check | `https://cyber-shield-api.fly.dev/health` |

---

## 📋 Étape 6 : Configurer Supabase (redirect URLs)

Va dans **Supabase → Authentication → Settings → Redirect URLs** et ajoute :
```
https://cyber-shield-web.fly.dev/**
```

---

## 📋 Commandes utiles

```bash
# Voir les logs en temps réel
fly logs -a cyber-shield-api
fly logs -a cyber-shield-web

# Redémarrer une app
fly restart -a cyber-shield-api

# Voir le status
fly status -a cyber-shield-api

# Mettre à jour après un git push
fly deploy -a cyber-shield-api
fly deploy -a cyber-shield-web

# Supprimer une app (si plus besoin)
fly apps destroy cyber-shield-api
```

---

## 📋 Mise à jour après modifications

Quand tu modifies le code et push sur GitHub :

```bash
# 1. Pull les dernières modifs
git pull

# 2. Redéployer le backend
cd Cyber Global Shield
fly deploy

# 3. Redéployer le frontend
cd apps/cyber-shield-web
fly deploy
```

---

## 💰 Limites gratuites Fly.io

| Ressource | Limite Gratuite |
|-----------|----------------|
| **Apps** | 3 machines (3 apps) |
| **RAM totale** | 3GB (1GB par app) |
| **Stockage** | 3GB total |
| **Trafic** | 160GB/mois |
| **Uptime** | ✅ Toujours actif (ne dort pas) |
| **Domaine** | ✅ `*.fly.dev` avec HTTPS automatique |

> ⚠️ **Carte bancaire requise** pour vérifier l'identité, mais tu ne seras pas facturé tant que tu restes dans les limites gratuites.

---

## ❌ Dépannage

### Erreur : "No space left on device"
```bash
fly scale storage 3gb -a cyber-shield-api
```

### Erreur : "Connection refused"
→ Vérifie que le port est bien `8000` pour le backend et `3000` pour le frontend dans les `fly.toml`

### Erreur : "Cannot find module"
→ Vérifie que le `Dockerfile` du frontend existe dans `apps/cyber-shield-web/Dockerfile`

### L'app est lente au premier appel
→ Fly.io garde les apps actives (configuré avec `auto_stop_machines = false`), donc pas de latence.
