# 🚄 Déploiement Railway — Cyber Global Shield

## Architecture sur Railway

```
┌─────────────────────────────────────────────────────────────┐
│                     Railway.app                              │
│                                                              │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │  Backend (Python)   │    │  Frontend (Next.js)      │    │
│  │  cyber-shield-api   │◄──►│  cyber-shield-web        │    │
│  │  Port 8000          │    │  Port 3000               │    │
│  └─────────┬───────────┘    └──────────────────────────┘    │
│            │                                                 │
│            ▼                                                 │
│  ┌─────────────────────┐    ┌──────────────────────────┐    │
│  │  Supabase (externe) │    │  Redis (Railway)         │    │
│  │  (déjà créé)        │    │  (optionnel)             │    │
│  └─────────────────────┘    └──────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 Étape 1 : Préparer le projet

### 1.1 Pousser le code sur GitHub

```bash
# Créer un repo sur GitHub, puis :
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/TON_USER/cyber-global-shield.git
git push -u origin main
```

### 1.2 Créer un compte Railway

Va sur **[https://railway.app](https://railway.app)** et connecte-toi avec GitHub.

---

## 📋 Étape 2 : Déployer le Backend (Python/FastAPI)

### 2.1 Nouveau projet
1. Clique sur **"New Project"**
2. Choisis **"Deploy from GitHub repo"**
3. Sélectionne ton repo `cyber-global-shield`

### 2.2 Configurer le service backend
Railway va détecter automatiquement le [`railway.json`](railway.json) à la racine.

1. Railway va créer un service. Renomme-le en **`cyber-shield-api`**
2. Va dans l'onglet **"Variables"** et ajoute :

```
PORT=8000
SUPABASE_URL=https://ton-projet.supabase.co
SUPABASE_KEY=ton-anon-key
SUPABASE_SERVICE_ROLE_KEY=ton-service-role-key
SUPABASE_JWT_SECRET=ton-jwt-secret
NEXT_PUBLIC_SUPABASE_URL=https://ton-projet.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=ton-anon-key
REDIS_URL=redis://...  (optionnel, ajoute un service Redis Railway)
```

3. Va dans l'onglet **"Settings"** → **"Public Networking"** → active-le
4. Note l'URL générée : `https://cyber-shield-api.up.railway.app`

---

## 📋 Étape 3 : Déployer le Frontend (Next.js)

### 3.1 Ajouter un second service
1. Dans le même projet Railway, clique sur **"New"** → **"Service"**
2. Choisis **"Deploy from GitHub repo"** → même repo
3. Renomme-le en **`cyber-shield-web`**

### 3.2 Configurer le build
Va dans **Settings** → **"Root Directory"** → mets : `apps/cyber-shield-web`

### 3.3 Configurer les variables
Va dans **Variables** et ajoute :

```
NEXT_PUBLIC_SUPABASE_URL=https://ton-projet.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=ton-anon-key
NEXT_PUBLIC_API_URL=https://cyber-shield-api.up.railway.app
```

### 3.4 Activer le domaine public
**Settings** → **"Public Networking"** → active-le
Tu obtiendras : `https://cyber-shield-web.up.railway.app`

---

## 📋 Étape 4 : Vérifier le déploiement

### Backend
```
https://cyber-shield-api.up.railway.app/health
https://cyber-shield-api.up.railway.app/docs
```

### Frontend
```
https://cyber-shield-web.up.railway.app
```

---

## 📋 Étape 5 : Configurer Supabase (si pas déjà fait)

1. Va dans **Supabase → Authentication → Settings**
2. Ajoute l'URL du frontend dans les **redirect URLs** :
   - `https://cyber-shield-web.up.railway.app/**`

---

## 🎯 Résumé des URLs après déploiement

| Service | URL |
|---------|-----|
| Frontend Next.js | `https://cyber-shield-web.up.railway.app` |
| Backend API | `https://cyber-shield-api.up.railway.app` |
| API Docs (Swagger) | `https://cyber-shield-api.up.railway.app/docs` |
| Supabase | Ton projet Supabase existant |

---

## 💰 Tarifs Railway

| Plan | Prix | Limites |
|------|------|---------|
| **Starter** | **$0/mois** (gratuit) | $5 de crédit offert, 500h/mois |
| **Developer** | $5/mois | $5 de crédit, pas de limite de temps |
| **Pro** | $20/mois | $20 de crédit, priorités |

👉 **Le plan Starter gratuit suffit pour tester !** Tu as $5 de crédit offert sans donner de carte bancaire.

---

## ❌ En cas d'erreur

### Erreur : "No Dockerfile found"
→ Vérifie que le fichier [`Cyber Global Shield/Dockerfile`](Cyber%20Global%20Shield/Dockerfile) existe bien.

### Erreur : "Module not found"
→ Vérifie que [`requirements-render.txt`](Cyber%20Global%20Shield/requirements-render.txt) contient `supabase>=2.1.0`.

### Erreur : "Cannot connect to Supabase"
→ Vérifie les variables d'environnement SUPABASE_URL et SUPABASE_KEY.

### Erreur : Frontend blank
→ Vérifie que `NEXT_PUBLIC_API_URL` pointe bien vers l'URL du backend Railway.

---

## 🔄 Mise à jour automatique

Railway se reconnecte à ton repo GitHub. **À chaque `git push` sur `main`**, Railway redéploie automatiquement !

```bash
git add .
git commit -m "fix: correction bug"
git push
# → Railway redéploie automatiquement en 2-3 minutes
```
