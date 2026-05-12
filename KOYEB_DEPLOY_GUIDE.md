# ☸️ Déploiement Koyeb — Cyber Global Shield (100% Gratuit, Sans Carte Bancaire)

## Pourquoi Koyeb ?

| Critère | Koyeb | Railway | Fly.io |
|---------|-------|---------|--------|
| **💰 Gratuit** | ✅ Oui | ⚠️ 500h/mois | ✅ Oui |
| **💳 Carte bancaire** | ❌ **Non requise** | ❌ Non requise | ⚠️ Requise |
| **⏰ Toujours actif** | ✅ Oui (1 service) | ❌ Dort après 15min | ✅ Oui |
| **💾 RAM** | 1GB | 1GB | 1GB |
| **🌍 Régions** | Europe, USA, Asie | USA, Europe | Monde entier |
| **🚀 Facilité** | Très simple (GitHub) | Simple | CLI nécessaire |

> ✅ **Koyeb est le meilleur choix si tu n'as pas de carte bancaire !**

---

## Architecture sur Koyeb

```
┌──────────────────────────────────────────────────────────────┐
│                         Koyeb                                 │
│                                                               │
│  ┌──────────────────────┐    ┌───────────────────────────┐   │
│  │  cyber-shield-api    │    │  cyber-shield-web         │   │
│  │  (Python FastAPI)    │◄──►│  (Next.js)                │   │
│  │  Port 8000           │    │  Port 3000                │   │
│  │  1GB RAM (gratuit)   │    │  1GB RAM (gratuit)        │   │
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

## 📋 Étape 1 : Créer un compte Koyeb

1. Va sur **[https://app.koyeb.com](https://app.koyeb.com)**
2. Clique **"Sign up"**
3. Choisis **"Sign up with GitHub"** (le plus simple)
4. ✅ **Aucune carte bancaire demandée**

---

## 📋 Étape 2 : Déployer le Backend (Python)

### 2.1 Créer un Web Service
1. Clique sur **"Create Web Service"**
2. **"Deploy from GitHub"** → sélectionne `sa32552/cyber-global-shield`
3. Configure le service :

```
┌─────────────────────────────────────────────────────┐
│  ⚙️ Service Configuration                            │
│                                                      │
│  Builder:      Dockerfile                            │
│  Dockerfile:   Cyber Global Shield/Dockerfile        │
│  Port:         8000                                  │
│  Command:      uvicorn app:app --host 0.0.0.0 --port 8000
│                                                      │
│  ─── Environment Variables ──────────────────────── │
│  PORT = 8000                                         │
│  SUPABASE_URL = https://ton-projet.supabase.co       │
│  SUPABASE_KEY = ton-anon-key                         │
│  SUPABASE_SERVICE_ROLE_KEY = ton-service-role-key    │
│  SUPABASE_JWT_SECRET = ton-jwt-secret                │
└─────────────────────────────────────────────────────┘
```

### 2.2 Lancer le déploiement
1. Clique **"Deploy"**
2. ⏱ Attends 3-5 minutes que le build termine
3. Une fois déployé, note l'URL : `https://cyber-shield-api-xxx.koyeb.app`

---

## 📋 Étape 3 : Déployer le Frontend (Next.js)

### 3.1 Créer un second Web Service
1. **"Create Web Service"** → **"Deploy from GitHub"** → même repo
2. Configure :

```
┌─────────────────────────────────────────────────────┐
│  ⚙️ Service Configuration                            │
│                                                      │
│  Builder:      Dockerfile                            │
│  Dockerfile:   apps/cyber-shield-web/Dockerfile      │
│  Port:         3000                                  │
│                                                      │
│  ─── Environment Variables ──────────────────────── │
│  PORT = 3000                                         │
│  NODE_ENV = production                               │
│  NEXT_PUBLIC_SUPABASE_URL = https://ton-projet.supabase.co
│  NEXT_PUBLIC_SUPABASE_ANON_KEY = ton-anon-key       │
│  NEXT_PUBLIC_API_URL = https://cyber-shield-api-xxx.koyeb.app
└─────────────────────────────────────────────────────┘
```

### 3.2 Lancer le déploiement
1. Clique **"Deploy"**
2. ⏱ Attends 3-5 minutes

---

## 📋 Étape 4 : Vérifier

| Service | URL |
|---------|-----|
| Frontend | `https://cyber-shield-web-xxx.koyeb.app` |
| Backend API | `https://cyber-shield-api-xxx.koyeb.app` |
| Swagger Docs | `https://cyber-shield-api-xxx.koyeb.app/docs` |
| Health Check | `https://cyber-shield-api-xxx.koyeb.app/health` |

---

## 📋 Étape 5 : Configurer Supabase

Va dans **Supabase → Authentication → Settings → Redirect URLs** et ajoute :
```
https://cyber-shield-web-xxx.koyeb.app/**
```

---

## 📋 Mise à jour après modifications

Quand tu modifies le code et push sur GitHub :

```bash
git add .
git commit -m "fix: correction bug"
git push
```

→ **Koyeb redéploie automatiquement** en 2-3 minutes ! ✅

---

## 💰 Limites gratuites Koyeb

| Ressource | Limite Gratuite |
|-----------|----------------|
| **Services** | 2 apps (1 toujours active, 1 qui dort) |
| **RAM** | 1GB par service |
| **Stockage** | 5GB |
| **Domaine** | ✅ `*.koyeb.app` avec HTTPS |
| **Carte bancaire** | ❌ **Pas nécessaire** |
| **Uptime** | ✅ 1 service toujours actif |

> ⚠️ **Astuce** : Le backend (API) doit être le service **toujours actif**. Le frontend peut se permettre de dormir (Next.js se réveille vite).

---

## ❌ Dépannage

### Erreur : "Dockerfile not found"
→ Vérifie le chemin exact :
- Backend : `Cyber Global Shield/Dockerfile`
- Frontend : `apps/cyber-shield-web/Dockerfile`

### Erreur : "Port not matching"
→ Vérifie que le port dans Koyeb correspond à `EXPOSE` dans le Dockerfile :
- Backend : port `8000`
- Frontend : port `3000`

### Erreur : "Cannot connect to Supabase"
→ Vérifie les variables d'environnement dans l'onglet **Settings** du service

### L'app est lente au premier appel (frontend)
→ Normal si le frontend s'est arrêté. Le backend reste actif grâce à la config.

---

## 📋 Comparaison finale

| Service | Gratuit | Carte bancaire | Toujours actif | Facilité |
|---------|---------|----------------|----------------|----------|
| **Koyeb** ✅ | ✅ 2 apps | ❌ Non | ✅ 1 service | ⭐ Très facile |
| **Fly.io** | ✅ 3 apps | ⚠️ Oui | ✅ Tous | ⭐⭐ CLI |
| **Railway** | ⚠️ 500h/mois | ❌ Non | ❌ Dort | ⭐ Très facile |
| **Render** | ✅ 2 apps | ❌ Non | ❌ Dort | ⭐ Très facile |

> **👉 Koyeb est le meilleur rapport qualité/prix pour toi : gratuit, sans carte bancaire, et 1 service toujours actif !**
