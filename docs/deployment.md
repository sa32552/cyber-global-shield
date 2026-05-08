# Deployment Guide

## Local Docker deployment

```bash
docker compose up --build
```

Services:

- Dashboard: `http://localhost:3000`
- API: `http://localhost:4000/api/v1/health`
- AI Engine: `http://localhost:8000/health`

## Production recommendation

- Deploy `apps/web` on Vercel or another edge-friendly Next.js host
- Deploy `apps/api` on Kubernetes, ECS, Fly.io, or a container platform with autoscaling
- Deploy `apps/ai` separately so model traffic and retry policy are isolated from ingestion
- Use managed PostgreSQL and Redis
- Put webhook/API ingress behind an API gateway with tenant auth and rate limiting

## Required hardening before go-live

- Secret manager integration for per-tenant provider tokens
- JWT or managed auth provider
- Idempotency keys for webhook retries
- Background worker autoscaling
- Alert delivery retry policies
- Observability on the observability platform itself