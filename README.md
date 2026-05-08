# AI Incident Layer

AI Incident Layer is a multi-tenant incident intelligence SaaS that ingests logs, metrics, and errors from tools like Sentry, Datadog, CloudWatch, and Kubernetes, then turns them into business impact, probable root cause, severity, and recommended actions.

## Monorepo

- `apps/api`: Node.js + TypeScript backend API, ingestion, incidents, alerts, WebSockets
- `apps/web`: Next.js dashboard
- `apps/ai`: Python FastAPI AI analysis service
- `packages/shared`: shared types and contracts
- `infra/docker`: Docker and Compose assets
- `docs`: architecture and integration notes

## Quick start

1. Copy `.env.example` values as needed.
2. Run `docker compose up --build`.
3. Open `http://localhost:3000` for the dashboard.
4. API will be available on `http://localhost:4000`.
5. AI service will be available on `http://localhost:8000`.