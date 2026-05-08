# Architecture

## Runtime topology

- `apps/api`: ingest, normalize, deduplicate, detect incidents, publish WebSocket updates, expose REST API
- `apps/ai`: LLM-facing analysis engine with strict structured JSON output
- `apps/web`: Next.js App Router dashboard for operators and engineering leadership
- PostgreSQL: multi-tenant source of truth
- Redis + BullMQ: async AI analysis and future alert fan-out

## Processing flow

1. External tool posts to `POST /api/v1/ingest/*`
2. API normalizes events into the canonical event shape
3. Noise filtering removes health/readiness spam
4. Fingerprinting and clustering assign events into incident groups
5. Threshold/spike detection creates or updates incidents
6. Incident is queued for AI analysis
7. AI result writes to `ai_analysis` and generates recommended actions
8. WebSocket broadcasts incident and analysis updates to dashboards

## Multi-tenant design

- Every log, service, incident, and integration is scoped by `project_id`
- Revenue assumptions live at the project level for business-loss modeling
- Integration configs are project-scoped and ready for per-tenant secrets management

## Future enterprise extensions

- Role-based auth and SCIM/SAML
- Kafka or Kinesis-based high-volume ingestion
- Feature flags for custom detection policies
- Fine-grained retention tiers and cold storage
- Audit trails and approval workflows for recommended actions