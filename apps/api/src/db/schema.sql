CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  avg_order_value NUMERIC(12,2) NOT NULL DEFAULT 120,
  conversion_rate NUMERIC(8,5) NOT NULL DEFAULT 0.035,
  revenue_per_request NUMERIC(12,4) NOT NULL DEFAULT 4.20,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE services (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  environment TEXT NOT NULL DEFAULT 'production',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, name)
);

CREATE TABLE logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  service_id UUID REFERENCES services(id) ON DELETE SET NULL,
  type TEXT NOT NULL CHECK (type IN ('error', 'metric', 'log')),
  external_id TEXT,
  fingerprint TEXT,
  timestamp TIMESTAMPTZ NOT NULL,
  message TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  incident_group_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE incident_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  service_id UUID REFERENCES services(id) ON DELETE SET NULL,
  cluster_key TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN',
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, cluster_key)
);

ALTER TABLE logs
  ADD CONSTRAINT fk_logs_incident_group
  FOREIGN KEY (incident_group_id) REFERENCES incident_groups(id) ON DELETE SET NULL;

CREATE TABLE incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  service_id UUID REFERENCES services(id) ON DELETE SET NULL,
  incident_group_id UUID REFERENCES incident_groups(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN',
  severity_score INTEGER NOT NULL CHECK (severity_score BETWEEN 0 AND 100),
  error_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
  affected_requests INTEGER NOT NULL DEFAULT 0,
  failed_requests INTEGER NOT NULL DEFAULT 0,
  business_loss_usd NUMERIC(12,2) NOT NULL DEFAULT 0,
  start_time TIMESTAMPTZ NOT NULL,
  end_time TIMESTAMPTZ,
  source TEXT NOT NULL DEFAULT 'mvp-rule-engine',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE incident_logs (
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  log_id UUID NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
  PRIMARY KEY (incident_id, log_id)
);

CREATE TABLE ai_analysis (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  root_cause TEXT NOT NULL,
  business_impact_usd NUMERIC(12,2) NOT NULL DEFAULT 0,
  severity INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 100),
  explanation TEXT NOT NULL,
  recommended_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
  evidence JSONB,
  confidence DOUBLE PRECISION,
  prompt_version TEXT NOT NULL DEFAULT 'v1',
  model TEXT NOT NULL DEFAULT 'gpt-5.4-mini',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('ROLLBACK', 'SCALE', 'FIX', 'NOTIFY')),
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'RECOMMENDED',
  executed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, provider)
);

CREATE INDEX idx_logs_project_timestamp ON logs(project_id, timestamp DESC);
CREATE INDEX idx_logs_service_timestamp ON logs(service_id, timestamp DESC);
CREATE INDEX idx_logs_fingerprint ON logs(fingerprint);
CREATE INDEX idx_incidents_project_status ON incidents(project_id, status);
CREATE INDEX idx_incidents_service_start ON incidents(service_id, start_time DESC);
CREATE INDEX idx_ai_analysis_incident_created ON ai_analysis(incident_id, created_at DESC);