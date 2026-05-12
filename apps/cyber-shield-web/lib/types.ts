// =============================================================================
// Cyber Global Shield — TypeScript Interfaces
// =============================================================================

// ---- Auth ----
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export interface ApiKeyResponse {
  api_key: string;
  created_at: string;
}

// ---- Dashboard ----
export interface DashboardOverview {
  status: string;
  timestamp: string;
  summary: {
    total_threats_blocked: number;
    active_alerts: number;
    critical_alerts: number;
    systems_monitored: number;
    compliance_score: number;
    uptime_percentage: number;
  };
  threat_trend: { date: string; count: number }[];
  alert_distribution: { severity: string; count: number }[];
  top_threats: { type: string; count: number; severity: string }[];
  recent_alerts: Alert[];
}

export interface Alert {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  timestamp: string;
  description: string;
  status: "open" | "investigating" | "resolved" | "dismissed";
  module: string;
}

export interface AlertSearchParams {
  severity?: string;
  status?: string;
  source?: string;
  limit?: number;
  offset?: number;
}

// ---- Ingestion ----
export interface LogEntry {
  timestamp: string;
  source: string;
  event_type: string;
  severity: string;
  message: string;
  src_ip?: string;
  dst_ip?: string;
  user?: string;
  protocol?: string;
  port?: number;
  raw?: Record<string, unknown>;
}

export interface IngestionStats {
  total_logs: number;
  logs_per_second: number;
  active_sources: string[];
  storage_used_gb: number;
  top_sources: { source: string; count: number }[];
}

// ---- ML Detection ----
export interface MLDetectionRequest {
  logs: LogEntry[];
}

export interface MLDetectionResult {
  anomaly_score: number;
  is_anomaly: boolean;
  threshold: number;
  explanation: string;
  detected_patterns: string[];
  severity: string;
  timestamp: string;
}

export interface MLCalibrateRequest {
  logs: LogEntry[];
  target_fpr?: number;
}

// ---- SOAR ----
export interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger: string;
  auto_execute: boolean;
  actions: PlaybookAction[];
  created_at: string;
  updated_at: string;
}

export interface PlaybookAction {
  id: string;
  type: string;
  name: string;
  params: Record<string, unknown>;
  order: number;
  rollback?: PlaybookAction;
}

export interface SOARExecuteRequest {
  playbook_id: string;
  alert_id: string;
  params?: Record<string, unknown>;
}

export interface SOARExecutionResult {
  execution_id: string;
  playbook_id: string;
  status: "running" | "completed" | "failed" | "rolled_back";
  started_at: string;
  completed_at?: string;
  actions: {
    action_id: string;
    status: string;
    result: Record<string, unknown>;
    duration_ms: number;
  }[];
  error?: string;
}

// ---- Agents ----
export interface AgentResult {
  agent: string;
  status: string;
  findings: string;
  confidence: number;
  recommendations: string[];
  duration_ms: number;
}

// ---- WebSocket Events ----
export interface WSEvent {
  type: string;
  data: Record<string, unknown>;
  timestamp: string;
}

// ---- System Health ----
export interface SystemHealth {
  status: "healthy" | "degraded" | "down";
  services: {
    api: string;
    kafka: string;
    clickhouse: string;
    redis: string;
    ray: string;
    fl_server: string;
  };
  uptime_seconds: number;
  version: string;
}

// ---- Settings ----
export interface PlatformSettings {
  app_name: string;
  version: string;
  environment: string;
  features: {
    ml_detection: boolean;
    federated_learning: boolean;
    quantum_modules: boolean;
    soar_auto_execute: boolean;
    threat_intel: boolean;
  };
}
