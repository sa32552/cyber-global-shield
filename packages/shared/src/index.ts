export type NormalizedEventType = "error" | "metric" | "log";

export interface NormalizedEvent {
  type: NormalizedEventType;
  service: string;
  timestamp: number;
  message: string;
  metadata: Record<string, unknown>;
}

export interface Incident {
  id: string;
  service: string;
  severityScore: number;
  errorRate: number;
  affectedRequests: number;
  startTime: string;
  status: "open" | "investigating" | "resolved";
}

export interface AIAnalysisResult {
  root_cause: string;
  business_impact_usd: number;
  severity: number;
  explanation: string;
  recommended_actions: string[];
  confidence?: number;
  evidence?: string[];
}

export interface IncidentDetail extends Incident {
  logs: NormalizedEvent[];
  analysis?: AIAnalysisResult;
  actions: Array<{
    id: string;
    type: "rollback" | "scale" | "notify" | "fix";
    title: string;
    status: "pending" | "recommended" | "executed";
  }>;
}

export interface OverviewMetrics {
  totalIncidents: number;
  activeIncidents: number;
  totalLossUsd: number;
  mttrMinutes: number;
}