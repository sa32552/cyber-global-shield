// =============================================================================
// Cyber Global Shield — REST API Client
// Uses Supabase session token as Bearer token for API calls.
// =============================================================================

import type {
  LoginRequest,
  LoginResponse,
  ApiKeyResponse,
  DashboardOverview,
  Alert,
  AlertSearchParams,
  LogEntry,
  IngestionStats,
  MLDetectionRequest,
  MLDetectionResult,
  MLCalibrateRequest,
  Playbook,
  SOARExecuteRequest,
  SOARExecutionResult,
  AgentResult,
  SystemHealth,
  PlatformSettings,
} from "./types";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function getAccessToken(): Promise<string | null> {
  // Try localStorage first (set by login page)
  const storedToken =
    typeof window !== "undefined" ? localStorage.getItem("token") : null;
  if (storedToken) return storedToken;

  // Try Supabase session (browser only)
  if (typeof window !== "undefined") {
    try {
      const { createClient } = await import("@/lib/supabase/client");
      const supabase = createClient();
      const { data } = await supabase.auth.getSession();
      if (data.session?.access_token) {
        return data.session.access_token;
      }
    } catch {
      // Supabase client not available
    }
  }

  return null;
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = await getAccessToken();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
    cache: "no-store",
  });

  if (!response.ok) {
    const text = await response.text();
    throw new ApiError(response.status, text || `Request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

// ---- Auth ----
export const auth = {
  login: (data: LoginRequest) =>
    request<LoginResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  register: (data: { email: string; password: string; full_name?: string; org_name?: string }) =>
    request<{ id: string; email: string; org_id: string; role: string; message: string }>(
      "/api/v1/auth/register",
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),

  generateApiKey: () =>
    request<ApiKeyResponse>("/api/v1/auth/api-key", {
      method: "POST",
    }),

  me: () =>
    request<{
      id: string;
      username: string;
      email: string;
      role: string;
      org_id: string;
      permissions: string[];
    }>("/api/v1/auth/me"),

  logout: () =>
    request<{ message: string }>("/api/v1/auth/logout", {
      method: "POST",
    }),
};

// ---- Dashboard ----
export const dashboard = {
  overview: () => request<DashboardOverview>("/api/v1/dashboard/overview"),

  alerts: (params?: AlertSearchParams) => {
    const search = new URLSearchParams();
    if (params?.severity) search.set("severity", params.severity);
    if (params?.status) search.set("status", params.status);
    if (params?.source) search.set("source", params.source);
    if (params?.limit) search.set("limit", String(params.limit));
    if (params?.offset) search.set("offset", String(params.offset));
    const qs = search.toString();
    return request<Alert[]>(`/api/v1/dashboard/alerts${qs ? `?${qs}` : ""}`);
  },
};

// ---- Ingestion ----
export const ingestion = {
  ingestLog: (log: LogEntry) =>
    request<{ id: string }>("/api/v1/ingest/log", {
      method: "POST",
      body: JSON.stringify(log),
    }),

  ingestBatch: (logs: LogEntry[]) =>
    request<{ count: number }>("/api/v1/ingest/batch", {
      method: "POST",
      body: JSON.stringify({ logs }),
    }),

  stats: () => request<IngestionStats>("/api/v1/ingest/stats"),
};

// ---- ML Detection ----
export const ml = {
  detect: (data: MLDetectionRequest) =>
    request<MLDetectionResult>("/api/v1/ml/detect", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  calibrate: (data: MLCalibrateRequest) =>
    request<{ threshold: number }>("/api/v1/ml/calibrate", {
      method: "POST",
      body: JSON.stringify(data),
    }),
};

// ---- SOAR ----
export const soar = {
  listPlaybooks: () => request<Playbook[]>("/api/v1/soar/playbooks"),

  execute: (data: SOARExecuteRequest) =>
    request<SOARExecutionResult>("/api/v1/soar/execute", {
      method: "POST",
      body: JSON.stringify(data),
    }),
};

// ---- Agents ----
export const agents = {
  triage: (alert: Alert) =>
    request<AgentResult>("/api/v1/agents/triage", {
      method: "POST",
      body: JSON.stringify(alert),
    }),

  investigate: (alert: Alert) =>
    request<AgentResult>("/api/v1/agents/investigate", {
      method: "POST",
      body: JSON.stringify(alert),
    }),

  pipeline: (alert: Alert) =>
    request<AgentResult>("/api/v1/agents/pipeline", {
      method: "POST",
      body: JSON.stringify(alert),
    }),
};

// ---- System ----
export const system = {
  health: () => request<SystemHealth>("/health"),

  settings: () => request<PlatformSettings>("/"),
};
