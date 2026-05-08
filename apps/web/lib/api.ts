const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export interface Project {
  id: string;
  name: string;
  slug: string;
}

export const bootstrapDemoProject = async () =>
  jsonFetch<Project & { seededIncidentId?: string }>("/api/v1/projects/bootstrap-demo", { method: "POST" });

export const getProjects = async () => jsonFetch<Project[]>("/api/v1/projects/list");
export const getOverview = async (projectId: string) => jsonFetch<any>(`/api/v1/incidents/overview?projectId=${projectId}`);
export const getIncidents = async (projectId: string) => jsonFetch<any[]>(`/api/v1/incidents/list?projectId=${projectId}`);
export const getIncident = async (incidentId: string) => jsonFetch<any>(`/api/v1/incidents/${incidentId}`);
export const getServices = async (projectId: string) => jsonFetch<any[]>(`/api/v1/services/list?projectId=${projectId}`);
export const getAlerts = async (projectId: string) => jsonFetch<any[]>(`/api/v1/alerts/list?projectId=${projectId}`);