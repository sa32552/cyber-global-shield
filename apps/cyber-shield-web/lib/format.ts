// =============================================================================
// Cyber Global Shield — Formatting Utilities
// =============================================================================

export function formatNumber(value: number): string {
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(1)}M`;
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(1)}K`;
  }
  return value.toLocaleString();
}

export function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

export function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleString("fr-FR", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelativeTime(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = now - then;

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `il y a ${days}j`;
  if (hours > 0) return `il y a ${hours}h`;
  if (minutes > 0) return `il y a ${minutes}min`;
  return "à l'instant";
}

export function severityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "#ef4444";
    case "high":
      return "#f97316";
    case "medium":
      return "#eab308";
    case "low":
      return "#22c55e";
    default:
      return "#6b7280";
  }
}

export function severityLabel(severity: string): string {
  switch (severity) {
    case "critical":
      return "Critique";
    case "high":
      return "Élevée";
    case "medium":
      return "Moyenne";
    case "low":
      return "Basse";
    default:
      return "Info";
  }
}

export function statusColor(status: string): string {
  switch (status) {
    case "healthy":
    case "completed":
      return "#22c55e";
    case "degraded":
    case "running":
      return "#eab308";
    case "down":
    case "failed":
      return "#ef4444";
    case "rolled_back":
      return "#f97316";
    default:
      return "#6b7280";
  }
}

export function statusLabel(status: string): string {
  switch (status) {
    case "open":
      return "Ouvert";
    case "investigating":
      return "En investigation";
    case "resolved":
      return "Résolu";
    case "dismissed":
      return "Ignoré";
    case "running":
      return "En cours";
    case "completed":
      return "Terminé";
    case "failed":
      return "Échoué";
    case "rolled_back":
      return "Rollback";
    default:
      return status;
  }
}
