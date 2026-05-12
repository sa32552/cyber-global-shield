import type { Alert } from "@/lib/types";
import { formatRelativeTime, severityColor } from "@/lib/format";
import { StatusBadge } from "./status-badge";

interface AlertListProps {
  alerts: Alert[];
  maxItems?: number;
}

export function AlertList({ alerts, maxItems = 10 }: AlertListProps) {
  const displayed = alerts.slice(0, maxItems);

  if (displayed.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">✅</div>
        <div>Aucune alerte active</div>
      </div>
    );
  }

  return (
    <div>
      {displayed.map((alert) => (
        <div key={alert.id} className="alert-item">
          <div
            className="alert-severity-line"
            style={{ background: severityColor(alert.severity) }}
          />
          <div className="alert-content">
            <div className="alert-title">{alert.title}</div>
            <div className="alert-meta">
              <StatusBadge type="severity" value={alert.severity} />
              <span>{alert.source}</span>
              <span>{formatRelativeTime(alert.timestamp)}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
