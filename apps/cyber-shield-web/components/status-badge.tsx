import { severityColor, severityLabel, statusColor, statusLabel } from "@/lib/format";

interface StatusBadgeProps {
  type: "severity" | "status";
  value: string;
}

export function StatusBadge({ type, value }: StatusBadgeProps) {
  if (type === "severity") {
    const color = severityColor(value);
    const label = severityLabel(value);
    return (
      <span className={`badge badge-${value}`}>
        <span className="badge-dot" style={{ background: color }} />
        {label}
      </span>
    );
  }

  const color = statusColor(value);
  const label = statusLabel(value);
  return (
    <span className="badge badge-info">
      <span className="badge-dot" style={{ background: color }} />
      {label}
    </span>
  );
}
