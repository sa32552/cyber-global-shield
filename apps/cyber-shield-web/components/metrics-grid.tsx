import { formatNumber } from "@/lib/format";

interface Metric {
  label: string;
  value: number;
  change?: number;
  format?: "number" | "percent";
  color?: string;
}

interface MetricsGridProps {
  metrics: Metric[];
}

export function MetricsGrid({ metrics }: MetricsGridProps) {
  return (
    <div className="metrics-grid">
      {metrics.map((metric) => {
        const displayValue =
          metric.format === "percent"
            ? `${(metric.value * 100).toFixed(1)}%`
            : formatNumber(metric.value);

        return (
          <div key={metric.label} className="card metric-card">
            <div className="metric-label">{metric.label}</div>
            <div
              className="metric-value"
              style={metric.color ? { color: metric.color } : undefined}
            >
              {displayValue}
            </div>
            {metric.change !== undefined && (
              <div
                className={`metric-change ${metric.change >= 0 ? "positive" : "negative"}`}
              >
                {metric.change >= 0 ? "↑" : "↓"} {Math.abs(metric.change)}%
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
