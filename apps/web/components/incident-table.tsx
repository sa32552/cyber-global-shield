import Link from "next/link";
import { currency, relativeDate } from "@/lib/format";

export function IncidentTable({ incidents }: { incidents: any[] }) {
  return (
    <div className="incident-list">
      {incidents.map((incident) => {
        const latestAnalysis = incident.analyses?.[0];
        return (
          <Link href={`/incidents/${incident.id}`} key={incident.id} className="incident-row">
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span className={`badge ${incident.severityScore >= 75 ? "high" : ""}`}>Severity {incident.severityScore}</span>
                <span className="live-dot" />
              </div>
              <div style={{ marginTop: 12, fontSize: "1.04rem", fontWeight: 600 }}>{incident.title}</div>
              <div className="subtle" style={{ marginTop: 6 }}>
                {latestAnalysis?.rootCause ?? "AI analysis pending"}
              </div>
            </div>
            <div>
              <div className="metric-label">Service</div>
              <div>{incident.service?.name ?? "Unknown"}</div>
            </div>
            <div>
              <div className="metric-label">Loss / hr</div>
              <div>{currency(Number(incident.businessLossUsd))}</div>
            </div>
            <div>
              <div className="metric-label">Started</div>
              <div>{relativeDate(incident.startTime)}</div>
            </div>
          </Link>
        );
      })}
    </div>
  );
}