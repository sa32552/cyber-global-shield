import { AppShell } from "@/components/app-shell";
import { getIncident } from "@/lib/api";
import { currency, relativeDate } from "@/lib/format";

export default async function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const incident = await getIncident(id);
  const analysis = incident.analyses?.[0];

  return (
    <AppShell activePath="/">
      <div className="topbar">
        <div>
          <div className="brand">Incident Detail</div>
          <h1 className="headline">{incident.title}</h1>
          <p className="subtle">AI-guided root cause analysis with evidence, impact, and the exact next actions to execute.</p>
        </div>
      </div>

      <section className="metrics-grid">
        <div className="panel metric"><div className="metric-label">Severity</div><div className="metric-value">{incident.severityScore}</div><div className="metric-trend">Live blended severity</div></div>
        <div className="panel metric"><div className="metric-label">Error rate</div><div className="metric-value">{Math.round(incident.errorRate * 100)}%</div><div className="metric-trend">Across grouped events</div></div>
        <div className="panel metric"><div className="metric-label">Affected requests</div><div className="metric-value">{incident.affectedRequests}</div><div className="metric-trend">Customer operations at risk</div></div>
        <div className="panel metric"><div className="metric-label">Loss estimate</div><div className="metric-value">{currency(Number(incident.businessLossUsd))}</div><div className="metric-trend">Current modeled exposure</div></div>
      </section>

      <section className="grid-two">
        <div className="panel"><div className="panel-inner"><div className="section-title">AI Explanation</div><div style={{ fontSize: "1.2rem", lineHeight: 1.5 }}>{analysis?.explanation ?? "Analysis pending."}</div><div className="kpi-strip" style={{ marginTop: 18 }}><div className="kpi-row"><span>Root cause</span><strong>{analysis?.rootCause ?? "Pending"}</strong></div><div className="kpi-row"><span>Business impact</span><strong>{currency(Number(analysis?.businessImpactUsd ?? incident.businessLossUsd))}</strong></div><div className="kpi-row"><span>Confidence</span><strong>{analysis?.confidence ? `${Math.round(analysis.confidence * 100)}%` : "N/A"}</strong></div></div></div></div>
        <div className="panel"><div className="panel-inner"><div className="section-title">Recommended Actions</div><div className="timeline">{incident.actions.map((action: any) => <div key={action.id} className="timeline-item"><strong>{action.title}</strong><div className="subtle">Type: {action.type} • Status: {action.status}</div></div>)}</div></div></div>
      </section>

      <section className="grid-two" style={{ marginTop: 18 }}>
        <div className="panel"><div className="panel-inner"><div className="section-title">Logs Timeline</div><div className="timeline">{incident.logs.map((entry: any) => <div key={entry.log.id} className="timeline-item"><strong>{relativeDate(entry.log.timestamp)}</strong><div>{entry.log.message}</div><div className="subtle">{JSON.stringify(entry.log.metadata)}</div></div>)}</div></div></div>
        <div className="panel"><div className="panel-inner"><div className="section-title">Evidence</div><div className="code-block">{JSON.stringify(analysis?.evidence ?? [], null, 2)}</div></div></div>
      </section>
    </AppShell>
  );
}