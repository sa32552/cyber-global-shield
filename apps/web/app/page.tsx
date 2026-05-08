import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { IncidentTable } from "@/components/incident-table";
import { RealtimeClient } from "@/components/realtime-client";
import { bootstrapDemoProject, getIncidents, getOverview } from "@/lib/api";
import { currency } from "@/lib/format";

export default async function Page() {
  const project = await bootstrapDemoProject();
  const [overview, incidents] = await Promise.all([getOverview(project.id), getIncidents(project.id)]);
  const critical = incidents[0];

  return (
    <AppShell activePath="/">
      <RealtimeClient projectId={project.id} />
      <div className="topbar">
        <div>
          <div className="brand">Operational Command</div>
          <h1 className="headline">Turn outage noise into business action.</h1>
          <p className="subtle">
            AI Incident Layer converts raw telemetry into dollar impact, likely root cause, and the next move your incident commander should make.
          </p>
        </div>
      </div>

      <section className="hero-band">
        <div className="panel">
          <div className="panel-inner">
            <div className="section-title">Critical Incident</div>
            <div style={{ fontSize: "2rem", maxWidth: "16ch", lineHeight: 1 }}>{critical?.title}</div>
            <p className="subtle">{critical?.analyses?.[0]?.explanation ?? "Analysis in progress."}</p>
            <div className="kpi-strip">
              <div className="kpi-row"><span>Most likely cause</span><strong>{critical?.analyses?.[0]?.rootCause ?? "Pending"}</strong></div>
              <div className="kpi-row"><span>Recommended action</span><strong>{critical?.analyses?.[0]?.recommendedActions?.[0] ?? "Await AI recommendation"}</strong></div>
              <div className="kpi-row"><span>Projected loss</span><strong>{currency(Number(critical?.businessLossUsd ?? 0))} / hr</strong></div>
            </div>
            {critical ? (
              <div style={{ marginTop: 16 }}>
                <Link href={`/incidents/${critical.id}`} className="nav-link active">Open incident room</Link>
              </div>
            ) : null}
          </div>
        </div>
        <div className="panel">
          <div className="panel-inner">
            <div className="section-title">Live Triage</div>
            <div className="code-block">
              {`severity_score: ${critical?.severityScore ?? 0}\nerror_rate: ${critical?.errorRate ?? 0}\naffected_requests: ${critical?.affectedRequests ?? 0}\nfailed_requests: ${critical?.failedRequests ?? 0}\nstatus: ${critical?.status ?? "OPEN"}`}
            </div>
          </div>
        </div>
      </section>

      <section className="metrics-grid">
        <div className="panel metric"><div className="metric-label">Total incidents</div><div className="metric-value">{overview.totalIncidents}</div><div className="metric-trend">Historical footprint across the project</div></div>
        <div className="panel metric"><div className="metric-label">Active incidents</div><div className="metric-value">{overview.activeIncidents}</div><div className="metric-trend">Open now and affecting customers</div></div>
        <div className="panel metric"><div className="metric-label">Estimated loss</div><div className="metric-value">{currency(overview.totalLossUsd)}</div><div className="metric-trend">Business impact mapped from failure volume</div></div>
        <div className="panel metric"><div className="metric-label">MTTR</div><div className="metric-value">{overview.mttrMinutes}m</div><div className="metric-trend">Average time to recover</div></div>
      </section>

      <section className="grid-two">
        <div className="panel"><div className="panel-inner"><div className="section-title">Incident Feed</div><IncidentTable incidents={incidents} /></div></div>
        <div className="panel"><div className="panel-inner"><div className="section-title">Operator Notes</div><div className="timeline"><div className="timeline-item"><strong>Business-first scoring</strong><div className="subtle">Each incident blends technical severity with revenue-weighted impact.</div></div><div className="timeline-item"><strong>Evidence-bound AI</strong><div className="subtle">The analysis engine is instructed to rely only on supplied logs, metrics, and deployment context.</div></div><div className="timeline-item"><strong>Immediate actioning</strong><div className="subtle">Recommended steps become structured incident actions for rollback, scale, notify, or fix workflows.</div></div></div></div></div>
      </section>
    </AppShell>
  );
}