import { AppShell } from "@/components/app-shell";
import { bootstrapDemoProject, getAlerts } from "@/lib/api";

export default async function AlertsPage() {
  const project = await bootstrapDemoProject();
  const alerts = await getAlerts(project.id);

  return (
    <AppShell activePath="/alerts">
      <div className="topbar">
        <div>
          <div className="brand">Alerts</div>
          <h1 className="headline">Notification and escalation surfaces.</h1>
          <p className="subtle">Slack, email, and webhook endpoints receive high-signal incidents after AI triage enriches the raw telemetry.</p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-inner">
          <div className="incident-list">
            {alerts.map((alert) => (
              <div key={alert.id} className="incident-row">
                <div>
                  <div style={{ fontWeight: 600, fontSize: "1.02rem" }}>{alert.provider}</div>
                  <div className="subtle">{JSON.stringify(alert.config)}</div>
                </div>
                <div>
                  <div className="metric-label">State</div>
                  <div>{alert.isActive ? "Active" : "Paused"}</div>
                </div>
                <div>
                  <div className="metric-label">Trigger</div>
                  <div>Severity 70+</div>
                </div>
                <div>
                  <div className="metric-label">Audience</div>
                  <div>On-call + business ops</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </AppShell>
  );
}