import { AppShell } from "@/components/app-shell";
import { bootstrapDemoProject, getServices } from "@/lib/api";

export default async function ServicesPage() {
  const project = await bootstrapDemoProject();
  const services = await getServices(project.id);

  return (
    <AppShell activePath="/services">
      <div className="topbar">
        <div>
          <div className="brand">Services</div>
          <h1 className="headline">Monitored services and blast radius.</h1>
          <p className="subtle">See which services are carrying active incident load and where revenue-critical traffic concentrates.</p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-inner">
          <div className="incident-list">
            {services.map((service) => (
              <div key={service.id} className="incident-row">
                <div>
                  <div style={{ fontSize: "1.1rem", fontWeight: 600 }}>{service.name}</div>
                  <div className="subtle">Environment: {service.environment}</div>
                </div>
                <div>
                  <div className="metric-label">Open incidents</div>
                  <div>{service.incidents.length}</div>
                </div>
                <div>
                  <div className="metric-label">Status</div>
                  <div>{service.incidents.length > 0 ? "Attention required" : "Healthy"}</div>
                </div>
                <div>
                  <div className="metric-label">Monitored by</div>
                  <div>Sentry, Datadog, CloudWatch</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </AppShell>
  );
}