"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { MetricsGrid } from "@/components/metrics-grid";
import { AlertList } from "@/components/alert-list";
import { ChartAlerts } from "@/components/chart-alerts";
import { ChartThreats } from "@/components/chart-threats";
import { RealtimeClient } from "@/components/realtime-client";
import { dashboard } from "@/lib/api";
import type { DashboardOverview } from "@/lib/types";

export default function DashboardPage() {
  const [data, setData] = useState<DashboardOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function fetchDashboard() {
    try {
      const res = await dashboard.overview();
      setData(res);
      setError(null);
    } catch (err: any) {
      setError(err.message ?? "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchDashboard();
    const interval = setInterval(fetchDashboard, 30_000);
    return () => clearInterval(interval);
  }, []);

  const metrics = data
    ? [
        {
          label: "Menaces Bloquées",
          value: data.summary.total_threats_blocked,
          format: "number" as const,
          color: "#22c55e",
        },
        {
          label: "Alertes Actives",
          value: data.summary.active_alerts,
          format: "number" as const,
          color: data.summary.critical_alerts > 0 ? "#ef4444" : "#f59e0b",
        },
        {
          label: "Score de Conformité",
          value: data.summary.compliance_score,
          format: "percent" as const,
          color: "#3b82f6",
        },
        {
          label: "Uptime",
          value: data.summary.uptime_percentage,
          format: "percent" as const,
          color: "#22c55e",
        },
      ]
    : [];

  return (
    <AppShell activePath="/">
      <RealtimeClient
        onAlert={() => fetchDashboard()}
        onSoarUpdate={() => fetchDashboard()}
        onMLDetection={() => fetchDashboard()}
        onSystemHealth={() => fetchDashboard()}
      />

      <div className="page-header">
        <h1>Dashboard SOC</h1>
        <p className="page-subtitle">
          Vue d'ensemble en temps réel de la plateforme Cyber Global Shield
        </p>
      </div>

      {loading && (
        <div className="loading-spinner">
          <div className="spinner" />
          <span>Chargement du tableau de bord…</span>
        </div>
      )}

      {error && (
        <div className="empty-state">
          <p style={{ color: "#ef4444" }}>Erreur : {error}</p>
          <button className="btn btn-primary" onClick={fetchDashboard}>
            Réessayer
          </button>
        </div>
      )}

      {data && (
        <>
          <MetricsGrid metrics={metrics} />

          <div className="charts-grid">
            <div className="chart-card">
              <h3 className="chart-title">Tendance des Alertes</h3>
              <ChartAlerts data={data.threat_trend} />
            </div>
            <div className="chart-card">
              <h3 className="chart-title">Répartition des Menaces</h3>
              <ChartThreats data={data.alert_distribution} />
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h3>Alertes Récentes</h3>
              <a href="/alerts" className="btn btn-ghost">
                Voir tout →
              </a>
            </div>
            <AlertList alerts={data.recent_alerts} maxItems={5} />
          </div>
        </>
      )}
    </AppShell>
  );
}
