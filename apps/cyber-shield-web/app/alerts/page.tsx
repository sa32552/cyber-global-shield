"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { AlertList } from "@/components/alert-list";
import { StatusBadge } from "@/components/status-badge";
import { RealtimeClient } from "@/components/realtime-client";
import { dashboard } from "@/lib/api";
import type { Alert } from "@/lib/types";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  async function fetchAlerts() {
    try {
      const params: Record<string, string> = {};
      if (severityFilter !== "all") params.severity = severityFilter;
      if (typeFilter !== "all") params.type = typeFilter;
      const res = await dashboard.alerts(params);
      setAlerts(res);
      setError(null);
    } catch (err: any) {
      setError(err.message ?? "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchAlerts();
  }, [severityFilter, typeFilter]);

  useEffect(() => {
    const interval = setInterval(fetchAlerts, 15_000);
    return () => clearInterval(interval);
  }, []);

  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const highCount = alerts.filter((a) => a.severity === "high").length;
  const mediumCount = alerts.filter((a) => a.severity === "medium").length;

  return (
    <AppShell activePath="/alerts">
      <RealtimeClient onAlert={fetchAlerts} />

      <div className="page-header">
        <h1>Alertes en Temps Réel</h1>
        <p className="page-subtitle">
          {alerts.length} alerte{alerts.length > 1 ? "s" : ""} active
          {alerts.length > 0 ? (
            <>
              {" "}— <span style={{ color: "#ef4444" }}>{criticalCount} critique{criticalCount > 1 ? "s" : ""}</span>
              , <span style={{ color: "#f97316" }}>{highCount} élevée{highCount > 1 ? "s" : ""}</span>
              , <span style={{ color: "#eab308" }}>{mediumCount} moyenne{mediumCount > 1 ? "s" : ""}</span>
            </>
          ) : null}
        </p>
      </div>

      <div className="filter-bar">
        <div className="filter-group">
          <label htmlFor="severity">Sévérité</label>
          <select
            id="severity"
            className="form-input"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">Toutes</option>
            <option value="critical">Critique</option>
            <option value="high">Élevée</option>
            <option value="medium">Moyenne</option>
            <option value="low">Basse</option>
          </select>
        </div>
        <div className="filter-group">
          <label htmlFor="type">Type</label>
          <select
            id="type"
            className="form-input"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="all">Tous</option>
            <option value="intrusion">Intrusion</option>
            <option value="malware">Malware</option>
            <option value="phishing">Phishing</option>
            <option value="anomaly">Anomalie</option>
            <option value="zero_day">Zero-Day</option>
          </select>
        </div>
        <button className="btn btn-primary" onClick={fetchAlerts}>
          Actualiser
        </button>
      </div>

      {loading && (
        <div className="loading-spinner">
          <div className="spinner" />
          <span>Chargement des alertes…</span>
        </div>
      )}

      {error && (
        <div className="empty-state">
          <p style={{ color: "#ef4444" }}>Erreur : {error}</p>
          <button className="btn btn-primary" onClick={fetchAlerts}>
            Réessayer
          </button>
        </div>
      )}

      {!loading && !error && alerts.length === 0 && (
        <div className="empty-state">
          <div style={{ fontSize: "3rem", marginBottom: "0.5rem" }}>✓</div>
          <p>Aucune alerte active pour les filtres sélectionnés</p>
        </div>
      )}

      {!loading && alerts.length > 0 && (
        <div className="panel">
          <AlertList alerts={alerts} />
        </div>
      )}
    </AppShell>
  );
}
