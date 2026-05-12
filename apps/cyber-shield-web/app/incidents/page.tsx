"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { IncidentTable } from "@/components/incident-table";
import { RealtimeClient } from "@/components/realtime-client";
import { soar } from "@/lib/api";
import type { Playbook, SOARExecutionResult } from "@/lib/types";

export default function IncidentsPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executions, setExecutions] = useState<SOARExecutionResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"executions" | "playbooks">("executions");

  async function fetchData() {
    try {
      const playbooksRes = await soar.listPlaybooks();
      setPlaybooks(playbooksRes);
      setExecutions([]);
      setError(null);
    } catch (err: any) {
      setError(err.message ?? "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 20_000);
    return () => clearInterval(interval);
  }, []);

  return (
    <AppShell activePath="/incidents">
      <RealtimeClient onSoarUpdate={fetchData} />

      <div className="page-header">
        <h1>Gestion des Incidents</h1>
        <p className="page-subtitle">
          {playbooks.length} playbook{playbooks.length > 1 ? "s" : ""} configuré
          {playbooks.length > 1 ? "s" : ""}
          {" — "}
          {executions.length} exécution{executions.length > 1 ? "s" : ""} récente
          {executions.length > 1 ? "s" : ""}
        </p>
      </div>

      <div className="tab-bar">
        <button
          className={`tab-btn ${tab === "executions" ? "active" : ""}`}
          onClick={() => setTab("executions")}
        >
          Exécutions Récentes
        </button>
        <button
          className={`tab-btn ${tab === "playbooks" ? "active" : ""}`}
          onClick={() => setTab("playbooks")}
        >
          Playbooks
        </button>
      </div>

      {loading && (
        <div className="loading-spinner">
          <div className="spinner" />
          <span>Chargement des incidents…</span>
        </div>
      )}

      {error && (
        <div className="empty-state">
          <p style={{ color: "#ef4444" }}>Erreur : {error}</p>
          <button className="btn btn-primary" onClick={fetchData}>
            Réessayer
          </button>
        </div>
      )}

      {!loading && !error && (
        <div className="panel">
          <IncidentTable
            playbooks={tab === "playbooks" ? playbooks : undefined}
            executions={tab === "executions" ? executions : undefined}
          />
        </div>
      )}
    </AppShell>
  );
}
