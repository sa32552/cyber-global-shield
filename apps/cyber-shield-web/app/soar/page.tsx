"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { PlaybookEditor } from "@/components/playbook-editor";
import { RealtimeClient } from "@/components/realtime-client";
import { soar } from "@/lib/api";
import type { Playbook } from "@/lib/types";

export default function SOARPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [executing, setExecuting] = useState<string | null>(null);
  const [executionResult, setExecutionResult] = useState<string | null>(null);

  async function fetchPlaybooks() {
    try {
      const res = await soar.listPlaybooks();
      setPlaybooks(res);
      if (!selectedPlaybook && res.length > 0) {
        setSelectedPlaybook(res[0]);
      }
      setError(null);
    } catch (err: any) {
      setError(err.message ?? "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchPlaybooks();
  }, []);

  async function handleExecute(playbookId: string) {
    setExecuting(playbookId);
    setExecutionResult(null);
    try {
      const res = await soar.execute({ playbook_id: playbookId, alert_id: "manual" });
      setExecutionResult(
        `Exécution terminée : ${res.status} (${res.duration_ms ?? "N/A"}ms)`
      );
    } catch (err: any) {
      setExecutionResult(`Erreur : ${err.message}`);
    } finally {
      setExecuting(null);
    }
  }

  return (
    <AppShell activePath="/soar">
      <RealtimeClient onSoarUpdate={fetchPlaybooks} />

      <div className="page-header">
        <h1>Playbooks SOAR</h1>
        <p className="page-subtitle">
          Automatisation des réponses aux incidents — {playbooks.length} playbook
          {playbooks.length > 1 ? "s" : ""} disponible{playbooks.length > 1 ? "s" : ""}
        </p>
      </div>

      {executionResult && (
        <div
          className="notification"
          style={{
            background: executionResult.startsWith("Erreur")
              ? "rgba(239,68,68,0.15)"
              : "rgba(34,197,94,0.15)",
            border: `1px solid ${
              executionResult.startsWith("Erreur") ? "#ef4444" : "#22c55e"
            }`,
            color: executionResult.startsWith("Erreur") ? "#ef4444" : "#22c55e",
          }}
        >
          {executionResult}
        </div>
      )}

      {loading && (
        <div className="loading-spinner">
          <div className="spinner" />
          <span>Chargement des playbooks…</span>
        </div>
      )}

      {error && (
        <div className="empty-state">
          <p style={{ color: "#ef4444" }}>Erreur : {error}</p>
          <button className="btn btn-primary" onClick={fetchPlaybooks}>
            Réessayer
          </button>
        </div>
      )}

      {!loading && !error && playbooks.length === 0 && (
        <div className="empty-state">
          <p>Aucun playbook configuré</p>
          <p style={{ fontSize: "0.875rem", color: "#94a3b8" }}>
            Créez un playbook via l'API SOAR pour commencer
          </p>
        </div>
      )}

      {!loading && !error && playbooks.length > 0 && (
        <div className="soar-layout">
          <aside className="soar-sidebar">
            <h3 style={{ marginBottom: "0.75rem", fontSize: "0.875rem", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Playbooks
            </h3>
            <div className="playbook-list">
              {playbooks.map((pb) => (
                <button
                  key={pb.id}
                  className={`playbook-list-item ${
                    selectedPlaybook?.id === pb.id ? "active" : ""
                  }`}
                  onClick={() => setSelectedPlaybook(pb)}
                >
                  <div className="playbook-list-name">{pb.name}</div>
                  <div className="playbook-list-trigger">{pb.trigger}</div>
                </button>
              ))}
            </div>
          </aside>

          <div className="soar-main">
            {selectedPlaybook && (
              <PlaybookEditor
                playbook={selectedPlaybook}
                onExecute={handleExecute}
              />
            )}
          </div>
        </div>
      )}
    </AppShell>
  );
}
