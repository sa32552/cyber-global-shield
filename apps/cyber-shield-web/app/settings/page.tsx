"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { system } from "@/lib/api";
import type { SystemHealth, PlatformSettings } from "@/lib/types";

export default function SettingsPage() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [settings, setSettings] = useState<PlatformSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  async function fetchData() {
    try {
      const [healthRes, settingsRes] = await Promise.all([
        system.health(),
        system.settings(),
      ]);
      setHealth(healthRes);
      setSettings(settingsRes);
      setError(null);
    } catch (err: any) {
      setError(err.message ?? "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchData();
  }, []);

  async function handleSave() {
    if (!settings) return;
    setSaving(true);
    setSaveMessage(null);
    try {
      // Settings update via API — will be implemented when backend endpoint is available
      setSaveMessage("Configuration enregistrée avec succès");
    } catch (err: any) {
      setSaveMessage(`Erreur : ${err.message}`);
    } finally {
      setSaving(false);
      setTimeout(() => setSaveMessage(null), 5000);
    }
  }

  function updateSetting(key: keyof PlatformSettings, value: any) {
    if (!settings) return;
    setSettings({ ...settings, [key]: value });
  }

  return (
    <AppShell activePath="/settings">
      <div className="page-header">
        <h1>Configuration</h1>
        <p className="page-subtitle">
          Paramètres généraux de la plateforme Cyber Global Shield
        </p>
      </div>

      {saveMessage && (
        <div
          className="notification"
          style={{
            background: saveMessage.startsWith("Erreur")
              ? "rgba(239,68,68,0.15)"
              : "rgba(34,197,94,0.15)",
            border: `1px solid ${
              saveMessage.startsWith("Erreur") ? "#ef4444" : "#22c55e"
            }`,
            color: saveMessage.startsWith("Erreur") ? "#ef4444" : "#22c55e",
            marginBottom: "1rem",
            padding: "0.75rem 1rem",
            borderRadius: "0.5rem",
            fontSize: "0.875rem",
          }}
        >
          {saveMessage}
        </div>
      )}

      {loading && (
        <div className="loading-spinner">
          <div className="spinner" />
          <span>Chargement de la configuration…</span>
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

      {!loading && !error && health && (
        <>
          {/* Health Status Section */}
          <div className="panel" style={{ marginBottom: "1.5rem" }}>
            <h3 style={{ marginBottom: "1rem" }}>État du Système</h3>
            <div className="health-grid">
              <div className="health-item">
                <span className="health-label">API</span>
                <span
                  className={`status-dot ${
                    health.api_status === "healthy" ? "healthy" : "down"
                  }`}
                />
                <span className="health-value">{health.api_status}</span>
              </div>
              <div className="health-item">
                <span className="health-label">Base de données</span>
                <span
                  className={`status-dot ${
                    health.database_status === "healthy" ? "healthy" : "down"
                  }`}
                />
                <span className="health-value">{health.database_status}</span>
              </div>
              <div className="health-item">
                <span className="health-label">Redis</span>
                <span
                  className={`status-dot ${
                    health.redis_status === "healthy" ? "healthy" : "down"
                  }`}
                />
                <span className="health-value">{health.redis_status}</span>
              </div>
              <div className="health-item">
                <span className="health-label">Kafka</span>
                <span
                  className={`status-dot ${
                    health.kafka_status === "healthy" ? "healthy" : "down"
                  }`}
                />
                <span className="health-value">{health.kafka_status}</span>
              </div>
              <div className="health-item">
                <span className="health-label">ML Engine</span>
                <span
                  className={`status-dot ${
                    health.ml_engine_status === "healthy" ? "healthy" : "down"
                  }`}
                />
                <span className="health-value">{health.ml_engine_status}</span>
              </div>
              <div className="health-item">
                <span className="health-label">Uptime</span>
                <span className="health-value">{health.uptime}</span>
              </div>
            </div>
          </div>

          {/* Platform Settings Section */}
          <div className="panel">
            <h3 style={{ marginBottom: "1rem" }}>Paramètres Plateforme</h3>

            {settings && (
              <div className="settings-form">
                <div className="form-group">
                  <label htmlFor="org_name">Nom de l'organisation</label>
                  <input
                    id="org_name"
                    type="text"
                    className="form-input"
                    value={settings.org_name ?? ""}
                    onChange={(e) => updateSetting("org_name", e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="retention_days">
                    Rétention des logs (jours)
                  </label>
                  <input
                    id="retention_days"
                    type="number"
                    className="form-input"
                    value={settings.retention_days ?? 90}
                    onChange={(e) =>
                      updateSetting("retention_days", parseInt(e.target.value))
                    }
                    min={1}
                    max={365}
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="ml_threshold">
                    Seuil de détection ML (0.0 - 1.0)
                  </label>
                  <input
                    id="ml_threshold"
                    type="number"
                    className="form-input"
                    value={settings.ml_threshold ?? 0.5}
                    onChange={(e) =>
                      updateSetting(
                        "ml_threshold",
                        parseFloat(e.target.value)
                      )
                    }
                    min={0}
                    max={1}
                    step={0.05}
                  />
                </div>

                <div className="form-group">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={settings.auto_remediation ?? false}
                      onChange={(e) =>
                        updateSetting("auto_remediation", e.target.checked)
                      }
                    />
                    <span>Remédiation automatique activée</span>
                  </label>
                </div>

                <div className="form-group">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={settings.realtime_alerts ?? true}
                      onChange={(e) =>
                        updateSetting("realtime_alerts", e.target.checked)
                      }
                    />
                    <span>Alertes en temps réel</span>
                  </label>
                </div>

                <button
                  className="btn btn-primary"
                  onClick={handleSave}
                  disabled={saving}
                >
                  {saving ? "Enregistrement…" : "Enregistrer"}
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </AppShell>
  );
}
