"use client";

import { useEffect, useState, useRef } from "react";
import { AppShell } from "@/components/app-shell";
import { ThreatMap } from "@/components/threat-map";
import { RealtimeClient } from "@/components/realtime-client";
import { dashboard } from "@/lib/api";

interface ThreatPoint {
  lat: number;
  lng: number;
  severity: string;
  label: string;
}

export default function ThreatsPage() {
  const [threats, setThreats] = useState<ThreatPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  async function fetchThreats() {
    try {
      const res = await dashboard.overview();
      const topThreats = res.top_threats ?? [];

      // Convert top threats to geo points (simulated with common attacker origins)
      const geoMap: Record<string, { lat: number; lng: number }> = {
        "russe": { lat: 55.7558, lng: 37.6173 },
        "chine": { lat: 39.9042, lng: 116.4074 },
        "nord-coréen": { lat: 39.0392, lng: 125.7625 },
        "iranien": { lat: 35.6892, lng: 51.3890 },
        "américain": { lat: 38.9072, lng: -77.0369 },
        "européen": { lat: 48.8566, lng: 2.3522 },
        "africain": { lat: -26.2041, lng: 28.0473 },
        "asiatique": { lat: 1.3521, lng: 103.8198 },
        "sud-américain": { lat: -23.5505, lng: -46.6333 },
        "australien": { lat: -33.8688, lng: 151.2093 },
      };

      const points: ThreatPoint[] = topThreats.map((t: any, i: number) => {
        const origin = Object.values(geoMap)[i % Object.keys(geoMap).length];
        return {
          lat: origin.lat + (Math.random() - 0.5) * 10,
          lng: origin.lng + (Math.random() - 0.5) * 10,
          severity: t.severity ?? "medium",
          label: `${t.type} (${t.count})`,
        };
      });

      setThreats(points);
      setStats({
        total: res.summary.total_threats_blocked,
        critical: topThreats.filter((t: any) => t.severity === "critical").length,
        high: topThreats.filter((t: any) => t.severity === "high").length,
        medium: topThreats.filter((t: any) => t.severity === "medium").length,
        low: topThreats.filter((t: any) => t.severity === "low").length,
      });
      setError(null);
    } catch (err: any) {
      setError(err.message ?? "Erreur de chargement");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 30_000);
    return () => clearInterval(interval);
  }, []);

  return (
    <AppShell activePath="/threats">
      <RealtimeClient onMLDetection={fetchThreats} />

      <div className="page-header">
        <h1>Carte des Menaces</h1>
        <p className="page-subtitle">
          Visualisation géographique des menaces en temps réel
        </p>
      </div>

      <div className="stats-row">
        <div className="stat-chip" style={{ borderColor: "#ef4444" }}>
          <span className="stat-dot" style={{ background: "#ef4444" }} />
          Critique: {stats.critical}
        </div>
        <div className="stat-chip" style={{ borderColor: "#f97316" }}>
          <span className="stat-dot" style={{ background: "#f97316" }} />
          Élevée: {stats.high}
        </div>
        <div className="stat-chip" style={{ borderColor: "#eab308" }}>
          <span className="stat-dot" style={{ background: "#eab308" }} />
          Moyenne: {stats.medium}
        </div>
        <div className="stat-chip" style={{ borderColor: "#22c55e" }}>
          <span className="stat-dot" style={{ background: "#22c55e" }} />
          Basse: {stats.low}
        </div>
        <div className="stat-chip" style={{ borderColor: "#3b82f6" }}>
          Total: {stats.total}
        </div>
      </div>

      {loading && (
        <div className="loading-spinner">
          <div className="spinner" />
          <span>Chargement de la carte des menaces…</span>
        </div>
      )}

      {error && (
        <div className="empty-state">
          <p style={{ color: "#ef4444" }}>Erreur : {error}</p>
          <button className="btn btn-primary" onClick={fetchThreats}>
            Réessayer
          </button>
        </div>
      )}

      {!loading && !error && (
        <div className="panel">
          <ThreatMap threats={threats} />
        </div>
      )}
    </AppShell>
  );
}
