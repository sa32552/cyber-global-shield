"use client";

import { useEffect, useRef } from "react";

// Simple canvas-based threat map (no external map library dependency)
interface ThreatPoint {
  lat: number;
  lng: number;
  severity: string;
  label: string;
}

interface ThreatMapProps {
  threats?: ThreatPoint[];
}

const severityColors: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

// Simple world map projection (Equirectangular)
function project(lat: number, lng: number, width: number, height: number) {
  const x = ((lng + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return { x, y };
}

export function ThreatMap({ threats = [] }: ThreatMapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;

    // Background
    ctx.fillStyle = "#0a0e1a";
    ctx.fillRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = "rgba(255,255,255,0.03)";
    ctx.lineWidth = 1;
    for (let lat = -90; lat <= 90; lat += 30) {
      const { y } = project(lat, 0, w, h);
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }
    for (let lng = -180; lng <= 180; lng += 30) {
      const { x } = project(0, lng, w, h);
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }

    // Continents (simplified polygons)
    ctx.fillStyle = "rgba(59, 130, 246, 0.08)";
    ctx.strokeStyle = "rgba(59, 130, 246, 0.15)";
    ctx.lineWidth = 1;

    // Simplified continent outlines
    const continents = [
      // North America
      [
        [50, -130],
        [50, -100],
        [50, -80],
        [45, -75],
        [40, -75],
        [30, -80],
        [25, -80],
        [20, -90],
        [20, -100],
        [25, -105],
        [30, -115],
        [40, -125],
        [50, -130],
      ],
      // South America
      [
        [10, -75],
        [5, -75],
        [0, -70],
        [-5, -70],
        [-10, -75],
        [-15, -75],
        [-20, -70],
        [-25, -70],
        [-30, -65],
        [-35, -60],
        [-40, -60],
        [-45, -65],
        [-50, -70],
        [-50, -65],
        [-45, -60],
        [-40, -55],
        [-35, -50],
        [-30, -50],
        [-25, -45],
        [-20, -40],
        [-15, -40],
        [-10, -45],
        [-5, -50],
        [0, -50],
        [5, -55],
        [10, -60],
        [10, -75],
      ],
      // Europe
      [
        [55, -10],
        [55, 0],
        [55, 10],
        [55, 20],
        [55, 30],
        [50, 30],
        [45, 30],
        [45, 25],
        [40, 25],
        [40, 20],
        [40, 15],
        [40, 10],
        [40, 5],
        [40, 0],
        [45, -5],
        [45, -10],
        [50, -10],
        [55, -10],
      ],
      // Africa
      [
        [35, -5],
        [35, 10],
        [35, 20],
        [35, 30],
        [30, 30],
        [25, 35],
        [20, 35],
        [15, 40],
        [10, 40],
        [5, 40],
        [0, 40],
        [-5, 40],
        [-10, 40],
        [-15, 35],
        [-20, 35],
        [-25, 35],
        [-30, 30],
        [-35, 25],
        [-35, 20],
        [-30, 15],
        [-25, 15],
        [-20, 15],
        [-15, 10],
        [-10, 10],
        [-5, 5],
        [0, 5],
        [5, 0],
        [5, -5],
        [10, -5],
        [10, -10],
        [15, -15],
        [20, -15],
        [25, -15],
        [30, -10],
        [35, -5],
      ],
      // Asia
      [
        [55, 30],
        [55, 40],
        [55, 50],
        [55, 60],
        [55, 70],
        [55, 80],
        [55, 90],
        [55, 100],
        [55, 110],
        [55, 120],
        [55, 130],
        [50, 130],
        [45, 135],
        [40, 130],
        [35, 130],
        [30, 125],
        [25, 120],
        [20, 115],
        [15, 110],
        [10, 105],
        [10, 100],
        [10, 95],
        [10, 90],
        [10, 85],
        [10, 80],
        [10, 75],
        [15, 75],
        [20, 70],
        [25, 65],
        [30, 60],
        [35, 55],
        [35, 50],
        [35, 45],
        [35, 40],
        [35, 35],
        [40, 30],
        [45, 30],
        [50, 30],
        [55, 30],
      ],
      // Australia
      [
        [-15, 115],
        [-15, 120],
        [-15, 125],
        [-15, 130],
        [-15, 135],
        [-15, 140],
        [-15, 145],
        [-20, 145],
        [-25, 145],
        [-30, 145],
        [-35, 145],
        [-35, 140],
        [-35, 135],
        [-35, 130],
        [-30, 125],
        [-25, 120],
        [-20, 115],
        [-15, 115],
      ],
    ];

    continents.forEach((continent) => {
      ctx.beginPath();
      const first = continent[0] as [number, number];
      const { x: sx, y: sy } = project(first[0], first[1], w, h);
      ctx.moveTo(sx, sy);
      for (let i = 1; i < continent.length; i++) {
        const pt = continent[i] as [number, number];
        const { x, y } = project(pt[0], pt[1], w, h);
        ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    });

    // Threat points
    threats.forEach((threat) => {
      const { x, y } = project(threat.lat, threat.lng, w, h);
      const color = severityColors[threat.severity] || "#64748b";
      const radius = threat.severity === "critical" ? 8 : 6;

      // Glow effect
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius * 3);
      gradient.addColorStop(0, color + "60");
      gradient.addColorStop(1, color + "00");
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, radius * 3, 0, Math.PI * 2);
      ctx.fill();

      // Point
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();

      // Border
      ctx.strokeStyle = "#fff";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });
  }, [threats]);

  return (
    <div className="threat-map-container">
      <canvas
        ref={canvasRef}
        style={{ width: "100%", height: "100%" }}
      />
    </div>
  );
}
