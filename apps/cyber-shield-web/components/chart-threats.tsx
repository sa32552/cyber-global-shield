"use client";

import { useEffect, useRef } from "react";
import { Chart, registerables } from "chart.js";

Chart.register(...registerables);

interface ChartThreatsProps {
  data: { type: string; count: number; severity: string }[];
}

const severityColors: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

export function ChartThreats({ data }: ChartThreatsProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const chartRef = useRef<Chart | null>(null);

  useEffect(() => {
    if (!canvasRef.current) return;

    if (chartRef.current) {
      chartRef.current.destroy();
    }

    const ctx = canvasRef.current.getContext("2d");
    if (!ctx) return;

    chartRef.current = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: data.map((d) => d.type),
        datasets: [
          {
            data: data.map((d) => d.count),
            backgroundColor: data.map(
              (d) => severityColors[d.severity] || "#64748b"
            ),
            borderColor: "#1a1f2e",
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#94a3b8",
              padding: 16,
              usePointStyle: true,
              pointStyle: "circle",
            },
          },
        },
      },
    });

    return () => {
      chartRef.current?.destroy();
    };
  }, [data]);

  return (
    <div className="chart-container">
      <canvas ref={canvasRef} />
    </div>
  );
}
