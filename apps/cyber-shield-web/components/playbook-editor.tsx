"use client";

import { useState } from "react";
import type { Playbook, PlaybookAction } from "@/lib/types";

interface PlaybookEditorProps {
  playbook: Playbook;
  onExecute?: (playbookId: string) => void;
}

export function PlaybookEditor({ playbook, onExecute }: PlaybookEditorProps) {
  const [expandedAction, setExpandedAction] = useState<string | null>(null);

  const sortedActions = [...playbook.actions].sort((a, b) => a.order - b.order);

  return (
    <div>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>
          {playbook.name}
        </div>
        <div style={{ color: "var(--text-muted)", fontSize: 13 }}>
          {playbook.description}
        </div>
        <div style={{ marginTop: 12, display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
            Déclencheur : <strong style={{ color: "var(--text-primary)" }}>{playbook.trigger}</strong>
          </span>
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
            Auto-exécution :{" "}
            {playbook.auto_execute ? (
              <span style={{ color: "var(--accent-green)" }}>Activée</span>
            ) : (
              <span style={{ color: "var(--accent-yellow)" }}>Manuelle</span>
            )}
          </span>
        </div>
      </div>

      <div className="playbook-canvas">
        {sortedActions.map((action, index) => (
          <div key={action.id}>
            <div
              className="playbook-action-card"
              onClick={() =>
                setExpandedAction(
                  expandedAction === action.id ? null : action.id
                )
              }
              style={{ cursor: "pointer" }}
            >
              <div
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: "50%",
                  background: "var(--accent-blue)",
                  color: "#fff",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 12,
                  fontWeight: 700,
                  flexShrink: 0,
                }}
              >
                {index + 1}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{action.name}</div>
                <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                  Type: {action.type}
                </div>
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                {expandedAction === action.id ? "▲" : "▼"}
              </div>
            </div>

            {expandedAction === action.id && (
              <div
                style={{
                  marginLeft: 40,
                  padding: 12,
                  background: "var(--bg-primary)",
                  borderRadius: "var(--radius-sm)",
                  fontSize: 12,
                  color: "var(--text-secondary)",
                  fontFamily: "monospace",
                }}
              >
                <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                  {JSON.stringify(action.params, null, 2)}
                </pre>
                {action.rollback && (
                  <div style={{ marginTop: 8, color: "var(--accent-orange)" }}>
                    ↺ Rollback : {action.rollback.name}
                  </div>
                )}
              </div>
            )}

            {index < sortedActions.length - 1 && (
              <div className="playbook-action-arrow">↓</div>
            )}
          </div>
        ))}
      </div>

      <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
        <button
          className="btn btn-primary"
          onClick={() => onExecute?.(playbook.id)}
        >
          ▶ Exécuter le playbook
        </button>
        <button className="btn">📋 Dupliquer</button>
        <button className="btn">📤 Exporter</button>
      </div>
    </div>
  );
}
