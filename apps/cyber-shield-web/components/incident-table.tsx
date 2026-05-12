import type { Playbook, SOARExecutionResult } from "@/lib/types";
import { formatTimestamp } from "@/lib/format";
import { StatusBadge } from "./status-badge";

interface IncidentTableProps {
  playbooks?: Playbook[];
  executions?: SOARExecutionResult[];
}

export function IncidentTable({ playbooks, executions }: IncidentTableProps) {
  if (executions && executions.length > 0) {
    return (
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Playbook</th>
              <th>Statut</th>
              <th>Démarré</th>
              <th>Durée</th>
            </tr>
          </thead>
          <tbody>
            {executions.map((exec) => (
              <tr key={exec.execution_id}>
                <td style={{ fontFamily: "monospace", fontSize: 12 }}>
                  {exec.execution_id.slice(0, 8)}...
                </td>
                <td>{exec.playbook_id}</td>
                <td>
                  <StatusBadge type="status" value={exec.status} />
                </td>
                <td>{formatTimestamp(exec.started_at)}</td>
                <td>
                  {exec.completed_at
                    ? `${Math.round(
                        (new Date(exec.completed_at).getTime() -
                          new Date(exec.started_at).getTime()) /
                          1000
                      )}s`
                    : "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (playbooks && playbooks.length > 0) {
    return (
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Nom</th>
              <th>Déclencheur</th>
              <th>Actions</th>
              <th>Auto</th>
              <th>Modifié</th>
            </tr>
          </thead>
          <tbody>
            {playbooks.map((pb) => (
              <tr key={pb.id}>
                <td style={{ fontWeight: 600 }}>{pb.name}</td>
                <td style={{ color: "var(--text-muted)" }}>{pb.trigger}</td>
                <td>{pb.actions.length}</td>
                <td>
                  {pb.auto_execute ? (
                    <span style={{ color: "var(--accent-green)" }}>✓</span>
                  ) : (
                    <span style={{ color: "var(--text-muted)" }}>✗</span>
                  )}
                </td>
                <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                  {formatTimestamp(pb.updated_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className="empty-state">
      <div className="empty-state-icon">📋</div>
      <div>Aucune donnée disponible</div>
    </div>
  );
}
