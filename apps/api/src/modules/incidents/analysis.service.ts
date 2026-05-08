import { prisma } from "../../lib/prisma";
import { publishProjectEvent } from "../realtime/socket";
import { analyzeIncident } from "../analysis/ai-client";

export const runAIAnalysisForIncident = async (incidentId: string) => {
  const incident = await prisma.incident.findUnique({
    where: { id: incidentId },
    include: {
      project: true,
      service: true,
      logs: {
        include: {
          log: true,
        },
      },
    },
  });

  if (!incident) {
    return;
  }

  const analysis = await analyzeIncident({
    incidentId: incident.id,
    service: incident.service?.name ?? "unknown-service",
    logs: incident.logs.map(({ log }) => ({
      timestamp: log.timestamp.toISOString(),
      message: log.message,
      metadata: log.metadata as Record<string, unknown>,
    })),
    metrics: {
      error_rate: incident.errorRate,
      affected_requests: incident.affectedRequests,
      failed_requests: incident.failedRequests,
    },
    revenueContext: {
      avgOrderValue: Number(incident.project.avgOrderValue),
      conversionRate: Number(incident.project.conversionRate),
      failedRequests: incident.failedRequests,
    },
  });

  await prisma.aIAnalysis.create({
    data: {
      incidentId,
      rootCause: analysis.root_cause,
      businessImpactUsd: analysis.business_impact_usd,
      severity: analysis.severity,
      explanation: analysis.explanation,
      recommendedActions: analysis.recommended_actions,
      evidence: analysis.evidence ?? [],
      confidence: analysis.confidence,
    },
  });

  await prisma.incident.update({
    where: { id: incidentId },
    data: {
      severityScore: analysis.severity,
      businessLossUsd: analysis.business_impact_usd,
      actions: {
        create: analysis.recommended_actions.map((action) => ({
          type: action.toLowerCase().includes("rollback") ? "ROLLBACK" : action.toLowerCase().includes("scale") ? "SCALE" : action.toLowerCase().includes("notify") ? "NOTIFY" : "FIX",
          title: action,
          status: "RECOMMENDED",
        })),
      },
    },
  });

  publishProjectEvent(incident.projectId, "incident:analysis_completed", {
    incidentId,
    analysis,
  });
};