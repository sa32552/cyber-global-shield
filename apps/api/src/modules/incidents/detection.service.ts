import { prisma } from "../../lib/prisma";
import { analysisQueue } from "../../queue/queues";
import { publishProjectEvent } from "../realtime/socket";
import { estimateBusinessLoss } from "./business-impact";

interface DetectionInput {
  projectId: string;
  serviceId?: string;
  incidentGroupId?: string;
  title: string;
  logIds: string[];
  errorRate: number;
  affectedRequests: number;
  failedRequests: number;
  startTime: Date;
  source?: string;
}

export const createOrUpdateIncident = async (input: DetectionInput) => {
  const existing = input.incidentGroupId
    ? await prisma.incident.findFirst({
        where: {
          projectId: input.projectId,
          incidentGroupId: input.incidentGroupId,
          status: { in: ["OPEN", "INVESTIGATING"] },
        },
      })
    : null;

  const loss = estimateBusinessLoss(input.failedRequests);

  if (existing) {
    const incident = await prisma.incident.update({
      where: { id: existing.id },
      data: {
        severityScore: Math.min(100, Math.round(existing.severityScore * 0.6 + input.errorRate * 40)),
        errorRate: input.errorRate,
        affectedRequests: { increment: input.affectedRequests },
        failedRequests: { increment: input.failedRequests },
        businessLossUsd: { increment: loss },
        logs: {
          createMany: {
            data: input.logIds.map((logId) => ({ incidentId: existing.id, logId })),
            skipDuplicates: true,
          },
        },
      },
    });

    publishProjectEvent(input.projectId, "incident:updated", incident);
    await analysisQueue.add("incident-analysis", { incidentId: incident.id });
    return incident;
  }

  const incident = await prisma.incident.create({
    data: {
      projectId: input.projectId,
      serviceId: input.serviceId,
      incidentGroupId: input.incidentGroupId,
      title: input.title,
      severityScore: Math.min(100, Math.max(25, Math.round(input.errorRate * 50 + input.failedRequests * 0.5))),
      errorRate: input.errorRate,
      affectedRequests: input.affectedRequests,
      failedRequests: input.failedRequests,
      businessLossUsd: loss,
      startTime: input.startTime,
      source: input.source ?? "mvp-rule-engine",
      logs: {
        createMany: {
          data: input.logIds.map((logId) => ({ logId })),
        },
      },
    },
  });

  publishProjectEvent(input.projectId, "incident:new", incident);
  await analysisQueue.add("incident-analysis", { incidentId: incident.id });
  return incident;
};