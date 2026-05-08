import { prisma } from "../../lib/prisma";
import { createFingerprint, toClusterKey } from "../ingestion/fingerprint";
import { clusterEvents, detectSpike, filterNoise } from "../ingestion/processing";
import type { NormalizedEventInput } from "../ingestion/schemas";
import { createOrUpdateIncident } from "./detection.service";

export const processEvents = async (projectId: string, source: string, events: NormalizedEventInput[]) => {
  const cleaned = filterNoise(events);
  if (cleaned.length === 0) {
    return [];
  }

  const servicesByName = new Map<string, string>();
  for (const serviceName of new Set(cleaned.map((event) => event.service))) {
    const service = await prisma.service.upsert({
      where: {
        projectId_name: {
          projectId,
          name: serviceName,
        },
      },
      update: {},
      create: {
        projectId,
        name: serviceName,
      },
    });
    servicesByName.set(serviceName, service.id);
  }

  const logIds: string[] = [];
  const persisted: Array<{
    id: string;
    message: string;
    service: string;
    incidentGroupId: string | null;
  }> = [];

  for (const event of cleaned) {
    const fingerprint = createFingerprint(event.service, event.message);
    const clusterKey = toClusterKey(fingerprint, event.type);

    const incidentGroup = await prisma.incidentGroup.upsert({
      where: {
        projectId_clusterKey: {
          projectId,
          clusterKey,
        },
      },
      update: {
        lastSeenAt: new Date(event.timestamp),
      },
      create: {
        projectId,
        serviceId: servicesByName.get(event.service),
        clusterKey,
        title: event.message.slice(0, 120),
        firstSeenAt: new Date(event.timestamp),
        lastSeenAt: new Date(event.timestamp),
      },
    });

    const log = await prisma.log.create({
      data: {
        projectId,
        serviceId: servicesByName.get(event.service),
        type: event.type,
        timestamp: new Date(event.timestamp),
        message: event.message,
        metadata: {
          ...event.metadata,
          source,
        },
        fingerprint,
        incidentGroupId: incidentGroup.id,
      },
    });

    logIds.push(log.id);
    persisted.push({
      id: log.id,
      message: log.message,
      service: event.service,
      incidentGroupId: log.incidentGroupId,
    });
  }

  const incidents = [];
  const grouped = clusterEvents(cleaned);

  for (const cluster of grouped) {
    const spike = detectSpike(cluster.events);
    const errors = cluster.events.filter((event) => event.type === "error");
    const failedRequests = errors.length;
    const errorRate = Number((errors.length / Math.max(cluster.events.length, 1)).toFixed(2));

    if (errors.length >= 5 || spike.isSpike || errorRate >= 0.4) {
      const matchingLogs = persisted.filter((log) =>
        cluster.events.some((event) => event.message === log.message && event.service === log.service),
      );
      const incidentGroupId = persisted.find((log) => log.message === cluster.events[0]?.message)?.incidentGroupId ?? undefined;

      const incident = await createOrUpdateIncident({
        projectId,
        serviceId: servicesByName.get(cluster.events[0]?.service ?? ""),
        incidentGroupId,
        title: cluster.title,
        logIds: matchingLogs.length > 0 ? matchingLogs.map((log) => log.id) : logIds,
        errorRate,
        affectedRequests: cluster.events.length,
        failedRequests,
        startTime: new Date(cluster.events[0]?.timestamp ?? Date.now()),
        source,
      });

      incidents.push(incident);
    }
  }

  return incidents;
};
