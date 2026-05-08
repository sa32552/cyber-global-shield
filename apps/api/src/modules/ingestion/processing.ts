import type { NormalizedEventInput } from "./schemas";

export const filterNoise = (events: NormalizedEventInput[]) =>
  events.filter((event) => {
    const message = event.message.toLowerCase();
    return !message.includes("healthcheck") && !message.includes("readiness probe") && !message.includes("liveness probe");
  });

export const detectSpike = (events: NormalizedEventInput[], windowMs = 5 * 60 * 1000) => {
  const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);
  const now = sorted.at(-1)?.timestamp ?? Date.now();
  const recent = sorted.filter((event) => now - event.timestamp <= windowMs);
  const previous = sorted.filter((event) => now - event.timestamp > windowMs && now - event.timestamp <= windowMs * 2);
  const baseline = Math.max(previous.length, 1);
  return {
    recentCount: recent.length,
    previousCount: previous.length,
    spikeRatio: recent.length / baseline,
    isSpike: recent.length >= 10 && recent.length / baseline >= 2,
  };
};

export const clusterEvents = (events: NormalizedEventInput[]) => {
  const clusters = new Map<string, NormalizedEventInput[]>();

  for (const event of events) {
    const key = `${event.service}:${event.type}:${event.message.toLowerCase().replace(/\d+/g, "#").slice(0, 48)}`;
    const cluster = clusters.get(key) ?? [];
    cluster.push(event);
    clusters.set(key, cluster);
  }

  return [...clusters.entries()].map(([key, groupedEvents]) => ({
    key,
    title: groupedEvents[0]?.message ?? key,
    events: groupedEvents,
  }));
};