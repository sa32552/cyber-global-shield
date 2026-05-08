import { z } from "zod";

export const normalizedEventSchema = z.object({
  type: z.enum(["error", "metric", "log"]),
  service: z.string().min(1),
  timestamp: z.number().int().positive(),
  message: z.string().min(1),
  metadata: z.record(z.unknown()).default({}),
});

export type NormalizedEventInput = z.infer<typeof normalizedEventSchema>;

export const ingestionPayloadSchema = z.object({
  projectId: z.string().uuid(),
  events: z.array(normalizedEventSchema).min(1),
  source: z.string().default("http"),
});

export const sentryWebhookSchema = z.object({
  projectId: z.string().uuid(),
  event_id: z.string(),
  level: z.string().optional(),
  culprit: z.string().optional(),
  message: z.string().optional(),
  timestamp: z.union([z.string(), z.number()]).optional(),
  tags: z.record(z.string()).optional(),
  extra: z.record(z.unknown()).optional(),
});

export const datadogWebhookSchema = z.object({
  projectId: z.string().uuid(),
  title: z.string(),
  text: z.string(),
  date: z.number(),
  service: z.string().default("unknown-service"),
  alert_type: z.string().optional(),
  tags: z.array(z.string()).optional(),
});