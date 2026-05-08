import { Router } from "express";
import { ingestionPayloadSchema, sentryWebhookSchema, datadogWebhookSchema } from "./schemas";
import { processEvents } from "../incidents/incident-engine";

export const ingestionRouter = Router();

ingestionRouter.post("/http", async (req, res, next) => {
  try {
    const payload = ingestionPayloadSchema.parse(req.body);
    const incidents = await processEvents(payload.projectId, payload.source, payload.events);
    res.status(202).json({ accepted: payload.events.length, incidentsTriggered: incidents.length });
  } catch (error) {
    next(error);
  }
});

ingestionRouter.post("/sentry", async (req, res, next) => {
  try {
    const payload = sentryWebhookSchema.parse(req.body);
    const service = payload.tags?.service ?? payload.culprit ?? "unknown-service";
    const incidents = await processEvents(payload.projectId, "sentry", [
      {
        type: "error",
        service,
        timestamp: typeof payload.timestamp === "number" ? payload.timestamp : Date.parse(payload.timestamp ?? new Date().toISOString()),
        message: payload.message ?? payload.culprit ?? "Sentry event",
        metadata: {
          event_id: payload.event_id,
          level: payload.level,
          tags: payload.tags ?? {},
          extra: payload.extra ?? {},
        },
      },
    ]);
    res.status(202).json({ accepted: 1, incidentsTriggered: incidents.length });
  } catch (error) {
    next(error);
  }
});

ingestionRouter.post("/datadog", async (req, res, next) => {
  try {
    const payload = datadogWebhookSchema.parse(req.body);
    const incidents = await processEvents(payload.projectId, "datadog", [
      {
        type: payload.alert_type === "error" ? "error" : "log",
        service: payload.service,
        timestamp: payload.date,
        message: `${payload.title}: ${payload.text}`,
        metadata: {
          tags: payload.tags ?? [],
          alert_type: payload.alert_type,
        },
      },
    ]);
    res.status(202).json({ accepted: 1, incidentsTriggered: incidents.length });
  } catch (error) {
    next(error);
  }
});

ingestionRouter.post("/cloudwatch", async (req, res, next) => {
  try {
    const body = req.body as {
      projectId: string;
      service: string;
      timestamp?: number;
      message: string;
      metadata?: Record<string, unknown>;
    };

    const incidents = await processEvents(body.projectId, "cloudwatch", [
      {
        type: "log",
        service: body.service,
        timestamp: body.timestamp ?? Date.now(),
        message: body.message,
        metadata: body.metadata ?? {},
      },
    ]);
    res.status(202).json({ accepted: 1, incidentsTriggered: incidents.length });
  } catch (error) {
    next(error);
  }
});
