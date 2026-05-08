import { Router } from "express";
import { prisma } from "../../lib/prisma";

export const integrationsRouter = Router();

integrationsRouter.get("/list", async (req, res, next) => {
  try {
    const projectId = String(req.query.projectId);
    const integrations = await prisma.integration.findMany({ where: { projectId } });
    res.json(integrations);
  } catch (error) {
    next(error);
  }
});

integrationsRouter.post("/seed-demo", async (req, res, next) => {
  try {
    const { projectId } = req.body as { projectId: string };
    await prisma.integration.createMany({
      data: [
        { projectId, provider: "sentry", config: { webhookUrl: "/api/v1/ingest/sentry" } },
        { projectId, provider: "datadog", config: { webhookUrl: "/api/v1/ingest/datadog" } },
        { projectId, provider: "cloudwatch", config: { method: "subscription-filter" } },
        { projectId, provider: "stripe", config: { revenueMapping: true } },
      ],
      skipDuplicates: true,
    });
    res.status(201).json({ ok: true });
  } catch (error) {
    next(error);
  }
});