import { Router } from "express";
import { prisma } from "../../lib/prisma";
import { randomUUID } from "crypto";

export const projectsRouter = Router();

projectsRouter.get("/list", async (_req, res, next) => {
  try {
    const projects = await prisma.project.findMany({ orderBy: { createdAt: "asc" } });
    res.json(projects);
  } catch (error) {
    next(error);
  }
});

projectsRouter.post("/bootstrap-demo", async (_req, res, next) => {
  try {
    const existing = await prisma.project.findUnique({ where: { slug: "demo-project" } });
    if (existing) {
      res.json(existing);
      return;
    }

    const project = await prisma.project.create({
      data: {
        name: "Demo Project",
        slug: "demo-project",
        avgOrderValue: 149,
        conversionRate: 0.042,
        revenuePerRequest: 6.26,
      },
    });

    const checkout = await prisma.service.create({ data: { projectId: project.id, name: "checkout-api" } });
    await prisma.service.create({ data: { projectId: project.id, name: "web-frontend" } });

    const now = Date.now();
    const demoLogs = await Promise.all(
      Array.from({ length: 12 }).map((_, index) =>
        prisma.log.create({
          data: {
            projectId: project.id,
            serviceId: checkout.id,
            type: "error",
            timestamp: new Date(now - index * 45000),
            message: index < 8 ? "Stripe charge creation failed with 502 upstream error" : "Payment retry attempt exhausted",
            metadata: {
              request_id: randomUUID(),
              release: "checkout-api@2026.04.14.1",
              region: "us-east-1",
            },
          },
        }),
      ),
    );

    const incident = await prisma.incident.create({
      data: {
        projectId: project.id,
        serviceId: checkout.id,
        title: "Checkout payment failures after deployment",
        severityScore: 82,
        errorRate: 0.68,
        affectedRequests: 1240,
        failedRequests: 318,
        businessLossUsd: 1990.12,
        startTime: new Date(now - 20 * 60000),
        source: "demo-seed",
        logs: {
          createMany: {
            data: demoLogs.map((log) => ({ logId: log.id })),
          },
        },
        analyses: {
          create: {
            rootCause: "Most likely cause is the recent checkout-api deployment introducing upstream payment gateway timeouts.",
            businessImpactUsd: 1990.12,
            severity: 84,
            explanation: "A sharp spike in payment failures began immediately after release checkout-api@2026.04.14.1. The dominant error pattern is Stripe charge creation returning 502, which aligns with a deployment or dependency regression rather than normal user behavior.",
            recommendedActions: [
              "Rollback checkout-api to the previous stable release immediately",
              "Fail open to queued payment retry flow for non-critical checkouts",
              "Page the payments on-call and validate Stripe upstream status",
            ],
            evidence: [
              "8 repeated logs mention Stripe charge creation failed with 502 upstream error",
              "Error burst started within the last 20 minutes",
            ],
            confidence: 0.81,
          },
        },
        actions: {
          create: [
            { type: "ROLLBACK", title: "Rollback checkout-api to previous stable version" },
            { type: "NOTIFY", title: "Notify payments on-call and customer support" },
            { type: "FIX", title: "Investigate Stripe timeout regression in release 2026.04.14.1" },
          ],
        },
      },
    });

    await prisma.integration.createMany({
      data: [
        { projectId: project.id, provider: "sentry", config: { endpoint: "/api/v1/ingest/sentry" } },
        { projectId: project.id, provider: "datadog", config: { endpoint: "/api/v1/ingest/datadog" } },
        { projectId: project.id, provider: "cloudwatch", config: { mode: "subscription" } },
        { projectId: project.id, provider: "stripe", config: { revenueMapping: true } },
      ],
      skipDuplicates: true,
    });

    res.status(201).json({ ...project, seededIncidentId: incident.id });
  } catch (error) {
    next(error);
  }
});