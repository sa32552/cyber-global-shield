import { Router } from "express";
import { prisma } from "../../lib/prisma";

export const incidentRouter = Router();

incidentRouter.get("/overview", async (req, res, next) => {
  try {
    const projectId = String(req.query.projectId);
    const [totalIncidents, activeIncidents, incidents] = await Promise.all([
      prisma.incident.count({ where: { projectId } }),
      prisma.incident.count({ where: { projectId, status: { in: ["OPEN", "INVESTIGATING"] } } }),
      prisma.incident.findMany({ where: { projectId }, select: { businessLossUsd: true, startTime: true, endTime: true } }),
    ]);

    const totalLossUsd = incidents.reduce((sum, incident) => sum + Number(incident.businessLossUsd), 0);
    const mttrMinutes = incidents.length
      ? Math.round(
          incidents.reduce((sum, incident) => {
            const end = incident.endTime ?? new Date();
            return sum + (end.getTime() - incident.startTime.getTime()) / 60000;
          }, 0) / incidents.length,
        )
      : 0;

    res.json({ totalIncidents, activeIncidents, totalLossUsd, mttrMinutes });
  } catch (error) {
    next(error);
  }
});

incidentRouter.get("/list", async (req, res, next) => {
  try {
    const projectId = String(req.query.projectId);
    const incidents = await prisma.incident.findMany({
      where: { projectId },
      include: {
        service: true,
        analyses: { orderBy: { createdAt: "desc" }, take: 1 },
      },
      orderBy: { updatedAt: "desc" },
    });
    res.json(incidents);
  } catch (error) {
    next(error);
  }
});

incidentRouter.get("/:id", async (req, res, next) => {
  try {
    const incident = await prisma.incident.findUnique({
      where: { id: req.params.id },
      include: {
        service: true,
        analyses: { orderBy: { createdAt: "desc" } },
        actions: true,
        logs: {
          include: { log: true },
        },
      },
    });

    if (!incident) {
      res.status(404).json({ message: "Incident not found" });
      return;
    }

    res.json(incident);
  } catch (error) {
    next(error);
  }
});