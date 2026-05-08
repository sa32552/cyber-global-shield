import { Router } from "express";
import { prisma } from "../../lib/prisma";

export const alertsRouter = Router();

alertsRouter.get("/list", async (req, res, next) => {
  try {
    const projectId = String(req.query.projectId);
    const integrations = await prisma.integration.findMany({ where: { projectId } });
    res.json(integrations);
  } catch (error) {
    next(error);
  }
});