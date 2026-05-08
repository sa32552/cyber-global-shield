import { Router } from "express";
import { prisma } from "../../lib/prisma";

export const servicesRouter = Router();

servicesRouter.get("/list", async (req, res, next) => {
  try {
    const projectId = String(req.query.projectId);
    const services = await prisma.service.findMany({
      where: { projectId },
      include: {
        incidents: {
          where: { status: { in: ["OPEN", "INVESTIGATING"] } },
        },
      },
      orderBy: { name: "asc" },
    });
    res.json(services);
  } catch (error) {
    next(error);
  }
});