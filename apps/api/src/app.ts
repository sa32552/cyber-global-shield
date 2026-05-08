import cors from "cors";
import express from "express";
import helmet from "helmet";
import pinoHttp from "pino-http";
import { logger } from "./lib/logger";
import { healthRouter } from "./modules/health";
import { ingestionRouter } from "./modules/ingestion/routes";
import { incidentRouter } from "./modules/incidents/routes";
import { servicesRouter } from "./modules/services/routes";
import { projectsRouter } from "./modules/services/projects.routes";
import { alertsRouter } from "./modules/alerts/routes";
import { integrationsRouter } from "./modules/integrations/routes";

export const createApp = () => {
  const app = express();

  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: "2mb" }));
  app.use(pinoHttp({ logger }));

  app.use("/api/v1", healthRouter);
  app.use("/api/v1/ingest", ingestionRouter);
  app.use("/api/v1/incidents", incidentRouter);
  app.use("/api/v1/projects", projectsRouter);
  app.use("/api/v1/services", servicesRouter);
  app.use("/api/v1/alerts", alertsRouter);
  app.use("/api/v1/integrations", integrationsRouter);

  app.use((error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    logger.error({ err: error }, "request failed");
    res.status(500).json({ message: error.message });
  });

  return app;
};
