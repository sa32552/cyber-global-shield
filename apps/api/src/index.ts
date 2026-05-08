import { createServer } from "http";
import { env } from "./config/env";
import { createApp } from "./app";
import { initRealtime } from "./modules/realtime/socket";
import { createWorker } from "./queue/queues";
import { runAIAnalysisForIncident } from "./modules/incidents/analysis.service";
import { logger } from "./lib/logger";

const app = createApp();
const server = createServer(app);
initRealtime(server);

createWorker<{ incidentId: string }>("analysis", async (job) => {
  await runAIAnalysisForIncident(job.data.incidentId);
});

server.listen(env.API_PORT, () => {
  logger.info(`API listening on port ${env.API_PORT}`);
});