import pino from "pino";

export const logger = pino({
  name: "ai-incident-layer-api",
  level: process.env.LOG_LEVEL ?? "info",
});