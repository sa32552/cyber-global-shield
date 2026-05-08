import { config as loadEnv } from "dotenv";
import { z } from "zod";

loadEnv();

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  API_PORT: z.coerce.number().default(4000),
  AI_SERVICE_URL: z.string().url(),
  JWT_SECRET: z.string().min(1),
  DEFAULT_AVG_ORDER_VALUE: z.coerce.number().default(120),
  DEFAULT_CONVERSION_RATE: z.coerce.number().default(0.035),
});

export const env = envSchema.parse(process.env);