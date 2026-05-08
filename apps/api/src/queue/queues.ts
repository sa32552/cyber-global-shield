import { Queue, Worker } from "bullmq";
import { redis } from "../lib/redis";

export const ingestionQueue = new Queue("ingestion", { connection: redis });
export const analysisQueue = new Queue("analysis", { connection: redis });

export const createWorker = <T>(
  name: string,
  handler: (job: { data: T }) => Promise<void>,
) => new Worker(name, async (job) => handler(job as { data: T }), { connection: redis });