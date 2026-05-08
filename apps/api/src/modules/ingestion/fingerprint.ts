import crypto from "crypto";

export const createFingerprint = (service: string, message: string) => {
  const normalized = message.toLowerCase().replace(/\d+/g, "#").slice(0, 160);
  return crypto.createHash("sha256").update(`${service}:${normalized}`).digest("hex");
};

export const toClusterKey = (fingerprint: string, type: string) => `${type}:${fingerprint.slice(0, 16)}`;