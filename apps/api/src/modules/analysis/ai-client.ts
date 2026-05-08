import { AIAnalysisResult } from "@ai-incident-layer/shared";
import { env } from "../../config/env";

interface AIRequest {
  incidentId: string;
  service: string;
  logs: Array<{
    timestamp: string;
    message: string;
    metadata: Record<string, unknown>;
  }>;
  metrics: Record<string, unknown>;
  deploymentHistory?: Array<Record<string, unknown>>;
  revenueContext: {
    avgOrderValue: number;
    conversionRate: number;
    failedRequests: number;
  };
}

export const SYSTEM_PROMPT = `You are an expert Site Reliability Engineer and Business Analyst.

Given system logs and metrics:
1. Identify root cause of the incident
2. Estimate business impact in USD
3. Suggest immediate actions
4. Assign severity score (0-100)

Rules:
- Only use provided logs and metrics
- If uncertain, say \"insufficient data\"
- Always return structured JSON
- Do not hallucinate deployments or infrastructure details
- Cite evidence from logs when possible
- Keep reasoning concise, factual, and operationally useful`;

export const analyzeIncident = async (payload: AIRequest): Promise<AIAnalysisResult> => {
  const response = await fetch(`${env.AI_SERVICE_URL}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      system_prompt: SYSTEM_PROMPT,
      input: payload,
    }),
  });

  if (!response.ok) {
    throw new Error(`AI service failed with status ${response.status}`);
  }

  return response.json() as Promise<AIAnalysisResult>;
};