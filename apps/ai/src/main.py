import json
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


class AIInput(BaseModel):
    incidentId: str
    service: str
    logs: List[Dict[str, Any]]
    metrics: Dict[str, Any]
    deploymentHistory: Optional[List[Dict[str, Any]]] = None
    revenueContext: Dict[str, Any]


class AnalyzeRequest(BaseModel):
    system_prompt: str
    input: AIInput


class AnalyzeResponse(BaseModel):
    root_cause: str
    business_impact_usd: float
    severity: int = Field(ge=0, le=100)
    explanation: str
    recommended_actions: List[str]
    confidence: Optional[float] = None
    evidence: Optional[List[str]] = None


app = FastAPI(title="AI Incident Layer - AI Engine", version="1.0.0")


def fallback_analysis(payload: AIInput) -> AnalyzeResponse:
    logs = payload.logs[:8]
    dominant_message = logs[0]["message"] if logs else "insufficient data"
    failed_requests = int(payload.metrics.get("failed_requests", 0) or 0)
    avg_order_value = float(payload.revenueContext.get("avgOrderValue", 120))
    conversion_rate = float(payload.revenueContext.get("conversionRate", 0.035))
    impact = round(failed_requests * avg_order_value * conversion_rate, 2)
    severity = max(20, min(95, int(payload.metrics.get("error_rate", 0) * 100)))

    return AnalyzeResponse(
        root_cause=f"Most likely cause: {dominant_message}" if dominant_message != "insufficient data" else "insufficient data",
        business_impact_usd=impact,
        severity=severity,
        explanation="Analysis generated from available logs and metrics only. Confidence is limited because the fallback path does not inspect broader deployment or tracing context.",
        recommended_actions=[
            "Rollback the most recent deployment if the error spike started right after release",
            "Scale the affected service if latency or saturation is contributing",
            "Inspect upstream dependency health and retry behavior",
        ],
        confidence=0.42,
        evidence=[log["message"] for log in logs],
    )


def llm_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or OpenAI is None:
        return fallback_analysis(request.input)

    client = OpenAI(api_key=api_key)
    response = client.responses.create(
        model="gpt-5.4-mini",
        input=[
            {"role": "system", "content": request.system_prompt},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "instruction": "Return only JSON with keys root_cause, business_impact_usd, severity, explanation, recommended_actions, confidence, evidence.",
                        "incident": request.input.model_dump(),
                    }
                ),
            },
        ],
        text={"format": {"type": "json_object"}},
    )

    raw = response.output_text
    parsed = json.loads(raw)
    return AnalyzeResponse(**parsed)


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "ai"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    return llm_analysis(request)