"""
FastAPI Microservice for Real-Time Threat Anomaly Detection
Provides REST endpoints for scoring security events via Isolation Forest & Statistical Heuristics.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import numpy as np
import time
import os

from model import load_or_train, FEATURES

app = FastAPI(
    title="Cybersecurity Anomaly Detection ML Microservice",
    description="Isolation Forest ML service for evaluating real-time cybersecurity telemetry and detecting network threats.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load or initialize Isolation Forest
model, scaler = load_or_train()

class SecurityEventPayload(BaseModel):
    event_id: Optional[str] = Field(None, description="Unique trace ID for the security event")
    source_ip: Optional[str] = Field("192.168.1.100", description="Originating IPv4 or IPv6 address")
    target_endpoint: Optional[str] = Field("/api/v1/auth/login", description="Target URI endpoint")
    request_rate_per_min: float = Field(..., ge=0, description="Observed requests per minute from this IP")
    failed_logins_last_10m: int = Field(0, ge=0, description="Consecutive failed authentication events")
    payload_size_kb: float = Field(0.0, ge=0, description="Size of payload in Kilobytes")
    geo_deviation_score: float = Field(0.0, ge=0, le=100, description="Deviation from expected geolocation (0-100)")
    unique_ports_scanned: int = Field(1, ge=1, description="Number of distinct network ports contacted")
    error_rate_percent: float = Field(0.0, ge=0, le=100, description="Percentage of 4xx/5xx responses")

class AnomalyResponse(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    severity: str
    reasons: List[str]
    model_version: str
    inference_time_ms: float

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "cybersecurity-threat-ml-service",
        "model_loaded": model is not None,
        "features": FEATURES
    }

@app.get("/model-info")
def model_info():
    return {
        "algorithm": "Isolation Forest",
        "contamination_rate": 0.08,
        "features": FEATURES,
        "input_dimensions": len(FEATURES),
        "status": "trained and active"
    }

@app.post("/detect", response_model=AnomalyResponse)
def detect_threat(event: SecurityEventPayload):
    start_time = time.perf_counter()
    
    # Feature vector construction
    vector = np.array([[
        event.request_rate_per_min,
        event.failed_logins_last_10m,
        event.payload_size_kb,
        event.geo_deviation_score,
        event.unique_ports_scanned,
        event.error_rate_percent
    ]])

    try:
        scaled_vector = scaler.transform(vector)
        # Isolation Forest decision_function: lower values indicate anomaly
        raw_score = float(model.decision_function(scaled_vector)[0])
        pred = int(model.predict(scaled_vector)[0]) # -1 = anomaly, 1 = normal
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

    # Normalize raw score (-0.5 to 0.5 typical) into normalized anomaly score 0.0 to 1.0 (higher = worse threat)
    normalized_score = max(0.0, min(1.0, float(0.5 - raw_score)))
    is_anomaly = bool(pred == -1 or normalized_score >= 0.58)

    # Statistical heuristic explanations
    reasons = []
    if event.failed_logins_last_10m >= 5:
        reasons.append(f"High failed login attempts ({event.failed_logins_last_10m} attempts in 10m)")
    if event.request_rate_per_min >= 200:
        reasons.append(f"Volumetric request spike ({event.request_rate_per_min:.0f} req/min)")
    if event.unique_ports_scanned >= 10:
        reasons.append(f"Port scanning behavior detected ({event.unique_ports_scanned} unique ports)")
    if event.payload_size_kb >= 150:
        reasons.append(f"Oversized suspicious payload ({event.payload_size_kb:.1f} KB)")
    if event.geo_deviation_score >= 50:
        reasons.append(f"Abnormal geo-deviation anomaly score ({event.geo_deviation_score:.1f}/100)")
    if event.error_rate_percent >= 40:
        reasons.append(f"Elevated HTTP error rate ({event.error_rate_percent:.1f}%)")

    # Determine Severity classification
    if normalized_score >= 0.85 or event.failed_logins_last_10m >= 20 or event.request_rate_per_min >= 800:
        severity = "CRITICAL"
        is_anomaly = True
    elif normalized_score >= 0.65 or event.failed_logins_last_10m >= 10 or event.unique_ports_scanned >= 20:
        severity = "HIGH"
        is_anomaly = True
    elif normalized_score >= 0.45 or len(reasons) > 0:
        severity = "MEDIUM"
        is_anomaly = True
    else:
        severity = "LOW"
        is_anomaly = False

    if not reasons:
        reasons.append("Behavior conforms to regular operational traffic baselines")

    inference_time = (time.perf_counter() - start_time) * 1000.0

    return AnomalyResponse(
        is_anomaly=is_anomaly,
        anomaly_score=round(normalized_score, 4),
        confidence=round(min(0.99, max(0.50, abs(raw_score) * 2 + 0.5)), 3),
        severity=severity,
        reasons=reasons,
        model_version="isolation-forest-v1.0",
        inference_time_ms=round(inference_time, 2)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
