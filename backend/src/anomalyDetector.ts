import axios from 'axios';
import { AnomalyDetectionRequest, AnomalyDetectionResponse, ThreatSeverity } from './types';

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:8001';

/**
 * Fallback statistical heuristic anomaly detection engine in TypeScript.
 * Used when the FastAPI ML microservice is offline or unreachable.
 */
function heuristicAnomalyDetection(req: AnomalyDetectionRequest): AnomalyDetectionResponse {
  let score = 0.15;
  const reasons: string[] = [];

  if (req.failed_logins_last_10m >= 5) {
    score += 0.35 + Math.min(0.3, req.failed_logins_last_10m * 0.02);
    reasons.push(`High failed login rate detected (${req.failed_logins_last_10m} events)`);
  }

  if (req.request_rate_per_min >= 200) {
    score += 0.30 + Math.min(0.2, (req.request_rate_per_min - 200) / 1000);
    reasons.push(`Elevated request throughput (${req.request_rate_per_min} req/min)`);
  }

  if (req.unique_ports_scanned >= 10) {
    score += 0.25;
    reasons.push(`Suspicious port scanning behavior (${req.unique_ports_scanned} ports)`);
  }

  if (req.payload_size_kb >= 150) {
    score += 0.20;
    reasons.push(`Anomalously large payload volume (${req.payload_size_kb.toFixed(1)} KB)`);
  }

  if (req.geo_deviation_score >= 50) {
    score += 0.20;
    reasons.push(`Geo-location outlier profile (${req.geo_deviation_score}/100)`);
  }

  if (req.error_rate_percent >= 40) {
    score += 0.15;
    reasons.push(`Elevated client error response pattern (${req.error_rate_percent}%)`);
  }

  score = Math.min(0.99, Math.max(0.05, score));

  let severity: ThreatSeverity = 'LOW';
  let isAnomaly = false;

  if (score >= 0.80 || req.failed_logins_last_10m >= 20 || req.request_rate_per_min >= 800) {
    severity = 'CRITICAL';
    isAnomaly = true;
  } else if (score >= 0.60 || req.failed_logins_last_10m >= 8) {
    severity = 'HIGH';
    isAnomaly = true;
  } else if (score >= 0.40 || reasons.length > 0) {
    severity = 'MEDIUM';
    isAnomaly = true;
  } else {
    severity = 'LOW';
    isAnomaly = false;
    reasons.push('Traffic matches regular baseline heuristics');
  }

  return {
    is_anomaly: isAnomaly,
    anomaly_score: Number(score.toFixed(3)),
    confidence: 0.88,
    severity,
    reasons,
    model_version: 'typescript-heuristic-engine-v1.0',
    inference_time_ms: 1.2
  };
}

export async function detectAnomaly(req: AnomalyDetectionRequest): Promise<AnomalyDetectionResponse> {
  try {
    const res = await axios.post<AnomalyDetectionResponse>(`${ML_SERVICE_URL}/detect`, req, {
      timeout: 2500
    });
    return res.data;
  } catch (error) {
    // Graceful fallback to heuristic evaluation
    return heuristicAnomalyDetection(req);
  }
}
