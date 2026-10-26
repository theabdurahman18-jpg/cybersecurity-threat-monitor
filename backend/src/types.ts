export interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: 'secops_admin' | 'security_analyst' | 'viewer';
  createdAt: string;
}

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type ThreatStatus = 'ACTIVE' | 'BLOCKED' | 'INVESTIGATING' | 'RESOLVED';

export interface ThreatEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  targetEndpoint: string;
  attackType: string;
  severity: ThreatSeverity;
  anomalyScore: number;
  status: ThreatStatus;
  payloadSizeKb: number;
  requestRatePerMin: number;
  geoCountry: string;
  explanation: string;
}

export interface BlockedIp {
  id: string;
  ipAddress: string;
  reason: string;
  blockedAt: string;
  blockedBy: string;
}

export interface AuditLog {
  id: string;
  action: string;
  actor: string;
  details: string;
  timestamp: string;
}

export interface AnomalyDetectionRequest {
  event_id?: string;
  source_ip: string;
  target_endpoint: string;
  request_rate_per_min: number;
  failed_logins_last_10m: number;
  payload_size_kb: number;
  geo_deviation_score: number;
  unique_ports_scanned: number;
  error_rate_percent: number;
}

export interface AnomalyDetectionResponse {
  is_anomaly: boolean;
  anomaly_score: number;
  confidence: number;
  severity: ThreatSeverity;
  reasons: string[];
  model_version: string;
  inference_time_ms: number;
}
