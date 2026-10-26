export interface ThreatEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  targetEndpoint: string;
  attackType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  anomalyScore: number;
  status: 'ACTIVE' | 'BLOCKED' | 'INVESTIGATING' | 'RESOLVED';
  payloadSizeKb: number;
  requestRatePerMin: number;
  geoCountry: string;
  explanation: string;
}

export interface ThreatSummary {
  totalThreats: number;
  highCriticalCount: number;
  blockedIpCount: number;
  severityBreakdown: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  attackTypeBreakdown: Record<string, number>;
  topTargetedEndpoints: Array<{ endpoint: string; count: number }>;
  topSourceIps: Array<{ ip: string; count: number }>;
  avgDetectionLatencyMs: number;
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
