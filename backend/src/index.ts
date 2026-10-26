import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { z } from 'zod';

import { store } from './store';
import { authenticate, generateToken, AuthRequest, requireRole } from './auth';
import { detectAnomaly } from './anomalyDetector';
import { socketManager } from './websocket';
import { ThreatEvent, ThreatSeverity } from './types';

dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Initialize WebSocket Gateway
socketManager.init(server);

// --- Health Check ---
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'online',
    service: 'cybersecurity-threat-monitor-backend',
    timestamp: new Date().toISOString(),
    activeSockets: socketManager.getConnectedCount()
  });
});

// --- Auth Endpoints ---
const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1)
});

app.post('/api/auth/login', (req: Request, res: Response) => {
  const parseResult = loginSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'Invalid input', details: parseResult.error.format() });
  }

  const { username, password } = parseResult.data;
  const user = store.getUserByUsername(username);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid username or credentials' });
  }

  const token = generateToken({ id: user.id, username: user.username, role: user.role });
  store.addAuditLog('USER_LOGIN', user.username, `Successful authentication as ${user.role}`);

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    }
  });
});

app.get('/api/auth/me', authenticate, (req: AuthRequest, res: Response) => {
  res.json({ user: req.user });
});

// --- Threat Endpoints ---
app.get('/api/threats', (req: Request, res: Response) => {
  const { severity, ip, limit = '50', offset = '0', attackType } = req.query;

  let threats = store.getAllThreats();

  if (severity && typeof severity === 'string' && severity !== 'ALL') {
    threats = threats.filter(t => t.severity.toUpperCase() === severity.toUpperCase());
  }

  if (ip && typeof ip === 'string') {
    threats = threats.filter(t => t.sourceIp.includes(ip));
  }

  if (attackType && typeof attackType === 'string' && attackType !== 'ALL') {
    threats = threats.filter(t => t.attackType.toLowerCase().includes(attackType.toLowerCase()));
  }

  const total = threats.length;
  const numLimit = parseInt(limit as string, 10) || 50;
  const numOffset = parseInt(offset as string, 10) || 0;
  const paginated = threats.slice(numOffset, numOffset + numLimit);

  res.json({
    total,
    limit: numLimit,
    offset: numOffset,
    data: paginated
  });
});

app.get('/api/threats/summary', (req: Request, res: Response) => {
  const threats = store.getAllThreats();
  const blockedIps = store.getBlockedIps();

  const severityCounts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  const attackTypeCounts: Record<string, number> = {};
  const ipCounts: Record<string, number> = {};
  const endpointCounts: Record<string, number> = {};

  for (const t of threats) {
    severityCounts[t.severity] = (severityCounts[t.severity] || 0) + 1;
    attackTypeCounts[t.attackType] = (attackTypeCounts[t.attackType] || 0) + 1;
    ipCounts[t.sourceIp] = (ipCounts[t.sourceIp] || 0) + 1;
    endpointCounts[t.targetEndpoint] = (endpointCounts[t.targetEndpoint] || 0) + 1;
  }

  const topTargetedEndpoints = Object.entries(endpointCounts)
    .map(([endpoint, count]) => ({ endpoint, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const topSourceIps = Object.entries(ipCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  res.json({
    totalThreats: threats.length,
    highCriticalCount: severityCounts.CRITICAL + severityCounts.HIGH,
    blockedIpCount: blockedIps.length,
    severityBreakdown: severityCounts,
    attackTypeBreakdown: attackTypeCounts,
    topTargetedEndpoints,
    topSourceIps,
    avgDetectionLatencyMs: 14.2
  });
});

app.patch('/api/threats/:id/status', authenticate, (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const { status } = req.body;

  const validStatuses = ['ACTIVE', 'BLOCKED', 'INVESTIGATING', 'RESOLVED'];
  if (!status || !validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status value' });
  }

  const updated = store.updateThreatStatus(id, status);
  if (!updated) {
    return res.status(404).json({ error: 'Threat event not found' });
  }

  store.addAuditLog('STATUS_UPDATE', req.user?.username || 'ANALYST', `Updated threat ${id} status to ${status}`);
  socketManager.broadcast('THREAT_STATUS_UPDATED', updated);

  res.json(updated);
});

// --- Blocked IPs Endpoints ---
app.get('/api/blocked-ips', (req: Request, res: Response) => {
  res.json(store.getBlockedIps());
});

app.post('/api/blocked-ips', authenticate, requireRole(['secops_admin']), (req: AuthRequest, res: Response) => {
  const { ipAddress, reason } = req.body;
  if (!ipAddress || typeof ipAddress !== 'string') {
    return res.status(400).json({ error: 'ipAddress is required' });
  }

  const blocked = store.blockIp(ipAddress, reason || 'Manual Admin Quarantine', req.user?.username || 'admin');
  store.addAuditLog('IP_BLOCK', req.user?.username || 'admin', `Quarantined IP ${ipAddress} - ${reason}`);
  socketManager.broadcast('IP_BLOCKED', blocked);

  res.status(201).json(blocked);
});

app.delete('/api/blocked-ips/:ip', authenticate, requireRole(['secops_admin']), (req: AuthRequest, res: Response) => {
  const { ip } = req.params;
  const removed = store.unblockIp(ip);
  if (removed) {
    store.addAuditLog('IP_UNBLOCK', req.user?.username || 'admin', `Released IP ${ip} from quarantine`);
    socketManager.broadcast('IP_UNBLOCKED', { ipAddress: ip });
    return res.json({ success: true, message: `IP ${ip} unblocked successfully` });
  }
  return res.status(404).json({ error: 'IP not found in blocked list' });
});

// --- Audit Logs ---
app.get('/api/audit-logs', (req: Request, res: Response) => {
  res.json(store.getAuditLogs());
});

// --- Threat Simulation / Injection Endpoint ---
const simulateSchema = z.object({
  type: z.enum(['brute_force', 'port_scan', 'ddos_surge', 'sql_injection', 'credential_stuffing']),
  customIp: z.string().optional()
});

app.post('/api/threats/simulate', async (req: Request, res: Response) => {
  const parseResult = simulateSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'Invalid simulation payload', details: parseResult.error.format() });
  }

  const simType = parseResult.data.type;
  let eventPayload: any = {};

  switch (simType) {
    case 'brute_force':
      eventPayload = {
        attackType: 'Brute Force Attack',
        source_ip: parseResult.data.customIp || `198.51.100.${Math.floor(Math.random() * 200 + 10)}`,
        target_endpoint: '/api/v1/auth/login',
        request_rate_per_min: 450 + Math.random() * 300,
        failed_logins_last_10m: Math.floor(Math.random() * 25) + 15,
        payload_size_kb: 4.8,
        geo_deviation_score: 82.5,
        unique_ports_scanned: 1,
        error_rate_percent: 88.0,
        geoCountry: 'RU'
      };
      break;

    case 'ddos_surge':
      eventPayload = {
        attackType: 'DDoS Surge',
        source_ip: parseResult.data.customIp || `203.0.113.${Math.floor(Math.random() * 200 + 10)}`,
        target_endpoint: '/api/v1/search',
        request_rate_per_min: 1600 + Math.random() * 900,
        failed_logins_last_10m: 1,
        payload_size_kb: 95.2,
        geo_deviation_score: 91.0,
        unique_ports_scanned: 3,
        error_rate_percent: 65.0,
        geoCountry: 'CN'
      };
      break;

    case 'port_scan':
      eventPayload = {
        attackType: 'Network Port Reconnaissance',
        source_ip: parseResult.data.customIp || `185.220.101.${Math.floor(Math.random() * 200 + 10)}`,
        target_endpoint: '/api/v1/internal/admin',
        request_rate_per_min: 120 + Math.random() * 80,
        failed_logins_last_10m: 0,
        payload_size_kb: 1.5,
        geo_deviation_score: 65.0,
        unique_ports_scanned: Math.floor(Math.random() * 50) + 15,
        error_rate_percent: 45.0,
        geoCountry: 'DE'
      };
      break;

    case 'sql_injection':
      eventPayload = {
        attackType: 'SQL Injection Probe',
        source_ip: parseResult.data.customIp || `192.0.2.${Math.floor(Math.random() * 200 + 10)}`,
        target_endpoint: '/api/v1/checkout?sku=1%27+OR+1%3D1--',
        request_rate_per_min: 65 + Math.random() * 40,
        failed_logins_last_10m: 2,
        payload_size_kb: 18.5,
        geo_deviation_score: 45.0,
        unique_ports_scanned: 1,
        error_rate_percent: 50.0,
        geoCountry: 'IR'
      };
      break;

    default:
      eventPayload = {
        attackType: 'Credential Stuffing Bot',
        source_ip: parseResult.data.customIp || `45.33.32.${Math.floor(Math.random() * 200 + 10)}`,
        target_endpoint: '/api/v1/auth/sso',
        request_rate_per_min: 320 + Math.random() * 120,
        failed_logins_last_10m: 12,
        payload_size_kb: 8.2,
        geo_deviation_score: 77.0,
        unique_ports_scanned: 2,
        error_rate_percent: 70.0,
        geoCountry: 'US'
      };
  }

  // Communicate with ML microservice or fallback heuristic
  const anomalyResult = await detectAnomaly({
    source_ip: eventPayload.source_ip,
    target_endpoint: eventPayload.target_endpoint,
    request_rate_per_min: eventPayload.request_rate_per_min,
    failed_logins_last_10m: eventPayload.failed_logins_last_10m,
    payload_size_kb: eventPayload.payload_size_kb,
    geo_deviation_score: eventPayload.geo_deviation_score,
    unique_ports_scanned: eventPayload.unique_ports_scanned,
    error_rate_percent: eventPayload.error_rate_percent
  });

  const isBlocked = store.isIpBlocked(eventPayload.source_ip);

  const newThreat: ThreatEvent = {
    id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    timestamp: new Date().toISOString(),
    sourceIp: eventPayload.source_ip,
    targetEndpoint: eventPayload.target_endpoint,
    attackType: eventPayload.attackType,
    severity: anomalyResult.severity,
    anomalyScore: anomalyResult.anomaly_score,
    status: isBlocked ? 'BLOCKED' : (anomalyResult.severity === 'CRITICAL' ? 'BLOCKED' : 'ACTIVE'),
    payloadSizeKb: Math.round(eventPayload.payload_size_kb * 10) / 10,
    requestRatePerMin: Math.round(eventPayload.request_rate_per_min),
    geoCountry: eventPayload.geoCountry,
    explanation: anomalyResult.reasons.join('; ')
  };

  // If critical, auto block
  if (anomalyResult.severity === 'CRITICAL' && !isBlocked) {
    store.blockIp(newThreat.sourceIp, `Automated response: ${newThreat.attackType}`, 'auto_soc_engine');
  }

  store.addThreat(newThreat);
  store.addAuditLog('SIMULATION_INJECTED', 'SIMULATOR', `Triggered simulated attack '${newThreat.attackType}' from ${newThreat.sourceIp} [Severity: ${newThreat.severity}]`);

  // Broadcast over WebSocket
  socketManager.broadcastThreat(newThreat);

  res.status(201).json({
    message: 'Simulation security threat injected and broadcasted',
    threat: newThreat,
    anomalyEvaluation: anomalyResult
  });
});

// Centralized error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('[Backend Error]:', err.message);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message
  });
});

export { app, server };

if (process.env.NODE_ENV !== 'test') {
  server.listen(PORT, () => {
    console.log(`[Cyber SOC Backend] Server listening on http://localhost:${PORT}`);
    console.log(`[Cyber SOC Backend] Real-time WebSocket streaming at ws://localhost:${PORT}/ws`);
  });
}
