import bcrypt from 'bcryptjs';
import { User, ThreatEvent, BlockedIp, AuditLog } from './types';

// Pre-computed bcrypt hash for 'admin123' and 'analyst123'
const ADMIN_HASH = bcrypt.hashSync('admin123', 10);
const ANALYST_HASH = bcrypt.hashSync('analyst123', 10);

class InMemoryStore {
  private users: Map<string, User> = new Map();
  private threats: ThreatEvent[] = [];
  private blockedIps: Map<string, BlockedIp> = new Map();
  private auditLogs: AuditLog[] = [];

  constructor() {
    this.seedUsers();
    this.seedBlockedIps();
    this.seedThreats();
    this.seedAuditLogs();
  }

  private seedUsers() {
    this.users.set('admin', {
      id: 'usr_sec_admin',
      username: 'admin',
      passwordHash: ADMIN_HASH,
      role: 'secops_admin',
      createdAt: new Date().toISOString()
    });

    this.users.set('analyst', {
      id: 'usr_sec_analyst',
      username: 'analyst',
      passwordHash: ANALYST_HASH,
      role: 'security_analyst',
      createdAt: new Date().toISOString()
    });
  }

  private seedBlockedIps() {
    const defaultBlocked: BlockedIp[] = [
      {
        id: 'blk_01',
        ipAddress: '198.51.100.44',
        reason: 'Exceeded SSH login failure threshold (50+ attempts)',
        blockedAt: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
        blockedBy: 'auto_ips'
      },
      {
        id: 'blk_02',
        ipAddress: '203.0.113.89',
        reason: 'Distributed volumetric layer 7 HTTP flood',
        blockedAt: new Date(Date.now() - 18 * 60 * 1000).toISOString(),
        blockedBy: 'ml_model'
      },
      {
        id: 'blk_03',
        ipAddress: '192.0.2.14',
        reason: 'Known malicious botnet node - C2 beaconing',
        blockedAt: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
        blockedBy: 'threat_intel'
      }
    ];

    for (const b of defaultBlocked) {
      this.blockedIps.set(b.ipAddress, b);
    }
  }

  private seedThreats() {
    this.threats = [
      {
        id: 'evt_01',
        timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
        sourceIp: '198.51.100.44',
        targetEndpoint: '/api/v1/auth/login',
        attackType: 'Brute Force Attack',
        severity: 'CRITICAL',
        anomalyScore: 0.94,
        status: 'BLOCKED',
        payloadSizeKb: 4.2,
        requestRatePerMin: 540.0,
        geoCountry: 'RU',
        explanation: 'High failed login attempts (42 attempts in 10m); Volumetric request spike'
      },
      {
        id: 'evt_02',
        timestamp: new Date(Date.now() - 18 * 60 * 1000).toISOString(),
        sourceIp: '203.0.113.89',
        targetEndpoint: '/api/v1/search',
        attackType: 'DDoS Surge',
        severity: 'CRITICAL',
        anomalyScore: 0.91,
        status: 'BLOCKED',
        payloadSizeKb: 88.5,
        requestRatePerMin: 1420.0,
        geoCountry: 'CN',
        explanation: 'Volumetric request spike (1420 req/min); Abnormal geo-deviation'
      },
      {
        id: 'evt_03',
        timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
        sourceIp: '192.0.2.14',
        targetEndpoint: '/api/v1/checkout',
        attackType: 'SQL Injection Injection Probe',
        severity: 'HIGH',
        anomalyScore: 0.78,
        status: 'ACTIVE',
        payloadSizeKb: 12.8,
        requestRatePerMin: 48.0,
        geoCountry: 'IR',
        explanation: 'Suspicious payload patterns detected in query parameters'
      },
      {
        id: 'evt_04',
        timestamp: new Date(Date.now() - 7 * 60 * 1000).toISOString(),
        sourceIp: '45.33.32.156',
        targetEndpoint: '/api/v1/admin/debug',
        attackType: 'Unauthorized Privilege Escalation',
        severity: 'HIGH',
        anomalyScore: 0.72,
        status: 'ACTIVE',
        payloadSizeKb: 3.1,
        requestRatePerMin: 15.0,
        geoCountry: 'US',
        explanation: 'Unauthenticated request to restricted admin endpoint from external range'
      },
      {
        id: 'evt_05',
        timestamp: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
        sourceIp: '185.220.101.5',
        targetEndpoint: '/api/v1/users',
        attackType: 'Network Port Reconnaissance',
        severity: 'MEDIUM',
        anomalyScore: 0.61,
        status: 'ACTIVE',
        payloadSizeKb: 1.2,
        requestRatePerMin: 85.0,
        geoCountry: 'DE',
        explanation: 'Port scanning behavior detected (18 unique ports contacted)'
      },
      {
        id: 'evt_06',
        timestamp: new Date(Date.now() - 1 * 60 * 1000).toISOString(),
        sourceIp: '103.21.244.0',
        targetEndpoint: '/api/v1/catalog',
        attackType: 'Rate Limit Abuse / Scraper',
        severity: 'LOW',
        anomalyScore: 0.38,
        status: 'ACTIVE',
        payloadSizeKb: 2.0,
        requestRatePerMin: 95.0,
        geoCountry: 'SG',
        explanation: 'Moderate burst frequency matching common web crawling patterns'
      }
    ];
  }

  private seedAuditLogs() {
    this.auditLogs = [
      {
        id: 'aud_01',
        action: 'SYSTEM_INITIALIZATION',
        actor: 'SYSTEM',
        details: 'Cyber Threat Detection Engine & ML pipeline booted',
        timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString()
      },
      {
        id: 'aud_02',
        action: 'AUTO_IP_BLOCK',
        actor: 'SOC_AUTOMATION',
        details: 'Blocked IP 198.51.100.44 following critical brute-force violation',
        timestamp: new Date(Date.now() - 24 * 60 * 1000).toISOString()
      },
      {
        id: 'aud_03',
        action: 'FIREWALL_RULE_ENFORCE',
        actor: 'SYSTEM',
        details: 'Mitigated DDoS surge from 203.0.113.89 with rate-limit drop',
        timestamp: new Date(Date.now() - 17 * 60 * 1000).toISOString()
      }
    ];
  }

  // User queries
  getUserByUsername(username: string): User | undefined {
    return this.users.get(username);
  }

  getUserById(id: string): User | undefined {
    for (const u of this.users.values()) {
      if (u.id === id) return u;
    }
    return undefined;
  }

  // Threat operations
  getAllThreats(): ThreatEvent[] {
    return [...this.threats];
  }

  addThreat(threat: ThreatEvent): ThreatEvent {
    this.threats.unshift(threat);
    return threat;
  }

  updateThreatStatus(id: string, status: ThreatEvent['status']): ThreatEvent | undefined {
    const item = this.threats.find(t => t.id === id);
    if (item) {
      item.status = status;
    }
    return item;
  }

  // Blocked IPs
  getBlockedIps(): BlockedIp[] {
    return Array.from(this.blockedIps.values());
  }

  isIpBlocked(ip: string): boolean {
    return this.blockedIps.has(ip);
  }

  blockIp(ipAddress: string, reason: string, blockedBy: string): BlockedIp {
    const record: BlockedIp = {
      id: `blk_${Date.now()}`,
      ipAddress,
      reason,
      blockedAt: new Date().toISOString(),
      blockedBy
    };
    this.blockedIps.set(ipAddress, record);
    return record;
  }

  unblockIp(ipAddress: string): boolean {
    return this.blockedIps.delete(ipAddress);
  }

  // Audit logs
  getAuditLogs(): AuditLog[] {
    return [...this.auditLogs];
  }

  addAuditLog(action: string, actor: string, details: string): AuditLog {
    const entry: AuditLog = {
      id: `aud_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      action,
      actor,
      details,
      timestamp: new Date().toISOString()
    };
    this.auditLogs.unshift(entry);
    return entry;
  }
}

export const store = new InMemoryStore();
