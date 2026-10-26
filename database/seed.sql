-- Seed administrative user (password: admin123)
-- bcrypt hash for 'admin123' with 10 salt rounds: $2a$10$wT0/K9G96yvG.y0n4nQ06uXk73uWl9Qc1.iG/gC7Nl7.b0bHq7bcy
INSERT INTO users (id, username, password_hash, role) 
VALUES ('usr_sec_admin', 'admin', '$2a$10$3e8l8BqV41PqO4M0zP9qAeVwA9B935sD1rGv12f/39kF1Z7Z7oG7q', 'secops_admin')
ON CONFLICT (username) DO NOTHING;

-- Seed analyst user (password: analyst123)
INSERT INTO users (id, username, password_hash, role) 
VALUES ('usr_sec_analyst', 'analyst', '$2a$10$3e8l8BqV41PqO4M0zP9qAeVwA9B935sD1rGv12f/39kF1Z7Z7oG7q', 'security_analyst')
ON CONFLICT (username) DO NOTHING;

-- Initial Blocked IPs
INSERT INTO blocked_ips (id, ip_address, reason, blocked_by) VALUES
('blk_01', '198.51.100.44', 'Exceeded SSH login failure threshold (50+ attempts)', 'auto_ips'),
('blk_02', '203.0.113.89', 'Distributed volumetric layer 7 HTTP flood', 'ml_model'),
('blk_03', '192.0.2.14', 'Known malicious botnet node - C2 beaconing', 'threat_intel')
ON CONFLICT (ip_address) DO NOTHING;

-- Initial Threat Incidents
INSERT INTO threat_events (id, timestamp, source_ip, target_endpoint, attack_type, severity, anomaly_score, status, payload_size_kb, request_rate_per_min, geo_country, explanation) VALUES
('evt_01', CURRENT_TIMESTAMP - INTERVAL '25 minutes', '198.51.100.44', '/api/v1/auth/login', 'Brute Force Attack', 'CRITICAL', 0.94, 'BLOCKED', 4.2, 540.0, 'RU', 'High failed login attempts (42 attempts in 10m); Volumetric request spike'),
('evt_02', CURRENT_TIMESTAMP - INTERVAL '18 minutes', '203.0.113.89', '/api/v1/search', 'DDoS Surge', 'CRITICAL', 0.91, 'BLOCKED', 88.5, 1420.0, 'CN', 'Volumetric request spike (1420 req/min); Abnormal geo-deviation'),
('evt_03', CURRENT_TIMESTAMP - INTERVAL '12 minutes', '192.0.2.14', '/api/v1/checkout', 'SQL Injection Injection Probe', 'HIGH', 0.78, 'ACTIVE', 12.8, 48.0, 'IR', 'Suspicious payload patterns detected in query parameters'),
('evt_04', CURRENT_TIMESTAMP - INTERVAL '7 minutes', '45.33.32.156', '/api/v1/admin/debug', 'Unauthorized Privilege Escalation', 'HIGH', 0.72, 'ACTIVE', 3.1, 15.0, 'US', 'Unauthenticated request to restricted admin endpoint from external range'),
('evt_05', CURRENT_TIMESTAMP - INTERVAL '4 minutes', '185.220.101.5', '/api/v1/users', 'Network Port Reconnaissance', 'MEDIUM', 0.61, 'ACTIVE', 1.2, 85.0, 'DE', 'Port scanning behavior detected (18 unique ports contacted)'),
('evt_06', CURRENT_TIMESTAMP - INTERVAL '1 minute', '103.21.244.0', '/api/v1/catalog', 'Rate Limit Abuse / Scraper', 'LOW', 0.38, 'ACTIVE', 2.0, 95.0, 'SG', 'Moderate burst frequency matching common web crawling patterns');

-- Initial Audit Logs
INSERT INTO audit_logs (id, action, actor, details, timestamp) VALUES
('aud_01', 'SYSTEM_INITIALIZATION', 'SYSTEM', 'Cyber Threat Detection Engine & ML pipeline booted', CURRENT_TIMESTAMP - INTERVAL '30 minutes'),
('aud_02', 'AUTO_IP_BLOCK', 'SOC_AUTOMATION', 'Blocked IP 198.51.100.44 following critical brute-force violation', CURRENT_TIMESTAMP - INTERVAL '24 minutes'),
('aud_03', 'FIREWALL_RULE_ENFORCE', 'SYSTEM', 'Mitigated DDoS surge from 203.0.113.89 with rate-limit drop', CURRENT_TIMESTAMP - INTERVAL '17 minutes');
