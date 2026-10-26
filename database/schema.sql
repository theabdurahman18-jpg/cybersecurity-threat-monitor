CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'analyst',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_events (
    id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    target_endpoint VARCHAR(255) NOT NULL,
    attack_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    anomaly_score DOUBLE PRECISION NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    payload_size_kb DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    request_rate_per_min DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    geo_country VARCHAR(10) NOT NULL DEFAULT 'UNKNOWN',
    explanation TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id VARCHAR(64) PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason VARCHAR(255) NOT NULL,
    blocked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    blocked_by VARCHAR(50) NOT NULL DEFAULT 'system_heuristic'
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    actor VARCHAR(50) NOT NULL,
    details TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_events(severity);
CREATE INDEX IF NOT EXISTS idx_threat_source_ip ON threat_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_events(timestamp);
