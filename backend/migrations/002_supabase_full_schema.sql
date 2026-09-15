-- ============================================================
-- Forecast – Full Supabase Schema Migration
-- ============================================================
-- Run this file in the Supabase SQL Editor (Dashboard → SQL Editor → New Query)
-- to create every table the application requires.
--
-- This is IDEMPOTENT: every statement uses IF NOT EXISTS / OR REPLACE
-- so it is safe to re-run.
-- ============================================================


-- ---------- Extensions ----------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";   -- uuid_generate_v4()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";    -- gen_random_uuid(), crypt(), etc.


-- ---------- Helper: auto-update updated_at ----------
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- ============================================================
-- 1. USERS
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id            VARCHAR(36)   PRIMARY KEY DEFAULT uuid_generate_v4()::TEXT,
    email         VARCHAR(320)  NOT NULL UNIQUE,
    password_hash VARCHAR(512)  NOT NULL,
    full_name     VARCHAR(200)  NOT NULL,
    role          VARCHAR(32)   NOT NULL DEFAULT 'VIEWER',
    is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ   NULL,

    CONSTRAINT users_role_check
        CHECK (role IN ('ADMIN', 'DATA_SCIENTIST', 'ANALYST', 'VIEWER'))
);

CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


-- ============================================================
-- 2. USER SESSIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS user_sessions (
    id          VARCHAR(36)   PRIMARY KEY DEFAULT uuid_generate_v4()::TEXT,
    user_id     VARCHAR(36)   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    jti         VARCHAR(64)   NOT NULL UNIQUE,
    token_hash  VARCHAR(64)   NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ   NOT NULL,
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ   NULL
);

CREATE INDEX IF NOT EXISTS ix_user_sessions_user_id  ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_user_sessions_jti      ON user_sessions(jti);


-- ============================================================
-- 3. AUDIT LOGS
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id          VARCHAR(36)   PRIMARY KEY DEFAULT uuid_generate_v4()::TEXT,
    user_id     VARCHAR(36)   NULL REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(100)  NOT NULL,
    resource    VARCHAR(255)  NULL,
    status      VARCHAR(32)   NOT NULL,
    metadata    JSONB         NULL,
    "timestamp" TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id   ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_action    ON audit_logs(action);
CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp ON audit_logs("timestamp");


-- ============================================================
-- 4. THREATS
-- ============================================================
CREATE TABLE IF NOT EXISTS threats (
    id                  VARCHAR(36)    PRIMARY KEY DEFAULT uuid_generate_v4()::TEXT,
    title               VARCHAR(256)   NOT NULL,
    description         VARCHAR(4000)  NOT NULL,
    severity            VARCHAR(16)    NOT NULL,
    src_ip              VARCHAR(45)    NULL,
    dst_ip              VARCHAR(45)    NULL,
    mitre_technique_id  VARCHAR(16)    NULL,
    mitre_tactic        VARCHAR(32)    NULL,
    confidence_score    DOUBLE PRECISION NOT NULL,
    iocs                JSONB          NOT NULL DEFAULT '[]'::JSONB,
    is_resolved         BOOLEAN        NOT NULL DEFAULT FALSE,
    detected_at         TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ    NOT NULL DEFAULT NOW(),

    CONSTRAINT threats_severity_check
        CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS ix_threats_severity           ON threats(severity);
CREATE INDEX IF NOT EXISTS ix_threats_src_ip             ON threats(src_ip);
CREATE INDEX IF NOT EXISTS ix_threats_dst_ip             ON threats(dst_ip);
CREATE INDEX IF NOT EXISTS ix_threats_mitre_technique_id ON threats(mitre_technique_id);
CREATE INDEX IF NOT EXISTS ix_threats_is_resolved        ON threats(is_resolved);

DROP TRIGGER IF EXISTS trg_threats_updated_at ON threats;
CREATE TRIGGER trg_threats_updated_at
    BEFORE UPDATE ON threats
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


-- ============================================================
-- 5. ANOMALIES
-- ============================================================
CREATE TABLE IF NOT EXISTS anomalies (
    id              VARCHAR(36)      PRIMARY KEY DEFAULT uuid_generate_v4()::TEXT,
    flow_id         VARCHAR(128)     NOT NULL,
    src_ip          VARCHAR(45)      NOT NULL,
    dst_ip          VARCHAR(45)      NOT NULL,
    src_port        INTEGER          NULL,
    dst_port        INTEGER          NULL,
    protocol        VARCHAR(16)      NULL,
    anomaly_score   DOUBLE PRECISION NOT NULL,
    is_anomalous    BOOLEAN          NOT NULL DEFAULT FALSE,
    status          VARCHAR(32)      NOT NULL DEFAULT 'pending',
    raw_features    JSONB            NULL,
    analyst_notes   VARCHAR(2000)    NULL,
    detected_at     TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    CONSTRAINT anomalies_status_check
        CHECK (status IN ('pending', 'confirmed', 'false_positive', 'resolved'))
);

CREATE INDEX IF NOT EXISTS ix_anomalies_flow_id      ON anomalies(flow_id);
CREATE INDEX IF NOT EXISTS ix_anomalies_src_ip       ON anomalies(src_ip);
CREATE INDEX IF NOT EXISTS ix_anomalies_dst_ip       ON anomalies(dst_ip);
CREATE INDEX IF NOT EXISTS ix_anomalies_is_anomalous ON anomalies(is_anomalous);
CREATE INDEX IF NOT EXISTS ix_anomalies_status       ON anomalies(status);

DROP TRIGGER IF EXISTS trg_anomalies_updated_at ON anomalies;
CREATE TRIGGER trg_anomalies_updated_at
    BEFORE UPDATE ON anomalies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


-- ============================================================
-- 6. THREAT ↔ ANOMALY LINK (many-to-many)
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_anomaly_links (
    id          VARCHAR(36) PRIMARY KEY DEFAULT uuid_generate_v4()::TEXT,
    threat_id   VARCHAR(36) NOT NULL REFERENCES threats(id)   ON DELETE CASCADE,
    anomaly_id  VARCHAR(36) NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_threat_anomaly_links_threat_id  ON threat_anomaly_links(threat_id);
CREATE INDEX IF NOT EXISTS ix_threat_anomaly_links_anomaly_id ON threat_anomaly_links(anomaly_id);


-- ============================================================
-- 7. FORECASTS
-- ============================================================
CREATE TABLE IF NOT EXISTS forecasts (
    id                VARCHAR(36)      PRIMARY KEY DEFAULT uuid_generate_v4()::TEXT,
    network_segment   VARCHAR(128)     NULL,
    horizon_hours     INTEGER          NOT NULL,
    sequence_length   INTEGER          NOT NULL,
    confidence        VARCHAR(16)      NOT NULL DEFAULT 'medium',
    model_version     VARCHAR(64)      NOT NULL DEFAULT 'v1',
    points            JSONB            NOT NULL,
    peak_threat_level DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    peak_timestamp    TIMESTAMPTZ      NOT NULL,
    generated_at      TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ      NOT NULL DEFAULT NOW(),

    CONSTRAINT forecasts_confidence_check
        CHECK (confidence IN ('low', 'medium', 'high'))
);

CREATE INDEX IF NOT EXISTS ix_forecasts_network_segment ON forecasts(network_segment);


-- ============================================================
-- 8. EVIDENCE
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence (
    id                       VARCHAR(36)   PRIMARY KEY DEFAULT uuid_generate_v4()::TEXT,
    threat_id                VARCHAR(36)   NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
    title                    VARCHAR(256)  NOT NULL,
    description              VARCHAR(2000) NULL,
    payload                  JSONB         NOT NULL,
    content_hash             VARCHAR(64)   NOT NULL,
    status                   VARCHAR(16)   NOT NULL DEFAULT 'draft',
    blockchain_tx_hash       VARCHAR(66)   NULL,
    blockchain_block_number  INTEGER       NULL,
    anchored_at              TIMESTAMPTZ   NULL,
    created_at               TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT evidence_status_check
        CHECK (status IN ('draft', 'hashed', 'anchored', 'verified', 'tampered'))
);

CREATE INDEX IF NOT EXISTS ix_evidence_threat_id    ON evidence(threat_id);
CREATE INDEX IF NOT EXISTS ix_evidence_content_hash ON evidence(content_hash);
CREATE INDEX IF NOT EXISTS ix_evidence_status       ON evidence(status);

DROP TRIGGER IF EXISTS trg_evidence_updated_at ON evidence;
CREATE TRIGGER trg_evidence_updated_at
    BEFORE UPDATE ON evidence
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


-- ============================================================
-- Done! All 8 tables are ready.
-- ============================================================
