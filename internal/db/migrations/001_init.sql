CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS schema_migrations (
    filename TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_by UUID NOT NULL REFERENCES users (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS projects_org_idx ON projects (organization_id);

CREATE TABLE IF NOT EXISTS project_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('zip', 'files', 'github')),
    version_label TEXT NOT NULL,
    storage_key TEXT,
    github_repo TEXT,
    github_ref TEXT,
    commit_sha TEXT,
    token_ciphertext BYTEA,
    file_count INTEGER NOT NULL DEFAULT 0,
    byte_size BIGINT NOT NULL DEFAULT 0,
    created_by UUID NOT NULL REFERENCES users (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS project_sources_project_idx ON project_sources (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    source_id UUID NOT NULL REFERENCES project_sources (id),
    status TEXT NOT NULL CHECK (status IN ('QUEUED', 'PREPARING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    scanners TEXT[] NOT NULL,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES users (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scans_project_idx ON scans (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    scanner TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cwe TEXT,
    cve TEXT,
    file_path TEXT,
    start_line INTEGER,
    end_line INTEGER,
    snippet TEXT,
    remediation TEXT,
    fingerprint TEXT NOT NULL,
    raw JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scan_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings (scan_id);
CREATE INDEX IF NOT EXISTS findings_project_idx ON findings (project_id);
CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings (severity);

CREATE TABLE IF NOT EXISTS scan_logs (
    id BIGSERIAL PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    scanner TEXT,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_logs_scan_idx ON scan_logs (scan_id, id);
