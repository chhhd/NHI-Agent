CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$ BEGIN
    CREATE TYPE connector_status AS ENUM (
        'PENDING', 'CONFIGURED', 'CONNECTED', 'DEGRADED', 'DISCONNECTED', 'ERROR'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE finding_status AS ENUM (
        'NEW', 'TRIAGED', 'ASSIGNED', 'REMEDIATION_IN_PROGRESS',
        'CREDENTIAL_REVOKED', 'RESCAN_PENDING', 'RESOLVED', 'REOPENED',
        'RECURRENCE', 'FALSE_POSITIVE', 'EXCEPTION', 'NEEDS_REVIEW',
        'SLA_OVERDUE', 'ACCEPTED_RISK'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS owners (
    owner_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    owner_type TEXT NOT NULL DEFAULT 'TEAM',
    contact TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
    project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    repository TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    policy_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    schedule_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    schedule_cron TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS connectors (
    connector_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(project_id) ON DELETE SET NULL,
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    status connector_status NOT NULL DEFAULT 'PENDING',
    base_url TEXT,
    secret_ref TEXT,
    last_checked_at TIMESTAMPTZ,
    error_message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_runs (
    scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(project_id) ON DELETE SET NULL,
    connector_id UUID REFERENCES connectors(connector_id) ON DELETE SET NULL,
    repository TEXT NOT NULL,
    trigger TEXT NOT NULL,
    ref TEXT,
    commit_sha TEXT,
    pull_request INTEGER,
    status TEXT NOT NULL,
    scanned_files INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    error_message TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    secret_type TEXT NOT NULL,
    masked_value TEXT NOT NULL DEFAULT '',
    secret_ref TEXT,
    active BOOLEAN,
    revoked BOOLEAN,
    created_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nhi (
    nhi_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    nhi_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    owner_id UUID REFERENCES owners(owner_id) ON DELETE SET NULL,
    environment TEXT NOT NULL DEFAULT 'unknown',
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0,
    linked_ai_agent TEXT,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credential_nhi_bindings (
    credential_id UUID NOT NULL REFERENCES credentials(credential_id) ON DELETE CASCADE,
    nhi_id UUID NOT NULL REFERENCES nhi(nhi_id) ON DELETE CASCADE,
    confidence NUMERIC(4,3) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (credential_id, nhi_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scan_runs(scan_id) ON DELETE SET NULL,
    project_id UUID REFERENCES projects(project_id) ON DELETE SET NULL,
    credential_id UUID REFERENCES credentials(credential_id) ON DELETE SET NULL,
    nhi_id UUID REFERENCES nhi(nhi_id) ON DELETE SET NULL,
    repository TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    secret_type TEXT NOT NULL,
    provider TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER,
    risk_level TEXT,
    status finding_status NOT NULL DEFAULT 'NEW',
    assigned_owner_id UUID REFERENCES owners(owner_id) ON DELETE SET NULL,
    sla_due_at TIMESTAMPTZ,
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}',
    UNIQUE (repository, fingerprint, file_path)
);

CREATE TABLE IF NOT EXISTS finding_status_history (
    history_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    from_status finding_status,
    to_status finding_status NOT NULL,
    actor TEXT NOT NULL,
    note TEXT,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id UUID NOT NULL REFERENCES credentials(credential_id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    raw_scope TEXT NOT NULL,
    source TEXT NOT NULL,
    inferred BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS activities (
    activity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nhi_id UUID REFERENCES nhi(nhi_id) ON DELETE SET NULL,
    credential_id UUID REFERENCES credentials(credential_id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource TEXT,
    provider TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'
);

-- 회사 AI Agent와 NHI/API 계정의 승인된 연결·접근 범위 기준선
CREATE TABLE IF NOT EXISTS agent_access_profiles (
    agent_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    owner TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    data JSONB NOT NULL
);

-- Gateway/Audit Log 호출을 기준선과 비교한 위장·범위 초과 판정 이력
CREATE TABLE IF NOT EXISTS agent_access_decisions (
    decision_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    severity TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_access_decisions_agent
    ON agent_access_decisions(agent_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_access_decisions_outcome
    ON agent_access_decisions(outcome, occurred_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_access_decisions_event
    ON agent_access_decisions(agent_id, event_id);

CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID REFERENCES findings(finding_id) ON DELETE CASCADE,
    nhi_id UUID REFERENCES nhi(nhi_id) ON DELETE CASCADE,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    level TEXT NOT NULL,
    factors JSONB NOT NULL,
    reasons JSONB NOT NULL,
    forced_rules JSONB NOT NULL DEFAULT '[]',
    scoring_version TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS recommendations (
    recommendation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES risk_assessments(assessment_id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    priority INTEGER NOT NULL,
    rationale TEXT NOT NULL,
    automatable BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recommendation_id UUID REFERENCES recommendations(recommendation_id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
    requested_by TEXT NOT NULL,
    assigned_to TEXT,
    decision_reason TEXT,
    decided_by TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS remediation_actions (
    action_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    approval_id UUID REFERENCES approval_requests(approval_id) ON DELETE SET NULL,
    finding_id UUID REFERENCES findings(finding_id) ON DELETE SET NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    before_state JSONB NOT NULL DEFAULT '{}',
    after_state JSONB NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS verification_results (
    verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id UUID NOT NULL REFERENCES remediation_actions(action_id) ON DELETE CASCADE,
    verified BOOLEAN NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    detail JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_risk ON findings(risk_level, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_project ON scan_runs(project_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_activity_nhi ON activities(nhi_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events(target_type, target_id);
