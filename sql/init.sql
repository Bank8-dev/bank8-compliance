-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
-- SPDX-License-Identifier: Apache-2.0

-- Bank8:Compliance — the service's own schema `compliance`
-- (schema-per-service): compliance_* domain tables + compliance.outbox /
-- compliance.audit_journal producer tables, all FORCE-RLS env-scoped,
-- per services/compliance/DESIGN.md §3.

CREATE SCHEMA IF NOT EXISTS compliance;

-- Customer risk rating (low/medium/high) with recorded rationale —
-- drives monitoring intensity.
CREATE TABLE IF NOT EXISTS compliance.customer_risk_profiles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    customer_id UUID NOT NULL,
    rating      TEXT NOT NULL CHECK (rating IN ('low', 'medium', 'high')),
    rationale   TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, customer_id)
);

-- KYC/CDD records lifecycle: initiated → verified → expired/refreshed.
CREATE TABLE IF NOT EXISTS compliance.kyc_records (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    customer_id UUID NOT NULL,
    status      TEXT NOT NULL DEFAULT 'initiated' CHECK (status IN ('initiated', 'verified', 'expired', 'refreshed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_kyc_customer
    ON compliance.kyc_records (env_id, customer_id);

-- Beneficial ownership disclosure. Identity by platform reference only —
-- never document bytes or plaintext identity numbers in bank8 rows
-- (DESIGN.md §8 invariant).
CREATE TABLE IF NOT EXISTS compliance.beneficial_owners (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id       UUID NOT NULL,
    kyc_id       UUID NOT NULL REFERENCES compliance.kyc_records(id) ON DELETE CASCADE,
    identity_ref TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_beneficial_owners_kyc
    ON compliance.beneficial_owners (kyc_id);
-- Idempotent disclosure: re-disclosing the same owner converges to the
-- same row (the handler's ON CONFLICT (kyc_id, identity_ref) target).
CREATE UNIQUE INDEX IF NOT EXISTS uq_compliance_beneficial_owners_kyc_ref
    ON compliance.beneficial_owners (kyc_id, identity_ref);

-- PEP (politically exposed person) determinations per KYC record.
CREATE TABLE IF NOT EXISTS compliance.pep_determinations (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id    UUID NOT NULL,
    kyc_id    UUID NOT NULL REFERENCES compliance.kyc_records(id) ON DELETE CASCADE,
    is_pep    BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_pep_kyc
    ON compliance.pep_determinations (kyc_id);
-- One live determination per KYC record — a re-determination updates in
-- place (the handler's ON CONFLICT (kyc_id) target; history rides the
-- audit journal).
CREATE UNIQUE INDEX IF NOT EXISTS uq_compliance_pep_kyc
    ON compliance.pep_determinations (kyc_id);

-- Sanctions screening results against a watchlist snapshot id.
CREATE TABLE IF NOT EXISTS compliance.sanctions_screens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id              UUID NOT NULL,
    subject             TEXT NOT NULL,
    result              TEXT NOT NULL CHECK (result IN ('clear', 'hit')),
    watchlist_snapshot  TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_screens_subject
    ON compliance.sanctions_screens (env_id, subject);

-- Declarative monitoring rules: threshold + aggregation window —
-- jurisdiction-registry-derived (never code).
CREATE TABLE IF NOT EXISTS compliance.monitoring_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    rule_code   TEXT NOT NULL,
    threshold   NUMERIC NOT NULL,
    -- `aggregation_window` — `window` is a PostgreSQL reserved word;
    -- greenfield rename per AGENTS.md (no migration).
    aggregation_window TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, rule_code)
);

-- Alerts: at most one per (subject, rule, window) — the unique index is
-- the dedupe floor (DESIGN.md §8).
CREATE TABLE IF NOT EXISTS compliance.alerts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    subject     TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('sanctions', 'monitoring', 'risk_breach')),
    source_ref  TEXT NOT NULL,
    aggregation_window TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewing', 'closed', 'escalated')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, subject, source, source_ref, aggregation_window)
);

CREATE INDEX IF NOT EXISTS idx_compliance_alerts_env_status
    ON compliance.alerts (env_id, status);

-- Cases: the investigation lifecycle with an audited actor claim.
CREATE TABLE IF NOT EXISTS compliance.cases (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id     UUID NOT NULL,
    alert_id   UUID NOT NULL REFERENCES compliance.alerts(id),
    status     TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'concluded', 'dismissed')),
    assignee   TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_cases_alert
    ON compliance.cases (alert_id);

-- Suspicious activities handed off to Reporting — report kinds use the
-- shared ReportKind vocabulary (bank8-regulatory-contracts).
CREATE TABLE IF NOT EXISTS compliance.suspicious_activities (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    case_id     UUID NOT NULL REFERENCES compliance.cases(id),
    report_kind TEXT NOT NULL CHECK (report_kind IN ('str', 'sar', 'ctr', 'eftr', 'lctr')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_id, report_kind)
);

-- ── Monitoring-rule threshold templates (JUR-REG-1) ───────────────────
-- The jurisdiction registry's AML/CTF thresholds, mirrored as rule
-- templates. The env-init consumer materializes the per-tenant rows from
-- the reporting registry at service-enable time (idempotent — mirrors
-- ledger's internal-account seeding); these template rows carry the
-- registry's values so a fresh tenant has the same defaults until the
-- registry updates them. Rule codes are generic AML families — no
-- jurisdiction or regulator names in code or rule codes.
COMMENT ON TABLE compliance.monitoring_rules IS 'Per-tenant AML rules; thresholds derive from the jurisdiction registry (reporting.return_templates.definition.thresholds) — never code.';

-- ── Env-scoped RLS (every table) ─────────────────────────────────────────
ALTER TABLE compliance.customer_risk_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.customer_risk_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS risk_profiles_dml ON compliance.customer_risk_profiles;
CREATE POLICY risk_profiles_dml ON compliance.customer_risk_profiles
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE compliance.kyc_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.kyc_records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS kyc_dml ON compliance.kyc_records;
CREATE POLICY kyc_dml ON compliance.kyc_records
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE compliance.beneficial_owners ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.beneficial_owners FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS beneficial_owners_dml ON compliance.beneficial_owners;
CREATE POLICY beneficial_owners_dml ON compliance.beneficial_owners
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE compliance.pep_determinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.pep_determinations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pep_dml ON compliance.pep_determinations;
CREATE POLICY pep_dml ON compliance.pep_determinations
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE compliance.sanctions_screens ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.sanctions_screens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS screens_dml ON compliance.sanctions_screens;
CREATE POLICY screens_dml ON compliance.sanctions_screens
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE compliance.monitoring_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.monitoring_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS monitoring_rules_dml ON compliance.monitoring_rules;
CREATE POLICY monitoring_rules_dml ON compliance.monitoring_rules
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE compliance.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alerts_dml ON compliance.alerts;
CREATE POLICY alerts_dml ON compliance.alerts
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE compliance.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.cases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cases_dml ON compliance.cases;
CREATE POLICY cases_dml ON compliance.cases
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

ALTER TABLE compliance.suspicious_activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.suspicious_activities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS suspicious_dml ON compliance.suspicious_activities;
CREATE POLICY suspicious_dml ON compliance.suspicious_activities
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: compliance rows are appended to the outbox in the SAME
-- transaction as the domain change; the shell's post-commit relay pushes
-- them to Bus POST /v1/produce (idempotency_key = row id). Generated
-- from sentin8-outbox::outbox_table_sql("compliance").
CREATE TABLE IF NOT EXISTS compliance.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_compliance_outbox_unrelayed
    ON compliance.outbox (created_at) WHERE relayed = false;
ALTER TABLE compliance.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON compliance.outbox;
CREATE POLICY outbox_select ON compliance.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON compliance.outbox;
CREATE POLICY outbox_insert ON compliance.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON compliance.outbox;
CREATE POLICY outbox_update ON compliance.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION compliance.compliance_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('compliance_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS compliance_outbox_notify_trigger ON compliance.outbox;
CREATE TRIGGER compliance_outbox_notify_trigger
    AFTER INSERT ON compliance.outbox
    FOR EACH ROW
    EXECUTE FUNCTION compliance.compliance_notify_outbox();

-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write),
-- then marked pushed. A Sys outage never drops audit.
-- Generated from sentin8-audit::audit_journal_sql("compliance").
CREATE TABLE IF NOT EXISTS compliance.audit_journal (
    id              UUID PRIMARY KEY,
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_journal_unpushed
    ON compliance.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE compliance.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON compliance.audit_journal;
CREATE POLICY audit_journal_dml ON compliance.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ── Per-service role grants + search_path (F1 — §4.3e) ──────────────────
-- The compliance service connects via its own PostgreSQL role
-- (bank8_compliance_service, created + granted by `sentin8-cli vertical
-- init/enroll` from this service's --print-registration
-- --section=pg_roles). Grants scoped to the OWN schema only — no blanket
-- grants, no cross-schema grants (DESIGN.md §8: inputs are events or
-- public-API reads, never ledger/payments/reporting tables).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bank8_compliance_service') THEN
        ALTER ROLE bank8_compliance_service SET search_path = compliance, public;
        GRANT USAGE ON SCHEMA compliance TO bank8_compliance_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA compliance TO bank8_compliance_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA compliance TO bank8_compliance_service;
    END IF;
END $$;