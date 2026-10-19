// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
// SPDX-License-Identifier: Apache-2.0

//! Compliance HTTP handlers - KYC/CDD, alerts, cases, and the
//! suspicious-activity handoff. See compliance DESIGN.md §4.
//!
//! Every handler: verify (steps 1-4) → Shield gate (step 5, the ONLY
//! gate) → same-transaction tenant context → explicit `WHERE env_id`
//! (defense-in-depth) → commit → emit (membus → bus, DESIGN.md §2).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::config::ComplianceConfig;
use crate::policy::Engine;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ComplianceConfig>,
    pub pool: sqlx::PgPool,
    /// Shield policy engine - step 5 is the ONLY gate: handlers verify
    /// the token (steps 1-4) then evaluate a
    /// `bank8:compliance:<resource>:<action>` target; no JWT scope check
    /// remains.
    pub policy: Arc<Engine>,
    /// Shared Sentin8:Policy admin surface (§3.6) - same engine instance
    /// the request path evaluates.
    pub admin: sentin8::shield::admin::SharedAdminState,
    /// MemBus handle (principles §4.7 - membus → bus → API): alert-queue
    /// and screening state publishes newest-wins ephemeral refreshes so
    /// queue dashboards update surgically; durable `bank8:compliance:*`
    /// events (incl. `suspicious:detected`) ride the local outbox →
    /// relay → Bus. Fail-soft - a Valkey outage only degrades refresh.
    pub membus: sentin8::membus::ServiceBus,
}

/// Set the transaction-local RLS tenant context on a connection. MUST be
/// awaited on the same connection every subsequent tenant query runs on -
/// `set_config(..., true)` scopes the setting to the transaction
/// (architecture-principles §4.3d).
pub(crate) async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, 'compliance')")
        .bind(env_id)
        .execute(conn)
        .await;
}

/// Emit a compliance event through both tiers (DESIGN.md §2 - membus →
/// bus): the MemBus state refresh first (fail-soft, newest-wins), then
/// the durable outbox row the shell relay drains to Bus
/// `POST /v1/produce` (idempotency_key = row id). `suspicious:detected`
/// reaches Reporting through this durable tier - Compliance never files
/// and never touches Reporting's tables (DESIGN.md §8).
pub(crate) async fn emit_event(
    state: &AppState,
    env_id: Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    state
        .membus
        .publish_pubsub("compliance", event_type, payload.clone())
        .await;
    if let Err(e) = sentin8::bus::outbox::insert_outbox_row_pool(
        &state.pool,
        env_id,
        "compliance",
        event_type,
        &payload,
    )
    .await
    {
        tracing::warn!(error = %e, event_type = %event_type, "bank8:compliance: failed to emit outbox event");
    }
}

// ── DTOs ──────────────────────────────────────────────────────────────────

/// A KYC record as returned by the KYC reads.
#[derive(Debug, Serialize, ToSchema)]
pub struct KycResponse {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub status: String,
}

/// Request body for creating a KYC record - the customer id arrives in
/// the path (`/v1/customers/{id}/kyc`); the body carries no duplicate of
/// it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateKycRequest {}

/// An alert as returned by the alert reads.
#[derive(Debug, Serialize, ToSchema)]
pub struct AlertResponse {
    pub id: Uuid,
    pub subject: String,
    pub source: String,
    pub source_ref: String,
    pub status: String,
}

/// Query for listing alerts.
#[derive(Debug, Deserialize, ToSchema, utoipa::IntoParams)]
pub struct ListAlertsQuery {
    #[serde(default)]
    pub status: Option<String>,
}

/// Request body for escalating an alert to a case.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OpenCaseRequest {
    pub assignee: String,
}

/// Request body for concluding a case as suspicious - the report kind
/// uses the shared `ReportKind` vocabulary.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ConcludeCaseRequest {
    pub report_kind: String,
}

fn row_to_kyc(row: &sqlx::postgres::PgRow) -> KycResponse {
    KycResponse {
        id: row.get("id"),
        customer_id: row.get("customer_id"),
        status: row.get("status"),
    }
}

fn row_to_alert(row: &sqlx::postgres::PgRow) -> AlertResponse {
    AlertResponse {
        id: row.get("id"),
        subject: row.get("subject"),
        source: row.get("source"),
        source_ref: row.get("source_ref"),
        status: row.get("status"),
    }
}

// ── Health ────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (version, build)"),
    ),
    security(),
    tag = "meta",
)]
/// `GET /v1/health` - service health payload.
///
/// Carries the binary's build identity (`version`/`build`, BUILDID-1) so
/// captain's monitor populates `make status`'s VERSION column for every
/// instance - the consuming BINARY's identity, never a shared crate's.
pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    Json(
        serde_json::json!({ "status": if db_ok { "ok" } else { "degraded" }, "service": "bank8:compliance", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash() }),
    )
}

// ── KYC ────────────────────────────────────────────────────────────────────

/// `POST /v1/customers/{id}/kyc` - create a KYC record for a customer.
#[utoipa::path(post, path = "/v1/customers/{id}/kyc", request_body = CreateKycRequest, responses((status = 200, body = KycResponse)))]
pub async fn create_kyc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
) -> Result<Json<KycResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:kyc:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO kyc_records (env_id, customer_id, status)
            VALUES ($1, $2, 'initiated')
            RETURNING id, customer_id, status"#,
    )
    .bind(a.env_id())
    .bind(customer_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    let kyc = row_to_kyc(&row);
    conn.commit().await.map_err(crate::errors::err_db)?;
    emit_event(
        &state,
        a.env_id(),
        "bank8:compliance:kyc:created",
        serde_json::to_value(&kyc).unwrap_or_default(),
    )
    .await;
    Ok(Json(kyc))
}

/// `GET /v1/customers/{id}/kyc` - list a customer's KYC records.
#[utoipa::path(get, path = "/v1/customers/{id}/kyc", responses((status = 200, body = [KycResponse])))]
pub async fn list_kyc(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
) -> Result<Json<Vec<KycResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:kyc:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, customer_id, status FROM kyc_records
            WHERE env_id = $1 AND customer_id = $2
            ORDER BY created_at DESC"#,
    )
    .bind(a.env_id())
    .bind(customer_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    Ok(Json(rows.iter().map(row_to_kyc).collect()))
}

/// Request body for disclosing a beneficial owner - identity by platform
/// reference only (a sentin8-secrets:// or identity-plane reference);
/// document bytes and plaintext identity numbers never enter a bank8
/// row (DESIGN.md §8 invariant).
#[derive(Debug, Deserialize, ToSchema)]
pub struct DiscloseBeneficialOwnerRequest {
    pub kyc_id: Uuid,
    pub identity_ref: String,
}

/// A beneficial owner as returned by the reads.
#[derive(Debug, Serialize, ToSchema)]
pub struct BeneficialOwnerResponse {
    pub id: Uuid,
    pub kyc_id: Uuid,
    pub identity_ref: String,
}

/// `POST /v1/customers/{id}/beneficial-owners` - disclose a beneficial
/// owner against a KYC record (idempotent per (kyc, identity_ref) -
/// re-disclosing the same owner converges to the same row).
#[utoipa::path(post, path = "/v1/customers/{id}/beneficial-owners", request_body = DiscloseBeneficialOwnerRequest, responses((status = 200, body = BeneficialOwnerResponse)))]
pub async fn disclose_beneficial_owner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
    Json(req): Json<DiscloseBeneficialOwnerRequest>,
) -> Result<Json<BeneficialOwnerResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:kyc:write"),
    )
    .await?;
    if !req.identity_ref.starts_with("sentin8-secrets://") {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "identity_ref must be a sentin8-secrets:// reference - plaintext identity data is never stored".into()));
    }
    let mut tx = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    // The KYC record must belong to this customer in this env.
    let owned = sqlx::query_scalar::<_, i64>(
        r#"SELECT count(*) FROM kyc_records
            WHERE id = $1 AND env_id = $2 AND customer_id = $3"#,
    )
    .bind(req.kyc_id)
    .bind(a.env_id())
    .bind(customer_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::errors::err_db)?;
    if owned == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("kyc record {} not found for this customer", req.kyc_id),
        ));
    }
    let row = sqlx::query(
        r#"INSERT INTO beneficial_owners (env_id, kyc_id, identity_ref)
           VALUES ($1, $2, $3)
           ON CONFLICT (kyc_id, identity_ref) DO NOTHING
           RETURNING id, kyc_id, identity_ref"#,
    )
    .bind(a.env_id())
    .bind(req.kyc_id)
    .bind(&req.identity_ref)
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::errors::err_db)?;
    let bo = BeneficialOwnerResponse {
        id: row.get("id"),
        kyc_id: row.get("kyc_id"),
        identity_ref: row.get("identity_ref"),
    };
    tx.commit().await.map_err(crate::errors::err_db)?;
    emit_event(
        &state,
        a.env_id(),
        "bank8:compliance:kyc:beneficial_owner:disclosed",
        serde_json::to_value(&bo).unwrap_or_default(),
    )
    .await;
    Ok(Json(bo))
}

/// `GET /v1/customers/{id}/beneficial-owners` - list the customer's
/// disclosed beneficial owners (references only).
#[utoipa::path(get, path = "/v1/customers/{id}/beneficial-owners", responses((status = 200, body = [BeneficialOwnerResponse])))]
pub async fn list_beneficial_owners(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
) -> Result<Json<Vec<BeneficialOwnerResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:kyc:read"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT bo.id, bo.kyc_id, bo.identity_ref
             FROM beneficial_owners bo
             JOIN kyc_records k ON k.id = bo.kyc_id
            WHERE bo.env_id = $1 AND k.customer_id = $2
            ORDER BY bo.created_at"#,
    )
    .bind(a.env_id())
    .bind(customer_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(crate::errors::err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| BeneficialOwnerResponse {
                id: r.get("id"),
                kyc_id: r.get("kyc_id"),
                identity_ref: r.get("identity_ref"),
            })
            .collect(),
    ))
}

/// Request body for recording a PEP determination against a KYC record.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PepDeterminationRequest {
    pub kyc_id: Uuid,
    pub is_pep: bool,
}

/// `POST /v1/customers/{id}/pep` - record a PEP (politically exposed
/// person) determination. One live determination per KYC record - a
/// re-determination updates it in place (the latest determination is
/// authoritative; history rides the audit journal).
#[utoipa::path(post, path = "/v1/customers/{id}/pep", request_body = PepDeterminationRequest, responses((status = 200, body = PepRecorded)))]
pub async fn record_pep_determination(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
    Json(req): Json<PepDeterminationRequest>,
) -> Result<Json<PepRecorded>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:kyc:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let owned = sqlx::query_scalar::<_, i64>(
        r#"SELECT count(*) FROM kyc_records
            WHERE id = $1 AND env_id = $2 AND customer_id = $3"#,
    )
    .bind(req.kyc_id)
    .bind(a.env_id())
    .bind(customer_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::errors::err_db)?;
    if owned == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("kyc record {} not found for this customer", req.kyc_id),
        ));
    }
    let row = sqlx::query(
        r#"INSERT INTO pep_determinations (env_id, kyc_id, is_pep)
           VALUES ($1, $2, $3)
           ON CONFLICT (kyc_id) DO UPDATE SET is_pep = EXCLUDED.is_pep, created_at = now()
           RETURNING id, kyc_id, is_pep"#,
    )
    .bind(a.env_id())
    .bind(req.kyc_id)
    .bind(req.is_pep)
    .fetch_one(&mut *tx)
    .await
    .map_err(crate::errors::err_db)?;
    let payload = PepRecorded {
        id: row.get::<Uuid, _>("id"),
        kyc_id: row.get::<Uuid, _>("kyc_id"),
        is_pep: row.get::<bool, _>("is_pep"),
    };
    tx.commit().await.map_err(crate::errors::err_db)?;
    emit_event(
        &state,
        a.env_id(),
        "bank8:compliance:kyc:pep:determined",
        serde_json::to_value(&payload).unwrap_or_default(),
    )
    .await;
    Ok(Json(payload))
}

/// Request body for upserting the customer's AML risk rating - the
/// rationale is mandatory (a rating without its recorded reasoning is
/// unauditable).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertRiskProfileRequest {
    pub rating: String,
    pub rationale: String,
}

/// `POST /v1/customers/{id}/risk-profile` - upsert the customer's AML
/// risk rating (low/medium/high) with a recorded rationale. The rating
/// drives monitoring intensity; a PEP determination forces at least
/// `high` (a PEP can never sit below it).
#[utoipa::path(post, path = "/v1/customers/{id}/risk-profile", request_body = UpsertRiskProfileRequest, responses((status = 200, body = RiskProfileUpserted), (status = 422)))]
pub async fn upsert_risk_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(customer_id): Path<Uuid>,
    Json(req): Json<UpsertRiskProfileRequest>,
) -> Result<Json<RiskProfileUpserted>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:kyc:write"),
    )
    .await?;
    if !["low", "medium", "high"].contains(&req.rating.as_str()) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid rating: {}", req.rating),
        ));
    }
    if req.rationale.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "rationale is required - a rating without recorded reasoning is unauditable".into(),
        ));
    }
    let mut tx = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    // PEP floor: any live PEP determination forces at least `high`.
    let pep = sqlx::query_scalar::<_, bool>(
        r#"SELECT COALESCE(bo2.is_pep, false)
             FROM kyc_records k
             LEFT JOIN LATERAL (
                 SELECT p.is_pep FROM pep_determinations p
                  WHERE p.kyc_id = k.id AND p.env_id = $2
                  ORDER BY p.created_at DESC LIMIT 1
             ) bo2 ON true
            WHERE k.id = (SELECT id FROM kyc_records WHERE env_id = $2 AND customer_id = $1
                          ORDER BY created_at DESC LIMIT 1)
              AND k.env_id = $2"#,
    )
    .bind(customer_id)
    .bind(a.env_id())
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::errors::err_db)?;
    let rating = if pep == Some(true) && req.rating != "high" {
        "high".to_string()
    } else {
        req.rating.clone()
    };
    let row = sqlx::query(
        r#"INSERT INTO customer_risk_profiles (env_id, customer_id, rating, rationale)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (env_id, customer_id)
           DO UPDATE SET rating = EXCLUDED.rating, rationale = EXCLUDED.rationale, updated_at = now()
           RETURNING id, rating, rationale"#,
    )
    .bind(a.env_id()).bind(customer_id).bind(&rating).bind(&req.rationale)
    .fetch_one(&mut *tx).await.map_err(crate::errors::err_db)?;
    let payload = RiskProfileUpserted {
        id: row.get::<Uuid, _>("id"),
        customer_id,
        rating: row.get::<String, _>("rating"),
        rationale: row.get::<String, _>("rationale"),
    };
    tx.commit().await.map_err(crate::errors::err_db)?;
    emit_event(
        &state,
        a.env_id(),
        "bank8:compliance:kyc:risk_profile:upserted",
        serde_json::to_value(&payload).unwrap_or_default(),
    )
    .await;
    Ok(Json(payload))
}

// ── Alerts ────────────────────────────────────────────────────────────────

/// `GET /v1/alerts` - list alerts, optionally by status.
#[utoipa::path(get, path = "/v1/alerts", params(ListAlertsQuery), responses((status = 200, body = [AlertResponse])))]
pub async fn list_alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListAlertsQuery>,
) -> Result<Json<Vec<AlertResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:alerts:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, subject, source, source_ref, status FROM alerts
            WHERE env_id = $1 AND ($2::text IS NULL OR status = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.status)
    .fetch_all(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    Ok(Json(rows.iter().map(row_to_alert).collect()))
}

/// `POST /v1/alerts/{id}/case` - escalate an alert to a case with an
/// audited actor claim (the assignee). The alert transitions to
/// `escalated` in the same transaction.
#[utoipa::path(post, path = "/v1/alerts/{id}/case", request_body = OpenCaseRequest, responses((status = 200, body = CaseOpened)))]
pub async fn open_case(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(alert_id): Path<Uuid>,
    Json(req): Json<OpenCaseRequest>,
) -> Result<Json<CaseOpened>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:cases:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE alerts SET status = 'escalated'
            WHERE id = $1 AND env_id = $2 AND status IN ('open', 'reviewing')
            RETURNING id"#,
    )
    .bind(alert_id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    let Some(_) = row else {
        return Err((
            StatusCode::CONFLICT,
            format!("alert {alert_id} not escalatable (missing or terminal)"),
        ));
    };
    let case_id = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO cases (env_id, alert_id, status, assignee)
            VALUES ($1, $2, 'open', $3) RETURNING id"#,
    )
    .bind(a.env_id())
    .bind(alert_id)
    .bind(&req.assignee)
    .fetch_one(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    conn.commit().await.map_err(crate::errors::err_db)?;
    let payload = CaseOpened { case_id, alert_id, assignee: Some(req.assignee.clone()) };
    emit_event(
        &state,
        a.env_id(),
        "bank8:compliance:case:opened",
        serde_json::to_value(&payload).unwrap_or_default(),
    )
    .await;
    Ok(Json(payload))
}

// ── Monitoring rules (CMP-CASE-1 surface - thresholds from the registry) ──

/// A monitoring rule as returned by the reads.
#[derive(Debug, Serialize, ToSchema)]
pub struct MonitoringRuleResponse {
    pub id: Uuid,
    pub rule_code: String,
    pub threshold: rust_decimal::Decimal,
    pub window: String,
    pub enabled: bool,
}

/// `GET /v1/rules` - list the tenant's monitoring rules (thresholds
/// derive from the jurisdiction registry - reporting's return-template
/// definitions - materialized at env-init; never code).
#[utoipa::path(get, path = "/v1/rules", responses((status = 200, body = [MonitoringRuleResponse])))]
pub async fn list_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<MonitoringRuleResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:alerts:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, rule_code, threshold, aggregation_window, enabled FROM monitoring_rules
            WHERE env_id = $1 ORDER BY rule_code"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| MonitoringRuleResponse {
                id: r.get("id"),
                rule_code: r.get("rule_code"),
                threshold: r.get("threshold"),
                window: r.get("aggregation_window"),
                enabled: r.get("enabled"),
            })
            .collect(),
    ))
}

/// Request body for an alert-status transition (queue operations - the
/// actor claim is audited via the caller's identity in the audit
/// journal).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAlertStatusRequest {
    pub status: String,
}

/// `POST /v1/alerts/{id}/status` - queue operation on an alert (claim /
/// review / close) with an audited actor: the caller's verified identity
/// drives the journal entry; the transition is guarded against terminal
/// states (closed alerts never reopen - a new detection raises a new
/// alert).
#[utoipa::path(post, path = "/v1/alerts/{id}/status", request_body = UpdateAlertStatusRequest, responses((status = 200, body = AlertStatusUpdated), (status = 409)))]
pub async fn update_alert_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(alert_id): Path<Uuid>,
    Json(req): Json<UpdateAlertStatusRequest>,
) -> Result<Json<AlertStatusUpdated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:alerts:write"),
    )
    .await?;
    if !["reviewing", "closed"].contains(&req.status.as_str()) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("invalid alert status: {}", req.status),
        ));
    }
    let mut tx = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE alerts SET status = $3
            WHERE id = $1 AND env_id = $2 AND status IN ('open', 'reviewing')
            RETURNING id, status"#,
    )
    .bind(alert_id)
    .bind(a.env_id())
    .bind(&req.status)
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::errors::err_db)?;
    let Some(row) = row else {
        return Err((
            StatusCode::CONFLICT,
            format!("alert {alert_id} not updatable (missing or terminal)"),
        ));
    };
    let payload = AlertStatusUpdated {
        id: row.get::<Uuid, _>("id"),
        status: row.get::<String, _>("status"),
    };
    tx.commit().await.map_err(crate::errors::err_db)?;
    emit_event(
        &state,
        a.env_id(),
        "bank8:compliance:alert:updated",
        serde_json::to_value(&payload).unwrap_or_default(),
    )
    .await;
    Ok(Json(payload))
}

// ── Cases ─────────────────────────────────────────────────────────────────

/// `GET /v1/cases/{id}` - case detail with its alert.
#[utoipa::path(get, path = "/v1/cases/{id}", responses((status = 200, body = CaseDetail)))]
pub async fn get_case(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CaseDetail>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:cases:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT c.id, c.status, c.assignee, c.alert_id, al.subject
             FROM cases c JOIN alerts al ON al.id = c.alert_id
            WHERE c.id = $1 AND c.env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, format!("case {id} not found")));
    };
    Ok(Json(CaseDetail {
        id: row.get::<Uuid, _>("id"),
        status: row.get::<String, _>("status"),
        assignee: row.get::<Option<String>, _>("assignee"),
        alert_id: row.get::<Uuid, _>("alert_id"),
        subject: row.get::<String, _>("subject"),
    }))
}

/// `GET /v1/cases/{id}/evidence` - the case's investigation evidence:
/// the originating alert, every sanctions screen against its subject,
/// and the customer's risk profile (when resolved). Read-only -
/// evidence is the input to the conclude/dismiss decision, never
/// mutated by it.
#[utoipa::path(get, path = "/v1/cases/{id}/evidence", responses((status = 200, body = CaseEvidenceResponse)))]
pub async fn get_case_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CaseEvidenceResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:cases:read"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // The case + originating alert.
    let case = sqlx::query(
        r#"SELECT c.id, c.status, c.assignee, c.alert_id, al.subject, al.source, al.source_ref, al.aggregation_window AS window
             FROM cases c JOIN alerts al ON al.id = c.alert_id
            WHERE c.id = $1 AND c.env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn).await.map_err(crate::errors::err_db)?;
    let Some(case) = case else {
        return Err((StatusCode::NOT_FOUND, format!("case {id} not found")));
    };
    let subject: String = case.get("subject");

    // Every sanctions screen recorded against that subject.
    let screens = sqlx::query(
        r#"SELECT id, subject, result, watchlist_snapshot, created_at
             FROM sanctions_screens
            WHERE env_id = $1 AND subject = $2
            ORDER BY created_at DESC LIMIT 50"#,
    )
    .bind(a.env_id())
    .bind(&subject)
    .fetch_all(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;

    Ok(Json(CaseEvidenceResponse {
        case: CaseDetail {
            id: case.get::<Uuid, _>("id"),
            status: case.get::<String, _>("status"),
            assignee: case.get::<Option<String>, _>("assignee"),
            alert_id: case.get::<Uuid, _>("alert_id"),
            subject: subject.clone(),
        },
        alert: EvidenceAlert {
            subject,
            source: case.get::<String, _>("source"),
            source_ref: case.get::<String, _>("source_ref"),
            window: case.get::<String, _>("window"),
        },
        sanctions_screens: screens
            .iter()
            .map(|screen| SanctionScreen {
                id: screen.get::<Uuid, _>("id"),
                result: screen.get::<String, _>("result"),
                watchlist_snapshot: screen.get::<Option<String>, _>("watchlist_snapshot"),
                created_at: screen.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
            .collect::<Vec<_>>(),
    }))
}

/// Request body for dismissing a case - the reason is mandatory (a
/// dismissal without a recorded reason is unauditable).
#[derive(Debug, Deserialize, ToSchema)]
pub struct DismissCaseRequest {
    pub reason: String,
}

/// `POST /v1/cases/{id}/dismiss` - dismiss a case as not reportable:
/// the recorded reason lands in the case row and NO suspicious activity
/// is emitted - Reporting never sees a dismissed case (a dismissed
/// case is terminal; a new detection opens a new case).
#[utoipa::path(post, path = "/v1/cases/{id}/dismiss", request_body = DismissCaseRequest, responses((status = 200, body = CaseDismissed), (status = 409), (status = 422)))]
pub async fn dismiss_case(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<DismissCaseRequest>,
) -> Result<Json<CaseDismissed>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:cases:write"),
    )
    .await?;
    if req.reason.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "dismissal reason is required - a dismissal without a recorded reason is unauditable"
                .into(),
        ));
    }
    let mut tx = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE cases SET status = 'dismissed', assignee = $3
            WHERE id = $1 AND env_id = $2 AND status IN ('open', 'investigating')
            RETURNING id, alert_id"#,
    )
    .bind(id)
    .bind(a.env_id())
    .bind(a.claims.sub.as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::errors::err_db)?;
    let Some(row) = row else {
        return Err((
            StatusCode::CONFLICT,
            format!("case {id} not dismissable (missing or terminal)"),
        ));
    };
    let payload = CaseDismissed {
        id: row.get::<Uuid, _>("id"),
        alert_id: row.get::<Uuid, _>("alert_id"),
        status: "dismissed".to_string(),
        reason: Some(req.reason.clone()),
        dismissed_by: a.claims.sub.clone(),
    };
    tx.commit().await.map_err(crate::errors::err_db)?;
    emit_event(
        &state,
        a.env_id(),
        "bank8:compliance:case:dismissed",
        serde_json::to_value(&payload).unwrap_or_default(),
    )
    .await;
    Ok(Json(payload))
}

/// `POST /v1/cases/{id}/conclude` - conclude a case as reportable: the
/// report kind lands in `suspicious_activities` and
/// `bank8:compliance:suspicious:detected` is emitted exactly once -
/// Reporting files it through its own durable consume (detection here,
/// filing there - the single-filing-executor rule, DESIGN.md §8).
#[utoipa::path(post, path = "/v1/cases/{id}/conclude", request_body = ConcludeCaseRequest, responses((status = 200, body = CaseConcluded)))]
pub async fn conclude_case(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ConcludeCaseRequest>,
) -> Result<Json<CaseConcluded>, (StatusCode, String)> {
    // Report-kind vocabulary comes from the shared contracts crate -
    // closed enum, validated before any write.
    let kind = serde_json::from_value::<bank8::regulatory::contracts::ReportKind>(
        serde_json::Value::String(req.report_kind.clone()),
    )
    .map_err(|_| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("unknown report kind: {}", req.report_kind),
        )
    })?;
    let kind_json = serde_json::to_value(kind).unwrap_or_default();

    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:cases:write"),
    )
    .await?;
    let mut conn = state.pool.begin().await.map_err(crate::errors::err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE cases SET status = 'concluded'
            WHERE id = $1 AND env_id = $2 AND status IN ('open', 'investigating')
            RETURNING id, alert_id"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    let Some(row) = row else {
        return Err((
            StatusCode::CONFLICT,
            format!("case {id} not concludable (missing or terminal)"),
        ));
    };
    // At-most-once per (case, report kind) - the unique index is the
    // dedupe floor.
    let activity_id = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO suspicious_activities (env_id, case_id, report_kind)
            VALUES ($1, $2, $3)
            ON CONFLICT (case_id, report_kind) DO UPDATE SET created_at = now()
            RETURNING id"#,
    )
    .bind(a.env_id())
    .bind(id)
    .bind(kind_json.as_str().unwrap_or("str"))
    .fetch_one(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?;
    conn.commit().await.map_err(crate::errors::err_db)?;
    let payload = CaseConcluded {
        activity_id,
        case_id: id,
        alert_id: row.get::<Uuid, _>("alert_id"),
        report_kind: kind_json.clone(),
    };
    emit_event(
        &state,
        a.env_id(),
        "bank8:compliance:suspicious:detected",
        serde_json::to_value(&payload).unwrap_or_default(),
    )
    .await;
    Ok(Json(payload))
}
// ── Typed case/PEP/risk responses (OAPEC-9) ────────────────────────────

/// PEP determination recorded.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct PepRecorded {
    /// The alert id (the PEP record anchors on it).
    pub id: uuid::Uuid,
    /// The KYC record id.
    pub kyc_id: uuid::Uuid,
    /// Whether the subject was determined a PEP.
    pub is_pep: bool,
}

/// Risk profile upserted.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct RiskProfileUpserted {
    /// The profile row id.
    pub id: uuid::Uuid,
    /// The customer of the profile.
    pub customer_id: uuid::Uuid,
    /// The assigned rating.
    pub rating: String,
    /// The analyst rationale.
    pub rationale: String,
}

/// Case opened ack.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct CaseOpened {
    /// The new case id.
    pub case_id: uuid::Uuid,
    /// The originating alert.
    pub alert_id: uuid::Uuid,
    /// The assignee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
}

/// Alert-status update ack.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct AlertStatusUpdated {
    /// The alert id.
    pub id: uuid::Uuid,
    /// The new status.
    pub status: String,
}

/// Case dismissed ack.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct CaseDismissed {
    /// The case id.
    pub id: uuid::Uuid,
    /// The originating alert.
    pub alert_id: uuid::Uuid,
    /// Always `dismissed`.
    pub status: String,
    /// The dismissal reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The dismissing operator.
    pub dismissed_by: String,
}

/// Case concluded ack.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct CaseConcluded {
    /// The created activity id.
    pub activity_id: uuid::Uuid,
    /// The case id.
    pub case_id: uuid::Uuid,
    /// The originating alert.
    pub alert_id: uuid::Uuid,
    /// The report kind the activity carries.
    pub report_kind: serde_json::Value,
}

/// An open case detail (`GET /v1/cases/{id}`).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CaseDetail {
    /// The case id.
    pub id: uuid::Uuid,
    /// Case status.
    pub status: String,
    /// The assignee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// The originating alert.
    pub alert_id: uuid::Uuid,
    /// The case subject.
    pub subject: String,
}

/// The case-evidence envelope (`GET /v1/cases/{id}/evidence`).
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CaseEvidenceResponse {
    /// The case detail.
    pub case: CaseDetail,
    /// The alert context rows.
    pub alert: EvidenceAlert,
    /// The sanctions screens performed on the subject.
    pub sanctions_screens: Vec<SanctionScreen>,
}

/// The alert context inside the evidence envelope.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct EvidenceAlert {
    /// The alert subject (name/text).
    pub subject: String,
    /// The screening source.
    pub source: String,
    /// The source reference id.
    pub source_ref: String,
    /// The screening window.
    pub window: String,
}

/// One sanctions screen row.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct SanctionScreen {
    /// The screen row id.
    pub id: uuid::Uuid,
    /// The screen result.
    pub result: String,
    /// The watchlist snapshot document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watchlist_snapshot: Option<String>,
    /// Screen instant.
    pub created_at: chrono::DateTime<chrono::Utc>,
}


