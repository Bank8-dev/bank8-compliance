// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
// SPDX-License-Identifier: Apache-2.0

//! Bank8:Compliance Admin UI handlers — RFW (Remote Flutter Widget)
//! definitions for the alert queue and case investigation pages. Icons
//! are Material Icons code points (hex strings), per principles §4.15.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use sqlx::Row;

use crate::auth;
use crate::handlers::{set_tenant_context, AppState};

/// GET /v1/admin/ui/{page} — return the RFW definition for the requested
/// admin page.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition", body = serde_json::Value),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("bank8:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:compliance:alerts:read"),
    )
    .await?;

    let page_def = match page.as_str() {
        "overview" => overview_page(),
        "alerts" => alerts_page(),
        "cases" => cases_page(),
        // ── Policy Studio (design §3.7) — shared page constructors; the
        // guard guarantees `Some` (§3.7 dispatch).
        p if sentin8::rfw::policy_page("bank8:compliance", p).is_some() => {
            sentin8::rfw::policy_page("bank8:compliance", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };

    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(page_def)).unwrap(),
    ))
}

fn overview_page() -> AdminUiPage {
    AdminPage::new("Compliance Overview")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("Detection & Investigation".into()),
            subtitle: None,
            children: vec![
                RemoteWidget::Text(WidgetText { text: "Sanctions screening and AML transaction monitoring run the moment a transaction or customer event happens; alerts escalate to cases with audited actor claims, and suspicious activities hand off to Reporting — the single filing executor.".into(), text_type: WidgetTextType::Body, align: TextAlign::Left, max_lines: None }),
            ],
            actions: vec![],
        }))
        .build()
}

fn alerts_page() -> AdminUiPage {
    AdminPage::new("Alert Queue")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("Open Alerts".into()),
            subtitle: None,
            children: vec![
                RemoteWidget::Text(WidgetText { text: "Filter by source (sanctions/monitoring/risk breach), status, and subject rating — an alert is raised at most once per (subject, rule, window).".into(), text_type: WidgetTextType::Body, align: TextAlign::Left, max_lines: None }),
            ],
            actions: vec![],
        }))
        .build()
}

fn cases_page() -> AdminUiPage {
    AdminPage::new("Case Investigation")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("Investigations".into()),
            subtitle: None,
            children: vec![
                RemoteWidget::Text(WidgetText { text: "Claim, review evidence, and conclude — a concluded suspicious case files through Reporting, never Compliance; case actor claims are first-class audit entries.".into(), text_type: WidgetTextType::Body, align: TextAlign::Left, max_lines: None }),
            ],
            actions: vec![],
        }))
        .build()
}

/// GET /v1/admin/overview — the data endpoint behind the overview page:
/// alert/case counts for the tenant env.
#[utoipa::path(
    get,
    path = "/v1/admin/overview",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    responses(
        (status = 200, description = "alert/case counts", body = serde_json::Value),
        (status = 403, description = "Caller lacks the admin scope"),
    ),
    security(("bank8:admin" = [])),
    tag = "admin-ui",
)]
pub async fn admin_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
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

    let alerts_open = sqlx::query(
        "SELECT count(*) AS n FROM alerts WHERE env_id = $1 AND status IN ('open', 'reviewing')",
    )
    .bind(a.env_id())
    .fetch_one(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?
    .get::<i64, _>("n");
    let cases_open = sqlx::query(
        "SELECT count(*) AS n FROM cases WHERE env_id = $1 AND status IN ('open', 'investigating')",
    )
    .bind(a.env_id())
    .fetch_one(&mut *conn)
    .await
    .map_err(crate::errors::err_db)?
    .get::<i64, _>("n");
    let suspicious =
        sqlx::query("SELECT count(*) AS n FROM suspicious_activities WHERE env_id = $1")
            .bind(a.env_id())
            .fetch_one(&mut *conn)
            .await
            .map_err(crate::errors::err_db)?
            .get::<i64, _>("n");

    Ok(Json(serde_json::json!({
        "alerts_open": alerts_open,
        "cases_open": cases_open,
        "suspicious_activities": suspicious,
        "service": "bank8:compliance",
    })))
}
