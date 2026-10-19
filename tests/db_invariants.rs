// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
// SPDX-License-Identifier: Apache-2.0

//! DB-backed schema-invariant tests (runtime-skip) - compliance
//! DESIGN.md §9. Exercises: FORCE-RLS rejects context-less inserts; the
//! at-most-once alert invariant (unique (env, subject, source,
//! source_ref, window)); one live PEP determination per KYC record;
//! idempotent beneficial-owner disclosure; at-most-once suspicious
//! activity per (case, report kind); identity references are
//! reference-only (§8). Skipped when `DATABASE_URL` is unreachable.

use sqlx::PgPool;
use uuid::Uuid;

async fn test_pool() -> Option<PgPool> {
    let url = std::env::var("BANK8_COMPLIANCE_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://bank8_compliance_service@localhost:5432/bank8".into());
    match sqlx::PgPool::connect(&url).await {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("skipping DB-backed compliance tests - no database: {e}");
            None
        }
    }
}

async fn with_context<'c>(pool: &'c PgPool, env_id: Uuid) -> sqlx::Transaction<'c, sqlx::Postgres> {
    let mut tx = pool.begin().await.expect("tx");
    // The context-set and every dependent insert share ONE transaction
    // (the ledger db_handlers discipline - set_config true is
    // transaction-local).
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', 'm2m', 'sys:admin')")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    tx
}

/// Seed one KYC-recorded customer and return (env, kyc id).
async fn seed_kyc(pool: &PgPool, env_id: Uuid) -> Option<Uuid> {
    let mut tx = with_context(pool, env_id).await;
    let kyc = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO kyc_records (env_id, customer_id, status)
           VALUES ($1, $2, 'verified') RETURNING id"#,
    )
    .bind(env_id)
    .bind(Uuid::new_v4())
    .fetch_one(&mut *tx)
    .await
    .ok()?;
    tx.commit().await.ok()?;
    Some(kyc)
}

/// FORCE-RLS: a context-less alert insert is rejected.
#[tokio::test]
async fn alert_insert_without_context_rejected() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let res = sqlx::query(
        r#"INSERT INTO alerts (env_id, subject, source, source_ref, aggregation_window)
           VALUES ($1, 'sub', 'sanctions', 'ref-1', 'w1')"#,
    )
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await;
    assert!(res.is_err(), "context-less insert must violate FORCE RLS");
}

/// The at-most-once alert invariant: the unique
/// (env, subject, source, source_ref, window) makes a replayed detection
/// converge - one alert, never duplicates.
#[tokio::test]
async fn alert_raise_is_at_most_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();
    let mut tx = with_context(&pool, env_id).await;
    let sql = r#"INSERT INTO alerts (env_id, subject, source, source_ref, aggregation_window)
                 VALUES ($1, 'customer-x', 'monitoring', 'rule-1', 'w-1')
                 ON CONFLICT (env_id, subject, source, source_ref, aggregation_window) DO NOTHING"#;
    let first = sqlx::query(sql).execute(&mut *tx).await.expect("first");
    let replay = sqlx::query(sql).execute(&mut *tx).await.expect("replay");
    tx.commit().await.expect("commit");
    assert_eq!(first.rows_affected(), 1);
    assert_eq!(
        replay.rows_affected(),
        0,
        "a replayed detection must NOT double-alert"
    );
}

/// One live PEP determination per KYC record - a re-determination
/// updates in place (the unique index on kyc_id).
#[tokio::test]
async fn pep_determination_is_one_per_kyc() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();
    let kyc_id = seed_kyc(&pool, env_id).await.expect("kyc");
    let mut tx = with_context(&pool, env_id).await;
    let sql = r#"INSERT INTO pep_determinations (env_id, kyc_id, is_pep)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (kyc_id) DO UPDATE SET is_pep = EXCLUDED.is_pep
                 RETURNING id, is_pep"#;
    let (id1, p1) = sqlx::query_as::<_, (Uuid, bool)>(sql)
        .bind(env_id)
        .bind(kyc_id)
        .bind(false)
        .fetch_one(&mut *tx)
        .await
        .expect("first");
    let (id2, p2) = sqlx::query_as::<_, (Uuid, bool)>(sql)
        .bind(env_id)
        .bind(kyc_id)
        .bind(true)
        .fetch_one(&mut *tx)
        .await
        .expect("second");
    tx.commit().await.expect("commit");
    assert_eq!(id1, id2, "the same KYC record keeps ONE live determination");
    assert!(
        (p1, p2) == (false, true),
        "the re-determination updates in place"
    );
    let count =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pep_determinations WHERE kyc_id = $1")
            .bind(kyc_id)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(count, 1);
}

/// Beneficial-owner disclosure is idempotent per (kyc, identity_ref) -
/// re-disclosing converges to the same row.
#[tokio::test]
async fn beneficial_owner_disclosure_is_idempotent() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();
    let kyc_id = seed_kyc(&pool, env_id).await.expect("kyc");
    let mut tx = with_context(&pool, env_id).await;
    let sql = r#"INSERT INTO beneficial_owners (env_id, kyc_id, identity_ref)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (kyc_id, identity_ref) DO NOTHING
                 RETURNING id"#;
    let id1 = sqlx::query_scalar::<_, Uuid>(sql)
        .bind(env_id)
        .bind(kyc_id)
        .bind("sentin8-secrets://test-bo")
        .fetch_one(&mut *tx)
        .await
        .expect("first");
    let dup = sqlx::query(sql)
        .bind(env_id)
        .bind(kyc_id)
        .bind("sentin8-secrets://test-bo")
        .fetch_optional(&mut *tx)
        .await
        .expect("second");
    tx.commit().await.expect("commit");
    assert!(dup.is_none(), "re-disclosure converges to the existing row");
    let count =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM beneficial_owners WHERE id = $1")
            .bind(id1)
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(count, 1);
}

/// The suspicious-activity handoff is at-most-once per (case, report
/// kind) - a redelivered conclude never double-files.
#[tokio::test]
async fn suspicious_activity_is_at_most_once_per_case() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let env_id = Uuid::new_v4();
    let kyc_id = seed_kyc(&pool, env_id).await.expect("kyc");
    let mut tx = with_context(&pool, env_id).await;
    let alert_id = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO alerts (env_id, subject, source, source_ref, aggregation_window, status)
           VALUES ($1, 'sub', 'sanctions', 'ref', 'w', 'escalated') RETURNING id"#,
    )
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("alert");
    let case_id = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO cases (env_id, alert_id, status, assignee)
           VALUES ($1, $2, 'investigating', 'analyst') RETURNING id"#,
    )
    .bind(env_id)
    .bind(alert_id)
    .fetch_one(&mut *tx)
    .await
    .expect("case");

    let sql = r#"INSERT INTO suspicious_activities (env_id, case_id, report_kind)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (case_id, report_kind) DO NOTHING"#;
    let first = sqlx::query(sql)
        .bind(env_id)
        .bind(case_id)
        .bind("sar")
        .execute(&mut *tx)
        .await
        .expect("first");
    let replay = sqlx::query(sql)
        .bind(env_id)
        .bind(case_id)
        .bind("sar")
        .execute(&mut *tx)
        .await
        .expect("replay");
    // A DIFFERENT kind for the same case is a distinct filing.
    let other = sqlx::query(sql)
        .bind(env_id)
        .bind(case_id)
        .bind("ctr")
        .execute(&mut *tx)
        .await
        .expect("other");
    let _ = kyc_id;
    tx.commit().await.expect("commit");
    assert_eq!(first.rows_affected(), 1);
    assert_eq!(
        replay.rows_affected(),
        0,
        "a replayed conclude must NOT double-file"
    );
    assert_eq!(
        other.rows_affected(),
        1,
        "a distinct report kind is a distinct filing"
    );
}
