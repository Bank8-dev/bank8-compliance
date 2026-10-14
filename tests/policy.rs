// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy wiring tests for Bank8:Compliance.
//! Per the platform policy design §6 (Definition of Done) — proves the
//! compliance wiring with the REAL seeded scope-mirror text: no-set →
//! deny; enforced no-match → deny; shadow never blocks; the mirror
//! permits its own grants; M2M parity; platform-admin scopes pass;
//! forbid beats permit; tenant role-keyed sets decide; cross-env sets
//! are isolated; the declared mirror covers EVERY handler action; the
//! enroll dry-run gate accepts the declared set. Pure tests (no DB).

use uuid::Uuid;

use bank8_compliance_server::registration::SCOPE_MIRROR_POLICIES;
use sentin8::shield::{
    Decision, EvalTarget, PolicyEngine, PolicyMode, PolicyOrigin, PolicySetRecord, RequestCtx,
};

const SERVICE: &str = "bank8:compliance";
const ENV: uuid::Uuid = uuid::Uuid::nil();

fn row(name: &str, policies: &str, mode: PolicyMode, origin: PolicyOrigin) -> PolicySetRecord {
    PolicySetRecord {
        id: Uuid::new_v4(),
        env_id: ENV,
        service: SERVICE.into(),
        policy_set_name: name.into(),
        description: String::new(),
        policies: policies.into(),
        schema: None,
        origin,
        mode,
        version: 1,
        enabled: true,
    }
}

fn ctx(token_tp: &str, scope_list: &[&str]) -> RequestCtx {
    RequestCtx::new(
        "subj-1",
        ENV,
        uuid::Uuid::nil(),
        token_tp,
        scope_list.iter().map(|s| s.to_string()).collect(),
    )
}

fn mirror_engine(mode: PolicyMode) -> PolicyEngine {
    let e = PolicyEngine::new(SERVICE);
    e.load_from_rows(vec![row(
        "scope-mirror",
        SCOPE_MIRROR_POLICIES,
        mode,
        PolicyOrigin::Platform,
    )])
    .expect("declared scope-mirror set must parse");
    e
}

#[test]
fn no_set_denies_everything() {
    let e = PolicyEngine::new(SERVICE);
    let out = e.evaluate(
        &ctx("user", &["bank8:compliance:kyc:read"]),
        &EvalTarget::new("bank8:compliance:kyc:read"),
    );
    assert!(!out.is_allow());
    assert!(matches!(out.enforce_decision, Decision::Deny { .. }));
}

#[test]
fn enforced_no_match_denies() {
    let e = mirror_engine(PolicyMode::Enforced);
    let out = e.evaluate(
        &ctx("user", &["bank8:compliance:alerts:read"]),
        &EvalTarget::new("bank8:compliance:cases:write"),
    );
    assert!(!out.is_allow(), "scope for another action must not satisfy");
}

#[test]
fn shadow_never_blocks() {
    let e = mirror_engine(PolicyMode::Shadow);
    let out = e.evaluate(
        &ctx("user", &[]),
        &EvalTarget::new("bank8:compliance:alerts:read"),
    );
    assert!(out.is_allow(), "shadow must never block");
    assert!(out.shadow_deny.is_some(), "would-deny must be reported");
}

#[test]
fn mirror_permits_own_grants() {
    let e = mirror_engine(PolicyMode::Enforced);
    for scope in [
        "bank8:compliance:kyc:read",
        "bank8:compliance:kyc:write",
        "bank8:compliance:alerts:read",
        "bank8:compliance:alerts:write",
        "bank8:compliance:cases:read",
        "bank8:compliance:cases:write",
    ] {
        let out = e.evaluate(&ctx("user", &[scope]), &EvalTarget::new(scope));
        assert!(out.is_allow(), "scope {scope} must allow action {scope}");
    }
}

#[test]
fn m2m_parity() {
    let e = mirror_engine(PolicyMode::Enforced);
    let allow = e.evaluate(
        &ctx("m2m", &["bank8:compliance:cases:write"]),
        &EvalTarget::new("bank8:compliance:cases:write"),
    );
    assert!(allow.is_allow(), "scoped M2M principal passes like a user");
    let deny = e.evaluate(
        &ctx("m2m", &[]),
        &EvalTarget::new("bank8:compliance:cases:write"),
    );
    assert!(!deny.is_allow(), "unscoped M2M is denied like a user");
}

#[test]
fn platform_admin_scopes_pass() {
    let e = mirror_engine(PolicyMode::Enforced);
    for action in [
        "bank8:compliance:kyc:write",
        "bank8:compliance:alerts:read",
        "bank8:compliance:cases:write",
    ] {
        let out = e.evaluate(
            &ctx("user", &["sentin8:sys:admin"]),
            &EvalTarget::new(action),
        );
        assert!(out.is_allow(), "sys:admin must pass {action}");
    }
}

/// Forbid beats permit — a tenant freeze on case conclusions (e.g. an
/// audit hold) overrides the mirror.
#[test]
fn forbid_beats_permit() {
    let e = PolicyEngine::new(SERVICE);
    e.load_from_rows(vec![
        row(
            "scope-mirror",
            SCOPE_MIRROR_POLICIES,
            PolicyMode::Enforced,
            PolicyOrigin::Platform,
        ),
        row(
            "tenant-freeze",
            "forbid(principal, action == Action::\"bank8:compliance:cases:write\", resource);",
            PolicyMode::Enforced,
            PolicyOrigin::Tenant,
        ),
    ])
    .expect("load");
    let out = e.evaluate(
        &ctx("user", &["bank8:compliance:cases:write"]),
        &EvalTarget::new("bank8:compliance:cases:write"),
    );
    assert!(
        matches!(out.enforce_decision, Decision::Deny { .. }),
        "forbid wins"
    );
}

#[test]
fn role_keyed_tenant_set_decides() {
    let e = PolicyEngine::new(SERVICE);
    e.load_from_rows(vec![row(
        "tenant-role-grant",
        "permit(principal, action == Action::\"bank8:compliance:cases:write\", resource) when { principal.roles.contains(\"bank8:compliance:admin\") };",
        PolicyMode::Enforced,
        PolicyOrigin::Tenant,
    )])
    .expect("load");
    let denied = e.evaluate(
        &ctx("user", &[]),
        &EvalTarget::new("bank8:compliance:cases:write"),
    );
    assert!(!denied.is_allow());
    let allowed = e.evaluate(
        &ctx("user", &[]).with_roles(
            ["bank8:compliance:admin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
        &EvalTarget::new("bank8:compliance:cases:write"),
    );
    assert!(allowed.is_allow());
}

#[test]
fn cross_env_set_isolated() {
    let other_env = uuid::Uuid::new_v4();
    let mut r = row(
        "other-env-set",
        SCOPE_MIRROR_POLICIES,
        PolicyMode::Enforced,
        PolicyOrigin::Platform,
    );
    r.env_id = other_env;
    let e = PolicyEngine::new(SERVICE);
    e.load_from_rows(vec![r]).expect("load");
    let out = e.evaluate(
        &ctx("user", &["bank8:compliance:alerts:read"]),
        &EvalTarget::new("bank8:compliance:alerts:read"),
    );
    assert!(
        !out.is_allow(),
        "another env's set must not decide this env"
    );
}

#[test]
fn declared_mirror_covers_every_handler_action() {
    const HANDLER_ACTIONS: &[&str] = &[
        "bank8:compliance:kyc:read",
        "bank8:compliance:kyc:write",
        "bank8:compliance:alerts:read",
        "bank8:compliance:alerts:write",
        "bank8:compliance:cases:read",
        "bank8:compliance:cases:write",
    ];
    let e = mirror_engine(PolicyMode::Enforced);
    for action in HANDLER_ACTIONS {
        let out = e.evaluate(&ctx("user", &[*action]), &EvalTarget::new(*action));
        assert!(
            out.is_allow(),
            "action {action} must be covered by the mirror"
        );
    }
}

#[test]
fn declared_set_passes_enroll_dry_run() {
    sentin8::shield::runtime::dry_run_mirror(SCOPE_MIRROR_POLICIES, "scope-mirror", SERVICE)
        .expect("declared compliance scope-mirror must permit its own grants");
}
