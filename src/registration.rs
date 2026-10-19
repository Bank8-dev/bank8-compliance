// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Bank8:Compliance.
//! Output via `--print-registration` flag. See `sentin8/design/sentin8-service-self-registration-design.md`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, AuditFinding, ErrorCode, M2mGrant, PgRole, PolicySetDecl,
    Registration, RelationDecl, ServiceActionEntry, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "bank8:compliance:read,bank8:compliance:write",
    role: "bank8_compliance_service",
    bypass_rls: false,
    // Grants live in the bank8 vertical database only (DBX §6.6
    // database-per-vertical, schema-per-service).
    database: "bank8",
    // Compliance owns all its reads - inputs arrive as events, never
    // cross-schema grants (compliance DESIGN.md §8).
    cross_schema_grants: &[],
}];

/// Workload scope grants (self-registration design §3.11). One entry per
/// workload this service presents a certificate for.
/// - `bank8:compliance` / `compliance` - the service's own client
///   (server.rs): bus produce/consume (alert/case events + worker
///   consume).
/// - `compliance-audit` - shell audit-journal pusher workload (audit
///   crate §6.8; boot step 8c).
/// - `compliance-worker` - the embedded screening worker (worker.rs):
///   SSE consume on the payments/ledger families.
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "bank8:compliance",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    // Shield hot-reload consumer (BUSPOLICY-1 - see bank8-reporting).
    M2mGrant {
        workload: "bank8:compliance-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "compliance",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "compliance-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    M2mGrant {
        workload: "compliance-worker",
        scopes: &["sentin8:bus:consume"],
    },
];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "bank8:compliance:admin",
        scope: "bank8:compliance:kyc:read",
    },
    AdminScope::Typed {
        role: "bank8:compliance:admin",
        scope: "bank8:compliance:kyc:write",
    },
    AdminScope::Typed {
        role: "bank8:compliance:admin",
        scope: "bank8:compliance:alerts:read",
    },
    AdminScope::Typed {
        role: "bank8:compliance:admin",
        scope: "bank8:compliance:alerts:write",
    },
    AdminScope::Typed {
        role: "bank8:compliance:admin",
        scope: "bank8:compliance:cases:read",
    },
    AdminScope::Typed {
        role: "bank8:compliance:admin",
        scope: "bank8:compliance:cases:write",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "bank8:compliance:admin",
        scope: "bank8:compliance:policy:read",
    },
    AdminScope::Typed {
        role: "bank8:compliance:admin",
        scope: "bank8:compliance:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode {
        enum_name: "ComplianceValidationFailed",
        error_code: "compliance_validation_failed",
        status_code: 422,
    },
    ErrorCode {
        enum_name: "ComplianceConflict",
        error_code: "compliance_conflict",
        status_code: 409,
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "alerts",
        label: "Alerts",
        ui_endpoint: "/v1/admin/ui/alerts",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe7f4",
    },
    AdminUiPage {
        route: "cases",
        label: "Cases",
        ui_endpoint: "/v1/admin/ui/cases",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe2c8",
    },
    // Sentin8:Policy admin surface (§3.6, post pattern).
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
    AdminUiPage {
        route: "relations",
        label: "Relations",
        ui_endpoint: "/v1/admin/ui/relations",
        data_endpoint: "/v1/admin/relations",
        icon: "0xe572",
    },
    AdminUiPage {
        route: "attributes",
        label: "Attributes",
        ui_endpoint: "/v1/admin/ui/attributes",
        data_endpoint: "/v1/admin/attributes",
        icon: "0xe8d3",
    },
];

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set - the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Step 5 is the only gate.
pub const SCOPE_MIRROR_POLICIES: &str = concat!(
    "permit(principal, action == Action::\"bank8:compliance:kyc:read\", resource) when { principal.scopes.contains(\"bank8:compliance:kyc:read\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:read\", resource) when { principal.scopes.contains(\"bank8:compliance:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:write\", resource) when { principal.scopes.contains(\"bank8:compliance:kyc:write\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:write\", resource) when { principal.scopes.contains(\"bank8:compliance:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:kyc:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:read\", resource) when { principal.scopes.contains(\"bank8:compliance:alerts:read\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:read\", resource) when { principal.scopes.contains(\"bank8:compliance:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:write\", resource) when { principal.scopes.contains(\"bank8:compliance:alerts:write\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:write\", resource) when { principal.scopes.contains(\"bank8:compliance:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:alerts:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:read\", resource) when { principal.scopes.contains(\"bank8:compliance:cases:read\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:read\", resource) when { principal.scopes.contains(\"bank8:compliance:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:write\", resource) when { principal.scopes.contains(\"bank8:compliance:cases:write\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:write\", resource) when { principal.scopes.contains(\"bank8:compliance:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\n",
    "permit(principal, action == Action::\"bank8:compliance:cases:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\n",
);

const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for bank8:compliance over the LIVE effective scope set (design §3.1d). Step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) - none declared by this
/// service today; env admins author their own graph via the relations
/// admin API.
const RELATIONS: &[RelationDecl] = &[];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

const AUDIT_FINDINGS: &[AuditFinding] = &[
    AuditFinding {
        finding: "Beneficial-owner identity data stored as document bytes or plaintext identity numbers",
        recommendation: "Identity references must remain platform references (sentin8-secrets:// or identity-plane references) - never document bytes or plaintext identity numbers in bank8 rows (compliance DESIGN.md §8).",
    },
];

const SERVICE_ACTIONS: &[ServiceActionEntry] = &[ServiceActionEntry {
    action: "compliance_case_conclude",
    service_type: "bank8:compliance",
    platform_domain_key: "bank8:compliance",
    method: "POST",
    endpoint: "/v1/cases",
    scope: "bank8:compliance:cases:write",
}];

fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::ComplianceOpenApi::openapi())
        .unwrap_or(serde_json::Value::Null)
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "bank8:compliance",
        subdomain: "bank8-compliance",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        admin_ui: Some(AdminUi {
            label: "Compliance",
            icon: "0xe7f4",
            service_flag: "compliance",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        audit_findings: Some(AUDIT_FINDINGS),
        service_actions: Some(SERVICE_ACTIONS),
        m2m_grants: Some(M2M_GRANTS),
        pg_roles: PG_ROLES,
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
