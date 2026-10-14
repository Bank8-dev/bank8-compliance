// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
// SPDX-License-Identifier: Apache-2.0

//! Compliance configuration.
//!
//! URLs only — no tokens. Compliance's inputs are Bus events and its
//! outputs (alert/case/suspicious:detected) ride the local outbox →
//! shell relay (compliance DESIGN.md §8) — `suspicious:detected` reaches
//! Reporting through Bus, never a direct call. The only outbound identity
//! is the worker's own certificate-presenting Bus client built in
//! `worker.rs` (CERTFREE-4V — single identity plane, principles §4.1):
//! a failed certificate mint fails the consume closed; there is no
//! static-token fallback.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

/// Compliance configuration.
#[derive(Clone)]
pub struct ComplianceConfig {
    pub port: u16,
    pub database_url: String,
    pub sentin8_auth_issuer: String,
    pub sentin8_auth_jwks_url: String,
    pub sentin8_bus_url: String,
    /// Bus stream families the screening worker consumes
    /// (`payments`, `ledger`).
    pub consume_families: Vec<String>,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request.
    pub sentin8_auth_client: AuthClient,
}

impl ComplianceConfig {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("BANK8_COMPLIANCE_PORT").expect("BANK8_COMPLIANCE_PORT must be set by captain").parse().expect("BANK8_COMPLIANCE_PORT must be a valid u16"),
            database_url: env::var("BANK8_COMPLIANCE_DATABASE_URL").unwrap_or_else(|_| env::var("DATABASE_URL").unwrap_or_else(|_| sentin8::config::Sentin8Config::default_database_url().to_string())),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL").unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            consume_families: env::var("BANK8_COMPLIANCE_CONSUME_FAMILIES")
                .map(|s| s.split(',').map(|f| f.trim().to_string()).filter(|f| !f.is_empty()).collect())
                .unwrap_or_else(|_| vec!["payments".into(), "ledger".into()]),
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }
}