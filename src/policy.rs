// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Compliance
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy integration for Bank8:Compliance.
//! Thin re-export of the shared bridge (`sentin8::shield::runtime`).
//! Boot wiring is shell-owned (policy design §4.2b): services only copy
//! `core.admin.policy` into their state. Step 5 is the ONLY gate
//! (compliance DESIGN.md §5).

#[allow(unused_imports)]
pub use sentin8::shield::runtime::{
    check_policy, engine_for, policy_bus_client, request_ctx, spawn_hot_reload,
};
pub use sentin8::shield::PolicyEngine as Engine;

/// Step 5 for compliance: verify (steps 1-4) already ran; evaluate + 403
/// on enforced deny. Handlers call this instead of any JWT scope check.
pub use sentin8::shield::runtime::require_policy as require;
