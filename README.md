# Bank8:Compliance - README

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs/read-3aa757.svg)](https://bank8.dev/docs/products/compliance)
[![Website](https://img.shields.io/badge/website-bank8.dev-1a73e8.svg)](https://bank8.dev)

AML/CTF and sanctions: customer risk rating, KYC/CDD and beneficial
ownership, PEP determination, sanctions screening, real-time transaction
monitoring, and alert/case management - detecting suspicious activity
and filing it through Bank8:Reporting.

## Summary

Bank8:Compliance is a Rust service owning the `compliance` schema in the
bank8 vertical database. It screens customers and transactions against
sanctions watchlists, runs AML/CTF transaction monitoring rules in
real time, manages the alert-to-case lifecycle, and records KYC/CDD,
beneficial-ownership, and PEP determinations. It *detects* suspicious
activity and hands the STR/SAR/CTR/EFTR/LCTR filing to Bank8:Reporting -
the vertical's single filing executor.

## Motivation

Financial-crime obligations are real-time and event-driven: a
transaction must be screened and monitored at the moment it happens,
not during a nightly batch. Compliance keeps the detection surface
(watchlists, monitoring rules, customer risk ratings, alert queues)
separate from both the money-movement hot path and the filing mechanism,
so a suspicious-activity detection becomes a filing without a bespoke
internal API.

## Architecture & High-Level Design

```mermaid
graph TD
    subgraph platform["Sentin8 platform"]
        BUS["Sentin8:Bus"]
        FUNC["Sentin8:Func<br/>(custom detection rules)"]
        AUTH["Sentin8:Auth"]
    end
    subgraph vertical["bank8 vertical"]
        CMP["Bank8:Compliance<br/>(API + embedded screening worker)"]
        LEDGER["Bank8:Ledger"]
        PAY["Bank8:Payments"]
        RPT["Bank8:Reporting"]
        JUR[("jurisdiction registry<br/>thresholds, watchlists")]
        PG[("bank8 database<br/>schema compliance")]
    end
    subgraph clients
        BFF["Sentin8:BFF /proxy/compliance/*"]
        ADM["apps/admin (alert/case queues)"]
    end
    ADM --> BFF -->|"user tokens /v1/*"| CMP
    CMP <-->|"verify tokens / certificate identity"| AUTH
    PAY -->|"instruction:created events"| BUS
    LEDGER -->|"customer:created / posting events"| BUS
    BUS -->|"SSE consume"| CMP
    CMP -->|"suspicious:detected → file"| RPT
    CMP -->|"alert/case events"| BUS
    FUNC -->|"custom detection hooks"| CMP
    CMP -.-> JUR
    CMP <-->|"schema compliance"| PG
```

## Key Traits and Data Structures

- `CustomerRiskProfile` - a customer's AML risk rating (low/medium/high)
  and its rationale, recomputed from KYC and transaction behavior.
- `KycRecord` / `BeneficialOwner` / `PepDetermination` - customer due
  diligence, ownership structure, and PEP status.
- `SanctionsScreen` - a screening result against a watchlist snapshot;
  hits generate alerts.
- `MonitoringRule` - a declarative AML rule (threshold, aggregation
  window) resolved from the jurisdiction registry.
- `Alert` / `Case` - the detection-to-investigation lifecycle with an
  audited actor claim.

## Rationale, Trade-offs, and Alternatives

- **Detection here, filing there** - the vertical's single-filing-executor
  rule: Compliance emits `bank8:compliance:suspicious:detected`; Reporting
  files it. No shared table grant, no dual filing paths.
- **Real-time, event-driven** - screening rides `bank8:payments:instruction:created`
  and `bank8:ledger:customer:created` events with a full snapshot payload,
  minimizing read-back (principles §4.7, event-first).
- **Thresholds are jurisdiction data** - LCTR/EFTR (Canada), CTR/SAR (US),
  AMLD/EBA thresholds (EU), MLR (UK) live in the registry, never in code.

See `DESIGN.md` for the wire-level detail and `BUSINESS.md` for the
business capabilities.

---

**Design attribution:** bank8:compliance and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
