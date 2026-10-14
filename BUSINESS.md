# Bank8:Compliance — Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Bank8:Compliance **does for the business**. For architecture read
> `README.md`; for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

- **Financial-crime detection in real time** — sanctions screening and
  AML/CTF transaction monitoring run the moment a transaction or
  customer event happens, not in a nightly batch.
- **A complete KYC/CDD record** — customer due diligence, beneficial
  ownership, PEP determination, and risk rating live together and drive
  monitoring intensity.
- **Detection that becomes a filing** — suspicious activity is handed
  to Bank8:Reporting as the single filing executor, so an STR/SAR/CTR
  is filed exactly once, on time.

## 2. Business Scope (What the Service Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | Customer risk rating | Low/medium/high AML rating with rationale |
| 2 | KYC/CDD | Customer due-diligence records and status |
| 3 | Beneficial ownership | Ownership-structure disclosure |
| 4 | PEP determination | Politically-exposed-person classification |
| 5 | Sanctions screening | Watchlist screening of customers and transactions |
| 6 | Transaction monitoring | Real-time AML rules with thresholds and windows |
| 7 | Alert/case management | Detection-to-investigation lifecycle with actor claims |
| 8 | Suspicious-activity handoff | STR/SAR/CTR/EFTR/LCTR detection → Reporting files |
| 9 | Domain events | `bank8:compliance:*` family |
| 10 | Health & ops | Health endpoint, metrics, audit journal |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Filing to regulators | Bank8:Reporting |
| Money movement | Bank8:Ledger / Bank8:Payments |
| Tenant-authored hook execution | Sentin8:Func |
| Watchlist source curation | Platform (snapshot ingestion) |

## 3. Business Capabilities

| Capability | Business rule |
|---|---|
| Screening | Every transaction/customer is screened against the current watchlist snapshot. |
| Monitoring | Rules fire per jurisdiction thresholds (LCTR/EFTR, CTR, AMLD/EBA, MLR). |
| Alerts | An alert is raised at most once per (subject, rule, window). |
| Cases | A case escalates with an audited actor claim; evidence (alert + subject screens) is read-only input to the decision. |
| KYC | Beneficial owners are held as secret references only — plaintext identity data is rejected at the API. |
| PEP | One live determination per KYC record; a PEP determination forces the risk rating to at least `high`. |
| Risk rating | Every rating carries a recorded rationale — an unexplained rating is unauditable and rejected. |
| Dismissal | A dismissed case records its reason and is terminal; nothing is filed for it. |
| Filing handoff | `suspicious:detected` is emitted once per case; Reporting files it. |

## 4. Business Events (Outbound)

| Event | Fires when |
|---|---|
| `bank8:compliance:kyc:created` | A KYC record is opened for a customer |
| `bank8:compliance:kyc:beneficial_owner:disclosed` | A beneficial owner is disclosed (secret-reference identity only) |
| `bank8:compliance:kyc:pep:determined` | A PEP determination is recorded/updated |
| `bank8:compliance:kyc:risk_profile:upserted` | The customer's AML rating changes (rationale recorded) |
| `bank8:compliance:alert:created` | A screen or rule produces a detection |
| `bank8:compliance:alert:updated` | A queue operation transitions an alert |
| `bank8:compliance:case:opened` | An alert escalates to a case |
| `bank8:compliance:case:dismissed` | A case is dismissed with a recorded reason (no filing) |
| `bank8:compliance:suspicious:detected` | A case concludes as reportable |

## 5. Business Rules & Invariants

1. An alert is raised at most once per (subject, rule, window).
2. A suspicious activity is emitted once per case; Reporting owns filing.
3. No watchlist secret or identity reference is stored as plaintext.

## 6. Target-User Roles & Use Cases

| Role | Use case |
|---|---|
| Compliance officer | Reviews alerts, opens cases, records decisions |
| AML analyst | Investigates cases, escalates suspicious activity |
| Regulator/FIU | Receives STR/SAR/CTR via Reporting |

## 7. KPIs / Success Criteria

- Screening latency ≤ seconds from the triggering event.
- Zero duplicate alerts.
- 100% of concluded suspicious cases reach Reporting.

## 8. Dependencies & Reliance on Other Services

- Bank8:Ledger, Bank8:Payments (events), Sentin8:Bus, Sentin8:Func,
  Bank8:Reporting (downstream filing).

## 9. Acceptance Criteria

1. A transaction event is screened and monitored in real time.
2. A rule breach raises exactly one alert.
3. A concluded suspicious case files through Reporting, not Compliance.

## 10. Open Business Questions

- Watchlist snapshot cadence.
- Alert deduplication windows.

---

**Design attribution:** bank8:compliance and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
