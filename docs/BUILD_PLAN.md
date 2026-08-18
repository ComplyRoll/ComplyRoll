# TrustRoll build plan

Status date: **2026-08-18**

## Outcome

TrustRoll will compile heterogeneous security and validation evidence into traceable FedRAMP 20x
VDR cases, class-aware response timelines, and consistent official reports.

The initial target is a provider security engineer or assessor working locally or in CI. A hosted
trust center is a later integration boundary, not the MVP.

## Primary users

| User | Primary job |
|---|---|
| CSP security engineer | Ingest detections, evaluate context, track mitigation, and detect coverage failures |
| CSP GRC owner | Produce correct, current, repeatable FedRAMP reports without spreadsheet reconciliation |
| Independent assessor | Review validation code, failure criteria, evidence, history, and provider rationale |
| Agency reviewer | Consume filtered, current, machine-readable certification information |

## Product boundaries

TrustRoll is:

- A normalized evidence and case engine.
- A rule-version-aware deadline calculator.
- A report compiler and validator.
- A foundation for persistent KSI validation.

TrustRoll is not initially:

- A replacement ticketing platform.
- A complete trust center.
- A vulnerability scanner.
- An automatic risk acceptance authority.
- An AI system that independently assigns PAIN or declares KSI compliance.

## Phase 0 — Harden the existing ingestion kernel

Target: 1–2 weeks

### Deliverables

- Port `stigroll` CKL, CKLB, XCCDF, and CCI functionality behind adapter interfaces.
- Preserve the existing `stigroll` command behavior as a compatibility entry point.
- Add fixture, unit, malformed-input, and golden-output tests.
- Record source file digest, parser version, ingest time, and diagnostics.
- Replace permissive XML handling where needed with bounded, secure parsing.
- Define stable observation fingerprints.
- Add a rule-source manifest with repository, commit, retrieval time, and schema version.

### Exit criteria

- Existing `stigroll` examples produce equivalent results.
- Parser failures cannot silently become clean assessments.
- Reimporting the same artifact is idempotent.
- Each observation can be traced to a source artifact and resource.

## Phase 1 — VDR case engine and official VER exports

Target: 3–4 weeks

### Deliverables

- SQLite-backed append-only event history and rebuildable projections.
- Information resource, observation, case, evaluation, rating change, response action, accepted
  vulnerability, and evidence records.
- Explicit IRV, LEV, PAIN, false-positive, and rationale workflow.
- Class B and Class C policy selection from pinned `FedRAMP/rules` data.
- Evaluation, mitigation, KEV, reporting, and 192-day acceptance clocks.
- Official JSON projections for:
  - VER-RPT-VDT Vulnerability Detail Report
  - VER-RPT-AVI Accepted Vulnerability Information
  - VER-TFR-MRH Historical VER Activity
- Markdown or HTML reports generated from the same projection records.
- JSON Schema validation with offline schema caching and digest verification.

### Proposed CLI

```text
trustroll rules sync --ref <commit-or-tag>
trustroll ingest <artifact...>
trustroll observations list
trustroll cases list
trustroll cases evaluate <case-id>
trustroll deadlines
trustroll report ver --class C --from <time> --to <time>
trustroll report historical --class C
trustroll validate <report.json>
```

### Exit criteria

- A CKLB/XCCDF assessment becomes a schema-valid VER report without spreadsheet manipulation.
- Every due date can identify the rule version and inputs used in its calculation.
- Changing an evaluation creates history rather than overwriting the prior evaluation.
- JSON and human-readable totals reconcile exactly.

## Phase 2 — Automation, detection coverage, and change integration

Target: 3–4 weeks

### Deliverables

- SARIF adapter.
- CycloneDX or SPDX adapter.
- CISA KEV enrichment.
- Initial cloud, container, or CSPM JSON adapter selected from design-partner demand.
- Git/deployment change-event ingestion.
- Expected-resource versus observed-resource coverage checks.
- Scanner and validation freshness checks.
- Change-triggered detection jobs.
- CI-friendly exit criteria and a reference GitHub Actions workflow.
- System-generated observations for failed imports, stale coverage, missing resources, or broken
  response workflows.

### Exit criteria

- A failed or stale detection process creates a reviewable vulnerability case.
- New or significantly changed resources can trigger a scoped detection request.
- A case can group equivalent observations while retaining every affected resource.

## Phase 3 — KSI validation and Security Decision Record evidence

Target: 4–6 weeks

### Deliverables

- Versioned validation definitions with objectives, scope, schedule, code reference, and explicit
  pass/fail/unknown criteria.
- Validation runs with coverage, result, evidence, freshness, and execution provenance.
- Provider comments and independent assessor comments stored side by side.
- Historical status and coverage trends.
- Multiple validation-method tracking for each KSI.
- Evidence links and summaries for Security Decision Record generation.
- SDR JSON generation and validation.
- Supporting, non-assertive links from observations and controls to KSIs.

### Exit criteria

- The system can demonstrate a KSI over time rather than attach a static artifact.
- An assessor can review the validation code version, criteria, result, evidence, and provider
  response together.
- Missing or stale validation is visible and eligible for VDR tracking.

## Phase 4 — Trust-center and ongoing certification integration

Target: after the local engine is stable

### Deliverables

- Authenticated, documented, read-only API.
- Human/JSON presentation consistency checks.
- Public, agency, assessor, and restricted evidence views.
- Just-in-time agency access integration.
- Agency user/system access inventory and history.
- Versioned certification-package snapshots.
- Quarterly Ongoing Certification Report projection.
- Feedback and assessor-review workflow integration.

### Exit criteria

- Authorized consumers can retrieve current and historical reports programmatically.
- Sensitive evidence can be withheld or abstracted without hiding material risk information.
- Every externally visible representation identifies its source snapshot and generation time.

## Cross-cutting acceptance requirements

| Area | Requirement |
|---|---|
| Correctness | Golden tests for deadline matrices, schemas, grouping, and report reconciliation |
| Provenance | Every derived value identifies source records, code/rule version, and generation time |
| Reproducibility | Historical reports can be regenerated from preserved events and pinned policies |
| Security | Inputs are untrusted; evidence is classified, minimized, redacted, and access controlled |
| Compatibility | Existing `stigroll` workflows remain available during migration |
| Explainability | No unexplained risk score or compliance conclusion |
| Portability | Local CLI remains a first-class supported deployment mode |

## Immediate backlog

1. Import the `stigroll` parser tests and fixtures without changing behavior.
2. Define the adapter protocol and canonical observation serialization.
3. Define the SQLite event and projection schema.
4. Implement rules source pinning and class selection.
5. Write golden tests for Class B and Class C evaluation and response clocks.
6. Implement official common-definition and VER schema resolution.
7. Produce the first end-to-end CKLB → case → VER JSON demonstration.
