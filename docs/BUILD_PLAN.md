# ComplyRoll build plan

Status date: **2026-08-20**

## Outcome

ComplyRoll will compile heterogeneous security and validation evidence into traceable FedRAMP 20x
VDR cases, class-aware response timelines, and consistent official-format reports.

The initial target is a provider security engineer or assessor working locally or in CI. A hosted
trust center is a later integration boundary, not the MVP.

## Primary users

| User | Primary job |
|---|---|
| CSP security engineer | Ingest detections, evaluate context, track mitigation, and detect coverage failures |
| CSP GRC owner | Produce correct, current, repeatable FedRAMP reports without spreadsheet reconciliation |
| Independent assessor | Recompute and validate cold from provider-supplied artifacts; review validation code, failure criteria, evidence, history, and provider rationale. Assessors do not operate ComplyRoll on the provider's behalf (advisory work bars assessing that offering for two years under `REC-IAS-SEP`) |
| Agency reviewer | Consume filtered, current, machine-readable certification information |

## Product boundaries

ComplyRoll is:

- A normalized evidence and case engine.
- A rule-version-aware deadline calculator.
- A report compiler and validator.
- A foundation for persistent KSI validation.

ComplyRoll is not initially:

- A replacement ticketing platform.
- A complete trust center.
- A vulnerability scanner.
- An automatic risk acceptance authority.
- An AI system that independently assigns PAIN or declares KSI compliance.

## Phase 0 — Harden the existing ingestion kernel

Target: 1–2 weeks

**Status: Complete — 2026-08-18**

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

### Completion record

- The CKLB, CKL, XCCDF/ARF, and CCI implementations now conform to explicit adapter and mapping
  protocols.
- The installed `stigroll` entry point and repository-root `stigroll.py` launcher preserve the
  predecessor's Markdown, CSV, JSON, CCI, mixed-input, and output-file workflows.
- Every artifact is SHA-256 identified before parsing. Every produced observation records the
  artifact digest/name, parser/version, resource, source record, ingest time, and diagnostics.
- Observation identity includes the parser version, exact artifact digest, source record, resource,
  and benchmark context. Reimporting identical bytes with the same parser produces the same IDs;
  changed artifacts or parser versions remain new normalized facts.
- JSON/XML size, structure, nesting, and element limits are enforced. XML DTD and entity
  declarations are rejected, malformed shapes fail explicitly, CSV formulas are neutralized, and
  Markdown table fields are escaped.
- `src/complyroll/data/fedramp-rules-source.json` pins the official dataset and schema by full Git
  commit, SHA-256 digests, dataset version, schema draft, and retrieval time.
- Synthetic CKLB, CKL, XCCDF, and CCI fixtures plus predecessor-generated golden files verify
  compatibility without customer data.

## Phase 1 — VDR case engine and official VER exports

Target: 3–4 weeks

**Status: In progress — started 2026-08-20**

### Current progress

- Schema version 1 establishes an append-only SQLite event log, ordered global replay, unique
  event and stream-version constraints, canonical payload digests, and projection checkpoints.
- Event appends are transactional and use expected stream versions to reject lost updates.
- Projection checkpoints use compare-and-swap semantics and can reset to sequence zero for a
  deterministic rebuild.
- ADR 0004 records the event-envelope, migration, integrity, and disposable-projection contract.
- The official rules snapshot is bundled offline and verified against the pinned commit, version,
  last-updated value, and SHA-256 before policy selection.
- Provider-facing 20x Class B and Class C VDR/VER rules are selected from official type, path,
  class, affected-party, and class-variant structures.
- Evaluation, PAIN response, reporting recurrence, and acceptance-threshold calculations carry the
  exact rule ID and dataset provenance; golden tests cover both classes.
- Official Common Definitions and the three initial VER report schemas are pinned to one immutable
  `FedRAMP/schemas` commit, digest verified, resolved offline, and checked as Draft 2020-12 schemas.
- Report validation returns deterministic, actionable JSON Pointers and complete schema
  provenance; golden examples cover Vulnerability Detail, Accepted Vulnerability, and Historical
  Activity documents.

### Deliverables

- SQLite-backed append-only event history and rebuildable projections.
- Information resource, observation, case, evaluation, rating change, response action, accepted
  vulnerability, and evidence records.
- Explicit IRV, LEV, PAIN, false-positive, and rationale workflow.
- Class B and Class C policy selection from pinned `FedRAMP/rules` data.
- Evaluation, mitigation, KEV, reporting, and 192-day acceptance clocks.
- Official-format JSON projections for:
  - VER-RPT-VDT Vulnerability Detail Report
  - VER-RPT-AVI Accepted Vulnerability Information
  - VER-TFR-MRH Historical VER Activity
- Markdown or HTML reports generated from the same projection records.
- JSON Schema validation with offline schema caching and digest verification.

### CLI

Implemented:

```text
complyroll report vdt <artifact...> --class C --package-uri <uri> --from <time> --to <time>
    [--evaluations <file>] [--detected-at <time>] [--as-of <time>] [--calendar-tz <name>]
    [-o <report.json>] [--markdown <report.md>]
complyroll validate <report.json> --schema <vulnerability-detail|accepted-vulnerability|historical-activity>
complyroll ingest <artifact...> --db <store> [--as-of <time>] [--actor <name>]
complyroll cases correlate --db <store> [--actor <name>]
complyroll cases attest-detection --db <store> --detected-at <time> --rationale <text>
    (--case <tracking-id> | --all-missing) [--actor <name>]
complyroll cases evaluate --db <store> --evaluations <file> [--actor <name>]
complyroll cases list --db <store>
complyroll cases history <tracking-id> --db <store>
complyroll report vdt --db <store> --class C --package-uri <uri> --from <time> --to <time>
    [--as-of <time>] [--calendar-tz <name>] [-o <report.json>] [--markdown <report.md>]
complyroll store verify --db <store>
```

Proposed:

```text
complyroll rules sync --ref <commit-or-tag>
complyroll observations list --db <store>
complyroll deadlines --db <store>
complyroll report avi --class C --from <time> --to <time>
complyroll report historical --class C
```

### Exit criteria

- A CKLB/XCCDF assessment becomes a schema-valid VER report without spreadsheet manipulation.
  **Met 2026-08-21 for the stateless path** (`complyroll report vdt`, golden-tested).
- Every due date can identify the rule version and inputs used in its calculation. **Met** (every
  deadline in the report carries rule id, force, anchor, inputs, and the dataset commit and digest).
- Changing an evaluation creates history rather than overwriting the prior evaluation. **Met
  2026-08-22** (ADR 0008: `cases evaluate` appends a second `case.evaluated` event for a changed
  evaluation, `cases history` lists both, `report vdt --db` carries the latest, and the rebuilt
  report is byte-identical to the stateless goldens, asserted in tests).
- JSON and human-readable totals reconcile exactly. **Met** (both renderers read one record list;
  a reconciliation test asserts the totals).

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

1. Define the SQLite event and projection schema. **Complete — 2026-08-20.**
2. Implement class-aware policy selection from the pinned rules source. **Complete — 2026-08-20.**
3. Write golden tests for Class B and Class C evaluation and response clocks. **Complete — 2026-08-20.**
4. Implement official common-definition and VER schema resolution. **Complete — 2026-08-20.**
5. Produce the first end-to-end CKLB → case → VER JSON demonstration. **Complete (stateless
   path) — 2026-08-21.** `complyroll report vdt` compiles the fixtures into a schema-valid
   Vulnerability Detail Report with a Markdown twin (ADR 0007); the event-sourced rebuild of the
   same report landed with item 6.
6. Persist `observation.recorded`, `detection.attested`, and `case.*` events from the compiler's
   inputs; rebuild the Vulnerability Detail Report from the event log and reconcile it against the
   stateless output byte for byte. **Complete, 2026-08-22** (ADR 0008: typed event contracts,
   `ingest`, `cases correlate|attest-detection|evaluate|list|history`, `report vdt --db`,
   `store verify`; the reconciliation is a test against the stateless goldens).
7. Accepted-vulnerability (`VER-RPT-AVI`) and historical-activity (`VER-TFR-MRH`) reports from the
   same record compiler.
