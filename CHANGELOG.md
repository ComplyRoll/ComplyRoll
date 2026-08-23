# Changelog

All notable project changes will be documented here.

## Unreleased

### Added

- Persisted history (ADR 0008). Typed version-1 event contracts for `artifact.ingested`,
  `observation.recorded`, `case.created`, `case.observation_linked`, `detection.attested`,
  `case.evaluated`, `case.pain_reduced`, `case.disposition_recorded`, and `case.identified`,
  validated on every append by `complyroll.events.EventRepository`; event metadata records the
  actor, method, tool version, and a per-run identifier.
- `complyroll ingest`, `complyroll cases correlate`, `complyroll cases attest-detection`,
  `complyroll cases evaluate`, `complyroll cases list`, `complyroll cases history`,
  `complyroll report vdt --db`, and `complyroll store verify`. Every write is idempotent: a
  repeated command appends nothing and a changed evaluation appends a new `case.evaluated`
  event instead of overwriting the earlier one.
- An event-sourced rebuild of the Vulnerability Detail Report that rehydrates recorded
  observations, folds each case stream, and runs the same record compiler; its output is
  byte-identical to the stateless report for the same inputs and that equality is a test.
- `Observation.from_canonical_dict` (the inverse of the ADR 0002 canonical form) and
  `SQLiteEventStore.verify_history`, which walks the log checking digests, contiguity, the
  sequence counter, and schema definitions and returns a structured report.
- `SQLiteEventStore.open_for_verification`, a diagnostic open path that never creates or modifies
  the file, so `store verify` reports faults (a truncated tail, an altered or missing schema
  object) on stores the normal open refuses instead of raising. The normal open and every append
  now also refuse a hole anywhere in history (event count versus highest sequence, per stream
  and globally), not only a truncated tail, and `store verify` validates every payload against
  its published contract after the store-level walk.
- `cases evaluate` refuses an evaluations file that would give two cases the same effective
  tracking id, and warns (`disposition_retained`, `reduction_retained`,
  `identification_retained`) when an entry omits a disposition, PAIN reductions, or a tracking-id
  override the case already holds, because no retraction event exists. An evaluations file that
  states the same PAIN reduction twice is refused on both paths. `cases attest-detection`
  reports cases where any observation already carries a source timestamp as not applicable, and
  `--all-missing` skips cases that are already attested. Every command except `ingest` reports
  `store_missing` rather than creating an empty store, and a failed `ingest` creates no file.
- The `case.disposition_recorded` contract enforces the evaluations file's cross-field rules
  (closed needs a closed disposition; a rationale only with acceptance; acceptance needs a
  rationale) at append and in the fold; the `observation.recorded` contract accepts only the
  exact timestamp text the canonical writer produces, and the repository reads every observation
  payload back through the canonical reader before storing it. Completed PAIN reductions render in
  canonical order on both paths, and a disposition recorded without an evaluation makes the
  replay fail closed.
- `SQLiteEventStore.transaction()`: one write transaction that every append inside it joins. The
  case writers fold, check, and append inside one transaction, so concurrent `cases evaluate`
  runs cannot both record the same provider tracking id, an artifact is ingested atomically, and
  one `ingest` run is all-or-nothing across its artifacts on a new store and an existing one
  alike. The fold refuses an incomplete or overfull artifact stream and an event whose artifact
  identity differs from its stream or repeats an observation identifier within the stream, and
  `store verify` reports them (`artifact_incomplete`, `artifact_overfull`,
  `artifact_stream_mismatch`, `artifact_duplicate_observation`). A whitespace-only acceptance
  rationale is refused by the `case.disposition_recorded` contract itself, so the fold carries no
  cross-field rule the audit cannot see.
- The repository parses every timestamp field of every contract as a real instant (hour 24
  included, which Python would otherwise roll into the next day), refuses an event stored on
  the wrong kind of stream or a `case.created` on another case's stream, and enforces the
  metadata rules (`run-<uuid4>`, a published method, `tool` equal to `complyroll`, a non-blank
  version); `store verify` audits all of these at rest through
  `complyroll.history.audit_history`. The rules are public
  as `complyroll.events.metadata_breaches`, `timestamp_pointers_for`, and
  `event_belongs_on_stream`, and the parser-version split as `complyroll.history.artifact_history`.
- When one artifact has streams under several parser versions, replay uses the newest and
  reports older streams as `artifact_superseded`.
- Output files publish with rollback: a failure while replacing the destinations restores the
  previous files, a rollback that itself fails exits with `output_rollback_failed` naming every
  destination left in its new state and the kept copy of its previous content, and a symbolic
  link is refused as a destination (`output_is_symlink`). A new store is built at a temporary
  path beside the destination and published with a hard link only on success, which refuses to
  overwrite a store that appeared meanwhile (`store_conflict`); `ingest` never deletes the
  destination path, and refuses a dangling symbolic link as `--db` (`store_unavailable`).
- JSON deadline objects carry `satisfied`; the Markdown detail section lists every observation
  id of a partly timestamped group and marks the untimestamped ones; a parity test walks the
  records. Help text names ARF; `--all-missing` reports how many cases it selected; the
  `reduction_retained` warning points at a new evaluation entry.
- A `[tool.mypy]` configuration so the type gate is reproducible from the repository.
- A `release.yml` workflow that publishes to PyPI through trusted publishing (OIDC, no stored
  token) when a `v<version>` tag is pushed: the tag must equal the `pyproject` version, the suite
  runs on the exact tree being published, and the publish job is gated by a `pypi` environment.

### Changed

- Every command that folds observations (`cases correlate`, `cases attest-detection`,
  `cases evaluate`, `report vdt --db`) fails closed on a store carrying an artifact stream with
  fewer observations than its `artifact.ingested` event declares. Only an interrupted ingest
  from an earlier version leaves such a stream; re-running `ingest` for that artifact completes
  it, and `store verify` names it as `artifact_incomplete`.
- Repository and issue URLs point at the `ComplyRoll` GitHub organization
  (`github.com/ComplyRoll/ComplyRoll`); the previous path redirects.
- The Vulnerability Detail Report compiler is split into `compile_records`, shared by the
  stateless and persisted paths so neither can drift from the other; `compile_vdt_report` keeps
  its signature, behavior, and output. Detection-time attestations are per case on the persisted
  path: when every attested case shares one instant the report carries the same
  `detectionTimeAttestation` block as before; otherwise the block lists each instant with the
  tracking ids it covers and has no single `detectedAt`.

## 0.2.0a0 - 2026-08-21

Hardening release driven by an independent audit of the Phase 0 and Phase 1 primitives.

### Fixed

- XML DTD and ENTITY declarations are now rejected by the parser itself (expat declaration
  handlers) instead of a UTF-8 byte scan. The scan could be bypassed by UTF-16 encoded documents,
  which then expanded internal entities into evidence records, and it falsely rejected legitimate
  checklists that quoted `<!DOCTYPE` inside CDATA or comments.
- `read_bounded` requires a regular file and reads with a bounded loop, so FIFOs and devices fail
  fast instead of blocking or growing without limit.
- A failed `COMMIT` in the SQLite event store now rolls back and raises `EventStoreBusyError`
  instead of leaving the connection inside an open transaction with phantom, unrecorded events
  visible to later reads.
- Every event-store method now maps SQLite failures to ComplyRoll error types: lock contention
  raises the retryable `EventStoreBusyError`, a corrupt file raises `EventIntegrityError`, a
  non-database file raises `UnsupportedSchemaError`, and disk-full, read-only, or I/O failures
  raise `EventStoreError` with SQLite's message. No raw `sqlite3` exception crosses the public
  boundary.
- A rollback that fails after a failed commit or body error closes the connection and reports
  it, instead of leaving the store inside an open transaction.
- Opening a brand-new store from several processes at once no longer fails spuriously: the
  WAL switch is skipped on established files, retried within the busy timeout otherwise, and
  schema creation is re-checked under the write lock so a peer's initialization is accepted.
- Domain validators raise `TypeError` for wrong input types (non-string text, non-datetime
  timestamps, bytes digests, a missing `ResourceRef`, non-string display fields) instead of
  failing inside a helper; a system observation cannot smuggle a falsy non-string past the
  empty-artifact-field rule.
- Opening a store verifies the stored DDL of every expected table, index, and trigger against
  the source DDL, so a same-named trigger with a different body no longer passes as append-only.
- Deleting the most recent events is detected: the AUTOINCREMENT counter must match the last
  stored sequence on open and before every append, which also stops the next append from
  minting a permanent gap.
- A path that cannot be opened (directory, missing parent, read-only location) raises
  `EventStoreError` instead of a raw `sqlite3` exception from the constructor.
- Reopening a store whose append-only triggers, indexes, or tables were removed now fails with
  `UnsupportedSchemaError`; `read_all` and `read_stream` raise `EventIntegrityError` when a gap
  shows that history was deleted.
- Domain dataclasses validate enum and boolean fields (`PainRating`, `CaseStatus`,
  `ObservationDisposition`, `SourceSeverity`, IRV/LEV flags) and coerce sequence fields to tuples.
  Artifact digests are normalized to lowercase so letter case no longer changes identity.
- `VulnerabilityCase.with_evaluation` refuses to silently reactivate ACCEPTED or CLOSED cases and
  keeps prior evaluations in `evaluation_history`.

### Added

- `complyroll report vdt`: a stateless compiler that turns CKLB, CKL, XCCDF, and ARF artifacts
  plus an operator evaluations file into a schema-valid Vulnerability Detail Report
  (`VER-RPT-VDT`) with a Markdown twin rendered from the same records. Open findings group into
  vulnerabilities with stable `case-` tracking ids; every vulnerability carries class-aware
  evaluation, PAIN response, and acceptance-threshold deadlines with rule id and force; overdue
  flags name the rule, force, class, inputs, due instant, dataset commit, and the optional-adoption
  period; `x-complyroll` carries generator, parser, rules, and schema provenance, the attestation,
  grouped observation ids, affected resources, compile diagnostics, and the disclaimer. The report
  period selects contents (activity-in-period rule with `excluded_by_period` diagnostics and an
  excluded count); groups with only some timestamped observations are marked `artifact-partial`;
  effective tracking ids must be unique; a case may close as accepted and is then routed to the
  accepted-vulnerability path; output files are written all-or-nothing. The compiler fails closed
  on any ingest error, missing detection time, or unmatched evaluation and validates the document
  before writing it (ADR 0007 and its amendment).
- `complyroll validate REPORT --schema ...` for offline validation of any report against the
  pinned official schemas with JSON Pointers and provenance.
- Correlation v0 (`complyroll.correlation`) and the bounded evaluations-file loader
  (`complyroll.reports.evaluations`).
- A calendar timezone on `CertificationProfile`; month and year deadline arithmetic now runs in
  that zone (default UTC) instead of on the UTC instant.
- ADR 0007 recording the report mappings, `examples/evaluations.json`, and golden report outputs.
- `ObservationOrigin` and system-generated observations: detection and response process failures
  can now be represented without a source artifact, with their own deterministic identity recipe
  (ADR 0002 amendment).
- Per-adapter parser version constants so a fix to one adapter does not re-identify observations
  from the others.
- WAL journal mode with `synchronous=FULL`, a configurable busy timeout, and schema verification
  on open for the event store (ADR 0004 amendment).
- `NOTICE` and `src/complyroll/data/README.md` recording that the bundled FedRAMP dataset and
  schemas are U.S. Government works redistributed unmodified and are not covered by the project
  license.
- A root `SECURITY.md` with a private vulnerability reporting channel, issue and pull request
  templates that forbid attaching real assessment artifacts, and a Developer Certificate of Origin
  requirement in `CONTRIBUTING.md`.
- Python 3.14 in the CI matrix, commit-SHA-pinned GitHub Actions, a console-script smoke test,
  Dependabot configuration, `py.typed`, and PEP 639 license metadata.

### Changed

- License changed from MIT to the Apache License, Version 2.0, before any public release. The
  Apache license adds an explicit patent grant and withholds trademark rights to the ComplyRoll
  name (Section 6); `NOTICE` carries the copyright and the U.S. Government data statement.
- README restructured around what runs today, with a disclaimer section, an independent-assessor
  section, and FedRAMP trademark attribution.
- Documentation now says "official-format" or "schema-valid" reports rather than "official
  reports", records the VDR/VER effective dates, and notes that the PAIN response targets
  (`VDR-TFR-PVR`) and evaluation window (`VER-TFR-EVU`) are SHOULD while the 192-day acceptance
  boundary (`VER-TFR-MAV`) is MUST.
- `CONTRIBUTING.md` no longer claims the package has no runtime dependencies.

## 0.1.0a0 (unreleased history)

### Changed

- Renamed the project, Python package, CLI, and parser identifiers from TrustRoll to ComplyRoll.
- Adopted the positioning: "Evidence automation for continuous authorization."

### Added

- Started Phase 1 with a migration-managed, append-only SQLite event store.
- Added transactional batch appends, optimistic stream concurrency, canonical payload digests,
  bounded event JSON, ordered replay, and rebuildable projection checkpoints.
- Added ADR 0004 documenting the event-envelope and disposable-projection storage contract.
- Added an offline, digest-verified official FedRAMP rules snapshot and bounded loader.
- Added 20x Class B/Class C provider-policy selection and provenance-bearing deadline calculation.
- Added golden evaluation, recurrence, PAIN response, and acceptance-threshold policy matrices.
- Added ADR 0005 documenting verified policy selection and fail-closed timeframe behavior.
- Added a digest-verified offline registry for official FedRAMP Common Definitions and the three
  initial VER report schemas.
- Added Draft 2020-12 report validation with enforced formats, actionable JSON Pointers, bounded
  raw JSON parsing, schema provenance, and fail-closed reference resolution.
- Added ADR 0006 documenting immutable schema pinning and the `jsonschema` dependency boundary.
- Completed the Phase 0 CKLB, CKL, XCCDF/ARF, and CCI adapter layer.
- Added artifact provenance, structured diagnostics, canonical observation serialization, and
  artifact-bound deterministic observation IDs.
- Added bounded JSON/XML parsing, CSV formula neutralization, and Markdown field escaping.
- Added a pinned, digest-verified metadata manifest for the official FedRAMP 2026 rules source.
- Added the backward-compatible `stigroll` package entry point and source-checkout launcher.
- Added synthetic fixtures and golden compatibility, malformed-input, security, provenance, and
  idempotency tests.

## 0.1.0a0 - 2026-08-18

- Create the TrustRoll pre-alpha repository scaffold.
- Define the FedRAMP 20x VDR product direction and phased build plan.
- Add foundational observation, evaluation, evidence, and case domain types.
- Add a minimal dependency-free CLI and unit tests.
