# Changelog

All notable project changes will be documented here.

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
  grouped observation ids, affected resources, and the disclaimer. The compiler fails closed on any
  ingest error, missing detection time, or unmatched evaluation and validates the document before
  writing it (ADR 0007).
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
