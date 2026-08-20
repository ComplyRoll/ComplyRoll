# Changelog

All notable project changes will be documented here.

## Unreleased

### Changed

- Renamed the project, Python package, CLI, and parser identifiers from TrustRoll to ComplyRoll.
- Adopted the positioning: "Evidence automation for continuous authorization."

### Added

- Started Phase 1 with a migration-managed, append-only SQLite event store.
- Added transactional batch appends, optimistic stream concurrency, canonical payload digests,
  bounded event JSON, ordered replay, and rebuildable projection checkpoints.
- Added ADR 0004 documenting the event-envelope and disposable-projection storage contract.
- Completed the Phase 0 CKLB, CKL, XCCDF/ARF, and CCI adapter layer.
- Added artifact provenance, structured diagnostics, canonical observation serialization, and
  artifact-bound deterministic observation IDs.
- Added bounded JSON/XML parsing, XML DTD/entity rejection, CSV formula neutralization, and
  Markdown field escaping.
- Added a pinned, digest-verified metadata manifest for the official FedRAMP 2026 rules source.
- Added the backward-compatible `stigroll` package entry point and source-checkout launcher.
- Added synthetic fixtures and golden compatibility, malformed-input, security, provenance, and
  idempotency tests.

## 0.1.0a0 - 2026-08-18

- Create the TrustRoll pre-alpha repository scaffold.
- Define the FedRAMP 20x VDR product direction and phased build plan.
- Add foundational observation, evaluation, evidence, and case domain types.
- Add a minimal dependency-free CLI and unit tests.
