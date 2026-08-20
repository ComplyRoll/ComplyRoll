# ADR 0003: Use bounded standard-library ingestion for Phase 0

- Status: Accepted
- Date: 2026-08-18

## Context

Assessment artifacts are untrusted and may be malformed or intentionally hostile. ComplyRoll also
needs to run on hardened workstations where adding dependencies may require separate approval.

## Decision

Phase 0 retains a dependency-free runtime and wraps Python's JSON and ElementTree parsers with
explicit file-size, nesting, node, and element bounds. XML DTD and entity declarations are
rejected before parsing. JSON must be UTF-8 and cannot contain non-standard numeric constants.
Parser errors and structurally invalid documents become explicit failed-ingest diagnostics.

Compatibility CSV and Markdown renderers neutralize formula-leading cells and raw markup without
changing normal predecessor output.

## Consequences

- No parser dependency or network access is required to ingest Phase 0 sources.
- Limits are deterministic, testable, and configurable by local callers.
- DTD-dependent XML is rejected even when its entity declarations would be harmless.
- Archive handling remains out of scope; any future archive adapter requires separate traversal,
  expansion, and extraction controls.
- Parser dependencies may still be reconsidered if later formats cannot be handled safely within
  these bounds.
