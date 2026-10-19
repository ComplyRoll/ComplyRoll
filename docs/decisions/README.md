# Architecture decision records

Each record below is listed with the decision it makes. Later changes are appended to a record
under `Amendment <date>` headings. An amendment can supersede part of the decision above it, so
read a record's amendments before relying on it.

- [ADR 0001: Separate observations from vulnerability cases](0001-observation-case-separation.md):
  immutable observations are stored apart from stateful vulnerability cases, with every source
  record and affected resource kept through grouping.
- [ADR 0002: Bind observation identity to the source
  artifact](0002-artifact-bound-observation-identity.md): observation identity is SHA-256 over
  the source, parser, record, resource, and context inputs plus the exact artifact digest, never
  ingestion time.
- [ADR 0003: Use bounded standard-library ingestion for
  Phase 0](0003-bounded-standard-library-ingestion.md): ingestion keeps a dependency-free runtime
  and wraps Python's JSON and ElementTree parsers in explicit file-size, nesting, node, and
  element bounds.
- [ADR 0004: Use an append-only SQLite event store](0004-append-only-sqlite-event-store.md):
  material changes are immutable event envelopes appended to SQLite under optimistic
  concurrency, with projections rebuildable from sequence zero.
- [ADR 0005: Select policy from a verified FedRAMP rules
  snapshot](0005-select-policy-from-verified-fedramp-rules.md): policy comes from the exact
  official `FedRAMP/rules` bytes, verified by digest before parsing, and every deadline carries
  its rule and provenance.
- [ADR 0006: Verify and resolve official VER schemas
  offline](0006-verify-and-resolve-official-ver-schemas-offline.md): the official report schemas
  are pinned to one `FedRAMP/schemas` commit, verified by digest, and resolved offline with the
  bounded `jsonschema` dependency.
- [ADR 0007: Compile the first Vulnerability Detail Report statelessly, and fix the mappings it
  needs](0007-stateless-vdt-compiler-and-report-mappings.md): fixes the report mappings
  (attested detection time, disposition table, clock semantics, overdue wording, the
  `x-complyroll` extension, and the evaluations file).
- [ADR 0008: Persist history as typed events and rebuild the report from the
  log](0008-persisted-history-and-event-sourced-rebuild.md): records the same inputs as typed
  events with published contracts and rebuilds the same report from the log, so changing an
  evaluation creates history instead of overwriting it.
- [ADR 0009: Adopt Common Definitions 0.3.0](0009-adopt-common-definitions-0-3-0.md): the new
  definitions give completed PAIN reductions an official slot and remediation its own
  disposition.
- [ADR 0010: Report projections from one record
  set](0010-report-projections-from-one-record-set.md): splits the compiler into one
  period-agnostic record set and three report projections, fixes the acceptance instant to the
  evaluation's, and makes the historical report a periodless snapshot of the whole population.
- [ADR 0011: SARIF adapter](0011-sarif-adapter.md): keyed on the located resource and the driver
  name rather than on producer fingerprints.
- [ADR 0012: CISA KEV enrichment](0012-cisa-kev-enrichment.md): the operator supplies the
  catalog, which is never fetched, bundled, or stored and is pinned in the report by the digest
  of its bytes.
- [ADR 0013: HDF adapter](0013-hdf-adapter.md): keyed on the declared target and the root
  profile. Waivers and attestations are recorded as metadata and never change a disposition,
  which the results decide unless impact 0 reads not applicable first.
- [ADR 0014: System-generated observations for detection process
  failures](0014-system-generated-observations.md): records a detection process failure as a
  system observation and case, opt-in per run with `--record-failed-imports`, with exit 3 and a
  schema 2 or 3 store.
- [ADR 0015: Coverage and freshness evidence](0015-coverage-and-freshness.md): a SARIF run with
  no results is an artifact-origin PASS observation of the scope it names, guarded on invocation
  success; a provider-supplied inventory is a per-run report input whose entries get coverage
  clocks from the pinned dataset, reported as evidence with a status per clock; a window that
  closes with no verification becomes a `VDR-CSO-FAV` system observation and case, with
  `--record-coverage-gaps` on a report or `cases coverage` into a schema 4 store.
- [ADR 0016: CycloneDX SBOM adapter](0016-cyclonedx-sbom-adapter.md): a vulnerability is located
  on a `package` resource keyed by the subject's lineage and a version-free package key, a case
  is one CVE from one tool, an inventory or an empty list never verifies coverage, and a
  standalone VEX document is refused.
