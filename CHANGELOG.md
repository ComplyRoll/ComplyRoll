# Changelog

All notable project changes will be documented here.

## Unreleased

### Fixed

- A compiled Vulnerability Detail Report is now byte-identical across any argument order, on the
  stateless path and the persisted path alike. Four things echoed the order the operator named
  files in: the artifact manifest, the ingest diagnostics and the unresolved-observation
  diagnostics, the members of a vulnerability that spans several files, and the election of the
  surviving reading when two files carry identical bytes under different names. The last two
  reached the report's content rather than only the order of a list, since a group's `title` and
  `description` take the first non-empty value found while walking its members. Each list is now
  ordered by its own content: artifacts by `(name, sha256)`, diagnostics by
  `(code, location, message, level)`, and group members by
  `(resource_type, resource_id, source_artifact_name, observation_id)`. Verified by a randomized
  permutation audit over a deliberately hostile artifact set, across the stateless path, the
  persisted path, and the two compared against each other. The goldens moved by permutation only.
  The event log is deliberately not order-independent: two stores built by ingesting the same
  files in opposite orders differ in bytes and in sequence, both verify clean, and both rebuild
  the identical report.
- `.arf`, the suffix OpenSCAP gives its ARF output, was refused unread while the CLI help text on
  the same argument promised ARF support. It now dispatches by root element exactly as `.xml`
  does, so a valid ARF is accepted under either suffix and a misnamed CKL still reaches the CKL
  adapter. Observation identity hashes the artifact digest and not its name, so anyone who worked
  around this by renaming a file will not get duplicate cases when they stop.
- A lone surrogate code point in a JSON string or object key (`"\ud800"`) passed the bounded JSON
  parser and then crashed the report writer and the event store on `.encode("utf-8")`, for any
  JSON artifact. `parse_json_bounded` now refuses it during the walk it already does, and the
  dispatcher reports `artifact_parse_failed` with the code point named. Verified by parser tests
  in `tests/test_safeio.py`.

### Added

- An ARF fixture and adapter tests. ARF was advertised in the README, the help text, and the
  adapter docstring with no fixture and no parse-level test behind it. The fixture nests its
  `TestResult` five levels down behind a sibling OVAL report, splits the asset identity between
  the ARF assets block and the XCCDF target, and carries an unevaluated rule in an embedded
  benchmark, so a document-scoped identity or identifier sweep fails the tests rather than
  passing them quietly.
- The Accepted Vulnerability Information report and the Historical VER Activity report
  (ADR 0010). The record compiler now builds one period-agnostic `CompiledRecordSet` from
  either path, and three projections read it: `project_vdt`, `project_avi`, and
  `project_historical`. `complyroll report avi` and `complyroll report historical` compile
  each report from scanner artifacts and an evaluations file or, with `--db`, from a store;
  the historical command takes no `--from` or `--to`, and each writes the JSON document and an
  optional Markdown twin. The accepted-vulnerability report selects accepted records by their
  activity instants in the period, counts the rest in `excludedByPeriod` and the active
  records in `activeNotReported`, and takes the acceptance instant from the evaluation's
  `completedAt`. The historical report is a periodless snapshot of every record as of
  `--as-of`, split on acceptance, with `finalDisposition` distinguishing a disposed record from
  an open one. `examples/evaluations-accepted.json` adds one accepted entry to the shipped
  evaluations file, and four goldens, `tests/golden/avi-fixtures.{json,md}` and
  `tests/golden/historical-fixtures.{json,md}`, pin the bytes. Verified by schema validation
  against the bundled `0.1.1` documents, by the goldens on both the stateless and the rebuilt
  path, by agreement between the two paths across reversed ingest order and every ingest
  permutation of a shared fleet case, and by a test that records the same evaluations in two
  stores eleven days apart and proves the report bytes are identical, so the store's
  `recordedAt` never reaches a report.
- A SARIF 2.1.0 adapter (ADR 0011). `report vdt`, `report avi`, `report historical`, and `ingest`
  now accept `.sarif` files, and names ending `.sarif.json`, from Trivy, Grype, Semgrep, CodeQL,
  Checkov, or any conforming producer, beside the STIG checklists. Each result becomes one
  observation per located resource: the driver name is the source tool, the rule identifier
  resolved in the spec's order (an index, then `rule.guid`, then a lone exact id match, never a
  prefix) is the source record id, the located file, image path, or logical name is the
  resource, scoped by the image or repository the run declares, and the driver name plus the
  automation category is the context key, through the unchanged nine-input identity of ADR 0002.
  Results that share an identity inside one artifact fold into one observation with an
  occurrence count and capped region lists. The caps count characters, not bytes, so a log that
  fills them with four-byte text, or with quotes and backslashes that JSON escapes twice inside a
  list, reaches the 512 KiB ceiling on one folded observation's canonical JSON, and that artifact is
  refused on both paths, before the event store's own cap can. A suppressed result stays open with
  its suppression recorded in metadata and a warning on the artifact, `baselineState` never moves a
  disposition, `kind: open` is recorded as unknown so every report flags it, and scanner severity is
  recorded as evidence and never sets PAIN. An integer `security-severity` is range-checked before
  conversion, so an integer too large for a float is invalid rather than an overflow, and a string
  must be an ASCII decimal, so `0_9` or another script's digits never band as CRITICAL. A
  `ruleConfigurationOverrides` level applies from the result's own invocation when the entry's
  descriptor reference resolves, by the same rules as a result's, to the result's own descriptor,
  the first such entry winning; the reference's id counts only when it has no index and no guid that
  names a descriptor, and then only if one descriptor alone has it, so descriptors that share an
  id each keep their own level. Clocks are kept only from 1970 through 9000 UTC, the spec's hour 24
  is read as the next midnight on every interpreter, a leap second or a date alone is refused, and
  of two spellings of the earliest instant under different offsets the one whose text sorts first is
  kept, so no order of results, runs, or invocations changes an observation's `observed_at`. Message
  placeholders, location links, and CVE, GHSA, and CWE identifiers take ASCII letters and digits
  only, and link text reads the spec's escaped brackets and backslashes in one linear pass; a
  message substitutes at most 1,024 placeholders, an observation keeps at most 64 identifiers, and a
  region line or column above 2**31 - 1 is absent. Diagnostics are coalesced per code per artifact
  with occurrence counts and the first JSON paths, each path and detail sanitized and cut at 512
  characters and each detail read from a bounded part of the value without sorting it, so one
  artifact's diagnostics stay within about 56,000 characters whatever the input's size. A run's
  shared rule and component data is resolved once, each shared tags, `deprecatedIds`, or
  `repoDigests` list and each of a result's own lists and fingerprints is cut once to the items a
  fold can keep, each shared uri and each descriptor id a result takes as its rule identifier is
  checked once, and each override entry is resolved to its descriptor once, so a result's cost is
  bounded by the caps rather than by the size of a template, list, or value it shares, or by the
  size of its own lists once for each resource it names. An artifact's observations are capped
  together at 256 MiB of canonical JSON, the same way on both paths. Six synthetic fixtures
  (`trivy-image`, `grype-image`, `semgrep-code`, `codeql-repo`, `checkov-iac`, and
  `sarif-spec-corners`) and two goldens (`tests/golden/vdt-sarif.json` and `vdt-sarif.md`) hold the
  behavior. Verified by the 271 tests in `tests/test_sarif.py`, by the goldens on the stateless
  path, and by the persisted path and the replay reader rebuilding the same report from history byte
  for byte.

### Changed

- Repositioned the one-line description. "Evidence automation for continuous authorization" used
  Rev5 and continuous-monitoring vocabulary for a tool that implements the 2026 Vulnerability
  Detection and Response and Vulnerability Evaluation and Reporting rules. The package, the
  repository, and the project page now all read "Compiles STIG and SCAP output into schema-valid
  FedRAMP 20x vulnerability reports, with every response clock read from FedRAMP's published rules
  dataset." The PyPI summary is baked in at build time, so it carries the old line until the next
  release.
- The report-schema bundle now pins `FedRAMP/schemas` commit `5156719a` (ADR 0009), which
  carries Common Definitions `0.3.0`. FedRAMP merged it on 2026-09-01 as upstream pull request
  22, closing three issues: `finalDisposition` gains `Remediated` (issue 3),
  `vulnerabilityDetail` gains an optional `painReductionEvents` array (issue 7), and the
  `painReductionEvent` definition now cites `VER-RPT-VDT` instead of a rule that does not exist
  ([issue 16](https://github.com/FedRAMP/schemas/issues/16), which ComplyRoll raised). The
  three report schemas are byte-identical to the `0.1.1` copies already bundled, and the rules
  dataset pin is unchanged. Report provenance in the JSON and the Markdown cites the new commit,
  so the two VDT goldens moved: the commit in both, and in the JSON the relocated key and the
  empty extension lists that are no longer emitted. The schema-examples golden gained a
  `Remediated` example and a `painReductionEvents` example, and new tests prove that the
  `0.3.0` bundle refuses an unknown disposition and a malformed reduction event.
- A `remediated` case now emits `finalDisposition: "Remediated"` instead of `Fully Mitigated`.
  Every other disposition mapping is unchanged, and `x-complyroll.remediated` stays.
- Completed PAIN reductions moved from `x-complyroll.painReductionEvents` to the official
  `painReductionEvents` slot on the vulnerability record, emitted only when a case has at least
  one. A consumer that read the extension key must read the official key instead and treat it as
  optional; the extension no longer carries an empty list for cases with no reductions. This is
  a breaking change to the pre-1.0 extension.
- `ReportOptions` is keyword-only and its period is optional (ADR 0010). `period_from` and
  `period_to` default to `None`, must be given together, and keep the ordering check;
  `has_period` and the `period` property replace direct reads, and a projection that needs a
  period and gets none fails with the compile error `report_period_missing` named after the
  report. Positional construction of `ReportOptions` no longer works. `_period_exclusion_reason`
  takes a `state` argument so the accepted-vulnerability report's `excluded_by_period`
  diagnostic reads "is accepted and no recorded activity between" the bounds instead of
  "has disposition None". `_require_acceptance_rationales` fails the accepted-vulnerability and
  historical projections with `acceptance_rationale_missing` when an accepted record's
  evaluation has no rationale; the detail report keeps setting accepted records aside without
  one. The detail report's bytes are unchanged by this work.
- The rules dataset now pins `FedRAMP/rules` commit `58487bda`, dataset version `2026.09.13.02`
  (ADR 0005 amendment). It closes
  [FedRAMP/community discussion 164](https://github.com/FedRAMP/community/discussions/164),
  which ComplyRoll raised on 2026-08-24 because five rules stated a cadence in prose and carried
  no `timeframe_type` or `timeframe_num`. FedRAMP answered on 2026-09-13 that the timeframes had
  been entered mostly by hand, added the pair to those rules in `2026.09.13.01` (upstream pull
  request 28), and gave the schema optional `timeframe_num_min` and `timeframe_num_max` for the
  one rule that states a range; `2026.09.13.02` (pull request 29) changed only glossary terms and
  definitions. In the VDR and VER scope ComplyRoll selects, the only change is `VDR-TFR-NMV`,
  which now carries a three-month `MUST` timeframe, so `SelectedRule.timeframe` and
  `deadline_for_rule` return it for both classes. No report deadline is computed from it: the
  rule is a recurrence clock per non-machine-based information resource, which ComplyRoll does
  not record yet. Verified by loading and selecting both classes against the new bytes (36 rules
  each, every other timeframe and PAIN matrix unchanged), by the policy golden, which gained the
  `VDR-TFR-NMV` entry under both classes, and by the six report goldens, which moved only in the
  rules provenance block and in the overdue explanations that cite the dataset commit.
- The CLI help text for report and ingest artifacts now reads "CKLB, CKL, XCCDF, ARF, or SARIF
  file", and the package description reads "Compiles STIG, SCAP, and SARIF output into
  schema-valid FedRAMP 20x vulnerability reports, with every response clock read from FedRAMP's
  published rules dataset". The PyPI summary is baked in at build time, so it carries the
  previous line until the next release.
- The observation helpers the STIG adapters shared (`_text`, `_unique`, `_parse_timestamp`,
  `_make_observation`, and `_missing_time_diagnostic`) moved out of `adapters/stig.py` into
  `adapters/common.py` as `text_of`, `unique`, `parse_timestamp`, `make_observation`, and
  `missing_time_diagnostic`, and `make_observation` takes a `resource_type` that defaults to
  `host`. The move is the only edit on the STIG code paths in this work; every existing golden
  is byte-identical, which is the proof it changed nothing.
- `IngestLimits` gained `max_results_per_run` and `max_observations_per_artifact`, both 50,000 by
  default, and `max_observation_bytes_per_artifact`, 256 MiB of canonical JSON summed over an
  artifact's observations, since a fold copies the capped lists it keeps into every observation that
  carries them; exceeding any of them refuses the artifact as `artifact_parse_failed`. Every
  existing limit keeps its value.
- `stigroll` skips a SARIF log with a warning on stderr (`warning: <name> is a SARIF log; stigroll
  rolls up STIG checklists only, skipping`) instead of rolling it up; a run whose only input is a
  SARIF log ends with `error: no findings parsed from any input` and exit status 1.

## 0.3.0a0 - 2026-08-23

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
