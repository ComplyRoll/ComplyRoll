# ADR 0015: Coverage and freshness evidence

- Status: Accepted
- Date: 2026-10-15

## Context

The pinned rules dataset asks a provider to run its detection processes on a cadence
(VDR-TFR-MVX, NMV, PDD, PCD and PSD) and, under VDR-CSO-FAV, to treat a failure of those
processes as a vulnerability. `docs/BUILD_PLAN.md` carries the deliverables "Expected-resource
versus observed-resource coverage checks" and "Scanner and validation freshness checks", and the
exit criterion "A stale detection process creates a reviewable vulnerability case". ADR 0014
built the detection-failure half of VDR-CSO-FAV and left stale coverage, unseen resources and
the clean scan to this slice.

The slice ships as three pull requests, each mergeable on its own, and this record grows with
them: one dated section per pull request, appended below the decision it adds, so the status
line and the sections above it stay as written. This first section is PR 1, the clean scan.
The inventory input, the coverage evidence block and the clocks are PR 2; coverage gaps as
system observations and cases are PR 3. Their decisions are not recorded until they are built.

Before this record, a SARIF run that reported no results was INFO `run_clean` and, with no other
run yielding an observation, ERROR `no_observations` (ADR 0011 Decision 13), and ADR 0014
Decision 2 refused to mint it (`clean_scan`). Because the CLI parses every artifact before it
opens the store, one clean log failed the whole `ingest` run that included it, with or without
`--record-failed-imports`, and operators dropped clean logs. That was backlog item 9's open half
and the first gap the adapter's users met.

## Decision 1: a clean SARIF run is an artifact-origin PASS observation of its scope

At the `run_clean` site in `adapters/sarif.py`, a run whose `results` member is an empty array
yields one observation when none of its invocations declares `executionSuccessful: false`:

- `source_type` `sarif`, `source_tool` the driver name, `source_record_id` `sarif.run`,
  `context_key` the run's automation key exactly as ADR 0011 Decision 2 builds it (`driver`, or
  `driver|category`).
- Resource: `image:<name>` when the run names an image through `properties.imageName` or its
  first `repoDigests` entry, else `scan:<driver>`. No new resource type: the vocabulary of ADR
  0011 (image, file, logical, scan) is unchanged.
- `observed_at`: the run clock of ADR 0011 Decision 8 (earliest invocation start, else earliest
  end), else absent with the shared `source_timestamp_missing` WARNING. Ingest time is never
  substituted.
- Disposition PASS, severity UNKNOWN, no identifiers, the run's scalars and lists as metadata
  inside the fixed vocabulary (`tool_version`, `automation_id`, `image_name`, `image_digests`,
  `repository_uri`, `revision_id` and the rest, plus `run_indexes` and `occurrence_count`).
- Title "`<driver>` run reported no results", cut at the title cap like any title. Description,
  fixed text with no producer input: the run shows the tool ran against the scope it named and
  found nothing it was configured to report; it is not evidence that the scope is free of
  vulnerabilities.

The observation is built as a fold candidate under its own record id and assembled by the
ordinary ADR 0011 Decision 9 fold, so:

- Its identity is the ordinary ADR 0002 artifact fingerprint, bound to the log's bytes. The
  same bytes re-ingest as `already_recorded`; other bytes are another observation. It rides the
  existing artifact stream as an `observation.recorded` event. No contract changes and no store
  schema bump.
- Two clean runs of one scope in one log fold into one observation (`occurrence_count` 2,
  `run_indexes` both), the way two results that share an identity do, instead of tripping the
  dispatcher's `duplicate_observation_identity` and refusing the log.
- A result whose rule id is spelled `sarif.run` and resolves to the same resource folds with it,
  the worst disposition winning; a producer cannot keep a clean run out by naming a rule.
- It counts against the per-artifact observation cap and byte budget.

The failed-invocation guard keeps ADR 0014 where it is: a run with no results whose invocation
failed mints nothing from this decision and stays `run_clean` plus `execution_unsuccessful`
plus, when nothing else yields, `no_observations`, which is the execution class with
`--record-failed-imports`. INFO `run_clean` is raised in both cases with its existing message. A
run whose `results` member is absent or null is `results_unknown` and never a clean run.

Consequences:

- A clean log ingests on both paths and exits 0, with or without `--record-failed-imports`;
  `IngestResult.successful` holds and no failure is recorded.
- Correlation groups OPEN observations only, so the clean run never becomes a case and no report
  lists it. Its purpose is coverage evidence: PR 2 reads it as an examination and a verification
  of the scope it names at the run clock.
- A clean run beside a refused run is withheld by the ERROR and the reading is refused as a
  partial reading, as a log with a finding beside a refused run is. Before this decision that
  log was the content class.
- `UnmintableReason.CLEAN_SCAN` is unreachable and retired (ADR 0014, amendment 2026-10-15):
  every `run_clean` either folds an observation or sits beside `execution_unsuccessful`, which
  the execution class claims first. The classifier reads codes alone again.
- ADR 0011 Decision 13 and its 2026-09-30 amendment are amended; backlog item 9 is complete.
- Every existing golden is byte-identical: `tests/fixtures/failed-invocation.sarif` run 1 is
  guarded, and no other fixture has an empty results array. The new fixture
  `tests/fixtures/clean-run.sarif` is one clocked image run.

Rejected alternatives:

- A system-origin observation, as backlog item 9 was written. A system observation's identity
  (ADR 0002, amendment 2026-08-21) is built from its recipe inputs, not from artifact bytes, and
  carries `complyroll` as its tool; the clean run is a fact the log states about itself, bound to
  the exact bytes that state it, and belongs on the artifact stream with the log's own
  provenance. ADR 0014's SYSTEM loop in the compiler would also have sent it to
  `_detection_failure`.
- Keeping the clean run out of the fold and letting the dispatcher's duplicate check decide
  collisions. Two clean runs of one scope in one log, which a tool that writes one run per target
  without `automationDetails` produces, would then refuse the whole log.
- A fifth resource type for a run's scope. The inventory of PR 2 names images and hosts, not
  runs, and the `scan:<driver>` fallback already exists for a result without a location.
- Dropping INFO `run_clean` once the run mints. The note is what an operator sees on standard
  error, and keeping one code and one message keeps the guarded run's output unchanged.
