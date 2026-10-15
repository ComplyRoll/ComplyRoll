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
yields one observation when every invocation it declares carries `executionSuccessful: true`. A
run with no `invocations` member makes no claim either way and still yields it. Only the JSON
booleans count: an invocation whose flag is absent, null or any other type, and an `invocations`
member that is present but not an array (it could hide a failed invocation), is WARNING
`execution_unverified` and backs no clean run, while the run's results, when it has any, are
still read as before. The observation:

- `source_type` `sarif`, `source_tool` the driver name, `source_record_id` `sarif.run`,
  `context_key` the run's automation key exactly as ADR 0011 Decision 2 builds it (`driver`, or
  `driver|category`).
- Resource: `image:<name>` when the run names an image through `properties.imageName` or its
  first `repoDigests` entry; else `scan:<repository uri>` when `versionControlProvenance[0]`
  names a repository, so two clean runs of two repositories by one driver are two observations
  that each keep their own `repository_uri` and `revision_id`; else `scan:<driver>`. No new
  resource type: the vocabulary of ADR 0011 (image, file, logical, scan) is unchanged.
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
- A result whose rule id is spelled `sarif.run` and resolves to the same resource shares its
  fold, and the producer's result takes the observation: the clean candidate yields with INFO
  `clean_run_superseded`, contributing no title, text, run index or occurrence. A producer
  naming that rule can neither dress a finding as a run that reported nothing nor make a clean
  run refuse the log. Under a different resource (an image-scoped clean run beside a
  locationless result) both stand as two observations.
- It counts against the per-artifact observation cap and byte budget.

The failed-invocation guard keeps ADR 0014 where it is: a run with no results whose invocation
failed mints nothing from this decision and stays `run_clean` plus `execution_unsuccessful`
plus, when nothing else yields, `no_observations`, which is the execution class with
`--record-failed-imports`. A run with no results whose invocation is unverified mints nothing
either and stays `run_clean` plus `execution_unverified` plus, when nothing else yields,
`no_observations`: the log held no usable content, which is the content class with the flag and
fatal without it, as it was before this record. INFO `run_clean` is raised in every case with its
existing message. A run whose `results` member is absent or null is `results_unknown` and never a
clean run.

Consequences:

- A clean log ingests on both paths and exits 0, with or without `--record-failed-imports`;
  `IngestResult.successful` holds and no failure is recorded.
- Correlation groups OPEN observations only, so the clean run never becomes a case and no report
  lists it. Its purpose is coverage evidence: PR 2 reads it as an examination and a verification
  of the scope it names at the run clock.
- A clean run beside a refused run is withheld by the ERROR and the reading is refused as a
  partial reading, as a log with a finding beside a refused run is. Before this decision that
  log was the content class.
- `UnmintableReason.CLEAN_SCAN` is retired (ADR 0014, amendment 2026-10-15): a `run_clean`
  either folds an observation, sits beside `execution_unsuccessful`, which the execution class
  claims first, or sits beside `execution_unverified`, where the reading held nothing usable and
  is the content class. The classifier reads codes alone again.
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
- Reading an absent `executionSuccessful` as success. The flag is required by the SARIF schema,
  and a run with `exitCode` 2 and an error notification but no flag would otherwise mint a PASS
  claiming the tool ran clean. Reading it as a failure was rejected too: that would turn every
  such run with results into an execution failure, which main never did.
- Letting the clean candidate fold with a result that spells `sarif.run` on equal terms. The
  fold's primary is chosen by content order, so the clean run's title and fixed text could
  replace a real finding's in the report. Refusing the collision was rejected because a producer
  could then keep any clean run out of the store by naming the rule.
- Keying the repository into the context instead of the resource. The resource is the scope the
  run names, as it is for the image case, and results of that run already use the repository as
  their file resource prefix.
- Dropping INFO `run_clean` once the run mints. The note is what an operator sees on standard
  error, and keeping one code and one message keeps the guarded run's output unchanged.

## PR 2: the inventory and the coverage evidence

### 2026-10-15: an unverified empty run names its cause

Decision 1 leaves a run with no results under an unverified invocation as `run_clean` plus
`execution_unverified` plus, when nothing else yields, `no_observations`, which is the content
class. The recorded failure carried `no_observations` alone, so it never said why the log held
nothing. The SARIF adapter now raises ERROR `clean_run_unverified` beside `no_observations` when
the reading yields nothing and at least one run had no results under an unverified invocation.
It is a content code (ADR 0014, second amendment of 2026-10-15), the record's `failure.codes`
name both, and a run whose invocation failed never raises it. Raising it per run at the
`run_clean` site was rejected: a productive run beside an unverified empty run is a successful
reading, and it would have become a refused log.

### 2026-10-15: only the failure type is listed as a detection failure

The compiler handed every system observation to `_detection_failure`, which reads the
`artifact.*` and `failure.*` metadata only a detection-process record carries. With one system
source type the two were the same set; this slice adds others. The loop now selects
`complyroll.detection-process` observations alone, so a system observation of any other reserved
type compiles as an ordinary record and is never listed in `detectionFailures`. No output moves,
since no other system type exists yet; a regression test builds one.

### 2026-10-15: the inventory is a per-run report input

`--inventory FILE` on `report vdt`, `report avi` and `report historical` reads one
`complyroll.inventory` document through the bounded reader, on the stateless path and beside
`--db` alike. No store holds an inventory, so it is never a second source of truth, and it is
never stored. A second `--inventory` is refused, and a refused file stops the run before anything
is written, as a KEV catalog does. The five coverage rules are resolved only when an inventory is
given; a pinned dataset that lacks any of them stops that run with ERROR
`coverage_rule_unavailable`, which names each missing rule. Coverage is derived in the record
compiler from the observations both paths hand it, so the persisted report equals the stateless
one byte for byte. `x-complyroll.coverage` and the Markdown `## Coverage` section appear only
with an inventory, so every report compiled without one is unchanged. A resource type may not
hold a colon, so a `type:id` context key reads one way, and `sampleGroup` and `job` follow the
inventory name rule, so the identities later built from them stay inside the 512-character cap.
