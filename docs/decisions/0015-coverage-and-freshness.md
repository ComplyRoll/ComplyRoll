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

Decided 2026-10-15 while PR 2 was built, from the approved slice plan and the rulings made at
each build step. PR 2 adds a provider-supplied inventory as a per-run report input and an
`x-complyroll.coverage` block that says, for each declared resource and coverage rule, when a
detection process last examined and last verified it, which window applies, and whether a window
closed with nothing verified. It adds no event, no store change, and no case, and every existing
golden is byte-identical. Each decision ends with its reason.

### Decision 2 (2026-10-15): an unverified empty run names its cause

When a SARIF reading yields nothing and at least one of its runs had an empty `results` array
under an unverified invocation (Decision 1), the adapter raises ERROR `clean_run_unverified`
beside `no_observations`, once per log, in fixed text. It is a content code (ADR 0014, second
amendment of 2026-10-15), so the recorded failure's `failure.codes` name both, and a run whose
invocation failed never raises it.
Why: the record carried `no_observations` alone and never said why the log held nothing, and
raising the code per run at the `run_clean` site would have refused a productive log.

### Decision 3 (2026-10-15): only the failure type is listed as a detection failure

The compiler hands a system observation to `_detection_failure` only when its source type is
`complyroll.detection-process`. A system observation of any other reserved type compiles as an
ordinary record and is never listed in `detectionFailures`. No output moves, since no other
system type exists yet, and a regression test builds one.
Why: `_detection_failure` reads `artifact.*` and `failure.*` metadata that only a failure record
carries, and PR 3 adds a second system source type.

### Decision 4 (2026-10-15): the inventory is a per-run report input

`--inventory FILE` on `report vdt`, `report avi`, and `report historical` reads one inventory
through a bounded reader, on the stateless path and beside `--db` alike. The report names it by
the SHA-256 of its raw bytes, with its name, size, and entry count, and never holds the bytes. A
second `--inventory` is refused, and a refused file stops the run before anything is written.
Why: no store holds an inventory, so like the KEV catalog (ADR 0012 Decision 1) it is never a
second source of truth, and the digest lets an assessor check a report against the file.

### Decision 5 (2026-10-15): a native JSON format with strict field rules

The inventory is `complyroll.inventory` version 1; `docs/DATA_MODEL.md` lists its fields. The
reader refuses and never repairs. It refuses unknown keys at every level, any identifier outside
the adapters' identity rule (at most 512 characters, no control, format, surrogate, or
line-separator code point, not blank), a colon in any `resourceType`, and a `name`,
`sampleGroup`, or `job` that is not 1 to 128 printable ASCII characters with no leading or
trailing space. The file is capped by `MAX_INVENTORY_BYTES` (8 MiB) and `MAX_INVENTORY_RESOURCES`
(20,000), with no per-entry cap on aliases or verifications beyond the parser's value bound.
Identifiers are not trimmed, `resourceType` is an open, case-sensitive vocabulary, and a JSON
null reads as absent on every optional field. OSCAL `inventory-item` and workbook importers are
deferred.
Why: an inventory pair must name only what an observation can carry, the colon rule makes a
`type:id` context key read one way, and the name rule keeps `sample-group/<name>` and PR 3's
job-keyed identities inside the 512-character identity cap.

### Decision 6 (2026-10-15): `driftLikely` belongs to machine entries only

`driftLikely` is `true`, `false`, or `"unknown"`. It is required when `machineBased` is true and
refused when it is false, and `verifications` is refused on a machine entry, even as an empty
array. A non-machine entry carries `VDR-TFR-NMV` and, with a `sampleGroup`, `VDR-TFR-PSD`, and
nothing else.
Why: `VDR-TFR-PDD` and `VDR-TFR-PCD` are detection cadence rules, and an attested review of a
procedure is not detection, so it cannot anchor a drift clock.

### Decision 7 (2026-10-15): exact matching, and examined is not verified

An observation matches an entry by its exact resource type and id or by an exact alias. Nothing
is normalized, so a checklist named by its filename stem matches only through an alias. Only
ARTIFACT observations count. A matching one with a source time examines the resource, and it
verifies a machine entry only when its disposition is OPEN, PASS, or NOT_APPLICABLE; NOT_REVIEWED,
ERROR, and UNKNOWN examine without verifying. A non-machine entry is verified only by its attested
`verifications`, labeled attested, and artifact evidence against it examines and never verifies.
Untimed evidence is listed and never examines or anchors, and ingest time is never substituted.
CKL evidence is always untimed and a STIG Viewer 3.x CKLB export carries no clock at any level,
so checklist evidence from those tools never anchors a clock; the CKLB adapter's four root clock
keys serve only hand-built files.
Why: AGENTS.md forbids treating a scanner or STIG result as complete proof, so a run full of
errors must not satisfy `VDR-TFR-MVX`, and an invented instant would make the clock ComplyRoll's.

### Decision 8 (2026-10-15): clocks come from entry attributes and the pinned dataset

A machine entry carries `VDR-TFR-MVX`, plus `VDR-TFR-PCD` when `driftLikely` is false and
`VDR-TFR-PDD` otherwise. A non-machine entry carries `VDR-TFR-NMV`, and a `sampleGroup` adds
`VDR-TFR-PSD` for the group. `"unknown"` drift takes `VDR-TFR-PDD` and raises WARNING
`drift_likelihood_unknown` as a report diagnostic, once per entry, located at the inventory name
and the entry's pair. Every due date comes from `SelectedPolicy.coverage_deadline`, which
refuses a rule outside `COVERAGE_RULE_IDS` and otherwise returns `deadline_for_rule` unchanged.
Days are exact elapsed time, and month clocks run in the policy profile's calendar zone, the one
`--calendar-tz` sets. Force rides on every clock and window and is printed on every row, SHOULD
as well as MUST.
Why: no deadline lives in code, unknown drift takes the shorter window rather than none, and one
zone source means coverage clocks and the other deadlines cannot disagree.

### Decision 9 (2026-10-15): with an inventory, all five rules must resolve

The five coverage rules are resolved only when `--inventory` is given, never through
`required_rule_ids`. Then all five must resolve, used or not: a pinned dataset that lacks any of
them stops the run with ERROR `coverage_rule_unavailable`, which names every missing rule in one
note located at the inventory's name, in the `kev_rule_unavailable` shape.
Why: a run without an inventory must not depend on rules it never reads, and a run with one must
not print a thinner projection than the dataset defines.

### Decision 10 (2026-10-15): anchors, cutoff, and windows

A clock anchors on the latest verification at or before as-of, else on `expectedSince`, labeled
`declared`. An `expectedSince` after as-of leaves the clock `unanchored`, with no due date and no
window. Evidence observed after as-of is listed under `later` and never used. One verified
instant is one anchor, however many observations or identical attestations share it. A window
closes at a due date that passes with no verification, and the next window anchors on the next
actual verification, never on the missed due date, so a lapse is one window (ADR 0007 Decision
6). Overdue is strict: a due date equal to as-of has not passed. A verification before
`expectedSince` counts, but no window closes before `expectedSince`. A verification after
`decommissionedAt` is listed and never anchors, and a trailing window closes only when its due
date is at or before decommissioning.
Why: windows anchored on due dates would turn one lapse into a growing series, and evidence after
as-of or after decommissioning describes another moment.

### Decision 11 (2026-10-15): status precedence

Each clock takes the first status that applies: `unanchored` (`expectedSince` after as-of),
`missing` (never examined within the cutoff), `undetermined` (examined, never verified), `stale`
(verified at least once and the current window lapsed), else `current`. Four calls follow from
the order. A resource with only untimed evidence is `missing`, and both projections print the
untimed count beside that status, so a checklist-only host never reads as unexamined. `missing`
and `undetermined` hold inside the first window too. A resource verified only before
`expectedSince`, with a lapsed window, reads `stale`. A verified, decommissioned resource whose
due date falls after decommissioning stays `current` however late as-of is, since there is no
decommissioned status; the row carries `decommissionedAt`. A `current` status is not a
compliance finding, and the block's fixed basis text says so.
Why: each status claims only what the evidence shows, and the order puts the least evidence first.

### Decision 12 (2026-10-15): sample groups

A `sampleGroup` adds one `VDR-TFR-PSD` clock for the group, named `logical:sample-group/<name>`
and satisfied by any verified member. The member whose verification anchors it is named as the
stand-in, and on a tie the first member in inventory order stands in. The group clock runs from
its earliest member's `expectedSince` and stops only when every member is decommissioned, at the
latest member's instant. Members keep their own clocks, and the summary counts a group clock once.
Why: `VDR-CSO-SIR` makes sampling a MAY, so sampling must not hide a member, and counting a shared
clock per member would multiply one clock.

### Decision 13 (2026-10-15): unregistered and later evidence

An artifact observation that names no entry is counted under `unregistered` by its exact pair,
untimed or timed within the cutoff. One observed after as-of goes to `later` instead.
Why: a short inventory makes a clean page, so what the inventory omits has to show.

### Decision 14 (2026-10-15): the block and its Markdown twin

`x-complyroll.coverage` and a Markdown `## Coverage` section after Inputs appear only with an
inventory. AVI and historical carry the same block as VDT, never selected by a period, because
coverage is measured at as-of. Beside the plan's fields, `untimed` is a count with
`untimedEvidence` listed separately, evidence has one shape per kind and names the identity it
carried so an alias match shows, `standIn` is null except on a group's verification anchor,
every clock carries its `contextKey`, and resource rows carry `attested`, `expectedSince`, and
`aliases`. The basis text says `VDR-TFR-MVX` is read from detection results until Phase 3
validation runs exist. No official field holds coverage, and the parity test covers every row.
Why: a reader needs the anchor evidence and the stand-in to check a status by hand, and the
official schemas offer no slot for any of it.

### Decision 15 (2026-10-15): derived once, before the record loop

The record compiler derives coverage right after the KEV rule check and before the record loop,
from the same observations both paths hand it, as a pure function of those observations, the
inventory, the policy, and as-of.
Why: the persisted report then equals the stateless one byte for byte, and a missing rule stops
the run before any record error is collected, as the KEV rule refusal does.

### Decision 16 (2026-10-15): refusals exit 1

A second `--inventory` is `invalid_option`, a refused file is `invalid_input`, and a missing
coverage rule is `coverage_rule_unavailable`. Each exits 1 and writes nothing, superseding the
plan's exit 2.
Why: the CLI contract is 0 success, 1 failure, 3 recorded failures, and 2 only for an argparse
usage error, every KEV refusal already exits 1, and a dedicated code would be a contract change.

### Decision 17 (2026-10-15): two golden pairs

`tests/golden/vdt-coverage.{json,md}` is the `vdt-fixtures` run plus `examples/inventory.json`,
with official fields equal to `vdt-fixtures.json`. Every observation in that fixture set is
untimed checklist or OpenSCAP evidence, so no machine clock can anchor on it, as Decision 7
predicts. That pair shows missing with its untimed count, unanchored, attested current and stale,
an attested stand-in, decommissioning, an alias, and an unregistered resource. A second pair,
`tests/golden/vdt-coverage-timed.{json,md}`, runs `codeql-repo.sarif` and `clean-run.sarif`,
Class C, UTC, as of 2026-09-03T12:00:00Z, against the test fixture
`tests/fixtures/inventory-timed.json`. It shows machine current, stale, and undetermined, a
machine stand-in, and an alias over machine evidence, and a direct test pins those three
statuses so a golden refresh cannot flip one silently.
Why: one golden cannot keep the official fields of the published fixture run and also reach the
machine statuses.

### Decision 18 (2026-10-15): left out of this pull request

PR 3, the data-integrity path sized band L, carries a closed window as a `VDR-CSO-FAV` system
observation and case: `--record-coverage-gaps`, `cases coverage`, the `coverage.recorded` event
and stream kind, store schema 4, and their audits. Out of the slice: `VDR-TFR-MVF` (Rev5) and
Classes A and D, which no modeled profile selects; OSCAL and workbook inventories; moving
digest-keyed failure cases onto a `job`; and `results_unknown` beside productive runs.
Why: PR 2 changes no store and opens no case, so it merges on its own.
