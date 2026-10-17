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
`missing` (never examined within the cutoff), `undetermined` (examined, but no verification
anchors the clock at as-of), `stale` (a verification anchors it and the current window lapsed),
else `current`, so `stale` and `current` both need an anchoring verification. Four calls follow from
the order. A resource with only untimed evidence is `missing`, and both projections print the
untimed count beside that status, so a checklist-only host never reads as unexamined. `missing`
and `undetermined` hold inside the first window too. A resource verified only before
`expectedSince`, by a verification whose window closed before it, reads `undetermined` on a
`declared` anchor with no evidence, inside the declared window and after it lapses, as a resource
examined and never verified does; a verification whose window reaches `expectedSince` anchors the
clock, and a later verification resumes it. A decommissioned resource whose clock a verification
anchors, falling due after decommissioning, stays `current` however late as-of is, since there is no
decommissioned status; the row carries `decommissionedAt`. A `current` status is not a
compliance finding, and the block's fixed basis text says so.
Why: each status claims only what the evidence shows, and the order puts the least evidence first.

### Decision 12 (2026-10-15): sample groups

A `sampleGroup` adds one `VDR-TFR-PSD` clock for the group, named `logical:sample-group/<name>`
and satisfied by any verified member. The member whose verification anchors it is named as the
stand-in. On a tie the member with the least pair stands in: the inventory sorts entries by type,
then id, by code point, so file order never decides it. The group clock runs from
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
A decommissioned entry keeps its clocks, and the summary counts them at every later as-of, so one
never examined counts as `expected` and `missing` for good; whether retirement drops an entry from
`expected` is decided with the gap cases in PR 3.
Why: PR 2 changes no store and opens no case, so it merges on its own.

## PR 3: coverage gaps become cases

Decided 2026-10-16 while PR 3 was built, from the approved slice plan and the rulings made at
each build step; where a ruling replaced the plan, the ruling is what is recorded. PR 3 makes each
window that closed with no verification a `VDR-CSO-FAV` system observation and, once grouped, a
case: on the stateless path with `--record-coverage-gaps`, and in the store with `cases
coverage`, a fourth stream kind, the `coverage.recorded` event, and store schema 4. Every golden
cut before this section is byte-identical, and the new pairs are
`tests/golden/vdt-coverage-gaps.{json,md}` and `tests/golden/historical-coverage-gaps.{json,md}`.
Each decision ends with its reason.

### Decision 19 (2026-10-16): retirement keeps the entry and its status

Decision 18's open question is answered: retirement does not drop an entry from `expected`. A
decommissioned entry stays `expected` and keeps its status at every later as-of, and the row's
`decommissionedAt` is the reader's signal that it was retired. Decision 10 already closes no
window after decommissioning, so a retired entry opens no gap after its `decommissionedAt`. The
only gap a retired entry that was never examined can open is one whose window closed before it
was retired, and that is a real lapse.
Why: changing the count would move `vdt-coverage.json`, and the gap rule already keeps a retired
resource from opening a case it did not earn.

### Decision 20 (2026-10-16): one gap observation per closed window

`reports/gaps.py` builds one SYSTEM-origin observation for each window of the coverage result,
under the SYSTEM identity recipe of the ADR 0002 amendment: `source_type` `complyroll.coverage`,
`source_tool` `complyroll`, parser `complyroll.coverage` version 1, `source_record_id`
`coverage-gap`, the clock's subject as the resource (the entry's own pair, or
`logical:sample-group/<name>` for a group clock), the context key of Decision 21, and
`observed_at` the window close, never as-of or ingest time. Disposition is OPEN, severity
UNKNOWN, there are no source identifiers, and `evidence_ids` holds `sha256:<inventory digest>`.
The metadata always carries the same eight keys: `coverage.rule`, `coverage.force`,
`coverage.anchor`, `coverage.anchorAt`, `coverage.windowClosedAt`, `coverage.inventorySha256`,
`coverage.job` (empty when the entry names none), and `coverage.basis`. The anchor, force and
digest are metadata, so they never move the id. The title is `<rule> window for <type>:<id>
closed <instant> with no verification recorded (VDR-CSO-FAV)`, without the plan's "coverage gap:"
lead, because a case renders as `<record id>: <title>` and the record id already reads
`coverage-gap`. The description says ComplyRoll recorded no verification inside the window and
that this records the absence of a verification, not a vulnerability. A case that groups several
windows takes one member's title, as every grouped case does, and lists every resource and
observation id.
Why: the identity is fixed by the inputs, so a past period rebuilds to the same ids, and one key
set lets the audit check one shape.

### Decision 21 (2026-10-16): the context key names its form

The context key is `<rule>:job:<job>` when the window's entry names a job, and
`<rule>:resource:<type>:<id>` otherwise. A sample group reads
`<rule>:resource:logical:sample-group/<name>`, and its window never borrows a job, even from an
entry whose own pair spells the group. Correlation groups by source type, record id and context
key, so a gap case is one rule and one detection job, or one rule and one resource: ADR 0014
Decision 17's one case per failing detection process, applied to coverage. In
`examples/inventory.json` the `VDR-TFR-MVX` windows of `host:lab-win-01` and
`host:ubuntu-web-01`, both under the job `weekly-stig-checklist`, share one case, and the two
windows of the sample group share another. No report prints the context key; an evaluation
builds it from the window's rule and context and the entry's `job`.
Why: the plan's resource form `<rule>:<type>:<id>` let a job-less resource of type `job` spell an
entry's job and merge two cases under one evaluation triple, and the second segment now always
tells the forms apart.

### Decision 22 (2026-10-16): derived once, and a gap never verifies itself

On a flagged run the compiler derives coverage once from the artifact observations, adds one gap
observation per window to the observation list, and then groups and matches evaluations, so the
coverage block and the gaps come from one projection. `derive_coverage` reads only
ARTIFACT-origin observations as evidence, and a test holds it to that with a real gap, so a gap,
which names the entry as its resource and is observed at the window close, never anchors or
verifies the window it reports, on either path. A gap takes `ingested_at` from the report's as-of
on the stateless path and from `--as-of` on `cases coverage`, as a failure does, and that instant
reaches neither the output nor the id.
Why: a second derivation could disagree with the block beside it, and a gap read as evidence
would erase the window it reports.

### Decision 23 (2026-10-16): every reserved type needs the full triple

ADR 0014 Decision 10's refusal of an entry without `contextKey` now covers every source type under
the reserved `complyroll.` prefix, on the stateless path and in `cases evaluate`, in the same order
as before. The message names the record by its kind: "detection process failure" for
`complyroll.detection-process`, "coverage gap" for `complyroll.coverage`, and "system record" for a
reserved type with no name of its own. The failure's text is unchanged byte for byte where the entry
gives `sourceType`. A gap is matched by `{"sourceRecordId": "coverage-gap", "sourceType":
"complyroll.coverage", "contextKey": "<context key>"}`, and a lone gap matched without its key is
refused with `evaluation_context_key_required`: "... matches the coverage gap <tracking id>; a
coverage gap is matched by sourceRecordId, sourceType and contextKey together, so add contextKey".
The refusal also covers a lone match without `sourceType`, and its remedy names every key the entry
leaves out: "so add sourceType" for an entry that gives `contextKey`, and "so add contextKey and
sourceType" for one that gives neither.
Why: every gap shares the record id and the source type, so an entry that applies to one gap
today turns ambiguous once a second is recorded, as a failure's does, and an entry without the
source type would also select an artifact record of the same record id and context key.

### Decision 24 (2026-10-16): a gap is detected when its window closed

A gap record's detection time is the earliest window close of its case, with
`detectedAtSource` `system`, and its one deadline is `VER-TFR-EVU` from that close, through the
existing system branch; `--detected-at` never applies to it. The `evaluation_before_detection`
remedy for source `system` now depends on the record's source type. A gap's remedy reads "a
coverage gap is detected when its window closed, so evaluate it at or after that instant, or
correct completedAt", with no as-of remedy. The failure's remedy is unchanged, and a reserved
type with no remedy of its own takes the failure's. The compiler, `cases evaluate` and `store
verify` print one text, as ADR 0007's amendment of 2026-10-14 requires.
Why: a failure's instant depends on when it was recorded, but a gap's close is fixed by the
inputs on both paths, so moving `--as-of` cures nothing.

### Decision 25 (2026-10-16): one test holds every reserved type to its texts

Three branch points name a system record's kind: `system_record_kind`, the order remedies, and
the Markdown attestation sentence. A test walks every module of the package for a reserved
`*_SOURCE_TYPE` constant and holds each type to a kind name of its own, an order remedy naming
that kind, and an attestation sentence naming it once. The three tables were not merged.
Why: each branch point falls back to the failure's text for a type it does not know, so a third
type added to one table alone would read as a failure, and a merged table would still need the
test.

### Decision 26 (2026-10-16): a gap closes as a failure closes

A missed window is a permanent fact. A later verification does not erase it: the window shows
`resumedAt`, and the case closes only by a disposition from an evaluation matched on the full
triple, with `completedAt` at or after the window close. PAIN, reachability and exploitability
come only from that evaluation (ADR 0014 Decision 10). Any disposition the evaluations file
accepts applies to a gap as it applies to a failure, and `accepted` lists the gap in the
`VER-RPT-AVI` report as an accepted risk, which is what an accepted missed window is.
Why: restricting dispositions by record kind would be a domain decision of its own, outside this
slice, and parity keeps one rule for every system record.

### Decision 27 (2026-10-16): `--record-coverage-gaps` is the stateless opt-in

`report vdt`, `report avi` and `report historical` take `--record-coverage-gaps`, separate from
`--record-failed-imports`, because evidence and cases are different commitments. With it each
closed window becomes a gap observation, and its record compiles like any other. Without
`--inventory` the flag is refused before anything is read ("report vdt --record-coverage-gaps
needs --inventory: a coverage gap is a window of an inventory entry's clock"), and beside `--db`
it joins the standard source conflict, which runs first ("report vdt takes either --db or
--record-coverage-gaps, never both"). Both are `invalid_option`, exit 1, and write nothing.
`ReportOptions` refuses the flag without an inventory, and `compile_record_set_from_history`
refuses it outright, so a library caller cannot make it a silent no-op.
Why: a gap is a window of an inventory entry's clock, and a report never records a gap into a
store; what a store holds is what `cases coverage` recorded.

### Decision 28 (2026-10-16): the window keys appear only on gap-aware runs

On a gap-aware run every window of the coverage block gains `recorded` and `trackingId`: `true`
and the effective tracking id of the record that carries its gap, or `false` and null. The
Markdown Windows table gains Recorded and Tracking ID columns and opens with one fixed sentence:
"A recorded window is a VDR-CSO-FAV system record of this run and names its tracking ID here even
when this report does not select the record, such as one detected after the report period." A
stateless run is gap-aware with the flag, and a persisted run under Decision 37. Every other run
writes the PR 2 window dicts unchanged.
Why: the keys say whether the run could record a window, so a run that could not must not carry
them, and every golden cut before PR 3 keeps its bytes.

### Decision 29 (2026-10-16): two metadata fields and no extension key

`CompiledRecordSet` and `ReportMetadata` carry `coverage_gaps`, the sorted tracking ids of every
gap record in the set whether or not a period selects it, which the exit status reads, and
`coverage_gap_records`, each window mapped to its tracking id or to none, which the window keys
read. The two differ on the persisted path, where a stored gap no window derives is a record
with no window and an unrecorded window has no record. No `x-complyroll` key is added.
Why: every recorded gap's tracking id is already on its window, while `detectionFailures` exists
because a failed artifact is absent from the manifest.

### Decision 30 (2026-10-16): exit 3 widens per flag

Exit 3 now means the output holds a system-generated `VDR-CSO-FAV` record: a detection process
failure or a coverage gap. Each flag answers for its own kind: a run exits 3 when
`--record-failed-imports` recorded a failure or `--record-coverage-gaps` recorded a gap, and once
with both. The output is written first, and a publish that fails still exits 1. `cases coverage`
exits 3 when it recorded a gap and 0 when it recorded none. `report --db` keeps 0 and 1 when the
store holds gaps, because `cases coverage` signalled them. `EXIT_DETECTION_FAILURES` keeps its
name. A separate exit code for gaps (open decision 3, option b) is not built; it is decided with
the "CI-friendly exit criteria" deliverable.
Why: a gap is a failure of the detection process under the same rule, and the JSON tells a
failure from a gap.

### Decision 31 (2026-10-16): the period rule applies unchanged

ADR 0014 Decision 18 holds for gaps. A gap record detected after the report period ends is left
out of the official VDT with INFO `excluded_by_period`, and it still counts for exit 3, is listed
by the historical snapshot, and keeps `recorded: true` and its tracking id on its window. A late
window that joins an existing case keeps that case in the VDT, because the case was detected at
its first close: at as-of 2026-09-21T12:00:00Z the sample group's third window, closed
2026-09-05T17:00:00Z, joins `case-a971b430300440cf`, which was detected 2026-07-04.
Why: a rebuild of a past period must not list gaps that closed after it, and a case is detected
once.

### Decision 32 (2026-10-16): a coverage stream is named for its gap record

The persisted path adds a fourth stream kind, `coverage/<fingerprint>`, where the fingerprint is
the gap record's SYSTEM identity hash, 64 lowercase hex characters. A stream holds exactly one
`coverage.recorded` v1 head and then one `observation.recorded` carrying the gap record, appended
in one batch at version 0. The head has six required fields and admits no other: `rule` (one of
the five coverage rules), `contextKey`, `windowClosedAt`, `anchor` (`declared` or
`verification`), `anchorAt`, and `inventorySha256`. It carries no tracking id, resource or stream
id, which are pure functions of the record. At append the repository refuses a record that opens
its stream and a record that is not the gap record its stream names. This replaces the plan's
`coverage/<sha256(contextKey)>/<closedAt>`.
Why: gaps under one job share a context key by design, and entries never scanned since one
`expectedSince` close at one instant, so the plan's id gave two gaps one stream and the second
could never be recorded; the fingerprint also keeps inventory identifiers out of stream ids.

### Decision 33 (2026-10-16): a store that records a gap is schema 4

`SUPPORTED_SCHEMA_VERSION` is 4. A coverage stream append needs schema 4, so the first one marks
the store inside its own transaction, as schemas 2 and 3 are marked, and a rollback undoes the
marker with the stream. The marking is the existing linear one: it inserts every missing
migration record up to 4, so a store that never held a failure carries records 2 ("failure
streams, ADR 0014") and 3 ("held failures, ADR 0014 amendment 2026-10-13") beside 4 ("coverage
gaps, ADR 0015") with neither kind present. No schema object changes. A store that never records
a gap stays at its version and readable by older builds, and a build that supports only schema 3
refuses a schema 4 store at open with "database schema 4 is newer than supported schema 3".
Why: a build that cannot read coverage streams must refuse the store rather than misread it, and
the existing marking already took a schema 1 store through to 3.

### Decision 34 (2026-10-16): five audits, and the reader refuses the four that name damage

`store verify` gains five codes in `AUDIT_FAULT_CODES`: `coverage_incomplete` (a stream missing its
head or its record), `coverage_overfull` (a second head or record), `coverage_stream_mismatch` (a
stream id that names no fingerprint, a record that is another stream's gap record, or a record ahead
of its head), `coverage_identity_breach`, and `coverage_schema_unmarked` (a coverage stream in a
store below schema 4, reported once). The identity check is wider than the plan's metadata keys,
origin and source type: it also holds the record id, the tool, the parser and its version, the
derived observation id, the disposition `open`, the source severity `unknown`, no source
identifiers, the one evidence id `sha256:<coverage.inventorySha256>`, `coverage.windowClosedAt`
against `observed_at`, `coverage.rule` against the context key's lead, and the head's six fields
against the record. A gap record that names an artifact digest or name is refused before that check,
as `payload_contract_invalid`, by the observation contract, which holds every system record to empty
artifact fields. `coverage_schema_unmarked` is content-neutral, as `failure_schema_unmarked` is: no
reader refuses it, and the evaluation order check still runs beside it. `_read_coverage_streams`
raises on each damaged shape the other four codes name, and on an event no coverage stream carries,
which `store verify` reports as `event_stream_mismatch`, each with the audit's text, so a report
from the store refuses a damaged coverage stream as `history_invalid` and names the fault
`store verify` names.
Why: each extra check restates the record's own identity or a field its builder fixes, which the
fingerprint alone cannot see, and one text per fault keeps the reader and the audit from drifting
apart.

### Decision 35 (2026-10-16): `cases coverage` records each gap once

`cases coverage --db STORE --inventory FILE --class B|C --as-of T [--calendar-tz NAME] [--actor
NAME]` derives coverage from the store's rehydrated observations through the report's own
`derive_report_coverage`, with the same bundled rules and the same `coverage_rule_unavailable`
refusal, and appends one coverage stream per derived window the store lacks, every stream in one
transaction. `--as-of` is required and `--calendar-tz` defaults to UTC. The stream id is the
idempotence key: a whole stream is skipped and printed as `already_recorded`, so the same inputs
append nothing and exit 0. The first recorded payload stands: after an edited inventory the
stored gap keeps its `coverage.inventorySha256` while the report's coverage block names the new
digest. A stream that is not whole, or that holds an event no coverage stream carries, is refused
rather than resumed, and every stream is judged before the first append, so a refusal writes
nothing. The derivation's warnings go to standard error, as a report prints them.
Why: a window closes against an as-of, so a default of now would make two runs over one store
disagree; history is append-only, so a recorded gap keeps the payload of the run that recorded
it, as a failure keeps its first `artifact.name`; and a half-written stream means something
other than this writer touched it.

### Decision 36 (2026-10-16): a recorded gap becomes a case after `cases correlate`

`cases coverage` records evidence, as `ingest` does, and opens no case. `rehydrate_observations`
appends each coverage stream's gap record in stream-open order, and no rule supersedes a gap, so
every coverage stream is current. A report from the store groups the recorded gaps at once, as it
groups every open observation, while `cases list`, `cases history` and `cases evaluate` reach a
gap only through the case stream `cases correlate` opens; before then an evaluation of the gap is
refused with `evaluation_unmatched`, "no case matches". The documented order is `ingest`, `cases
correlate`, `cases attest-detection`, `cases evaluate`, `cases coverage`, `cases correlate`, then
`cases evaluate` again for the gaps' entries, and the report.
Why: correlation is the one writer that opens cases, for gaps as for every other observation.

### Decision 37 (2026-10-16): persisted gap awareness is schema 4 plus an inventory

A report from a store is gap-aware when the store is marked schema 4 and the run has an
inventory. It maps each derived window to a stored gap by rebuilding the window's gap observation
and comparing ids, which never depend on the ingest time. The marker decides, not the presence of
a coverage stream: through the repository the two agree, and a store marked 4 by hand with no
coverage stream reads gap-aware with every window unrecorded. Without an inventory there is no
coverage block, and the stored gaps still report as records. This narrows the plan's divergence
1: a store that never ran `cases coverage` reads exactly like the stateless run without the flag,
with no window keys and no `coverage_gap_unrecorded` notes.
Why: the PR 2 replay goldens, compiled from stores that never recorded a gap, keep their bytes.

### Decision 38 (2026-10-16): three notes name where history and the run disagree

A gap-aware persisted run can disagree with its store in three ways, each an INFO note in JSON
and Markdown. `coverage_gap_unrecorded`, located at `<inventory name> <type>:<id>`, is a derived
window with no stored gap: no case carries it, and `cases coverage` with the run's inventory,
as-of, class and calendar zone records it. `coverage_gap_contradicted`, located at `coverage-gap`,
is a stored gap no derived window matches with a verification inside its own `(anchorAt,
windowClosedAt]`, as a late upload leaves; the note names the earliest such evidence.
`coverage_gap_unmatched`, located at `coverage-gap`, is a stored gap no derived window matches
with no verification inside it, so the run's inventory, as-of, class or calendar zone may differ
from the run that recorded it. The case stays in the report in both of the last two. This
replaces the plan's single `coverage_gap_contradicted`.
Why: an operator or a pipeline must tell "evidence disproves this" from "this run's inputs
differ" without parsing a message, and only the first has a disposition that answers it.

### Decision 39 (2026-10-16): a false positive is advised only for a whole case

A disposition answers a case, and a case per rule and job, or per sample group, can carry several
windows, so each underived gap's note is read against the other recorded gaps of its case. A
sibling stands when this run still derives it or when it is unmatched; a contradicted sibling
never stands. A contradicted note advises a false-positive disposition only when no sibling
stands, and otherwise names each standing gap with why it stands and says the case stays open
until every other gap it carries is contradicted or disposed on its own merits. An unmatched note
names the standing siblings too and never advises.
Why: a false positive prompted by one disproved window would also close a sibling window that
nothing disproves.

### Decision 40 (2026-10-16): a stored gap's window comes from its own record

The contradicted check takes the window from the stored record, its `coverage.anchorAt` and its
observed instant, which the reader holds to its head, and files evidence exactly as the derivation
files it, by the run's as-of: a sample-group clock is verified by any member and every other clock
by the entry that names it, by id or by alias, and evidence after the run's as-of is never named. An
alias names the same resource, so a gap recorded before its resource was renamed, with the old id
kept as an alias, is read against the renamed entry's evidence.
Why: the window disproved must be the one that was recorded, not one this run would derive.

### Left for later (2026-10-16)

- A value check that `coverage.anchorAt` precedes `coverage.windowClosedAt`. The audit holds
  `coverage.force`, `coverage.job` and `coverage.basis` to presence only, since no report renders
  them from a stored record, and a stored `anchorAt` after the close gives an empty window, so
  that gap reads unmatched rather than failing.
- A registry of report diagnostic codes, with a test that every emitted code is in it, as
  `AUDIT_FAULT_CODES` is for `store verify`. The three INFO codes above are pinned by tests alone.
- Formatter debt: seventeen legacy files were not `ruff format` clean before this slice, and none
  was reformatted here.
- A separate exit code for gaps, open decision 3 option b, decided with the CI exit criteria
  deliverable (Decision 30).
- Decision 10's first sentence does not say that a verification before `expectedSince` anchors a
  clock only when its window reaches `expectedSince`. Decision 11 states it, and so does
  `docs/FEDRAMP_2026_MAPPING.md` from this date.

## Amendment (2026-10-17): an explicit true is necessary for a clean run, not sufficient

Found in a review of the SARIF slice against main. Decision 1 minted a clean run whenever every
invocation a run declares carries `executionSuccessful: true`. The same log can contradict the
flag: an invocation with a nonzero `exitCode` or an exit signal, or with an `error`-level entry in
`toolExecutionNotifications` or `toolConfigurationNotifications` ("rule pack failed to load"); a
`conversion.invocation` (the converter's own run, SARIF 3.22) that does not declare a clean
execution; and results that may live outside the run, under `externalPropertyFileReferences` or
the log's `inlineExternalProperties`, which ADR 0011 Decision 13 already says are never read. Each
minted a PASS that PR 2 read as a verification of a scope nobody had examined, which is the
failure the domain invariants forbid most: a failed detection process read as a clean one.

A run with no results and any of those signals now mints nothing. It raises one WARNING naming
the first cause found, in this order: `execution_errors_reported`, `conversion_unverified`,
`results_external`; each is a code of its own because a coalesced code keeps only its first
message. It then behaves exactly as an unverified empty run does under Decision 1: when nothing
else in the log yields, `no_observations` and `clean_run_unverified` (Decision 2), which is the
content class with `--record-failed-imports` and fatal without it. A failed invocation still
claims the run first, and a missing or non-boolean flag is still `execution_unverified`. An
`exitCode` counts only when it is absent or the JSON integer 0, and a notification only when its
level is exactly `error`, since an absent level defaults to `warning`. The log-level
`inlineExternalProperties` member is now WARNING `inline_external_properties_ignored`; before,
any results inside it were dropped with no diagnostic at all. `clean_run_unverified` now reads
"SARIF log has a run with no results that cannot be verified as clean, which is not a clean run",
because its old text named an invocation that the external-results cause does not involve.

A run that has results is read exactly as before, whatever these signals say, and no golden moves:
no fixture's empty run carries any of them. Some bytes that minted a clean run now mint nothing,
so this parser reads them differently under the same `SARIF_PARSER_VERSION`, `1`, as PR #25 and
PR 1 of this record already did. ADR 0002 makes the parser version an identity input precisely
so that a changed reading is a new fact. No released build carries the SARIF adapter (0.3.0a0
predates it), so only a store built from main since 2026-09-22 can hold an older reading; bumping
the version is left for a decision before the first release that ships SARIF. Meanwhile the ingest
writer refuses, as `history_invalid`, to resume an artifact stream whose head declared another
observation count than this parser reads from the same bytes. It used to append the difference,
and the stream then held more observations than its head declared, so every later rebuild
refused the store as `artifact_overfull`.
Why: a clean run is coverage evidence, so it must fail closed on any signal in the log that the
run did not complete, not on the one flag alone.
