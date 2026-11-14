# ADR 0018: Change-triggered detection

- Status: Accepted
- Date: 2026-11-09

## Context

The pinned rules dataset has one rule about detection after a change. `VDR-CSO-DAC`, Detect After
Changes, force SHOULD: "Providers SHOULD automatically perform vulnerability detection on
representative samples of new or significantly changed information resources." It carries no
timeframe, so the dataset gives this slice no window. `VDR-CSO-AKE`, Avoid KEVs, force SHOULD NOT:
"Providers SHOULD NOT deploy or otherwise activate new machine-based information resources with
Known Exploited Vulnerabilities." It carries no timeframe either. Two Key Security Indicators sit
beside them and neither is a clock source: `KSI-CMT-LMC`, Logging Changes, "Modifications to the
cloud service offering are logged and monitored.", and `KSI-CMT-VTD`, Validating Throughout
Deployment, "Persistent testing and validation of changes throughout deployment is automated."

`docs/BUILD_PLAN.md` Phase 2 carries the deliverables "Git/deployment change-event ingestion" and
"Change-triggered detection jobs", and the exit criterion "New or significantly changed resources
can trigger a scoped detection request". ADR 0014 built the system observation for a detection
process failure. ADR 0015 built the provider-supplied inventory, its bounded reader, the
projection derived once from the evidence, and the closed window as a reviewable record. This
slice reuses each of those shapes rather than inventing a second one.

The slice ships as three pull requests, each mergeable on its own, and this record grows with them
as ADR 0015 did: one dated section per pull request, appended below the decisions it adds, so the
status line and the sections above it stay as written. This first section is the change contract
and the stateless projection. Changes in the store and unmet windows as cases are later sections,
and their decisions are not recorded until they are built. Decision numbers follow the approved
plan, so 10 through 13 belong to those later sections and Decision 14 lands here.

## Decision 1: a scoped detection request is a document ComplyRoll writes, not a job it runs

ComplyRoll runs no scanner and fetches nothing. A request is therefore three things it can do
locally: record the change as a provider-stated fact, project for each resource the change touched
whether detection reached it at or after the change, and write the resources still waiting as a
document a pipeline consumes.

The document is `complyroll.detection-request` version 1, written by `changes pending` (Decision
9). It lists only the resources that still need detection: per change, the `changeId`, `kind`,
`occurredAt`, `detectBy`, the `job` the provider expects to act and the `source`, and for each
waiting resource its `resourceType`, `resourceId`, inventory `aliases`, `sampleGroup` and `status`.
A resource that is `detected` is left out of the request and listed in the report block instead.
So is a row whose entry or group is decommissioned at or before as-of, whatever its status: no scan
can clear it, so it is not waiting, and it leaves the request and its counts. It stays in the block
with its status, as `lapsed` where the window closed first, so the closed window stays a recorded
fact. A change with no waiting resource has no request entry.

The document also carries `schema`, `schemaVersion`, `rule`, `force`, `provenance` (the pinned
rules source the force was read from, in the block's shape), `asOf`, `input`, `inventorySha256`
and `summary`. `summary.pending` counts every waiting row, whatever its status, and
`summary.byStatus` gives the split across `lapsed`, `undetermined` and `pending`.

Why: the pipeline that owns the scanner needs the resource names and nothing else, and the report
block already carries the evidence trail an assessor reads.

## Decision 2: a native change contract first, no source adapter

The input is a JSON document of ComplyRoll's own, `complyroll.changes` version 1, read by a bounded
reader that refuses and never repairs, as the inventory is (ADR 0015 Decision 5), with one
exception: `rationale` goes through `diagnostic_text`, which removes control and invisible format
characters other than tab and newline. No adapter for
git, Terraform, Kubernetes or a deployment record ships. The README carries one shell recipe that
writes the contract from `git log --format` for a repository whose commits name their resources,
as a worked example and not a parser. Every input is untrusted and bounded, and every fixture is
synthetic.

Top level: `schema` (`complyroll.changes`, checked first), `schemaVersion` (the JSON integer 1),
`name` (the name rule), `changes` (an array of at most `MAX_CHANGES`, 20,000, entries). The file is
capped by `MAX_CHANGES_BYTES` (8 MiB) through the bounded reader at depth 16 and the standard value
bound.

| Change field | Rule |
|---|---|
| `changeId` | Required, the name rule (1 to 128 printable ASCII, no edge space), unique in the file |
| `kind` | Required, `created` or `modified` |
| `occurredAt` | Required instant, the inventory's instant rule |
| `source` | Required object: `tool` (name rule) and `reference` (identity text, at most 512), such as a commit id, a deployment id, a ticket |
| `resources` | Required array of 1 to `MAX_CHANGE_RESOURCES` (1,000) `resourceType` and `resourceId` pairs, identity text, no colon in the type, no repeated pair; `resourceType` `package` refused as the inventory refuses it |
| `significant` | Required JSON boolean, on a `created` change too |
| `rationale` | Required, 1 to 512 printable characters through `diagnostic_text`; why the provider calls the change significant or not |
| `detectBy` | Optional instant, not before `occurredAt`; the provider's window for detection after this change |
| `job` | Optional, the name rule; the detection process expected to reach the resources |

Unknown keys are refused at every level, and a JSON null reads as absent on every optional field.
`kind` is a closed vocabulary because the two kinds are what the rule names ("new or significantly
changed"); retirement is the inventory's `decommissionedAt`, not a change. The file's identity is
the SHA-256 of its raw bytes, taken before a BOM is stripped. Changes sort by `occurredAt`, then
`changeId`, and each change's resources by pair, so file order never reaches an output. The reader
imports the inventory's field readers rather than copying them, so the two contracts cannot drift.

Why: an operator input must name only what an observation can carry, and the contract has to be
stable before any adapter can target it. The first source worth an adapter is a design-partner
call.

## Decision 3: a change names inventory entries; an unregistered resource is listed, not refused

A change's resource matches an inventory entry by its exact pair or by an exact alias, as evidence
does (ADR 0015 Decision 7). Nothing is normalized. The pair `logical:sample-group/<name>` names a
sample group only when no entry or alias spells that pair and at least one entry carries
`sampleGroup` `<name>`. An entry that spells the pair is an entry and wins, as ADR 0015 Decision 21
allows, and a group name no entry carries is unregistered like any other pair.

Two spellings of one entry in one change are one obligation: a change naming an entry's pair and
its alias makes one row, keyed by the entry, with the first spelling in sort order as `matchedAs`.
A change naming a group and one of its members stays two rows (Decision 4).

A resource no entry names gets one obligation row with status `unregistered` per (change,
resource), and its pair is listed once under `unregistered` with the change ids that named it. It
raises WARNING `change_resource_unregistered` once per pair, at the first change naming it, located
at `<changes name> <changeId> <type>:<id>`, and it opens no obligation: a clock belongs to an
inventory entry, and ComplyRoll will not invent an entry from a change. The remedy in the message
is to add the resource to the inventory, with `expectedSince` at or before `occurredAt` for a
`created` change. `--changes` without `--inventory` is refused before anything is read
(`invalid_option`, exit 1).

Why: the inventory is the one authority for what detection is expected to reach, and a new
resource the inventory lacks is exactly the signal `VDR-CSO-DAC` exists for, so it must show loudly
rather than be dropped or refused.

## Decision 4: the provider states significance and the sample; ComplyRoll records both

No significance score is derived. `significant` and `rationale` are copied into the block, the
rationale as the reader cleaned it, and only a change that is `created`, or `modified` with
`significant: true`, opens an
obligation on each resource it names. A `modified` change with `significant: false` is recorded and
listed with status `logged`, and never opens one.

The representative sample is whatever the provider names. A change that names one member of a
sample group obliges that member. A change that names the group itself is one obligation satisfied
by any verified member, with the stand-in named, as the `VDR-TFR-PSD` clock works (ADR 0015
Decision 12). ComplyRoll never widens a member change to its group or narrows a group change to one
member.

Why: the PAIN rule in `AGENTS.md` forbids deriving a judgment from a single field, and "significant"
and "representative" are the provider's judgments under a SHOULD. Recording the rationale beside
the claim is what lets an assessor check it.

## Decision 5: a verification at or after the change satisfies it; the window is provider-set

An obligation is `(change, resource)`. It is satisfied by the first verification of that resource
observed at or after `occurredAt` and at or before as-of, in ADR 0015 Decision 7's sense: an
ARTIFACT observation with a source time whose disposition is OPEN, PASS or NOT_APPLICABLE for a
machine entry, or an attested `verifications` entry with `at` at or after `occurredAt` for a
non-machine entry. Evidence before `occurredAt` never counts, however recent. Evidence after as-of
is never used, and untimed evidence is counted and never satisfies. A CycloneDX scope observation
satisfies only when it is PASS (ADR 0015 amendment 2026-10-19).

The window is the provider's. `detectBy` is the due date when the change carries one, and the
pinned dataset gives `VDR-CSO-DAC` no timeframe, so no deadline is read from it and none is
hardcoded. Without `detectBy` the obligation has no due date: it stays open, prints its age, and
never lapses. With `detectBy`, a window that passes before the first satisfying verification, or
with none at all, is closed. Overdue is strict, as it is for coverage: a `detectBy` equal to as-of
has not passed. A verification after the window closed still satisfies: the row reads `detected`
with `late: true`, `windowClosedAt` and `resumedAt`, and the resource leaves the request document
because the pipeline has already reached it. Force is read from the pinned dataset through
`policy.rule` and printed on every row. A dataset that lacks `VDR-CSO-DAC` refuses the run with
ERROR `change_rule_unavailable`, as `coverage_rule_unavailable` does.

The entry's lifecycle bounds the obligation the way it bounds a coverage clock (ADR 0015 Decisions
10 and 19):

- A change whose `occurredAt` is after as-of is listed under `later` with its resources and nothing
  else: no row, no summary count, no warning, no request entry. An AVI or historical run at a past
  as-of never carries a future change in its rows, summary, request or gaps; only the block's
  `later` list names it.
- A decommission counts only at or before as-of. A decommission after as-of has not happened at
  as-of, so the obligation runs on.
- A change on an entry whose `decommissionedAt` is before `occurredAt` reads `retired`, opens
  nothing, and raises WARNING `change_after_decommission` once per obligation.
- An entry decommissioned at or after `occurredAt` and before `detectBy` closes no window: the
  obligation reads `retired`. With no `detectBy` the window is open, so the same entry reads
  `retired` with no warning, since a request must not ask a pipeline to scan a retired resource
  forever. A window whose `detectBy` is at or before `decommissionedAt` closes as usual.
- A change on an entry whose `expectedSince` is after `occurredAt` runs from `occurredAt` as the
  provider stated it and raises WARNING `change_precedes_expected_since`. The warning fires only on
  a row that opens an obligation, never on `logged`, `retired` or `unregistered`, and a group is
  compared by its earliest member `expectedSince`.

The coverage clocks are untouched. A `created` change and a new inventory entry overlap on purpose:
the entry's `expectedSince` opens the recurrence clocks, and the change opens the sharper,
provider-windowed obligation under a different rule. The block's fixed basis text says so.

Why: `AGENTS.md` forbids a hardcoded deadline only where the dataset can supply one, and here it
cannot. A window the provider sets with a rationale is a claim an assessor can check, and an
invented one would be ComplyRoll's.

## Decision 6: status precedence per obligation

Each obligation takes the first status that applies, where `T` is `occurredAt`, `D` is `detectBy`,
`X` is the entry's or group's decommission instant, considered only at or before as-of, and `V` is
the first satisfying verification:

| Order | Condition | Status |
|---|---|---|
| 1 | no entry and no group | `unregistered` |
| 2 | `X` before `T` | `retired`, WARNING `change_after_decommission` |
| 3 | `X` at or after `T`, and `D` absent or `X` before `D` | `retired` |
| 4 | a `modified` change with `significant: false` | `logged` |
| 5 | `V` exists | `detected`; `late`, `windowClosedAt` and `resumedAt` when `V` is after `D` |
| 6 | `D` before as-of | `lapsed`, with `windowClosedAt` |
| 7 | anything examined at or after `T` | `undetermined` |
| 8 | otherwise | `pending` |

`retired` stands before `detected`, and a `retired` row still carries the first satisfying
verification when one exists, so no fact is lost. A `detected` row names the evidence, the stand-in
for a group and the lag from `occurredAt`. The request document carries exactly the `lapsed`,
`undetermined` and `pending` rows, less the rows of a resource decommissioned at or before as-of
(Decision 1, which outranks "exactly" here). A `detected` status is not a compliance finding, and
the basis text says so.

Why: each status claims only what the evidence shows. A late verification is still detection, so
the request stops asking for it, while the closed window it missed stays a recorded fact.

## Decision 7: the block, the Markdown twin, and parity with the request

`x-complyroll.changes` and a Markdown `## Changes` section after `## Coverage` appear only with
`--changes`. The block's `input` names the change file by `name`, `sizeBytes`, `sha256` and
`changeCount`, never its bytes, and the request document carries the same object. The block also
carries the rule, its force and rules provenance, `asOf`, the inventory digest, a summary with a
count per status, one row per change at or before as-of, one row per obligation, the `unregistered`
and `later` lists, and fixed basis text. AVI and historical carry the same block, measured at as-of
and never selected by a period. The request document is derived from the same obligation rows, so
a parity test holds every `pending`, `undetermined` and `lapsed` row to one request entry and every
other row to none, with the one exclusion Decision 1 names. No official field holds any of it.

Why: an assessor needs the evidence that closed each obligation, and the pipeline needs only the
open ones. One derivation feeding both keeps them from disagreeing.

## Decision 8: `VDR-CSO-AKE` is a diagnostic, not a case

ADR 0012 Decision 10 left `VDR-CSO-AKE` out of scope. This slice adds a diagnostic and a row flag,
nothing more. When the satisfying verification of a `created` change's machine-based resource is an
observation whose artifact (the same digest) also carries an OPEN finding on that resource that the
KEV enrichment (ADR 0012) marks as a Known Exploited Vulnerability with a catalog `dateAdded` at or
before `occurredAt`, the block's row gains `kevAtActivation: true` with the tracking ids, and
WARNING `kev_at_activation` names the change and the resource, once per obligation. A CVE that
joined the catalog after the change was not a KEV at activation and is not flagged.

`kevAtActivation` is `null` unless the question applies: `--kev` given, a `created` change, a
machine-based entry, status `detected`. A finding is in scope when it sits on the entry, and a
CycloneDX vulnerability row sits on a `package` resource, so a BOM's own KEV would otherwise read as
if the image it verified had none. When the satisfying verification is a CycloneDX scope
observation, the OPEN rows of that same artifact digest whose source type is CycloneDX and whose
resource is a `package` count as findings on the verified entry.

Where the question applies, every artifact holding a verification at the first satisfying instant
answers together, with no tie-break, since several can verify at one instant:

- `true` when any of them carries a finding in scope the catalog listed on or before `occurredAt`'s
  UTC date. A stale catalog can still say `true`. `kevTrackingIds` is the sorted union across them,
  each id as its record publishes it, so an evaluation's override reaches the row. The block is not
  selected by a period (Decision 7), so that record can fall outside one report's selection.
- `false` only when none says `true`, at least one carries an OPEN CVE-bearing finding in scope, no
  finding in scope may have lost a CVE from its identifier list, and the catalog's release date is
  on or after `occurredAt`'s UTC date.
- `null` otherwise. A clean run shows no CVE to check (ADR 0015: a clean run is never proof the
  scope is free of vulnerabilities), a cut identifier list may hide one, and a catalog older than
  the change cannot show what was listed at the change.

`false` says only that the findings these artifacts carried were not listed. It is no claim that
the resource carries no KEV.

Why: the KEV finding is already a record with its own `VDR-TFR-KEV` clock, and a second case for the
same finding would double it. The diagnostic makes the activation visible without a new record type.

## Decision 9: commands and flags

- `report vdt|avi|historical --changes FILE` reads one change file beside `--inventory`. A second
  `--changes` is `invalid_option`, a refused file is `invalid_input`, and both exit 1 and write
  nothing (ADR 0015 Decision 16).
- `changes pending ARTIFACT... --changes FILE --inventory FILE --class B|C --as-of T [--calendar-tz
  NAME] [--kev FILE] [--record-failed-imports] [--output PATH]` writes the request document to
  standard output or `--output`. It takes the same artifact positionals as `report`, because the
  obligations are read against the same evidence, and it refuses what `report` refuses about reading
  those artifacts. It builds no record, so a refusal about one, such as `detection_time_missing`,
  does not apply. It runs no coverage clock, so a dataset that lacks a coverage rule does not stop
  it.
  `--record-failed-imports` has its `report` meaning: a mintable failure is noted on standard error
  and the run continues, and without the flag a failed reading exits 1 and writes nothing. It takes
  no `--evaluations` or `--detected-at`, since neither moves a source time and so neither moves a
  status, and no `--package-uri`, since a request has no use for one; an internal placeholder fills
  the option and reaches no output. It exits 0 whether or not anything is waiting, including when a
  failure was noted: `summary.pending` is the signal, and a dedicated exit code would change the
  ADR 0017 contract for a document that is not a recorded failure.
- `--changes` beside `--db` is refused by the standard source conflict ("report vdt takes either
  --db or --changes, never both"). A compile from history refuses a change set passed through the
  library for the same reason, because the store never read that file and a block built there
  would name an input the history does not hold.

Why: each flag answers for its own kind of record, and the command names follow `cases coverage`.

## Decision 14: the grouping criterion is marked Met

`docs/BUILD_PLAN.md` gains "**Met, 2026-11-09** (shipped since ADR 0001: correlation keeps every
distinct affected resource of a group, `correlation/__init__.py`, pinned by
`tests/test_correlation.py`)" on the exit criterion "A case can group equivalent observations while
retaining every affected resource", with no code change.

Why: the criterion has been true since Phase 1, and the mark records the check rather than letting
the line read as open work.

## Rejected alternatives

- A significance score derived from the change. The significance of a change is the provider's
  judgment under a SHOULD, and `AGENTS.md` forbids deriving a judgment from a single field.
- An adapter per source first. Each adapter would carry its own copy of the rules, and the contract
  has to stand before any adapter can target it.
- Refusing an unregistered resource. A resource the inventory lacks is the signal the rule exists
  for, so one bad pair must not stop the run or hide the rest of the file.
- Borrowing the entry's drift clock (`VDR-TFR-PDD` or `VDR-TFR-PCD`) as the window. That hardcodes a
  reading of a rule that names no timeframe.
- A request as a store event. A request is a projection of the changes and the evidence at as-of,
  so storing it would record a second copy that can disagree with its own inputs.
- A new exit code for a waiting resource. The ADR 0017 contract is one table, and a document that
  is not a recorded failure does not belong on it.
- A `VDR-CSO-AKE` case. The KEV finding is already a reviewable record with its own clock.
- One case per resource when a window closes. The request is scoped by the change, so a later
  section keeps the case at that scope with every resource listed on it.

## PR 2: recorded changes (2026-11-12)

`changes record` appends each declared change as history, and `report --db` and `changes pending
--db` derive the same projection from what the store holds. This section adds Decision 9's PR 2
commands, Decision 10, and the compatibility items of Decision 13. The rest of Decision 13 and
Decisions 11 and 12 belong to the section that makes an unmet window a case.

### Decision 9, continued (2026-11-12): the commands of recorded changes

- `changes record --db STORE --changes FILE [--as-of T] [--actor NAME]` appends each change the
  store lacks, one stream per change, in one transaction. A second `--changes` is `invalid_option`,
  a missing store is `store_missing`, and it exits 0 or 1. `--as-of` defaults to the current second
  and is recorded as `recordedAt`.
- `report vdt|avi|historical --db STORE --inventory FILE` prints the block when the store holds at
  least one change stream. Without `--inventory` there is no block and no refusal, as for coverage,
  and the change streams are not read. `--changes` beside `--db` stays refused: a compile from a
  store never reads a change file, so a block built from one would claim an input the history does
  not hold, which is the refusal PR 1 recorded in Decision 9.
- `changes pending --db STORE --inventory FILE --class B|C --as-of T [--calendar-tz NAME] [--kev
  FILE] [-o FILE]` writes the request from the store. It refuses artifacts, `--changes` and
  `--record-failed-imports` in the wording `report` uses, needs `--inventory`, and with no change
  stream writes an empty request and exits 0, because a store that recorded nothing has nothing
  waiting. That holds on a dataset lacking `VDR-CSO-DAC` too: Decision 5's
  `change_rule_unavailable` applies to a store holding changes, in a message that says so, and an
  empty request read against no rule carries `force` null. `changes pending` without artifacts or
  `--db` is now `invalid_option` with exit 1, as `report` is, instead of an argparse usage error.

Why: each path needs an inventory because no store holds one, by ADR 0015 Decision 4, and each
refusal says what the store already answers for.

### Decision 10 (2026-11-12): a change is a fifth stream kind behind schema 5

A recorded change is the stream `change/<sha256(changeId)>` holding exactly one `change.recorded`
v1 event and nothing else. The payload carries every contract field as the bounded reader read it,
`recordedAt`, `changesSha256` and `changesName`. Keeping the file's `name` is what lets a stored
change's diagnostics be located where the stateless path locates them.

The change id is the idempotence key. Contract fields are compared as read, field by field in the
contract's order, and `change_conflict` names the first that differs: `kind`, `occurredAt`,
`source`, `resources`, `significant`, `rationale`, `detectBy`, `job`. So a file spelling the same
instant with another offset is `already_recorded`, and `recordedAt`, `changesSha256` and
`changesName` may differ, which lets a file that grows, or is renamed, re-record cleanly. The same
id with a differing contract field is refused before any append, because history is append-only and
the first recorded payload stands. Every change in the file is judged before the first append, so a
conflict, a contract refusal or the size cap writes nothing. The run is one store transaction, so a
later failure rolls it back; a caller that supplies the transaction and catches the error owns that
rollback.

A change stream append needs schema 5, marked inside the same transaction as schemas 2 to 4 are
(ADR 0015 Decision 33), with migration record 5 ("change streams, ADR 0018").

`store verify` gains `change_incomplete`, `change_overfull`, `change_stream_mismatch` and
`change_schema_unmarked`. `change_stream_mismatch` covers a stream id that is not the sha256 of the
payload's `changeId`, an event no change stream carries, and a `change.recorded` on a stream of any
other kind; the last two are also `event_stream_mismatch`, the older code that says only that an
event is misplaced. `read_stored_changes` refuses the shapes the first three name, as
`history_invalid` on the command line. `change_schema_unmarked` is content-neutral, as
`coverage_schema_unmarked` is: no reader refuses it, and the evaluation order check still runs
beside it. `rehydrate_observations` is untouched: a change is a fact, not an observation.

The store feeds the projection through `StoredChangeSet`, the changes sorted as a `ChangeSet` sorts
them with each one's stored name and digest. Its `input` on this path is `{"source": "store",
"changesSha256": [{"sha256": ..., "changes": n}, ...]}`, sorted by digest, and no name or size,
because a store can hold changes from several files. The Markdown intro line is the twin of that
object and reads the digests and counts. Those are the only bytes of a published output the two
paths word apart, as the ADR 0008 amendment of this date records. A refusal can word its own input:
`change_rule_unavailable` says a change file was supplied on one path and that the store holds
recorded changes on the other, and nothing is published either way.

Why: the digest keeps provider identifiers out of stream ids, as the coverage fingerprint does, and
one event per stream makes the idempotence check a stream-exists check.

### Decision 13, compatibility (2026-11-12): what each build does with the other's store

- 0.4.0a0 against a store this build wrote: the first `changes record` marks schema 5, so 0.4.0a0
  refuses the store at open ("database schema 5 is newer than supported schema 4") and its `store
  verify` reports `schema_version_unsupported` (ADR 0004 amendment 2026-10-03). A store that never
  records a change stays at its version, and 0.4.0a0 reads it unchanged.
- This build against a 0.4.0a0 store: schema 4 and below open as before, with no change stream and
  every report byte-identical, and a read never marks a schema. Every golden cut before this leg
  recompiles byte-identical.
- A store marked 5 and read by this build is gap-aware only if it holds a coverage stream, so
  recording a change turns on no coverage window key and no `coverage_gap_*` note. ADR 0015 Decision
  37's amendment of this date records why.

Why: every bump now has to say what each build does with the other's store, and a store that
never recorded a change has to stay readable by the build that wrote it.

## PR 3: closed windows as cases (2026-11-14)

A change window that closed with nothing verified in it becomes one system observation, and every
such window of one change becomes one case, on the stateless path with `--record-change-gaps` and
in a store with `cases changes`. With the request document of the first section, this meets the
Phase 2 exit criterion "New or significantly changed resources can trigger a scoped detection
request": the request names what is still waiting, and a case records each window that closed
before detection reached it. This section adds Decision 9's PR 3 commands, Decisions 11 and 12, and
the rest of Decision 13. Where the build departs from the approved plan, the decision says so, and
the departures are listed together at the end of the section. One golden pair is new,
`tests/golden/vdt-change-gaps.{json,md}`, and no existing golden moved.

### Decision 9, continued (2026-11-14): the commands of change gaps

- `report vdt|avi|historical --record-change-gaps` records each change window the run derives that
  closed with no verification (Decision 11). It needs `--changes`, which needs `--inventory`, and
  without it the run is refused before anything is read: "report vdt --record-change-gaps needs
  --changes: a change gap is the closed window of a declared change". Beside `--db` it joins the
  standard source conflict, which runs first: "report vdt takes either --db or
  --record-change-gaps, never both", or "report vdt takes either --db or --changes,
  --record-change-gaps, never both" when both are named. Each is `invalid_option`, exit 1, and
  writes nothing. `ReportOptions` refuses the flag without a change set, and
  `compile_record_set_from_history` refuses it outright, so a library caller cannot make it a
  silent no-op.
- `cases changes --db STORE --inventory FILE --class B|C --as-of T [--calendar-tz NAME] [--actor
  NAME]` derives the change projection from the store's recorded changes and rehydrated
  observations, through the function a report from the store uses, and appends one change gap
  stream for each closed window the store lacks, every stream in one transaction. It prints one
  line per gap, first those it recorded and then those already recorded, each in obligation order,
  as `<observation id>: recorded <window>` or `<observation id>: already_recorded <window>`, where
  the window reads `VDR-CSO-DAC window for <type>:<id> after change <changeId> closed <instant>`,
  and then a count. It exits 3 when it recorded a gap and 0 otherwise, so a rerun exits 0. A store
  that holds no change stream exits 0, appends nothing, and marks no schema. A dataset without
  `VDR-CSO-DAC` refuses only a store that holds a change, with `change_rule_unavailable` in the
  store's wording of Decision 9's PR 2 bullet. The stream id is the idempotence key, so a recorded
  gap keeps its first payload, and every stream is judged before the first append, so a refusal
  writes nothing. It takes no `--kev`, because KEV fills `kevAtActivation` and never moves a
  status or a window, and no `--changes`, because the store holds them. `--calendar-tz` is
  accepted for parity with `cases coverage` and moves nothing, because a change window closes at an
  instant; its help says so.

Why: a gap is a window of a declared change, and a report never records one into a store; what a
store holds is what `cases changes` recorded from the store's own changes and evidence, as
`cases coverage` records coverage gaps.

### Decision 11 (2026-11-14): a closed window is a system observation on a sixth stream kind

`reports/change_gaps.py` builds one SYSTEM-origin observation, under the ADR 0002 SYSTEM recipe,
for every obligation row whose `windowClosedAt` is set: a `lapsed` row, a `lapsed` row of a
resource decommissioned after the close, and a `detected` row with `late: true`. The builder keys
on the field, never on the status, so a late verification does not withdraw the gap. The window
did close empty, and the case closes by a disposition (Decision 12). The module is the twin of
`reports/gaps.py`, and neither is importable from `adapters/`.

| Recipe input | Value |
|---|---|
| `source_type` | `complyroll.change`, a reserved type no adapter can emit for an artifact observation |
| `source_tool` | `complyroll` |
| `parser_name`, `parser_version` | `complyroll.change`, `1` |
| `source_record_id` | `change-detection-gap` |
| `resource_type`, `resource_id` | The obligation's resource: the entry's own pair, or `logical` and `sample-group/<name>` for a group row |
| `context_key` | `VDR-CSO-DAC:change:<changeId>` (Decision 12) |
| `observed_at` | The window close, which is the change's `detectBy`, in UTC; never as-of or ingest time |

The record is OPEN with severity UNKNOWN, no source identifiers, and no artifact name or digest.
`evidence_ids` holds `sha256:<change file digest>`: the file a stateless run read, or on the store
path the file that first recorded the change, which a later re-record never replaces. Neither
digest enters the id, so both paths mint the same id for the same window. `ingested_at` is the
report's as-of or the `--as-of` of `cases changes`, and reaches neither the id nor a report. The
metadata always carries the same ten keys: `change.rule` (`VDR-CSO-DAC`), `change.force`,
`change.id`, `change.kind`, `change.occurredAt`, `change.detectBy`, `change.job` (empty when the
change names none), `change.changesSha256`, `change.inventorySha256`, and `change.basis` (the
block's basis text). `change.force` is the force the projection read from the pinned dataset,
SHOULD today, and never a value the builder writes. The id moves with the resource, the change id
and `detectBy`, and with nothing else: not as-of, the ingest time, the occurrence, the kind, the
job, the force, or either digest. The title is `VDR-CSO-DAC window for <type>:<id> after change
<changeId> closed <instant> with no verification recorded (VDR-CSO-FAV)`. The description reads
"ComplyRoll recorded no verification of this resource between the change and the window close;
this records the absence of a verification, not a vulnerability."

The gaps are derived once. On a flagged stateless run the compiler checks the KEV catalog date and
its rule, derives coverage, which refuses a missing coverage rule and then an unusable source
clock, adds the coverage gaps when asked, derives the change projection, which refuses a missing
change rule, adds the change gaps, and only then groups the observations and matches evaluations.
So the block and the gap records come from one projection, and among these refusals the first is
the same with or without the flag. A flagged run reads every one of them before the
evaluation-match refusal. An unflagged run matches evaluations first, as before this section. A
run with `--record-coverage-gaps` alone keeps the order it had before this section: it derives
coverage, so the coverage rule and the source clocks, before the match, and reads the catalog
date, the KEV rule, and the change rule after it.
`compile_record_set` refuses a projection handed to it that was not derived from the run's own
options. The projection reads only ARTIFACT-origin observations, so a gap never satisfies the
obligation it reports, on either path, and neither does a coverage gap inside a change window.

The persisted stream is `changegap/<fingerprint>`, named for the gap record's SYSTEM identity hash
as `coverage/<fingerprint>` is. It holds one `change.gap_recorded` v1 head and one
`observation.recorded` carrying the gap record. The head has six required fields and admits no
other: `changeId`, `contextKey`, `windowClosedAt`, `occurredAt`, `changesSha256`, and
`inventorySha256`, each restating a field of the record (`change.id`, the context key,
`change.detectBy`, `change.occurredAt`, and the two digests). Two rules go past the coverage shape
of ADR 0015 Decision 32:

- The repository accepts a change gap stream only whole: one batch at version 0 holding the head
  and then the record. The stream is written once and never extended, as a change stream is, so an
  incomplete, overfull, or out-of-order stream cannot be written through the repository.
- At append the repository holds each head field to the record field it restates, and holds the
  head to the change it names. The store must hold the `change/` stream of `changeId`, and its
  first `change.recorded` must record the head's `occurredAt`, a `detectBy` equal to
  `windowClosedAt`, and the head's `changesSha256`. So neither `cases changes` nor a library caller
  can write a gap of a change the store never recorded, or of another reading of it.

A `changegap/` id never starts with `change/` and sorts after the whole `change/` range, so neither
kind's prefix scan reads the other. A change gap stream append needs schema 6, marked inside the
append's transaction by the existing linear marking, with migration record 6 ("change gap streams,
ADR 0018"). It is a sixth schema rather than the fifth because a build that stops at the PR 2
section would open a store holding `changegap/` streams without refusing it. Each of its readers
filters to its own kind, so it would skip the streams and drop the cases in silence, which is the
misread a schema bump exists to prevent (ADR 0015 Decision 33).
Why: the record's identity is fixed by the inputs, so a past period rebuilds to the same ids, and
the coverage shape is already audited and understood. A change gap has a parent stream, so the
writer checks the parent the reader checks, and leaves nothing the reader would refuse.

### Decision 12 (2026-11-14): one case per change

Correlation groups by source type, record id, and context key, so with the key
`VDR-CSO-DAC:change:<changeId>` every closed window of one change is one case, listing every
resource and observation id. That case is the scoped detection request as a reviewable object. A
change that names a `job` does not move the key. A change id may hold `:` and spaces, so every
reader splits the key at its first two colons only, and every line that names the change names it
whole.

The evaluation match is the full triple, `{"sourceRecordId": "change-detection-gap",
"sourceType": "complyroll.change", "contextKey": "VDR-CSO-DAC:change:<changeId>"}`, under the
reserved-type refusals of ADR 0015 Decision 23, whose kind name for `complyroll.change` is "change
detection gap". An entry short of a key that matches one gap is refused as
`evaluation_context_key_required`, ending "a change detection gap is matched by sourceRecordId,
sourceType and contextKey together, so add" and the keys it leaves out; `cases evaluate` refuses
it as `evaluation_unmatched` with the same text. An entry that matches several gaps is
`evaluation_ambiguous` and names each candidate's context key. The ADR 0015 Decision 25 walk test
finds this third reserved type and holds it to its kind name, its order remedy, and its
attestation clause.

A case is detected at the earliest window close among its gaps, with `detectedAtSource` `system`,
and an unevaluated one carries one deadline, `VER-TFR-EVU` from that close, whose timeframe is
read from the pinned dataset. Every window of one change closes at its `detectBy`, so a case that
a run or a store can hold has one close. `--detected-at` never applies, and `cases attest-detection`
reports a change gap case `attestation_not_applicable`. An evaluation completed before the close
is refused as `evaluation_before_detection`, with the remedy "a change detection gap is detected
when its window closed, so evaluate it at or after that instant, or correct completedAt", by the
compiler, `cases evaluate`, and `store verify` alike. With no attestation, the Markdown sentence
names the kind as "for a change detection gap, from the instant its change window closed".

A gap closes as a coverage gap closes (ADR 0015 Decision 26). A later verification never closes
it: the row reads `detected` with `late: true` and `resumedAt`, and on the store path a
verification inside the window makes the note `change_gap_contradicted` (Decision 13). Only a
disposition from an evaluation matched on the full triple closes it, and any disposition the
evaluations file accepts applies. `accepted` carries no `finalDisposition`, as for any record, and
lists the gap in `VER-RPT-AVI`. A gap detected after the report period is left out of the official
VDT with INFO `excluded_by_period` and still counts for exit 3 (ADR 0014 Decision 18).

`cases list` adds its `CONTEXT KEY` column once the store holds a coverage gap case or a change
detection gap case, with `-` for every other case, and a listing with neither is unchanged byte for
byte. A change id may hold spaces, so the key cell runs to the end of its line.

A known limit, left open: a case spanning several resources takes one member's title as its
description, as the job and group cases of ADR 0015 do. The description names one resource while
`resources` and `observationIds` list every member. The title carries the change id, which names
the case.

Why: the request is scoped by the change, so the case is too, and every affected resource stays on
it.

### Decision 13, continued (2026-11-14): exit status, awareness, audits, and compatibility

- **Exit 3.** Exit 3 keeps its ADR 0017 meaning: the output holds a system-generated `VDR-CSO-FAV`
  record. `--record-change-gaps` answers for its own kind beside the other two record flags, and a
  run that recorded any kind exits 3 once. `cases changes` exits 3 when it recorded a gap, and
  `report --db` keeps 0 and 1. No exit code is added, the reference gate is unchanged, and a
  `warn-changes` gate policy is left for later (the ADR 0017 amendment of this date).
- **Row keys.** On a change-gap-aware run every obligation row gains `recorded` and `trackingId`:
  both null where no window closed; `true` and the effective tracking id of the record that carries
  the gap; or, on the store path only, `false` and null for a closed window no stored gap carries.
  A run that is not aware carries neither key, so every block written before this section keeps
  its bytes, and the request document never carries them. The Markdown Obligations table gains
  Recorded and Tracking ID columns and opens with one fixed sentence, "A recorded row is a
  VDR-CSO-FAV system record of this run and names its tracking ID here even when this report does
  not select the record, such as one detected after the report period. A row whose window did not
  close records nothing and reads n/a." A run that holds a change gap record lists
  `complyroll.change` in `parserVersions`; an aware run that holds none, as where no window
  closed, does not.
- **Awareness.** A stateless run is change-gap-aware with the flag. A report from a store is aware
  when the run has an inventory and the store holds at least one `changegap/` stream, read by
  `EventRepository.holds_change_gap_stream`, which loads no stream. Change gap awareness and
  coverage gap awareness each follow their own stream kind, so recording one kind turns on no key
  or note of the other, and a store with no `changegap/` stream reports as it did before this
  section, byte for byte. An aware run maps each derived closed window to a stored gap by
  rebuilding the gap and comparing ids.
- **Notes.** An aware run from a store names each disagreement with its store in an INFO note, the
  change twins of ADR 0015 Decisions 38 to 40. `change_gap_unrecorded` is a closed window no
  stored gap carries, so no case does; `cases changes` with the run's inventory, as-of, and class
  records it. `change_gap_contradicted` is a stored gap no window derives, with a verification
  inside its window `[occurredAt, detectBy]`, closed at both ends as the derivation reads it.
  `change_gap_unmatched` is a stored gap no window derives and nothing inside it disproves, so the
  run's inventory, as-of, or class may differ from the run that recorded it. A stored change
  cannot differ, because history is append-only, and no note names a calendar zone. Every note
  names the change id, is located `<changes name> <changeId> <type>:<id>`, and follows the change
  block's warnings: unrecorded windows in obligation order, then stored gaps by occurrence, change
  id, and resource. A group gap is disproved by a member's verification under `VDR-TFR-PSD`, and a
  verification under an alias disproves as the derivation files it. One case carries every
  resource of a change, so the whole-case advice of ADR 0015 Decision 39 is the usual case here: a
  contradicted note advises a false positive only when no other gap of its case stands.
- **Audits and reader refusals.** `store verify` gains five codes in `AUDIT_FAULT_CODES`:
  `changegap_incomplete` and `changegap_overfull` (a stream that is not one head and one record),
  `changegap_stream_mismatch` (an id that names no fingerprint, a record that is another stream's,
  a stream that does not open with its head, or a head whose change id names no recorded change or
  whose occurrence, window close, or change file digest is not the one that change records),
  `changegap_identity_breach`, and `changegap_schema_unmarked` (a change gap stream in a store
  below schema 6). The identity check holds the record to every field its builder fixes: origin,
  source type, tool, parser, record id, derived id, disposition, severity, identifiers,
  description, and title; exactly the ten metadata keys, with `change.rule` the DAC rule, a
  `change.id` that names a change and spells the context key, `change.detectBy` equal to the
  observed instant as the writer spells it, `change.occurredAt` at or before the close, a rule
  force, a change kind, a basis text the writer records, both digests as SHA-256 text, and the one
  evidence id `sha256:<change.changesSha256>`; and the head's six fields against the record. A
  record edited in place in a field the fingerprint covers, with its fingerprint and id re-derived,
  is an identity breach that names the field when the field is the source type, tool, parser name
  or version, or record id, which are read before the stream id, and a stream mismatch when it is
  the resource type or id, the context key, or the observed instant, because the record is then
  another stream's gap record. Edited with neither re-derived, it is `payload_contract_invalid`,
  because the observation contract recomputes the fingerprint first. The parent check is one
  past ADR 0015 Decision 34, because a coverage gap has no parent stream. Every command that reads
  the store's observations back, `report --db`, `cases correlate`, `cases changes`, and `changes
  pending --db` among them, refuses each shape the first four codes name with the audit's text, as
  `history_invalid`, and refuses an event on a change gap stream that does not belong there.
  `changegap_schema_unmarked` is content-neutral, as the failure, coverage, and change markers are:
  no reader refuses it, and the evaluation order check still runs beside it.
- **Divergences.** A store whose gaps were recorded with the report's inventory, as-of, and class
  gives the stateless run's bytes with `--record-change-gaps`, but for the block's `input` and its
  Markdown intro line, which the PR 2 section already names. Otherwise the three notes above name
  where the two disagree. The ADR 0008 amendment of this date records it.
- **Compatibility.** A store this build wrote, under the build that stops at the PR 2 section: the
  first `cases changes` that records a gap marks schema 6, so that build refuses the store at open
  ("database schema 6 is newer than supported schema 5") and its `store verify` reports
  `schema_version_unsupported` ("database is marked schema 6; this build opens schemas 1 to 5"). A
  store that never records a change gap stays at its version, and that build reads it unchanged.
  Under 0.4.0a0: through the repository a gap is recorded only in a store that holds a change, which
  is already schema 5 and already refused by 0.4.0a0 (the PR 2 bullets above), so the gap changes
  only the schema its refusal names. This build against a store either earlier build wrote:
  schemas 1 to 5 open as before, with no change gap stream and every report byte-identical, a read
  never marks a schema, and a `cases changes` run that records nothing marks nothing. Every golden
  cut before this section recompiles byte-identical. No parser version moves: no adapter changed,
  and the SYSTEM recipe's parser is new.
- **A known limit, left open.** A stored gap whose window closed after a past as-of is not
  filtered out of a run at that as-of. The run derives no such window, so the gap reads
  `change_gap_unmatched` and its record stays in the report, detected after the as-of. A stored
  coverage gap reads the same way today, so this is cleanup for both kinds.

Why: where a change gap and a coverage gap have the same shape the answers are the coverage ones,
and each difference follows from a change window being an instant pair the provider set and from
a change gap having a parent stream.

### Departures from the approved plan (2026-11-14)

- The builder lives in `reports/change_gaps.py`, not `reports/changes.py` as Decision 11 of the
  plan said, so the projection module stays the projection's, as coverage splits `coverage.py` from
  `gaps.py`.
- A gap is built for every closed window, a late detection's included, where the plan said "each
  lapsed window". A builder keyed on the `lapsed` status would stop deriving a recorded gap once a
  late verification arrived, and would never record a late window on the stateless path, though
  Decision 5 says the closed window stays a recorded fact.
- The kind, remedy, and attestation tables of ADR 0015 Decision 25 landed with the builder, ahead
  of the plan's evaluations step, so no build of this section read a change gap as a failure.
- Awareness and orphans were open in the plan. A report from a store is aware when it has an
  inventory and the store holds a `changegap/` stream. A head whose change id names no change
  stream, or whose occurrence, close, or change file digest disagrees with that stored change, is
  `changegap_stream_mismatch` in `store verify` and `history_invalid` on every reader, never an
  uncaught exception.
- A change gap stream is write-once at the repository: head and record in one batch at version 0.
  The coverage shape of ADR 0015 Decision 32 does not enforce this.
- The repository checks the head against the record and against the stored change at append.
  Coverage checks head against record only in the reader and the audit.
- `change.force` is the force the projection read from the pinned dataset, where the plan wrote
  `SHOULD`; the value is the same today, and no force is written in code.
- The builder refuses a row whose window does not close at its change's `detectBy`, so
  `observed_at` and `change.detectBy` are one instant by construction. A derived projection never
  reaches the refusal.
- "The earliest window close of the case" is one close in practice, since every window of one
  change closes at its `detectBy`; a case with two closes can only be built through the library.
