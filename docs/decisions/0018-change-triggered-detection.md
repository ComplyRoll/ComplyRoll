# ADR 0018: Change-triggered detection

- Status: Accepted
- Date: 2026-11-08

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
whether detection reached it after the change, and write the resources still waiting as a document
a pipeline consumes.

The document is `complyroll.detection-request` version 1, written by `changes pending` (Decision
9). It lists only the resources that still need detection: per change, the `changeId`, `kind`,
`occurredAt`, `detectBy`, the `job` the provider expects to act and the `source`, and for each
waiting resource its `resourceType`, `resourceId`, inventory `aliases`, `sampleGroup` and `status`.
A resource that is `detected` is left out of the request and listed in the report block instead. A
change with no waiting resource has no request entry.

The document also carries `schema`, `schemaVersion`, `rule`, `force`, `provenance` (the pinned
rules source the force was read from, in the block's shape), `asOf`, `input`, `inventorySha256`
and `summary`. `summary.pending` counts every waiting row, whatever its status, and
`summary.byStatus` gives the split across `lapsed`, `undetermined` and `pending`.

Why: the pipeline that owns the scanner needs the resource names and nothing else, and the report
block already carries the evidence trail an assessor reads.

## Decision 2: a native change contract first, no source adapter

The input is a JSON document of ComplyRoll's own, `complyroll.changes` version 1, read by a bounded
reader that refuses and never repairs, as the inventory is (ADR 0015 Decision 5). No adapter for
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

No significance score is derived. `significant` and `rationale` are copied into the block as
written, and only a change that is `created`, or `modified` with `significant: true`, opens an
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

## Decision 5: the obligation closes on a verification after the change; the window is provider-set

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
  as-of never carries a future change in its block or its request.
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
`undetermined` and `pending` rows. A `detected` status is not a compliance finding, and the basis
text says so.

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
other row to none. No official field holds any of it.

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

`kevAtActivation` is `null` unless the question applies and can be answered: `--kev` given, a
`created` change, a machine-based entry, status `detected`. Then it is `true` or `false`. A
CycloneDX vulnerability row sits on a `package` resource, so a BOM's own KEV would otherwise read as
an affirmative `false` for the image it verified. When the satisfying verification is a CycloneDX
scope observation, the OPEN rows of that same artifact digest whose source type is CycloneDX and
whose resource is a `package` count as findings on the verified entry.

Why: the KEV finding is already a record with its own `VDR-TFR-KEV` clock, and a second case for the
same finding would double it. The diagnostic makes the activation visible without a new record type.

## Decision 9: commands and flags

- `report vdt|avi|historical --changes FILE` reads one change file beside `--inventory`. A second
  `--changes` is `invalid_option`, a refused file is `invalid_input`, and both exit 1 and write
  nothing (ADR 0015 Decision 16).
- `changes pending ARTIFACT... --changes FILE --inventory FILE --class B|C --as-of T [--calendar-tz
  NAME] [--kev FILE] [--record-failed-imports] [--output PATH]` writes the request document to
  standard output or `--output`. It takes the same artifact positionals as `report`, because the
  obligations are read against the same evidence, and it refuses what `report` refuses about those
  inputs. It runs no coverage clock, so a dataset that lacks a coverage rule does not stop it.
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

`docs/BUILD_PLAN.md` gains "**Met, 2026-11-08** (shipped since ADR 0001: correlation keeps every
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
