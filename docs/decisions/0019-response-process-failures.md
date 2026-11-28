# ADR 0019: Response-process and attestation failures

- Status: Accepted
- Date: 2026-11-26

## Context

`VDR-CSO-FAV`, "Failures Are Vulnerabilities", reads in the pinned rules dataset: "Providers MUST
treat problems or failures with their vulnerability detection and response processes as
vulnerabilities." `AGENTS.md` carries the same rule as a domain invariant. ADR 0014 claimed its
detection half for a failed import, and recorded missing attestations and response-process
failures as a scope change (its Decision 17). ADR 0015 and ADR 0018 added the coverage gap and
the change detection gap, both on the detection side. Nothing yet recorded a failure of the
response half.

Two such failures are visible in data ComplyRoll already holds, with no new operator input:

- A remediation that did not hold. A case whose disposition resolves to `remediated` gains an
  open artifact observation detected after the remediation. Before this record
  `correlate_cases` linked that observation without looking at the disposition, and the case
  kept publishing `finalDisposition: Remediated` while a scanner said the weakness was back.
- A lapsed attestation. A case whose evidence declares no detection time has no evaluation
  clock until an operator attests one. If none arrives, its evaluation window lapses unseen.

Phase 3 of `docs/BUILD_PLAN.md` carries "response-process and attestation failures" from Phase 2.
The slice plan (`Plans/response-failures-plan.md`, approved 2026-11-26) cuts it in three: this
record is the first pull request, the two failures above. `ResponseAction` records and a lapsed
planned response are the second, and the `VER-TFR-MHR` and `VER-TFR-MRH` recurrence clocks the
third. This record follows the shape of ADR 0015's third section and ADR 0018's third section,
and says where it departs. Decision numbers follow the approved plan.

## Decision 1: the remediation instant is an evaluation's `completedAt`

A case was remediated at the `completedAt` of the evaluation in force when its current
`remediated` disposition was first recorded. On the stateless path that is the record's own
evaluation. In history it is read from the case stream: the fold walks the dispositions in
order, and a run of dispositions that each resolve to `remediated` keeps the instant of the
evaluation in force at its first one, so a re-evaluation that keeps the disposition moves the
current `completedAt` and not the remediation instant. A disposition that does not resolve to
`remediated` ends the run, and a later `remediated` starts a new one. `CaseState.remediated_at`
carries the instant, and `CaseState.remediation_episode` the run's 1-based position among the
case's remediated runs (Kyle's ruling K2), so a run that starts at an instant an earlier run
shared is still a new failed remediation. The store's `recordedAt` never reaches a report or an
identity (ADR 0010).

A disposition resolves to `remediated` when its status is `remediated`, or `closed` with
`closedDisposition` `remediated`: both publish `finalDisposition: Remediated`. Re-detection after
`fully_mitigated` or `partially_mitigated` is expected, since a mitigated weakness still exists,
and after `false_positive` or `accepted` it is the operator's standing ruling. None of those is a
recurrence.
Why: an operator's evaluation is the only clock a remediation has, and the first-recorded rule
keeps a routine re-review from moving the instant a failure is measured from.

## Decision 2: what recurs

An observation recurs when it is ARTIFACT-origin, open, a member of the remediated record's
group, and detected strictly after the remediation instant. A system record never recurs. A
detection at the remediation instant does not recur, because the scan that confirmed the
remediation can share it. A member that declares no source timestamp cannot be ordered against
the remediation: it is warned about (Decision 3) and never recorded. The group is the report's
own, every current open observation, linked or not, so the warning and the record agree before
`cases correlate` links what came back.
Why: only a timed artifact finding after the remediation shows that the weakness came back.

## Decision 3: ComplyRoll warns and never sets a disposition

The original case keeps the operator's `remediated` disposition. Every report, on both paths and
whatever else the run records, adds one WARNING `recurrence_after_remediation` per remediated
record, located at its source record id. It names the record, the remediation instant, how many
open observations were detected after it and the earliest of them with its resource, and how many
members declare no source timestamp. It ends "the remediation did not hold" when a timed member
came back, and "whether the remediation held cannot be told" when only untimed members are open,
then "and the record keeps its disposition until an evaluation changes it". The operator
re-evaluates. `REPORT_DIAGNOSTIC_CODES` holds the code. A WARNING never moves an exit code (ADR
0017 I3).

The comparison is strict: a member detected at the remediation instant raises no warning. A
change to `closed` with `closedDisposition` `remediated` keeps the warning, since that still
resolves to `remediated`; a change to any disposition that does not clears it. An untimed member
raises no warning when the record's detection time is an attestation at or before the remediation
instant, since the attestation already dates the weakness before the remediation (Kyle's ruling
K4). The trade-off: a new untimed scan of such a record is not flagged. A timed member detected
after the remediation still is.
Why: ComplyRoll has never set a disposition itself, and the slice keeps that line (Kyle's ruling
D3a).

## Decision 4: one recurrence record per failed remediation and resource

`reports/response_gaps.py` builds one SYSTEM-origin observation per resource that came back, under
the SYSTEM identity recipe of the ADR 0002 amendment:

| Recipe input | Value |
|---|---|
| `source_type` | `complyroll.recurrence`, a reserved type no adapter can emit |
| `source_tool` | `complyroll` |
| `parser_name`, `parser_version` | `complyroll.recurrence`, `1` |
| `source_record_id` | `remediation-recurrence` |
| `resource_type`, `resource_id` | The recurring observation's resource |
| `context_key` | `<correlation tracking id>:remediated:<remediation instant>:<episode>` |
| `observed_at` | The earliest recurring detection on that resource, in UTC |

The episode is the remediated run's position of Decision 1, written as `str(int)` writes a
positive integer. Ties at one instant on one resource go to the lowest observation id, so they
mint one record.
The record is OPEN with severity UNKNOWN, no source identifiers, and no artifact name or digest;
`evidence_ids` holds the recurring observation's id. The metadata always carries the same four
keys: `recurrence.caseTrackingId`, `recurrence.remediatedAt`, `recurrence.observationId`, and
`recurrence.observationDetectedAt`. The title is `remediation of <tracking id> recorded <instant>
did not hold: <type>:<id> detected again <instant> (VDR-CSO-FAV)`. The description says
ComplyRoll recorded an open observation of the weakness on the resource after its case was
recorded remediated, and that this records that the remediation did not hold, a failure of the
response process. The id moves with the resource, the case, the remediation instant and the
detection, and with nothing else: not the ingest time or the recurring observation's id, so a
newer parser that rereads the same scan names the same record. The correlation tracking id is
used, never an operator's provider tracking id, so an override does not move the identity.
Correlation groups by source type, record id and context key, so one failed remediation is one
case listing every resource that came back, and a second remediation that also fails is a second
case, even at the same instant.

The first record stands (Kyle's ruling K1). A failed remediation and resource, keyed by the
record's context key and resource, is recorded once: when a scan dated earlier than the recorded
detection is ingested later, `cases response-gaps` reports the stored record as already recorded
and appends nothing, and a report notes the earlier detection (Decision 11).
Why: the identity is fixed by the inputs, and one record per resource keeps each resource's
evidence on the case without a same-instant collision.

## Decision 5: one lapse record per case and window

A case's first sighting S is the earliest `ingested_at` of its linked observations, read from
every artifact stream, current or superseded. An ingest's `ingested_at` is its `--as-of`, or its
run time at second precision when none is given: the instant ComplyRoll saw the reading, as ADR
0014 reads a detection process failure (Kyle's ruling K3). A case with no link has no first
sighting and records nothing. Its window closes at the `VER-TFR-EVU` deadline from S under the
run's class and calendar zone, selected from the pinned dataset: seven days for Class B and five
for Class C today. A case is untimed when no linked observation declares a source timestamp, no
attestation is recorded, and the report's current group for the case holds no observation that
declares one, linked or not; a system record is always timed. A run of `cases response-gaps
--as-of T` records a lapse when the case is untimed, T is at or after S, and T is at or past the
close, and once recorded the lapse is permanent. S stands in for the detection time: when the
ingest instant is at or after the true detection, the window can only close after the true one,
so the lapse is never early. ComplyRoll cannot check that condition, and an `--as-of` or a later
attestation that dates detection after S can leave a recorded lapse before the deadline the
attestation gives. The lapse records that the run found the case untimed at or after the first
sighting's deadline, and an attestation entered after the deadline but before the first run that
sees it prevents the record. A first sighting whose deadline falls past what a timestamp holds is
an invalid store clock: `store verify` rejects it, and a report that must derive the window refuses
it with `clock_out_of_range`, never an uncaught overflow; the audit is the stricter, as it is for
policy.

| Recipe input | Value |
|---|---|
| `source_type` | `complyroll.attestation` |
| `source_tool` | `complyroll` |
| `parser_name`, `parser_version` | `complyroll.attestation`, `1` |
| `source_record_id` | `attestation-lapse` |
| `resource_type`, `resource_id` | `logical`, `case/<correlation tracking id>` |
| `context_key` | `<correlation tracking id>` |
| `observed_at` | The window close |

`evidence_ids` holds `case:<tracking id>`. The metadata always carries five keys:
`attestation.caseTrackingId`, `attestation.firstSeenAt`, `attestation.windowClosedAt`,
`attestation.rule` (`VER-TFR-EVU`), and `attestation.force`, the force the dataset states, which
the repository holds to the force the pinned rules give `VER-TFR-EVU` in a supported class. The
title is `detection time of <tracking id> was not attested within VER-TFR-EVU from <S>
(VDR-CSO-FAV)`. The id moves with the case and the window close only. Lapses of one case under
two profiles share its context key, so they are one case.
Why: Kyle's rulings R3 and F1. The wall-clock `attestedAt` cannot be ordered against an operator
instant, so the run reads whether the case is timed now, and an attestation made before any run
sees the lapse prevents it: the record is only as frequent as the runs.

## Decision 6: a store recording instant becomes a report instant here, and only here

S is a recording instant, the ingest's `--as-of` or its run time when none is given, and it
reaches a report through the lapse's title and window close. ADR 0014 already reports a detection
process failure at its recording instant, so the precedent stands (Kyle's ruling K3). The store's
own `recorded_at`, a case's `createdAt`, and an attestation's `attestedAt` are wall-clock
instants, and none of them reaches a report record or an identity.
Why: the instant is fixed once the reading is recorded, so a past period rebuilds to the same
bytes. Byte identity across stores built from the same scans needs `--as-of` on every ingest, since
an ingest without one records its own run time.

## Decision 7: detection time and clocks

Both kinds carry `detectedAtSource` `system`. A recurrence case is detected at its earliest
recurring detection, a lapse case at its window close. `--detected-at` never applies. The one
deadline of an unevaluated case is `VER-TFR-EVU` from that instant. ADR 0015 Decision 25's three
tables gain both types: the kind names "remediation recurrence" and "lapsed attestation"; the
order remedies "a remediation recurrence is detected when its recurring observation was detected"
and "a lapsed attestation is detected when its evaluation window closed", each ending "so evaluate
it at or after that instant, or correct completedAt"; and the Markdown attestation clauses "for a
remediation recurrence, from the instant its recurring observation was detected" and "for a lapsed
attestation, from the instant its evaluation window closed". The walk test finds five reserved
types.
Why: a record whose instant is fixed by its inputs names no as-of remedy.

## Decision 8: persisted only, one command

Both kinds are recorded in a store only (Kyle's ruling 7b). `cases response-gaps --db STORE --as-of
T --class B|C [--calendar-tz NAME] [--actor NAME]` derives both kinds from the store and appends
one stream per record the store lacks, every stream in one transaction. `--as-of` and `--class`
are required; `--calendar-tz` defaults to UTC. It prints one line per record, those it recorded
first and then those already recorded, as `<observation id>: recorded <title less the rule>` or
`<observation id>: already_recorded <title less the rule>`, and then a count. It exits 3 when it
recorded one and 0 otherwise, so a rerun exits 0. A store with nothing to record appends nothing
and marks no schema. Recurrences are derived whatever the as-of: `--as-of` sets the lapse window
and each record's ingest time. No report flag records a response gap; the stateless path keeps
the warning of Decision 3, never a record.
Why: a lapse needs a first sighting only history holds, and one command for both keeps one
recording run.

## Decision 9: one new stream kind, schema 7

A seventh stream kind, `response-gap/<fingerprint>`, is named for its record's SYSTEM identity
hash, 64 lowercase hex characters, as a coverage stream is. It holds one `response_gap.recorded`
v1 head and then the one `observation.recorded` it mints, written whole and once: one batch at
version 0. The head has nine fields, all required as in every contract: `kind` (`recurrence` or
`attestation`), `caseTrackingId`, and `contextKey`; `remediatedAt`, `observationId` and
`observationDetectedAt`, which a recurrence fills; and `firstSeenAt`, `windowClosedAt` and `rule`
(`VER-TFR-EVU`), which a lapse fills. The fields of the other kind are null, which the contract
holds as `case.disposition_recorded` holds its pair. At append the repository holds the head's
kind to the record's source type and every other field to the record field it restates.
`SUPPORTED_SCHEMA_VERSION` is 7, with migration record 7 ("response gap streams, ADR 0019"),
marked inside the append's transaction by the existing linear marking. A store that never records
a response gap stays at its version.
Why: a build that cannot read the stream must refuse the store rather than skip it, and the
fingerprint keeps case and resource identifiers out of stream ids.

## Decision 10: store doctrine

`store verify` gains five codes in `AUDIT_FAULT_CODES`: `responsegap_incomplete` and
`responsegap_overfull` (a stream that is not one head and one record),
`responsegap_stream_mismatch` (an id that names no fingerprint, a record that is another stream's,
or a stream that does not open with its head), `responsegap_identity_breach` (a record that is not
one its writer mints, whose metadata is not exactly its kind's keys with the values its writer
records, or whose head names another kind, case, key or instant), and
`responsegap_schema_unmarked` (a response gap stream in a store below schema 7). Every command
that reads the store's observations refuses each of the first four with the audit's text, as
`history_invalid`. The fifth is content-neutral, as every marker fault is, and the evaluation order
check runs beside it. The head is held to its own record alone, never to the case's current state:
a case missing or moved since is not a fault, since a gap recorded before `cases correlate` is
legal (ADR 0015 Decision 36). Whatever a report from the store refuses, `store verify` rejects.
Why: one text per fault keeps the reader and the audit from drifting apart.

## Decision 11: four notes name where a store and its run disagree

A report from a store that holds a response gap stream reads the store's response gaps against the
run, each disagreement an INFO note, the twins of ADR 0015 Decisions 38 to 40:

- `response_gap_unrecorded`: a response gap the run derives that no record carries, so no case
  does; `cases response-gaps` records it.
- `response_gap_contradicted`: a recorded gap the run derives no gap for, against which the store
  holds evidence. A recurrence is contradicted when no current open observation of its case on its
  resource was detected after its own remediation instant; a lapse when a linked observation that
  declares a source timestamp was recorded at or before its own window close.
- `response_gap_unmatched`: a recorded gap the run derives no gap for, with nothing against it, so
  the evidence or the run's class or calendar zone may differ from the run that recorded it.
- `response_gap_earlier_detection`: a recorded recurrence whose failed remediation and resource
  the run finds detected earlier than the record says. The record stands as written (Decision 4),
  so the note names the earlier instant and no second record is made.

A recorded gap the run does not derive stands, with no note, when the run rebuilds it from its own
record: a recurrence from its own remediation instant, whatever the case's disposition now, and a
lapse from its case's first sighting, whether or not the case is timed now. So an attestation
after a lapse, or a re-evaluation after a recurrence, writes no note. A derived recurrence whose
context key and resource a stored record holds is that record, never unrecorded. Each note is
located `<record id> <case tracking id>` and read against the other recorded gaps of its case: a
contradicted note advises a false positive only when no other gap of the case stands (ADR 0015
Decision 39). A store that holds no response gap stream writes none of these notes and reads as it
did before, except for the recurrence WARNING of Decision 3, which every report carries.
Why: a permanent fact must not turn every later report into a note, and an operator must tell
"evidence disproves this" from "this run's inputs differ" without parsing a message.

## Decision 12: goldens

No existing golden moved. Two pairs are new: `tests/golden/vdt-recurrence-warning.{json,md}`, a
stateless run carrying only the warning, which a store built from the same scans reports byte for
byte before `cases correlate`; and `tests/golden/historical-response-gaps.{json,md}`, cut from a
store that recorded both kinds and then attested the untimed case, so its lapse stands with no
note. The episode ordinal of Kyle's ruling K2 moved the second pair's recurrence context key, so
its case tracking id and observation id were recut on 2026-11-27; the first pair did not move.

## Exit status

Exit 3 keeps its ADR 0017 meaning, that the output holds a system-generated `VDR-CSO-FAV` record,
now of any of five kinds. `cases response-gaps` is a fifth place exit 3 comes from (the ADR 0017
amendment of this date). No exit code is added, and `report --db` still answers 0 or 1.

## Compatibility

A store a 0.5.0a0 build wrote opens and reads identically: the trial of 2026-11-26 built a schema 6
store with 0.5.0a0 holding a failure, coverage gaps, changes and change gaps, and `store verify`,
`cases list`, and `report vdt`, `avi` and `historical` with and without an inventory gave the same
bytes under both builds, with the store's bytes unchanged by the reads. `cases response-gaps` on
that store records nothing and leaves it at schema 6. A store this build marks 7 is refused by
0.5.0a0 at open ("database schema 7 is newer than supported schema 6"), and its `store verify`
reports `schema_version_unsupported`. No parser version moves.

## Rejected alternatives

- ComplyRoll reopening the case (plan D3b). Truer to the scanner, but it would override an
  operator ruling for the first time.
- Recording recurrences on the stateless path (plan D7a). It needs a group, match, mint and regroup
  order no earlier slice used, and is reachable only when the pre-remediation artifact is passed
  too; the warning covers it.
- The wall-clock `attestedAt` as the lapse's evidence (plan D5). It would put a wall-clock
  instant into a report record and break ADR 0010's byte identity.
- One recurrence record per recurring observation (plan D4). Two members at one instant on one
  resource collided; one per resource names the earliest.

## Left for later

- `ResponseAction` records and a lapsed planned response: the second pull request.
- The `VER-TFR-MHR` and `VER-TFR-MRH` recurrence clocks: the third.
- A value check that a lapse's window close is the `VER-TFR-EVU` deadline from its first sighting
  under some class. The class is the run's, which the record does not hold, so the audit checks
  the close is after the sighting only.
- A recurrence detected after a run's `--as-of` is still recorded by that run, as the report's
  warning names it whatever its as-of.

## PR 2: the lapsed planned response (2026-11-27)

The second pull request of the slice adds a third failure of the response process: a provider's
own planned reduction that did not happen. A case whose current evaluation states a next planned
reduction ("to N2 by 2026-09-11"), whose planned time has passed, and whose rating is still above
the target with no reduction to the target recorded by then, is a response process that failed.
Before this section every report kept publishing that `projectedNextReduction` with an
`estimatedAt` in the past and said nothing. The approved plan is `Plans/response-actions-plan.md`
(approved 2026-11-27, Kyle's rulings D1 1a, D2 2a, D3 3a, D12 12a); decision letters below follow
it. Where the build departs from the plan, the decision says so.

### Decision 13: the evaluation is the response action record (plan D1, ruling 1a)

`projectedNextReduction` (`estimatedAt`, `targetRating`) is the planned action, its planned time
and target PAIN, and `painReductionEvents` (`reducedAt`, `rating`) are the completed ones, their
completed time and actual result. Both are official fields of the pinned Common Definitions schema
and both are already in history. No new file, command, event type for the action, or stream kind
is added. A completed remediation or full mitigation is carried as the disposition at its
evaluation's `completedAt` (Decision 1). A plan to remediate cannot be stated, since the field
holds a target rating and none sits below N1. The action's kind, an owner, and evidence of its
own are not carried. `docs/DATA_MODEL.md` says where each planned field lives.
Why: the failure is visible in data ComplyRoll already holds, as the first two were, and a second
record of the same plan would be the generic tracker `AGENTS.md` warns against.

### Decision 14: what lapses (plan D2 and D3, rulings 2a and 3a)

A record has a lapsed planned response at a run's as-of T when all five hold:

1. It is an ARTIFACT-origin record whose current evaluation carries `projectedNextReduction` with
   planned time E and target R.
2. T is strictly after E, the comparison every deadline uses. A run at E records nothing.
3. Its current rating is above the target: `pain` > R.
4. No completed reduction to R or below is recorded with `reducedAt` from the current evaluation's
   `completedAt` through E, both ends included.
5. Its resolved status is not `remediated`, `fully_mitigated` or `false_positive`, however reached
   (`closed` with that `closedDisposition`, or `isFalsePositive` with no disposition). No
   disposition, an active one, `partially_mitigated` and `accepted` can lapse, the last two also
   when closed as such.

The clock is the provider's own `estimatedAt`, never the pinned `VDR-TFR-PVR` target: a passed PVR
target is already published as `overdueStatus`, so a case for each would report one lateness twice.
The planned time carries no FedRAMP force of its own; the record's one rule is `VDR-CSO-FAV`.
Condition 4's window opens at `completedAt` because the current evaluation asserts the rating and
the plan together at that instant, so a reduction followed by a re-rating upward does not hide a
lapse. The cost: an operator who files a new evaluation after an on-time reduction and leaves the
rating and the plan as they were gets a record.

`reports/response_gaps.py` holds the one pure function, over a group, the evaluation the report
reads for it, and the as-of, that serves the warning on both paths and the record. A store reads
the report's own groups and each case's reported evaluation, never the folded cases alone (plan
F2), so a case no current open observation matches, a `stale_case`, is in no report and neither
warns nor records.
Why: Kyle's rulings 2a and 3a; a provider that revises its estimate before the time passes never
sees a record.

### Decision 15: a WARNING on every report (plan D4)

Every report adds one WARNING `planned_reduction_lapsed` per record that meets Decision 14 at the
report's as-of, on the stateless and persisted paths, whether or not a store has recorded the
lapse, located at the record's source record id. It names the record, the planned time, the target,
the current rating and the evaluation the window opens at, and ends "the planned reduction is not
recorded, and the record keeps its plan until an evaluation changes it". `REPORT_DIAGNOSTIC_CODES`
holds the code. A WARNING never moves an exit code (ADR 0017 I3). ComplyRoll does not remove or
rewrite the published `projectedNextReduction`.

### Decision 16: one record per case and plan (plan D5)

| Recipe input | Value |
|---|---|
| `source_type` | `complyroll.response-plan`, a reserved type no adapter can emit |
| `source_tool` | `complyroll` |
| `parser_name`, `parser_version` | `complyroll.response-plan`, `1` |
| `source_record_id` | `planned-response-lapse` |
| `resource_type`, `resource_id` | `logical`, `case/<correlation tracking id>` |
| `context_key` | `<correlation tracking id>:planned:<planned time>:<target rating>` |
| `observed_at` | The planned time E, in UTC |

The record is OPEN with severity UNKNOWN, no source identifiers, and no artifact name or digest;
`evidence_ids` holds `case:<tracking id>`. Its metadata always carries the same three keys:
`plan.caseTrackingId`, `plan.estimatedAt` and `plan.targetRating`. The current rating is not
recorded: it moves, and a record is held to its own inputs alone. The title is `planned reduction
of <tracking id> to N<R> was not recorded by <E> (VDR-CSO-FAV)`; "by" keeps it true when a
reduction is recorded after E. The planned time is written as every response gap instant is, so
two offsets of one instant are one record, and the target as `str(int)` writes a rating, `1` to
`5`, in the context key and the metadata, with `N` before it in the title only. The same plan
restated by a later evaluation is the same record, and a new plan that also lapses is a second
case. The correlation tracking id is used, never a provider override.

### Decision 17: detection time and clocks (plan D6)

The record carries `detectedAtSource` `system` and is detected at E. `--detected-at` never
applies. The one deadline of the unevaluated case is `VER-TFR-EVU` from E. ADR 0015 Decision 25's
three tables gain the type: the kind name "lapsed planned response", the order remedy "a lapsed
planned response is detected when its planned time passed, so evaluate it at or after that
instant, or correct completedAt", and the attestation clause "for a lapsed planned response, from
the instant its planned reduction was expected". The walk test finds six reserved types; the test
of this record that pinned exactly five was updated to six, where the plan expected no test change.

### Decision 18: recorded in a store only, by the same command (plan D7)

`cases response-gaps --db STORE --as-of T --class B|C` gains the third kind with no new flag: it
derives recurrences, then lapsed attestations, then lapsed plans, appends one stream per record
the store lacks, and prints the same two line shapes. It exits 3 when it records one and 0
otherwise. No class or calendar zone enters the kind's identity. No report flag records a plan
lapse; the stateless path keeps the warning of Decision 15.

The run reads every case's reported evaluation, so it refuses with exit 1 and appends nothing
where a report from the store refuses for the same reason: a case, stale or not, that records a
disposition and no evaluation (`disposition_without_evaluation`). A build at `09193ab` ran past
that case. It also refuses, as `tracking_id_collision` and before the first append, a run whose
new records would open a group under an id another record already publishes, such as a provider
override equal to the new record's correlation id; the text names the id, both records and the
group the run would open. This holds for all three kinds, since each record's correlation id is a
function of its inputs that an override can name, so no run turns a store a report compiles into
one that `report --db` and `store verify` refuse.

The run can record a plan lapse for a record no report can compile yet (Kyle's ruling on audit
finding B01, 2026-11-27: keep, and say so). A case with no detection time, no source timestamp and
no attestation, that carries an evaluation with a passed, unmet plan, has its plan lapse recorded,
beside that case's lapsed attestation, while every report from the store refuses with
`detection_time_missing` and so prints no warning. Once the case is attested, the report compiles,
warns, and reads the recorded lapse with no note. The lapse depends only on the case, the planned
time and the target, never on the detection time, and the derivation is the same function over the
same groups and evaluations as the warning; a report that refuses as a whole prints nothing.

### Decision 19: a second head type on the same stream kind, schema 8 (plan D8)

The stream kind stays `response-gap/<fingerprint>`. A plan lapse opens its stream with a new head
type, `response_gap.plan_lapsed` v1, followed by the one `observation.recorded` it mints. The head
has four fields, all required: `caseTrackingId`, `contextKey`, `estimatedAt`, and `targetRating`
as an integer from 1 to 5, as `case.evaluated` holds `pain`; the repository holds each to the
record field it restates, the target to the text its record spells. The append that writes the
head marks the store schema 8, migration record 8 ("planned response gap heads, ADR 0019"), chosen
by head type as `failure.held` marks 3 where `failure.recorded` marks 2. The two earlier kinds keep
`response_gap.recorded` v1 byte for byte, and a store that records only them stays at 7.
`SUPPORTED_SCHEMA_VERSION` is 8. Every contract stays at version 1.
Why: a build that cannot read the head must refuse the store at open rather than meet it as a
contract fault.

### Decision 20: store doctrine (plan D9)

The five `responsegap_*` audit codes cover the new kind with no new code. Incomplete and overfull
count heads of either type together; a stream mismatch includes a stream that opens with neither
head; an identity breach includes a record its writer does not mint, among them one ingested at or
before its planned time (the run ingests at its as-of, strictly after E), metadata that is not
exactly the three keys with the values its head states, a head of the other type, and a head that
names another case, key, instant or rating. `responsegap_schema_unmarked` gains a second text, as
the failure fault has: a `response_gap.plan_lapsed` head in a store below schema 8 names 8, at the
first such stream, before the schema 7 check. The incomplete, overfull, head order and write-once
texts now name both head types for every response gap stream, a PR 1 one included; the codes do not
change. The head is held to its own record alone. Whatever a report from the store refuses as a
fault of the log, `store verify` rejects. A missing detection time is not one: a report refuses an
untimed record with `detection_time_missing` until an attestation supplies the input it waits for,
and `store verify` passes the store, as it did before this record.

### Decision 21: notes where a store and its run disagree (plan D10)

`response_gap_unrecorded` names a plan lapse the run derives that no record carries.
`response_gap_contradicted` names a recorded plan lapse against which the store holds a reduction
to its target or below, dated from the current evaluation's `completedAt` through its planned time,
while the case's current evaluation still states that plan, the same planned time and target; the
note names the earliest such reduction. The contradiction test comes first. A recorded plan lapse
that is not contradicted stands with no note, whether or not the run still derives it: a plan
revised, met late or closed does not undo the fact that the planned time passed.
`response_gap_unmatched` and `response_gap_earlier_detection` cannot arise for this kind, since no
class, calendar zone or scan order enters its identity. Decision 11's gate holds: a store that
holds no response gap stream writes none of these notes, so the first plan lapse of such a store
reads with the warning alone until `cases response-gaps` records something, which is why a store
built from the warning golden's scan reports that golden byte for byte. Once the store holds a
response gap of any kind, a derived plan lapse no record carries is `response_gap_unrecorded`.

### Decision 22: goldens (plan D11)

No existing golden moved; the first step proved it before anything else was built. Two pairs are
new: `tests/golden/vdt-planned-reduction-warning.{json,md}`, a stateless run of one partly
mitigated finding whose plan passed, carrying only the warning, which a store built from the same
scan reports byte for byte; and `tests/golden/historical-planned-response.{json,md}`, cut from a
store that recorded the lapse and then correlated it. The nine existing tests the plan names now
carry the warning and pass unchanged.

### Decision 23: how the deliverable reads (plan D12, ruling 12a)

`docs/BUILD_PLAN.md` reads the lapsed planned response as Met and the response action records as
delivered with named limits: carried as the evaluation's planned and completed reductions, with
kind, owner and evidence not carried. Only the recurrence clocks, the third pull request, stay
open in the item.

### Decision 24: the remediation instant is untouched (plan D14)

A completed reduction never replaces the evaluation's `completedAt` as the remediation instant of
Decision 1, which would move this record's earlier identities.

### Limits

- The record is only as frequent as the runs. A plan revised, met or closed before any run sees
  the lapse leaves no record.
- A projection stated with a planned time before its own `completedAt` has an empty window: it
  warns on the first report past its time and is recorded by the first run. That is a stale plan
  carried into a new evaluation, and it is read as one.
- On the store path a reduction an earlier file stated and a later one dropped is still in history
  and still counts inside the window; a stateless run of the later file never sees it.
- A system record's plan never lapses, as a system record never recurs (Decision 2). A lapse
  about a failure record is left for a later ruling.
- A plan to remediate cannot be stated, so it cannot lapse.
- A projection whose target is not below the current rating never lapses. Whether to warn about
  one is left out.
- Instants are read to the microsecond, as `docs/SECURITY.md` and `docs/DATA_MODEL.md` already
  say of every clock: two planned times, or a planned time and a reduction, less than a
  microsecond apart compare equal, so they are one plan, or a reduction at the planned time. This
  is a documented limit with no code change (Kyle's ruling on audit finding C01, 2026-11-27).

### Compatibility (2026-11-27)

A store a 0.5.0a0 build wrote, and one a build at `09193ab` wrote, open and read identically
before a plan lapse is recorded. The trial built a schema 6 store with 0.5.0a0 (installed from
PyPI) holding a failure, coverage gaps, changes and change gaps, and a schema 7 store with
`09193ab` holding the same plus a recurrence and a lapsed attestation. `store verify`, `cases
list`, and `report vdt` with and without an inventory, `report historical` and `report avi` gave
the same bytes under the old and the new build at an as-of equal to the stores' one planned time.
At a later as-of the schema 6 store's reports differed only by the new warning; the schema 7
store, which already holds a response gap, also gained `response_gap_unrecorded` for the unrecorded
plan, as Decision 21's gate says. The new build's reads left each store's bytes and version
unchanged. `cases response-gaps` from the new build at the planned time recorded
nothing and kept each store's version; past it, it recorded the plan lapse and marked the store 8
(from 6, migration records 7 and 8). Both older builds refuse a schema 8 store at open ("database
schema 8 is newer than supported schema 6" and "... schema 7"), and their `store verify` reports
`schema_version_unsupported`. No parser version moves.

### Rejected alternatives (2026-11-27)

- A new operator record of response actions, with a file, a command and an event (plan D1b). It
  states the plan a second time beside the official field and needs a reconciliation rule.
- Warning only, with no record (plan D2b). Kyle ruled the lapse a recorded case.
- Leaving accepted records out (plan D3b), or every record that publishes a final disposition
  (D3c). An accepted report still publishes the stale plan, and D3c skips the shipped example's own
  pattern, a partly mitigated record with work still planned.
- The pinned `VDR-TFR-PVR` target as the clock. Its lateness is already `overdueStatus`.
- A `response_gap.recorded` v2 beside v1, the first versioned contract and one that never
  replaces its v1; and adding the kind to v1 inside schema 7, which would make every new field
  optional or fail stores written since `09193ab`, and meet a build at `09193ab` as a contract
  fault instead of a refusal at open.

### Left for later (2026-11-27)

- The `VER-TFR-MHR` and `VER-TFR-MRH` recurrence clocks: the third pull request.
- A warning for a projection whose target is not below the current rating, and for a published
  projection on a remediated or fully mitigated record.
- The action's kind, owner and evidence, when a user asks for one.
