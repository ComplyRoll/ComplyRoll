# ADR 0010: Report projections from one record set

- Status: Accepted
- Date: 2026-09-05

## Context

Backlog item 7 of the build plan, the last open item of Phase 1, asked for the Accepted
Vulnerability Information report (`VER-RPT-AVI`) and the Historical VER Activity report
(`VER-TFR-MRH`) from the same record compiler that produces the Vulnerability Detail Report.
Both official schemas have been bundled and verified offline since ADR 0006, at version `0.1.1`
under the commit ADR 0009 pinned, but nothing compiled a document against either of them.

ADR 0007 built the stateless detail-report compiler, and ADR 0008 rebuilt the same report from
persisted history with a byte-identity test between the two paths. In that design
`compile_records` did two jobs: it turned normalized inputs into compiled vulnerability records,
and it selected which of those records the detail report publishes for its period. The second
job is the one that differs between the three reports. The detail report publishes active
records with activity in the period and sets accepted records aside. The accepted-vulnerability
report publishes only accepted records, with a rationale each, for a period. The historical
report has no period at all and publishes every record the provider knows about, split on
acceptance, as of one instant.

The persisted path added a fact the stateless path does not have. `complyroll cases evaluate`
writes `case.disposition_recorded` with a `recordedAt` of `iso_utc(now)`, the instant the command
ran, and the evaluations file it reads has no such field. Whether that instant may reach a report
decides whether the two paths can stay byte-identical for the new reports.

## Decision 1: one period-agnostic record set, three projections

`compile_records` is split at the point where selection began. `compile_record_set` turns
normalized inputs into a `CompiledRecordSet`: every compiled record in correlation order, the
order of the group key of source type, source record identifier, and context key, which is not
tracking-identifier order; the artifact manifest; the ingest and rebuild diagnostics, the rules and generator
provenance, the parser versions, and the `ReportOptions` of the run. Nothing in the set depends
on a report period. Two producers build it: `compile_record_set_from_artifacts` on the stateless
path and `compile_record_set_from_history` on the persisted path, the latter unchanged from
ADR 0008 apart from returning the set instead of a report.

Three projections read it. `project_vdt` is the detail report as before. `project_avi` selects
the accepted records for the period and publishes each as an `acceptedVulnerabilityInfo` item,
`vulnerabilityDetail` plus `acceptanceRationale`; the `x-complyroll` extension stays inside
`vulnerabilityDetail`, where every projection publishes it, and the wrapping item gets no
second extension block. `project_historical` publishes the whole set. `compile_vdt_report`,
`compile_avi_report`, `compile_historical_report`, and their `_from_history` twins are one-line
compositions of a producer and a projection, so a report built either way is the same function
of the same set. Each projection validates its document against its own bundled schema and
records that schema in `x-complyroll.schemaSource`.

The set's diagnostics are shared. Each projection copies them and appends its own selection
diagnostics after them, so a diagnostic raised at ingest or at rebuild, such as `stale_case` or
`artifact_superseded`, sits at the same position in every report. `_common_extension` gives the
three documents one shared `x-complyroll` block; the detail and accepted-vulnerability reports
add `excludedByPeriod` to it, and the accepted-vulnerability report adds `activeNotReported`.

`ReportOptions` becomes keyword-only and its period optional. `period_from` and `period_to`
default to `None`, must be given together, and keep the ordering check. `has_period` says
whether a period is present, and `period` returns the tuple or raises `ValueError`. Projections
that select by period call `_report_period(options, report_name)` first, which turns a missing
period into the compile error `report_period_missing` named after the report that needs it. The
historical projection never reads the period, so one `ReportOptions` can drive all three
reports in one run.

## Decision 2: the accepted-vulnerability period selects on activity instants alone

An accepted record is in the accepted-vulnerability report for a period exactly when
`_period_exclusion_reason` returns `None` for it, the predicate the detail report already applies
to disposed records: a record detected after the period ended is out, and otherwise a record
with a disposition is in when any of its activity instants falls inside the inclusive bounds.
`CompiledVulnerability.activity_instants` holds the detection instant, the evaluation's
`completedAt`, each completed PAIN reduction, and the projected next reduction. Every accepted
record has a disposition, so the activity test always applies. Each accepted record the period
leaves out is counted in `excludedByPeriod` and named in an INFO diagnostic, `excluded_by_period`,
whose message takes one of the helper's two forms: "was detected `instant`, after the period
ended `to`" for a record detected after the period, and otherwise "is accepted and no recorded
activity between `from` and `to`". The helper takes that standing, "is accepted", as its `state`
argument; without it the second form would carry the detail report's wording and print
`has disposition None`, because an accepted record has no final disposition. Active records are not a selection this report makes, so they get
no diagnostic and appear only as the `activeNotReported` count.

The acceptance instant is the `completedAt` of the evaluation that carries the acceptance. That
is the limitation to know: an acceptance recorded in a period whose evaluation completed in an
earlier period, with no other activity since, does not by itself place the record in the later
period's report. The evaluations file records no separate acceptance instant, so there is
nothing on the stateless path that could.

`case.disposition_recorded.recordedAt` is excluded from every report byte. On the persisted path
it is `iso_utc(now)` at `complyroll cases evaluate` time; on the stateless path it does not
exist. A report that read it would print a value that depends on when a command ran rather than
on what the provider recorded, and the two paths would disagree. The rebuild maps only the
case's current evaluation and its disposition status, closed disposition, and acceptance
rationale into the compiler. A test builds two stores whose evaluations were recorded eleven days
apart and proves the accepted-vulnerability and historical bytes are identical.

## Decision 3: the historical report is a periodless snapshot of the whole population

The historical projection takes no period and ignores one when the options carry it, so a
missing period is not an error there. `generatedAt` is `options.as_of`. `activeVulnerabilities`
holds every record that is not accepted, disposed records included, in record order;
`finalDisposition` is what distinguishes a disposed record from an open one, and the Markdown
twin prints it in the Disposition cell. `acceptedVulnerabilities` holds every accepted record as
the same `acceptedVulnerabilityInfo` item the accepted-vulnerability report publishes. The two
arrays partition the set; nothing is sampled and nothing is explained, so the projection appends
no selection diagnostics, and its extension is the common block alone, with no
`excludedByPeriod` and no `activeNotReported`. The document has no `reportPeriod` member either;
the official historical schema does not define one. Overdue status is computed against `as_of` exactly as
in the detail report. The Markdown twin has no Report period line.

Each record is its current state. The fold keeps every `case.evaluated` event and each
reduction's sequence, but the official `vulnerabilityDetail` item has one `evaluationCompletedAt`,
one `currentRating`, one disposition, and the `painReductionEvents` list, and the historical
schema's two arrays are lists of that item. A per-case evaluation timeline has no slot in it
and is not representable there, so the timeline stays on `complyroll cases history` and the
rebuild maps only `current_evaluation`. Because both paths read only current state, the
stateless and persisted historical reports are byte-identical by construction rather than by
declaring one of them degraded.

## Decision 4: a missing acceptance rationale stops the reports that publish it

The official `acceptedVulnerabilityInfo` item requires `acceptanceRationale`, and an empty string
would satisfy the schema while saying nothing. `_require_acceptance_rationales` runs at the top of
`project_avi` and `project_historical`. For every accepted record whose evaluation records no
rationale, or one that is blank once stripped, it raises one ERROR diagnostic,
`acceptance_rationale_missing`, naming the tracking identifier with the source record as its
location, all of them together in record order so an operator fixes the file once. Both inputs
already refuse a blank rationale, `parse_evaluations` for the file and the
`case.disposition_recorded` payload contract for the store, so this is a defensive invariant
rather than a path an operator can reach with the shipped writers.

The detail report keeps its side channel: `AcceptedVulnerability(record, rationale or "")` on
`report.accepted`. It sets accepted records aside and publishes neither them nor their rationale,
so failing that report on a fact it never prints would block the one report that does not need
the fact. The guard lives in the projections that publish the item, not in the record set.

## Decision 5: the Markdown twins are renderings, not the monthly report

Each report's Markdown twin is the consistent human-readable form of the same data that the
certification-data rules require (`CDS-CSO-CBF`), rendered from the same compiled records as the
JSON and reconciled against it by tests. No twin is the monthly human-readable report
`VER-TFR-MHR`, which is a MUST with its own content expectations that ComplyRoll has not mapped.
The historical report's retrieval cadence under `VER-TFR-MRH`, a SHOULD that the rule sets at
once a month for Class B and every 14 days for Class C, is the operator's to schedule; ComplyRoll
compiles the snapshot it is asked for at
the `as_of` it is given and schedules nothing.

## Consequences

- Two new commands, `complyroll report avi` and `complyroll report historical`, each with the
  stateless file form and the `--db` store form. The historical command takes no `--from` or
  `--to`. `report vdt` is unchanged and this decision moves none of its bytes.
- Four new goldens, `tests/golden/avi-fixtures.{json,md}` and
  `tests/golden/historical-fixtures.{json,md}`, compiled from the fixtures with
  `examples/evaluations-accepted.json`, which is `examples/evaluations.json` plus one accepted
  entry for `banner_etc_issue`. The accepted record's `overdueStatus` is exactly
  `{"isOverdue": false}`: the acceptance satisfies the response and categorization deadlines, and
  `explanation` is emitted only when a record is overdue. The accepted-vulnerability extension
  carries `activeNotReported` 5 and `excludedByPeriod` 0; the historical extension carries
  neither, the historical document has no `reportPeriod`, and its `generatedAt` is the run's
  `as_of`.
- Every `ReportOptions` construction is keyword-only, and a reader of `period_from` or
  `period_to` must handle `None` or go through `period`.
- The replay tests cover the two new projections the way ADR 0008 covered the first: golden
  bytes from a rebuilt store, agreement with the stateless compile across reversed ingest order
  and every ingest permutation of a fleet, and the recording-instant test that keeps Decision 2
  honest.
- `complyroll cases history` remains the only surface for a case's evaluation timeline.
- Phase 1 of the build plan closes with this record.

## Rejected alternatives

Three separate compilers, one per report, were rejected because the byte-identity claim of
ADR 0008 is a claim about one compiler, and three would have needed the claim proved three
times over three sets of drift. A period on the historical report was rejected because the
official document has no `reportPeriod` and the rule describes a snapshot of activity to date,
not a window; adding one would have invented a selection the schema cannot express. Using
`case.disposition_recorded.recordedAt` as the acceptance instant was rejected because it exists
on one path only and records when a command ran, so a report that read it would print bytes the
stateless path cannot reproduce. A `case.accepted` event, version 2, carrying an explicit
acceptance instant that both an evaluations file and a store could record, would remove the
Decision 2 limitation; it is listed here as future work and is not built now, because it changes
the input contract of both paths and nothing in the current rules requires the instant.
