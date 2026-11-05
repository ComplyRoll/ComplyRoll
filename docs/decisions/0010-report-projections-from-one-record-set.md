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

## Amendment 2026-10-19: the detail report applies Decision 2, and the snapshot counts both arrays

Found in a review of the slice against main, and decided by the maintainer.

The detail report set every accepted record aside and counted it in its Summary row "Accepted,
reported under VER-RPT-AVI", with an INFO `accepted_excluded` saying it belongs in that report.
That row predates Decision 2 and was left unchanged by it ("`report vdt` is unchanged"), so for a
period with no activity on an accepted record the two reports disagreed: September's detail
report counted the banner record of `examples/evaluations-accepted.json` as reported under
VER-RPT-AVI, and September's AVI report excluded it. The detail report now applies Decision 2's
predicate to accepted records. One the AVI of the period carries is set aside as before. One it
leaves out is excluded by the period in the detail report too: it is counted in
`excludedByPeriod` and the "Excluded by report period" row, and named by the INFO
`excluded_by_period` that the AVI report raises for it, in the same words. Every record of the
set still lands in exactly one of the detail report's three Summary rows, and the detail report's
accepted row equals the AVI report's "Accepted vulnerabilities reported" for the same period.

The historical Summary counted its Evaluated, Not yet evaluated, Overdue, KEV and Current PAIN
rows over `activeVulnerabilities` alone, while the snapshot publishes `acceptedVulnerabilities`
too (Decision 3), so the Markdown said fewer than the JSON carried: `historical-kev` published 9
records in the KEV catalog, 6 past their due date, and its Summary said 8 and 5, against ADR 0012
Decision 5's rule that an accepted past-due record is counted. Every row but the two array sizes
now counts both arrays. An accepted record is always evaluated and never overdue, so it moves the
Evaluated, KEV and PAIN rows and never the Overdue row.

No JSON byte moved and no detail or AVI golden moved: no golden compiles an accepted record
outside its period. Three historical Markdown twins moved in their Summary rows alone
(`historical-fixtures`, `historical-kev`, `historical-coverage-gaps`); `historical-failed`
holds no accepted record and is unchanged.

## Amendment 2026-11-04: the compiler module is split, with no behavior change

Cleanup item CL-72, decided by the maintainer. `reports/vdt.py` had grown to 3795 lines holding the
record compile, what the reports share and the detail report itself, so `avi` and
`historical` imported its private names and `history/` imported a report module. Decision 1 stands
as written: one record set, three projections. Only the modules they live in changed.

| Module | Holds | Names |
|---|---|---|
| `reports.model` | constants, diagnostics, options and the compiled record types | `DISCLAIMER`, `EXTENSION_KEY`, `GENERATOR_NAME`, `FINAL_DISPOSITIONS`, `ACTIVE_STATUSES`, `ReportDiagnostic`, `REPORT_DIAGNOSTIC_CODES`, `ReportCompileError`, `ReportOptions`, `DetectionAttestation`, `CompiledDeadline`, `CompiledArtifact`, `CompiledDetectionFailure`, `CompiledVulnerability`, `AcceptedVulnerability`, `ReportMetadata`, `CompiledReport`, `CompiledRecordSet`, `evaluation_location`, `iso`, `require_aware`, `_require_absolute_http_uri` |
| `reports.checks` | clock, order, tracking id and record-kind rules shared with `history/` | `_EVALUATION_RULE`, `_RESPONSE_RULE`, `_ACCEPTANCE_RULE`, `_SYSTEM_RECORD_KINDS`, `system_record_kind`, `CLOCK_OUT_OF_RANGE`, `EvaluatedClock`, `clock_problem`, `_clock_deadlines`, `detection_clock_message`, `evaluation_clock_message`, `observation_clock_message`, `detection_clock`, `resolve_detection_time`, `_ORDER_REMEDIES`, `_SYSTEM_ORDER_REMEDIES`, `evaluation_order_diagnostic`, `_is_system_group`, `TRACKING_ID_COLLISION`, `TrackingIdClaim`, `ClaimT`, `published_tracking_id`, `tracking_id_collisions`, `tracking_id_collision_message` |
| `reports.records` | the record compile: ingest, evaluation match, KEV, coverage, deadlines | `_KEV_RULE`, `_CVE_PREFIX`, `compile_record_set_from_artifacts`, `compile_record_set`, `_artifact_order`, `_diagnostic_order`, `_unresolved_order`, `_Reading`, `_ingest_all`, `_collect_diagnostics`, `_warn_duplicates`, `_record_detection_failure`, `_ElectedReading`, `_elect_reading`, `_require_artifact`, `_match_evaluations`, `_matches`, `_detection_failure`, `_ordered_detection_failures`, `_is_numeric_version`, `_numeric_version`, `_require_unique_tracking_ids`, `_require_kev_catalog_by_as_of`, `_kev_rule`, `_kev_diagnostics`, `_kev_location`, `derive_report_coverage`, `_coverage`, `_selects`, `_coverage_belongs`, `_window_gap_ids`, `_coverage_gap_divergences`, `_disproving_evidence`, `_underived_gap`, `_gap_window`, `_gap_order`, `coverage_diagnostics`, `_records_carry`, `_build_record`, `_canonical_reductions`, `_describe`, `_compute_deadlines`, `_compiled`, `_kev_deadline`, `_kev_clause`, `_explanation`, `_optional_adoption_notice`, `_obtain_dates`, `_reachability`, `_exploitability`, `_parser_versions` |
| `reports.projection` | period, acceptance, extension block and schema check helpers the report projections share | `attested_instant`, `attestation_groups`, `report_period`, `require_acceptance_rationales`, `_acceptance_rationale`, `accepted_vulnerability`, `period_exclusion_reason`, `schema_provenance`, `validate_document`, `common_extension`, `report_period_block`, `_attestation_block` |
| `reports.markdown` | the section writers the three Markdown twins share | `_RECORDED_WINDOW_NOTE`, `write_kev_summary`, `write_header`, `write_provenance`, `_vulnerability_row`, `write_vulnerability_table`, `write_attestation_section`, `_system_detection_sentence`, `write_inputs`, `_write_detection_failures`, `write_coverage`, `_coverage_resource_row`, `_write_coverage_evidence`, `_coverage_evidence`, `_coverage_ref`, `_drift_label`, `_optional_iso`, `write_diagnostics_section`, `write_footer`, `_disposition_label`, `_write_detail`, `_KEV_TAILS`, `_kev_line`, `_write_observation_ids`, `_flag`, `_cell` |
| `reports.vdt` | the Vulnerability Detail Report and nothing else | `CompiledVdtReport`, `compile_vdt_report`, `compile_records`, `project_vdt`, `_select_for_period`, `_keeps_open_kev_work`, `_build_document`, `_render_markdown` |

`coverage_label` joined `reports.coverage`, the one thing that would otherwise tie `markdown` to
`records`. The coverage group stays in `reports.records` because one patch of `select_policy` has to
cover every reader of it in the compile, and `history/` could not be free of the pipeline anyway:
`fold` and `order` read `reports.replay`, which imports it. What `history/` read from `reports.vdt`
now comes from `model`, `checks` and two names of `records`. `model` and `checks` import nothing
from `records`, `projection`, `markdown` or `vdt`. Moving them below `reports/` would also take
`coverage`, `evaluations`, `gaps`, `inventory` and `kev`. That move is not scheduled.

No behavior moved. Each definition was cut by script and compared by AST with the module before the
split: identical after the rename table below, apart from three docstrings and one comment that
named or pointed at something that moved, with every other string constant byte for byte and every
other comment token for token. No golden, fixture or example changed.

A name became public only where another `src` module imports it, so 23 names changed spelling. Every
other name kept its spelling, and a name only tests reach stayed private where it landed.

| Before the split | Now |
|---|---|
| `_accepted` | `reports.projection.accepted_vulnerability` |
| `_accepted_info` | `reports.avi.accepted_info` |
| `_attestation_groups` | `reports.projection.attestation_groups` |
| `_attested_instant` | `reports.projection.attested_instant` |
| `_common_extension` | `reports.projection.common_extension` |
| `_coverage_label` | `reports.coverage.coverage_label` |
| `_iso` | `reports.model.iso` |
| `_period_exclusion_reason` | `reports.projection.period_exclusion_reason` |
| `_report_period` | `reports.projection.report_period` |
| `_report_period_block` | `reports.projection.report_period_block` |
| `_require_acceptance_rationales` | `reports.projection.require_acceptance_rationales` |
| `_require_aware` | `reports.model.require_aware` |
| `_schema_provenance` | `reports.projection.schema_provenance` |
| `_validate_document` | `reports.projection.validate_document` |
| `_write_attestation_section` | `reports.markdown.write_attestation_section` |
| `_write_coverage` | `reports.markdown.write_coverage` |
| `_write_diagnostics_section` | `reports.markdown.write_diagnostics_section` |
| `_write_footer` | `reports.markdown.write_footer` |
| `_write_header` | `reports.markdown.write_header` |
| `_write_inputs` | `reports.markdown.write_inputs` |
| `_write_kev_summary` | `reports.markdown.write_kev_summary` |
| `_write_provenance` | `reports.markdown.write_provenance` |
| `_write_vulnerability_table` | `reports.markdown.write_vulnerability_table` |

`_accepted` is not `accepted` because `project_historical` binds a local of that name and reads the
function in the same scope.

`complyroll.reports` exports what it did, each name the same object. `reports.vdt.__all__` is
`CompiledVdtReport`, `compile_records`, `compile_vdt_report` and `project_vdt`, and nothing is
re-exported for what left. `vdt.py` imports only what it reads, so a moved name it still reads, such
as `ReportOptions`, can still be imported from it, and that is no promise. A name it does not read
is gone, so a test still patching `select_policy` on that module raises `AttributeError` rather than
rebinding a name nothing reads there.

ADRs 0008, 0012, 0013, 0014 and 0015 and the sections above cite `reports.vdt`, `vdt.py` lines and
the old spellings as they stood when written, and they stay unchanged. These two tables are where a
reader following one of those citations lands.
