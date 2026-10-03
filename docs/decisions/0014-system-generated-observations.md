# ADR 0014: System-generated observations for detection process failures

- Status: Accepted
- Date: 2026-09-30

## Context

VDR-CSO-FAV, "Failures Are Vulnerabilities", reads in the pinned rules dataset: "Providers MUST
treat problems or failures with their vulnerability detection and response processes as
vulnerabilities." `AGENTS.md` carries the same rule as a domain invariant: "A detection or
response process failure is itself eligible to become an observation and case."
`docs/BUILD_PLAN.md` lists the Phase 2 deliverable "System-generated observations for failed
imports, stale coverage, missing resources, or broken response workflows" and the exit criterion
"A failed or stale detection process creates a reviewable vulnerability case", and backlog item
9 asks for a failed SARIF invocation to become evidence of a detection gap instead of an error.

Before this ADR a failed detection was an error and nothing more. On the stateless path
`_ingest_all` in `reports/vdt.py` raised `ReportCompileError` on any reading's ERROR, so
`report vdt|avi|historical` exited 1 and wrote nothing. `ingest` parsed every artifact before it
opened the store and returned 1 on the first ERROR, so the store learned nothing either. A SARIF
run whose invocation said `executionSuccessful: false` was WARNING `execution_unsuccessful` (ADR
0011 Decision 13): the artifact imported and the run exited 0. Each failure reached a terminal
and none reached a report, so none had a tracking id, a detection time, an evaluation clock, or
a lifecycle. `ObservationOrigin.SYSTEM` and its identity recipe have existed since the
2026-08-21 amendment to ADR 0002, but nothing built a system observation.

This ADR turns a failed detection into a vulnerability record when the operator asks for it. It
claims the detection-process half of VDR-CSO-FAV only: a truncated or corrupt scanner output, a
result file with no usable content, and a scanner that reports its own failed invocation.
Response-process failures and missing attestations are a recorded scope change (Decision 17).
Stale coverage, unseen resources, and the clean scan belong to the coverage and freshness slice.

## Decision 1: three failure classes, one closed vocabulary

`classify_ingest` in `adapters/failures.py` takes one `IngestResult` and returns None for a
reading with no ERROR and no failed invocation, or a `FailureClassification` that names exactly
one of a `FailureClass` and an `UnmintableReason`. It reads diagnostic codes, levels, and three
structured fields on the result, `format_rejected`, `failed_execution_at`, and `withheld`, and
never message text. A mintable failure is exactly one class, checked in this order, first match
wins:

1. `execution`: any `execution_unsuccessful` diagnostic. A SARIF log whose only run failed and
   reported null results carries `execution_unsuccessful`, `results_unknown`, and
   `no_observations`, and is `execution`.
2. `parse`: ERROR `artifact_parse_failed` without `format_rejected`. That covers truncated or
   corrupt bytes and the input bounds (`InputLimitError`, `UnsafeXmlError`), which the
   dispatcher `ingest_stig_artifact` reports under that code.
3. `content`: every ERROR code is in `CONTENT_CODES` (`invalid_stig`, `invalid_rules`,
   `invalid_rule`, `invalid_run`, `invalid_result`, `rule_id_missing`,
   `identity_input_invalid`, `invalid_profile`, `invalid_control`, `no_observations`), and the
   reading neither has observations nor withheld any it read (`result.withheld`).

A sole `no_observations` is `content`. A CKLB STIG with `rules: []`, a CKL with no VULN, an
XCCDF TestResult with no rule-result, an HDF document with no control observations, and a SARIF
log whose every run has null results each read nothing, and an empty result is not a clean scan.
A CKLB whose `stigs` array is empty is a format rejection instead (Decision 2).

The vocabulary is closed and fails closed. `PARSE_CODES` and `CONTENT_CODES` make
`CLASS_CODES`; `UNMINTABLE_CODES` holds `artifact_read_failed`, `unsupported_artifact`,
`duplicate_observation_identity`, and the three CCI map loader codes, which never reach an ingest
result. An ERROR code outside `CLASS_CODES` is the `unknown_code` refusal, so a new adapter error
stays fatal until someone classifies it. `VocabularyWalkTests` in `tests/test_failures.py` walks
every `DiagnosticLevel.ERROR` emission site under `adapters/` by AST and asserts that its code is
in exactly one of `CLASS_CODES` and `UNMINTABLE_CODES`, so a new site is found without editing
the test.

## Decision 2: some failures stay fatal

A reading with an ERROR is checked for an unmintable reason first, in this order
(`_unmintable_reason`), and a refused reading behaves exactly as it did before this ADR: its
ERRORs are printed, the report or the ingest exits 1, and nothing is written. On the stateless
report the mintable failures read in the same run print their own ERRORs too, so the run names
every failed file exactly as it would without the flag. `ingest` stops reading at the first reading
it refuses while reading it, which is every reason but `read_elsewhere`. It names that reading and
then every mintable failure read before it, and a file listed after it is not read. `read_elsewhere`
is decided only once every file is read. A run refused for it names every mintable failure it read
in listed order, the refused reading included. When the store decides the refusal (Decision 13),
those lines come after one ERROR `failure_read_elsewhere` per refused reading, in name order.
Without the flag `ingest` names only the first failed file. One more refusal comes after the writes
and is not an unmintable reason: a mintable failure, side records included, whose system observation
a superseded failure stream holds and that no reading of the digest would supersede at birth
(Decision 13). That run writes one ERROR `failure_held_by_superseded_stream` per refused reading, in
name order, between the diagnostics each reading wrote as it was read and every held failure's own
diagnostics in listed order. It exits 1 with nothing written, so with the flag a side record can
stop a run that would exit 0 without it.

| Reason | Condition | Why |
|---|---|---|
| `no_digest` | `result.artifact` is None (`artifact_read_failed`, the size cap) | no identity |
| `unsupported` | an ERROR `unsupported_artifact` | operator input |
| `format_rejected` | `result.format_rejected` | operator input |
| `duplicate_identity` | an ERROR `duplicate_observation_identity` | the reading has findings |
| `partial_reading` | `result.observations` is not empty, or the adapter withheld observations it read; SARIF and HDF fail closed | minting would drop findings |
| `unknown_code` | any ERROR code outside `CLASS_CODES` | fail closed |
| `clean_scan` | see below | coverage slice |
| `read_elsewhere` | assigned by the caller, see below | no double report |

`format_rejected` is a structured flag, so the classifier never reads message text to tell a
wrong kind of file from a broken one. The dispatcher sets it for an `AdapterParseError` only,
and `XccdfAdapter.parse` sets it for a Benchmark with no TestResult. The adapters raise one for
a CKLB root that is not an object or has no non-empty `stigs` array; an XML root that is not the
claimed format; a SARIF root that is not an object, a `version` other than `2.1.0`, or `runs`
that is not an array; and an HDF root that is not an object, one that carries `stigs`, a
`baselines` or `controls` root, `profiles` that is not a non-empty array, a `platform` that is
not an object, or no non-empty `version` string. `test_every_parse_error_site_is_a_case` pins
one case per raise site, and each reachable case reads as a format rejection through the
dispatcher. The emptiness checks differ: HDF `profiles: []` is rejected, while profiles that
carry no controls, or a SARIF log with `runs: []`, is a reading with no observations and the
content class. A bound exceeded, or any other `ValueError` or `TypeError`, is a parse failure.

`withheld` is a structured flag too. The SARIF and HDF adapters withhold every observation once
a reading has an ERROR, so a log with one good run and one broken run returns none. Each sets
`withheld` when it read at least one observation and withheld it (`_ArtifactParse.run`,
`_HdfParse.run`), and the dispatcher passes it through, so that log is a `partial_reading` and
never `content`.

`clean_scan` holds when the ERROR codes are exactly `{no_observations}`, at least one INFO
`run_clean` is present, and neither `execution_unsuccessful` nor `results_unknown` is. That is
backlog item 9's clean scan, which the coverage slice owns.

`read_elsewhere` is not decided by `classify_ingest`, which sees one result.
`FailureClassification.read_elsewhere` assigns it, and only the stateless path calls it, when the
same bytes read successfully under another name in the same run. `ingest` refuses the same condition
without assigning the reason: within the run it exits 1 with the failed reading's own ERRORs, and
against the store it writes ERROR `failure_read_elsewhere` (Decision 13).

## Decision 3: opt-in per run

`--record-failed-imports` on `report vdt`, `report avi`, `report historical`, and `ingest` turns
a mintable failure into a system observation. Its help text is "record a detection process
failure (VDR-CSO-FAV) as a system observation instead of stopping; exits 3 when one is
recorded". Without the flag every path behaves as it did before this ADR: a fatal class exits 1
with nothing written, and an execution failure stays a non-fatal WARNING with exit 0 and the
report or store written. With the flag, a failure stops `ingest` only for the reasons Decision 2
lists, and in one more case: a failure whose system observation a superseded failure stream holds,
and that no reading of its bytes would supersede at birth, exits 1 with nothing written, a side
record included (Decision 13). The help text keeps its wording, and this ADR and the README carry
the exception. The compiler takes a keyword, `record_failed_imports: bool = False`, on
`compile_record_set_from_artifacts`, `compile_vdt_report`, `compile_avi_report`, and
`compile_historical_report`; `ReportOptions` is untouched, because replay shares it and the flag
means nothing there.

## Decision 4: one identity for every class

`system_observation_for` in `adapters/failures.py` builds the one system observation of a
mintable failure:

| Field | Value |
|---|---|
| `source_type` | `complyroll.detection-process` |
| `source_tool` | `complyroll` |
| `parser_name`, `parser_version` | `complyroll.detection-failures`, `1` |
| `source_record_id` | `detection-process-failure` |
| `resource` | `ResourceRef(resource_id="sha256:<digest>", resource_type="artifact")` |
| `context_key` | `sha256:<digest>` |
| `disposition`, `source_severity` | OPEN, UNKNOWN |
| `source_identifiers` | empty |
| `evidence_ids` | `("sha256:<digest>",)` |
| `title` | `source artifact sha256:<digest> did not yield complete detection results (VDR-CSO-FAV)` |
| `description` | empty |
| `origin` | SYSTEM, with the artifact name and digest empty |
| `observed_at` | Decision 6 |
| `ingested_at` | the failed reading's `ingested_at` |
| `observation_id` | `derived_observation_id`, the ADR 0002 SYSTEM recipe |

The observation is built with `Observation(...)` by keyword and then given its derived id with
`replace`, because `make_observation` is artifact-bound. The identity inputs are the constants
above, the digest, and the instant, so the id never depends on the artifact's name, the ingest
time, the failed reading's parser, or the class. A later parser that reads the same bytes and
fails another way does not move it.

The title holds for all three classes, names the rule, and tells two failures apart by digest,
and no untrusted text reaches it. `_describe` in `reports/vdt.py` renders the official
description as `detection-process-failure: source artifact sha256:<digest> did not yield
complete detection results (VDR-CSO-FAV)`.

The class, the codes, and the failed reading live in metadata, sorted by key:

| Key | Value |
|---|---|
| `artifact.name` | `diagnostic_text(name)`, at most 512 characters |
| `artifact.sha256` | the digest |
| `artifact.sizeBytes` | decimal |
| `artifact.mediaType` | from the dispatcher |
| `artifact.parser`, `artifact.parserVersion` | the failed reading's parser |
| `failure.class` | `execution`, `parse`, or `content` |
| `failure.codes` | the reading's sorted distinct ERROR codes, `encode_list` |
| `failure.clock` | `invocation` or `as-of` |
| `failure.rule` | `VDR-CSO-FAV` |

`failure.codes` adds `execution_unsuccessful` for the execution class, so a side record's list
is never empty. No key is named `truncated`, so the KEV enrichment's `cve_may_be_missing` stays
False for a system record.

## Decision 5: the resource is the artifact

`artifact` joins the resource types beside `host`, `image`, `file`, `logical`, and `scan` as a
permanent identity input, and its id is `sha256:<digest>`, never the name: two names for one set
of bytes are one resource, and a rename cannot open a second case.

The evidence file is not an information resource in the FRD-VLD sense. The affected thing is the
detection process that produced it, and ComplyRoll does not know that process's identity: no
scanner inventory exists until the coverage and freshness slice. The digest is the only stable
handle this slice has. One case per failing process is a rejected alternative for now and the
seam the coverage slice opens: once an expected detection job exists, a failure can name it and
the case can move to it by a tracking-id override, with no change to this recipe.

## Decision 6: observed_at

An execution failure takes the failed invocation's own clock when the scanner declared one, and
its `failure.clock` is `invocation`. The SARIF adapter collects it in the same pass as the run
clock (`_run_clock` in `adapters/sarif.py`), so no clock diagnostic is emitted twice, and runs
that pass right after the `execution_unsuccessful` WARNING, before any later identity check can
refuse the run: the earliest `startTimeUtc` among invocations with `executionSuccessful: false`,
else the earliest `endTimeUtc` among them. `_ArtifactParse.run` returns it as
`failed_execution_at`, and the clock is used as declared, exactly as an artifact observation's
source timestamp is.

Every other failure, and an execution failure with no declared clock, takes the instant
ComplyRoll saw the failure, and its `failure.clock` is `as-of`. On the stateless path that is
the report's `--as-of`, the instant `_ingest_all` already hands the dispatcher. On the persisted
path it is the ingest's `--as-of`, or the current time at second precision when none is given.
Neither is clamped to a report period.

This instant is the time ComplyRoll detected the failure, not a substitute for a scanner
timestamp, so ARCHITECTURE's rule against substituting ingestion time for a detection time does
not apply. `failure.clock`, and `clock` in `detectionFailures`, let a reader tell the two kinds
of instant apart.

## Decision 7: one case per failing digest

Correlation groups by `(complyroll.detection-process, detection-process-failure,
sha256:<digest>)`, so the tracking id is `tracking_id_for` over those three values and is stable
per digest. A failure seen again under a new name or in a new run lands on the same case, and
`detection.detectionSource` is `complyroll`.

The lifecycle uses the existing dispositions:

- `remediated`: a rerun produced good bytes, or the pipeline that wrote the bad output was fixed.
  On the persisted path a later good reading of new bytes is a different digest, so the operator
  closes the old case.
- `false_positive`: there was no real failure, for example a misnamed text file the classifier
  minted a parse failure for.
- `fully_mitigated`: only for a failure that persists while its risk has been reduced.
- A parser upgrade that reads the same bytes supersedes a parse or content failure (R3, Decision
  13), and the case reads INFO `stale_case`.

## Decision 8: `detectedAtSource` is `system`

`_resolve_detection_time` in `reports/vdt.py` checks for a system group first (`_is_system_group`)
and returns the group's earliest `observed_at` with the source `system`. `--detected-at` still
applies to untimed artifact records in the same run and never to a system record, and
`cases attest-detection` never attests a system case, because its link is timestamped
(`_any_link_is_timestamped` in `history/writers.py`). In the documented persisted recipe
`--all-missing` selects 6 cases, not 9.

## Decision 9: conditional rendering only

Each new part of a report appears only when the record set holds at least one system
observation, and no existing golden moved.

- `detectionFailures` in `x-complyroll`, derived in `compile_record_set` from the system
  observations' metadata, so both paths build it from the same inputs. Each entry is `{name,
  sha256, sizeBytes, parser, parserVersion, failureClass, failureCodes, observedAt, clock,
  trackingId}`, where `trackingId` is the effective id of the record holding that observation,
  after any evaluation or provider override. `_ordered_detection_failures` sorts by name,
  sha256, parser, parser version (compared as `history.fold._newest_stream` compares them),
  observedAt, and the version as written, which is a total order: the persisted path can hold
  several current failures of one digest. The list sits in the record set, so it is present even
  when the record is excluded from a period. `CompiledDetectionFailure` is the entry's type and
  is exported from `complyroll.reports`.
- `parserVersions` gains `complyroll.detection-failures: "1"` whenever a system observation was
  minted, because `_parser_versions` reads every observation in the record set, reported or not.
- Markdown: `### Detection process failures` under Inputs (`_write_detection_failures`), a table
  of Artifact, SHA-256 (a 12-character prefix), Parser (name and version), Class, Observed at,
  Clock, and Tracking ID. Every cell passes `_cell`.
- `_write_attestation_section`: when no record was attested and a reported record is a system
  record, the sentence reads "Every reported vulnerability carried a detection time from its
  source artifact or, for a detection process failure, from the instant ComplyRoll or the
  scanner recorded it. No attestation was needed." Otherwise it is unchanged. A unit test pins
  the sentence, because the goldens attest their untimed fixtures.
- AVI and historical count attested records by `"attestation"`, so `system` never counts. AVI
  lists a system record only if an evaluation accepts it; historical lists it like any record.

## Decision 10: PAIN only from an evaluation

A system record is UNKNOWN severity, carries no identifiers, and gets PAIN, reachability, and
exploitability only from an evaluation that matches it; nothing is derived from the class or the
codes. EVU runs from the detection time for the selected class.

The documented evaluation match is the full triple `{"sourceRecordId":
"detection-process-failure", "sourceType": "complyroll.detection-process", "contextKey":
"sha256:<digest>"}`. A hostile CKLB can mint an ARTIFACT observation with the same record id and
context key (group id `detection-process-failure`, STIG id `sha256:<digest>`), but it can never
carry the source type (Decision 14), so the triple matches the system record alone. An entry
without `contextKey`, with or without `sourceType`, matches every system record and is refused
in one of two ways, ambiguity first. On the stateless report two or more matches are refused with
`evaluation_ambiguous`, whose message names each matching tracking id and then the match keys the
entry leaves out: "add contextKey" when it gives `sourceType`, and "add contextKey or sourceType"
when it gives neither (`EvaluationMatch.ambiguity_remedy`). An entry that gives `contextKey` but
not `sourceType` matches a hostile record beside the system one and is told "add sourceType". A
single system record matched without `contextKey`, as in a run with one failure, is refused there
with `evaluation_context_key_required`, whose message names the tracking id and says a detection
process failure is matched by `sourceRecordId`, `sourceType` and `contextKey` together.
Accepting it would let a file that applies today turn ambiguous once a failure of another digest
is recorded. `reports.vdt` and `cases evaluate` apply both refusals in the same order and share
the remedy and the context-key text (`EvaluationMatch.ambiguity_remedy` and
`EvaluationMatch.context_key_required`). `cases evaluate` prints both under
`evaluation_unmatched`, as it prints every match it cannot apply, and its ambiguity message says
"cases" where the report's says "vulnerabilities" and orders the tracking ids differently. Both
are tested on both paths.

On the stateless path a failure observed at the as-of is detected again at every run's as-of,
so an evaluation file reused across runs predates the later runs' detection. The compiler does
not check that order; that is pre-existing behavior for any evaluation and is recorded for
review. The persisted path fixes the instant at ingest.

## Decision 11: exit 3 when a failure was recorded

`EXIT_DETECTION_FAILURES = 3` in `cli.py`. `_run_report` returns 3 when the flag was given, the
report was published, and `metadata.detection_failures` is not empty; the output is still
written. `ingest` returns 3 when it recorded a failure or found one already recorded, after it
has published the store and printed its lines, so a rerun of the same inputs prints
`already_recorded` and still exits 3. A failure another failure stream holds prints
`already_recorded` too, with WARNING `failure_held_by_another_stream` in place of
`detection_failure_recorded` (Decision 12). One rerun exits 1 instead. If the first run's failure
was held by another stream and a later ingest has superseded that holder, the rerun meets the hold
again and is refused (Decision 13). A side record keeps the WARNING and exit 3 instead when a
reading of the digest, current or superseded, would supersede its failure at birth under R4; a pure
failure in that position is refused before the writes with `failure_read_elsewhere` (Decision 13),
so it exits 1 either way. Exit 0 would turn a loud failure quiet, and exit 1 already means nothing
was written. The failures' diagnostics wait for the publish too, and a run that exits 1 instead
writes each held reading's own diagnostics, ERRORs included, so it names every failed file it read
(Decision 2) and never claims a recording it then discarded.

`report ... --db` keeps 0 and 1 even when the store holds failures: the failure was signalled
with 3 when `ingest` recorded it. `report ... --db --record-failed-imports` is refused by
`_report_source_conflict` ("report vdt takes either --db or --record-failed-imports, never
both"), because a store already recorded or refused its failures at ingest.

## Decision 12: a `failure/` stream kind and a `failure.recorded` v1 event

A failure is recorded on its own stream, `failure/<sha256>/<parser_name>/<parser_version>`, named
for the failed reading's parser (`failure_stream_id`, `failure_stream_components`,
`is_failure_stream`, and `stream_kind` returning `failure`, in `events/contracts.py`). The
execution class records its failure stream beside the artifact stream rather than on it, because
the artifact identity check would refuse a SYSTEM observation there.

The head is `failure.recorded` v1 (`FAILURE_RECORDED_V1`):

| Field | Contract |
|---|---|
| `name` | non-blank text, `diagnostic_text` applied |
| `sha256` | a lowercase SHA-256 |
| `sizeBytes` | a count |
| `mediaType`, `parserName`, `parserVersion` | non-blank text |
| `ingestedAt` | a timestamp |
| `failureClass` | `execution`, `parse`, or `content` |
| `failureCodes` | at least one, unique, each from `FAILURE_CODE_VALUES` |
| `clock` | `invocation` or `as-of` |
| `diagnostics` | at most `FAILURE_DIAGNOSTIC_CAP + 2` entries |

There is no `trackingId`: it is a pure function of the stored observation and is derived at
replay, identically on both paths. The head is followed by exactly one `observation.recorded`
carrying the system observation. The head's `diagnostics` is the `failure_diagnostics` list
(Decision 14) for a failed reading, and only `detection_failure_recorded` for a side record,
whose artifact stream head already holds the `execution_unsuccessful` WARNING, so replay emits
every diagnostic once, as the stateless path does.

Placement is a table of three kinds: `observation.recorded` goes on artifact and failure
streams, `failure.recorded` on failure streams only. `_placement_problem` checks at import that
the three sets cover the event types, that case types share nothing with the other two, and that
`observation.recorded` is the only type artifact and failure streams share.

`record_failure` in `history/writers.py` writes the head and the observation in one transaction.
An existing stream holding both is `already_recorded`; a half-written stream is refused rather
than resumed. One observation id is stored once per digest across failure streams: when another
failure stream of the digest already holds it (the same bytes under two parsers at one instant, or
an execution failure with a declared clock read again by another parser or version), the writer
reports `already_recorded`, writes nothing, drops the `detection_failure_recorded` notice, and adds
WARNING `failure_held_by_another_stream` naming that stream (`_held_by_another_stream`), whether it
is an older or a newer version, the same version spelled another way, or another parser. A rerun
finds the reading's own stream and stays silent. The WARNING says no failure was recorded under the
reading's parser and version and it stays recorded under the holder's. For a held failure nothing of
the reading reaches history. For a side record the reading's artifact stream is recorded as usual,
and R1 to R4 then decide over every stream of the digest, the holder's failure stream included.
Usually the reading is current by R1 and only the `detectionFailures` entry is the holder's. When
the holder is a held failure under the same parser at a newer version and every artifact stream of
the digest is under that parser, R2 supersedes the reading's artifact, so the persisted report
carries the holder's failure and none of the reading (INFO `artifact_superseded_by_failure`). A hold
is not kept when the holder ends the run superseded and the reading's failure would not be
superseded at birth. Recording the failure would then leave its system observation in no persisted
report, so `ingest` refuses the run (Decision 13). One such hold is a parse or content holder that
the side record's own artifact outranks under R3. A held failure whose holder an earlier reading
already superseded is refused the same way. The holder is found by the digest's prefix alone, so the
writer folds the store (`artifact_history`) before it parses the holder's id, and a failure stream
id that names no reading is refused there with a `HistoryError`, which `ingest` reports as
`history_invalid`.

The once-per-digest rule is enforced at append (`failure_identity_breach` and
`failure_duplicate_observation_message` in `events/repository.py`), at read (`_read_failure_streams`
raises unless each stream is one head and one observation), and in the audit, which gains
`failure_incomplete`, `failure_overfull`, `failure_stream_mismatch`,
`failure_duplicate_observation`, and `failure_schema_unmarked`. `failure_identity_breach` requires
the head's `sha256`, `parserName`, and `parserVersion` to match the stream id, and the observation
to be SYSTEM, carry the source type `complyroll.detection-process`, carry `sha256:<digest>` as its
context key and resource id, and carry its derived id. The fingerprint covers none of the
observation's metadata and replay renders `detectionFailures` from it, so it also requires exactly
the ten keys `system_observation_for` writes (`FAILURE_METADATA_KEYS`): `artifact.sha256`,
`artifact.parser`, and `artifact.parserVersion` equal to the stream id's, `artifact.sizeBytes`
spelled as a count, `failure.class` and `failure.clock` from their vocabularies, `failure.codes`
spelled exactly as the writer stores it, the compact JSON array (`encode_list`) of at least one
code from `FAILURE_CODE_VALUES`, sorted and distinct, and `failure.rule` equal to `VDR-CSO-FAV`.
The writer appends the head first, and the append refuses a failure stream that an observation
opens. `_read_failure_streams` and the audit see both events, so they also require the head to
come before the stream's observation, and the head's `name`, `sizeBytes`, `mediaType`,
`failureClass`, `failureCodes`, and `clock` to equal the observation's `artifact.name`,
`artifact.sizeBytes`, `artifact.mediaType`, `failure.class`, `failure.codes`, and `failure.clock`
(`failure_record_disagreement`), so a head that lists its codes in another order is refused too.
The reader raises on either, and the audit reports each as `failure_stream_mismatch`.

## Decision 13: supersession across kinds, rules R1 to R5

Per digest, `_split_streams` in `history/fold.py` decides which artifact and failure streams are
current. It is the one split both `artifact_history` and `rehydrate_observations` read, so a
report and `cases correlate` can never disagree, and `cases correlate` creates and links system
cases with no other change.

- **R1.** The artifact winner W is the newest artifact stream, by `_newest_stream`, as before.
- **R2.** W is superseded by a failure stream under W's parser name at a strictly newer version,
  but only when every artifact stream of the digest is under that parser name: a newer parser
  that can no longer read bytes an older one read. A side record never triggers it, because its
  own artifact stream sits at its version (`_replaced_readings`).
- **R3.** A parse or content failure under parser P at version v is superseded by any artifact
  stream of the digest, current or superseded, under another parser name, or under P at a
  version of at least v. At equal versions the artifact wins, with no sequence tiebreak. Because
  superseded artifact streams count, a failure that a newer parser resolved never comes back
  (`_failure_is_superseded`).
- **R4.** An execution failure under P at v is superseded only by an artifact stream under P at a
  version of at least v whose head carries no `execution_unsuccessful`. A parser upgrade that
  reads the same failed invocation keeps the failure current, so the case keeps its detection
  time.
- **R5.** Failure streams never supersede one another.

Numeric or text comparison is decided once per digest, over every artifact and failure version
of that digest, and every rule compares that way. Deciding it per rule could let R2 retire W in
favor of a failure that R3, comparing the other way, retires too, leaving the digest with
nothing current to report. A digest with no failure stream compares exactly as it did before.

`_superseded_artifacts` in `reports/replay.py` reports INFO `artifact_superseded` when the
reading was replaced by a newer reading, and INFO `artifact_superseded_by_failure` when R2
replaced it, naming the failure the report carries instead; the fold records each replacement as
it decides it, so there is always one to name, and the old `AssertionError` branch is gone.
`_superseded_failures` reports a superseded failure as INFO `failure_superseded`. A case whose
system observation is no longer current reads INFO `stale_case` (`_stale_cases`) when `cases
correlate` ran while the failure was current; a failure superseded before any correlate leaves
no system case to go stale.

`ingest` checks the store before the first append. Inside the run's one transaction,
`_refuse_failures_read_elsewhere` in `cli.py` asks `reading_elsewhere` in `history/fold.py`,
passing the held failure's class, whether the store holds a reading of the failed bytes that
keeps the failure out. That is either of two things. The first is a current reading R2 could not
replace: one under another parser name, or under the same parser at the failed version or later,
whatever the failure's class. The second is any reading of the digest, current or superseded,
that would supersede the failure at birth: `_failure_is_superseded` itself, so R3 for a parse or
content failure and R4 for an execution failure, compared the way the fold compares the digest
once the failure's version joins it. The current readings are asked first, so every failure the
first check refused is still refused and named the same way. If either holds, `ingest` writes
ERROR `failure_read_elsewhere` naming that stream and returns 1 with nothing appended. `ingest`
therefore never records a held failure that the fold supersedes at birth. Before this rule a
superseded reading under another parser, or under the same parser at the failed version or
later, let such a failure through: the run exited 3 while every report showed only INFO
`failure_superseded`. A side record is not weighed before the writes, because it is recorded with
the reading it sits beside. R4 supersedes one at birth only when the store already holds a newer
reading of the same bytes by the same parser that reports no failed invocation, which is a parser
downgrade. Both kinds are weighed again after the writes when the writer met a hold. Within one run,
a failed reading whose bytes another artifact read successfully keeps its raw ERRORs and exits 1,
exactly as without the flag.

`ingest` checks the store again after the run's writes when `record_failure` met a hold (Decision
12). Still inside the one transaction, it folds the store once (`artifact_history`, which sees the
run's own appends). For each held reading in name order, pure failure or side record, it asks
`held_failure_lost` in `history/fold.py` whether two things are true. The first is that the holder
is superseded. The second is that no reading of the digest, current or superseded, would supersede
the reading's failure at birth under R3 or R4, compared the way the fold compares the digest once
the failure's version joins it. That is the second check above without the first. The R2 join is not
asked, because a side record's own artifact would match it. Recording such a failure loses it: its
id is the holder's, so its system observation, parser, version, and instant reach no persisted
report. When the holder was the digest's only failure, no failure for these bytes reaches one, while
a stateless run reports the reading's own. If any reading qualifies, `ingest` raises inside the
transaction, so the run's appends roll back, artifact streams included. It then writes one ERROR
`failure_held_by_superseded_stream` per refused reading, in name order, naming the holder, and
returns 1. The ERRORs are written only after the rollback, so a rollback that fails reports
`store_unavailable` in place of the refusal ERRORs; the diagnostics each reading wrote as it was
read, and each pure failure's own diagnostics, still appear as on any failed run, and no line claims
the store was left unchanged. A hold whose holder stays current keeps the WARNING, and so does a
side record whose failure a reading supersedes at birth, which no report would carry anyway.

The remedy depends on the instant. A failure with no declared clock records on its own stream when
ingested at another `--as-of`. A side record whose scanner declared its clock can only be ingested
without the flag, which records its artifact and accepts the loss, and every later version that
meets the same hold is refused the same way, unless a clean reading under the same parser at that
version or later supersedes its failure at birth. A held failure whose scanner declared its clock
has no recording path: without the flag its ERRORs exit 1, so it is dropped from the run. Until the
refused file is removed or ingested another way, no other file of that run is recorded. The check
sees only holds met in the run. When a later ingest supersedes the holder of a failure held earlier,
that later run meets no hold, so the earlier failure stays in no persisted report (Decision 15), and
a rerun of the held reading is refused, unless the rerun is a side record whose failure a reading of
the digest, current or superseded, supersedes at birth under R4, in which case the rerun keeps the
WARNING and exits 3; a pure failure in that position is refused before the writes with
`failure_read_elsewhere`.

## Decision 14: the source type guarantee lives in the adapters

Every adapter sets `source_type` from a literal constant, so no input byte can produce a
`complyroll.` source type. `Observation.__post_init__` in `models.py` also refuses
`RESERVED_SOURCE_TYPE_PREFIX` on an ARTIFACT observation, as defense in depth. The guarantee is
worded for what it delivers: a reader identifies a system record by `detectedAtSource` `system`,
resource type `artifact`, and membership in `detectionFailures`. A SARIF driver named
`complyroll` gives an ARTIFACT record with source type `sarif` that none of those three match,
and a test pins it. Codes come from the closed vocabulary, and no message text enters identity.

Every untrusted string (the file name, and any diagnostic message or location) passes
`diagnostic_text` before it reaches metadata, a payload, a demoted diagnostic, or
`detectionFailures`. `failure_diagnostics` in `adapters/failures.py` is the one diagnostics list
both paths use for a failed reading:

1. The reading's diagnostics, ordered by code, location, message, and level over the raw values.
   The helper does not import `complyroll.reports`, and a fresh-interpreter import test pins that.
2. Cut at `FAILURE_DIAGNOSTIC_CAP`, 62 entries. On overflow one WARNING
   `failure_diagnostics_truncated` names the dropped count.
3. Every ERROR demoted to WARNING under the same code. Every message and location passes
   `diagnostic_text`, and a missing location becomes the artifact name; a location the adapter
   gave, such as `stigs[0].rules`, is kept.
4. WARNING `detection_failure_recorded` last, naming the class and the digest.

The list is at most 64 entries, which is the contract's `maxItems`. A side record contributes
only `detection_failure_recorded`, and its artifact's own diagnostics flow as before. A failed
reading that loses the election to another name for the same bytes contributes only the existing
`duplicate_artifact` WARNING on the stateless path and nothing on the persisted path, the same
divergence duplicate artifacts already have.

## Decision 15: an equivalence carve-out, by dated amendment to ADR 0008 Decision 5

ADR 0008 Decision 5 promises byte-identical stateless and `--db` output. A system observation
takes its instant from the ingest `--as-of` on one path and the report as-of on the other, so
the promise gets a dated amendment rather than a silent exception.

Fields that may differ: `observedAt` of a system observation and so its `observationIds`, the
record's `detected_at` and EVU due date, period inclusion, `detectionFailures[].observedAt`, and
the INFOs `failure_superseded`, `artifact_superseded_by_failure`, and `stale_case`.

The two paths are byte-identical when all of these hold: the same inputs and the same flag;
every failure's `observed_at` equals the report as-of or comes from a declared scanner clock; no
stream of the digest is superseded; no two input names share a digest; and no ingest reported
`failure_held_by_another_stream`. When one did, no failure was recorded under the reading's parser
and version, and the failure stays recorded under the holder's parser, version, and codes, where a
stateless run reports the reading's own. For a held failure nothing of the reading reaches history,
so the persisted report keeps whatever the digest's streams held before, such as an older reading's
artifact, findings, and diagnostics. For a side record the reading's artifact stream is recorded as
usual, and R1 to R4 then decide over every stream of the digest, the holder's failure stream
included. Usually the reading is current by R1 and only the `detectionFailures` entry is the
holder's. When the holder is a held failure under the same parser at a newer version and every
artifact stream of the digest is under that parser, R2 supersedes the reading's artifact, so the
persisted report carries the holder's failure and none of the reading (INFO
`artifact_superseded_by_failure`). A hold is not kept when the holder ends the run superseded and
the reading's failure would not be superseded at birth: `ingest` refuses the run (Decision 13), so a
side record whose holder the run itself supersedes never reaches a store, and neither does a held
failure whose holder an earlier reading already superseded.

A failure held earlier whose holder a later ingest supersedes is still lost. The later run met no
hold, so nothing refuses it, and the persisted report carries no failure of the reading (INFO
`failure_superseded` for the holder) where a stateless run reports the reading's own. The condition
above already excludes it, because the run that met the hold warned. The documented recipes meet
every condition, and `FailedImportDivergenceTests` in `tests/test_replay.py` pins each divergence: a
later ingest as-of, a superseded stream, two names for one digest, one digest failing under two
parsers (one stateless record, two persisted members of one case, R5), and another failure stream
holding the failure, for a held failure and for a side record, a side record whose artifact a newer
held failure supersedes (R2), and a holder that a later ingest supersedes.

## Decision 16: a store that records a failure is schema 2

New stores are still created at `user_version` 1 (`SCHEMA_VERSION` in `store/sqlite.py`), so a
store that never records a failure stays readable by earlier builds, even when `ingest` ran with
the flag. The repository appends a failure stream with `requires_schema=2`
(`FAILURE_STREAM_SCHEMA_VERSION`), and `SQLiteEventStore.append` calls `_mark_schema` inside the
same transaction: it inserts migration row 2 ("failure streams, ADR 0014") and sets
`user_version = 2`, so a rollback leaves both untouched. This build opens versions 1 and 2
(`SUPPORTED_SCHEMA_VERSION`); version 1 requires migration row 1, version 2 rows 1 and 2, and
anything newer is refused as before. No schema object changes. A failure stream in a store left
at version 1 is the audit fault `failure_schema_unmarked`.

## Decision 17: missing attestations and response-process failures are a recorded scope change

VDR-CSO-FAV and the BUILD_PLAN deliverable name response workflows too, and the deliverable
names stale coverage and missing resources. This slice builds none of them:

- `detection_time_missing` stays fatal. The operator remedy is `--detected-at` or `cases
  attest-detection`, and an untimed record could not be published either way.
- Response-process failures (a broken remediation workflow) and missing attestations are not
  import failures, and each needs its own inputs. `docs/BUILD_PLAN.md` gains the Phase 2
  deliverable "Response-process and attestation failures", which owns them.
- The coverage and freshness slice owns the clean scan (`clean_scan` above), stale or unseen
  resources, `results_unknown` beside productive runs, `profile_not_loaded`, per-check error
  dispositions, and one case per failing detection process (Decision 5).

## Decision 18: period exclusion is unchanged

A system record follows the same period rule as every record. A stateless report compiled after
its period ends detects its failures after the period, so they are excluded from the official
VDT; each still appears in `detectionFailures`, its WARNINGs, and exit 3. On the persisted path
an ingest during the month places the failure in the period. Exempting system records would make
a persisted re-compile of a past period list failures recorded after it.

## Worked examples

The tracking ids below are the ones `tests/golden/vdt-failed.md` carries, compiled from the three
golden fixtures plus `failed-truncated.sarif`, `failed-invalid-rules.cklb`, and
`failed-invocation.sarif`, with `examples/evaluations-failed.json`, `--detected-at
2026-08-01T00:00:00Z`, as-of 2026-08-21T12:00:00Z, the August period, Class C, and
`--record-failed-imports`. The run exits 3.

- `case-d3bb8e4fb3b61a5f` is the parse failure of `failed-truncated.sarif`, cut inside a string
  so the JSON error is the stable "Unterminated string" form. It is observed at the as-of with
  clock `as-of` and codes `[artifact_parse_failed]`. The evaluation in
  `examples/evaluations-failed.json` matches it by the full triple and gives it PAIN 3, so its
  VDR-TFR-PVR due date is 2026-12-27T12:00:00Z, and its EVU due date 2026-08-26T12:00:00Z is met.
- `case-088261de64a0133c` is the content failure of `failed-invalid-rules.cklb`, whose one STIG
  has an object for `rules`: codes `[invalid_rules, no_observations]`, observed at the as-of,
  EVU due 2026-08-26T12:00:00Z and not overdue. Its `invalid_rules` diagnostic keeps the in-file
  location `stigs[0].rules`.
- `case-f03af85468885cad` is the execution side record of `failed-invocation.sarif`. Its first
  run succeeds with one result, which imports as an ordinary record; its second run has
  `executionSuccessful: false`, `results: []`, and a `startTimeUtc` of 2026-08-04T10:00:00Z, so
  the system record is observed at that instant with clock `invocation`, and its EVU due date of
  2026-08-09T10:00:00Z is overdue at the as-of. Every system record's detail reads "Detection
  source: complyroll" and its detection time `(source: system)`.

The supersession examples are `FailureWorkedExampleTests` in `tests/test_replay.py`, which checks
the replayed report after every step. One parser at versions 1 to 4 reads or fails the same
bytes:

- V1 reads, V2 fails, V3 reads, V4 fails. After V1 the report carries V1's reading. After V2 it
  carries the V2 failure and INFO `artifact_superseded_by_failure` for V1 (R2). After V3 it
  carries V3's reading, `artifact_superseded` for V1, `failure_superseded` for V2 (R3), and
  `stale_case` for the system case. After V4 it carries the V4 failure,
  `artifact_superseded_by_failure` for V1 and V3, and `failure_superseded` for V2: R3 counts the
  superseded V3, so V2 stays resolved.
- V1 fails, V2 reads, V3 fails. After V1 the report carries the V1 failure. After V2 it carries
  V2's reading, `failure_superseded` for V1, and `stale_case`. After V3 it carries the V3
  failure, `artifact_superseded_by_failure` for V2, and `failure_superseded` for V1.
- An execution failure across a parser upgrade, with the scanner's clock dropped so each record
  is observed at its ingest as-of. At the same as-of the upgraded reading imports, its failure is
  `already_recorded` (one id per digest per instant), and the report keeps one failure entry
  under version 1, observed at 2026-08-21T12:00:00Z, while the artifacts manifest shows parser
  version 2. One day later both failure streams stay current (R4): `detectionFailures` lists
  version 1 at 2026-08-21T12:00:00Z and version 2 at 2026-08-22T12:00:00Z, and the one case
  keeps the detection time 2026-08-21T12:00:00Z with two observation ids.

## Consequences

- Stateless clocks never run. Outside the execution class, a stateless failure is detected at
  the run's as-of, so its EVU clock restarts on every run. Only the persisted path ages a
  failure, which is why the persisted half is in this slice.
- After-period exclusion: the monthly workflow runs the stateless report after the month ends,
  so a stateless system record is excluded from the official VDT (Decision 18). It still appears
  in `detectionFailures`, the WARNINGs, and exit 3.
- Exit 3 is new. A pipeline that treats any non-zero status as failure fails on a recorded
  detection failure, which is the intent; one that wants the report anyway reads exit 3 as
  "written, with failures".
- The flag has to be adopted. Until a pipeline passes it, every failure behaves as before.
- A misnamed text file mints a parse failure. A `.json` file that is not JSON is attributed to
  CKLB and is `parse`; format rejection catches the wrong shape, not the wrong syntax, so the
  operator closes such a case `false_positive`.
- Older builds and newer stores. A build before this ADR opens a schema 2 store with
  `UnsupportedSchemaError`, so `report vdt --db`, `cases list --db`, and `ingest --db` exit 1
  with `error: store_unavailable: database schema 2 is newer than supported schema 1` and leave
  the store's bytes unchanged. Its `store verify` opens without the version check and does not
  refuse on the version: it walks the log and reports each failure stream's events as faults,
  for example on the persisted recipe's store:

  ```
  error: sequence 17: event_stream_mismatch: event 'failure.recorded' does not belong on stream 'failure/59e5a0bee03780b92cd21e2da90d4c8ead7eb94a70f3d904fa141a55620691e9/complyroll.sarif/1'
  error: sequence 17: payload_contract_invalid: no published contract for event 'failure.recorded' version 1; published contracts are: artifact.ingested v1, case.created v1, case.disposition_recorded v1, case.evaluated v1, case.identified v1, case.observation_linked v1, case.pain_reduced v1, detection.attested v1, observation.recorded v1
  error: sequence 18: event_stream_mismatch: event 'observation.recorded' does not belong on stream 'failure/59e5a0bee03780b92cd21e2da90d4c8ead7eb94a70f3d904fa141a55620691e9/complyroll.sarif/1'
  faults: 9 domain fault(s) in 53 verified event(s)
  ```

  It exits 1. The three lines above are the first of nine, one triple per failure stream, and
  the last line is the summary. A store that never records a failure stays at `user_version` 1,
  and an earlier build reads it with byte-identical report output.
- The cross-parser corner: the stateless path elects one reading by name within one run, while
  history keeps every failure stream current (R5), so the same bytes failing under two parsers
  give one stateless record and two persisted members of one case. The carve-out excludes it.
- Evaluation drift: an evaluation of a system case whose failure no longer occurs is
  `evaluation_unmatched` on the stateless path, as for any case that disappears.
- Model guard reach: a hand-edited store holding an ARTIFACT observation with a `complyroll.`
  source type stops loading; no shipped adapter can write one.
- The cleanup list gains the raw artifact name in the existing Inputs table and the other
  pre-existing raw-name surfaces, and the `_cell` gap they share.
- Four goldens hold the behavior (`tests/golden/vdt-failed.json`, `vdt-failed.md`,
  `historical-failed.json`, `historical-failed.md`), and the 22 goldens that existed before are
  byte-identical. The 16 report goldens of runs without a failure recompile byte-identical with
  the flag on, which `test_every_report_golden_recompiles_byte_identical_with_the_flag` pins.

## Rejected alternatives

- The failed reading's parser in the context key: persisted supersession groups streams by
  digest alone, so a parser upgrade would open a second case for one failing set of bytes, and
  R4's persisting execution failure would lose its detection time.
- A later failure of the same digest inheriting the first failure's instant, so every record of
  a digest shares one id: the observation would take its instant from the store rather than
  from its own reading, which the stateless path cannot reproduce. The case already keeps the
  earliest detection time, because a group's detection time is its earliest `observed_at`.
- Minting in the adapters: an adapter sees one file, while `read_elsewhere` and the opt-in flag
  are decisions about the whole run, and each adapter would carry its own copy of the recipe
  and the vocabulary.
- Default-on: every existing caller would change, including today's exit 0 for an execution
  failure; the default can flip with the CI exit criteria deliverable.
- One case per failing process: ComplyRoll has no inventory of detection processes yet; the
  coverage slice opens that seam (Decision 5).
- `ingest.failed` as the event name: a side record's artifact imported, so "ingest failed" would
  be false.
- The system observation on the artifact stream: the artifact identity check refuses a SYSTEM
  observation there.
- A title per class: a later parser that reclassifies a failure would move its title.
- Minting unreadable or oversize inputs by name: with no digest there is no identity that
  survives a rename.
- Minting a partial reading beside its findings: the reading's own findings cannot be published
  from a failed result, and the record would hide them.
- Minting a format rejection as `parse`: a file of the wrong kind is operator input.
- Documenting the silent misreport by an older build instead of marking schema 2: a store must
  never be misread quietly.
- A `--failure-observed-at` flag that would let a stateless run pin the instant: deferred, not
  refused. The persisted path already fixes the instant at ingest.
- Keeping, documented and pinned, the hold of a side record whose own artifact outranks a parse or
  content holder under R3: the run would exit 3 for a failure that no persisted report carries,
  which is a loud failure turned quiet one step later.
- Keeping the WARNING when the scanner declared the failure's clock, since no other `--as-of` can
  change its id: the refusal stays uniform, and an operator who accepts the loss says so by
  ingesting without the flag.
- A new unmintable reason `held_by_superseded`: the refusal is decided against the store after the
  writes, not from the reading, and `ingest` assigns no reason for `read_elsewhere` either. The
  ERROR code identifies it.
- Deciding before the writes, beside the `failure_read_elsewhere` check: when a side record's own
  artifact supersedes the holder, that artifact exists only once the run has written it.
