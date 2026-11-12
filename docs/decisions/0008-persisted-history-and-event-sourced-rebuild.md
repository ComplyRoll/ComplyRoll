# ADR 0008: Persist history as typed events and rebuild the report from the log

- Status: Accepted
- Date: 2026-08-22

## Context

ADR 0007 delivered the first report as a pure function of artifacts and an evaluations file.
Phase 1 still has one open exit criterion: changing an evaluation must create history rather
than overwrite the prior evaluation. ADR 0004 built the append-only store for exactly that, but
nothing writes to it, no event payload contract exists, and `event_type` is free text. This
record fixes the contracts, the streams, the commands that write them, and the rule that makes
the persisted path trustworthy: the report rebuilt from the log must be byte-identical to the
stateless report compiled from the same inputs.

## Decision 1: every event has a published payload contract

`complyroll.events` owns a registry `{(event_type, event_version): JSON Schema}`. Each schema is
a Draft 2020-12 document with `additionalProperties: false`, validated with the `jsonschema`
dependency ComplyRoll already carries. The domain layer appends through `EventRepository`, which
validates the payload against the registry before calling `SQLiteEventStore.append` and rejects
unknown types or versions. The store stays a generic envelope log; the repository is the only
code that knows what an event means.

Every event's metadata is `{"actor", "method", "tool", "toolVersion", "runId"}`: the actor
named on the command line (`--actor`, defaulting to the operating-system user name and recorded
as such), the method `cli`, the generator name and version, and one run identifier per command
invocation, spelled `run-<uuid4>`, so every event a single run produced can be found together.

## Decision 2: streams and event types (version 1)

Artifact stream `artifact/<sha256>/<parser_name>/<parser_version>`:

| Event | Payload |
|---|---|
| `artifact.ingested` | `name`, `sha256`, `sizeBytes`, `mediaType`, `parserName`, `parserVersion`, `ingestedAt`, `observationCount`, `diagnostics` (list of `{level, code, message, location?}`) |
| `observation.recorded` | exactly `Observation.to_canonical_dict()` (ADR 0002), one event per observation, in parser order |

Case stream `case/<tracking_id>` where the tracking id is the correlation v0 identifier
(ADR 0007 Decision 3):

| Event | Payload |
|---|---|
| `case.created` | `trackingId`, `sourceType`, `sourceRecordId`, `contextKey`, `title`, `description`, `createdAt` |
| `case.observation_linked` | `observationId`, `resourceId`, `resourceType`, `observedAt` or null, `sourceTool`, `sourceArtifactSha256`, `sourceIdentifiers` |
| `detection.attested` | `detectedAt`, `rationale`, `attestedAt` |
| `case.evaluated` | `completedAt`, `isInternetReachable`, `isLikelyExploitable`, `pain` (1 to 5), `potentialAgencyImpact`, `rationale`, `evaluator`, `isFalsePositive`, `supplementaryRiskInformation` or null, `projectedNextReduction` or null (`estimatedAt`, `targetRating`) |
| `case.pain_reduced` | `reducedAt`, `rating` |
| `case.disposition_recorded` | `status` (any `CaseStatus` value other than `new`, `evaluating`, `active`), `closedDisposition` or null, `acceptanceRationale` or null, `recordedAt` |
| `case.identified` | `providerTrackingId` (the operator's override of the reported identifier) |

Timestamps are RFC 3339 with an offset, normalized to UTC `Z` form on write, with one exception:
`observation.recorded` is exactly `Observation.to_canonical_dict()` (ADR 0002), so its
`observed_at` and `ingested_at` keep the text that dictionary writes (an explicit offset, UTC as
`+00:00`). Streams are the aggregate boundary: one artifact ingestion and one case each have
their own optimistic version.

## Decision 3: every write is idempotent

- `ingest`: an artifact stream that already exists (same bytes, same parser, same parser
  version) is left alone and reported as `already_recorded`; a different parser version is a new
  stream, matching ADR 0002's identity rule.
- `cases correlate`: creates a case stream only when none exists for the tracking id, and links
  only observations that are not yet linked.
- `cases attest-detection`: a case that already carries an identical attestation is skipped.
- `cases evaluate`: an evaluation whose canonical payload equals the case's latest
  `case.evaluated` payload is skipped; any difference appends a new event. The same rule applies
  to `case.pain_reduced` (by content), `case.disposition_recorded` (by content), and
  `case.identified` (by value).

Re-running any command over the same inputs therefore appends nothing, and re-running after a
real change appends exactly the change. That is what makes the log a history rather than a
mirror.

## Decision 4: history, not overwrite

A case's evaluations are all of its `case.evaluated` events in recorded order. The current
evaluation is the latest; the earlier ones remain readable through `cases history` and in the
fold. Nothing in the domain layer can update or delete an event (the store's triggers and
schema verification enforce it), and nothing in the fold collapses history.

## Decision 5: the rebuild rehydrates observations and re-runs the same compiler

The persisted report is produced by reading every `observation.recorded` payload back into an
`Observation`, running the same correlation v0, folding each case stream into its current state
(attestation, evaluations, reductions, disposition, identified tracking id), and handing the
result to the same record compiler ADR 0007 built. Artifact provenance and ingest diagnostics
come from `artifact.ingested` events in recorded order. Nothing is recomputed differently and
nothing is cached, so the persisted path cannot drift from the stateless path by construction.

The acceptance test for this slice is reconciliation: the report rebuilt from a store that was
populated by `ingest`, `cases correlate`, `cases attest-detection`, and `cases evaluate` from
the fixtures and `examples/evaluations.json` is byte-identical, JSON and Markdown, to the
stateless report compiled with the same options. The existing goldens are the expected output.

Projection tables and checkpoints (ADR 0004) remain the plan for when stream counts make an
in-memory fold too slow; at Phase 1 volumes the fold is read on demand.

## Decision 6: commands

```text
complyroll ingest <artifact...> --db <store> [--as-of <time>] [--actor <name>]
complyroll cases correlate --db <store> [--actor <name>]
complyroll cases attest-detection --db <store> --detected-at <time> --rationale <text>
    (--case <tracking-id> | --all-missing) [--actor <name>]
complyroll cases evaluate --db <store> --evaluations <file> [--actor <name>]
complyroll cases list --db <store>
complyroll cases history <tracking-id> --db <store>
complyroll report vdt --db <store> --class <B|C> --package-uri <uri> --from <time> --to <time>
    [--as-of <time>] [--calendar-tz <name>] [-o <file>] [--markdown <file>]
complyroll store verify --db <store>
```

`report vdt` takes either artifacts with `--evaluations`/`--detected-at` (stateless) or `--db`
(persisted), never both. `store verify` walks the whole log, checking every payload digest,
sequence and stream-version contiguity, the AUTOINCREMENT counter, and the schema definitions,
and returns a structured report with a non-zero exit on any fault. Exit codes and diagnostics
follow ADR 0007.

## Decision 7: what stays out of this slice

Projection tables and checkpoint-driven rebuilds; the full-envelope digest and hash chain
(ADR 0004 follow-up, Tier 2); accepted-vulnerability and historical-activity reports
(BUILD_PLAN item 7); manual case split and merge; an event for deleting or retracting an
evaluation (corrections are new evaluations with rationale, never removals).

## Consequences

- Phase 1 exit criterion 3 is met: a second, different evaluation appends a second
  `case.evaluated` event, the report reflects the latest, and `cases history` shows both.
- The stateless compiler is unchanged in behavior; its internals are split so both paths share
  one record compiler.
- `observation.recorded` freezes `Observation.to_canonical_dict()` as a stored contract; any
  future change to that dictionary needs a new event version and a reader for both.
- The event registry is the place the hash chain and the projection tables attach later.

## Amendment 2026-08-22: rules the first implementation settled

The build that landed these decisions settled the following points the original text left
implicit. They bind the persisted path from this date.

- **Attestations are per case on the persisted path.** The compiler resolves detection time per
  group from a per-tracking-id attestation map; the stateless `--detected-at` is the default for
  every group with no source timestamp. When every attested record shares one instant, the
  `x-complyroll.detectionTimeAttestation` block is unchanged (`detectedAt`, `appliedTo`, `count`).
  When instants differ, the block carries `appliedTo`, `count`, and an `attestations` list of
  `{detectedAt, appliedTo}` entries sorted by instant then tracking id, with no scalar
  `detectedAt`; the Markdown twin lists each instant with the identifiers it covers. An
  attestation still never overrides a source timestamp, and `cases attest-detection` does not
  record one for a case where any linked observation carries a timestamp (the compiler would
  use that source time and the attestation could never reach a report); such cases are reported
  as not applicable. `--all-missing` selects only cases with no timestamped observation and no
  attestation yet; re-attesting an attested case takes an explicit `--case`, and the latest
  attestation then governs.
- **Effective tracking ids are unique at write time.** `cases evaluate` computes every case's
  effective identifier (entry `trackingId`, else the recorded `providerTrackingId`, else the
  correlation identifier) across all cases and refuses the file before appending anything when two
  cases would share one, matching the compiler's `tracking_id_collision` rule.
- **Omissions do not retract.** Decision 7 provides no retraction event, so an evaluations entry
  that omits a disposition, PAIN reductions, or a `trackingId` override the case already holds
  appends nothing and the recorded values stand; `cases evaluate` prints `disposition_retained`,
  `reduction_retained`, and `identification_retained` warnings so the operator knows a change
  needs a new entry with rationale. A PAIN reduction is one event keyed by instant and rating,
  so an evaluations file that states the same reduction twice is refused at the parse boundary
  on both paths. The byte-identity guarantee of Decision 5 therefore holds for a store whose
  evaluations were recorded from the same file the stateless report is compiled with.
  Completed PAIN reductions are rendered in canonical order (by instant, then rating) on both
  paths, so the order in which a file lists them or a store recorded them cannot change a report.
- **The disposition contract carries the parser's cross-field rules.** `case.disposition_recorded`
  refuses, at append and again in the fold, a `closed` status with no `closedDisposition`, an
  `acceptanceRationale` on a status that accepts no risk, and an accepted disposition with no
  rationale; these are the rules the evaluations file already obeys, so history cannot hold a
  shape the report compiler would refuse or misroute. A case stream that records a disposition
  but no evaluation makes the replay fail closed (`disposition_without_evaluation`).
- **Stored observations are readable or refused.** The `observation.recorded` contract accepts
  only the text `Observation.to_canonical_dict()` writes: `YYYY-MM-DDTHH:MM:SS`, an optional
  six-digit fraction, and a `+HH:MM` or `-HH:MM` offset (no `Z`, no seconds in the offset). A
  pattern cannot tell a whole second spelled with six zero digits, or an impossible date, from
  text the writer produced, so the repository also reads every observation payload back through
  `Observation.from_canonical_dict` before storing it, and `store verify` does the same on its
  contract pass; the log therefore cannot hold an observation the replay reader refuses, and one
  that reached the log some other way is reported rather than declared healthy. The reader also
  requires an artifact-bound observation's identifier to equal the one its fields derive.
- **`observation.recorded` keeps one open map.** `source_metadata` is a free-form string-to-string
  map in `Observation.to_canonical_dict()`, so its contract allows string-valued additional
  properties there; every other object in every contract is `additionalProperties: false`.
- **`store verify` inspects files the normal open refuses.**
  `SQLiteEventStore.open_for_verification` opens a store without the refusing checks and never
  creates or modifies the file, so a truncated tail, an altered trigger, or a missing schema
  object is reported as a fault (`sequence_counter_mismatch`, `schema_object_altered`,
  `schema_object_missing`) instead of an exception. Faults are ordered schema objects by type and
  name, migration, counter, then rows by sequence. The normal constructor keeps refusing such
  files. A hole anywhere in history is refused, not only a truncated tail: the normal open and
  every `append` check that the event count equals the highest sequence and that each stream's
  event count equals its highest version, so nothing can be written past a deleted middle event.
  After the store-level walk is clean, `store verify` also validates every payload against its
  published contract and reports `payload_contract_invalid`, so a payload that reached the log
  without passing through the repository cannot be declared healthy. Verifying a WAL-mode store
  may leave `-shm` and `-wal` sidecar files beside it; the database file's bytes do not change.
- **Replay never drops a case silently.** A case stream whose tracking id matches no group in the
  rehydrated observations produces a `stale_case` diagnostic.
- **Only `ingest` creates a store, and a failed ingest creates nothing.** Every other command
  (`cases correlate`, `cases attest-detection`, `cases evaluate`, `cases list`, `cases history`,
  `report vdt --db`, `store verify`) reports `store_missing` when the path does not exist;
  `ingest` parses every artifact before it opens or creates the store, so a run that fails on any
  artifact leaves no file behind. A resumed ingest stamps the replayed observations with the
  ingestion instant already recorded on the artifact event, not the resuming run's. `report vdt`
  refuses `--db` together with artifacts, `--evaluations`, or `--detected-at` (`invalid_option`):
  the persisted path takes those facts from history.
- **Stored text is canonical or rejected.** `Observation.from_canonical_dict` accepts a timestamp
  only when the parsed value re-serializes to the exact stored text.

## Amendment 2026-08-22 (second): rules a cross-vendor audit showed were unenforced

An OpenAI-engine audit of the committed slice found invariants the text promised and nothing
enforced, mostly at concurrency and contract boundaries. They bind from this date.

- **Writers run in one store transaction.** `SQLiteEventStore.transaction()` opens one
  `BEGIN IMMEDIATE` transaction that every append inside it joins. `cases correlate`,
  `cases attest-detection`, and `cases evaluate` fold, check, and append inside one such
  transaction, so two concurrent runs serialize on the write lock and the second re-folds after
  the first commits; the effective-tracking-id uniqueness rule therefore holds across streams,
  not only within one run's memory.
- **An artifact is ingested atomically, and an `ingest` run is all-or-nothing.** `record_ingest`
  writes the artifact event and every observation inside one transaction, and the writers join a
  transaction their caller already holds, so `complyroll ingest` wraps every artifact of one run in
  a single transaction: a run that fails on any artifact leaves the store exactly as it was, on a
  new store and an existing one alike, and an empty summary means nothing became durable. A
  stream that nonetheless holds fewer observations than its artifact event declares (history
  written by an older version) is incomplete: the fold refuses it and `store verify` reports
  `artifact_incomplete`. The mirror holds too: a stream holding more observations than it declared
  is `artifact_overfull`, and an `artifact.ingested` or `observation.recorded` whose digest, parser
  name, or parser version differs from the stream it sits on is `artifact_stream_mismatch`; an
  observation identifier repeated within one stream is `artifact_duplicate_observation`. All three
  are refused at append, refused by the fold, and reported at rest, so an observation can never be
  counted under an artifact it did not come from, nor counted twice under its own.
- **Only `ingest` creates a store, and it never deletes one.** A new store is built at a
  temporary path beside the destination and published only when the whole run succeeded; a
  failure removes the temporary file and nothing else. No command unlinks a path it did not
  create in the same run. A `--db` path that is a symbolic link with nothing behind it is refused
  (`store_unavailable`, naming the link's target) rather than built beside and then reported as a
  conflict; a link to a real store is opened in place.
- **Every timestamp is a real instant.** The repository parses every timestamp-typed field of
  every contract (the set is derived from the schemas, nested and nullable fields included), so an
  impossible date or hour is refused at append and reported by `store verify`, not discovered by
  the fold. Hour 24 is refused explicitly: Python parses `T24:00:00Z` and rolls the date
  forward, which would move a deadline into the next day in silence. The derivation walks the
  applicator branches a contract may carry (`oneOf`, `anyOf`, `allOf`, `if`, `then`, `else`,
  `dependentSchemas`) and refuses, at import, a contract carrying a `$ref` anywhere or a timestamp
  inside any array form, so a field it cannot reach cannot be published.
- **Events belong to their stream.** `artifact.ingested` and `observation.recorded` are accepted
  only on artifact streams, every `case.*` event and `detection.attested` only on case streams,
  and a `case.created` only on the stream its `trackingId` names. `store verify` reports any
  event stored on the wrong kind of stream.
- **Metadata is enforced, not described.** `runId` must be `run-` followed by a canonical
  version-4 UUID, `method` one of the published methods (`cli`, `library`), `tool` exactly
  `complyroll`, and `toolVersion` non-blank; the repository refuses anything else at append and
  `store verify` reports it at rest.
- **The newest parser stream wins.** When one artifact digest has streams under several parser
  versions, the fold rehydrates only the stream with the newest version. Versions compare as
  tuples of integers when every dot-separated component of every candidate is an ASCII number,
  with leading and trailing zero components ignored so `1`, `01`, and `1.0` are one version and
  `10` follows `9`; otherwise they compare as text. Two streams that tie leave the later-recorded
  one current, so the choice never depends on read order. The fold then reads only it and the
  replay reports each older stream as `artifact_superseded`. Decision 5's byte identity with the
  stateless report holds for a log in which no artifact has a superseded stream. Once one does,
  the persisted report differs from the stateless one by exactly that diagnostic in the
  extension block and the Markdown diagnostics list, even when the installed parser version
  equals the newest recorded one: the history holds a fact the files alone do not, and the report
  says so rather than hiding it to preserve the bytes.
- **`store verify` audits the domain, not only the bytes.** After the store-level walk it runs
  `audit_history`: every payload against its contract and, for observations, the reader; every
  event against its stream kind and, on artifact streams, against the artifact identity the
  stream names; every artifact stream for completeness in both directions and for repeated
  observation identifiers; every metadata envelope against the rules above. Every cross-field
  rule of the disposition contract, including that an acceptance rationale carries text and not
  only whitespace, lives in the contract itself, so nothing the fold refuses is invisible to the
  audit. The README's claim is scoped to exactly that.

## Rejected alternatives

Recomputing the report from case events alone, without rehydrating observations, was rejected
because it would duplicate correlation logic in the fold and could drift from the stateless
path. Mutable "current state" tables as the source of truth were rejected in ADR 0004 and remain
rejected. Deriving the actor from the evaluations file's `evaluator` was rejected because the
evaluator is who made the judgement and the actor is who recorded it; both are kept.

## Amendment 2026-09-30: failure streams and the equivalence carve-out

ADR 0014 records a detection process failure as a system observation on both paths when the
operator passes `--record-failed-imports`. The persisted half adds a third stream kind and a new
event, and the stateless and persisted paths can no longer promise identical bytes for every
store. These rules bind from this date.

- **Decision 5 has a carve-out for system observations.** A system observation takes its instant
  from the ingest `--as-of` on the persisted path and from the report as-of on the stateless
  path, unless the scanner declared the failed invocation's clock. The fields that may differ
  are `observedAt` of a system observation and so its `observationIds`, the record's
  `detected_at` and EVU due date, period inclusion, `detectionFailures[].observedAt`, and the
  INFOs `failure_superseded`, `artifact_superseded_by_failure`, and `stale_case`. The two paths
  are byte-identical when all of these hold: the same inputs and the same flag; every failure's
  `observed_at` equals the report as-of or comes from a declared scanner clock; no stream of the
  digest is superseded; no two input names share a digest; and no ingest reported
  `failure_held_by_another_stream`, which `record_failure` adds when another failure stream of
  the digest already holds the reading's system observation. No failure stream is then written
  under the reading's parser and version, and the failure stays recorded under the holder's
  parser, version, and codes, where a stateless run reports the reading's own. Without the flag,
  and for a store that holds no failure stream, Decision 5 holds exactly as amended above.
  `FailedImportDivergenceTests` in `tests/test_replay.py` pins each divergence.
- **A third stream kind, `failure/<sha256>/<parser_name>/<parser_version>`.** It is named for the
  parser whose reading failed and holds exactly one `failure.recorded` head and one
  `observation.recorded` carrying the system observation, written in one transaction by
  `record_failure`; a half-written stream is refused rather than resumed. `observation.recorded`
  is accepted on artifact and failure streams, `failure.recorded` on failure streams only, and
  every case event on case streams only. One system observation id is stored once per digest
  across failure streams. The audit gains `failure_incomplete`, `failure_overfull`,
  `failure_stream_mismatch`, `failure_duplicate_observation`, and `failure_schema_unmarked`.
- **`failure.recorded` v1.** The payload is `name` (through `diagnostic_text`), `sha256`,
  `sizeBytes`, `mediaType`, `parserName`, `parserVersion`, `ingestedAt`, `failureClass`
  (`execution`, `parse`, or `content`), `failureCodes` (at least one, unique, from the closed
  vocabulary), `clock` (`invocation` or `as-of`), and `diagnostics` (at most 64 entries). There
  is no `trackingId`; the replay derives it from the stored observation, as the stateless path
  does.
- **The newest parser stream wins, across kinds.** The rule above still picks the artifact winner
  W per digest (R1), and failure streams join it under ADR 0014 Decision 13: W is replaced by a
  failure under W's parser name at a strictly newer version when every artifact stream of the
  digest is under that parser name (R2), reported as `artifact_superseded_by_failure`; a parse
  or content failure is superseded by any artifact stream of the digest, current or superseded,
  under another parser name or under its parser at a version of at least its own (R3); an
  execution failure only by a reading under its parser at such a version whose head carries no
  `execution_unsuccessful` (R4); and failures never supersede one another (R5). A superseded
  failure is reported as `failure_superseded`. Whether a digest's versions compare numerically
  is decided once over every artifact and failure version of that digest. A digest with no
  failure stream is split exactly as before.
- **A store that records a failure is schema 2.** New stores are still created at `user_version`
  1. The first `failure.recorded` append inserts migration row 2 ("failure streams, ADR 0014")
  and sets `user_version` to 2 in the same transaction. This build opens 1 and 2; a build before
  ADR 0014 refuses a schema 2 store at open with `database schema 2 is newer than supported
  schema 1`, and its `store verify`, which opens without that check, reports each failure
  stream's events as `event_stream_mismatch` and `payload_contract_invalid` faults (ADR 0014,
  Consequences). A store that never records a failure stays at schema 1 and stays readable by
  earlier builds.

## Amendment 2026-10-13: holds

ADR 0014's amendment of this date stores a failure another failure stream already holds as a
`failure.held` v1 head and the reading's own system observation, on the reading's own failure
stream. One system observation id may now sit on several failure streams of a digest, and the
fold rehydrates it once, from the carrier: the stream whose observation was recorded first
among those no reading supersedes (R6). These rules bind from this date.

- **The Decision 5 carve-out keeps its five conditions.** For history written from this date
  the fifth can also be read from the store: no failure stream of the digest opens with
  `failure.held`. The sentence "No failure stream is then written under the reading's parser
  and version" in the 2026-09-30 amendment no longer holds, because the reading is stored as a
  hold. INFO `failure_held` joins the fields that may differ.
- **Ingest diagnostics have a second source.** Decision 5 says artifact provenance and ingest
  diagnostics come from `artifact.ingested` events. Persisted ingest diagnostics also come from
  the failure head that carries its observation, `failure.recorded` or `failure.held` (R6),
  each read once as the stateless path emits it (ADR 0014, Decision 12). A dormant hold
  contributes only INFO `failure_held`.
- **`failure.held` v1.** The event is accepted on failure streams only, with the payload of
  `failure.recorded` v1. A failure stream holds one head of either type and one
  `observation.recorded`. The audit gains `failure_hold_orphaned`, a hold whose observation is
  not first held by a `failure.recorded` stream, so it has six failure codes. This supersedes
  three phrases of the 2026-09-30 amendment's stream-kind bullet: "exactly one
  `failure.recorded` head" now reads one head of either type, "`failure.recorded` on failure
  streams only" covers `failure.held` too, and "One system observation id is stored once per
  digest across failure streams" holds for `failure.recorded` streams, while a hold stores the
  id again beneath the recorded stream that holds it first.
- **Stored diagnostics narrow.** The stored-diagnostic contract admits only `info` and
  `warning` for `artifact.ingested`, `failure.recorded`, and `failure.held`. A head edited to
  carry an ERROR is `payload_contract_invalid` in `store verify` and stops the fold with
  `history_invalid`. No writer ever stored an ERROR diagnostic, so no released store holds one.
- **A store that records a hold is schema 3.** The first hold append inserts migration row 3
  ("held failures, ADR 0014 amendment 2026-10-13") and sets `user_version` to 3 in the same
  transaction; a store with failure streams and no hold stays at 2. This supersedes "This build
  opens 1 and 2" above and the `store verify` sentence that follows it. This build opens 1 to
  3. An earlier build refuses a schema 3 store at open, and its `store verify` reports
  `schema_version_unsupported` (ADR 0004, amendment 2026-10-03).

## Amendment 2026-10-14: the writers and the audit order evaluations

- `cases evaluate` resolves each matched case's detection time from the open observation
  group a report from the store reads, through the compiler's resolver, and refuses the
  whole file before any append when an entry completed before it, printing the compiler's
  `evaluation_before_detection` lines. A partly timestamped group is applied and the
  compiler's WARNING printed. Every matched entry of a case a report would print is
  checked, an unchanged one included. The order check runs before the effective tracking
  identifier check, as the compiler orders them, so a file refused for both prints the
  ordering lines.
- `cases attest-detection` refuses an attestation that would become a case's detection
  time when the case's current evaluation completed before it. Every blocking case is
  named and nothing is appended, for `--case` and `--all-missing` alike.
- The writers therefore never leave an evaluation before a detection time the record owns
  in a case a report would print. `ingest` can: a newer parser that reads a timestamp from
  bytes an older one read as untimed moves the detection time later. `ingest` records
  evidence and does not refuse it. `store verify` reports the inversion as the audit fault
  `evaluation_before_detection`, at the current evaluation's sequence with the compiler's
  message, and a report from the store refuses the record. The check runs only on a log
  with no other fault, because it folds cases and rehydrates observations. Unlike a
  tracking identifier collision, which the audit leaves to the report, this state can
  arrive through `ingest`, which an operator does not expect to change an evaluated case.
  The writers and the check skip a case no report prints: one with no open group
  (`stale_case`) or no resolvable detection time. If a later ingest brings its group back,
  the report and `store verify` check it then. The check folds every case, so a log whose
  case streams do not fold, which a report from the store already refuses as
  `history_invalid`, now fails `store verify` the same way where it passed before.
- Decision 5: refuse versus publish joins the ways the two paths may differ. A failure
  detected at the as-of is detected at the ingest `--as-of` in history and at each
  report's as-of on the stateless path. An evaluation completed between the two compiles
  from history and is refused by a later stateless run. One completed before the ingest
  `--as-of` is refused from history, while a stateless run at an as-of no later than its
  `completedAt` passes the same check (ADR 0014 amendment of this date).

## Amendment 2026-10-14 (second): what the case writers fold and what store verify reports

`cases correlate` folds every existing case stream of an open group, each one it may extend,
before its first append. A stream that does not fold refuses the run with the error a report
from the store prints for that stream, and nothing is appended, inside a caller's open
transaction too. The second 2026-08-22 amendment's "fold, check, and append" now holds for
correlate: every case writer folds each case stream it appends to before its first append.
`cases evaluate` folds every case, `cases attest-detection` each case it attests, and
`cases correlate` each case of an open group. A writer need not fold a case stream it cannot
extend: correlate never reads a case no open group names, and `cases attest-detection` folds
only the cases it attests, so damage there does not stop them, while `report --db`,
`cases list` and `store verify` still refuse it. `ingest` appends only to artifact and failure
streams, folds no case stream, and records evidence (amendment 2026-10-14); an order inversion
`ingest` leaves elsewhere is still not a writer refusal.

The content-neutral faults are reported by `store verify` and refused by no reader and no case
writer. They are defined by shape, because `event_stream_mismatch` and
`payload_contract_invalid` are refused on a case stream: an event on a non-case stream whose
type does not belong there, with any `payload_contract_invalid`, `artifact_incomplete` or
`artifact_overfull` that event alone causes, since the artifact and failure readers read only
the types that belong on their streams and no reader reads a stream of no kind; an
`event_metadata_invalid`; and a `failure_schema_unmarked`. The repository never writes one,
and none changes the bytes of any report. One writer refuses one shape: a failure stream is
written whole, so `ingest --record-failed-imports` exits 1 with `history_invalid` rather than
resume one that holds an event no failure stream carries. History is append-only, so refusing
them on read would leave the store unreportable with no repair. `store verify` checks the
metadata envelope's shape, not who wrote it. Run `store verify` before relying on a store.

`store verify` still checks evaluation order when its only other faults are
`event_metadata_invalid` or `failure_schema_unmarked`, the two that are content-neutral on any
stream and never affect a fold. If the check then cannot fold or rehydrate, the faults already
found are reported alone, as before. Without this, a store with one tampered metadata envelope
could never again report an inversion from `store verify`, while every report from it refuses
the record. This supersedes, for those two codes, the 2026-10-14 amendment's "The check runs
only on a log with no other fault". With the paragraph above it narrows the reading of the
second 2026-08-22 amendment's metadata bullet: the repository refuses an envelope outside the
rules at append, and at rest only `store verify` reports it. Neither earlier text is edited.

## Amendment 2026-10-16: coverage streams and the gap divergences

ADR 0015 records a coverage window that closed with no verification as a system observation, on
the stateless path with `--record-coverage-gaps` and in the store with `cases coverage`. The
persisted half adds a fourth stream kind and a new event, and a store's recorded gaps can disagree
with the windows a run derives, so Decision 5 gets a second named carve-out in the style of ADR
0014 Decision 15. These rules bind from this date.

- **Decision 5 has a carve-out for coverage gaps.** A gap is observed at its window close, which
  the inputs fix on both paths, so unlike a failure it never takes an ingest or report as-of, and
  the refuse-versus-publish divergence of the 2026-10-14 amendment does not arise for it. What may
  differ is which gaps a store holds against which windows a run derives. A window `cases
  coverage` never recorded reads `recorded: false` and `trackingId: null`, opens no case, and is
  INFO `coverage_gap_unrecorded`, where the stateless run with the flag has its case. A stored gap
  the run derives no window for keeps its case and is INFO `coverage_gap_contradicted` when the
  run's evidence holds a verification inside its window, as a late upload leaves, or INFO
  `coverage_gap_unmatched` when it holds none, where the stateless run has no such record. A gap
  recorded against an earlier copy of the inventory keeps that copy's `coverage.inventorySha256`
  while the coverage block names the inventory given to the run. The two paths are byte-identical
  when `cases coverage` ran with the report's inventory, as-of, class, and calendar zone; no
  evidence observed inside a recorded window reached the store after it; the stateless run passes
  `--record-coverage-gaps`; and the conditions of the 2026-09-30 amendment hold for any failure.
  `tests/test_coverage_history.py` pins each divergence and the replay of both gap goldens.
- **Gap awareness is the schema marker.** A report from a store is gap-aware only when the store
  is marked schema 4 and the run has an inventory, and only a gap-aware run writes the window keys
  and the three notes above. A store that never recorded a gap compiles exactly as Decision 5 and
  ADR 0015's PR 2 describe, so every replay golden cut before this date keeps its bytes.
- **A fourth stream kind, `coverage/<fingerprint>`.** It is named for the gap record's SYSTEM
  identity hash and holds exactly one `coverage.recorded` head and one `observation.recorded`
  carrying the gap record, written in one batch by `cases coverage`; a stream that is not whole is
  refused rather than resumed, and a whole one is skipped, so its first recorded payload stands.
  `observation.recorded` is accepted on artifact, failure, and coverage streams, and
  `coverage.recorded` on coverage streams only. `rehydrate_observations` appends each coverage
  stream's record in stream-open order, and no rule supersedes a gap. The audit gains
  `coverage_incomplete`, `coverage_overfull`, `coverage_stream_mismatch`,
  `coverage_identity_breach`, and `coverage_schema_unmarked`.
- **`coverage.recorded` v1.** The payload is `rule`, `contextKey`, `windowClosedAt`, `anchor`,
  `anchorAt`, and `inventorySha256`, every one required and no other allowed. Like
  `failure.recorded` it carries no tracking id, and it carries no stream id either: both are
  derived from the stored record at replay.
- **A store that records a gap is schema 4.** The first coverage append inserts migration row 4
  ("coverage gaps, ADR 0015"), and rows 2 and 3 when the store lacks them, and sets `user_version`
  to 4 in the same transaction; a store that never records a gap stays at its version. This
  supersedes "This build opens 1 to 3" in the 2026-10-13 amendment: this build opens 1 to 4. A
  build that opens only 1 to 3 refuses a schema 4 store at open with `database schema 4 is newer
  than supported schema 3`, and its `store verify` reports `schema_version_unsupported`.
- **One more content-neutral fault.** `coverage_schema_unmarked`, a coverage stream in a store
  below schema 4, joins `event_metadata_invalid` and `failure_schema_unmarked`: no reader and no
  case writer refuses it, it changes no report's bytes, and `store verify` still checks evaluation
  order beside it. This widens the second 2026-10-14 amendment's two codes to three. One more
  writer refuses one shape: `cases coverage` exits 1 with `history_invalid` rather than resume a
  coverage stream that holds an event no coverage stream carries. The fold now refuses that shape on
  any coverage stream and on every read path, so `report ... --db`, `cases correlate`, and
  `cases coverage` each exit 1 with `history_invalid` and the text of the placement audit's
  `event_stream_mismatch` fault.

## Amendment 2026-10-21: what store verify names that a reader refuses

A report from the store refused several shapes that `store verify` passed or ended in a
traceback on. Anything a reader refuses, `store verify` now rejects with a named fault. These
rules bind from this date.

- **A case stream id that names no tracking id.** Every reader that folds cases used to end in
  a `ValueError` traceback on a stream such as `case/foo` whose first event is not
  `case.created`. The fold now raises `history_invalid` with "stream ... names no tracking id",
  so `report ... --db`, `cases list`, `cases evaluate` and `cases attest-detection` refuse it,
  and the audit reports it as
  `case_tracking_id_mismatch` once per stream, at its first event, whatever that event's type.
  A `case.created` on such a stream is no longer reported a second time.
- **A failure record holds every field its builder fixes.** The identity check now also holds
  the system record's record id, tool and parser to the builder's, its disposition to `open`,
  its severity to `unknown`, its source identifiers and artifact fields to empty, its title to
  the one built from its digest, its description to empty, and its evidence ids to exactly
  `["sha256:<digest>"]`, which `system_observation_for` stores, as the 2026-10-16 amendment's
  audit fixes hold a gap record. A record edited to `pass` used to verify and then drop out of
  `detectionFailures`, and an edited title used to verify and reach the report as the
  vulnerability description. Each is `failure_stream_mismatch` in the audit and
  refused by the failure reader and at append.
- **A failure class names its own codes.** `classify_ingest` derives the class from the codes
  (execution when `execution_unsuccessful` is present, then parse for any parse code, then
  content), so the record's metadata class must be the one its codes name. The class decides
  supersession, so a forged class used to verify and rank a reading under rules that do not
  apply to it. The mismatch is `failure_stream_mismatch`, and the head is held to the record by
  the existing disagreement check.
- **A gap record's metadata values.** The audit held `coverage.force`, `coverage.job` and
  `coverage.basis` to presence and never compared the anchor with the close (ADR 0015, "Left
  for later" of 2026-10-16). `coverage.anchorAt` must now be an instant in the form the writer
  spells it that precedes `coverage.windowClosedAt`, since no rule's timeframe is empty;
  `coverage.force` a rule force; `coverage.job` the job the context key names, or empty when
  the key names the record's own resource; and `coverage.basis` a text the writer has
  recorded. A reworded basis is added to the accepted texts, never put in place of one. The
  record's title must be the one its rule, resource and window close build, and its description
  the builder's. Each is `coverage_identity_breach`, refused by the coverage reader and at
  append. Without an inventory to derive windows from, `store verify` cannot tell a window from
  another the same rule could have run: an `anchorAt` moved earlier, still before the close, or
  a `force` swapped for another rule force, made the same in head and record, verifies clean.
- **A disposition with no evaluation.** The replay's `disposition_without_evaluation` refusal
  (first 2026-08-22 amendment) is now also an audit fault of that code, at the case's last
  disposition, with the report's message. No case writer records the state, and `cases
  correlate` still extends such a case, as it extends any case it may.

`AUDIT_FAULT_CODES` gains `disposition_without_evaluation`; the other shapes reuse existing
codes. A marker lowered below its own migration records is now `migration_unexpected` (ADR
0004, amendment of this date), a store fault. Like every store fault it stops `store verify`
before the domain audit, so no domain fault in such a store, `failure_schema_unmarked` and
`coverage_schema_unmarked` included, is reported until the marker agrees with its records. For a
store whose marker and records agree, those two stay content-neutral as the second 2026-10-14
amendment describes. The
writer refuses no new shape except the marking append of ADR 0004, and no golden changes.

## Amendment 2026-10-25: clocks no report can compute with

0.3.0a0 read CKLB and XCCDF clocks, and every clock given on the command line or in an evaluations
file (`--as-of`, `--detected-at`, and an evaluation's `completedAt`, `reducedAt` and `estimatedAt`),
with unguarded parsers, so a store an earlier build wrote can hold a clock in any year. Such a store
verified clean, and then some readers ended in an `OverflowError` traceback. The current readers
hold every one of those clocks to the years 1970 through 9000 UTC (the CHANGELOG has them), so no
current build writes such a clock; this amendment is about history an earlier build left.

Every use a reader makes of a stored clock that can overflow is refused, and nothing else, by
one predicate, `reports.vdt.clock_problem`, which the readers and `store verify` share. The uses
were found by probing stores written with each clock source an earlier build left unguarded
(source clocks, attestations, evaluation `completedAt`, pain reduction and projection instants,
and coverage gaps recorded at a late `--as-of`) through every reader: the three reports with and
without `--inventory` under both classes, `cases correlate`, `cases coverage`, `cases evaluate`,
`cases list` and `store verify`. Three uses overflow:

- **The conversion to UTC.** A source clock whose UTC instant falls outside the years 1 to 9999,
  such as year 1 with a positive offset or year 9999 with a negative one. A report refuses the
  record whose detection time it is, and with `--inventory` coverage refuses every observation
  carrying one; both are the ERROR `clock_out_of_range`, raised as `ReportCompileError`. `cases
  coverage` refuses it the same way, and `cases correlate` refuses the link that would store it
  as `history_invalid`, with nothing appended. The order check of `cases evaluate` and
  `attest-detection` passes such a group by, as it passes one with no detection time; the report
  refuses it. Attestations and evaluation instants are stored in UTC, so only a source clock
  reaches this.
- **The detection deadline.** A detection time, from a source clock or an attestation, whose
  VER-TFR-EVU deadline overflows: 5 days under Class C and 7 under Class B in the pinned rules, so
  a detection time late in 9999-12 is refused under one class and not the other.
- **The evaluation deadlines.** An evaluation `completedAt` whose VDR-TFR-PVR response target or
  VER-TFR-MAV threshold overflows. MAV runs 192 days in both classes and is always computed, so a
  `completedAt` on or after 9999-06-23 is refused under both; PVR is never longer. The report
  refuses the record whose evaluation it is, under its own class. Its message names the first of
  the two that overflows, in the order the report computes them, PVR then MAV, so which rule it
  names depends on the evaluation's PAIN and context.

Each refusal is the ERROR `clock_out_of_range` in a report. Only the conversion reaches `cases
coverage` and `cases correlate`; neither computes a deadline, so a store whose clocks overflow only
a deadline is refused by a report alone. Pain reduction and projection
instants are only compared and printed, and a coverage window never runs from an anchor later
than the run's `--as-of`, so none of them is refused. A clock that computes is never refused:
year 1 with no offset, 1969, 9001 and 9990 as source clocks, and a `completedAt` of 9999-06-22,
report exactly as before, byte for byte.

`store verify` reports each as the audit fault `clock_out_of_range`, which `AUDIT_FAULT_CODES`
gains, beside `evaluation_before_detection` and under the same conditions. An observation whose
source time has no UTC instant is a fault at its own sequence. A group's detection time, resolved
with the recorded attestations as a report from the store resolves it, is a fault when its
deadline overflows under either class, at the earliest observation or the attestation that gives
it. The current evaluation of that group's case is a fault, at the event that recorded it, when
its deadlines overflow under either class. Verify does not know which class a report will use, so
it names every clock some report would refuse. It loads the same pinned rules the report does,
and since every one of these timeframes is in days in every class, the calendar zone cannot
change the answer. Each fault carries the reader's message, with one difference: it names the first
class whose deadline overflows, B before C, where a report names its own class. Verify also names
the evaluation of a group whose detection deadline already overflows, which a report never reaches
because it refuses the record for its detection time first.

An append-only store has no repair for such a clock. Refusing it in the event contract instead
was rejected: every command, `cases list` included, would then refuse the whole store, including
the stores whose clocks report today. No golden changes.

## Amendment 2026-10-26: a case stream that does not hold one case.created, first

Every reader that folds a case refuses a case stream whose first event is not `case.created`, as
`history_invalid` with "case ... begins with ..., not 'case.created'", and one that carries a second
`case.created`, with "case ... carries unexpected event 'case.created' at sequence N". The audit had
no fault for either. Alone, the evaluation order check met one by folding every case and raised, so
`store verify` stopped with that `history_invalid` outside the audit and `audit_history` raised
instead of reporting. Beside a fault no reader refuses (`event_metadata_invalid`,
`failure_schema_unmarked`, `coverage_schema_unmarked`) the order check swallowed the error, and
`store verify` named the other fault alone; beside any other fault the check did not run. Either way
a store every reader refuses was rejected without the fault that refuses it, which the 2026-10-21
amendment's rule forbids.

The audit now reports both as `case_stream_mismatch`, which `AUDIT_FAULT_CODES` gains, with the
readers' messages: a first event of another type, once per case stream at that event, and every
`case.created` after the first, each at its own sequence. One code serves both because they break
one rule, that a case stream holds exactly one `case.created` and holds it first; unlike a failure
or coverage stream, a case stream has no count of events to be overfull against. The fold names only
the first problem it meets, so a stream holding several carries one fault per problem in the audit
and one refusal in a reader. `EventRepository.append` still accepts a second `case.created`; the
rule asks `store verify` to name what a reader refuses, not the writer to refuse it, so that is left
as it is. A second `case.created` naming another tracking id is also `case_tracking_id_mismatch`,
and a first event that does not belong on a case stream at all is also `event_stream_mismatch`, each
at the same sequence; the two describe different facts. A stream whose id names no tracking id stays
`case_tracking_id_mismatch` alone, as that amendment decided.

With this, each refusal in the case fold's own code has a named fault. A stream whose id names no
tracking id, or a `case.created` naming another, is `case_tracking_id_mismatch`; a first event other
than `case.created`, or a later `case.created`, is `case_stream_mismatch`; any other event that does
not belong on a case stream is `event_stream_mismatch`, and also `payload_contract_invalid` when its
type is unpublished; a payload its contract refuses is `payload_contract_invalid`. Whether a field
read in the fold asks more of a value than the contract does is a claim about values, and it was
false for an integer until the 2026-11-02 amendment. What is shown for it is a sweep, not a proof:
`test_history.FoldContractSweepTests` reads every field of every event a case, artifact or failure
fold reads, against a bank of values, and no fold refuses a value its contract passes except a
tracking id another stream names, which is `case_tracking_id_mismatch`. `case_stream_mismatch` is
not a fault the order check runs beside, so a store that carries it is not folded. The readers and
writers refuse exactly what they refused before, and no golden changes.

## Amendment 2026-11-02: a system observation's clock, and a JSON integer

Two more shapes broke the rule of the 2026-10-21 amendment, both found by a differential probe of
`store verify` against the readers. Neither is a shape any command writes.

**A system observation's clock.** The 2026-10-25 amendment names an observation whose source time
has no UTC instant, and on an artifact stream it does. A failure or coverage stream's observation is
a system observation, whose identity converts that clock to UTC (ADR 0002, amendment 2026-08-21), so
computing its fingerprint while validating the payload raised `OverflowError`. That is not a
`ValueError`, so it passed every refusal: `store verify`, each report from the store, `cases
correlate`, `cases coverage`, `cases evaluate`, `cases attest-detection --case` on a case that
carries an evaluation, `ingest --record-failed-imports` of a failed file when the clock is on a
failure stream, and `EventRepository.append` ended in a traceback.

A system observation with such a clock has no identity, so `Observation` refuses it, as
`ObservationClockError`, a `ValueError`. The repository refuses the payload as `EventContractError`.
`store verify` names it as the existing fault `clock_out_of_range`, in the words an artifact
observation's clock carries, at its own sequence. That fault comes from the contract check rather
than from the walk the 2026-10-25 amendment gates, because the record cannot be built to ask
`clock_problem`, and the walk's order and clock checks do not run beside it, for the same reason.
The readers refuse it as `history_invalid`, "event N is not a readable observation", where an
artifact observation's clock is `clock_out_of_range`: they refuse a record they cannot read, not one
they read and cannot compute with. A command that does not read the stream, such as `cases list`,
still passes such a store, and verify rejects it; the rule does not ask the converse.

No command writes the shape. `--as-of` on `ingest`, a report and `cases coverage` is refused as
`invalid_input`, an invocation clock in a failed reading is read by `parse_clock` and refused as
`source_timestamp_invalid`, and a gap's clock is computed in UTC. 0.3.0a0 has no failure or coverage
stream. So only a store written around the repository holds it. An `ingested_at` with no UTC instant
was probed on each stream kind: no reader converts it and verify passes it, so it is not a gap.

**A JSON integer.** A contract's `integer` is JSON Schema's, which admits `1.0`. Every fold reads
such a field through `_count`, which requires a JSON integer. So `pain`, `targetRating` or `rating`
as `1.0`, `sizeBytes` or `observationCount` as `3.0`, passed the contract, and
`EventRepository.append` stored them. Then alone, `store verify` stopped outside its audit with
`history_invalid` and no fault (a failure head's `sizeBytes` as `failure_stream_mismatch`); beside
`event_metadata_invalid` it named that fault and passed over this one, as the 2026-10-26 amendment
describes for a second creation.

The repository now validates each contract with `integer` meaning what the folds read: an `int` that
is not a `bool`. The bool stays refused, as both sides already refused it. Such a value is
`payload_contract_invalid` at its sequence, alone and beside any other fault, and
`EventRepository.append` refuses it. A reader that reads the field still refuses it, in the
contract's words rather than `_count`'s. For `pain`, `targetRating` and `rating` the reader's code
changes from `history_invalid` to `event_contract_invalid`, because the case fold validates an event
before it reads it and the commands print that error by its own code. `sizeBytes` and
`observationCount` keep `history_invalid`, "event N is not a readable ...", because the artifact and
failure folds wrap that error. The contract documents do not change, and this needs no new event
version: no reader has read such a value, and no command writes one (`cases evaluate` refuses a
fractional rating as `invalid_input`, on 0.3.0a0 as well, and the two counts are computed). A
validator reading the documents by themselves still passes `1.0`, since JSON Schema has no way to
refuse it.

Each stream kind's shape was probed through `store verify`, the reports, `cases list`, `cases
correlate`, `cases coverage`, `cases evaluate` and `cases attest-detection` before and after this
change. No command that succeeded on such a store before now refuses it, and verify had already
rejected every one. Stores written by 0.3.0a0 and by the base of this change verify and report byte
for byte as before, and no golden changes.

## Amendment 2026-11-03: a tracking identifier collision is a store fault

The 2026-10-14 amendment leaves a tracking identifier collision to the report, "unlike" an inverted
evaluation, on the premise that it cannot arrive through `ingest`. That premise is false, and
"effective tracking ids are unique at write time" (2026-08-22) holds for `cases evaluate` alone.
This amendment corrects the first and qualifies the second; both stay as written above.

The route needs only the command line, on every build from 0.3.0a0. `cases evaluate` records an
override that names a correlation id no case holds yet, which its check accepts because it compares
cases. A later `ingest` brings a group with that id. Once that group has a detection time, every
report refuses the store as `tracking_id_collision`, at any `--as-of` and under either class, with
or without a `cases correlate` in between, while `store verify` passed it. A store written around
the writers reaches the same state, two evaluated cases sharing one override among them.

A second route needs one file and no override. A correlation id is 64 bits of SHA-256, so two groups
can share one, and a search on a laptop found a pair in under a minute:
`["cklb","R44e0d066875d4bc4","S"]` and `["cklb","Re463e3245367e5c9","S"]` both give
`case-8c2b3a84c332d647`. By accident the odds are about n^2/2^65, roughly 3e-8 at a million records,
so this takes a crafted or adversary-influenced file, not bad luck. `ingest` accepts the file, and
every report then refuses the store. `cases correlate` refuses it too, as `store_conflict`, because
it opens one stream per group, so no later group gets a case. A store 0.3.0a0 correlated holds one
case for the pair: `cases correlate` passes there, and every report still refuses.

`tracking_id_collision` joins `AUDIT_FAULT_CODES`, on the precedent of
`evaluation_before_detection`, and is checked in the same two branches under the same conditions.
`reports.vdt.tracking_id_collisions` decides it for both sides and `tracking_id_collision_message`
words it, so the fault carries the report's message, `evaluations[N]` included, and the two cannot
drift. The rule reads no clock and no report option. The claimants are what a report compiles, read
as it reads them: each current group claims its correlation id, or the override
`reports.replay.case_evaluations` gives it. An override reaches a report only through the case's
current evaluation, so one with no current evaluation claims nothing. A stale case has no group, so
it claims nothing either. A group no case holds yet still claims its correlation id, which is the
variant the writer's check misses. Two groups under one correlation id each claim and share that
id's evaluation, so the check walks the groups a report compiles and not
`history.order.current_groups`, a mapping that keeps one of them. The fault sits at the latest event
recording an override among the two claimants, the event a new override answers. A pair with no
override sits at the latest `observation.recorded` among the pair's observations: the event that
brought it, until a later scan of either rule moves it.

`cases evaluate` now counts what a report would publish, which qualifies "every case's effective
identifier ... across all cases" (2026-08-22). It counted every folded case, so once a claimant went
stale it refused every file at `recorded history`, an entry about an unrelated case included, while
`store verify` passed and every report succeeded. The command line alone reaches that: an override
naming the id a detection failure will get, or that failure's own override onto a natural id
arriving later, and then the same bytes read under their right name, which supersedes the failure
and leaves its case stale. The writer was wrong, not verify, because a report publishes no record
for that case. A case with no current group now claims nothing, whether the run touches it or not. A
case the run touches claims the entry's `trackingId`, else the recorded override, else its
correlation id. A case it does not touch claims its override only with a current evaluation, else
its correlation id. A case holding an override no report reads, other than its own id, claims
nothing, not its correlation id, because the writer never counted that id for it and counting it
would refuse a run that used to pass.

Every claim is one the old check counted, so this adds no refusal: anything it accepted is accepted
now. It still misses what it missed, a group no case holds and the correlation id of such an unread
case, and verify names what either leaves. A refusal located at `recorded history` now means two
current records already claim one id, so a report refuses that store and verify rejects it. A
refusal naming an entry is located at that entry, where it read `recorded history` when the entry's
case came first in id order.

The fault can name a store before its report does. A group with no detection time is not compiled,
so a report stops at `detection_time_missing` first and meets the collision after the attestation.
The collision is already recorded by then, and attesting cannot clear it, so verify names it. The
reverse holds wherever the check runs: on a log the check runs on, a report that refuses with this
code has its message named by verify at the same store, and a table in
`tests/test_evaluation_order.py` holds that across the stores it builds. Beside a walk fault no
report refuses, such as `event_stream_mismatch`, the check does not run, as
`evaluation_before_detection` does not. Verify then rejects the store under that fault while the
report names the collision. Only a store written around the repository holds that pair, and the
rule, that verify rejects what a reader refuses with a named fault, still holds.

This also states the boundary of the 2026-10-21 rule, "anything a reader refuses, `store verify` now
rejects with a named fault". The rule is about what a store records. A refusal asking for the
workflow's next step that contradicts nothing recorded, such as `detection_time_missing`, is not a
fault: the store is in a normal state, and `examples/README.md` shows that refusal as a step before
attestation. Nor is a refusal of a run's own input, such as `evaluation_unmatched` for an entry no
case matches or an override that would merge two records. That code located at `recorded history` is
no such refusal: it names the store's own collision, and verify rejects that store.

A store holding a collision verified clean before and now exits 1. Every report already refused it,
so no report stops that worked. Where an override made the collision and an entry can name a
claimant, a new override clears both: `cases evaluate` with another `trackingId` records it, and the
store then verifies and reports. An append-only store has no other repair, and two collisions have
no repair through the command line.

Two groups under one correlation id share whatever override their case holds, and where `cases
correlate` refused they have no case to name. So one crafted file holding two groups under one
64-bit id stops every report and `cases correlate` from then on, verify names it, and the remedy is
a new store rebuilt from sources without that file. A claimant whose stored context key is only
whitespace, which an XCCDF `TestResult id=" "` under a benchmark with no id gives, cannot be named
either: `contextKey` must be non-blank, so once a twin under a real name makes its source record
ambiguous, no entry reaches it, and verify and every report refuse from then on. A CKLB file's blank
STIG name is not that case: it is stored as `cklb`, which an entry can name. Refusing a second
identity under a held id, widening the id, and reaching a whitespace context key are not decided
here; each needs its own ruling.

The message now quotes an override through `shown`, cut past 200 characters of the quoted form, as
other stored values are, on both sides. A plain override of up to 198 characters prints as before,
and one heavy in escapes is cut sooner. No golden changes.

## Amendment 2026-11-03 (second): `ingest` refuses a second identity under a held id

The amendment above says "`ingest` accepts the file" and leaves refusing it to its own ruling. The
ruling came the same day: `ingest` refuses a second identity under a tracking id already held, which
keeps ids and goldens where they are, though it is a new refusal. This corrects that sentence, which
stays as written above. An identity here is the group key a tracking id is derived from,
`(source_type, source_record_id, context_key)`.

The check runs in `_run_ingest`, inside the transaction and before anything is appended, just after
`failure_read_elsewhere`, with its logic in `history.writers.tracking_id_refusals`. It is not in
`record_ingest`: a run scans the log once, and library callers and test stores stay as they are.

It maps each tracking id to the identities holding it, from every `observation.recorded` in the
store: every stream kind, every disposition, current or superseded. A superseded reading counts
because its case stream still exists, so `cases correlate` would link a second identity onto another
identity's case. A non-open observation counts because identity does not depend on disposition, and
a later scan can open it. It then walks this run's identities in listed order, each file's in file
order, adding as it goes. An identity whose id has a set not holding it is refused, so a pair inside
one file, across two files of a run and across two runs are all refused. An identity already in its
id's set is fine, unless the store already held that id under two identities when the walk began.

A run's identities include the system observation each failed reading or side record would mint,
after that file's own, through `system_observation_for`, because a failure's id can be searched for
too. That call can raise `ValueError`. Such a failure brings no identity to the walk, and
`record_failure` meets the same error once the writes begin and refuses the run as
`history_invalid`, as it always has. If another identity is refused first, the run names that one,
and nothing is recorded either way.

The refusal is one ERROR `tracking_id_held` per refused identity, located at the name of the file
that first brought it. It names the id and both identities through `shown`, the holder being the
first identity recorded or walked under that id, and ends "nothing was recorded by this run". The
run exits 1, records nothing, and at a path with nothing behind it publishes no store.
`--record-failed-imports` does not turn it into a failure, because it is not a failed reading: that
run exits 1, not 3, and each pure failure then writes its own diagnostics after the refusal lines,
as under `failure_read_elsewhere` (ADR 0014 Decision 13). `REPORT_DIAGNOSTIC_CODES` grows by one.

An earlier build or a library caller can have left a store holding a pair, and no command changes
what it holds. There are two kinds.

A live pair is two current groups under one id. Verify names it and every report refuses it. `cases
correlate` says `store_conflict` when both groups meet in one correlate. When the first was already
correlated it exits 0 and links the later side onto the first's case, so its exit 0 clears nothing.
No override can part the two, and the remedy is a new store rebuilt from sources without that file.

A latent pair is both identities held with at most one current, because a side is not open or its
reading is superseded. Verify, every report and `cases correlate` name no collision in it, so
verify's exit 0 does not mean no pair, nor that its reports are right: a report puts the current
side under whatever evaluation the id's case holds, so `report avi` can publish it with the
acceptance rationale an operator wrote for the other side. One more current reading of the other
side would make it live and stop every report, the outcome this check exists to prevent. The remedy
is the same new store, rebuilt without the file holding one of them. Until a run brings either side
or an election makes it live, nothing names the pair.

So an id the store holds under two identities is closed, live or latent, overriding "an identity
already in its id's set is fine" for that id alone. The ids are fixed before the walk, so a pair
inside the run closes nothing. Any identity a run brings under a closed id is refused, a rerun of
bytes already recorded included: mirroring `record_ingest`'s own test for that could drift, and a
rerun's only cost is exit 1 on a store that holds a pair, with the pair named to the operator. A new
identity keeps the words above. A restated side reads "tracking id X is already held by OTHER and
IDENTITY, so a run may bring neither and nothing was recorded by this run", OTHER being the first
holder that is not that identity. Each identity is named once a run. An id with one holder is as
above, and a rerun of a lone holder passes.

A run bringing no identity under that id passes, and it can still move which readings are current,
because a reading of bytes the store already holds, under another parser or version, joins their
election (ADR 0014, R1 to R6). So one file two adapters read can clear a live pair: recorded by an
earlier build as CKLB with both sides in it, the same bytes named `.sarif` read as neither side,
that reading wins, verify and every report then pass, and the store holds a latent pair. So "from
then on" and "no repair through the command line" in the amendment above hold only until such a
reading. The same election can bring a retired side back and make a latent pair live, which has
been reproduced only with parser versions no shipped build has. This predates the check, which
compares identities and does not weigh elections.

The boundary the amendment above states covers the refusal: it is a refusal of a run's own input,
not a store fault, so a refused run leaves verify's answer as it was. The amendment above says a
code located at `recorded history` names the store's own collision and verify rejects that store.
This code is located at the file that brought the identity, and a run bringing no identity under
that id passes, so the refusal is of that run's input even on a closed id, where a restated side's
line names two stored identities.

A genuine accident would meet the same refusal, about 3e-8 at a million records. Neither file is
wrong there, no option or override lets both in, and its only remedy today is a separate store.

The three fields are read from the raw payloads through `EventRepository.read_all`, with no
observation rehydrated, no new store API, no schema change and no new table. On a synthetic store of
15000 observations an `ingest` took about 0.8 s before this and about 1.4 s after, nearly all of the
difference being `read_all`'s check of each row. Rehydrating them took 5.7 s. A payload whose three
fields are not all text is read past, and verify names it.

A log the read path refuses stops the run as `store_integrity` with nothing recorded, as an `ingest`
recording a failure already did and as every report does. This is a second new refusal on a plain
`ingest`, which used to read only its own streams and pass such a store. Nothing is lost by it: no
report can read that store and `store verify` names it. Reading past it would not hold either: once
`read_all` trips on a page SQLite cannot read, the append in the same transaction fails too, under a
message that blames the append. A file that does not open is refused at open, as it was.

Left out, on purpose. `cases coverage` gets no check: its id needs a second preimage or control of
the inventory, and a later crafted file is refused by this check. The id's width stays. An override
onto a natural id stays as the amendment above describes it, because an override is no identity.
`cases correlate` is not changed. `store verify` does not name a latent pair: no reader refuses one
as a pair, and exit 1 would fail stores the reports still read. No golden, fixture, example,
tracking id or store byte moves for a store with no pair, and a run on such a store reads exactly as
it did.

## Amendment 2026-11-04: `store verify` warns on a latent pair

The amendment above says "Until a run brings either side or an election makes it live, nothing names
the pair", "verify's exit 0 does not mean no pair" and, under Left out, "`store verify` does not
name a latent pair". The ruling came the next day: verify warns on a latent pair and still exits 0.
Those sentences stay as written above and stop holding here. Reports and `cases correlate` still
name no collision in one.

When verify finds no fault it calls `history.writers.latent_pair_warnings`, and prints one WARNING
`tracking_id_latent_pair` per tracking id the log holds under two or more identities, on standard
error, before the unchanged `ok:` line, in the order the log first holds each id. Each line names
the id and its first two holders through `shown`, then counts any more, so only that count grows
with them. The scan is `_identities_held`, the same one `ingest` closes an id by, so the two agree:
the warning names exactly the ids a run may bring nothing under.

Whether a side is current is not read. Two current groups under one id each claim it, which is a
`tracking_id_collision` fault, so on a store with no fault every id held twice has at most one side
current. So exit 0 with no warning means the log holds no id under two identities.

That holds of a store no writer is changing. Verify's reads are not one snapshot and were not before
this: the integrity walk, the audit and this scan each read for themselves. So a writer committing
both sides of a pair just after the audit gets it named here as latent when it is live, beside an
`ok:` count taken before that write, and the next verify names it as the fault. No `ingest` of this
build can do that, because it refuses a pair inside its write transaction. It takes a library caller
or an earlier build, and the pair is named either way, with the same remedy.

Only a store with no fault reaches the warning. A live pair keeps its `tracking_id_collision` lines
and a store with any other fault prints what it did, so every exit 1 reads byte for byte as before.
A pair beside a fault is named once that fault is gone, which includes the latent shape that fails
verify and every report as `evaluation_before_detection`.

An election can still move a store between the two answers, as the amendment above says. One that
clears a live pair now leaves exit 0 with this warning, and one that brings a retired side back
turns the warning into the fault. What it can no longer do is leave a pair unnamed.

This is not a refusal, so the store rule asks nothing of it, and ADR 0017 I3 already says a WARNING
never changes an exit. ADR 0017's table row for `store verify` stands, because only the exit status
is a contract there. A job gating on verify's exit status does not see this line. The line carries
no
location: the amendments above say a code located at `recorded history` names a store's own
collision and verify rejects that store, and this one names a store's own pair and verify passes
it. `REPORT_DIAGNOSTIC_CODES` grows by one. Verify reads the log once more, the read the amendment
above costs an `ingest`.

Left out, on purpose. A report does not warn, since no reader refuses a latent pair and a report's
output is compared byte for byte. `cases correlate` does not either. No golden, fixture, example,
tracking id or store byte moves, and verify on a store with no pair reads exactly as it did.

## Amendment 2026-11-09: what a replay of recorded changes may word apart

ADR 0018 records declared changes in the store on a fifth stream kind, `change/<sha256(changeId)>`,
so a report and a detection request can be derived from the log with no change file in hand.
Decision 5 promises the rebuilt report is byte-identical to the stateless one compiled from the same
inputs. The file cannot be named on a path that never read it, so this is a named carve-out, in the
style of the ADR 0014 and ADR 0015 ones. These rules bind from this date.

- **Decision 5 has a carve-out for the change file's provenance.** A store that recorded exactly the
  file a stateless run reads gives that run's bytes but for three things: the `input` object of
  `x-complyroll.changes`, its twin the first sentence of the Markdown `## Changes` section, and the
  detection request's `input` object. Stateless, `input` names the file by its name, size, digest
  and change count. On the store path it is `source: store` and each distinct `changesSha256` with
  its count, and the sentence reads the same digests and counts.
- **Nothing else moves.** Every other byte is identical, including diagnostics, their locations and
  their order, which is why a stored change keeps the `changesName` of the file it came from. On the
  store path a request's diagnostics include what a report from that store prints about its own
  readings, as they do for `report --db` (Decision 5), with `stale_case` saying "this request"
  instead of "this report". `recordedAt` reaches no output. A refused run publishes nothing, and
  `change_rule_unavailable` says which input it read, a change file or recorded changes.
- **The gap divergences stay the coverage ones.** A lapsed window as a case belongs to a later
  section of ADR 0018 and adds none here. Whether a run is coverage-gap-aware follows a coverage
  stream, as ADR 0015 Decision 37's amendment of this date records, so recording a change adds no
  window key and no `coverage_gap_*` note.

The test of this carve-out compares the real output of both paths, not their derived objects:
`tests/test_changes_persisted.py` holds the JSON, the Markdown, the request and standard error to
each other with only those regions cut, and `tests/golden/vdt-changes-replay.{json,md}` are the
replay pair of `tests/golden/vdt-changes.{json,md}`. A store that never records a change reads as it
did, and no existing golden moved.
