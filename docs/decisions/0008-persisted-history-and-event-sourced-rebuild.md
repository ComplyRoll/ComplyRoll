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
