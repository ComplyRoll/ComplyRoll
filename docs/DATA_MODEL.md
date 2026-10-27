# Data model

## Observation versus case

An observation is an immutable statement from a source at a particular time. A vulnerability
case is the provider's stateful response to one logical weakness.

One case can contain many observations across resources and time. One observation belongs to no
more than one active case unless an explicit, reviewable exception model is later introduced.

## Durable event envelope

Material changes are stored as ordered event envelopes. Domain entities remain independent from
SQLite and are serialized into versioned event payloads at the persistence boundary.

| Field | Purpose |
|---|---|
| `sequence` | Monotonic global replay position assigned by SQLite |
| `event_id` | Globally unique idempotency and conflict identifier |
| `stream_id` | Aggregate history, such as one vulnerability case |
| `stream_version` | Monotonic optimistic-concurrency version within the stream |
| `event_type` | Stable event name such as `case.evaluated` |
| `event_version` | Payload-schema version for that event type |
| `occurred_at` | When the represented domain action occurred |
| `recorded_at` | When ComplyRoll durably appended the envelope |
| `payload` | Canonical JSON object containing versioned domain data |
| `metadata` | Canonical JSON object containing actor and method provenance |
| `payload_sha256` | Integrity digest over the exact canonical payload bytes only; metadata, type, stream, and timestamps are outside it until the planned full-envelope digest and hash chain |

A named projection checkpoint records the last global sequence applied. Projection tables are
query accelerators, not source history, and must be rebuildable from sequence zero. Committed
history is gap-free: global sequences and stream versions are contiguous, and reads raise an
integrity error when a gap shows that an event was removed.

## Policy deadline

A calculated deadline is a derived value with explicit inputs and policy provenance:

| Field | Purpose |
|---|---|
| `rule_id` / `rule_name` | Official rule that supplied the timeframe |
| `force` | Selected MUST, SHOULD, MAY, or negative force for the profile |
| `start_at` | Detection, completed evaluation, catalog listing, or recurrence anchor |
| `due_at` | UTC result of applying the structured source timeframe, or an external due date |
| `timeframe` | Exact source amount and unit, or null when the rule carries none |
| `profile` | Certification type, path, class, and affected party |
| `provenance` | Repository, commit, dataset version/date, and SHA-256 |
| `description` | Source context for PAIN response matrix entries when applicable |

An absent structured timeframe is represented as unavailable, not inferred from rule prose. A
192-day acceptance deadline is an escalation threshold and never an automatic acceptance event.

`VDR-TFR-KEV` is the one selected rule whose deadline is not a duration at all, so its row
publishes `"timeframe": null` and the anchor `catalog`: `start_at` is the date the CISA catalog
added the entry, at 00:00:00Z, and `due_at` is the end of the catalog's published due date in
UTC, which is the midnight that begins the following day. Neither instant reads the configured
calendar timezone, because one global catalog has to mean the same instant in every report that
cites it.

## CISA KEV enrichment

A KEV clock is a report-time enrichment, not a stored record. It exists only on a run given a
catalog with `--kev`, and it reaches the compiler as a report option rather than as an event, so
the stateless and persisted paths produce identical bytes (ADR 0012).

Each compiled vulnerability's `x-complyroll` gains a `kev` key, null when the record matched no
catalog entry dated on or before the UTC date of `--as-of`:

| Field | Purpose |
|---|---|
| `cveId` | The identifier the clock is bound to: earliest due date, lowest `cveID` on a tie |
| `dueDate` | The catalog's published `dueDate` for that entry, used literally |
| `dueAt` | The end of that date in UTC, the midnight beginning the following day |
| `satisfied` | Whether the record is remediated or a false positive, as recorded at run time |
| `pastDue` | Not satisfied and `--as-of` is strictly after `dueAt` |
| `status` | `remediated`, `falsePositive`, `accepted`, `pastDue`, or `open` |
| `entries` | Every matched entry, with `cveId`, `dateAdded`, `dueDate`, and the two optional catalog flags |

`status` is the first of those that applies, in that order, so a satisfied record reports how it
was satisfied and an accepted record reports `accepted` even when `pastDue` is true. Counts of
records past a KEV due date read `pastDue` and never `status`, so an accepted record that missed
its date is counted.

The report-level `x-complyroll` gains `kevSource`, which identifies the catalog the run read:

| Field | Purpose |
|---|---|
| `name` | The catalog file's base name |
| `sha256` | SHA-256 of the raw bytes as read, before any BOM is stripped |
| `sizeBytes` | Size of those bytes |
| `catalogVersion` | The catalog's own version string, descriptive only |
| `dateReleased` | The catalog's release instant, normalized to UTC |
| `count` | The entry count the catalog declares |
| `entriesConsidered` | How many entries this run applied after the `dateAdded` filter |

`catalogVersion` is not unique within a day and entries change after publication, so the digest
and not the version is the catalog's identity. Neither key exists in a run given no catalog.

## Detection process failures

A detection process failure is a stored record, unlike a KEV clock. With
`--record-failed-imports`, an artifact that cannot be parsed (class `parse`), holds no usable
content (class `content`), or reports a failed scanner invocation (class `execution`) becomes one
system observation, built by `system_observation_for` in `adapters/failures.py` (ADR 0014). A
failed invocation in a log that still imports adds the system observation beside the log's own
observations; a reading that fails adds it in place of them. Without the flag nothing is minted.

The observation uses the SYSTEM identity recipe of the ADR 0002 amendment, with these inputs:

| Recipe input | Value |
|---|---|
| `source_type` | `complyroll.detection-process`, which no adapter can emit for an artifact observation |
| `source_tool` | `complyroll` |
| `parser_name`, `parser_version` | `complyroll.detection-failures`, `1` |
| `source_record_id` | `detection-process-failure` |
| `resource_type`, `resource_id` | `artifact`, `sha256:<digest>` of the failed artifact |
| `context_key` | `sha256:<digest>` of the failed artifact |
| `observed_at` | The failed invocation's declared clock, else the instant ComplyRoll saw the failure |

The other fields are fixed: disposition open, source severity unknown, no source identifiers,
`evidence_ids` holding `sha256:<digest>`, `ingested_at` from the failed reading, and the title
`source artifact sha256:<digest> did not yield complete detection results (VDR-CSO-FAV)`. The
name, the parser that failed, and the class are metadata, never identity, so one digest observed
at one instant has one id however it was named or read:

| Metadata key | Purpose |
|---|---|
| `artifact.name` | The failed file's name, passed through `diagnostic_text` |
| `artifact.sha256`, `artifact.sizeBytes`, `artifact.mediaType` | The failed bytes |
| `artifact.parser`, `artifact.parserVersion` | The parser whose reading failed |
| `failure.class` | `execution`, `parse`, or `content` |
| `failure.codes` | The sorted diagnostic codes that decided the class, from a closed vocabulary |
| `failure.clock` | `invocation` when the scanner declared the failed run's clock, else `as-of` |
| `failure.rule` | `VDR-CSO-FAV` |

Correlation groups by source type, record id, and context key, as it does every observation, so
each failing digest is one case. Each report built from a record set that holds a system observation
gains three things, and a record set without one renders exactly as before:

- the record's `x-complyroll.detectedAtSource` is `system`, and its detection time is the
  earliest `observed_at` in its group;
- the report-level `x-complyroll.parserVersions` gains `complyroll.detection-failures`;
- the report-level `x-complyroll.detectionFailures` lists every system observation in the record
  set, reported or excluded by the period, sorted by name, digest, parser, parser version, and
  observation time.

| `detectionFailures` field | Purpose |
|---|---|
| `name`, `sha256`, `sizeBytes` | The failed artifact |
| `parser`, `parserVersion` | The parser whose reading failed |
| `failureClass`, `failureCodes`, `clock` | The metadata values above |
| `observedAt` | The system observation's `observed_at` |
| `trackingId` | The effective tracking id of the record that holds the observation |

On the persisted path a failure is recorded on its own stream,
`failure/<sha256>/<parser_name>/<parser_version>`, named for the failed reading. The stream holds
exactly two events: a `failure.recorded` v1 head (a `failure.held` v1 head for a hold, below)
and one `observation.recorded` carrying the system observation. A failed invocation in a log
that imported records its failure stream beside the artifact stream, never on it.

| `failure.recorded` field | Purpose |
|---|---|
| `name` | The failed file's name, passed through `diagnostic_text` |
| `sha256`, `sizeBytes`, `mediaType` | The failed bytes; `sha256` must match the stream id |
| `parserName`, `parserVersion` | The failed reading's parser; both must match the stream id |
| `ingestedAt` | When ComplyRoll read the bytes |
| `failureClass` | `execution`, `parse`, or `content` |
| `failureCodes` | At least one, unique, each from `FAILURE_CODE_VALUES` |
| `clock` | `invocation` or `as-of` |
| `diagnostics` | What the failed reading contributes to a report, at most 64 entries |

The head carries no tracking id, because the tracking id is derived from the stored observation
at replay, identically on both paths.

A system observation id is the digest and the instant, so two readings of one digest can mint
the same id. A failure another failure stream of the digest already holds is stored as a hold:
the reading's own stream opens with a `failure.held` v1 head, which has the fields above, and
holds the reading's own system record under the shared id. The hold names no holder. The holder
is the first failure stream of the digest holding the id, and it must open with
`failure.recorded`. The replay reads each id once, from the stream whose observation was recorded
first among those no reading supersedes, and names each of the other streams no reading
supersedes with INFO `failure_held`. A store that holds a failure stream is schema version 2,
and version 3 once it holds a hold (see ARCHITECTURE.md, Storage direction); a store that never
records one stays at version 1.

## Information resource inventory and coverage

An information resource inventory is a per-run report input, like a KEV catalog, and never a
stored record. A run given `--inventory FILE` measures detection coverage against it. The
inventory reaches the compiler as a report option rather than as an event, so the stateless and
persisted paths produce identical bytes. Measuring coverage adds and changes no observation:
observations stay immutable source facts, and coverage is derived from them at report time (ADR
0015). Recording a coverage gap, described below, adds a system observation and changes none.

The document is ComplyRoll-native JSON, `examples/inventory.json` is a worked example, and
`InformationResource` under Core entities is its parsed entry.

| Root field | Rule |
|---|---|
| `schema` | `complyroll.inventory`; checked first, so a KEV catalog is refused at once |
| `schemaVersion` | The JSON integer 1 |
| `name` | 1 to 128 printable ASCII characters with no leading or trailing space |
| `resources` | An array of at most `MAX_INVENTORY_RESOURCES` (20,000) entries |

| Entry field | Rule |
|---|---|
| `resourceType` | Required identity text with no colon, matched exactly and case-sensitively |
| `resourceId` | Required identity text, matched exactly |
| `machineBased` | Required JSON boolean |
| `expectedSince` | Required instant from which detection is expected to reach the resource |
| `driftLikely` | `true`, `false`, or `"unknown"`; required on a machine entry, refused on others |
| `sampleGroup` | Optional, under the name rule; adds a `VDR-TFR-PSD` clock for the group |
| `job` | Optional, under the name rule; names the detection process meant to reach the resource |
| `decommissionedAt` | Optional instant, not before `expectedSince`; the entry's clocks stop there |
| `aliases` | Optional array of `resourceType` and `resourceId` pairs that also name the entry |
| `verifications` | Optional, non-machine only: attestations, each an `at` and a `reference` |

The reader refuses and never repairs:

- Unknown keys are refused at every level, and every field is type-checked before any pattern.
- Identity text (`resourceType`, `resourceId`, and both alias fields) follows the adapters'
  rule: at most `MAX_IDENTITY_CHARS` (512) characters, no control, format, surrogate, or
  line-separator code point, and not blank. It is never trimmed, so an identifier with a stray
  space is accepted and never matches. `reference` takes the same rule at 512 characters.
- `resourceType` is an open vocabulary, so `Host` never matches `host`. A colon is refused in an
  entry's type and an alias's type, so a `type:id` context key splits one way.
- `name`, `sampleGroup`, and `job` follow the name rule (`MAX_NAME_CHARS`, 128).
- An instant is an RFC 3339 subset with an uppercase `T` and either an uppercase `Z` or a numeric
  offset, at most 64 characters, matched against an ASCII pattern before it is parsed, normalized
  to UTC, and held between the years 1970 and 9000 UTC, which is the KEV `dateReleased` rule.
  Fractional seconds are truncated to microseconds, so two instants that differ only beyond the
  sixth fractional digit compare equal, `--as-of` included.
- A JSON null reads as absent on every optional field, where the KEV reader refuses it.
- `verifications` is refused on a machine entry, even as an empty array.
- A repeated pair, an alias that names another entry, and an alias that repeats another alias or
  its own entry's pair are refused, and the message names both positions.
- The file is read through the bounded reader at `MAX_INVENTORY_BYTES` (8 MiB) and JSON depth
  16 with the standard 500,000-value bound, and no per-entry cap on aliases or verifications
  applies beyond it.

Entries sort by pair, aliases by pair, and verifications by instant, then reference, so file
order never reaches a report. The inventory's identity is the SHA-256 of its raw bytes, taken
before a BOM is stripped.

### The coverage block

The report-level `x-complyroll` gains `coverage` on a run given an inventory, built from one
`CoverageResult` in `complyroll.reports.coverage`. All three reports carry the same block, and no
period selects from it, because coverage is measured at as-of:

| Key | Content |
|---|---|
| `inventory` | `name`, `sha256`, `sizeBytes`, and `entries`: the file's identity, never its bytes |
| `asOf` | The run's as-of instant in UTC; evidence observed later is never used |
| `basis` | Fixed text saying what a status can and cannot claim |
| `summary` | One row per rule, all five in rule-id order, with `expected` and a count per status |
| `resources` | One row per entry, sorted by type, then id |
| `windows` | Every window that closed with no verification, by rule, subject, and close |
| `unregistered` | Observed resources no entry names, each with its `observations` count |
| `later` | Evidence observed after `asOf`, listed and never used |

A summary row also carries `ruleId` and `force`, and counts distinct clocks, so a sample group's
clock counts once. A resource row:

| Field | Purpose |
|---|---|
| `resourceType`, `resourceId` | The entry's own pair, never an alias |
| `machineBased`, `attested` | `attested` is true when only attestations can verify the entry |
| `driftLikely`, `sampleGroup`, `job` | As declared, null when absent |
| `expectedSince`, `decommissionedAt`, `aliases` | As declared |
| `lastExamined`, `lastVerified` | The latest examination and verification within the cutoff |
| `examined` | How many timed artifact observations examined the entry within the cutoff |
| `untimed`, `untimedEvidence` | How many matching observations carry no source time, and which |
| `afterDecommission` | Evidence observed after `decommissionedAt`, listed and never used |
| `clocks` | The entry's clocks in rule-id order |

A clock and a window share most fields:

| Field | Purpose |
|---|---|
| `ruleId`, `force` | The coverage rule and its selected force, MUST or SHOULD |
| `contextKey` | `<resourceType>:<resourceId>`, or `logical:sample-group/<name>` for a group clock |
| `status` | Clocks only: `current`, `stale`, `missing`, `unanchored`, or `undetermined` |
| `anchor` | `verification`, or `declared` when the clock runs from `expectedSince`; else null |
| `anchorAt` | The instant the clock or window runs from |
| `dueAt` | Clocks only: when the current window falls due |
| `closedAt`, `resumedAt` | Windows only: the due date that passed, and the resuming verification |
| `evidence` | The evidence a verification anchor stands on, else null |
| `standIn` | The member whose verification anchors a group clock, else null |

An unanchored clock has null `anchorAt` and `dueAt`, and a window not yet resumed has a null
`resumedAt`. Evidence carries `kind` (`observation` or `attestation`), `at` (null when untimed),
and the `resourceType` and `resourceId` it named, so a match through an alias shows; then
`observationId` and `disposition` for an observation, or `reference` for an attestation. What
each status means is in `docs/FEDRAMP_2026_MAPPING.md`, under Coverage and freshness.

The Markdown twin gains a `## Coverage` section after Inputs. It names the inventory, its digest,
as-of, and the rules dataset commit, prints the basis, and then has eight subsections: Coverage
by rule, Resources, Clocks, Windows, Unregistered resources, Untimed evidence, Evidence after
decommissioning, and Evidence after as-of. A missing clock with untimed evidence prints the count
beside the status, so a checklist-only host never reads as unexamined. The parity test checks
that the twin states every summary row, resource, clock, window, unregistered resource, and
listed piece of evidence the JSON block carries.

### Coverage gaps

A coverage gap is a stored record, unlike the coverage block. With `--record-coverage-gaps` on a
report, or `cases coverage` into a store, each window in the block becomes one system
observation, built by `coverage_gap_observation` in `reports/gaps.py` (ADR 0015). Without either,
nothing is minted. The observation uses the SYSTEM identity recipe of the ADR 0002 amendment,
with these inputs:

| Recipe input | Value |
|---|---|
| `source_type` | `complyroll.coverage`, which no adapter can emit for an artifact observation |
| `source_tool` | `complyroll` |
| `parser_name`, `parser_version` | `complyroll.coverage`, `1` |
| `source_record_id` | `coverage-gap` |
| `resource_type`, `resource_id` | The clock's subject: the entry's own pair, or `logical` and `sample-group/<name>` for a group clock |
| `context_key` | `<rule>:job:<job>` when the entry names a job, else `<rule>:resource:<type>:<id>` of the subject |
| `observed_at` | The window's close, never as-of or ingest time |

The other fields are fixed: disposition open, source severity unknown, no source identifiers,
`evidence_ids` holding `sha256:<inventory digest>`, `ingested_at` from the report's as-of or from
the `--as-of` of `cases coverage`, which reaches neither the id nor a report, and the title
`<rule> window for <type>:<id> closed <instant> with no verification recorded (VDR-CSO-FAV)`. The
description says ComplyRoll recorded no verification inside the window, and that this records
the absence of a verification, not a vulnerability. The metadata always carries the same eight
keys, and none of them moves the id:

| Metadata key | Purpose |
|---|---|
| `coverage.rule`, `coverage.force` | The coverage rule and its selected force |
| `coverage.anchor`, `coverage.anchorAt` | What the window ran from, `declared` or `verification`, and when |
| `coverage.windowClosedAt` | The window's close, the same instant as `observed_at` |
| `coverage.inventorySha256` | The inventory whose entry carried the clock |
| `coverage.job` | The entry's `job`, or empty text when it names none or the clock is a group's |
| `coverage.basis` | The block's fixed basis text |

Correlation groups by source type, record id, and context key, so a gap case is one rule and one
job, or one rule and one resource. The window's `contextKey` in the block names the clock, while
the gap's context key names the case, and no report prints the latter. A gap record renders as a
failure record does: `detectedAtSource` `system`, detection at the earliest window close of its
case, one `VER-TFR-EVU` deadline from that close, and PAIN only from an evaluation matched on the
full triple. `parserVersions` gains `complyroll.coverage`. A gap-aware run, one with the flag or a
report from a store marked schema 4 given an inventory, adds two keys to every window of the
block, and the Markdown Windows table gains a column for each:

| Window key | Purpose |
|---|---|
| `recorded` | True when a gap record of the run carries the window |
| `trackingId` | That record's effective tracking id, else null |

On the persisted path each gap is recorded on its own stream, `coverage/<fingerprint>`, named for
the gap record's SYSTEM identity hash. The stream holds exactly two events: a `coverage.recorded`
v1 head and one `observation.recorded` carrying the gap record.

| `coverage.recorded` field | Purpose |
|---|---|
| `rule` | The coverage rule, one of the five |
| `contextKey` | The record's context key |
| `windowClosedAt` | The window's close |
| `anchor`, `anchorAt` | What the window ran from, and when |
| `inventorySha256` | The inventory whose entry carried the clock |

Every field is required, no other is allowed, and `store verify` holds each to the record it
heads. The head carries no tracking id and no stream id, because both are derived from the stored
record at replay. A recorded stream is never rewritten, so after an edited inventory the stored
`inventorySha256` stays the first run's. A store that holds a coverage stream is schema version
4, and one that never records a gap stays at its version.

## Report extension (x-complyroll)

Everything ComplyRoll adds beyond the official minimum structure lives under one `x-complyroll`
key, at the report level and on each vulnerability, so a future official field cannot collide
with it (ADR 0007 Decision 8). The report level carries the generator name and version
(`generator`), the parser versions (`parserVersions`), the rules dataset and schema commits and
digests (`rulesSource`, `schemaSource`), and the compile diagnostics (`diagnostics`). Each
vulnerability carries every computed deadline with its rule and force (`deadlines`, each with
`ruleId`, `ruleName`, and `force`; a deadline's `satisfied` says that what stops its clock is
recorded, not that it was recorded by `dueAt`, and no field reports lateness, ADR 0007 amendment
2026-10-26), the grouped observation ids and affected resources
(`observationIds`, `resources`), the detection-time source (`detectedAtSource`: `artifact`,
`artifact-partial`, `attestation`, or `system` for a detection process failure or a coverage
gap), and the evaluator and rationale (`evaluator`, `rationale`). The KEV keys,
`detectionFailures`, and `coverage` described above live under the same key.

The JSON is the complete machine record. The Markdown twin renders the same records for a reader,
with a detail section per vulnerability, and a parity test checks that the twin states every
observation id, deadline, and artifact the JSON carries. That makes the document the provider's and
assessor's working record, and `docs/SECURITY.md` requires redacting it before it is shared with an
agency.

## Schema validation result

Official report validation produces an immutable result rather than a boolean with discarded
context:

| Field | Purpose |
|---|---|
| `report_schema` | Vulnerability Detail, Accepted Vulnerability, or Historical Activity target |
| `provenance` | Official repository, commit, schema ID, schema version, and exact SHA-256 |
| `issues` | Deterministically sorted structural or format failures |
| `instance_pointer` | JSON Pointer to the invalid report value |
| `schema_pointer` | JSON Pointer to the official constraint that failed |
| `validator` | Draft 2020-12 keyword such as `required`, `enum`, or `format` |
| `message` | Human-readable validator explanation |

An empty issue tuple means the document satisfies the selected minimum official structure. It is
not a conclusion that the report is semantically complete, accurate, or compliant with every
narrative rule.

## Core entities

Implemented in `complyroll.models` today: `ResourceRef`, `EvidenceArtifact`, `Observation`,
`Evaluation`, and `VulnerabilityCase`. `models.Evaluation` and `models.VulnerabilityCase` are
exported but unused by production code: the report compiler reads evaluations through
`complyroll.reports.evaluations` and case state through the fold in `complyroll.history`, and
reconciling or retiring the two classes is Phase 2 cleanup. `AcceptedVulnerability` predates
ADR 0010 in `complyroll.reports`; ADR 0010 made the accepted-vulnerability and historical
reports publish it, as described below. `InformationResource` shipped with ADR 0015 in
`complyroll.reports.inventory`, beside the KEV reader. `ResponseAction`, `ValidationDefinition`,
and `ValidationRun` remain planned entities; their tables describe intent, not shipped code.

### InformationResource

`complyroll.reports.inventory` parses the inventory described above into three frozen types, and
a directly built one holds the reader's rules:

- `Inventory`: `name`, `sha256`, `size_bytes`, and `entries` sorted by pair. `entry_for(type,
  id)` returns the entry an exact pair or an exact alias names; nothing is normalized.
- `InformationResource`: `resource_type`, `resource_id`, `machine_based`, `expected_since`,
  `drift_likely` (`True`, `False`, or `"unknown"` on a machine entry, `None` on any other),
  `sample_group`, `job`, `decommissioned_at`, `aliases`, and `verifications`. `identities` lists
  the entry's own pair, then its aliases.
- `Verification`: `at` in UTC and `reference`, one operator-attested verification of a
  non-machine resource.

An alias is a `ResourceRef`, the type an observation's resource already uses, so an alias names
exactly what an observation can carry. Observations carry `host` for the STIG sources and
`image`, `file`, `logical`, or `scan` for SARIF (ADR 0011); `target` or `scan` for HDF (ADR
0013); `image`, `scan`, or `package` for CycloneDX (ADR 0016); `artifact`, with
`sha256:<digest>` of the failed artifact as the id, for a detection process failure (ADR 0014).
The vocabulary stays open, so an entry may name a type no adapter emits yet, and no observation
matches it until one does. The one exception is `package`: a package is a component of the image
or host that carries it, so the inventory refuses it on an entry and on an alias, and the coverage
reader never lists a package observation as unregistered.

Planned fields not carried yet: `service_id` (cloud service or component membership),
`boundary_status` (in, inherited, interconnected, customer-responsible, or unknown), and
`reachability_context` (paths by which data or actions can reach the resource). The planned
`drift_likelihood` shipped as `driftLikely`.

### Observation

| Field | Purpose |
|---|---|
| `observation_id` | ComplyRoll identifier |
| `fingerprint` | Stable deduplication key |
| `source_tool` | Scanner, activity, or validation source |
| `source_record_id` | Rule, CVE, check, ticket, or upstream identifier |
| `source_type` | STIG, XCCDF, SARIF, HDF, CycloneDX (`cyclonedx`), process health, etc. |
| `resource` | Affected information resource |
| `observed_at` | When the condition was observed |
| `ingested_at` | When ComplyRoll received it |
| `source_severity` | Original normalized severity without PAIN interpretation |
| `disposition` | Open, pass, not applicable, not reviewed, error, or unknown |
| `evidence_ids` | Content-addressed supporting evidence |
| `source_artifact_digest` | Integrity and idempotency anchor (lowercase hex; blank for system observations) |
| `origin` | `artifact` for observations parsed from a source file; `system` for observations ComplyRoll generates about its own detection and response process: detection process failures since ADR 0014, with stale scans and missing resources planned |

`observed_at` may be unknown when a source format does not declare an assessment timestamp.
ComplyRoll records that absence and emits a diagnostic; it does not treat file modification or
ingestion time as equivalent evidence. The official Vulnerability Detail schema requires a
detection time, so a case built from such an observation needs an explicit, attributable
detection-time attestation before it can be reported (ADR 0007 Decision 2: `--detected-at` on
the stateless path, `cases attest-detection` on the persisted path).

System observations carry no artifact name or digest; they require `observed_at` (the detection
window) and a non-blank `context_key` naming the producing validation or job. Their identity is
SHA-256 over a JSON-encoded list of origin, source type, tool, parser name and version, record
identifier, resource, context key, and the UTC observation time (ADR 0002 amendment). The first
production recipe, for detection process failures, uses the failed artifact's digest as the
context key, because ComplyRoll has no inventory of detection jobs yet; see Detection process
failures above and the ADR 0002 amendment of 2026-09-30. The second, for coverage gaps (ADR
0015), keys on the inventory entry's `job` when it names one; see Coverage gaps above. Failure
cases stay keyed on the digest.

A SARIF observation (ADR 0011) takes its identity from the literal source type `sarif`, the
driver name as `source_tool`, the rule identifier resolved in the spec's order as
`source_record_id`, the located resource (`image`, `file`, `logical`, or `scan`, with the scoped
uri or logical name as the id), the driver name plus the automation category as `context_key`,
and the artifact digest, through the same nine-input recipe as every other artifact
observation. The result's region, its message text, the producer's `fingerprints` and
`partialFingerprints`, and its `guid` and `correlationGuid` are recorded as metadata and are
never identity. A line move, a reworded message, or a producer's own hashing scheme changes the
log's bytes, so the observation id moves with the artifact digest, as it does for every
artifact, while the resource and the tracking id are kept.

An HDF observation (ADR 0013) takes its identity from the literal source type `hdf`, the source
tool `inspec`, or `heimdall-tools` when `platform.name` is `Heimdall Tools`, the control `id` as
`source_record_id`, the declared target (`target` with `platform.target_id` as the id, or `scan`
with the root profile name when the document declares no target), the name of the root profile
the control hangs under as `context_key`, and the artifact digest, through the same nine-input
recipe. The profile version and `sha256`, the result clocks, the waiver and attestation data, and
the layer of an overlay that carried the results are recorded as metadata and are never
identity. A profile patch or a renamed leaf under the same root changes the document's bytes, so
the observation id moves with the artifact digest, as it does for every artifact, while the
tracking id is kept: its context key is the root profile name, and the version, `sha256`, and
leaf name are not in it.

A CycloneDX observation (ADR 0016) takes its identity from the literal source type `cyclonedx`, the
tool named in `metadata.tools` as `source_tool` and as `context_key`, the vulnerability `id` as
`source_record_id`, a resource, and the artifact digest, through the same nine-input recipe. A
vulnerability is located on a `package` resource whose id is `<scope type>:<lineage>|<package key>`,
for example `image:registry.example.test/web|pkg:npm/lodash`. The scope type is `image` for a
container subject and `scan` otherwise. The lineage is the subject name without its tag or digest,
so `web:1.4` and `web:1.5` share it; a name that is wholly a digest of `md5`, `sha1`, `sha224`,
`sha256`, `sha384`, `sha512` or `blake3`, at that digest's exact length, is its own lineage. The
package key is version-free: a purl reduced
by a frozen qualifier strip set and case table (`pkg:`; `oci` and `docker` keep `repository_url`),
or `component:<type>/<group>/<name>` when there is no usable purl, or `ref:<ref>` when an `affects`
ref resolves to no component. Each document also yields one observation of its subject under the
record id `cyclonedx.bom`, on the scope resource `image:<name>[:<tag>|@<digest>]` or
`scan:<group>/<name>`, which is the pair an inventory entry names: NOT_REVIEWED for an inventory or
an empty list, PASS only when a vulnerability record whose `analysis` has the state `exploitable` or
`in_triage`, or none of a `state`, a `justification`, and a `detail`, resolves to a component the
document lists other than its subject, in an `affects` entry that does not mark the installed
version `unaffected` (ADR 0016 Decision 9). Coverage reads only this observation of a CycloneDX
document, and only a PASS one verifies. Versions, purls as written, bom-refs, the subject's tag and
digest, and any embedded VEX analysis are recorded as metadata and are never identity, so an
upgraded package keeps its resource and its case.

### Phase 0 observation identity

The deterministic observation fingerprint is SHA-256 over:

- Source type and source tool
- Parser name and parser version
- Source record identifier
- Resource type and stable resource identifier
- Benchmark/profile context key
- Exact source artifact SHA-256

The artifact digest makes importing identical bytes idempotent while ensuring a later, changed
assessment remains a separate immutable observation. Parser versioning prevents a changed
normalizer from silently reusing an earlier identifier. Display text and scanner severity are not
separate identity inputs, and any change to their source bytes is captured through the artifact
digest.

### VulnerabilityCase

| Field | Purpose |
|---|---|
| `case_id` | Provider tracking identifier used in reports |
| `title` / `description` | Logical weakness description |
| `status` | New, evaluating, active, mitigated, remediated, accepted, false positive, closed |
| `observation_ids` | Complete supporting observation set |
| `current_evaluation_id` | Current contextual assessment |
| `response_actions` | Planned and completed work |
| `rating_history` | PAIN reductions and evidence |
| `owner` | Responsible provider role or system |

### Evaluation

| Field | Purpose |
|---|---|
| `completed_at` | Starts evaluation-relative response clocks |
| `is_internet_reachable` | IRV classification and rationale |
| `is_likely_exploitable` | LEV classification and rationale |
| `pain` | N1 to N5 potential agency impact |
| `potential_agency_impact` | Human explanation of customer effects |
| `is_false_positive` | False-positive conclusion |
| `rationale` | Explainable context and evidence references |
| `evaluator` | Human or automated actor, with method/version |

Evaluation revisions append history. They never rewrite the original completed time or rationale.
In the in-memory aggregate, `VulnerabilityCase.with_evaluation` moves the previous evaluation into
`evaluation_history` and refuses to reactivate an ACCEPTED or CLOSED case unless the caller passes
an explicit reopen flag. Durable history lives in the event log.

`completedAt` is ordered against `detectedAt`. A report refuses a record whose evaluation completed
strictly before a detection time that is the record's own (an artifact timestamp, an attestation,
or a recorded detection process failure) with the ERROR `evaluation_before_detection`. A group
with only some timestamps keeps its record and gets the WARNING
`evaluation_before_partial_detection`, because an untimed observation may have detected the
weakness earlier. `cases evaluate` checks every entry it matches, refuses on the ERROR and prints
the WARNING. `cases attest-detection` checks only a detection time its own attestation decides, and
`store verify` reports only the ERROR, at the current evaluation. Reductions and projections are
not ordered: `reducedAt` and `estimatedAt` start no clock.

### ResponseAction (planned)

Records a partial mitigation, full mitigation, remediation, validation, or other response. It
includes planned time, completed time, target PAIN, actual result, owner, and evidence.

Mitigation and remediation are not interchangeable. A fully mitigated weakness can still exist
until remediated.

### AcceptedVulnerability

Acceptance is a case state with an explicit rationale and continued monitoring. It is not a
silent age-based closure. ComplyRoll can flag the 192-day categorization requirement but cannot
make the acceptance decision.

Implemented in `complyroll.reports`, and published by the accepted-vulnerability and historical
reports since ADR 0010. An evaluation with `disposition: "accepted"`
and a non-blank `acceptanceRationale` marks the case accepted, whether it arrives in an
evaluations file or as a `case.disposition_recorded` event. The detail report sets each
accepted record aside on `report.accepted` as `AcceptedVulnerability(record, rationale)` and
publishes neither. The accepted-vulnerability and historical reports publish each as an
`acceptedVulnerabilityInfo` item and refuse to compile, with the ERROR diagnostic
`acceptance_rationale_missing`, when an accepted record's evaluation carries no rationale. The
acceptance instant is the evaluation's `completedAt`; the store's `recordedAt` never reaches a
report.

### ValidationDefinition and ValidationRun (planned)

A definition states what is being demonstrated, scope, code or query version, schedule, and clear
pass/fail/unknown criteria. A run records execution provenance, result, coverage, evidence, and
provider/assessor comments.

### EvidenceArtifact

Evidence metadata is separate from its body:

- Evidence type
- URI or content-addressed location
- Description
- SHA-256 digest
- Collected and last-updated times
- Producer and method version
- Sensitivity classification (`restricted`, `internal`, or `public`; `restricted` by default)
- Redacted representation
- Retention status

Of the fields above, the implemented `EvidenceArtifact` carries identifier, digest, type,
description, collection time, location, and sensitivity. Producer, method version, last-updated
time, redacted representation, and retention status are planned.

## Explicitly separate vocabularies

| Vocabulary | Meaning |
|---|---|
| DISA CAT | STIG severity category |
| CVSS | Technical severity characteristics |
| Scanner severity | Source-specific prioritization |
| LEV | Likelihood of exploitation in service context |
| IRV | Ability of internet-originating data/actions to reach the weakness |
| PAIN | Potential adverse effect to federal agency customers |

ComplyRoll may display these together but must not silently convert one into another.
