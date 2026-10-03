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
exactly two events: a `failure.recorded` v1 head and one `observation.recorded` carrying the
system observation. A failed invocation in a log that imported records its failure stream
beside the artifact stream, never on it.

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
at replay, identically on both paths. A store that holds a failure stream is schema version 2
(see ARCHITECTURE.md, Storage direction); a store that never records one stays at version 1.

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
reports publish it, as described below. `InformationResource`,
`ResponseAction`, `ValidationDefinition`, and `ValidationRun` remain planned entities; their
tables describe intent, not shipped code.

### InformationResource (planned)

| Field | Purpose |
|---|---|
| `resource_id` | Stable provider identifier |
| `resource_type` | Host, image, repository, service, policy, process, identity, etc. Observations already carry one on `ResourceRef`: `host` for the STIG sources and `image`, `file`, `logical`, or `scan` for SARIF (ADR 0011); `target` or `scan` for HDF (ADR 0013); `artifact`, with `sha256:<digest>` of the failed artifact as the id, for a detection process failure (ADR 0014) |
| `service_id` | Cloud service or component membership |
| `boundary_status` | In, inherited, interconnected, customer-responsible, or unknown |
| `drift_likelihood` | Likely, not likely, or unknown |
| `reachability_context` | Paths by which data or actions can reach the resource |

### Observation

| Field | Purpose |
|---|---|
| `observation_id` | ComplyRoll identifier |
| `fingerprint` | Stable deduplication key |
| `source_tool` | Scanner, activity, or validation source |
| `source_record_id` | Rule, CVE, check, ticket, or upstream identifier |
| `source_type` | STIG, XCCDF, SARIF, SBOM, process health, etc. |
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
failures above and the ADR 0002 amendment of 2026-09-30.

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
| `pain` | N1–N5 potential agency impact |
| `potential_agency_impact` | Human explanation of customer effects |
| `is_false_positive` | False-positive conclusion |
| `rationale` | Explainable context and evidence references |
| `evaluator` | Human or automated actor, with method/version |

Evaluation revisions append history. They never rewrite the original completed time or rationale.
In the in-memory aggregate, `VulnerabilityCase.with_evaluation` moves the previous evaluation into
`evaluation_history` and refuses to reactivate an ACCEPTED or CLOSED case unless the caller passes
an explicit reopen flag. Durable history lives in the event log.

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
