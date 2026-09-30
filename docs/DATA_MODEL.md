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
| `resource_type` | Host, image, repository, service, policy, process, identity, etc. Observations already carry one on `ResourceRef`: `host` for the STIG sources and `image`, `file`, `logical`, or `scan` for SARIF (ADR 0011); `target` or `scan` for HDF (ADR 0013) |
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
| `origin` | `artifact` for observations parsed from a source file; `system` for observations ComplyRoll generates about its own detection and response process (stale scans, missing resources, failed imports) |

`observed_at` may be unknown when a source format does not declare an assessment timestamp.
ComplyRoll records that absence and emits a diagnostic; it does not treat file modification or
ingestion time as equivalent evidence. The official Vulnerability Detail schema requires a
detection time, so a case built from such an observation needs an explicit, attributable
detection-time attestation before it can be reported (ADR 0007 Decision 2: `--detected-at` on
the stateless path, `cases attest-detection` on the persisted path).

System observations carry no artifact name or digest; they require `observed_at` (the detection
window) and a non-blank `context_key` naming the producing validation or job. Their identity is
SHA-256 over a JSON-encoded list of origin, source type, tool, parser name and version, record
identifier, resource, context key, and the UTC observation time (ADR 0002 amendment).

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
