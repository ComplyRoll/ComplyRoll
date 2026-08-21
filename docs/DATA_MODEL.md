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
| `payload_sha256` | Integrity digest over the exact canonical payload bytes |

A named projection checkpoint records the last global sequence applied. Projection tables are
query accelerators, not source history, and must be rebuildable from sequence zero.

## Policy deadline

A calculated deadline is a derived value with explicit inputs and policy provenance:

| Field | Purpose |
|---|---|
| `rule_id` / `rule_name` | Official rule that supplied the timeframe |
| `force` | Selected MUST, SHOULD, MAY, or negative force for the profile |
| `start_at` | Detection, completed evaluation, or recurrence anchor |
| `due_at` | UTC result of applying the structured source timeframe |
| `timeframe` | Exact source amount and unit |
| `profile` | Certification type, path, class, and affected party |
| `provenance` | Repository, commit, dataset version/date, and SHA-256 |
| `description` | Source context for PAIN response matrix entries when applicable |

An absent structured timeframe is represented as unavailable, not inferred from rule prose. A
192-day acceptance deadline is an escalation threshold and never an automatic acceptance event.

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

### InformationResource

| Field | Purpose |
|---|---|
| `resource_id` | Stable provider identifier |
| `resource_type` | Host, image, repository, service, policy, process, identity, etc. |
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
| `evidence_refs` | Content-addressed supporting evidence |
| `source_artifact_digest` | Integrity and idempotency anchor |

`observed_at` may be unknown when a source format does not declare an assessment timestamp.
ComplyRoll records that absence and emits a diagnostic; it does not treat file modification or
ingestion time as equivalent evidence.

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

### ResponseAction

Records a partial mitigation, full mitigation, remediation, validation, or other response. It
includes planned time, completed time, target PAIN, actual result, owner, and evidence.

Mitigation and remediation are not interchangeable. A fully mitigated weakness can still exist
until remediated.

### AcceptedVulnerability

Acceptance is a case state with an explicit rationale and continued monitoring. It is not a
silent age-based closure. ComplyRoll can flag the 192-day categorization requirement but cannot
make the acceptance decision.

### ValidationDefinition and ValidationRun

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
- Sensitivity classification
- Redacted representation
- Retention status

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
