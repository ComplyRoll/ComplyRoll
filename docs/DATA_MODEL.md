# Data model

## Observation versus case

An observation is an immutable statement from a source at a particular time. A vulnerability
case is the provider's stateful response to one logical weakness.

One case can contain many observations across resources and time. One observation belongs to no
more than one active case unless an explicit, reviewable exception model is later introduced.

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
| `observation_id` | TrustRoll identifier |
| `fingerprint` | Stable deduplication key |
| `source_tool` | Scanner, activity, or validation source |
| `source_record_id` | Rule, CVE, check, ticket, or upstream identifier |
| `source_type` | STIG, XCCDF, SARIF, SBOM, process health, etc. |
| `resource` | Affected information resource |
| `observed_at` | When the condition was observed |
| `ingested_at` | When TrustRoll received it |
| `source_severity` | Original normalized severity without PAIN interpretation |
| `disposition` | Open, pass, not applicable, not reviewed, error, or unknown |
| `evidence_refs` | Content-addressed supporting evidence |
| `source_artifact_digest` | Integrity and idempotency anchor |

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
silent age-based closure. TrustRoll can flag the 192-day categorization requirement but cannot
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

TrustRoll may display these together but must not silently convert one into another.
