# FedRAMP 2026 mapping

Status date: **2026-08-20**

This document is a design mapping, not a replacement for official rules. Runtime policy must use
a pinned copy of the canonical [`FedRAMP/rules`](https://github.com/FedRAMP/rules) dataset.

The current pin is recorded in `src/complyroll/data/fedramp-rules-source.json`: dataset version
`2026.07.14.01` at commit `58efbf3d898496dd4a3a419eba78e458bbad5cb6`, with separate rules and
schema SHA-256 digests. Phase 1 now bundles and verifies the exact official dataset bytes before
selecting provider-facing 20x Class B or Class C rules. Runtime deadlines come from the selected
structured rules rather than the planning tables below or application constants.

The pinned `VDR-TFR-NMV` rule currently states its three-month expectation in prose without
structured timeframe fields. ComplyRoll preserves the rule but does not calculate that clock until
an authoritative structured value is available. KEV due dates likewise require the applicable
CISA catalog input.

## Current program context

FedRAMP 20x is a generally available certification type under the Consolidated Rules for 2026.
The public Class B and Class C pipelines are scheduled to open on August 31, 2026. Class C is the
practical successor to the prior Moderate route, but certification classes express assurance
depth rather than replacing agency impact categorization one for one.

## VDR and VER must be implemented together

- VDR defines persistent vulnerability detection and response.
- VER defines contextual evaluation and reporting.
- CDS governs certification-data sharing and human/machine consistency.
- SDR records provider implementation, validation, assessment, and evidence.
- KSI rules define the measurable outcomes that persistent validation must demonstrate.
- CCM defines ongoing reports and review cycles.

## VDR scope

A VDR vulnerability is not limited to a CVE or scanner finding. Relevant sources include:

- Assessment and scanning
- Threat intelligence and KEV monitoring
- Vulnerability disclosure and bug bounty
- Penetration testing and incident response
- Automated control and KSI testing
- Supply-chain monitoring
- Resource drift
- Stale Security Decision Record statements
- Failures in the detection or response process

This scope is why ComplyRoll models `Observation` separately from `VulnerabilityCase`.

## Class C operational mapping

These values describe the current rules for planning and tests. Application code must select them
from the pinned canonical dataset.

| Rule concept | Current Class C expectation | ComplyRoll behavior |
|---|---:|---|
| Machine verification/validation | 3 days, MUST | Coverage and freshness clock |
| Representative machine detection | 3 days, SHOULD | Sampling record and freshness clock |
| Drift-prone resource detection | 14 days, SHOULD | Inventory coverage clock |
| Non-drift-prone resource detection | 1 month, SHOULD | Inventory coverage clock |
| Non-machine verification/validation | 3 months, MUST | Review schedule |
| Complete evaluation | 5 days from detection, SHOULD | Evaluation due date |
| Human-readable activity report | Monthly, MUST | Report projection |
| Historical JSON activity | Every 14 days, SHOULD | Snapshot/API projection |
| Accepted-vulnerability categorization | 192 days from evaluation, MUST | Escalation; never automatic acceptance |

### Current Class C PAIN response targets

The clock begins from completed evaluation and targets a reduction in PAIN through partial
mitigation, full mitigation, or remediation.

| PAIN | LEV + IRV | LEV + not IRV | Not LEV |
|---|---:|---:|---:|
| N5 | 2 days | 4 days | 16 days |
| N4 | 4 days | 8 days | 64 days |
| N3 | 16 days | 32 days | 128 days |
| N2 | 48 days | 128 days | 192 days |

N1 vulnerabilities are handled during routine operations under the current table. KEVs also
follow applicable CISA KEV due dates.

## Required evaluation information

ComplyRoll must support:

- Provider tracking identifier
- Detection time and source
- Evaluation completion time
- Internet-reachable classification
- Likely-exploitable classification
- Current and historical PAIN
- Each completed PAIN reduction
- Planned next reduction and target PAIN
- Overdue status and explanation
- Supplementary risk information
- Final disposition
- Separate accepted-vulnerability rationale

## Official JSON projections

Initial output targets:

- [Vulnerability Detail Report](https://fedramp.gov/schemas/fedramp-vulnerability-detail-report-schema-2026-06-24.json)
- [Accepted Vulnerability Information](https://fedramp.gov/schemas/fedramp-accepted-vulnerability-info-schema-2026-06-24.json)
- [Historical VER Activity](https://fedramp.gov/schemas/fedramp-historical-ver-activity-schema-2026-06-24.json)
- [Common schema definitions](https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json)

Later output targets:

- [Security Decision Record](https://fedramp.gov/schemas/fedramp-security-decision-record-schema-2026-06-24.json)
- [Ongoing Certification Report](https://fedramp.gov/schemas/fedramp-ongoing-certification-report-schema-2026-06-24.json)

FedRAMP schemas are minimum structures. ComplyRoll should preserve provider extensions while
validating the required official structure and preventing key collisions.

## KSI implications

The current dataset contains 46 KSIs across 10 themes. Class C currently requires at least two
automated verification/validation methods per KSI and six months of historical persistent
validation metrics.

ComplyRoll must record validation definitions and runs, not merely upload evidence files. A useful
record includes objective, scope, code version, cycle, criteria, result, coverage, evidence,
provider response, and independent assessor response.

## Certification data sharing implications

FedRAMP-compatible trust centers require programmatic access, uninterrupted authorized access,
and access inventory/history. Human and machine-readable formats must remain consistent through
automation.

ComplyRoll's local core should generate the normalized projections; a later trust-center adapter
can publish them with authorization, logging, redaction, and availability controls.

## Nuances to preserve

- Do not say PAIN is a replacement name for CVSS.
- Do not say a STIG result proves a KSI.
- Do not say POA&Ms universally disappeared; agencies may use provider vulnerability information
  in their own POA&M processes.
- Do not use "internet accessible" as a substitute for "internet reachable."
- Do not use mitigation and remediation interchangeably.
- Do not embed superseded pilot drafts when stable 2026 rules exist.
