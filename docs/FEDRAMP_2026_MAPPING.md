# FedRAMP 2026 mapping

Status date: **2026-09-16**

This document is a design mapping, not a replacement for official rules. Runtime policy must use
a pinned copy of the canonical [`FedRAMP/rules`](https://github.com/FedRAMP/rules) dataset.

The current pin is recorded in `src/complyroll/data/fedramp-rules-source.json`: dataset version
`2026.09.13.02` at commit `58487bda77d76d9ce334304ec2e779ece7cc7d54`, with separate rules and
schema SHA-256 digests. Phase 1 now bundles and verifies the exact official dataset bytes before
selecting provider-facing 20x Class B or Class C rules. Runtime deadlines come from the selected
structured rules rather than the planning tables below or application constants.

The report-schema bundle is independently pinned to official `FedRAMP/schemas` commit
`5156719aa7d0def16cf66f6197db9d6c0024e0e7`. It contains Common Definitions version `0.3.0` and
the Vulnerability Detail, Accepted Vulnerability, and Historical VER Activity schemas at version
`0.1.1`. Each document is digest verified and all cross-document references resolve from the
offline bundle before validation begins. Digests are of the bytes served by GitHub at that commit;
`https://fedramp.gov/schemas/` serves the same documents minified, so byte digests differ there
while the parsed JSON is identical.

`VDR-TFR-NMV` carries a structured three-month `MUST` timeframe since rules `2026.09.13.01`, and
the policy layer exposes it through `SelectedRule.timeframe` and `deadline_for_rule`. The reports
do not turn it into a per-vulnerability deadline: the rule is a recurrence clock on each
non-machine-based information resource, and ComplyRoll has no information resource records yet,
so that clock is scheduled with the Phase 2 coverage and freshness work. KEV due dates require the
applicable CISA catalog input, and `VDR-TFR-KEV` applies "even if the vulnerability has been fully
mitigated", so a KEV clock stops on remediation, not on mitigation.

ComplyRoll raised the missing pair on 2026-08-24 as
[FedRAMP/community discussion 164](https://github.com/FedRAMP/community/discussions/164):
`VDR-TFR-NMV` and four other flat rules stated a numeric cadence in prose while carrying no
`timeframe_type` or `timeframe_num`, against 17 flat rules that carried the pair at the top level.
FedRAMP answered on 2026-09-13 that the timeframes had been entered mostly by hand and these were
missed, added the pair to five rules in `2026.09.13.01`
([FedRAMP/rules pull request 28](https://github.com/FedRAMP/rules/pull/28)): `VDR-TFR-NMV`,
`CCM-OCR-AVL`, `IVV-CSF-MCA`, `MKT-CAS-RFR`, and `MKT-IIP-DLA`, and gave the schema optional
`timeframe_num_min` and `timeframe_num_max` for `CCM-QTR-SAR`, the one rule that states a range.
Only `VDR-TFR-NMV` is inside the VDR and VER scope ComplyRoll selects. The range fields are not
read by the loader, and a selected rule that carried `timeframe_type` without `timeframe_num`
would still be refused rather than read as a range.

Common Definitions `0.2.1` cited `VER-RPT-PAE` for its `painReductionEvent` definition, a rule
identifier that does not exist in the pinned dataset, and no bundled report schema referenced the
definition, so "each completed PAIN reduction" had no official slot and shipped as a provider
extension. ComplyRoll raised this as
[FedRAMP/schemas issue 16](https://github.com/FedRAMP/schemas/issues/16). FedRAMP resolved it
upstream on 2026-09-01 in commit
[5156719a](https://github.com/FedRAMP/schemas/commit/5156719aa7d0def16cf66f6197db9d6c0024e0e7),
where Common Definitions `0.3.0` re-points the definition at `VER-RPT-VDT`. The same commit
closed two other upstream issues by adding an optional `painReductionEvents` array to
`vulnerabilityDetail` (issue 7) and `Remediated` to the `finalDisposition` enumeration
(issue 3). ComplyRoll adopted that pin on 2026-09-04 (ADR 0009), and completed reductions now
publish in the official slot.

## Current program context

FedRAMP 20x is in Phase 3 under the Consolidated Rules for 2026; FedRAMP describes it as a
"widely available" certification path with Class A, B, and C rules finalized and Class D in a
Phase 4 pilot. The Class A pipeline opened August 3, 2026 and the Class B and Class C pipelines
open August 31, 2026 per the official timeline
(<https://www.fedramp.gov/2026/timeline/>). Class C is the practical successor to the prior
Moderate route, but certification classes express assurance depth rather than replacing agency
impact categorization one for one.

### Effective dates

The dataset's `effective` block for VDR and VER reads "Mandated by CISA BOD 26-04": optional
adoption 2026-07-04, obtain and maintain by 2026-12-07, default grace until 2027-03-07. Both
rulesets apply to 20x and Rev5 certifications in Classes B, C, and D. The Consolidated Rules
become mandatory program-wide on 2027-01-01, no new Rev5 applications are accepted after
2027-06-11, and all grace periods expire 2028-02-01. Any "compliant as of" output must cite the
per-ruleset dates from the dataset, not the program-wide ones.

### Force

`VDR-TFR-PVR` (PAIN response targets) and `VER-TFR-EVU` (evaluation window) carry force SHOULD
for every class. `VER-TFR-MAV` (192-day accepted-vulnerability categorization) and
`VER-TFR-MHR` (monthly human-readable report) are MUST. The official `overdueStatus` definition
points at EVU and MAV. A missed PAIN target is overdue against a SHOULD target and must be
labeled as such, not as a MUST violation.

### Reportable-incident thresholds

`VER-TFR-IRI`: Class C SHOULD (Class A/B MAY) treat internet-reachable, likely-exploitable
vulnerabilities rated above N3 as FedRAMP reportable incidents until partially mitigated to N3 or
below. `VER-TFR-NRI`: Class D SHOULD (A/B/C MAY) treat non-internet-reachable, likely-exploitable
vulnerabilities at N5 as reportable incidents until N4 or below. ComplyRoll should derive an
incident-candidate flag from class, IRV, LEV, and current PAIN.

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
| Human-readable activity report | Monthly, MUST | Not mapped; the Markdown twins are renderings of the JSON reports, not this report (ADR 0010) |
| Historical JSON activity | Every 14 days, SHOULD | `report historical` compiles the whole-population snapshot as of a given instant; the cadence is the operator's |
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

## Official-format JSON projections

ComplyRoll output validated against these schemas is "official-format" or "schema-valid". It is
not an official FedRAMP document and schema validity is not a compliance determination.

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

The current dataset contains 46 KSIs across 10 themes. `FRC-CSX-VVK` requires at least two
automated verification/validation methods per KSI for Class C (one for Class B, four for Class
D), and `FRC-CSX-MOT` requires six months of historical persistent validation metrics for Class C
(eighteen for Class D). `SDR-CSX-KMT` additionally requires Class C providers to supply, per KSI,
a 30-day summary, an up-to-one-year summary, and all daily metric data up to the past year where
available. Four KSIs (`KSI-CNA-EIS`, `KSI-MLA-ALA`, `KSI-SVC-PRR`, `KSI-SVC-RUD`) are optional for
Class B and required for Class C through `varies_by_class`.

ComplyRoll must record validation definitions and runs, not merely upload evidence files. A useful
record includes objective, scope, code version, cycle, criteria, result, coverage, evidence,
provider response, and independent assessor response.

## Certification data sharing implications

Trust centers that satisfy the CDS ruleset require documented programmatic access
(`CDS-TRC-PAC`), uninterrupted authorized access (`CDS-TRC-USH`), an agency access inventory and
history (`CDS-TRC-AAI`), and access logs with summaries retained at least six months
(`CDS-TRC-ACL`). Human-readable and machine-readable formats must remain consistent through
automation (`CDS-CSO-CBF`), and every report carries the FedRAMP identifier (`CDS-CSO-FID`).
Certification-data snapshots align to each Ongoing Certification Report period (`CDS-CSO-HAD`);
the report itself is due every three months (`CCM-OCR-AVL`).

ComplyRoll's local core should generate the normalized projections; a later trust-center adapter
can publish them with authorization, logging, redaction, and availability controls.

## Nuances to preserve

- Do not say PAIN is a replacement name for CVSS.
- Do not say a STIG result proves a KSI.
- Do not say POA&Ms universally disappeared; agencies may use provider vulnerability information
  in their own POA&M processes.
- Do not use "internet accessible" as a substitute for "internet reachable."
- Do not use mitigation and remediation interchangeably. Common Definitions `0.3.0` gives
  remediation its own `finalDisposition` value, `Remediated`, distinct from `Fully Mitigated`.
- Do not embed superseded pilot drafts when stable 2026 rules exist.
- Do not treat the acceptance instant as anything but the evaluation's `completedAt`. The
  accepted-vulnerability report selects by activity instants, so an acceptance recorded in a
  later period than the one its evaluation completed in, with no other activity since, is not
  placed in the later period's report (ADR 0010).
- Do not read the historical report as a window. `report historical` is a snapshot of the whole
  known population as of one instant, with `finalDisposition` distinguishing disposed records
  from open ones, and the retrieval cadence of `VER-TFR-MRH` (once a month for Class B, every
  14 days for Class C, both SHOULD) is the operator's to schedule.
- Do not call a Markdown twin the monthly human-readable report. The twins are renderings of the
  JSON reports under `CDS-CSO-CBF`; `VER-TFR-MHR` is not mapped.
