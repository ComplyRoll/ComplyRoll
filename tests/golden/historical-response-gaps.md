# Historical VER Activity Report

- **Certification package:** https://example.test/cpo
- **Certification class:** C
- **Generated at:** 2026-09-15T12:00:00Z
- **Calendar timezone:** UTC

## Provenance

| Source | Reference | Digest |
|---|---|---|
| Rules dataset | https://github.com/FedRAMP/rules at 58487bda77d76d9ce334304ec2e779ece7cc7d54 (version 2026.09.13.02, updated 2026-09-13) | 64915d88e72353c95f321ea4a9014516ac9441972cbd7f3d1abef7d1514c8fc8 |
| Report schema | https://github.com/FedRAMP/schemas at 5156719aa7d0def16cf66f6197db9d6c0024e0e7 (https://fedramp.gov/schemas/fedramp-historical-ver-activity-schema-2026-06-24.json version 0.1.1) | dbbddb51ee25bfe9568c1dcfe1047ea206539dc91dad1fd2658f1a5accf2a6fb |
| Generator | complyroll 0.5.0a0 | n/a |

## Summary

| Measure | Count |
|---|---:|
| Active vulnerabilities | 4 |
| Accepted vulnerabilities | 0 |
| Evaluated | 1 |
| Not yet evaluated | 3 |
| Overdue | 2 |
| Current PAIN N1 | 0 |
| Current PAIN N2 | 0 |
| Current PAIN N3 | 1 |
| Current PAIN N4 | 0 |
| Current PAIN N5 | 0 |

## Active vulnerabilities

| Tracking ID | Source record | Resources | Detected | Evaluation completed | IRV | LEV | PAIN | Next due | Overdue | Disposition |
|---|---|---:|---|---|---|---|---|---|---|---|
| case-a28eeaac0789b5e2 | V-299001 | 1 | 2026-09-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-21e6bd73f9174969 | attestation-lapse | 1 | 2026-09-06T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-11T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-d89cd83626f1cb44 | remediation-recurrence | 1 | 2026-09-12T08:40:00Z | n/a | n/a | n/a | n/a | 2026-09-17T08:40:00Z (VER-TFR-EVU) | no | active |
| case-748ec5056f5557ed | CVE-2099-0101 | 2 | 2026-09-02T10:15:00Z | 2026-09-05T15:00:00Z | yes | yes | N3 | n/a | no | Remediated |

## Active vulnerability details

### case-a28eeaac0789b5e2: V-299001

- **Description:** V-299001: SYNTHETIC. PostgreSQL must log every failed connection attempt
- **Detection source:** stig-viewer-3
- **Detected at:** 2026-09-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-7fe10c3abc6d8a5704f17e0da1d895602bf7cedc12245f1c1f34b0478a6125ca
- **Affected resources:** host lab-db-01
- **Source identifiers:** CCI-000172
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T00:00:00Z and closed 2026-09-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T00:00:00Z | 2026-09-06T00:00:00Z | no |

### case-21e6bd73f9174969: attestation-lapse

- **Description:** attestation-lapse: detection time of case-a28eeaac0789b5e2 was not attested within VER-TFR-EVU from 2026-09-01T00:00:00Z (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-09-06T00:00:00Z (source: system)
- **Observations:** obs-5e1b2b5cf665b208a471fb68c878627a207694012c555f4472872516db3ac823
- **Affected resources:** logical case/case-a28eeaac0789b5e2
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-06T00:00:00Z and closed 2026-09-11T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-06T00:00:00Z | 2026-09-11T00:00:00Z | no |

### case-d89cd83626f1cb44: remediation-recurrence

- **Description:** remediation-recurrence: remediation of case-748ec5056f5557ed recorded 2026-09-05T15:00:00Z did not hold: image:registry.example.test/recurrence/api:1.4.2/usr/lib/libexample-json.so.2 detected again 2026-09-12T08:40:00Z (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-09-12T08:40:00Z (source: system)
- **Observations:** obs-96b8956b3a49f8026796a7ef9c68a42448ada45873af753313b60c3d910b2806
- **Affected resources:** image registry.example.test/recurrence/api:1.4.2/usr/lib/libexample-json.so.2
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-12T08:40:00Z | 2026-09-17T08:40:00Z | no |

### case-748ec5056f5557ed: CVE-2099-0101

- **Description:** CVE-2099-0101: example-json: synthetic flaw for recurrence tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-5d3d36f638f2f652f25ede282b6db91fa395458f6d5619a69a678387da78d28c, obs-dec9d12f79d8a7f3c56f96b44085a7e1ac0174c43076f3630ea626fb25d31e94
- **Affected resources:** image registry.example.test/recurrence/api:1.4.0/usr/lib/libexample-json.so.2, image registry.example.test/recurrence/api:1.4.2/usr/lib/libexample-json.so.2
- **Source identifiers:** CVE-2099-0101
- **Evaluation completed:** 2026-09-05T15:00:00Z by Example Provider vulnerability team (synthetic recurrence fixture)
- **Internet reachable:** yes; **likely exploitable:** yes; **PAIN:** N3
- **Potential agency impact:** SYNTHETIC. The API image parses tenant-supplied JSON with the flawed package, so a crafted request could crash the service that serves agency data.
- **Rationale:** SYNTHETIC. The image was rebuilt with the package pinned above the fixed version, and the build log for the rebuilt image showed the upgrade.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** Remediated; **remediated:** yes
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-05T15:00:00Z | 2026-09-21T15:00:00Z | yes |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-05T15:00:00Z | 2027-03-16T15:00:00Z | yes |

## Accepted vulnerabilities

No accepted vulnerabilities are recorded.

## Detection time attestation

The operator attested a detection time of 2026-09-01T00:00:00Z for 1 vulnerability record(s) whose source artifacts declare no assessment timestamp. ComplyRoll never substitutes file modification or ingestion time for a detection time.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| attestation-untimed.cklb | 326a343eb64c | complyroll.cklb 1 | 1 |
| recurrence-api-after.sarif | a9cf6dddcb86 | complyroll.sarif 2 | 1 |
| recurrence-api-before.sarif | 064a704afcef | complyroll.sarif 2 | 1 |

## Diagnostics

- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [attestation-untimed.cklb]
- **warning** recurrence_after_remediation: case-748ec5056f5557ed is recorded remediated at 2026-09-05T15:00:00Z, and 1 open observation(s) of it were detected after that instant, the earliest at 2026-09-12T08:40:00Z on image:registry.example.test/recurrence/api:1.4.2/usr/lib/libexample-json.so.2; the remediation did not hold, and the record keeps its disposition until an evaluation changes it [CVE-2099-0101]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
