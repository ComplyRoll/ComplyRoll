# Vulnerability Detail Report

- **Certification package:** https://example.test/cpo
- **Report period:** 2026-08-01T00:00:00Z to 2026-08-31T23:59:59Z
- **Certification class:** C
- **Generated at:** 2026-08-21T12:00:00Z
- **Calendar timezone:** UTC

## Provenance

| Source | Reference | Digest |
|---|---|---|
| Rules dataset | https://github.com/FedRAMP/rules at 58efbf3d898496dd4a3a419eba78e458bbad5cb6 (version 2026.07.14.01, updated 2026-07-14) | 135707003f0aaa5ceb10d7d32c2681e5b1585a4eaf4403d0d135837787e5ae8e |
| Report schema | https://github.com/FedRAMP/schemas at ae43ae2952c5dd5c56d54d12e8b92c7db1b3710a (https://fedramp.gov/schemas/fedramp-vulnerability-detail-report-schema-2026-06-24.json version 0.1.1) | 5e9499e8cb9d0367c888ce41040175270fc9f007ae4f61d0ced34cca81cfe497 |
| Generator | complyroll 0.2.0a0 | n/a |

## Summary

| Measure | Count |
|---|---:|
| Vulnerabilities reported | 6 |
| Evaluated | 2 |
| Not yet evaluated | 4 |
| Overdue | 5 |
| Accepted, reported under VER-RPT-AVI | 0 |
| Excluded by report period | 0 |
| Current PAIN N1 | 0 |
| Current PAIN N2 | 0 |
| Current PAIN N3 | 1 |
| Current PAIN N4 | 1 |
| Current PAIN N5 | 0 |

## Vulnerabilities

| Tracking ID | Source record | Resources | Detected | Evaluation completed | IRV | LEV | PAIN | Next due | Overdue | Disposition |
|---|---|---:|---|---|---|---|---|---|---|---|
| case-490f49bfdd1bd019 | V-253260 | 1 | 2026-08-01T00:00:00Z | 2026-08-05T16:00:00Z | yes | yes | N4 | 2026-08-09T16:00:00Z (VDR-TFR-PVR) | yes | active |
| case-9bed0d8f88355393 | V-260469 | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-1f3e011db93cc89e | V-260470 | 1 | 2026-08-01T00:00:00Z | 2026-08-04T12:00:00Z | yes | yes | N3 | n/a | no | Partially Mitigated |
| case-621d85d6533ce6e5 | V-260474 | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-04efea8c137ae82f | banner_etc_issue | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-6719b316a5ea510b | no_cci_mapping | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |

## Vulnerability details

### case-490f49bfdd1bd019: V-253260

- **Description:** V-253260: Windows must remove the Fax Server role
- **Detection source:** stig-viewer-2
- **Detected at:** 2026-08-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-6e3d196cb5f895fecc7d879eac03f954de2d99f46fdd0bccc11d8f0e88a66dc4
- **Affected resources:** host lab-win-01
- **Source identifiers:** CCI-000366
- **Evaluation completed:** 2026-08-05T16:00:00Z by Example Provider vulnerability team (manual review, procedure VM-04)
- **Internet reachable:** yes; **likely exploitable:** yes; **PAIN:** N4
- **Potential agency impact:** The Fax Server role exposes a legacy service on a Windows host inside the authorization boundary, and a successful exploit would give an attacker a foothold next to agency workloads.
- **Rationale:** The role is installed and listening on the host. Public exploit code exists for the service version in use and the host answers from the internet-facing segment, so exploitation is likely rather than theoretical.
- **Projected next reduction:** N3 by 2026-08-28T16:00:00Z
- **Completed PAIN reductions:** N4 at 2026-08-12T16:00:00Z
- **Disposition:** active; **remediated:** no
- **Overdue:** VDR-TFR-PVR (SHOULD, Class C): the response target for PAIN N4, internet reachable, likely exploitable ran from the completed evaluation 2026-08-05T16:00:00Z and passed 2026-08-09T16:00:00Z with no disposition recorded. Rules dataset commit 58efbf3d898496dd4a3a419eba78e458bbad5cb6. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-08-05T16:00:00Z | 2026-08-09T16:00:00Z | no |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-08-05T16:00:00Z | 2027-02-13T16:00:00Z | no |

### case-9bed0d8f88355393: V-260469

- **Description:** V-260469: Ubuntu must display the Standard Mandatory DoD Notice
- **Detection source:** stig-viewer-3
- **Detected at:** 2026-08-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-f841f4f0e47c5d8710658d433ee82715d679f7a5cfbd9afb4a4e216688ad3926
- **Affected resources:** host lab-ubuntu-01
- **Source identifiers:** CCI-000048
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58efbf3d898496dd4a3a419eba78e458bbad5cb6. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | no |

### case-1f3e011db93cc89e: V-260470

- **Description:** V-260470: Ubuntu must disable account identifiers after 35 days of inactivity
- **Detection source:** stig-viewer-3
- **Detected at:** 2026-08-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-6cdf3ee1f2fa3cf51ea8aac1cc05c8534ec5e56d8398edd559ef5f226b68a674
- **Affected resources:** host lab-ubuntu-01
- **Source identifiers:** CCI-000366, CCI-000795, CCI-003627
- **Evaluation completed:** 2026-08-04T12:00:00Z by Example Provider vulnerability team (manual review, procedure VM-04)
- **Internet reachable:** yes; **likely exploitable:** yes; **PAIN:** N3
- **Potential agency impact:** Dormant accounts stay usable on a host that serves agency tenant data, so a stolen credential keeps working longer than the account owner remains authorized.
- **Rationale:** Inactive accounts are not disabled on the shared Ubuntu host. Session records confirm the host is reachable from the tenant-facing load balancer and that password authentication is accepted, so the weakness is both reachable and usable.
- **Supplementary risk information:** A compensating conditional access rule now blocks sign-in from outside the corporate network while the account expiry policy is finished.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** Partially Mitigated; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-08-04T12:00:00Z | 2026-08-20T12:00:00Z | yes |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-08-04T12:00:00Z | 2027-02-12T12:00:00Z | yes |

### case-621d85d6533ce6e5: V-260474

- **Description:** V-260474: Orphan rule with no CCI reference
- **Detection source:** stig-viewer-3
- **Detected at:** 2026-08-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-dd8f546726ab5b2cb9a096254bd3679185ca8f2cd10045dd7de289ad5553e5d6
- **Affected resources:** host lab-ubuntu-01
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58efbf3d898496dd4a3a419eba78e458bbad5cb6. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | no |

### case-04efea8c137ae82f: banner_etc_issue

- **Description:** banner_etc_issue: xccdf_org.ssgproject.content_rule_banner_etc_issue
- **Detection source:** xccdf
- **Detected at:** 2026-08-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-c1a949d8bba45d81b6badd35b2a1c985370d60f37503e3ddf5c79e07ed45e883
- **Affected resources:** host lab-ubuntu-02
- **Source identifiers:** CCI-000048
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58efbf3d898496dd4a3a419eba78e458bbad5cb6. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | no |

### case-6719b316a5ea510b: no_cci_mapping

- **Description:** no_cci_mapping: xccdf_org.ssgproject.content_rule_no_cci_mapping
- **Detection source:** xccdf
- **Detected at:** 2026-08-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-9d9083ec3329bc5beea5a41c62fb26a19048cbeba1e2c7dc2c7f1e63a081fb21
- **Affected resources:** host lab-ubuntu-02
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58efbf3d898496dd4a3a419eba78e458bbad5cb6. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | no |

## Detection time attestation

The operator attested a detection time of 2026-08-01T00:00:00Z for 6 vulnerability record(s) whose source artifacts declare no assessment timestamp. ComplyRoll never substitutes file modification or ingestion time for a detection time.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| ubuntu-host.cklb | 97d123900424 | complyroll.cklb 1 | 6 |
| windows-host.ckl | e5dfc628039c | complyroll.ckl 1 | 2 |
| openscap-results.xml | 3f5deac4a3d9 | complyroll.xccdf 1 | 3 |

## Diagnostics

- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [ubuntu-host.cklb]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [windows-host.ckl]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [openscap-results.xml]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
