# Vulnerability Detail Report

- **Certification package:** https://example.test/cpo
- **Report period:** 2026-08-01T00:00:00Z to 2026-08-31T23:59:59Z
- **Certification class:** C
- **Generated at:** 2026-08-21T12:00:00Z
- **Calendar timezone:** UTC

## Provenance

| Source | Reference | Digest |
|---|---|---|
| Rules dataset | https://github.com/FedRAMP/rules at 58487bda77d76d9ce334304ec2e779ece7cc7d54 (version 2026.09.13.02, updated 2026-09-13) | 64915d88e72353c95f321ea4a9014516ac9441972cbd7f3d1abef7d1514c8fc8 |
| Report schema | https://github.com/FedRAMP/schemas at 5156719aa7d0def16cf66f6197db9d6c0024e0e7 (https://fedramp.gov/schemas/fedramp-vulnerability-detail-report-schema-2026-06-24.json version 0.1.1) | 5e9499e8cb9d0367c888ce41040175270fc9f007ae4f61d0ced34cca81cfe497 |
| Generator | complyroll 0.3.0a0 | n/a |

## Summary

| Measure | Count |
|---|---:|
| Vulnerabilities reported | 13 |
| Evaluated | 2 |
| Not yet evaluated | 11 |
| Overdue | 12 |
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
| case-656d627b62275ba8 | coverage-gap | 2 | 2026-07-04T00:00:00Z | n/a | n/a | n/a | n/a | 2026-07-09T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-56e1eee78e97395f | coverage-gap | 1 | 2026-07-04T00:00:00Z | n/a | n/a | n/a | n/a | 2026-07-09T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-fe51d8e4d9c79b36 | coverage-gap | 1 | 2026-07-15T16:00:00Z | n/a | n/a | n/a | n/a | 2026-07-20T16:00:00Z (VER-TFR-EVU) | yes | active |
| case-9c9bf88832065e17 | coverage-gap | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-987c96e87614506a | coverage-gap | 1 | 2026-07-15T00:00:00Z | n/a | n/a | n/a | n/a | 2026-07-20T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-23ec0644fabe50d3 | coverage-gap | 1 | 2026-07-15T00:00:00Z | n/a | n/a | n/a | n/a | 2026-07-20T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-a971b430300440cf | coverage-gap | 1 | 2026-07-04T00:00:00Z | n/a | n/a | n/a | n/a | 2026-07-09T00:00:00Z (VER-TFR-EVU) | yes | active |
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
- **Overdue:** VDR-TFR-PVR (SHOULD, Class C): the response target for PAIN N4, internet reachable, likely exploitable ran from the completed evaluation 2026-08-05T16:00:00Z and passed 2026-08-09T16:00:00Z with no disposition recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

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
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

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
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | no |

### case-656d627b62275ba8: coverage-gap

- **Description:** coverage-gap: coverage gap: VDR-TFR-MVX window for host:lab-win-01 closed 2026-07-04T00:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-07-04T00:00:00Z (source: system)
- **Observations:** obs-59fbb69836e1874231e0ce7eed88c5669b626cb453ace189f6345424340c93a1, obs-4b422e90cbdc0a568f0e800f372d48d2120de7a62675d79d8339f92fde253970
- **Affected resources:** host lab-win-01, host ubuntu-web-01
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-07-04T00:00:00Z and closed 2026-07-09T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-07-04T00:00:00Z | 2026-07-09T00:00:00Z | no |

### case-56e1eee78e97395f: coverage-gap

- **Description:** coverage-gap: coverage gap: VDR-TFR-MVX window for host:lab-rhel-01 closed 2026-07-04T00:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-07-04T00:00:00Z (source: system)
- **Observations:** obs-93163dadcffc2fa5e3efd858b439b2be6c792975a029a95596b26b92be6fd56c
- **Affected resources:** host lab-rhel-01
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-07-04T00:00:00Z and closed 2026-07-09T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-07-04T00:00:00Z | 2026-07-09T00:00:00Z | no |

### case-fe51d8e4d9c79b36: coverage-gap

- **Description:** coverage-gap: coverage gap: VDR-TFR-NMV window for logical:backup-restore-procedure closed 2026-07-15T16:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-07-15T16:00:00Z (source: system)
- **Observations:** obs-27323a204397b0a2cb25d1f0effb7b7cf11c687350d862fc34b9a75d0773c7ea
- **Affected resources:** logical backup-restore-procedure
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-07-15T16:00:00Z and closed 2026-07-20T16:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-07-15T16:00:00Z | 2026-07-20T16:00:00Z | no |

### case-9c9bf88832065e17: coverage-gap

- **Description:** coverage-gap: coverage gap: VDR-TFR-PCD window for host:lab-win-01 closed 2026-08-01T00:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-08-01T00:00:00Z (source: system)
- **Observations:** obs-c5143479e12c76daad73fd1e458defd592a1dbca33644f9b7040ee7573c27f7b
- **Affected resources:** host lab-win-01
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | no |

### case-987c96e87614506a: coverage-gap

- **Description:** coverage-gap: coverage gap: VDR-TFR-PDD window for host:ubuntu-web-01 closed 2026-07-15T00:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-07-15T00:00:00Z (source: system)
- **Observations:** obs-6ef76ee108c6ebc7e7ef2d90bee2d983e2e952c9d812d97b312697826056a2d7
- **Affected resources:** host ubuntu-web-01
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-07-15T00:00:00Z and closed 2026-07-20T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-07-15T00:00:00Z | 2026-07-20T00:00:00Z | no |

### case-23ec0644fabe50d3: coverage-gap

- **Description:** coverage-gap: coverage gap: VDR-TFR-PDD window for host:lab-rhel-01 closed 2026-07-15T00:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-07-15T00:00:00Z (source: system)
- **Observations:** obs-2476582a72700fbb5250049faf3faaf3daabaaefead5c7881b86ee7ef3e2ba4b
- **Affected resources:** host lab-rhel-01
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-07-15T00:00:00Z and closed 2026-07-20T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-07-15T00:00:00Z | 2026-07-20T00:00:00Z | no |

### case-a971b430300440cf: coverage-gap

- **Description:** coverage-gap: coverage gap: VDR-TFR-PSD window for logical:sample-group/ir-runbooks closed 2026-07-04T00:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-07-04T00:00:00Z (source: system)
- **Observations:** obs-140cae03473a44858d421f78684c8f31360a8d78486f425ca6a433ae37d785ce, obs-1db1082f48622e26508155b2cf0dc4adf2a6cf8abc3faa705477a641f0db7667
- **Affected resources:** logical sample-group/ir-runbooks
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-07-04T00:00:00Z and closed 2026-07-09T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-07-04T00:00:00Z | 2026-07-09T00:00:00Z | no |

### case-04efea8c137ae82f: banner_etc_issue

- **Description:** banner_etc_issue: xccdf_org.ssgproject.content_rule_banner_etc_issue
- **Detection source:** xccdf
- **Detected at:** 2026-08-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-c1a949d8bba45d81b6badd35b2a1c985370d60f37503e3ddf5c79e07ed45e883
- **Affected resources:** host lab-ubuntu-02
- **Source identifiers:** CCI-000048
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

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
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-01T00:00:00Z and closed 2026-08-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-01T00:00:00Z | 2026-08-06T00:00:00Z | no |

## Detection time attestation

The operator attested a detection time of 2026-08-01T00:00:00Z for 6 vulnerability record(s) whose source artifacts declare no assessment timestamp. ComplyRoll never substitutes file modification or ingestion time for a detection time.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| openscap-results.xml | 3f5deac4a3d9 | complyroll.xccdf 1 | 3 |
| ubuntu-host.cklb | 97d123900424 | complyroll.cklb 1 | 6 |
| windows-host.ckl | e5dfc628039c | complyroll.ckl 1 | 2 |

## Coverage

Coverage of the inventory example-boundary (7 entries, 1954 bytes, SHA-256 553f46343b7896851926232f9920ce16e708483495002852050277243fb1b84f) as of 2026-08-21T12:00:00Z, with clocks from rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54.

VDR-TFR-MVX is read from detection results until Phase 3 validation runs exist. Coverage is measured against the provider-supplied inventory named by its SHA-256 digest, so an observed resource the inventory omits is listed as unregistered and is never expected. Evidence that determined no status (NOT_REVIEWED, ERROR or UNKNOWN) examines a resource without verifying it, untimed evidence never anchors a clock, and a non-machine resource is verified only by an operator attestation. A current status is not a compliance finding.

### Coverage by rule

| Rule | Force | Expected | Current | Stale | Missing | Unanchored | Undetermined |
|---|---|---:|---:|---:|---:|---:|---:|
| VDR-TFR-MVX | MUST | 4 | 0 | 0 | 3 | 1 | 0 |
| VDR-TFR-NMV | MUST | 3 | 1 | 1 | 1 | 0 | 0 |
| VDR-TFR-PCD | SHOULD | 1 | 0 | 0 | 1 | 0 | 0 |
| VDR-TFR-PDD | SHOULD | 3 | 0 | 0 | 2 | 1 | 0 |
| VDR-TFR-PSD | SHOULD | 1 | 0 | 1 | 0 | 0 | 0 |

### Resources

| Resource | Kind | Aliases | Drift likely | Sample group | Job | Expected since | Decommissioned | Last examined | Last verified | Examined | Untimed | Clocks |
|---|---|---|---|---|---|---|---|---|---|---:|---:|---|
| host:lab-rhel-01 | machine | n/a | unknown | n/a | n/a | 2026-07-01T00:00:00Z | 2026-08-10T00:00:00Z | n/a | n/a | 0 | 0 | VDR-TFR-MVX MUST missing; VDR-TFR-PDD SHOULD missing |
| host:lab-ubuntu-03 | machine | n/a | yes | n/a | n/a | 2026-09-01T00:00:00Z | n/a | n/a | n/a | 0 | 0 | VDR-TFR-MVX MUST unanchored; VDR-TFR-PDD SHOULD unanchored |
| host:lab-win-01 | machine | n/a | no | n/a | weekly-stig-checklist | 2026-07-01T00:00:00Z | n/a | n/a | n/a | 0 | 2 | VDR-TFR-MVX MUST missing (2 untimed); VDR-TFR-PCD SHOULD missing (2 untimed) |
| host:ubuntu-web-01 | machine | host:lab-ubuntu-01 | yes | n/a | weekly-stig-checklist | 2026-07-01T00:00:00Z | n/a | n/a | n/a | 0 | 6 | VDR-TFR-MVX MUST missing (6 untimed); VDR-TFR-PDD SHOULD missing (6 untimed) |
| logical:backup-restore-procedure | attested | n/a | n/a | n/a | n/a | 2026-04-01T00:00:00Z | n/a | 2026-04-15T16:00:00Z | 2026-04-15T16:00:00Z | 0 | 0 | VDR-TFR-NMV MUST stale |
| logical:contingency-plan | attested | n/a | n/a | ir-runbooks | n/a | 2026-07-01T00:00:00Z | n/a | n/a | n/a | 0 | 0 | VDR-TFR-NMV MUST missing; VDR-TFR-PSD SHOULD stale |
| logical:incident-response-procedure | attested | n/a | n/a | ir-runbooks | n/a | 2026-07-01T00:00:00Z | n/a | 2026-08-03T17:00:00Z | 2026-08-03T17:00:00Z | 0 | 0 | VDR-TFR-NMV MUST current; VDR-TFR-PSD SHOULD stale |

### Clocks

| Resource | Rule | Force | Status | Anchor | Anchored at | Due at | Evidence | Stand-in |
|---|---|---|---|---|---|---|---|---|
| host:lab-rhel-01 | VDR-TFR-MVX | MUST | missing | declared | 2026-07-01T00:00:00Z | 2026-07-04T00:00:00Z | n/a | n/a |
| host:lab-rhel-01 | VDR-TFR-PDD | SHOULD | missing | declared | 2026-07-01T00:00:00Z | 2026-07-15T00:00:00Z | n/a | n/a |
| host:lab-ubuntu-03 | VDR-TFR-MVX | MUST | unanchored | n/a | n/a | n/a | n/a | n/a |
| host:lab-ubuntu-03 | VDR-TFR-PDD | SHOULD | unanchored | n/a | n/a | n/a | n/a | n/a |
| host:lab-win-01 | VDR-TFR-MVX | MUST | missing | declared | 2026-07-01T00:00:00Z | 2026-07-04T00:00:00Z | n/a | n/a |
| host:lab-win-01 | VDR-TFR-PCD | SHOULD | missing | declared | 2026-07-01T00:00:00Z | 2026-08-01T00:00:00Z | n/a | n/a |
| host:ubuntu-web-01 | VDR-TFR-MVX | MUST | missing | declared | 2026-07-01T00:00:00Z | 2026-07-04T00:00:00Z | n/a | n/a |
| host:ubuntu-web-01 | VDR-TFR-PDD | SHOULD | missing | declared | 2026-07-01T00:00:00Z | 2026-07-15T00:00:00Z | n/a | n/a |
| logical:backup-restore-procedure | VDR-TFR-NMV | MUST | stale | verification | 2026-04-15T16:00:00Z | 2026-07-15T16:00:00Z | attested: Restore test record RT-2026-04 on logical:backup-restore-procedure at 2026-04-15T16:00:00Z | n/a |
| logical:contingency-plan | VDR-TFR-NMV | MUST | missing | declared | 2026-07-01T00:00:00Z | 2026-10-01T00:00:00Z | n/a | n/a |
| logical:contingency-plan | VDR-TFR-PSD | SHOULD | stale | verification | 2026-08-03T17:00:00Z | 2026-08-06T17:00:00Z | attested: IR tabletop record TT-2026-08 on logical:incident-response-procedure at 2026-08-03T17:00:00Z | logical:incident-response-procedure |
| logical:incident-response-procedure | VDR-TFR-NMV | MUST | current | verification | 2026-08-03T17:00:00Z | 2026-11-03T17:00:00Z | attested: IR tabletop record TT-2026-08 on logical:incident-response-procedure at 2026-08-03T17:00:00Z | n/a |
| logical:incident-response-procedure | VDR-TFR-PSD | SHOULD | stale | verification | 2026-08-03T17:00:00Z | 2026-08-06T17:00:00Z | attested: IR tabletop record TT-2026-08 on logical:incident-response-procedure at 2026-08-03T17:00:00Z | logical:incident-response-procedure |

### Windows

A recorded window is a VDR-CSO-FAV system record of this run and names its tracking ID here even when this report does not select the record, such as one detected after the report period.

| Rule | Context | Force | Anchor | Anchored at | Closed at | Resumed at | Evidence | Stand-in | Recorded | Tracking ID |
|---|---|---|---|---|---|---|---|---|---|---|
| VDR-TFR-MVX | host:lab-rhel-01 | MUST | declared | 2026-07-01T00:00:00Z | 2026-07-04T00:00:00Z | n/a | n/a | n/a | yes | case-56e1eee78e97395f |
| VDR-TFR-MVX | host:lab-win-01 | MUST | declared | 2026-07-01T00:00:00Z | 2026-07-04T00:00:00Z | n/a | n/a | n/a | yes | case-656d627b62275ba8 |
| VDR-TFR-MVX | host:ubuntu-web-01 | MUST | declared | 2026-07-01T00:00:00Z | 2026-07-04T00:00:00Z | n/a | n/a | n/a | yes | case-656d627b62275ba8 |
| VDR-TFR-NMV | logical:backup-restore-procedure | MUST | verification | 2026-04-15T16:00:00Z | 2026-07-15T16:00:00Z | n/a | attested: Restore test record RT-2026-04 on logical:backup-restore-procedure at 2026-04-15T16:00:00Z | n/a | yes | case-fe51d8e4d9c79b36 |
| VDR-TFR-PCD | host:lab-win-01 | SHOULD | declared | 2026-07-01T00:00:00Z | 2026-08-01T00:00:00Z | n/a | n/a | n/a | yes | case-9c9bf88832065e17 |
| VDR-TFR-PDD | host:lab-rhel-01 | SHOULD | declared | 2026-07-01T00:00:00Z | 2026-07-15T00:00:00Z | n/a | n/a | n/a | yes | case-23ec0644fabe50d3 |
| VDR-TFR-PDD | host:ubuntu-web-01 | SHOULD | declared | 2026-07-01T00:00:00Z | 2026-07-15T00:00:00Z | n/a | n/a | n/a | yes | case-987c96e87614506a |
| VDR-TFR-PSD | logical:sample-group/ir-runbooks | SHOULD | declared | 2026-07-01T00:00:00Z | 2026-07-04T00:00:00Z | 2026-08-03T17:00:00Z | n/a | n/a | yes | case-a971b430300440cf |
| VDR-TFR-PSD | logical:sample-group/ir-runbooks | SHOULD | verification | 2026-08-03T17:00:00Z | 2026-08-06T17:00:00Z | n/a | attested: IR tabletop record TT-2026-08 on logical:incident-response-procedure at 2026-08-03T17:00:00Z | logical:incident-response-procedure | yes | case-a971b430300440cf |

### Unregistered resources

| Resource | Observations |
|---|---:|
| host:lab-ubuntu-02 | 3 |

### Untimed evidence

- **host:lab-win-01:** observation obs-57e96b5e68e7278977ebf3eaed197fb61c24c7cea52fffb6e4b96ead1a08c660 (pass) on host:lab-win-01, untimed; observation obs-6e3d196cb5f895fecc7d879eac03f954de2d99f46fdd0bccc11d8f0e88a66dc4 (open) on host:lab-win-01, untimed
- **host:ubuntu-web-01:** observation obs-1577127e3e0aaa0b19f428f196a0d90407c3cb1be1864738f30fd1b64470d7f9 (pass) on host:lab-ubuntu-01, untimed; observation obs-49da1ef09ba9877e9ad9885dbcba70198a805e64f64c4578e0e1b77bba33a4b1 (not_applicable) on host:lab-ubuntu-01, untimed; observation obs-6cdf3ee1f2fa3cf51ea8aac1cc05c8534ec5e56d8398edd559ef5f226b68a674 (open) on host:lab-ubuntu-01, untimed; observation obs-7876b3a041cd260c9987490da7e6d6dd370be17ac84dddc3c7a748ca0e4e98c0 (not_reviewed) on host:lab-ubuntu-01, untimed; observation obs-dd8f546726ab5b2cb9a096254bd3679185ca8f2cd10045dd7de289ad5553e5d6 (open) on host:lab-ubuntu-01, untimed; observation obs-f841f4f0e47c5d8710658d433ee82715d679f7a5cfbd9afb4a4e216688ad3926 (open) on host:lab-ubuntu-01, untimed

### Evidence after decommissioning

No evidence was observed after a resource was decommissioned.

### Evidence after as-of

- attested: IR tabletop record TT-2026-09 on logical:incident-response-procedure at 2026-09-02T17:00:00Z

## Diagnostics

- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [openscap-results.xml]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [ubuntu-host.cklb]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [windows-host.ckl]
- **warning** drift_likelihood_unknown: host:lab-rhel-01 declares driftLikely "unknown", so it carries VDR-TFR-PDD, the shorter drift window, until the inventory says whether drift is likely [example-boundary host:lab-rhel-01]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
