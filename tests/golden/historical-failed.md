# Historical VER Activity Report

- **Certification package:** https://example.test/cpo
- **Certification class:** C
- **Generated at:** 2026-08-21T12:00:00Z
- **Calendar timezone:** UTC

## Provenance

| Source | Reference | Digest |
|---|---|---|
| Rules dataset | https://github.com/FedRAMP/rules at 58487bda77d76d9ce334304ec2e779ece7cc7d54 (version 2026.09.13.02, updated 2026-09-13) | 64915d88e72353c95f321ea4a9014516ac9441972cbd7f3d1abef7d1514c8fc8 |
| Report schema | https://github.com/FedRAMP/schemas at 5156719aa7d0def16cf66f6197db9d6c0024e0e7 (https://fedramp.gov/schemas/fedramp-historical-ver-activity-schema-2026-06-24.json version 0.1.1) | dbbddb51ee25bfe9568c1dcfe1047ea206539dc91dad1fd2658f1a5accf2a6fb |
| Generator | complyroll 0.3.0a0 | n/a |

## Summary

| Measure | Count |
|---|---:|
| Active vulnerabilities | 10 |
| Accepted vulnerabilities | 0 |
| Evaluated | 3 |
| Not yet evaluated | 7 |
| Overdue | 7 |
| Current PAIN N1 | 0 |
| Current PAIN N2 | 0 |
| Current PAIN N3 | 2 |
| Current PAIN N4 | 1 |
| Current PAIN N5 | 0 |

## Active vulnerabilities

| Tracking ID | Source record | Resources | Detected | Evaluation completed | IRV | LEV | PAIN | Next due | Overdue | Disposition |
|---|---|---:|---|---|---|---|---|---|---|---|
| case-490f49bfdd1bd019 | V-253260 | 1 | 2026-08-01T00:00:00Z | 2026-08-05T16:00:00Z | yes | yes | N4 | 2026-08-09T16:00:00Z (VDR-TFR-PVR) | yes | active |
| case-9bed0d8f88355393 | V-260469 | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-1f3e011db93cc89e | V-260470 | 1 | 2026-08-01T00:00:00Z | 2026-08-04T12:00:00Z | yes | yes | N3 | n/a | no | Partially Mitigated |
| case-621d85d6533ce6e5 | V-260474 | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-f03af85468885cad | detection-process-failure | 1 | 2026-08-04T10:00:00Z | n/a | n/a | n/a | n/a | 2026-08-09T10:00:00Z (VER-TFR-EVU) | yes | active |
| case-d3bb8e4fb3b61a5f | detection-process-failure | 1 | 2026-08-21T12:00:00Z | 2026-08-21T12:00:00Z | no | no | N3 | 2026-12-27T12:00:00Z (VDR-TFR-PVR) | no | active |
| case-088261de64a0133c | detection-process-failure | 1 | 2026-08-21T12:00:00Z | n/a | n/a | n/a | n/a | 2026-08-26T12:00:00Z (VER-TFR-EVU) | no | active |
| case-77fba1630a50ca9f | EXS-0001 | 1 | 2026-08-03T10:00:00Z | n/a | n/a | n/a | n/a | 2026-08-08T10:00:00Z (VER-TFR-EVU) | yes | active |
| case-04efea8c137ae82f | banner_etc_issue | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-6719b316a5ea510b | no_cci_mapping | 1 | 2026-08-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-06T00:00:00Z (VER-TFR-EVU) | yes | active |

## Active vulnerability details

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

### case-f03af85468885cad: detection-process-failure

- **Description:** detection-process-failure: source artifact sha256:59e5a0bee03780b92cd21e2da90d4c8ead7eb94a70f3d904fa141a55620691e9 did not yield complete detection results (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-08-04T10:00:00Z (source: system)
- **Observations:** obs-984694b7e0dd037c99412208fc91e1332ddfdd2488f37c117bd26a4096e1967f
- **Affected resources:** artifact sha256:59e5a0bee03780b92cd21e2da90d4c8ead7eb94a70f3d904fa141a55620691e9
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-04T10:00:00Z and closed 2026-08-09T10:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-04T10:00:00Z | 2026-08-09T10:00:00Z | no |

### case-d3bb8e4fb3b61a5f: detection-process-failure

- **Description:** detection-process-failure: source artifact sha256:a8aca932d8fc140bdc97cb5a8006bd860754666b94297ef63a152cd2419c90c8 did not yield complete detection results (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-08-21T12:00:00Z (source: system)
- **Observations:** obs-6cd3787a252ee233835c1a8f81bb50a9a87d732e25a97c349c2555fc1955a47b
- **Affected resources:** artifact sha256:a8aca932d8fc140bdc97cb5a8006bd860754666b94297ef63a152cd2419c90c8
- **Source identifiers:** n/a
- **Evaluation completed:** 2026-08-21T12:00:00Z by Example Provider vulnerability team (detection process review, procedure VM-07)
- **Internet reachable:** no; **likely exploitable:** no; **PAIN:** N3
- **Potential agency impact:** Findings from one ExampleScan run were never recorded, so a weakness on the hosts that run covers could go unreported to agencies until a complete scan reads them.
- **Rationale:** The ExampleScan log was cut off while the scanner was writing it, so none of the run's results can be read. The hosts the run covers sit on an internal segment with no internet path, and a gap in detection is not itself exploitable, so the rating reflects how long findings could stay unreported rather than an exposed weakness.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-21T12:00:00Z | 2026-08-26T12:00:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-08-21T12:00:00Z | 2026-12-27T12:00:00Z | no |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-08-21T12:00:00Z | 2027-03-01T12:00:00Z | no |

### case-088261de64a0133c: detection-process-failure

- **Description:** detection-process-failure: source artifact sha256:f51e7b7624956be0f40545639b3ee63ab7b5a27cb647ad2a3435df6bc6dcc372 did not yield complete detection results (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-08-21T12:00:00Z (source: system)
- **Observations:** obs-196f0c7b40dcbb75cc51810ab7b35294fd67af4f114770059b4ea9aa02b41bee
- **Affected resources:** artifact sha256:f51e7b7624956be0f40545639b3ee63ab7b5a27cb647ad2a3435df6bc6dcc372
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-21T12:00:00Z | 2026-08-26T12:00:00Z | no |

### case-77fba1630a50ca9f: EXS-0001

- **Description:** EXS-0001: Synthetic finding: the example service accepts TLS 1.0
- **Detection source:** ExampleScan
- **Detected at:** 2026-08-03T10:00:00Z (source: artifact)
- **Observations:** obs-d103230fb829a973e19c4b09c0bb304e076598a9f594adc069021836e9b5cced
- **Affected resources:** file config/example-service.yaml
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-03T10:00:00Z and closed 2026-08-08T10:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-03T10:00:00Z | 2026-08-08T10:00:00Z | no |

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

## Accepted vulnerabilities

No accepted vulnerabilities are recorded.

## Detection time attestation

The operator attested a detection time of 2026-08-01T00:00:00Z for 6 vulnerability record(s) whose source artifacts declare no assessment timestamp. ComplyRoll never substitutes file modification or ingestion time for a detection time.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| failed-invocation.sarif | 59e5a0bee037 | complyroll.sarif 1 | 1 |
| openscap-results.xml | 3f5deac4a3d9 | complyroll.xccdf 1 | 3 |
| ubuntu-host.cklb | 97d123900424 | complyroll.cklb 1 | 6 |
| windows-host.ckl | e5dfc628039c | complyroll.ckl 1 | 2 |

### Detection process failures

| Artifact | SHA-256 | Parser | Class | Observed at | Clock | Tracking ID |
|---|---|---|---|---|---|---|
| failed-invalid-rules.cklb | f51e7b762495 | complyroll.cklb 1 | content | 2026-08-21T12:00:00Z | as-of | case-088261de64a0133c |
| failed-invocation.sarif | 59e5a0bee037 | complyroll.sarif 1 | execution | 2026-08-04T10:00:00Z | invocation | case-f03af85468885cad |
| failed-truncated.sarif | a8aca932d8fc | complyroll.sarif 1 | parse | 2026-08-21T12:00:00Z | as-of | case-d3bb8e4fb3b61a5f |

## Diagnostics

- **warning** artifact_parse_failed: Unterminated string starting at: line 18 column 21 (char 419) [failed-truncated.sarif]
- **warning** detection_failure_recorded: recorded a detection process failure of class content for source artifact sha256:f51e7b7624956be0f40545639b3ee63ab7b5a27cb647ad2a3435df6bc6dcc372 (VDR-CSO-FAV) [failed-invalid-rules.cklb]
- **warning** detection_failure_recorded: recorded a detection process failure of class execution for source artifact sha256:59e5a0bee03780b92cd21e2da90d4c8ead7eb94a70f3d904fa141a55620691e9 (VDR-CSO-FAV) [failed-invocation.sarif]
- **warning** detection_failure_recorded: recorded a detection process failure of class parse for source artifact sha256:a8aca932d8fc140bdc97cb5a8006bd860754666b94297ef63a152cd2419c90c8 (VDR-CSO-FAV) [failed-truncated.sarif]
- **warning** execution_unsuccessful: invocation reports executionSuccessful false; its results are still read (1 occurrence: runs[1].invocations[0]) [failed-invocation.sarif]
- **warning** invalid_rules: STIG entry has no rules array [stigs[0].rules]
- **warning** no_observations: CKLB contains no usable rules [failed-invalid-rules.cklb]
- **info** run_clean: run reports no results (1 occurrence: runs[1]) [failed-invocation.sarif]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [failed-invalid-rules.cklb]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [openscap-results.xml]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [ubuntu-host.cklb]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [windows-host.ckl]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
