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
| KEV catalog | kev-catalog.json, CISA KEV catalog version 2026.09.14, released 2026-09-14T17:00:00.123400Z, 11 entries | 40c6d1465ca52c5ddb3b7bf1a6d92cfe884e33b4d2e90ac4551090e66d6c49fd |
| Generator | complyroll 0.3.0a0 | n/a |

## Summary

| Measure | Count |
|---|---:|
| Active vulnerabilities | 10 |
| Accepted vulnerabilities | 1 |
| Evaluated | 9 |
| Not yet evaluated | 2 |
| Overdue | 6 |
| Known exploited, CISA KEV | 9 |
| Past a CISA KEV due date | 6 |
| Current PAIN N1 | 0 |
| Current PAIN N2 | 9 |
| Current PAIN N3 | 0 |
| Current PAIN N4 | 0 |
| Current PAIN N5 | 0 |

## Active vulnerabilities

| Tracking ID | Source record | Resources | Detected | Evaluation completed | IRV | LEV | PAIN | Next due | Overdue | Disposition |
|---|---|---:|---|---|---|---|---|---|---|---|
| case-d71ea9b36c49f957 | CVE-2099-0001 | 1 | 2026-09-02T10:15:00Z | 2026-09-03T15:00:00Z | no | yes | N2 | 2026-09-11T00:00:00Z (VDR-TFR-KEV) | yes | active |
| case-bfcbac2c7be88a19 | CVE-2099-0001 | 1 | 2026-09-02T10:15:00Z | 2026-09-09T15:00:00Z | no | yes | N2 | 2026-09-11T00:00:00Z (VDR-TFR-KEV) | yes | active |
| case-47c219a4b195f33c | CVE-2099-0002 | 1 | 2026-09-02T10:15:00Z | n/a | n/a | n/a | n/a | 2026-09-07T10:15:00Z (VER-TFR-EVU) | yes | active |
| case-c4a0253c9a9ff48b | CVE-2099-0004 | 1 | 2026-09-02T10:15:00Z | 2026-09-04T15:00:00Z | no | yes | N2 | 2026-09-04T00:00:00Z (VDR-TFR-KEV) | yes | Fully Mitigated |
| case-fdc849d3efe49644 | CVE-2099-0005 | 1 | 2026-09-02T10:15:00Z | 2026-09-05T15:00:00Z | no | yes | N2 | n/a | no | Remediated |
| case-f5d5b19005c2d816 | CVE-2099-0007 | 1 | 2026-09-02T10:15:00Z | 2026-09-07T15:00:00Z | no | yes | N2 | n/a | no | False Positive |
| case-1a88bd335ba6c185 | CVE-2099-0008 | 1 | 2026-09-02T10:15:00Z | 2026-09-10T15:00:00Z | no | yes | N2 | 2027-01-16T15:00:00Z (VDR-TFR-PVR) | no | active |
| case-9d2c5885ea234bd0 | CVE-2099-0009 | 1 | 2026-09-02T10:15:00Z | 2026-09-11T15:00:00Z | no | yes | N2 | 2026-06-16T00:00:00Z (VDR-TFR-KEV) | yes | active |
| case-154434fe3008eee7 | CVE-2099-0011 | 1 | 2026-09-02T10:15:00Z | n/a | n/a | n/a | n/a | 2026-09-07T10:15:00Z (VER-TFR-EVU) | yes | active |
| case-587d3908c5469d3d | CVE-2099-0100 | 1 | 2026-09-02T10:15:00Z | 2026-09-08T15:00:00Z | no | yes | N2 | 2027-01-14T15:00:00Z (VDR-TFR-PVR) | no | active |

## Active vulnerability details

### case-d71ea9b36c49f957: CVE-2099-0001

- **Description:** CVE-2099-0001: libexample-net: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-70f5bbcefde3c0717c3c6b987d5292dda9800960b8a3717b1fc7bc26b4907fd9
- **Affected resources:** image registry.example.test/kev/web:2.3.1/usr/lib/libexample-net.so.4
- **Source identifiers:** CVE-2099-0001
- **Known exploited:** CVE-2099-0001 (added 2026-08-27, due 2026-09-10, ransomware use Known, forensic triage No); the clock follows CVE-2099-0001, due date 2026-09-10 ended 2026-09-11T00:00:00Z; past due
- **Evaluation completed:** 2026-09-03T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** active; **remediated:** no
- **Overdue:** VDR-TFR-KEV (SHOULD, Class C): the CISA KEV catalog (version 2026.09.14, released 2026-09-14T17:00:00.123400Z) lists CVE-2099-0001 with due date 2026-09-10, which ended 2026-09-11T00:00:00Z with no remediation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-03T15:00:00Z | 2027-01-09T15:00:00Z | no |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-03T15:00:00Z | 2027-03-14T15:00:00Z | no |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-08-27T00:00:00Z | 2026-09-11T00:00:00Z | no |

### case-bfcbac2c7be88a19: CVE-2099-0001

- **Description:** CVE-2099-0001: libexample-net: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-c47a43253274987bb15af19e1b6613f7004242ac7279676fecb107e7d999db9a
- **Affected resources:** image registry.example.test/kev/worker:2.3.1/usr/lib/libexample-net.so.4
- **Source identifiers:** CVE-2099-0001
- **Known exploited:** CVE-2099-0001 (added 2026-08-27, due 2026-09-10, ransomware use Known, forensic triage No); the clock follows CVE-2099-0001, due date 2026-09-10 ended 2026-09-11T00:00:00Z; past due
- **Evaluation completed:** 2026-09-09T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** active; **remediated:** no
- **Overdue:** VDR-TFR-KEV (SHOULD, Class C): the CISA KEV catalog (version 2026.09.14, released 2026-09-14T17:00:00.123400Z) lists CVE-2099-0001 with due date 2026-09-10, which ended 2026-09-11T00:00:00Z with no remediation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-09T15:00:00Z | 2027-01-15T15:00:00Z | no |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-09T15:00:00Z | 2027-03-20T15:00:00Z | no |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-08-27T00:00:00Z | 2026-09-11T00:00:00Z | no |

### case-47c219a4b195f33c: CVE-2099-0002

- **Description:** CVE-2099-0002: example-parser: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-368234084916415d3f3ca10504c6bfa5467e6862c2441ecced6904530af38569
- **Affected resources:** image registry.example.test/kev/web:2.3.1/app/package-lock.json
- **Source identifiers:** CVE-2099-0002, CVE-2099-0003
- **Known exploited:** CVE-2099-0002 (added 2026-09-08, due 2026-09-22, ransomware use Unknown, forensic triage No), CVE-2099-0003 (added 2026-09-10, due 2026-09-24, ransomware use Unknown, forensic triage Yes); the clock follows CVE-2099-0002, due date 2026-09-22 ends 2026-09-23T00:00:00Z; open
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-02T10:15:00Z and closed 2026-09-07T10:15:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | no |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-09-08T00:00:00Z | 2026-09-23T00:00:00Z | no |

### case-c4a0253c9a9ff48b: CVE-2099-0004

- **Description:** CVE-2099-0004: example-tls: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-1f1833ac4c20387535636df8ba36be6ecf6eea80cc88ee4ebe51bd3146f45192
- **Affected resources:** image registry.example.test/kev/web:2.3.1/lib/apk/db/installed
- **Source identifiers:** CVE-2099-0004
- **Known exploited:** CVE-2099-0004 (added 2026-08-20, due 2026-09-03, ransomware use Unknown, forensic triage No); the clock follows CVE-2099-0004, due date 2026-09-03 ended 2026-09-04T00:00:00Z; past due
- **Evaluation completed:** 2026-09-04T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Supplementary risk information:** SYNTHETIC. A network policy blocks the flawed listener while the package upgrade waits for the next image build.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** Fully Mitigated; **remediated:** no
- **Overdue:** VDR-TFR-KEV (SHOULD, Class C): the CISA KEV catalog (version 2026.09.14, released 2026-09-14T17:00:00.123400Z) lists CVE-2099-0004 with due date 2026-09-03, which ended 2026-09-04T00:00:00Z with no remediation recorded. A recorded mitigation does not stop this clock. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-04T15:00:00Z | 2027-01-10T15:00:00Z | yes |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-04T15:00:00Z | 2027-03-15T15:00:00Z | yes |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-08-20T00:00:00Z | 2026-09-04T00:00:00Z | no |

### case-fdc849d3efe49644: CVE-2099-0005

- **Description:** CVE-2099-0005: example-image: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-2e6b882bd6827969fc74657d6af81a9784d0e64c38e7c3e142f408309bea419f
- **Affected resources:** image registry.example.test/kev/web:2.3.1/usr/share/example-image/VERSION
- **Source identifiers:** CVE-2099-0005
- **Known exploited:** CVE-2099-0005 (added 2026-08-25, due 2026-09-08, ransomware use Known, forensic triage No); the clock follows CVE-2099-0005, due date 2026-09-08 ended 2026-09-09T00:00:00Z; stopped by remediation
- **Evaluation completed:** 2026-09-05T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** Remediated; **remediated:** yes
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-05T15:00:00Z | 2027-01-11T15:00:00Z | yes |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-05T15:00:00Z | 2027-03-16T15:00:00Z | yes |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-08-25T00:00:00Z | 2026-09-09T00:00:00Z | yes |

### case-f5d5b19005c2d816: CVE-2099-0007

- **Description:** CVE-2099-0007: example-xml: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-4643e554521c669726dd5e0fb71afe25240be3b49cc0a3d19f439e28850299bb
- **Affected resources:** image registry.example.test/kev/web:2.3.1/app/requirements.txt
- **Source identifiers:** CVE-2099-0007
- **Known exploited:** CVE-2099-0007 (added 2026-09-01, due 2026-09-04, ransomware use Unknown, forensic triage No); the clock follows CVE-2099-0007, due date 2026-09-04 ended 2026-09-05T00:00:00Z; stopped as a false positive
- **Evaluation completed:** 2026-09-07T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** False Positive; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-07T15:00:00Z | 2027-01-13T15:00:00Z | yes |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-07T15:00:00Z | 2027-03-18T15:00:00Z | yes |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-09-01T00:00:00Z | 2026-09-05T00:00:00Z | yes |

### case-1a88bd335ba6c185: CVE-2099-0008

- **Description:** CVE-2099-0008: example-auth: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-d6750e0bad0027389729da2ffa9f1a88884325092234439485cee32fb37328df
- **Affected resources:** image registry.example.test/kev/web:2.3.1/app/Gemfile.lock
- **Source identifiers:** CVE-2099-0008
- **Known exploited:** no entry in the supplied CISA KEV catalog dated on or before 2026-09-15
- **Evaluation completed:** 2026-09-10T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-10T15:00:00Z | 2027-01-16T15:00:00Z | no |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-10T15:00:00Z | 2027-03-21T15:00:00Z | no |

### case-9d2c5885ea234bd0: CVE-2099-0009

- **Description:** CVE-2099-0009: example-zip: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-dcbf31d3115f8fb450ccad9ce4a1fee35589c930cc41afc2e812ea1b58535626
- **Affected resources:** image registry.example.test/kev/web:2.3.1/usr/bin/example-zip
- **Source identifiers:** CVE-2099-0009
- **Known exploited:** CVE-2099-0009 (added 2026-06-01, due 2026-06-15, ransomware use Unknown, forensic triage No); the clock follows CVE-2099-0009, due date 2026-06-15 ended 2026-06-16T00:00:00Z; past due
- **Evaluation completed:** 2026-09-11T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** active; **remediated:** no
- **Overdue:** VDR-TFR-KEV (SHOULD, Class C): the CISA KEV catalog (version 2026.09.14, released 2026-09-14T17:00:00.123400Z) lists CVE-2099-0009 with due date 2026-06-15, which ended 2026-06-16T00:00:00Z with no remediation recorded. The due date had passed before detection at 2026-09-02T10:15:00Z. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-11T15:00:00Z | 2027-01-17T15:00:00Z | no |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-11T15:00:00Z | 2027-03-22T15:00:00Z | no |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-06-01T00:00:00Z | 2026-06-16T00:00:00Z | no |

### case-154434fe3008eee7: CVE-2099-0011

- **Description:** CVE-2099-0011: example-http: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-cd6cf79195e199e35c66af32a5a8c4798a596b54abbd8f463ac135e8327c0922
- **Affected resources:** image registry.example.test/kev/web:2.3.1/app/pom.xml
- **Source identifiers:** CVE-2099-0011
- **Known exploited:** CVE-2099-0011 (added 2026-08-24, due 2026-09-07, ransomware use Unknown, forensic triage No); the clock follows CVE-2099-0011, due date 2026-09-07 ended 2026-09-08T00:00:00Z; past due
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-02T10:15:00Z and closed 2026-09-07T10:15:00Z with no evaluation recorded. VDR-TFR-KEV (SHOULD, Class C): the CISA KEV catalog (version 2026.09.14, released 2026-09-14T17:00:00.123400Z) lists CVE-2099-0011 with due date 2026-09-07, which ended 2026-09-08T00:00:00Z with no remediation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | no |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-08-24T00:00:00Z | 2026-09-08T00:00:00Z | no |

### case-587d3908c5469d3d: CVE-2099-0100

- **Description:** CVE-2099-0100: example-log: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-ba33df3f7ef20a6811a2dea572cf6eb86d71aba285d0dad6dd12734e6455f57e
- **Affected resources:** image registry.example.test/kev/web:2.3.1/app/go.sum
- **Source identifiers:** CVE-2099-0100
- **Known exploited:** no entry in the supplied CISA KEV catalog dated on or before 2026-09-15
- **Evaluation completed:** 2026-09-08T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-08T15:00:00Z | 2027-01-14T15:00:00Z | no |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-08T15:00:00Z | 2027-03-19T15:00:00Z | no |

## Accepted vulnerabilities

| Tracking ID | Source record | Resources | Detected | Evaluation completed | IRV | LEV | PAIN | Next due | Overdue | Disposition |
|---|---|---:|---|---|---|---|---|---|---|---|
| case-94c71266d391144a | CVE-2099-0006 | 1 | 2026-09-02T10:15:00Z | 2026-09-06T15:00:00Z | no | yes | N2 | 2026-09-01T00:00:00Z (VDR-TFR-KEV) | no | accepted |

## Accepted vulnerability details

### case-94c71266d391144a: CVE-2099-0006

- **Description:** CVE-2099-0006: example-cron: synthetic flaw for KEV tests
- **Detection source:** Trivy
- **Detected at:** 2026-09-02T10:15:00Z (source: artifact)
- **Observations:** obs-236ab0190434375c821e5838513cf614bb0cbb2fa093d6a0bb7828e76f059aee
- **Affected resources:** image registry.example.test/kev/web:2.3.1/etc/example-cron/release
- **Source identifiers:** CVE-2099-0006
- **Known exploited:** CVE-2099-0006 (added 2026-08-10, due 2026-08-31, ransomware use Unknown, forensic triage No); the clock follows CVE-2099-0006, due date 2026-08-31 ended 2026-09-01T00:00:00Z; accepted, past due
- **Evaluation completed:** 2026-09-06T15:00:00Z by Example Provider vulnerability team (synthetic KEV fixture)
- **Internet reachable:** no; **likely exploitable:** yes; **PAIN:** N2
- **Potential agency impact:** SYNTHETIC. The flawed package runs inside the image but holds no agency data on its own.
- **Rationale:** SYNTHETIC. The service is internal only and the flaw needs local access, so reachability is ruled out and exploitation stays plausible.
- **Projected next reduction:** none planned
- **Completed PAIN reductions:** none recorded
- **Disposition:** accepted; **remediated:** no
- **Acceptance rationale:** SYNTHETIC. Accepted under change record CR-2099 until the scheduler is retired at the end of the quarter.
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-02T10:15:00Z | 2026-09-07T10:15:00Z | yes |
| VDR-TFR-PVR | Mitigation and Remediation Expectations | SHOULD | evaluation | 2026-09-06T15:00:00Z | 2027-01-12T15:00:00Z | yes |
| VER-TFR-MAV | Mark Accepted Vulnerabilities | MUST | evaluation | 2026-09-06T15:00:00Z | 2027-03-17T15:00:00Z | yes |
| VDR-TFR-KEV | Remediate KEVs | SHOULD | catalog | 2026-08-10T00:00:00Z | 2026-09-01T00:00:00Z | no |

## Detection time attestation

Every reported vulnerability carried a detection time from its source artifact. No attestation was needed.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| kev-image-web.sarif | 37776a3ba338 | complyroll.sarif 2 | 10 |
| kev-image-worker.sarif | facea1dd3b8d | complyroll.sarif 2 | 1 |

## Diagnostics

- **info** kev_entries_after_as_of: 1 catalog entry dated after 2026-09-15 was not applied; 1 compiled record carries it [sha256:40c6d1465ca52c5ddb3b7bf1a6d92cfe884e33b4d2e90ac4551090e66d6c49fd]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
