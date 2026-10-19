# Vulnerability Detail Report

- **Certification package:** https://example.test/cpo
- **Report period:** 2026-09-01T00:00:00Z to 2026-09-30T23:59:59Z
- **Certification class:** C
- **Generated at:** 2026-09-15T12:00:00Z
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
| Vulnerabilities reported | 6 |
| Evaluated | 0 |
| Not yet evaluated | 6 |
| Overdue | 6 |
| Accepted, reported under VER-RPT-AVI | 0 |
| Excluded by report period | 0 |
| Current PAIN N1 | 0 |
| Current PAIN N2 | 0 |
| Current PAIN N3 | 0 |
| Current PAIN N4 | 0 |
| Current PAIN N5 | 0 |

## Vulnerabilities

| Tracking ID | Source record | Resources | Detected | Evaluation completed | IRV | LEV | PAIN | Next due | Overdue | Disposition |
|---|---|---:|---|---|---|---|---|---|---|---|
| case-10f5974d95a33fdf | CVE-2024-0001 | 2 | 2026-09-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-889c19760e425785 | CVE-2024-0002 | 1 | 2026-09-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-04716522daa6f550 | js/unused-local-variable | 1 | 2026-09-01T02:00:00.123456Z | n/a | n/a | n/a | n/a | 2026-09-06T02:00:00.123456Z (VER-TFR-EVU) | yes | active |
| case-d2b9f5abf1fe44ac | js/xss-through-dom | 1 | 2026-09-01T02:00:00.123456Z | n/a | n/a | n/a | n/a | 2026-09-06T02:00:00.123456Z (VER-TFR-EVU) | yes | active |
| case-5cfbebe8d4b91c27 | python.lang.security.audit.exec-detected.exec-detected | 1 | 2026-09-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-0e3754ea1c369285 | python.lang.security.audit.subprocess-shell-true.subprocess-shell-true | 1 | 2026-09-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T00:00:00Z (VER-TFR-EVU) | yes | active |

## Vulnerability details

### case-10f5974d95a33fdf: CVE-2024-0001

- **Description:** CVE-2024-0001: requests: header leak on cross-origin redirect
- **Detection source:** Trivy
- **Detected at:** 2026-09-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-332bed1a07ff200779b02085e7293e6a5907d1ad5bdd953ffbb55cad87f38037, obs-7f44594825d875616e4d99e73ad97905324212a706139bb36d7dc2d4f768adc7
- **Affected resources:** image ghcr.io/example/app:1.4.2/app/requirements.txt, image ghcr.io/example/app:1.4.2/usr/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA
- **Source identifiers:** CVE-2024-0001
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T00:00:00Z and closed 2026-09-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T00:00:00Z | 2026-09-06T00:00:00Z | no |

### case-889c19760e425785: CVE-2024-0002

- **Description:** CVE-2024-0002: musl: out-of-bounds read in wcsnrtombs
- **Detection source:** Trivy
- **Detected at:** 2026-09-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-17a6f60c6eca605a8b959469b9166ce415f52bdc21de05ae25078b79d608c21a
- **Affected resources:** image ghcr.io/example/app:1.4.2/library/alpine
- **Source identifiers:** CVE-2024-0002
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T00:00:00Z and closed 2026-09-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T00:00:00Z | 2026-09-06T00:00:00Z | no |

### case-04716522daa6f550: js/unused-local-variable

- **Description:** js/unused-local-variable: Unused variable, import, function or class
- **Detection source:** CodeQL
- **Detected at:** 2026-09-01T02:00:00.123456Z (source: artifact)
- **Observations:** obs-5eed8cd90893738613d23955692bf60df48eb1b6c3ec34d5df5ee2354a1b096f
- **Affected resources:** file https://github.com/example/webapp/src/ui/helpers.js
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T02:00:00.123456Z and closed 2026-09-06T02:00:00.123456Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T02:00:00.123456Z | 2026-09-06T02:00:00.123456Z | no |

### case-d2b9f5abf1fe44ac: js/xss-through-dom

- **Description:** js/xss-through-dom: DOM text reinterpreted as HTML
- **Detection source:** CodeQL
- **Detected at:** 2026-09-01T02:00:00.123456Z (source: artifact)
- **Observations:** obs-fdcb47349a49f24da9ed9ef671d72a2302f8c726e5fe17cee8524e7f15ba12df
- **Affected resources:** file https://github.com/example/webapp/src/ui/render.js
- **Source identifiers:** CWE-116, CWE-79
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T02:00:00.123456Z and closed 2026-09-06T02:00:00.123456Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T02:00:00.123456Z | 2026-09-06T02:00:00.123456Z | no |

### case-5cfbebe8d4b91c27: python.lang.security.audit.exec-detected.exec-detected

- **Description:** python.lang.security.audit.exec-detected.exec-detected: Semgrep Finding: python.lang.security.audit.exec-detected.exec-detected
- **Detection source:** Semgrep OSS
- **Detected at:** 2026-09-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-45e05f930d5f91b636e6d26625044d9b4dd104ec40db9cdb3971697ed4711a66
- **Affected resources:** file src/app/runner.py
- **Source identifiers:** CWE-95
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T00:00:00Z and closed 2026-09-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T00:00:00Z | 2026-09-06T00:00:00Z | no |

### case-0e3754ea1c369285: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true

- **Description:** python.lang.security.audit.subprocess-shell-true.subprocess-shell-true: Semgrep Finding: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
- **Detection source:** Semgrep OSS
- **Detected at:** 2026-09-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-b6143153ace3697d49767f66473c0fa68ceab73dec61df50b03c6c3e77376dfc
- **Affected resources:** file src/app/tasks.py
- **Source identifiers:** CWE-78
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T00:00:00Z and closed 2026-09-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T00:00:00Z | 2026-09-06T00:00:00Z | no |

## Detection time attestation

The operator attested a detection time of 2026-09-01T00:00:00Z for 4 vulnerability record(s) whose source artifacts declare no assessment timestamp. ComplyRoll never substitutes file modification or ingestion time for a detection time.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| codeql-repo.sarif | bf5a9a4d1bbb | complyroll.sarif 2 | 3 |
| semgrep-code.sarif | 1a19d26f7975 | complyroll.sarif 2 | 2 |
| trivy-image.sarif | 5ec28341654c | complyroll.sarif 2 | 3 |

## Diagnostics

- **info** baseline_state_ignored: baselineState is recorded as metadata and never changes a disposition (3 occurrences: runs[0].results[0], runs[0].results[1], runs[0].results[2]) [codeql-repo.sarif]
- **info** results_collapsed: result folded into an observation that shares its identity (1 occurrence: runs[0].results[1]) [semgrep-code.sarif]
- **info** results_collapsed: result folded into an observation that shares its identity (2 occurrences: runs[0].results[1], runs[0].results[4]) [trivy-image.sarif]
- **warning** results_suppressed: result carries an accepted suppression; its disposition is unchanged (1 occurrence: runs[0].results[2]) [semgrep-code.sarif]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [semgrep-code.sarif]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [trivy-image.sarif]
- **warning** unresolved_observation: js/xss-through-dom on https://github.com/example/webapp/src/ui/legacy.js has disposition unknown and was not reported as a vulnerability [codeql-repo.sarif]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
