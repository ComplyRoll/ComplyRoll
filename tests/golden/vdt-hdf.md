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
| Vulnerabilities reported | 5 |
| Evaluated | 0 |
| Not yet evaluated | 5 |
| Overdue | 4 |
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
| case-1706b7990cce1346 | CVE-2099-0001 | 1 | 2026-09-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-057bbe4ee9dde990 | CVE-2099-0102 | 1 | 2026-09-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-71446ac59461edb8 | CVE-2099-0103 | 1 | 2026-09-01T00:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-181b4b18c88fe895 | SYN-LNX-0001 | 1 | 2026-09-10T21:02:11Z | n/a | n/a | n/a | n/a | 2026-09-15T21:02:11Z (VER-TFR-EVU) | no | active |
| case-db1a983f4e0a849a | SYN-RHL-0001 | 1 | 2026-09-08T16:01:30Z | n/a | n/a | n/a | n/a | 2026-09-13T16:01:30Z (VER-TFR-EVU) | yes | active |

## Vulnerability details

### case-1706b7990cce1346: CVE-2099-0001

- **Description:** CVE-2099-0001: CVE-2099-0001: synthlib: synthetic cross-site scripting in the template renderer
- **Detection source:** heimdall-tools
- **Detected at:** 2026-09-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-57743407f37bbeba0fbac2295ff639f12c27fd77febc41dfc01dbeba65b39519
- **Affected resources:** target registry.example.test/web:1.4.2
- **Source identifiers:** CVE-2099-0001, CWE-79
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T00:00:00Z and closed 2026-09-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T00:00:00Z | 2026-09-06T00:00:00Z | no |

### case-057bbe4ee9dde990: CVE-2099-0102

- **Description:** CVE-2099-0102: CVE-2099-0102: synthcrypt: synthetic heap overflow in the record decoder
- **Detection source:** heimdall-tools
- **Detected at:** 2026-09-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-a339485bcdccdf6217f93567e0f573f5aae57f9c90b6470afad26f35be765547
- **Affected resources:** target registry.example.test/web:1.4.2
- **Source identifiers:** CVE-2099-0102
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T00:00:00Z and closed 2026-09-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T00:00:00Z | 2026-09-06T00:00:00Z | no |

### case-71446ac59461edb8: CVE-2099-0103

- **Description:** CVE-2099-0103: CVE-2099-0103: synthzip: synthetic path traversal on archive extraction
- **Detection source:** heimdall-tools
- **Detected at:** 2026-09-01T00:00:00Z (source: attestation)
- **Observations without a source timestamp:** obs-a6049562adb7185a3ab4fcf65040462c0bcda7d85cf98ebeafa230fd34305b15
- **Affected resources:** target registry.example.test/web:1.4.2
- **Source identifiers:** CVE-2099-0103
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-01T00:00:00Z and closed 2026-09-06T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T00:00:00Z | 2026-09-06T00:00:00Z | no |

### case-181b4b18c88fe895: SYN-LNX-0001

- **Description:** SYN-LNX-0001: The synthd service must restrict its configuration file mode
- **Detection source:** inspec
- **Detected at:** 2026-09-10T21:02:11Z (source: artifact)
- **Observations:** obs-2b1f8b0785e86b295f3a1f4288734b5bfff35163745c4c6f2a88638a5abd5624
- **Affected resources:** target 3f0c9a2e-6d4b-4c1e-9a7b-2f1e8d5c4b3a
- **Source identifiers:** CCI-000366
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-10T21:02:11Z | 2026-09-15T21:02:11Z | no |

### case-db1a983f4e0a849a: SYN-RHL-0001

- **Description:** SYN-RHL-0001: The synthd daemon must not run as root
- **Detection source:** inspec
- **Detected at:** 2026-09-08T16:01:30Z (source: artifact)
- **Observations:** obs-252ca5b9898729a0934843c0d6235316123782a983190f1f6a4248ff04ec6611
- **Affected resources:** target 7d2e4f10-3b6a-4c8d-9e1f-5a6b7c8d9e0f
- **Source identifiers:** CCI-000048
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-09-08T16:01:30Z and closed 2026-09-13T16:01:30Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-08T16:01:30Z | 2026-09-13T16:01:30Z | no |

## Detection time attestation

The operator attested a detection time of 2026-09-01T00:00:00Z for 3 vulnerability record(s) whose source artifacts declare no assessment timestamp. ComplyRoll never substitutes file modification or ingestion time for a detection time.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| inspec-linux-host.hdf.json | 36e929218a49 | complyroll.hdf 1 | 6 |
| inspec-overlay.json | a965c0f73307 | complyroll.hdf 1 | 3 |
| saf-trivy-image.hdf.json | 6b36d5a302d0 | complyroll.hdf 1 | 3 |

## Diagnostics

- **warning** control_attested: control carries attestation data; the disposition comes from its results and the attestation is recorded as metadata (1 occurrence: profiles[1].controls[1]) [inspec-overlay.json]
- **warning** control_waived: control carries waiver data; the disposition comes from its results and the waiver is recorded as metadata (1 occurrence: profiles[0].controls[5]) [inspec-linux-host.hdf.json]
- **info** converted_document: platform.name is Heimdall Tools; the source tool is heimdall-tools and the resource is the converter's target (1 occurrence: platform) [saf-trivy-image.hdf.json]
- **info** impact_zero_not_applicable: impact is 0, so the control is not applicable whatever its results say (1 occurrence: profiles[0].controls[3]; first: results would read OPEN) [inspec-linux-host.hdf.json]
- **info** profile_control_shadowed: control has no results and the same id carries results in another profile of this run; it yields no observation (2 occurrences: profiles[0].controls[0], profiles[0].controls[1]) [inspec-overlay.json]
- **warning** source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [saf-trivy-image.hdf.json]
- **warning** unresolved_observation: SYN-LNX-0005 on 3f0c9a2e-6d4b-4c1e-9a7b-2f1e8d5c4b3a has disposition error and was not reported as a vulnerability [inspec-linux-host.hdf.json]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
