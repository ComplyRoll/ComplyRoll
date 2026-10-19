# Historical VER Activity Report

- **Certification package:** https://example.test/cpo
- **Certification class:** C
- **Generated at:** 2026-10-03T12:00:00Z
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
| Active vulnerabilities | 6 |
| Accepted vulnerabilities | 0 |
| Evaluated | 0 |
| Not yet evaluated | 6 |
| Overdue | 0 |
| Current PAIN N1 | 0 |
| Current PAIN N2 | 0 |
| Current PAIN N3 | 0 |
| Current PAIN N4 | 0 |
| Current PAIN N5 | 0 |

## Active vulnerabilities

| Tracking ID | Source record | Resources | Detected | Evaluation completed | IRV | LEV | PAIN | Next due | Overdue | Disposition |
|---|---|---:|---|---|---|---|---|---|---|---|
| case-b6bd658a4ffea56b | CVE-2022-48174 | 1 | 2026-10-01T12:00:00Z | n/a | n/a | n/a | n/a | 2026-10-06T12:00:00Z (VER-TFR-EVU) | no | active |
| case-8b9104e175637348 | CVE-2023-0286 | 2 | 2026-10-01T12:00:00Z | n/a | n/a | n/a | n/a | 2026-10-06T12:00:00Z (VER-TFR-EVU) | no | active |
| case-0f4d0f825af49a8a | CVE-2023-38037 | 1 | 2026-10-01T12:00:00Z | n/a | n/a | n/a | n/a | 2026-10-06T12:00:00Z (VER-TFR-EVU) | no | active |
| case-316e8e2251393517 | CVE-2023-5678 | 1 | 2026-10-01T12:00:00Z | n/a | n/a | n/a | n/a | 2026-10-06T12:00:00Z (VER-TFR-EVU) | no | active |
| case-b6cc25fd202e4964 | CVE-2024-0727 | 1 | 2026-10-01T12:00:00Z | n/a | n/a | n/a | n/a | 2026-10-06T12:00:00Z (VER-TFR-EVU) | no | active |
| case-031f4bfb066badaa | GHSA-rv95-896h-c2vc | 1 | 2026-10-01T12:00:00Z | n/a | n/a | n/a | n/a | 2026-10-06T12:00:00Z (VER-TFR-EVU) | no | active |

## Active vulnerability details

### case-b6bd658a4ffea56b: CVE-2022-48174

- **Description:** CVE-2022-48174
- **Detection source:** grype
- **Detected at:** 2026-10-01T12:00:00Z (source: artifact)
- **Observations:** obs-03f26b45916cb1d0cd87f242ce7ad64fea8a25bc99f0db4216bfe3eb4833ac90
- **Affected resources:** package image:registry.example.test/api\|component:library//busybox-static
- **Source identifiers:** CVE-2022-48174
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-10-01T12:00:00Z | 2026-10-06T12:00:00Z | no |

### case-8b9104e175637348: CVE-2023-0286

- **Description:** CVE-2023-0286: A type confusion vulnerability relating to X.400 address processing
- **Detection source:** trivy
- **Detected at:** 2026-10-01T12:00:00Z (source: artifact)
- **Observations:** obs-de2b67f016bab95eb0abfd15c9350634da019a52319800597379a777242511da, obs-767337656cb549771ba6cc082a8c05c57d7d5f1349d07836d43b9b402e1451e3
- **Affected resources:** package image:registry.example.test/api\|pkg:rpm/centos/openssl-libs?arch=x86_64, package image:registry.example.test/api\|pkg:rpm/centos/openssl?arch=x86_64
- **Source identifiers:** CVE-2023-0286, CWE-843
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-10-01T12:00:00Z | 2026-10-06T12:00:00Z | no |

### case-0f4d0f825af49a8a: CVE-2023-38037

- **Description:** CVE-2023-38037: ActiveSupport Encrypted File writes contents to a temporary file with default permissions.
- **Detection source:** trivy
- **Detected at:** 2026-10-01T12:00:00Z (source: artifact)
- **Observations:** obs-3ded09ae2784b5721b3a08442744726db79a0f70cd87e9c65e68f1554df8d75d
- **Affected resources:** package image:registry.example.test/api\|pkg:gem/activesupport
- **Source identifiers:** CVE-2023-38037, CWE-379, CWE-732
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-10-01T12:00:00Z | 2026-10-06T12:00:00Z | no |

### case-316e8e2251393517: CVE-2023-5678

- **Description:** CVE-2023-5678
- **Detection source:** grype
- **Detected at:** 2026-10-01T12:00:00Z (source: artifact)
- **Observations:** obs-00ed41532d10f959bf6b6752ad645c5d2248a837b16d77c418857c4dccb5f13d
- **Affected resources:** package image:registry.example.test/api\|pkg:deb/debian/libssl3?arch=amd64
- **Source identifiers:** CVE-2023-5678
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-10-01T12:00:00Z | 2026-10-06T12:00:00Z | no |

### case-b6cc25fd202e4964: CVE-2024-0727

- **Description:** CVE-2024-0727
- **Detection source:** grype
- **Detected at:** 2026-10-01T12:00:00Z (source: artifact)
- **Observations:** obs-7c23e13f450624ed77ccb4fccf32caa82e8377b42b9be7b4871fcd01899c8414
- **Affected resources:** package image:registry.example.test/api\|pkg:deb/debian/libssl3?arch=amd64
- **Source identifiers:** CVE-2024-0727
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-10-01T12:00:00Z | 2026-10-06T12:00:00Z | no |

### case-031f4bfb066badaa: GHSA-rv95-896h-c2vc

- **Description:** GHSA-rv95-896h-c2vc
- **Detection source:** grype
- **Detected at:** 2026-10-01T12:00:00Z (source: artifact)
- **Observations:** obs-923f768ac7f93f0d11aaf4b429fbcdd8a4d83da8e16b782c463ef1afc988abf4
- **Affected resources:** package image:registry.example.test/api\|pkg:npm/express
- **Source identifiers:** GHSA-rv95-896h-c2vc
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-10-01T12:00:00Z | 2026-10-06T12:00:00Z | no |

## Accepted vulnerabilities

No accepted vulnerabilities are recorded.

## Detection time attestation

Every reported vulnerability carried a detection time from its source artifact. No attestation was needed.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| grype-image.cdx.json | 01912bd68ded | complyroll.cyclonedx 1 | 5 |
| trivy-image.cdx.json | dff25bd7b9d8 | complyroll.cyclonedx 1 | 4 |

## Diagnostics

- **warning** package_identity_weak: an affected component has no usable purl; its key is built from its type, group and name (1 occurrence: vulnerabilities[4].affects[0]) [grype-image.cdx.json]
- **info** package_instances_folded: installs of one package with different bom-refs fold into one observation (1 occurrence: vulnerabilities[2].affects[0]) [grype-image.cdx.json]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
