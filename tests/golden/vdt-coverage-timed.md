# Vulnerability Detail Report

- **Certification package:** https://example.test/cpo
- **Report period:** 2026-09-01T00:00:00Z to 2026-09-30T23:59:59Z
- **Certification class:** C
- **Generated at:** 2026-09-03T12:00:00Z
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
| Vulnerabilities reported | 2 |
| Evaluated | 0 |
| Not yet evaluated | 2 |
| Overdue | 0 |
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
| case-04716522daa6f550 | js/unused-local-variable | 1 | 2026-09-01T02:00:00.123456Z | n/a | n/a | n/a | n/a | 2026-09-06T02:00:00.123456Z (VER-TFR-EVU) | no | active |
| case-d2b9f5abf1fe44ac | js/xss-through-dom | 1 | 2026-09-01T02:00:00.123456Z | n/a | n/a | n/a | n/a | 2026-09-06T02:00:00.123456Z (VER-TFR-EVU) | no | active |

## Vulnerability details

### case-04716522daa6f550: js/unused-local-variable

- **Description:** js/unused-local-variable: Unused variable, import, function or class
- **Detection source:** CodeQL
- **Detected at:** 2026-09-01T02:00:00.123456Z (source: artifact)
- **Observations:** obs-5eed8cd90893738613d23955692bf60df48eb1b6c3ec34d5df5ee2354a1b096f
- **Affected resources:** file https://github.com/example/webapp/src/ui/helpers.js
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

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
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T02:00:00.123456Z | 2026-09-06T02:00:00.123456Z | no |

## Detection time attestation

Every reported vulnerability carried a detection time from its source artifact. No attestation was needed.

## Inputs

| Artifact | SHA-256 | Parser | Observations |
|---|---|---|---:|
| clean-run.sarif | ee91754fbc49 | complyroll.sarif 2 | 1 |
| codeql-repo.sarif | bf5a9a4d1bbb | complyroll.sarif 2 | 3 |

## Coverage

Coverage of the inventory timed-boundary (5 entries, 1526 bytes, SHA-256 49e3d4806d4bd6cd9e918b2751b5aeb1c9fe8473398b104799fb27fb62b35c2e) as of 2026-09-03T12:00:00Z, with clocks from rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54.

VDR-TFR-MVX is read from detection results until Phase 3 validation runs exist. Coverage is measured against the provider-supplied inventory named by its SHA-256 digest, so an observed resource the inventory omits is listed as unregistered and is never expected. Evidence that determined no status (NOT_REVIEWED, ERROR or UNKNOWN) examines a resource without verifying it, untimed evidence never anchors a clock, and a non-machine resource is verified only by an operator attestation. A current status is not a compliance finding.

### Coverage by rule

| Rule | Force | Expected | Current | Stale | Missing | Unanchored | Undetermined |
|---|---|---:|---:|---:|---:|---:|---:|
| VDR-TFR-MVX | MUST | 5 | 2 | 1 | 1 | 0 | 1 |
| VDR-TFR-NMV | MUST | 0 | 0 | 0 | 0 | 0 | 0 |
| VDR-TFR-PCD | SHOULD | 1 | 1 | 0 | 0 | 0 | 0 |
| VDR-TFR-PDD | SHOULD | 4 | 1 | 1 | 1 | 0 | 1 |
| VDR-TFR-PSD | SHOULD | 1 | 1 | 0 | 0 | 0 | 0 |

### Resources

| Resource | Kind | Aliases | Drift likely | Sample group | Job | Expected since | Decommissioned | Last examined | Last verified | Examined | Untimed | Clocks |
|---|---|---|---|---|---|---|---|---|---|---:|---:|---|
| file:https://github.com/example/webapp/src/ui/helpers.js | machine | n/a | no | n/a | nightly-codeql | 2026-09-01T00:00:00Z | n/a | 2026-09-01T02:00:00.123456Z | 2026-09-01T02:00:00.123456Z | 1 | 0 | VDR-TFR-MVX MUST current; VDR-TFR-PCD SHOULD current |
| file:https://github.com/example/webapp/src/ui/index.js | machine | n/a | yes | webapp-ui | n/a | 2026-09-01T00:00:00Z | n/a | n/a | n/a | 0 | 0 | VDR-TFR-MVX MUST missing; VDR-TFR-PDD SHOULD missing; VDR-TFR-PSD SHOULD current |
| file:https://github.com/example/webapp/src/ui/legacy.js | machine | n/a | yes | n/a | nightly-codeql | 2026-09-01T00:00:00Z | n/a | 2026-09-01T02:00:00.123456Z | n/a | 1 | 0 | VDR-TFR-MVX MUST undetermined; VDR-TFR-PDD SHOULD undetermined |
| file:src/ui/render.js | machine | file:https://github.com/example/webapp/src/ui/render.js | yes | webapp-ui | nightly-codeql | 2026-09-01T00:00:00Z | n/a | 2026-09-01T02:00:00.123456Z | 2026-09-01T02:00:00.123456Z | 1 | 0 | VDR-TFR-MVX MUST current; VDR-TFR-PDD SHOULD current; VDR-TFR-PSD SHOULD current |
| image:registry.example.test/synthetic/example-service:1.4.0 | machine | n/a | yes | n/a | nightly-image-scan | 2026-08-01T00:00:00Z | n/a | 2026-08-05T10:00:00Z | 2026-08-05T10:00:00Z | 1 | 0 | VDR-TFR-MVX MUST stale; VDR-TFR-PDD SHOULD stale |

### Clocks

| Resource | Rule | Force | Status | Anchor | Anchored at | Due at | Evidence | Stand-in |
|---|---|---|---|---|---|---|---|---|
| file:https://github.com/example/webapp/src/ui/helpers.js | VDR-TFR-MVX | MUST | current | verification | 2026-09-01T02:00:00.123456Z | 2026-09-04T02:00:00.123456Z | observation obs-5eed8cd90893738613d23955692bf60df48eb1b6c3ec34d5df5ee2354a1b096f (open) on file:https://github.com/example/webapp/src/ui/helpers.js at 2026-09-01T02:00:00.123456Z | n/a |
| file:https://github.com/example/webapp/src/ui/helpers.js | VDR-TFR-PCD | SHOULD | current | verification | 2026-09-01T02:00:00.123456Z | 2026-10-01T02:00:00.123456Z | observation obs-5eed8cd90893738613d23955692bf60df48eb1b6c3ec34d5df5ee2354a1b096f (open) on file:https://github.com/example/webapp/src/ui/helpers.js at 2026-09-01T02:00:00.123456Z | n/a |
| file:https://github.com/example/webapp/src/ui/index.js | VDR-TFR-MVX | MUST | missing | declared | 2026-09-01T00:00:00Z | 2026-09-04T00:00:00Z | n/a | n/a |
| file:https://github.com/example/webapp/src/ui/index.js | VDR-TFR-PDD | SHOULD | missing | declared | 2026-09-01T00:00:00Z | 2026-09-15T00:00:00Z | n/a | n/a |
| file:https://github.com/example/webapp/src/ui/index.js | VDR-TFR-PSD | SHOULD | current | verification | 2026-09-01T02:00:00.123456Z | 2026-09-04T02:00:00.123456Z | observation obs-fdcb47349a49f24da9ed9ef671d72a2302f8c726e5fe17cee8524e7f15ba12df (open) on file:https://github.com/example/webapp/src/ui/render.js at 2026-09-01T02:00:00.123456Z | file:src/ui/render.js |
| file:https://github.com/example/webapp/src/ui/legacy.js | VDR-TFR-MVX | MUST | undetermined | declared | 2026-09-01T00:00:00Z | 2026-09-04T00:00:00Z | n/a | n/a |
| file:https://github.com/example/webapp/src/ui/legacy.js | VDR-TFR-PDD | SHOULD | undetermined | declared | 2026-09-01T00:00:00Z | 2026-09-15T00:00:00Z | n/a | n/a |
| file:src/ui/render.js | VDR-TFR-MVX | MUST | current | verification | 2026-09-01T02:00:00.123456Z | 2026-09-04T02:00:00.123456Z | observation obs-fdcb47349a49f24da9ed9ef671d72a2302f8c726e5fe17cee8524e7f15ba12df (open) on file:https://github.com/example/webapp/src/ui/render.js at 2026-09-01T02:00:00.123456Z | n/a |
| file:src/ui/render.js | VDR-TFR-PDD | SHOULD | current | verification | 2026-09-01T02:00:00.123456Z | 2026-09-15T02:00:00.123456Z | observation obs-fdcb47349a49f24da9ed9ef671d72a2302f8c726e5fe17cee8524e7f15ba12df (open) on file:https://github.com/example/webapp/src/ui/render.js at 2026-09-01T02:00:00.123456Z | n/a |
| file:src/ui/render.js | VDR-TFR-PSD | SHOULD | current | verification | 2026-09-01T02:00:00.123456Z | 2026-09-04T02:00:00.123456Z | observation obs-fdcb47349a49f24da9ed9ef671d72a2302f8c726e5fe17cee8524e7f15ba12df (open) on file:https://github.com/example/webapp/src/ui/render.js at 2026-09-01T02:00:00.123456Z | file:src/ui/render.js |
| image:registry.example.test/synthetic/example-service:1.4.0 | VDR-TFR-MVX | MUST | stale | verification | 2026-08-05T10:00:00Z | 2026-08-08T10:00:00Z | observation obs-bcc0abe46ca6b0be67b4ab860b40daa91654dc1db853876ddc12ba5077e10178 (pass) on image:registry.example.test/synthetic/example-service:1.4.0 at 2026-08-05T10:00:00Z | n/a |
| image:registry.example.test/synthetic/example-service:1.4.0 | VDR-TFR-PDD | SHOULD | stale | verification | 2026-08-05T10:00:00Z | 2026-08-19T10:00:00Z | observation obs-bcc0abe46ca6b0be67b4ab860b40daa91654dc1db853876ddc12ba5077e10178 (pass) on image:registry.example.test/synthetic/example-service:1.4.0 at 2026-08-05T10:00:00Z | n/a |

### Windows

| Rule | Context | Force | Anchor | Anchored at | Closed at | Resumed at | Evidence | Stand-in |
|---|---|---|---|---|---|---|---|---|
| VDR-TFR-MVX | image:registry.example.test/synthetic/example-service:1.4.0 | MUST | declared | 2026-08-01T00:00:00Z | 2026-08-04T00:00:00Z | 2026-08-05T10:00:00Z | n/a | n/a |
| VDR-TFR-MVX | image:registry.example.test/synthetic/example-service:1.4.0 | MUST | verification | 2026-08-05T10:00:00Z | 2026-08-08T10:00:00Z | n/a | observation obs-bcc0abe46ca6b0be67b4ab860b40daa91654dc1db853876ddc12ba5077e10178 (pass) on image:registry.example.test/synthetic/example-service:1.4.0 at 2026-08-05T10:00:00Z | n/a |
| VDR-TFR-PDD | image:registry.example.test/synthetic/example-service:1.4.0 | SHOULD | verification | 2026-08-05T10:00:00Z | 2026-08-19T10:00:00Z | n/a | observation obs-bcc0abe46ca6b0be67b4ab860b40daa91654dc1db853876ddc12ba5077e10178 (pass) on image:registry.example.test/synthetic/example-service:1.4.0 at 2026-08-05T10:00:00Z | n/a |

### Unregistered resources

Every observed resource is in the inventory.

### Untimed evidence

No inventory resource has untimed evidence.

### Evidence after decommissioning

No evidence was observed after a resource was decommissioned.

### Evidence after as-of

No evidence was observed after as-of.

## Diagnostics

- **info** baseline_state_ignored: baselineState is recorded as metadata and never changes a disposition (3 occurrences: runs[0].results[0], runs[0].results[1], runs[0].results[2]) [codeql-repo.sarif]
- **info** run_clean: run reports no results (1 occurrence: runs[0]) [clean-run.sarif]
- **warning** unresolved_observation: js/xss-through-dom on https://github.com/example/webapp/src/ui/legacy.js has disposition unknown and was not reported as a vulnerability [codeql-repo.sarif]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
