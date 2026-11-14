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
| Generator | complyroll 0.4.0a0 | n/a |

## Summary

| Measure | Count |
|---|---:|
| Vulnerabilities reported | 4 |
| Evaluated | 0 |
| Not yet evaluated | 4 |
| Overdue | 1 |
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
| case-0488e724b51dbd9b | change-detection-gap | 1 | 2026-08-20T00:00:00Z | n/a | n/a | n/a | n/a | 2026-08-25T00:00:00Z (VER-TFR-EVU) | yes | active |
| case-5fb2afe5f9d47d6c | change-detection-gap | 1 | 2026-09-01T01:00:00Z | n/a | n/a | n/a | n/a | 2026-09-06T01:00:00Z (VER-TFR-EVU) | no | active |
| case-04716522daa6f550 | js/unused-local-variable | 1 | 2026-09-01T02:00:00.123456Z | n/a | n/a | n/a | n/a | 2026-09-06T02:00:00.123456Z (VER-TFR-EVU) | no | active |
| case-d2b9f5abf1fe44ac | js/xss-through-dom | 1 | 2026-09-01T02:00:00.123456Z | n/a | n/a | n/a | n/a | 2026-09-06T02:00:00.123456Z (VER-TFR-EVU) | no | active |

## Vulnerability details

### case-0488e724b51dbd9b: change-detection-gap

- **Description:** change-detection-gap: VDR-CSO-DAC window for image:registry.example.test/synthetic/example-service:1.4.0 after change CHG-2001 closed 2026-08-20T00:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-08-20T00:00:00Z (source: system)
- **Observations:** obs-228b7afeb4f5bb07934d17ec6f1693fd88825b96c48ad71deea3fe38db99fee1
- **Affected resources:** image registry.example.test/synthetic/example-service:1.4.0
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** VER-TFR-EVU (SHOULD, Class C): the evaluation window opened at detection 2026-08-20T00:00:00Z and closed 2026-08-25T00:00:00Z with no evaluation recorded. Rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54. The VDR and VER rulesets are in their optional-adoption period until 2026-12-07.

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-08-20T00:00:00Z | 2026-08-25T00:00:00Z | no |

### case-5fb2afe5f9d47d6c: change-detection-gap

- **Description:** change-detection-gap: VDR-CSO-DAC window for file:src/ui/render.js after change CHG-2003 closed 2026-09-01T01:00:00Z with no verification recorded (VDR-CSO-FAV)
- **Detection source:** complyroll
- **Detected at:** 2026-09-01T01:00:00Z (source: system)
- **Observations:** obs-7293ce227cc7c7c514fe1d4af13ae7418b291b86e48ac3eb1d73c7ace04eac25
- **Affected resources:** file src/ui/render.js
- **Source identifiers:** n/a
- **Evaluation:** not yet completed
- **Disposition:** active; **remediated:** no
- **Overdue:** not overdue

| Rule | Name | Force | Anchor | Start | Due | Satisfied |
|---|---|---|---|---|---|---|
| VER-TFR-EVU | Evaluate Vulnerabilities Quickly | SHOULD | detection | 2026-09-01T01:00:00Z | 2026-09-06T01:00:00Z | no |

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

Every reported vulnerability carried a detection time from its source artifact or, for a change detection gap, from the instant its change window closed. No attestation was needed.

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

## Changes

Changes declared in timed-changes (6 changes, 3063 bytes, SHA-256 72757cd6671011f642de47c2c1d854693fc375be55a884dbd5a6f333c4d6f48c), read against the inventory with SHA-256 49e3d4806d4bd6cd9e918b2751b5aeb1c9fe8473398b104799fb27fb62b35c2e as of 2026-09-03T12:00:00Z, under VDR-CSO-DAC (SHOULD) from rules dataset commit 58487bda77d76d9ce334304ec2e779ece7cc7d54.

VDR-CSO-DAC states no timeframe, so a window here is only the provider's own detectBy, and a change without a window is tracked but never lapses. Changes are measured against the provider-supplied inventory named by its SHA-256 digest, so a resource it omits is listed as unregistered and opens no obligation. A detection obligation is satisfied only by a verification at or after the change and at or before as-of; an examination that verified nothing does not satisfy one, and neither does untimed evidence. A created change and a new entry's coverage clocks overlap on purpose, under different rules. A detected status is not a compliance finding.

### Obligations by status

| Status | Obligations |
|---|---:|
| unregistered | 0 |
| retired | 0 |
| logged | 0 |
| detected | 3 |
| lapsed | 1 |
| undetermined | 1 |
| pending | 1 |

### Declared changes

| Change | Kind | Occurred at | Source | Significant | Rationale | Detect by | Job | Force |
|---|---|---|---|---|---|---|---|---|
| CHG-2001 | modified | 2026-08-10T00:00:00Z | registry: push 8842 | yes | Base layer rebuilt after the last image scan. | 2026-08-20T00:00:00Z | nightly-image-scan | SHOULD |
| CHG-2002 | modified | 2026-08-28T00:00:00Z | ticket: CR-2026-204 | yes | Template engine swapped across the UI sample. | n/a | n/a | SHOULD |
| CHG-2003 | modified | 2026-09-01T00:10:00Z | git: commit 0c4d9aa | yes | Render path change with a one-hour scan window the nightly run missed. | 2026-09-01T01:00:00Z | nightly-codeql | SHOULD |
| CHG-2004 | modified | 2026-09-01T00:30:00Z | git: commit 5ab10c2 | yes | Sanitizer helper rewritten. | 2026-09-05T00:00:00Z | nightly-codeql | SHOULD |
| CHG-2005 | modified | 2026-09-01T00:40:00Z | git: commit 77e9d31 | yes | Legacy renderer touched; the scan could not resolve its data flow. | 2026-09-10T00:00:00Z | nightly-codeql | SHOULD |
| CHG-2006 | modified | 2026-09-02T09:00:00Z | git: commit e8812f0 | yes | Helper follow-up after the nightly scan; no scan has run since. | 2026-09-09T00:00:00Z | nightly-codeql | SHOULD |

### Obligations

A recorded row is a VDR-CSO-FAV system record of this run and names its tracking ID here even when this report does not select the record, such as one detected after the report period. A row whose window did not close records nothing and reads n/a.

| Change | Resource | Entry | Sample group | Matched as | Status | Force | Evidence | Stand-in | Lag seconds | Age seconds | Late | Window closed | Resumed | Untimed | KEV at activation | KEV tracking IDs | Recorded | Tracking ID |
|---|---|---|---|---|---|---|---|---|---:|---:|---|---|---|---:|---|---|---|---|
| CHG-2001 | image:registry.example.test/synthetic/example-service:1.4.0 | image:registry.example.test/synthetic/example-service:1.4.0 | n/a | image:registry.example.test/synthetic/example-service:1.4.0 | lapsed | SHOULD | n/a | n/a | n/a | 2116800 | no | 2026-08-20T00:00:00Z | n/a | 0 | n/a | n/a | yes | case-0488e724b51dbd9b |
| CHG-2002 | logical:sample-group/webapp-ui | n/a | webapp-ui | n/a | detected | SHOULD | observation obs-fdcb47349a49f24da9ed9ef671d72a2302f8c726e5fe17cee8524e7f15ba12df (open) on file:https://github.com/example/webapp/src/ui/render.js at 2026-09-01T02:00:00.123456Z | file:src/ui/render.js | 352800 | n/a | no | n/a | n/a | 0 | n/a | n/a | n/a | n/a |
| CHG-2003 | file:src/ui/render.js | file:src/ui/render.js | webapp-ui | file:https://github.com/example/webapp/src/ui/render.js | detected | SHOULD | observation obs-fdcb47349a49f24da9ed9ef671d72a2302f8c726e5fe17cee8524e7f15ba12df (open) on file:https://github.com/example/webapp/src/ui/render.js at 2026-09-01T02:00:00.123456Z | n/a | 6600 | n/a | yes | 2026-09-01T01:00:00Z | 2026-09-01T02:00:00.123456Z | 0 | n/a | n/a | yes | case-5fb2afe5f9d47d6c |
| CHG-2004 | file:https://github.com/example/webapp/src/ui/helpers.js | file:https://github.com/example/webapp/src/ui/helpers.js | n/a | file:https://github.com/example/webapp/src/ui/helpers.js | detected | SHOULD | observation obs-5eed8cd90893738613d23955692bf60df48eb1b6c3ec34d5df5ee2354a1b096f (open) on file:https://github.com/example/webapp/src/ui/helpers.js at 2026-09-01T02:00:00.123456Z | n/a | 5400 | n/a | no | n/a | n/a | 0 | n/a | n/a | n/a | n/a |
| CHG-2005 | file:https://github.com/example/webapp/src/ui/legacy.js | file:https://github.com/example/webapp/src/ui/legacy.js | n/a | file:https://github.com/example/webapp/src/ui/legacy.js | undetermined | SHOULD | n/a | n/a | n/a | 213600 | no | n/a | n/a | 0 | n/a | n/a | n/a | n/a |
| CHG-2006 | file:https://github.com/example/webapp/src/ui/helpers.js | file:https://github.com/example/webapp/src/ui/helpers.js | n/a | file:https://github.com/example/webapp/src/ui/helpers.js | pending | SHOULD | n/a | n/a | n/a | 97200 | no | n/a | n/a | 0 | n/a | n/a | n/a | n/a |

### Unregistered resources

Every resource a change names is in the inventory.

### Changes after as-of

No change occurred after as-of.

## Diagnostics

- **info** baseline_state_ignored: baselineState is recorded as metadata and never changes a disposition (3 occurrences: runs[0].results[0], runs[0].results[1], runs[0].results[2]) [codeql-repo.sarif]
- **info** run_clean: run reports no results (1 occurrence: runs[0]) [clean-run.sarif]
- **warning** unresolved_observation: js/xss-through-dom on https://github.com/example/webapp/src/ui/legacy.js has disposition unknown and was not reported as a vulnerability [codeql-repo.sarif]
- **warning** change_precedes_expected_since: change CHG-2002 occurred before logical:sample-group/webapp-ui's expectedSince 2026-09-01T00:00:00Z; the obligation runs from occurredAt as the provider stated it, and the two statements disagree [timed-changes CHG-2002 logical:sample-group/webapp-ui]

---

Generated by ComplyRoll; informational; not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP Consolidated Rules for 2026.
