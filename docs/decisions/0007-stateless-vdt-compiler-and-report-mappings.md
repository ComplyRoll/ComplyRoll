# ADR 0007: Compile the first Vulnerability Detail Report statelessly, and fix the mappings it needs

- Status: Accepted
- Date: 2026-08-21

## Context

Phase 1 exit criterion 1 reads: a CKLB/XCCDF assessment becomes a schema-valid VER report without
spreadsheet manipulation. Every primitive that criterion needs already exists as a library
(hardened ingestion, class-aware policy deadlines, offline schema validation), but nothing joins
them, and three mapping questions block the join. Each of them is a domain decision, not an
implementation detail, so they are recorded here before the compiler is written.

The official Vulnerability Detail Report (`VER-RPT-VDT`, schema version 0.1.1 with Common
Definitions 0.2.1) requires, per vulnerability, only `providerTrackingId`,
`detection.detectedAt`, `detection.detectionSource`, and `vulnerabilityDescription`. The
remaining fields are optional but carry the evaluation, clocks, and disposition that make the
report useful. The report envelope requires `certificationPackageOverviewUri`, a
`reportPeriod`, and the `vulnerabilities` array. The schemas permit additional properties.

## Decision 1: the first compiler is a pure function of artifacts plus explicit inputs

`complyroll report vdt` compiles a Vulnerability Detail Report directly from source artifacts and
an optional evaluations file. It does not read or write the event store. Persistence, case
history, and rebuildable projections remain the Phase 1 design, but they are the second slice,
not a prerequisite for the first report. A stateless compiler is reproducible by construction:
the same artifacts, evaluations, package configuration, and `--as-of` instant produce the same
bytes, which is exactly the property an independent assessor is told to test.

The compiler fails closed. An artifact that does not ingest successfully stops the run with a
non-zero exit and the diagnostics on stderr; partial reports are not written. The JSON document
is validated against the bundled official schema before it is written, and the Markdown twin is
rendered from the same record list, so the two cannot disagree.

## Decision 2: detection time is attested, never substituted

`detection.detectedAt` is required by the official schema. ComplyRoll already refuses to treat
file modification time or ingestion time as a detection time (ADR 0002, `docs/DATA_MODEL.md`).
Those two facts collide for every CKL, and for CKLB and XCCDF files that omit timestamps.

Resolution: when every observation grouped into a vulnerability carries `observed_at`, the
earliest one is the detection time. When none does, the operator must attest a detection time
explicitly with `--detected-at <RFC 3339>`. The attestation applies to every vulnerability that
lacks a source timestamp, is recorded in the report's `x-complyroll` extension as
`detectionTimeAttestation` with the supplied value and the count of vulnerabilities it covered,
and appears in the Markdown twin. Without an attestation, a vulnerability lacking a source
timestamp is a compile error that names the affected tracking identifiers; it is never silently
dropped and never given a guessed time.

When the event store learns domain events, the same attestation becomes a `detection.attested`
event with an actor, and the stateless flag is retired.

## Decision 3: which observations are vulnerabilities, and how they group

Only observations with disposition `open` are vulnerabilities in a Vulnerability Detail Report.
`pass`, `not_applicable`, `not_reviewed`, `error`, and `unknown` dispositions are not detected
weaknesses; `error` and `unknown` are surfaced as diagnostics so they are not lost. Treating
unreviewed checks as vulnerabilities would overstate exposure; treating them as clean would
understate it, and the compatibility roll-up already counts them separately.

Correlation v0 groups open observations by `(source_type, source_record_id, context_key)`. A rule
that fails on many hosts is one vulnerability with many affected resources, which is how VDR
expects providers to report (`VER-EVA-GRV`). Every grouped observation identifier and every
affected resource is preserved in the `x-complyroll` extension, so grouping never destroys
instance detail (README non-negotiable rule 4). The provider tracking identifier is
`case-` followed by the first sixteen hex characters of SHA-256 over the JSON-encoded group key,
which is stable across runs, artifacts, and hosts. Operators may override it per vulnerability in
the evaluations file when they already track the weakness under another identifier.

Manual split and merge, cross-source correlation, and fingerprint-independent grouping remain
event-store work.

## Decision 4: `CaseStatus` to `finalDisposition`

The official enumeration is `Fully Mitigated`, `Partially Mitigated`, and `False Positive`, and
the field is omitted while a vulnerability is still active.

| ComplyRoll status | `finalDisposition` | Report |
|---|---|---|
| `new`, `evaluating`, `active` | omitted | VDT |
| `partially_mitigated` | `Partially Mitigated` | VDT |
| `fully_mitigated` | `Fully Mitigated` | VDT |
| `remediated` | `Fully Mitigated` | VDT |
| `false_positive` | `False Positive` | VDT |
| `accepted` | not applicable | AVI only, never VDT |
| `closed` | the disposition recorded when the case closed; an error if none was | VDT |

Remediation is stronger than full mitigation (the weakness no longer exists rather than being
unreachable), and the official vocabulary has no separate value for it. Mapping it to
`Fully Mitigated` is the truthful choice inside that vocabulary; the `x-complyroll` extension
records `remediated: true` so the distinction is not lost. Accepted vulnerabilities are reported
under `VER-RPT-AVI` with an `acceptanceRationale`; they never appear in the detail report
(the schema description says so explicitly).

In the stateless compiler the status comes from the evaluations file (`disposition` field).
Absent an evaluation, a vulnerability is active.

## Decision 5: package configuration is explicit input

`certificationPackageOverviewUri`, the certification class, the report period, the calendar
timezone, and the `--as-of` instant are operator inputs supplied as command-line options in this
slice. A package configuration file is deferred until two commands need the same values. The
calendar timezone defaults to UTC and is recorded in the extension; the `--as-of` instant
defaults to the current UTC time and is recorded as `generatedAt` in the extension so a rerun can
reproduce the same overdue flags.

## Decision 6: clock semantics

- A timeframe expressed in hours, days, or weeks is an exact elapsed duration from the anchor
  instant: two days means 172,800 seconds. No rounding to end of day. This is the conservative
  reading, never later than any calendar interpretation.
- Months and years are calendar arithmetic performed in the configured calendar timezone, with
  month-end clamping, then converted to UTC for output. ADR 0005 previously performed that
  arithmetic on the UTC instant; `--calendar-tz` is how the compiler selects the provider's
  calendar, and the policy engine gains a timezone parameter to match.
- Recurring obligations (monthly report, detection cycles) anchor on the actual completion time
  of the previous cycle, not on the previous due date, so schedules do not ratchet toward the
  28th. The compiler does not yet emit recurrence clocks; this records the rule for when it does.
- The evaluation clock (`VER-TFR-EVU`) starts at `detectedAt`. Response clocks (`VDR-TFR-PVR`)
  and the accepted-vulnerability threshold (`VER-TFR-MAV`) start at `evaluationCompletedAt`.
- A KEV clock, when added, stops only on remediation, because `VDR-TFR-KEV` applies "even if the
  vulnerability has been fully mitigated".

## Decision 7: overdue means overdue against a named rule with its force

`overdueStatus.isOverdue` is true when, at the `--as-of` instant, any of the following has
passed: the evaluation window with no evaluation recorded (`VER-TFR-EVU`), the PAIN response
target with no disposition recorded (`VDR-TFR-PVR`), or the 192-day acceptance threshold with no
disposition and no acceptance (`VER-TFR-MAV`). The required `explanation` names the rule
identifier, its force, the class, the inputs (PAIN, IRV, LEV where relevant), the due instant,
and the provenance commit. A SHOULD target is reported as overdue against a SHOULD target, never
as a MUST violation; only `VER-TFR-MAV` is a MUST boundary. While the ruleset's `obtain` date
(2026-12-07 for VDR and VER) has not passed at `--as-of`, the explanation also says the ruleset
is in its optional-adoption period. The extension carries every computed deadline with rule,
force, anchor, and due instant so the flag can be audited.

## Decision 8: provider extensions live under one namespaced key

Everything ComplyRoll adds beyond the official minimum structure goes under a single
`x-complyroll` object, at the report level and per vulnerability, so a future official field can
never collide with it. Report level: generator name and version, parser versions, rules dataset
commit, version, and digest, schema commit and digest, `generatedAt`, calendar timezone,
detection-time attestation, and the disclaimer sentence. Vulnerability level: observation
identifiers, affected resources, source identifiers (CCIs), computed deadlines, `remediated`,
and `painReductionEvents` using the Common Definitions `painReductionEvent` shape, which the
official report schemas do not yet reference (the definition cites `VER-RPT-PAE`, a rule the
pinned dataset does not contain).

The disclaimer travels with every emitted document: "Generated by ComplyRoll; informational;
not a FedRAMP® determination; the provider remains responsible for compliance with the FedRAMP
Consolidated Rules for 2026."

## Decision 9: the evaluations file

Evaluations are supplied as a bounded JSON document:

```json
{
  "evaluations": [
    {
      "match": {"sourceRecordId": "V-220697"},
      "trackingId": "optional provider identifier override",
      "completedAt": "2026-08-20T16:00:00Z",
      "isInternetReachable": true,
      "isLikelyExploitable": true,
      "pain": 4,
      "potentialAgencyImpact": "…",
      "rationale": "…",
      "evaluator": "…",
      "isFalsePositive": false,
      "disposition": null,
      "projectedNextReduction": {"estimatedAt": "2026-08-24T16:00:00Z", "targetRating": 3},
      "painReductionEvents": [],
      "supplementaryRiskInformation": null
    }
  ]
}
```

`match` selects vulnerabilities by `sourceRecordId` with an optional `contextKey` and
`sourceType`; an entry that matches nothing or matches more than one vulnerability is an error.
Every evaluation must carry `completedAt`, IRV, LEV, PAIN, `potentialAgencyImpact`,
`rationale`, and `evaluator` (`VER-EVA-*` and the evaluator provenance rule in
`docs/SECURITY.md`). `disposition`, when present, is one of the `CaseStatus` values from
Decision 4. The file is parsed with the same bounds and duplicate-key rejection as every other
untrusted JSON input.

## Decision 10: the language stays Python through the VDR/VER obtain date

ComplyRoll remains Python at least until 2026-12-07. The verified domain surface, the compliance
and scanner ecosystem an assessor already runs, and the hiring audience all read Python, and none
of the audit findings were language limits. The decision is revisited at Phase 2 adapters; if a
TypeScript sibling is ever built, it consumes ComplyRoll's JSON outputs, which forces the
canonical-form decision recorded in ADR 0004.

## Consequences

- `complyroll report vdt` and `complyroll validate` become the first user-facing commands, and
  the README demo is a fixture-to-report run.
- The policy engine gains an explicit calendar timezone; ADR 0005's UTC-only calendar arithmetic
  is superseded for months and years.
- The event-store slice that follows must reproduce exactly this report from events, which is
  the reconciliation test for that slice.
- Accepted-vulnerability and historical-activity reports reuse the same record compiler with
  different selection rules.

## Rejected alternatives

Starting the evaluation clock at ingestion time when no source timestamp exists was rejected
because it makes an overdue evaluation look compliant. Inventing a fourth disposition value for
remediation was rejected because the official enumeration is closed. Building the projection
layer first was rejected because it delays the exit criterion by weeks for no gain in
reproducibility. Emitting extension fields at the top level of each vulnerability was rejected
because a future official field could collide with them.
