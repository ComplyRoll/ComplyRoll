# ADR 0009: Adopt Common Definitions 0.3.0

- Status: Accepted
- Date: 2026-09-04

## Context

ADR 0006 pinned the report-schema bundle to `FedRAMP/schemas` commit
`ae43ae2952c5dd5c56d54d12e8b92c7db1b3710a`, with Common Definitions at version `0.2.1`. That
version cited `VER-RPT-PAE` for its `painReductionEvent` definition, a rule identifier the pinned
rules dataset does not contain, and no report schema referenced the definition. ComplyRoll raised
the gap as [FedRAMP/schemas issue 16](https://github.com/FedRAMP/schemas/issues/16) and, per
ADR 0007 Decision 8, shipped completed PAIN reductions under the `x-complyroll` extension because
the official structure had no slot for them. ADR 0007 Decision 4 mapped the `remediated` case
status to `Fully Mitigated` because the official `finalDisposition` enumeration had no value for
remediation.

On 2026-09-01 FedRAMP merged pull request 22 as commit
`5156719aa7d0def16cf66f6197db9d6c0024e0e7`. It changes one file, Common Definitions, from
`0.2.1` to `0.3.0`: `finalDisposition` gains `Remediated` (upstream issue 3),
`vulnerabilityDetail` gains an optional `painReductionEvents` array of `painReductionEvent`
(upstream issue 7), and the `painReductionEvent` description now cites `VER-RPT-VDT` (issue 16).
The three report schemas are byte-identical to the `0.1.1` copies already bundled. The
`FedRAMP/rules` pin is unaffected. Both additions land on the `vulnerabilityDetail` definition
that the Vulnerability Detail Report's `vulnerabilities` items resolve to.

## Decision 1: re-pin the bundle to commit 5156719a

The manifest now records commit `5156719aa7d0def16cf66f6197db9d6c0024e0e7`, retrieved
2026-09-04T22:52:22Z, with Common Definitions at `0.3.0` and SHA-256
`ed810d60584580fb86cda3f846d94504a14e09538122c27c5b5231d41151d6de`. The three report-schema
entries are unchanged. The bundled bytes are the ones GitHub serves at that commit, and the
loader verifies them exactly as ADR 0006 describes.

The pin is that merge commit and not the `main` head. Later commits on `main` touch only the
Security Decision Record and package overview schemas, which ComplyRoll does not bundle, and a
pin should name the commit that introduced the change being adopted so that the manifest, the
report provenance, and this record all cite one reviewable diff.

## Decision 2: `remediated` maps to `Remediated`

The `remediated` status now emits `finalDisposition: "Remediated"`. Every other row of the
ADR 0007 Decision 4 table is unchanged: `fully_mitigated` still emits `Fully Mitigated`,
`partially_mitigated` and `false_positive` emit their official values, active statuses omit the
field, `closed` emits the disposition recorded at close, and `accepted` never appears in a detail
report.

## Decision 3: completed reductions publish in the official slot

`painReductionEvents` moves from the per-vulnerability `x-complyroll` object to the official
`vulnerabilityDetail` record. The list is emitted only when a case has at least one completed
reduction, following the `projectedNextReduction` pattern for optional official fields, and its
items keep the `reducedAt` and `rating` shape and the canonical order, by instant and then
rating, that the ADR 0008 amendment of 2026-08-22 settled. The extension no longer carries a
copy: one fact, one place. The extension
keeps `remediated`, because `Remediated` as a disposition and `remediated` as a case fact are
read by different consumers and the flag costs nothing to keep.

This is a breaking change to the `x-complyroll` extension. ComplyRoll is pre-1.0 and the
extension is documented as the place where fields wait for an official slot, so a field leaving
it when the official slot arrives is the extension working as intended. The change ships in the
next pre-release and the CHANGELOG names the moved key.

## Consequences

- Reports validate against Common Definitions `0.3.0`. Report provenance (`schemaSource` in the
  JSON and the Provenance table in the Markdown) now cites commit `5156719a`, so the two VDT
  goldens moved: the commit in both, and in the JSON the relocated key plus the empty extension
  lists that are no longer emitted. The schema-examples golden gained a `Remediated` example and
  a `painReductionEvents` example so the validity test exercises both additions.
- A consumer that read `x-complyroll.painReductionEvents` must read `painReductionEvents` on the
  vulnerability record instead, and must treat the key as optional: an empty list is no longer
  emitted.
- A consumer that read `finalDisposition` sees a fourth value, `Remediated`, where it previously
  saw `Fully Mitigated` for remediated cases. `x-complyroll.remediated` is unchanged.
- Reductions on a vulnerability record are now checked by the schema. Under `0.2.1` the key
  would have passed as an unchecked additional property; under `0.3.0` a malformed item is a
  validation error, and a test proves it.
- ADR 0006 and ADR 0007 carry dated amendments pointing here. Their original text stands as the
  record of the decision at the time.

## Rejected alternatives

Waiting for a tagged upstream release was rejected because the schemas are versioned by the
`$schemaVersion` inside each document and identified by commit, which is what the ADR 0006
manifest already pins, and because the correction resolves an issue ComplyRoll itself raised.
Keeping a duplicate copy of `painReductionEvents` in the extension for compatibility was
rejected because two copies of one list invite drift, and the extension exists to hold fields
that have no official slot, not to mirror ones that do. Pinning the `main` head was rejected
because the commits after `5156719a` change schemas ComplyRoll does not bundle, and the pin
should name the diff that was reviewed.
