# ADR 0005: Select policy from a verified FedRAMP rules snapshot

- Status: Accepted
- Date: 2026-08-20

## Context

Phase 1 must calculate Class B and Class C VDR and VER deadlines without maintaining a second
hand-written policy table. Every result must identify the official rule, dataset version, commit,
and digest that supplied it. Policy loading must also remain offline and reproducible on hardened
workstations.

The official `FedRAMP/rules` dataset represents certification applicability at the rule-subset
level, type-specific rules under `all`, `20x`, or `rev5` scopes, class variants under
`varies_by_class`, and response targets under structured `pain_timeframes` entries.

## Decision

ComplyRoll bundles the exact official dataset bytes identified by
`fedramp-rules-source.json`. Loading calculates SHA-256 before parsing and rejects content whose
digest, dataset version, or last-updated value differs from the manifest. JSON parsing is bounded,
rejects duplicate keys and non-standard constants, and does not use the network at runtime.

The initial policy selector supports provider-facing FedRAMP 20x Program profiles for Class B and
Class C. It selects VDR and VER rules only when the official subset applicability includes the
profile's certification type, path, class, and affected party. It merges the `all` and `20x`
scopes, resolves the matching class level, and preserves the rule identifier, force, statement,
timeframe, and PAIN response matrix.

Deadline results contain the source rule and complete policy provenance. Evaluation begins at
detection, response begins at completed evaluation, and the 192-day acceptance threshold only
flags that provider categorization is required. It never accepts risk automatically. N1 has no
response deadline in the structured matrix and remains routine provider operations.

ComplyRoll calculates structured hours, days, and weeks as elapsed UTC durations. Months and years
use calendar arithmetic in UTC and clamp to the last valid day of the destination month. Business
days fail closed until an explicit holiday and timezone calendar is selected.

ComplyRoll does not derive a timeframe from prose. In the current pinned dataset,
`VDR-TFR-NMV` states three months but does not include `timeframe_type` and `timeframe_num`; the
selected rule therefore has no calculable direct timeframe. KEV due dates also remain external
inputs from the applicable CISA catalog rather than being inferred from FedRAMP prose.

Golden test fixtures record the expected Class B and Class C matrices for regression detection;
runtime calculations always read the verified official dataset.

## Consequences

Benefits:

- Rule changes require a new manifest and verified snapshot rather than application-code edits.
- Every calculated deadline carries reproducible source provenance.
- Class differences in force, recurrence, evaluation, and PAIN response targets remain explicit.
- Missing structured source data blocks calculation instead of producing an undocumented default.

Costs and limits:

- The full official dataset adds roughly 555 KiB to the package.
- Full JSON Schema validation is deferred to the schema-resolution slice; this loader validates
  the structures it consumes and verifies the dataset digest, while the manifest pins the schema
  digest for that follow-on work.
- Class A, Class D, Rev5, Agency-path, and non-provider policy selection are not yet supported.
- Business-day and KEV deadlines need separate authoritative calendars or source inputs.

## Rejected alternatives

Hardcoding the published deadline tables was rejected because it would create an unversioned
second policy source. Parsing numbers from human-readable rule statements was rejected because it
would be brittle and could silently misinterpret future language. Fetching rules during every run
was rejected because it would break offline reproducibility and historical report regeneration.
