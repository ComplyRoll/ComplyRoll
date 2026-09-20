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

## Amendment 2026-09-16: re-pin to rules 2026.09.13.02

The bundle now pins `FedRAMP/rules` commit `58487bda77d76d9ce334304ec2e779ece7cc7d54`, dataset
version `2026.09.13.02`, last updated 2026-09-13, SHA-256
`64915d88e72353c95f321ea4a9014516ac9441972cbd7f3d1abef7d1514c8fc8`, and the schema at that
commit, SHA-256 `eb4710bee0b06d0f8f803302ac2e88b934ef2bc942d0b548738c7304f0cb418f`. The process
this record describes was followed as written: the manifest records the new commit, retrieval
time, version, last-updated value, and both digests, and the loader verifies them before any
rule is selected.

The paragraph above that gives `VDR-TFR-NMV` no calculable direct timeframe records the dataset
as it stood at `2026.07.14.01`. ComplyRoll raised that gap as FedRAMP/community discussion 164
and FedRAMP fixed it in `2026.09.13.01` (upstream pull request 28): the rule now carries
`timeframe_type` `months` and `timeframe_num` `3`, so `SelectedRule.timeframe` and
`deadline_for_rule` return the three-month clock for Class B and Class C. The report compiler
computes no per-vulnerability deadline from it, because the rule is a recurrence clock on each
non-machine-based information resource and ComplyRoll has no such records yet; that clock
belongs to the coverage and freshness slice of Phase 2. The same upstream change gave the schema
optional `timeframe_num_min` and `timeframe_num_max` for `CCM-QTR-SAR`, a rule outside the
selected VDR and VER scope. The loader does not read the range fields, and a selected rule that
carried `timeframe_type` without `timeframe_num` is still refused. Within the VDR and VER
documents, the only other change between the two pins is the `terms` array of 41 rules, which
the selector does not read; `2026.09.13.02` (upstream pull request 29) touched only those arrays
and the FRD definitions. The selected rule count stays at 36 per class, and every other
timeframe, force, and PAIN matrix is unchanged, as the policy golden shows.
