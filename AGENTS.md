# Repository instructions

TrustRoll is a local-first FedRAMP 20x VDR evidence compiler. Preserve its auditability and avoid
turning it into a generic compliance dashboard.

## Start here

Read these files before changing architecture or domain behavior:

1. `README.md`
2. `docs/BUILD_PLAN.md`
3. `docs/ARCHITECTURE.md`
4. `docs/DATA_MODEL.md`
5. `docs/FEDRAMP_2026_MAPPING.md`
6. `docs/SECURITY.md`

## Domain invariants

- Observations are immutable source facts; vulnerability cases are stateful aggregates.
- Never derive PAIN directly from CAT, CVSS, scanner severity, or a single finding.
- Never treat a STIG or scanner result as complete proof of a KSI.
- Never discard per-resource observations when grouping a vulnerability case.
- Preserve source timestamps, tool identity, source identifiers, and evidence digests.
- Policy calculations must record the pinned FedRAMP rules source and version.
- Human- and machine-readable projections must use the same normalized records.
- A detection or response process failure is itself eligible to become an observation and case.
- Avoid language that implies TrustRoll is FedRAMP approved or government endorsed.

## Source and dependency policy

- Use the official `FedRAMP/rules` structured dataset as the canonical rules source.
- Do not hardcode a deadline when it can be selected from the pinned rules dataset.
- Preserve compatibility with Python 3.11 or newer.
- Keep the domain model independent from web frameworks and database implementations.
- New runtime dependencies require a documented reason and a security/maintenance assessment.

## Commands

Run from the repository root:

```bash
PYTHONPATH=src python3 -m trustroll version
PYTHONPATH=src python3 -m trustroll plan
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
```

## Change expectations

- Add or update tests for every domain behavior change.
- Add an architecture decision record under `docs/decisions/` for meaningful data-model,
  persistence, policy, or security decisions.
- Keep examples synthetic and free of customer, agency, employee, credential, and infrastructure
  details.
- Treat all imported assessment files as untrusted input.
