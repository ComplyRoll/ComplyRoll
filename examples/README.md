# Examples

Synthetic inputs for the fixture-to-report demo. Nothing here describes a real system, agency,
person, or address.

`evaluations.json` supplies the contextual judgement ComplyRoll cannot read from a scanner:
internet reachability, likely exploitability, PAIN, potential agency impact, rationale, and the
evaluator who stands behind them. One entry records a disposition; the other records a planned
next PAIN reduction and a completed one.

Run both commands from the repository root.

```bash
complyroll report vdt \
  tests/fixtures/ubuntu-host.cklb \
  tests/fixtures/windows-host.ckl \
  tests/fixtures/openscap-results.xml \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-31T23:59:59Z \
  --as-of 2026-08-21T12:00:00Z \
  --detected-at 2026-08-01T00:00:00Z \
  --evaluations examples/evaluations.json \
  -o report.json \
  --markdown report.md

complyroll validate report.json --schema vulnerability-detail
```

The fixtures declare no assessment timestamp, so `--detected-at` is required. ComplyRoll never
substitutes file modification or ingestion time for a detection time; without the attestation the
run stops and names the affected tracking identifiers.

`--as-of` fixes the instant the overdue flags are calculated against. Supplying it makes the run
reproducible byte for byte; omitting it uses the current UTC time.
