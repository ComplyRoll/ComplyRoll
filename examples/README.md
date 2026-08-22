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

## Persisted path

The stateless command above compiles a report from files alone. The persisted path records
the same work as history first, so changing an evaluation appends a second evaluation
instead of overwriting the first. Run these six commands in order from the repository root.

```bash
complyroll ingest \
  tests/fixtures/ubuntu-host.cklb \
  tests/fixtures/windows-host.ckl \
  tests/fixtures/openscap-results.xml \
  --db complyroll.db \
  --as-of 2026-08-21T12:00:00Z

complyroll cases correlate --db complyroll.db

complyroll cases attest-detection \
  --db complyroll.db \
  --all-missing \
  --detected-at 2026-08-01T00:00:00Z \
  --rationale "The fixtures declare no assessment timestamp; the assessment ran on 1 August."

complyroll cases evaluate --db complyroll.db --evaluations examples/evaluations.json

complyroll cases list --db complyroll.db

complyroll report vdt \
  --db complyroll.db \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-31T23:59:59Z \
  --as-of 2026-08-21T12:00:00Z \
  -o report.json \
  --markdown report.md
```

The report this produces is byte-identical to the stateless one. Re-running any of the
first four commands appends nothing; edit `examples/evaluations.json` and re-run
`cases evaluate` to see a second evaluation appear in
`complyroll cases history <tracking-id> --db complyroll.db`.

`complyroll store verify --db complyroll.db` walks the whole log and exits non-zero on any
integrity fault.
