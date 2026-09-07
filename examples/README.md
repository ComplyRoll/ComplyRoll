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

Each writing command reports what it recorded on standard output, and its warnings on
standard error. The five commands before the report print this, with the ingest warnings
about the fixtures' missing timestamps left out:

```text
ubuntu-host.cklb: recorded 6 observation(s)
windows-host.ckl: recorded 2 observation(s)
openscap-results.xml: recorded 3 observation(s)

created 6 case(s), linked 6 observation(s), skipped 0 already-linked observation(s)

selected 6 case(s) with no source timestamp on any observation
attested 6 case(s), skipped 0 unchanged case(s), 0 not applicable case(s)

evaluations: 2 appended, 0 skipped
pain reductions: 1 appended, 0 skipped
dispositions: 1 appended, 0 skipped
identifications: 0 appended, 0 skipped

TRACKING ID            PROVIDER ID  SOURCE RECORD     RESOURCES  EVALUATIONS  PAIN  DISPOSITION
case-04efea8c137ae82f  -            banner_etc_issue          1            0  -     active
case-1f3e011db93cc89e  -            V-260470                  1            1  3     partially_mitigated
case-490f49bfdd1bd019  -            V-253260                  1            1  4     active
case-621d85d6533ce6e5  -            V-260474                  1            0  -     active
case-6719b316a5ea510b  -            no_cci_mapping            1            0  -     active
case-9bed0d8f88355393  -            V-260469                  1            0  -     active
```

`--all-missing` chooses its own cases, so it reports how many it chose before it reports
what it did with them. A second sweep selects nothing, because a case that already carries
an attestation is not missing a detection time; revising one takes an explicit `--case`.

The report this produces is byte-identical to the stateless one. Re-running any of the
first four commands appends nothing; edit `examples/evaluations.json` and re-run
`cases evaluate` to see a second evaluation appear in
`complyroll cases history <tracking-id> --db complyroll.db`.

Only `ingest` creates a store, and it never deletes one. A store that does not exist yet is
built at a temporary path beside the destination and linked into place once the whole run
succeeded, so a failed ingest leaves the operator exactly what they had. If another run
publishes a store at that path first, this one says so and stops rather than overwriting it:

```text
error: store_conflict: a store appeared at 'complyroll.db' while this run was building one; repeat the run against it
```

## Accepted vulnerabilities and the other two reports

`evaluations-accepted.json` is `evaluations.json` with one more entry. It accepts the
`banner_etc_issue` finding in the OpenSCAP results, rated PAIN 2, with the acceptance
rationale the official format requires. One accepted record changes what each report holds.
The Vulnerability Detail Report leaves it out and says so in a diagnostic. The Accepted
Vulnerability Information report (VER-RPT-AVI) publishes it with its rationale. The
Historical VER Activity snapshot (VER-TFR-MRH) lists it beside the five active records.

The three commands take the same inputs. `report avi` takes the same report period as
`report vdt` and publishes the accepted records that had recorded activity inside it.
`report historical` has no period: it is a snapshot as of `--as-of`, and it rejects `--from`
and `--to` as unrecognized arguments. Run these from the repository root.

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
  --evaluations examples/evaluations-accepted.json \
  -o vdt.json \
  --markdown vdt.md

complyroll report avi \
  tests/fixtures/ubuntu-host.cklb \
  tests/fixtures/windows-host.ckl \
  tests/fixtures/openscap-results.xml \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-31T23:59:59Z \
  --as-of 2026-08-21T12:00:00Z \
  --detected-at 2026-08-01T00:00:00Z \
  --evaluations examples/evaluations-accepted.json \
  -o avi.json \
  --markdown avi.md

complyroll report historical \
  tests/fixtures/ubuntu-host.cklb \
  tests/fixtures/windows-host.ckl \
  tests/fixtures/openscap-results.xml \
  --class C \
  --package-uri https://example.test/cpo \
  --as-of 2026-08-21T12:00:00Z \
  --detected-at 2026-08-01T00:00:00Z \
  --evaluations examples/evaluations-accepted.json \
  -o historical.json \
  --markdown historical.md

complyroll validate vdt.json --schema vulnerability-detail
complyroll validate avi.json --schema accepted-vulnerability
complyroll validate historical.json --schema historical-activity
```

The detail report prints one line on standard error that the other two do not, naming the
report the accepted record belongs in:

```text
info: accepted_excluded: case-04efea8c137ae82f is an accepted vulnerability and belongs in the VER-RPT-AVI report, not the Vulnerability Detail Report [banner_etc_issue]
```

The same three reports compile from a store. Run the persisted sequence above with
`examples/evaluations-accepted.json` in place of `examples/evaluations.json` at the
`cases evaluate` step. The evaluate and list commands then print this instead:

```text
evaluations: 3 appended, 0 skipped
pain reductions: 1 appended, 0 skipped
dispositions: 2 appended, 0 skipped
identifications: 0 appended, 0 skipped

TRACKING ID            PROVIDER ID  SOURCE RECORD     RESOURCES  EVALUATIONS  PAIN  DISPOSITION
case-04efea8c137ae82f  -            banner_etc_issue          1            1  2     accepted
case-1f3e011db93cc89e  -            V-260470                  1            1  3     partially_mitigated
case-490f49bfdd1bd019  -            V-253260                  1            1  4     active
case-621d85d6533ce6e5  -            V-260474                  1            0  -     active
case-6719b316a5ea510b  -            no_cci_mapping            1            0  -     active
case-9bed0d8f88355393  -            V-260469                  1            0  -     active
```

Then compile the other two reports from the store. Neither run names `--detected-at` or
`--evaluations`, because the store already holds the attestation and the evaluations, and
naming either beside `--db` is refused.

```bash
complyroll report avi \
  --db complyroll.db \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-31T23:59:59Z \
  --as-of 2026-08-21T12:00:00Z \
  -o avi.json \
  --markdown avi.md

complyroll report historical \
  --db complyroll.db \
  --class C \
  --package-uri https://example.test/cpo \
  --as-of 2026-08-21T12:00:00Z \
  -o historical.json \
  --markdown historical.md
```

Each persisted report is byte-identical to its stateless twin, JSON and Markdown alike. With
the fixed `--as-of`, the AVI and historical outputs are `tests/golden/avi-fixtures.json`,
`tests/golden/avi-fixtures.md`, `tests/golden/historical-fixtures.json`, and
`tests/golden/historical-fixtures.md`.

Move the start of the period past the acceptance, say `--from 2026-08-07T00:00:00Z`, and
`report avi` publishes no accepted record, counts one as excluded by the period, and explains
why in a diagnostic. The snapshot still holds it, because a snapshot has no period to fall
outside of.

```text
info: excluded_by_period: case-04efea8c137ae82f is accepted and no recorded activity between 2026-08-07T00:00:00Z and 2026-08-31T23:59:59Z [banner_etc_issue]
```

The `--markdown` twin of each report is a rendering of the same data in a consistent
human-readable form (CDS-CSO-CBF). It is not the monthly human-readable report
`VER-TFR-MHR`. ComplyRoll also does not schedule the retrieval cadence `VER-TFR-MRH` sets for
historical activity (once a month for Class B, every 14 days for Class C, both SHOULD); the
operator runs `report historical` when it is due.

## Verifying the log

`complyroll store verify --db complyroll.db` walks the whole log and exits non-zero on any
fault. It checks the bytes first (every payload digest, sequence and stream-version
contiguity, the AUTOINCREMENT counter, the schema objects) and then audits the domain:
every payload against its published contract, every observation through the replay reader,
every event against its stream kind and against the artifact identity its stream names, every
artifact stream for completeness in both directions (`artifact_incomplete`, `artifact_overfull`) and
for repeated observation identifiers (`artifact_duplicate_observation`), and every metadata
envelope. A healthy store prints one line:

```text
ok: 36 event(s) verified
```

A domain fault names the event it belongs to and what is wrong with it. This is a store
whose artifact event declares two observations that no observation event follows, which is
what an ingest interrupted by an older version leaves behind:

```text
error: sequence 37: artifact_incomplete: artifact stream 'artifact/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/complyroll.cklb/1' is incomplete: declared 2 observations, found 0
faults: 1 domain fault(s) in 37 verified event(s)
```

Verifying a WAL-mode store may leave `-shm` and `-wal` sidecar files beside it; the database
file's own bytes do not change.
