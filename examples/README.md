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
reproducible byte for byte; omitting it uses the current UTC time. With the `--as-of` above,
`report.json` and `report.md` are `tests/golden/vdt-fixtures.json` and
`tests/golden/vdt-fixtures.md`, byte for byte.

## Report period and output files

The report period selects contents: a vulnerability appears when it had activity inside
`--from`/`--to` (detection, evaluation, a PAIN reduction, or a planned reduction), or when it is
still undisposed and was detected on or before the period end. With `--kev`, open KEV work stays
listed (the ADR 0007 amendment of 2026-09-25). A record appears in the detail report with no other
activity in the period when it is not accepted, its KEV clock is matched and not satisfied, it was
detected by the period end, and one of its matched catalog entries was listed on or before the UTC
date of the period end. Every exclusion is reported as an `excluded_by_period` diagnostic and
counted in the document, so "nothing happened" is distinguishable from "nothing was compiled".

Output files are written all-or-nothing: a failed Markdown write leaves no JSON behind, a failure
while publishing restores the previous files, and a rollback that itself fails names the files
left in their new state and where their previous content was kept.

[ADR 0007](../docs/decisions/0007-stateless-vdt-compiler-and-report-mappings.md) records the
period and output rules in its 2026-08-21 amendment.

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

The report this produces is byte-identical to the stateless one: both paths run one record
compiler, and that equality is a test. A store that records detection process failures matches
its stateless twin under the conditions in Detection process failures below (ADR 0014
Decision 15). Re-running any of the first four commands appends nothing. Change one PAIN rating
in a copy of `examples/evaluations.json` and re-run `cases evaluate` with it to see a second
evaluation appear in `complyroll cases history <tracking-id> --db complyroll.db`, while the
report carries the latest one. Nothing can update or delete an event; a correction is a new
event with its rationale.

A store that records coverage gaps adds `cases coverage` and a second `cases correlate` after the
four writing commands, and its report takes `--inventory`; Coverage gaps in a store below walks
through it. The first gap `cases coverage` records moves the store to schema version 4.

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

Each persisted report is byte-identical to its stateless twin, JSON and Markdown alike; with
detection process failures in the store, that holds under the conditions in Detection process
failures below. With the fixed `--as-of`, the AVI and historical outputs are
`tests/golden/avi-fixtures.json`, `tests/golden/avi-fixtures.md`,
`tests/golden/historical-fixtures.json`, and `tests/golden/historical-fixtures.md`.

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

## The predecessor stigroll command

`stigroll` is the predecessor STIG roll-up, rebuilt on the hardened adapters and locked to its
original output byte for byte. Roll up the synthetic fixtures with it from the repository root:

```bash
stigroll tests/fixtures/windows-host.ckl tests/fixtures/ubuntu-host.cklb --format json
```

## Other formats

`report vdt`, `report avi`, `report historical`, and `ingest` take SARIF 2.1.0 logs beside the
checklists: a `.sarif` file, or a name ending `.sarif.json`, from Trivy, Grype, Semgrep, CodeQL,
Checkov, or any conforming producer (ADR 0011). Each result becomes one observation per located
resource, scoped by the image or repository the run declares, and the driver name keeps two
scanners that report the same CVE as separate cases. This run adds the Trivy image scan from the
test fixtures to the three checklists above.

```bash
complyroll report vdt \
  tests/fixtures/ubuntu-host.cklb \
  tests/fixtures/windows-host.ckl \
  tests/fixtures/openscap-results.xml \
  tests/fixtures/trivy-image.sarif \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-31T23:59:59Z \
  --as-of 2026-08-21T12:00:00Z \
  --detected-at 2026-08-01T00:00:00Z \
  --evaluations examples/evaluations.json \
  -o vdt-mixed.json \
  --markdown vdt-mixed.md
```

Trivy and Semgrep logs declare no scan time, so `--detected-at` is required for them exactly as
it is for the checklists; the CodeQL fixture carries invocation clocks and needs no attestation. The
report gains two vulnerabilities, `case-10f5974d95a33fdf` (CVE-2024-0001, two files in the
image) and `case-889c19760e425785` (CVE-2024-0002), the inputs table names the parser, and the
diagnostics record that the five Trivy results folded into three observations:

```text
| trivy-image.sarif | 5ec28341654c | complyroll.sarif 1 | 3 |
```

```text
info: results_collapsed: result folded into an observation that shares its identity (2 occurrences: runs[0].results[1], runs[0].results[4]) [trivy-image.sarif]
warning: source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [trivy-image.sarif]
```

A log whose run carries no results is evidence that the tool ran. `tests/fixtures/clean-run.sarif`
is one ExampleScan run over an image with `results: []` under a successful invocation. It ingests
on both paths and exits 0, with one PASS observation of the image it names (record `sarif.run`,
observed at the invocation's start) and nothing for a report to list; the inputs table counts it
and the diagnostics keep the `run_clean` note:

```text
| clean-run.sarif | ee91754fbc49 | complyroll.sarif 1 | 1 |
```

```text
info: run_clean: run reports no results (1 occurrence: runs[0]) [clean-run.sarif]
```

The observation's description says what it is not: the run found nothing it was configured to
report, which is not evidence that the image is free of vulnerabilities. A run with no results
whose invocation reports `executionSuccessful: false` mints nothing; it is the failed invocation
of the detection process failures section. One whose invocation never declares
`executionSuccessful: true` mints nothing either and is `execution_unverified`; with nothing else
in the log it fails with `no_observations` and `clean_run_unverified`, and the second code is
what names the cause in a recorded failure (ADR 0015 decision 1 and its PR 2 section).

## Known exploited vulnerabilities

`VDR-TFR-KEV` says a provider should remediate a Known Exploited Vulnerability by the due date
in CISA's catalog, "even if the vulnerability has been fully mitigated". Supply that catalog
with `--kev` and each report gains the clock (ADR 0012).

Download the feed yourself. ComplyRoll never fetches it, ships no copy of it, and records
nothing about it in the event store: it is a per-run input, read from a local file, on the
stateless path and the `--db` path alike. Take the JSON feed from CISA's Known Exploited
Vulnerabilities Catalog page, save it, and pass the path. The report pins whichever bytes it
read by their SHA-256, so a report can always be checked against the catalog it was compiled
from.

The commands below use the synthetic catalog and SARIF logs from the test fixtures, so they run
from a source checkout with no download. Every identifier in them is `CVE-2099-*`; none of it is
CISA data.

```bash
complyroll report vdt \
  tests/fixtures/kev-image-web.sarif \
  tests/fixtures/kev-image-worker.sarif \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --as-of 2026-09-15T12:00:00Z \
  --calendar-tz UTC \
  --evaluations examples/evaluations-kev.json \
  --kev tests/fixtures/kev-catalog.json \
  -o vdt-kev.json \
  --markdown vdt-kev.md

complyroll report avi \
  tests/fixtures/kev-image-web.sarif \
  tests/fixtures/kev-image-worker.sarif \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --as-of 2026-09-15T12:00:00Z \
  --calendar-tz UTC \
  --evaluations examples/evaluations-kev.json \
  --kev tests/fixtures/kev-catalog.json \
  -o avi-kev.json \
  --markdown avi-kev.md

complyroll report historical \
  tests/fixtures/kev-image-web.sarif \
  tests/fixtures/kev-image-worker.sarif \
  --class C \
  --package-uri https://example.test/cpo \
  --as-of 2026-09-15T12:00:00Z \
  --calendar-tz UTC \
  --evaluations examples/evaluations-kev.json \
  --kev tests/fixtures/kev-catalog.json \
  -o historical-kev.json \
  --markdown historical-kev.md
```

These are the six files under `tests/golden/` whose names end `-kev`, byte for byte. The SARIF
fixtures declare an invocation clock, so no `--detected-at` is needed, and the same three
commands compile from a store by replacing the two logs and `--evaluations` with
`--db complyroll.db`: `--kev` sits beside `--db` rather than conflicting with it, because no
store holds a catalog.

Each report names the catalog in its Provenance table and counts the clock in its Summary:

```text
| KEV catalog | kev-catalog.json, CISA KEV catalog version 2026.09.14, released 2026-09-14T17:00:00.123400Z, 11 entries | 40c6d1465ca52c5ddb3b7bf1a6d92cfe884e33b4d2e90ac4551090e66d6c49fd |
```

```text
| Known exploited, CISA KEV | 8 |
| Past a CISA KEV due date | 5 |
```

and each record carries a line naming every matched entry, which entry the clock follows, and
where that clock stands:

```text
- **Known exploited:** CVE-2099-0004 (added 2026-08-20, due 2026-09-03, ransomware use Unknown, forensic triage No); the clock follows CVE-2099-0004, due date 2026-09-03 ended 2026-09-04T00:00:00Z; past due
```

That record is fully mitigated, and it is overdue anyway, which is what the rule's parenthetical
asks for. A remediated or false-positive record stops the clock; acceptance does not. An
accepted record is never officially overdue, so the AVI report shows "Overdue 0" beside "Past a
CISA KEV due date 1" and publishes the missed date on the record.

The run also reports what the catalog could not answer for. One fixture entry is dated after
`--as-of`, so it was not applied:

```text
info: kev_entries_after_as_of: 1 catalog entry dated after 2026-09-15 was not applied; 1 compiled record carries it [sha256:40c6d1465ca52c5ddb3b7bf1a6d92cfe884e33b4d2e90ac4551090e66d6c49fd]
```

A catalog released after `--as-of` stops the run instead of being applied, because entries change
after publication and a later catalog cannot show which due dates were in force then. To
regenerate an old report, use the catalog that was current at its `--as-of`; the old report's
`kevSource` digest says which one that was. A catalog more than three days old is a warning, not
a refusal, and a run given no catalog produces exactly the bytes it produced before, with no
`kev` key anywhere.

## Coverage against an inventory

`VDR-TFR-MVX`, `VDR-TFR-NMV`, `VDR-TFR-PDD`, `VDR-TFR-PCD`, and `VDR-TFR-PSD` ask a provider to
reach each information resource with detection on a cadence. ComplyRoll cannot know which
resources a provider has, so the provider lists them in an inventory and passes it with
`--inventory`. Like a KEV catalog, the inventory is a per-run input, read from a local file and
never written to the store, and the report names it by its SHA-256 (ADR 0015).

`examples/inventory.json` declares a synthetic boundary named `example-boundary` with seven
entries. Compile the first report on this page with it:

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
  --inventory examples/inventory.json \
  -o vdt-coverage.json \
  --markdown vdt-coverage.md
```

These are `tests/golden/vdt-coverage.json` and `tests/golden/vdt-coverage.md`, byte for byte.
Their official fields equal those of `vdt-fixtures.json`: the inventory adds the
`x-complyroll.coverage` block and a Markdown `## Coverage` section and changes nothing else.
Standard error carries the three `source_timestamp_missing` warnings and one
`drift_likelihood_unknown` warning. The same report compiles from a store: run the sequence
under Persisted path and add `--inventory examples/inventory.json` to its `report vdt --db`
command. The inventory sits beside `--db` because no store holds one.

The Coverage section opens with a count per rule:

```text
| Rule | Force | Expected | Current | Stale | Missing | Unanchored | Undetermined |
|---|---|---:|---:|---:|---:|---:|---:|
| VDR-TFR-MVX | MUST | 4 | 0 | 0 | 3 | 1 | 0 |
| VDR-TFR-NMV | MUST | 3 | 1 | 1 | 1 | 0 | 0 |
| VDR-TFR-PCD | SHOULD | 1 | 0 | 0 | 1 | 0 | 0 |
| VDR-TFR-PDD | SHOULD | 3 | 0 | 0 | 2 | 1 | 0 |
| VDR-TFR-PSD | SHOULD | 1 | 0 | 1 | 0 | 0 | 0 |
```

Each entry is placed to show one reading:

- `host:ubuntu-web-01` is the host `ubuntu-host.cklb` calls `lab-ubuntu-01`, so the entry lists
  that name as an alias, and the checklist's six observations reach it only through the alias.
  The checklist declares no assessment time, so its observations are untimed: they never examine
  the host or anchor a clock, and its `VDR-TFR-MVX` and `VDR-TFR-PDD` clocks read
  `missing (6 untimed)`. The count beside the status keeps a checklist-only host from reading as
  unexamined.
- `host:lab-win-01` declares `driftLikely` false, so it carries `VDR-TFR-PCD` instead of
  `VDR-TFR-PDD`. Its two observations from `windows-host.ckl` are untimed too, so both clocks
  read `missing (2 untimed)`.
- `host:lab-rhel-01` declares `driftLikely` `"unknown"`, which takes `VDR-TFR-PDD` and raises the
  warning, and was decommissioned on 2026-08-10. Nothing ever examined it, so both clocks are
  `missing`, and the windows that closed before it was decommissioned are listed.
- `host:lab-ubuntu-03` is expected from 2026-09-01, after `--as-of`, so its clocks are
  `unanchored`, with no due date and no window.
- `logical:incident-response-procedure` is not machine-based, so only its attested
  `verifications` can verify it. The tabletop of 2026-08-03 makes `VDR-TFR-NMV` `current`, due
  three calendar months later at 2026-11-03T17:00:00Z. Its second tabletop, on 2026-09-02, is
  after `--as-of`, so it is listed under Evidence after as-of and never used.
- `logical:contingency-plan` has no verification, so its `VDR-TFR-NMV` clock is `missing`.
- Those two share the sample group `ir-runbooks`, so one `VDR-TFR-PSD` clock,
  `logical:sample-group/ir-runbooks`, covers both. The procedure's 2026-08-03 tabletop stands in
  for the group, the group's window fell due three days later, and nothing has verified a member
  since, so the clock is `stale` on both member rows. The group shows two windows: the declared
  one from 2026-07-01, which closed on 2026-07-04 and resumed at the tabletop, and the one that
  closed on 2026-08-06 and has not resumed.
- `logical:backup-restore-procedure` was last attested on 2026-04-15, so its `VDR-TFR-NMV`
  window closed at 2026-07-15T16:00:00Z and the clock is `stale`.
- `host:lab-ubuntu-02`, which `openscap-results.xml` scanned, is left out of the inventory on
  purpose, so its three observations are listed as unregistered rather than dropped.

A `current` status is not a compliance finding, and the report says so in fixed text above the
tables. On this run a lapsed window is evidence, not a vulnerability case; with
`--record-coverage-gaps` it becomes one, as Coverage gaps as cases below shows.

The official fixture set can only show what untimed evidence reaches. Every observation in those
three files is untimed, so no machine clock can anchor on them, and no machine entry above can be
`current`, `stale`, or `undetermined`. A second pair under `tests/golden/`,
`vdt-coverage-timed.json` and `.md`, covers those statuses with two SARIF logs that declare their
own clocks and the test fixture `tests/fixtures/inventory-timed.json`:

```bash
complyroll report vdt \
  tests/fixtures/codeql-repo.sarif \
  tests/fixtures/clean-run.sarif \
  --class C \
  --package-uri https://example.test/cpo \
  --calendar-tz UTC \
  --as-of 2026-09-03T12:00:00Z \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --inventory tests/fixtures/inventory-timed.json \
  -o vdt-coverage-timed.json \
  --markdown vdt-coverage-timed.md
```

There `helpers.js` is `current`, verified by an open CodeQL result. The clean-run image is
`stale`: its PASS observation of 2026-08-05 verified it, and nothing has since. `legacy.js`,
examined only by a result whose disposition is unknown, is `undetermined`. `index.js` was never
scanned, yet its sample group's `VDR-TFR-PSD` clock is `current`, because `render.js` stands in,
reached through an alias that matches the repository URL the scanner reports.

### Coverage gaps as cases

`VDR-CSO-FAV` says a failure of the detection process is a vulnerability, and a window that closed
with no verification is one. With `--record-coverage-gaps`, each window in the block becomes a
system observation of its own and a vulnerability case (ADR 0015): windows of one rule whose entries
name the same `job` share a case, the windows of one sample group share a case, and every other
window is a case of its own. The flag needs `--inventory`. Add it to the first command in this
section:

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
  --inventory examples/inventory.json \
  --record-coverage-gaps \
  -o vdt-coverage-gaps.json \
  --markdown vdt-coverage-gaps.md
```

It writes `tests/golden/vdt-coverage-gaps.json` and `tests/golden/vdt-coverage-gaps.md`, byte for
byte, and exits 3, so a pipeline that stops on a non-zero exit still stops. Standard error carries
the same four warnings as the run without the flag. Run as `report historical`, without `--from`
and `--to` and with `examples/evaluations-accepted.json`, the same inputs give
`tests/golden/historical-coverage-gaps.json` and `.md`, also with exit 3, and `report avi` exits 3
too.

The nine windows become nine gap observations and seven cases:

| Rule | Context | Closed at | Tracking ID |
|---|---|---|---|
| VDR-TFR-MVX | host:lab-rhel-01 | 2026-07-04T00:00:00Z | case-56e1eee78e97395f |
| VDR-TFR-MVX | host:lab-win-01 | 2026-07-04T00:00:00Z | case-656d627b62275ba8 |
| VDR-TFR-MVX | host:ubuntu-web-01 | 2026-07-04T00:00:00Z | case-656d627b62275ba8 |
| VDR-TFR-NMV | logical:backup-restore-procedure | 2026-07-15T16:00:00Z | case-fe51d8e4d9c79b36 |
| VDR-TFR-PCD | host:lab-win-01 | 2026-08-01T00:00:00Z | case-9c9bf88832065e17 |
| VDR-TFR-PDD | host:lab-rhel-01 | 2026-07-15T00:00:00Z | case-23ec0644fabe50d3 |
| VDR-TFR-PDD | host:ubuntu-web-01 | 2026-07-15T00:00:00Z | case-987c96e87614506a |
| VDR-TFR-PSD | logical:sample-group/ir-runbooks | 2026-07-04T00:00:00Z | case-a971b430300440cf |
| VDR-TFR-PSD | logical:sample-group/ir-runbooks | 2026-08-06T17:00:00Z | case-a971b430300440cf |

A case is one rule and one detection job, or one rule and one resource when the entry names no
job. `host:lab-win-01` and `host:ubuntu-web-01` both name the job `weekly-stig-checklist`, so their
`VDR-TFR-MVX` windows share one case, and the two windows of the sample group share another.
`host:lab-rhel-01` names no job, so each of its windows is a case of its own. A shared case takes
one member's title, `coverage-gap: VDR-TFR-MVX window for host:lab-win-01 closed
2026-07-04T00:00:00Z with no verification recorded (VDR-CSO-FAV)`, and lists both hosts under its
resources.

Each gap is detected when its window closed, with `detectedAtSource` `system`, so `--detected-at`
never applies to it, and its evaluation window (`VER-TFR-EVU`) runs from that close. Every gap
case above is overdue for evaluation at the as-of. The record says that ComplyRoll found no
verification inside the window. It does not say that the resource has a vulnerability, and it
carries no PAIN until an operator evaluates it. In the coverage block every window gains
`recorded` and `trackingId`, and the Markdown Windows table gains Recorded and Tracking ID columns
under one fixed sentence ([`docs/CLI.md`](../docs/CLI.md), Coverage gaps as cases).

A later verification never erases a gap; it only resumes the window. A case closes by an
evaluation's disposition. `examples/evaluations-coverage.json` is `evaluations.json` plus one entry
for lab-rhel-01's `VDR-TFR-MVX` case: the host was retired on 2026-08-10 before any detection job
reached it, so the entry's disposition is `remediated`. It matches on all three keys:

```json
{"sourceRecordId": "coverage-gap", "sourceType": "complyroll.coverage", "contextKey": "VDR-TFR-MVX:resource:host:lab-rhel-01"}
```

No report prints the context key. It is the rule, then `job:` and the entry's job when the entry
names one, else `resource:` and the clock's pair. lab-win-01's shared case is
`VDR-TFR-MVX:job:weekly-stig-checklist`, and the sample group's is
`VDR-TFR-PSD:resource:logical:sample-group/ir-runbooks`. Every gap shares the record id and the
source type, so the same entry without `contextKey` names all seven cases, and the run stops with
exit 1 and writes nothing:

```text
error: evaluation_ambiguous: sourceRecordId='coverage-gap', sourceType='complyroll.coverage' matches 7 vulnerabilities (case-656d627b62275ba8, case-56e1eee78e97395f, case-fe51d8e4d9c79b36, case-9c9bf88832065e17, case-987c96e87614506a, case-23ec0644fabe50d3, case-a971b430300440cf); add contextKey [evaluations[2]]
```

Run the command above with `--evaluations examples/evaluations-coverage.json` in place of
`examples/evaluations.json`. It still exits 3, and the case now reads:

```text
| case-56e1eee78e97395f | coverage-gap | 1 | 2026-07-04T00:00:00Z | 2026-08-12T15:00:00Z | no | no | N2 | n/a | no | Remediated |
```

Every other record and the whole coverage block equal the golden's, and the window still reads
`recorded: true` with that tracking id: the disposition closed the case, and the missed window
stays on the record. The evaluation completed after the window closed. One completed before
2026-07-04T00:00:00Z would stop the run with `evaluation_before_detection`, whose remedy reads "a
coverage gap is detected when its window closed, so evaluate it at or after that instant, or
correct completedAt". Any disposition applies to a gap as it does to a failure, and `accepted`
lists the gap in the accepted-vulnerability report as an accepted risk.

### Coverage gaps in a store

On the persisted path `cases coverage` records the gaps, and the report takes `--inventory` beside
`--db`. Run the first four commands under Persisted path with `--db coverage.db`, then these:

```bash
complyroll cases coverage \
  --db coverage.db \
  --inventory examples/inventory.json \
  --class C \
  --as-of 2026-08-21T12:00:00Z

complyroll cases correlate --db coverage.db

complyroll report vdt \
  --db coverage.db \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-31T23:59:59Z \
  --as-of 2026-08-21T12:00:00Z \
  --inventory examples/inventory.json \
  -o vdt-coverage-gaps.json \
  --markdown vdt-coverage-gaps.md
```

`cases coverage` derives the windows from the store's evidence exactly as the report does and
records one stream per window. It writes the `drift_likelihood_unknown` warning to standard error,
prints one line per gap, nine in all, and exits 3:

```text
obs-93163dadcffc2fa5e3efd858b439b2be6c792975a029a95596b26b92be6fd56c: recorded VDR-TFR-MVX window for host:lab-rhel-01 closed 2026-07-04T00:00:00Z
obs-59fbb69836e1874231e0ce7eed88c5669b626cb453ace189f6345424340c93a1: recorded VDR-TFR-MVX window for host:lab-win-01 closed 2026-07-04T00:00:00Z
recorded 9 coverage gap(s), skipped 0 already-recorded coverage gap(s)
```

Run again with the same inputs it appends nothing, prints `already_recorded` on each line, and
exits 0. A recorded gap is evidence, as an ingested observation is, so `cases correlate` opens its
case and prints `created 7 case(s), linked 9 observation(s), skipped 6 already-linked
observation(s)`. An evaluation of a gap before that is refused with `evaluation_unmatched`, "no
case matches". The report is the stateless golden pair again, byte for byte. `cases evaluate --db
coverage.db --evaluations examples/evaluations-coverage.json` then closes lab-rhel-01's case:

```text
evaluations: 1 appended, 2 skipped
pain reductions: 0 appended, 1 skipped
dispositions: 1 appended, 1 skipped
identifications: 0 appended, 0 skipped
```

and the report from the store equals the stateless run with that file. The first gap moves the
store to schema version 4, recorded as migration 4, "coverage gaps, ADR 0015", beside records 2 and
3. `complyroll store verify --db coverage.db` prints `ok: 72 event(s) verified`. An earlier build
refuses the store with `database schema 4 is newer than supported schema 3`.

A store records a gap once, so a report from it can disagree with the windows its own run
derives. Each disagreement is an INFO note, and a recorded gap keeps its case whatever the note
says. Record the gaps of a fresh store at `--as-of 2026-08-05T00:00:00Z`, before the sample
group's second window closes, and report at the golden as-of. The store holds eight gaps, and the
report names the ninth window and leaves it without a case:

```text
info: coverage_gap_unrecorded: the VDR-TFR-PSD window for logical:sample-group/ir-runbooks closed 2026-08-06T17:00:00Z with no verification, and history records no gap for it, so no case in this report carries it; cases coverage with this run's inventory, as-of, class and calendar zone records it [example-boundary logical:sample-group/ir-runbooks]
```

Running `cases coverage` again at the golden as-of records it, `cases correlate` links it to the
group's case, and the report is the golden pair again. Two notes name a recorded gap the run does
not derive. `coverage_gap_contradicted` means the run's evidence holds a verification inside the
gap's window, as a late upload leaves. The note names the earliest one, and a false-positive
disposition is the remedy only when the note advises it: a case can carry other gaps that still
stand, and the note names each of those. `coverage_gap_unmatched` means nothing disproves the gap,
so the report's inventory, as-of, class, or calendar zone may differ from the run that recorded
it. Reporting this store with `--class B` prints one for each Class C gap whose window Class B
does not derive, beside a `coverage_gap_unrecorded` note for each Class B window. No disposition
answers it; report with the inputs `cases coverage` used.

## InSpec and HDF

InSpec writes its results as HDF with `inspec exec --reporter json`, and the MITRE SAF CLI's
`saf convert` writes the same shape from other tools' output. ComplyRoll reads both (ADR 0013).
A file whose name ends `.hdf.json` is HDF. A bare `.json` file is HDF when its parsed root has a
`profiles` array, a `platform` object, and no `stigs` key; anything else stays a CKLB checklist.
A failed control is a vulnerability. A waiver or an attestation is kept as metadata and never
changes a disposition: the results decide it, except that impact 0 reads not applicable first.

The three fixtures are synthetic: a native InSpec run against a Linux host, a Trivy image scan
converted by `saf convert`, and an overlay profile run over the baseline it wraps.

```bash
complyroll report vdt \
  tests/fixtures/inspec-linux-host.hdf.json \
  tests/fixtures/saf-trivy-image.hdf.json \
  tests/fixtures/inspec-overlay.json \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --as-of 2026-09-15T12:00:00Z \
  --detected-at 2026-09-01T00:00:00Z \
  -o vdt-hdf.json \
  --markdown vdt-hdf.md
```

These are `tests/golden/vdt-hdf.json` and `tests/golden/vdt-hdf.md`, byte for byte. The native
runs stamp a `start_time` on every result, and those clocks are the detection times. The
converted Trivy document carries no scan time at all, so `--detected-at` supplies one for its
three records and the report says so under "Detection time attestation". Five records are
reported, and four of them are overdue at the `--as-of` instant.

The persisted path needs one more step than the KEV section's `--db` swap. Run these four
commands in order from the repository root:

```bash
complyroll ingest \
  tests/fixtures/inspec-linux-host.hdf.json \
  tests/fixtures/saf-trivy-image.hdf.json \
  tests/fixtures/inspec-overlay.json \
  --db hdf.db \
  --as-of 2026-09-15T12:00:00Z

complyroll cases correlate --db hdf.db

complyroll cases attest-detection \
  --db hdf.db \
  --all-missing \
  --detected-at 2026-09-01T00:00:00Z \
  --rationale "The Trivy conversion declares no scan timestamp; the image was scanned on 1 September."

complyroll report vdt \
  --db hdf.db \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-09-01T00:00:00Z \
  --to 2026-09-30T23:59:59Z \
  --as-of 2026-09-15T12:00:00Z \
  -o vdt-hdf.json \
  --markdown vdt-hdf.md
```

The three commands before the report print this on standard output:

```text
inspec-linux-host.hdf.json: recorded 6 observation(s)
saf-trivy-image.hdf.json: recorded 3 observation(s)
inspec-overlay.json: recorded 3 observation(s)

created 5 case(s), linked 5 observation(s), skipped 0 already-linked observation(s)

selected 3 case(s) with no source timestamp on any observation
attested 3 case(s), skipped 0 unchanged case(s), 0 not applicable case(s)
```

and the report is the same two golden files. The attestation step is not optional here. A
store records attested detection times as events, so `report vdt` refuses `--detected-at` beside
`--db` (`src/complyroll/cli.py:869`), and without the attestation the report exits 1, writes no
file, and names the three converted records:

```text
error: detection_time_missing: no source timestamp and no --detected-at attestation for: case-057bbe4ee9dde990, case-1706b7990cce1346, case-71446ac59461edb8
```

After the four commands, `complyroll store verify --db hdf.db` prints
`ok: 28 event(s) verified`.

Each input is read by the HDF parser, including the overlay, whose name has no `.hdf`:

```text
| inspec-linux-host.hdf.json | 36e929218a49 | complyroll.hdf 1 | 6 |
| inspec-overlay.json | a965c0f73307 | complyroll.hdf 1 | 3 |
| saf-trivy-image.hdf.json | 6b36d5a302d0 | complyroll.hdf 1 | 3 |
```

The report also carries these diagnostics, which the stateless run prints on standard error:

```text
warning: control_attested: control carries attestation data; the attestation is recorded as metadata and never changes the disposition (1 occurrence: profiles[1].controls[1]) [inspec-overlay.json]
warning: control_waived: control carries waiver data; the waiver is recorded as metadata and never changes the disposition (1 occurrence: profiles[0].controls[5]) [inspec-linux-host.hdf.json]
info: converted_document: platform.name is Heimdall Tools; the source tool is heimdall-tools and the resource is the converter's target (1 occurrence: platform) [saf-trivy-image.hdf.json]
info: impact_zero_not_applicable: impact is 0, so the control is not applicable whatever its results say (1 occurrence: profiles[0].controls[3]; first: results would read OPEN) [inspec-linux-host.hdf.json]
info: profile_control_shadowed: control has no results and the same id carries results in another profile of this run; it yields no observation (2 occurrences: profiles[0].controls[0], profiles[0].controls[1]) [inspec-overlay.json]
warning: source_timestamp_missing: source artifact does not declare an observation timestamp; observed_at is unknown [saf-trivy-image.hdf.json]
warning: unresolved_observation: SYN-LNX-0005 on 3f0c9a2e-6d4b-4c1e-9a7b-2f1e8d5c4b3a has disposition error and was not reported as a vulnerability [inspec-linux-host.hdf.json]
```

Each line is a decision the report did not hide. SYN-LNX-0004 failed, but its impact is 0, so it
is not applicable and is not reported. SYN-LNX-0006 carries a waiver, and its skipped result
decides it, so it reads not reviewed. SYN-LNX-0005 passed with a backtrace, which InSpec writes
when a check raised, so it reads as an error and is named rather than reported. In the overlay,
the wrapper's copies of SYN-RHL-0001 and SYN-RHL-0002 have no results, so the baseline's copies
decide both. SYN-RHL-0002 carries the passed result `saf attest apply` appended, so it reads PASS
and is not reported. The attester's name appears nowhere in the report.

## Detection process failures

`VDR-CSO-FAV` says a provider must treat problems or failures in its vulnerability detection and
response processes as vulnerabilities. By default a scanner output ComplyRoll cannot read stops
the run: the command prints its errors, exits 1, and writes nothing. With
`--record-failed-imports`, an artifact that fails to parse or holds no usable content becomes a
system observation and a vulnerability of its own instead, and so does a failed scanner
invocation that a SARIF log reports; the command writes its output and exits 3 (ADR 0014). The
flag is taken by `report vdt`, `report avi`, `report historical`, and `ingest`. A file that could
not be read, an unsupported or rejected format, a duplicate observation identity, a reading that
found some usable results beside its errors, whether it kept them (a checklist) or withheld them
all (SARIF and HDF fail closed), and an error code ComplyRoll has not classified still stop the
run with the flag.

Three synthetic fixtures cover the three failure classes:

- `failed-truncated.sarif` is a SARIF log cut off inside a string. It cannot be parsed, so it
  is class `parse`.
- `failed-invalid-rules.cklb` is a CKLB whose STIG writes `rules` as an object instead of an
  array. It parses but holds nothing usable, so it is class `content`.
- `failed-invocation.sarif` has two runs. The first reports one finding; the second reports
  `executionSuccessful: false` and no results. The log still imports, and the failed invocation
  adds a system observation of class `execution` beside the finding, observed at the
  invocation's own `startTimeUtc`.

`examples/evaluations-failed.json` is `evaluations.json` plus one entry that evaluates the parse
failure. A failure is evaluated like any other vulnerability and gets PAIN only from an
evaluation. Its entry matches on the source type, the record id, and the failed artifact's digest
as the context key:

```json
{"sourceRecordId": "detection-process-failure", "sourceType": "complyroll.detection-process", "contextKey": "sha256:a8aca932d8fc140bdc97cb5a8006bd860754666b94297ef63a152cd2419c90c8"}
```

All three parts are needed. Every system record shares the record id and the source type, so
the same entry without `contextKey` names all three failures, and the run stops with exit 1 and
writes nothing:

```text
error: evaluation_ambiguous: sourceRecordId='detection-process-failure', sourceType='complyroll.detection-process' matches 3 vulnerabilities (case-f03af85468885cad, case-d3bb8e4fb3b61a5f, case-088261de64a0133c); add contextKey [evaluations[2]]
```

A run holding a single failure refuses that entry too, with `evaluation_context_key_required`, so
an evaluation file that applies today still applies when a failure of another digest is recorded
beside it. `cases evaluate` refuses it with the same message, printed under
`evaluation_unmatched`.

Run this from the repository root. It exits 3, so a pipeline that treats any non-zero exit as a
failure still stops:

```bash
complyroll report vdt \
  tests/fixtures/ubuntu-host.cklb \
  tests/fixtures/windows-host.ckl \
  tests/fixtures/openscap-results.xml \
  tests/fixtures/failed-truncated.sarif \
  tests/fixtures/failed-invalid-rules.cklb \
  tests/fixtures/failed-invocation.sarif \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-31T23:59:59Z \
  --as-of 2026-08-21T12:00:00Z \
  --detected-at 2026-08-01T00:00:00Z \
  --evaluations examples/evaluations-failed.json \
  --record-failed-imports \
  -o vdt-failed.json \
  --markdown vdt-failed.md
```

The two files it writes are `tests/golden/vdt-failed.json` and `tests/golden/vdt-failed.md`,
byte for byte. Run as `report historical`, without `--from` and `--to`, the same inputs give
`tests/golden/historical-failed.json` and `tests/golden/historical-failed.md`, also with exit 3,
and `report avi` exits 3 too. Without the flag the `report vdt` command exits 1, writes no file,
and prints the three errors that stopped it:

```text
error: artifact_parse_failed: Unterminated string starting at: line 18 column 21 (char 419) [failed-truncated.sarif]
error: invalid_rules: STIG entry has no rules array [stigs[0].rules]
error: no_observations: CKLB contains no usable rules [failed-invalid-rules.cklb]
```

With the flag the same three print as warnings, and a `detection_failure_recorded` warning names
each recorded failure by class and digest. These are the first seven lines of standard error;
the rest are a `run_clean` note for the failed run's empty results and the fixtures' missing
timestamps:

```text
warning: artifact_parse_failed: Unterminated string starting at: line 18 column 21 (char 419) [failed-truncated.sarif]
warning: detection_failure_recorded: recorded a detection process failure of class content for source artifact sha256:f51e7b7624956be0f40545639b3ee63ab7b5a27cb647ad2a3435df6bc6dcc372 (VDR-CSO-FAV) [failed-invalid-rules.cklb]
warning: detection_failure_recorded: recorded a detection process failure of class execution for source artifact sha256:59e5a0bee03780b92cd21e2da90d4c8ead7eb94a70f3d904fa141a55620691e9 (VDR-CSO-FAV) [failed-invocation.sarif]
warning: detection_failure_recorded: recorded a detection process failure of class parse for source artifact sha256:a8aca932d8fc140bdc97cb5a8006bd860754666b94297ef63a152cd2419c90c8 (VDR-CSO-FAV) [failed-truncated.sarif]
warning: execution_unsuccessful: invocation reports executionSuccessful false; its results are still read (1 occurrence: runs[1].invocations[0]) [failed-invocation.sarif]
warning: invalid_rules: STIG entry has no rules array [stigs[0].rules]
warning: no_observations: CKLB contains no usable rules [failed-invalid-rules.cklb]
```

A diagnostic keeps the location its adapter gave it, so `invalid_rules` still points at
`stigs[0].rules` inside the checklist, in the report's diagnostics as on standard error. Only a
diagnostic with no location of its own takes the artifact's name.

The Markdown report adds a table of the failures under Inputs. Two of them are not in the Inputs
table above it: `failed-truncated.sarif` could not be parsed, and `failed-invalid-rules.cklb`
parsed but held no usable rules. `failed-invocation.sarif` is in both, because its first run's
finding was read:

```text
| Artifact | SHA-256 | Parser | Class | Observed at | Clock | Tracking ID |
|---|---|---|---|---|---|---|
| failed-invalid-rules.cklb | f51e7b762495 | complyroll.cklb 1 | content | 2026-08-21T12:00:00Z | as-of | case-088261de64a0133c |
| failed-invocation.sarif | 59e5a0bee037 | complyroll.sarif 1 | execution | 2026-08-04T10:00:00Z | invocation | case-f03af85468885cad |
| failed-truncated.sarif | a8aca932d8fc | complyroll.sarif 1 | parse | 2026-08-21T12:00:00Z | as-of | case-d3bb8e4fb3b61a5f |
```

Each failure is one vulnerability per failed artifact digest. Its detection time has the source
`system`, and its evaluation window (VER-TFR-EVU) opens at that time. The execution failure was
detected at its invocation's clock, 2026-08-04T10:00:00Z, so its window closed 2026-08-09T10:00:00Z
and it is overdue. The other two have no scanner clock, so they were detected at `--as-of`. The
content failure's window closes 2026-08-26T12:00:00Z. The parse failure was evaluated at PAIN N3, so
its response target (VDR-TFR-PVR) is 2026-12-27T12:00:00Z. `--detected-at` never applies to a system
record: the attestation covers the same six cases as in the first example.

On the stateless path a failure detected at `--as-of` is detected again at each run's `--as-of`,
so an evaluation file reused for a later run carries a `completedAt` before that run's detection.
The compiler refuses that record with `evaluation_before_detection` (ADR 0007 amendment
2026-10-14). Report such a run with an `--as-of` no later than the evaluation's `completedAt`, or
from history when `ingest` recorded the failure at an `--as-of` no later than `completedAt`. A
store that recorded it later refuses the record too; the evaluation must then complete at or
after the ingest `--as-of`.

The persisted path takes the flag on `ingest` only. Run these commands in order from the
repository root:

```bash
complyroll ingest \
  tests/fixtures/ubuntu-host.cklb \
  tests/fixtures/windows-host.ckl \
  tests/fixtures/openscap-results.xml \
  tests/fixtures/failed-truncated.sarif \
  tests/fixtures/failed-invalid-rules.cklb \
  tests/fixtures/failed-invocation.sarif \
  --record-failed-imports \
  --db failed.db \
  --as-of 2026-08-21T12:00:00Z

complyroll cases correlate --db failed.db

complyroll cases attest-detection \
  --db failed.db \
  --all-missing \
  --detected-at 2026-08-01T00:00:00Z \
  --rationale "The fixtures declare no assessment timestamp; the assessment ran on 1 August."

complyroll cases evaluate --db failed.db --evaluations examples/evaluations-failed.json

complyroll cases list --db failed.db

complyroll report vdt \
  --db failed.db \
  --class C \
  --package-uri https://example.test/cpo \
  --from 2026-08-01T00:00:00Z \
  --to 2026-08-31T23:59:59Z \
  --as-of 2026-08-21T12:00:00Z \
  -o vdt-failed.json \
  --markdown vdt-failed.md
```

`ingest` exits 3 after it has written the store, and the other five exit 0. The five commands
before the report print this on standard output:

```text
ubuntu-host.cklb: recorded 6 observation(s)
windows-host.ckl: recorded 2 observation(s)
openscap-results.xml: recorded 3 observation(s)
failed-invocation.sarif: recorded 1 observation(s)
failed-invocation.sarif: recorded detection failure (execution)
failed-invalid-rules.cklb: recorded detection failure (content)
failed-truncated.sarif: recorded detection failure (parse)

created 10 case(s), linked 10 observation(s), skipped 0 already-linked observation(s)

selected 6 case(s) with no source timestamp on any observation
attested 6 case(s), skipped 0 unchanged case(s), 0 not applicable case(s)

evaluations: 3 appended, 0 skipped
pain reductions: 1 appended, 0 skipped
dispositions: 1 appended, 0 skipped
identifications: 0 appended, 0 skipped

TRACKING ID            PROVIDER ID  SOURCE RECORD              RESOURCES  EVALUATIONS  PAIN  DISPOSITION
case-04efea8c137ae82f  -            banner_etc_issue                   1            0  -     active
case-088261de64a0133c  -            detection-process-failure          1            0  -     active
case-1f3e011db93cc89e  -            V-260470                           1            1  3     partially_mitigated
case-490f49bfdd1bd019  -            V-253260                           1            1  4     active
case-621d85d6533ce6e5  -            V-260474                           1            0  -     active
case-6719b316a5ea510b  -            no_cci_mapping                     1            0  -     active
case-77fba1630a50ca9f  -            EXS-0001                           1            0  -     active
case-9bed0d8f88355393  -            V-260469                           1            0  -     active
case-d3bb8e4fb3b61a5f  -            detection-process-failure          1            1  3     active
case-f03af85468885cad  -            detection-process-failure          1            0  -     active
```

The sweep selects the same 6 cases as the persisted path above. A system observation always
carries its own instant, so the sweep never selects a failure, and `EXS-0001` carries its
invocation's clock. The report is the same two golden files, and `report historical --db
failed.db` with the same class, package, and `--as-of` writes the two historical ones.
Re-running the `ingest` command appends nothing, prints `already_recorded` for each line on
standard output, and exits 3 again, so a pipeline that reruns it still sees the failures. Its
standard error repeats the first run's word for word, each `detection_failure_recorded` warning
included: the failures are already in the store, and the rerun reports their diagnostics again
without recording anything. `report --db` keeps exit codes 0 and 1, because `ingest` already
signalled the failures, and refuses the flag:

```text
error: invalid_option: report vdt takes either --db or --record-failed-imports, never both
```

The two paths produce the same bytes here because `ingest` ran at the report's `--as-of`. A
system observation without a scanner clock takes its instant from `ingest` on the persisted path
and from the report run on the stateless one. Given the same inputs, the reports match when each
such failure was ingested at the report's `--as-of`, no stream of a failed artifact's digest is
superseded, no two input names share a digest, and no `ingest` reported
`failure_held_by_another_stream` (ADR 0014 Decision 15).

The first failure `ingest` records moves the store to schema version 2, and
`complyroll store verify --db failed.db` prints `ok: 53 event(s) verified`. A store that never
records a failure stays at version 1, even when `ingest` ran with the flag. An earlier ComplyRoll
build cannot open a version 2 store: its `ingest`, `cases`, and `report --db` commands stop with

```text
error: store_unavailable: database schema 2 is newer than supported schema 1
```

and its `store verify` reports the failure streams as domain faults and exits 1.

A store that records a hold, a failure that another failure stream of its digest already holds,
moves on to schema version 3. An earlier build refuses it the same way, naming schema 3 as newer
than the schema it supports. A store that records a coverage gap moves to schema version 4, as
Coverage gaps in a store describes.

The clean log described under Other formats is not a detection failure: it imports as a PASS
observation with or without the flag, and records no failure. A SARIF log that yields nothing and
has a run with no `results` array, or a null one, is not a clean run: that run's results are
unknown (`results_unknown`), so with the flag the log is a `content` failure.

## Verifying the log

`complyroll store verify --db complyroll.db` walks the whole log and exits non-zero on any
fault. It checks the bytes first (every payload digest, sequence and stream-version
contiguity, the AUTOINCREMENT counter, the schema objects) and then audits the domain:
every payload against its published contract, every observation through the replay reader,
every event against its stream kind and against the artifact identity its stream names, every
artifact stream for completeness in both directions (`artifact_incomplete`, `artifact_overfull`) and
for repeated observation identifiers (`artifact_duplicate_observation`), the current evaluation of
each case a report would print against its detection time, and every metadata envelope. A store
that recorded coverage gaps is also audited for `coverage_incomplete` and `coverage_overfull` (a
coverage stream without exactly one head and one gap record), `coverage_stream_mismatch` (a stream
id or a record that is not its stream's own), `coverage_identity_breach` (a record that is not a
gap record, or a head that disagrees with it), and `coverage_schema_unmarked` (a coverage stream
in a store marked below schema 4). A healthy store prints one line:

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

## Python API

The commands run on a library you can import directly.

| Entry point | What it does |
|---|---|
| `complyroll.adapters.ingest_stig_artifact(path)` | CKLB, CKL, XCCDF, ARF, SARIF, and HDF files become immutable observations with artifact digest, parser identity, timestamps, and structured diagnostics |
| `complyroll.policy.load_bundled_policy(profile)` | Selects the 36 provider-facing VDR and VER rules for a 20x Class B or Class C profile from the pinned official dataset and calculates evaluation, PAIN response, and acceptance-threshold deadlines with full provenance, in the provider's calendar timezone |
| `complyroll.store.SQLiteEventStore` | Append-only event log with optimistic concurrency, payload digests, schema and tail-integrity verification, and projection checkpoints. Domain events are written only through `complyroll.events.EventRepository`, which validates every payload against a published contract (ADR 0008) |

Run each snippet below from the repository root with the package installed.

### Ingest one artifact

Ingest an artifact and inspect its observations and diagnostics:

```python
from pathlib import Path

from complyroll.adapters import ingest_stig_artifact

result = ingest_stig_artifact(Path("tests/fixtures/ubuntu-host.cklb"))
if not result.successful:
    for diagnostic in result.errors:
        print(diagnostic.code, diagnostic.message)
else:
    print(result.observations[0].to_canonical_json())
```

### Calculate a response deadline

Calculate a Class C response target with rule provenance:

```python
from datetime import UTC, datetime

from complyroll.models import PainRating
from complyroll.policy import CertificationClass, CertificationProfile, load_bundled_policy

policy = load_bundled_policy(CertificationProfile(CertificationClass.C))
deadline = policy.response_deadline(
    datetime(2026, 8, 21, 15, 0, tzinfo=UTC),
    pain=PainRating.N4,
    is_internet_reachable=True,
    is_likely_exploitable=True,
)
print(deadline.rule_id, deadline.force.value, deadline.due_at.isoformat())
print(deadline.provenance.commit, deadline.provenance.dataset_sha256)
```

### Validate a report

Validate a report against the pinned official schema:

```python
from pathlib import Path

from complyroll.schemas import ReportSchema, validate_bundled_report_bytes

result = validate_bundled_report_bytes(
    ReportSchema.VULNERABILITY_DETAIL, Path("tests/golden/vdt-fixtures.json").read_bytes()
)
for issue in result.issues:
    print(issue.instance_pointer, issue.validator, issue.message)
print(result.provenance.schema_version, result.provenance.schema_sha256)
```

The golden detail report is valid, so the loop prints nothing and the last line names the schema
version and its SHA-256.
