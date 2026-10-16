# Command reference

Every command below takes `--help`, which prints its full option list. Each report compiles on
one of two paths: the stateless path reads the artifacts and compiles the report directly
([ADR 0007](decisions/0007-stateless-vdt-compiler-and-report-mappings.md)), and the persisted
path records the same inputs as history in an event store first, then rebuilds the report from
it with `--db` ([ADR 0008](decisions/0008-persisted-history-and-event-sourced-rebuild.md)).

| Command | What it does |
|---|---|
| `complyroll report vdt ARTIFACT... --class C --package-uri URI --from T --to T [--evaluations FILE] [--kev FILE] [--inventory FILE] [--detected-at T] [--record-failed-imports] [--record-coverage-gaps] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Compiles CKLB, CKL, XCCDF, ARF, SARIF, and HDF files into an official-format Vulnerability Detail Report (`VER-RPT-VDT`): open findings grouped into vulnerabilities with stable tracking ids, class-aware deadlines with rule ids and force, overdue flags with explanations, and a Markdown twin rendered from the same records. With `--kev`, a CISA Known Exploited Vulnerabilities catalog the operator supplies, each record also carries the KEV clock `VDR-TFR-KEV` sets from that catalog's due dates. With `--inventory`, an information resource inventory the operator supplies, every report also carries the coverage evidence described under Coverage against an inventory below. With `--record-failed-imports`, an artifact that cannot be parsed or holds no usable content no longer stops the run: it, and any log that reports a failed scanner invocation, becomes a system observation and a vulnerability of its own (`VDR-CSO-FAV`, ADR 0014), and the command writes the report and exits 3. A file that cannot be read, an unsupported or rejected format, a duplicate observation identity, a partial reading, or an unclassified error code still stops the run (ADR 0014 Decision 2). With `--record-coverage-gaps`, which needs `--inventory`, each coverage window that closed with no verification becomes a system observation and a vulnerability too (`VDR-CSO-FAV`, ADR 0015), and the command writes the report and exits 3; Coverage against an inventory below has the details. A SARIF run that reports no results under a successful invocation is not a failure: it imports as one PASS observation of the scope it names, with or without the flag, and is never proof that the scope is free of vulnerabilities (ADR 0015). Validated against the bundled official schema before anything is written |
| `complyroll report avi ARTIFACT... --class C --package-uri URI --from T --to T [--evaluations FILE] [--kev FILE] [--inventory FILE] [--detected-at T] [--record-failed-imports] [--record-coverage-gaps] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Compiles the same artifacts into an official-format Accepted Vulnerability Information report (`VER-RPT-AVI`): every accepted vulnerability with recorded activity in the report period, each with the acceptance rationale the official item requires, and a count of the active records that belong in the detail report instead. An accepted record whose evaluation carries no rationale stops the compile |
| `complyroll report historical ARTIFACT... --class C --package-uri URI [--evaluations FILE] [--kev FILE] [--inventory FILE] [--detected-at T] [--record-failed-imports] [--record-coverage-gaps] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Compiles a Historical VER Activity snapshot (`VER-TFR-MRH`) as of `--as-of`, with no report period: every non-accepted vulnerability, disposed ones included, under `activeVulnerabilities` and every accepted one under `acceptedVulnerabilities`, each in its current state |
| `complyroll ingest ARTIFACT... --db STORE [--as-of T] [--record-failed-imports] [--actor NAME]` | Records each artifact and its observations as typed events (`artifact.ingested`, `observation.recorded`) in an append-only SQLite store, validated against published contracts before they are written. Re-running over the same bytes appends nothing. With `--record-failed-imports`, each detection process failure is recorded on its own stream as a `failure.recorded` event and a system observation, and the run exits 3, while the readings ADR 0014 Decision 2 keeps fatal still stop it with exit 1 and nothing written; a failure another failure stream already holds is recorded as a hold on it, as a `failure.held` event; a store that records a failure is marked schema 2, or 3 once it records a hold, which an earlier build's `ingest`, `cases`, and `report --db` refuse to open |
| `complyroll cases correlate\|attest-detection\|evaluate\|coverage\|list\|history --db STORE` | Opens one case per vulnerability, records attested detection times and operator evaluations as events, lists cases, and prints one case's full history. A changed evaluation appends a second `case.evaluated` event; the earlier one stays readable. `cases correlate` folds each existing case stream it may extend before it appends anything, and refuses a store where one does not fold with the error `report vdt --db` prints, appending nothing. `cases coverage` records each coverage window the store's evidence closed with no verification as a system observation on a stream of its own, marks the store schema 4, and exits 3 when it recorded one (ADR 0015) |
| `complyroll report vdt --db STORE --class C --package-uri URI --from T --to T [--kev FILE] [--inventory FILE] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Rebuilds the Vulnerability Detail Report from the event log through the same record compiler as the stateless path. The output is byte-identical to the stateless report for the same inputs, and that equality is a test; a store holding detection process failures matches the stateless run with `--record-failed-imports` when each failure was ingested at the report's `--as-of` or carries a scanner clock, no stream of its digest is superseded, no two input names share a digest, and no `ingest` reported `failure_held_by_another_stream` (ADR 0014). A store that recorded coverage gaps matches the stateless run with `--record-coverage-gaps` when `cases coverage` ran with the report's inventory, `--as-of`, class, and calendar zone and no evidence inside a recorded window arrived after it (ADR 0015) |
| `complyroll report avi --db STORE --class C --package-uri URI --from T --to T [--kev FILE] [--inventory FILE] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Rebuilds the Accepted Vulnerability Information report from the same event log through the same record set. The output is byte-identical to the stateless report for the same inputs, and that equality is a test, including one that records the evaluations at two different instants and proves the recording instant never reaches the report. Detection process failures and coverage gaps carry the same conditions as `report vdt --db` (ADR 0014, ADR 0015) |
| `complyroll report historical --db STORE --class C --package-uri URI [--kev FILE] [--inventory FILE] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Rebuilds the Historical VER Activity snapshot from the same event log; it takes no `--from` or `--to`. The output is byte-identical to the stateless snapshot for the same inputs, and that equality is a test. Detection process failures and coverage gaps carry the same conditions as `report vdt --db` (ADR 0014, ADR 0015) |
| `complyroll store verify --db STORE` | Walks the whole log checking event names against the append grammar, positive integer version columns, payload digests, stored JSON against the append rules, sequence and stream-version contiguity, the sequence counter, the schema definitions, and the header's schema marker and application id, then audits the domain (every payload against its published contract, every event against its stream kind and the artifact identity its stream names, every artifact stream for completeness in both directions and for repeated observation identifiers, every failure and coverage stream for its one head and one observation, the current evaluation of each case a report would print against its detection time, every metadata envelope), and exits non-zero on any fault, including on files the normal open refuses. A metadata envelope outside the rules, an event on a non-case stream it does not belong on (with the contract or count faults only that event causes) and a failure or coverage schema marker left low are reported here: no report and no case writer refuses them, `ingest --record-failed-imports` refuses only to resume a failure stream that holds such an event and `cases coverage` only a coverage stream, and none changes a report's bytes (ADR 0008) |
| `complyroll validate REPORT --schema vulnerability-detail\|accepted-vulnerability\|historical-activity` | Validates a report against the pinned official schema, offline, printing JSON Pointers for every failure and the exact schema provenance |
| `stigroll <files> [--cci-list U_CCI_List.xml] [--format markdown\|csv\|json] [-o FILE]` | The predecessor STIG roll-up, rebuilt on the hardened adapters and locked to its original output byte-for-byte |

The rows show `--class C`; every report command also takes `--class B`. `complyroll version`
and `complyroll plan` take no options: one prints the version, the other the implementation
phases.

## Coverage against an inventory

`report vdt`, `report avi`, and `report historical` take `--inventory FILE` on both paths: a
`complyroll.inventory` JSON document listing the resources the provider expects its detection
processes to cover. It is read locally and never stored, so it sits beside `--db` rather than
conflicting with it, as `--kev` does, and the persisted report stays byte-identical to the
stateless one. Each report gains the `x-complyroll.coverage` block and a Markdown `## Coverage`
section, which say for each resource and coverage rule when detection last examined and last
verified it and whether a window closed with nothing verified. A run without the flag produces
exactly the bytes it produced before
([ADR 0015](decisions/0015-coverage-and-freshness.md)). The format and the block are described in
[`DATA_MODEL.md`](DATA_MODEL.md), and what each status means in
[`FEDRAMP_2026_MAPPING.md`](FEDRAMP_2026_MAPPING.md).

`--inventory` alone never changes the exit code of a run that compiles: a stale or missing
resource is evidence in the report, not a failure. These stop the run, each with one ERROR line
on standard error, exit 1, and nothing written:

- A second `--inventory` is `invalid_option`.
- A file the reader refuses is `invalid_input`, with a message that starts "inventory" and names
  the position, such as an unknown key, a field outside its rule, more than 20,000 resources, or
  a file over 8 MiB.
- A pinned rules dataset that lacks any of the five coverage rules is `coverage_rule_unavailable`,
  which names every missing rule. A run without `--inventory` never reads them.
- Naming the inventory as `-o` or `--markdown` is `invalid_option`, refused as an input overwrite.

The command contract is 0 for success, 1 for failure, 3 when the output holds a system-generated
`VDR-CSO-FAV` record, and 2 only for an argparse usage error. Each flag answers for its own kind:
a run exits 3 when `--record-failed-imports` recorded a failure or `--record-coverage-gaps`
recorded a coverage gap, and once with both. The output is written first, and a publish that
fails still exits 1.

An entry whose `driftLikely` is `"unknown"` carries `VDR-TFR-PDD`, the shorter drift window, and
raises WARNING `drift_likelihood_unknown` once per entry. The warning goes to standard error and
into the report's diagnostics, located at the inventory name and the entry's pair.

### Coverage gaps as cases

With `--record-coverage-gaps` as well, each window in the block, a coverage clock's due date that
passed with no verification, becomes a `VDR-CSO-FAV` system observation of its own and a
vulnerability case (ADR 0015). Its source type is `complyroll.coverage` and its record id
`coverage-gap`. It is detected at the window close, with `detectedAtSource` `system`, so
`--detected-at` never applies to it, and it gets PAIN only from an evaluation. Windows of one rule
share a case when their entries name the same `job`, the windows of one sample group share a case,
and every other window is a case of its own. The command writes its outputs and exits 3. A gap
detected after `--to` is left out of the official VDT with INFO `excluded_by_period` and still
counts for exit 3. A gap records that ComplyRoll found no verification inside the window. It is not
a finding that the resource has a vulnerability.

The flag is refused, with exit 1 and nothing written, without `--inventory` and beside `--db`.
The `--db` conflict is checked first:

```text
error: invalid_option: report vdt --record-coverage-gaps needs --inventory: a coverage gap is a window of an inventory entry's clock
error: invalid_option: report vdt takes either --db or --record-coverage-gaps, never both
```

A run that can record a gap is gap-aware. Its block adds two keys to every window: `recorded`,
true when a gap record carries the window, and `trackingId`, that record's tracking id or null.
The Markdown Windows table gains Recorded and Tracking ID columns and opens with this sentence:

```text
A recorded window is a VDR-CSO-FAV system record of this run and names its tracking ID here even when this report does not select the record, such as one detected after the report period.
```

A stateless run is gap-aware with the flag. A run from a store is gap-aware when the store is
marked schema 4, which `cases coverage` does, and the run has `--inventory`. Every other run
writes the windows exactly as before. When no attestation was needed, the Markdown Detection time
attestation section ends its sentence with "or, for a coverage gap, from the instant its coverage
window closed. No attestation was needed."

An evaluation closes a gap as it closes any record, matched on all three keys. The context key is
`<rule>:job:<job>` when the entry names a job, else `<rule>:resource:<type>:<id>`, which a sample
group spells `<rule>:resource:logical:sample-group/<name>`. No report prints it, so build it from
the window's rule and context and the entry's `job`:

```json
{"sourceRecordId": "coverage-gap", "sourceType": "complyroll.coverage", "contextKey": "VDR-TFR-MVX:resource:host:lab-rhel-01"}
```

An entry without `contextKey` is refused as `evaluation_ambiguous`, or as
`evaluation_context_key_required` when it matches a single gap. An entry without `sourceType` that
matches a single gap is refused as `evaluation_context_key_required` too, and the message ends by
naming each key to add. An evaluation completed before the window closed is refused as
`evaluation_before_detection`, with the remedy "a coverage gap is detected when its window closed,
so evaluate it at or after that instant, or correct completedAt".

### Coverage gaps in a store

On the persisted path `cases coverage` records the gaps, and `report --db --inventory` reports
them. A report from a store that recorded gaps can disagree with what its own run derives, and
says so with one of three INFO notes, in the report's diagnostics and on standard error (ADR
0008, amendment 2026-10-16). A recorded gap keeps its case in the report under every note:

| Code | When | Located at | What to do |
|---|---|---|---|
| `coverage_gap_unrecorded` | The run derives a window the store holds no gap for, so no case carries it | `<inventory name> <type>:<id>` | Run `cases coverage` with the report's inventory, `--as-of`, `--class`, and `--calendar-tz`, then `cases correlate` |
| `coverage_gap_contradicted` | The store holds a gap the run derives no window for, and a verification lies inside the gap's window, as a late upload leaves; the note names the earliest one | `coverage-gap` | Dispose the case as a false positive when the note advises it. While the note names other gaps of the case that still stand, answer each of those on its own merits first |
| `coverage_gap_unmatched` | The store holds a gap the run derives no window for, and no verification lies inside it, so the report's inputs may differ from the run that recorded the gap | `coverage-gap` | Check the report's inventory, `--as-of`, `--class`, and `--calendar-tz` against the `cases coverage` run; no disposition answers this note |

## The cases subcommands

The `cases` row above names six subcommands. Each takes these options:

```text
complyroll cases correlate --db STORE [--actor NAME]
complyroll cases attest-detection --db STORE --detected-at T --rationale TEXT
    (--case ID | --all-missing) [--actor NAME]
complyroll cases evaluate --db STORE --evaluations FILE [--actor NAME]
complyroll cases coverage --db STORE --inventory FILE --class C --as-of T
    [--calendar-tz NAME] [--actor NAME]
complyroll cases list --db STORE
complyroll cases history TRACKING_ID --db STORE
```

`cases coverage` derives the coverage windows from the store's evidence exactly as `report --db
--inventory` does, and appends one `coverage/<fingerprint>` stream per window it has not
recorded: a `coverage.recorded` event and the gap's system observation. It prints one line per
gap, first those it recorded and then those already recorded, each in window order, and a count:

```text
obs-93163dadcffc2fa5e3efd858b439b2be6c792975a029a95596b26b92be6fd56c: recorded VDR-TFR-MVX window for host:lab-rhel-01 closed 2026-07-04T00:00:00Z
recorded 9 coverage gap(s), skipped 0 already-recorded coverage gap(s)
```

It exits 3 when it recorded a gap and 0 when every gap was already recorded, so a rerun appends
nothing. A gap recorded once keeps its first payload, even when the inventory has changed since.
`--as-of` is required, because a window closes against it, and `--calendar-tz` defaults to UTC.
Warnings such as `drift_likelihood_unknown` go to standard error, as a report prints them. The
first gap it records marks the store schema 4, which an earlier build refuses to open. A
recorded gap reaches a report from the store at once, but it is not a case until `cases
correlate` runs, so `cases list` and `cases evaluate` reach it only after that. These stop the
run with exit 1 and append nothing:

| Refusal | Code |
|---|---|
| No `--inventory` | `invalid_option`: `cases coverage needs --inventory: a coverage gap is a window of an inventory entry's clock` |
| A second `--inventory` | `invalid_option`: `cases coverage takes one --inventory file, not 2` |
| An inventory the reader refuses | `invalid_input` |
| An `--as-of` that does not parse | `invalid_input` |
| An unknown `--calendar-tz` | `invalid_option` |
| A rules dataset without all five coverage rules | `coverage_rule_unavailable` |
| A store that does not exist | `store_missing`; no store is created |
| A coverage stream that is not whole, or holds an event no coverage stream carries | `history_invalid` |

`--db`, `--class`, and `--as-of` are required, so leaving one out is a usage error with exit 2.

For the Python API (`complyroll.adapters`, `complyroll.policy`, `complyroll.schemas`, and
`complyroll.store`), see the Python API section of [`examples/README.md`](../examples/README.md).
