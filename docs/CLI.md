# Command reference

Every command below takes `--help`, which prints its full option list. Each report compiles on
one of two paths: the stateless path reads the artifacts and compiles the report directly
([ADR 0007](decisions/0007-stateless-vdt-compiler-and-report-mappings.md)), and the persisted
path records the same inputs as history in an event store first, then rebuilds the report from
it with `--db` ([ADR 0008](decisions/0008-persisted-history-and-event-sourced-rebuild.md)).

This page names `--db`'s argument `STORE` and an instant `T`, such as `2026-10-01T00:00:00Z`;
`--help` prints the same two as `PATH` and `RFC3339`.

| Command | What it does |
|---|---|
| `complyroll report vdt ARTIFACT... --class C --package-uri URI --from T --to T [--evaluations FILE] [--kev FILE] [--inventory FILE] [--changes FILE] [--detected-at T] [--record-failed-imports] [--record-coverage-gaps] [--record-change-gaps] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Compiles CKLB, CKL, XCCDF, ARF, SARIF, HDF, and CycloneDX JSON files into an official-format Vulnerability Detail Report (`VER-RPT-VDT`): open findings grouped into vulnerabilities with stable tracking ids, class-aware deadlines with rule ids and force, overdue flags with explanations, and a Markdown twin rendered from the same records. With `--kev`, a CISA Known Exploited Vulnerabilities catalog the operator supplies, each record also carries the KEV clock `VDR-TFR-KEV` sets from that catalog's due dates. With `--inventory`, an information resource inventory the operator supplies, every report also carries the coverage evidence described under Coverage against an inventory below. With `--changes`, which needs `--inventory`, a change file the operator supplies, every report also carries the detection status of each declared change described under Declared changes below. With `--record-failed-imports`, an artifact that cannot be parsed or holds no usable content no longer stops the run: it, and any log that reports a failed scanner invocation, becomes a system observation and a vulnerability of its own (`VDR-CSO-FAV`, ADR 0014), and the command writes the report and exits 3. A file that cannot be read, an unsupported or rejected format, a duplicate observation identity, a partial reading, or an unclassified error code still stops the run (ADR 0014 Decision 2). With `--record-coverage-gaps`, which needs `--inventory`, each coverage window that closed with no verification becomes a system observation and a vulnerability too (`VDR-CSO-FAV`, ADR 0015), and the command writes the report and exits 3; Coverage against an inventory below has the details. With `--record-change-gaps`, which needs `--changes`, each change window that closed with no verification becomes a system observation too, and the windows of one change one vulnerability (`VDR-CSO-FAV`, ADR 0018), and the command writes the report and exits 3; Change gaps as cases below has the details. A SARIF run that reports no results under a successful invocation is not a failure: it imports as one PASS observation of the scope it names, with or without the flag, and is never proof that the scope is free of vulnerabilities (ADR 0015). CycloneDX documents below says what each kind of SBOM yields and which ones stop the run. Validated against the bundled official schema before anything is written |
| `complyroll report avi ARTIFACT... --class C --package-uri URI --from T --to T [--evaluations FILE] [--kev FILE] [--inventory FILE] [--changes FILE] [--detected-at T] [--record-failed-imports] [--record-coverage-gaps] [--record-change-gaps] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Compiles the same artifacts into an official-format Accepted Vulnerability Information report (`VER-RPT-AVI`): every accepted vulnerability with recorded activity in the report period, each with the acceptance rationale the official item requires, and a count of the records that are not accepted, which the detail report reports or excludes by the same period. The detail report's "Accepted, reported under VER-RPT-AVI" row counts exactly the records this report carries for the period. An accepted record whose evaluation carries no rationale stops the compile |
| `complyroll report historical ARTIFACT... --class C --package-uri URI [--evaluations FILE] [--kev FILE] [--inventory FILE] [--changes FILE] [--detected-at T] [--record-failed-imports] [--record-coverage-gaps] [--record-change-gaps] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Compiles a Historical VER Activity snapshot (`VER-TFR-MRH`) as of `--as-of`, with no report period: every non-accepted vulnerability, disposed ones included, under `activeVulnerabilities` and every accepted one under `acceptedVulnerabilities`, each in its current state |
| `complyroll changes pending ARTIFACT... --changes FILE --inventory FILE --class C --as-of T [--calendar-tz NAME] [--kev FILE] [--record-failed-imports] [-o FILE]` | Writes a `complyroll.detection-request` JSON document: the resources a declared change still waits on, for the pipeline that owns the scanner. It exits 0 whether or not anything is waiting, and `summary.pending` is the count (ADR 0018); Declared changes below has the details |
| `complyroll changes pending --db STORE --inventory FILE --class C --as-of T [--calendar-tz NAME] [--kev FILE] [-o FILE]` | Writes the same request from the changes and the evidence a store holds. It refuses artifacts, `--changes`, and `--record-failed-imports`, and writes an empty request when the store recorded no change (ADR 0018) |
| `complyroll changes record --db STORE --changes FILE [--as-of T] [--actor NAME]` | Appends each change the store lacks as a `change.recorded` event on a stream of its own, in one transaction, marking the store schema 5. A change already recorded is left alone; the same id with a different value is refused as `change_conflict` and nothing is written (ADR 0018). Exits 0 or 1 |
| `complyroll ingest ARTIFACT... --db STORE [--as-of T] [--record-failed-imports] [--actor NAME]` | Records each artifact and its observations as typed events (`artifact.ingested`, `observation.recorded`) in an append-only SQLite store, validated against published contracts before they are written. Re-running over the same bytes appends nothing. With `--record-failed-imports`, each detection process failure is recorded on its own stream as a `failure.recorded` event and a system observation, and the run exits 3, while the readings ADR 0014 Decision 2 keeps fatal still stop it with exit 1 and nothing written, among them a standalone CycloneDX VEX document, a malformed CycloneDX inventory, and a malformed empty BOM, so one such file stops the whole glob; a failure another failure stream already holds is recorded as a hold on it, as a `failure.held` event; a failure whose bytes the store already holds an outranking reading of is refused with `failure_read_elsewhere`, and the run exits 1 with nothing appended (ADR 0014 Decision 13); a second identity under a tracking id the store or the run already holds is refused with `tracking_id_held`, with or without the flag, and the run exits 1 with nothing appended and, at a path with nothing behind it, no store published; an id the store already holds under two identities is closed, so a run bringing either side is refused the same way, a rerun included; a live pair, two current groups, is named by verify and refused by every report, and `cases correlate` says `store_conflict` when both groups meet in one correlate, and exits 0 and links the later side onto the first's case when the first was already correlated; every report and `cases correlate` name no collision in a latent pair, with at most one side current, and verify warns `tracking_id_latent_pair` and exits 0 on one when the store has no fault (ADR 0008 amendment 2026-11-04); and because that check reads the whole log, a log the read path refuses stops the run as `store_integrity` with nothing appended (ADR 0008 amendment 2026-11-03, second); a store that records a failure is marked schema 2, or 3 once it records a hold, which an earlier build's `ingest`, `cases`, and `report --db` refuse to open |
| `complyroll cases correlate\|attest-detection\|evaluate\|coverage\|changes\|response-gaps\|list\|history --db STORE` | Opens one case per vulnerability, records attested detection times and operator evaluations as events, lists cases, and prints one case's full history. A changed evaluation appends a second `case.evaluated` event; the earlier one stays readable. `cases correlate` folds each existing case stream it may extend before it appends anything, and refuses a store where one does not fold with the error `report vdt --db` prints, appending nothing. `cases coverage` records each coverage window the store's evidence closed with no verification as a system observation on a stream of its own, marks the store schema 4, and exits 3 when it recorded one (ADR 0015). `cases changes` does the same for each change window the store's recorded changes and evidence closed with no verification, marks the store schema 6, and exits 3 when it recorded one (ADR 0018). `cases response-gaps` records each remediation a later open observation contradicts, each case whose detection time was not attested within its `VER-TFR-EVU` window, and each planned reduction not recorded by its planned time, marks the store schema 7, or 8 once it records a lapsed planned response, and exits 3 when it recorded one (ADR 0019). `cases list` and `cases history` read only `case/` streams, so they print a case whose observations `store verify` faults; `store verify` is the check of the observations behind a case |
| `complyroll report vdt --db STORE --class C --package-uri URI --from T --to T [--kev FILE] [--inventory FILE] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Rebuilds the Vulnerability Detail Report from the event log through the same record compiler as the stateless path. The output is byte-identical to the stateless report for the same inputs, and that equality is a test; a store holding detection process failures matches the stateless run with `--record-failed-imports` when each failure was ingested at the report's `--as-of` or carries a scanner clock, no stream of its digest is superseded, no two input names share a digest, and no `ingest` reported `failure_held_by_another_stream` (ADR 0014). A store that recorded coverage gaps matches the stateless run with `--record-coverage-gaps` when `cases coverage` ran with the report's inventory, `--as-of`, class, and calendar zone and no evidence inside a recorded window arrived after it (ADR 0015). A store that recorded changes matches the stateless run with that change file but for the change block's `input` and its Markdown intro line (ADR 0008 amendment 2026-11-12). A store that recorded change gaps matches the stateless run with `--record-change-gaps` under the same carve-out when `cases changes` ran with the report's inventory, `--as-of`, and class and no evidence inside a recorded window arrived after it (ADR 0008 amendment 2026-11-14) |
| `complyroll report avi --db STORE --class C --package-uri URI --from T --to T [--kev FILE] [--inventory FILE] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Rebuilds the Accepted Vulnerability Information report from the same event log through the same record set. The output is byte-identical to the stateless report for the same inputs, and that equality is a test, including one that records the evaluations at two different instants and proves the recording instant never reaches the report. Detection process failures, coverage gaps, and change gaps carry the same conditions as `report vdt --db` (ADR 0014, ADR 0015, ADR 0018), and recorded changes the same carve-out (ADR 0008 amendment 2026-11-12) |
| `complyroll report historical --db STORE --class C --package-uri URI [--kev FILE] [--inventory FILE] [--as-of T] [--calendar-tz NAME] [-o FILE] [--markdown FILE]` | Rebuilds the Historical VER Activity snapshot from the same event log; it takes no `--from` or `--to`. The output is byte-identical to the stateless snapshot for the same inputs, and that equality is a test. Detection process failures, coverage gaps, and change gaps carry the same conditions as `report vdt --db` (ADR 0014, ADR 0015, ADR 0018), and recorded changes the same carve-out (ADR 0008 amendment 2026-11-12) |
| `complyroll store verify --db STORE` | Walks the whole log checking every event column for valid UTF-8 (`event_text_invalid`), and every schema object the store never created (`schema_text_invalid`), event names against the append grammar, positive integer version columns, payload digests, stored JSON and timestamps against the append rules and the exact text `append` writes, sequence and stream-version contiguity, the sequence counter, each projection checkpoint for a non-negative integer count and a readable time (`projection_checkpoint_invalid`), the schema definitions, the header's schema marker and application id, and the migration records against the marker, then audits the domain (every payload against its published contract, every event against its stream kind and the artifact identity its stream names, every case stream id for its tracking id and every case stream for exactly one `case.created`, as its first event (`case_stream_mismatch`), every artifact stream for completeness in both directions and for repeated observation identifiers, every failure and coverage stream for its one head and one observation, every change stream for its one `change.recorded` and the change id its stream digests, every change gap stream for its one head and one observation, for the gap record its head restates, and for the recorded change its head names, every response gap stream for its one head and one observation and for the record its head restates, every case that records a disposition with no evaluation, the current evaluation of each case a report would print against its detection time, every pair of current groups a report would publish under one tracking id (`tracking_id_collision`), every clock a store holds that a report, `cases coverage`, `cases changes` or `cases correlate` cannot compute with: a source clock with no UTC instant, on an observation of any stream, and a detection time or evaluation `completedAt` whose deadline overflows, which only a report computes (`clock_out_of_range`), every metadata envelope), and exits non-zero on any fault, including on files the normal open refuses. On a store with no fault, each tracking id the log holds under two identities prints WARNING `tracking_id_latent_pair` on standard error and verify still exits 0 (ADR 0008 amendment 2026-11-04). A metadata envelope outside the rules, an event on a non-case stream it does not belong on (with the contract or count faults only that event causes) and a failure, coverage, change, change gap or response gap schema marker left low are reported here: no report and no case writer refuses them, `ingest --record-failed-imports` refuses only to resume a failure stream that holds such an event and `cases coverage` only a coverage stream, and none changes a report's bytes (ADR 0008). A misplaced event is the exception on change, coverage, and change gap streams: an event on a change stream that does not belong there, or a `change.recorded` on any other stream, is refused as `history_invalid` by `report --db --inventory` and by `changes pending --db`, the two readers of change streams (ADR 0018 Decision 10), and an event on a coverage, change gap or response gap stream that does not belong there is refused as `history_invalid` by every command that reads the store's observations back (ADR 0015 Decision 34, ADR 0018 Decision 13, ADR 0019 Decision 10) |
| `complyroll validate REPORT --schema vulnerability-detail\|accepted-vulnerability\|historical-activity` | Validates a report against the pinned official schema, offline, printing JSON Pointers for every failure and the exact schema provenance |
| `stigroll <files> [--cci-list U_CCI_List.xml] [--format markdown\|csv\|json] [-o FILE]` | The predecessor STIG roll-up, rebuilt on the hardened adapters; its roll-up is locked to its original output byte-for-byte, and its warning and error lines escape control characters |

The rows show `--class C`; every report command also takes `--class B`. `complyroll version`
and `complyroll plan` take no options: one prints the version, the other the implementation
phases.

## Exit status

`ingest`, every `cases` subcommand, `changes record` and `store verify` require `--db`, so `report`
and `changes pending` are the two commands with a stateless and a persisted path. Code 2 is an
argparse usage error on every command, including a `report` whose artifacts are split around
options, because the artifacts are one run of positional arguments.

| Command | Path | 0 | 1 | 3 |
|---|---|---|---|---|
| `version`, `plan` | none | always | an uncaught exception only | never |
| `ingest` | store | stored, or nothing new; also an execution-class failure without `--record-failed-imports`, which stays WARNING `execution_unsuccessful` (ADR 0014 Decision 3) | a refusal; a fatal-class failure without the flag; with the flag, a failure ADR 0014 Decision 2 keeps fatal, and the one rerun that meets a superseded holder (ADR 0014 Decisions 11 and 13); a mapped domain exception | with the flag, a failure recorded or found already recorded, reruns included |
| `cases correlate`, `attest-detection`, `evaluate`, `list`, `history` | store | success; `attest-detection` and `evaluate` may print `warning:` lines | a refusal, a missing store, a mapped domain exception | never |
| `cases coverage` | store | this run recorded no gap, including a rerun that finds every gap already recorded | a missing or second inventory, a missing store, a parse failure | this run recorded at least one gap |
| `cases changes` | store | this run recorded no change gap, including a rerun that finds every gap already recorded and a store that holds no change | a missing or second inventory, a missing store, a parse failure, `change_rule_unavailable`, `history_invalid` | this run recorded at least one change gap |
| `cases response-gaps` | store | this run recorded no response gap, including a rerun that finds every one already recorded and a store with nothing to record | a missing store, a parse failure, an unknown calendar zone, `history_invalid` | this run recorded at least one response gap |
| `report vdt\|avi\|historical` | stateless | published with no flagged record; `--inventory` or `--changes` alone; an execution-class failure without the flag (WARNING) | a pre-flight refusal; a `ReportCompileError`, which carries every ERROR; a publish failure; `error_diagnostic_unpublished` | published, and `--record-failed-imports` with a failure, `--record-coverage-gaps` with a gap, or `--record-change-gaps` with a change gap, once when several apply; a record outside the report period still counts (ADR 0015 Decision 31) |
| `changes pending` | stateless | the request was written, whether or not anything is waiting; also an execution-class failure without the flag, which stays WARNING `execution_unsuccessful`, and a failure noted by `--record-failed-imports` | a refusal; a missing or second input; a failed reading without the flag; a `ReportCompileError`; a publish failure | never |
| `changes record` | store | every change is recorded or already recorded, including a rerun with nothing new | a refusal, a missing or second change file, a missing store, `change_conflict`, a damaged change stream | never |
| `changes pending --db` | store | the request was written, including the empty request of a store that recorded no change | a refusal, a missing store, `history_invalid`, a `ReportCompileError` | never |
| `report ... --db` | store | published, even when the store holds failures and gaps | the same refusals, and any record flag beside `--db` | never |
| `store verify` | store | `ok: N event(s) verified`, failures and gaps included; may print `warning:` lines | an integrity or domain fault, a missing store | never |
| `validate` | file | `valid: ID VERSION SHA256` | unreadable, too large, malformed, or schema-invalid; schema issue lines carry no `error:` prefix; `x-complyroll` is never read | never |
| `stigroll` | files | any input yielded findings, even when others failed to parse | no findings, a bad CCI list, an `-o` failure as a traceback | never |

Outside the table: exit 1 with a traceback for an uncaught `ValueError` or `TypeError`, 120 when
stdout is closed at interpreter flush, 130 on SIGINT, and a `BrokenPipeError` raised inside an
action, which reads as `store_unavailable`.

Every clock flag (`--as-of`, `--from`, `--to`, `--detected-at`) takes at most 64 characters, a
whole-minute UTC offset and an instant in the years 1970 through 9000 UTC; anything else is
`invalid_input`. The spec's `T24:00` reads as the next midnight on every interpreter.

Text output escapes control characters: every line the `complyroll` and `stigroll` commands print
that can carry input (diagnostics, status and summary lines, and argparse's usage error message),
on stdout or stderr, spells a newline, carriage return, U+2028, U+2029, DEL and every other C0 or
C1 control as an escape (`\n`, `\r`, `\u2028`, `\x1b`), so an argument, a file name or stored
text cannot forge a line. Help text and the usage block carry no input. A tab is kept, since
`cases history` separates its fields with tabs. JSON output is unchanged. A stream that cannot
encode a character writes it as a backslash escape, and a report written to such a stdout spells
it as a JSON `\u` escape, so the same document is written and the run does not end on it.
Documents are not lines and are not covered: a Markdown report file carries stored text as
written, and `stigroll`'s Markdown and CSV roll-ups carry checklist text as their Markdown cell
escapes and CSV formula neutralization leave it.

An event past one of the store's caps (1 MiB of JSON, 64 levels of nesting, or 100,000 values in
its payload or its metadata) is a refusal, `event_too_large` with exit 1, and the run appends
nothing. An evaluations file whose rationale runs past 1 MiB reaches it through `cases evaluate`,
which used to end in a `ValueError` traceback.

Four rules hold across the table:

- No written report, and no exit 0 or 3, carries an ERROR diagnostic. Every ERROR the compiler
  builds raises `ReportCompileError`, a recorded failure carries its ERRORs demoted to WARNING,
  replay refuses a stored ERROR, and a compiled report that carries one is refused with
  `error_diagnostic_unpublished` and never written; no current input reaches that refusal. So a
  job that fails on exit 1 fails on ERROR diagnostics. Exit 1 is not ERROR alone: it also covers
  refusals, publish failures and schema-invalid output.
- Exit 3 comes from five places only: a stateless `report` with a record flag, `ingest
  --record-failed-imports`, `cases coverage`, `cases changes`, and `cases response-gaps`.
- Overdue state, KEV clocks, WARNING and INFO diagnostics, and `--inventory` alone never change an
  exit code. A report with overdue records exits 0.
- `report --db` answers 0 or 1 only. No exit code depends on scanner severity or CVSS.

A failed scanner invocation that is not flagged exits 0 with WARNING `execution_unsuccessful`, so
a CI job must pass `--record-failed-imports` for the failure to reach exit 3 (ADR 0017 Decision
5). [`examples/ci/`](../examples/ci/README.md) holds a reference GitHub Actions workflow and a gate
script that read these exit codes. A green job is not a FedRAMP determination.

## CycloneDX documents

A file named `*.cdx.json`, or a bare `.json` file whose `bomFormat` is `CycloneDX`, is read as a
CycloneDX 1.4 to 1.7 JSON document ([ADR 0016](decisions/0016-cyclonedx-sbom-adapter.md)). What
it yields depends on its `vulnerabilities` member:

| Document | What it yields |
|---|---|
| No `vulnerabilities` member (K1, an inventory such as Syft writes) | One NOT_REVIEWED observation of its subject and WARNING `vulnerabilities_absent`. It is not a detection and verifies no coverage clock |
| `"vulnerabilities": []` (K2) | One NOT_REVIEWED observation of its subject and WARNING `match_unverified`, whatever tool is named, because Trivy writes the same empty list with vulnerability scanning turned off. A clean Grype or Trivy run therefore never verifies a coverage clock |
| Vulnerability records and components besides the subject (K3) | One OPEN observation per vulnerability and `package` resource, plus one observation of the subject: PASS when at least one `affects` ref resolves to a component the document lists other than the subject, on a record whose `analysis` has the state `exploitable` or `in_triage`, or none of a `state`, a `justification`, and a `detail`, in an `affects` entry that does not mark the installed version `unaffected`, else NOT_REVIEWED with `match_unverified`. Only that observation of the subject is coverage evidence, and only as PASS: the vulnerability observations never examine or verify an image. A document that names no tool is ERROR `invalid_bom`, which `--record-failed-imports` records as a detection process failure |
| Vulnerability records and no component but the subject (K4, a standalone VEX document) | Refused: ComplyRoll does not join artifacts, so record its statements as evaluations |

A standalone VEX document, a K1 or K2 document that is structurally malformed or whose tool name,
tool, or scope id cannot be an identity (over 512 characters, or a control character), and a
`vulnerabilities` member that is not an array are refused as formats, with exit 1 and nothing
written, with or without `--record-failed-imports`, because none of them is a failed detection. One
such file in an `ingest` or `report` glob stops the whole run. An embedded `analysis` state such as
`not_affected` never changes a finding's disposition: it draws a warning naming the claim, and the
outcome is recorded with `--evaluations` or `cases evaluate`. A judged record, a `justification` or
a `detail` with no `state` included, never makes the observation of the subject PASS, and neither
does an `affects` entry that marks the installed version `unaffected`. Detection time is the
document's `metadata.timestamp`; `--detected-at` applies only to a document without one.

A case is one CVE from one tool, across every image and package it affects. Ingest one export
format per tool per target: a Grype SARIF log and a Grype CycloneDX document of the same image
carry different source types, so every CVE in them would count twice.

The fixtures reproduce `tests/golden/vdt-cyclonedx.json` and its Markdown twin byte for byte on
both paths:

```bash
complyroll report vdt tests/fixtures/grype-image.cdx.json tests/fixtures/trivy-image.cdx.json \
  --class C --package-uri https://example.test/cpo --calendar-tz UTC \
  --as-of 2026-10-03T12:00:00Z --from 2026-10-01T00:00:00Z --to 2026-10-31T23:59:59Z \
  -o vdt-cyclonedx.json --markdown vdt-cyclonedx.md

complyroll ingest tests/fixtures/grype-image.cdx.json tests/fixtures/trivy-image.cdx.json \
  --db history.db --as-of 2026-10-02T12:00:00Z --actor golden
complyroll cases correlate --db history.db --actor golden
complyroll report vdt --db history.db --class C --package-uri https://example.test/cpo \
  --calendar-tz UTC --as-of 2026-10-03T12:00:00Z \
  --from 2026-10-01T00:00:00Z --to 2026-10-31T23:59:59Z -o vdt.json --markdown vdt.md
```

`ingest` prints `recorded 5 observation(s)` and `recorded 4 observation(s)`, each count including
the observation of the subject, and both report commands warn `package_identity_weak` because
one Grype component carries no purl. `cases correlate` creates six cases.

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
a run exits 3 when `--record-failed-imports` recorded a failure, `--record-coverage-gaps`
recorded a coverage gap, or `--record-change-gaps` recorded a change gap, and once with several.
The output is written first, and a publish that fails still exits 1. Every command's codes are
under [Exit status](#exit-status).

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

A stateless run is gap-aware with the flag. A run from a store is gap-aware when the store holds
a coverage stream, which `cases coverage` records, and the run has `--inventory`. Every other run
writes the windows exactly as before. When no attestation was needed, the Markdown Detection time
attestation section ends its sentence with "or, for a coverage gap, from the instant its coverage
window closed. No attestation was needed."

An evaluation closes a gap as it closes any record, matched on all three keys. The context key is
`<rule>:job:<job>` when the entry names a job, else `<rule>:resource:<type>:<id>`, which a sample
group spells `<rule>:resource:logical:sample-group/<name>`. No report document carries it, so build
it from the window's rule and context and the entry's `job`, or read it from the last column of
`cases list`, which a listing adds once the store holds a gap case:

```json
{"sourceRecordId": "coverage-gap", "sourceType": "complyroll.coverage", "contextKey": "VDR-TFR-MVX:resource:host:lab-rhel-01"}
```

An entry without `contextKey` is refused as `evaluation_ambiguous`, whose message gives each
matching case's context key (the first ten, in tracking id order), or as
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

## Declared changes

`report vdt`, `report avi`, and `report historical` take `--changes FILE` on the stateless path: a
`complyroll.changes` JSON document naming what changed, when, and which resources it touched. It
needs `--inventory`, because a change is read against the inventory or not at all, and it is read
locally and never stored. Each report gains the `x-complyroll.changes` block and a Markdown
`## Changes` section, which give each change and resource a status from the evidence at or after
the change. A run without the flag produces exactly the bytes it produced before
([ADR 0018](decisions/0018-change-triggered-detection.md)). The format, the block, and each status
are described in [`DATA_MODEL.md`](DATA_MODEL.md).

`changes pending` writes the resources still waiting as a request document for the pipeline that
owns the scanner, read from the same artifacts as `report`, to standard output or `-o`/`--output`:

```bash
complyroll changes pending tests/fixtures/codeql-repo.sarif tests/fixtures/clean-run.sarif \
  --changes tests/fixtures/changes-timed.json --inventory tests/fixtures/inventory-timed.json \
  --class C --as-of 2026-09-03T12:00:00Z -o request.json
```

`--changes` alone never changes the exit code of a report that compiles, and `changes pending`
exits 0 whether or not anything is waiting, so read `summary.pending`. With
`--record-failed-imports` a mintable failure is noted on standard error and the run continues, and
`changes pending` still exits 0, because a request holds no system record. It takes no
`--evaluations`, `--detected-at`, or `--package-uri`. These stop a run, each with one ERROR line on
standard error, exit 1, and nothing written:

- A second `--changes` or `--inventory` is `invalid_option`, as is a second `--kev` on `changes
  pending`. `--changes` without `--inventory` is `invalid_option`, refused before anything is read,
  and so is `changes pending` without `--changes`.
- A change file the reader refuses is `invalid_input`, with a message that starts "changes" and
  names the position.
- `--changes` beside `--db` is `invalid_option` ("report vdt takes either --db or --changes, never
  both"), as are artifacts, `--changes`, or `--record-failed-imports` beside `changes pending --db`.
- A pinned rules dataset without `VDR-CSO-DAC` is `change_rule_unavailable`.
- Naming the change file as `-o` or `--markdown` is `invalid_option`, refused as an input overwrite,
  and a symbolic-link output is `output_is_symlink`.

`changes record --db STORE --changes FILE` appends each change the store lacks as its own stream,
in one transaction, so a refusal writes nothing. `--as-of` defaults to the current second and is
stored as `recordedAt`, which reaches no output. A change already recorded is left alone, so a file
that grows re-records cleanly, and the same id with a different value is `change_conflict`, naming
the first differing field. The first change it records marks the store schema 5, which 0.4.0a0
refuses to open; a store that never records a change stays at its version. A damaged change stream
is `history_invalid`.

`report vdt|avi|historical --db STORE --inventory FILE` then carries the block from what the store
recorded, when it holds at least one change stream and the run has an inventory, and
`changes pending --db STORE --inventory FILE --class C --as-of T` writes the request from the same
rows. Without `--inventory` there is no block. Compiled from a store, the block's `input` and its
Markdown intro line name the store and each file digest instead of the file; every other byte
equals the stateless run over the same file (ADR 0008 amendment 2026-11-12). A pinned rules dataset
without `VDR-CSO-DAC` refuses a store holding changes too, in a message that says the store holds
recorded changes. A store holding none reads no rule, so `changes pending --db` still writes its
empty request, with `force` null, and exits 0.

### Writing a change file from git

`--changes` reads ComplyRoll's own `complyroll.changes` document, described in
[`DATA_MODEL.md`](DATA_MODEL.md); there is no git adapter. This worked example, which needs `jq`,
writes that document from `git log --format` for a repository whose commits name their resources
in `Resource:` trailers, such as `Resource: image:registry.example.test/api:2.1`, and mark a
change that is not significant with `Significant: false`:

```bash
format='%H%x09%cI%x09%(trailers:key=Resource,valueonly,separator=%x1F)%x09'
format+='%(trailers:key=Significant,valueonly,separator=%x1F)%x09%s'
git log --no-merges --since=2026-09-01 --format="$format" |
jq -Rn '{
  schema: "complyroll.changes", schemaVersion: 1, name: "git-changes",
  changes: [inputs | split("\t") | select(.[2] != "") | {
    changeId: ("git-" + .[0][:12]),
    kind: "modified",
    occurredAt: .[1],
    source: {tool: "git", reference: ("commit " + .[0])},
    resources: [.[2] | split("\u001f") | unique[]
      | capture("^(?<resourceType>[^:]+):(?<resourceId>.+)$")],
    significant: (.[3] != "false"),
    rationale: (.[4:] | join("\t"))[:512]
  }]
}' > changes.json
```

It is an example to adapt, not a parser. It calls every commit a modification, sets no `detectBy`
window, and takes the subject line as the rationale, so a commit it should not count is yours to
filter. ComplyRoll refuses a file that breaks the contract; the only text it cleans is `rationale`.

### Change gaps as cases

With `--record-change-gaps` as well, each obligation row whose window closed, a `lapsed` row or a
`detected` row with `late: true`, becomes a `VDR-CSO-FAV` system observation of its own (ADR
0018). Its source type is `complyroll.change`, its record id `change-detection-gap`, and its
context key `VDR-CSO-DAC:change:<changeId>`, so every closed window of one change is one case that
lists every resource. It is detected at the window close, the change's `detectBy`, with
`detectedAtSource` `system`, so `--detected-at` never applies to it, and it gets PAIN only from an
evaluation. A later verification never closes it; only a disposition does. The command writes its
outputs and exits 3. A gap detected after `--to` is left out of the official VDT with INFO
`excluded_by_period` and still counts for exit 3. A gap records that ComplyRoll found no
verification between the change and the window close. It is not a finding that the resource has a
vulnerability.

The flag is refused, with exit 1 and nothing written, without `--changes` and beside `--db`. The
`--db` conflict is checked first, and beside `--changes` as well it names both:

```text
error: invalid_option: report vdt --record-change-gaps needs --changes: a change gap is the closed window of a declared change
error: invalid_option: report vdt takes either --db or --record-change-gaps, never both
```

A run that can record a change gap is change-gap-aware. Its block adds two keys to every
obligation row: `recorded`, true when a gap record carries the window and null when no window
closed, and `trackingId`, that record's tracking id or null. The request document never carries
them. The Markdown Obligations table gains Recorded and Tracking ID columns and opens with this
sentence:

```text
A recorded row is a VDR-CSO-FAV system record of this run and names its tracking ID here even when this report does not select the record, such as one detected after the report period. A row whose window did not close records nothing and reads n/a.
```

A stateless run is aware with the flag. A run from a store is aware when the store holds a change
gap stream, which `cases changes` records, and the run has `--inventory`; there a closed window no
stored gap carries reads `recorded` false. Every other run writes the block exactly as before.
When no attestation was needed, the Markdown Detection time attestation sentence names "for a
change detection gap, from the instant its change window closed".

An evaluation closes a change gap as it closes any record, matched on all three keys. Build the
context key from the change id, or read it from the last column of `cases list`:

```json
{"sourceRecordId": "change-detection-gap", "sourceType": "complyroll.change", "contextKey": "VDR-CSO-DAC:change:CHG-2001"}
```

An entry without `contextKey` that matches several gaps is refused as `evaluation_ambiguous`, whose
message gives each matching case's context key. An entry short of a key that matches a single gap
is refused as `evaluation_context_key_required` by a report, and as `evaluation_unmatched` by
`cases evaluate`, and the message ends "a change detection gap is matched by sourceRecordId,
sourceType and contextKey together, so add" and the keys it leaves out. An evaluation completed
before the window closed is refused as `evaluation_before_detection`, with the remedy "a change
detection gap is detected when its window closed, so evaluate it at or after that instant, or
correct completedAt". `cases attest-detection --case` on a change gap case warns
`attestation_not_applicable`, and `--all-missing` never selects one.

### Change gaps in a store

On the persisted path `cases changes` records the gaps, and `report --db --inventory` reports
them. A report from a store that recorded change gaps can disagree with what its own run derives,
and says so with one of three INFO notes, in the report's diagnostics and on standard error (ADR
0008, amendment 2026-11-14). Each note names the change id and is located at
`<changes name> <changeId> <type>:<id>`. A recorded gap keeps its case in the report under every
note:

| Code | When | What to do |
|---|---|---|
| `change_gap_unrecorded` | The run derives a closed window the store holds no gap for, so no case carries it | Run `cases changes` with the report's inventory, `--as-of`, and `--class`, then `cases correlate` |
| `change_gap_contradicted` | The store holds a gap the run derives no window for, and a verification lies inside the gap's window | Dispose the case as a false positive only when the note advises it, which it does when no other gap of the case still stands |
| `change_gap_unmatched` | The store holds a gap the run derives no window for, and no verification lies inside it, so the report's inputs may differ from the run that recorded the gap | Check the report's inventory, `--as-of`, and `--class` against the `cases changes` run; no disposition answers this note |

A store whose gaps were recorded with the report's inventory, `--as-of`, and class gives the
stateless run's bytes with `--record-change-gaps`, but for the block's `input` and its Markdown
intro line. One limit is open: a stored gap whose window closed after an earlier `--as-of` is not
filtered out of a report at that instant, so it reads `change_gap_unmatched` and its record stays,
as a stored coverage gap does today.

## Remediations that did not hold and lapsed attestations

A remediated record that a later scan finds again keeps the operator's disposition: ComplyRoll
never sets one. Every report, on both paths, adds one WARNING `recurrence_after_remediation` per
such record, naming the remediation instant and the earliest detection after it, and counting
any open member that declares no source timestamp, whose time cannot be ordered against the
remediation (ADR 0019). A detection at the remediation instant raises no warning. An untimed
member raises none when the record's detection time is an attestation at or before the
remediation, so a new untimed scan of such a record is not flagged. The instant is the
`completedAt` of the record's evaluation; from a store, of the evaluation in force when the
current remediated disposition was first recorded, so a re-evaluation that keeps the disposition
does not move it. Only a disposition that resolves to `remediated` counts, `closed` with
`closedDisposition` `remediated` among them. Re-evaluate the record: the warning goes when its
disposition changes to one that does not resolve to `remediated`.

Every report also warns `planned_reduction_lapsed` once per record whose own planned reduction
passed unrecorded (ADR 0019, section of 2026-11-27): the record is ARTIFACT-origin (a system
record never warns), its evaluation states a `projectedNextReduction` whose `estimatedAt` is
strictly before the report's `--as-of`, its current rating is above the `targetRating`, no
completed reduction to the target or below is recorded from the evaluation's `completedAt`
through `estimatedAt`, and its disposition does not resolve to `remediated`, `fully_mitigated` or
`false_positive`. The warning names the planned time, the target, the current rating and the
evaluation, and the report publishes the projection unchanged. From a store, a reduction an
earlier evaluation stated and a later one dropped still counts, since history keeps it.
Re-evaluate the record: the warning goes when the evaluation lowers the rating to the target,
records the reduction inside the window, resolves the record to `remediated`, `fully_mitigated`
or `false_positive`, or states a new plan that is not itself overdue and unmet; a new plan is
read on its own terms. Closing the record as `partially_mitigated` or `accepted` keeps the
warning.

In a store, `cases response-gaps` records those failures, and one more, as `VDR-CSO-FAV` system
records: a remediation that did not hold, one record per resource that came back; a case whose
detection time was not attested within the `VER-TFR-EVU` window from the earliest ingest of its
linked evidence; and a lapsed planned response, one record per case and plan. No report flag
records any of them. A report from a store that holds a response gap
reads it against its own run with one of four INFO notes, each located at
`<record id> <case tracking id>`:

| Code | When | What to do |
|---|---|---|
| `response_gap_unrecorded` | The run derives a response gap the store holds no record for, so no case carries it | Run `cases response-gaps` with the report's `--as-of`, `--class`, and calendar zone, then `cases correlate` |
| `response_gap_contradicted` | The store holds a response gap the run cannot rebuild from its own record, and the store holds evidence against it | Dispose the case as a false positive only when the note advises it, which it does when no other gap of the case still stands |
| `response_gap_unmatched` | The store holds a response gap the run cannot rebuild, with nothing against it, so the evidence or the report's class or calendar zone may differ from the run that recorded it | Check the report's `--class` and calendar zone against the `cases response-gaps` run; no disposition answers this note |
| `response_gap_earlier_detection` | The store holds a remediation recurrence the run finds detected earlier than its record says, from a scan ingested after it was recorded | Nothing to record: the first record stands, and the note names the earlier instant |

A recorded gap the run rebuilds from its own record writes no note, so attesting a case after its
lapse was recorded, or re-evaluating a case after its recurrence was recorded, leaves the report
quiet. A recorded lapsed planned response is read for a contradiction first: it is
`response_gap_contradicted` when the case's current evaluation still states the recorded plan and
records a reduction to the target or below inside its window. Otherwise it stands with no note,
whether or not the run still derives it, so a plan revised, met late or closed leaves the report
quiet, and neither `response_gap_unmatched` nor `response_gap_earlier_detection` arises for it.
An evaluation closes a response gap as it closes any record, matched on all three keys; read
the context key from the last column of `cases list`:

```json
{"sourceRecordId": "remediation-recurrence", "sourceType": "complyroll.recurrence",
 "contextKey": "case-748ec5056f5557ed:remediated:2026-09-05T15:00:00Z:1"}
{"sourceRecordId": "attestation-lapse", "sourceType": "complyroll.attestation",
 "contextKey": "case-a28eeaac0789b5e2"}
{"sourceRecordId": "planned-response-lapse", "sourceType": "complyroll.response-plan",
 "contextKey": "case-748ec5056f5557ed:planned:2026-09-11T16:00:00Z:2"}
```

A lapsed planned response's context key ends on the planned time and the target rating, so the
same plan restated by a later evaluation is the same case, and a new plan that also lapses is a
second case.

A recurrence's context key ends on the remediated episode, the 1-based position of that
remediated run in the case, so a second remediation that fails is a second case even at the same
instant.

An entry short of a key is refused, and the message ends "a remediation recurrence is matched by
sourceRecordId, sourceType and contextKey together, so add" or the same with "a lapsed
attestation" or "a lapsed planned response". An evaluation completed before the record's
detection time is refused as `evaluation_before_detection`, with the remedy "a remediation
recurrence is detected when its recurring observation was detected", "a lapsed attestation is
detected when its evaluation window closed" or "a lapsed planned response is detected when its
planned time passed", each ending "so evaluate it at or after that instant, or correct
completedAt".

## The cases subcommands

The `cases` row above names eight subcommands. Each takes these options:

```text
complyroll cases correlate --db STORE [--actor NAME]
complyroll cases attest-detection --db STORE --detected-at T --rationale TEXT
    (--case ID | --all-missing) [--actor NAME]
complyroll cases evaluate --db STORE --evaluations FILE [--actor NAME]
complyroll cases coverage --db STORE --inventory FILE --class C --as-of T
    [--calendar-tz NAME] [--actor NAME]
complyroll cases changes --db STORE --inventory FILE --class C --as-of T
    [--calendar-tz NAME] [--actor NAME]
complyroll cases response-gaps --db STORE --class C --as-of T [--calendar-tz NAME]
    [--actor NAME]
complyroll cases list --db STORE
complyroll cases history TRACKING_ID --db STORE
```

`cases list` prints one row per case. Once the store holds a coverage gap, change detection gap,
remediation recurrence, lapsed attestation, or lapsed planned response case it adds a last
column, `CONTEXT KEY`, with that
case's context key, and `-` for every other case; a listing with none of them is unchanged. A
change id may hold spaces, so the key cell runs to the end of its line. It folds only the case
streams, so it still lists the cases of a store that `store verify` rejects for damage elsewhere,
such as a damaged artifact stream or an orphaned hold. Run `store verify` to check the whole store.
`cases list` and `cases history` read only `case/` streams and rehydrate no observation, so each
exits 0 and prints a case whose artifact, failure, coverage, change gap or response gap stream
`store verify` faults; `store verify` is the check of the observations behind a case. `cases
attest-detection` reads an artifact stream only when a case it attests carries an evaluation, so
it can attest on a store whose artifact streams are damaged; `store verify` and every report from
the store still refuse it.

`cases evaluate` refuses a file with exit 1 and appends nothing when the store it would leave holds
two records a report publishes under one tracking id. It prints one `evaluation_unmatched` line
that names each such pair, the pairs joined by `; `. It counts what a report would publish once
the run is written: a case the file evaluates under the entry's `trackingId`, else its recorded
override, else its correlation id; any other case under its override only while it has a current
evaluation, else under its correlation id; and a group `ingest` brought that no case holds yet,
before `cases correlate` runs, under its correlation id. A pair naming such a group gives its
source record id and context key, and the case whose new `trackingId` clears it. An override
naming a correlation id no current group has is accepted, and an `ingest` that later brings that
group leaves a collision `store verify` names. A pair located at `recorded history` names a
collision the store already holds: every run is then refused unless it moves a claimant off that
id, as an entry stating another `trackingId` for it does (ADR 0008 amendments 2026-11-03 and
2026-11-14, fourth).

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
| An `--as-of` that does not parse, or names an instant outside the years 1970 through 9000 UTC | `invalid_input` |
| An unknown `--calendar-tz` | `invalid_option` |
| A rules dataset without all five coverage rules | `coverage_rule_unavailable` |
| A store that does not exist | `store_missing`; no store is created |
| A coverage stream that is not whole, or holds an event no coverage stream carries | `history_invalid` |

`--db`, `--class`, and `--as-of` are required, so leaving one out is a usage error with exit 2.

`cases changes` derives the change windows from the store's recorded changes and evidence exactly
as `report --db --inventory` does, and appends one `changegap/<fingerprint>` stream per closed
window it has not recorded, written whole in one batch: a `change.gap_recorded` event and the
gap's system observation. It prints one line per gap, first those it recorded and then those
already recorded, each in obligation order, and a count:

```text
obs-228b7afeb4f5bb07934d17ec6f1693fd88825b96c48ad71deea3fe38db99fee1: recorded VDR-CSO-DAC window for image:registry.example.test/synthetic/example-service:1.4.0 after change CHG-2001 closed 2026-08-20T00:00:00Z
obs-7293ce227cc7c7c514fe1d4af13ae7418b291b86e48ac3eb1d73c7ace04eac25: recorded VDR-CSO-DAC window for file:src/ui/render.js after change CHG-2003 closed 2026-09-01T01:00:00Z
recorded 2 change gap(s), skipped 0 already-recorded change gap(s)
```

It exits 3 when it recorded a gap and 0 otherwise, so a rerun, which prints `already_recorded`
lines, appends nothing. A store that holds no change exits 0, appends nothing, and marks no
schema. A gap recorded once keeps its first payload. Warnings of the change block, such as
`change_precedes_expected_since`, go to standard error. `--as-of` is required, because a window
closes against it. `--calendar-tz` is accepted for parity with `cases coverage` and moves nothing,
because a change window closes at an instant. It takes no `--kev` and no `--changes`, so either is
a usage error with exit 2. The first gap it records marks the store schema 6, which an earlier
build refuses to open, and the repository accepts a gap only of a change the store recorded. A
recorded gap reaches a report from the store at once, but it is not a case until `cases
correlate` runs, so `cases list` and `cases evaluate` reach it only after that. These stop the run
with exit 1 and append nothing:

| Refusal | Code |
|---|---|
| No `--inventory` | `invalid_option`: `cases changes needs --inventory: a change names inventory resources, so its windows are read against an inventory` |
| A second `--inventory` | `invalid_option`: `cases changes takes one --inventory file, not 2` |
| A store that does not exist | `store_missing`; no store is created |
| An inventory the reader refuses, or an `--as-of` that does not parse or names an instant outside the years 1970 through 9000 UTC | `invalid_input` |
| An unknown `--calendar-tz` | `invalid_option` |
| A rules dataset without `VDR-CSO-DAC`, on a store that holds a change | `change_rule_unavailable` |
| A change or change gap stream that is not whole, or holds an event its kind does not carry | `history_invalid` |

`cases response-gaps` derives the three kinds of response gap from the store exactly as a report
from the store reads them, recurrences first, then lapsed attestations, then lapsed planned
responses, and appends one `response-gap/<fingerprint>` stream per record it has not recorded,
written whole in one batch: a head event and the record's system observation (ADR 0019). The head
is `response_gap.recorded` for the first two kinds and `response_gap.plan_lapsed` for the third.
A remediation that did not hold is read from the report's own grouping of
every current open observation, linked or not, so it is recorded before `cases correlate` links
what came back. A failed remediation and resource is recorded once: a scan dated earlier than the
recorded detection and ingested after it appends nothing, and the stored record is listed as
already recorded. A lapse is recorded when a case with linked evidence has no source timestamp on
any link or on any current reading of it, linked or not, and no attestation, and `--as-of` is at
or past the `VER-TFR-EVU` deadline, under `--class` and `--calendar-tz`, from the case's first
sighting: the earliest ingest instant of that evidence, which is the ingest's `--as-of`, or its
run time at second precision when none was given. Stores built from the same scans give the same
bytes only when every ingest names `--as-of`. A run whose `--as-of` is before the first sighting
records no lapse. The first sighting stands in for the detection time, so the lapse is never early
only when the ingest instant is at or after the true detection; ComplyRoll cannot check that.
Once recorded a lapse is permanent, and an attestation made before any run sees the lapse
prevents it. A lapsed planned response is recorded when a run whose `--as-of` is strictly after
the planned time finds the plan unmet, as the `planned_reduction_lapsed` warning above reads it,
from the evaluation each case reports with: a case no current open observation matches is in no
report and records nothing. No class or calendar zone enters it. The run can record a plan lapse
for a record no report can compile yet: a case with no detection time has its plan lapse
recorded, and its lapsed attestation too once that case's own `VER-TFR-EVU` window has closed
(either can close first), while every report from the store refuses with
`detection_time_missing`; once the case is attested, the report warns and the record stands with
no note. The lapse depends only on the case, the planned time and the target, never on the
detection time (ADR 0019, Kyle's ruling B01). No record is made when, by the first run past the
planned time, the store holds a reduction to the target or below inside the window, the current
rating is at or below the target, or the record resolves to `remediated`, `fully_mitigated` or
`false_positive`. A revised plan is a
new plan read on its own terms, and may itself be overdue and unmet; closing as `accepted` or
`partially_mitigated` prevents nothing. So the record is only as frequent as the runs. It prints
one line per record, first those it recorded and then those already recorded, and a count.
Each record line is the record's id and its title less the rule. The record lines below are
output and cannot wrap. The first block is the golden store of `historical-response-gaps`, the
second that of `historical-planned-response`:

```text
obs-96b8956b3a49f8026796a7ef9c68a42448ada45873af753313b60c3d910b2806: recorded remediation of case-748ec5056f5557ed recorded 2026-09-05T15:00:00Z did not hold: image:registry.example.test/recurrence/api:1.4.2/usr/lib/libexample-json.so.2 detected again 2026-09-12T08:40:00Z
obs-5e1b2b5cf665b208a471fb68c878627a207694012c555f4472872516db3ac823: recorded detection time of case-a28eeaac0789b5e2 was not attested within VER-TFR-EVU from 2026-09-01T00:00:00Z
recorded 2 response gap(s), skipped 0 already-recorded response gap(s)
```

```text
obs-4bcc9691dc01e41d9981f1bb5ae812e64c2972b276b4179608c0fb5eace781e6: recorded planned reduction of case-748ec5056f5557ed to N2 was not recorded by 2026-09-11T16:00:00Z
recorded 1 response gap(s), skipped 0 already-recorded response gap(s)
```

It exits 3 when it recorded one and 0 otherwise, so a rerun appends nothing. A store with nothing
to record exits 0 and marks no schema. The first record marks the store schema 7, which an earlier
build refuses to open, and the first lapsed planned response marks it schema 8, which a build that
knows only schema 7 refuses to open; a store that records only the two earlier kinds stays at 7.
A recorded gap reaches a report from the store at once, but it is not a case
until `cases correlate` runs. These stop the run with exit 1 and append nothing:

| Refusal | Code |
|---|---|
| A store that does not exist | `store_missing`; no store is created |
| An `--as-of` that does not parse or names an instant outside the years 1970 through 9000 UTC | `invalid_input` |
| An unknown `--calendar-tz` | `invalid_option` |
| A response gap stream that is not whole, or holds an event its kind does not carry | `history_invalid` |
| A case, stale or not, that records a disposition and no evaluation, which a report from the store also refuses; a build at `09193ab` ran past it | `disposition_without_evaluation` |
| A record this run would append that opens a group under an id another record already publishes, such as a provider override equal to its correlation id | `tracking_id_collision` |

`--db`, `--class`, and `--as-of` are required, so leaving one out is a usage error with exit 2.

For the Python API (`complyroll.adapters`, `complyroll.policy`, `complyroll.schemas`, and
`complyroll.store`), see the Python API section of [`examples/README.md`](../examples/README.md).
