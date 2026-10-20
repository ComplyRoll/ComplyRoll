# ADR 0017: CI exit criteria and a reference workflow

- Status: Accepted
- Date: 2026-10-19

## Context

Phase 2 of the build plan lists CI-friendly exit criteria and a reference GitHub Actions
workflow. A CI job can read three things from ComplyRoll without parsing a report: the exit
status, the lines on stderr, and the files written. Only the exit status is a contract today, and
it is written down in one paragraph of `docs/CLI.md`, not as a table a pipeline author can check
command by command.

ADR 0014 Decision 11 gave exit 3 to a run that recorded a detection process failure, and ADR 0015
Decision 30 widened it to a run whose output holds any system-generated `VDR-CSO-FAV` record: a
detection process failure or a coverage gap. Two questions were deferred to this deliverable. ADR
0015 Decision 30 deferred a separate exit code for gaps (its open decision 3, option b). ADR 0014
said, in its rejected alternatives, that the `--record-failed-imports` default "can flip with the
CI exit criteria deliverable". No release carries exit 3: the only tag, `v0.3.0a0`, predates both
ADRs.

Three facts shape the answer. No exit code reflects overdue records or CISA KEV clocks: the
synthetic sample exits 0 with five overdue records, and the KEV sample exits 0 with five records
past a KEV due date. Every ERROR diagnostic the compiler builds stops the run as a
`ReportCompileError`, exit 1 with nothing written, so no written report carries one; but that is
observed, not enforced where reports are written. And without `--record-failed-imports` a failed
scanner invocation is an execution-class failure that stays WARNING `execution_unsuccessful` and
exits 0 (ADR 0014 Decision 3), so a CI job that omits the flag passes a broken scanner.

The original intent for the reference was an example that ingests, compiles all three reports,
validates them, and fails the job on ERROR diagnostics.

Nothing in this record changes what ComplyRoll is: it compiles evidence and reports it. A green CI
job is not a FedRAMP determination, does not show that any KSI is met, and is not a statement that
an authorizing official or FedRAMP has approved anything.

## Decision 1: the exit contract is written down and unchanged

`ingest`, every `cases` subcommand and `store verify` require `--db`, so only `report` has a
stateless and a persisted path. Code 2 is an argparse usage error on every command, including a
`report` whose artifacts are split around options, because the artifacts are one `nargs="*"` run.

| Command | Path | 0 | 1 | 3 |
|---|---|---|---|---|
| `version`, `plan` | none | always | an uncaught exception only | never |
| `ingest` | store | stored, or nothing new; also an execution-class failure without `--record-failed-imports`, which stays WARNING `execution_unsuccessful` (ADR 0014 Decision 3) | a refusal; a fatal-class failure without the flag; with the flag, a failure ADR 0014 Decision 2 keeps fatal, and the one rerun that meets a superseded holder (ADR 0014 Decisions 11 and 13); a mapped domain exception | with the flag, a failure recorded or found already recorded, reruns included |
| `cases correlate`, `attest-detection`, `evaluate`, `list`, `history` | store | success; `attest-detection` and `evaluate` may print `warning:` lines | a refusal, a missing store, a mapped domain exception | never |
| `cases coverage` | store | this run recorded no gap, including a rerun that finds every gap already recorded | a missing or second inventory, a missing store, a parse failure | this run recorded at least one gap |
| `report vdt\|avi\|historical` | stateless | published with no flagged record; `--inventory` alone; an execution-class failure without the flag (WARNING) | a pre-flight refusal; a `ReportCompileError`, which carries every ERROR; a publish failure; `error_diagnostic_unpublished` (Decision 2) | published, and `--record-failed-imports` with a failure or `--record-coverage-gaps` with a gap, once with both; a record outside the report period still counts (ADR 0015 Decision 31) |
| `report ... --db` | store | published, even when the store holds failures and gaps | the same refusals, and either record flag beside `--db` | never |
| `store verify` | store | `ok: N event(s) verified`, failures and gaps included | an integrity or domain fault, a missing store | never |
| `validate` | file | `valid: ID VERSION SHA256` | unreadable, too large, malformed, or schema-invalid; schema issue lines carry no `error:` prefix; `x-complyroll` is never read | never |
| `stigroll` | files | any input yielded findings, even when others failed to parse | no findings, a bad CCI list, an `-o` failure as a traceback | never |

Outside the contract: exit 1 with a traceback for an uncaught `ValueError` or `TypeError`, 120
when stdout is closed at interpreter flush, 130 on SIGINT, and a `BrokenPipeError` raised inside
an action, which reads as `store_unavailable`.

Five invariants hold:

- **I1.** No written report, and no exit 0 or 3, carries an ERROR diagnostic. Every ERROR the
  compiler builds raises `ReportCompileError`; a recorded failure carries its ERRORs demoted to
  WARNING; replay refuses a stored ERROR; and from this record `_publish` refuses one too
  (Decision 2). So "fail the job on ERROR diagnostics" is part of "fail on exit 1". Exit 1 also
  covers refusals, publish failures and schema-invalid output, and is never described as ERROR
  alone.
- **I2.** Exit 3 comes from three places only: a stateless `report` with its flag, `ingest
  --record-failed-imports`, and `cases coverage`.
- **I3.** Overdue state, KEV clocks, WARNING and INFO diagnostics, and `--inventory` alone never
  change an exit code.
- **I4.** `report --db` answers 0 or 1 only (ADR 0014 Decision 11, ADR 0015 Decision 30).
- **I5.** No exit code depends on scanner severity or CVSS. The adapters read and normalize
  severity, and no exit decision uses it.

The test that asserts a fresh-store `ingest` exiting 3 prints no ERROR is one `ingest` pin, not a
general proof of I1. The general proof is the property test of Decision 10.
Why: a CI job needs a contract it can read command by command, and the existing one is complete
for refusals and for system-generated records. Writing it down changes no caller.

## Decision 2: a compiled report carrying an ERROR is never written

`_publish`, the only writer of a report, checks the compiled report's diagnostics after writing
them to stderr and before rendering anything. If any is an ERROR, it refuses with
`error_diagnostic_unpublished`, exit 1, and writes no file. No current input reaches the branch:
a test reaches it with a stub report, and every existing test and golden is unchanged.
Why: I1 is what makes "fail on ERROR" part of "fail on exit 1", so it should be enforced at the
writer rather than only observed. Because nothing reaches the branch today, the change is visible
only for an input that cannot yet exist, and CHANGELOG says so.

## Decision 3: coverage gaps keep exit 3

ADR 0015 open decision 3, option b, a separate exit code for gaps, is not built. Exit 3 keeps
meaning that the output holds a system-generated `VDR-CSO-FAV` record of either kind.
Why:
- A single status cannot say "both" without hiding one kind or growing combinatorially. A gap
  code needs a precedence rule that hides gaps whenever a failure exists, and response-process
  failures, a later deliverable, would be a third kind.
- The report already tells the kinds apart per record, on both paths:
  `x-complyroll.detectionFailures` for failures and `coverage.windows[].recorded` with
  `trackingId` for gaps.
- ADR 0015 Decision 30 gave gaps exit 3 because a gap is a failure of the detection process under
  the same rule. A gap code would reverse that reason.
- A gap code would still not reach `report --db` (I4) or a `cases coverage` rerun, which exits 0,
  so a persisted CI job would gain nothing.
- The need behind it, failing on a broken scanner while tolerating a lapsed schedule, is met by the
  reference gate's `warn-gaps` policy (Decision 6) without a code change.

The counterpoint is recorded: no release has carried exit 3, so a gap code would break no released
caller. It is rejected on the reasons above, not on compatibility.

## Decision 4: both record flags stay opt-in

`--record-failed-imports` and `--record-coverage-gaps` stay off by default. There is no CI profile
flag, and the package reads no environment variable. This closes ADR 0014's deferral as not
flipped; ADR 0014 Decisions 3 and 11 are unchanged.
Why:
- Flipping `--record-failed-imports` would change callers three ways: a fatal-class artifact would
  go from exit 1 with nothing written to a written report with exit 3; an execution failure would
  go from 0 to 3; and on `ingest`, a failure held by a superseded stream would turn an exit 0 into
  exit 1. It would also mark stores schema 2 or 3, which earlier builds refuse to open.
- Both flags are on/off switches with no negative form, so a flip needs a negation flag, which is
  new surface.
- `--record-coverage-gaps` needs `--inventory`. On by default, it would either refuse every run
  without an inventory or silently not apply, and it would move every `--inventory` caller from 0
  to 3.
- A CI profile flag has the same half-application problem, would be refused beside `--db`, and
  would bundle two auditable choices under one word.
- An environment variable would be the first one the package reads, so a runner's leaked
  environment could change exit codes, which is the definition of a silent change.

## Decision 5: a CI job passes `--record-failed-imports`

Without the flag, a failed scanner invocation exits 0 with WARNING `execution_unsuccessful` (ADR
0014 Decision 3, unchanged). The reference gate always passes the flag, `docs/CLI.md` and
`examples/ci/README.md` say a CI job must, and a reference test shows the gate catches an
execution-only failure because of it.
Why: Decision 4 keeps the default, so the hazard is closed where CI is configured rather than by
changing every caller.

## Decision 6: the reference gate reads exit codes only

`examples/ci/complyroll-gate.sh` compiles the three reports on the stateless path, validates each
against its pinned official schema, and turns the exit codes into one verdict. It never reads
stderr, a report's JSON, severity, CVSS or a count. It always passes `--record-failed-imports`, and
passes `--inventory` with `--record-coverage-gaps` when the operator names an inventory.

| Signal | Gate exit |
|---|---|
| a gate input is wrong: a bad policy value, a missing required input, no artifact, an artifact argument starting with `-`, or an output directory that exists and is not empty (Decision 9) | 1, before any ComplyRoll command |
| any `report` or `validate` exit other than 0 or 3, or ComplyRoll missing | 1 |
| a report exit 3 with no inventory given | 3, a detection process failure |
| a report exit 3, an inventory given, the probe exits 3 | 3, a detection process failure, with gaps possibly also recorded |
| a report exit 3, an inventory given, the probe exits 0, policy `fail` | 3, a coverage gap |
| the same, policy `warn-gaps` | 0, with a warning annotation |
| the probe exits other than 0 or 3 | 1 |
| overdue records, KEV past due, WARNING, INFO | not gated |

The policy has two values. `fail`, the default, fails the job on any system-generated record.
`warn-gaps` turns a coverage gap into a warning and still fails on a detection process failure.

Every report call and the probe carry one `--as-of`. When the operator sets none, the gate
resolves one UTC instant at start, at second precision, and passes it to every call. Without
that, each command would take its own current instant, and the three reports of one run would
disagree on as-of, overdue flags, coverage windows and failure instants, though every projection
must come from the same records.

To tell a failure from a gap without reading JSON, the gate runs one failure-only probe, only when
an inventory was given and a report exited 3. It is one `report historical` to stdout, discarded,
with the artifacts, `--class`, `--package-uri`, `--as-of`, `--detected-at`, `--calendar-tz` and
`--record-failed-imports`, and nothing else. Its exit 3 means a detection process failure; its
exit 0 means the main run's exit 3 was gaps alone. It omits `--evaluations` because an evaluations
file that evaluates a gap record refuses with `evaluation_unmatched` once the gap is not recorded,
and it omits the KEV catalog and the inventory because neither can produce a failure. The probe
relies on one compiler property: detection process failures come from the artifacts alone,
independent of the evaluations, the KEV catalog and the inventory. A reference test pins it by
checking, wherever the probe runs, that the probe's verdict equals the presence of
`detectionFailures` in that run's historical report.

Every message is fixed text. The gap message says that a window closed with no verification, and
that a gap records an absence of verification, not a vulnerability in the resource. Every exit-3
message names where the records are: the historical report in the uploaded artifact, which lists
every record, including any detected after `--to` that the detail report leaves out. The job
summary carries only the gate's own text: the verdict, one exit line per command, and the
disclaimer. It never carries a report or its Markdown twin. It ends with one fixed sentence:
"This gate reads ComplyRoll exit codes only. Its result is not a FedRAMP determination and not
evidence that any KSI is met; open, overdue and KEV past-due records are not gated (ADR 0017)."
No gate-emitted line uses the words pass, passed, passes, passing, compliant, compliance,
approved, approval, certified or authorized, and a test enforces it.
Why: the exit codes Decision 1 freezes are the only stable interface, so a copied script that
reads only them stays correct. The probe keeps the policy in exit codes while letting an operator
tolerate a lapsed schedule without passing a broken scanner.

## Decision 7: overdue records and KEV clocks are not a CI failure condition yet

The gate does not fail on overdue records or on KEV clocks. They are visible in the uploaded
reports and their Markdown twins.
Why:
- Overdue mixes MUST and SHOULD clocks; every overdue record in the synthetic sample is SHOULD.
- Gap and failure records go overdue on VER-TFR-EVU as well, so failing on overdue and on system
  records would count the same record twice.
- An accepted record past its KEV due date reads `pastDue: true` and `isOverdue: false`.
- The per-deadline clocks carry no past-due flag, so a MUST-only gate would recompute a clock
  outside the pinned rules provenance.
- Clocks move without commits, so a pull-request job would turn red overnight with no change.

## Decision 8: the reference compiles on the stateless path

The reference compiles each report directly from the artifacts. It does not `ingest` into a store
and report with `--db`.
Why: on an ephemeral runner a store holds no history, and a store carried across runs loses the
gap signal, because `report --db` never exits 3 and a `cases coverage` rerun exits 0. A fresh
store per run adds about six commands and nothing the stateless compile lacks. This departs from
the original intent's word "ingests", and the reference README describes the persisted variant in
prose: read `detectionFailures` and `coverage.windows[].recorded` in the report.

The stateless path gives up two things a store keeps, and the reference README says so:
- **A first-detection time across runs.** Only a store carries an untimed finding's detection
  time from one run to the next. Untimed sources such as CKL and CKLB need `--detected-at` or
  refuse with `detection_time_missing`, so the gate's `CR_DETECTED_AT` is an operator attestation
  that is true for that run only. A constant in a recurring job would attest that every later
  finding was detected on one fixed date, which is false and moves its clocks. Operators drop it
  for timed sources and derive the report period per run, for example in a prior step that appends
  `CR_FROM` and `CR_TO` to `$GITHUB_ENV`. The sample workflow keeps fixed values, marked as the
  synthetic fixtures' own.
- **Evaluations that outlive their findings.** An evaluation whose finding has left the inputs
  refuses with `evaluation_unmatched`, exit 1, so a dropped host or a re-scanned artifact turns
  the job red until the evaluations file changes in step. The persisted variant is where
  evaluations outlive artifacts.

## Decision 9: reference hardening and the install pin

The reference workflow `examples/ci/complyroll-reports.yml`:
- grants top-level `contents: read` only, with no job-level `permissions`, no
  `pull_request_target`, no secrets and no `id-token`, and checks out with
  `persist-credentials: false`;
- pins every action to a full commit SHA equal to this repository's own pin for that action;
- puts no `${{` expression in a `run:` line, so inputs reach the gate only through `env:`;
- uploads the reports with `if: always()`, `if-no-files-found: warn` and `retention-days: 30`;
- needs no network after install, because the rules and schemas are bundled and verified by
  SHA-256, and the KEV catalog and inventory are local files;
- installs ComplyRoll from a pinned git commit on `main` that carries the exit behavior the gate
  reads, Decisions 1 and 3 to 8 (the base commit of the change that adds this record, so not
  Decision 2's guard, which no input reaches), until a pre-release carries this record; the README
  tells adopters to switch then to an exact, hash-checked PyPI pin.

The gate script is POSIX `sh`, takes the artifacts as its arguments so paths with spaces and globs
work, and runs under dash and bash. The workflow runs it from `examples/ci/`, the path its header
tells adopters to copy it to, so a test runs exactly what the workflow runs. The script:
- refuses, before any ComplyRoll command, an artifact argument that starts with `-`, which would
  parse as an option, and says to prefix the path with `./`;
- deletes nothing, and refuses an output directory that exists and is not empty, so a refused run
  never uploads an earlier run's reports as its own and the CLI's refusal of a symbolic-link
  output still applies;
- writes the job summary only when `GITHUB_STEP_SUMMARY` is set and non-empty, so a local run
  under `set -u` still reaches its verdict;
- puts no report text in the job summary. Each Markdown twin carries scanner-supplied text whose
  link and image syntax is not neutralized (`docs/SECURITY.md`), and GitHub renders the summary as
  Markdown, so the twins go only into the uploaded artifact.
Why: a reference is copied as written, so it should be safe to copy. A git commit pin is the only
install line that works today against a build with this contract.

## Decision 10: a test keeps the reference honest

`tests/test_reference_ci.py` runs in the existing 3.11 to 3.14 matrix, with no new CI job. It runs
the gate script through a `complyroll` shim over scenarios that reproduce ten existing golden pairs
byte for byte: `vdt-fixtures`, `avi-fixtures`, `historical-fixtures`, `vdt-coverage-gaps`,
`historical-coverage-gaps`, `vdt-failed`, `historical-failed`, `vdt-kev`, `avi-kev` and
`historical-kev`. It asserts that no ComplyRoll invocation exits 2, pins the probe property, pins
the workflow and the script as text (permissions, SHA pins equal to the repository's own, no `${{`
in a run line, no `rm`, POSIX constructs only), asserts that the job summary holds gate text and
no line of any twin, that every call shares one as-of, and that a stale evaluation, a used output
directory and an argument starting with `-` each exit 1, runs the wording test, and kills a named
list of mutants.
`tests/test_exit_contract.py` pins Decision 2 with a stub report, scans every golden for an ERROR
diagnostic, checks that every golden run exiting 0 or 3 prints no `error:` line, and pins each row
of the Decision 1 table not pinned elsewhere.
Why: the workflow never runs in this repository's CI, so a test that runs its script and reads its
text is what stops it from drifting from the code.

## Decision 11: `ruff check` and `mypy` run in CI; format checking waits

`ci.yml` gains a `lint` job on Python 3.11 that installs the package and the pinned tools from a
root `requirements-lint.txt` and runs `ruff check src tests stigroll.py` and `mypy`. Both are clean
today. The job landed ahead of the rest of this record, in its own change, and is a required
check on `main`. `ruff format --check` is not added: thirty files are not `ruff format` clean
under ruff 0.16.6, the same count at each of the four earlier merges checked back to the README
reorganization, and reformatting them is its own change.
Why: the lint and type gates `CONTRIBUTING.md` names should be enforced, and a mass reformat
inside this record would hide its real changes.

## Decision 12: known exit edges stay as they are

Four edges are documented in the Decision 1 table, pinned as they are, and left for later:
`stigroll` exits 0 when one input yields findings and another fails to parse; a `BrokenPipeError`
inside an action reads as `store_unavailable`; `validate` prints schema issue lines without an
`error:` prefix; and an `ingest` rerun exits 3 while a `cases coverage` rerun exits 0.
Why: each has callers, and this record changes no caller.

## Worked examples

All runs use the synthetic fixtures under `tests/fixtures/` and `examples/`, package URI
`https://example.test/cpo`, class C, and the period and as-of the goldens fix.

**A green run.** The reference workflow's defaults compile `ubuntu-host.cklb`, `windows-host.ckl`
and `openscap-results.xml` with `examples/evaluations-accepted.json`. Each report exits 0, each
validates, and the gate exits 0. The accepted and historical reports equal `avi-fixtures` and
`historical-fixtures` byte for byte. Any overdue record in the reports leaves the verdict as it
is (Decision 7). The job summary shows the verdict, the six exit lines and the disclaimer, and no
report text. With `CR_AS_OF` unset, the gate resolves one instant and every call carries it.

**A failure.** Adding `failed-truncated.sarif`, `failed-invalid-rules.cklb` and
`failed-invocation.sarif`, with `examples/evaluations-failed.json`, records three detection
process failures. Each report exits 3, and with no inventory named the gate exits 3 with the
failure message; the detail and historical reports equal `vdt-failed` and `historical-failed`.
`failed-invocation.sarif` alone shows Decision 5: without `--record-failed-imports` the report
exits 0 with WARNING `execution_unsuccessful`, and through the gate, which always passes the flag,
it exits 3.

**A refusal.** `ubuntu-host.cklb` alone with `examples/evaluations.json`, whose evaluations name
findings from the other two checklists, makes each report refuse with `evaluation_unmatched`, and
the gate exits 1 with no report written (Decision 8).

**Gaps under `fail`.** The three checklists with `examples/evaluations.json` and
`examples/inventory.json` record coverage gaps and no failure. Each report exits 3, the probe exits
0, and the gate exits 3 with the gap message; the detail report equals `vdt-coverage-gaps`. A gap
here records that ComplyRoll found no verification inside a window, not that a resource has a
vulnerability.

**Gaps under `warn-gaps`.** The same inputs with `examples/evaluations-coverage.json`, which
evaluates a gap record, still make each report exit 3. The probe exits 0, because the failure-only
compile carries no evaluations, and the gate exits 0 with one warning annotation. With the failed
fixtures added under `warn-gaps`, the probe exits 3 and the gate exits 3: `warn-gaps` never passes
a broken scanner.

## Consequences

- A pipeline author reads one exit table, and no existing caller changes.
- A report carrying an ERROR can never be written, though no input produces one today. A future
  feature that wants such a report must amend Decision 2.
- A CI job that omits `--record-failed-imports` still passes a failed scanner invocation; the
  reference and the docs are what prevent it.
- The CI policy lives in a copied shell script. A correct copy stays correct, because it reads only
  the frozen exit codes; an operator's modified copy is the operator's.
- The `warn-gaps` policy depends on failures coming from the artifacts alone. A compiler change
  that breaks that fails the probe parity test.
- A store carried across CI runs loses the gap signal. The persisted variant reads the report
  instead.
- The reference installs from a git commit, which bypasses PyPI trusted-publishing provenance
  until a pre-release carries this record.
- Every dependabot actions bump turns the reference's pin test red until `examples/ci/` follows,
  one extra commit per bump.
- The reference test adds about 100 to 120 seconds to each matrix leg, estimated from local runs.
- The reference installs a commit without Decision 2's guard. The copied gate behaves the same,
  because no input reaches the guard.
- The install resolves `setuptools` and `jsonschema` with its extra, about nineteen
  distributions, from the network without hashes, so it is neither reproducible nor
  hash-verified; the lock-file item in `docs/SECURITY.md` covers it.
- The workflow text test checks the install line's shape only, so a nonexistent commit or one
  before the exit contract passes, and nothing in this repository runs the workflow or its install.
- Probe parity is pinned on the scenarios the test lists. A change that breaks probe independence
  for a shape they do not cover would pass.
- Under `fail`, a system-generated record the operator already accepted or closed by evaluation
  still fails the job while its artifact stays in the inputs. The remedies are removing the
  failed artifact, `warn-gaps` for gaps, or `continue-on-error` on the job.
- Every compile already validates its report against the pinned schema before writing it, so the
  gate's `validate` re-checks the bytes on disk through the public command; the test reaches a
  failing `validate` only through its shim.
- A ruff or mypy release can turn CI red with no code change; each bump is its own reviewed change.
- The lint job pins ruff and mypy exactly but without hashes, and their own dependencies, like the
  package's, resolve unpinned. A later move to hashes installs a hashed lint lock first and then
  the package with `--no-deps` as a separate step, because pip's hash-checking mode refuses a
  local directory requirement in the same call.

## Left for later

- Overdue and KEV gating: an opt-in reader of official fields only, `overdueStatus.isOverdue` and
  `x-complyroll.kev.pastDue == true` on every record, run on a scheduled trigger and never on pull
  requests, recomputing no clock, in a versioned CLI surface with its own record. The KEV field is
  `pastDue`, never `status`, because an accepted record past its date keeps `status: "accepted"`.
  The overdue reader settles SHOULD versus MUST before it reads `overdueStatus.isOverdue`.
- Reformatting the thirty files that are not `ruff format` clean, then adding `ruff format --check`
  to CI.
- The stale comment in the test that asserts only the flag turns recorded failures into exit 3,
  which still reads "Until `ingest` records failures into a store".
- The four known exit edges of Decision 12.
- An exact, hash-checked PyPI pin in the reference at the next pre-release; until then, a
  follow-up commit can move the git pin to the commit that carries Decision 2.
- An install-line check that the pinned commit descends from the exit contract, when the test
  runs inside a git checkout, and one run of the copied workflow in a throwaway repository before
  the reference is announced.
- Probe parity scenarios for a failed artifact read under another name, two names for one failed
  digest, and a failure record evaluated closed.

## Rejected alternatives

- Exit 4 for gap-only runs, with 3 winning: hides gaps whenever a failure exists, reverses ADR 0015
  Decision 30's reason, and still misses `report --db` and reruns.
- A `complyroll gate` command that reads the reports and decides: a second policy calculation,
  since deciding MUST-only overdue means recomputing per-deadline past-due.
- `validate --fail-on` with new codes for overdue and KEV: counts SHOULD clocks and counts system
  records twice.
- A `--ci` profile flag: refused beside `--db`, and two auditable choices under one word.
- An environment variable that sets either flag: the first environment read in the package, so a
  leaked runner environment could change exit codes.
- Flipping either record flag's default: changes existing callers (Decision 4).
- A `warn` policy value that warns on every system record: passes a broken scanner.
- An `evidence` policy value that passes `--inventory` without the gap flag: gap cases are never
  recorded, and an evaluations file that evaluates a gap record refuses.
- Reading `detectionFailures` from the JSON in the gate script: couples a copied script to the
  extension's shape and puts policy in shell.
- A `ci.yml` job or smoke step that runs the reference: duplicates the workflow's inputs in a
  second file that can drift, while the console-script wrapper is already exercised.
- A bash script with arrays: needs a bash 3.2 empty-array idiom that fails.
- A `complyroll==0.3.0a1` pin in the reference: fails at install until that tag exists.
- Appending the historical report's Markdown twin to the job summary: puts scanner-supplied text,
  whose link and image syntax is not neutralized, on a page GitHub renders.
- Deleting earlier outputs before each compile: removes a symbolic-link destination before the CLI
  can refuse it, and destroys reports a refused run would otherwise leave in place.
- Letting each command take its own current instant when no as-of is given: the reports of one run
  disagree.
