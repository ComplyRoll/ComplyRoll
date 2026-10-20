# Reference CI gate

A GitHub Actions workflow and a POSIX `sh` gate script that compile the three VER reports from
scanner artifacts, validate each one, and turn ComplyRoll's exit codes into one job result. The
design is recorded in [ADR 0017](../../docs/decisions/0017-ci-exit-criteria.md). Everything here
runs on the synthetic fixtures in this repository; nothing describes a real system.

- `complyroll-reports.yml` is the workflow. It sits outside `.github/`, so it never runs here.
- `complyroll-gate.sh` holds every command and the verdict. The workflow only sets inputs and
  calls it, so a local run and a test run exactly what the workflow runs.

## What the gate does

The gate compiles `report vdt`, `report avi` and `report historical` on the stateless path, writes
each as JSON with its Markdown twin, and runs `complyroll validate` on each JSON file against its
pinned official schema. It reads exit codes only. It never reads standard error, a report's JSON,
severity, CVSS or a count.

| Gate exit | Meaning |
|---|---|
| 0 | Every report compiled and validated, and none holds a system-generated record. Under `warn-gaps`, also a run whose only system-generated records are coverage gaps; it adds one warning annotation. |
| 1 | A command refused its input, a report failed schema validation, ComplyRoll is not installed, or a gate input is wrong. `diagnostics.log` in the output directory holds every command's standard error. |
| 3 | A system-generated `VDR-CSO-FAV` record the policy fails on: a detection process failure (ADR 0014), or a coverage gap (ADR 0015) under the default policy. |

Each command's own exit codes are listed under
[Exit status](../../docs/CLI.md#exit-status) in `docs/CLI.md`.

## What a clean job means

A clean job means the reports compiled, each one is valid against its official schema, and none
holds a detection process failure or, when an inventory is named, a coverage gap. It is not a
FedRAMP determination and not evidence that any KSI is met. Open findings, overdue records and
KEV past-due records do not change the result. They are in the uploaded reports and their
Markdown twins, where a person reads them.

## Copying it into a repository

Copy `complyroll-reports.yml` to `.github/workflows/` and `complyroll-gate.sh` to
`examples/ci/complyroll-gate.sh`, the path the gate step runs. Then replace the fixture paths on
the gate step with your own artifacts and set the inputs in the job's `env:` block.

Artifacts are the script's arguments, so paths with spaces and shell globs both work:
`sh examples/ci/complyroll-gate.sh scans/*.cklb "scans/host one.ckl"`. An argument that starts
with `-` would read as an option, so the gate refuses it; prefix such a path with `./`.

Every other input is an environment variable:

| Variable | Required | Default or values |
|---|---|---|
| `CR_OUT` | no | `complyroll-reports`. Must not exist yet, or must be an empty directory. |
| `CR_CLASS` | yes | The certification class, for example `C`. |
| `CR_PACKAGE_URI` | yes | The package URI the reports name. |
| `CR_FROM`, `CR_TO` | yes | The report period. In a recurring job, derive it per run. |
| `CR_AS_OF` | no | Unset: the gate takes one UTC instant at start and hands it to every call. |
| `CR_DETECTED_AT` | no | Unset. An attestation that is true for this run only. |
| `CR_CALENDAR_TZ` | no | Unset, which the CLI reads as UTC. The IANA calendar for month and year arithmetic. |
| `CR_EVALUATIONS` | no | Unset. An evaluations file. |
| `CR_KEV` | no | Unset. A CISA KEV catalog file the operator supplies. |
| `CR_INVENTORY` | no | Unset. An inventory file; turns on coverage gap records. |
| `CR_SYSTEM_RECORDS` | no | `fail` (the default) or `warn-gaps`. |

The gate deletes nothing. It refuses an output directory that already holds files, so a refused
run never uploads an earlier run's reports as its own. A GitHub-hosted runner starts each job in
a fresh workspace, so the default directory is empty there; a local rerun needs a new `CR_OUT`.

When `CR_AS_OF` is unset, the gate resolves one UTC instant, to the second, before the first
command and hands it to all of them. The three reports of one run therefore agree on their
as-of, their overdue flags and their coverage windows.

`CR_DETECTED_AT` is needed only for untimed sources such as CKL and CKLB, which carry no
assessment time; without it they refuse with `detection_time_missing`. It attests that every
untimed finding in this run was detected at that instant. A constant in a recurring job would
attest that every later finding was detected on one fixed date, which is false and moves its
clocks. Set it per run from when the scan actually ran, and drop it for timed sources such as
SARIF, which declare their own clock.

The sample workflow fixes `CR_FROM`, `CR_TO`, `CR_AS_OF` and `CR_DETECTED_AT` because the
synthetic fixtures need them. In a real job, remove `CR_FROM` and `CR_TO` from the `env:` block and
set them in a step before the gate, for example the previous calendar month:

```yaml
      - name: Report period
        run: |
          python - >> "$GITHUB_ENV" <<'EOF'
          from datetime import datetime, timedelta, timezone
          start_of_month = datetime.now(timezone.utc).replace(
              day=1, hour=0, minute=0, second=0, microsecond=0
          )
          end = start_of_month - timedelta(seconds=1)
          start = end.replace(day=1, hour=0, minute=0, second=0)
          print(f"CR_FROM={start:%Y-%m-%dT%H:%M:%SZ}")
          print(f"CR_TO={end:%Y-%m-%dT%H:%M:%SZ}")
          EOF
```

The run line holds no `${{` expression, which keeps the workflow's rule that inputs reach a
shell only through the environment.

## Why `--record-failed-imports` is always set

Without the flag, a scanner log that reports a failed invocation compiles with WARNING
`execution_unsuccessful` and exits 0, so a broken scanner would leave the job green. With it, the
failure becomes a `VDR-CSO-FAV` record and the report exits 3. A CI job must set the flag, and
the gate always does (ADR 0017 Decision 5). The default stays as it is for other callers.

## Inventories and the policy

With `CR_INVENTORY` set, the gate also adds `--inventory` and `--record-coverage-gaps`, so each
coverage window that closed with no verification becomes a record of its own and the report exits
3. A gap records an absence of verification inside the window. It is not a finding that the
resource has a vulnerability.

A report exit of 3 then has two possible causes, so the gate runs one more command when it sees
one: a failure-only `report historical` with the artifacts and none of the evaluations, the KEV
catalog or the inventory, discarded to `/dev/null`. Detection process failures come from the
artifacts alone, so that command exits 3 only when a failure was recorded, and exits 0 when the
main exit 3 was gaps alone.

`CR_SYSTEM_RECORDS` decides what a gap does. Under `fail`, the default, any system-generated
record fails the job. Under `warn-gaps`, a run whose only records are coverage gaps exits 0 with
one warning annotation, and a detection process failure still exits 3: `warn-gaps` never lets a
broken scanner through.

A system-generated record still fails the job under `fail` after an evaluation accepts or closes
it, for as long as the artifact or window that produced it is in the inputs. The remedies are
removing the failed artifact from the inputs, `warn-gaps` for gaps, or `continue-on-error` on the
job.

Evaluations change in step with the artifacts. An evaluation whose finding has left the inputs, a
dropped host or a rescanned artifact for example, refuses with `evaluation_unmatched` and the job
exits 1 until the evaluations file is edited.

## Records outside the period

Every exit-3 message points at `historical.json` in the uploaded artifact. It is a snapshot as of
the run's as-of with no period, so it lists every record, including a record detected after
`CR_TO`, which the detail report leaves out with INFO `excluded_by_period` and which still counts
for exit 3. Failures are under `x-complyroll.detectionFailures` and gap windows under
`x-complyroll.coverage.windows`.

## Why the stateless path

The gate compiles each report straight from the artifacts and does not keep a store. On a fresh
runner a store holds no history, and a store carried from run to run loses the signal the gate
reads: `report --db` never exits 3, a `cases coverage` rerun that finds every gap already recorded
exits 0, and an `ingest --record-failed-imports` rerun exits 3 again for a failure it already
holds. A fresh store per run adds about six commands and nothing the stateless compile lacks.

The stateless path gives up two things a store keeps:

- **A first-detection time across runs.** Only a store carries an untimed finding's detection
  time from one run to the next, which is why `CR_DETECTED_AT` is true for one run only.
- **Evaluations that outlive their findings.** On the stateless path an evaluation refuses once
  its finding leaves the inputs.

A persisted variant ingests into a store kept between runs, evaluates there, and reports with
`--db`. Because `report --db` answers 0 or 1 only, that variant reads the records instead of an
exit code: `x-complyroll.detectionFailures` and `x-complyroll.coverage.windows[].recorded` in the
report. It is where evaluations outlive artifacts. The persisted commands are in
[`examples/README.md`](../README.md).

## Overdue records and KEV clocks

The gate does not fail on overdue records or on KEV due dates (ADR 0017 Decision 7). Overdue
mixes MUST and SHOULD clocks. Gap and failure records go overdue too, so failing on both would
count one record twice. An accepted record past its KEV date reads `pastDue: true` and
`isOverdue: false`. Clocks also move without a commit, so a pull-request job would turn red
overnight with no change.

The follow-up recorded in ADR 0017 is a separate reader of the official fields only,
`overdueStatus.isOverdue` and `x-complyroll.kev.pastDue`, run on a schedule and never on pull
requests, recomputing no clock.

## Security posture

- The workflow grants `contents: read` and nothing else. It has no `pull_request_target`, uses no
  secrets and requests no `id-token`, and checks out with `persist-credentials: false`.
- Every action is pinned to a full commit SHA, the same pin this repository's own workflows use.
- No `run:` line holds a `${{` expression. A value derived from the event goes in `env:`, for
  example `CR_SYSTEM_RECORDS: ${{ github.event_name == 'schedule' && 'fail' || 'warn-gaps' }}`,
  and reaches the script as an ordinary variable.
- Nothing after the install step needs the network. The rules dataset and the schemas are bundled
  and checked by SHA-256, and the KEV catalog and the inventory are local files.
- The job summary holds the gate's own fixed text only: the verdict, one exit line per command and
  a closing disclaimer. The reports and their Markdown twins carry scanner-supplied text whose
  Markdown link and image syntax is not neutralized ([`docs/SECURITY.md`](../../docs/SECURITY.md)),
  and GitHub renders the summary as Markdown, so they go only into the uploaded artifact.
- Gate messages are fixed text and never echo an input value, a path or report content.

## The install pin

The workflow installs ComplyRoll from a pinned commit on `main` that carries the exit behavior the
gate reads. No published pre-release carries ADR 0017 yet. Once one does, switch the install step
to an exact version in pip's hash-checking mode, with `--require-hashes` and a requirements file
that pins ComplyRoll and its dependencies by hash.

## A non-blocking trial

To watch the gate before it can block a merge, set `continue-on-error: true` on the job. A gate
exit of 1 or 3 then no longer fails the workflow run, and the step log and the uploaded reports
are the same as in a blocking run.
