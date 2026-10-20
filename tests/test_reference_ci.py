# ******************************************************************************
# *Title: Reference CI Tests*
# *Author: Kyle Versluis*
# *Description: Runs the reference CI gate through a shim and pins its text.*
# ******************************************************************************
"""Anti-rot tests for `examples/ci/`, the reference CI gate of ADR 0017 (Design 4.5)."""

# *--- Imports ---*

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import chdir
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from test_cli import (
    ACCEPTED_EVALUATIONS,
    EXAMPLE_INVENTORY,
    FAILED_ARTIFACTS,
    INVOCATION_FIXTURE,
    KEV_ARGUMENTS,
    KEV_ARTIFACTS,
    KEV_AS_OF,
    KEV_CATALOG,
    KEV_EVALUATIONS,
    KEV_PERIOD,
    PREVIOUS_REPORT,
    REPO_ROOT,
    REPORT_ARGUMENTS,
    run,
)
from test_coverage_gap_report import EXAMPLE_EVALUATIONS, GAP_FLAG
from test_coverage_history import COVERAGE_EVALUATIONS
from test_reports import FAILED_EVALUATIONS, GOLDEN, REPORT_KINDS

# *--- Configuration ---*

ROOT = REPO_ROOT.resolve()
#: The gate as the workflow runs it, relative to the repository root.
GATE = "examples/ci/complyroll-gate.sh"
GATE_SCRIPT = ROOT / GATE
WORKFLOW = ROOT / "examples" / "ci" / "complyroll-reports.yml"
WORKFLOW_NAME = "examples/ci/complyroll-reports.yml"
#: The repository's own workflows, whose action pins the reference must equal.
PIN_SOURCES = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "release.yml",
)
#: Seconds one gate run may take before it is treated as hung.
GATE_TIMEOUT = 300
#: Scenarios run side by side; each owns its directory, log and output.
WORKERS = max(1, min(4, os.cpu_count() or 1))
SH = shutil.which("sh")

# *--- Fixed Gate Text ---*

GAP_TEXT = (
    "A window closed with no verification. A coverage gap records an absence of "
    "verification, not a vulnerability in the resource."
)
CLEAN = (
    "Gate exit 0: each report compiled and validated against its pinned official schema, "
    "and none holds a system-generated record."
)
WARNED_GAP = (
    "Gate exit 0: a coverage gap was recorded (ADR 0015), and warn-gaps makes it a warning. "
    f"{GAP_TEXT}"
)
REFUSED = (
    "Gate exit 1: a command refused its input, or a report failed validation against its "
    "pinned official schema; see diagnostics.log in the uploaded artifact."
)
PROBE_REFUSED = (
    "Gate exit 1: the failure-only compile refused its input; see diagnostics.log in the "
    "uploaded artifact."
)
FAILURE_ONLY = "Gate exit 3: a detection process failure was recorded (ADR 0014)."
FAILURE = (
    "Gate exit 3: a detection process failure was recorded; coverage gaps may also be recorded."
)
GAP = f"Gate exit 3: a coverage gap was recorded (ADR 0015). {GAP_TEXT}"
WHERE = (
    "Every record is listed in historical.json in the uploaded artifact, under "
    "x-complyroll.detectionFailures and x-complyroll.coverage.windows, including any detected "
    "after the period end that vdt.json leaves out."
)
DISCLAIMER = (
    "This gate reads ComplyRoll exit codes only. Its result is not a FedRAMP determination and "
    "not evidence that any KSI is met; open, overdue and KEV past-due records are not gated "
    "(ADR 0017)."
)
VERDICTS = (CLEAN, WARNED_GAP, REFUSED, PROBE_REFUSED, FAILURE_ONLY, FAILURE, GAP)
#: The verdicts that name where the records are, on stdout and in the summary.
RECORD_VERDICTS = (WARNED_GAP, FAILURE_ONLY, FAILURE, GAP)
#: The see-also tail every gap annotation ends with (Forge F-14).
GAP_TAIL = (
    "a coverage gap was recorded, an absence of verification, not a vulnerability; see "
    "historical.json in the uploaded artifact."
)
FAILURE_ANNOTATION = (
    "::error::ComplyRoll gate exit 3: a detection process failure was recorded; see "
    "historical.json in the uploaded artifact."
)
#: The one annotation line each verdict prints; the clean verdict prints none.
ANNOTATIONS = {
    CLEAN: None,
    WARNED_GAP: f"::warning::ComplyRoll gate: warn-gaps makes this a warning; {GAP_TAIL}",
    REFUSED: (
        "::error::ComplyRoll gate exit 1: a command refused its input or a report failed "
        "schema validation; see diagnostics.log in the uploaded artifact."
    ),
    PROBE_REFUSED: (
        "::error::ComplyRoll gate exit 1: the failure-only compile refused its input; see "
        "diagnostics.log in the uploaded artifact."
    ),
    FAILURE_ONLY: FAILURE_ANNOTATION,
    FAILURE: FAILURE_ANNOTATION,
    GAP: f"::error::ComplyRoll gate exit 3: {GAP_TAIL}",
}
#: Every line the job summary may hold besides the exit lines and blanks.
SUMMARY_TEXT = frozenset({"## ComplyRoll gate", "```text", "```", WHERE, DISCLAIMER, *VERDICTS})
EXIT_LINE = re.compile(r"(?:(?:report|validate) (?:vdt|avi|historical)|failure probe): exit \d+")
INSTANT = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
AS_OF_LINE = re.compile(rf"as-of: (?:CR_AS_OF|{INSTANT}, resolved once at start)")
#: What the gate appends to `GITHUB_OUTPUT` once its inputs pass and `CR_OUT` exists.
STARTED = "started=true\n"
#: Approval language no gate-emitted line may carry (Design 3.3, Forge F-09): the listed
#: words, and any word starting `approv`, `authoriz` or `certif`.
BANNED = re.compile(
    r"\b(?:pass|passed|passes|passing|compliant|compliance)\b|\b(?:approv|authoriz|certif)\w*",
    re.IGNORECASE,
)

# *--- Scenario Inputs ---*


def option(argv: Sequence[str], flag: str) -> str:
    return argv[list(argv).index(flag) + 1]


#: The three base fixtures, as the golden runs name them.
BASE_ARTIFACTS = tuple(REPORT_ARGUMENTS[2:5])
#: The gate inputs every golden run over the base fixtures shares, read from its argv.
BASE_INPUTS = {
    "CR_CLASS": option(REPORT_ARGUMENTS, "--class"),
    "CR_PACKAGE_URI": option(REPORT_ARGUMENTS, "--package-uri"),
    "CR_FROM": option(REPORT_ARGUMENTS, "--from"),
    "CR_TO": option(REPORT_ARGUMENTS, "--to"),
    "CR_AS_OF": option(REPORT_ARGUMENTS, "--as-of"),
    "CR_DETECTED_AT": option(REPORT_ARGUMENTS, "--detected-at"),
}
#: The inputs of the KEV golden runs; SARIF is timed, so no detection attestation.
KEV_INPUTS = {
    "CR_CLASS": option(KEV_ARGUMENTS, "--class"),
    "CR_PACKAGE_URI": option(KEV_ARGUMENTS, "--package-uri"),
    "CR_CALENDAR_TZ": option(KEV_ARGUMENTS, "--calendar-tz"),
    "CR_FROM": option(KEV_PERIOD, "--from"),
    "CR_TO": option(KEV_PERIOD, "--to"),
    "CR_AS_OF": KEV_AS_OF,
    "CR_EVALUATIONS": str(KEV_EVALUATIONS),
    "CR_KEV": str(KEV_CATALOG),
}
#: The flags the failure-only probe must never carry (Design 3.2).
PROBE_EXCLUDED = ("--evaluations", "--kev", "--inventory", GAP_FLAG, "--from", "--to", "-o")

#: A stand-in for an installed `complyroll`: runs the checked-out source and logs each call
#: as its exit code and arguments, tab separated. `SHIM_FAIL_VALIDATE=KIND` makes the
#: validation of that kind's report exit 1, as a schema-invalid report would.
#: `SHIM_FAIL_PROBE=1` makes a `report historical` call with no `-o`, the probe, exit 1.
SHIM = """#!/bin/sh
rc=
if [ "${1:-}" = validate ] && [ -n "${SHIM_FAIL_VALIDATE:-}" ]; then
  case ${2:-} in
    */"$SHIM_FAIL_VALIDATE".json) rc=1 ;;
  esac
fi
if [ "${1:-}" = report ] && [ "${2:-}" = historical ] && [ -n "${SHIM_FAIL_PROBE:-}" ]; then
  rc=1
  for arg in "$@"; do
    [ "$arg" != -o ] || rc=
  done
fi
if [ -z "$rc" ]; then
  PYTHONPATH=@SRC@ PYTHONDONTWRITEBYTECODE=1 @PYTHON@ -m complyroll "$@"
  rc=$?
fi
{
  printf '%s' "$rc"
  for arg in "$@"; do
    printf '\\t%s' "$arg"
  done
  printf '\\n'
} >>"$SHIM_LOG"
exit "$rc"
"""

# *--- Reference Workflow ---*

ENV_ENTRY = re.compile(r'(CR_[A-Z_]+): (?:"([^"]*)"|([^\s"#]+))(?:\s+#.*)?')
RUN_LINE = re.compile(r"\s+(?:- )?run: (.+)")
USES_LINE = re.compile(r"\s+(?:- )?uses: ([\w.-]+/[\w.-]+)@(\S+?)(?: # (\S+))?")
PINNED_USES = re.compile(r"[0-9a-f]{40} # v\d+\.\d+\.\d+")
GIT_PIN = re.compile(r"complyroll @ git\+https://github\.com/ComplyRoll/ComplyRoll@[0-9a-f]{40}")
PYPI_PIN = re.compile(r"complyroll==\d+(?:\.\d+)*[0-9A-Za-z.+!-]*")


@dataclass(frozen=True)
class Workflow:
    """The reference workflow read as text, line by line, without a YAML parser."""

    lines: tuple[str, ...]

    @classmethod
    def read(cls) -> Workflow:
        return cls(tuple(WORKFLOW.read_text(encoding="utf-8").splitlines()))

    def where(self, number: int) -> str:
        return f"{WORKFLOW_NAME}:{number}: {self.lines[number - 1].strip()}"

    def env(self) -> dict[str, str]:
        """Parse the job's `env:` block; a line that does not parse is a failure."""

        start = self.lines.index("    env:")
        values: dict[str, str] = {}
        for number, line in enumerate(self.lines[start + 1 :], start + 2):
            if line.strip() and not line.startswith("      "):
                break
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            match = ENV_ENTRY.fullmatch(entry)
            if match is None:
                raise AssertionError(f"unparsed env line: {self.where(number)}")
            values[match[1]] = match[2] if match[2] is not None else match[3]
        return values

    def runs(self) -> list[tuple[int, str]]:
        return [
            (number, match[1])
            for number, line in enumerate(self.lines, 1)
            if (match := RUN_LINE.fullmatch(line))
        ]

    def gate_runs(self) -> list[tuple[int, list[str]]]:
        return [
            (number, shlex.split(value))
            for number, value in self.runs()
            if shlex.split(value)[:2] == ["sh", GATE]
        ]

    def gate_command(self) -> list[str]:
        (_, command), *rest = self.gate_runs()
        if rest:
            raise AssertionError("more than one run line invokes the gate")
        return command

    def steps(self) -> list[list[str]]:
        start = self.lines.index("    steps:")
        steps: list[list[str]] = []
        for line in self.lines[start + 1 :]:
            if line.startswith("      - "):
                steps.append([line])
            elif steps:
                steps[-1].append(line)
        return steps

    def step_using(self, action: str) -> list[str]:
        (step,) = [step for step in self.steps() if any(f"uses: {action}@" in s for s in step)]
        return step

    def gate_step(self) -> list[str]:
        (step,) = [step for step in self.steps() if any(f"run: sh {GATE} " in s for s in step)]
        return step


def repository_pins() -> dict[str, set[tuple[str, str | None]]]:
    pins: dict[str, set[tuple[str, str | None]]] = {}
    for source in PIN_SOURCES:
        for line in source.read_text(encoding="utf-8").splitlines():
            if match := USES_LINE.fullmatch(line):
                pins.setdefault(match[1], set()).add((match[2], match[3]))
    return pins


# *--- Gate Script Text ---*


def script_text() -> str:
    return GATE_SCRIPT.read_text(encoding="utf-8")


def script_code() -> list[tuple[int, str]]:
    """The gate's lines that are not whole-line comments, with their line numbers."""

    return [
        (number, line)
        for number, line in enumerate(script_text().splitlines(), 1)
        if not line.lstrip().startswith("#")
    ]


def unquoted_expansions() -> Iterator[tuple[int, str]]:
    """Yield each `${` outside quotes, tracking quote state across lines."""

    double = single = False
    for number, line in enumerate(script_text().splitlines(), 1):
        if not (double or single) and line.lstrip().startswith("#"):
            continue
        index = 0
        while index < len(line):
            char = line[index]
            if single:
                single = char != "'"
            elif char == "\\":
                index += 1
            elif char == "'" and not double:
                single = True
            elif char == '"':
                double = not double
            elif char == "#" and not double and (index == 0 or line[index - 1].isspace()):
                break
            elif line.startswith("${", index) and not double:
                yield number, line
            index += 1


# *--- Scenarios ---*


@dataclass(frozen=True)
class Scenario:
    """One gate run: its inputs and what the run must show."""

    name: str
    #: `CR_*` and `SHIM_*` values; None leaves the variable unset.
    inputs: Mapping[str, str | None]
    artifacts: Sequence[str]
    exit: int = 0
    #: The vdt, avi and historical report exits; None for a run refused before any call.
    reports: tuple[int, int, int] | None = (0, 0, 0)
    validates: tuple[int, int, int] = (0, 0, 0)
    #: The failure probe's exit, or None where the probe must not run.
    probe: int | None = None
    verdict: str | None = CLEAN
    shell: Sequence[str] = ("sh",)
    #: Whether `GITHUB_STEP_SUMMARY` and `GITHUB_OUTPUT` name files, as on a runner.
    runner_files: bool = True
    #: Builds files in the run's directory and returns the artifacts to name.
    prepare: Callable[[Path, Path, Sequence[str]], Sequence[str]] | None = None

    @property
    def reaches_verdict(self) -> bool:
        return self.reports is not None


@dataclass(frozen=True)
class ShimCall:
    code: int
    argv: tuple[str, ...]


@dataclass(frozen=True)
class GateRun:
    """What one gate run left behind: its streams, the shim log, the summary and outputs."""

    scenario: Scenario
    code: int
    stdout: str
    stderr: str
    calls: tuple[ShimCall, ...]
    #: The summary file's text, or None when no summary file exists.
    summary: str | None
    #: The step output file's text, or None when no output file exists.
    output: str | None
    directory: Path
    out: Path

    @property
    def lines(self) -> list[str]:
        return self.stdout.splitlines()

    def report_calls(self) -> list[ShimCall]:
        return [call for call in self.calls if call.argv[:1] == ("report",) and "-o" in call.argv]

    def report_call(self, kind: str) -> ShimCall:
        (call,) = [call for call in self.report_calls() if call.argv[1] == kind]
        return call

    def probe_calls(self) -> list[ShimCall]:
        return [
            call
            for call in self.calls
            if call.argv[:2] == ("report", "historical") and "-o" not in call.argv
        ]

    def validate_calls(self) -> list[ShimCall]:
        return [call for call in self.calls if call.argv[:1] == ("validate",)]

    def logged(self) -> list[tuple[int, tuple[str, ...]]]:
        """The shim log with this run's output directory spelled `<out>`."""

        return [
            (call.code, tuple(arg.replace(str(self.out), "<out>") for arg in call.argv))
            for call in self.calls
        ]

    def document(self, kind: str) -> Any:
        return json.loads((self.out / f"{kind}.json").read_text(encoding="utf-8"))

    def diagnostics(self) -> str:
        path = self.out / "diagnostics.log"
        return path.read_text(encoding="utf-8") if path.is_file() else ""

    def explain(self) -> str:
        return (
            f"scenario {self.scenario.name}, exit {self.code}\nstdout:\n{self.stdout}"
            f"stderr:\n{self.stderr}diagnostics.log:\n{self.diagnostics()}"
        )


def copy_base_fixtures(directory: Path, out: Path, artifacts: Sequence[str]) -> list[str]:
    copies = directory / "fixture copies"
    copies.mkdir()
    for artifact in artifacts:
        shutil.copyfile(artifact, copies / Path(artifact).name)
    return [str(copies / Path(artifact).name) for artifact in artifacts]


def add_unsupported_file(directory: Path, out: Path, artifacts: Sequence[str]) -> list[str]:
    notes = directory / "notes.txt"
    notes.write_text("Synthetic notes, not an assessment artifact.\n", encoding="utf-8")
    return [*artifacts, str(notes)]


def leave_previous_report(directory: Path, out: Path, artifacts: Sequence[str]) -> Sequence[str]:
    out.mkdir()
    (out / "previous.json").write_text(PREVIOUS_REPORT, encoding="utf-8")
    return artifacts


def leave_dotfile(directory: Path, out: Path, artifacts: Sequence[str]) -> Sequence[str]:
    out.mkdir()
    (out / ".previous.json").write_text(PREVIOUS_REPORT, encoding="utf-8")
    return artifacts


#: The inputs the gate refuses to run without, each tested unset on its own (Forge F-08).
REQUIRED_INPUTS = ("CR_CLASS", "CR_PACKAGE_URI", "CR_FROM", "CR_TO")
#: The scenarios repeated under the second dialect (Forge F-13).
DIALECT_SCENARIOS = ("gaps-evaluated-warn", "both-kinds-warn")


def missing_scenario(variable: str) -> str:
    return f"missing-{variable.lower().replace('_', '-')}"


def dialects() -> list[tuple[str, tuple[str, ...]]]:
    """Each of dash and `bash --posix` that is found and is not the `sh` on PATH."""

    found: list[tuple[str, tuple[str, ...]]] = []
    for name, dialect in (("dash", ("dash",)), ("bash-posix", ("bash", "--posix"))):
        path = shutil.which(dialect[0])
        if path and not (SH and os.path.realpath(path) == os.path.realpath(SH)):
            found.append((name, (path, *dialect[1:])))
    return found


#: The first of dash and `bash --posix` that `sh` is not: bash on ubuntu, dash on macOS.
SECOND_DIALECT = next(iter(dialects()), None)


def build_scenarios(workflow: Workflow) -> list[Scenario]:
    """Every Design 4.5 scenario; the workflow's own inputs are the defaults."""

    command = workflow.gate_command()
    defaults = {key: value for key, value in workflow.env().items() if key != "CR_OUT"}
    shell, artifacts = (command[0],), command[2:]
    gaps = {**BASE_INPUTS, "CR_INVENTORY": str(EXAMPLE_INVENTORY)}
    warned_gaps = {
        **gaps,
        "CR_EVALUATIONS": str(COVERAGE_EVALUATIONS),
        "CR_SYSTEM_RECORDS": "warn-gaps",
    }
    # The failed fixtures follow the base three, as `with_failed_artifacts` orders them.
    failed = [*BASE_ARTIFACTS, *FAILED_ARTIFACTS]
    scenarios = [
        Scenario("yaml-defaults", defaults, artifacts, shell=shell),
        Scenario(
            "gaps-record",
            {**gaps, "CR_EVALUATIONS": str(EXAMPLE_EVALUATIONS)},
            BASE_ARTIFACTS,
            exit=3,
            reports=(3, 3, 3),
            probe=0,
            verdict=GAP,
        ),
        Scenario(
            "gaps-accepted-record",
            {**gaps, "CR_EVALUATIONS": str(ACCEPTED_EVALUATIONS)},
            BASE_ARTIFACTS,
            exit=3,
            reports=(3, 3, 3),
            probe=0,
            verdict=GAP,
        ),
        Scenario(
            "gaps-evaluated-warn",
            warned_gaps,
            BASE_ARTIFACTS,
            reports=(3, 3, 3),
            probe=0,
            verdict=WARNED_GAP,
        ),
        # Forge F-03: a probe that refuses is exit 1 under warn-gaps, never a warning.
        Scenario(
            "probe-refused",
            {**warned_gaps, "SHIM_FAIL_PROBE": "1"},
            BASE_ARTIFACTS,
            exit=1,
            reports=(3, 3, 3),
            probe=1,
            verdict=PROBE_REFUSED,
        ),
        Scenario(
            "failed",
            {**BASE_INPUTS, "CR_EVALUATIONS": str(FAILED_EVALUATIONS)},
            failed,
            exit=3,
            reports=(3, 3, 3),
            verdict=FAILURE_ONLY,
        ),
        Scenario(
            "execution-only",
            BASE_INPUTS,
            [*BASE_ARTIFACTS, str(INVOCATION_FIXTURE)],
            exit=3,
            reports=(3, 3, 3),
            verdict=FAILURE_ONLY,
        ),
        Scenario(
            "both-kinds-warn",
            {**gaps, "CR_SYSTEM_RECORDS": "warn-gaps"},
            failed,
            exit=3,
            reports=(3, 3, 3),
            probe=3,
            verdict=FAILURE,
        ),
        Scenario("kev", KEV_INPUTS, KEV_ARTIFACTS),
        Scenario(
            "space-in-path",
            {**BASE_INPUTS, "CR_EVALUATIONS": str(EXAMPLE_EVALUATIONS)},
            BASE_ARTIFACTS,
            prepare=copy_base_fixtures,
        ),
        Scenario(
            "refused",
            BASE_INPUTS,
            BASE_ARTIFACTS,
            exit=1,
            reports=(1, 1, 1),
            verdict=REFUSED,
            prepare=add_unsupported_file,
        ),
        # Forge F-04: a schema-invalid report of each kind, one scenario per kind.
        *(
            Scenario(
                f"invalid-output-{kind}",
                {**defaults, "SHIM_FAIL_VALIDATE": kind},
                artifacts,
                exit=1,
                validates=(int(kind == "vdt"), int(kind == "avi"), int(kind == "historical")),
                verdict=REFUSED,
            )
            for kind in REPORT_KINDS
        ),
        Scenario(
            "bad-policy",
            {**defaults, "CR_SYSTEM_RECORDS": "warn"},
            artifacts,
            exit=1,
            reports=None,
            verdict=None,
        ),
        *(
            Scenario(
                missing_scenario(variable),
                {**defaults, variable: None},
                artifacts,
                exit=1,
                reports=None,
                verdict=None,
            )
            for variable in REQUIRED_INPUTS
        ),
        Scenario("no-artifacts", defaults, (), exit=1, reports=None, verdict=None),
        Scenario("unset-as-of", {**defaults, "CR_AS_OF": None}, artifacts),
        Scenario(
            "stale-evaluation",
            {**BASE_INPUTS, "CR_EVALUATIONS": str(EXAMPLE_EVALUATIONS)},
            BASE_ARTIFACTS[:1],
            exit=1,
            reports=(1, 1, 1),
            verdict=REFUSED,
        ),
        Scenario(
            "stale-output",
            defaults,
            artifacts,
            exit=1,
            reports=None,
            verdict=None,
            prepare=leave_previous_report,
        ),
        # `ls -A`, not `ls`: a directory holding only a dotfile is not empty.
        Scenario(
            "stale-output-dotfile",
            defaults,
            artifacts,
            exit=1,
            reports=None,
            verdict=None,
            prepare=leave_dotfile,
        ),
        Scenario(
            "leading-dash",
            defaults,
            [artifacts[0], "-host.cklb"],
            exit=1,
            reports=None,
            verdict=None,
        ),
        # Not in the 4.5 table: the gate refuses a CR_OUT starting with `-` the same way.
        Scenario(
            "leading-dash-output",
            {**defaults, "CR_OUT": "-cr-out"},
            artifacts,
            exit=1,
            reports=None,
            verdict=None,
        ),
        Scenario("no-summary-env", defaults, artifacts, runner_files=False),
    ]
    # `yaml-defaults` again under each dialect found that `sh` is not already.
    for name, dialect in dialects():
        scenarios.append(Scenario(f"yaml-defaults-{name}", defaults, artifacts, shell=dialect))
    # The gap, failure and probe branches again under the second dialect only.
    if SECOND_DIALECT is not None:
        name, dialect = SECOND_DIALECT
        by_name = {scenario.name: scenario for scenario in scenarios}
        for base in DIALECT_SCENARIOS:
            scenarios.append(replace(by_name[base], name=f"{base}-{name}", shell=dialect))
    return scenarios


class Gate:
    """The reference gate run through a shim, one directory per scenario, results kept."""

    def __init__(self, root: Path, scenarios: Sequence[Scenario]) -> None:
        self.root = root
        self.scenarios = {scenario.name: scenario for scenario in scenarios}
        self.bin = root / "bin"
        self.bin.mkdir()
        shim = self.bin / "complyroll"
        shim.write_text(
            SHIM.replace("@SRC@", shlex.quote(str(ROOT / "src"))).replace(
                "@PYTHON@", shlex.quote(sys.executable)
            ),
            encoding="utf-8",
        )
        shim.chmod(0o755)
        self._results: dict[str, GateRun | Exception] = {}

    def prefetch(self) -> None:
        """Run every scenario not yet run, side by side."""

        pending = [name for name in self.scenarios if name not in self._results]
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for name, outcome in zip(pending, pool.map(self._attempt, pending), strict=True):
                self._results[name] = outcome

    def has(self, name: str) -> bool:
        return name in self.scenarios

    def result(self, name: str) -> GateRun:
        if name not in self._results:
            self._results[name] = self._attempt(name)
        outcome = self._results[name]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def results(self) -> list[GateRun]:
        return [self.result(name) for name in self.scenarios]

    def _attempt(self, name: str) -> GateRun | Exception:
        try:
            return self._run(self.scenarios[name])
        except Exception as error:
            return error

    def _run(self, scenario: Scenario) -> GateRun:
        directory = self.root / scenario.name
        directory.mkdir()
        out = directory / "out"
        log = directory / "shim.log"
        log.write_text("", encoding="utf-8")
        summary = directory / "summary.md"
        output = directory / "output.txt"
        path = os.environ.get("PATH", os.defpath)
        env = {"PATH": f"{self.bin}{os.pathsep}{path}", "SHIM_LOG": str(log), "CR_OUT": str(out)}
        if scenario.runner_files:
            summary.write_text("", encoding="utf-8")
            output.write_text("", encoding="utf-8")
            env["GITHUB_STEP_SUMMARY"] = str(summary)
            env["GITHUB_OUTPUT"] = str(output)
        for key, value in scenario.inputs.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        artifacts = list(scenario.artifacts)
        if scenario.prepare is not None:
            artifacts = list(scenario.prepare(directory, out, artifacts))
        completed = subprocess.run(
            [*scenario.shell, GATE, *artifacts],
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            timeout=GATE_TIMEOUT,
            check=False,
        )
        calls = tuple(
            ShimCall(int(code), tuple(argv))
            for code, *argv in (
                line.split("\t") for line in log.read_text(encoding="utf-8").splitlines()
            )
        )
        return GateRun(
            scenario=scenario,
            code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            calls=calls,
            summary=summary.read_text(encoding="utf-8") if summary.exists() else None,
            output=output.read_text(encoding="utf-8") if output.exists() else None,
            directory=directory,
            out=out,
        )


# *--- Gate Scenarios ---*


@unittest.skipIf(SH is None, "the reference gate needs a POSIX sh")
class GateScenarioTests(unittest.TestCase):
    """Design 4.5: every scenario through the gate, with its goldens and exit lines."""

    gate: Gate

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        directory = tempfile.TemporaryDirectory(prefix="complyroll-reference-ci-")
        cls.addClassCleanup(directory.cleanup)
        cls.gate = Gate(Path(directory.name), build_scenarios(Workflow.read()))
        cls.gate.prefetch()

    # *--- Helpers ---*

    def result(self, name: str) -> GateRun:
        return self.gate.result(name)

    def summarized(self) -> list[GateRun]:
        """The runs that reach the verdict with a summary file named."""

        return [
            result
            for result in self.gate.results()
            if result.scenario.reaches_verdict and result.scenario.runner_files
        ]

    def each(self) -> list[GateRun]:
        return self.gate.results()

    def assert_gate(self, result: GateRun) -> None:
        """The scenario's exit, verdict and annotation, with the records line where it belongs."""

        scenario = result.scenario
        self.assertEqual(result.code, scenario.exit, msg=result.explain())
        self.assertEqual(result.stderr, "", msg=result.explain())
        verdicts = [line for line in result.lines if line in VERDICTS]
        self.assertEqual(verdicts, [scenario.verdict])
        records_line = scenario.verdict in RECORD_VERDICTS
        self.assertEqual(result.lines.count(WHERE), int(records_line))
        annotation = ANNOTATIONS[scenario.verdict] if scenario.verdict else None
        expected = [] if annotation is None else [annotation]
        self.assertEqual(self.warnings(result) + self.errors(result), expected)
        self.assertEqual(result.output, STARTED if scenario.runner_files else None)

    def assert_golden(self, result: GateRun, kind: str, golden: str) -> None:
        for suffix in ("json", "md"):
            with self.subTest(report=f"{kind}.{suffix}", golden=f"{golden}.{suffix}"):
                self.assertEqual(
                    (result.out / f"{kind}.{suffix}").read_bytes(),
                    (GOLDEN / f"{golden}.{suffix}").read_bytes(),
                )

    def assert_in_process(self, result: GateRun, kind: str) -> None:
        """The gate's report equals an in-process `run()` of the argv the shim logged."""

        call = result.report_call(kind)
        argv = list(call.argv)
        with tempfile.TemporaryDirectory() as directory, chdir(ROOT):
            paths = {"json": Path(directory) / "report.json", "md": Path(directory) / "report.md"}
            argv[argv.index("-o") + 1] = str(paths["json"])
            argv[argv.index("--markdown") + 1] = str(paths["md"])
            code, _, err = run(argv)
            self.assertEqual(code, call.code, msg=err)
            for suffix, path in paths.items():
                with self.subTest(report=f"{kind}.{suffix}"):
                    self.assertEqual(
                        (result.out / f"{kind}.{suffix}").read_bytes(), path.read_bytes()
                    )

    def assert_stopped(self, result: GateRun, message: str) -> None:
        """A refused input: exit 1, one message, no call, no stdout, summary or step output."""

        self.assertEqual(result.code, 1, msg=result.explain())
        self.assertEqual(result.stderr, f"{message}\n")
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.calls, ())
        self.assertEqual(result.summary, "")
        self.assertEqual(result.output, "")

    def warnings(self, result: GateRun) -> list[str]:
        return [line for line in result.lines if line.startswith("::warning::")]

    def errors(self, result: GateRun) -> list[str]:
        return [line for line in result.lines if line.startswith("::error::")]

    # *--- Scenarios Over The Goldens ---*

    def test_yaml_defaults(self) -> None:
        result = self.result("yaml-defaults")

        self.assert_gate(result)
        self.assertIn("as-of: CR_AS_OF", result.lines)
        self.assertEqual(self.warnings(result) + self.errors(result), [])
        self.assert_golden(result, "avi", "avi-fixtures")
        self.assert_golden(result, "historical", "historical-fixtures")
        self.assert_in_process(result, "vdt")

    def test_yaml_defaults_read_the_workflow_inputs(self) -> None:
        result = self.result("yaml-defaults")
        workflow = Workflow.read()
        env = workflow.env()
        artifacts = workflow.gate_command()[2:]

        self.assertEqual(env["CR_SYSTEM_RECORDS"], "fail")
        for call in result.report_calls():
            with self.subTest(report=call.argv[1]):
                argv = call.argv
                self.assertEqual(list(argv[2 : 2 + len(artifacts)]), artifacts)
                self.assertEqual(option(argv, "--class"), env["CR_CLASS"])
                self.assertEqual(option(argv, "--package-uri"), env["CR_PACKAGE_URI"])
                self.assertEqual(option(argv, "--as-of"), env["CR_AS_OF"])
                self.assertEqual(option(argv, "--detected-at"), env["CR_DETECTED_AT"])
                self.assertEqual(option(argv, "--evaluations"), env["CR_EVALUATIONS"])
                if argv[1] != "historical":
                    self.assertEqual(option(argv, "--from"), env["CR_FROM"])
                    self.assertEqual(option(argv, "--to"), env["CR_TO"])

    def test_gaps_record(self) -> None:
        result = self.result("gaps-record")

        self.assert_gate(result)
        self.assertEqual(self.warnings(result), [])
        # Forge F-14: the annotation a reviewer sees says what a gap is not.
        self.assertEqual(self.errors(result), [ANNOTATIONS[GAP]])
        self.assertTrue(self.errors(result)[0].endswith(GAP_TAIL))
        self.assert_golden(result, "vdt", "vdt-coverage-gaps")

    def test_gaps_accepted_record(self) -> None:
        result = self.result("gaps-accepted-record")

        self.assert_gate(result)
        self.assert_golden(result, "historical", "historical-coverage-gaps")

    def test_gaps_evaluated_warn(self) -> None:
        # The probe carries no evaluations: with them it would exit 1, since the evaluation
        # of a gap record finds no gap record to match.
        result = self.result("gaps-evaluated-warn")

        self.assert_gate(result)
        self.assertEqual(self.warnings(result), [ANNOTATIONS[WARNED_GAP]])
        self.assertTrue(self.warnings(result)[0].endswith(GAP_TAIL))
        self.assertEqual(self.errors(result), [])

    def test_probe_refused(self) -> None:
        # Forge F-03: under warn-gaps a refused probe must not read as gaps alone.
        result = self.result("probe-refused")

        self.assert_gate(result)
        self.assertEqual(self.warnings(result), [])
        self.assertEqual(len(self.errors(result)), 1)
        self.assertEqual([call.code for call in result.probe_calls()], [1])

    def test_failed(self) -> None:
        result = self.result("failed")

        self.assert_gate(result)
        self.assertEqual(len(self.errors(result)), 1)
        self.assertEqual(result.probe_calls(), [])
        self.assert_golden(result, "vdt", "vdt-failed")
        self.assert_golden(result, "historical", "historical-failed")

    def test_execution_only(self) -> None:
        # Without --record-failed-imports the same run exits 0 with a WARNING.
        result = self.result("execution-only")

        self.assert_gate(result)
        self.assertEqual(len(self.errors(result)), 1)
        failures = result.document("historical")["x-complyroll"]["detectionFailures"]
        self.assertEqual([item["name"] for item in failures], [INVOCATION_FIXTURE.name])

    def test_both_kinds_warn(self) -> None:
        # warn-gaps never turns a recorded detection process failure into a warning.
        result = self.result("both-kinds-warn")

        self.assert_gate(result)
        self.assertEqual(self.warnings(result), [])
        self.assertEqual(len(self.errors(result)), 1)

    def test_kev(self) -> None:
        result = self.result("kev")

        self.assert_gate(result)
        for kind in REPORT_KINDS:
            self.assert_golden(result, kind, f"{kind}-kev")

    def test_space_in_path(self) -> None:
        result = self.result("space-in-path")

        self.assert_gate(result)
        copies = [str(result.directory / "fixture copies" / Path(a).name) for a in BASE_ARTIFACTS]
        for call in result.report_calls():
            self.assertEqual(list(call.argv[2:5]), copies)
        self.assert_golden(result, "vdt", "vdt-fixtures")
        self.assert_in_process(result, "avi")
        self.assert_in_process(result, "historical")

    # *--- Refusals After The First Call ---*

    def test_refused(self) -> None:
        result = self.result("refused")

        self.assert_gate(result)
        self.assertEqual(result.validate_calls(), [])
        self.assertIn("unsupported_artifact", result.diagnostics())
        self.assertEqual(sorted(path.name for path in result.out.iterdir()), ["diagnostics.log"])

    def assert_invalid_output(self, kind: str) -> None:
        result = self.result(f"invalid-output-{kind}")

        self.assert_gate(result)
        self.assertEqual(len(self.errors(result)), 1)
        failed = [call.argv[1] for call in result.validate_calls() if call.code != 0]
        self.assertEqual(failed, [str(result.out / f"{kind}.json")])

    def test_invalid_output_vdt(self) -> None:
        self.assert_invalid_output("vdt")

    def test_invalid_output_avi(self) -> None:
        self.assert_invalid_output("avi")

    def test_invalid_output_historical(self) -> None:
        self.assert_invalid_output("historical")

    def test_stale_evaluation(self) -> None:
        result = self.result("stale-evaluation")

        self.assert_gate(result)
        self.assertEqual(result.validate_calls(), [])
        self.assertIn("evaluation_unmatched", result.diagnostics())
        self.assertEqual(sorted(path.name for path in result.out.iterdir()), ["diagnostics.log"])

    # *--- Refusals Before Any Call ---*

    def test_bad_policy(self) -> None:
        result = self.result("bad-policy")

        self.assert_stopped(result, "error: CR_SYSTEM_RECORDS is fail or warn-gaps")
        self.assertFalse(result.out.exists())

    def test_missing_input(self) -> None:
        # Forge F-08: each required input on its own, so no check can go missing unseen.
        for variable in REQUIRED_INPUTS:
            with self.subTest(variable=variable):
                result = self.result(missing_scenario(variable))

                self.assert_stopped(result, f"error: set {variable}")
                self.assertFalse(result.out.exists())

    def test_no_artifacts(self) -> None:
        result = self.result("no-artifacts")

        self.assert_stopped(result, "error: name at least one artifact")
        self.assertFalse(result.out.exists())

    def test_stale_output(self) -> None:
        result = self.result("stale-output")

        self.assert_stopped(result, "error: CR_OUT exists and is not empty; name a fresh directory")
        self.assertEqual([path.name for path in result.out.iterdir()], ["previous.json"])
        self.assertEqual(
            (result.out / "previous.json").read_text(encoding="utf-8"), PREVIOUS_REPORT
        )

    def test_stale_output_dotfile(self) -> None:
        result = self.result("stale-output-dotfile")

        self.assert_stopped(result, "error: CR_OUT exists and is not empty; name a fresh directory")
        self.assertEqual([path.name for path in result.out.iterdir()], [".previous.json"])
        self.assertEqual(
            (result.out / ".previous.json").read_text(encoding="utf-8"), PREVIOUS_REPORT
        )

    def test_leading_dash(self) -> None:
        result = self.result("leading-dash")

        self.assert_stopped(result, "error: an artifact argument starts with -; prefix it with ./")
        self.assertFalse(result.out.exists())

    def test_leading_dash_output(self) -> None:
        result = self.result("leading-dash-output")

        self.assert_stopped(result, "error: CR_OUT starts with -; prefix it with ./")
        self.assertFalse((ROOT / "-cr-out").exists())

    # *--- Clock And Summary Variable ---*

    def test_unset_as_of(self) -> None:
        result = self.result("unset-as-of")

        self.assert_gate(result)
        resolved = [line for line in result.lines if line.startswith("as-of: ")]
        self.assertEqual(len(resolved), 1)
        self.assertRegex(resolved[0], rf"^as-of: {INSTANT}, resolved once at start$")
        instant = resolved[0].split()[1].rstrip(",")
        calls = [*result.report_calls(), *result.probe_calls()]
        self.assertEqual(len(calls), 3)
        for call in calls:
            self.assertEqual(call.argv.count("--as-of"), 1)
            self.assertEqual(option(call.argv, "--as-of"), instant)
        for kind in REPORT_KINDS:
            self.assertEqual(result.document(kind)["x-complyroll"]["generatedAt"], instant)

    def test_no_summary_env(self) -> None:
        result = self.result("no-summary-env")

        self.assert_gate(result)
        self.assertIn(DISCLAIMER, result.lines)
        self.assertIsNone(result.summary)
        self.assertIsNone(result.output)
        self.assertEqual(
            sorted(path.name for path in result.directory.iterdir()), ["out", "shim.log"]
        )

    # *--- Dialects ---*

    def assert_same_run(self, name: str, reference_name: str = "yaml-defaults") -> None:
        if not self.gate.has(name):
            self.skipTest(
                f"{name}: the shell is absent, or it is the sh {reference_name} ran under"
            )
        result, reference = self.result(name), self.result(reference_name)

        self.assertEqual(result.code, reference.code, msg=result.explain())
        self.assertEqual(result.stdout, reference.stdout)
        self.assertEqual(result.stderr, reference.stderr)
        self.assertEqual(result.summary, reference.summary)
        self.assertEqual(result.output, reference.output)
        self.assertEqual(result.logged(), reference.logged())
        for kind in REPORT_KINDS:
            for suffix in ("json", "md"):
                with self.subTest(report=f"{kind}.{suffix}"):
                    self.assertEqual(
                        (result.out / f"{kind}.{suffix}").read_bytes(),
                        (reference.out / f"{kind}.{suffix}").read_bytes(),
                    )

    def assert_same_run_under_the_second_dialect(self, base: str) -> None:
        if SECOND_DIALECT is None:
            self.skipTest("neither dash nor bash is found apart from sh")
        self.assert_same_run(f"{base}-{SECOND_DIALECT[0]}", base)

    def test_yaml_defaults_under_dash(self) -> None:
        self.assert_same_run("yaml-defaults-dash")

    def test_yaml_defaults_under_bash_posix(self) -> None:
        self.assert_same_run("yaml-defaults-bash-posix")

    def test_gaps_evaluated_warn_under_the_second_dialect(self) -> None:
        # Forge F-13: the gap and probe branches under the shell sh is not.
        self.assert_same_run_under_the_second_dialect("gaps-evaluated-warn")

    def test_both_kinds_warn_under_the_second_dialect(self) -> None:
        self.assert_same_run_under_the_second_dialect("both-kinds-warn")

    # *--- Every Scenario ---*

    def test_no_shim_call_exits_2(self) -> None:
        # The dynamic form of "every complyroll line parses under build_parser()".
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                self.assertEqual([call.argv for call in result.calls if call.code == 2], [])

    def test_exit_lines_match_the_calls(self) -> None:
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                scenario = result.scenario
                if scenario.reports is None:
                    self.assertEqual(
                        [line for line in result.lines if EXIT_LINE.fullmatch(line)], []
                    )
                    continue
                reports = result.report_calls()
                self.assertEqual([call.argv[1] for call in reports], list(REPORT_KINDS))
                validated = {Path(call.argv[1]).stem: call for call in result.validate_calls()}
                expected: list[str] = []
                for kind, call, status, valid in zip(
                    REPORT_KINDS, reports, scenario.reports, scenario.validates, strict=True
                ):
                    self.assertEqual(call.code, status, msg=result.explain())
                    expected.append(f"report {kind}: exit {status}")
                    if status in (0, 3):
                        self.assertEqual(validated[kind].code, valid)
                        expected.append(f"validate {kind}: exit {valid}")
                    else:
                        self.assertNotIn(kind, validated)
                probes = result.probe_calls()
                if scenario.probe is None:
                    self.assertEqual(probes, [])
                else:
                    self.assertEqual([call.code for call in probes], [scenario.probe])
                    expected.append(f"failure probe: exit {scenario.probe}")
                self.assertEqual(
                    [line for line in result.lines if EXIT_LINE.fullmatch(line)], expected
                )

    def test_probe_parity(self) -> None:
        # ADR 0017 Decision 6: detection failures come from the artifacts alone.
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                for probe in result.probe_calls():
                    failures = result.document("historical")["x-complyroll"].get(
                        "detectionFailures"
                    )
                    self.assertEqual(probe.code == 3, bool(failures))

    def test_the_probe_reads_failures_only(self) -> None:
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                for probe in result.probe_calls():
                    self.assertEqual([flag for flag in PROBE_EXCLUDED if flag in probe.argv], [])
                    self.assertIn("--record-failed-imports", probe.argv)
                    # The probe reads the same artifacts, in the same order, as the reports.
                    report = result.report_call("historical").argv
                    self.assertEqual(
                        probe.argv[2 : probe.argv.index("--class")],
                        report[2 : report.index("--class")],
                    )

    def test_every_call_shares_one_as_of(self) -> None:
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                calls = [*result.report_calls(), *result.probe_calls()]
                instants = {option(call.argv, "--as-of") for call in calls}
                self.assertLessEqual(len(instants), 1)
                as_of = result.scenario.inputs.get("CR_AS_OF")
                if calls and as_of is not None:
                    self.assertEqual(instants, {as_of})

    def test_stdout_holds_fixed_gate_text_only(self) -> None:
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                if not result.scenario.reaches_verdict:
                    continue
                for line in result.lines:
                    self.assertTrue(
                        line in SUMMARY_TEXT
                        or EXIT_LINE.fullmatch(line)
                        or AS_OF_LINE.fullmatch(line)
                        or line in ANNOTATIONS.values(),
                        line,
                    )
                self.assertEqual(result.lines.count(DISCLAIMER), 1)

    # *--- Step Output (Forge F-01) ---*

    def test_started_is_written_only_once_the_gate_starts(self) -> None:
        # The upload step reads it: a run refused before the compile uploads nothing.
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                if not result.scenario.runner_files:
                    self.assertIsNone(result.output)
                elif result.scenario.reaches_verdict:
                    self.assertEqual(result.output, STARTED)
                else:
                    self.assertEqual(result.output, "")

    # *--- Summary (Forge F8) ---*

    def test_runs_stopped_before_the_verdict_write_no_summary(self) -> None:
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                if not result.scenario.reaches_verdict:
                    self.assertEqual(result.summary, "")
                elif not result.scenario.runner_files:
                    self.assertIsNone(result.summary)

    def test_summary_holds_fixed_gate_text_only(self) -> None:
        for result in self.summarized():
            with self.subTest(scenario=result.scenario.name):
                assert result.summary is not None
                lines = result.summary.splitlines()
                self.assertEqual(lines[0], "## ComplyRoll gate")
                self.assertIn(result.scenario.verdict, lines)
                for line in lines:
                    self.assertTrue(
                        not line or line in SUMMARY_TEXT or EXIT_LINE.fullmatch(line), repr(line)
                    )

    def test_summary_exit_lines_equal_the_stdout_exit_lines(self) -> None:
        # Forge F-07: the summary keeps every per-command exit line, in order.
        for result in self.summarized():
            with self.subTest(scenario=result.scenario.name):
                assert result.summary is not None
                summary = [
                    line for line in result.summary.splitlines() if EXIT_LINE.fullmatch(line)
                ]
                stdout = [line for line in result.lines if EXIT_LINE.fullmatch(line)]
                self.assertTrue(stdout)
                self.assertEqual(summary, stdout)

    def test_summary_names_where_the_records_are(self) -> None:
        # Forge F-07: every exit-3 verdict and the warned gap point at historical.json.
        for result in self.summarized():
            with self.subTest(scenario=result.scenario.name):
                assert result.summary is not None
                expected = int(result.scenario.verdict in RECORD_VERDICTS)
                self.assertEqual(result.summary.splitlines().count(WHERE), expected)

    def test_summary_holds_no_twin_line(self) -> None:
        # Forge F4: the twins carry scanner text whose link and image syntax is live Markdown.
        for result in self.summarized():
            with self.subTest(scenario=result.scenario.name):
                assert result.summary is not None
                summary = {line.strip() for line in result.summary.splitlines() if line.strip()}
                for twin in result.out.glob("*.md"):
                    twin_lines = {
                        line.strip()
                        for line in twin.read_text(encoding="utf-8").splitlines()
                        if line.strip()
                    }
                    self.assertEqual(summary & twin_lines, set(), twin.name)

    def test_summary_carries_the_disclaimer_once(self) -> None:
        for result in self.summarized():
            with self.subTest(scenario=result.scenario.name):
                assert result.summary is not None
                self.assertEqual(result.summary.splitlines().count(DISCLAIMER), 1)

    # *--- Wording (Design 3.3) ---*

    def test_gate_lines_carry_no_approval_word(self) -> None:
        for result in self.each():
            with self.subTest(scenario=result.scenario.name):
                emitted = [result.stdout, result.stderr, result.summary or ""]
                for line in "\n".join(emitted).splitlines():
                    self.assertIsNone(BANNED.search(line), line)


# *--- Workflow Text ---*


class WorkflowTextTests(unittest.TestCase):
    """Design 4.5 workflow text tests, read line by line without a YAML parser."""

    def setUp(self) -> None:
        self.workflow = Workflow.read()
        self.lines = self.workflow.lines

    def test_the_workflow_is_ascii(self) -> None:
        self.assertTrue(WORKFLOW.read_bytes().isascii())

    def test_permissions_are_contents_read_only(self) -> None:
        indices = [
            i for i, line in enumerate(self.lines) if line.strip().startswith("permissions:")
        ]
        self.assertEqual(len(indices), 1)
        (index,) = indices
        self.assertEqual(self.lines[index], "permissions:")
        self.assertEqual(self.lines[index + 1], "  contents: read")
        self.assertFalse(self.lines[index + 2].startswith(" "), self.lines[index + 2])
        for number, line in enumerate(self.lines, 1):
            self.assertIsNone(re.search(r":\s*write\b", line), self.workflow.where(number))

    def test_credentials_and_secrets_stay_out(self) -> None:
        checkout = self.workflow.step_using("actions/checkout")
        self.assertIn("          persist-credentials: false", checkout)
        text = "\n".join(self.lines)
        for needle in ("pull_request_target", "secrets.", "id-token"):
            self.assertNotIn(needle, text)

    def test_expressions_appear_only_in_the_concurrency_block(self) -> None:
        index = self.lines.index("concurrency:")
        found = [i for i, line in enumerate(self.lines) if "${{" in line]
        self.assertEqual(found, [index + 1, index + 2], [self.workflow.where(i + 1) for i in found])
        self.assertTrue(self.lines[index + 1].startswith("  group: "))
        # Forge F-16: a newer push cancels a pull request run, never a main-branch run.
        self.assertEqual(
            self.lines[index + 2],
            "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
        )
        for number, value in self.workflow.runs():
            self.assertNotIn("${{", value, self.workflow.where(number))

    def test_no_step_turns_the_gate_non_blocking(self) -> None:
        # Forge F-06: continue-on-error is an opt-in edit (README), never in the reference.
        for number, line in enumerate(self.lines, 1):
            self.assertNotIn("continue-on-error", line, self.workflow.where(number))

    def test_the_gate_runs_from_the_checkout_root(self) -> None:
        # Forge F-06: the run line's relative paths hold only at the workspace root.
        checkout = [line.strip() for line in self.workflow.step_using("actions/checkout")]
        self.assertEqual([line for line in checkout if line.startswith("path:")], [])
        for number, line in enumerate(self.lines, 1):
            self.assertNotIn("working-directory", line, self.workflow.where(number))

    def test_the_job_has_a_timeout(self) -> None:
        self.assertTrue(any(re.fullmatch(r"\s+timeout-minutes: \d+", line) for line in self.lines))

    def test_one_run_line_invokes_the_gate_on_existing_files(self) -> None:
        runs = self.workflow.gate_runs()
        self.assertEqual(len(runs), 1)
        mentions = [n for n, value in self.workflow.runs() if "complyroll-gate.sh" in value]
        self.assertEqual(mentions, [runs[0][0]])
        (_, command), *_ = runs
        self.assertGreater(len(command), 2)
        for argument in command[1:]:
            self.assertTrue((ROOT / argument).is_file(), argument)

    def test_the_header_names_the_gate_path(self) -> None:
        # Forge F14: the header must not send the script anywhere the run line does not read.
        header = []
        for line in self.lines:
            if not line.startswith("#"):
                break
            header.append(line)
        self.assertIn(GATE, " ".join(header))
        self.assertEqual(self.workflow.gate_command()[1], GATE)

    def test_the_install_line_has_a_pinned_shape(self) -> None:
        installs = [(n, shlex.split(v)) for n, v in self.workflow.runs() if "pip install" in v]
        self.assertEqual(len(installs), 1)
        ((number, command),) = installs
        self.assertEqual(
            command[:4], ["python", "-m", "pip", "install"], self.workflow.where(number)
        )
        requirements = [argument for argument in command[4:] if not argument.startswith("-")]
        self.assertEqual(len(requirements), 1, self.workflow.where(number))
        shapes = [shape for shape in (GIT_PIN, PYPI_PIN) if shape.fullmatch(requirements[0])]
        self.assertEqual(len(shapes), 1, self.workflow.where(number))

    def test_every_action_matches_the_repository_pin(self) -> None:
        pins = repository_pins()
        uses = [
            (number, match)
            for number, line in enumerate(self.lines, 1)
            if (match := USES_LINE.fullmatch(line))
        ]
        self.assertEqual(len(uses), sum("uses:" in line for line in self.lines))
        self.assertTrue(uses)
        for number, match in uses:
            action, sha, version = match[1], match[2], match[3]
            with self.subTest(line=number):
                expected = pins.get(action, set())
                wanted = ", ".join(f"{pin} # {tag}" for pin, tag in sorted(expected, key=str))
                self.assertIsNotNone(
                    PINNED_USES.fullmatch(f"{sha} # {version}"),
                    f"{self.workflow.where(number)}: pin {action} to a full SHA and # vX.Y.Z",
                )
                self.assertIn(
                    (sha, version),
                    expected,
                    f"{self.workflow.where(number)}: expected {action}@{wanted or 'a pin'} as in "
                    ".github/workflows/ci.yml or release.yml",
                )

    def test_the_upload_step_runs_only_once_the_gate_started(self) -> None:
        # Forge F-01: on failure too, but never for a run the gate refused before CR_OUT.
        gate = [line.strip() for line in self.workflow.gate_step()]
        self.assertEqual([line for line in gate if line.startswith("id:")], ["id: gate"])
        step = [line.strip() for line in self.workflow.step_using("actions/upload-artifact")]
        self.assertEqual(
            [line for line in step if line.startswith("if:")],
            ["if: always() && steps.gate.outputs.started == 'true'"],
        )
        self.assertIn("if-no-files-found: warn", step)
        self.assertIn("retention-days: 30", step)
        (path,) = [line for line in step if line.startswith("path: ")]
        self.assertEqual(path, f"path: {self.workflow.env()['CR_OUT']}/")

    def test_the_env_block_parses_into_yaml_defaults(self) -> None:
        env = self.workflow.env()
        start = self.lines.index("    env:")
        entries = [
            line
            for line in self.lines[start + 1 : self.lines.index("    steps:")]
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertEqual(len(entries), len(env))
        for key in ("CR_OUT", "CR_CLASS", "CR_PACKAGE_URI", "CR_FROM", "CR_TO"):
            self.assertIn(key, env)
        (scenario,) = [s for s in build_scenarios(self.workflow) if s.name == "yaml-defaults"]
        self.assertEqual(dict(scenario.inputs), {k: v for k, v in env.items() if k != "CR_OUT"})
        self.assertEqual(list(scenario.artifacts), self.workflow.gate_command()[2:])


# *--- Gate Script Text ---*


class ScriptTextTests(unittest.TestCase):
    """Design 4.5 script text tests: POSIX sh, no network or delete, quoted expansions."""

    def test_the_script_is_ascii_with_a_sh_shebang(self) -> None:
        self.assertTrue(GATE_SCRIPT.read_bytes().isascii())
        self.assertEqual(script_text().splitlines()[0], "#!/bin/sh")

    def test_no_network_install_or_delete_command(self) -> None:
        for number, line in script_code():
            for word in ("eval", "curl", "wget", "pip", "git", "https?", "rm"):
                self.assertIsNone(re.search(rf"\b{word}\b", line), f"{GATE}:{number}: {line}")

    def test_the_runner_variables_are_read_only_with_a_default(self) -> None:
        code = "\n".join(line for _, line in script_code())
        for variable in ("GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT"):
            with self.subTest(variable=variable):
                self.assertGreater(code.count(variable), 0)
                self.assertEqual(code.count(variable), code.count(f"${{{variable}:-}}"))

    def test_started_follows_the_output_checks(self) -> None:
        # Forge F-01: started=true only after the CR_OUT refusal, mkdir and the log.
        code = [line for _, line in script_code()]
        (started,) = [i for i, line in enumerate(code) if "started=true" in line]
        for needle in ("CR_OUT exists and is not empty", 'mkdir -p "$out"', ': > "$log"'):
            with self.subTest(before=needle):
                (index,) = [i for i, line in enumerate(code) if needle in line]
                self.assertLess(index, started)
        # Forge delta M-01: and before the first compile, so a gate that dies mid-run uploads.
        first_compile = min(i for i, line in enumerate(code) if 'compile "$kind" "$@"' in line)
        self.assertLess(started, first_compile)

    def test_no_bashism(self) -> None:
        patterns = {
            "errexit": r"\bset\s+(?:-[a-zA-Z]*e|-o\s+errexit)",
            "array": r"\w+=\(|\$\{#?\w+\[",
            "local": r"\blocal\b",
            "[[": r"\[\[",
            "pipefail": r"\bpipefail\b",
            "shopt": r"\bshopt\b",
            "function": r"\bfunction\b",
            "source": r"^\s*source\b",
            "== in [": r"\[\s[^]]*==",
            "here string": r"<<<",
            "&>": r"&>",
            "$'": r"\$'",
        }
        for number, line in script_code():
            for name, pattern in patterns.items():
                self.assertIsNone(re.search(pattern, line), f"{name}: {GATE}:{number}: {line}")

    def test_braced_expansions_are_quoted(self) -> None:
        # The plain assignments do not split; every other ${...} sits inside double quotes.
        assignment = re.compile(r"\s*(?:out|log|policy|as_of)=\$\{[A-Z_]+(?::-[^}]*)?\}")
        for number, line in unquoted_expansions():
            self.assertIsNotNone(assignment.fullmatch(line), f"{GATE}:{number}: {line}")

    def test_script_lines_carry_no_approval_word(self) -> None:
        # Every message the gate can print, a path no scenario reaches included.
        for number, line in script_code():
            self.assertIsNone(BANNED.search(line), f"{GATE}:{number}: {line}")


if __name__ == "__main__":
    unittest.main()
