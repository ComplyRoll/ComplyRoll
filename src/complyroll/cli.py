"""ComplyRoll command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from . import __version__
from .adapters import DiagnosticLevel
from .policy import CertificationClass
from .reports import (
    ReportCompileError,
    ReportDiagnostic,
    ReportInputError,
    ReportOptions,
    compile_vdt_report,
    load_evaluations,
    parse_rfc3339,
)
from .schemas import (
    MAX_REPORT_BYTES,
    ReportDocumentError,
    ReportSchema,
    validate_bundled_report_bytes,
)

PHASES = (
    ("0", "Harden stigroll ingestion and provenance"),
    ("1", "Build VDR cases, policy clocks, and VER exports"),
    ("2", "Add automation, coverage, and change integration"),
    ("3", "Add KSI validation and SDR evidence"),
    ("4", "Integrate trust-center and ongoing certification workflows"),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="complyroll",
        description="Local-first evidence compiler for FedRAMP 20x VDR.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("version", help="show the ComplyRoll version")
    subparsers.add_parser("plan", help="show the high-level implementation phases")

    report = subparsers.add_parser("report", help="compile an official-format report")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    vdt = report_commands.add_parser(
        "vdt",
        help="compile a Vulnerability Detail Report (VER-RPT-VDT)",
        description=(
            "Compile a Vulnerability Detail Report from source artifacts and explicit "
            "operator inputs. Output is official-format JSON; it is not a FedRAMP "
            "determination."
        ),
    )
    vdt.add_argument("artifacts", nargs="+", metavar="ARTIFACT", help="CKLB, CKL, or XCCDF file")
    vdt.add_argument(
        "--class",
        dest="certification_class",
        required=True,
        choices=[item.value for item in CertificationClass],
        help="certification class whose rules select the deadlines",
    )
    vdt.add_argument(
        "--package-uri",
        required=True,
        metavar="URI",
        help="absolute http or https URI of the Certification Package Overview",
    )
    vdt.add_argument(
        "--from",
        dest="period_from",
        required=True,
        metavar="RFC3339",
        help="start of the report period",
    )
    vdt.add_argument(
        "--to",
        dest="period_to",
        required=True,
        metavar="RFC3339",
        help="end of the report period",
    )
    vdt.add_argument(
        "--evaluations",
        metavar="FILE",
        help="JSON file of completed contextual evaluations",
    )
    vdt.add_argument(
        "--detected-at",
        metavar="RFC3339",
        help="attested detection time for vulnerabilities whose sources declare none",
    )
    vdt.add_argument(
        "--as-of",
        metavar="RFC3339",
        help="instant the overdue flags are calculated against (default: now, UTC)",
    )
    vdt.add_argument(
        "--calendar-tz",
        default="UTC",
        metavar="NAME",
        help="IANA calendar used for month and year arithmetic (default: UTC)",
    )
    vdt.add_argument("-o", "--output", metavar="FILE", help="write JSON here instead of stdout")
    vdt.add_argument("--markdown", metavar="FILE", help="also write the human-readable twin")

    validate = subparsers.add_parser(
        "validate",
        help="validate a report against a bundled official schema",
    )
    validate.add_argument("report", metavar="REPORT", help="JSON report file to validate")
    validate.add_argument(
        "--schema",
        required=True,
        choices=[item.value for item in ReportSchema],
        help="official schema to validate against",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "version":
        print(f"ComplyRoll {__version__}")
        return 0

    if args.command == "plan":
        for phase, outcome in PHASES:
            print(f"Phase {phase}: {outcome}")
        return 0

    if args.command == "report":
        if args.report_command == "vdt":
            return _run_report_vdt(args)
        raise AssertionError(f"unhandled report command: {args.report_command}")

    if args.command == "validate":
        return _run_validate(args)

    raise AssertionError(f"unhandled command: {args.command}")


def _run_report_vdt(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    artifacts = [Path(item) for item in args.artifacts]
    output = Path(args.output) if args.output else None
    markdown = Path(args.markdown) if args.markdown else None
    evaluations_path = Path(args.evaluations) if args.evaluations else None

    try:
        _refuse_input_overwrite(
            outputs=(output, markdown),
            inputs=(*artifacts, *(item for item in (evaluations_path,) if item)),
        )
        options = ReportOptions(
            certification_class=CertificationClass(args.certification_class),
            package_uri=args.package_uri,
            period_from=parse_rfc3339(args.period_from, "--from"),
            period_to=parse_rfc3339(args.period_to, "--to"),
            as_of=(
                parse_rfc3339(args.as_of, "--as-of")
                if args.as_of
                else datetime.now(UTC).replace(microsecond=0)
            ),
            calendar_timezone=args.calendar_tz,
            detected_at_attestation=(
                parse_rfc3339(args.detected_at, "--detected-at") if args.detected_at else None
            ),
        )
        evaluations = load_evaluations(evaluations_path) if evaluations_path else None
    except ReportInputError as exc:
        return _fail(stderr, "invalid_input", str(exc))
    except (TypeError, ValueError) as exc:
        return _fail(stderr, "invalid_option", str(exc))

    try:
        report = compile_vdt_report(artifacts, options=options, evaluations=evaluations)
    except ReportCompileError as exc:
        _write_diagnostics(stderr, exc.diagnostics)
        return 1

    _write_diagnostics(stderr, report.diagnostics)

    # Render everything before writing anything, so a failed second write cannot
    # leave a half-published pair of reports behind (ADR 0007 amendment).
    json_text = report.to_json()
    targets: list[tuple[Path, str]] = []
    if output is not None:
        targets.append((output, json_text))
    if markdown is not None:
        targets.append((markdown, report.to_markdown()))

    try:
        _write_all_or_nothing(targets)
    except OSError as exc:
        location = getattr(exc, "filename", None)
        return _fail(stderr, "output_write_failed", str(exc), location=location)

    if output is None:
        sys.stdout.write(json_text)
    return 0


def _run_validate(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    path = Path(args.report)
    try:
        size = path.stat().st_size
        if size > MAX_REPORT_BYTES:
            raise ReportDocumentError(
                f"report is {size} bytes; maximum is {MAX_REPORT_BYTES} bytes"
            )
        content = path.read_bytes()
    except OSError as exc:
        return _fail(stderr, "report_read_failed", str(exc), location=str(path))
    except ReportDocumentError as exc:
        return _fail(stderr, "report_too_large", str(exc), location=str(path))

    try:
        result = validate_bundled_report_bytes(ReportSchema(args.schema), content)
    except ReportDocumentError as exc:
        return _fail(stderr, "report_malformed", str(exc), location=str(path))

    provenance = result.provenance
    summary = (
        f"{provenance.schema_id} {provenance.schema_version} {provenance.schema_sha256}"
    )
    if result.is_valid:
        print(f"valid: {summary}")
        return 0
    for issue in result.issues:
        location = issue.instance_pointer or "<root>"
        print(f"{location}: {issue.validator}: {issue.message}", file=stderr)
    print(f"schema: {summary}", file=stderr)
    return 1


def _refuse_input_overwrite(
    *,
    outputs: Sequence[Path | None],
    inputs: Sequence[Path],
) -> None:
    resolved_inputs = {item.resolve(): item for item in inputs}
    written: dict[Path, Path] = {}
    for target in outputs:
        if target is None:
            continue
        resolved = target.resolve()
        source = resolved_inputs.get(resolved)
        if source is not None:
            raise ValueError(f"refusing to overwrite the input file {source}")
        if resolved in written:
            raise ValueError(f"refusing to write two outputs to the same file {target}")
        written[resolved] = target


def _write_all_or_nothing(targets: Sequence[tuple[Path, str]]) -> None:
    """Write every output, or none of them.

    Each destination is staged in a temporary file beside it and fsynced. Only after
    every staged write succeeds are the destinations replaced, so a failed Markdown
    write leaves no JSON behind and a failed JSON write leaves no Markdown.
    """

    staged: list[tuple[Path, Path]] = []
    try:
        for destination, content in targets:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                staged.append((Path(handle.name), destination))
    except OSError:
        _discard(staged)
        raise

    try:
        for temporary, destination in staged:
            os.replace(temporary, destination)
    except OSError:
        _discard(staged)
        raise


def _discard(staged: Sequence[tuple[Path, Path]]) -> None:
    for temporary, _ in staged:
        temporary.unlink(missing_ok=True)


def _write_diagnostics(stream: TextIO, diagnostics: Sequence[ReportDiagnostic]) -> None:
    for diagnostic in diagnostics:
        print(diagnostic.render(), file=stream)


def _fail(stream: TextIO, code: str, message: str, location: str | None = None) -> int:
    diagnostic = ReportDiagnostic(
        level=DiagnosticLevel.ERROR,
        code=code,
        message=message,
        location=location,
    )
    print(diagnostic.render(), file=stream)
    return 1
