"""ComplyRoll command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from . import __version__
from .adapters import DiagnosticLevel, IngestDiagnostic, IngestResult, ingest_stig_artifact
from .events import EventContractError, EventMetadata, EventRepository, require_tracking_id
from .history import (
    CaseNotFoundError,
    CaseState,
    EvaluationMatchError,
    HistoryError,
    apply_evaluations,
    attest_detection,
    case_history,
    correlate_cases,
    fold_all_cases,
    record_ingest,
)
from .policy import CertificationClass
from .reports import (
    CompiledVdtReport,
    ReportCompileError,
    ReportDiagnostic,
    ReportInputError,
    ReportOptions,
    compile_vdt_report,
    compile_vdt_report_from_history,
    load_evaluations,
    parse_rfc3339,
)
from .schemas import (
    MAX_REPORT_BYTES,
    ReportDocumentError,
    ReportSchema,
    validate_bundled_report_bytes,
)
from .store import (
    EventConcurrencyError,
    EventIntegrityError,
    EventStoreError,
    IntegrityFault,
    SQLiteEventStore,
)

PHASES = (
    ("0", "Harden stigroll ingestion and provenance"),
    ("1", "Build VDR cases, policy clocks, and VER exports"),
    ("2", "Add automation, coverage, and change integration"),
    ("3", "Add KSI validation and SDR evidence"),
    ("4", "Integrate trust-center and ongoing certification workflows"),
)


def _default_actor() -> str:
    """Return the operating-system user name, or a placeholder when there is none."""

    try:
        return getpass.getuser()
    except (KeyError, OSError):  # pragma: no cover - depends on the host account database
        return "unknown"


#: Resolved once, so `--help` prints the name every event of a run would carry.
DEFAULT_ACTOR = _default_actor()

#: The `cases list` columns, each with whether its values are right-aligned numbers.
CASE_COLUMNS: tuple[tuple[str, bool], ...] = (
    ("TRACKING ID", False),
    ("PROVIDER ID", False),
    ("SOURCE RECORD", False),
    ("RESOURCES", True),
    ("EVALUATIONS", True),
    ("PAIN", False),
    ("DISPOSITION", False),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="complyroll",
        description="Local-first evidence compiler for FedRAMP 20x VDR.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("version", help="show the ComplyRoll version")
    subparsers.add_parser("plan", help="show the high-level implementation phases")

    ingest = subparsers.add_parser(
        "ingest",
        help="record source artifacts and their observations as history",
        description=(
            "Parse each artifact and append it, with every observation it produced, to "
            "the event store. Recording the same artifact twice appends nothing."
        ),
    )
    ingest.add_argument("artifacts", nargs="+", metavar="ARTIFACT", help="CKLB, CKL, or XCCDF file")
    _add_database_option(ingest, "event store to append to, created when it does not exist")
    ingest.add_argument(
        "--as-of",
        metavar="RFC3339",
        help="instant recorded as the ingestion time (default: now, UTC)",
    )
    _add_actor_option(ingest)

    cases = subparsers.add_parser("cases", help="work with the persisted vulnerability cases")
    case_commands = cases.add_subparsers(dest="cases_command", required=True)

    correlate = case_commands.add_parser(
        "correlate",
        help="create cases for the recorded observations and link them",
    )
    _add_database_option(correlate, "event store holding the recorded observations")
    _add_actor_option(correlate)

    attest = case_commands.add_parser(
        "attest-detection",
        help="attest a detection time for cases whose sources declare none",
    )
    _add_database_option(attest, "event store holding the cases")
    attest.add_argument(
        "--detected-at",
        required=True,
        metavar="RFC3339",
        help="attested detection time",
    )
    attest.add_argument(
        "--rationale",
        required=True,
        metavar="TEXT",
        help="why this instant is the detection time",
    )
    selection = attest.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--case",
        action="append",
        dest="case_ids",
        metavar="ID",
        help="tracking identifier to attest; repeat for several cases",
    )
    selection.add_argument(
        "--all-missing",
        action="store_true",
        help=(
            "attest every case that carries no attestation yet and whose every "
            "observation link declares no source timestamp; a case already attested is "
            "not missing a detection time, so re-attesting it requires an explicit --case"
        ),
    )
    _add_actor_option(attest)

    evaluate = case_commands.add_parser(
        "evaluate",
        help="apply an evaluations file to the cases it selects",
    )
    _add_database_option(evaluate, "event store holding the cases")
    evaluate.add_argument(
        "--evaluations",
        required=True,
        metavar="FILE",
        help="JSON file of completed contextual evaluations",
    )
    _add_actor_option(evaluate)

    listing = case_commands.add_parser("list", help="list every recorded case")
    _add_database_option(listing, "event store to read")

    history = case_commands.add_parser("history", help="show one case's recorded history")
    history.add_argument("tracking_id", metavar="TRACKING_ID", help="case tracking identifier")
    _add_database_option(history, "event store to read")

    report = subparsers.add_parser("report", help="compile an official-format report")
    report_commands = report.add_subparsers(dest="report_command", required=True)
    vdt = report_commands.add_parser(
        "vdt",
        help="compile a Vulnerability Detail Report (VER-RPT-VDT)",
        description=(
            "Compile a Vulnerability Detail Report from source artifacts and explicit "
            "operator inputs, or from persisted history with --db. Output is "
            "official-format JSON; it is not a FedRAMP determination."
        ),
    )
    vdt.add_argument("artifacts", nargs="*", metavar="ARTIFACT", help="CKLB, CKL, or XCCDF file")
    vdt.add_argument(
        "--db",
        metavar="PATH",
        help="compile from this event store instead of from artifacts",
    )
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

    store = subparsers.add_parser("store", help="inspect the event store")
    store_commands = store.add_subparsers(dest="store_command", required=True)
    verify = store_commands.add_parser(
        "verify",
        help="walk the whole log and report every integrity fault",
        description=(
            "Walk the whole log and report every integrity fault. Verifying a WAL-mode "
            "store may leave -shm and -wal sidecar files beside it, while the database "
            "file's own bytes stay unchanged."
        ),
    )
    _add_database_option(verify, "event store to walk")

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


def _add_database_option(parser: argparse.ArgumentParser, help_text: str) -> None:
    """Add the required `--db` option every persisted command carries."""

    parser.add_argument("--db", required=True, metavar="PATH", help=help_text)


def _add_actor_option(parser: argparse.ArgumentParser) -> None:
    """Add the `--actor` option every writing command records in its metadata."""

    parser.add_argument(
        "--actor",
        default=DEFAULT_ACTOR,
        metavar="NAME",
        help="who is recording this work (default: %(default)s)",
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "version":
        print(f"ComplyRoll {__version__}")
        return 0

    if args.command == "plan":
        for phase, outcome in PHASES:
            print(f"Phase {phase}: {outcome}")
        return 0

    if args.command == "ingest":
        return _run_ingest(args)

    if args.command == "cases":
        return _run_cases(args)

    if args.command == "report":
        if args.report_command == "vdt":
            return _run_report_vdt(args)
        raise AssertionError(f"unhandled report command: {args.report_command}")

    if args.command == "store":
        if args.store_command == "verify":
            return _run_store_verify(args)
        raise AssertionError(f"unhandled store command: {args.store_command}")

    if args.command == "validate":
        return _run_validate(args)

    raise AssertionError(f"unhandled command: {args.command}")


def _run_ingest(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    database = Path(args.db)
    artifacts = [Path(item) for item in args.artifacts]
    try:
        ingested_at = _instant(args.as_of, "--as-of")
        metadata = _metadata(args)
    except ReportInputError as exc:
        return _fail(stderr, "invalid_input", str(exc))
    except ValueError as exc:
        return _fail(stderr, "invalid_option", str(exc))

    existed = database.exists()

    def ingest() -> int:
        # Every artifact is parsed before the store is opened, so a run that fails on
        # any of them records nothing and leaves no database file behind: opening a
        # SQLite path creates the file, and a failed first run would otherwise leave an
        # empty store where the operator had none.
        parsed: list[tuple[Path, IngestResult]] = []
        for path in artifacts:
            result = ingest_stig_artifact(path, ingested_at=ingested_at)
            _write_diagnostics(stderr, _as_report_diagnostics(result.diagnostics, path.name))
            if result.errors or result.artifact is None:
                # Fail closed: a damaged artifact stops the run before it, or any
                # artifact after it, becomes history.
                return 1
            parsed.append((path, result))

        with _open_repository(database) as repository:
            for path, result in parsed:
                outcome = record_ingest(
                    repository, result, metadata=metadata, ingested_at=ingested_at
                )
                if outcome.already_recorded:
                    print(f"{path.name}: already_recorded")
                else:
                    print(f"{path.name}: recorded {outcome.observation_count} observation(s)")
        return 0

    code = _persisted_run(stderr, ingest)
    if code != 0 and not existed:
        _discard_created_store(database)
    return code


def _discard_created_store(database: Path) -> None:
    """Remove the store a failed run created, so a failed ingest leaves nothing.

    Parsing every artifact first stops a damaged one from ever reaching the store, but
    a payload the contract refuses is only refused once the store is open, and opening
    a SQLite path is what creates the file. A path that held no file when the command
    started holds nothing but this run's litter now, and the operator asked for an
    ingestion, not for an empty database (ADR 0008 amendment). A store that already
    existed is never touched.
    """

    for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
        with suppress(OSError):
            path.unlink(missing_ok=True)


def _run_cases(args: argparse.Namespace) -> int:
    if args.cases_command == "correlate":
        return _run_cases_correlate(args)
    if args.cases_command == "attest-detection":
        return _run_cases_attest(args)
    if args.cases_command == "evaluate":
        return _run_cases_evaluate(args)
    if args.cases_command == "list":
        return _run_cases_list(args)
    if args.cases_command == "history":
        return _run_cases_history(args)
    raise AssertionError(f"unhandled cases command: {args.cases_command}")


def _run_cases_correlate(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    database = Path(args.db)
    try:
        metadata = _metadata(args)
    except ValueError as exc:
        return _fail(stderr, "invalid_option", str(exc))
    missing = _refuse_missing_store(stderr, database)
    if missing is not None:
        return missing

    def correlate() -> int:
        with _open_repository(database) as repository:
            outcome = correlate_cases(repository, metadata=metadata, now=_now())
        print(
            f"created {len(outcome.created)} case(s), "
            f"linked {outcome.linked} observation(s), "
            f"skipped {outcome.skipped_links} already-linked observation(s)"
        )
        return 0

    return _persisted_run(stderr, correlate)


def _run_cases_attest(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    database = Path(args.db)
    try:
        detected_at = parse_rfc3339(args.detected_at, "--detected-at")
        selected = tuple(require_tracking_id(item) for item in (args.case_ids or ()))
        metadata = _metadata(args)
    except ReportInputError as exc:
        return _fail(stderr, "invalid_input", str(exc))
    except ValueError as exc:
        return _fail(stderr, "invalid_option", str(exc))
    missing = _refuse_missing_store(stderr, database)
    if missing is not None:
        return missing

    def attest() -> int:
        with _open_repository(database) as repository:
            tracking_ids = (
                _cases_missing_detection(fold_all_cases(repository))
                if args.all_missing
                else selected
            )
            outcome = attest_detection(
                repository,
                tracking_ids,
                detected_at=detected_at,
                rationale=args.rationale,
                metadata=metadata,
                now=_now(),
            )
        for tracking_id in outcome.not_applicable:
            print(
                f"warning: attestation_not_applicable: {tracking_id} carries a source timestamp",
                file=stderr,
            )
        print(
            f"attested {len(outcome.attested)} case(s), "
            f"skipped {len(outcome.skipped)} unchanged case(s), "
            f"{len(outcome.not_applicable)} not applicable case(s)"
        )
        return 0

    return _persisted_run(stderr, attest)


def _run_cases_evaluate(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    database = Path(args.db)
    evaluations_path = Path(args.evaluations)
    try:
        metadata = _metadata(args)
    except ValueError as exc:
        return _fail(stderr, "invalid_option", str(exc))
    missing = _refuse_missing_store(stderr, database)
    if missing is not None:
        return missing

    def evaluate() -> int:
        evaluations = load_evaluations(evaluations_path)
        with _open_repository(database) as repository:
            outcome = apply_evaluations(repository, evaluations, metadata=metadata, now=_now())
        for warning in outcome.warnings:
            print(f"warning: {warning}", file=stderr)
        for label, appended, skipped in (
            ("evaluations", outcome.evaluations_appended, outcome.evaluations_skipped),
            ("pain reductions", outcome.reductions_appended, outcome.reductions_skipped),
            ("dispositions", outcome.dispositions_appended, outcome.dispositions_skipped),
            (
                "identifications",
                outcome.identifications_appended,
                outcome.identifications_skipped,
            ),
        ):
            print(f"{label}: {appended} appended, {skipped} skipped")
        return 0

    return _persisted_run(stderr, evaluate)


def _run_cases_list(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    database = Path(args.db)
    missing = _refuse_missing_store(stderr, database)
    if missing is not None:
        return missing

    def listing() -> int:
        with _open_repository(database) as repository:
            cases = fold_all_cases(repository)
        for line in _case_table(cases):
            print(line)
        return 0

    return _persisted_run(stderr, listing)


def _run_cases_history(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    database = Path(args.db)
    try:
        tracking_id = require_tracking_id(args.tracking_id)
    except ValueError as exc:
        return _fail(stderr, "invalid_option", str(exc))
    missing = _refuse_missing_store(stderr, database)
    if missing is not None:
        return missing

    def listing() -> int:
        with _open_repository(database) as repository:
            entries = case_history(repository, tracking_id)
        for entry in entries:
            print(entry.render())
        return 0

    return _persisted_run(stderr, listing)


def _run_store_verify(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    database = Path(args.db)
    missing = _refuse_missing_store(stderr, database)
    if missing is not None:
        return missing

    def verify() -> int:
        # The verification path opens read-only and skips the refusals the constructor
        # applies, so a file damaged in exactly those ways can still be described.
        with SQLiteEventStore.open_for_verification(database) as store:
            report = store.verify_history()
            if not report.ok:
                for fault in report.faults:
                    print(f"error: {fault.code}: {_fault_message(fault)}", file=stderr)
                print(report.render(), file=stderr)
                # A log with holes in it cannot be read event by event, and a contract
                # failure read off damaged rows would describe the damage twice.
                print(
                    "warning: payload_contracts_unchecked: the faults above were "
                    "reported instead; verify again once they are fixed",
                    file=stderr,
                )
                return 1
            breaches = _payload_contract_breaches(store)

        if breaches:
            for sequence, message in breaches:
                print(
                    f"error: payload_contract_invalid: sequence {sequence}: {message}",
                    file=stderr,
                )
            print(
                f"faults: {len(breaches)} payload(s) do not satisfy their published "
                f"contract in {report.checked_events} verified event(s)",
                file=stderr,
            )
            return 1
        print(report.render())
        return 0

    return _persisted_run(stderr, verify)


def _payload_contract_breaches(store: SQLiteEventStore) -> tuple[tuple[int, str], ...]:
    """Return every stored payload that does not satisfy its published contract.

    The store's own walk proves the log is intact: nothing was rewritten, no sequence
    is missing, every digest still matches. Intact is not the same as readable. A
    payload appended around `EventRepository`, or one a since-tightened contract would
    now refuse, is a faithfully stored event the replay reader will not read, and a
    verify that printed "ok" over it would leave the operator to discover that from a
    failing `report vdt`. So a clean log is read once more through the contracts that
    give its events meaning (ADR 0008 Decision 1).
    """

    repository = EventRepository(store)
    breaches: list[tuple[int, str]] = []
    for record in repository.read_all():
        try:
            repository.validate_payload(
                record.event_type, record.payload, event_version=record.event_version
            )
        except EventContractError as exc:
            breaches.append((record.sequence, str(exc)))
    return tuple(breaches)


def _run_report_vdt(args: argparse.Namespace) -> int:
    stderr = sys.stderr
    database = Path(args.db) if args.db else None
    artifacts = [Path(item) for item in args.artifacts]
    output = Path(args.output) if args.output else None
    markdown = Path(args.markdown) if args.markdown else None
    evaluations_path = Path(args.evaluations) if args.evaluations else None

    conflict = _report_source_conflict(args)
    if conflict is not None:
        return _fail(stderr, "invalid_option", conflict)
    if database is not None:
        missing = _refuse_missing_store(stderr, database)
        if missing is not None:
            return missing

    try:
        _refuse_input_overwrite(
            outputs=(output, markdown),
            inputs=(
                *artifacts,
                *(item for item in (evaluations_path, database) if item),
            ),
        )
        options = ReportOptions(
            certification_class=CertificationClass(args.certification_class),
            package_uri=args.package_uri,
            period_from=parse_rfc3339(args.period_from, "--from"),
            period_to=parse_rfc3339(args.period_to, "--to"),
            as_of=_instant(args.as_of, "--as-of"),
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

    def compile_report() -> CompiledVdtReport:
        if database is None:
            return compile_vdt_report(artifacts, options=options, evaluations=evaluations)
        with _open_repository(database) as repository:
            return compile_vdt_report_from_history(repository, options=options)

    return _persisted_run(
        stderr,
        lambda: _publish(stderr, compile_report(), output=output, markdown=markdown),
    )


def _report_source_conflict(args: argparse.Namespace) -> str | None:
    """Return why a `report vdt` run names the wrong sources, or None when it is fine.

    A store already holds its artifacts, its evaluations, and the detection times an
    operator attested, so naming any of them alongside `--db` asks one run to honour two
    sources of truth. Naming neither leaves nothing to compile.
    """

    named = [
        name
        for name, present in (
            ("artifacts", bool(args.artifacts)),
            ("--evaluations", args.evaluations is not None),
            ("--detected-at", args.detected_at is not None),
        )
        if present
    ]
    if args.db is not None and named:
        return f"report vdt takes either --db or {', '.join(named)}, never both"
    if args.db is None and not args.artifacts:
        return "report vdt needs at least one artifact, or --db"
    return None


def _publish(
    stderr: TextIO,
    report: CompiledVdtReport,
    *,
    output: Path | None,
    markdown: Path | None,
) -> int:
    """Write one compiled report to its destinations, all of them or none."""

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


@contextmanager
def _open_repository(path: Path) -> Iterator[EventRepository]:
    """Open one store for the duration of a command and always close it."""

    store = SQLiteEventStore(path)
    try:
        yield EventRepository(store)
    finally:
        store.close()


def _persisted_run(stream: TextIO, action: Callable[[], int]) -> int:
    """Run one command against the store, reporting a domain failure as one error line.

    The clauses are ordered most specific first, so a missing case is reported as a
    missing case rather than as unreadable history, and a version conflict is reported
    as a conflict rather than as an unavailable store.
    """

    try:
        return action()
    except ReportCompileError as exc:
        _write_diagnostics(stream, exc.diagnostics)
        return 1
    except CaseNotFoundError as exc:
        return _fail(stream, "case_not_found", str(exc))
    except EvaluationMatchError as exc:
        return _fail(stream, "evaluation_unmatched", str(exc))
    except HistoryError as exc:
        return _fail(stream, "history_invalid", str(exc))
    except EventContractError as exc:
        return _fail(stream, "event_contract_invalid", str(exc))
    except EventConcurrencyError as exc:
        return _fail(stream, "store_conflict", str(exc))
    except EventIntegrityError as exc:
        return _fail(stream, "store_integrity", str(exc))
    except EventStoreError as exc:
        return _fail(stream, "store_unavailable", str(exc))
    except ReportInputError as exc:
        return _fail(stream, "invalid_input", str(exc))
    except OSError as exc:
        location = getattr(exc, "filename", None)
        return _fail(stream, "store_unavailable", str(exc), location=location)


def _refuse_missing_store(stream: TextIO, database: Path) -> int | None:
    """Refuse a command whose store must already exist, creating nothing.

    Opening a SQLite path that holds no file makes an empty database, so a typo in
    `--db` would otherwise be answered with an empty report, or with a correlation
    that found nothing to correlate, and a new file where the operator had none.
    `ingest` is the one command that may create a store.
    """

    if database.is_file():
        return None
    return _fail(
        stream,
        "store_missing",
        f"no event store at {str(database)!r}; only ingest creates one",
    )


def _metadata(args: argparse.Namespace) -> EventMetadata:
    """Build the one metadata envelope every event of this invocation carries.

    `EventMetadata` mints a fresh run identifier per instance, so building it once per
    invocation is what makes a run's events findable together.
    """

    return EventMetadata(actor=args.actor)


def _now() -> datetime:
    """Return the current UTC instant at second precision."""

    return datetime.now(UTC).replace(microsecond=0)


def _instant(value: str | None, flag: str) -> datetime:
    """Return the instant a flag names, or the current UTC instant at second precision."""

    if value is None:
        return _now()
    return parse_rfc3339(value, flag)


def _cases_missing_detection(cases: Sequence[CaseState]) -> tuple[str, ...]:
    """Return the cases that carry no attestation and no source timestamp at all.

    A case with no links at all is still missing a detection time, so it is selected. A
    case that already carries an attestation is not missing one, whatever that
    attestation says, so revising it is an explicit `--case` decision rather than
    something a sweep does on the operator's behalf.
    """

    return tuple(
        case.tracking_id
        for case in cases
        if case.attestation is None and all(link.observed_at is None for link in case.links)
    )


def _case_table(cases: Sequence[CaseState]) -> tuple[str, ...]:
    """Render the case listing, header first, sized to its widest cell per column."""

    rows = [_case_row(case) for case in cases]
    widths = [
        max([len(header), *(len(row[index]) for row in rows)])
        for index, (header, _) in enumerate(CASE_COLUMNS)
    ]
    headers = tuple(header for header, _ in CASE_COLUMNS)
    return tuple(_case_line(values, widths) for values in (headers, *rows))


def _case_row(case: CaseState) -> tuple[str, ...]:
    """Return one case's cells, in `CASE_COLUMNS` order."""

    resources = {(link.resource_type, link.resource_id) for link in case.links}
    evaluation = case.current_evaluation
    disposition = case.disposition
    return (
        case.tracking_id,
        case.provider_tracking_id or "-",
        case.source_record_id,
        str(len(resources)),
        str(case.evaluation_count),
        "-" if evaluation is None else str(int(evaluation.pain)),
        "active" if disposition is None else disposition.status.value,
    )


def _case_line(values: Sequence[str], widths: Sequence[int]) -> str:
    cells = [
        value.rjust(width) if numeric else value.ljust(width)
        for value, width, (_, numeric) in zip(values, widths, CASE_COLUMNS, strict=True)
    ]
    return "  ".join(cells).rstrip()


def _fault_message(fault: IntegrityFault) -> str:
    """Fold the offending sequence into a fault's message when it names one."""

    if fault.sequence is None:
        return fault.message
    return f"sequence {fault.sequence}: {fault.message}"


def _as_report_diagnostics(
    diagnostics: Sequence[IngestDiagnostic],
    location: str,
) -> tuple[ReportDiagnostic, ...]:
    """Render ingest diagnostics the way the report path renders them.

    The artifact name stands in for a diagnostic that names no location, so what an
    operator reads never depends on the directory the artifact was read from.
    """

    return tuple(
        ReportDiagnostic(
            level=item.level,
            code=item.code,
            message=item.message,
            location=item.location or location,
        )
        for item in diagnostics
    )


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
