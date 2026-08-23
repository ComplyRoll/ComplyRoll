"""ComplyRoll command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
import shutil
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
    audit_history,
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
    ingest.add_argument(
        "artifacts", nargs="+", metavar="ARTIFACT", help="CKLB, CKL, XCCDF, or ARF file"
    )
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
    vdt.add_argument(
        "artifacts", nargs="*", metavar="ARTIFACT", help="CKLB, CKL, XCCDF, or ARF file"
    )
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
    dangling = _refuse_dangling_store_link(stderr, database)
    if dangling is not None:
        return dangling

    recorded: list[str] = []

    def ingest(target: Path) -> int:
        # Every artifact is parsed before the store is opened, so a run that fails on any
        # of them records nothing at all: opening a SQLite path is what creates the file,
        # and an existing store must not gain one artifact's history from a run the next
        # artifact stopped.
        parsed: list[tuple[Path, IngestResult]] = []
        for path in artifacts:
            result = ingest_stig_artifact(path, ingested_at=ingested_at)
            _write_diagnostics(stderr, _as_report_diagnostics(result.diagnostics, path.name))
            if result.errors or result.artifact is None:
                # Fail closed: a damaged artifact stops the run before it, or any
                # artifact after it, becomes history.
                return 1
            parsed.append((path, result))

        # One transaction around every artifact of the run. Each `record_ingest` joins it
        # rather than opening its own, so a failure on any artifact leaves the store
        # exactly as it was and the empty summary below is the truth: nothing became
        # durable (ADR 0008, second amendment).
        with _open_repository(target) as repository, repository.transaction():
            for path, result in parsed:
                outcome = record_ingest(
                    repository, result, metadata=metadata, ingested_at=ingested_at
                )
                if outcome.already_recorded:
                    recorded.append(f"{path.name}: already_recorded")
                else:
                    recorded.append(
                        f"{path.name}: recorded {outcome.observation_count} observation(s)"
                    )
        return 0

    # A store that is already there is opened in place; concurrent writers contend on the
    # store's own transactions. A path with nothing behind it is built elsewhere and
    # published, because only a build that finished should ever appear at that path.
    code = (
        _persisted_run(stderr, lambda: ingest(database))
        if database.exists()
        else _build_and_publish_store(stderr, database, ingest)
    )
    if code != 0:
        return code
    # Reported only once the store is published, so no run ever claims to have recorded
    # observations it then discarded.
    for line in recorded:
        print(line)
    return 0


def _build_and_publish_store(
    stderr: TextIO,
    database: Path,
    build: Callable[[Path], int],
) -> int:
    """Build a new store beside its destination and publish it once the run succeeded.

    An ingest into a path with no file behind it used to open that path directly and
    unlink it again when the run failed. Between the existence check and the failure a
    concurrent ingest can create and populate a real store at exactly that path, and the
    failing run would delete it. So a new store is built at a temporary path in the
    destination's own directory and published with `os.link`, which refuses to overwrite:
    a store that appeared meanwhile is reported, never clobbered (ADR 0008, second
    amendment). Nothing but the temporary file is ever removed.

    The temporary is closed before it is linked, so SQLite has removed its `-wal` and
    `-shm` sidecars and the published file is the whole store.
    """

    try:
        temporary = _reserve_store_path(database)
    except OSError as exc:
        location = getattr(exc, "filename", None)
        return _fail(stderr, "store_unavailable", str(exc), location=location)

    def publish() -> int:
        code = build(temporary)
        if code != 0:
            return code
        try:
            os.link(temporary, database)
        except FileExistsError:
            return _fail(
                stderr,
                "store_conflict",
                f"a store appeared at {str(database)!r} while this run was building "
                "one; repeat the run against it",
            )
        return 0

    try:
        return _persisted_run(stderr, publish)
    finally:
        _discard_store_path(temporary)


def _reserve_store_path(database: Path) -> Path:
    """Reserve a unique path beside the destination for the store being built.

    The file is created empty and exclusively, which is what makes the name this run's
    alone. SQLite reads a zero-length file as a new database, so the reservation costs
    nothing beyond the name.
    """

    handle, name = tempfile.mkstemp(
        dir=database.parent, prefix=f".{database.name}.", suffix=".tmp"
    )
    os.close(handle)
    return Path(name)


def _discard_store_path(temporary: Path) -> None:
    """Remove the store this run built at a temporary path, and its sidecars.

    Only this run's own temporary is removed. The destination is never unlinked, whether
    it held a store when the run started or one appeared while the run was building:
    a failed ingest must leave the operator exactly what they had.
    """

    for path in (temporary, Path(f"{temporary}-wal"), Path(f"{temporary}-shm")):
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
        if args.all_missing:
            # A sweep chooses its own cases, so the count it chose is the one fact the
            # operator cannot read off the command line.
            print(
                f"selected {len(tracking_ids)} case(s) with no source timestamp on "
                "any observation"
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
            # The store's walk proves the bytes are intact: nothing rewritten, no
            # sequence missing, every digest still matching. Intact is not the same as
            # meaningful, so an intact log is audited once more against the contracts,
            # stream kinds, artifact counts, and metadata rules that give its events
            # meaning (ADR 0008, second amendment).
            faults = audit_history(EventRepository(store))

        if faults:
            for domain_fault in faults:
                print(f"error: {domain_fault.render()}", file=stderr)
            print(
                f"faults: {len(faults)} domain fault(s) in "
                f"{report.checked_events} verified event(s)",
                file=stderr,
            )
            return 1
        print(report.render())
        return 0

    return _persisted_run(stderr, verify)


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

    # Both destination refusals are decided from the paths alone, so they run here rather
    # than at publication time: a run that was never going to be allowed to write its
    # outputs should not parse an artifact or open a store before it says so.
    linked = _symlink_destination((output, markdown))
    if linked is not None:
        return _fail(
            stderr,
            "output_is_symlink",
            "the output destination is a symbolic link; publishing replaces a destination "
            "and restores it from a copy of its bytes, which would keep the content and "
            "lose the link",
            location=str(linked),
        )

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

    # A symbolic-link destination is refused in `_run_report_vdt`, before anything is
    # parsed or opened, because the paths are all that decision needs.
    try:
        _write_all_or_nothing(targets)
    except OutputRollbackError as exc:
        return _fail(stderr, "output_rollback_failed", _rollback_message(exc))
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


def _refuse_dangling_store_link(stream: TextIO, database: Path) -> int | None:
    """Refuse an `ingest --db` path that is a symbolic link with nothing behind it.

    `Path.exists` follows links, so a dangling one reads as a path with no store, and the
    run builds a store beside it and then fails to publish: `os.link` refuses a name the
    link already occupies, and the operator is told a store appeared meanwhile, which is
    not what happened. A link pointing at a real store is not refused; that store is
    opened in place, through the link, as any other existing store is.
    """

    if not database.is_symlink() or database.exists():
        return None
    return _fail(
        stream,
        "store_unavailable",
        f"the store path is a symbolic link to {_link_target(database)!r}, which does not "
        "exist; point the link at a store, or name the store itself",
        location=str(database),
    )


def _link_target(link: Path) -> str:
    """Return what one symbolic link points at, or a placeholder when it cannot be read."""

    try:
        return os.readlink(link)
    except OSError:
        return "an unreadable path"


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


class OutputRollbackError(Exception):
    """A failed publication could not be undone, so the destinations are left mixed.

    Carries the failure that stopped the publication and every destination still holding
    this run's content, each with the keeper that holds what it held before (or None when
    this run created the destination and could not remove it again) and the error the
    rollback itself raised for that destination. Those keepers are the only remaining copy
    of the previous reports, so they stay on disk (ADR 0007 amendment).
    """

    def __init__(
        self,
        cause: OSError,
        stranded: Sequence[tuple[Path, Path | None, OSError]],
    ) -> None:
        self.cause = cause
        self.stranded: tuple[tuple[Path, Path | None, OSError], ...] = tuple(stranded)
        super().__init__(str(cause))


def _rollback_message(failure: OutputRollbackError) -> str:
    """Word the one line an operator reads when the outputs could not be put back.

    Each destination carries the error that stopped its own restore. A permission problem
    and a full filesystem call for different remedies, and the original write failure is
    not necessarily the reason the rollback failed too, so naming only the first would
    send the operator after the wrong one.
    """

    stranded = "; ".join(
        (
            f"{destination} holds this run's content and what it held before is kept at "
            f"{keeper} (restore failed: {error})"
            if keeper is not None
            else f"{destination} holds this run's content, which this run created and "
            f"could not remove again (removal failed: {error})"
        )
        for destination, keeper, error in failure.stranded
    )
    return (
        f"{failure.cause}, and putting the outputs back failed as well: {stranded}. "
        "Restore each destination by hand from the file kept beside it."
    )


def _symlink_destination(destinations: Sequence[Path | None]) -> Path | None:
    """Return the first destination that is a symbolic link, or None when none is.

    Publishing replaces a destination and restores it from a copy of its bytes, which
    would follow the link on the way in and replace the link itself on the way back: the
    content would survive and the link would not. `Path.is_symlink` does not follow the
    link, so a dangling one is refused too (ADR 0007 amendment).

    The check runs on the paths alone, so `report vdt` can make it before it parses an
    artifact or opens a store: refusing a destination the run was never going to be
    allowed to write should not cost the operator a compile first.
    """

    for destination in destinations:
        if destination is not None and destination.is_symlink():
            return destination
    return None


def _write_all_or_nothing(targets: Sequence[tuple[Path, str]]) -> None:
    """Write every output, or none of them.

    Each destination is staged in a temporary file beside it and fsynced, and every
    destination that already exists is preserved beside itself, before any destination
    is replaced. Two renames cannot be one atomic step, so the rule is made good by
    rollback: a replace that fails restores every destination this run had already
    replaced, removes the ones this run created, and leaves no temporary behind. A
    failed Markdown write therefore leaves the previous JSON exactly as it was, and a
    failed JSON write leaves the previous Markdown (ADR 0007 amendment).

    A rollback can fail too. When it does, every destination it could not put back keeps
    the copy of its previous content beside it and `OutputRollbackError` names both, so a
    mixed pair of outputs is reported and recoverable rather than silent and lost.

    What two renames still cannot promise is power-failure atomicity across two paths;
    a crash between them leaves one destination updated, which the next run overwrites.
    """

    staged = _stage(targets)
    preserved: list[Path | None] = []
    try:
        for _, destination in staged:
            preserved.append(_preserve(destination))
    except OSError:
        _remove_preserved(preserved)
        _discard(staged)
        raise

    published = 0
    try:
        for temporary, destination in staged:
            os.replace(temporary, destination)
            published += 1
    except OSError as exc:
        stranded = _roll_back(staged[:published], preserved[:published])
        _discard(staged)
        # Every keeper but the ones still holding a destination's previous content: those
        # are what the operator recovers from, so removing them is what the message below
        # would be apologising for.
        kept = {keeper for _, keeper, _ in stranded if keeper is not None}
        _remove_preserved([keeper for keeper in preserved if keeper not in kept])
        if stranded:
            raise OutputRollbackError(exc, stranded) from exc
        raise
    _remove_preserved(preserved)


def _stage(targets: Sequence[tuple[Path, str]]) -> tuple[tuple[Path, Path], ...]:
    """Write every output to a fsynced temporary file beside its own destination."""

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
    return tuple(staged)


def _preserve(destination: Path) -> Path | None:
    """Copy one existing destination beside itself, or return None when it has none.

    The copy is what a failed publication is restored from. Bytes are copied rather than
    hard linked so the rollback still works on a filesystem that has no links, and a
    report is bounded by `MAX_REPORT_BYTES`, so the copy is cheap.
    """

    if not destination.exists():
        return None
    handle, name = tempfile.mkstemp(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".keep"
    )
    os.close(handle)
    keeper = Path(name)
    try:
        shutil.copyfile(destination, keeper)
    except OSError:
        keeper.unlink(missing_ok=True)
        raise
    return keeper


def _roll_back(
    published: Sequence[tuple[Path, Path]],
    preserved: Sequence[Path | None],
) -> tuple[tuple[Path, Path | None, OSError], ...]:
    """Put back every destination this run had already replaced.

    A destination that existed before the run is restored from its preserved copy; one
    that did not is removed, since this run is the only thing that created it. Whatever
    could not be put back is returned, each destination with the keeper that still holds
    its previous content and with the error that stopped its own restore, so the caller
    can keep that keeper and name all three in its error. Suppressing a failed restore and
    then deleting the keeper left the operator with new JSON beside old Markdown, no copy
    of either previous file, and not a word about it (ADR 0007 amendment).
    """

    stranded: list[tuple[Path, Path | None, OSError]] = []
    for (_, destination), keeper in zip(published, preserved, strict=True):
        try:
            if keeper is None:
                destination.unlink(missing_ok=True)
            else:
                os.replace(keeper, destination)
        except OSError as exc:
            stranded.append((destination, keeper, exc))
    return tuple(stranded)


def _remove_preserved(preserved: Sequence[Path | None]) -> None:
    """Remove every preserved copy still on disk, restored or not."""

    for keeper in preserved:
        if keeper is not None:
            with suppress(OSError):
                keeper.unlink(missing_ok=True)


def _discard(staged: Sequence[tuple[Path, Path]]) -> None:
    for temporary, _ in staged:
        with suppress(OSError):
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
