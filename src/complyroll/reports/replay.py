"""Rebuild report record sets from persisted history (ADR 0008 Decision 5).

Artifacts, observations, and ingest diagnostics are read back from `artifact.ingested`
and `observation.recorded` events in recorded order; each case stream is folded into its
current state; and the result is handed to the same record compiler the stateless path
uses. Nothing is recomputed differently and nothing is cached, so a report rebuilt from
the log is byte-identical to the stateless report compiled from the same inputs. A current
failure stream reads back as its system observation and its head's diagnostics, which are
what the stateless path compiled for that failure (ADR 0014 records where the two differ).
Current is the stream that carries the failure: a hold left dormant beneath it is named,
not read back (ADR 0014, amendment 2026-10-13). A coverage stream reads back as its gap
record, and a store marked schema 4 compiles gap aware, naming each window no recorded gap
carries and each recorded gap this run derives no window for (ADR 0015).

Detection-time attestations are per case here rather than one flag on the command line.
An attestation still applies only to a group where no observation declares a source
timestamp. When every attested case shares one instant the report emits the same
`detectionTimeAttestation` object the stateless path emits: that instant, the tracking
identifiers it applied to, and their count. When cases carry different attested instants
there is no single report-level instant to publish, so the block names each instant with
the records it covers instead of asserting one that would be false for some of them.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from complyroll.adapters import DiagnosticLevel
from complyroll.correlation import group_open_observations
from complyroll.events import COVERAGE_STREAM_SCHEMA_VERSION, EventRepository, is_failure_stream
from complyroll.models import Observation

from .avi import CompiledAviReport, project_avi
from .evaluations import EvaluationInput, EvaluationMatch
from .historical import CompiledHistoricalReport, project_historical
from .vdt import (
    CompiledArtifact,
    CompiledRecordSet,
    CompiledVdtReport,
    DetectionAttestation,
    ReportCompileError,
    ReportDiagnostic,
    ReportOptions,
    compile_record_set,
    project_vdt,
)

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from complyroll.history import ArtifactHistory, ArtifactRecord, CaseState, FailureRecord


def compile_vdt_report_from_history(
    repository: EventRepository,
    *,
    options: ReportOptions,
) -> CompiledVdtReport:
    """Compile one Vulnerability Detail Report from stored history.

    See `compile_record_set_from_history` for what is read back and for why
    `options.detected_at_attestation` is ignored on this path.
    """

    return project_vdt(compile_record_set_from_history(repository, options=options))


def compile_avi_report_from_history(
    repository: EventRepository,
    *,
    options: ReportOptions,
) -> CompiledAviReport:
    """Compile one Accepted Vulnerability Information report from stored history.

    See `compile_record_set_from_history` for what is read back and for why
    `options.detected_at_attestation` is ignored on this path.
    """

    return project_avi(compile_record_set_from_history(repository, options=options))


def compile_historical_report_from_history(
    repository: EventRepository,
    *,
    options: ReportOptions,
) -> CompiledHistoricalReport:
    """Compile one Historical VER Activity snapshot from stored history.

    See `compile_record_set_from_history` for what is read back and for why
    `options.detected_at_attestation` is ignored on this path.
    """

    return project_historical(compile_record_set_from_history(repository, options=options))


def compile_record_set_from_history(
    repository: EventRepository,
    *,
    options: ReportOptions,
) -> CompiledRecordSet:
    """Compile the record set every report projects from, out of stored history.

    `options.detected_at_attestation` is ignored on this path. Attestations are facts
    the log already holds, one `detection.attested` event per case, so a command-line
    flag has nothing to add and must not silently override what an operator filed.
    `options.record_coverage_gaps` is refused rather than ignored: a report never records a
    gap, `cases coverage` does (ADR 0015). The store decides instead: one marked schema 4
    has recorded gaps, so with an inventory the report is gap aware, each window naming the
    recorded gap that carries it or none. A store that never recorded a gap reads exactly
    as the stateless run without the flag, whatever the build that reads it.
    """

    if not isinstance(options, ReportOptions):
        raise TypeError("options must be a ReportOptions")
    if options.record_coverage_gaps:
        raise ValueError(
            "record_coverage_gaps applies only to a compile from artifacts; a report from "
            "history never records a coverage gap"
        )
    # Imported here because `complyroll.history` reads the report layer's evaluation
    # shapes, so a module-level import would close a cycle whenever history is the
    # first of the two packages a caller imports.
    from complyroll.history import artifact_history, fold_all_cases, rehydrate_observations

    history = artifact_history(repository)
    artifacts = tuple(_compiled_artifact(record) for record in history.current)
    observations = rehydrate_observations(repository)
    cases = fold_all_cases(repository)
    diagnostics = (
        _ingest_diagnostics((*history.current, *history.current_failures))
        + _superseded_artifacts(history)
        + _superseded_failures(history)
        + _held_failures(history)
        + _stale_cases(cases, observations)
    )
    return compile_record_set(
        artifacts=artifacts,
        observations=observations,
        ingest_diagnostics=diagnostics,
        evaluations_by_tracking_id=_evaluations(cases),
        attestation=_attestation(cases),
        options=options,
        gap_aware=(
            options.inventory is not None
            and repository.store.schema_version >= COVERAGE_STREAM_SCHEMA_VERSION
        ),
    )


def _compiled_artifact(record: ArtifactRecord) -> CompiledArtifact:
    """Read one stored artifact provenance record as the compiler's artifact."""

    return CompiledArtifact(
        name=record.name,
        sha256=record.sha256,
        parser=record.parser_name,
        parser_version=record.parser_version,
        size_bytes=record.size_bytes,
        observation_count=record.observation_count,
    )


def _ingest_diagnostics(
    records: Sequence[ArtifactRecord | FailureRecord],
) -> tuple[ReportDiagnostic, ...]:
    """Reproduce the ingest diagnostics the stateless path would have raised.

    The artifact name stands in for a diagnostic that names no location, exactly as the
    stateless compiler substitutes the artifact's file name, so a report never depends
    on the directory layout of the machine that ingested it.

    A current failure's head holds `failure_diagnostics`, every ERROR already demoted, and
    a side record's holds only its `detection_failure_recorded` notice, because the
    reading's own diagnostics are on its artifact stream (ADR 0014). Each diagnostic is
    therefore read back once, as the stateless path emits it.

    No stored diagnostic is an ERROR. `record_ingest` refuses one, a failure head carries
    each one demoted, and the contracts of `artifact.ingested`, `failure.recorded` and
    `failure.held` admit INFO and WARNING alone. The fold checks every head against its
    contract before it reads it, so an ERROR planted in a stored head stops the fold with
    `HistoryError` and never reaches here. The refusal below stays behind that check, so
    an ERROR that ever got past it would still stop the run as a failed ingest does.
    """

    diagnostics: list[ReportDiagnostic] = []
    errors: list[ReportDiagnostic] = []
    for record in records:
        for item in record.diagnostics:
            entry = ReportDiagnostic(
                level=item.level,
                code=item.code,
                message=item.message,
                location=item.location or record.name,
            )
            if item.level is DiagnosticLevel.ERROR:
                errors.append(entry)
            else:
                diagnostics.append(entry)
    if errors:
        raise ReportCompileError(errors)
    return tuple(diagnostics)


def _superseded_artifacts(history: ArtifactHistory) -> tuple[ReportDiagnostic, ...]:
    """Name every artifact stream a newer reading or a newer parser's failure replaced.

    One artifact digest read by two parser versions is two streams (ADR 0002), and the
    fold rehydrates only the newest, because reading both would report every finding
    twice under two sets of observation identifiers. Dropping the older reading in
    silence would leave the page unable to say that history holds an earlier reading of
    the same bytes, so each one is named here with the version that replaced it.

    A newer version of the parser that read every stream of the digest, failing on the
    same bytes, replaces them all with its failure (ADR 0014, R2). That reading is named
    as `artifact_superseded_by_failure`, with the failure the report carries instead. The
    fold records each replacement as it decides it, so there is always one to name.
    """

    diagnostics: list[ReportDiagnostic] = []
    for record in history.superseded:
        newest = history.replaced_by[record.stream_id]
        if is_failure_stream(newest.stream_id):
            code = "artifact_superseded_by_failure"
            message = (
                f"{record.name} was recorded by {record.parser_name} {record.parser_version} "
                f"and failed under the newer {newest.parser_name} {newest.parser_version}; "
                "this report carries the failure, so the older reading is in history but not "
                "in it"
            )
        else:
            code = "artifact_superseded"
            message = (
                f"{record.name} was recorded by {record.parser_name} "
                f"{record.parser_version} and again by {newest.parser_name} "
                f"{newest.parser_version}; this report reads the newest stream, so the "
                "older reading is in history but not in it"
            )
        diagnostics.append(
            ReportDiagnostic(
                level=DiagnosticLevel.INFO,
                code=code,
                message=message,
                location=record.stream_id or record.name,
            )
        )
    return tuple(diagnostics)


def _superseded_failures(history: ArtifactHistory) -> tuple[ReportDiagnostic, ...]:
    """Name every failure stream a reading of the same bytes resolved (ADR 0014, R3, R4).

    A resolved failure's system observation is not rehydrated, so its case reads as
    `stale_case`. This names the failure itself, so the page can say why.
    """

    return tuple(
        ReportDiagnostic(
            level=DiagnosticLevel.INFO,
            code="failure_superseded",
            message=(
                f"{record.name} failed under {record.parser_name} {record.parser_version}, "
                "and history holds a reading of the same bytes that resolves it; the failure "
                "is in history but not in this report"
            ),
            location=record.stream_id or record.name,
        )
        for record in history.superseded_failures
    )


def _held_failures(history: ArtifactHistory) -> tuple[ReportDiagnostic, ...]:
    """Name every failure stream R6 leaves dormant (ADR 0014, amendment 2026-10-13).

    A hold stores its own reading of a system observation another failure stream of the
    same bytes also holds. The report carries one record of that observation, the earliest
    no reading supersedes, so a dormant hold's head and record are in no `detectionFailures`
    entry and its diagnostics are not read back. This names the hold, at its own stream,
    with the parser and version whose record the report carries in its place.
    """

    diagnostics: list[ReportDiagnostic] = []
    for record in history.dormant_failures:
        carrier = history.carried_by[record.stream_id]
        diagnostics.append(
            ReportDiagnostic(
                level=DiagnosticLevel.INFO,
                code="failure_held",
                message=(
                    f"{record.name} failed under {record.parser_name} {record.parser_version}; "
                    f"this report carries the same failure as {carrier.parser_name} "
                    f"{carrier.parser_version} recorded it, so this reading's failure is in "
                    "history but not in it"
                ),
                location=record.stream_id or record.name,
            )
        )
    return tuple(diagnostics)


def _stale_cases(
    cases: Sequence[CaseState],
    observations: Sequence[Observation],
) -> tuple[ReportDiagnostic, ...]:
    """Name every stored case that no current observation group matches.

    History outlives any one ingest. A case whose artifact was never re-ingested, or
    whose observations are no longer open, has nothing to report against, and dropping
    it silently would let a report shrink with no explanation on the page.
    """

    known = {group.tracking_id for group in group_open_observations(observations)}
    return tuple(
        ReportDiagnostic(
            level=DiagnosticLevel.INFO,
            code="stale_case",
            message=(
                f"{case.tracking_id} is recorded in history but no open observation "
                "group matches it, so it is not in this report"
            ),
            location=case.stream_id,
        )
        for case in cases
        if case.tracking_id not in known
    )


def _attestation(cases: Sequence[CaseState]) -> DetectionAttestation:
    """Collect every case's attested detection time, keyed by tracking identifier.

    There is no default: history attests one case at a time, never globally.
    """

    return DetectionAttestation(
        by_tracking_id={
            case.tracking_id: case.attestation.detected_at
            for case in cases
            if case.attestation is not None
        }
    )


def _evaluations(cases: Sequence[CaseState]) -> dict[str, EvaluationInput]:
    """Rebuild the compiler's evaluation input from each case's folded state.

    `index` is the case's position in tracking-identifier order. It only ever surfaces
    through `EvaluationInput.location`, which the compiler cites when two tracking-id
    overrides collide; on this path that citation reads as a position in the case list
    rather than a line in an evaluations file.

    A disposition rides on the evaluation the compiler reads, so a case that carries a
    disposition and no evaluation has a recorded fact with nowhere to go. Skipping it
    would drop a filed disposition off the report with nothing on the page to say so,
    which is exactly the silent shrink `stale_case` exists to prevent, so the rebuild
    stops instead. `cases evaluate` cannot produce that state; reaching it means the
    log was written by something else.
    """

    errors: list[ReportDiagnostic] = []
    evaluations: dict[str, EvaluationInput] = {}
    for index, case in enumerate(cases):
        current = case.current_evaluation
        if current is None:
            if case.disposition is not None:
                errors.append(
                    ReportDiagnostic(
                        level=DiagnosticLevel.ERROR,
                        code="disposition_without_evaluation",
                        message=(
                            f"{case.tracking_id} records disposition "
                            f"{case.disposition.status.value!r} with no evaluation, so the "
                            "disposition cannot be reported"
                        ),
                        location=case.stream_id,
                    )
                )
            continue
        disposition = case.disposition
        evaluations[case.tracking_id] = EvaluationInput(
            index=index,
            match=EvaluationMatch(
                source_record_id=case.source_record_id,
                context_key=case.context_key,
                source_type=case.source_type,
            ),
            completed_at=current.completed_at,
            is_internet_reachable=current.is_internet_reachable,
            is_likely_exploitable=current.is_likely_exploitable,
            pain=current.pain,
            potential_agency_impact=current.potential_agency_impact,
            rationale=current.rationale,
            evaluator=current.evaluator,
            tracking_id=case.provider_tracking_id,
            is_false_positive=current.is_false_positive,
            disposition=None if disposition is None else disposition.status,
            closed_disposition=(None if disposition is None else disposition.closed_disposition),
            projected_next_reduction=current.projected_next_reduction,
            pain_reduction_events=tuple(item.event for item in case.pain_reductions),
            supplementary_risk_information=current.supplementary_risk_information,
            acceptance_rationale=(
                None if disposition is None else disposition.acceptance_rationale
            ),
        )
    if errors:
        raise ReportCompileError(errors)
    return evaluations


__all__ = [
    "compile_avi_report_from_history",
    "compile_historical_report_from_history",
    "compile_record_set_from_history",
    "compile_vdt_report_from_history",
]
