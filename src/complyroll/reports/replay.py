"""Rebuild the Vulnerability Detail Report from persisted history (ADR 0008 Decision 5).

Artifacts, observations, and ingest diagnostics are read back from `artifact.ingested`
and `observation.recorded` events in recorded order; each case stream is folded into its
current state; and the result is handed to the same record compiler the stateless path
uses. Nothing is recomputed differently and nothing is cached, so a report rebuilt from
the log is byte-identical to the stateless report compiled from the same inputs.

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
from complyroll.events import EventRepository
from complyroll.models import Observation

from .evaluations import EvaluationInput, EvaluationMatch
from .vdt import (
    CompiledArtifact,
    CompiledVdtReport,
    DetectionAttestation,
    ReportCompileError,
    ReportDiagnostic,
    ReportOptions,
    compile_records,
)

if TYPE_CHECKING:  # pragma: no cover - imported for annotations only
    from complyroll.history import ArtifactRecord, CaseState


def compile_vdt_report_from_history(
    repository: EventRepository,
    *,
    options: ReportOptions,
) -> CompiledVdtReport:
    """Compile one Vulnerability Detail Report from stored history.

    `options.detected_at_attestation` is ignored on this path. Attestations are facts
    the log already holds, one `detection.attested` event per case, so a command-line
    flag has nothing to add and must not silently override what an operator filed.
    """

    if not isinstance(options, ReportOptions):
        raise TypeError("options must be a ReportOptions")
    # Imported here because `complyroll.history` reads the report layer's evaluation
    # shapes, so a module-level import would close a cycle whenever history is the
    # first of the two packages a caller imports.
    from complyroll.history import artifact_records, fold_all_cases, rehydrate_observations

    records = artifact_records(repository)
    artifacts = tuple(_compiled_artifact(record) for record in records)
    observations = rehydrate_observations(repository)
    cases = fold_all_cases(repository)
    diagnostics = _ingest_diagnostics(records) + _stale_cases(cases, observations)
    return compile_records(
        artifacts=artifacts,
        observations=observations,
        ingest_diagnostics=diagnostics,
        evaluations_by_tracking_id=_evaluations(cases),
        attestation=_attestation(cases),
        options=options,
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


def _ingest_diagnostics(records: Sequence[ArtifactRecord]) -> tuple[ReportDiagnostic, ...]:
    """Reproduce the ingest diagnostics the stateless path would have raised.

    The artifact name stands in for a diagnostic that names no location, exactly as the
    stateless compiler substitutes the artifact's file name, so a report never depends
    on the directory layout of the machine that ingested it. An error-level diagnostic
    cannot reach history through `record_ingest`, so one found here is a damaged log and
    stops the run the same way a failed ingest does.
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
            closed_disposition=(
                None if disposition is None else disposition.closed_disposition
            ),
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


__all__ = ["compile_vdt_report_from_history"]
