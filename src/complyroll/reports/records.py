# ******************************************************************************
# *Title: Record Compiler*
# *Author: Kyle Versluis*
# *Description: Compile source artifacts into the period-agnostic record set.*
# ******************************************************************************
"""Compile source artifacts into the record set every report reads from (ADR 0010).

`compile_record_set` turns normalized inputs into the period-agnostic record set, so one
vulnerability is compiled once however many reports describe it.
`compile_record_set_from_artifacts` is the stateless path, and it fails closed: an artifact
that does not ingest, a vulnerability with no detection time, or an evaluation that matches
nothing stops the run with diagnostics and no output.
"""

# *--- Imports ---*

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from complyroll import __version__
from complyroll.adapters import (
    DETECTION_FAILURE_SOURCE_TYPE,
    ArtifactProvenance,
    DiagnosticLevel,
    FailureClassification,
    IngestResult,
    classify_ingest,
    failure_diagnostics,
    ingest_stig_artifact,
    system_observation_for,
)
from complyroll.adapters.common import diagnostic_text
from complyroll.correlation import (
    VulnerabilityGroup,
    correlate_observations,
    group_open_observations,
)
from complyroll.models import (
    RESERVED_SOURCE_TYPE_PREFIX,
    CaseStatus,
    Observation,
    ObservationOrigin,
)
from complyroll.policy import (
    COVERAGE_RULE_IDS,
    CertificationProfile,
    PolicyDeadline,
    PolicyRuleNotFoundError,
    SelectedPolicy,
    SelectedRule,
    load_bundled_rule_source_snapshot,
    select_policy,
)
from complyroll.policy.source import RuleSourceSnapshot

from .changes import DAC_RULE, ChangeProjection, StoredChangeSet, derive_changes
from .changes_input import ChangeSet
from .checks import (
    CLOCK_OUT_OF_RANGE,
    TRACKING_ID_COLLISION,
    clock_problem,
    detection_clock,
    detection_clock_message,
    evaluation_clock_message,
    evaluation_order_diagnostic,
    observation_clock_message,
    published_tracking_id,
    resolve_detection_time,
    system_record_kind,
    tracking_id_collision_message,
    tracking_id_collisions,
)
from .coverage import (
    DRIFT_LIKELIHOOD_UNKNOWN,
    PDD_RULE,
    CoverageEvidence,
    CoverageResult,
    CoverageWindow,
    FiledEvidence,
    coverage_label,
    derive_coverage,
    file_evidence,
)
from .evaluations import EvaluationInput, EvaluationSet, record_label
from .gaps import COVERAGE_GAP_SOURCE_TYPE, coverage_gap_observation, coverage_gap_observations
from .inventory import Inventory
from .kev import KEV_STALE_AFTER, KevCatalog, KevClock, cve_may_be_missing, kev_clock
from .model import (
    ACTIVE_STATUSES,
    FINAL_DISPOSITIONS,
    CompiledArtifact,
    CompiledDeadline,
    CompiledDetectionFailure,
    CompiledRecordSet,
    CompiledVulnerability,
    DetectionAttestation,
    ReportCompileError,
    ReportDiagnostic,
    ReportOptions,
    iso,
    require_aware,
)

# *--- Configuration ---*

_KEV_RULE = "VDR-TFR-KEV"
_CVE_PREFIX = "CVE-"


# *--- Core Logic ---*


def compile_record_set_from_artifacts(
    artifact_paths: Sequence[Path],
    *,
    options: ReportOptions,
    evaluations: EvaluationSet | None = None,
    record_failed_imports: bool = False,
) -> CompiledRecordSet:
    """Ingest artifacts, match evaluations, and compile the record set they describe.

    This is the stateless path's front half. Every report the package projects from
    the same artifacts starts here, so ingest happens once per run rather than once
    per report. With `record_failed_imports`, an artifact whose failure is mintable
    becomes a system observation instead of stopping the run (ADR 0014); without it
    every failure stops the run exactly as before. With `options.record_coverage_gaps`,
    each coverage window that closed with no verification becomes a coverage gap system
    observation, added before grouping so an evaluation finds its record (ADR 0015).
    """

    if not isinstance(options, ReportOptions):
        raise TypeError("options must be a ReportOptions")
    if evaluations is not None and not isinstance(evaluations, EvaluationSet):
        raise TypeError("evaluations must be an EvaluationSet")

    ingest_diagnostics: list[ReportDiagnostic] = []
    artifacts, observations = _ingest_all(
        artifact_paths,
        options,
        ingest_diagnostics,
        record_failed_imports=record_failed_imports,
    )
    # Derived once, from the evidence alone, before its gaps join the list; each gap is
    # ingested at the run's as-of, as every artifact and failure of this path is.
    coverage = None
    inventory = options.inventory
    if options.record_coverage_gaps and inventory is not None:
        policy = select_policy(load_bundled_rule_source_snapshot(), options.profile)
        coverage = _coverage(observations, inventory, policy, options.as_of)
        observations.extend(coverage_gap_observations(coverage, ingested_at=options.as_of))
    groups = group_open_observations(observations)
    matches = _match_evaluations(groups, evaluations)
    return compile_record_set(
        artifacts=artifacts,
        observations=observations,
        ingest_diagnostics=ingest_diagnostics,
        evaluations_by_tracking_id=matches,
        attestation=DetectionAttestation(default=options.detected_at_attestation),
        options=options,
        coverage=coverage,
        gap_aware=options.record_coverage_gaps,
    )


def derive_changes_from_artifacts(
    artifact_paths: Sequence[Path],
    *,
    options: ReportOptions,
    record_failed_imports: bool = False,
) -> tuple[ChangeProjection, tuple[ReportDiagnostic, ...]]:
    """Ingest artifacts and project the options' change file, with no report around it.

    The request document's front half: the same reading of the artifacts, the same refusals
    about reading them, and the same projection as a report with the same flags, so a request
    and a report's block cannot disagree (ADR 0018). It builds no record, so a refusal about
    one, such as `detection_time_missing`, does not apply. The diagnostics are the ingest's,
    in the report's order, then the projection's warnings.
    """

    if not isinstance(options, ReportOptions):
        raise TypeError("options must be a ReportOptions")
    change_set = options.changes
    if change_set is None or options.inventory is None:
        raise ValueError("deriving a change projection needs a change set and an inventory")

    ingest_diagnostics: list[ReportDiagnostic] = []
    _, observations = _ingest_all(
        artifact_paths,
        options,
        ingest_diagnostics,
        record_failed_imports=record_failed_imports,
    )
    return derive_request_changes(observations, ingest_diagnostics, change_set, options=options)


def derive_request_changes(
    observations: Sequence[Observation],
    ingest_diagnostics: Sequence[ReportDiagnostic],
    change_input: ChangeSet | StoredChangeSet,
    *,
    options: ReportOptions,
) -> tuple[ChangeProjection, tuple[ReportDiagnostic, ...]]:
    """Project changes over evidence already read: both paths of a detection request."""

    inventory = options.inventory
    if inventory is None:
        raise ValueError("deriving a change projection needs an inventory")
    # The report path meets these two refusals on its way to the projection. Without them a
    # late catalog is applied and an unusable clock ends the run in the derivation.
    if options.kev_catalog is not None:
        _require_kev_catalog_by_as_of(options.kev_catalog, options)
    _refuse_unusable_clocks(observations)
    policy = select_policy(load_bundled_rule_source_snapshot(), options.profile)
    projection = _changes(observations, change_input, inventory, policy, options)
    return projection, (
        *sorted(ingest_diagnostics, key=_diagnostic_order),
        *projection.warnings,
    )


def compile_record_set(
    *,
    artifacts: Sequence[CompiledArtifact],
    observations: Sequence[Observation],
    ingest_diagnostics: Sequence[ReportDiagnostic],
    evaluations_by_tracking_id: Mapping[str, EvaluationInput],
    attestation: DetectionAttestation,
    options: ReportOptions,
    coverage: CoverageResult | None = None,
    gap_aware: bool = False,
    stored_changes: StoredChangeSet | None = None,
) -> CompiledRecordSet:
    """Compile the period-agnostic record set from already-normalized inputs.

    This is where the ordering guarantees `compile_records` documents are made: the
    artifact manifest and the ingest diagnostics are put in their total order here,
    on the one path both the stateless compile and the event-sourced rebuild share.
    Every report projection reads the set this returns, so a record is compiled once
    and selected many times.

    `coverage` is a projection the caller already derived from these observations, so it
    is not derived twice; it must belong to the options. With `gap_aware`, every coverage
    window is mapped to the record that carries its gap, or to None when none does, and
    each window no record carries and each gap record no window derives is named in an
    INFO note, which only a compile from history can meet (ADR 0015, divergences 1 and 2).
    `stored_changes` is what a store recorded, the persisted twin of `options.changes` (ADR 0018).
    """

    if not isinstance(options, ReportOptions):
        raise TypeError("options must be a ReportOptions")
    if not isinstance(attestation, DetectionAttestation):
        raise TypeError("attestation must be a DetectionAttestation")
    if stored_changes is not None and options.changes is not None:
        raise ValueError("a compile reads changes from a file or from a store, never both")

    diagnostics: list[ReportDiagnostic] = sorted(ingest_diagnostics, key=_diagnostic_order)
    correlation = correlate_observations(observations)
    # Excluded observations are kept in the order they were read, so this block echoed
    # the caller's artifact order too. Only this list is ordered here; the diagnostics
    # raised below it follow the groups, which correlation already orders by group key.
    for observation in sorted(correlation.unresolved, key=_unresolved_order):
        diagnostics.append(
            ReportDiagnostic(
                level=DiagnosticLevel.WARNING,
                code="unresolved_observation",
                message=(
                    f"{observation.source_record_id} on "
                    f"{observation.resource.resource_id} has disposition "
                    f"{observation.disposition.value} and was not reported as a vulnerability"
                ),
                location=observation.source_artifact_name or observation.context_key,
            )
        )

    groups = correlation.groups
    snapshot = load_bundled_rule_source_snapshot()
    policy = select_policy(snapshot, options.profile)
    catalog = options.kev_catalog
    kev_rule: SelectedRule | None = None
    if catalog is not None:
        _require_kev_catalog_by_as_of(catalog, options)
        kev_rule = _kev_rule(policy, catalog)
    # Derived from the same observations on both paths, so the persisted report and the
    # stateless one carry the same block (ADR 0015).
    inventory = options.inventory
    if coverage is None:
        coverage = (
            None if inventory is None else _coverage(observations, inventory, policy, options.as_of)
        )
    elif not _coverage_belongs(coverage, inventory, policy, options):
        raise ValueError("coverage must be derived from these options' inventory, as-of and policy")
    if gap_aware and coverage is None:
        raise ValueError("a gap-aware compile needs an inventory")
    # After coverage, which has refused any out-of-range clock by name; a coverage gap in
    # these observations is a system record, so it never satisfies a change.
    change_input = options.changes if stored_changes is None else stored_changes
    changes = (
        None
        if change_input is None or inventory is None
        else _changes(observations, change_input, inventory, policy, options)
    )

    compiled: list[CompiledVulnerability] = []
    # Each record with no detection time, as (correlation id, label), named in id order.
    missing_detection: list[tuple[str, str]] = []
    errors: list[ReportDiagnostic] = []
    kev_incomplete: list[CompiledVulnerability] = []
    detection_failures: list[CompiledDetectionFailure] = []
    # Each coverage gap observation's id, to the published id of the record carrying it,
    # and to the record as a diagnostic names it.
    gap_tracking: dict[str, str] = {}
    gap_labels: dict[str, str] = {}

    for group in groups:
        evaluation = evaluations_by_tracking_id.get(group.tracking_id)
        label = record_label(
            group.tracking_id, None if evaluation is None else evaluation.tracking_id
        )
        clock = detection_clock(group, attestation)
        problem = None if clock is None else clock_problem(clock, (policy,))
        if clock is not None and problem is not None:
            errors.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code=CLOCK_OUT_OF_RANGE,
                    message=detection_clock_message(label, clock, problem),
                    location=group.source_record_id,
                )
            )
            continue
        detected_at, detected_source = resolve_detection_time(group, attestation)
        if detected_at is None:
            missing_detection.append((group.tracking_id, label))
            continue
        if detected_source == "artifact-partial":
            diagnostics.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.WARNING,
                    code="detection_time_partial",
                    message=(
                        f"{label} groups "
                        f"{len(group.untimestamped_observation_ids)} observation(s) that "
                        "declare no source timestamp; the earliest known timestamp is the "
                        "detection time"
                    ),
                    location=group.source_record_id,
                )
            )
        # The order check runs before the record is built, so a record refused for both
        # reasons names its ordering error before `closed_without_disposition`. Every
        # record's errors are collected and the loop moves on, so one run names them all.
        record_errors: list[ReportDiagnostic] = []
        if evaluation is not None:
            order = evaluation_order_diagnostic(
                tracking_id=label,
                location=group.source_record_id,
                detected_at=detected_at,
                detected_source=detected_source,
                completed_at=evaluation.completed_at,
                source_type=group.source_type,
            )
            if order is not None and order.level is DiagnosticLevel.ERROR:
                record_errors.append(order)
            elif order is not None:
                diagnostics.append(order)
            problem = clock_problem(evaluation.completed_at, (policy,), evaluation=evaluation)
            if problem is not None:
                record_errors.append(
                    ReportDiagnostic(
                        level=DiagnosticLevel.ERROR,
                        code=CLOCK_OUT_OF_RANGE,
                        message=evaluation_clock_message(label, evaluation.completed_at, problem),
                        location=group.source_record_id,
                    )
                )
        # The record's deadlines would overflow on a refused clock, so it is not built.
        if not any(item.code == CLOCK_OUT_OF_RANGE for item in record_errors):
            try:
                record = _build_record(
                    group=group,
                    detected_at=detected_at,
                    detected_at_source=detected_source,
                    evaluation=evaluation,
                    policy=policy,
                    snapshot=snapshot,
                    options=options,
                    kev_rule=kev_rule,
                )
            except ReportCompileError as exc:
                record_errors.extend(exc.diagnostics)
        if record_errors:
            errors.extend(record_errors)
            continue
        compiled.append(record)
        # Only the failure type carries the metadata `_detection_failure` reads; any other
        # reserved source type is a record like any other and is never listed (ADR 0015).
        detection_failures.extend(
            _detection_failure(item, record.tracking_id)
            for item in group.observations
            if item.origin is ObservationOrigin.SYSTEM
            and item.source_type == DETECTION_FAILURE_SOURCE_TYPE
        )
        gaps = [
            item.observation_id
            for item in group.observations
            if item.origin is ObservationOrigin.SYSTEM
            and item.source_type == COVERAGE_GAP_SOURCE_TYPE
        ]
        gap_tracking.update((gap_id, record.tracking_id) for gap_id in gaps)
        gap_labels.update((gap_id, record.label) for gap_id in gaps)
        if kev_rule is not None and any(cve_may_be_missing(item) for item in group.observations):
            kev_incomplete.append(record)

    if missing_detection:
        errors.insert(
            0,
            ReportDiagnostic(
                level=DiagnosticLevel.ERROR,
                code="detection_time_missing",
                message=(
                    "no source timestamp and no --detected-at attestation for: "
                    + ", ".join(label for _, label in sorted(missing_detection))
                ),
            ),
        )
    if errors:
        raise ReportCompileError(errors)

    _require_unique_tracking_ids(compiled)
    if changes is not None:
        # An evaluation may rename a record, and a change row names it as the record does.
        changes = changes.with_published_tracking_ids(
            {record.original_tracking_id: record.tracking_id for record in compiled}
        )
    if catalog is not None:
        diagnostics.extend(_kev_diagnostics(catalog, compiled, kev_incomplete, options))
    if coverage is not None:
        diagnostics.extend(coverage_diagnostics(coverage))
    gap_records: dict[CoverageWindow, str | None] | None = None
    if gap_aware and coverage is not None:
        window_ids = _window_gap_ids(coverage, options)
        gap_records = {window: gap_tracking.get(gap_id) for window, gap_id in window_ids.items()}
        diagnostics.extend(
            _coverage_gap_divergences(coverage, window_ids, gap_tracking, gap_labels, observations)
        )
    if changes is not None:
        diagnostics.extend(changes.warnings)
    return CompiledRecordSet(
        records=tuple(compiled),
        artifacts=tuple(sorted(artifacts, key=_artifact_order)),
        diagnostics=tuple(diagnostics),
        rules_provenance=policy.provenance,
        parser_versions=_parser_versions(observations),
        generator_version=__version__,
        options=options,
        detection_failures=_ordered_detection_failures(detection_failures),
        coverage=coverage,
        coverage_gaps=tuple(sorted(set(gap_tracking.values()))),
        coverage_gap_records=gap_records,
        changes=changes,
    )


def _artifact_order(artifact: CompiledArtifact) -> tuple[str, str]:
    """Return the total order the artifact manifest is published in.

    `name` leads because it is already in every artifact record, so two runs have to
    agree on it for their documents to be byte-equal at all, and because the Markdown
    Inputs table is what a human scans by file name. `sha256` breaks the tie: two
    artifacts may carry the same name from different directories, and a report must
    not depend on which one the operator happened to name first.
    """

    return (artifact.name, artifact.sha256)


def _diagnostic_order(diagnostic: ReportDiagnostic) -> tuple[str, str, str, str]:
    """Return the total order ingest diagnostics are published in.

    Ingest diagnostics have no narrative order to preserve: each one is an independent
    note about one artifact, and the sequence they arrived in only records which file
    the caller read first. Code leads so a reader sees one kind of problem together,
    then location, then the message and level that distinguish two notes sharing both.
    """

    return (
        diagnostic.code,
        diagnostic.location or "",
        diagnostic.message,
        diagnostic.level.value,
    )


def _unresolved_order(observation: Observation) -> tuple[str, str, str, str, str]:
    """Return the total order unresolved observations are reported in.

    The fields are the ones the diagnostic renders (its location, then the record,
    resource, and disposition its message names), so the published order is the order
    a reader would sort the printed lines into. `observation_id` is last and is a
    content fingerprint, so the order is total even where every rendered field agrees.
    """

    return (
        observation.source_artifact_name or observation.context_key,
        observation.source_record_id,
        observation.resource.resource_id,
        observation.disposition.value,
        observation.observation_id,
    )


# *--- Ingest ---*

#: One reading of an artifact and, when failed imports are recorded, how it failed.
_Reading = tuple[IngestResult, FailureClassification | None]


def _ingest_all(
    artifact_paths: Sequence[Path],
    options: ReportOptions,
    diagnostics: list[ReportDiagnostic],
    *,
    record_failed_imports: bool = False,
) -> tuple[list[CompiledArtifact], list[Observation]]:
    if not artifact_paths:
        raise ReportCompileError(
            (
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="no_artifacts",
                    message="at least one source artifact is required",
                ),
            )
        )

    errors: list[ReportDiagnostic] = []
    by_digest: dict[str, list[_Reading]] = {}
    # Mintable failures by digest, none of whose diagnostics are appended yet: whether a
    # failure contributes its own or `failure_diagnostics` depends on whether the same
    # bytes read successfully elsewhere in the run, which is known only after the loop.
    held: dict[str, list[tuple[IngestResult, FailureClassification]]] = {}

    for raw_path in artifact_paths:
        path = Path(raw_path)
        result = ingest_stig_artifact(path, ingested_at=options.as_of)
        classification = classify_ingest(result) if record_failed_imports else None
        if result.errors and classification is not None and classification.mintable:
            held.setdefault(_require_artifact(result).digest_sha256, []).append(
                (result, classification)
            )
            continue
        _collect_diagnostics(result, path.name, diagnostics, errors)
        if result.errors or result.artifact is None:
            continue
        by_digest.setdefault(result.artifact.digest_sha256, []).append((result, classification))

    failed: dict[str, list[tuple[IngestResult, FailureClassification]]] = {}
    for digest, readings in held.items():
        for result, classification in readings:
            # Bytes that read successfully under another name are a misnamed copy, not a
            # failed detection, so the reading stops the run exactly as it always has.
            if digest in by_digest:
                classification = classification.read_elsewhere()
            if classification.mintable:
                failed.setdefault(digest, []).append((result, classification))
            else:
                _collect_diagnostics(result, _require_artifact(result).name, diagnostics, errors)

    if errors:
        # The run stops, so nothing is recorded: every held failure names itself with its
        # own ERRORs, exactly as the run would without the flag.
        for readings in failed.values():
            for result, _ in readings:
                _collect_diagnostics(result, _require_artifact(result).name, diagnostics, errors)
        raise ReportCompileError(sorted(errors, key=_diagnostic_order))

    artifacts: list[CompiledArtifact] = []
    observations: list[Observation] = []
    # By elected name, which is the order the manifest is published in. Nothing
    # downstream reads the observation list in order (correlation orders each group's
    # members and sorts what it excludes), so this loop decides no output on its own;
    # walking it in the published order keeps that true of what a reader sees here too.
    elected = sorted(
        (_elect_reading(group) for group in by_digest.values()),
        key=lambda item: (item[0].artifact.name, item[0].artifact.digest_sha256),
    )
    for read, skipped in elected:
        _warn_duplicates(read, skipped, diagnostics)
        artifacts.append(
            CompiledArtifact(
                name=read.artifact.name,
                sha256=read.artifact.digest_sha256,
                parser=read.artifact.parser_name,
                parser_version=read.artifact.parser_version,
                size_bytes=read.artifact.size_bytes,
                observation_count=len(read.observations),
            )
        )
        observations.extend(read.observations)
        # Only a side record reaches here classified: its artifact imports as it always
        # has, and the failed invocation is recorded beside it.
        _record_detection_failure(read, options, diagnostics, observations)

    # A failed artifact is not in the manifest, which lists what was read; its system
    # observation's metadata becomes its entry in `detectionFailures` instead.
    for read, skipped in sorted(
        (_elect_reading(group) for group in failed.values()),
        key=lambda item: (item[0].artifact.name, item[0].artifact.digest_sha256),
    ):
        _warn_duplicates(read, skipped, diagnostics)
        _record_detection_failure(read, options, diagnostics, observations)

    return artifacts, observations


def _collect_diagnostics(
    result: IngestResult,
    name: str,
    diagnostics: list[ReportDiagnostic],
    errors: list[ReportDiagnostic],
) -> None:
    """Append one reading's diagnostics: ERRORs to `errors`, the rest to `diagnostics`."""

    for item in result.diagnostics:
        entry = ReportDiagnostic(
            level=item.level,
            code=item.code,
            message=item.message,
            # The artifact name, never the supplied path: diagnostics are embedded in
            # the report, which must not depend on the caller's directory layout.
            location=item.location or name,
        )
        if item.level is DiagnosticLevel.ERROR:
            errors.append(entry)
        else:
            diagnostics.append(entry)


def _warn_duplicates(
    read: _ElectedReading,
    skipped: Sequence[ArtifactProvenance],
    diagnostics: list[ReportDiagnostic],
) -> None:
    """Note each reading of the elected reading's bytes that the report does not carry.

    Both names are file names the operator supplied, so they pass through `diagnostic_text`,
    as the adapters' diagnostic paths and the failure diagnostics do, before the report
    embeds them.
    """

    elected = diagnostic_text(read.artifact.name)
    for duplicate in skipped:
        diagnostics.append(
            ReportDiagnostic(
                level=DiagnosticLevel.WARNING,
                code="duplicate_artifact",
                message=(
                    "identical artifact bytes were supplied more than once; this "
                    f"report reads them as {elected}"
                ),
                location=diagnostic_text(duplicate.name),
            )
        )


def _record_detection_failure(
    read: _ElectedReading,
    options: ReportOptions,
    diagnostics: list[ReportDiagnostic],
    observations: list[Observation],
) -> None:
    """Mint the system observation of one elected reading's failure, if it has one.

    A failed reading contributes `failure_diagnostics` in place of its own diagnostics,
    with every ERROR demoted, and a side record contributes only its one
    `detection_failure_recorded` WARNING. The instant is the run's as-of, the moment
    ComplyRoll saw the failure, unless the scanner declared the failed invocation's own
    clock. It is never clamped to the report period (ADR 0014).
    """

    classification = read.classification
    if classification is None:
        return
    name = read.artifact.name
    for item in failure_diagnostics(read.result, classification, name=name):
        diagnostics.append(
            ReportDiagnostic(
                level=item.level,
                code=item.code,
                message=item.message,
                location=item.location,
            )
        )
    observations.append(
        system_observation_for(read.result, classification, name=name, observed_at=options.as_of)
    )


@dataclass(frozen=True, slots=True)
class _ElectedReading:
    """The one reading of a set of identical artifact bytes that the report carries.

    `result` and `classification` are the reading as ingested and, when failed imports
    are recorded, how it failed; a clean reading, or any reading of a run that records
    no failures, has no classification.
    """

    artifact: ArtifactProvenance
    observations: tuple[Observation, ...]
    result: IngestResult
    classification: FailureClassification | None


def _elect_reading(
    candidates: Sequence[_Reading],
) -> tuple[_ElectedReading, tuple[ArtifactProvenance, ...]]:
    """Choose which of several readings of one artifact's bytes the report carries.

    The same bytes may be supplied twice under different file names, and only one
    reading can be in the report: the observations of the second would restate every
    finding of the first under the same fingerprints. Keeping whichever arrived first
    made the manifest name, and the name every observation carries, depend on the
    order the operator listed the files in. Electing the lowest name instead makes the
    choice a property of the file set. Two candidates that share a name also share
    their bytes, so every field either could contribute is identical and which one is
    elected is not observable. Failed readings of one digest are elected the same way,
    so one failure is recorded however many names its bytes were supplied under.
    """

    readings = sorted(
        (
            _ElectedReading(_require_artifact(item), item.observations, item, classification)
            for item, classification in candidates
        ),
        key=lambda item: item.artifact.name,
    )
    read, *rest = readings
    return read, tuple(item.artifact for item in rest)


def _require_artifact(result: IngestResult) -> ArtifactProvenance:
    """Return one candidate's artifact, which `_ingest_all` has already checked for.

    A mintable failure always carries one, because a reading with no digest is refused.
    """

    artifact = result.artifact
    if artifact is None:  # pragma: no cover - candidates are filtered before election
        raise AssertionError("a candidate reading must carry an artifact")
    return artifact


# *--- Evaluation Matching ---*


def _match_evaluations(
    groups: Sequence[VulnerabilityGroup],
    evaluations: EvaluationSet | None,
) -> dict[str, EvaluationInput]:
    if evaluations is None or not evaluations.entries:
        return {}
    matched: dict[str, EvaluationInput] = {}
    claimed_by: dict[str, EvaluationInput] = {}
    errors: list[ReportDiagnostic] = []

    for entry in evaluations.entries:
        candidates = [group for group in groups if _matches(entry, group)]
        if not candidates:
            errors.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="evaluation_unmatched",
                    message=f"no vulnerability matches {entry.match.describe()}",
                    location=entry.location,
                )
            )
            continue
        if len(candidates) > 1:
            named = ", ".join(group.tracking_id for group in candidates)
            errors.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="evaluation_ambiguous",
                    message=(
                        f"{entry.match.describe()} matches {len(candidates)} vulnerabilities "
                        f"({named}); {entry.match.ambiguity_remedy(candidates)}"
                    ),
                    location=entry.location,
                )
            )
            continue
        group = candidates[0]
        # A lone system record would match an entry short of the full triple, so the next
        # record of another key, or an artifact record of the same key, would turn the same
        # file ambiguous; every reserved source type needs the triple (ADR 0014 Decision 10,
        # ADR 0015 Decision 23).
        if group.source_type.startswith(RESERVED_SOURCE_TYPE_PREFIX) and (
            entry.match.context_key is None or entry.match.source_type is None
        ):
            errors.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="evaluation_context_key_required",
                    message=entry.match.context_key_required(
                        group.tracking_id, kind=system_record_kind(group.source_type)
                    ),
                    location=entry.location,
                )
            )
            continue
        previous = claimed_by.get(group.tracking_id)
        if previous is not None:
            errors.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="evaluation_duplicate",
                    message=(
                        f"{group.tracking_id} is evaluated by both {previous.location} "
                        f"and {entry.location}"
                    ),
                    location=entry.location,
                )
            )
            continue
        claimed_by[group.tracking_id] = entry
        matched[group.tracking_id] = entry

    if errors:
        raise ReportCompileError(errors)
    return matched


def _matches(entry: EvaluationInput, group: VulnerabilityGroup) -> bool:
    if entry.match.source_record_id != group.source_record_id:
        return False
    if entry.match.context_key is not None and entry.match.context_key != group.context_key:
        return False
    return not (
        entry.match.source_type is not None and entry.match.source_type != group.source_type
    )


# *--- Detection Failures ---*


def _detection_failure(observation: Observation, tracking_id: str) -> CompiledDetectionFailure:
    """Describe one detection-process observation for `detectionFailures`, from its metadata."""

    metadata = dict(observation.source_metadata)
    observed_at = observation.observed_at
    if observed_at is None:  # pragma: no cover - a system observation is always timed
        raise AssertionError("a system observation must carry observed_at")
    return CompiledDetectionFailure(
        name=metadata["artifact.name"],
        sha256=metadata["artifact.sha256"],
        size_bytes=int(metadata["artifact.sizeBytes"]),
        parser=metadata["artifact.parser"],
        parser_version=metadata["artifact.parserVersion"],
        failure_class=metadata["failure.class"],
        failure_codes=tuple(json.loads(metadata["failure.codes"])),
        observed_at=observed_at.astimezone(UTC),
        clock=metadata["failure.clock"],
        tracking_id=tracking_id,
    )


def _ordered_detection_failures(
    failures: Sequence[CompiledDetectionFailure],
) -> tuple[CompiledDetectionFailure, ...]:
    """Put `detectionFailures` in its total order: name, sha256, parser, version, instant.

    The persisted path can hold several current failures of one digest, differing in
    parser, version or instant, so the order must reach past the digest. Parser versions
    compare by the rule `history.fold._newest_stream` applies, reproduced here because
    this module cannot import the history package: when every version of a digest is
    dot-separated ASCII digits they compare as numbers with trailing zero components
    dropped, so 10 follows 9 and 1.0 ties 1, and otherwise the digest's versions compare
    as text. The version as written breaks the last tie, so the order is total.
    """

    numeric: dict[str, bool] = {}
    for item in failures:
        numeric[item.sha256] = numeric.get(item.sha256, True) and _is_numeric_version(
            item.parser_version
        )

    def key(
        item: CompiledDetectionFailure,
    ) -> tuple[str, str, str, tuple[int, ...], str, datetime, str]:
        number: tuple[int, ...] = ()
        text = item.parser_version
        if numeric[item.sha256]:
            number, text = _numeric_version(item.parser_version), ""
        return (
            item.name,
            item.sha256,
            item.parser,
            number,
            text,
            item.observed_at,
            item.parser_version,
        )

    return tuple(sorted(failures, key=key))


def _is_numeric_version(version: str) -> bool:
    """Return True when every dot-separated component is ASCII digits `int` can read.

    The same test as `history.fold._is_numeric_version`, so U+00B2 and U+2460, which
    `str.isdigit` accepts and `int` refuses, fall to the text comparison.
    """

    parts = version.split(".")
    return bool(parts) and all(part.isascii() and part.isdigit() for part in parts)


def _numeric_version(version: str) -> tuple[int, ...]:
    """Return the tuple one numeric parser version compares as, trailing zeros dropped."""

    parts = [int(part) for part in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


# *--- Tracking IDs ---*


def _require_unique_tracking_ids(records: Sequence[CompiledVulnerability]) -> None:
    """Refuse a trackingId override that would merge two vulnerabilities."""

    collisions = [
        ReportDiagnostic(
            level=DiagnosticLevel.ERROR,
            code=TRACKING_ID_COLLISION,
            message=tracking_id_collision_message(previous, record),
            location=record.evaluation_location,
        )
        for previous, record in tracking_id_collisions(records)
    ]
    if collisions:
        raise ReportCompileError(collisions)


# *--- KEV ---*


def _require_kev_catalog_by_as_of(catalog: KevCatalog, options: ReportOptions) -> None:
    """Refuse a CISA KEV catalog released after `as_of` (ADR 0012 Decision 6).

    Entries change after publication, so a later catalog cannot show that the due date
    it carries was in force at `as_of`. Regenerating an old report needs the catalog
    that was current then, and the old report's `kevSource` names its digest.
    """

    if catalog.date_released <= options.as_of:
        return
    raise ReportCompileError(
        (
            ReportDiagnostic(
                level=DiagnosticLevel.ERROR,
                code="kev_catalog_after_as_of",
                message=(
                    f"the CISA KEV catalog was released {iso(catalog.date_released)}, "
                    f"after as_of {iso(options.as_of)}; a later catalog cannot show which "
                    "due dates were in force at as_of, so supply the catalog current then"
                ),
                location=_kev_location(catalog),
            ),
        )
    )


def _kev_rule(policy: SelectedPolicy, catalog: KevCatalog) -> SelectedRule:
    """Return the selected VDR-TFR-KEV rule, or stop the run when the policy lacks it.

    Only a run with a catalog asks, so a run without one never needs the rule. The
    refusal is a catalog-level note like every other one that is not per record, so it
    is located by the catalog digest rather than by a record id (ADR 0012).
    """

    try:
        return policy.rule(_KEV_RULE)
    except PolicyRuleNotFoundError as exc:
        raise ReportCompileError(
            (
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="kev_rule_unavailable",
                    message=(
                        "a CISA KEV catalog was supplied, but the Class "
                        f"{policy.profile.certification_class.value} policy selects no "
                        f"{_KEV_RULE} rule, so no KEV clock can run"
                    ),
                    location=_kev_location(catalog),
                ),
            )
        ) from exc


def _kev_diagnostics(
    catalog: KevCatalog,
    records: Sequence[CompiledVulnerability],
    incomplete: Sequence[CompiledVulnerability],
    options: ReportOptions,
) -> list[ReportDiagnostic]:
    """Return the catalog-level KEV notes, then the per-record ones, in their fixed order.

    Catalog-level notes are located by the catalog digest and never name the file, so
    the same bytes under another path raise the same notes (ADR 0012). `incomplete` is
    in record order, and so are the per-record notes.
    """

    location = _kev_location(catalog)
    as_of_date = options.as_of.astimezone(UTC).date()
    notes: list[ReportDiagnostic] = []

    if options.as_of - catalog.date_released > KEV_STALE_AFTER:
        notes.append(
            ReportDiagnostic(
                level=DiagnosticLevel.WARNING,
                code="kev_catalog_stale",
                message=(
                    f"the CISA KEV catalog was released {iso(catalog.date_released)}, more "
                    f"than {KEV_STALE_AFTER.days} days before as_of {iso(options.as_of)}; "
                    "entries CISA added since its release are not applied"
                ),
                location=location,
            )
        )

    later = frozenset(entry.cve_id for entry in catalog.entries if entry.date_added > as_of_date)
    if later:
        carrying = sum(1 for record in records if later.intersection(record.source_identifiers))
        entries = "1 catalog entry" if len(later) == 1 else f"{len(later)} catalog entries"
        verb = "was" if len(later) == 1 else "were"
        notes.append(
            ReportDiagnostic(
                level=DiagnosticLevel.INFO,
                code="kev_entries_after_as_of",
                message=(
                    f"{entries} dated after {as_of_date.isoformat()} {verb} not applied; "
                    f"{_records_carry(carrying)} {'it' if len(later) == 1 else 'one of them'}"
                ),
                location=location,
            )
        )

    with_cve = sum(
        1
        for record in records
        if any(identifier.startswith(_CVE_PREFIX) for identifier in record.source_identifiers)
    )
    if not with_cve:
        notes.append(
            ReportDiagnostic(
                level=DiagnosticLevel.INFO,
                code="kev_no_cve_identifiers",
                message=(
                    "a CISA KEV catalog was supplied, but no compiled record carries a CVE "
                    "identifier, so no entry could match"
                ),
                location=location,
            )
        )
    elif not any(record.kev is not None for record in records):
        notes.append(
            ReportDiagnostic(
                level=DiagnosticLevel.INFO,
                code="kev_no_matches",
                message=(
                    f"{_records_carry(with_cve)} CVE identifiers, and none matched a CISA "
                    f"KEV catalog entry dated on or before {as_of_date.isoformat()}"
                ),
                location=location,
            )
        )

    for record in incomplete:
        notes.append(
            ReportDiagnostic(
                level=DiagnosticLevel.WARNING,
                code="kev_match_incomplete",
                message=(
                    f"{record.label} groups an observation whose source identifiers "
                    "were cut at the adapter's limit, and a CVE may be among those dropped, "
                    "so a CISA KEV entry for it cannot be matched"
                ),
                location=record.source_record_id,
            )
        )
    return notes


def _kev_location(catalog: KevCatalog) -> str:
    return f"sha256:{catalog.sha256}"


# *--- Coverage ---*


def derive_report_coverage(
    observations: Sequence[Observation],
    inventory: Inventory,
    profile: CertificationProfile,
    as_of: datetime,
) -> CoverageResult:
    """Derive the coverage block a report of these inputs carries, as the report derives it.

    `cases coverage` records the gaps of exactly this projection (ADR 0015): the policy the
    profile selects from the pinned dataset, the same refusal when it lacks a coverage
    rule, and a derivation that never reads a system observation as evidence.
    """

    if not isinstance(inventory, Inventory):
        raise TypeError("inventory must be an Inventory")
    if not isinstance(profile, CertificationProfile):
        raise TypeError("profile must be a CertificationProfile")
    require_aware(as_of, "as_of")
    policy = select_policy(load_bundled_rule_source_snapshot(), profile)
    return _coverage(observations, inventory, policy, as_of)


def _coverage(
    observations: Sequence[Observation],
    inventory: Inventory,
    policy: SelectedPolicy,
    as_of: datetime,
) -> CoverageResult:
    """Return the coverage projection, or stop the run when the policy lacks a coverage rule.

    Only a run with an inventory asks, so a run without one never needs the five rules
    (ADR 0015). Every rule the policy lacks is named in one note, located at the
    inventory's name like every other note about the inventory as a whole.
    """

    missing = [rule_id for rule_id in COVERAGE_RULE_IDS if not _selects(policy, rule_id)]
    if missing:
        raise ReportCompileError(
            (
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="coverage_rule_unavailable",
                    message=(
                        "an information resource inventory was supplied, but the Class "
                        f"{policy.profile.certification_class.value} policy selects no "
                        f"{', '.join(missing)} rule, so no coverage clock can run"
                    ),
                    location=inventory.name,
                ),
            )
        )
    _refuse_unusable_clocks(observations)
    return derive_coverage(observations, inventory, policy, as_of)


def _refuse_unusable_clocks(observations: Sequence[Observation]) -> None:
    """Stop the run on an observation clock the projections cannot convert to UTC."""

    # Each projection converts every observation's clock to UTC, so one that cannot be is
    # refused here, named, rather than ending the run in the derivation.
    unusable = tuple(
        ReportDiagnostic(
            level=DiagnosticLevel.ERROR,
            code=CLOCK_OUT_OF_RANGE,
            message=observation_clock_message(
                observation.observation_id, observation.observed_at, problem
            ),
            location=observation.source_record_id,
        )
        for observation in observations
        if observation.observed_at is not None
        and (problem := clock_problem(observation.observed_at)) is not None
    )
    if unusable:
        raise ReportCompileError(unusable)


def _changes(
    observations: Sequence[Observation],
    change_set: ChangeSet | StoredChangeSet,
    inventory: Inventory,
    policy: SelectedPolicy,
    options: ReportOptions,
) -> ChangeProjection:
    """Return the change projection, or stop the run when the policy lacks its rule."""

    if not _selects(policy, DAC_RULE):
        raise ReportCompileError(
            (
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="change_rule_unavailable",
                    message=(
                        "a change file was supplied, but the Class "
                        f"{policy.profile.certification_class.value} policy selects no "
                        f"{DAC_RULE} rule, so no change can be read against it"
                    ),
                    location=change_set.name or None,
                ),
            )
        )
    return derive_changes(
        observations,
        change_set,
        inventory,
        policy,
        options.as_of,
        kev_catalog=options.kev_catalog,
    )


def _selects(policy: SelectedPolicy, rule_id: str) -> bool:
    try:
        policy.rule(rule_id)
    except PolicyRuleNotFoundError:
        return False
    return True


def _coverage_belongs(
    coverage: CoverageResult,
    inventory: Inventory | None,
    policy: SelectedPolicy,
    options: ReportOptions,
) -> bool:
    """Return whether a handed projection was derived from these options and policy."""

    return (
        inventory is not None
        and coverage.inventory == inventory
        and coverage.as_of == options.as_of
        and coverage.profile == policy.profile
        and coverage.provenance == policy.provenance
    )


def _window_gap_ids(coverage: CoverageResult, options: ReportOptions) -> dict[CoverageWindow, str]:
    """Return the id of each window's gap, rebuilt from the window alone.

    The id depends only on the window, never on the ingest time, so rebuilding the gap
    here names the observation whichever path recorded it.
    """

    return {
        window: coverage_gap_observation(
            window, inventory=coverage.inventory, ingested_at=options.as_of
        ).observation_id
        for window in coverage.windows
    }


def _coverage_gap_divergences(
    coverage: CoverageResult,
    window_ids: Mapping[CoverageWindow, str],
    gap_tracking: Mapping[str, str],
    gap_labels: Mapping[str, str],
    observations: Sequence[Observation],
) -> list[ReportDiagnostic]:
    """Name each window no gap record carries, then each gap record no window derives.

    A stateless run records every window it derives and nothing else, so only a compile
    from history meets either (ADR 0015, divergences 1 and 2). A missed window is a
    permanent fact: a gap this run no longer derives keeps its case, and the note says why,
    as `coverage_gap_contradicted` when evidence inside the window disproves it and as
    `coverage_gap_unmatched` when none does. A disposition answers a whole case, so each
    note is read against the other recorded gaps of its case as well.
    """

    notes: list[ReportDiagnostic] = []
    for window, gap_id in window_ids.items():
        if gap_id in gap_tracking:
            continue
        label = coverage_label(window.key.subject)
        notes.append(
            ReportDiagnostic(
                level=DiagnosticLevel.INFO,
                code="coverage_gap_unrecorded",
                message=(
                    f"the {window.rule_id} window for {label} closed {iso(window.closed_at)} "
                    "with no verification, and history records no gap for it, so no case in "
                    "this report carries it; cases coverage with this run's inventory, as-of, "
                    "class and calendar zone records it"
                ),
                location=f"{coverage.inventory.name} {label}",
            )
        )
    derived = set(window_ids.values())
    recorded = sorted(
        (
            item
            for item in observations
            if item.origin is ObservationOrigin.SYSTEM
            and item.source_type == COVERAGE_GAP_SOURCE_TYPE
            and item.observation_id in gap_tracking
        ),
        key=_gap_order,
    )
    underived = [item for item in recorded if item.observation_id not in derived]
    disproof: dict[str, CoverageEvidence | None] = {}
    if underived:
        # One filing serves every underived gap; refiling per gap was O(gaps x observations).
        filed = file_evidence(observations, coverage.inventory, coverage.as_of)
        disproof = {item.observation_id: _disproving_evidence(item, filed) for item in underived}
    # Each case's recorded gaps, in window order, so siblings are found once per case.
    cases: dict[str, list[Observation]] = {}
    for item in recorded:
        cases.setdefault(gap_tracking[item.observation_id], []).append(item)
    for item in recorded:
        if item.observation_id not in disproof:
            continue
        tracking_id = gap_tracking[item.observation_id]
        siblings = [other for other in cases[tracking_id] if other is not item]
        # A sibling still derived, or one nothing disproves, keeps the case open.
        standing = [
            (other, other.observation_id in derived)
            for other in siblings
            if other.observation_id in derived or disproof[other.observation_id] is None
        ]
        notes.append(
            _underived_gap(
                item,
                gap_labels[item.observation_id],
                disproof[item.observation_id],
                standing=standing,
                shared=bool(siblings),
            )
        )
    return notes


def _disproving_evidence(gap: Observation, filed: FiledEvidence) -> CoverageEvidence | None:
    """Return the earliest verification inside a recorded gap's window, or None.

    The window is (anchorAt, windowClosedAt] from the record's own metadata, which the
    reader holds to its head and its close to the instant it is observed at. Evidence is
    filed as the derivation files it, so a verification after this run's as-of is not used.
    """

    closed_at = gap.observed_at
    if closed_at is None:  # pragma: no cover - a gap is always observed at its window close
        raise ValueError(f"coverage gap {gap.observation_id} has no window close")
    rule = gap.context_key.split(":", 1)[0]
    anchor_at = datetime.fromisoformat(dict(gap.source_metadata)["coverage.anchorAt"])
    return next(
        (
            item
            for item in filed.verifying(rule_id=rule, subject=gap.resource)
            if item.at is not None and anchor_at < item.at <= closed_at
        ),
        None,
    )


def _underived_gap(
    gap: Observation,
    label: str,
    evidence: CoverageEvidence | None,
    *,
    standing: Sequence[tuple[Observation, bool]],
    shared: bool,
) -> ReportDiagnostic:
    """Name a recorded gap this run derives no window for, and why it derives none.

    With evidence inside the window the gap is contradicted and the earliest is named.
    Without it the gap is unmatched: nothing disproves it, and the inputs of this run and
    of the one that recorded it may differ, which no disposition answers. A disposition
    answers the whole case, so a contradicted note advises a false positive only when no
    other recorded gap of its case stands. Each that does is named with why it stands:
    this run still derives it (True), or neither derives nor disproves it (False).
    """

    closed_at = gap.observed_at
    if closed_at is None:  # pragma: no cover - a gap is always observed at its window close
        raise ValueError(f"coverage gap {gap.observation_id} has no window close")
    described = f"{label} carries the recorded gap of {_gap_window(gap)}"
    others = ", and ".join(
        f"{_gap_window(other)}, which this run "
        + ("still derives" if still_derived else "neither derives nor disproves")
        for other, still_derived in standing
    )
    if evidence is None or evidence.at is None:
        tail = "the gap stays recorded"
        if others:
            tail = f"{tail}, and the case also carries {others}"
        return ReportDiagnostic(
            level=DiagnosticLevel.INFO,
            code="coverage_gap_unmatched",
            message=(
                f"{described}, and this run derives no such window and holds no verification "
                "inside it, so its inventory, as-of, class or calendar zone may differ from "
                f"the run that recorded the gap; {tail}"
            ),
            location=gap.source_record_id,
        )
    if others:
        advice = (
            f"but the case also carries {others}, so it stays open until every other gap it "
            "carries is contradicted or disposed on its own merits"
        )
    elif shared:
        advice = (
            "and every other recorded gap of the case is contradicted too, so an evaluation "
            "can dispose the case as a false positive"
        )
    else:
        advice = "and an evaluation can dispose it as a false positive"
    return ReportDiagnostic(
        level=DiagnosticLevel.INFO,
        code="coverage_gap_contradicted",
        message=(
            f"{described}, but {evidence.kind.value} {evidence.reference} on "
            f"{coverage_label(evidence.resource)} verified it at {iso(evidence.at)}, inside "
            f"that window, so this run derives no such window; the gap stays recorded, {advice}"
        ),
        location=gap.source_record_id,
    )


def _gap_window(gap: Observation) -> str:
    """Return a recorded gap as its window reads: rule, context subject and close."""

    closed = "" if gap.observed_at is None else iso(gap.observed_at)
    rule = gap.context_key.split(":", 1)[0]
    return f"the {rule} window for {coverage_label(gap.resource)} that closed {closed}"


def _gap_order(gap: Observation) -> tuple[str, str, str, str, str]:
    """Order gap records as their windows are ordered: by rule, subject and close."""

    closed = "" if gap.observed_at is None else iso(gap.observed_at)
    rule = gap.context_key.split(":", 1)[0]
    subject = gap.resource
    return (rule, subject.resource_type, subject.resource_id, closed, gap.observation_id)


def coverage_diagnostics(coverage: CoverageResult) -> list[ReportDiagnostic]:
    """Return one note per warning an inventory entry raised, in entry order (type, then id).

    Each is located at the inventory's name and the entry's pair, so the same entry in the
    same inventory raises the same note whichever path or file name supplied it.
    """

    notes: list[ReportDiagnostic] = []
    for resource in coverage.resources:
        label = coverage_label(resource.entry.ref)
        for code in resource.warnings:
            if code != DRIFT_LIKELIHOOD_UNKNOWN:
                raise ValueError(f"unhandled coverage warning {code!r}")
            notes.append(
                ReportDiagnostic(
                    level=DiagnosticLevel.WARNING,
                    code=DRIFT_LIKELIHOOD_UNKNOWN,
                    message=(
                        f'{label} declares driftLikely "unknown", so it carries {PDD_RULE}, '
                        "the shorter drift window, until the inventory says whether drift is "
                        "likely"
                    ),
                    location=f"{coverage.inventory.name} {label}",
                )
            )
    return notes


def _records_carry(count: int) -> str:
    return "1 compiled record carries" if count == 1 else f"{count} compiled records carry"


# *--- Record Building ---*


def _build_record(
    *,
    group: VulnerabilityGroup,
    detected_at: datetime,
    detected_at_source: str,
    evaluation: EvaluationInput | None,
    policy: SelectedPolicy,
    snapshot: RuleSourceSnapshot,
    options: ReportOptions,
    kev_rule: SelectedRule | None = None,
) -> CompiledVulnerability:
    if evaluation is not None:
        evaluation = _canonical_reductions(evaluation)
    status = evaluation.resolved_status if evaluation is not None else None
    if evaluation is not None and evaluation.case_status is CaseStatus.CLOSED and status is None:
        raise ReportCompileError(
            (
                ReportDiagnostic(
                    level=DiagnosticLevel.ERROR,
                    code="closed_without_disposition",
                    message=(
                        f"{record_label(group.tracking_id, evaluation.tracking_id)} is closed "
                        "with no recorded disposition; supply closedDisposition"
                    ),
                    location=evaluation.location,
                ),
            )
        )

    is_accepted = status is CaseStatus.ACCEPTED
    final_disposition = None if status is None else FINAL_DISPOSITIONS.get(status)
    if status is not None and status not in ACTIVE_STATUSES and not is_accepted:
        if final_disposition is None:  # pragma: no cover - FINAL_DISPOSITIONS is exhaustive
            raise AssertionError(f"unmapped case status: {status}")
    disposition_recorded = final_disposition is not None

    deadlines, overdue_clauses = _compute_deadlines(
        detected_at=detected_at,
        evaluation=evaluation,
        policy=policy,
        options=options,
        disposition_recorded=disposition_recorded,
        acceptance_recorded=is_accepted,
    )
    # The KEV clock runs after the other three, so deadlines and clauses read EVU, PVR,
    # MAV, KEV. An accepted record keeps its clock but is never officially overdue on it.
    kev: KevClock | None = None
    catalog = options.kev_catalog
    if kev_rule is not None and catalog is not None:
        entries = catalog.matches(
            group.source_identifiers, on_or_before=options.as_of.astimezone(UTC).date()
        )
        if entries:
            kev = kev_clock(entries, status=status, as_of=options.as_of)
            deadlines += (_kev_deadline(kev, kev_rule),)
            if kev.past_due and not is_accepted:
                overdue_clauses += (
                    _kev_clause(kev, kev_rule, catalog, options, detected_at, status),
                )
    explanation = ""
    if overdue_clauses:
        explanation = _explanation(overdue_clauses, policy, snapshot, options)

    return CompiledVulnerability(
        tracking_id=published_tracking_id(group, evaluation),
        source_type=group.source_type,
        source_record_id=group.source_record_id,
        context_key=group.context_key,
        description=_describe(group),
        detected_at=detected_at,
        detected_at_source=detected_at_source,
        detection_source=group.detection_source,
        observation_ids=group.observation_ids,
        resources=group.resources,
        source_identifiers=group.source_identifiers,
        deadlines=deadlines,
        is_overdue=bool(overdue_clauses),
        overdue_explanation=explanation,
        evaluation=evaluation,
        final_disposition=final_disposition,
        remediated=status is CaseStatus.REMEDIATED,
        status=status,
        untimestamped_observation_ids=group.untimestamped_observation_ids,
        original_tracking_id=group.tracking_id,
        kev_checked=kev_rule is not None,
        kev=kev,
    )


def _canonical_reductions(evaluation: EvaluationInput) -> EvaluationInput:
    """Return the evaluation with its completed PAIN reductions in canonical order.

    Order is by instant, then by rating. The stateless path reads reductions in the
    order an evaluations file states them and the persisted path in the order they were
    appended, and neither order is a fact about the vulnerability, so ordering them
    here is what lets the two paths render the same history the same way (ADR 0008
    Decision 5). Both renderings read the record this returns, so the JSON array and
    the Markdown line can never disagree.
    """

    events = evaluation.pain_reduction_events
    ordered = tuple(sorted(events, key=lambda item: (item.reduced_at, int(item.rating))))
    if ordered == events:
        return evaluation
    return replace(evaluation, pain_reduction_events=ordered)


def _describe(group: VulnerabilityGroup) -> str:
    title = group.title.strip()
    if not title:
        return group.source_record_id
    # A title that already leads with the record id, as an HDF CVE control's does, is kept
    # as written rather than prefixed twice; the match is exact and case-sensitive.
    record_id = group.source_record_id
    if title == record_id or title.startswith(f"{record_id}: "):
        return title
    return f"{record_id}: {title}"


def _compute_deadlines(
    *,
    detected_at: datetime,
    evaluation: EvaluationInput | None,
    policy: SelectedPolicy,
    options: ReportOptions,
    disposition_recorded: bool,
    acceptance_recorded: bool,
) -> tuple[tuple[CompiledDeadline, ...], tuple[str, ...]]:
    as_of = options.as_of
    class_name = options.certification_class.value
    deadlines: list[CompiledDeadline] = []
    clauses: list[str] = []

    evaluation_deadline = policy.evaluation_deadline(detected_at)
    evaluated = evaluation is not None
    deadlines.append(_compiled(evaluation_deadline, anchor="detection", satisfied=evaluated))
    if not evaluated and as_of > evaluation_deadline.due_at:
        clauses.append(
            f"{evaluation_deadline.rule_id} ({evaluation_deadline.force.value}, "
            f"Class {class_name}): the evaluation window opened at detection "
            f"{iso(detected_at)} and closed {iso(evaluation_deadline.due_at)} "
            "with no evaluation recorded."
        )

    if evaluation is None:
        return tuple(deadlines), tuple(clauses)

    resolved = disposition_recorded or acceptance_recorded
    response = policy.response_deadline(
        evaluation.completed_at,
        pain=evaluation.pain,
        is_internet_reachable=evaluation.is_internet_reachable,
        is_likely_exploitable=evaluation.is_likely_exploitable,
    )
    if response is not None:
        deadlines.append(_compiled(response, anchor="evaluation", satisfied=resolved))
        if not resolved and as_of > response.due_at:
            clauses.append(
                f"{response.rule_id} ({response.force.value}, Class {class_name}): the "
                f"response target for PAIN {evaluation.pain.name}, "
                f"{_reachability(evaluation.is_internet_reachable)}, "
                f"{_exploitability(evaluation.is_likely_exploitable)} ran from the "
                f"completed evaluation {iso(evaluation.completed_at)} and passed "
                f"{iso(response.due_at)} with no disposition recorded."
            )

    acceptance = policy.acceptance_deadline(evaluation.completed_at)
    deadlines.append(_compiled(acceptance, anchor="evaluation", satisfied=resolved))
    if not resolved and as_of > acceptance.due_at:
        clauses.append(
            f"{acceptance.rule_id} ({acceptance.force.value}, Class {class_name}): the "
            f"{acceptance.timeframe.display_amount}-{acceptance.timeframe.unit.value} "
            f"categorization threshold ran from the completed evaluation "
            f"{iso(evaluation.completed_at)} and passed {iso(acceptance.due_at)} with "
            "no disposition and no acceptance recorded."
        )
    return tuple(deadlines), tuple(clauses)


def _compiled(deadline: PolicyDeadline, *, anchor: str, satisfied: bool) -> CompiledDeadline:
    return CompiledDeadline(
        rule_id=deadline.rule_id,
        rule_name=deadline.rule_name,
        force=deadline.force.value,
        anchor=anchor,
        start_at=deadline.start_at,
        due_at=deadline.due_at,
        timeframe_amount=deadline.timeframe.display_amount,
        timeframe_unit=deadline.timeframe.unit.value,
        satisfied=satisfied,
    )


def _kev_deadline(kev: KevClock, rule: SelectedRule) -> CompiledDeadline:
    """Return the VDR-TFR-KEV deadline, whose due date is the catalog's, not a timeframe."""

    return CompiledDeadline(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        force=rule.force.value,
        anchor="catalog",
        start_at=kev.start_at,
        due_at=kev.due_at,
        timeframe_amount=None,
        timeframe_unit=None,
        satisfied=kev.satisfied,
    )


def _kev_clause(
    kev: KevClock,
    rule: SelectedRule,
    catalog: KevCatalog,
    options: ReportOptions,
    detected_at: datetime,
    status: CaseStatus | None,
) -> str:
    """Explain a past-due KEV clock; only a past-due clock is written, so "ended" is past."""

    bound = kev.bound
    clause = (
        f"{rule.rule_id} ({rule.force.value}, Class {options.certification_class.value}): "
        f"the CISA KEV catalog (version {catalog.catalog_version}, released "
        f"{iso(catalog.date_released)}) lists {bound.cve_id} with due date "
        f"{bound.due_date.isoformat()}, which ended {iso(kev.due_at)} with no "
        "remediation recorded."
    )
    if detected_at > kev.due_at:
        clause += f" The due date had passed before detection at {iso(detected_at)}."
    if status in (CaseStatus.PARTIALLY_MITIGATED, CaseStatus.FULLY_MITIGATED):
        clause += " A recorded mitigation does not stop this clock."
    return clause


def _explanation(
    clauses: Sequence[str],
    policy: SelectedPolicy,
    snapshot: RuleSourceSnapshot,
    options: ReportOptions,
) -> str:
    parts = list(clauses)
    parts.append(f"Rules dataset commit {policy.provenance.commit}.")
    obtain = _optional_adoption_notice(snapshot, options.as_of)
    if obtain:
        parts.append(obtain)
    return " ".join(parts)


def _optional_adoption_notice(snapshot: RuleSourceSnapshot, as_of: datetime) -> str:
    dates = _obtain_dates(snapshot)
    if not dates:
        return ""
    earliest = min(dates.values())
    if as_of.astimezone(UTC).date().isoformat() >= earliest:
        return ""
    if len(set(dates.values())) == 1:
        rendered = earliest
    else:
        rendered = " and ".join(
            f"{value} ({document})" for document, value in sorted(dates.items())
        )
    return f"The VDR and VER rulesets are in their optional-adoption period until {rendered}."


def _obtain_dates(snapshot: RuleSourceSnapshot) -> dict[str, str]:
    data = snapshot.data
    dates: dict[str, str] = {}
    for document_id in ("VDR", "VER"):
        node: Any = data.get("FRR", {}).get(document_id, {})
        for key in ("info", "effective", "date", "obtain"):
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(key)
        if isinstance(node, str) and node:
            dates[document_id] = node
    return dates


def _reachability(value: bool) -> str:
    return "internet reachable" if value else "not internet reachable"


def _exploitability(value: bool) -> str:
    return "likely exploitable" if value else "not likely exploitable"


def _parser_versions(observations: Sequence[Observation]) -> tuple[tuple[str, str], ...]:
    pairs = {(item.parser_name, item.parser_version) for item in observations}
    return tuple(sorted(pairs))


__all__ = [
    "compile_record_set",
    "compile_record_set_from_artifacts",
    "coverage_diagnostics",
    "derive_changes_from_artifacts",
    "derive_request_changes",
    "derive_report_coverage",
]
