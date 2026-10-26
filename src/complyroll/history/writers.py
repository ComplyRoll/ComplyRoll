"""Idempotent commands that write history (ADR 0008 Decision 3).

Every writer here is a library function; the command-line surface that calls them is a
separate slice. Re-running any of them over the same inputs appends nothing, and
re-running after a real change appends exactly the change. That is the property that
makes the log a history rather than a mirror of the last run.

Two payload fields record when an operator's assertion was filed rather than what it
asserts: `detection.attested.attestedAt` and `case.disposition_recorded.recordedAt`.
They are excluded from the content comparison, so re-running a command tomorrow with
the same facts still appends nothing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from complyroll.adapters import (
    ArtifactProvenance,
    DiagnosticLevel,
    FailureClass,
    FailureClassification,
    IngestDiagnostic,
    IngestResult,
    failure_diagnostics,
    system_observation_for,
)
from complyroll.adapters.failures import DETECTION_FAILURE_RECORDED, failure_recorded_message
from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.events import (
    COVERAGE_RECORDED,
    FAILURE_HEAD_TYPES,
    FAILURE_HELD,
    MAX_BATCH_EVENTS,
    OBSERVATION_ID_KEY,
    UNDISPOSED_STATUSES,
    EventMetadata,
    EventRepository,
    PendingEvent,
    artifact_stream_id,
    canonical_payload_digest,
    case_stream_id,
    coverage_head_payload,
    coverage_stream_id_of,
    failure_hold_orphan_message,
    failure_stream_id,
    is_case_stream,
    iso_utc,
    parse_utc,
)
from complyroll.models import RESERVED_SOURCE_TYPE_PREFIX, CaseStatus, Observation
from complyroll.policy import CertificationProfile
from complyroll.reports.coverage import CoverageResult
from complyroll.reports.evaluations import EvaluationInput, EvaluationSet
from complyroll.reports.gaps import coverage_gap_observations
from complyroll.reports.inventory import Inventory
from complyroll.reports.vdt import (
    ReportDiagnostic,
    clock_problem,
    coverage_diagnostics,
    derive_report_coverage,
    observation_clock_message,
    system_record_kind,
)
from complyroll.store import EventRecord
from complyroll.store.sqlite import shown

from .fold import (
    ARTIFACT_INGESTED,
    CASE_CREATED,
    CASE_DISPOSITION_RECORDED,
    CASE_EVALUATED,
    CASE_IDENTIFIED,
    CASE_OBSERVATION_LINKED,
    CASE_PAIN_REDUCED,
    DETECTION_ATTESTED,
    FAILURE_RECORDED,
    OBSERVATION_RECORDED,
    CaseNotFoundError,
    CaseState,
    HistoryError,
    _coverage_stream_problem,
    _failure_record,
    _failure_stream_problem,
    _stream_tracking_id,
    artifact_history,
    fold_case_records,
    rehydrate_observations,
)
from .order import EvaluationOrderError, case_order_diagnostic, current_groups

#: Fields that say when an assertion was filed, not what it asserts.
CLERICAL_FIELDS: Mapping[str, frozenset[str]] = {
    DETECTION_ATTESTED: frozenset({"attestedAt"}),
    CASE_DISPOSITION_RECORDED: frozenset({"recordedAt"}),
}

#: The WARNING a failure carries when another failure stream of its digest already holds it.
FAILURE_HELD_BY_ANOTHER_STREAM = "failure_held_by_another_stream"


class EvaluationMatchError(HistoryError):
    """One or more evaluations did not select exactly one case."""

    def __init__(self, problems: Sequence[str]) -> None:
        self.problems: tuple[str, ...] = tuple(problems)
        summary = "; ".join(self.problems)
        super().__init__(f"evaluations could not be applied: {summary}")


@dataclass(frozen=True, slots=True)
class IngestOutcome:
    """What one `record_ingest` call did."""

    stream_id: str
    appended: bool
    observation_count: int
    diagnostics: tuple[IngestDiagnostic, ...]

    @property
    def already_recorded(self) -> bool:
        """Return True when the artifact was already in history and nothing was written."""

        return not self.appended


@dataclass(frozen=True, slots=True)
class FailureOutcome:
    """What one `record_failure` call did.

    `stream_id` is this reading's own failure stream, written now or found already
    recorded. `observation_id` is the system observation the store holds for this failure,
    and `failure_class` the class its head records, which a rerun can classify another way.
    `held_by` names the recorded failure stream that first holds that observation when this
    reading's stream is a hold beneath it, and is None otherwise. It is never stored: the
    log already says which stream holds an observation first.
    """

    stream_id: str
    appended: bool
    observation_id: str
    failure_class: FailureClass
    diagnostics: tuple[IngestDiagnostic, ...]
    held_by: str | None = None

    @property
    def already_recorded(self) -> bool:
        """Return True when the failure was already in history and nothing was written."""

        return not self.appended


@dataclass(frozen=True, slots=True)
class CoverageOutcome:
    """What one `record_coverage_gaps` call did (ADR 0015).

    `recorded` is each gap this call wrote and `already_recorded` each one whose stream the
    store already held, both in window order. A gap already recorded keeps the payload its
    stream was first written with, so its entry here is this run's rebuild of it, under the
    same id. `coverage` is the projection the gaps came from, and `diagnostics` the notes
    its derivation raised, which a report from the same inputs raises too.
    """

    coverage: CoverageResult
    recorded: tuple[Observation, ...]
    already_recorded: tuple[Observation, ...]
    diagnostics: tuple[ReportDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class CorrelationOutcome:
    """What one `correlate_cases` call did."""

    created: tuple[str, ...]
    linked: int
    skipped_links: int


@dataclass(frozen=True, slots=True)
class AttestationOutcome:
    """What one `attest_detection` call did.

    `not_applicable` names the cases where at least one linked observation already
    carries a source timestamp. An attestation never overrides a source timestamp, and
    the compiler takes the earliest known source time for a partly timestamped group
    (`artifact-partial`, ADR 0007 amendment), so an attestation on such a case could
    never reach a report and recording it would state a detection time nothing uses.
    """

    attested: tuple[str, ...]
    skipped: tuple[str, ...]
    not_applicable: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EvaluationOutcome:
    """Appended and skipped counts per event type for one `apply_evaluations` call.

    `warnings` carries the facts the store holds that the evaluations file no longer
    states. ComplyRoll has no retraction event (ADR 0008 Decision 7), so those facts
    stay in history and the two report paths would otherwise disagree in silence.
    """

    evaluations_appended: int = 0
    evaluations_skipped: int = 0
    reductions_appended: int = 0
    reductions_skipped: int = 0
    dispositions_appended: int = 0
    dispositions_skipped: int = 0
    identifications_appended: int = 0
    identifications_skipped: int = 0
    warnings: tuple[str, ...] = ()

    @property
    def appended(self) -> int:
        """Return how many events this call appended in total."""

        return (
            self.evaluations_appended
            + self.reductions_appended
            + self.dispositions_appended
            + self.identifications_appended
        )

    @property
    def skipped(self) -> int:
        """Return how many events this call left alone as unchanged."""

        return (
            self.evaluations_skipped
            + self.reductions_skipped
            + self.dispositions_skipped
            + self.identifications_skipped
        )


def _transaction_scope(repository: EventRepository) -> AbstractContextManager[Any]:
    """Open one store transaction, or join the caller's when one is already open.

    Each writer here is atomic on its own, and `SQLiteEventStore.transaction` refuses to
    nest, so a caller that needs several writer calls to commit or roll back together had
    no way to ask for it: `complyroll ingest` recorded each artifact in its own
    transaction, and a run that failed on the second artifact left the first durable while
    the buffered summary printed nothing. Joining an open transaction makes the writer's
    own scope a no-op and leaves the outer block to decide (ADR 0008, second amendment).
    """

    if repository.store.in_transaction:
        return nullcontext()
    return repository.transaction()


def content_digest(event_type: str, payload: Mapping[str, Any]) -> str:
    """Digest one payload's asserted content, ignoring its clerical filing time."""

    excluded = CLERICAL_FIELDS.get(event_type, frozenset())
    if not excluded:
        return canonical_payload_digest(payload)
    return canonical_payload_digest(
        {key: value for key, value in payload.items() if key not in excluded}
    )


def record_ingest(
    repository: EventRepository,
    ingest_result: IngestResult,
    *,
    metadata: EventMetadata,
    ingested_at: datetime,
) -> IngestOutcome:
    """Record one artifact ingestion and its observations, once and atomically.

    The artifact event and every observation are written inside one store transaction, so
    an interrupted run records the whole artifact or none of it. That matters because the
    artifact event declares the observation count: a stream holding a prefix of what it
    declared is a claim history cannot support, and both verification and replay used to
    accept one. The resume path below still exists for streams an earlier version wrote in
    separate batches, so a store already carrying such a prefix can be finished rather than
    condemned. A caller that already holds a transaction has this one join it instead, so
    `complyroll ingest` can make a whole run of artifacts all-or-nothing.

    An artifact stream that already carries every observation is left alone and reported as
    already recorded. A different parser version is a different stream (ADR 0002).

    One artifact ingestion is one instant: a resumed tail is stamped with the instant
    the stream was opened with rather than with this run's, so an artifact interrupted
    and resumed under a different `--as-of` does not end up with two ingestion times
    inside one stream. The instant is not part of an observation's identity, so
    restamping the tail changes no fingerprint and no observation identifier.
    """

    artifact = ingest_result.artifact
    if artifact is None or ingest_result.errors:
        raise HistoryError("only a successful ingest can be recorded as history")
    with _transaction_scope(repository):
        return _record_ingest(repository, ingest_result, metadata=metadata, ingested_at=ingested_at)


def _record_ingest(
    repository: EventRepository,
    ingest_result: IngestResult,
    *,
    metadata: EventMetadata,
    ingested_at: datetime,
) -> IngestOutcome:
    """Read the stream and write what is missing, inside the caller's transaction."""

    artifact = ingest_result.artifact
    if artifact is None:  # pragma: no cover - the caller refuses a failed ingest first
        raise HistoryError("only a successful ingest can be recorded as history")

    stream_id = artifact_stream_id(
        artifact.digest_sha256, artifact.parser_name, artifact.parser_version
    )
    observations = ingest_result.observations
    diagnostics = ingest_result.diagnostics
    existing = repository.read_stream(stream_id)
    recorded = sum(1 for record in existing if record.event_type == OBSERVATION_RECORDED)

    if existing:
        if existing[0].event_type != ARTIFACT_INGESTED:
            raise HistoryError(
                f"artifact stream {stream_id!r} begins with {existing[0].event_type!r}"
            )
        # The resume below completes a stream a crash left short; it never reconciles a
        # parser that now reads the same bytes into another count. Appending that tail
        # left the stream overfull, and every later rebuild refused the store.
        declared = existing[0].payload.get("observationCount")
        if type(declared) is not int or declared != len(observations):
            raise HistoryError(
                f"artifact stream {stream_id!r} was opened for another observation count "
                f"than the {len(observations)} this parser reads from the same bytes; a "
                "parser whose reading changed needs a new version"
            )
        if recorded > len(observations):
            raise HistoryError(
                f"artifact stream {stream_id!r} holds {recorded} observation(s) but the "
                f"parser produced {len(observations)}"
            )
        if recorded == len(observations):
            return IngestOutcome(
                stream_id=stream_id,
                appended=False,
                observation_count=len(observations),
                diagnostics=diagnostics,
            )

    opened_at = _stream_ingested_at(existing[0]) if existing else ingested_at
    pending: list[PendingEvent] = []
    if not existing:
        pending.append(
            PendingEvent(
                event_type=ARTIFACT_INGESTED,
                payload={
                    "name": artifact.name,
                    "sha256": artifact.digest_sha256,
                    "sizeBytes": artifact.size_bytes,
                    "mediaType": artifact.media_type,
                    "parserName": artifact.parser_name,
                    "parserVersion": artifact.parser_version,
                    "ingestedAt": iso_utc(opened_at),
                    "observationCount": len(observations),
                    "diagnostics": [item.to_dict() for item in diagnostics],
                },
                occurred_at=opened_at,
                metadata=metadata,
            )
        )
    for observation in observations[recorded:]:
        stamped = (
            observation
            if observation.ingested_at == opened_at
            else replace(observation, ingested_at=opened_at)
        )
        pending.append(
            PendingEvent(
                event_type=OBSERVATION_RECORDED,
                payload=stamped.to_canonical_dict(),
                occurred_at=opened_at,
                metadata=metadata,
            )
        )

    _append_all(repository, stream_id, pending, expected_version=len(existing))
    return IngestOutcome(
        stream_id=stream_id,
        appended=True,
        observation_count=len(observations),
        diagnostics=diagnostics,
    )


def record_failure(
    repository: EventRepository,
    result: IngestResult,
    classification: FailureClassification,
    *,
    metadata: EventMetadata,
    ingested_at: datetime,
) -> FailureOutcome:
    """Record one detection process failure as a failure stream, once and atomically.

    A failure stream is one head, `failure.recorded` or `failure.held`, and the one system
    observation the failure mints, written together in one transaction (ADR 0014). The head's
    diagnostics are `failure_diagnostics`: the failed reading's own, demoted and capped, for a
    failed reading, and only `detection_failure_recorded` for a side record, whose artifact
    stream already holds its `execution_unsuccessful` WARNING. `ingested_at` is the instant
    the system observation is observed at, unless the scanner declared the failed
    invocation's own clock, and the instant the head records.

    A stream already holding its head and its observation is reported as already recorded.
    A stream holding anything else is refused rather than resumed, because nothing ever
    writes one half of a failure stream. A system observation's identity is the digest and
    the instant, never the parser, so another failure stream of the digest can already hold
    this one. The reading's own stream is then written as a hold: a `failure.held` head with
    the payload a `failure.recorded` head would carry, and the reading's own system
    observation (ADR 0014, amendment 2026-10-13). The notice stays, and WARNING
    `failure_held_by_another_stream` names the holder, on this run and on every rerun. A
    holder whose stream id names no failed reading is refused with `HistoryError`, as the
    fold refuses it.
    """

    _require_aware(ingested_at, "ingested_at")
    artifact = result.artifact
    failure_class = classification.failure_class
    if artifact is None or failure_class is None:
        raise HistoryError("only a mintable detection process failure can be recorded")
    try:
        observation = system_observation_for(
            result, classification, name=artifact.name, observed_at=ingested_at
        )
        diagnostics = failure_diagnostics(result, classification, name=artifact.name)
    except ValueError as exc:
        raise HistoryError(f"the detection process failure cannot be recorded: {exc}") from exc
    if observation.ingested_at != ingested_at:
        observation = replace(observation, ingested_at=ingested_at)
    with _transaction_scope(repository):
        return _record_failure(
            repository,
            artifact,
            classification,
            failure_class,
            observation,
            diagnostics,
            metadata=metadata,
            ingested_at=ingested_at,
        )


def _record_failure(
    repository: EventRepository,
    artifact: ArtifactProvenance,
    classification: FailureClassification,
    failure_class: FailureClass,
    observation: Observation,
    diagnostics: tuple[IngestDiagnostic, ...],
    *,
    metadata: EventMetadata,
    ingested_at: datetime,
) -> FailureOutcome:
    """Read the failure stream and write it whole when it is new, inside the transaction."""

    stream_id = failure_stream_id(
        artifact.digest_sha256, artifact.parser_name, artifact.parser_version
    )
    existing = repository.read_stream(stream_id)
    if existing:
        heads = [record for record in existing if record.event_type in FAILURE_HEAD_TYPES]
        observed = [record for record in existing if record.event_type == OBSERVATION_RECORDED]
        problem = _failure_stream_problem(stream_id, len(heads), len(observed))
        reason = None if problem is None else problem[1]
        if reason is None and len(heads) + len(observed) != len(existing):
            reason = f"failure stream {stream_id!r} holds an event no failure stream carries"
        if reason is not None:
            raise HistoryError(
                f"{reason}; a failure stream is written whole, so it is refused rather than resumed"
            )
        observation_id = str(observed[0].payload.get(OBSERVATION_ID_KEY))
        # A reading this build classifies another way, such as one an earlier build recorded,
        # meets its stream on rerun, and the notice names the class history holds.
        recorded_class = _failure_record(repository, heads[0]).failure_class
        diagnostics = tuple(
            replace(item, message=failure_recorded_message(recorded_class, artifact.digest_sha256))
            if item.code == DETECTION_FAILURE_RECORDED
            else item
            for item in diagnostics
        )
        if heads[0].event_type != FAILURE_HELD:
            return FailureOutcome(
                stream_id=stream_id,
                appended=False,
                observation_id=observation_id,
                failure_class=recorded_class,
                diagnostics=diagnostics,
            )
        # A rerun of a hold says so again, so every run that meets the hold names its holder.
        holder = repository.failure_observations_of_digest(stream_id).get(observation_id)
        if holder is None:
            raise HistoryError(failure_hold_orphan_message(stream_id, observation_id, None))
        return FailureOutcome(
            stream_id=stream_id,
            appended=False,
            observation_id=observation_id,
            failure_class=recorded_class,
            diagnostics=(*diagnostics, _held_by_another_stream(repository, holder, artifact)),
            held_by=holder,
        )

    holder = repository.failure_observations_of_digest(stream_id).get(observation.observation_id)
    reported = diagnostics
    if holder is not None:
        # Worded before anything is appended, so a holder the fold refuses stops the write.
        reported = (*diagnostics, _held_by_another_stream(repository, holder, artifact))
    # The head stores the name the observation's metadata carries, which
    # `system_observation_for` has already passed through `diagnostic_text`, so the head
    # and the replayed `detectionFailures` entry cannot name the failure two ways. A hold's
    # head stores what a recorded head would; the WARNING is the run's, not history's.
    name = dict(observation.source_metadata)["artifact.name"]
    pending = [
        PendingEvent(
            event_type=FAILURE_RECORDED if holder is None else FAILURE_HELD,
            payload={
                "name": name,
                "sha256": artifact.digest_sha256,
                "sizeBytes": artifact.size_bytes,
                "mediaType": artifact.media_type,
                "parserName": artifact.parser_name,
                "parserVersion": artifact.parser_version,
                "ingestedAt": iso_utc(ingested_at),
                "failureClass": failure_class.value,
                "failureCodes": list(classification.codes),
                "clock": "invocation" if classification.clock is not None else "as-of",
                "diagnostics": [item.to_dict() for item in diagnostics],
            },
            occurred_at=ingested_at,
            metadata=metadata,
        ),
        PendingEvent(
            event_type=OBSERVATION_RECORDED,
            payload=observation.to_canonical_dict(),
            occurred_at=ingested_at,
            metadata=metadata,
        ),
    ]
    _append_all(repository, stream_id, pending, expected_version=0)
    return FailureOutcome(
        stream_id=stream_id,
        appended=True,
        observation_id=observation.observation_id,
        failure_class=failure_class,
        diagnostics=reported,
        held_by=holder,
    )


def record_coverage_gaps(
    repository: EventRepository,
    inventory: Inventory,
    *,
    profile: CertificationProfile,
    as_of: datetime,
    metadata: EventMetadata,
) -> CoverageOutcome:
    """Record each coverage window the store's evidence closed empty, once and atomically.

    The windows are derived as a report from this store derives them (ADR 0015): from the
    rehydrated observations, with the inventory, profile and as-of given, and each gap is
    ingested at that as-of, as the stateless run ingests its gaps at its own. A gap's stream
    is named by its gap record, so the stream id is the idempotence key: a stream already
    holding its head and record is left alone, and the first recorded payload stands even
    where this run's inventory digest differs. A stream holding anything else is refused,
    not resumed, because nothing ever writes one half of a coverage stream; the fold refuses
    a half the reader can see before this reads it. A new stream is written head first, as
    one batch at version 0.

    The rehydration and every append run in one store transaction, or in the caller's, so
    a run records every gap it derives or none of them.
    """

    if not isinstance(inventory, Inventory):
        raise TypeError("inventory must be an Inventory")
    _require_aware(as_of, "as_of")
    with _transaction_scope(repository):
        return _record_coverage_gaps(
            repository, inventory, profile=profile, as_of=as_of, metadata=metadata
        )


def _record_coverage_gaps(
    repository: EventRepository,
    inventory: Inventory,
    *,
    profile: CertificationProfile,
    as_of: datetime,
    metadata: EventMetadata,
) -> CoverageOutcome:
    """Derive the gaps and write the streams the store lacks, inside the transaction."""

    coverage = derive_report_coverage(rehydrate_observations(repository), inventory, profile, as_of)
    recorded: list[Observation] = []
    already: list[Observation] = []
    # Every stream is read and judged before the first append, so a refusal writes nothing.
    for gap in coverage_gap_observations(coverage, ingested_at=as_of):
        stream_id = coverage_stream_id_of(gap)
        existing = repository.read_stream(stream_id)
        if not existing:
            recorded.append(gap)
            continue
        heads = [record for record in existing if record.event_type == COVERAGE_RECORDED]
        observed = [record for record in existing if record.event_type == OBSERVATION_RECORDED]
        # NOTE: Unreachable today: `_read_coverage_streams`, run by `rehydrate_observations`
        # above, refuses both shapes first. The checks stay so this writer refuses a stream it
        # would resume on its own, whatever that reader comes to accept.
        problem = _coverage_stream_problem(stream_id, len(heads), len(observed))
        reason = None if problem is None else problem[1]
        if reason is None and len(heads) + len(observed) != len(existing):
            reason = f"coverage stream {stream_id!r} holds an event no coverage stream carries"
        if reason is not None:
            raise HistoryError(
                f"{reason}; a coverage stream is written whole, so it is refused rather than "
                "resumed"
            )
        already.append(gap)
    for gap in recorded:
        repository.append_batch(
            coverage_stream_id_of(gap),
            (
                _pending(COVERAGE_RECORDED, coverage_head_payload(gap), as_of, metadata),
                _pending(OBSERVATION_RECORDED, gap.to_canonical_dict(), as_of, metadata),
            ),
            expected_version=0,
        )
    return CoverageOutcome(
        coverage=coverage,
        recorded=tuple(recorded),
        already_recorded=tuple(already),
        diagnostics=tuple(coverage_diagnostics(coverage)),
    )


def _held_by_another_stream(
    repository: EventRepository,
    holder: str,
    artifact: ArtifactProvenance,
) -> IngestDiagnostic:
    """Warn that another failure stream of the digest holds this reading's failure (ADR 0014).

    A system observation's identity is the digest and the instant, never the parser, so a
    failure read at one instant, or a failed invocation whose scanner declared its clock,
    derives the same observation under every parser and version that reads it. The reading
    is recorded as a hold beneath the first failure stream holding that observation, with
    its own parser, version, codes and metadata. A report carries the earliest record of the
    observation that no reading of these bytes supersedes (R6): while the holder stands that
    is the holder's, and once a reading supersedes the holder it is the hold's. A rerun of a
    hold warns again, and a rerun of a recorded failure never does.

    The store is folded first. The holder is found by the digest's prefix alone, and the fold
    refuses a failure stream id that names no reading with a `HistoryError`, which `ingest`
    reports as `history_invalid`, so no hold is written beneath such a stream.
    """

    artifact_history(repository)
    return IngestDiagnostic(
        level=DiagnosticLevel.WARNING,
        code=FAILURE_HELD_BY_ANOTHER_STREAM,
        message=(
            f"{holder} already holds this failure's system observation, so the failure is "
            f"recorded under {artifact.parser_name} {artifact.parser_version} as a hold on it; "
            "a report carries the earliest record of that observation that no reading of these "
            "bytes supersedes"
        ),
    )


def correlate_cases(
    repository: EventRepository,
    *,
    metadata: EventMetadata,
    now: datetime,
) -> CorrelationOutcome:
    """Create the cases correlation v0 finds, and link the observations behind them.

    A case stream is created only when none exists for the tracking identifier, and an
    observation is linked only once, so re-running after a new ingest appends exactly
    the new links.

    Every existing case stream of a group is folded before anything is appended, so a
    stream that does not fold stops the run with the error a report prints for it, and
    nothing is written, inside a caller's transaction too (ADR 0008). A case stream no
    group names is not folded here.

    The rehydration and every append run in one store transaction. A second run that starts
    while this one is working contends on the write lock and then reads history including
    everything this run wrote, rather than deciding a case does not exist and creating a
    second one.
    """

    _require_aware(now, "now")
    with _transaction_scope(repository):
        return _correlate_cases(repository, metadata=metadata, now=now)


def _correlate_cases(
    repository: EventRepository,
    *,
    metadata: EventMetadata,
    now: datetime,
) -> CorrelationOutcome:
    """Correlate and link inside the caller's transaction."""

    groups = group_open_observations(rehydrate_observations(repository))
    created: list[str] = []
    linked = 0
    skipped_links = 0

    # Fold every stream this run may extend before the first append: a refusal after an
    # append would leave that append in a caller's open transaction.
    streams: list[tuple[VulnerabilityGroup, str, tuple[EventRecord, ...]]] = []
    for group in groups:
        stream_id = case_stream_id(group.tracking_id)
        existing = repository.read_stream(stream_id)
        if existing:
            fold_case_records(repository, group.tracking_id, existing)
        _require_linkable_clocks(group, existing)
        streams.append((group, stream_id, existing))

    for group, stream_id, existing in streams:
        pending: list[PendingEvent] = []
        if not existing:
            pending.append(
                PendingEvent(
                    event_type=CASE_CREATED,
                    payload=_case_created_payload(group, now),
                    occurred_at=now,
                    metadata=metadata,
                )
            )
            created.append(group.tracking_id)

        already_linked = {
            record.payload.get("observationId")
            for record in existing
            if record.event_type == CASE_OBSERVATION_LINKED
        }
        for observation in group.observations:
            if observation.observation_id in already_linked:
                skipped_links += 1
                continue
            already_linked.add(observation.observation_id)
            pending.append(
                PendingEvent(
                    event_type=CASE_OBSERVATION_LINKED,
                    payload=_link_payload(observation),
                    occurred_at=now,
                    metadata=metadata,
                )
            )
            linked += 1

        _append_all(repository, stream_id, pending, expected_version=len(existing))

    return CorrelationOutcome(created=tuple(created), linked=linked, skipped_links=skipped_links)


def attest_detection(
    repository: EventRepository,
    tracking_ids: Iterable[str],
    *,
    detected_at: datetime,
    rationale: str,
    metadata: EventMetadata,
    now: datetime,
) -> AttestationOutcome:
    """Attest a detection time for cases whose sources declare none.

    A case with any linked observation that carries a source timestamp needs no
    attestation and is reported as not applicable instead of gaining an inert event:
    the compiler resolves such a group from its earliest known source time, whether the
    rest of the group is timestamped or not, so nothing attested here could reach a
    report. A case with no links at all is still missing a timestamp, so it is
    attested. A case that already carries the same attested instant and rationale is
    skipped.

    Every case this call touches is read and written in one store transaction, so a
    concurrent run cannot read a case as unattested that this one has already attested.

    An attestation that would become a case's detection time is ordered against the
    case's current evaluation, as a report from the store orders it. Each case that
    would gain an attestation and carries an evaluation is resolved from its current open
    group with the new instant, and is refused only when the resolved source is
    `attestation`: a group the compiler times from a source timestamp is not this
    command's to refuse, whatever its links say. Every blocking case is named in one
    `EvaluationOrderError`, in the report's order, and nothing is appended, for an
    explicit selection and an `--all-missing` sweep alike. A case with no open group,
    which the report lists as `stale_case`, is not checked.
    """

    _require_aware(detected_at, "detected_at")
    _require_aware(now, "now")
    if not isinstance(rationale, str) or not rationale.strip():
        raise HistoryError("rationale must be non-blank text")
    with _transaction_scope(repository):
        return _attest_detection(
            repository,
            tracking_ids,
            detected_at=detected_at,
            rationale=rationale,
            metadata=metadata,
            now=now,
        )


def _attest_detection(
    repository: EventRepository,
    tracking_ids: Iterable[str],
    *,
    detected_at: datetime,
    rationale: str,
    metadata: EventMetadata,
    now: datetime,
) -> AttestationOutcome:
    """Attest the selected cases inside the caller's transaction."""

    payload = {
        "detectedAt": iso_utc(detected_at),
        "rationale": rationale,
        "attestedAt": iso_utc(now),
    }
    wanted = content_digest(DETECTION_ATTESTED, payload)
    attested: list[str] = []
    skipped: list[str] = []
    not_applicable: list[str] = []
    pending: list[tuple[str, tuple[EventRecord, ...]]] = []

    for tracking_id in _unique(tracking_ids):
        stream_id = case_stream_id(tracking_id)
        existing = repository.read_stream(stream_id)
        if not existing:
            raise CaseNotFoundError(f"no case stream exists for {tracking_id!r}")
        if _any_link_is_timestamped(existing):
            not_applicable.append(tracking_id)
            continue
        latest = _latest_payload(existing, DETECTION_ATTESTED)
        if latest is not None and content_digest(DETECTION_ATTESTED, latest) == wanted:
            skipped.append(tracking_id)
            continue
        pending.append((tracking_id, tuple(existing)))

    # Every case is checked before the first append, so a refusal names every blocking
    # case and leaves history as it found it, even inside a caller's open transaction.
    _require_attestation_order(repository, pending, detected_at=detected_at)

    for tracking_id, existing in pending:
        repository.append(
            case_stream_id(tracking_id),
            DETECTION_ATTESTED,
            payload,
            occurred_at=now,
            metadata=metadata,
            expected_version=len(existing),
        )
        attested.append(tracking_id)

    return AttestationOutcome(
        attested=tuple(attested),
        skipped=tuple(skipped),
        not_applicable=tuple(not_applicable),
    )


def apply_evaluations(
    repository: EventRepository,
    evaluation_set: EvaluationSet,
    *,
    metadata: EventMetadata,
    now: datetime,
) -> EvaluationOutcome:
    """Apply an evaluations file to the cases it selects, appending only the changes.

    Entries select cases exactly as the stateless compiler does: `sourceRecordId` with
    an optional `contextKey` and `sourceType`, where zero matches and more than one
    match are both errors, and two entries may not claim the same case. An evaluation
    whose canonical payload equals the case's latest `case.evaluated` payload is
    skipped; any difference appends a second evaluation, and the earlier one stays
    readable (ADR 0008 Decision 4).

    Two cases may not end this run sharing one effective tracking id, which the
    compiler refuses as well. That check runs before the first append, so a refused
    run leaves history exactly as it found it. Facts the store holds and the file no
    longer states are kept and reported in `EvaluationOutcome.warnings`.

    Every matched entry, an unchanged one included, is ordered against its case's
    detection time, resolved from the current open group and the case's recorded
    attestation exactly as a report from the store resolves it. An entry completed
    before a detection time that is the record's own refuses the whole file before any
    append, with every `evaluation_before_detection` ERROR the report would raise, in
    its order (`EvaluationOrderError`). An entry completed before a partly timestamped
    group's earliest known timestamp is applied, and the report's
    `evaluation_before_partial_detection` WARNING joins `EvaluationOutcome.warnings`
    without its level prefix. A case with no open group (`stale_case`) or no resolvable
    detection time is not checked, since no report prints a detection time for it.

    The fold, the checks, and every append run inside one store transaction. Uniqueness
    across cases is a claim about the whole log, and two runs that each folded a store
    without the other's writes could both pass it and both commit the same provider
    identifier. Holding the write lock from the fold to the last append makes the second
    run wait, re-fold, and see the first run's events.
    """

    if not isinstance(evaluation_set, EvaluationSet):
        raise TypeError("evaluation_set must be an EvaluationSet")
    _require_aware(now, "now")
    with _transaction_scope(repository):
        return _apply_evaluations(repository, evaluation_set, metadata=metadata, now=now)


def _apply_evaluations(
    repository: EventRepository,
    evaluation_set: EvaluationSet,
    *,
    metadata: EventMetadata,
    now: datetime,
) -> EvaluationOutcome:
    """Fold, check, and append inside the caller's transaction."""

    streams = _case_streams(repository)
    cases = tuple(
        sorted(
            (
                fold_case_records(repository, tracking_id, records)
                for tracking_id, records in streams.items()
            ),
            key=lambda state: state.tracking_id,
        )
    )
    matched = _match_cases(evaluation_set, cases)
    # The order check runs before the effective tracking id check, as the compiler orders
    # them, so a file refused for both prints the report's ordering lines.
    warnings: list[str] = _require_evaluation_order(repository, cases, matched)
    _require_unique_effective_ids(cases, matched)
    counters = dict.fromkeys(
        (
            "evaluations_appended",
            "evaluations_skipped",
            "reductions_appended",
            "reductions_skipped",
            "dispositions_appended",
            "dispositions_skipped",
            "identifications_appended",
            "identifications_skipped",
        ),
        0,
    )

    for case in cases:
        entry = matched.get(case.tracking_id)
        if entry is None:
            continue
        records = streams[case.tracking_id]
        pending: list[PendingEvent] = []

        if entry.tracking_id is not None:
            if case.provider_tracking_id == entry.tracking_id:
                counters["identifications_skipped"] += 1
            else:
                pending.append(
                    _pending(
                        CASE_IDENTIFIED,
                        {"providerTrackingId": entry.tracking_id},
                        now,
                        metadata,
                    )
                )
                counters["identifications_appended"] += 1
        elif case.provider_tracking_id is not None:
            warnings.append(_identification_retained_warning(case, entry))

        evaluated = _evaluation_payload(entry)
        latest_evaluation = _latest_payload(records, CASE_EVALUATED)
        if latest_evaluation is not None and canonical_payload_digest(
            latest_evaluation
        ) == canonical_payload_digest(evaluated):
            counters["evaluations_skipped"] += 1
        else:
            pending.append(_pending(CASE_EVALUATED, evaluated, now, metadata))
            counters["evaluations_appended"] += 1

        recorded_reductions = {
            content_digest(CASE_PAIN_REDUCED, record.payload): record.payload
            for record in records
            if record.event_type == CASE_PAIN_REDUCED
        }
        stated_reductions: set[str] = set()
        for event in entry.pain_reduction_events:
            reduction = {"reducedAt": iso_utc(event.reduced_at), "rating": int(event.rating)}
            digest = content_digest(CASE_PAIN_REDUCED, reduction)
            stated_reductions.add(digest)
            if digest in recorded_reductions:
                counters["reductions_skipped"] += 1
                continue
            recorded_reductions[digest] = reduction
            pending.append(_pending(CASE_PAIN_REDUCED, reduction, now, metadata))
            counters["reductions_appended"] += 1
        retained_reductions = [
            payload
            for digest, payload in recorded_reductions.items()
            if digest not in stated_reductions
        ]
        if retained_reductions:
            warnings.append(_reduction_retained_warning(case, entry, retained_reductions))

        disposition = _disposition_payload(entry, now)
        latest_disposition = _latest_payload(records, CASE_DISPOSITION_RECORDED)
        if disposition is None:
            if latest_disposition is not None:
                warnings.append(_disposition_retained_warning(case, entry, latest_disposition))
        elif latest_disposition is not None and content_digest(
            CASE_DISPOSITION_RECORDED, latest_disposition
        ) == content_digest(CASE_DISPOSITION_RECORDED, disposition):
            counters["dispositions_skipped"] += 1
        else:
            pending.append(_pending(CASE_DISPOSITION_RECORDED, disposition, now, metadata))
            counters["dispositions_appended"] += 1

        _append_all(repository, case.stream_id, pending, expected_version=len(records))

    return EvaluationOutcome(
        evaluations_appended=counters["evaluations_appended"],
        evaluations_skipped=counters["evaluations_skipped"],
        reductions_appended=counters["reductions_appended"],
        reductions_skipped=counters["reductions_skipped"],
        dispositions_appended=counters["dispositions_appended"],
        dispositions_skipped=counters["dispositions_skipped"],
        identifications_appended=counters["identifications_appended"],
        identifications_skipped=counters["identifications_skipped"],
        warnings=tuple(warnings),
    )


def _case_streams(repository: EventRepository) -> dict[str, tuple[EventRecord, ...]]:
    """Group every case stream's events by tracking identifier in one pass."""

    grouped: dict[str, list[EventRecord]] = {}
    for record in repository.read_all():
        if not is_case_stream(record.stream_id):
            continue
        grouped.setdefault(_stream_tracking_id(record.stream_id), []).append(record)
    return {tracking_id: tuple(records) for tracking_id, records in grouped.items()}


def _match_cases(
    evaluation_set: EvaluationSet,
    cases: Sequence[CaseState],
) -> dict[str, EvaluationInput]:
    matched: dict[str, EvaluationInput] = {}
    claimed: dict[str, EvaluationInput] = {}
    problems: list[str] = []

    for entry in evaluation_set.entries:
        candidates = [case for case in cases if _matches(entry, case)]
        if not candidates:
            problems.append(f"{entry.location}: no case matches {entry.match.describe()}")
            continue
        if len(candidates) > 1:
            named = ", ".join(case.tracking_id for case in candidates)
            problems.append(
                f"{entry.location}: {entry.match.describe()} matches {len(candidates)} "
                f"cases ({named}); {entry.match.ambiguity_remedy()}"
            )
            continue
        case = candidates[0]
        # The same refusal, in the same order, as `reports.vdt._match_evaluations`.
        if case.source_type.startswith(RESERVED_SOURCE_TYPE_PREFIX) and (
            entry.match.context_key is None or entry.match.source_type is None
        ):
            refusal = entry.match.context_key_required(
                case.tracking_id, kind=system_record_kind(case.source_type)
            )
            problems.append(f"{entry.location}: {refusal}")
            continue
        previous = claimed.get(case.tracking_id)
        if previous is not None:
            problems.append(
                f"{entry.location}: {case.tracking_id} is already evaluated by {previous.location}"
            )
            continue
        claimed[case.tracking_id] = entry
        matched[case.tracking_id] = entry

    if problems:
        raise EvaluationMatchError(problems)
    return matched


def _require_unique_effective_ids(
    cases: Sequence[CaseState],
    matched: Mapping[str, EvaluationInput],
) -> None:
    """Refuse a run that would leave two cases sharing one effective tracking id.

    A case's effective id is the entry's `trackingId` when this run states one, else
    the recorded `providerTrackingId`, else the correlation id. Every folded case
    counts, including the ones this run does not touch, so an override recorded by an
    earlier run still collides. `reports.vdt` refuses the same data, so accepting it
    here would write history the report cannot compile.
    """

    claimed: dict[str, tuple[CaseState, str]] = {}
    problems: list[str] = []
    for case in cases:
        entry = matched.get(case.tracking_id)
        effective = case.effective_tracking_id
        location = "recorded history"
        if entry is not None:
            location = entry.location
            if entry.tracking_id is not None:
                effective = entry.tracking_id
        previous = claimed.get(effective)
        if previous is None:
            claimed[effective] = (case, location)
            continue
        previous_case, previous_location = previous
        problems.append(
            f"{location}: effective tracking id {shown(effective)} is claimed by "
            f"{previous_location} (originally {previous_case.tracking_id}) and "
            f"{location} (originally {case.tracking_id}); an override may rename one "
            "case but may not merge two"
        )
    if problems:
        raise EvaluationMatchError(problems)


def _require_evaluation_order(
    repository: EventRepository,
    cases: Sequence[CaseState],
    matched: Mapping[str, EvaluationInput],
) -> list[str]:
    """Refuse a run that would leave an evaluation before its record's detection time.

    Observations are rehydrated once, and every matched entry is checked, whether or not
    it changes the case. Diagnostics follow the compiler's group order, so a refusal
    prints the lines `report vdt --db` would print. Returns the partial-detection
    WARNINGs as warning text, `code: message [location]`.
    """

    if not matched:
        return []
    by_tracking_id = {case.tracking_id: case for case in cases}
    blocked: list[ReportDiagnostic] = []
    warnings: list[str] = []
    for tracking_id, group in current_groups(repository).items():
        entry = matched.get(tracking_id)
        case = by_tracking_id.get(tracking_id)
        if entry is None or case is None:
            continue
        attested_at = None if case.attestation is None else case.attestation.detected_at
        diagnostic = case_order_diagnostic(
            case, group, completed_at=entry.completed_at, attested_at=attested_at
        )
        if diagnostic is None:
            continue
        if diagnostic.level is DiagnosticLevel.ERROR:
            blocked.append(diagnostic)
        else:
            warnings.append(_unprefixed(diagnostic))
    if blocked:
        raise EvaluationOrderError(blocked)
    return warnings


def _require_attestation_order(
    repository: EventRepository,
    pending: Sequence[tuple[str, Sequence[EventRecord]]],
    *,
    detected_at: datetime,
) -> None:
    """Refuse attestations that would leave a current evaluation before detection.

    Only a case that carries an evaluation is resolved, and observations are rehydrated
    only when there is one, so a sweep over unevaluated cases reads no artifact stream.
    """

    evaluated: dict[str, CaseState] = {}
    for tracking_id, records in pending:
        case = fold_case_records(repository, tracking_id, records)
        if case.current_evaluation is not None:
            evaluated[tracking_id] = case
    if not evaluated:
        return
    blocked: list[ReportDiagnostic] = []
    for tracking_id, group in current_groups(repository).items():
        target = evaluated.get(tracking_id)
        if target is None or target.current_evaluation is None:
            continue
        diagnostic = case_order_diagnostic(
            target,
            group,
            completed_at=target.current_evaluation.completed_at,
            attested_at=detected_at,
            sources=("attestation",),
        )
        if diagnostic is not None and diagnostic.level is DiagnosticLevel.ERROR:
            blocked.append(diagnostic)
    if blocked:
        raise EvaluationOrderError(blocked)


def _unprefixed(diagnostic: ReportDiagnostic) -> str:
    """Return a diagnostic's rendered line without its level, as a writer warning."""

    return diagnostic.render().removeprefix(f"{diagnostic.level.value}: ")


def _identification_retained_warning(case: CaseState, entry: EvaluationInput) -> str:
    """Explain that a tracking id override the file dropped stays in history."""

    return (
        f"identification_retained: {case.tracking_id}: {entry.location} states no trackingId, "
        f"so the recorded override {shown(case.provider_tracking_id)} stands and the persisted "
        "report keeps reporting it; ComplyRoll has no retraction event, and returning to the "
        "correlation identifier is not something an evaluations file can ask for"
    )


def _disposition_retained_warning(
    case: CaseState,
    entry: EvaluationInput,
    recorded: Mapping[str, Any],
) -> str:
    """Explain that a disposition the file dropped stays in history."""

    return (
        f"disposition_retained: {case.tracking_id}: {entry.location} states no disposition, "
        f"so the recorded {recorded.get('status')} disposition stands; ComplyRoll has no "
        "retraction event, and changing it needs a new disposition with a rationale"
    )


def _reduction_retained_warning(
    case: CaseState,
    entry: EvaluationInput,
    retained: Sequence[Mapping[str, Any]],
) -> str:
    """Explain that PAIN reductions the file dropped stay in history."""

    described = ", ".join(
        f"PAIN {payload.get('rating')} at {payload.get('reducedAt')}" for payload in retained
    )
    return (
        f"reduction_retained: {case.tracking_id}: {entry.location} no longer states "
        f"{len(retained)} recorded PAIN reduction(s) ({described}); ComplyRoll has no "
        "retraction event, so the recorded reductions stand, and changing them needs a "
        "new evaluation entry with a rationale"
    )


def _stream_ingested_at(head: EventRecord) -> datetime:
    """Return the ingestion instant an open artifact stream already recorded."""

    value = head.payload.get("ingestedAt")
    if not isinstance(value, str):
        raise HistoryError(f"artifact event at sequence {head.sequence} declares no ingestedAt")
    try:
        return parse_utc(value)
    except ValueError as exc:
        raise HistoryError(
            f"artifact event at sequence {head.sequence} declares an unreadable ingestedAt: {exc}"
        ) from exc


def _any_link_is_timestamped(records: Sequence[EventRecord]) -> bool:
    """Return True when at least one of a case's links carries a source timestamp.

    One timestamped link is enough for the compiler to resolve the whole group from
    the earliest known source time, so it is also enough to make an attestation inert.
    A case with no links at all reaches nothing here and stays attestable.
    """

    return any(
        record.payload.get("observedAt") is not None
        for record in records
        if record.event_type == CASE_OBSERVATION_LINKED
    )


def _matches(entry: EvaluationInput, case: CaseState) -> bool:
    """Select a case exactly as `reports.vdt._matches` selects a group."""

    if entry.match.source_record_id != case.source_record_id:
        return False
    if entry.match.context_key is not None and entry.match.context_key != case.context_key:
        return False
    return not (entry.match.source_type is not None and entry.match.source_type != case.source_type)


def _case_created_payload(group: VulnerabilityGroup, now: datetime) -> dict[str, Any]:
    """Build `case.created` from the group, falling back to the source record id.

    A rule can report without a title, and the payload contract requires a non-blank
    title and description, so the source record identifier stands in for both.
    """

    title = group.title.strip() or group.source_record_id
    description = group.description.strip() or title
    return {
        "trackingId": group.tracking_id,
        "sourceType": group.source_type,
        "sourceRecordId": group.source_record_id,
        "contextKey": group.context_key,
        "title": title,
        "description": description,
        "createdAt": iso_utc(now),
    }


def _require_linkable_clocks(group: VulnerabilityGroup, existing: Sequence[EventRecord]) -> None:
    """Refuse a group whose next link would carry a source time with no UTC instant.

    A link stores its observation's clock in UTC, so such a clock, which only an earlier
    build could record, ended the run in a traceback. It is refused before the first append,
    by the predicate `store verify` names it with (CL-54). Skipping an observation already
    linked changes nothing: its link stored the clock in UTC, so it had a UTC instant.
    """

    linked = {
        record.payload.get("observationId")
        for record in existing
        if record.event_type == CASE_OBSERVATION_LINKED
    }
    for observation in group.observations:
        if observation.observation_id in linked or observation.observed_at is None:
            continue
        problem = clock_problem(observation.observed_at)
        if problem is not None:
            raise HistoryError(
                observation_clock_message(
                    observation.observation_id, observation.observed_at, problem
                )
            )


def _link_payload(observation: Observation) -> dict[str, Any]:
    return {
        "observationId": observation.observation_id,
        "resourceId": observation.resource.resource_id,
        "resourceType": observation.resource.resource_type,
        "observedAt": (
            None if observation.observed_at is None else iso_utc(observation.observed_at)
        ),
        "sourceTool": observation.source_tool,
        "sourceArtifactSha256": observation.source_artifact_digest,
        "sourceIdentifiers": list(observation.source_identifiers),
    }


def _evaluation_payload(entry: EvaluationInput) -> dict[str, Any]:
    projection = entry.projected_next_reduction
    return {
        "completedAt": iso_utc(entry.completed_at),
        "isInternetReachable": entry.is_internet_reachable,
        "isLikelyExploitable": entry.is_likely_exploitable,
        "pain": int(entry.pain),
        "potentialAgencyImpact": entry.potential_agency_impact,
        "rationale": entry.rationale,
        "evaluator": entry.evaluator,
        "isFalsePositive": entry.is_false_positive,
        "supplementaryRiskInformation": entry.supplementary_risk_information,
        "projectedNextReduction": (
            None
            if projection is None
            else {
                "estimatedAt": iso_utc(projection.estimated_at),
                "targetRating": int(projection.target_rating),
            }
        ),
    }


def _disposition_payload(entry: EvaluationInput, now: datetime) -> dict[str, Any] | None:
    status = entry.case_status
    if status is None or status in UNDISPOSED_STATUSES:
        return None
    closed: CaseStatus | None = entry.closed_disposition
    return {
        "status": status.value,
        "closedDisposition": None if closed is None else closed.value,
        "acceptanceRationale": entry.acceptance_rationale,
        "recordedAt": iso_utc(now),
    }


def _pending(
    event_type: str,
    payload: Mapping[str, Any],
    occurred_at: datetime,
    metadata: EventMetadata,
) -> PendingEvent:
    return PendingEvent(
        event_type=event_type,
        payload=payload,
        occurred_at=occurred_at,
        metadata=metadata,
    )


def _append_all(
    repository: EventRepository,
    stream_id: str,
    pending: Sequence[PendingEvent],
    *,
    expected_version: int,
) -> None:
    """Append a run of events to one stream, in transactional batches."""

    version = expected_version
    for start in range(0, len(pending), MAX_BATCH_EVENTS):
        chunk = tuple(pending[start : start + MAX_BATCH_EVENTS])
        repository.append_batch(stream_id, chunk, expected_version=version)
        version += len(chunk)


def _latest_payload(
    records: Sequence[EventRecord],
    event_type: str,
) -> dict[str, Any] | None:
    latest: dict[str, Any] | None = None
    for record in records:
        if record.event_type == event_type:
            latest = record.payload
    return latest


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _require_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")


__all__ = [
    "CLERICAL_FIELDS",
    "AttestationOutcome",
    "CorrelationOutcome",
    "CoverageOutcome",
    "EvaluationMatchError",
    "EvaluationOrderError",
    "EvaluationOutcome",
    "FailureOutcome",
    "IngestOutcome",
    "apply_evaluations",
    "attest_detection",
    "content_digest",
    "correlate_cases",
    "record_coverage_gaps",
    "record_failure",
    "record_ingest",
]
