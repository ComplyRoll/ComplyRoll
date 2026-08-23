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

from complyroll.adapters import IngestDiagnostic, IngestResult
from complyroll.correlation import VulnerabilityGroup, group_open_observations
from complyroll.events import (
    MAX_BATCH_EVENTS,
    UNDISPOSED_STATUSES,
    EventMetadata,
    EventRepository,
    PendingEvent,
    artifact_stream_id,
    canonical_payload_digest,
    case_stream_id,
    is_case_stream,
    iso_utc,
    parse_utc,
    tracking_id_from_stream,
)
from complyroll.models import CaseStatus, Observation
from complyroll.reports.evaluations import EvaluationInput, EvaluationSet
from complyroll.store import EventRecord

from .fold import (
    ARTIFACT_INGESTED,
    CASE_CREATED,
    CASE_DISPOSITION_RECORDED,
    CASE_EVALUATED,
    CASE_IDENTIFIED,
    CASE_OBSERVATION_LINKED,
    CASE_PAIN_REDUCED,
    DETECTION_ATTESTED,
    OBSERVATION_RECORDED,
    CaseNotFoundError,
    CaseState,
    HistoryError,
    fold_case_records,
    rehydrate_observations,
)

#: Fields that say when an assertion was filed, not what it asserts.
CLERICAL_FIELDS: Mapping[str, frozenset[str]] = {
    DETECTION_ATTESTED: frozenset({"attestedAt"}),
    CASE_DISPOSITION_RECORDED: frozenset({"recordedAt"}),
}


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
        return _record_ingest(
            repository, ingest_result, metadata=metadata, ingested_at=ingested_at
        )


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

    for group in groups:
        stream_id = case_stream_id(group.tracking_id)
        existing = repository.read_stream(stream_id)
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
        repository.append(
            stream_id,
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
    _require_unique_effective_ids(cases, matched)

    warnings: list[str] = []
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
                warnings.append(
                    _disposition_retained_warning(case, entry, latest_disposition)
                )
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
        grouped.setdefault(tracking_id_from_stream(record.stream_id), []).append(record)
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
                f"cases ({named}); add contextKey or sourceType"
            )
            continue
        case = candidates[0]
        previous = claimed.get(case.tracking_id)
        if previous is not None:
            problems.append(
                f"{entry.location}: {case.tracking_id} is already evaluated by "
                f"{previous.location}"
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
            f"{location}: effective tracking id {effective!r} is claimed by "
            f"{previous_location} (originally {previous_case.tracking_id}) and "
            f"{location} (originally {case.tracking_id}); an override may rename one "
            "case but may not merge two"
        )
    if problems:
        raise EvaluationMatchError(problems)


def _identification_retained_warning(case: CaseState, entry: EvaluationInput) -> str:
    """Explain that a tracking id override the file dropped stays in history."""

    return (
        f"identification_retained: {case.tracking_id}: {entry.location} states no trackingId, "
        f"so the recorded override {case.provider_tracking_id!r} stands and the persisted "
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
        raise HistoryError(
            f"artifact event at sequence {head.sequence} declares no ingestedAt"
        )
    try:
        return parse_utc(value)
    except ValueError as exc:
        raise HistoryError(
            f"artifact event at sequence {head.sequence} declares an unreadable "
            f"ingestedAt: {exc}"
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
    return not (
        entry.match.source_type is not None and entry.match.source_type != case.source_type
    )


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
    "EvaluationMatchError",
    "EvaluationOutcome",
    "IngestOutcome",
    "apply_evaluations",
    "attest_detection",
    "content_digest",
    "correlate_cases",
    "record_ingest",
]
