"""Fold the event log back into domain state (ADR 0008 Decisions 4 and 5).

Nothing here collapses history. A case's evaluations are all of its `case.evaluated`
events in recorded order and the current evaluation is simply the latest, so a second,
different evaluation is visible alongside the first rather than replacing it. Every
folded record carries the global sequence of the event that produced it, so a history
listing can cite the log rather than paraphrase it.

Payloads are stored, untrusted bytes: each one is re-checked against its published
contract before it is read, and a payload that does not fit raises rather than folding
into a plausible-looking case.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from complyroll.adapters import DiagnosticLevel, IngestDiagnostic
from complyroll.events import (
    EventContractError,
    EventRepository,
    case_stream_id,
    is_case_stream,
    parse_utc,
    tracking_id_from_stream,
)
from complyroll.models import CaseStatus, Observation, PainRating
from complyroll.reports.evaluations import PainReductionEvent, ProjectedReduction
from complyroll.store import EventRecord

ARTIFACT_INGESTED = "artifact.ingested"
OBSERVATION_RECORDED = "observation.recorded"
CASE_CREATED = "case.created"
CASE_OBSERVATION_LINKED = "case.observation_linked"
DETECTION_ATTESTED = "detection.attested"
CASE_EVALUATED = "case.evaluated"
CASE_PAIN_REDUCED = "case.pain_reduced"
CASE_DISPOSITION_RECORDED = "case.disposition_recorded"
CASE_IDENTIFIED = "case.identified"


class HistoryError(ValueError):
    """Stored history cannot be folded into domain state."""


class CaseNotFoundError(HistoryError):
    """No case stream exists for the requested tracking identifier."""


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """One `artifact.ingested` event, read back as artifact provenance."""

    name: str
    sha256: str
    size_bytes: int
    media_type: str
    parser_name: str
    parser_version: str
    ingested_at: datetime
    observation_count: int
    diagnostics: tuple[IngestDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class ObservationLink:
    """One observation linked to a case, with the event that linked it."""

    sequence: int
    observation_id: str
    resource_id: str
    resource_type: str
    observed_at: datetime | None
    source_tool: str
    source_artifact_sha256: str
    source_identifiers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AttestationRecord:
    """The operator's attested detection time for a case."""

    sequence: int
    detected_at: datetime
    rationale: str
    attested_at: datetime


@dataclass(frozen=True, slots=True)
class EvaluationRecord:
    """One completed contextual evaluation, as it was recorded."""

    sequence: int
    completed_at: datetime
    is_internet_reachable: bool
    is_likely_exploitable: bool
    pain: PainRating
    potential_agency_impact: str
    rationale: str
    evaluator: str
    is_false_positive: bool
    supplementary_risk_information: str | None
    projected_next_reduction: ProjectedReduction | None


@dataclass(frozen=True, slots=True)
class PainReductionRecord:
    """One completed PAIN reduction."""

    sequence: int
    reduced_at: datetime
    rating: PainRating

    @property
    def event(self) -> PainReductionEvent:
        """Return the report-layer shape for this reduction."""

        return PainReductionEvent(reduced_at=self.reduced_at, rating=self.rating)


@dataclass(frozen=True, slots=True)
class DispositionRecord:
    """The disposition of record for a case.

    The stored payload is untrusted, so the consistency `reports.evaluations` requires
    of an evaluations entry is re-checked on the way back out rather than assumed from
    the contract: a closed case names what it closed as, a closing disposition needs a
    closed status, and only a case that accepts risk carries an acceptance rationale.
    A rationale of whitespace is no rationale; `minLength` cannot tell the difference
    and a vulnerability routed out of the detail report as accepted must say why.
    """

    sequence: int
    status: CaseStatus
    closed_disposition: CaseStatus | None
    acceptance_rationale: str | None
    recorded_at: datetime

    def __post_init__(self) -> None:
        if self.status is CaseStatus.CLOSED:
            if self.closed_disposition is None:
                raise HistoryError(
                    "closedDisposition is required when status is 'closed'"
                )
        elif self.closed_disposition is not None:
            raise HistoryError("closedDisposition is only valid when status is 'closed'")

        rationale = self.acceptance_rationale
        if self.accepts_risk:
            if rationale is None or not rationale.strip():
                raise HistoryError(
                    "acceptanceRationale is required when the case accepts risk"
                )
        elif rationale is not None:
            raise HistoryError(
                "acceptanceRationale is only valid when the case accepts risk"
            )

    @property
    def resolved_status(self) -> CaseStatus | None:
        """Return the status that decides `finalDisposition`, resolving `closed`."""

        if self.status is CaseStatus.CLOSED:
            return self.closed_disposition
        return self.status

    @property
    def accepts_risk(self) -> bool:
        """Return True when this disposition accepts the vulnerability's residual risk."""

        return self.resolved_status is CaseStatus.ACCEPTED


@dataclass(frozen=True, slots=True)
class CaseState:
    """One case stream folded into its current state, with its history intact."""

    tracking_id: str
    provider_tracking_id: str | None
    source_type: str
    source_record_id: str
    context_key: str
    title: str
    description: str
    created_at: datetime
    created_sequence: int
    links: tuple[ObservationLink, ...]
    attestation: AttestationRecord | None
    evaluations: tuple[EvaluationRecord, ...]
    pain_reductions: tuple[PainReductionRecord, ...]
    disposition: DispositionRecord | None
    identified_sequence: int | None
    last_sequence: int

    @property
    def stream_id(self) -> str:
        """Return the event stream this case was folded from."""

        return case_stream_id(self.tracking_id)

    @property
    def effective_tracking_id(self) -> str:
        """Return the operator's override when one was recorded, else the correlation id."""

        return self.provider_tracking_id or self.tracking_id

    @property
    def observation_ids(self) -> tuple[str, ...]:
        """Return the linked observation identifiers in the order they were linked."""

        return tuple(link.observation_id for link in self.links)

    @property
    def current_evaluation(self) -> EvaluationRecord | None:
        """Return the latest evaluation, or None while the case is unevaluated."""

        return self.evaluations[-1] if self.evaluations else None

    @property
    def evaluation_count(self) -> int:
        """Return how many evaluations this case has recorded."""

        return len(self.evaluations)


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One line of a case's history listing."""

    sequence: int
    recorded_at: datetime
    event_type: str
    actor: str
    summary: str

    def render(self) -> str:
        """Return the single-line form a `cases history` listing prints."""

        stamp = self.recorded_at.isoformat().replace("+00:00", "Z")
        return f"{self.sequence}\t{stamp}\t{self.event_type}\t{self.actor}\t{self.summary}"


def rehydrate_observations(repository: EventRepository) -> tuple[Observation, ...]:
    """Read every `observation.recorded` payload back into an `Observation`.

    Order is the order the events were recorded, which is the order the parsers
    produced them, so correlation sees exactly what the stateless path sees.
    """

    observations: list[Observation] = []
    for record in repository.read_all():
        if record.event_type != OBSERVATION_RECORDED:
            continue
        try:
            repository.validate_payload(
                record.event_type, record.payload, event_version=record.event_version
            )
            observations.append(Observation.from_canonical_dict(record.payload))
        except (EventContractError, TypeError, ValueError) as exc:
            raise HistoryError(
                f"event {record.sequence} is not a readable observation: {exc}"
            ) from exc
    return tuple(observations)


def artifact_records(repository: EventRepository) -> tuple[ArtifactRecord, ...]:
    """Read artifact provenance and ingest diagnostics back, in recorded order."""

    records: list[ArtifactRecord] = []
    for event in repository.read_all():
        if event.event_type != ARTIFACT_INGESTED:
            continue
        repository.validate_payload(
            event.event_type, event.payload, event_version=event.event_version
        )
        payload = event.payload
        records.append(
            ArtifactRecord(
                name=_text(payload, "name"),
                sha256=_text(payload, "sha256"),
                size_bytes=_count(payload, "sizeBytes"),
                media_type=_text(payload, "mediaType"),
                parser_name=_text(payload, "parserName"),
                parser_version=_text(payload, "parserVersion"),
                ingested_at=_timestamp(payload, "ingestedAt"),
                observation_count=_count(payload, "observationCount"),
                diagnostics=_diagnostics(payload.get("diagnostics")),
            )
        )
    return tuple(records)


def fold_case(repository: EventRepository, tracking_id: str) -> CaseState:
    """Fold one case stream into its current state."""

    stream_id = case_stream_id(tracking_id)
    records = repository.read_stream(stream_id)
    if not records:
        raise CaseNotFoundError(f"no case stream exists for {tracking_id!r}")
    return fold_case_records(repository, tracking_id, records)


def fold_all_cases(repository: EventRepository) -> tuple[CaseState, ...]:
    """Fold every case stream, sorted by tracking identifier."""

    streams: dict[str, list[EventRecord]] = {}
    for record in repository.read_all():
        if not is_case_stream(record.stream_id):
            continue
        streams.setdefault(record.stream_id, []).append(record)
    states = [
        fold_case_records(repository, tracking_id_from_stream(stream_id), records)
        for stream_id, records in streams.items()
    ]
    return tuple(sorted(states, key=lambda state: state.tracking_id))


def fold_case_records(
    repository: EventRepository,
    tracking_id: str,
    records: Sequence[EventRecord],
) -> CaseState:
    """Fold one already-read case stream, in stream order."""

    ordered = tuple(records)
    if not ordered:
        raise CaseNotFoundError(f"no case stream exists for {tracking_id!r}")
    created = ordered[0]
    if created.event_type != CASE_CREATED:
        raise HistoryError(
            f"case {tracking_id!r} begins with {created.event_type!r}, not {CASE_CREATED!r}"
        )
    for record in ordered:
        repository.validate_payload(
            record.event_type, record.payload, event_version=record.event_version
        )

    payload = created.payload
    provider_tracking_id: str | None = None
    identified_sequence: int | None = None
    links: list[ObservationLink] = []
    attestation: AttestationRecord | None = None
    evaluations: list[EvaluationRecord] = []
    reductions: list[PainReductionRecord] = []
    disposition: DispositionRecord | None = None

    for record in ordered[1:]:
        body = record.payload
        if record.event_type == CASE_OBSERVATION_LINKED:
            links.append(
                ObservationLink(
                    sequence=record.sequence,
                    observation_id=_text(body, "observationId"),
                    resource_id=_text(body, "resourceId"),
                    resource_type=_text(body, "resourceType"),
                    observed_at=_optional_timestamp(body, "observedAt"),
                    source_tool=_text(body, "sourceTool"),
                    source_artifact_sha256=_text(body, "sourceArtifactSha256"),
                    source_identifiers=_text_list(body, "sourceIdentifiers"),
                )
            )
        elif record.event_type == DETECTION_ATTESTED:
            attestation = AttestationRecord(
                sequence=record.sequence,
                detected_at=_timestamp(body, "detectedAt"),
                rationale=_text(body, "rationale"),
                attested_at=_timestamp(body, "attestedAt"),
            )
        elif record.event_type == CASE_EVALUATED:
            evaluations.append(_evaluation_record(record.sequence, body))
        elif record.event_type == CASE_PAIN_REDUCED:
            reductions.append(
                PainReductionRecord(
                    sequence=record.sequence,
                    reduced_at=_timestamp(body, "reducedAt"),
                    rating=_rating(body, "rating"),
                )
            )
        elif record.event_type == CASE_DISPOSITION_RECORDED:
            disposition = DispositionRecord(
                sequence=record.sequence,
                status=_status(body, "status"),
                closed_disposition=_optional_status(body, "closedDisposition"),
                acceptance_rationale=_optional_text(body, "acceptanceRationale"),
                recorded_at=_timestamp(body, "recordedAt"),
            )
        elif record.event_type == CASE_IDENTIFIED:
            provider_tracking_id = _text(body, "providerTrackingId")
            identified_sequence = record.sequence
        else:
            raise HistoryError(
                f"case {tracking_id!r} carries unexpected event {record.event_type!r} "
                f"at sequence {record.sequence}"
            )

    recorded_tracking_id = _text(payload, "trackingId")
    if recorded_tracking_id != tracking_id:
        raise HistoryError(
            f"case stream {tracking_id!r} records tracking id {recorded_tracking_id!r}"
        )

    return CaseState(
        tracking_id=tracking_id,
        provider_tracking_id=provider_tracking_id,
        source_type=_text(payload, "sourceType"),
        source_record_id=_text(payload, "sourceRecordId"),
        context_key=_text(payload, "contextKey"),
        title=_text(payload, "title"),
        description=_text(payload, "description"),
        created_at=_timestamp(payload, "createdAt"),
        created_sequence=created.sequence,
        links=tuple(links),
        attestation=attestation,
        evaluations=tuple(evaluations),
        pain_reductions=tuple(reductions),
        disposition=disposition,
        identified_sequence=identified_sequence,
        last_sequence=ordered[-1].sequence,
    )


def case_history(repository: EventRepository, tracking_id: str) -> tuple[HistoryEntry, ...]:
    """Return the history listing for one case, newest last."""

    stream_id = case_stream_id(tracking_id)
    records = repository.read_stream(stream_id)
    if not records:
        raise CaseNotFoundError(f"no case stream exists for {tracking_id!r}")
    return history_entries(records)


def history_entries(records: Sequence[EventRecord]) -> tuple[HistoryEntry, ...]:
    """Summarize a run of events as one line each."""

    return tuple(
        HistoryEntry(
            sequence=record.sequence,
            recorded_at=record.recorded_at,
            event_type=record.event_type,
            actor=_actor(record.metadata),
            summary=summarize(record.event_type, record.payload),
        )
        for record in records
    )


def summarize(event_type: str, payload: Mapping[str, Any]) -> str:
    """Return the one-line summary a history listing prints for one event."""

    try:
        if event_type == ARTIFACT_INGESTED:
            return (
                f"ingested {_text(payload, 'name')} with "
                f"{_count(payload, 'observationCount')} observation(s)"
            )
        if event_type == OBSERVATION_RECORDED:
            return f"recorded observation {_text(payload, 'observation_id')}"
        if event_type == CASE_CREATED:
            return (
                f"created case for {_text(payload, 'sourceRecordId')} "
                f"({_text(payload, 'sourceType')})"
            )
        if event_type == CASE_OBSERVATION_LINKED:
            return (
                f"linked observation {_text(payload, 'observationId')} on "
                f"{_text(payload, 'resourceType')} {_text(payload, 'resourceId')}"
            )
        if event_type == DETECTION_ATTESTED:
            return f"attested detection at {_text(payload, 'detectedAt')}"
        if event_type == CASE_EVALUATED:
            return (
                f"evaluated PAIN {_count(payload, 'pain')} completed "
                f"{_text(payload, 'completedAt')} by {_text(payload, 'evaluator')}"
            )
        if event_type == CASE_PAIN_REDUCED:
            return (
                f"reduced PAIN to {_count(payload, 'rating')} at "
                f"{_text(payload, 'reducedAt')}"
            )
        if event_type == CASE_DISPOSITION_RECORDED:
            return f"recorded disposition {_text(payload, 'status')}"
        if event_type == CASE_IDENTIFIED:
            return f"identified as {_text(payload, 'providerTrackingId')}"
    except HistoryError:
        return f"{event_type} (payload could not be summarized)"
    return event_type


def _evaluation_record(sequence: int, payload: Mapping[str, Any]) -> EvaluationRecord:
    projection = payload.get("projectedNextReduction")
    projected: ProjectedReduction | None = None
    if projection is not None:
        if not isinstance(projection, Mapping):
            raise HistoryError("projectedNextReduction must be an object or null")
        projected = ProjectedReduction(
            estimated_at=_timestamp(projection, "estimatedAt"),
            target_rating=_rating(projection, "targetRating"),
        )
    return EvaluationRecord(
        sequence=sequence,
        completed_at=_timestamp(payload, "completedAt"),
        is_internet_reachable=_flag(payload, "isInternetReachable"),
        is_likely_exploitable=_flag(payload, "isLikelyExploitable"),
        pain=_rating(payload, "pain"),
        potential_agency_impact=_text(payload, "potentialAgencyImpact"),
        rationale=_text(payload, "rationale"),
        evaluator=_text(payload, "evaluator"),
        is_false_positive=_flag(payload, "isFalsePositive"),
        supplementary_risk_information=_optional_text(payload, "supplementaryRiskInformation"),
        projected_next_reduction=projected,
    )


def _diagnostics(value: Any) -> tuple[IngestDiagnostic, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise HistoryError("diagnostics must be an array")
    items: list[IngestDiagnostic] = []
    for entry in value:
        if not isinstance(entry, Mapping):
            raise HistoryError("each diagnostic must be an object")
        location = entry.get("location")
        items.append(
            IngestDiagnostic(
                level=DiagnosticLevel(_text(entry, "level")),
                code=_text(entry, "code"),
                message=_text(entry, "message"),
                location=None if location is None else str(location),
            )
        )
    return tuple(items)


def _actor(metadata: Mapping[str, Any]) -> str:
    actor = metadata.get("actor")
    return actor if isinstance(actor, str) and actor.strip() else "unknown"


def _text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise HistoryError(f"{key} must be text")
    return value


def _optional_text(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise HistoryError(f"{key} must be text or null")
    return value


def _timestamp(payload: Mapping[str, Any], key: str) -> datetime:
    try:
        return parse_utc(_text(payload, key))
    except ValueError as exc:
        raise HistoryError(f"{key} is not an RFC 3339 timestamp: {exc}") from exc


def _optional_timestamp(payload: Mapping[str, Any], key: str) -> datetime | None:
    if payload.get(key) is None:
        return None
    return _timestamp(payload, key)


def _flag(payload: Mapping[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise HistoryError(f"{key} must be true or false")
    return value


def _count(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise HistoryError(f"{key} must be an integer")
    return value


def _rating(payload: Mapping[str, Any], key: str) -> PainRating:
    try:
        return PainRating(_count(payload, key))
    except ValueError as exc:
        raise HistoryError(f"{key} must be an integer from 1 to 5") from exc


def _status(payload: Mapping[str, Any], key: str) -> CaseStatus:
    try:
        return CaseStatus(_text(payload, key))
    except ValueError as exc:
        raise HistoryError(f"{key} is not a case status") from exc


def _optional_status(payload: Mapping[str, Any], key: str) -> CaseStatus | None:
    if payload.get(key) is None:
        return None
    return _status(payload, key)


def _text_list(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise HistoryError(f"{key} must be an array of strings")
    return tuple(value)


__all__ = [
    "ARTIFACT_INGESTED",
    "CASE_CREATED",
    "CASE_DISPOSITION_RECORDED",
    "CASE_EVALUATED",
    "CASE_IDENTIFIED",
    "CASE_OBSERVATION_LINKED",
    "CASE_PAIN_REDUCED",
    "DETECTION_ATTESTED",
    "OBSERVATION_RECORDED",
    "ArtifactRecord",
    "AttestationRecord",
    "CaseNotFoundError",
    "CaseState",
    "DispositionRecord",
    "EvaluationRecord",
    "HistoryEntry",
    "HistoryError",
    "ObservationLink",
    "PainReductionRecord",
    "artifact_records",
    "case_history",
    "fold_all_cases",
    "fold_case",
    "fold_case_records",
    "history_entries",
    "rehydrate_observations",
    "summarize",
]
