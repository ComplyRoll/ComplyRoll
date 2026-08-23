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
from typing import Any, Final, TypeGuard

from complyroll.adapters import DiagnosticLevel, IngestDiagnostic
from complyroll.events import (
    OBSERVATION_ID_KEY,
    EventContractError,
    EventRepository,
    artifact_identity_breach,
    case_stream_id,
    duplicate_observation_message,
    event_belongs_on_stream,
    is_artifact_stream,
    is_case_stream,
    metadata_breaches,
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

#: The codes `audit_history` reports. `store verify` prints them, so they are part of the
#: command's contract rather than wording that can drift.
AUDIT_FAULT_CODES: Final[tuple[str, ...]] = (
    "artifact_duplicate_observation",
    "artifact_incomplete",
    "artifact_overfull",
    "artifact_stream_mismatch",
    "case_tracking_id_mismatch",
    "event_metadata_invalid",
    "event_stream_mismatch",
    "payload_contract_invalid",
)


class HistoryError(ValueError):
    """Stored history cannot be folded into domain state."""


class CaseNotFoundError(HistoryError):
    """No case stream exists for the requested tracking identifier."""


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """One `artifact.ingested` event, read back as artifact provenance.

    `stream_id` and `sequence` locate the event the record came from, so a diagnostic about
    an artifact can cite the stream rather than describe it. Both carry a default because
    the fold is the only writer of this record and every reader of it only reads.
    """

    name: str
    sha256: str
    size_bytes: int
    media_type: str
    parser_name: str
    parser_version: str
    ingested_at: datetime
    observation_count: int
    diagnostics: tuple[IngestDiagnostic, ...]
    stream_id: str = ""
    sequence: int = 0


@dataclass(frozen=True, slots=True)
class ArtifactHistory:
    """Every artifact stream in the log, split by ADR 0008's parser-version rule.

    `current` is the stream the fold reads for each artifact digest, in recorded order.
    `superseded` is every older-parser stream for a digest that also has a newer one; those
    observations are not rehydrated, and the replay reports each as `artifact_superseded`
    so a report never silently drops or doubles an artifact's findings.
    """

    current: tuple[ArtifactRecord, ...]
    superseded: tuple[ArtifactRecord, ...]


@dataclass(frozen=True, slots=True)
class HistoryFault:
    """One domain problem found in stored history, reported rather than raised.

    `sequence` is the event the fault belongs to; for an incomplete artifact stream it is
    the `artifact.ingested` event that declared the count nothing finished writing.
    """

    sequence: int
    code: str
    message: str

    def render(self) -> str:
        """Return the single-line form a verification command prints."""

        return f"sequence {self.sequence}: {self.code}: {self.message}"


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

    The stored payload is untrusted, and every reader here validates it against
    `case.disposition_recorded` before building this record, so every rule belongs to the
    contract rather than to a second copy of them here.

    The rules this record carries no version of: `_DISPOSITION_CONSISTENCY` in
    `complyroll.events.contracts` pairs `status: closed` with a string `closedDisposition`
    and every other status with a null one, and a risk-accepting status with a string
    `acceptanceRationale` and every other status with a null one; and the
    `acceptanceRationale` property's own `_NON_BLANK_PATTERN` requires that string to hold
    a character that is not whitespace, so three spaces is not a rationale at append and
    is not a rationale at rest. That last rule used to live here alone, which let
    `store verify` certify a store `report vdt --db` then refused.
    """

    sequence: int
    status: CaseStatus
    closed_disposition: CaseStatus | None
    acceptance_rationale: str | None
    recorded_at: datetime

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
    """Read every current `observation.recorded` payload back into an `Observation`.

    Order is the order the events were recorded, which is the order the parsers produced
    them, so correlation sees exactly what the stateless path sees.

    Only the newest parser stream for each artifact digest is read (see `artifact_history`).
    Replay used to read every historical stream for the same bytes while the stateless path
    ran only the installed parser, so re-ingesting an artifact under a newer parser broke
    byte identity and reported every finding twice.
    """

    views = _read_artifact_streams(repository)
    current, _ = _split_by_parser_version(views)
    events = sorted(
        (event for view in current for event in view.observations),
        key=lambda event: event.sequence,
    )
    observations: list[Observation] = []
    for record in events:
        # `_read_artifact_streams` has already validated the payload against the contract,
        # and that validation reads every `observation.recorded` back through this same
        # reader, so this call is building the object rather than re-checking it. It stays
        # wrapped because the wrapper is what turns a reader's refusal into history's.
        try:
            observations.append(Observation.from_canonical_dict(record.payload))
        except (TypeError, ValueError) as exc:
            raise HistoryError(
                f"event {record.sequence} is not a readable observation: {exc}"
            ) from exc
    return tuple(observations)


def artifact_records(repository: EventRepository) -> tuple[ArtifactRecord, ...]:
    """Read current artifact provenance and ingest diagnostics back, in recorded order."""

    return artifact_history(repository).current


def superseded_artifact_records(repository: EventRepository) -> tuple[ArtifactRecord, ...]:
    """Read back the artifact streams a newer parser version has superseded."""

    return artifact_history(repository).superseded


def artifact_history(repository: EventRepository) -> ArtifactHistory:
    """Read every artifact stream back, split into the current ones and the superseded.

    One artifact digest can carry several streams, one per parser version (ADR 0002), and
    only the newest is current. Versions compare as tuples of integers when every
    dot-separated component of every candidate is numeric, so 10 follows 9 rather than
    preceding it; otherwise they compare as text. Numerically equal spellings are one
    version: `1`, `01`, and `1.0` all compare as `(1,)`. Two streams that tie on version
    leave the later-recorded one current, so the choice never depends on read order.

    The digest alone groups the streams. The stateless path runs exactly one parser over an
    artifact's bytes, so the persisted path has to end with exactly one stream per digest
    for the two to stay byte-identical (ADR 0008 Decision 5).

    A stream holding fewer observations than its `artifact.ingested` event declares is
    incomplete and raises: it is a half-written ingest from a version that wrote artifacts
    in batches, and reporting from its prefix would understate the artifact while the
    event still claimed the full count.

    Both tuples are ordered by the sequence of the `artifact.ingested` event, which is the
    recorded order the report lists artifacts in.
    """

    views = _read_artifact_streams(repository)
    current, superseded = _split_by_parser_version(views)
    return ArtifactHistory(
        current=_records_in_recorded_order(current),
        superseded=_records_in_recorded_order(superseded),
    )


def audit_history(repository: EventRepository) -> tuple[HistoryFault, ...]:
    """Report every domain fault in stored history, without raising on any of them.

    The store's own walk proves the bytes are intact: nothing rewritten, no sequence
    missing, every digest still matching. Intact is not the same as meaningful. This is the
    domain half, and it reports rather than raises because a command that has to describe a
    damaged log cannot use a reader that stops at the first problem:

    - `payload_contract_invalid`: a payload that fails its published contract, including an
      `observation.recorded` the replay reader would refuse and an unpublished event type.
    - `event_stream_mismatch`: an event stored on the wrong kind of stream, which every
      reader ignores while the log looks healthy.
    - `case_tracking_id_mismatch`: a `case.created` naming a tracking id its stream does not.
    - `artifact_stream_mismatch`: an artifact event or an observation naming an artifact its
      stream does not, which would rehydrate under bytes it never came from.
    - `artifact_incomplete`: a stream holding fewer observations than it declared.
    - `artifact_overfull`: a stream holding more, the mirror image of the same damage: one
      observation counted twice puts a finding in the report the artifacts do not carry.
    - `artifact_duplicate_observation`: one observation identifier stored twice on the same
      stream, which is the damage above with the count forged to match: a head declaring
      five that carries five copies of one observation adds up, names the artifact its
      stream names, and still rehydrates one finding five times.
    - `event_metadata_invalid`: a metadata envelope outside the rules `EventMetadata` keeps.

    Faults are ordered by sequence and then by code, so one damaged file always describes
    itself the same way. A store-level failure (an unreadable file, a hole in history) is
    still raised: this walk is for a log the store has already called intact.
    """

    faults: list[HistoryFault] = []
    declared: dict[str, tuple[int, int]] = {}
    observed: dict[str, int] = {}
    identifiers: dict[str, set[str]] = {}
    for record in repository.read_all():
        contract_faults = _contract_faults(repository, record)
        faults.extend(contract_faults)
        faults.extend(_placement_faults(record))
        faults.extend(_metadata_faults(record))
        if not contract_faults:
            # A payload its own contract already refused says nothing dependable about the
            # artifact it came from, so its identity is read only once the payload reads.
            faults.extend(_identity_faults(record))
        if record.event_type == ARTIFACT_INGESTED:
            count = record.payload.get("observationCount")
            if record.stream_id not in declared and _is_whole_number(count):
                declared[record.stream_id] = (record.sequence, int(count))
        elif record.event_type == OBSERVATION_RECORDED:
            observed[record.stream_id] = observed.get(record.stream_id, 0) + 1
            if not contract_faults:
                faults.extend(_duplicate_faults(record, identifiers))
    for stream_id, (sequence, count) in declared.items():
        found = observed.get(stream_id, 0)
        if found == count:
            continue
        code = "artifact_incomplete" if found < count else "artifact_overfull"
        message = (
            _incomplete_message(stream_id, count, found)
            if found < count
            else _overfull_message(stream_id, count, found)
        )
        faults.append(HistoryFault(sequence=sequence, code=code, message=message))
    return tuple(sorted(faults, key=lambda fault: (fault.sequence, fault.code)))


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


@dataclass(frozen=True, slots=True)
class _ArtifactStreamView:
    """One stream's artifact history: its provenance record and its observation events."""

    stream_id: str
    record: ArtifactRecord | None
    observations: tuple[EventRecord, ...]


def _read_artifact_streams(repository: EventRepository) -> tuple[_ArtifactStreamView, ...]:
    """Group every stream carrying artifact history, in the order the streams were opened.

    A stream with no `artifact.ingested` event still appears when it carries observations,
    because dropping it would lose history rather than describe it; such a stream declares
    no count and belongs to no digest, so neither completeness nor supersession applies.

    Every event read here has to name the artifact its stream names, and has to name it
    only once. An observation copied onto another artifact's stream is not this artifact's
    finding, and rehydrating it would report one finding under two artifacts; the same
    observation stored twice on its own stream would report one finding twice under one
    artifact, which the count check cannot see when the head was forged to declare it.
    Either one stops the read rather than being counted (ADR 0008, second amendment).

    The payload is validated before either check, because both read the payload: a payload
    missing `parser_version` names version None, and describing that as an event on the
    wrong stream points the operator at the stream when the payload is what is wrong.
    `audit_history` orders the same two checks the same way.
    """

    heads: dict[str, EventRecord] = {}
    observations: dict[str, list[EventRecord]] = {}
    identifiers: dict[str, set[str]] = {}
    order: list[str] = []
    for record in repository.read_all():
        if record.event_type not in (ARTIFACT_INGESTED, OBSERVATION_RECORDED):
            continue
        _require_readable_artifact_event(repository, record)
        breach = artifact_identity_breach(record.stream_id, record.event_type, record.payload)
        if breach is not None:
            raise HistoryError(f"event {record.sequence} is on the wrong stream: {breach}")
        if record.stream_id not in observations:
            observations[record.stream_id] = []
            order.append(record.stream_id)
        if record.event_type == OBSERVATION_RECORDED:
            _require_unrepeated_observation(record, identifiers)
            observations[record.stream_id].append(record)
        elif record.stream_id not in heads:
            heads[record.stream_id] = record

    views: list[_ArtifactStreamView] = []
    for stream_id in order:
        head = heads.get(stream_id)
        found = observations[stream_id]
        provenance = None if head is None else _artifact_record(repository, head)
        if provenance is not None and len(found) < provenance.observation_count:
            raise HistoryError(
                _incomplete_message(stream_id, provenance.observation_count, len(found))
            )
        if provenance is not None and len(found) > provenance.observation_count:
            raise HistoryError(
                _overfull_message(stream_id, provenance.observation_count, len(found))
            )
        views.append(
            _ArtifactStreamView(
                stream_id=stream_id, record=provenance, observations=tuple(found)
            )
        )
    return tuple(views)


#: What an unreadable artifact-stream event is called in the message the fold raises.
_ARTIFACT_EVENT_NAMES: Final[dict[str, str]] = {
    ARTIFACT_INGESTED: "artifact record",
    OBSERVATION_RECORDED: "observation",
}


def _require_readable_artifact_event(
    repository: EventRepository,
    record: EventRecord,
) -> None:
    """Refuse one artifact-stream event whose payload does not satisfy its own contract.

    Read before anything else in the walk, because everything else in the walk reads the
    payload. A contract-invalid observation used to be described by the fold as being on
    the wrong stream naming "version None", which is the identity check reporting a field
    the payload simply does not have.
    """

    try:
        repository.validate_payload(
            record.event_type, record.payload, event_version=record.event_version
        )
    except EventContractError as exc:
        described = _ARTIFACT_EVENT_NAMES.get(record.event_type, record.event_type)
        raise HistoryError(
            f"event {record.sequence} is not a readable {described}: {exc}"
        ) from exc


def _require_unrepeated_observation(
    record: EventRecord,
    identifiers: dict[str, set[str]],
) -> None:
    """Refuse one observation identifier the same artifact stream already carries."""

    observation_id = str(record.payload.get(OBSERVATION_ID_KEY))
    seen = identifiers.setdefault(record.stream_id, set())
    if observation_id in seen:
        raise HistoryError(duplicate_observation_message(record.stream_id, observation_id))
    seen.add(observation_id)


def _artifact_record(repository: EventRepository, event: EventRecord) -> ArtifactRecord:
    """Read one validated `artifact.ingested` event back as artifact provenance."""

    repository.validate_payload(
        event.event_type, event.payload, event_version=event.event_version
    )
    payload = event.payload
    return ArtifactRecord(
        name=_text(payload, "name"),
        sha256=_text(payload, "sha256"),
        size_bytes=_count(payload, "sizeBytes"),
        media_type=_text(payload, "mediaType"),
        parser_name=_text(payload, "parserName"),
        parser_version=_text(payload, "parserVersion"),
        ingested_at=_timestamp(payload, "ingestedAt"),
        observation_count=_count(payload, "observationCount"),
        diagnostics=_diagnostics(payload.get("diagnostics")),
        stream_id=event.stream_id,
        sequence=event.sequence,
    )


def _split_by_parser_version(
    views: Sequence[_ArtifactStreamView],
) -> tuple[tuple[_ArtifactStreamView, ...], tuple[_ArtifactStreamView, ...]]:
    """Keep the newest parser stream for each digest and hand back the rest as superseded.

    See `artifact_history` for the comparison rule. A stream carrying no artifact event
    belongs to no digest and is always current.
    """

    by_digest: dict[str, list[_ArtifactStreamView]] = {}
    for view in views:
        if view.record is not None:
            by_digest.setdefault(view.record.sha256, []).append(view)

    superseded: set[str] = set()
    for candidates in by_digest.values():
        if len(candidates) == 1:
            continue
        winner = _newest_stream(candidates)
        superseded.update(
            view.stream_id for view in candidates if view.stream_id != winner.stream_id
        )
    current = tuple(view for view in views if view.stream_id not in superseded)
    older = tuple(view for view in views if view.stream_id in superseded)
    return current, older


def _records_in_recorded_order(
    views: Sequence[_ArtifactStreamView],
) -> tuple[ArtifactRecord, ...]:
    """Return one group's artifact records ordered by the event that recorded them."""

    records = [view.record for view in views if view.record is not None]
    return tuple(sorted(records, key=lambda record: record.sequence))


def _newest_stream(candidates: Sequence[_ArtifactStreamView]) -> _ArtifactStreamView:
    """Return one digest's newest parser stream.

    Every candidate numeric means a numeric comparison, so parser version 10 follows 9. One
    candidate that is not makes the whole group compare as text, because there is no
    meaningful order between `2` and `2.0-rc1` beyond the one the strings give. The stream's
    own sequence breaks a tie, leaving the later-recorded stream current, and two spellings
    of one number tie rather than one of them winning on how it was written.
    """

    if all(_is_numeric_version(_version_of(view)) for view in candidates):
        return max(
            candidates,
            key=lambda view: (_numeric_version(_version_of(view)), _sequence_of(view)),
        )
    return max(candidates, key=lambda view: (_version_of(view), _sequence_of(view)))


def _version_of(view: _ArtifactStreamView) -> str:
    return "" if view.record is None else view.record.parser_version


def _sequence_of(view: _ArtifactStreamView) -> int:
    return 0 if view.record is None else view.record.sequence


def _is_numeric_version(version: str) -> bool:
    """Return True when every dot-separated component is ASCII digits `int` can read.

    `str.isdigit` is true of U+00B2 (superscript two) and U+2460 (circled digit one),
    which `int` refuses, so the numeric branch would have raised on a parser version
    spelled with either rather than falling back to the text comparison that handles
    every other version this cannot order numerically.
    """

    parts = version.split(".")
    return bool(parts) and all(part.isascii() and part.isdigit() for part in parts)


def _numeric_version(version: str) -> tuple[int, ...]:
    """Return the tuple one numeric parser version compares as.

    `int` loses a leading zero and trailing zero components are dropped, so `1`, `01`,
    and `1.0` are one version rather than three and the tie between them falls to the
    recorded sequence like any other tie. Without the trailing zeros going, `1.0` beat
    `1` on length alone, which let a numerically equal spelling override the
    later-recorded rule in silence. `1.0.1` still outranks `1`, and `10` still
    outranks `9`.
    """

    parts = [int(part) for part in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _is_whole_number(value: Any) -> TypeGuard[int]:
    """Return True for a JSON integer, which `True` is not however Python spells it.

    A `TypeGuard` rather than a plain bool, so a caller that has asked the question does
    not have to assert the answer again to read the value as the integer it now is.
    """

    return isinstance(value, int) and not isinstance(value, bool)


def _incomplete_message(stream_id: str, declared: int, found: int) -> str:
    """Word one incomplete artifact stream the same way everywhere it is reported."""

    return (
        f"artifact stream {stream_id!r} is incomplete: declared {declared} observations, "
        f"found {found}"
    )


def _overfull_message(stream_id: str, declared: int, found: int) -> str:
    """Word one overfull artifact stream the same way everywhere it is reported.

    The mirror of `_incomplete_message`. An incomplete stream understates its artifact;
    an overfull one puts a finding in the report the artifact never carried, because the
    extra observation was copied from somewhere else.
    """

    return (
        f"artifact stream {stream_id!r} is overfull: declared {declared} observations, "
        f"found {found}"
    )


def _identity_faults(record: EventRecord) -> tuple[HistoryFault, ...]:
    """Report one artifact-stream event naming an artifact its stream does not.

    The artifact-stream analogue of the `case.created` tracking-id check in
    `_placement_faults`: an artifact stream id is an artifact's identity, so both events
    it carries have to name that identity in their payload as well.
    """

    breach = artifact_identity_breach(record.stream_id, record.event_type, record.payload)
    if breach is None:
        return ()
    return (
        HistoryFault(
            sequence=record.sequence,
            code="artifact_stream_mismatch",
            message=breach,
        ),
    )


def _duplicate_faults(
    record: EventRecord,
    identifiers: dict[str, set[str]],
) -> tuple[HistoryFault, ...]:
    """Report one observation identifier stored twice on the same artifact stream.

    `identifiers` carries the identifiers already seen per stream and is updated here, so
    the walk reports the repeat rather than the first copy: the first copy is history, the
    second is the one that puts a finding in the report twice. An observation on a stream
    of another kind is the placement check's business, so it is not counted here.
    """

    if not is_artifact_stream(record.stream_id):
        return ()
    observation_id = str(record.payload.get(OBSERVATION_ID_KEY))
    seen = identifiers.setdefault(record.stream_id, set())
    if observation_id in seen:
        return (
            HistoryFault(
                sequence=record.sequence,
                code="artifact_duplicate_observation",
                message=duplicate_observation_message(record.stream_id, observation_id),
            ),
        )
    seen.add(observation_id)
    return ()


def _contract_faults(
    repository: EventRepository,
    record: EventRecord,
) -> tuple[HistoryFault, ...]:
    """Report one stored payload that does not satisfy its published contract."""

    try:
        repository.validate_payload(
            record.event_type, record.payload, event_version=record.event_version
        )
    except EventContractError as exc:
        return (
            HistoryFault(
                sequence=record.sequence,
                code="payload_contract_invalid",
                message=str(exc),
            ),
        )
    return ()


def _placement_faults(record: EventRecord) -> tuple[HistoryFault, ...]:
    """Report one event stored on a stream its kind does not belong on."""

    if not event_belongs_on_stream(record.event_type, record.stream_id):
        return (
            HistoryFault(
                sequence=record.sequence,
                code="event_stream_mismatch",
                message=(
                    f"event {record.event_type!r} does not belong on stream "
                    f"{record.stream_id!r}"
                ),
            ),
        )
    if record.event_type != CASE_CREATED:
        return ()
    try:
        expected = tracking_id_from_stream(record.stream_id)
    except ValueError as exc:
        return (
            HistoryFault(
                sequence=record.sequence,
                code="case_tracking_id_mismatch",
                message=f"stream {record.stream_id!r} names no tracking id: {exc}",
            ),
        )
    recorded = record.payload.get("trackingId")
    if recorded == expected:
        return ()
    return (
        HistoryFault(
            sequence=record.sequence,
            code="case_tracking_id_mismatch",
            message=(
                f"{CASE_CREATED} records tracking id {recorded!r} on stream "
                f"{record.stream_id!r}, which names {expected!r}"
            ),
        ),
    )


def _metadata_faults(record: EventRecord) -> tuple[HistoryFault, ...]:
    """Report one metadata envelope outside the rules `EventMetadata` enforces."""

    problems = metadata_breaches(record.metadata)
    if not problems:
        return ()
    return (
        HistoryFault(
            sequence=record.sequence,
            code="event_metadata_invalid",
            message="; ".join(problems),
        ),
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
    "AUDIT_FAULT_CODES",
    "CASE_CREATED",
    "CASE_DISPOSITION_RECORDED",
    "CASE_EVALUATED",
    "CASE_IDENTIFIED",
    "CASE_OBSERVATION_LINKED",
    "CASE_PAIN_REDUCED",
    "DETECTION_ATTESTED",
    "OBSERVATION_RECORDED",
    "ArtifactHistory",
    "ArtifactRecord",
    "AttestationRecord",
    "CaseNotFoundError",
    "CaseState",
    "DispositionRecord",
    "EvaluationRecord",
    "HistoryEntry",
    "HistoryError",
    "HistoryFault",
    "ObservationLink",
    "PainReductionRecord",
    "artifact_history",
    "artifact_records",
    "audit_history",
    "case_history",
    "fold_all_cases",
    "fold_case",
    "fold_case_records",
    "history_entries",
    "rehydrate_observations",
    "summarize",
    "superseded_artifact_records",
]
