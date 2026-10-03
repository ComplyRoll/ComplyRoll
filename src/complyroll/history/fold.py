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
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final, TypeGuard, TypeVar

from complyroll.adapters import DiagnosticLevel, FailureClass, IngestDiagnostic
from complyroll.adapters.failures import EXECUTION_UNSUCCESSFUL
from complyroll.events import (
    FAILURE_STREAM_SCHEMA_VERSION,
    OBSERVATION_ID_KEY,
    EventContractError,
    EventRepository,
    artifact_identity_breach,
    case_stream_id,
    duplicate_observation_message,
    event_belongs_on_stream,
    failure_duplicate_observation_message,
    failure_head_order_message,
    failure_identity_breach,
    failure_record_disagreement,
    failure_stream_components,
    is_artifact_stream,
    is_case_stream,
    is_failure_stream,
    metadata_breaches,
    parse_utc,
    tracking_id_from_stream,
)
from complyroll.models import CaseStatus, Observation, PainRating
from complyroll.reports.evaluations import PainReductionEvent, ProjectedReduction
from complyroll.store import EventRecord

ARTIFACT_INGESTED = "artifact.ingested"
OBSERVATION_RECORDED = "observation.recorded"
FAILURE_RECORDED = "failure.recorded"
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
    "failure_duplicate_observation",
    "failure_incomplete",
    "failure_overfull",
    "failure_schema_unmarked",
    "failure_stream_mismatch",
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
class FailureRecord:
    """One `failure.recorded` event, read back as a recorded detection process failure.

    The head of a failure stream (ADR 0014): the reading that failed, named the way the
    stream names it, and the diagnostics the failure contributes to a report. `stream_id`
    and `sequence` locate the event, as they do on `ArtifactRecord`.
    """

    name: str
    sha256: str
    size_bytes: int
    media_type: str
    parser_name: str
    parser_version: str
    ingested_at: datetime
    failure_class: FailureClass
    failure_codes: tuple[str, ...]
    clock: str
    diagnostics: tuple[IngestDiagnostic, ...]
    stream_id: str = ""
    sequence: int = 0


@dataclass(frozen=True, slots=True)
class ArtifactHistory:
    """Every artifact and failure stream in the log, split by the supersession rules.

    `current` is the artifact stream the fold reads for each artifact digest, in recorded
    order. `superseded` is every artifact stream a newer reading of the same bytes replaced;
    those observations are not rehydrated, and the replay names each one so a report never
    silently drops or doubles an artifact's findings. `current_failures` and
    `superseded_failures` split the failure streams the same way (ADR 0014), and
    `replaced_by` maps each superseded artifact stream to the record that replaced it: the
    digest's current artifact stream, or the failure stream R2 superseded it with.
    """

    current: tuple[ArtifactRecord, ...]
    superseded: tuple[ArtifactRecord, ...]
    current_failures: tuple[FailureRecord, ...] = ()
    superseded_failures: tuple[FailureRecord, ...] = ()
    # Derived from the streams above, so it adds nothing to equality, and a mapping cannot
    # be hashed.
    replaced_by: Mapping[str, ArtifactRecord | FailureRecord] = field(
        default_factory=dict, compare=False
    )


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

    Only the current streams for each artifact digest are read (see `artifact_history`).
    Replay used to read every historical stream for the same bytes while the stateless path
    ran only the installed parser, so re-ingesting an artifact under a newer parser broke
    byte identity and reported every finding twice. A current failure stream contributes its
    one system observation, so `cases correlate` creates and links a system case exactly as
    it does any other (ADR 0014).
    """

    split = _split_streams(_read_artifact_streams(repository), _read_failure_streams(repository))
    events = sorted(
        (
            *(event for view in split.current for event in view.observations),
            *(view.observation for view in split.current_failures),
        ),
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
    event still claimed the full count. A failure stream that is not exactly one head and
    one observation raises for the same reason.

    Failure streams of the same digest join the split under rules R1 to R5 (ADR 0014; see
    `_split_streams`), so a newer parser that can no longer read the bytes replaces the
    older reading, and a reading of the bytes replaces a failure it resolved. Every version
    of a digest, artifact and failure streams alike, decides together whether that digest
    compares numerically, so one comparison orders all of its streams.

    Every tuple is ordered by the sequence of the stream's head event, which is the
    recorded order the report lists artifacts in.
    """

    split = _split_streams(_read_artifact_streams(repository), _read_failure_streams(repository))
    return ArtifactHistory(
        current=_records_in_recorded_order(split.current),
        superseded=_records_in_recorded_order(split.superseded),
        current_failures=_failures_in_recorded_order(split.current_failures),
        superseded_failures=_failures_in_recorded_order(split.superseded_failures),
        replaced_by=split.replaced_by,
    )


def reading_elsewhere(
    history: ArtifactHistory,
    sha256: str,
    *,
    parser_name: str,
    parser_version: str,
    failure_class: FailureClass | None = None,
) -> ArtifactRecord | None:
    """Return a reading of these bytes that keeps a failure under this parser out of history.

    A failed reading joins history only to replace the digest's current reading under R2:
    one under the same parser name at a lower version, which the newer version can no
    longer read. A current reading under another parser name, or under this one at the
    failed version or later, means the bytes read successfully elsewhere, so `ingest`
    refuses the failure rather than recording it (ADR 0014).

    Given the failure's class, any reading of the digest, current or superseded, that
    would supersede the failure under R3 or R4 is returned as well, so `ingest` never
    records a failure the fold would supersede at birth. The current readings are asked
    first, so every reading refused without the class is refused, and named, the same way
    with it. Versions compare as the fold compares them: every version of the digest, the
    failed one included, decides together whether the comparison is numeric.
    """

    numeric = _digest_compares_numerically(history, sha256, parser_version)
    failed = _version_key(parser_version, numeric)
    for record in history.current:
        if record.sha256 == sha256 and (
            record.parser_name != parser_name
            or _version_key(record.parser_version, numeric) >= failed
        ):
            return record
    if failure_class is None:
        return None
    failure = _PendingFailure(failure_class, parser_name, parser_version)
    return _failure_superseded_at_birth(history, sha256, failure, numeric=numeric)


def held_failure_lost(
    history: ArtifactHistory,
    sha256: str,
    *,
    parser_name: str,
    parser_version: str,
    failure_class: FailureClass,
    holder: str,
) -> bool:
    """Return whether a failure another failure stream holds would reach no persisted report.

    A system observation's identity is the digest and the instant, never the parser, so
    `record_failure` writes nothing for a failure whose observation `holder` already holds.
    The failure is lost when the holder is superseded and no reading of the digest, current
    or superseded, would supersede the failure at birth under R3 or R4: recorded, it would
    be current, but its observation is the holder's. `reading_elsewhere`'s R2 check is not
    asked, because a side record's own artifact stream would match it. `ingest` asks this
    once its writes are in and refuses the run when it holds (ADR 0014 Decision 13).
    """

    if all(record.stream_id != holder for record in history.superseded_failures):
        return False
    numeric = _digest_compares_numerically(history, sha256, parser_version)
    failure = _PendingFailure(failure_class, parser_name, parser_version)
    return _failure_superseded_at_birth(history, sha256, failure, numeric=numeric) is None


def _failure_superseded_at_birth(
    history: ArtifactHistory,
    sha256: str,
    failure: _PendingFailure,
    *,
    numeric: bool,
) -> ArtifactRecord | None:
    """Return the first reading of the digest that would supersede a failure at birth.

    R3 and R4 as the fold applies them (`_failure_is_superseded`), one reading at a time,
    the current readings before the superseded ones.
    """

    for record in (*history.current, *history.superseded):
        if record.sha256 == sha256 and _failure_is_superseded(failure, (record,), numeric=numeric):
            return record
    return None


@dataclass(frozen=True, slots=True)
class _PendingFailure:
    """A failure weighed without being recorded: what R3 and R4 read of it."""

    failure_class: FailureClass
    parser_name: str
    parser_version: str


def _digest_compares_numerically(history: ArtifactHistory, sha256: str, version: str) -> bool:
    """Return whether one digest's versions, and one not yet in history, compare numerically.

    Artifact and failure streams count alike, current or superseded, as `_split_streams`
    counts them.
    """

    versions = [
        record.parser_version
        for record in (*history.current, *history.superseded)
        if record.sha256 == sha256
    ]
    versions.extend(
        record.parser_version
        for record in (*history.current_failures, *history.superseded_failures)
        if record.sha256 == sha256
    )
    versions.append(version)
    return all(_is_numeric_version(item) for item in versions)


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

    Failure streams (ADR 0014) have five of their own:

    - `failure_stream_mismatch`: a failure head naming a reading its stream does not; an
      observation on a failure stream that is not its digest's system record, metadata
      included; a stream that does not open with its head; or a head and a system record
      that describe two different failures.
    - `failure_incomplete` and `failure_overfull`: a failure stream that is not exactly one
      `failure.recorded` and one observation.
    - `failure_duplicate_observation`: two failure streams of one digest holding the same
      system observation, which would rehydrate one failure twice.
    - `failure_schema_unmarked`: a failure stream in a store still at schema 1, which a
      build that predates failure streams would open and misread.

    Faults are ordered by sequence and then by code, so one damaged file always describes
    itself the same way. A store-level failure (an unreadable file, a hole in history) is
    still raised: this walk is for a log the store has already called intact.
    """

    faults: list[HistoryFault] = []
    declared: dict[str, tuple[int, int]] = {}
    observed: dict[str, int] = {}
    identifiers: dict[str, set[str]] = {}
    holders: dict[tuple[str, str], str] = {}
    # Per failure stream: the first event's sequence, its heads, and its observations.
    failure_shapes: dict[str, list[int]] = {}
    # Per failure stream: the first head or observation, and each one whose payload reads.
    failure_openers: dict[str, EventRecord] = {}
    failure_pairs: dict[str, dict[str, EventRecord]] = {}
    for record in repository.read_all():
        contract_faults = _contract_faults(repository, record)
        faults.extend(contract_faults)
        faults.extend(_placement_faults(record))
        faults.extend(_metadata_faults(record))
        identity_faults: tuple[HistoryFault, ...] = ()
        if not contract_faults:
            # A payload its own contract already refused says nothing dependable about the
            # artifact it came from, so its identity is read only once the payload reads.
            identity_faults = _identity_faults(record)
            faults.extend(identity_faults)
        if is_failure_stream(record.stream_id):
            shape = failure_shapes.setdefault(record.stream_id, [record.sequence, 0, 0])
            if record.event_type == FAILURE_RECORDED:
                shape[1] += 1
            elif record.event_type == OBSERVATION_RECORDED:
                shape[2] += 1
            if record.event_type in (FAILURE_RECORDED, OBSERVATION_RECORDED):
                failure_openers.setdefault(record.stream_id, record)
                if not contract_faults and not identity_faults:
                    pair = failure_pairs.setdefault(record.stream_id, {})
                    pair.setdefault(record.event_type, record)
        if record.event_type == ARTIFACT_INGESTED:
            count = record.payload.get("observationCount")
            if record.stream_id not in declared and _is_whole_number(count):
                declared[record.stream_id] = (record.sequence, int(count))
        elif record.event_type == OBSERVATION_RECORDED:
            observed[record.stream_id] = observed.get(record.stream_id, 0) + 1
            if not contract_faults:
                faults.extend(_duplicate_faults(record, identifiers, holders))
    for stream_id, (first, heads, observations) in failure_shapes.items():
        problem = _failure_stream_problem(stream_id, heads, observations)
        if problem is not None:
            faults.append(HistoryFault(sequence=first, code=problem[0], message=problem[1]))
        faults.extend(
            _failure_pair_faults(
                stream_id,
                heads,
                failure_openers.get(stream_id),
                None if problem is not None else failure_pairs.get(stream_id, {}),
            )
        )
    faults.extend(_schema_faults(repository, failure_shapes))
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

    Only artifact streams are read here. A failure stream also carries an
    `observation.recorded`, and reading it here would make it a headless artifact stream
    that is always current, outside every supersession rule; `_read_failure_streams` reads
    it instead (ADR 0014).
    """

    heads: dict[str, EventRecord] = {}
    observations: dict[str, list[EventRecord]] = {}
    identifiers: dict[str, set[str]] = {}
    order: list[str] = []
    for record in repository.read_all():
        if record.event_type not in (ARTIFACT_INGESTED, OBSERVATION_RECORDED):
            continue
        if not is_artifact_stream(record.stream_id):
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


@dataclass(frozen=True, slots=True)
class _FailureStreamView:
    """One failure stream: its head, read back, and its one system observation event."""

    stream_id: str
    record: FailureRecord
    observation: EventRecord


def _read_failure_streams(repository: EventRepository) -> tuple[_FailureStreamView, ...]:
    """Read every failure stream back, in the order the streams were opened (ADR 0014).

    A failure stream is one `failure.recorded` and the one system observation it mints,
    written whole in one transaction and head first, so anything else raises: a missing
    half is incomplete, a second head or observation is overfull, an observation ahead of
    its head is out of order, and a head and a record that describe two failures disagree.
    The reader refuses each rather than reporting from a stream no writer produced. Each
    event is checked the way `_read_artifact_streams` checks its own, contract first and
    then identity, which for the record includes its metadata.

    One system observation is stored once per digest. Its identity is the digest and the
    instant, never the parser, so two failure streams of one digest holding it would
    rehydrate one failure twice, and the second one read raises.
    """

    heads: dict[str, list[EventRecord]] = {}
    observations: dict[str, list[EventRecord]] = {}
    holders: dict[tuple[str, str], str] = {}
    opened_by: dict[str, str] = {}
    for record in repository.read_all():
        if record.event_type not in (FAILURE_RECORDED, OBSERVATION_RECORDED):
            continue
        if not is_failure_stream(record.stream_id):
            continue
        _require_readable_artifact_event(repository, record)
        breach = failure_identity_breach(record.stream_id, record.event_type, record.payload)
        if breach is not None:
            raise HistoryError(f"event {record.sequence} is on the wrong stream: {breach}")
        opened_by.setdefault(record.stream_id, record.event_type)
        heads.setdefault(record.stream_id, [])
        found = observations.setdefault(record.stream_id, [])
        if record.event_type == FAILURE_RECORDED:
            heads[record.stream_id].append(record)
            continue
        digest = failure_stream_components(record.stream_id)[0]
        observation_id = str(record.payload.get(OBSERVATION_ID_KEY))
        holder = holders.setdefault((digest, observation_id), record.stream_id)
        if holder != record.stream_id:
            raise HistoryError(
                failure_duplicate_observation_message(record.stream_id, observation_id, holder)
            )
        found.append(record)

    views: list[_FailureStreamView] = []
    for stream_id, found in observations.items():
        problem = _failure_stream_problem(stream_id, len(heads[stream_id]), len(found))
        if problem is not None:
            raise HistoryError(problem[1])
        if opened_by[stream_id] != FAILURE_RECORDED:
            raise HistoryError(failure_head_order_message(stream_id))
        head = heads[stream_id][0]
        disagreement = failure_record_disagreement(stream_id, head.payload, found[0].payload)
        if disagreement is not None:
            raise HistoryError(disagreement)
        views.append(
            _FailureStreamView(
                stream_id=stream_id,
                record=_failure_record(repository, head),
                observation=found[0],
            )
        )
    return tuple(views)


#: What an unreadable artifact- or failure-stream event is called in the message the fold
#: raises.
_ARTIFACT_EVENT_NAMES: Final[dict[str, str]] = {
    ARTIFACT_INGESTED: "artifact record",
    FAILURE_RECORDED: "failure record",
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


def _failure_record(repository: EventRepository, event: EventRecord) -> FailureRecord:
    """Read one validated `failure.recorded` event back as a recorded failure."""

    repository.validate_payload(event.event_type, event.payload, event_version=event.event_version)
    payload = event.payload
    return FailureRecord(
        name=_text(payload, "name"),
        sha256=_text(payload, "sha256"),
        size_bytes=_count(payload, "sizeBytes"),
        media_type=_text(payload, "mediaType"),
        parser_name=_text(payload, "parserName"),
        parser_version=_text(payload, "parserVersion"),
        ingested_at=_timestamp(payload, "ingestedAt"),
        failure_class=FailureClass(_text(payload, "failureClass")),
        failure_codes=_text_list(payload, "failureCodes"),
        clock=_text(payload, "clock"),
        diagnostics=_diagnostics(payload.get("diagnostics")),
        stream_id=event.stream_id,
        sequence=event.sequence,
    )


@dataclass(frozen=True, slots=True)
class _StreamSplit:
    """Every artifact and failure stream, split into what replay reads and what it names."""

    current: tuple[_ArtifactStreamView, ...]
    superseded: tuple[_ArtifactStreamView, ...]
    current_failures: tuple[_FailureStreamView, ...]
    superseded_failures: tuple[_FailureStreamView, ...]
    replaced_by: dict[str, ArtifactRecord | FailureRecord]


def _split_streams(
    artifacts: Sequence[_ArtifactStreamView],
    failures: Sequence[_FailureStreamView],
) -> _StreamSplit:
    """Split one log's artifact and failure streams by digest under R1 to R5 (ADR 0014).

    The one split both `artifact_history` and `rehydrate_observations` read, so a report
    and `cases correlate` can never disagree about which streams are current. Per digest:

    - R1: the artifact winner W is the newest artifact stream, by `_newest_stream`.
    - R2: W is superseded by a failure stream under W's parser name at a strictly newer
      version, but only when every artifact stream of the digest is under that parser name:
      a newer parser that can no longer read bytes an older one read.
    - R3 and R4 decide each failure stream against every artifact stream of the digest,
      current or superseded (`_failure_is_superseded`).
    - R5: failure streams never supersede one another.

    Every version of the digest, artifact and failure streams alike, decides whether the
    digest compares numerically, so each comparison above is made one way. Deciding it per
    rule could let R2 retire W in favour of a failure that R3, comparing the other way,
    retires too, leaving the digest with nothing current to report. A stream carrying no
    artifact event belongs to no digest and is always current.
    """

    readings: dict[str, list[_ArtifactStreamView]] = {}
    heads: dict[str, ArtifactRecord] = {}
    for view in artifacts:
        if view.record is not None:
            readings.setdefault(view.record.sha256, []).append(view)
            heads[view.stream_id] = view.record
    failed: dict[str, list[_FailureStreamView]] = {}
    for failure in failures:
        failed.setdefault(failure.record.sha256, []).append(failure)

    replaced_by: dict[str, ArtifactRecord | FailureRecord] = {}
    superseded: set[str] = set()
    for digest in sorted(readings.keys() | failed.keys()):
        digest_readings = readings.get(digest, [])
        digest_failures = failed.get(digest, [])
        records = [heads[view.stream_id] for view in digest_readings]
        versions = [record.parser_version for record in records]
        versions.extend(failure.record.parser_version for failure in digest_failures)
        numeric = all(_is_numeric_version(version) for version in versions)
        if digest_readings:
            replaced_by.update(
                _replaced_readings(digest_readings, digest_failures, heads, numeric=numeric)
            )
        superseded.update(
            failure.stream_id
            for failure in digest_failures
            if _failure_is_superseded(failure.record, records, numeric=numeric)
        )
    superseded.update(replaced_by)
    return _StreamSplit(
        current=tuple(view for view in artifacts if view.stream_id not in superseded),
        superseded=tuple(view for view in artifacts if view.stream_id in superseded),
        current_failures=tuple(view for view in failures if view.stream_id not in superseded),
        superseded_failures=tuple(view for view in failures if view.stream_id in superseded),
        replaced_by=replaced_by,
    )


def _replaced_readings(
    readings: Sequence[_ArtifactStreamView],
    failures: Sequence[_FailureStreamView],
    heads: Mapping[str, ArtifactRecord],
    *,
    numeric: bool,
) -> dict[str, ArtifactRecord | FailureRecord]:
    """Map each superseded artifact stream of one digest to the record replacing it (R1, R2).

    Under R1 the replacement is W. Under R2 it is the newest failure stream under W's parser
    at a version newer than W's, which is always current: R3 and R4 retire a failure only
    for an artifact stream under another parser name or at a version of at least its own,
    and R2 applies only when there is neither. When R2 applies, W is replaced as well.
    """

    winner = heads[_newest_stream(readings, numeric=numeric).stream_id]
    newest = _version_key(winner.parser_version, numeric)
    newer = [
        failure
        for failure in failures
        if failure.record.parser_name == winner.parser_name
        and _version_key(failure.record.parser_version, numeric) > newest
    ]
    if newer and all(heads[view.stream_id].parser_name == winner.parser_name for view in readings):
        replacement = _newest_stream(newer, numeric=numeric).record
        return {view.stream_id: replacement for view in readings}
    return {view.stream_id: winner for view in readings if view.stream_id != winner.stream_id}


def _failure_is_superseded(
    failure: FailureRecord | _PendingFailure,
    readings: Sequence[ArtifactRecord],
    *,
    numeric: bool,
) -> bool:
    """Return whether an artifact stream of the digest supersedes one failure stream.

    `readings` is every artifact stream of the digest, current or superseded, so a failure
    a newer parser resolved stays resolved when a still newer parser fails in turn. No
    other failure stream is consulted (R5), and no sequence breaks a tie: at equal versions
    the artifact stream wins. `reading_elsewhere` and `held_failure_lost` ask the same of a
    failure that is not recorded, one reading at a time.

    - R3: a parse or content failure under parser P at version v is superseded by an
      artifact stream under another parser name, or under P at a version of at least v.
    - R4: an execution failure is superseded only by an artifact stream under P at a version
      of at least v whose head carries no `execution_unsuccessful`. A parser upgrade that
      reads the same failed invocation keeps the failure current, so its case keeps its
      detection time, and a side record never supersedes itself.
    """

    version = _version_key(failure.parser_version, numeric)
    if failure.failure_class is FailureClass.EXECUTION:
        return any(
            reading.parser_name == failure.parser_name
            and _version_key(reading.parser_version, numeric) >= version
            and all(item.code != EXECUTION_UNSUCCESSFUL for item in reading.diagnostics)
            for reading in readings
        )
    return any(
        reading.parser_name != failure.parser_name
        or _version_key(reading.parser_version, numeric) >= version
        for reading in readings
    )


def _records_in_recorded_order(
    views: Sequence[_ArtifactStreamView],
) -> tuple[ArtifactRecord, ...]:
    """Return one group's artifact records ordered by the event that recorded them."""

    records = [view.record for view in views if view.record is not None]
    return tuple(sorted(records, key=lambda record: record.sequence))


def _failures_in_recorded_order(
    views: Sequence[_FailureStreamView],
) -> tuple[FailureRecord, ...]:
    """Return one group's failure records ordered by the event that recorded them."""

    return tuple(sorted((view.record for view in views), key=lambda record: record.sequence))


_Stream = TypeVar("_Stream", _ArtifactStreamView, _FailureStreamView)


def _newest_stream(candidates: Sequence[_Stream], *, numeric: bool | None = None) -> _Stream:
    """Return one digest's newest parser stream.

    Every candidate numeric means a numeric comparison, so parser version 10 follows 9. One
    candidate that is not makes the whole group compare as text, because there is no
    meaningful order between `2` and `2.0-rc1` beyond the one the strings give. The stream's
    own sequence breaks a tie, leaving the later-recorded stream current, and two spellings
    of one number tie rather than one of them winning on how it was written. `numeric`
    overrides the candidates' own answer with the one their whole digest gives.
    """

    if numeric is None:
        numeric = all(_is_numeric_version(_version_of(view)) for view in candidates)
    mode = numeric
    return max(
        candidates,
        key=lambda view: (_version_key(_version_of(view), mode), _sequence_of(view)),
    )


def _version_key(version: str, numeric: bool) -> tuple[tuple[int, ...], str]:
    """Return what one parser version compares as, numerically or as text.

    One shape for both modes, so a comparison never mixes a number with a string: within a
    digest every version takes the same mode, and the unused half is the same everywhere.
    """

    if numeric:
        return (_numeric_version(version), "")
    return ((), version)


def _version_of(view: _ArtifactStreamView | _FailureStreamView) -> str:
    return "" if view.record is None else view.record.parser_version


def _sequence_of(view: _ArtifactStreamView | _FailureStreamView) -> int:
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


def _failure_stream_problem(
    stream_id: str,
    heads: int,
    observations: int,
) -> tuple[str, str] | None:
    """Return the fault code and message for a failure stream that is not whole, else None.

    A failure stream is one `failure.recorded` and the one system observation it mints,
    written in one transaction (ADR 0014), so it declares no count: the shape is the
    declaration. A second head or a second observation is overfull, and a missing one is
    incomplete. The reader raises with this message, the audit reports it under this code,
    and the writer refuses to resume such a stream, so all three describe it one way.
    """

    found = f"found {heads} failure record(s) and {observations} observation(s)"
    if heads > 1 or observations > 1:
        return (
            "failure_overfull",
            f"failure stream {stream_id!r} is overfull: a failure stream holds one failure "
            f"record and one observation, {found}",
        )
    if heads < 1 or observations < 1:
        return (
            "failure_incomplete",
            f"failure stream {stream_id!r} is incomplete: a failure stream holds one failure "
            f"record and one observation, {found}",
        )
    return None


def _failure_pair_faults(
    stream_id: str,
    heads: int,
    opener: EventRecord | None,
    pair: Mapping[str, EventRecord] | None,
) -> tuple[HistoryFault, ...]:
    """Report a failure stream out of order, or whose two events describe two failures.

    The audit's half of the two checks `_read_failure_streams` makes on a whole stream
    (ADR 0014). A stream with no head is already incomplete, so only one that holds a head
    is out of order when its observation opens it, and the fault is at that observation.
    `pair` is None for a stream that is not whole; otherwise it holds each event whose
    payload and identity read, and the two are compared only when both did, because an
    event that did not is already a fault of its own. The fault is at the record, which is
    what `detectionFailures` renders.
    """

    faults: list[HistoryFault] = []
    if heads and opener is not None and opener.event_type != FAILURE_RECORDED:
        faults.append(
            HistoryFault(
                sequence=opener.sequence,
                code="failure_stream_mismatch",
                message=failure_head_order_message(stream_id),
            )
        )
    if pair is not None and FAILURE_RECORDED in pair and OBSERVATION_RECORDED in pair:
        observation = pair[OBSERVATION_RECORDED]
        disagreement = failure_record_disagreement(
            stream_id, pair[FAILURE_RECORDED].payload, observation.payload
        )
        if disagreement is not None:
            faults.append(
                HistoryFault(
                    sequence=observation.sequence,
                    code="failure_stream_mismatch",
                    message=disagreement,
                )
            )
    return tuple(faults)


def _identity_faults(record: EventRecord) -> tuple[HistoryFault, ...]:
    """Report one artifact- or failure-stream event naming a reading its stream does not.

    The artifact-stream analogue of the `case.created` tracking-id check in
    `_placement_faults`: an artifact stream id is an artifact's identity, so both events
    it carries have to name that identity in their payload as well. A failure stream id is
    a failed reading's identity, and its observation has to be that digest's system record
    (ADR 0014).
    """

    breach = artifact_identity_breach(record.stream_id, record.event_type, record.payload)
    code = "artifact_stream_mismatch"
    if breach is None:
        breach = failure_identity_breach(record.stream_id, record.event_type, record.payload)
        code = "failure_stream_mismatch"
    if breach is None:
        return ()
    return (
        HistoryFault(
            sequence=record.sequence,
            code=code,
            message=breach,
        ),
    )


def _schema_faults(
    repository: EventRepository,
    failure_streams: Mapping[str, Sequence[int]],
) -> tuple[HistoryFault, ...]:
    """Report failure streams in a store that never marked itself schema 2 (ADR 0014).

    The first failure append marks the store in the same transaction, so a schema 1 store
    holding a failure stream was written past the repository, and a build that predates
    failure streams would open it and misread them instead of refusing it. One fault, at
    the first failure stream's first event, names the store's condition once rather than
    once per stream. `failure_streams` maps each failure stream to its first sequence first.
    """

    if not failure_streams:
        return ()
    version = repository.store.schema_version
    if version >= FAILURE_STREAM_SCHEMA_VERSION:
        return ()
    stream_id, shape = min(failure_streams.items(), key=lambda item: item[1][0])
    return (
        HistoryFault(
            sequence=shape[0],
            code="failure_schema_unmarked",
            message=(
                f"failure stream {stream_id!r} is in a store at schema {version}; a store "
                f"holding failure streams is marked schema {FAILURE_STREAM_SCHEMA_VERSION}, "
                "so a build that cannot read them refuses it rather than misreading it"
            ),
        ),
    )


def _duplicate_faults(
    record: EventRecord,
    identifiers: dict[str, set[str]],
    holders: dict[tuple[str, str], str],
) -> tuple[HistoryFault, ...]:
    """Report one observation identifier stored twice where one copy is all there may be.

    `identifiers` carries the identifiers already seen per artifact stream and is updated
    here, so the walk reports the repeat rather than the first copy: the first copy is
    history, the second is the one that puts a finding in the report twice. `holders` does
    the same for failure streams per digest, because a system observation's identity is the
    digest and the instant, never the parser, and two failure streams of one digest holding
    it would rehydrate one failure twice (ADR 0014). A repeat on one failure stream is that
    stream's overfull shape instead. An observation on a stream of another kind is the
    placement check's business, so it is not counted here.
    """

    if is_failure_stream(record.stream_id):
        return _failure_duplicate_faults(record, holders)
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


def _failure_duplicate_faults(
    record: EventRecord,
    holders: dict[tuple[str, str], str],
) -> tuple[HistoryFault, ...]:
    """Report one system observation another failure stream of its digest already holds."""

    try:
        digest = failure_stream_components(record.stream_id)[0]
    except ValueError:
        # A failure stream id that names no reading is the identity check's to report.
        return ()
    observation_id = str(record.payload.get(OBSERVATION_ID_KEY))
    holder = holders.setdefault((digest, observation_id), record.stream_id)
    if holder == record.stream_id:
        return ()
    return (
        HistoryFault(
            sequence=record.sequence,
            code="failure_duplicate_observation",
            message=failure_duplicate_observation_message(record.stream_id, observation_id, holder),
        ),
    )


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
    "FAILURE_RECORDED",
    "OBSERVATION_RECORDED",
    "ArtifactHistory",
    "ArtifactRecord",
    "AttestationRecord",
    "CaseNotFoundError",
    "CaseState",
    "DispositionRecord",
    "EvaluationRecord",
    "FailureRecord",
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
    "held_failure_lost",
    "history_entries",
    "reading_elsewhere",
    "rehydrate_observations",
    "summarize",
    "superseded_artifact_records",
]
