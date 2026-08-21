"""Foundational ComplyRoll domain types.

These types intentionally keep source observations separate from contextual VDR
evaluations. Scanner severity cannot assign PAIN.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, IntEnum
from typing import Any, Self, TypeVar


class SourceSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class ObservationDisposition(str, Enum):
    OPEN = "open"
    PASS = "pass"
    NOT_APPLICABLE = "not_applicable"
    NOT_REVIEWED = "not_reviewed"
    ERROR = "error"
    UNKNOWN = "unknown"


class ObservationOrigin(str, Enum):
    """Where an observation came from, which decides its identity recipe.

    ARTIFACT observations are bound to received bytes. SYSTEM observations record a
    process failure the provider must treat as a vulnerability (VDR-CSO-FAV) and are
    bound to the producing job and its detection window instead.
    """

    ARTIFACT = "artifact"
    SYSTEM = "system"


class Sensitivity(str, Enum):
    RESTRICTED = "restricted"
    INTERNAL = "internal"
    PUBLIC = "public"


class PainRating(IntEnum):
    N1 = 1
    N2 = 2
    N3 = 3
    N4 = 4
    N5 = 5


class CaseStatus(str, Enum):
    NEW = "new"
    EVALUATING = "evaluating"
    ACTIVE = "active"
    PARTIALLY_MITIGATED = "partially_mitigated"
    FULLY_MITIGATED = "fully_mitigated"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


def _require_text(value: object, field_name: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be text, got {type(value).__name__}")
    if not value or not value.strip():
        raise ValueError(f"{field_name} must not be blank")


def _require_aware(value: object, field_name: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")


def _require_sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a hexadecimal string, got {type(value).__name__}")
    digest = value.lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{field_name} must be a 64-character hexadecimal SHA-256 digest")
    return digest


EnumT = TypeVar("EnumT", bound=Enum)


def _require_enum(value: object, enum_type: type[EnumT], field_name: str) -> EnumT:
    """Reject look-alike values so a wrong type never reaches serialization."""

    if not isinstance(value, enum_type):
        article = "an" if enum_type.__name__[0] in "AEIOU" else "a"
        raise TypeError(
            f"{field_name} must be {article} {enum_type.__name__}, "
            f"got {type(value).__name__}"
        )
    return value


def _require_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {type(value).__name__}")
    return value


def _require_sensitivity(value: object) -> Sensitivity:
    if isinstance(value, Sensitivity):
        return value
    allowed = ", ".join(member.value for member in Sensitivity)
    if not isinstance(value, str):
        raise TypeError(f"sensitivity must be a Sensitivity or one of: {allowed}")
    try:
        return Sensitivity(value)
    except ValueError as exc:
        raise ValueError(f"sensitivity must be one of: {allowed}") from exc


def _coerce_str_tuple(value: object, field_name: str) -> tuple[str, ...]:
    """Freeze any string sequence into a tuple so a caller cannot alias the model."""

    if isinstance(value, str | bytes | bytearray):
        raise TypeError(f"{field_name} must be a sequence of strings, not a single value")
    if not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable of strings")
    items = tuple(value)
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} entries must be strings, got {type(item).__name__}")
    return items


def _coerce_pair_tuple(value: object, field_name: str) -> tuple[tuple[str, str], ...]:
    """Freeze a mapping or pair sequence into an immutable tuple of string pairs."""

    if isinstance(value, Mapping):
        candidates: tuple[Any, ...] = tuple(value.items())
    elif isinstance(value, str | bytes | bytearray) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be a mapping or a sequence of pairs")
    else:
        candidates = tuple(value)
    pairs: list[tuple[str, str]] = []
    for item in candidates:
        if isinstance(item, str) or not isinstance(item, Iterable):
            raise TypeError(f"{field_name} entries must be (key, value) string pairs")
        parts = tuple(item)
        if len(parts) != 2 or not all(isinstance(part, str) for part in parts):
            raise TypeError(f"{field_name} entries must be (key, value) string pairs")
        pairs.append((parts[0], parts[1]))
    return tuple(pairs)


@dataclass(frozen=True, slots=True)
class ResourceRef:
    resource_id: str
    resource_type: str

    def __post_init__(self) -> None:
        _require_text(self.resource_id, "resource_id")
        _require_text(self.resource_type, "resource_type")


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    evidence_id: str
    digest_sha256: str
    evidence_type: str
    description: str
    collected_at: datetime
    location: str | None = None
    sensitivity: Sensitivity | str = Sensitivity.RESTRICTED

    def __post_init__(self) -> None:
        _require_text(self.evidence_id, "evidence_id")
        _require_text(self.evidence_type, "evidence_type")
        _require_text(self.description, "description")
        _require_aware(self.collected_at, "collected_at")
        object.__setattr__(
            self, "digest_sha256", _require_sha256(self.digest_sha256, "digest_sha256")
        )
        object.__setattr__(self, "sensitivity", _require_sensitivity(self.sensitivity))


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    source_type: str
    source_tool: str
    parser_name: str
    parser_version: str
    source_record_id: str
    resource: ResourceRef
    observed_at: datetime | None
    ingested_at: datetime
    disposition: ObservationDisposition
    source_severity: SourceSeverity = SourceSeverity.UNKNOWN
    title: str = ""
    description: str = ""
    source_artifact_digest: str = ""
    source_artifact_name: str = ""
    source_identifiers: tuple[str, ...] = field(default_factory=tuple)
    source_metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    context_key: str = ""
    origin: ObservationOrigin = ObservationOrigin.ARTIFACT

    def __post_init__(self) -> None:
        for value, name in (
            (self.observation_id, "observation_id"),
            (self.source_type, "source_type"),
            (self.source_tool, "source_tool"),
            (self.parser_name, "parser_name"),
            (self.parser_version, "parser_version"),
            (self.source_record_id, "source_record_id"),
        ):
            _require_text(value, name)
        _require_enum(self.origin, ObservationOrigin, "origin")
        if not isinstance(self.resource, ResourceRef):
            raise TypeError(f"resource must be a ResourceRef, got {type(self.resource).__name__}")
        for value, name in (
            (self.title, "title"),
            (self.description, "description"),
            (self.source_artifact_name, "source_artifact_name"),
            (self.source_artifact_digest, "source_artifact_digest"),
            (self.context_key, "context_key"),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be text, got {type(value).__name__}")
        _require_enum(self.disposition, ObservationDisposition, "disposition")
        _require_enum(self.source_severity, SourceSeverity, "source_severity")
        if self.observed_at is not None:
            _require_aware(self.observed_at, "observed_at")
        _require_aware(self.ingested_at, "ingested_at")

        object.__setattr__(
            self,
            "source_identifiers",
            _coerce_str_tuple(self.source_identifiers, "source_identifiers"),
        )
        object.__setattr__(
            self, "source_metadata", _coerce_pair_tuple(self.source_metadata, "source_metadata")
        )
        object.__setattr__(
            self, "evidence_ids", _coerce_str_tuple(self.evidence_ids, "evidence_ids")
        )

        if self.origin is ObservationOrigin.ARTIFACT:
            _require_text(self.source_artifact_name, "source_artifact_name")
            object.__setattr__(
                self,
                "source_artifact_digest",
                _require_sha256(self.source_artifact_digest, "source_artifact_digest"),
            )
        else:
            if self.source_artifact_name != "":
                raise ValueError("system observations must leave source_artifact_name empty")
            if self.source_artifact_digest != "":
                raise ValueError("system observations must leave source_artifact_digest empty")
            if self.observed_at is None:
                raise ValueError("system observations must declare observed_at")
            _require_text(self.context_key, "context_key")

        if len(set(self.source_identifiers)) != len(self.source_identifiers):
            raise ValueError("source_identifiers must not contain duplicates")
        metadata_keys = [key for key, _ in self.source_metadata]
        if len(set(metadata_keys)) != len(metadata_keys):
            raise ValueError("source_metadata keys must not contain duplicates")

    @property
    def fingerprint(self) -> str:
        """Return a stable fingerprint for idempotent source ingestion.

        The fingerprint intentionally excludes mutable display fields and severity.
        It is an observation identity aid, not a vulnerability-case correlation rule.
        Artifact-bound and system-generated observations use separate recipes; see
        ADR 0002 and its 2026-08-21 amendment.
        """

        if self.origin is ObservationOrigin.SYSTEM:
            return hashlib.sha256(self._system_identity_payload().encode("utf-8")).hexdigest()
        parts = (
            self.source_type,
            self.source_tool,
            self.parser_name,
            self.parser_version,
            self.source_record_id,
            self.resource.resource_type,
            self.resource.resource_id,
            self.context_key,
            self.source_artifact_digest,
        )
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()

    def _system_identity_payload(self) -> str:
        """Return the injective JSON identity payload for a system observation."""

        observed_at = self.observed_at
        if observed_at is None:  # pragma: no cover - guaranteed by __post_init__
            raise ValueError("system observations must declare observed_at")
        return json.dumps(
            [
                "system",
                self.source_type,
                self.source_tool,
                self.parser_name,
                self.parser_version,
                self.source_record_id,
                self.resource.resource_type,
                self.resource.resource_id,
                self.context_key,
                observed_at.astimezone(UTC).isoformat(),
            ],
            separators=(",", ":"),
            ensure_ascii=True,
        )

    @property
    def derived_observation_id(self) -> str:
        """Return the deterministic identifier used by source adapters."""

        return f"obs-{self.fingerprint}"

    def metadata_value(self, key: str, default: str = "") -> str:
        """Return one immutable source metadata value."""

        return dict(self.source_metadata).get(key, default)

    def to_canonical_dict(self) -> dict[str, Any]:
        """Serialize the observation without runtime- or renderer-specific types."""

        return {
            "observation_id": self.observation_id,
            "fingerprint": self.fingerprint,
            "source_type": self.source_type,
            "source_tool": self.source_tool,
            "parser_name": self.parser_name,
            "parser_version": self.parser_version,
            "source_record_id": self.source_record_id,
            "resource": {
                "resource_id": self.resource.resource_id,
                "resource_type": self.resource.resource_type,
            },
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "ingested_at": self.ingested_at.isoformat(),
            "disposition": self.disposition.value,
            "source_severity": self.source_severity.value,
            "title": self.title,
            "description": self.description,
            "source_artifact_digest": self.source_artifact_digest,
            "source_artifact_name": self.source_artifact_name,
            "source_identifiers": list(self.source_identifiers),
            "source_metadata": dict(self.source_metadata),
            "evidence_ids": list(self.evidence_ids),
            "context_key": self.context_key,
            "origin": self.origin.value,
        }

    def to_canonical_json(self) -> str:
        """Return deterministic JSON suitable for hashing, fixtures, and pipelines."""

        return json.dumps(
            self.to_canonical_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class Evaluation:
    evaluation_id: str
    completed_at: datetime
    is_internet_reachable: bool
    is_likely_exploitable: bool
    pain: PainRating
    potential_agency_impact: str
    rationale: str
    evaluator: str
    is_false_positive: bool = False
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for value, name in (
            (self.evaluation_id, "evaluation_id"),
            (self.potential_agency_impact, "potential_agency_impact"),
            (self.rationale, "rationale"),
            (self.evaluator, "evaluator"),
        ):
            _require_text(value, name)
        _require_aware(self.completed_at, "completed_at")
        _require_enum(self.pain, PainRating, "pain")
        for flag, name in (
            (self.is_internet_reachable, "is_internet_reachable"),
            (self.is_likely_exploitable, "is_likely_exploitable"),
            (self.is_false_positive, "is_false_positive"),
        ):
            _require_bool(flag, name)
        object.__setattr__(
            self, "evidence_ids", _coerce_str_tuple(self.evidence_ids, "evidence_ids")
        )


@dataclass(frozen=True, slots=True)
class VulnerabilityCase:
    case_id: str
    title: str
    description: str
    status: CaseStatus
    observation_ids: tuple[str, ...]
    created_at: datetime
    current_evaluation: Evaluation | None = None
    evaluation_history: tuple[Evaluation, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.case_id, "case_id")
        _require_text(self.title, "title")
        _require_text(self.description, "description")
        _require_aware(self.created_at, "created_at")
        _require_enum(self.status, CaseStatus, "status")
        object.__setattr__(
            self,
            "observation_ids",
            _coerce_str_tuple(self.observation_ids, "observation_ids"),
        )
        if not self.observation_ids:
            raise ValueError("a vulnerability case must contain at least one observation")
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ValueError("observation_ids must not contain duplicates")
        if self.current_evaluation is not None and not isinstance(
            self.current_evaluation, Evaluation
        ):
            raise TypeError("current_evaluation must be an Evaluation or None")
        history = tuple(self.evaluation_history)
        for item in history:
            if not isinstance(item, Evaluation):
                raise TypeError("evaluation_history entries must be Evaluation instances")
        object.__setattr__(self, "evaluation_history", history)

    def with_evaluation(self, evaluation: Evaluation, *, reopen: bool = False) -> Self:
        """Return a new case projection with the supplied current evaluation.

        A closed or accepted case is a decision of record, so re-evaluating one requires
        an explicit reopen. The displaced evaluation moves into `evaluation_history`.
        Persistence will append the corresponding evaluation event before replacing the
        current projection. The frozen model prevents accidental in-place history
        mutation in the domain layer.
        """

        if not isinstance(evaluation, Evaluation):
            raise TypeError(f"evaluation must be an Evaluation, got {type(evaluation).__name__}")
        if self.status in {CaseStatus.ACCEPTED, CaseStatus.CLOSED} and not reopen:
            raise ValueError(
                f"re-evaluating a {self.status.value} case requires reopen=True"
            )
        history = self.evaluation_history
        if self.current_evaluation is not None:
            history = (*history, self.current_evaluation)
        return type(self)(
            case_id=self.case_id,
            title=self.title,
            description=self.description,
            status=CaseStatus.FALSE_POSITIVE if evaluation.is_false_positive else CaseStatus.ACTIVE,
            observation_ids=self.observation_ids,
            created_at=self.created_at,
            current_evaluation=evaluation,
            evaluation_history=history,
        )
