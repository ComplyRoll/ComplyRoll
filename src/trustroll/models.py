"""Foundational TrustRoll domain types.

These types intentionally keep source observations separate from contextual VDR
evaluations. Scanner severity cannot assign PAIN.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import Self


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


def _require_text(value: str, field_name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{field_name} must not be blank")


def _require_aware(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")


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
    sensitivity: str = "restricted"

    def __post_init__(self) -> None:
        _require_text(self.evidence_id, "evidence_id")
        _require_text(self.evidence_type, "evidence_type")
        _require_text(self.description, "description")
        _require_aware(self.collected_at, "collected_at")
        digest = self.digest_sha256.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("digest_sha256 must be a 64-character hexadecimal SHA-256 digest")


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    source_type: str
    source_tool: str
    source_record_id: str
    resource: ResourceRef
    observed_at: datetime
    ingested_at: datetime
    disposition: ObservationDisposition
    source_severity: SourceSeverity = SourceSeverity.UNKNOWN
    title: str = ""
    description: str = ""
    source_artifact_digest: str | None = None
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)
    context_key: str = ""

    def __post_init__(self) -> None:
        for value, name in (
            (self.observation_id, "observation_id"),
            (self.source_type, "source_type"),
            (self.source_tool, "source_tool"),
            (self.source_record_id, "source_record_id"),
        ):
            _require_text(value, name)
        _require_aware(self.observed_at, "observed_at")
        _require_aware(self.ingested_at, "ingested_at")

    @property
    def fingerprint(self) -> str:
        """Return a stable fingerprint for idempotent source ingestion.

        The fingerprint intentionally excludes mutable display fields and severity.
        It is an observation identity aid, not a vulnerability-case correlation rule.
        """

        parts = (
            self.source_type,
            self.source_tool,
            self.source_record_id,
            self.resource.resource_type,
            self.resource.resource_id,
            self.context_key,
        )
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


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


@dataclass(frozen=True, slots=True)
class VulnerabilityCase:
    case_id: str
    title: str
    description: str
    status: CaseStatus
    observation_ids: tuple[str, ...]
    created_at: datetime
    current_evaluation: Evaluation | None = None

    def __post_init__(self) -> None:
        _require_text(self.case_id, "case_id")
        _require_text(self.title, "title")
        _require_text(self.description, "description")
        _require_aware(self.created_at, "created_at")
        if not self.observation_ids:
            raise ValueError("a vulnerability case must contain at least one observation")
        if len(set(self.observation_ids)) != len(self.observation_ids):
            raise ValueError("observation_ids must not contain duplicates")

    def with_evaluation(self, evaluation: Evaluation) -> Self:
        """Return a new case projection with the supplied current evaluation.

        Persistence will append the corresponding evaluation event before replacing
        the current projection. The frozen model prevents accidental in-place history
        mutation in the domain layer.
        """

        return type(self)(
            case_id=self.case_id,
            title=self.title,
            description=self.description,
            status=CaseStatus.FALSE_POSITIVE if evaluation.is_false_positive else CaseStatus.ACTIVE,
            observation_ids=self.observation_ids,
            created_at=self.created_at,
            current_evaluation=evaluation,
        )
