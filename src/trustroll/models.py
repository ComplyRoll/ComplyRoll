"""Foundational TrustRoll domain types.

These types intentionally keep source observations separate from contextual VDR
evaluations. Scanner severity cannot assign PAIN.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import Any, Self


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


def _require_sha256(value: str, field_name: str) -> str:
    digest = value.lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{field_name} must be a 64-character hexadecimal SHA-256 digest")
    return digest


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
        _require_sha256(self.digest_sha256, "digest_sha256")


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
        if self.observed_at is not None:
            _require_aware(self.observed_at, "observed_at")
        _require_aware(self.ingested_at, "ingested_at")
        _require_text(self.source_artifact_name, "source_artifact_name")
        _require_sha256(self.source_artifact_digest, "source_artifact_digest")

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
        """

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
