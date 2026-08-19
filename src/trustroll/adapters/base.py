"""Adapter contracts and immutable ingestion result types."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from trustroll.models import Observation


class DiagnosticLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class IngestDiagnostic:
    level: DiagnosticLevel
    code: str
    message: str
    location: str | None = None

    def to_dict(self) -> dict[str, str]:
        value = {
            "level": self.level.value,
            "code": self.code,
            "message": self.message,
        }
        if self.location:
            value["location"] = self.location
        return value


@dataclass(frozen=True, slots=True)
class ArtifactProvenance:
    artifact_id: str
    name: str
    source_path: str
    digest_sha256: str
    size_bytes: int
    media_type: str
    parser_name: str
    parser_version: str
    ingested_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.artifact_id, "artifact_id"),
            (self.name, "name"),
            (self.source_path, "source_path"),
            (self.media_type, "media_type"),
            (self.parser_name, "parser_name"),
            (self.parser_version, "parser_version"),
        ):
            if not value or not value.strip():
                raise ValueError(f"{field_name} must not be blank")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must not be negative")
        digest = self.digest_sha256.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("digest_sha256 must be a SHA-256 digest")
        if self.ingested_at.tzinfo is None or self.ingested_at.utcoffset() is None:
            raise ValueError("ingested_at must include a timezone")

    @classmethod
    def from_bytes(
        cls,
        *,
        path: Path,
        content: bytes,
        media_type: str,
        parser_name: str,
        parser_version: str,
        ingested_at: datetime,
    ) -> "ArtifactProvenance":
        digest = hashlib.sha256(content).hexdigest()
        return cls(
            artifact_id=f"artifact-sha256-{digest}",
            name=path.name,
            source_path=str(path),
            digest_sha256=digest,
            size_bytes=len(content),
            media_type=media_type,
            parser_name=parser_name,
            parser_version=parser_version,
            ingested_at=ingested_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "name": self.name,
            "source_path": self.source_path,
            "digest_sha256": self.digest_sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "parser_name": self.parser_name,
            "parser_version": self.parser_version,
            "ingested_at": self.ingested_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ParsedDocument:
    kind: str
    value: Any


@dataclass(frozen=True, slots=True)
class AdapterOutput:
    observations: tuple[Observation, ...]
    diagnostics: tuple[IngestDiagnostic, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class IngestResult:
    artifact: ArtifactProvenance | None
    observations: tuple[Observation, ...]
    diagnostics: tuple[IngestDiagnostic, ...]

    @property
    def errors(self) -> tuple[IngestDiagnostic, ...]:
        return tuple(item for item in self.diagnostics if item.level is DiagnosticLevel.ERROR)

    @property
    def warnings(self) -> tuple[IngestDiagnostic, ...]:
        return tuple(item for item in self.diagnostics if item.level is DiagnosticLevel.WARNING)

    @property
    def successful(self) -> bool:
        return self.artifact is not None and bool(self.observations) and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "successful": self.successful,
            "artifact": self.artifact.to_dict() if self.artifact else None,
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
            "observations": [observation.to_canonical_dict() for observation in self.observations],
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


class SourceAdapter(Protocol):
    """A parser that turns one already-bounded document into observations."""

    name: str
    version: str
    media_type: str

    def parse(
        self,
        document: ParsedDocument,
        artifact: ArtifactProvenance,
        *,
        ingested_at: datetime,
    ) -> AdapterOutput: ...


class ControlMapping(Protocol):
    def controls_for(self, identifier: str) -> tuple[str, ...]: ...


class AdapterParseError(ValueError):
    """Raised when a supported document is not a usable source artifact."""
