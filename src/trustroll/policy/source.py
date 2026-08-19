"""Validation and loading for pinned FedRAMP rule-source manifests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Any


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _require_sha256(value: Any, field_name: str) -> str:
    digest = _require_text(value, field_name).lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{field_name} must be a SHA-256 digest")
    return digest


@dataclass(frozen=True, slots=True)
class RuleSourceManifest:
    manifest_version: str
    repository: str
    commit: str
    retrieved_at: datetime
    dataset_path: str
    dataset_version: str
    dataset_last_updated: str
    dataset_sha256: str
    schema_path: str
    schema_id: str
    schema_draft: str
    schema_sha256: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RuleSourceManifest":
        retrieved_text = _require_text(value.get("retrieved_at"), "retrieved_at")
        if retrieved_text.endswith("Z"):
            retrieved_text = f"{retrieved_text[:-1]}+00:00"
        try:
            retrieved_at = datetime.fromisoformat(retrieved_text)
        except ValueError as exc:
            raise ValueError("retrieved_at must be an ISO 8601 timestamp") from exc
        if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
            raise ValueError("retrieved_at must include a timezone")

        commit = _require_text(value.get("commit"), "commit").lower()
        if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
            raise ValueError("commit must be a full 40-character Git commit")

        return cls(
            manifest_version=_require_text(value.get("manifest_version"), "manifest_version"),
            repository=_require_text(value.get("repository"), "repository"),
            commit=commit,
            retrieved_at=retrieved_at,
            dataset_path=_require_text(value.get("dataset_path"), "dataset_path"),
            dataset_version=_require_text(value.get("dataset_version"), "dataset_version"),
            dataset_last_updated=_require_text(
                value.get("dataset_last_updated"), "dataset_last_updated"
            ),
            dataset_sha256=_require_sha256(value.get("dataset_sha256"), "dataset_sha256"),
            schema_path=_require_text(value.get("schema_path"), "schema_path"),
            schema_id=_require_text(value.get("schema_id"), "schema_id"),
            schema_draft=_require_text(value.get("schema_draft"), "schema_draft"),
            schema_sha256=_require_sha256(value.get("schema_sha256"), "schema_sha256"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "manifest_version": self.manifest_version,
            "repository": self.repository,
            "commit": self.commit,
            "retrieved_at": self.retrieved_at.isoformat(),
            "dataset_path": self.dataset_path,
            "dataset_version": self.dataset_version,
            "dataset_last_updated": self.dataset_last_updated,
            "dataset_sha256": self.dataset_sha256,
            "schema_path": self.schema_path,
            "schema_id": self.schema_id,
            "schema_draft": self.schema_draft,
            "schema_sha256": self.schema_sha256,
        }


def load_bundled_rule_source_manifest() -> RuleSourceManifest:
    resource = files("trustroll").joinpath("data/fedramp-rules-source.json")
    value = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("rule-source manifest must contain a JSON object")
    return RuleSourceManifest.from_dict(value)
