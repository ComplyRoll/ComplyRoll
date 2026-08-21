"""Validation and loading for pinned FedRAMP rule-source manifests and snapshots."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

MAX_RULE_SOURCE_BYTES = 8 * 1024 * 1024
MAX_RULE_SOURCE_DEPTH = 128
MAX_RULE_SOURCE_VALUES = 500_000


class PolicySourceError(ValueError):
    """Base error for an invalid or unverifiable policy source."""


class PolicySourceIntegrityError(PolicySourceError):
    """A policy snapshot did not match its pinned manifest."""


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _require_sha256(value: Any, field_name: str) -> str:
    digest = _require_text(value, field_name).lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{field_name} must be a SHA-256 digest")
    return digest


def _require_relative_path(value: Any, field_name: str) -> str:
    text = _require_text(value, field_name)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or path == PurePosixPath("."):
        raise ValueError(f"{field_name} must be a repository-relative path")
    return text


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
    def from_dict(cls, value: dict[str, Any]) -> RuleSourceManifest:
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
            dataset_path=_require_relative_path(value.get("dataset_path"), "dataset_path"),
            dataset_version=_require_text(value.get("dataset_version"), "dataset_version"),
            dataset_last_updated=_require_text(
                value.get("dataset_last_updated"), "dataset_last_updated"
            ),
            dataset_sha256=_require_sha256(value.get("dataset_sha256"), "dataset_sha256"),
            schema_path=_require_relative_path(value.get("schema_path"), "schema_path"),
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


@dataclass(frozen=True, slots=True)
class RuleSourceSnapshot:
    """A digest-verified official rules dataset and its provenance."""

    manifest: RuleSourceManifest
    content_sha256: str
    _content: bytes

    @property
    def data(self) -> dict[str, Any]:
        """Return a defensive copy so callers cannot mutate verified policy content."""

        value = _parse_json_bounded(self._content)
        if not isinstance(value, dict):  # Already established when the snapshot was loaded.
            raise AssertionError("verified rule source no longer contains an object")
        return value


def load_rule_source_snapshot(
    path: Path,
    manifest: RuleSourceManifest | None = None,
) -> RuleSourceSnapshot:
    """Load and verify a local rules snapshot against an immutable manifest."""

    selected_manifest = manifest or load_bundled_rule_source_manifest()
    size = path.stat().st_size
    if size > MAX_RULE_SOURCE_BYTES:
        raise PolicySourceError(
            f"rule source is {size} bytes; maximum is {MAX_RULE_SOURCE_BYTES} bytes"
        )
    content = path.read_bytes()
    if len(content) > MAX_RULE_SOURCE_BYTES:
        raise PolicySourceError(
            f"rule source is {len(content)} bytes; maximum is {MAX_RULE_SOURCE_BYTES} bytes"
        )
    return _snapshot_from_bytes(content, selected_manifest)


def load_bundled_rule_source_snapshot() -> RuleSourceSnapshot:
    """Load the offline rules snapshot bundled at the manifest's exact commit."""

    manifest = load_bundled_rule_source_manifest()
    resource = files("complyroll").joinpath("data").joinpath(manifest.dataset_path)
    content = resource.read_bytes()
    if len(content) > MAX_RULE_SOURCE_BYTES:
        raise PolicySourceError(
            f"bundled rule source exceeds the {MAX_RULE_SOURCE_BYTES}-byte limit"
        )
    return _snapshot_from_bytes(content, manifest)


def load_bundled_rule_source_manifest() -> RuleSourceManifest:
    resource = files("complyroll").joinpath("data/fedramp-rules-source.json")
    value = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("rule-source manifest must contain a JSON object")
    return RuleSourceManifest.from_dict(value)


def _snapshot_from_bytes(
    content: bytes,
    manifest: RuleSourceManifest,
) -> RuleSourceSnapshot:
    digest = hashlib.sha256(content).hexdigest()
    if digest != manifest.dataset_sha256:
        raise PolicySourceIntegrityError(
            "rule-source SHA-256 does not match the pinned manifest: "
            f"expected {manifest.dataset_sha256}, got {digest}"
        )

    value = _parse_json_bounded(content)
    if not isinstance(value, dict):
        raise PolicySourceError("rule source must contain a JSON object")
    info = value.get("info")
    if not isinstance(info, dict):
        raise PolicySourceError("rule source is missing the info object")
    if info.get("version") != manifest.dataset_version:
        raise PolicySourceIntegrityError(
            "rule-source version does not match the pinned manifest"
        )
    if info.get("last_updated") != manifest.dataset_last_updated:
        raise PolicySourceIntegrityError(
            "rule-source last_updated does not match the pinned manifest"
        )
    if not isinstance(value.get("FRR"), dict):
        raise PolicySourceError("rule source is missing the FRR rule collection")

    return RuleSourceSnapshot(
        manifest=manifest,
        content_sha256=digest,
        _content=content,
    )


def _parse_json_bounded(content: bytes) -> Any:
    def reject_nonstandard_constant(value: str) -> None:
        raise PolicySourceError(f"non-standard JSON constant is prohibited: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise PolicySourceError(f"duplicate JSON object key is prohibited: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("utf-8"),
            parse_constant=reject_nonstandard_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except UnicodeDecodeError as exc:
        raise PolicySourceError("rule source must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise PolicySourceError(f"rule source contains malformed JSON: {exc}") from exc
    except RecursionError as exc:
        raise PolicySourceError("rule source exceeds the safe JSON recursion limit") from exc

    values_seen = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        values_seen += 1
        if values_seen > MAX_RULE_SOURCE_VALUES:
            raise PolicySourceError(
                f"rule source contains more than {MAX_RULE_SOURCE_VALUES} JSON values"
            )
        if depth > MAX_RULE_SOURCE_DEPTH:
            raise PolicySourceError(
                f"rule source exceeds {MAX_RULE_SOURCE_DEPTH} levels of JSON nesting"
            )
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value
