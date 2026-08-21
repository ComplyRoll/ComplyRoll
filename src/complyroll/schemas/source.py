"""Verified, offline loading and reference resolution for official FedRAMP schemas."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT202012


COMMON_DEFINITIONS_NAME = "common-definitions"
MAX_SCHEMA_BYTES = 1024 * 1024
MAX_SCHEMA_DEPTH = 128
MAX_SCHEMA_VALUES = 100_000
REQUIRED_FORMAT_CHECKERS = ("date", "date-time", "uri")


class SchemaSourceError(ValueError):
    """Base error for an invalid or unusable official schema bundle."""


class SchemaIntegrityError(SchemaSourceError):
    """A schema did not match its pinned source manifest."""


class SchemaDefinitionError(SchemaSourceError):
    """A pinned document is not a valid JSON Schema definition."""


class SchemaResolutionError(SchemaSourceError):
    """A schema reference cannot be resolved from the offline bundle."""


class SchemaNotFoundError(SchemaSourceError):
    """A requested schema name is not present in the verified bundle."""


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


def _require_commit(value: Any) -> str:
    commit = _require_text(value, "commit").lower()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ValueError("commit must be a full 40-character Git commit")
    return commit


def _require_timestamp(value: Any) -> datetime:
    text = _require_text(value, "retrieved_at")
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        timestamp = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("retrieved_at must be an ISO 8601 timestamp") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("retrieved_at must include a timezone")
    return timestamp


@dataclass(frozen=True, slots=True)
class SchemaManifestEntry:
    name: str
    path: str
    schema_id: str
    version: str
    sha256: str

    @classmethod
    def from_dict(cls, value: dict[str, Any], index: int) -> "SchemaManifestEntry":
        prefix = f"schemas[{index}]"
        return cls(
            name=_require_text(value.get("name"), f"{prefix}.name"),
            path=_require_relative_path(value.get("path"), f"{prefix}.path"),
            schema_id=_require_text(value.get("id"), f"{prefix}.id"),
            version=_require_text(value.get("version"), f"{prefix}.version"),
            sha256=_require_sha256(value.get("sha256"), f"{prefix}.sha256"),
        )


@dataclass(frozen=True, slots=True)
class SchemaBundleManifest:
    manifest_version: str
    repository: str
    commit: str
    retrieved_at: datetime
    schema_draft: str
    schemas: tuple[SchemaManifestEntry, ...]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SchemaBundleManifest":
        raw_schemas = value.get("schemas")
        if not isinstance(raw_schemas, list) or not raw_schemas:
            raise ValueError("schemas must be a non-empty array")
        entries: list[SchemaManifestEntry] = []
        for index, raw_entry in enumerate(raw_schemas):
            if not isinstance(raw_entry, dict):
                raise ValueError(f"schemas[{index}] must be an object")
            entries.append(SchemaManifestEntry.from_dict(raw_entry, index))

        _require_unique((entry.name for entry in entries), "schema names")
        _require_unique((entry.path for entry in entries), "schema paths")
        _require_unique((entry.schema_id for entry in entries), "schema identifiers")
        return cls(
            manifest_version=_require_text(value.get("manifest_version"), "manifest_version"),
            repository=_require_text(value.get("repository"), "repository"),
            commit=_require_commit(value.get("commit")),
            retrieved_at=_require_timestamp(value.get("retrieved_at")),
            schema_draft=_require_text(value.get("schema_draft"), "schema_draft"),
            schemas=tuple(entries),
        )

    def entry(self, name: str) -> SchemaManifestEntry:
        for entry in self.schemas:
            if entry.name == name:
                return entry
        raise SchemaNotFoundError(f"schema {name!r} is not present in the source manifest")


@dataclass(frozen=True, slots=True)
class SchemaDocument:
    entry: SchemaManifestEntry
    content_sha256: str
    _content: bytes

    @property
    def schema(self) -> dict[str, Any]:
        """Return a newly parsed object so verified content cannot be mutated."""

        value = _parse_json_bounded(self._content)
        if not isinstance(value, dict):  # Established when the bundle was loaded.
            raise AssertionError("verified schema no longer contains an object")
        return value

    @property
    def content(self) -> bytes:
        """Return the exact immutable bytes used for digest verification."""

        return self._content


@dataclass(frozen=True, slots=True)
class SchemaBundle:
    manifest: SchemaBundleManifest
    documents: tuple[SchemaDocument, ...]
    _registry: Registry

    def document(self, name: str) -> SchemaDocument:
        if not isinstance(name, str) or not name:
            raise TypeError("schema name must be non-blank text")
        for document in self.documents:
            if document.entry.name == name:
                return document
        raise SchemaNotFoundError(f"schema {name!r} is not present in the verified bundle")

    @property
    def registry(self) -> Registry:
        """Return the immutable, network-free reference registry."""

        return self._registry


def load_bundled_schema_manifest() -> SchemaBundleManifest:
    resource = files("complyroll").joinpath("data/fedramp-ver-schemas-source.json")
    value = _parse_json_bounded(resource.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("schema-source manifest must contain a JSON object")
    return SchemaBundleManifest.from_dict(value)


def load_bundled_schema_bundle() -> SchemaBundle:
    """Load all official VER schemas from package data without network access."""

    manifest = load_bundled_schema_manifest()
    data_directory = files("complyroll").joinpath("data")
    contents = (
        (entry, data_directory.joinpath(entry.path).read_bytes())
        for entry in manifest.schemas
    )
    return _load_schema_contents(manifest, contents)


def load_schema_bundle(directory: Path, manifest: SchemaBundleManifest) -> SchemaBundle:
    """Load a local schema cache against an already trusted source manifest."""

    if not isinstance(directory, Path):
        raise TypeError("directory must be a pathlib.Path")
    if not isinstance(manifest, SchemaBundleManifest):
        raise TypeError("manifest must be a SchemaBundleManifest")

    def contents() -> Iterable[tuple[SchemaManifestEntry, bytes]]:
        for entry in manifest.schemas:
            schema_path = directory / entry.path
            size = schema_path.stat().st_size
            if size > MAX_SCHEMA_BYTES:
                raise SchemaSourceError(
                    f"schema {entry.name!r} is {size} bytes; maximum is {MAX_SCHEMA_BYTES}"
                )
            yield entry, schema_path.read_bytes()

    return _load_schema_contents(manifest, contents())


def _load_schema_contents(
    manifest: SchemaBundleManifest,
    contents: Iterable[tuple[SchemaManifestEntry, bytes]],
) -> SchemaBundle:
    documents = tuple(_load_document(entry, content, manifest) for entry, content in contents)
    if len(documents) != len(manifest.schemas):
        raise SchemaSourceError("schema bundle did not supply every manifest entry")
    missing_formats = tuple(
        name
        for name in REQUIRED_FORMAT_CHECKERS
        if name not in Draft202012Validator.FORMAT_CHECKER.checkers
    )
    if missing_formats:
        raise SchemaDefinitionError(
            "required JSON Schema format checkers are unavailable: "
            + ", ".join(missing_formats)
        )

    resources = []
    for document in documents:
        schema = document.schema
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise SchemaDefinitionError(
                f"schema {document.entry.name!r} is not valid Draft 2020-12: {exc.message}"
            ) from exc
        resources.append(
            (document.entry.schema_id, DRAFT202012.create_resource(schema))
        )
    registry = Registry().with_resources(resources)
    _verify_reference_graph(documents, registry)
    return SchemaBundle(manifest=manifest, documents=documents, _registry=registry)


def _load_document(
    entry: SchemaManifestEntry,
    content: bytes,
    manifest: SchemaBundleManifest,
) -> SchemaDocument:
    if len(content) > MAX_SCHEMA_BYTES:
        raise SchemaSourceError(
            f"schema {entry.name!r} exceeds the {MAX_SCHEMA_BYTES}-byte limit"
        )
    digest = hashlib.sha256(content).hexdigest()
    if digest != entry.sha256:
        raise SchemaIntegrityError(
            f"schema {entry.name!r} SHA-256 does not match the manifest: "
            f"expected {entry.sha256}, got {digest}"
        )
    value = _parse_json_bounded(content)
    if not isinstance(value, dict):
        raise SchemaDefinitionError(f"schema {entry.name!r} must contain a JSON object")
    if value.get("$schema") != manifest.schema_draft:
        raise SchemaIntegrityError(f"schema {entry.name!r} draft does not match the manifest")
    if value.get("$id") != entry.schema_id:
        raise SchemaIntegrityError(f"schema {entry.name!r} identifier does not match the manifest")
    if value.get("$schemaVersion") != entry.version:
        raise SchemaIntegrityError(f"schema {entry.name!r} version does not match the manifest")
    return SchemaDocument(entry=entry, content_sha256=digest, _content=content)


def _verify_reference_graph(
    documents: tuple[SchemaDocument, ...],
    registry: Registry,
) -> None:
    for document in documents:
        resolver = registry.resolver(document.entry.schema_id)
        for pointer, reference in _iter_references(document.schema):
            try:
                resolver.lookup(reference)
            except Unresolvable as exc:
                location = pointer or "<root>"
                raise SchemaResolutionError(
                    f"schema {document.entry.name!r} has an offline-unresolvable $ref "
                    f"at {location}: {reference}"
                ) from exc


def _iter_references(value: Any) -> Iterable[tuple[str, str]]:
    stack: list[tuple[Any, tuple[str | int, ...]]] = [(value, ())]
    while stack:
        current, path = stack.pop()
        if isinstance(current, dict):
            reference = current.get("$ref")
            if reference is not None:
                if not isinstance(reference, str) or not reference:
                    raise SchemaDefinitionError(f"$ref at {_json_pointer(path)} must be text")
                yield _json_pointer(path + ("$ref",)), reference
            stack.extend((item, path + (key,)) for key, item in current.items())
        elif isinstance(current, list):
            stack.extend((item, path + (index,)) for index, item in enumerate(current))


def _parse_json_bounded(content: bytes) -> Any:
    def reject_nonstandard_constant(value: str) -> None:
        raise SchemaSourceError(f"non-standard JSON constant is prohibited: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise SchemaSourceError(f"duplicate JSON object key is prohibited: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("utf-8"),
            parse_constant=reject_nonstandard_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except UnicodeDecodeError as exc:
        raise SchemaSourceError("schema content must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise SchemaSourceError(f"schema content contains malformed JSON: {exc}") from exc
    except RecursionError as exc:
        raise SchemaSourceError("schema content exceeds the safe JSON recursion limit") from exc

    values_seen = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        values_seen += 1
        if values_seen > MAX_SCHEMA_VALUES:
            raise SchemaSourceError(
                f"schema content contains more than {MAX_SCHEMA_VALUES} JSON values"
            )
        if depth > MAX_SCHEMA_DEPTH:
            raise SchemaSourceError(
                f"schema content exceeds {MAX_SCHEMA_DEPTH} levels of JSON nesting"
            )
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value


def _require_unique(values: Iterable[str], field_name: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"{field_name} must not contain duplicates: {value}")
        seen.add(value)


def _json_pointer(parts: Iterable[str | int]) -> str:
    encoded = (str(part).replace("~", "~0").replace("/", "~1") for part in parts)
    return "".join(f"/{part}" for part in encoded)
