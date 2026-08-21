"""Actionable validation of FedRAMP VER reports against a verified offline bundle."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from jsonschema import Draft202012Validator
from referencing.exceptions import Unresolvable

from .source import (
    SchemaBundle,
    SchemaResolutionError,
    load_bundled_schema_bundle,
)

MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_REPORT_DEPTH = 128
MAX_REPORT_VALUES = 500_000


class ReportDocumentError(ValueError):
    """A report document is malformed or exceeds a validation bound."""


class ReportSchema(str, Enum):
    VULNERABILITY_DETAIL = "vulnerability-detail"
    ACCEPTED_VULNERABILITY = "accepted-vulnerability"
    HISTORICAL_ACTIVITY = "historical-activity"


@dataclass(frozen=True, slots=True)
class SchemaProvenance:
    repository: str
    commit: str
    schema_id: str
    schema_version: str
    schema_sha256: str


@dataclass(frozen=True, slots=True)
class SchemaValidationIssue:
    instance_pointer: str
    schema_pointer: str
    validator: str
    message: str


@dataclass(frozen=True, slots=True)
class SchemaValidationResult:
    report_schema: ReportSchema
    provenance: SchemaProvenance
    issues: tuple[SchemaValidationIssue, ...]

    @property
    def is_valid(self) -> bool:
        return not self.issues

    def raise_for_errors(self) -> None:
        if self.issues:
            raise ReportSchemaValidationError(self)


class ReportSchemaValidationError(ValueError):
    """A report failed one or more official schema constraints."""

    def __init__(self, result: SchemaValidationResult) -> None:
        self.result = result
        summaries = []
        for issue in result.issues[:5]:
            location = issue.instance_pointer or "<root>"
            summaries.append(f"{location}: {issue.message}")
        suffix = "" if len(result.issues) <= 5 else f"; plus {len(result.issues) - 5} more"
        message = (
            f"report failed {result.report_schema.value} schema validation with "
            f"{len(result.issues)} issue(s): " + "; ".join(summaries) + suffix
        )
        super().__init__(message)


def validate_report(
    bundle: SchemaBundle,
    report_schema: ReportSchema,
    instance: Any,
) -> SchemaValidationResult:
    """Validate one JSON-compatible value without retrieving remote references."""

    if not isinstance(bundle, SchemaBundle):
        raise TypeError("bundle must be a SchemaBundle")
    if not isinstance(report_schema, ReportSchema):
        raise TypeError("report_schema must be a ReportSchema")

    document = bundle.document(report_schema.value)
    validator = Draft202012Validator(
        document.schema,
        registry=bundle.registry,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    try:
        raw_errors = validator.iter_errors(instance)
        issues = tuple(sorted((_issue_from_error(error) for error in raw_errors), key=_issue_key))
    except Unresolvable as exc:
        raise SchemaResolutionError(
            f"schema {report_schema.value!r} attempted an unavailable reference"
        ) from exc

    manifest = bundle.manifest
    return SchemaValidationResult(
        report_schema=report_schema,
        provenance=SchemaProvenance(
            repository=manifest.repository,
            commit=manifest.commit,
            schema_id=document.entry.schema_id,
            schema_version=document.entry.version,
            schema_sha256=document.content_sha256,
        ),
        issues=issues,
    )


def validate_bundled_report(
    report_schema: ReportSchema,
    instance: Any,
) -> SchemaValidationResult:
    """Load the verified official bundle and validate one report value."""

    return validate_report(load_bundled_schema_bundle(), report_schema, instance)


def validate_bundled_report_bytes(
    report_schema: ReportSchema,
    content: bytes,
) -> SchemaValidationResult:
    """Parse bounded UTF-8 JSON and validate it against the official schema."""

    instance = _parse_report_json(content)
    return validate_bundled_report(report_schema, instance)


def _issue_from_error(error: Any) -> SchemaValidationIssue:
    return SchemaValidationIssue(
        instance_pointer=_json_pointer(error.absolute_path),
        schema_pointer=_json_pointer(error.absolute_schema_path),
        validator=str(error.validator),
        message=error.message,
    )


def _issue_key(issue: SchemaValidationIssue) -> tuple[str, str, str, str]:
    return (
        issue.instance_pointer,
        issue.schema_pointer,
        issue.validator,
        issue.message,
    )


def _parse_report_json(content: bytes) -> Any:
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if len(content) > MAX_REPORT_BYTES:
        raise ReportDocumentError(
            f"report is {len(content)} bytes; maximum is {MAX_REPORT_BYTES} bytes"
        )

    def reject_nonstandard_constant(value: str) -> None:
        raise ReportDocumentError(f"non-standard JSON constant is prohibited: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ReportDocumentError(f"duplicate JSON object key is prohibited: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("utf-8"),
            parse_constant=reject_nonstandard_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except UnicodeDecodeError as exc:
        raise ReportDocumentError("report must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ReportDocumentError(f"report contains malformed JSON: {exc}") from exc
    except RecursionError as exc:
        raise ReportDocumentError("report exceeds the safe JSON recursion limit") from exc

    values_seen = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        values_seen += 1
        if values_seen > MAX_REPORT_VALUES:
            raise ReportDocumentError(
                f"report contains more than {MAX_REPORT_VALUES} JSON values"
            )
        if depth > MAX_REPORT_DEPTH:
            raise ReportDocumentError(
                f"report exceeds {MAX_REPORT_DEPTH} levels of JSON nesting"
            )
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value


def _json_pointer(parts: Iterable[str | int]) -> str:
    encoded = (str(part).replace("~", "~0").replace("/", "~1") for part in parts)
    return "".join(f"/{part}" for part in encoded)
