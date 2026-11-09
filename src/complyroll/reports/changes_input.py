# ******************************************************************************
# *Title: Change Input*
# *Author: Kyle Versluis*
# *Description: Bounded reader for the provider-supplied change file.*
# ******************************************************************************
"""The provider's declared changes as a per-run report input (ADR 0018)."""

# *--- Imports ---*

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from complyroll.adapters.common import diagnostic_text
from complyroll.adapters.safeio import (
    IngestLimits,
    InputLimitError,
    parse_json_bounded,
    read_bounded,
)
from complyroll.models import ResourceRef

from .evaluations import ReportInputError

# NOTE: The inventory's field rules, imported so both inputs refuse alike. Each raises through
# the inventory's `_refusal`, so `parse_changes` renames the refusal once, at the boundary.
from .inventory import (
    MAX_REFERENCE_CHARS,
    _boolean,
    _identity,
    _instant,
    _label,
    _optional_instant,
    _optional_label,
    _ref_key,
    _refusal,
    _reject_unknown_keys,
    _require_utc_aware,
    _required,
    _resource_type,
    _string,
    _text,
)
from .kev import detail, excerpt, json_type

# *--- Configuration ---*

CHANGES_SCHEMA = "complyroll.changes"
CHANGES_SCHEMA_VERSION = 1
# The inventory's bounds: every valid document nests five levels deep.
MAX_CHANGES_BYTES = 8 * 1024 * 1024
MAX_CHANGES = 20_000
MAX_CHANGE_RESOURCES = 1_000
MAX_RATIONALE_CHARS = 512
CHANGES_LIMITS = IngestLimits(max_artifact_bytes=MAX_CHANGES_BYTES, max_json_depth=16)

_ROOT_KEYS = frozenset({"schema", "schemaVersion", "name", "changes"})
_CHANGE_KEYS = frozenset(
    {
        "changeId",
        "kind",
        "occurredAt",
        "source",
        "resources",
        "significant",
        "rationale",
        "detectBy",
        "job",
    }
)
_SOURCE_KEYS = frozenset({"tool", "reference"})
_RESOURCE_KEYS = frozenset({"resourceType", "resourceId"})
_INVENTORY_PREFIX = "inventory"
_CHANGES_PREFIX = "changes"


# *--- Types ---*


class ChangeKind(str, Enum):
    CREATED = "created"
    MODIFIED = "modified"


@dataclass(frozen=True, slots=True)
class ChangeSource:
    """Where the provider's change record lives: the tool, and a commit, deployment or ticket."""

    tool: str
    reference: str


@dataclass(frozen=True, slots=True)
class Change:
    """One change the provider declares: what it touched, and whether it calls it significant."""

    change_id: str
    kind: ChangeKind
    occurred_at: datetime
    source: ChangeSource
    resources: tuple[ResourceRef, ...]
    significant: bool
    rationale: str
    detect_by: datetime | None = None
    job: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ChangeKind):
            raise TypeError("kind must be a ChangeKind")
        _require_utc_aware(self.occurred_at, "occurred_at")
        if self.detect_by is not None:
            _require_utc_aware(self.detect_by, "detect_by")
            if self.detect_by < self.occurred_at:
                raise ValueError("detect_by must not precede occurred_at")
        keys = [_ref_key(ref) for ref in self.resources]
        if not keys or keys != sorted(set(keys)):
            raise ValueError("resources must be present, sorted by type and id, and distinct")

    @property
    def opens_obligation(self) -> bool:
        """Return True for the kinds VDR-CSO-DAC names: new, or significantly changed."""
        return self.kind is ChangeKind.CREATED or self.significant


@dataclass(frozen=True, slots=True)
class ChangeSet:
    """One validated change file, identified by the SHA-256 of its raw bytes, never stored."""

    name: str
    sha256: str
    size_bytes: int
    changes: tuple[Change, ...]

    def __post_init__(self) -> None:
        keys = [(change.occurred_at, change.change_id) for change in self.changes]
        if keys != sorted(keys):
            raise ValueError("changes must be sorted by occurred_at, then change_id")
        if len({change.change_id for change in self.changes}) != len(keys):
            raise ValueError("a change id must name exactly one change")

    @property
    def change_count(self) -> int:
        return len(self.changes)


# *--- Loader ---*


def load_changes(path: Path) -> ChangeSet:
    """Read one change file from disk and validate it; nothing is ever fetched or stored."""
    location = Path(path)
    # NOTE: read_bounded refuses a non-regular file with a plain ValueError, so it is wrapped
    # beside OSError; InputLimitError is a ValueError too.
    try:
        content = read_bounded(location, CHANGES_LIMITS)
    except InputLimitError as exc:
        raise ReportInputError(f"changes exceeds a limit: {detail(exc)}") from exc
    except (OSError, ValueError) as exc:
        raise ReportInputError(f"changes cannot be read: {detail(exc)}") from exc
    return parse_changes(content)


def parse_changes(content: bytes) -> ChangeSet:
    """Validate the bytes of one change file into an immutable change set.

    Exported, so it bounds itself: `safeio.parse_json_bounded` never checks size.
    """
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if len(content) > MAX_CHANGES_BYTES:
        raise ReportInputError(
            f"changes is {len(content)} bytes; maximum is {MAX_CHANGES_BYTES} bytes"
        )
    # Identity is the raw bytes, taken before safeio strips a BOM, as the inventory's is.
    digest = hashlib.sha256(content).hexdigest()
    try:
        value = parse_json_bounded(content, CHANGES_LIMITS)
    except InputLimitError as exc:
        raise ReportInputError(f"changes exceeds a limit: {detail(exc)}") from exc
    except (ValueError, RecursionError) as exc:
        raise ReportInputError(f"changes must be a JSON document: {detail(exc)}") from exc
    try:
        return _parse_changes(value, sha256=digest, size_bytes=len(content))
    except ReportInputError as exc:
        raise ReportInputError(_renamed(str(exc))) from None
    except (ValueError, RecursionError, OverflowError) as exc:
        raise ReportInputError(f"changes is invalid: {detail(exc)}") from exc


def _parse_changes(value: Any, *, sha256: str, size_bytes: int) -> ChangeSet:
    if not isinstance(value, dict):
        raise _refusal("", f"the top level is {json_type(value)}, not an object")
    # The schema is read first, so another document, an inventory say, is named as one.
    schema = _string(value, "schema", "")
    if schema != CHANGES_SCHEMA:
        raise _refusal("", f"schema must be {CHANGES_SCHEMA!r}, got {excerpt(schema)}")
    _schema_version(value)
    _reject_unknown_keys(value, _ROOT_KEYS, "")
    name = _label(_string(value, "name", ""), "name", "")

    raw_changes = _required(value, "changes", "")
    if not isinstance(raw_changes, list):
        raise _refusal("", f"changes must be an array, got {json_type(raw_changes)}")
    if len(raw_changes) > MAX_CHANGES:
        raise _refusal("", f"changes holds {len(raw_changes)} entries; maximum is {MAX_CHANGES}")

    owners: dict[str, str] = {}
    changes: list[Change] = []
    for index, raw_change in enumerate(raw_changes):
        where = f"changes[{index}]"
        change = _parse_change(raw_change, where)
        if change.change_id in owners:
            raise _refusal(where, f"changeId repeats {owners[change.change_id]}")
        owners[change.change_id] = where
        changes.append(change)
    return ChangeSet(
        name=name,
        sha256=sha256,
        size_bytes=size_bytes,
        changes=tuple(sorted(changes, key=lambda item: (item.occurred_at, item.change_id))),
    )


def _parse_change(raw: Any, where: str) -> Change:
    if not isinstance(raw, dict):
        raise _refusal(where, f"the change must be an object, got {json_type(raw)}")
    _reject_unknown_keys(raw, _CHANGE_KEYS, where)
    change_id = _label(_string(raw, "changeId", where), "changeId", where)
    kind = _kind(raw, where)
    occurred_at = _instant(_string(raw, "occurredAt", where), "occurredAt", where)
    source = _source(raw, where)
    resources = _resources(raw, where)
    significant = _boolean(raw, "significant", where)
    rationale = _rationale(raw, where)
    detect_by = _optional_instant(raw, "detectBy", where)
    if detect_by is not None and detect_by < occurred_at:
        raise _refusal(where, "detectBy must not be before occurredAt")
    return Change(
        change_id=change_id,
        kind=kind,
        occurred_at=occurred_at,
        source=source,
        resources=resources,
        significant=significant,
        rationale=rationale,
        detect_by=detect_by,
        job=_optional_label(raw, "job", where),
    )


# *--- Field Rules ---*


def _schema_version(raw: Mapping[str, Any]) -> None:
    value = _required(raw, "schemaVersion", "")
    if isinstance(value, bool) or not isinstance(value, int):
        raise _refusal("", f"schemaVersion must be a JSON integer, got {json_type(value)}")
    # NOTE: A JSON integer has no size limit, so the value is never echoed.
    if value != CHANGES_SCHEMA_VERSION:
        raise _refusal(
            "",
            f"schemaVersion must be {CHANGES_SCHEMA_VERSION}; this build reads no other version",
        )


def _kind(raw: Mapping[str, Any], where: str) -> ChangeKind:
    value = _string(raw, "kind", where)
    try:
        return ChangeKind(value)
    except ValueError:
        raise _refusal(where, f"kind must be created or modified, got {excerpt(value)}") from None


def _source(raw: Mapping[str, Any], where: str) -> ChangeSource:
    value = _required(raw, "source", where)
    if not isinstance(value, dict):
        raise _refusal(where, f"source must be an object, got {json_type(value)}")
    at = f"{where}.source"
    _reject_unknown_keys(value, _SOURCE_KEYS, at)
    return ChangeSource(
        tool=_label(_string(value, "tool", at), "tool", at),
        reference=_text(_string(value, "reference", at), "reference", at, MAX_REFERENCE_CHARS),
    )


def _resources(raw: Mapping[str, Any], where: str) -> tuple[ResourceRef, ...]:
    value = _required(raw, "resources", where)
    if not isinstance(value, list):
        raise _refusal(where, f"resources must be an array, got {json_type(value)}")
    if not value:
        raise _refusal(where, "resources must name at least one resource")
    if len(value) > MAX_CHANGE_RESOURCES:
        raise _refusal(
            where, f"resources holds {len(value)} entries; maximum is {MAX_CHANGE_RESOURCES}"
        )
    owners: dict[tuple[str, str], str] = {}
    for position, item in enumerate(value):
        at = f"{where}.resources[{position}]"
        if not isinstance(item, dict):
            raise _refusal(at, f"the resource must be an object, got {json_type(item)}")
        _reject_unknown_keys(item, _RESOURCE_KEYS, at)
        resource_type = _resource_type(item, at)
        resource_id = _identity(_string(item, "resourceId", at), "resourceId", at)
        key = (resource_type, resource_id)
        if key in owners:
            raise _refusal(at, f"resourceType and resourceId repeat {owners[key]}")
        owners[key] = at
    return tuple(
        ResourceRef(resource_id=resource_id, resource_type=resource_type)
        for resource_type, resource_id in sorted(owners)
    )


# SECURITY: The one repaired field. A rationale is free text a person wrote, so it is sanitized
# the way a diagnostic detail is; the bound is read first, so nothing is ever cut.
def _rationale(raw: Mapping[str, Any], where: str) -> str:
    value = _string(raw, "rationale", where)
    if len(value) > MAX_RATIONALE_CHARS:
        raise _refusal(
            where, f"rationale is {len(value)} characters; maximum is {MAX_RATIONALE_CHARS}"
        )
    cleaned = diagnostic_text(value)
    if not cleaned.strip():
        raise _refusal(where, "rationale must not be blank")
    return cleaned


# *--- Helper Functions ---*


def _renamed(message: str) -> str:
    """Return a refusal raised through the inventory's rules, named as the change file's."""
    return _CHANGES_PREFIX + message.removeprefix(_INVENTORY_PREFIX)


__all__ = [
    "CHANGES_LIMITS",
    "CHANGES_SCHEMA",
    "CHANGES_SCHEMA_VERSION",
    "MAX_CHANGES",
    "MAX_CHANGES_BYTES",
    "MAX_CHANGE_RESOURCES",
    "MAX_RATIONALE_CHARS",
    "Change",
    "ChangeKind",
    "ChangeSet",
    "ChangeSource",
    "load_changes",
    "parse_changes",
]
