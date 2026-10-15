# ******************************************************************************
# *Title: Information Resource Inventory*
# *Author: Kyle Versluis*
# *Description: Bounded reader for the information resource inventory input.*
# ******************************************************************************
"""The provider's information resource inventory as a per-run report input (ADR 0015)."""

# *--- Imports ---*

from __future__ import annotations

import dataclasses
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from complyroll.adapters.common import (
    MAX_CLOCK_YEAR,
    MAX_IDENTITY_CHARS,
    MIN_CLOCK_YEAR,
    identity_problem,
)
from complyroll.adapters.safeio import (
    IngestLimits,
    InputLimitError,
    parse_json_bounded,
    read_bounded,
)
from complyroll.models import ResourceRef

from .evaluations import ReportInputError, parse_rfc3339

# NOTE: The KEV reader's message hygiene and instant pattern, shared so both per-run inputs
# quote, cut, and parse alike (ADR 0012).
from .kev import (
    _DATE_RELEASED,
    MAX_DATE_RELEASED_CHARS,
    _detail,
    _excerpt,
    _json_type,
    _utc_text,
)

# *--- Configuration ---*

INVENTORY_SCHEMA = "complyroll.inventory"
INVENTORY_SCHEMA_VERSION = 1
# The KEV-class bounds: a 20,000-resource inventory is far under 8 MiB, and every valid
# document nests six levels deep.
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_INVENTORY_RESOURCES = 20_000
INVENTORY_LIMITS = IngestLimits(max_artifact_bytes=MAX_INVENTORY_BYTES, max_json_depth=16)
MAX_NAME_CHARS = 128
MAX_REFERENCE_CHARS = 512
MAX_INSTANT_CHARS = MAX_DATE_RELEASED_CHARS

# The one string value driftLikely takes beside the JSON booleans.
DRIFT_UNKNOWN = "unknown"

_ROOT_KEYS = frozenset({"schema", "schemaVersion", "name", "resources"})
_ENTRY_KEYS = frozenset(
    {
        "resourceType",
        "resourceId",
        "machineBased",
        "expectedSince",
        "driftLikely",
        "sampleGroup",
        "job",
        "decommissionedAt",
        "aliases",
        "verifications",
    }
)
_ALIAS_KEYS = frozenset({"resourceType", "resourceId"})
_VERIFICATION_KEYS = frozenset({"at", "reference"})
# Printable ASCII with no leading or trailing space, so the name prints as one plain label.
_NAME = re.compile(r"[\x21-\x7e]([\x20-\x7e]{0,126}[\x21-\x7e])?")
_INSTANT = _DATE_RELEASED
_ABSENT = object()


# *--- Types ---*


@dataclass(frozen=True, slots=True)
class Verification:
    """One operator-attested verification of a non-machine resource."""

    at: datetime
    reference: str

    def __post_init__(self) -> None:
        _require_utc_aware(self.at, "at")

    def to_dict(self) -> dict[str, Any]:
        return {"at": _utc_text(self.at), "reference": self.reference}


@dataclass(frozen=True, slots=True)
class InformationResource:
    """One inventory entry: a resource the provider expects its detection to cover."""

    resource_type: str
    resource_id: str
    machine_based: bool
    expected_since: datetime
    # True, False or DRIFT_UNKNOWN on a machine entry; always None on a non-machine entry.
    drift_likely: bool | str | None = None
    sample_group: str | None = None
    job: str | None = None
    decommissioned_at: datetime | None = None
    aliases: tuple[ResourceRef, ...] = ()
    verifications: tuple[Verification, ...] = ()

    def __post_init__(self) -> None:
        _require_utc_aware(self.expected_since, "expected_since")
        if self.decommissioned_at is not None:
            _require_utc_aware(self.decommissioned_at, "decommissioned_at")
            if self.decommissioned_at < self.expected_since:
                raise ValueError("decommissioned_at must not precede expected_since")
        drift = self.drift_likely
        if drift is not None and not isinstance(drift, bool) and drift != DRIFT_UNKNOWN:
            raise ValueError("drift_likely must be True, False, DRIFT_UNKNOWN, or None")
        if self.machine_based and drift is None:
            raise ValueError("a machine-based resource must declare drift_likely")
        if not self.machine_based and drift is not None:
            raise ValueError("only a machine-based resource declares drift_likely")
        if self.machine_based and self.verifications:
            raise ValueError("only a non-machine resource carries attested verifications")
        keys = [_ref_key(alias) for alias in self.aliases]
        if keys != sorted(set(keys)) or _ref_key(self.ref) in keys:
            raise ValueError("aliases must be sorted, distinct, and not the entry's own pair")
        moments = [(item.at, item.reference) for item in self.verifications]
        if moments != sorted(moments):
            raise ValueError("verifications must be sorted by instant, then reference")

    @property
    def ref(self) -> ResourceRef:
        return ResourceRef(resource_id=self.resource_id, resource_type=self.resource_type)

    @property
    def identities(self) -> tuple[ResourceRef, ...]:
        """Return every identity that names this entry: its own pair, then its aliases."""
        return (self.ref, *self.aliases)

    def to_dict(self) -> dict[str, Any]:
        """Return the entry in the input form, with only the optional fields it declares."""
        value: dict[str, Any] = {
            "resourceType": self.resource_type,
            "resourceId": self.resource_id,
            "machineBased": self.machine_based,
            "expectedSince": _utc_text(self.expected_since),
        }
        if self.drift_likely is not None:
            value["driftLikely"] = self.drift_likely
        if self.sample_group is not None:
            value["sampleGroup"] = self.sample_group
        if self.job is not None:
            value["job"] = self.job
        if self.decommissioned_at is not None:
            value["decommissionedAt"] = _utc_text(self.decommissioned_at)
        if self.aliases:
            value["aliases"] = [
                {"resourceType": alias.resource_type, "resourceId": alias.resource_id}
                for alias in self.aliases
            ]
        if self.verifications:
            value["verifications"] = [item.to_dict() for item in self.verifications]
        return value


@dataclass(frozen=True, slots=True)
class Inventory:
    """One validated inventory, identified by the SHA-256 of its raw bytes, never stored."""

    name: str
    sha256: str
    size_bytes: int
    entries: tuple[InformationResource, ...]
    # NOTE: The index stays out of equality, hashing, and repr, so an inventory is hashable
    # and the report options that will carry it stay hashable, as a KEV catalog does.
    _index: Mapping[tuple[str, str], InformationResource] = field(
        init=False, compare=False, hash=False, repr=False
    )

    def __post_init__(self) -> None:
        keys = [_ref_key(entry.ref) for entry in self.entries]
        if keys != sorted(set(keys)):
            raise ValueError("Inventory entries must be sorted by type and id with no repeats")
        index: dict[tuple[str, str], InformationResource] = {}
        for entry in self.entries:
            for identity in entry.identities:
                key = _ref_key(identity)
                if key in index:
                    raise ValueError("an identity must name exactly one inventory entry")
                index[key] = entry
        object.__setattr__(self, "_index", MappingProxyType(index))

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    def entry_for(self, resource_type: str, resource_id: str) -> InformationResource | None:
        """Return the entry an exact pair or exact alias names; nothing is normalized."""
        return self._index.get((resource_type, resource_id))

    def to_document(self) -> dict[str, Any]:
        """Return the inventory in its canonical input form, which reads back to equal entries."""
        return {
            "schema": INVENTORY_SCHEMA,
            "schemaVersion": INVENTORY_SCHEMA_VERSION,
            "name": self.name,
            "resources": [entry.to_dict() for entry in self.entries],
        }


# *--- Loader ---*


def load_inventory(path: Path) -> Inventory:
    """Read one inventory from disk and validate it; nothing is ever fetched or stored."""
    location = Path(path)
    # NOTE: read_bounded refuses a non-regular file with a plain ValueError, so it is wrapped
    # beside OSError; InputLimitError is a ValueError too.
    try:
        content = read_bounded(location, INVENTORY_LIMITS)
    except InputLimitError as exc:
        raise ReportInputError(f"inventory exceeds a limit: {_detail(exc)}") from exc
    except (OSError, ValueError) as exc:
        raise ReportInputError(f"inventory cannot be read: {_detail(exc)}") from exc
    return parse_inventory(content)


def parse_inventory(content: bytes) -> Inventory:
    """Validate the bytes of one inventory document into an immutable inventory.

    Exported, so it bounds itself: `safeio.parse_json_bounded` never checks size.
    """
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if len(content) > MAX_INVENTORY_BYTES:
        raise ReportInputError(
            f"inventory is {len(content)} bytes; maximum is {MAX_INVENTORY_BYTES} bytes"
        )
    # Identity is the raw bytes, taken before safeio strips a BOM, as the KEV catalog's is.
    digest = hashlib.sha256(content).hexdigest()
    try:
        value = parse_json_bounded(content, INVENTORY_LIMITS)
    except InputLimitError as exc:
        raise ReportInputError(f"inventory exceeds a limit: {_detail(exc)}") from exc
    except (ValueError, RecursionError) as exc:
        raise ReportInputError(f"inventory must be a JSON document: {_detail(exc)}") from exc
    # NOTE: The year window keeps every instant clear of overflow; this block is the backstop,
    # since OverflowError is not a ValueError and would otherwise escape as a traceback.
    try:
        return _parse_inventory(value, sha256=digest, size_bytes=len(content))
    except ReportInputError:
        raise
    except (ValueError, RecursionError, OverflowError) as exc:
        raise ReportInputError(f"inventory is invalid: {_detail(exc)}") from exc


def _parse_inventory(value: Any, *, sha256: str, size_bytes: int) -> Inventory:
    if not isinstance(value, dict):
        raise _refusal("", f"the top level is {_json_type(value)}, not an object")
    # The schema is read first, so another document, a KEV catalog say, is named as one.
    schema = _string(value, "schema", "")
    if schema != INVENTORY_SCHEMA:
        raise _refusal("", f"schema must be {INVENTORY_SCHEMA!r}, got {_excerpt(schema)}")
    _schema_version(value)
    _reject_unknown_keys(value, _ROOT_KEYS, "")
    name = _string(value, "name", "")
    if _NAME.fullmatch(name) is None:
        raise _refusal(
            "",
            f"name must be 1 to {MAX_NAME_CHARS} printable ASCII characters with no leading or "
            f"trailing space, got {_excerpt(name)}",
        )

    raw_entries = _required(value, "resources", "")
    if not isinstance(raw_entries, list):
        raise _refusal("", f"resources must be an array, got {_json_type(raw_entries)}")
    if len(raw_entries) > MAX_INVENTORY_RESOURCES:
        raise _refusal(
            "",
            f"resources holds {len(raw_entries)} entries; maximum is {MAX_INVENTORY_RESOURCES}",
        )

    # Every pair and alias names one entry. Pairs are claimed first, in file order, so an
    # alias naming a later entry is refused as firmly as one naming an earlier entry.
    owners: dict[tuple[str, str], str] = {}
    parsed: list[tuple[str, InformationResource, list[ResourceRef]]] = []
    for index, raw_entry in enumerate(raw_entries):
        where = f"resources[{index}]"
        entry, aliases = _parse_entry(raw_entry, where)
        key = _ref_key(entry.ref)
        if key in owners:
            raise _refusal(where, f"resourceType and resourceId repeat {owners[key]}")
        owners[key] = where
        parsed.append((where, entry, aliases))
    for where, _, aliases in parsed:
        for position, alias in enumerate(aliases):
            at = f"{where}.aliases[{position}]"
            key = _ref_key(alias)
            owner = owners.get(key)
            if owner == where:
                raise _refusal(at, "the alias repeats the entry's own resourceType and resourceId")
            if owner is not None and ".aliases[" in owner:
                raise _refusal(at, f"the alias repeats {owner}")
            if owner is not None:
                raise _refusal(at, f"the alias names another entry, {owner}")
            owners[key] = at

    # The aliases join their entry only now, so every repeat above is refused by name.
    entries = [
        dataclasses.replace(entry, aliases=tuple(sorted(aliases, key=_ref_key)))
        for _, entry, aliases in parsed
    ]
    return Inventory(
        name=name,
        sha256=sha256,
        size_bytes=size_bytes,
        entries=tuple(sorted(entries, key=lambda entry: _ref_key(entry.ref))),
    )


def _parse_entry(raw_entry: Any, where: str) -> tuple[InformationResource, list[ResourceRef]]:
    """Return one entry without aliases, and its aliases in file order for the caller."""
    if not isinstance(raw_entry, dict):
        raise _refusal(where, f"the entry must be an object, got {_json_type(raw_entry)}")
    _reject_unknown_keys(raw_entry, _ENTRY_KEYS, where)
    resource_type = _identity(_string(raw_entry, "resourceType", where), "resourceType", where)
    resource_id = _identity(_string(raw_entry, "resourceId", where), "resourceId", where)
    machine_based = _boolean(raw_entry, "machineBased", where)
    expected_since = _instant(_string(raw_entry, "expectedSince", where), "expectedSince", where)
    drift_likely = _drift_likely(raw_entry, where, machine_based=machine_based)
    sample_group = _optional_identity(raw_entry, "sampleGroup", where)
    job = _optional_identity(raw_entry, "job", where)
    decommissioned_at = _optional_instant(raw_entry, "decommissionedAt", where)
    if decommissioned_at is not None and decommissioned_at < expected_since:
        raise _refusal(where, "decommissionedAt must not be before expectedSince")
    aliases = _aliases(raw_entry, where)
    verifications = _verifications(raw_entry, where, machine_based=machine_based)
    entry = InformationResource(
        resource_type=resource_type,
        resource_id=resource_id,
        machine_based=machine_based,
        expected_since=expected_since,
        drift_likely=drift_likely,
        sample_group=sample_group,
        job=job,
        decommissioned_at=decommissioned_at,
        verifications=tuple(sorted(verifications, key=lambda item: (item.at, item.reference))),
    )
    return entry, aliases


def _aliases(raw_entry: Mapping[str, Any], where: str) -> list[ResourceRef]:
    raw = _optional(raw_entry, "aliases")
    if raw is _ABSENT:
        return []
    if not isinstance(raw, list):
        raise _refusal(where, f"aliases must be an array, got {_json_type(raw)}")
    aliases: list[ResourceRef] = []
    for position, item in enumerate(raw):
        at = f"{where}.aliases[{position}]"
        if not isinstance(item, dict):
            raise _refusal(at, f"the alias must be an object, got {_json_type(item)}")
        _reject_unknown_keys(item, _ALIAS_KEYS, at)
        resource_type = _identity(_string(item, "resourceType", at), "resourceType", at)
        resource_id = _identity(_string(item, "resourceId", at), "resourceId", at)
        aliases.append(ResourceRef(resource_id=resource_id, resource_type=resource_type))
    return aliases


def _verifications(
    raw_entry: Mapping[str, Any], where: str, *, machine_based: bool
) -> list[Verification]:
    raw = _optional(raw_entry, "verifications")
    if raw is _ABSENT:
        return []
    # A machine-based resource is verified by detection results, never by attestation.
    if machine_based:
        raise _refusal(where, "verifications are for entries whose machineBased is false")
    if not isinstance(raw, list):
        raise _refusal(where, f"verifications must be an array, got {_json_type(raw)}")
    verifications: list[Verification] = []
    for position, item in enumerate(raw):
        at = f"{where}.verifications[{position}]"
        if not isinstance(item, dict):
            raise _refusal(at, f"the verification must be an object, got {_json_type(item)}")
        _reject_unknown_keys(item, _VERIFICATION_KEYS, at)
        instant = _instant(_string(item, "at", at), "at", at)
        reference = _text(_string(item, "reference", at), "reference", at, MAX_REFERENCE_CHARS)
        verifications.append(Verification(at=instant, reference=reference))
    return verifications


# *--- Field Rules ---*


def _required(raw: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in raw:
        raise _refusal(where, f"{key} is required")
    return raw[key]


def _optional(raw: Mapping[str, Any], key: str) -> Any:
    """Return an optional field, or _ABSENT when it is missing or a JSON null."""
    value = raw.get(key)
    return _ABSENT if value is None else value


def _string(raw: Mapping[str, Any], key: str, where: str) -> str:
    """Return a required field that must be a JSON string, checked before any pattern."""
    value = _required(raw, key, where)
    if not isinstance(value, str):
        raise _refusal(where, f"{key} must be a JSON string, got {_json_type(value)}")
    return value


def _boolean(raw: Mapping[str, Any], key: str, where: str) -> bool:
    value = _required(raw, key, where)
    if not isinstance(value, bool):
        raise _refusal(where, f"{key} must be a JSON boolean, got {_json_type(value)}")
    return value


def _schema_version(raw: Mapping[str, Any]) -> None:
    value = _required(raw, "schemaVersion", "")
    if isinstance(value, bool) or not isinstance(value, int):
        raise _refusal("", f"schemaVersion must be a JSON integer, got {_json_type(value)}")
    # NOTE: A JSON integer has no size limit, so the value is never echoed.
    if value != INVENTORY_SCHEMA_VERSION:
        raise _refusal(
            "",
            f"schemaVersion must be {INVENTORY_SCHEMA_VERSION}; this build reads no other version",
        )


# SECURITY: Identity text is refused, never repaired, by the rule the adapters apply, so an
# inventory pair can only ever name what an observation can carry (ADR 0011 decision 10).
def _identity(value: str, key: str, where: str) -> str:
    return _text(value, key, where, MAX_IDENTITY_CHARS)


def _text(value: str, key: str, where: str, cap: int) -> str:
    problem = identity_problem(value, cap)
    if problem is not None:
        raise _refusal(where, f"{key} {problem}")
    if not value.strip():
        raise _refusal(where, f"{key} must not be blank")
    return value


def _optional_identity(raw: Mapping[str, Any], key: str, where: str) -> str | None:
    value = _optional(raw, key)
    if value is _ABSENT:
        return None
    if not isinstance(value, str):
        raise _refusal(where, f"{key} must be a JSON string, got {_json_type(value)}")
    return _identity(value, key, where)


def _drift_likely(raw: Mapping[str, Any], where: str, *, machine_based: bool) -> bool | str | None:
    value = _optional(raw, "driftLikely")
    if value is _ABSENT:
        if machine_based:
            raise _refusal(where, "driftLikely is required when machineBased is true")
        return None
    # Drift clocks are detection cadence rules, and an attested procedure is not detection.
    if not machine_based:
        raise _refusal(where, "driftLikely is for entries whose machineBased is true")
    if isinstance(value, bool) or value == DRIFT_UNKNOWN:
        return value
    got = _excerpt(value) if isinstance(value, str) else _json_type(value)
    raise _refusal(where, f'driftLikely must be true, false or "unknown", got {got}')


def _instant(value: str, key: str, where: str) -> datetime:
    """Return an RFC 3339 instant in UTC, read the way the KEV reader reads dateReleased."""
    # parse_rfc3339 quotes its whole input, so the length is checked before anything quotes it.
    if len(value) > MAX_INSTANT_CHARS:
        raise _refusal(where, f"{key} must be at most {MAX_INSTANT_CHARS} characters")
    if _INSTANT.fullmatch(value) is None:
        raise _refusal(where, f"{key} must be an RFC 3339 timestamp, got {_excerpt(value)}")
    try:
        parsed = parse_rfc3339(value, key)
    except ReportInputError:
        raise _refusal(where, f"{key} must be a real RFC 3339 instant, got {value!r}") from None
    # NOTE: Year 1 with a positive offset and year 9999 with a negative one overflow here.
    try:
        instant: datetime | None = parsed.astimezone(UTC)
    except OverflowError:
        instant = None
    if instant is None or not MIN_CLOCK_YEAR <= instant.year <= MAX_CLOCK_YEAR:
        raise _refusal(
            where,
            f"{key} must fall in the years {MIN_CLOCK_YEAR} through {MAX_CLOCK_YEAR} UTC, "
            f"got {value!r}",
        )
    return instant


def _optional_instant(raw: Mapping[str, Any], key: str, where: str) -> datetime | None:
    value = _optional(raw, key)
    if value is _ABSENT:
        return None
    if not isinstance(value, str):
        raise _refusal(where, f"{key} must be a JSON string, got {_json_type(value)}")
    return _instant(value, key, where)


def _reject_unknown_keys(raw: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = [key for key in raw if key not in allowed]
    if not unknown:
        return
    more = f" and {len(unknown) - 1} more" if len(unknown) > 1 else ""
    raise _refusal(where, f"unknown key {_excerpt(min(unknown))}{more}")


# *--- Helper Functions ---*


def _ref_key(ref: ResourceRef) -> tuple[str, str]:
    return (ref.resource_type, ref.resource_id)


def _require_utc_aware(value: object, name: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _refusal(where: str, problem: str) -> ReportInputError:
    location = f" {where}" if where else ""
    return ReportInputError(f"inventory{location}: {problem}")


__all__ = [
    "DRIFT_UNKNOWN",
    "INVENTORY_LIMITS",
    "INVENTORY_SCHEMA",
    "INVENTORY_SCHEMA_VERSION",
    "MAX_INSTANT_CHARS",
    "MAX_INVENTORY_BYTES",
    "MAX_INVENTORY_RESOURCES",
    "MAX_NAME_CHARS",
    "MAX_REFERENCE_CHARS",
    "InformationResource",
    "Inventory",
    "Verification",
    "load_inventory",
    "parse_inventory",
]
