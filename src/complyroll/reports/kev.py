# ******************************************************************************
# *Title: CISA KEV Catalog*
# *Author: Kyle Versluis*
# *Description: Bounded loader and clock inputs for the CISA KEV catalog.*
# ******************************************************************************
"""The CISA Known Exploited Vulnerabilities catalog as a per-run report input (ADR 0012)."""

# *--- Imports ---*

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from complyroll.adapters.safeio import (
    IngestLimits,
    InputLimitError,
    parse_json_bounded,
    read_bounded,
)
from complyroll.adapters.sarif import MAX_CLOCK_YEAR, MIN_CLOCK_YEAR
from complyroll.models import CaseStatus, Observation

from .evaluations import ReportInputError, parse_rfc3339

# *--- Configuration ---*

# The live feed was 1,737,207 bytes and 1717 entries on 2026-09-22.
MAX_KEV_CATALOG_BYTES = 8 * 1024 * 1024
MAX_KEV_ENTRIES = 20_000
# The feed nests five levels deep; the default node bound already covers 20,000 entries.
KEV_LIMITS = IngestLimits(max_artifact_bytes=MAX_KEV_CATALOG_BYTES, max_json_depth=16)
# The shortest BOD 26-04 Table 1 timeline: an older catalog can miss a whole clock.
KEV_STALE_AFTER = timedelta(days=3)

# Remediation and a false positive stop the clock; mitigation and acceptance do not.
KEV_STOPS = frozenset({CaseStatus.REMEDIATED, CaseStatus.FALSE_POSITIVE})

# A refusal quotes an unvalidated value only as a repr cut to this many characters.
MAX_QUOTED_CHARS = 64
MAX_DETAIL_CHARS = 160
MAX_DATE_RELEASED_CHARS = 64
# A truncation note longer than this is not decoded; it counts as naming every list.
MAX_TRUNCATED_METADATA_BYTES = 4 * 1024

# SECURITY: ASCII classes only. `fromisoformat` alone also accepts basic, week, space-separated,
# hour-only, and comma-fraction forms, and `\d` would admit every Unicode digit. The hour stops
# at 23 because 3.14 reads T24:00:00 as the next midnight where 3.11 and 3.13 refuse it.
_DATE_RELEASED_PATTERN = (
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-9]{2}:[0-9]{2}"
    r"(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})"
)
_DATE_RELEASED = re.compile(_DATE_RELEASED_PATTERN)
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
# The same 4-19 digit sequence bound the SARIF adapter extracts (ADR 0011 Decision 5).
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")
_CATALOG_VERSION = re.compile(r"[\x21-\x7e]{1,64}")
_LABEL = re.compile(r"[\x20-\x7e]{1,32}")

_SOURCE_IDENTIFIERS_KEY = "source_identifiers"
_CVE_PREFIX = "CVE-"


# *--- Types ---*


@dataclass(frozen=True, slots=True)
class KevEntry:
    """One catalog entry the clock reads; its instants are computed once, here."""

    cve_id: str
    date_added: date
    due_date: date
    known_ransomware_campaign_use: str | None = None
    forensic_triage: str | None = None
    start_at: datetime = field(init=False)
    due_at: datetime = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "start_at", start_instant(self.date_added))
        object.__setattr__(self, "due_at", due_instant(self.due_date))

    def to_dict(self) -> dict[str, Any]:
        """Return the five catalog fields the report publishes; the instants ride on the clock."""
        return {
            "cveId": self.cve_id,
            "dateAdded": self.date_added.isoformat(),
            "dueDate": self.due_date.isoformat(),
            "forensicTriage": self.forensic_triage,
            "knownRansomwareCampaignUse": self.known_ransomware_campaign_use,
        }


@dataclass(frozen=True, slots=True)
class KevCatalog:
    """One validated catalog, identified by the SHA-256 of its raw bytes (decision 3)."""

    name: str
    sha256: str
    size_bytes: int
    catalog_version: str
    date_released: datetime
    declared_count: int
    entries: tuple[KevEntry, ...]
    # NOTE: The index stays out of equality, hashing, and repr, so a catalog is hashable and
    # the ReportOptions that carries it stays hashable.
    _index: Mapping[str, KevEntry] = field(init=False, compare=False, hash=False, repr=False)

    def __post_init__(self) -> None:
        cve_ids = [entry.cve_id for entry in self.entries]
        if cve_ids != sorted(set(cve_ids)):
            raise ValueError("KevCatalog entries must be sorted by cve_id with no repeats")
        object.__setattr__(
            self, "_index", MappingProxyType({entry.cve_id: entry for entry in self.entries})
        )

    def matches(self, identifiers: Iterable[str], *, on_or_before: date) -> tuple[KevEntry, ...]:
        """Return the entries whose cveID equals an identifier exactly, listed by the date given.

        Sorted by due date, then cveID, so the first entry is the one the clock binds to.
        """
        found = {
            self._index[identifier]
            for identifier in identifiers
            if identifier.startswith(_CVE_PREFIX) and identifier in self._index
        }
        listed = (entry for entry in found if entry.date_added <= on_or_before)
        return tuple(sorted(listed, key=lambda entry: (entry.due_date, entry.cve_id)))

    def considered(self, on_or_before: date) -> int:
        """Return how many entries were listed on or before the date given."""
        return sum(1 for entry in self.entries if entry.date_added <= on_or_before)

    def later_than(self, on_or_before: date) -> int:
        """Return how many entries were listed after the date given, and so were not applied."""
        return len(self.entries) - self.considered(on_or_before)


class KevStatus(str, Enum):
    """The one state a KEV clock is in, so no reader has to infer it from the booleans."""

    OPEN = "open"
    PAST_DUE = "pastDue"
    ACCEPTED = "accepted"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "falsePositive"


@dataclass(frozen=True, slots=True)
class KevClock:
    """The one VDR-TFR-KEV clock a matched record gets, bound to its earliest due date."""

    entries: tuple[KevEntry, ...]
    satisfied: bool
    past_due: bool
    status: KevStatus

    @property
    def bound(self) -> KevEntry:
        """Return the entry the clock follows: the earliest due date, then the lowest cveID."""
        return self.entries[0]

    @property
    def start_at(self) -> datetime:
        return self.bound.start_at

    @property
    def due_at(self) -> datetime:
        return self.bound.due_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "cveId": self.bound.cve_id,
            "dueDate": self.bound.due_date.isoformat(),
            "dueAt": _utc_text(self.due_at),
            "entries": [entry.to_dict() for entry in self.entries],
            "pastDue": self.past_due,
            "satisfied": self.satisfied,
            "status": self.status.value,
        }


# *--- Clock ---*


# NOTE: The end of the due date in UTC is the midnight that starts the next UTC day. A fixed
# reference no --calendar-tz can move, and a strict `>` against it never flags a fractional
# instant on the due date itself (ADR 0012 decision 5).
def due_instant(day: date) -> datetime:
    """Return the instant a catalog due date ends: the next day at 00:00:00Z."""
    return datetime.combine(day + timedelta(days=1), time(0), UTC)


def start_instant(day: date) -> datetime:
    """Return the instant a catalog date begins: that day at 00:00:00Z."""
    return datetime.combine(day, time(0), UTC)


def kev_clock(
    entries: Sequence[KevEntry], *, status: CaseStatus | None, as_of: datetime
) -> KevClock:
    """Return the clock for a record's matched entries, given its resolved status at as_of."""
    if not entries:
        raise ValueError("a KEV clock needs at least one matched catalog entry")
    ordered = tuple(sorted(entries, key=lambda entry: (entry.due_date, entry.cve_id)))
    satisfied = status in KEV_STOPS
    # The gate every existing clock uses: an unsatisfied clock, then the strict comparison.
    past_due = not satisfied and as_of > ordered[0].due_at
    if status is CaseStatus.REMEDIATED:
        kev_status = KevStatus.REMEDIATED
    elif status is CaseStatus.FALSE_POSITIVE:
        kev_status = KevStatus.FALSE_POSITIVE
    elif status is CaseStatus.ACCEPTED:
        kev_status = KevStatus.ACCEPTED
    elif past_due:
        kev_status = KevStatus.PAST_DUE
    else:
        kev_status = KevStatus.OPEN
    return KevClock(entries=ordered, satisfied=satisfied, past_due=past_due, status=kev_status)


# The SARIF adapter keeps the MAX_LIST_ITEMS lexicographically smallest distinct identifiers
# (`adapters/sarif.py` `_first_identifiers`), so every dropped identifier sorts after the
# largest kept one. A dropped CVE is possible only while that largest one sorts at or before
# the `CVE-` prefix. An adapter that cuts differently must be re-checked against this.
def cve_may_be_missing(observation: Observation) -> bool:
    """Return whether a CVE identifier may have been cut from this observation's list."""
    note = observation.metadata_value("truncated")
    if not note or not _names_source_identifiers(note):
        return False
    kept = observation.source_identifiers
    return not kept or max(kept)[: len(_CVE_PREFIX)] <= _CVE_PREFIX


def _names_source_identifiers(note: str) -> bool:
    """Return whether a truncation note names the identifier list, failing toward yes."""
    # SECURITY: On the --db path the note comes from stored events, bounded only by the event
    # cap, and json.loads raises RecursionError on 3.11 for a deeply nested value.
    if (
        len(note) > MAX_TRUNCATED_METADATA_BYTES
        or len(note.encode("utf-8", "surrogatepass")) > MAX_TRUNCATED_METADATA_BYTES
    ):
        return True
    try:
        names = json.loads(note)
    except (ValueError, TypeError, RecursionError):
        return True
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        return True
    return _SOURCE_IDENTIFIERS_KEY in names


# *--- Loader ---*


def load_kev_catalog(path: Path) -> KevCatalog:
    """Read one CISA KEV catalog from disk and validate it; nothing is ever fetched."""
    location = Path(path)
    # NOTE: read_bounded refuses a non-regular file with a plain ValueError, so it is wrapped
    # beside OSError; InputLimitError is a ValueError too.
    try:
        content = read_bounded(location, KEV_LIMITS)
    except InputLimitError as exc:
        raise ReportInputError(f"KEV catalog exceeds a limit: {_detail(exc)}") from exc
    except (OSError, ValueError) as exc:
        raise ReportInputError(f"KEV catalog cannot be read: {_detail(exc)}") from exc
    return parse_kev_catalog(content, name=location.name)


def parse_kev_catalog(content: bytes, *, name: str) -> KevCatalog:
    """Validate the bytes of one CISA KEV JSON feed into an immutable catalog.

    Exported, so it bounds itself: `safeio.parse_json_bounded` never checks size.
    """
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if not isinstance(name, str) or not name.strip():
        raise ReportInputError("KEV catalog name must not be blank")
    if len(content) > MAX_KEV_CATALOG_BYTES:
        raise ReportInputError(
            f"KEV catalog is {len(content)} bytes; maximum is {MAX_KEV_CATALOG_BYTES} bytes"
        )
    # Identity is the raw bytes, taken before safeio strips a BOM (decision 3).
    digest = hashlib.sha256(content).hexdigest()
    try:
        value = parse_json_bounded(content, KEV_LIMITS)
    except InputLimitError as exc:
        raise ReportInputError(f"KEV catalog exceeds a limit: {_detail(exc)}") from exc
    except (ValueError, RecursionError) as exc:
        raise ReportInputError(f"KEV catalog must be the CISA JSON feed: {_detail(exc)}") from exc
    # NOTE: The year window keeps every date clear of overflow; this block is the backstop,
    # since OverflowError is not a ValueError and would otherwise escape as a traceback.
    try:
        return _parse_catalog(value, name=name, sha256=digest, size_bytes=len(content))
    except ReportInputError:
        raise
    except (ValueError, RecursionError, OverflowError) as exc:
        raise ReportInputError(f"KEV catalog is invalid: {_detail(exc)}") from exc


def _parse_catalog(value: Any, *, name: str, sha256: str, size_bytes: int) -> KevCatalog:
    if not isinstance(value, dict):
        raise ReportInputError(
            f"KEV catalog must be the CISA JSON feed: the top level is {_json_type(value)}, "
            "not an object"
        )
    catalog_version = _matching(
        _string(value, "catalogVersion", ""),
        _CATALOG_VERSION,
        "",
        "catalogVersion",
        "1 to 64 printable ASCII characters with no spaces",
    )
    date_released = _date_released(_string(value, "dateReleased", ""))
    declared_count = _count(value)

    raw_entries = value.get("vulnerabilities")
    if not isinstance(raw_entries, list):
        raise _refusal("", f"vulnerabilities must be an array, got {_json_type(raw_entries)}")
    if len(raw_entries) > MAX_KEV_ENTRIES:
        raise _refusal(
            "", f"vulnerabilities holds {len(raw_entries)} entries; maximum is {MAX_KEV_ENTRIES}"
        )
    if declared_count != len(raw_entries):
        raise _refusal(
            "", f"count is {declared_count} but vulnerabilities holds {len(raw_entries)} entries"
        )

    first_seen: dict[str, int] = {}
    entries: list[KevEntry] = []
    for index, raw_entry in enumerate(raw_entries):
        entry = _parse_entry(raw_entry, index)
        if entry.cve_id in first_seen:
            raise _refusal(
                f"vulnerabilities[{index}] ({entry.cve_id})",
                f"cveID repeats vulnerabilities[{first_seen[entry.cve_id]}]",
            )
        first_seen[entry.cve_id] = index
        entries.append(entry)

    return KevCatalog(
        name=name,
        sha256=sha256,
        size_bytes=size_bytes,
        catalog_version=catalog_version,
        date_released=date_released,
        declared_count=declared_count,
        entries=tuple(sorted(entries, key=lambda entry: entry.cve_id)),
    )


def _parse_entry(raw_entry: Any, index: int) -> KevEntry:
    where = f"vulnerabilities[{index}]"
    if not isinstance(raw_entry, dict):
        raise _refusal(where, f"the entry must be an object, got {_json_type(raw_entry)}")
    cve_id = _matching(_string(raw_entry, "cveID", where), _CVE_ID, where, "cveID", "CVE-YYYY-NNNN")
    # A refusal names the cveID only once it has passed validation.
    where = f"{where} ({cve_id})"
    return KevEntry(
        cve_id=cve_id,
        date_added=_date(raw_entry, "dateAdded", where),
        due_date=_date(raw_entry, "dueDate", where),
        known_ransomware_campaign_use=_label(raw_entry, "knownRansomwareCampaignUse", where),
        forensic_triage=_label(raw_entry, "forensicTriage", where),
    )


# *--- Field Rules ---*


def _string(raw: Mapping[str, Any], key: str, where: str) -> str:
    """Return a required field that must be a JSON string, checked before any pattern."""
    if key not in raw:
        raise _refusal(where, f"{key} is required")
    value = raw[key]
    if not isinstance(value, str):
        raise _refusal(where, f"{key} must be a JSON string, got {_json_type(value)}")
    return value


def _matching(value: str, pattern: re.Pattern[str], where: str, key: str, shape: str) -> str:
    if pattern.fullmatch(value) is None:
        raise _refusal(where, f"{key} must be {shape}, got {_excerpt(value)}")
    return value


def _date(raw: Mapping[str, Any], key: str, where: str) -> date:
    # `date.fromisoformat` accepts "20260915" and "2026-W38-2", so the shape is checked first.
    value = _matching(_string(raw, key, where), _DATE, where, key, "a YYYY-MM-DD date")
    try:
        day = date.fromisoformat(value)
    except ValueError:
        raise _refusal(where, f"{key} must be a real calendar date, got {value!r}") from None
    if not MIN_CLOCK_YEAR <= day.year <= MAX_CLOCK_YEAR:
        raise _refusal(where, f"{key} must fall in {_year_window()}, got {value!r}")
    return day


def _date_released(value: str) -> datetime:
    # parse_rfc3339 quotes its whole input, so the length is checked before anything quotes it.
    if len(value) > MAX_DATE_RELEASED_CHARS:
        raise _refusal("", f"dateReleased must be at most {MAX_DATE_RELEASED_CHARS} characters")
    _matching(value, _DATE_RELEASED, "", "dateReleased", "an RFC 3339 timestamp")
    try:
        parsed = parse_rfc3339(value, "dateReleased")
    except ReportInputError:
        raise _refusal("", f"dateReleased must be a real RFC 3339 instant, got {value!r}") from None
    # NOTE: Year 1 with a positive offset and year 9999 with a negative one overflow here.
    try:
        released = parsed.astimezone(UTC)
    except OverflowError:
        released = None
    if released is None or not MIN_CLOCK_YEAR <= released.year <= MAX_CLOCK_YEAR:
        raise _refusal("", f"dateReleased must fall in {_year_window()} UTC, got {value!r}")
    return released


def _count(raw: Mapping[str, Any]) -> int:
    if "count" not in raw:
        raise _refusal("", "count is required")
    value = raw["count"]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _refusal("", f"count must be a JSON integer, got {_json_type(value)}")
    if value < 0:
        raise _refusal("", f"count must not be negative, got {value}")
    return value


def _label(raw: Mapping[str, Any], key: str, where: str) -> str | None:
    """Return an optional short label; a JSON null is refused, not read as absent."""
    if key not in raw:
        return None
    return _matching(
        _string(raw, key, where), _LABEL, where, key, "1 to 32 printable ASCII characters"
    )


# *--- Messages ---*


def _refusal(where: str, problem: str) -> ReportInputError:
    location = f" {where}" if where else ""
    return ReportInputError(f"KEV catalog{location}: {problem}")


def _excerpt(value: str) -> str:
    """Quote an unvalidated string as a repr cut to MAX_QUOTED_CHARS characters."""
    text = repr(value[:MAX_QUOTED_CHARS])
    if len(text) <= MAX_QUOTED_CHARS:
        return text
    return f"{text[: MAX_QUOTED_CHARS - 3]}..."


def _detail(exc: BaseException) -> str:
    """Return an exception's text as cut, printable ASCII, since it may quote the input."""
    raw = str(exc)
    text = ascii(raw[:MAX_DETAIL_CHARS])[1:-1]
    if len(raw) > MAX_DETAIL_CHARS or len(text) > MAX_DETAIL_CHARS:
        return f"{text[: MAX_DETAIL_CHARS - 3]}..."
    return text


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int | float):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    if isinstance(value, dict):
        return "an object"
    return type(value).__name__


def _year_window() -> str:
    return f"the years {MIN_CLOCK_YEAR} through {MAX_CLOCK_YEAR}"


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "KEV_LIMITS",
    "KEV_STALE_AFTER",
    "KEV_STOPS",
    "MAX_KEV_CATALOG_BYTES",
    "MAX_KEV_ENTRIES",
    "KevCatalog",
    "KevClock",
    "KevEntry",
    "KevStatus",
    "cve_may_be_missing",
    "due_instant",
    "kev_clock",
    "load_kev_catalog",
    "parse_kev_catalog",
    "start_instant",
]
