# ******************************************************************************
# *Title: Adapter Common Helpers*
# *Author: Kyle Versluis*
# *Description: Observation-building helpers shared by the source adapters.*
# ******************************************************************************
"""Helpers shared by the source adapters."""

# *--- Imports ---*

from __future__ import annotations

import heapq
import json
import re
import reprlib
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from itertools import islice
from typing import Any

from complyroll.models import Observation, ObservationDisposition, ResourceRef, SourceSeverity

from .base import ArtifactProvenance, DiagnosticLevel, IngestDiagnostic
from .safeio import IngestLimits, InputLimitError

# *--- Configuration ---*

MAX_IDENTITY_CHARS = 512
MAX_TITLE_CHARS = 512
MAX_DESCRIPTION_CHARS = 4_096
MAX_METADATA_VALUE_CHARS = 512
MAX_LIST_ITEMS = 64
MAX_LIST_ITEM_CHARS = 256
MAX_OBSERVATION_JSON_BYTES = 512 * 1024
TRUNCATION_MARKER = "...[truncated]"
# A coalesced diagnostic names at most this many JSON paths.
MAX_DIAGNOSTIC_PATHS = 5
# Source clocks are kept only inside these UTC years, well clear of the year 1 and year 9999
# edges where the UTC conversion and the deadline arithmetic overflow.
MIN_CLOCK_YEAR = 1970
MAX_CLOCK_YEAR = 9000

SEVERITY_RANK = {
    SourceSeverity.CRITICAL: 5,
    SourceSeverity.HIGH: 4,
    SourceSeverity.MEDIUM: 3,
    SourceSeverity.LOW: 2,
    SourceSeverity.INFORMATIONAL: 1,
    SourceSeverity.UNKNOWN: 0,
}
EVIDENCE_SANITIZED_SUMMARY = (
    "control, format, or separator characters were removed from evidence text"
)
EVIDENCE_TRUNCATED_SUMMARY = (
    "evidence text was cut at its cap; the truncated metadata key names the members"
)

_PROHIBITED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_LINE_BREAK_CATEGORIES = frozenset({"Zl", "Zp"})
_KEPT_CONTROLS = frozenset({"\t", "\n"})

# SECURITY: Every pattern is fixed and anchored on token boundaries; none is built from input.
# Letters and digits are ASCII only: \d also matches other scripts' digits, and a case-blind
# letter class also matches U+0130, U+0131, U+017F, and U+212A, so either would let a lookalike
# become a placeholder or an identifier. A CVE sequence number has 4 to 19 digits, the bound
# of the cveId pattern in the CVE record format.
CVE = re.compile(r"(?<![A-Za-z0-9])CVE-([0-9]{4})-([0-9]{4,19})(?![0-9])", re.IGNORECASE | re.ASCII)
GHSA = re.compile(
    r"(?<![A-Za-z0-9])GHSA(?:-[A-Za-z0-9]{4}){3}(?![A-Za-z0-9])", re.IGNORECASE | re.ASCII
)
CWE = re.compile(r"(?<![A-Za-z0-9])CWE-([0-9]{1,5})(?![0-9])", re.IGNORECASE | re.ASCII)
# The spec's end-of-day clock, 24:00 with zero seconds, and any hour 24 fromisoformat reads:
# one of its date forms, one separator character of any kind, then the hour.
END_OF_DAY = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2})T24(:00(?::00(?:\.0+)?)?)((?:[Z+-].*)?)", re.DOTALL
)
HOUR_24 = re.compile(
    r"[0-9]{4}(?:-[0-9]{2}-[0-9]{2}|[0-9]{4}|-?W[0-9]{2}(?:-?[0-9])?).24", re.DOTALL
)

# *--- Types ---*


class IdentityRefused(Exception):
    """Raised once identity_input_invalid is recorded; the enclosing run or result stops."""


@dataclass(frozen=True, slots=True)
class Cleaned:
    """Evidence texts sanitized and capped once, with what every use of them reports."""

    items: tuple[str, ...]
    # How many texts lost characters to sanitizing and how many were cut at their cap, and
    # whether the first cut came before the first sanitizing.
    sanitized: int
    cut: int
    cut_first: bool

    @property
    def text(self) -> str:
        """Return the kept text of a single evidence value, or empty text."""
        return self.items[0] if self.items else ""


@dataclass(slots=True)
class DiagnosticEntry:
    level: DiagnosticLevel
    summary: str
    detail: str
    count: int = 0
    paths: list[str] = field(default_factory=list)
    fixed: IngestDiagnostic | None = None


# Every code is reported once per artifact with a count, its first MAX_DIAGNOSTIC_PATHS JSON
# paths, and its first detail, and each path and the detail are cut at
# MAX_METADATA_VALUE_CHARS. One code's message is its summary, a frame with the count's digits,
# the paths with their separators, and the detail, so an artifact's diagnostics come to at most
# 55,727 characters plus the count digits, and 117 for the two fixed messages (decision 9).
class Diagnostics:
    """Per-artifact diagnostic coalescer that keeps first-seen order."""

    def __init__(self) -> None:
        self._entries: dict[str, DiagnosticEntry] = {}

    def add(
        self,
        level: DiagnosticLevel,
        code: str,
        summary: str,
        path: str,
        detail: str = "",
        count: int = 1,
    ) -> None:
        """Count occurrences of a code at a JSON path, as if each were added in turn."""
        entry = self._entries.get(code)
        if entry is None:
            entry = DiagnosticEntry(level, summary, diagnostic_text(detail))
            self._entries[code] = entry
        entry.count += count
        room = min(count, MAX_DIAGNOSTIC_PATHS - len(entry.paths))
        if room > 0:
            entry.paths.extend([diagnostic_text(path)] * room)

    def add_fixed(self, diagnostic: IngestDiagnostic) -> None:
        """Record a diagnostic that is emitted verbatim, once per artifact."""
        if diagnostic.code not in self._entries:
            self._entries[diagnostic.code] = DiagnosticEntry(
                diagnostic.level, diagnostic.message, "", fixed=diagnostic
            )

    @property
    def has_errors(self) -> bool:
        return any(entry.level is DiagnosticLevel.ERROR for entry in self._entries.values())

    def emit(self, location: str) -> tuple[IngestDiagnostic, ...]:
        """Render every code once, in the order it was first seen."""
        rendered: list[IngestDiagnostic] = []
        for code, entry in self._entries.items():
            if entry.fixed is not None:
                rendered.append(entry.fixed)
                continue
            noun = "occurrence" if entry.count == 1 else "occurrences"
            paths = ", ".join(entry.paths)
            if entry.count > len(entry.paths):
                paths += ", ..."
            detail = f"; first: {entry.detail}" if entry.detail else ""
            message = f"{entry.summary} ({entry.count} {noun}: {paths}{detail})"
            rendered.append(IngestDiagnostic(entry.level, code, message, location))
        return tuple(rendered)


# *--- Helper Functions ---*


def text_of(value: object) -> str:
    """Return the stripped text of a string value; anything else is empty text."""
    return value.strip() if isinstance(value, str) else ""


def unique(values: list[str]) -> tuple[str, ...]:
    """Drop empty and repeated values while keeping first-seen order."""
    return tuple(dict.fromkeys(value for value in values if value))


def parse_timestamp(value: object) -> datetime | None:
    """Parse an aware ISO 8601 timestamp; naive or unparsable text counts as absent."""
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


# *--- Text Hygiene ---*


# SECURITY: Identity inputs are refused, never repaired. A control, format, surrogate, or
# line-separator code point, or an over-cap length, fails the artifact closed (decision 10).
def identity_problem(value: str, cap: int) -> str | None:
    """Describe why text cannot be an identity input, or None when it can."""
    if len(value) > cap:
        return f"is {len(value)} characters; maximum is {cap}"
    if value.isascii() and value.isprintable():
        return None
    for char in value:
        if unicodedata.category(char) in _PROHIBITED_CATEGORIES:
            return f"contains prohibited code point U+{ord(char):04X}"
    return None


def sanitize(text: str) -> tuple[str, bool]:
    """Strip Cc (except tab and newline), Cf, and Cs; map Zl and Zp to newline."""
    if text.isascii() and text.isprintable():
        return text, False
    kept: list[str] = []
    changed = False
    for char in text:
        category = unicodedata.category(char)
        if category in _LINE_BREAK_CATEGORIES:
            kept.append("\n")
            changed = True
        elif category in _PROHIBITED_CATEGORIES and char not in _KEPT_CONTROLS:
            changed = True
        else:
            kept.append(char)
    return "".join(kept), changed


# Text shorter than the cap less the marker comes back whole with the marker after it, so the
# result stays under the cap.
def truncate(text: str, cap: int) -> str:
    """Cut text at the cap less the marker and append the marker, never passing the cap."""
    return text[: cap - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def clean(values: Iterable[object], cap: int) -> Cleaned:
    """Sanitize, strip, and cap each string value, counting what was removed or cut."""
    items: list[str] = []
    sanitized = cut = 0
    cut_first = False
    for value in values:
        text = text_of(value)
        if not text:
            continue
        cleaned, changed = sanitize(text)
        cleaned = cleaned.strip()
        sanitized += changed
        if len(cleaned) > cap:
            cleaned = truncate(cleaned, cap)
            if not cut:
                cut_first = not sanitized
            cut += 1
        if cleaned:
            items.append(cleaned)
    return Cleaned(tuple(items), sanitized, cut, cut_first)


def encode_list(items: Iterable[Any]) -> str:
    return json.dumps(list(items), ensure_ascii=False, separators=(",", ":"))


# SECURITY: A path can embed a producer key and a detail quotes a producer value, so both are
# sanitized and cut before a diagnostic stores them (decision 9).
def diagnostic_text(text: str) -> str:
    """Sanitize one diagnostic path or detail and cut it at MAX_METADATA_VALUE_CHARS."""
    cleaned, _changed = sanitize(text)
    if len(cleaned) > MAX_METADATA_VALUE_CHARS:
        return truncate(cleaned, MAX_METADATA_VALUE_CHARS)
    return cleaned


class DetailRepr(reprlib.Repr):
    """A reprlib.Repr that renders an object's first members in insertion order."""

    def repr_dict(self, x: dict[Any, Any], level: int) -> str:
        if not x:
            return "{}"
        if level <= 0:
            return "{" + self.fillvalue + "}"
        pieces = [
            f"{self.repr1(key, level - 1)}: {self.repr1(value, level - 1)}"
            for key, value in islice(x.items(), self.maxdict)
        ]
        if len(x) > self.maxdict:
            pieces.append(self.fillvalue)
        return "{" + ", ".join(pieces) + "}"


# NOTE: reprlib renders a container from its first few members at a bounded depth, but its
# own object rendering sorts every key first; this one reads only the first members, in their
# own order. The other reprlib limits still apply, so an integer longer than 40 characters or a
# member deeper than six levels is shortened even in a small container.
_DETAIL_REPR = DetailRepr()
_DETAIL_REPR.maxstring = MAX_METADATA_VALUE_CHARS
_DETAIL_REPR.maxother = MAX_METADATA_VALUE_CHARS


def quoted(value: object) -> str:
    """Return the repr a diagnostic detail quotes, reading only a bounded part of the value."""
    if isinstance(value, str):
        # One past the detail cap, so an over-cap value is still cut with the marker.
        return repr(value[: MAX_METADATA_VALUE_CHARS + 1])
    if isinstance(value, (list, Mapping)):
        return _DETAIL_REPR.repr(value)
    # A JSON number carries at most the parser's integer digit limit, so its repr is bounded.
    return repr(value)


# *--- Timestamps ---*


# The contract regex and the canonical round trip both refuse a seconds-bearing offset, which
# Python's parser accepts; the check lives here so no adapter writes an observed_at the
# store would refuse (decision 8).
def parse_clock(value: object) -> datetime | None:
    """Parse an aware timestamp with a whole-minute offset inside the supported years."""
    text = value.strip() if isinstance(value, str) else ""
    # NOTE: Spec 3.9 lets hour 24 name the midnight that ends a day, but fromisoformat reads
    # it only from Python 3.14, in every spelling. So the spec's 24:00 with zero seconds is
    # read here as the next day's 00:00, and any other hour 24 is refused, on every version.
    end_of_day = END_OF_DAY.fullmatch(text)
    if end_of_day is not None:
        day, clock, zone = end_of_day.groups()
        parsed = parse_timestamp(f"{day}T00{clock}{zone}")
    elif HOUR_24.match(text):
        return None
    else:
        parsed = parse_timestamp(value)
    if parsed is None:
        return None
    offset = parsed.utcoffset()
    if offset is None or offset % timedelta(minutes=1):
        return None
    # NOTE: Only instants from 1970 through 9000 UTC are kept. Year 1 with a positive offset
    # overflows the UTC conversion, and year 9999 overflows the later deadline arithmetic.
    try:
        if end_of_day is not None:
            parsed += timedelta(days=1)
        instant = parsed.astimezone(UTC)
    except OverflowError:
        return None
    if not MIN_CLOCK_YEAR <= instant.year <= MAX_CLOCK_YEAR:
        return None
    return parsed


# Two clocks can name one instant under different offsets, and min alone keeps whichever it
# meets first, so the text breaks the tie: the kept spelling depends only on the set of clocks,
# never on the order of results, runs, or invocations (decision 8).
def earliest(clocks: Iterable[datetime]) -> datetime:
    """Return the earliest clock and, of one instant's spellings, the one whose text sorts first."""
    return min(clocks, key=lambda clock: (clock, clock.isoformat()))


# *--- Identifier Extraction ---*


def extract_identifiers(texts: Iterable[str]) -> set[str]:
    """Pull CVE, GHSA, and CWE identifiers out of free text, normalized."""
    found: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in CVE.finditer(text):
            found.add(f"CVE-{match.group(1)}-{match.group(2)}")
        for match in GHSA.finditer(text):
            found.add(f"GHSA-{match.group(0)[5:].lower()}")
        for match in CWE.finditer(text):
            found.add(f"CWE-{int(match.group(1))}")
    return found


# Each of the first MAX_LIST_ITEMS of a union has fewer than MAX_LIST_ITEMS smaller members,
# so it is among the first MAX_LIST_ITEMS of its own part: cutting every part and then the
# union keeps exactly what cutting the whole union keeps (decision 5).
def first_identifiers(found: Iterable[str]) -> tuple[tuple[str, ...], bool]:
    """Return the first MAX_LIST_ITEMS distinct identifiers, sorted, and whether any was cut."""
    smallest = heapq.nsmallest(MAX_LIST_ITEMS + 1, set(found))
    return tuple(smallest[:MAX_LIST_ITEMS]), len(smallest) > MAX_LIST_ITEMS


# *--- Observation Construction ---*


# The observation id derives from the fingerprint, so the record is built once with a
# placeholder id and then replaced with the id it derives for itself.
def make_observation(
    *,
    artifact: ArtifactProvenance,
    source_type: str,
    source_tool: str,
    source_record_id: str,
    resource_id: str,
    resource_type: str = "host",
    observed_at: datetime | None,
    ingested_at: datetime,
    disposition: ObservationDisposition,
    severity: SourceSeverity,
    title: str,
    description: str,
    identifiers: tuple[str, ...],
    context_key: str,
    metadata: Mapping[str, str] | None = None,
) -> Observation:
    """Build one observation with its derived identity from adapter-supplied fields."""
    observation = Observation(
        observation_id="pending",
        source_type=source_type,
        source_tool=source_tool,
        parser_name=artifact.parser_name,
        parser_version=artifact.parser_version,
        source_record_id=source_record_id,
        resource=ResourceRef(resource_id=resource_id, resource_type=resource_type),
        observed_at=observed_at,
        ingested_at=ingested_at,
        disposition=disposition,
        source_severity=severity,
        title=title,
        description=description,
        source_artifact_digest=artifact.digest_sha256,
        source_artifact_name=artifact.name,
        source_identifiers=identifiers,
        source_metadata=tuple(sorted((metadata or {}).items())),
        context_key=context_key,
    )
    return replace(observation, observation_id=observation.derived_observation_id)


def missing_time_diagnostic(artifact: ArtifactProvenance) -> IngestDiagnostic:
    """Return the warning every adapter emits when an artifact declares no scan time."""
    return IngestDiagnostic(
        DiagnosticLevel.WARNING,
        "source_timestamp_missing",
        "source artifact does not declare an observation timestamp; observed_at is unknown",
        artifact.name,
    )


def observation_bytes(observation: Observation, *, ceiling: int, budget: int, spent: int) -> int:
    """Return an observation's canonical JSON size, refusing it past the ceiling or the budget."""
    # WARN: The caps of decision 9 count characters, not bytes. A quote or backslash in a
    # list item is escaped twice and costs four bytes, as four-byte text does, so text at
    # every cap can pass this ceiling, ASCII or not, and then the artifact fails closed the
    # same way on the stateless and persisted paths (decision 9).
    size = len(observation.to_canonical_json().encode("utf-8"))
    if size > ceiling:
        raise InputLimitError(
            f"observation {observation.observation_id} is {size} bytes of canonical JSON; "
            f"maximum is {ceiling}"
        )
    # SECURITY: The sum is checked as each observation is built, so the artifact fails
    # closed before its observations hold much more than the budget (decision 9).
    if spent + size > budget:
        raise InputLimitError(f"artifact yields more than {budget} bytes of observation JSON")
    return size


# *--- Evidence Parse ---*


class EvidenceParse:
    """One artifact's shared parse state: provenance, limits, and coalesced diagnostics."""

    def __init__(
        self, artifact: ArtifactProvenance, ingested_at: datetime, limits: IngestLimits
    ) -> None:
        self.artifact = artifact
        self.ingested_at = ingested_at
        self.limits = limits
        self.diagnostics = Diagnostics()
        self.observation_bytes = 0

    # A shared uri's checks are kept in its run's memo, so the text is checked once however
    # many results or locations use it, and each use is still refused or warned at its own path.
    def _require_identity(
        self,
        value: str,
        cap: int,
        what: str,
        path: str,
        memo: dict[str, str | None] | None = None,
    ) -> None:
        """Record identity_input_invalid and stop when text cannot be an identity input."""
        if memo is None:
            problem = identity_problem(value, cap)
        elif value in memo:
            problem = memo[value]
        else:
            problem = memo[value] = identity_problem(value, cap)
        if problem is None:
            return
        self.diagnostics.add(
            DiagnosticLevel.ERROR,
            "identity_input_invalid",
            "an identity input cannot be used as written",
            path,
            detail=f"{what} {problem}",
        )
        raise IdentityRefused(what)

    def _evidence(
        self, value: object, cap: int, member: str, path: str, truncated: set[str]
    ) -> str:
        """Sanitize and cap one evidence text, recording what was removed or cut."""
        cleaned = clean((value,), cap)
        self._replay(cleaned, member, path, truncated)
        return cleaned.text

    def _evidence_list(
        self, values: Iterable[Any], member: str, path: str, truncated: set[str]
    ) -> tuple[str, ...]:
        """Sanitize and cap every string of a list-valued member."""
        cleaned = clean(values, MAX_LIST_ITEM_CHARS)
        self._replay(cleaned, member, path, truncated)
        return cleaned.items

    def _scalar(
        self, scalars: dict[str, str], key: str, value: object, path: str, truncated: set[str]
    ) -> None:
        """Store one non-uri scalar metadata value when it is present."""
        cleaned = clean((value,), MAX_METADATA_VALUE_CHARS)
        self._keep_scalar(scalars, key, cleaned, path, truncated)

    def _keep_scalar(
        self, scalars: dict[str, str], key: str, cleaned: Cleaned, path: str, truncated: set[str]
    ) -> None:
        """Store one cleaned scalar metadata value when it is present."""
        self._replay(cleaned, key, path, truncated)
        if cleaned.text:
            scalars[key] = cleaned.text

    # A shared text is cleaned once, so each result that carries it reports that cleaning at
    # its own path. Same-path reports coalesce, so the counts in first-seen order are exactly
    # what cleaning each text again here would have added.
    def _replay(self, cleaned: Cleaned, member: str, path: str, truncated: set[str]) -> None:
        """Record what cleaning removed or cut, as if the texts were cleaned at this path."""
        if not cleaned.sanitized and not cleaned.cut:
            return
        reports = [
            ("evidence_sanitized", EVIDENCE_SANITIZED_SUMMARY, cleaned.sanitized),
            ("evidence_truncated", EVIDENCE_TRUNCATED_SUMMARY, cleaned.cut),
        ]
        if cleaned.cut_first:
            reports.reverse()
        for code, summary, count in reports:
            if count:
                self.diagnostics.add(DiagnosticLevel.WARNING, code, summary, path, count=count)
        if cleaned.cut:
            truncated.add(member)

    def _cut(self, items: list[Any], member: str, path: str, truncated: set[str]) -> list[Any]:
        """Cut a list-valued member at MAX_LIST_ITEMS."""
        if len(items) <= MAX_LIST_ITEMS:
            return items
        truncated.add(member)
        self.diagnostics.add(
            DiagnosticLevel.WARNING, "evidence_truncated", EVIDENCE_TRUNCATED_SUMMARY, path
        )
        return items[:MAX_LIST_ITEMS]

    def _clock(self, value: object, path: str) -> datetime | None:
        """Parse one source clock; a present but unusable value is diagnosed and absent."""
        if value is None:
            return None
        parsed = parse_clock(value)
        if parsed is None:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "source_timestamp_invalid",
                "clock value is not an aware timestamp with a whole-minute offset in the years "
                f"{MIN_CLOCK_YEAR} to {MAX_CLOCK_YEAR} UTC; ignored",
                path,
            )
        return parsed
