# ******************************************************************************
# *Title: SARIF Adapter*
# *Author: Kyle Versluis*
# *Description: SARIF 2.1.0 adapter on the ADR 0002 observation identity.*
# ******************************************************************************
"""SARIF 2.1.0 source adapter (ADR 0011)."""

# *--- Imports ---*

from __future__ import annotations

import heapq
import json
import math
import re
import reprlib
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cached_property
from itertools import islice
from typing import Any, TypeVar

from complyroll.models import Observation, ObservationDisposition, SourceSeverity

from .base import (
    AdapterOutput,
    AdapterParseError,
    ArtifactProvenance,
    DiagnosticLevel,
    IngestDiagnostic,
    ParsedDocument,
)
from .common import make_observation, missing_time_diagnostic, parse_timestamp, text_of
from .safeio import DEFAULT_LIMITS, IngestLimits, InputLimitError

# *--- Configuration ---*

# The parser version is an observation identity input (ADR 0002), so SARIF owns its own:
# a SARIF correction can never re-mint a CKLB, CKL, or XCCDF observation.
SARIF_PARSER_VERSION = "1"
SARIF_MEDIA_TYPE = "application/sarif+json"
SARIF_SOURCE_TYPE = "sarif"
SARIF_VERSION = "2.1.0"

MAX_IDENTITY_CHARS = 512
MAX_URI_CHARS = 2_048
MAX_LOCATIONS_PER_RESULT = 256
MAX_MESSAGE_ARGUMENTS = 32
# One expansion substitutes at most this many placeholders. An empty argument adds no text,
# so the description budget alone would not stop a template made of placeholders.
MAX_MESSAGE_PLACEHOLDERS = 1_024
MAX_TITLE_CHARS = 512
MAX_DESCRIPTION_CHARS = 4_096
MAX_METADATA_VALUE_CHARS = 512
MAX_LIST_ITEMS = 64
MAX_LIST_ITEM_CHARS = 256
# A region line or column above the signed 32-bit range is absent, so a region's text stays
# short enough to prefix a location message inside MAX_LIST_ITEM_CHARS.
MAX_REGION_INTEGER = 2**31 - 1
MAX_OBSERVATION_JSON_BYTES = 512 * 1024
TRUNCATION_MARKER = "...[truncated]"
# A coalesced diagnostic names at most this many JSON paths.
MAX_DIAGNOSTIC_PATHS = 5
# SARIF clocks are kept only inside these UTC years, well clear of the year 1 and year 9999
# edges where the UTC conversion and the deadline arithmetic overflow.
MIN_CLOCK_YEAR = 1970
MAX_CLOCK_YEAR = 9000

RESOURCE_TYPE_IMAGE = "image"
RESOURCE_TYPE_FILE = "file"
RESOURCE_TYPE_LOGICAL = "logical"
RESOURCE_TYPE_SCAN = "scan"

# The fixed metadata vocabulary: a producer can never mint a key (decision 9).
METADATA_KEYS = frozenset(
    {
        "tool_version",
        "tool_semantic_version",
        "tool_information_uri",
        "run_indexes",
        "automation_id",
        "automation_category",
        "image_name",
        "image_digests",
        "repository_uri",
        "revision_id",
        "rule_component",
        "rule_name",
        "rule_help_uri",
        "rule_tags",
        "rule_deprecated_ids",
        "result_kind",
        "result_kinds",
        "level",
        "level_source",
        "security_severity",
        "severity_source",
        "baseline_state",
        "guid",
        "correlation_guid",
        "fingerprints",
        "partial_fingerprints",
        "taxa",
        "suppressed",
        "suppression_kinds",
        "suppression_statuses",
        "location_uri",
        "uri_base_id",
        "uri_base",
        "logical_locations",
        "regions",
        "location_messages",
        "occurrence_count",
        "truncated",
    }
)

_KIND_DISPOSITIONS = {
    "fail": ObservationDisposition.OPEN,
    "pass": ObservationDisposition.PASS,
    "notApplicable": ObservationDisposition.NOT_APPLICABLE,
    "review": ObservationDisposition.NOT_REVIEWED,
    "informational": ObservationDisposition.NOT_REVIEWED,
    "open": ObservationDisposition.UNKNOWN,
}
_LEVEL_SEVERITIES = {
    "error": SourceSeverity.HIGH,
    "warning": SourceSeverity.MEDIUM,
    "note": SourceSeverity.LOW,
    "none": SourceSeverity.INFORMATIONAL,
}
# The worst disposition and the highest severity win a fold (decision 9).
_DISPOSITION_RANK = {
    ObservationDisposition.OPEN: 5,
    ObservationDisposition.UNKNOWN: 4,
    ObservationDisposition.NOT_REVIEWED: 3,
    ObservationDisposition.NOT_APPLICABLE: 2,
    ObservationDisposition.PASS: 1,
    ObservationDisposition.ERROR: 0,
}
_SEVERITY_RANK = {
    SourceSeverity.CRITICAL: 5,
    SourceSeverity.HIGH: 4,
    SourceSeverity.MEDIUM: 3,
    SourceSeverity.LOW: 2,
    SourceSeverity.INFORMATIONAL: 1,
    SourceSeverity.UNKNOWN: 0,
}
_SUPPRESSION_ACCEPTED = "accepted"
_SEMGREP_FINGERPRINT_PLACEHOLDER = "requires login"
_EVIDENCE_SANITIZED_SUMMARY = (
    "control, format, or separator characters were removed from evidence text"
)
_EVIDENCE_TRUNCATED_SUMMARY = (
    "evidence text was cut at its cap; the truncated metadata key names the members"
)

_PROHIBITED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_LINE_BREAK_CATEGORIES = frozenset({"Zl", "Zp"})
_KEPT_CONTROLS = frozenset({"\t", "\n"})
_LINK_ESCAPES = frozenset({"\\", "[", "]"})
_NO_REGION = (0, 0, 0, 0)

# SECURITY: Every pattern is fixed and anchored on token boundaries; none is built from input.
# Letters and digits are ASCII only: \d also matches other scripts' digits, and a case-blind
# letter class also matches U+0130, U+0131, U+017F, and U+212A, so either would let a lookalike
# become a placeholder or an identifier. A CVE sequence number has 4 to 19 digits, the bound
# of the cveId pattern in the CVE record format.
_PLACEHOLDER = re.compile(r"\{([0-9]{1,9})\}")
_BRACE = re.compile(r"[{}]")
_LINK_SPECIAL = re.compile(r"[\\\[\]]")
_LINK_TARGET = re.compile(r"\]\([0-9]{1,9}\)")
_CVE = re.compile(
    r"(?<![A-Za-z0-9])CVE-([0-9]{4})-([0-9]{4,19})(?![0-9])", re.IGNORECASE | re.ASCII
)
_GHSA = re.compile(
    r"(?<![A-Za-z0-9])GHSA(?:-[A-Za-z0-9]{4}){3}(?![A-Za-z0-9])", re.IGNORECASE | re.ASCII
)
_CWE = re.compile(r"(?<![A-Za-z0-9])CWE-([0-9]{1,5})(?![0-9])", re.IGNORECASE | re.ASCII)
# A security-severity string must be an ASCII decimal: float() also reads digit-group
# underscores, exponents, and other scripts' digits, so '0_9' would read as 9.0.
_DECIMAL = re.compile(r"[0-9]+(?:\.[0-9]+)?")
# The spec's end-of-day clock, 24:00 with zero seconds, and any hour 24 fromisoformat reads:
# one of its date forms, one separator character of any kind, then the hour.
_END_OF_DAY = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2})T24(:00(?::00(?:\.0+)?)?)((?:[Z+-].*)?)", re.DOTALL
)
_HOUR_24 = re.compile(
    r"[0-9]{4}(?:-[0-9]{2}-[0-9]{2}|[0-9]{4}|-?W[0-9]{2}(?:-?[0-9])?).24", re.DOTALL
)

# *--- Types ---*

_RegionKey = tuple[int, int, int, int]
_FoldKey = tuple[str, str, str, str, str]
_Part = TypeVar("_Part", str, tuple[str, str])


class _IdentityRefused(Exception):
    """Raised once identity_input_invalid is recorded; the enclosing run or result stops."""


@dataclass(frozen=True, slots=True)
class _Cleaned:
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


_NOTHING = _Cleaned((), 0, 0, False)


@dataclass(frozen=True, slots=True)
class _SecuritySeverity:
    """One security-severity property: its verbatim text, score, usability, and quoted detail."""

    verbatim: _Cleaned
    score: float | None
    usable: bool
    detail: str


@dataclass(slots=True)
class _Template:
    """A shared message template with its links flattened, and its expansion without arguments."""

    text: str
    bare: _Cleaned | None = None


@dataclass(slots=True)
class _RulePositions:
    """One component's descriptors by id and by guid; a value two of them carry maps to None."""

    by_id: dict[str, tuple[Mapping[str, Any], int] | None]
    by_guid: dict[str, tuple[Mapping[str, Any], int] | None]


# NOTE: The override match compares components by identity, so the keys hold id(component).
# Every component lives in the parsed document for the whole parse, so an id names one.
@dataclass(slots=True)
class _Overrides:
    """One invocation's first level per descriptor its overrides resolve to, by position."""

    levels: dict[tuple[int, int], tuple[str, _Cleaned]]


@dataclass(slots=True)
class _RunCache:
    """Lookups and memos over one run's shared tool data, each built on first use."""

    component_guids: dict[str, tuple[Mapping[str, Any], str]] | None = None
    rules: dict[str, _RulePositions] = field(default_factory=dict)
    overrides: dict[int, _Overrides] = field(default_factory=dict)
    components: dict[str, _ComponentMemo] = field(default_factory=dict)
    descriptors: dict[tuple[str, int], _DescriptorMemo] = field(default_factory=dict)
    artifact_uris: dict[int, str] = field(default_factory=dict)
    base_uris: dict[str, str] = field(default_factory=dict)
    # Every shared uri is checked at MAX_URI_CHARS, so its text alone keys its check.
    uri_problems: dict[str, str | None] = field(default_factory=dict)
    # A shared location uri's segment check, kept beside its identity check.
    uri_suspicious: dict[str, bool] = field(default_factory=dict)
    # A descriptor id is checked at MAX_IDENTITY_CHARS, so its text alone keys its check.
    rule_id_problems: dict[str, str | None] = field(default_factory=dict)


@dataclass(slots=True)
class _RunScope:
    """What one run says it scanned, resolved once and shared by every result in it."""

    index: int
    path: str
    driver: Mapping[str, Any]
    driver_name: str
    extensions: list[Any]
    components: list[tuple[str, Mapping[str, Any]]]
    artifacts: list[Any]
    invocations: list[Any]
    original_uri_base_ids: Mapping[str, Any]
    context_key: str
    image_name: str
    repository_uri: str
    clock: datetime | None
    scalars: dict[str, str]
    lists: dict[str, tuple[str, ...]]
    truncated: set[str]
    # Every result reads the run's shared tool data through this, so that text is read once.
    cache: _RunCache = field(default_factory=_RunCache)


@dataclass(frozen=True, slots=True)
class _RuleRef:
    """The component and descriptor one result resolves to, in the spec's order."""

    component: _ComponentMemo | None
    descriptor: _DescriptorMemo | None
    descriptor_index: int | None


@dataclass(slots=True)
class _Hit:
    """One resource a result's locations name, with the evidence gathered beside it."""

    resource_type: str
    resource_id: str
    regions: list[tuple[_RegionKey, str]]
    messages: list[tuple[_RegionKey, str]]
    scalars: dict[str, str]
    logical: list[str]
    truncated: set[str]


@dataclass(slots=True)
class _Candidate:
    """One result's contribution to one observation before folding."""

    order: tuple[Any, ...]
    path: str
    run_index: int
    kind: str
    disposition: ObservationDisposition
    severity: SourceSeverity
    severity_scalars: dict[str, str]
    observed_at: datetime | None
    title: str
    description: str
    # The first MAX_LIST_ITEMS identifiers in sorted order, and whether any was cut.
    identifiers: tuple[str, ...]
    identifiers_cut: bool
    scalars: dict[str, str]
    # Every list but a location's logical names arrives cut by _fold_part, and a run's or a
    # descriptor's is one tuple that every result carrying it shares.
    lists: dict[str, Sequence[str]]
    pairs: dict[str, Sequence[tuple[str, str]]]
    regions: list[tuple[_RegionKey, str]]
    messages: list[tuple[_RegionKey, str]]
    suppressed: str
    truncated: set[str]


@dataclass(slots=True)
class _DiagnosticEntry:
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
class _Diagnostics:
    """Per-artifact diagnostic coalescer that keeps first-seen order."""

    def __init__(self) -> None:
        self._entries: dict[str, _DiagnosticEntry] = {}

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
            entry = _DiagnosticEntry(level, summary, _diagnostic_text(detail))
            self._entries[code] = entry
        entry.count += count
        room = min(count, MAX_DIAGNOSTIC_PATHS - len(entry.paths))
        if room > 0:
            entry.paths.extend([_diagnostic_text(path)] * room)

    def add_fixed(self, diagnostic: IngestDiagnostic) -> None:
        """Record a diagnostic that is emitted verbatim, once per artifact."""
        if diagnostic.code not in self._entries:
            self._entries[diagnostic.code] = _DiagnosticEntry(
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


# *--- JSON Access ---*


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _sequence(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _natural(value: object) -> int | None:
    """Return a non-negative JSON integer; bools and everything else count as absent."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _property_texts(properties: Mapping[str, Any] | None) -> list[str]:
    """Collect the tag, cwe, and cve strings of a property bag for identifier extraction."""
    if properties is None:
        return []
    texts: list[str] = []
    for member in ("tags", "cwe", "cve"):
        value = properties.get(member)
        if isinstance(value, str):
            texts.append(value)
        else:
            texts.extend(item for item in _sequence(value) if isinstance(item, str))
    return texts


# *--- Text Hygiene ---*


# SECURITY: Identity inputs are refused, never repaired. A control, format, surrogate, or
# line-separator code point, or an over-cap length, fails the artifact closed (decision 10).
def _identity_problem(value: str, cap: int) -> str | None:
    """Describe why text cannot be an identity input, or None when it can."""
    if len(value) > cap:
        return f"is {len(value)} characters; maximum is {cap}"
    if value.isascii() and value.isprintable():
        return None
    for char in value:
        if unicodedata.category(char) in _PROHIBITED_CATEGORIES:
            return f"contains prohibited code point U+{ord(char):04X}"
    return None


# The uri is never opened, so a climbing segment is warned about and kept as written.
def _uri_is_suspicious(uri: str) -> bool:
    """Say whether a location uri has a '..' segment or a '//' prefix."""
    return uri.startswith("//") or ".." in uri.split("/")


def _sanitize(text: str) -> tuple[str, bool]:
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
def _truncate(text: str, cap: int) -> str:
    """Cut text at the cap less the marker and append the marker, never passing the cap."""
    return text[: cap - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def _clean(values: Iterable[object], cap: int) -> _Cleaned:
    """Sanitize, strip, and cap each string value, counting what was removed or cut."""
    items: list[str] = []
    sanitized = cut = 0
    cut_first = False
    for value in values:
        text = text_of(value)
        if not text:
            continue
        cleaned, changed = _sanitize(text)
        cleaned = cleaned.strip()
        sanitized += changed
        if len(cleaned) > cap:
            cleaned = _truncate(cleaned, cap)
            if not cut:
                cut_first = not sanitized
            cut += 1
        if cleaned:
            items.append(cleaned)
    return _Cleaned(tuple(items), sanitized, cut, cut_first)


def _encode_list(items: Iterable[Any]) -> str:
    return json.dumps(list(items), ensure_ascii=False, separators=(",", ":"))


# SECURITY: A path can embed a producer key and a detail quotes a producer value, so both are
# sanitized and cut before a diagnostic stores them (decision 9).
def _diagnostic_text(text: str) -> str:
    """Sanitize one diagnostic path or detail and cut it at MAX_METADATA_VALUE_CHARS."""
    cleaned, _changed = _sanitize(text)
    if len(cleaned) > MAX_METADATA_VALUE_CHARS:
        return _truncate(cleaned, MAX_METADATA_VALUE_CHARS)
    return cleaned


class _DetailRepr(reprlib.Repr):
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
_DETAIL_REPR = _DetailRepr()
_DETAIL_REPR.maxstring = MAX_METADATA_VALUE_CHARS
_DETAIL_REPR.maxother = MAX_METADATA_VALUE_CHARS


def _quoted(value: object) -> str:
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
# Python's parser accepts; the check lives here so SARIF never writes an observed_at the
# store would refuse (decision 8).
def _sarif_timestamp(value: object) -> datetime | None:
    """Parse an aware timestamp with a whole-minute offset inside the supported years."""
    text = value.strip() if isinstance(value, str) else ""
    # NOTE: Spec 3.9 lets hour 24 name the midnight that ends a day, but fromisoformat reads
    # it only from Python 3.14, in every spelling. So the spec's 24:00 with zero seconds is
    # read here as the next day's 00:00, and any other hour 24 is refused, on every version.
    end_of_day = _END_OF_DAY.fullmatch(text)
    if end_of_day is not None:
        day, clock, zone = end_of_day.groups()
        parsed = parse_timestamp(f"{day}T00{clock}{zone}")
    elif _HOUR_24.match(text):
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
def _earliest(clocks: Iterable[datetime]) -> datetime:
    """Return the earliest clock and, of one instant's spellings, the one whose text sorts first."""
    return min(clocks, key=lambda clock: (clock, clock.isoformat()))


# *--- Message Expansion ---*


# SECURITY: One left-to-right pass, never str.format: a substituted argument is never
# rescanned, so producer text cannot reach the formatter as a pattern (decision 5). A
# literal run is read only as far as the room left and at most MAX_MESSAGE_PLACEHOLDERS
# placeholders are substituted, so one pass costs the budget, never the template's size.
def _expand_message(text: str, arguments: list[Any]) -> tuple[str, bool]:
    """Replace {n} placeholders, unescape doubled braces, and say if the expansion was cut."""
    # One past the cap: an expansion that overruns it is then cut with the marker.
    budget = MAX_DESCRIPTION_CHARS + 1
    pieces: list[str] = []
    size = 0
    position = 0
    placeholders = 0
    cut = False
    length = len(text)
    while position < length and size < budget:
        room = budget - size
        char = text[position]
        if char == "{":
            if text.startswith("{{", position):
                piece = "{"
                position += 2
            else:
                match = _PLACEHOLDER.match(text, position)
                if match is None:
                    piece = "{"
                    position += 1
                elif placeholders == MAX_MESSAGE_PLACEHOLDERS:
                    return "".join(pieces), True
                else:
                    placeholders += 1
                    index = int(match.group(1))
                    argument = arguments[index] if index < len(arguments) else None
                    if index < MAX_MESSAGE_ARGUMENTS and isinstance(argument, str):
                        piece = argument
                    else:
                        piece = match.group(0)
                    position = match.end()
        elif char == "}":
            piece = "}"
            position += 2 if text.startswith("}}", position) else 1
        else:
            brace = _BRACE.search(text, position, position + room)
            end = brace.start() if brace is not None else min(length, position + room)
            piece = text[position:end]
            position = end
        if len(piece) > room:
            piece = piece[:room]
            cut = True
        pieces.append(piece)
        size += len(piece)
    # Template left unread once the budget is spent is text the expansion never produced.
    return "".join(pieces), cut or position < length


def _description(template: str, arguments: list[Any]) -> _Cleaned:
    """Expand a flattened template and clean it as a description."""
    expanded, cut = _expand_message(template, arguments)
    cleaned = _clean((expanded,), MAX_DESCRIPTION_CHARS)
    if not cut or cleaned.cut:
        return cleaned
    # WARN: A placeholder cap stop is inside the cap, and cleaning can shorten an overrun back
    # under it; either way text went unread, so the cut is marked here rather than lost.
    text = _truncate(cleaned.text, MAX_DESCRIPTION_CHARS)
    return _Cleaned((text,), cleaned.sanitized, 1, False)


def _template_description(template: _Template | None, arguments: list[Any]) -> _Cleaned:
    """Describe a result from a shared template; without arguments that happens once."""
    if template is None:
        return _NOTHING
    if arguments:
        return _description(template.text, arguments)
    if template.bare is None:
        template.bare = _description(template.text, arguments)
    return template.bare


# SECURITY: One left-to-right pass. Link text ends at its first unescaped bracket; a "[" there
# abandons the link, which stays as written, and the scan resumes at that "[", so no text is
# read twice however brackets and backslashes nest.
def _flatten_links(text: str) -> str:
    """Reduce [label](n) location links to their label, unescaped as spec 3.11.6 writes it."""
    parts: list[str] = []
    kept = 0
    opener = text.find("[")
    while opener >= 0:
        label: list[str] = []
        cursor = opener + 1
        while True:
            special = _LINK_SPECIAL.search(text, cursor)
            if special is None:
                # An unterminated link with no bracket after it, so the rest stays as written.
                return "".join([*parts, text[kept:]])
            index = special.start()
            label.append(text[cursor:index])
            if text[index] != "\\":
                break
            # Only a backslash or a bracket is escaped; any other backslash stays as written.
            escaped = text[index + 1 : index + 2]
            if escaped in _LINK_ESCAPES:
                label.append(escaped)
                cursor = index + 2
            else:
                label.append("\\")
                cursor = index + 1
        if text[index] == "[":
            opener = index
            continue
        # A link to a URI, or text in brackets alone, is not a location link and stays as written.
        target = _LINK_TARGET.match(text, index)
        if target is None:
            opener = text.find("[", index + 1)
            continue
        parts += (text[kept:opener], *label)
        kept = target.end()
        opener = text.find("[", kept)
    return "".join([*parts, text[kept:]])


def _message_string(holder: Mapping[str, Any] | None, member: str, message_id: str) -> str:
    """Read a message string by id from a descriptor or component string table."""
    if holder is None:
        return ""
    strings = _mapping(holder.get(member))
    entry = _mapping(strings.get(message_id)) if strings is not None else None
    return text_of(entry.get("text")) if entry is not None else ""


# *--- Identifier Extraction ---*


def _extract_identifiers(texts: Iterable[str]) -> set[str]:
    """Pull CVE, GHSA, and CWE identifiers out of free text, normalized."""
    found: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in _CVE.finditer(text):
            found.add(f"CVE-{match.group(1)}-{match.group(2)}")
        for match in _GHSA.finditer(text):
            found.add(f"GHSA-{match.group(0)[5:].lower()}")
        for match in _CWE.finditer(text):
            found.add(f"CWE-{int(match.group(1))}")
    return found


# Each of the first MAX_LIST_ITEMS of a union has fewer than MAX_LIST_ITEMS smaller members,
# so it is among the first MAX_LIST_ITEMS of its own part: cutting every part and then the
# union keeps exactly what cutting the whole union keeps (decision 5).
def _first_identifiers(found: Iterable[str]) -> tuple[tuple[str, ...], bool]:
    """Return the first MAX_LIST_ITEMS distinct identifiers, sorted, and whether any was cut."""
    smallest = heapq.nsmallest(MAX_LIST_ITEMS + 1, set(found))
    return tuple(smallest[:MAX_LIST_ITEMS]), len(smallest) > MAX_LIST_ITEMS


# *--- Regions and Scores ---*


def _region_integer(value: object) -> int | None:
    """Return a region line or column, or None when it is absent or past MAX_REGION_INTEGER."""
    number = _natural(value)
    return number if number is not None and number <= MAX_REGION_INTEGER else None


def _region(region: Mapping[str, Any] | None) -> tuple[_RegionKey | None, str]:
    """Return the numeric sort key and the display text of a line-and-column region."""
    if region is None:
        return None, ""
    start_line = _region_integer(region.get("startLine"))
    if start_line is None:
        return None, ""
    start_column = _region_integer(region.get("startColumn"))
    end_line = _region_integer(region.get("endLine"))
    end_column = _region_integer(region.get("endColumn"))
    text = str(start_line)
    if start_column is not None:
        text += f":{start_column}"
    if end_line is not None or end_column is not None:
        text += f"-{end_line if end_line is not None else start_line}"
        if end_column is not None:
            text += f":{end_column}"
    return (start_line, start_column or 0, end_line or 0, end_column or 0), text


def _score(raw: object) -> tuple[float | None, bool]:
    """Return (score, usable); a usable None is GitHub's unset 0.0 (decision 7)."""
    if isinstance(raw, bool):
        return None, False
    if isinstance(raw, int):
        # WARN: float() overflows above about 1.8e308: on every integer of 310 or more digits
        # and on most of 309, which a JSON number can carry, so the range check runs first.
        if raw < 0 or raw > 10:
            return None, False
        value = float(raw)
    elif isinstance(raw, float):
        value = raw
    elif isinstance(raw, str):
        text = raw.strip()
        if not _DECIMAL.fullmatch(text):
            return None, False
        value = float(text)
    else:
        return None, False
    if not math.isfinite(value):
        return None, False
    if value == 0.0:
        return None, True
    if value < 0.0 or value > 10.0:
        return None, False
    return value, True


def _band(score: float) -> SourceSeverity:
    if score >= 9.0:
        return SourceSeverity.CRITICAL
    if score >= 7.0:
        return SourceSeverity.HIGH
    if score >= 4.0:
        return SourceSeverity.MEDIUM
    return SourceSeverity.LOW


def _is_component_prefix(descriptor_id: str, rule_id: str) -> bool:
    """Apply spec 3.52.4: the descriptor id must be the rule id or a slash-bounded prefix."""
    # Compared in place, never joined: a descriptor id longer than the rule id costs nothing.
    return rule_id == descriptor_id or (
        rule_id.startswith(descriptor_id) and rule_id.startswith("/", len(descriptor_id))
    )


def _fold_order(item: tuple[_FoldKey, list[_Candidate]]) -> tuple[str, str, str, str]:
    driver_name, record_id, resource_type, resource_id, context_key = item[0]
    return (context_key, record_id, resource_type, resource_id)


# *--- Shared Evidence ---*

# A run's tool data is shared by every result that names it, so each shared text is read,
# sanitized, and cut once per run, each shared uri is checked once per run, and each result
# replays what that cleaning reported. A result's own lists and fingerprints are cut once too,
# however many resources it names, so each fold a result joins costs a bounded amount and the
# parse costs the artifact's bytes plus that bound for each resource a result names
# (decision 9).


# Each of a fold union's first MAX_LIST_ITEMS items is among the first MAX_LIST_ITEMS of the
# list it came from, and one item past them keeps the cut flag, so a list is cut here once
# and every fold that carries it keeps what the whole list would have given it.
def _fold_part(items: Iterable[_Part]) -> tuple[_Part, ...]:
    """Keep a list's MAX_LIST_ITEMS + 1 smallest distinct items, in sorted order."""
    return tuple(heapq.nsmallest(MAX_LIST_ITEMS + 1, set(items)))


def _shared_list(cleaned: _Cleaned) -> _Cleaned:
    """Cut a shared list once, keeping what its cleaning reported."""
    return _Cleaned(_fold_part(cleaned.items), cleaned.sanitized, cleaned.cut, cleaned.cut_first)


def _security_severity(properties: Mapping[str, Any] | None) -> _SecuritySeverity | None:
    """Read one property bag's security-severity: verbatim text, score, usability, detail."""
    if properties is None or "security-severity" not in properties:
        return None
    raw = properties["security-severity"]
    verbatim = raw if isinstance(raw, str) else _encode_list([raw])[1:-1]
    score, usable = _score(raw)
    cleaned = _clean((verbatim,), MAX_METADATA_VALUE_CHARS)
    return _SecuritySeverity(cleaned, score, usable, _quoted(raw))


class _Templates:
    """One string table's message templates by id, each read and flattened on first use."""

    def __init__(self, holder: Mapping[str, Any], member: str) -> None:
        self._holder = holder
        self._member = member
        self._found: dict[str, _Template | None] = {}

    def get(self, message_id: str) -> _Template | None:
        """Return the template an id names, or None when the table has no text for it."""
        if message_id in self._found:
            return self._found[message_id]
        # The raw text decides whether the id resolves, so a template that flattens to
        # nothing still stops the fallback, as it always has.
        text = _message_string(self._holder, self._member, message_id)
        template = _Template(_flatten_links(text)) if text else None
        self._found[message_id] = template
        return template


class _ComponentMemo:
    """One tool component's shared evidence, each part read on first use."""

    def __init__(self, component: Mapping[str, Any], label: str) -> None:
        self.component = component
        self.label = label
        self.messages = _Templates(component, "globalMessageStrings")

    @cached_property
    def name(self) -> _Cleaned:
        name = text_of(self.component.get("name")) or self.label
        return _clean((name,), MAX_METADATA_VALUE_CHARS)


class _DescriptorMemo:
    """One rule descriptor's shared evidence, each part read on first use."""

    def __init__(self, descriptor: Mapping[str, Any]) -> None:
        self.descriptor = descriptor
        self.messages = _Templates(descriptor, "messageStrings")

    @cached_property
    def properties(self) -> Mapping[str, Any] | None:
        return _mapping(self.descriptor.get("properties"))

    @cached_property
    def descriptor_id(self) -> str:
        return text_of(self.descriptor.get("id"))

    @cached_property
    def help_uri(self) -> str:
        return text_of(self.descriptor.get("helpUri"))

    @cached_property
    def name(self) -> _Cleaned:
        return _clean((self.descriptor.get("name"),), MAX_METADATA_VALUE_CHARS)

    @cached_property
    def title(self) -> _Cleaned:
        short = _mapping(self.descriptor.get("shortDescription"))
        text = text_of(short.get("text")) if short is not None else ""
        return _clean((text or text_of(self.descriptor.get("name")),), MAX_TITLE_CHARS)

    @cached_property
    def full_description(self) -> _Template | None:
        full = _mapping(self.descriptor.get("fullDescription"))
        text = text_of(full.get("text")) if full is not None else ""
        return _Template(_flatten_links(text)) if text else None

    @cached_property
    def tags(self) -> _Cleaned:
        tags = _sequence(self.properties.get("tags")) if self.properties else []
        return _shared_list(_clean(tags, MAX_LIST_ITEM_CHARS))

    @cached_property
    def deprecated_ids(self) -> _Cleaned:
        deprecated = _sequence(self.descriptor.get("deprecatedIds"))
        return _shared_list(_clean(deprecated, MAX_LIST_ITEM_CHARS))

    @cached_property
    def identifiers(self) -> tuple[tuple[str, ...], bool]:
        """Return the descriptor's first identifiers and whether any was cut."""
        texts = [self.descriptor_id, text_of(self.descriptor.get("name"))]
        texts.extend(_property_texts(self.properties))
        for relationship in _sequence(self.descriptor.get("relationships")):
            entry = _mapping(relationship)
            target = _mapping(entry.get("target")) if entry is not None else None
            if target is not None:
                texts.append(text_of(target.get("id")))
        return _first_identifiers(_extract_identifiers(texts))

    @cached_property
    def security_severity(self) -> _SecuritySeverity | None:
        return _security_severity(self.properties)

    @cached_property
    def default_level(self) -> tuple[str, _Cleaned] | None:
        configuration = _mapping(self.descriptor.get("defaultConfiguration"))
        level = text_of(configuration.get("level")) if configuration is not None else ""
        return (level, _clean((level,), MAX_METADATA_VALUE_CHARS)) if level else None


def _component_memo(scope: _RunScope, component: Mapping[str, Any], label: str) -> _ComponentMemo:
    """Return the run's one memo for a component, which its label names."""
    memo = scope.cache.components.get(label)
    if memo is None:
        memo = scope.cache.components[label] = _ComponentMemo(component, label)
    return memo


def _descriptor_memo(
    scope: _RunScope, label: str, descriptor: Mapping[str, Any], position: int
) -> _DescriptorMemo:
    """Return the run's one memo for a descriptor, which its component and position name."""
    memo = scope.cache.descriptors.get((label, position))
    if memo is None:
        memo = scope.cache.descriptors[(label, position)] = _DescriptorMemo(descriptor)
    return memo


def _artifact_uri(scope: _RunScope, index: int) -> str:
    """Return the uri of the run artifact at an index inside run.artifacts, read once."""
    uri = scope.cache.artifact_uris.get(index)
    if uri is None:
        entry = _mapping(scope.artifacts[index])
        location = _mapping(entry.get("location")) if entry is not None else None
        uri = scope.cache.artifact_uris[index] = text_of(location.get("uri")) if location else ""
    return uri


def _base_uri(scope: _RunScope, base_id: str) -> str:
    """Return the uri originalUriBaseIds gives a base id, or empty text, read once."""
    uri = scope.cache.base_uris.get(base_id)
    if uri is None:
        entry = _mapping(scope.original_uri_base_ids.get(base_id))
        uri = scope.cache.base_uris[base_id] = text_of(entry.get("uri")) if entry else ""
    return uri


# *--- Rule Resolution ---*


def _component_guids(scope: _RunScope) -> dict[str, tuple[Mapping[str, Any], str]]:
    """Map each component guid to the first component carrying it, built once per run."""
    guids = scope.cache.component_guids
    if guids is None:
        guids = scope.cache.component_guids = {}
        for label, component in scope.components:
            guid = text_of(component.get("guid"))
            if guid:
                guids.setdefault(guid, (component, label))
    return guids


def _resolve_component(
    scope: _RunScope, reference: Mapping[str, Any] | None
) -> tuple[Mapping[str, Any] | None, str]:
    """Resolve the component a rule reference names: index, then guid, then the driver."""
    tool_component = _mapping(reference.get("toolComponent")) if reference is not None else None
    if tool_component is not None:
        index = _natural(tool_component.get("index"))
        if index is not None:
            extension = _mapping(scope.extensions[index]) if index < len(scope.extensions) else None
            return extension, f"extensions[{index}]"
        guid = text_of(tool_component.get("guid"))
        if guid:
            found = _component_guids(scope).get(guid)
            return found if found is not None else (None, f"guid:{guid}")
    return scope.driver, "driver"


def _rule_positions(scope: _RunScope, label: str, rules: list[Any]) -> _RulePositions:
    """Index one component's descriptors by id and by guid, built once per run."""
    positions = scope.cache.rules.get(label)
    if positions is None:
        positions = scope.cache.rules[label] = _RulePositions({}, {})
        for position, item in enumerate(rules):
            rule = _mapping(item)
            if rule is None:
                continue
            for key, table in (("id", positions.by_id), ("guid", positions.by_guid)):
                value = text_of(rule.get(key))
                if value:
                    # Only a lone match names a descriptor, so a second carrier voids the value.
                    table[value] = None if value in table else (rule, position)
    return positions


def _resolve_descriptor(
    scope: _RunScope,
    component: Mapping[str, Any] | None,
    label: str,
    reference: Mapping[str, Any] | None,
    rule_index: object,
    string_id: str,
) -> tuple[Mapping[str, Any] | None, int | None]:
    """Resolve rule.index, else ruleIndex, else rule.guid, else a lone id match, in the rules."""
    if component is None:
        return None, None
    rules = _sequence(component.get("rules"))
    index = _natural(reference.get("index")) if reference is not None else None
    if index is None:
        index = _natural(rule_index)
    if index is not None:
        descriptor = _mapping(rules[index]) if index < len(rules) else None
        return descriptor, index
    positions = _rule_positions(scope, label, rules)
    # NOTE: Spec 3.52.6: rule.guid names the descriptor in theComponent whose guid equals it.
    # A guid that no descriptor carries, or that several carry, falls through to the id match.
    guid = text_of(reference.get("guid")) if reference is not None else ""
    found = positions.by_guid.get(guid) if guid else None
    if found is None and string_id:
        # NOTE: Extra-spec courtesy for producers that emit no index, such as Semgrep and
        # Grype. Spec 3.52.4 keeps the id out of the lookup, so only a lone exact match counts.
        found = positions.by_id.get(string_id)
    if found is None:
        return None, None
    return found


def _overrides(scope: _RunScope, invocation_index: int) -> _Overrides:
    """Resolve one invocation's level-setting overrides to descriptors, built once per run."""
    overrides = scope.cache.overrides.get(invocation_index)
    if overrides is not None:
        return overrides
    overrides = scope.cache.overrides[invocation_index] = _Overrides({})
    invocation = _mapping(scope.invocations[invocation_index])
    entries = invocation.get("ruleConfigurationOverrides") if invocation is not None else None
    for override in _sequence(entries):
        entry = _mapping(override)
        reference = _mapping(entry.get("descriptor")) if entry is not None else None
        if entry is None or reference is None:
            continue
        configuration = _mapping(entry.get("configuration"))
        level = text_of(configuration.get("level")) if configuration is not None else ""
        if not level:
            # An entry without a level never decides, so a later one can.
            continue
        # An entry names the descriptor its reference resolves to by a result's rules, with
        # no ruleIndex beside it; one that names none, or an unusable entry, never matches.
        component, label = _resolve_component(scope, reference)
        descriptor, position = _resolve_descriptor(
            scope, component, label, reference, None, text_of(reference.get("id"))
        )
        if component is None or descriptor is None or position is None:
            continue
        key = (id(component), position)
        if key not in overrides.levels:
            overrides.levels[key] = (level, _clean((level,), MAX_METADATA_VALUE_CHARS))
    return overrides


def _override_level(
    scope: _RunScope, result: Mapping[str, Any], rule: _RuleRef
) -> tuple[str, _Cleaned] | None:
    """Return the level the first override naming the result's descriptor sets, cleaned."""
    provenance = _mapping(result.get("provenance"))
    raw_index = provenance.get("invocationIndex") if provenance is not None else None
    # NOTE: Spec 3.48.6: an absent index defaults to 0 beside a lone invocation, else to -1.
    # An explicit negative index is the spec's unknown invocation, so no override applies.
    if isinstance(raw_index, bool) or not isinstance(raw_index, int):
        invocation_index = 0 if len(scope.invocations) == 1 else -1
    else:
        invocation_index = raw_index
    if invocation_index < 0 or invocation_index >= len(scope.invocations):
        return None
    # A result with no resolved descriptor takes no override, whatever index it carries.
    if rule.component is None or rule.descriptor is None or rule.descriptor_index is None:
        return None
    key = (id(rule.component.component), rule.descriptor_index)
    return _overrides(scope, invocation_index).levels.get(key)


# *--- Artifact Parse ---*


class _ArtifactParse:
    """One artifact's parse state: run scopes, identity folds, coalesced diagnostics."""

    def __init__(
        self, artifact: ArtifactProvenance, ingested_at: datetime, limits: IngestLimits
    ) -> None:
        self.artifact = artifact
        self.ingested_at = ingested_at
        self.limits = limits
        self.diagnostics = _Diagnostics()
        self.folds: dict[_FoldKey, list[_Candidate]] = {}
        self.observation_bytes = 0

    def run(self, runs: list[Any]) -> AdapterOutput:
        """Scan every run, fold by identity, and fail closed on any error."""
        for index, run in enumerate(runs):
            self._scan_run(index, run)
        if not self.folds:
            self.diagnostics.add_fixed(
                IngestDiagnostic(
                    DiagnosticLevel.ERROR,
                    "no_observations",
                    "SARIF log contains no usable results",
                    self.artifact.name,
                )
            )
        observations: list[Observation] = []
        # SECURITY: An ERROR anywhere withholds every observation (refuse identity).
        if not self.diagnostics.has_errors:
            observations = [
                self._assemble(key, candidates)
                for key, candidates in sorted(self.folds.items(), key=_fold_order)
            ]
        return AdapterOutput(tuple(observations), self.diagnostics.emit(self.artifact.name))

    # Diagnostic and hygiene helpers

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
            problem = _identity_problem(value, cap)
        elif value in memo:
            problem = memo[value]
        else:
            problem = memo[value] = _identity_problem(value, cap)
        if problem is None:
            return
        self.diagnostics.add(
            DiagnosticLevel.ERROR,
            "identity_input_invalid",
            "an identity input cannot be used as written",
            path,
            detail=f"{what} {problem}",
        )
        raise _IdentityRefused(what)

    # Uris are text that is never opened or fetched; over the cap or with a prohibited
    # code point they are refused whole, never cut (decision 10).
    def _uri(
        self, value: object, what: str, path: str, memo: dict[str, str | None] | None = None
    ) -> str:
        """Return a uri verbatim, or empty when absent."""
        uri = text_of(value)
        if uri:
            self._require_identity(uri, MAX_URI_CHARS, what, path, memo)
        return uri

    def _evidence(
        self, value: object, cap: int, member: str, path: str, truncated: set[str]
    ) -> str:
        """Sanitize and cap one evidence text, recording what was removed or cut."""
        cleaned = _clean((value,), cap)
        self._replay(cleaned, member, path, truncated)
        return cleaned.text

    def _evidence_list(
        self, values: Iterable[Any], member: str, path: str, truncated: set[str]
    ) -> tuple[str, ...]:
        """Sanitize and cap every string of a list-valued member."""
        cleaned = _clean(values, MAX_LIST_ITEM_CHARS)
        self._replay(cleaned, member, path, truncated)
        return cleaned.items

    def _scalar(
        self, scalars: dict[str, str], key: str, value: object, path: str, truncated: set[str]
    ) -> None:
        """Store one non-uri scalar metadata value when it is present."""
        cleaned = _clean((value,), MAX_METADATA_VALUE_CHARS)
        self._keep_scalar(scalars, key, cleaned, path, truncated)

    def _keep_scalar(
        self, scalars: dict[str, str], key: str, cleaned: _Cleaned, path: str, truncated: set[str]
    ) -> None:
        """Store one cleaned scalar metadata value when it is present."""
        self._replay(cleaned, key, path, truncated)
        if cleaned.text:
            scalars[key] = cleaned.text

    # A shared text is cleaned once, so each result that carries it reports that cleaning at
    # its own path. Same-path reports coalesce, so the counts in first-seen order are exactly
    # what cleaning each text again here would have added.
    def _replay(self, cleaned: _Cleaned, member: str, path: str, truncated: set[str]) -> None:
        """Record what cleaning removed or cut, as if the texts were cleaned at this path."""
        if not cleaned.sanitized and not cleaned.cut:
            return
        reports = [
            ("evidence_sanitized", _EVIDENCE_SANITIZED_SUMMARY, cleaned.sanitized),
            ("evidence_truncated", _EVIDENCE_TRUNCATED_SUMMARY, cleaned.cut),
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
            DiagnosticLevel.WARNING, "evidence_truncated", _EVIDENCE_TRUNCATED_SUMMARY, path
        )
        return items[:MAX_LIST_ITEMS]

    def _clock(self, value: object, path: str) -> datetime | None:
        """Parse one SARIF clock; a present but unusable value is diagnosed and absent."""
        if value is None:
            return None
        parsed = _sarif_timestamp(value)
        if parsed is None:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "source_timestamp_invalid",
                "clock value is not an aware timestamp with a whole-minute offset in the years "
                f"{MIN_CLOCK_YEAR} to {MAX_CLOCK_YEAR} UTC; ignored",
                path,
            )
        return parsed

    # Run scope

    def _scan_run(self, index: int, run: Any) -> None:
        path = f"runs[{index}]"
        try:
            scope = self._run_scope(index, run, path)
        except _IdentityRefused:
            return
        if scope is None:
            return
        if "results" not in run or run["results"] is None:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "results_unknown",
                "run declares no results array; its results are unknown and the run is skipped",
                path,
            )
            return
        results = run["results"]
        if not isinstance(results, list):
            self.diagnostics.add(
                DiagnosticLevel.ERROR, "invalid_run", "run results must be an array", path
            )
            return
        if not results:
            self.diagnostics.add(DiagnosticLevel.INFO, "run_clean", "run reports no results", path)
            return
        if len(results) > self.limits.max_results_per_run:
            raise InputLimitError(
                f"{path} contains {len(results)} results; "
                f"maximum is {self.limits.max_results_per_run}"
            )
        for result_index, result in enumerate(results):
            try:
                self._scan_result(scope, result_index, result)
            except _IdentityRefused:
                continue

    def _run_scope(self, index: int, run: Any, path: str) -> _RunScope | None:
        """Resolve the driver, scope, clocks, and run-level evidence, or diagnose the run."""
        if not isinstance(run, Mapping):
            self.diagnostics.add(
                DiagnosticLevel.ERROR, "invalid_run", "run must be an object", path
            )
            return None
        tool = _mapping(run.get("tool"))
        driver = _mapping(tool.get("driver")) if tool is not None else None
        driver_name = text_of(driver.get("name")) if driver is not None else ""
        if driver is None or not driver_name:
            self.diagnostics.add(
                DiagnosticLevel.ERROR,
                "invalid_run",
                "tool.driver.name is missing, not a string, or empty",
                path,
            )
            return None
        self._require_identity(
            driver_name, MAX_IDENTITY_CHARS, "driver name", f"{path}.tool.driver.name"
        )
        extensions = _sequence(tool.get("extensions")) if tool is not None else []
        components: list[tuple[str, Mapping[str, Any]]] = [("driver", driver)]
        for position, extension in enumerate(extensions):
            if isinstance(extension, Mapping):
                components.append((f"extensions[{position}]", extension))
        if "externalPropertyFileReferences" in run:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "external_properties_ignored",
                "externalPropertyFileReferences is present; external files are never opened",
                path,
            )
        invocations = _sequence(run.get("invocations"))
        for position, invocation in enumerate(invocations):
            entry = _mapping(invocation)
            if entry is not None and entry.get("executionSuccessful") is False:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "execution_unsuccessful",
                    "invocation reports executionSuccessful false; its results are still read",
                    f"{path}.invocations[{position}]",
                )

        truncated: set[str] = set()
        scalars: dict[str, str] = {}
        lists: dict[str, tuple[str, ...]] = {}
        self._scalar(scalars, "tool_version", driver.get("version"), path, truncated)
        self._scalar(
            scalars, "tool_semantic_version", driver.get("semanticVersion"), path, truncated
        )
        information_uri = self._uri(
            driver.get("informationUri"),
            "tool informationUri",
            f"{path}.tool.driver.informationUri",
        )
        if information_uri:
            scalars["tool_information_uri"] = information_uri

        # The last slash-separated component of an automation id is the run instance and is
        # dropped, so a per-run id can never re-mint a case (decision 2).
        context_key = driver_name
        automation = _mapping(run.get("automationDetails"))
        automation_id = text_of(automation.get("id")) if automation is not None else ""
        if automation_id:
            self._require_identity(
                automation_id, MAX_IDENTITY_CHARS, "automation id", f"{path}.automationDetails.id"
            )
            scalars["automation_id"] = automation_id
            category = automation_id.rpartition("/")[0] if "/" in automation_id else ""
            if category:
                scalars["automation_category"] = category
                context_key = f"{driver_name}|{category}"

        properties = _mapping(run.get("properties"))
        repo_digests = _sequence(properties.get("repoDigests")) if properties is not None else []
        digests = _shared_list(_clean(repo_digests, MAX_LIST_ITEM_CHARS))
        self._replay(digests, "image_digests", path, truncated)
        if digests.items:
            lists["image_digests"] = digests.items
        image_name = text_of(properties.get("imageName")) if properties is not None else ""
        if not image_name and repo_digests:
            image_name = text_of(repo_digests[0])
        if image_name:
            self._require_identity(
                image_name, MAX_IDENTITY_CHARS, "image name", f"{path}.properties.imageName"
            )
            scalars["image_name"] = image_name

        repository_uri = ""
        provenance = _sequence(run.get("versionControlProvenance"))
        first = _mapping(provenance[0]) if provenance else None
        if first is not None:
            repository_text = text_of(first.get("repositoryUri"))
            if repository_text.endswith("/"):
                repository_text = repository_text[:-1]
            repository_uri = self._uri(
                repository_text,
                "repository uri",
                f"{path}.versionControlProvenance[0].repositoryUri",
            )
            if repository_uri:
                scalars["repository_uri"] = repository_uri
            self._scalar(scalars, "revision_id", first.get("revisionId"), path, truncated)

        return _RunScope(
            index=index,
            path=path,
            driver=driver,
            driver_name=driver_name,
            extensions=extensions,
            components=components,
            artifacts=_sequence(run.get("artifacts")),
            invocations=invocations,
            original_uri_base_ids=_mapping(run.get("originalUriBaseIds")) or {},
            context_key=context_key,
            image_name=image_name,
            repository_uri=repository_uri,
            clock=self._run_clock(path, invocations),
            scalars=scalars,
            lists=lists,
            truncated=truncated,
        )

    # Earlier is the conservative reading of a detection clock (decision 8).
    def _run_clock(self, path: str, invocations: list[Any]) -> datetime | None:
        """Return the earliest invocation start, else the earliest end, else None."""
        starts: list[datetime] = []
        ends: list[datetime] = []
        for position, invocation in enumerate(invocations):
            entry = _mapping(invocation)
            if entry is None:
                continue
            for member, bucket in (("startTimeUtc", starts), ("endTimeUtc", ends)):
                if member in entry:
                    parsed = self._clock(entry[member], f"{path}.invocations[{position}].{member}")
                    if parsed is not None:
                        bucket.append(parsed)
        if starts:
            return _earliest(starts)
        if ends:
            return _earliest(ends)
        return None

    # Result scope

    def _scan_result(self, scope: _RunScope, index: int, result: Any) -> None:
        path = f"{scope.path}.results[{index}]"
        if not isinstance(result, Mapping):
            self.diagnostics.add(
                DiagnosticLevel.ERROR, "invalid_result", "result must be an object", path
            )
            return
        resolved = self._resolve_rule(scope, result, path)
        if resolved is None:
            return
        rule, record_id = resolved
        truncated = set(scope.truncated)
        scalars = dict(scope.scalars)
        lists: dict[str, Sequence[str]] = dict(scope.lists)
        pairs: dict[str, Sequence[tuple[str, str]]] = {}

        kind_present = "kind" in result
        kind = text_of(result.get("kind"))
        if kind_present:
            disposition = _KIND_DISPOSITIONS.get(kind)
            if disposition is None:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "invalid_result_kind",
                    "result kind is outside the six SARIF values; the disposition is unknown",
                    path,
                    detail=_quoted(kind),
                )
                disposition = ObservationDisposition.UNKNOWN
        else:
            disposition = ObservationDisposition.OPEN
        kind_text = self._evidence(kind, MAX_METADATA_VALUE_CHARS, "result_kind", path, truncated)

        level, level_source, level_text = self._effective_level(
            scope, result, rule, kind_present, kind
        )
        severity, severity_scalars = self._severity(
            result, rule, level, level_source, level_text, path, truncated
        )

        descriptor = rule.descriptor
        if rule.component is not None:
            self._keep_scalar(scalars, "rule_component", rule.component.name, path, truncated)
        if descriptor is not None:
            self._keep_scalar(scalars, "rule_name", descriptor.name, path, truncated)
            help_uri = self._uri(
                descriptor.help_uri,
                "rule helpUri",
                f"{path}.rule.helpUri",
                scope.cache.uri_problems,
            )
            if help_uri:
                scalars["rule_help_uri"] = help_uri
            for member, cleaned in (
                ("rule_tags", descriptor.tags),
                ("rule_deprecated_ids", descriptor.deprecated_ids),
            ):
                self._replay(cleaned, member, path, truncated)
                if cleaned.items:
                    lists[member] = cleaned.items

        # A producer's baseline diff is producer-owned state and never moves a disposition.
        if "baselineState" in result:
            self._scalar(scalars, "baseline_state", result.get("baselineState"), path, truncated)
            self.diagnostics.add(
                DiagnosticLevel.INFO,
                "baseline_state_ignored",
                "baselineState is recorded as metadata and never changes a disposition",
                path,
            )
        self._scalar(scalars, "guid", result.get("guid"), path, truncated)
        self._scalar(scalars, "correlation_guid", result.get("correlationGuid"), path, truncated)
        # A result's own lists and fingerprints join one fold for each resource it names, so
        # each is cut once here (see _fold_part).
        for member, key in (
            ("fingerprints", "fingerprints"),
            ("partialFingerprints", "partial_fingerprints"),
        ):
            recorded = self._fingerprint_pairs(result.get(member), key, path, truncated)
            if recorded:
                pairs[key] = _fold_part(recorded)
        taxa_ids = [
            text_of(taxon.get("id"))
            for taxon in _sequence(result.get("taxa"))
            if isinstance(taxon, Mapping)
        ]
        taxa = _fold_part(self._evidence_list(taxa_ids, "taxa", path, truncated))
        if taxa:
            lists["taxa"] = taxa

        # A suppressed result stays OPEN: a developer's nosemgrep comment is exactly what an
        # evaluator must see (decision 6).
        suppressed = ""
        suppressions = _sequence(result.get("suppressions"))
        if suppressions:
            kinds: list[str] = []
            statuses: list[str] = []
            accepted = False
            for suppression in suppressions:
                entry = _mapping(suppression)
                if entry is None:
                    continue
                status = text_of(entry.get("status"))
                kinds.append(text_of(entry.get("kind")))
                statuses.append(status)
                if not status or status == _SUPPRESSION_ACCEPTED:
                    accepted = True
            suppressed = "true" if accepted else "false"
            if accepted:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "results_suppressed",
                    "result carries an accepted suppression; its disposition is unchanged",
                    path,
                )
            suppression_kinds = _fold_part(
                self._evidence_list(kinds, "suppression_kinds", path, truncated)
            )
            if suppression_kinds:
                lists["suppression_kinds"] = suppression_kinds
            suppression_statuses = _fold_part(
                self._evidence_list(statuses, "suppression_statuses", path, truncated)
            )
            if suppression_statuses:
                lists["suppression_statuses"] = suppression_statuses

        observed_at = self._result_clock(scope, result, path)
        title, description = self._describe(result, rule, path, truncated)
        # The descriptor's identifiers arrive already cut; cutting a part and then the union
        # keeps what cutting the whole union keeps (see _first_identifiers).
        found = _extract_identifiers(self._identifier_sources(result, rule, record_id))
        shared_cut = False
        if rule.descriptor is not None:
            shared, shared_cut = rule.descriptor.identifiers
            found.update(shared)
        identifiers, identifiers_cut = _first_identifiers(found)
        identifiers_cut = identifiers_cut or shared_cut

        hits = self._locations(scope, result, path)
        if not hits:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "resource_identity_fallback",
                "result has no usable location; the driver name is the scan resource",
                path,
            )
            hits = {
                (RESOURCE_TYPE_SCAN, scope.driver_name): _Hit(
                    RESOURCE_TYPE_SCAN, scope.driver_name, [], [], {}, [], set()
                )
            }
        for (resource_type, resource_id), hit in hits.items():
            first_region = min((key for key, _text in hit.regions), default=_NO_REGION)
            candidate_scalars = {**scalars, **hit.scalars}
            # The order is a function of content alone, so the fold ignores result order.
            candidate = _Candidate(
                order=(
                    first_region,
                    description,
                    title,
                    tuple(sorted(candidate_scalars.items())),
                    tuple(sorted(severity_scalars.items())),
                    kind_text,
                    suppressed,
                ),
                path=path,
                run_index=scope.index,
                kind=kind_text,
                disposition=disposition,
                severity=severity,
                severity_scalars=severity_scalars,
                observed_at=observed_at,
                title=title,
                description=description,
                identifiers=identifiers,
                identifiers_cut=identifiers_cut,
                scalars=candidate_scalars,
                lists={**lists, **({"logical_locations": hit.logical} if hit.logical else {})},
                pairs=pairs,
                regions=hit.regions,
                messages=hit.messages,
                suppressed=suppressed,
                truncated=truncated | hit.truncated,
            )
            fold_key: _FoldKey = (
                scope.driver_name,
                record_id,
                resource_type,
                resource_id,
                scope.context_key,
            )
            bucket = self.folds.get(fold_key)
            if bucket is None:
                if len(self.folds) >= self.limits.max_observations_per_artifact:
                    raise InputLimitError(
                        f"artifact yields more than "
                        f"{self.limits.max_observations_per_artifact} observations"
                    )
                bucket = self.folds[fold_key] = []
            bucket.append(candidate)

    def _resolve_rule(
        self, scope: _RunScope, result: Mapping[str, Any], path: str
    ) -> tuple[_RuleRef, str] | None:
        """Resolve the component and descriptor, then the identity string (decision 4)."""
        reference = _mapping(result.get("rule"))
        component, label = _resolve_component(scope, reference)
        string_id = text_of(result.get("ruleId"))
        if not string_id and reference is not None:
            string_id = text_of(reference.get("id"))
        descriptor, descriptor_index = _resolve_descriptor(
            scope, component, label, reference, result.get("ruleIndex"), string_id
        )
        component_memo = None
        if component is not None:
            component_memo = _component_memo(scope, component, label)
        descriptor_memo = None
        if descriptor is not None and descriptor_index is not None:
            descriptor_memo = _descriptor_memo(scope, label, descriptor, descriptor_index)
        descriptor_id = descriptor_memo.descriptor_id if descriptor_memo is not None else ""
        record_id = string_id or descriptor_id
        if not record_id:
            self.diagnostics.add(
                DiagnosticLevel.ERROR,
                "rule_id_missing",
                "no ruleId, rule.id, rule.index, or ruleIndex resolves to a rule identifier",
                path,
            )
            return None
        # A descriptor's id is shared by every result that names it, so its check is kept in the
        # run's memo, and each of those results is still refused at its own path.
        memo = None if string_id else scope.cache.rule_id_problems
        self._require_identity(record_id, MAX_IDENTITY_CHARS, "rule identifier", path, memo)
        if string_id and descriptor_id and not _is_component_prefix(descriptor_id, string_id):
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "rule_reference_conflict",
                "the rule id string and the resolved descriptor id disagree; the string wins",
                path,
                detail=f"{_quoted(string_id)} against descriptor {_quoted(descriptor_id)}",
            )
        return _RuleRef(component_memo, descriptor_memo, descriptor_index), record_id

    def _effective_level(
        self,
        scope: _RunScope,
        result: Mapping[str, Any],
        rule: _RuleRef,
        kind_present: bool,
        kind: str,
    ) -> tuple[str, str, _Cleaned]:
        """Apply the level chain of spec 3.27.10, name the step that decided it, and clean it."""
        if kind_present and kind != "fail":
            return "none", "forced_none", _clean(("none",), MAX_METADATA_VALUE_CHARS)
        level = text_of(result.get("level"))
        if level:
            return level, "result", _clean((level,), MAX_METADATA_VALUE_CHARS)
        # An override or a rule default is shared, so it arrives cleaned once per run.
        override = _override_level(scope, result, rule)
        if override is not None:
            return override[0], "invocation_override", override[1]
        default = rule.descriptor.default_level if rule.descriptor is not None else None
        if default is not None:
            return default[0], "rule_default", default[1]
        return "warning", "default", _clean(("warning",), MAX_METADATA_VALUE_CHARS)

    def _severity(
        self,
        result: Mapping[str, Any],
        rule: _RuleRef,
        level: str,
        level_source: str,
        level_text: _Cleaned,
        path: str,
        truncated: set[str],
    ) -> tuple[SourceSeverity, dict[str, str]]:
        """Map security-severity when usable, else the level, and record the source."""
        scalars: dict[str, str] = {"level_source": level_source}
        self._keep_scalar(scalars, "level", level_text, path, truncated)
        # The result's own property wins; the descriptor's is read once per run.
        chosen = _security_severity(_mapping(result.get("properties")))
        if chosen is None and rule.descriptor is not None:
            chosen = rule.descriptor.security_severity
        severity: SourceSeverity | None = None
        if chosen is not None:
            self._keep_scalar(scalars, "security_severity", chosen.verbatim, path, truncated)
            if not chosen.usable:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "security_severity_invalid",
                    "security-severity is not a finite number above 0 and at most 10; ignored",
                    path,
                    detail=chosen.detail,
                )
            elif chosen.score is not None:
                severity = _band(chosen.score)
        if severity is not None:
            scalars["severity_source"] = "security-severity"
            return severity, scalars
        mapped = _LEVEL_SEVERITIES.get(level)
        if mapped is None:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "invalid_level",
                "effective level is outside error, warning, note, and none; severity unknown",
                path,
                detail=_quoted(level),
            )
            mapped = SourceSeverity.UNKNOWN
        scalars["severity_source"] = "level"
        return mapped, scalars

    def _result_clock(
        self, scope: _RunScope, result: Mapping[str, Any], path: str
    ) -> datetime | None:
        """Return the first detection time, else the last, else the run clock, else None."""
        provenance = _mapping(result.get("provenance"))
        if provenance is not None:
            for member in ("firstDetectionTimeUtc", "lastDetectionTimeUtc"):
                if member in provenance:
                    parsed = self._clock(provenance[member], f"{path}.provenance.{member}")
                    if parsed is not None:
                        return parsed
        if scope.clock is not None:
            return scope.clock
        self.diagnostics.add_fixed(missing_time_diagnostic(self.artifact))
        return None

    def _describe(
        self, result: Mapping[str, Any], rule: _RuleRef, path: str, truncated: set[str]
    ) -> tuple[str, str]:
        """Return the capped title and the expanded, capped description (decision 5)."""
        descriptor = rule.descriptor
        message = _mapping(result.get("message"))
        text = text_of(message.get("text")) if message is not None else ""
        message_id = text_of(message.get("id")) if message is not None else ""
        arguments = _sequence(message.get("arguments")) if message is not None else []
        if text:
            # Links are flattened on the template, so argument text is never scanned.
            described = _description(_flatten_links(text), arguments)
        else:
            template: _Template | None = None
            if message_id and descriptor is not None:
                template = descriptor.messages.get(message_id)
            if template is None and message_id and rule.component is not None:
                template = rule.component.messages.get(message_id)
            if template is None and descriptor is not None:
                template = descriptor.full_description
            described = _template_description(template, arguments)
        self._replay(described, "description", path, truncated)
        title = descriptor.title if descriptor is not None else _NOTHING
        self._replay(title, "title", path, truncated)
        return title.text, described.text

    # The descriptor's id is among its own identifiers, read once for the run, so a result
    # reads the rule identifier only when it is not the descriptor's.
    def _identifier_sources(
        self, result: Mapping[str, Any], rule: _RuleRef, record_id: str
    ) -> list[str]:
        """Gather the result's own texts decision 5 reads for CVE, GHSA, and CWE identifiers."""
        shared = rule.descriptor is not None and record_id == rule.descriptor.descriptor_id
        texts = [] if shared else [record_id]
        texts.extend(_property_texts(_mapping(result.get("properties"))))
        for taxon in _sequence(result.get("taxa")):
            entry = _mapping(taxon)
            if entry is not None:
                texts.append(text_of(entry.get("id")))
        return texts

    def _fingerprint_pairs(
        self, value: object, key: str, path: str, truncated: set[str]
    ) -> list[tuple[str, str]]:
        """Record producer fingerprints as capped name and value pairs, never as keys."""
        mapping = _mapping(value)
        if mapping is None:
            return []
        recorded: list[tuple[str, str]] = []
        for name, item in mapping.items():
            if not isinstance(item, str) or item == _SEMGREP_FINGERPRINT_PLACEHOLDER:
                continue
            pair_name = self._evidence(name, MAX_LIST_ITEM_CHARS, key, path, truncated)
            pair_value = self._evidence(item, MAX_LIST_ITEM_CHARS, key, path, truncated)
            if pair_name and pair_value:
                recorded.append((pair_name, pair_value))
        return recorded

    # Location identity

    def _locations(
        self, scope: _RunScope, result: Mapping[str, Any], path: str
    ) -> dict[tuple[str, str], _Hit]:
        """Return one hit per distinct resource among result.locations (decision 3)."""
        locations = _sequence(result.get("locations"))
        if len(locations) > MAX_LOCATIONS_PER_RESULT:
            raise InputLimitError(
                f"{path} carries {len(locations)} locations; maximum is {MAX_LOCATIONS_PER_RESULT}"
            )
        hits: dict[tuple[str, str], _Hit] = {}
        for position, location in enumerate(locations):
            entry = _mapping(location)
            if entry is None:
                continue
            hit = self._locate(scope, entry, f"{path}.locations[{position}]")
            if hit is None:
                continue
            existing = hits.get((hit.resource_type, hit.resource_id))
            if existing is None:
                hits[(hit.resource_type, hit.resource_id)] = hit
                continue
            existing.regions.extend(hit.regions)
            existing.messages.extend(hit.messages)
            existing.logical.extend(hit.logical)
            existing.truncated |= hit.truncated
        return hits

    # The uri is identity as written: never resolved against a base, never decoded or
    # normalized, so a repository-relative path is the same on every runner (decision 3).
    def _locate(self, scope: _RunScope, location: Mapping[str, Any], path: str) -> _Hit | None:
        """Turn one location into a resource hit, or None when it names nothing usable."""
        truncated: set[str] = set()
        physical = _mapping(location.get("physicalLocation"))
        artifact_location = _mapping(physical.get("artifactLocation")) if physical else None
        uri = ""
        # A run artifact's uri is shared by every location that names it by index.
        memo: dict[str, str | None] | None = None
        if artifact_location is not None:
            uri = text_of(artifact_location.get("uri"))
            if not uri:
                artifact_index = _natural(artifact_location.get("index"))
                if artifact_index is not None and artifact_index < len(scope.artifacts):
                    uri = _artifact_uri(scope, artifact_index)
                    memo = scope.cache.uri_problems
        region_key, region_text = _region(_mapping(physical.get("region")) if physical else None)
        # The message is cut before its region prefix joins it, so the finished item is at
        # most MAX_LIST_ITEM_CHARS with one marker.
        prefix = f"{region_text}: " if region_text else ""
        message = _mapping(location.get("message"))
        message_text = self._evidence(
            message.get("text") if message is not None else None,
            MAX_LIST_ITEM_CHARS - len(prefix),
            "location_messages",
            path,
            truncated,
        )
        logical_names: list[str] = []
        for logical_location in _sequence(location.get("logicalLocations")):
            entry = _mapping(logical_location)
            if entry is None:
                continue
            name = text_of(entry.get("fullyQualifiedName")) or text_of(entry.get("name"))
            if name:
                logical_names.append(name)

        scalars: dict[str, str] = {}
        if uri:
            uri_path = f"{path}.physicalLocation.artifactLocation.uri"
            self._require_identity(uri, MAX_URI_CHARS, "location uri", uri_path, memo)
            verdicts = scope.cache.uri_suspicious if memo is not None else None
            if verdicts is None:
                suspicious = _uri_is_suspicious(uri)
            elif uri in verdicts:
                suspicious = verdicts[uri]
            else:
                suspicious = verdicts[uri] = _uri_is_suspicious(uri)
            if suspicious:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "uri_suspicious",
                    "location uri has a '..' segment or a '//' prefix; kept verbatim, never opened",
                    uri_path,
                )
            scalars["location_uri"] = uri
            base_id = text_of(artifact_location.get("uriBaseId")) if artifact_location else ""
            if base_id:
                self._scalar(scalars, "uri_base_id", base_id, path, truncated)
                base_uri = self._uri(
                    _base_uri(scope, base_id),
                    "original uri base",
                    f"{scope.path}.originalUriBaseIds.{base_id}.uri",
                    scope.cache.uri_problems,
                )
                if base_uri:
                    scalars["uri_base"] = base_uri
            if scope.image_name:
                resource_type, resource_id = RESOURCE_TYPE_IMAGE, f"{scope.image_name}/{uri}"
            elif scope.repository_uri:
                resource_type, resource_id = RESOURCE_TYPE_FILE, f"{scope.repository_uri}/{uri}"
            else:
                resource_type, resource_id = RESOURCE_TYPE_FILE, uri
        elif logical_names:
            name = logical_names[0]
            self._require_identity(
                name, MAX_IDENTITY_CHARS, "logical location name", f"{path}.logicalLocations"
            )
            prefix = scope.image_name or scope.repository_uri
            resource_type = RESOURCE_TYPE_LOGICAL
            resource_id = f"{prefix}/{name}" if prefix else name
        else:
            return None

        logical = self._evidence_list(logical_names, "logical_locations", path, truncated)
        regions = [(region_key, region_text)] if region_key is not None else []
        messages: list[tuple[_RegionKey, str]] = []
        if message_text:
            messages.append((region_key or _NO_REGION, prefix + message_text))
        return _Hit(
            resource_type, resource_id, regions, messages, scalars, list(logical), truncated
        )

    # Folding

    # The fold is a pure function of the candidate set: every choice is a max, a min, or a
    # sort, so result order never reaches the observation (decision 9).
    def _assemble(self, key: _FoldKey, candidates: list[_Candidate]) -> Observation:
        """Fold every candidate that shares an identity into one bounded observation."""
        driver_name, record_id, resource_type, resource_id, context_key = key
        ordered = sorted(candidates, key=lambda candidate: candidate.order)
        primary = ordered[0]
        path = primary.path
        truncated: set[str] = set()
        for candidate in ordered:
            truncated |= candidate.truncated
        worst = max(ordered, key=lambda candidate: _DISPOSITION_RANK[candidate.disposition])
        strongest = max(ordered, key=lambda candidate: _SEVERITY_RANK[candidate.severity])
        observed = [candidate.observed_at for candidate in ordered if candidate.observed_at]
        observed_at = _earliest(observed) if observed else None

        metadata = dict(primary.scalars)
        metadata.update(strongest.severity_scalars)
        if worst.kind:
            metadata["result_kind"] = worst.kind
        flags = {candidate.suppressed for candidate in ordered}
        if "true" in flags:
            metadata["suppressed"] = "true"
        elif "false" in flags:
            metadata["suppressed"] = "false"

        # A run's or a descriptor's items are one shared tuple, so it joins the union once
        # however many candidates carry it.
        parts: dict[str, dict[int, Sequence[str]]] = {}
        for candidate in ordered:
            for member, items in candidate.lists.items():
                parts.setdefault(member, {})[id(items)] = items
        lists = {member: set[str]().union(*shared.values()) for member, shared in parts.items()}
        lists["result_kinds"] = {candidate.kind for candidate in ordered if candidate.kind}
        for member, union in lists.items():
            if union:
                metadata[member] = _encode_list(self._cut(sorted(union), member, path, truncated))
        run_indexes = sorted({candidate.run_index for candidate in ordered})
        metadata["run_indexes"] = _encode_list(
            self._cut(run_indexes, "run_indexes", path, truncated)
        )
        for member in ("regions", "location_messages"):
            entries: set[tuple[_RegionKey, str]] = set()
            for candidate in ordered:
                entries.update(candidate.regions if member == "regions" else candidate.messages)
            if entries:
                texts = list(dict.fromkeys(text for _key, text in sorted(entries)))
                metadata[member] = _encode_list(self._cut(texts, member, path, truncated))
        for member in ("fingerprints", "partial_fingerprints"):
            pairs: set[tuple[str, str]] = set()
            for candidate in ordered:
                pairs.update(candidate.pairs.get(member, ()))
            if pairs:
                kept = self._cut(sorted(pairs), member, path, truncated)
                metadata[member] = _encode_list(list(pair) for pair in kept)
        identifiers, identifiers_cut = _first_identifiers(
            identifier for candidate in ordered for identifier in candidate.identifiers
        )
        if identifiers_cut or any(candidate.identifiers_cut for candidate in ordered):
            truncated.add("source_identifiers")
            self.diagnostics.add(
                DiagnosticLevel.WARNING, "evidence_truncated", _EVIDENCE_TRUNCATED_SUMMARY, path
            )
        metadata["occurrence_count"] = str(len(ordered))
        for candidate in ordered[1:]:
            self.diagnostics.add(
                DiagnosticLevel.INFO,
                "results_collapsed",
                "result folded into an observation that shares its identity",
                candidate.path,
            )
        if truncated:
            metadata["truncated"] = _encode_list(sorted(truncated))
        foreign = sorted(set(metadata) - METADATA_KEYS)
        if foreign:
            raise RuntimeError(f"metadata keys outside the fixed vocabulary: {foreign}")

        observation = make_observation(
            artifact=self.artifact,
            source_type=SARIF_SOURCE_TYPE,
            source_tool=driver_name,
            source_record_id=record_id,
            resource_id=resource_id,
            resource_type=resource_type,
            observed_at=observed_at,
            ingested_at=self.ingested_at,
            disposition=worst.disposition,
            severity=strongest.severity,
            title=primary.title,
            description=primary.description,
            identifiers=identifiers,
            context_key=context_key,
            metadata=metadata,
        )
        # WARN: The caps of decision 9 count characters, not bytes. A quote or backslash in a
        # list item is escaped twice and costs four bytes, as four-byte text does, so text at
        # every cap can pass this ceiling, ASCII or not, and then the artifact fails closed the
        # same way on the stateless and persisted paths (decision 9).
        size = len(observation.to_canonical_json().encode("utf-8"))
        if size > MAX_OBSERVATION_JSON_BYTES:
            raise InputLimitError(
                f"observation {observation.observation_id} is {size} bytes of canonical JSON; "
                f"maximum is {MAX_OBSERVATION_JSON_BYTES}"
            )
        # SECURITY: The sum is checked as each observation is built, so the artifact fails
        # closed before its observations hold much more than the budget (decision 9).
        self.observation_bytes += size
        budget = self.limits.max_observation_bytes_per_artifact
        if self.observation_bytes > budget:
            raise InputLimitError(f"artifact yields more than {budget} bytes of observation JSON")
        return observation


# *--- Adapter ---*


# SECURITY: The adapter reads only the already-parsed document. It opens no path and
# fetches no uri; helpUri, informationUri, originalUriBaseIds, and repositoryUri are text.
class SarifAdapter:
    """Parse one bounded SARIF 2.1.0 document into observations and coalesced diagnostics."""

    name = "complyroll.sarif"
    version = SARIF_PARSER_VERSION
    media_type = SARIF_MEDIA_TYPE

    # The limits reach the adapter through its constructor (decision 11), so the parse
    # signature the STIG adapters share stays as base.py defines it.
    def __init__(self, limits: IngestLimits = DEFAULT_LIMITS) -> None:
        self.limits = limits

    def parse(
        self,
        document: ParsedDocument,
        artifact: ArtifactProvenance,
        *,
        ingested_at: datetime,
    ) -> AdapterOutput:
        data = document.value
        if not isinstance(data, Mapping):
            raise AdapterParseError("SARIF root must be a JSON object")
        if data.get("version") != SARIF_VERSION:
            raise AdapterParseError(f"SARIF version must be the string {SARIF_VERSION}")
        runs = data.get("runs")
        if not isinstance(runs, list):
            raise AdapterParseError("SARIF runs must be an array")
        return _ArtifactParse(artifact, ingested_at, self.limits).run(runs)
