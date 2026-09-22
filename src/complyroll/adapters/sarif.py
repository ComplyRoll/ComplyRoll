# ******************************************************************************
# *Title: SARIF Adapter*
# *Author: Kyle Versluis*
# *Description: SARIF 2.1.0 adapter on the ADR 0002 observation identity.*
# ******************************************************************************
"""SARIF 2.1.0 source adapter (ADR 0011)."""

# *--- Imports ---*

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

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
MAX_TITLE_CHARS = 512
MAX_DESCRIPTION_CHARS = 4_096
MAX_METADATA_VALUE_CHARS = 512
MAX_LIST_ITEMS = 64
MAX_LIST_ITEM_CHARS = 256
MAX_OBSERVATION_JSON_BYTES = 512 * 1024
TRUNCATION_MARKER = "...[truncated]"
# A coalesced diagnostic names at most this many JSON paths.
MAX_DIAGNOSTIC_PATHS = 5

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
# The worst disposition and the highest severity win a fold (decision 8).
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
_EVIDENCE_TRUNCATED_SUMMARY = (
    "evidence text was cut at its cap; the truncated metadata key names the members"
)

_PROHIBITED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_LINE_BREAK_CATEGORIES = frozenset({"Zl", "Zp"})
_KEPT_CONTROLS = frozenset({"\t", "\n"})
_NO_REGION = (0, 0, 0, 0)

# SECURITY: Every pattern is fixed and anchored on token boundaries; none is built from input.
_PLACEHOLDER = re.compile(r"\{(\d{1,9})\}")
_LINK = re.compile(r"\[([^\[\]]*)\]\((\d{1,9})\)")
_CVE = re.compile(r"(?<![A-Za-z0-9])CVE-(\d{4})-(\d{4,})(?![0-9])", re.IGNORECASE)
_GHSA = re.compile(r"(?<![A-Za-z0-9])GHSA(?:-[A-Za-z0-9]{4}){3}(?![A-Za-z0-9])", re.IGNORECASE)
_CWE = re.compile(r"(?<![A-Za-z0-9])CWE-(\d{1,5})(?![0-9])", re.IGNORECASE)

# *--- Types ---*

_RegionKey = tuple[int, int, int, int]
_FoldKey = tuple[str, str, str, str, str]


class _IdentityRefused(Exception):
    """Raised once identity_input_invalid is recorded; the enclosing run or result stops."""


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
    lists: dict[str, list[str]]
    truncated: set[str]


@dataclass(frozen=True, slots=True)
class _RuleRef:
    """The component and descriptor one result resolves to, in the spec's order."""

    component: Mapping[str, Any] | None
    label: str
    descriptor: Mapping[str, Any] | None
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
    identifiers: set[str]
    scalars: dict[str, str]
    lists: dict[str, list[str]]
    pairs: dict[str, list[tuple[str, str]]]
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


# Every code is reported once per artifact with a count and the first few JSON paths, so the
# diagnostics payload is bounded by the number of codes and not by the input (decision 16).
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
    ) -> None:
        """Count one occurrence of a code at a JSON path."""
        entry = self._entries.get(code)
        if entry is None:
            entry = _DiagnosticEntry(level, summary, detail)
            self._entries[code] = entry
        entry.count += 1
        if len(entry.paths) < MAX_DIAGNOSTIC_PATHS:
            entry.paths.append(path)

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
# line-separator code point, or an over-cap length, fails the artifact closed (decision 13).
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


def _truncate(text: str, cap: int) -> str:
    """Cut text to exactly the cap, marker included."""
    return text[: cap - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def _encode_list(items: Iterable[Any]) -> str:
    return json.dumps(list(items), ensure_ascii=False, separators=(",", ":"))


# *--- Timestamps ---*


# The contract regex and the canonical round trip both refuse a seconds-bearing offset, which
# Python's parser accepts; the check lives here so SARIF never writes an observed_at the
# store would refuse (decision 12).
def _sarif_timestamp(value: object) -> datetime | None:
    """Parse an aware timestamp whose UTC offset is a whole number of minutes."""
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    offset = parsed.utcoffset()
    if offset is None or offset % timedelta(minutes=1):
        return None
    return parsed


# *--- Message Expansion ---*


# SECURITY: One left-to-right pass, never str.format: a substituted argument is never
# rescanned, so producer text cannot reach the formatter as a pattern (decision 14).
def _expand_message(text: str, arguments: list[Any]) -> str:
    """Replace {n} placeholders from the arguments and unescape doubled braces."""
    # One past the cap: an expansion that overruns it is then cut with the marker.
    budget = MAX_DESCRIPTION_CHARS + 1
    pieces: list[str] = []
    size = 0
    position = 0
    length = len(text)
    while position < length and size < budget:
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
                else:
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
            end = position
            while end < length and text[end] not in "{}":
                end += 1
            piece = text[position:end]
            position = end
        room = budget - size
        if len(piece) > room:
            piece = piece[:room]
        pieces.append(piece)
        size += len(piece)
    return "".join(pieces)


def _flatten_links(text: str) -> str:
    """Reduce [label](n) location links to their label."""
    return _LINK.sub(lambda match: match.group(1), text)


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


# *--- Regions and Scores ---*


def _region(region: Mapping[str, Any] | None) -> tuple[_RegionKey | None, str]:
    """Return the numeric sort key and the display text of a line-and-column region."""
    if region is None:
        return None, ""
    start_line = _natural(region.get("startLine"))
    if start_line is None:
        return None, ""
    start_column = _natural(region.get("startColumn"))
    end_line = _natural(region.get("endLine"))
    end_column = _natural(region.get("endColumn"))
    text = str(start_line)
    if start_column is not None:
        text += f":{start_column}"
    if end_line is not None or end_column is not None:
        text += f"-{end_line if end_line is not None else start_line}"
        if end_column is not None:
            text += f":{end_column}"
    return (start_line, start_column or 0, end_line or 0, end_column or 0), text


def _score(raw: object) -> tuple[float | None, bool]:
    """Return (score, usable); a usable None is GitHub's unset 0.0 (decision 11)."""
    if isinstance(raw, bool):
        return None, False
    if isinstance(raw, int | float):
        value = float(raw)
    elif isinstance(raw, str):
        try:
            value = float(raw.strip())
        except ValueError:
            return None, False
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
    return rule_id == descriptor_id or rule_id.startswith(f"{descriptor_id}/")


def _fold_order(item: tuple[_FoldKey, list[_Candidate]]) -> tuple[str, str, str, str]:
    driver_name, record_id, resource_type, resource_id, context_key = item[0]
    return (context_key, record_id, resource_type, resource_id)


# *--- Rule Resolution ---*


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
            for label, component in scope.components:
                if text_of(component.get("guid")) == guid:
                    return component, label
            return None, f"guid:{guid}"
    return scope.driver, "driver"


def _resolve_descriptor(
    component: Mapping[str, Any] | None,
    reference: Mapping[str, Any] | None,
    result: Mapping[str, Any],
    string_id: str,
) -> tuple[Mapping[str, Any] | None, int | None]:
    """Resolve rule.index, else ruleIndex, else a lone id match, in the component's rules."""
    if component is None:
        return None, None
    rules = _sequence(component.get("rules"))
    index = _natural(reference.get("index")) if reference is not None else None
    if index is None:
        index = _natural(result.get("ruleIndex"))
    if index is not None:
        descriptor = _mapping(rules[index]) if index < len(rules) else None
        return descriptor, index
    if not string_id:
        return None, None
    # NOTE: Spec 3.52.3 step three: with no index, the descriptor whose id equals the string
    # id is the rule; more than one match makes the reference invalid, so none is chosen.
    matches = [
        (position, rule)
        for position, item in enumerate(rules)
        if (rule := _mapping(item)) is not None and text_of(rule.get("id")) == string_id
    ]
    if len(matches) != 1:
        return None, None
    return matches[0][1], matches[0][0]


def _override_level(scope: _RunScope, result: Mapping[str, Any], rule: _RuleRef) -> str:
    """Return the level a ruleConfigurationOverrides entry sets for this result's rule."""
    provenance = _mapping(result.get("provenance"))
    invocation_index = _natural(provenance.get("invocationIndex")) if provenance else None
    if invocation_index is None and len(scope.invocations) == 1:
        invocation_index = 0
    if invocation_index is None or invocation_index >= len(scope.invocations):
        return ""
    invocation = _mapping(scope.invocations[invocation_index])
    if invocation is None or rule.component is None:
        return ""
    for override in _sequence(invocation.get("ruleConfigurationOverrides")):
        entry = _mapping(override)
        reference = _mapping(entry.get("descriptor")) if entry is not None else None
        if entry is None or reference is None:
            continue
        component, _label = _resolve_component(scope, reference)
        if component is not rule.component:
            continue
        index = _natural(reference.get("index"))
        matched = index is not None and index == rule.descriptor_index
        if not matched and rule.descriptor is not None:
            reference_id = text_of(reference.get("id"))
            matched = bool(reference_id) and reference_id == text_of(rule.descriptor.get("id"))
        if not matched:
            continue
        configuration = _mapping(entry.get("configuration"))
        level = text_of(configuration.get("level")) if configuration is not None else ""
        if level:
            return level
    return ""


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

    def _require_identity(self, value: str, cap: int, what: str, path: str) -> None:
        """Record identity_input_invalid and stop when text cannot be an identity input."""
        problem = _identity_problem(value, cap)
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
    # code point they are refused whole, never cut (decision 13).
    def _uri(self, value: object, what: str, path: str) -> str:
        """Return a uri verbatim, or empty when absent."""
        uri = text_of(value)
        if uri:
            self._require_identity(uri, MAX_URI_CHARS, what, path)
        return uri

    def _evidence(
        self, value: object, cap: int, member: str, path: str, truncated: set[str]
    ) -> str:
        """Sanitize and cap one evidence text, recording what was removed or cut."""
        text = text_of(value)
        if not text:
            return ""
        cleaned, changed = _sanitize(text)
        cleaned = cleaned.strip()
        if changed:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "evidence_sanitized",
                "control, format, or separator characters were removed from evidence text",
                path,
            )
        if len(cleaned) > cap:
            cleaned = _truncate(cleaned, cap)
            truncated.add(member)
            self.diagnostics.add(
                DiagnosticLevel.WARNING, "evidence_truncated", _EVIDENCE_TRUNCATED_SUMMARY, path
            )
        return cleaned

    def _evidence_list(
        self, values: Iterable[Any], member: str, path: str, truncated: set[str]
    ) -> list[str]:
        """Sanitize and cap every string of a list-valued member."""
        items: list[str] = []
        for value in values:
            if isinstance(value, str):
                text = self._evidence(value, MAX_LIST_ITEM_CHARS, member, path, truncated)
                if text:
                    items.append(text)
        return items

    def _scalar(
        self, scalars: dict[str, str], key: str, value: object, path: str, truncated: set[str]
    ) -> None:
        """Store one non-uri scalar metadata value when it is present."""
        text = self._evidence(value, MAX_METADATA_VALUE_CHARS, key, path, truncated)
        if text:
            scalars[key] = text

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
                "clock value is not an aware timestamp with a whole-minute offset; ignored",
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
        lists: dict[str, list[str]] = {}
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
        # dropped, so a per-run id can never re-mint a case (decision 5).
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
        digests = self._evidence_list(repo_digests, "image_digests", path, truncated)
        if digests:
            lists["image_digests"] = digests
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

    # Earlier is the conservative reading of a detection clock (decision 12).
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
            return min(starts)
        if ends:
            return min(ends)
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
        lists = {member: list(items) for member, items in scope.lists.items()}
        pairs: dict[str, list[tuple[str, str]]] = {}

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
                    detail=repr(kind),
                )
                disposition = ObservationDisposition.UNKNOWN
        else:
            disposition = ObservationDisposition.OPEN
        kind_text = self._evidence(kind, MAX_METADATA_VALUE_CHARS, "result_kind", path, truncated)

        level, level_source = self._effective_level(scope, result, rule, kind_present, kind)
        severity, severity_scalars = self._severity(
            result, rule, level, level_source, path, truncated
        )

        descriptor = rule.descriptor
        if rule.component is not None:
            component_name = text_of(rule.component.get("name")) or rule.label
            self._scalar(scalars, "rule_component", component_name, path, truncated)
        if descriptor is not None:
            self._scalar(scalars, "rule_name", descriptor.get("name"), path, truncated)
            help_uri = self._uri(descriptor.get("helpUri"), "rule helpUri", f"{path}.rule.helpUri")
            if help_uri:
                scalars["rule_help_uri"] = help_uri
            rule_properties = _mapping(descriptor.get("properties"))
            raw_tags = _sequence(rule_properties.get("tags")) if rule_properties else []
            tags = self._evidence_list(raw_tags, "rule_tags", path, truncated)
            if tags:
                lists["rule_tags"] = tags
            deprecated = self._evidence_list(
                _sequence(descriptor.get("deprecatedIds")), "rule_deprecated_ids", path, truncated
            )
            if deprecated:
                lists["rule_deprecated_ids"] = deprecated

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
        for member, key in (
            ("fingerprints", "fingerprints"),
            ("partialFingerprints", "partial_fingerprints"),
        ):
            recorded = self._fingerprint_pairs(result.get(member), key, path, truncated)
            if recorded:
                pairs[key] = recorded
        taxa_ids = [
            text_of(taxon.get("id"))
            for taxon in _sequence(result.get("taxa"))
            if isinstance(taxon, Mapping)
        ]
        taxa = self._evidence_list(taxa_ids, "taxa", path, truncated)
        if taxa:
            lists["taxa"] = taxa

        # A suppressed result stays OPEN: a developer's nosemgrep comment is exactly what an
        # evaluator must see (decision 10).
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
            suppression_kinds = self._evidence_list(kinds, "suppression_kinds", path, truncated)
            if suppression_kinds:
                lists["suppression_kinds"] = suppression_kinds
            suppression_statuses = self._evidence_list(
                statuses, "suppression_statuses", path, truncated
            )
            if suppression_statuses:
                lists["suppression_statuses"] = suppression_statuses

        observed_at = self._result_clock(scope, result, path)
        title, description = self._describe(result, rule, path, truncated)
        identifiers = _extract_identifiers(self._identifier_sources(result, rule, record_id))

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
        descriptor, descriptor_index = _resolve_descriptor(component, reference, result, string_id)
        descriptor_id = text_of(descriptor.get("id")) if descriptor is not None else ""
        record_id = string_id or descriptor_id
        if not record_id:
            self.diagnostics.add(
                DiagnosticLevel.ERROR,
                "rule_id_missing",
                "no ruleId, rule.id, rule.index, or ruleIndex resolves to a rule identifier",
                path,
            )
            return None
        self._require_identity(record_id, MAX_IDENTITY_CHARS, "rule identifier", path)
        if string_id and descriptor_id and not _is_component_prefix(descriptor_id, string_id):
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "rule_reference_conflict",
                "the rule id string and the resolved descriptor id disagree; the string wins",
                path,
                detail=f"{string_id!r} against descriptor {descriptor_id!r}",
            )
        return _RuleRef(component, label, descriptor, descriptor_index), record_id

    def _effective_level(
        self,
        scope: _RunScope,
        result: Mapping[str, Any],
        rule: _RuleRef,
        kind_present: bool,
        kind: str,
    ) -> tuple[str, str]:
        """Apply the level chain of spec 3.27.10 and name the step that decided it."""
        if kind_present and kind != "fail":
            return "none", "forced_none"
        level = text_of(result.get("level"))
        if level:
            return level, "result"
        override = _override_level(scope, result, rule)
        if override:
            return override, "invocation_override"
        descriptor = rule.descriptor
        configuration = _mapping(descriptor.get("defaultConfiguration")) if descriptor else None
        default = text_of(configuration.get("level")) if configuration is not None else ""
        if default:
            return default, "rule_default"
        return "warning", "default"

    def _severity(
        self,
        result: Mapping[str, Any],
        rule: _RuleRef,
        level: str,
        level_source: str,
        path: str,
        truncated: set[str],
    ) -> tuple[SourceSeverity, dict[str, str]]:
        """Map security-severity when usable, else the level, and record the source."""
        scalars: dict[str, str] = {"level_source": level_source}
        self._scalar(scalars, "level", level, path, truncated)
        holders: tuple[Mapping[str, Any] | None, ...] = (result, rule.descriptor)
        severity: SourceSeverity | None = None
        for holder in holders:
            properties = _mapping(holder.get("properties")) if holder is not None else None
            if properties is None or "security-severity" not in properties:
                continue
            raw = properties["security-severity"]
            verbatim = raw if isinstance(raw, str) else _encode_list([raw])[1:-1]
            self._scalar(scalars, "security_severity", verbatim, path, truncated)
            score, usable = _score(raw)
            if not usable:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "security_severity_invalid",
                    "security-severity is not a finite number above 0 and at most 10; ignored",
                    path,
                    detail=repr(raw),
                )
            elif score is not None:
                severity = _band(score)
            break
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
                detail=repr(level),
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
        """Return the capped title and the expanded, capped description (decision 14)."""
        descriptor = rule.descriptor
        message = _mapping(result.get("message"))
        text = text_of(message.get("text")) if message is not None else ""
        message_id = text_of(message.get("id")) if message is not None else ""
        if not text and message_id:
            text = _message_string(descriptor, "messageStrings", message_id) or _message_string(
                rule.component, "globalMessageStrings", message_id
            )
        if not text and descriptor is not None:
            full = _mapping(descriptor.get("fullDescription"))
            text = text_of(full.get("text")) if full is not None else ""
        if text:
            # Links are flattened on the template, so argument text is never scanned.
            arguments = _sequence(message.get("arguments")) if message is not None else []
            text = _expand_message(_flatten_links(text), arguments)
        description = self._evidence(text, MAX_DESCRIPTION_CHARS, "description", path, truncated)
        title_text = ""
        if descriptor is not None:
            short = _mapping(descriptor.get("shortDescription"))
            title_text = text_of(short.get("text")) if short is not None else ""
            title_text = title_text or text_of(descriptor.get("name"))
        title = self._evidence(title_text, MAX_TITLE_CHARS, "title", path, truncated)
        return title, description

    def _identifier_sources(
        self, result: Mapping[str, Any], rule: _RuleRef, record_id: str
    ) -> list[str]:
        """Gather the texts decision 15 reads for CVE, GHSA, and CWE identifiers."""
        texts = [record_id]
        descriptor = rule.descriptor
        if descriptor is not None:
            texts.append(text_of(descriptor.get("id")))
            texts.append(text_of(descriptor.get("name")))
            texts.extend(_property_texts(_mapping(descriptor.get("properties"))))
            for relationship in _sequence(descriptor.get("relationships")):
                entry = _mapping(relationship)
                target = _mapping(entry.get("target")) if entry is not None else None
                if target is not None:
                    texts.append(text_of(target.get("id")))
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
        """Return one hit per distinct resource among result.locations (decision 7)."""
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
    # normalized, so a repository-relative path is the same on every runner (decision 6).
    def _locate(self, scope: _RunScope, location: Mapping[str, Any], path: str) -> _Hit | None:
        """Turn one location into a resource hit, or None when it names nothing usable."""
        truncated: set[str] = set()
        physical = _mapping(location.get("physicalLocation"))
        artifact_location = _mapping(physical.get("artifactLocation")) if physical else None
        uri = ""
        if artifact_location is not None:
            uri = text_of(artifact_location.get("uri"))
            if not uri:
                artifact_index = _natural(artifact_location.get("index"))
                if artifact_index is not None and artifact_index < len(scope.artifacts):
                    entry = _mapping(scope.artifacts[artifact_index])
                    entry_location = _mapping(entry.get("location")) if entry is not None else None
                    uri = text_of(entry_location.get("uri")) if entry_location else ""
        region_key, region_text = _region(_mapping(physical.get("region")) if physical else None)
        message = _mapping(location.get("message"))
        message_text = self._evidence(
            message.get("text") if message is not None else None,
            MAX_LIST_ITEM_CHARS,
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
            self._require_identity(uri, MAX_URI_CHARS, "location uri", uri_path)
            if uri.startswith("//") or ".." in uri.split("/"):
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
                base_entry = _mapping(scope.original_uri_base_ids.get(base_id))
                base_uri = self._uri(
                    base_entry.get("uri") if base_entry is not None else None,
                    "original uri base",
                    f"{scope.path}.originalUriBaseIds.{base_id}.uri",
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
            paired = f"{region_text}: {message_text}" if region_text else message_text
            messages.append((region_key or _NO_REGION, paired))
        return _Hit(resource_type, resource_id, regions, messages, scalars, logical, truncated)

    # Folding

    # The fold is a pure function of the candidate set: every choice is a max, a min, or a
    # sort, so result order never reaches the observation (decision 8).
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
        observed_at = min(observed) if observed else None

        metadata = dict(primary.scalars)
        metadata.update(strongest.severity_scalars)
        if worst.kind:
            metadata["result_kind"] = worst.kind
        flags = {candidate.suppressed for candidate in ordered}
        if "true" in flags:
            metadata["suppressed"] = "true"
        elif "false" in flags:
            metadata["suppressed"] = "false"

        lists: dict[str, list[str]] = {}
        for candidate in ordered:
            for member, items in candidate.lists.items():
                lists.setdefault(member, []).extend(items)
        lists["result_kinds"] = [candidate.kind for candidate in ordered if candidate.kind]
        for member, items in lists.items():
            if items:
                metadata[member] = _encode_list(
                    self._cut(sorted(set(items)), member, path, truncated)
                )
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

        identifiers: set[str] = set()
        for candidate in ordered:
            identifiers |= candidate.identifiers
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
            identifiers=tuple(sorted(identifiers)),
            context_key=context_key,
            metadata=metadata,
        )
        # The caps of decision 13 make this unreachable in theory; the check keeps the
        # stateless and persisted paths refusing the same input the same way (decision 16).
        size = len(observation.to_canonical_json().encode("utf-8"))
        if size > MAX_OBSERVATION_JSON_BYTES:
            raise InputLimitError(
                f"observation {observation.observation_id} is {size} bytes of canonical JSON; "
                f"maximum is {MAX_OBSERVATION_JSON_BYTES}"
            )
        return observation


# *--- Adapter ---*


# SECURITY: The adapter reads only the already-parsed document. It opens no path and
# fetches no uri; helpUri, informationUri, originalUriBaseIds, and repositoryUri are text.
class SarifAdapter:
    """Parse one bounded SARIF 2.1.0 document into observations and coalesced diagnostics."""

    name = "complyroll.sarif"
    version = SARIF_PARSER_VERSION
    media_type = SARIF_MEDIA_TYPE

    # The limits reach the adapter through its constructor (decision 17), so the parse
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
