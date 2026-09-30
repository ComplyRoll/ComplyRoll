# ******************************************************************************
# *Title: HDF Adapter*
# *Author: Kyle Versluis*
# *Description: HDF (InSpec exec-json) adapter on the ADR 0002 identity.*
# ******************************************************************************
"""Heimdall Data Format (InSpec exec-json) source adapter (ADR 0013)."""

# *--- Imports ---*

from __future__ import annotations

import heapq
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
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
from .common import (
    EVIDENCE_TRUNCATED_SUMMARY,
    MAX_DESCRIPTION_CHARS,
    MAX_IDENTITY_CHARS,
    MAX_LIST_ITEMS,
    MAX_OBSERVATION_JSON_BYTES,
    MAX_TITLE_CHARS,
    SEVERITY_RANK,
    EvidenceParse,
    IdentityRefused,
    earliest,
    encode_list,
    extract_identifiers,
    first_identifiers,
    make_observation,
    missing_time_diagnostic,
    observation_bytes,
    quoted,
    text_of,
)
from .safeio import DEFAULT_LIMITS, IngestLimits, InputLimitError

# *--- Configuration ---*

# The parser version is an observation identity input (ADR 0002), so HDF owns its own:
# an HDF correction can never re-mint a CKLB, CKL, XCCDF, or SARIF observation.
HDF_PARSER_VERSION = "1"
HDF_MEDIA_TYPE = "application/json"
HDF_SOURCE_TYPE = "hdf"
HDF_NATIVE_TOOL = "inspec"
HDF_CONVERTER_TOOL = "heimdall-tools"
# saf convert writes this platform name on every document it converts; compared exactly.
HDF_CONVERTER_PLATFORM = "Heimdall Tools"

# A parent_profile chain cannot outgrow the profile count without a cycle, and the walk keeps
# a visited set, so this also bounds every chain (decision 10).
MAX_PROFILES_PER_DOCUMENT = 64

RESOURCE_TYPE_TARGET = "target"
RESOURCE_TYPE_SCAN = "scan"

# The fixed metadata vocabulary: a producer can never mint a key (decision 10).
HDF_METADATA_KEYS = frozenset(
    {
        "platform_name",
        "platform_release",
        "producer_version",
        "profile_name",
        "profile_title",
        "profile_version",
        "profile_sha256",
        "profile_parent",
        "profile_status",
        "impact",
        "severity_tag",
        "severity_override",
        "severity_source",
        "disposition_source",
        "group_id",
        "rule_id",
        "stig_id",
        "nist_tags",
        "waived",
        "waiver_justification",
        "waiver_expiration",
        "waiver_run",
        "waiver_skipped",
        "attested",
        "attestation_status",
        "attestation_explanation",
        "attestation_frequency",
        "attestation_updated",
        "result_count",
        "passed_count",
        "failed_count",
        "skipped_count",
        "error_count",
        "unknown_count",
        "failed_results",
        "failure_messages",
        "occurrence_count",
        "truncated",
    }
)
# A fold takes each group whole from one candidate, so one copy's justification is never
# paired with another copy's expiration (decision 9).
_WAIVER_KEYS = frozenset(
    {"waived", "waiver_justification", "waiver_expiration", "waiver_run", "waiver_skipped"}
)
_ATTESTATION_KEYS = frozenset(
    {
        "attested",
        "attestation_status",
        "attestation_explanation",
        "attestation_frequency",
        "attestation_updated",
    }
)
# A fold takes these from the strongest candidate, and each list from every candidate.
_SEVERITY_KEYS = frozenset({"impact", "severity_tag", "severity_override", "severity_source"})
_LIST_KEYS = frozenset({"failed_results", "failure_messages", "nist_tags"})

# A failure beats an error, a pass beats a skip, and not applicable ranks lowest, as the
# producers roll a control up; this is not SARIF's worst-wins table (decision 4).
HDF_DISPOSITION_RANK = {
    ObservationDisposition.OPEN: 5,
    ObservationDisposition.ERROR: 4,
    ObservationDisposition.UNKNOWN: 3,
    ObservationDisposition.PASS: 2,
    ObservationDisposition.NOT_REVIEWED: 1,
    ObservationDisposition.NOT_APPLICABLE: 0,
}

# InSpec's own three statuses and the converters' error spelling (decision 4).
_RESULT_STATUSES = {
    "failed": ObservationDisposition.OPEN,
    "error": ObservationDisposition.ERROR,
    "passed": ObservationDisposition.PASS,
    "skipped": ObservationDisposition.NOT_REVIEWED,
}
# Each result counts once, under the disposition it read; no result reads not applicable.
_COUNT_KEYS = {
    ObservationDisposition.PASS: "passed_count",
    ObservationDisposition.OPEN: "failed_count",
    ObservationDisposition.NOT_REVIEWED: "skipped_count",
    ObservationDisposition.ERROR: "error_count",
    ObservationDisposition.UNKNOWN: "unknown_count",
}
_ZERO_COUNTS = dict.fromkeys(("result_count", *_COUNT_KEYS.values()), 0)

# The five names of InSpec's impact table and Heimdall's severities (decision 7).
_SEVERITY_TAGS = {
    "none": SourceSeverity.INFORMATIONAL,
    "low": SourceSeverity.LOW,
    "medium": SourceSeverity.MEDIUM,
    "high": SourceSeverity.HIGH,
    "critical": SourceSeverity.CRITICAL,
}
# InSpec's impact thresholds, read from the top; below the last one is informational.
_IMPACT_BANDS = (
    (0.9, SourceSeverity.CRITICAL),
    (0.7, SourceSeverity.HIGH),
    (0.4, SourceSeverity.MEDIUM),
    (0.1, SourceSeverity.LOW),
)

# The two code_desc texts saf attest apply writes on the result it appends (decision 5).
_ATTESTED_MARKER = "Manually verified status provided through attestation"
_EXPIRED_MARKER = "Manual verification status provided through attestation has expired"

# SECURITY: The pattern is fixed, ASCII only, and matched whole, so another script's digits
# never become a CCI.
_CCI = re.compile(r"CCI-[0-9]{6}", re.ASCII)

# *--- Types ---*

_FoldKey = tuple[str, str, str, str]


@dataclass(slots=True)
class _Profile:
    """One indexed profile: its position, name, parent link, and cleaned scalars."""

    path: str
    name: str
    # None for a root; otherwise the stripped parent_profile text, which may name nothing.
    parent: str | None
    body: Mapping[str, Any]
    scalars: dict[str, str] = field(default_factory=dict)
    truncated: set[str] = field(default_factory=set)
    # Parent links between the profile and its root, set once its chain resolves.
    depth: int = 0


@dataclass(slots=True)
class _Candidate:
    """One control entry's contribution to one observation before folding."""

    order: tuple[Any, ...]
    path: str
    # The profile's depth under its root, which orders the shadowed copies (decision 9).
    depth: int
    has_results: bool
    disposition: ObservationDisposition
    disposition_source: str
    severity: SourceSeverity
    severity_scalars: dict[str, str]
    observed_at: datetime | None
    title: str
    description: str
    # The first MAX_LIST_ITEMS identifiers in sorted order, and whether any was cut.
    identifiers: tuple[str, ...]
    identifiers_cut: bool
    scalars: dict[str, str]
    # Every list arrives cut by _fold_part, so a fold's union stays bounded.
    lists: dict[str, tuple[str, ...]]
    counts: dict[str, int]
    truncated: set[str]


# *--- Helper Functions ---*


# SECURITY: The sniff reads only an already-bounded parse, and stigs is tested first, so a
# document that claims to be a checklist stays a checklist (decision 1).
def looks_like_hdf(value: object) -> bool:
    """Say whether a parsed bare .json document has the exec-json root keys."""
    return (
        isinstance(value, Mapping)
        and "stigs" not in value
        and isinstance(value.get("profiles"), list)
        and isinstance(value.get("platform"), Mapping)
    )


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _tag_items(value: object) -> list[Any]:
    """Return a tag's items: a string is one item, a list its members, anything else none."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _impact(raw: object) -> float | int | None:
    """Return an impact that is a JSON number from 0 to 1, or None (decision 7)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        # WARN: float() overflows above about 1.8e308: on every integer of 310 or more digits
        # and on most of 309, which a JSON number can carry, so the range check runs first.
        return raw if 0 <= raw <= 1 else None
    if isinstance(raw, float):
        return raw if math.isfinite(raw) and 0.0 <= raw <= 1.0 else None
    return None


def _severity_name(raw: object) -> SourceSeverity | None:
    """Map a severity tag to its severity; case and surrounding space are ignored."""
    return _SEVERITY_TAGS.get(raw.strip().lower()) if isinstance(raw, str) else None


def _severity(
    override: SourceSeverity | None, tag: SourceSeverity | None, impact: float | int | None
) -> tuple[SourceSeverity, str]:
    """Pick the override, else the tag, else the impact band, and name the source."""
    if override is not None:
        return override, "severityoverride"
    if tag is not None:
        return tag, "severity"
    if impact is not None:
        for threshold, severity in _IMPACT_BANDS:
            if impact >= threshold:
                return severity, "impact"
        return SourceSeverity.INFORMATIONAL, "impact"
    return SourceSeverity.UNKNOWN, "none"


# InSpec writes a check that raised as its RSpec status, often passed, plus an exception and
# a backtrace; both upstream readers call that an error. Only presence is read (decision 4).
def _has_backtrace(result: Mapping[str, Any]) -> bool:
    """Say whether a result carries a backtrace that is not null, false, or empty text."""
    if "backtrace" not in result:
        return False
    value = result["backtrace"]
    return value is not None and value is not False and value != ""


def _is_attestation_result(result: Mapping[str, Any], attested: bool) -> bool:
    """Say whether a result is the one saf attest apply appended to an attested control."""
    return attested and result.get("code_desc") in (_ATTESTED_MARKER, _EXPIRED_MARKER)


def _result_disposition(result: Mapping[str, Any]) -> ObservationDisposition | None:
    """Read one result; None when its status is outside the four known values."""
    if _has_backtrace(result):
        return ObservationDisposition.ERROR
    status = result.get("status")
    return _RESULT_STATUSES.get(status) if isinstance(status, str) else None


def _control_disposition(
    impact: float | int | None, dispositions: list[ObservationDisposition]
) -> tuple[ObservationDisposition, str, ObservationDisposition]:
    """Roll a control up: impact 0, then no results, then the highest-ranked result."""
    rolled = (
        max(dispositions, key=HDF_DISPOSITION_RANK.__getitem__)
        if dispositions
        else ObservationDisposition.ERROR
    )
    if impact is not None and impact == 0:
        return ObservationDisposition.NOT_APPLICABLE, "impact_zero", rolled
    if not dispositions:
        return ObservationDisposition.ERROR, "no_results", rolled
    return rolled, "results", rolled


def _description(control: Mapping[str, Any]) -> object:
    """Return desc, else the descriptions entry labelled default, else nothing."""
    desc = control.get("desc")
    if text_of(desc):
        return desc
    descriptions = control.get("descriptions")
    if isinstance(descriptions, list):
        for entry in descriptions:
            if isinstance(entry, Mapping) and entry.get("label") == "default":
                return entry.get("data")
    return None


# Each of a fold union's first MAX_LIST_ITEMS items is among the first MAX_LIST_ITEMS of the
# list it came from, and one item past them keeps the cut flag, so a list is cut here once.
def _fold_part(items: Iterable[str]) -> tuple[str, ...]:
    """Keep a list's MAX_LIST_ITEMS + 1 smallest distinct items, in sorted order."""
    return tuple(heapq.nsmallest(MAX_LIST_ITEMS + 1, set(items)))


# *--- Core Logic ---*


class _HdfParse(EvidenceParse):
    """One document's parse state: the profile index, identity folds, coalesced diagnostics."""

    def __init__(
        self, artifact: ArtifactProvenance, ingested_at: datetime, limits: IngestLimits
    ) -> None:
        super().__init__(artifact, ingested_at, limits)
        self.folds: dict[_FoldKey, list[_Candidate]] = {}
        self.profiles: dict[str, _Profile] = {}
        # Names refused as identity inputs; a profile hanging under one is skipped silently.
        self.refused: set[str] = set()
        self.roots: dict[str, str | None] = {}
        self.source_tool = HDF_NATIVE_TOOL
        self.target = ""
        self.scalars: dict[str, str] = {}
        self.truncated: set[str] = set()
        # A control id is checked at MAX_IDENTITY_CHARS, so its text alone keys its check.
        self.id_problems: dict[str, str | None] = {}

    def run(self, data: Mapping[str, Any]) -> AdapterOutput:
        """Scan every profile's controls, fold by identity, and fail closed on any error."""
        if self._scan_document(data):
            for profile in self._index_profiles(data["profiles"]):
                root = self._root_of(profile)
                if root is not None:
                    self._scan_profile(profile, root)
            self._shadow()
        if not self.folds:
            self.diagnostics.add_fixed(
                IngestDiagnostic(
                    DiagnosticLevel.ERROR,
                    "no_observations",
                    "HDF document contains no usable controls",
                    self.artifact.name,
                )
            )
        observations: list[Observation] = []
        # SECURITY: An ERROR anywhere withholds every observation (refuse identity).
        if not self.diagnostics.has_errors:
            observations = [self._assemble(key, self.folds[key]) for key in sorted(self.folds)]
        return AdapterOutput(tuple(observations), self.diagnostics.emit(self.artifact.name))

    # Document and profiles

    def _scan_document(self, data: Mapping[str, Any]) -> bool:
        """Read the platform and producer once; False when the target is refused."""
        platform: Mapping[str, Any] = data["platform"]
        if platform.get("name") == HDF_CONVERTER_PLATFORM:
            self.source_tool = HDF_CONVERTER_TOOL
            self.diagnostics.add(
                DiagnosticLevel.INFO,
                "converted_document",
                "platform.name is Heimdall Tools; the source tool is heimdall-tools and the "
                "resource is the converter's target",
                "platform",
            )
        self.target = text_of(platform.get("target_id"))
        if self.target:
            # SECURITY: target_id is an identity input, refused whole and never repaired
            # (decision 10).
            try:
                self._require_identity(
                    self.target, MAX_IDENTITY_CHARS, "target_id", "platform.target_id"
                )
            except IdentityRefused:
                return False
        else:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "resource_identity_fallback",
                "platform.target_id is absent, blank, or not a string; the root profile name "
                "is the resource",
                "platform",
            )
        for key, member in (("platform_name", "name"), ("platform_release", "release")):
            self._scalar(self.scalars, key, platform.get(member), "platform", self.truncated)
        self._scalar(
            self.scalars, "producer_version", data.get("version"), "version", self.truncated
        )
        return True

    def _profile_error(self, summary: str, path: str) -> None:
        self.diagnostics.add(DiagnosticLevel.ERROR, "invalid_profile", summary, path)

    def _index_profiles(self, profiles: list[Any]) -> list[_Profile]:
        """Index every profile by name, in document order; a repeat is an error."""
        indexed: list[_Profile] = []
        for index, body in enumerate(profiles):
            path = f"profiles[{index}]"
            if not isinstance(body, Mapping):
                self._profile_error("profile must be an object", path)
                continue
            name = text_of(body.get("name"))
            if not name:
                self._profile_error("profile name is missing, not a string, or empty", path)
                continue
            # SECURITY: A profile name is an identity input, refused whole (decision 10).
            try:
                self._require_identity(name, MAX_IDENTITY_CHARS, "profile name", f"{path}.name")
            except IdentityRefused:
                self.refused.add(name)
                continue
            if name in self.profiles:
                self._profile_error("profile name is carried by two profiles", path)
                continue
            raw_parent = body.get("parent_profile")
            parent = None if raw_parent is None else text_of(raw_parent)
            profile = _Profile(path, name, parent, body)
            self.profiles[name] = profile
            indexed.append(profile)
        return indexed

    # The walk follows parent_profile upward with a visited set, and every profile it passes
    # shares the answer and learns its depth, so each link is followed once and each fault is
    # reported once.
    def _root_of(self, profile: _Profile) -> str | None:
        """Return the name of the root a profile hangs under, or None when the chain breaks."""
        chain: list[str] = []
        current = profile
        root: str | None
        while True:
            if current.name in self.roots:
                root = self.roots[current.name]
                break
            if current.name in chain:
                closing = self.profiles[chain[-1]]
                self._profile_error("parent_profile links form a cycle", closing.path)
                root = None
                break
            chain.append(current.name)
            if current.parent is None:
                root = current.name
                break
            parent = self.profiles.get(current.parent)
            if parent is None:
                if current.parent not in self.refused:
                    self._profile_error(
                        "parent_profile names no profile in this document", current.path
                    )
                root = None
                break
            current = parent
        for name in chain:
            self.roots[name] = root
        if root is not None and chain:
            # A walk that reached the root counts from it; one that met a resolved profile
            # counts on from that profile's depth.
            depth = -1 if chain[-1] == current.name else current.depth
            for name in reversed(chain):
                depth += 1
                self.profiles[name].depth = depth
        return root

    def _scan_profile(self, profile: _Profile, root: str) -> None:
        """Clean one profile's scalars once, then scan its controls."""
        body, path = profile.body, profile.path
        status = body.get("status")
        if status is not None and status != "loaded":
            message = body.get("status_message")
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "profile_not_loaded",
                "profile status is not loaded; its controls carry no results and yield error "
                "observations",
                path,
                detail=f"status {quoted(status)}, status_message {quoted(message)}",
            )
        for key, member in (
            ("profile_name", "name"),
            ("profile_title", "title"),
            ("profile_version", "version"),
            ("profile_sha256", "sha256"),
            ("profile_parent", "parent_profile"),
            ("profile_status", "status"),
        ):
            self._scalar(profile.scalars, key, body.get(member), path, profile.truncated)
        controls = body.get("controls")
        if not isinstance(controls, list):
            self._profile_error("profile controls must be an array", path)
            return
        if len(controls) > self.limits.max_results_per_run:
            raise InputLimitError(
                f"{path} contains {len(controls)} controls; "
                f"maximum is {self.limits.max_results_per_run}"
            )
        for index, control in enumerate(controls):
            try:
                self._scan_control(profile, root, index, control)
            except IdentityRefused:
                continue

    # Controls and results

    def _control_error(self, summary: str, path: str) -> None:
        self.diagnostics.add(DiagnosticLevel.ERROR, "invalid_control", summary, path)

    def _scan_control(self, profile: _Profile, root: str, index: int, control: object) -> None:
        """Roll one control entry up into a candidate under its fold key."""
        path = f"{profile.path}.controls[{index}]"
        if not isinstance(control, Mapping):
            self._control_error("control must be an object", path)
            return
        record_id = text_of(control.get("id"))
        if not record_id:
            self._control_error("control id is missing, not a string, or empty", path)
            return
        # SECURITY: A control id is an identity input, refused whole (decision 10).
        self._require_identity(
            record_id, MAX_IDENTITY_CHARS, "control id", f"{path}.id", self.id_problems
        )
        results = control.get("results")
        if not isinstance(results, list):
            self._control_error("control results must be an array", path)
            return
        if len(results) > self.limits.max_results_per_run:
            raise InputLimitError(
                f"{path} contains {len(results)} results; "
                f"maximum is {self.limits.max_results_per_run}"
            )
        truncated = self.truncated | profile.truncated
        scalars = {**self.scalars, **profile.scalars}
        lists: dict[str, tuple[str, ...]] = {}
        tags = _mapping(control.get("tags")) or {}

        impact = None
        if control.get("impact") is not None:
            impact = _impact(control["impact"])
            if impact is None:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "invalid_impact",
                    "impact is not a number from 0 to 1; it sets neither applicability nor "
                    "severity",
                    path,
                    detail=quoted(control["impact"]),
                )
        severity, severity_scalars = self._control_severity(tags, impact, path, truncated)

        # Absent, null, and every empty or false value mean none; any other value is one, and
        # only an object's members are read, so a malformed member is never silent (decision 5).
        raw_waiver = control.get("waiver_data")
        if raw_waiver:
            self._waiver(_mapping(raw_waiver), scalars, path, truncated)
        raw_attestation = control.get("attestation_data")
        # A marker result under any attestation lends no clock and no text, whatever its shape.
        attested = bool(raw_attestation)
        attestation = _mapping(raw_attestation)
        if attestation:
            for key, member in (
                ("attestation_status", "status"),
                ("attestation_explanation", "explanation"),
                ("attestation_frequency", "frequency"),
                ("attestation_updated", "updated"),
            ):
                self._scalar(scalars, key, attestation.get(member), path, truncated)

        counts = dict(_ZERO_COUNTS)
        dispositions: list[ObservationDisposition] = []
        clocks: list[datetime] = []
        failures: list[object] = []
        messages: list[object] = []
        expired = False
        for position, result in enumerate(results):
            result_path = f"{path}.results[{position}]"
            if not isinstance(result, Mapping):
                self._control_error("result must be an object", result_path)
                continue
            disposition, clock, marker = self._scan_result(
                result, result_path, attested, failures, messages
            )
            dispositions.append(disposition)
            counts["result_count"] += 1
            counts[_COUNT_KEYS[disposition]] += 1
            expired = expired or marker == _EXPIRED_MARKER
            if clock is not None:
                clocks.append(clock)
        if attested:
            scalars["attested"] = "expired" if expired else "true"
            notes = ["expired"] if expired else []
            if attestation is None:
                notes.append("attestation_data is not an object")
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "control_attested",
                "control carries attestation data; the attestation is recorded as metadata and "
                "never changes the disposition",
                path,
                detail="; ".join(notes),
            )

        disposition, source, rolled = _control_disposition(impact, dispositions)
        # An empty copy's line waits for _shadow, which knows whether the copy yields anything.
        if source == "impact_zero" and results:
            self._impact_zero(path, rolled)
        for key, member, items in (
            ("failed_results", "failed_results", failures),
            ("failure_messages", "failure_messages", messages),
            ("nist_tags", "nist_tags", _tag_items(tags.get("nist"))),
        ):
            kept = _fold_part(self._evidence_list(items, member, path, truncated))
            if kept:
                lists[key] = kept
        for key, member in (("group_id", "gid"), ("rule_id", "rid"), ("stig_id", "stig_id")):
            self._scalar(scalars, key, tags.get(member), path, truncated)

        title = self._evidence(control.get("title"), MAX_TITLE_CHARS, "title", path, truncated)
        description = self._evidence(
            _description(control), MAX_DESCRIPTION_CHARS, "description", path, truncated
        )
        identifiers, identifiers_cut = first_identifiers(
            self._identifiers(control, tags, record_id, path)
        )
        # The order is a function of content alone, so the fold ignores document order. The cut
        # keys come last, so a text that spells the cut marker never ties with one that was cut.
        candidate = _Candidate(
            order=(
                title,
                description,
                tuple(
                    sorted({**scalars, **severity_scalars, "disposition_source": source}.items())
                ),
                tuple(sorted(lists.items())),
                tuple(sorted(truncated)),
            ),
            path=path,
            depth=profile.depth,
            has_results=bool(results),
            disposition=disposition,
            disposition_source=source,
            severity=severity,
            severity_scalars=severity_scalars,
            observed_at=earliest(clocks) if clocks else None,
            title=title,
            description=description,
            identifiers=identifiers,
            identifiers_cut=identifiers_cut,
            scalars=scalars,
            lists=lists,
            counts=counts,
            truncated=truncated,
        )
        if self.target:
            fold_key = (root, record_id, RESOURCE_TYPE_TARGET, self.target)
        else:
            fold_key = (root, record_id, RESOURCE_TYPE_SCAN, root)
        bucket = self.folds.get(fold_key)
        if bucket is None:
            if len(self.folds) >= self.limits.max_observations_per_artifact:
                raise InputLimitError(
                    f"artifact yields more than "
                    f"{self.limits.max_observations_per_artifact} observations"
                )
            bucket = self.folds[fold_key] = []
        bucket.append(candidate)

    def _scan_result(
        self,
        result: Mapping[str, Any],
        path: str,
        attested: bool,
        failures: list[object],
        messages: list[object],
    ) -> tuple[ObservationDisposition, datetime | None, object]:
        """Read one result's disposition and clock, keeping a failure's texts."""
        disposition = _result_disposition(result)
        if disposition is None:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "invalid_result_status",
                "result status is not passed, failed, skipped, or error; the result is unknown",
                path,
                detail=quoted(result.get("status")),
            )
            disposition = ObservationDisposition.UNKNOWN
        if _is_attestation_result(result, attested):
            # The appended result's start_time is when the attestation was applied and its
            # message names who attested, so neither is read (decision 5).
            return disposition, None, result.get("code_desc")
        clock = None
        start = result.get("start_time")
        # A converter writes "" by design, so an empty clock is absent without a warning.
        if start is not None and not (isinstance(start, str) and not start.strip()):
            clock = self._clock(start, f"{path}.start_time")
        if disposition in (ObservationDisposition.OPEN, ObservationDisposition.ERROR):
            failures.append(result.get("code_desc"))
            message = result.get("message")
            messages.append(message if text_of(message) else result.get("exception"))
        return disposition, clock, None

    def _control_severity(
        self, tags: Mapping[str, Any], impact: float | int | None, path: str, truncated: set[str]
    ) -> tuple[SourceSeverity, dict[str, str]]:
        """Read both severity tags and the impact, and record which one decided."""
        scalars: dict[str, str] = {}
        if impact is not None:
            scalars["impact"] = json.dumps(impact + 0.0 if isinstance(impact, float) else impact)
        named: dict[str, SourceSeverity | None] = {}
        for key, member in (
            ("severity_override", "severityoverride"),
            ("severity_tag", "severity"),
        ):
            raw = tags.get(member)
            named[member] = None
            if raw is None:
                continue
            self._scalar(scalars, key, raw, path, truncated)
            named[member] = _severity_name(raw)
            if named[member] is None:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "invalid_severity_tag",
                    "severity tag is not none, low, medium, high, or critical; ignored",
                    path,
                    detail=quoted(raw),
                )
        severity, source = _severity(named["severityoverride"], named["severity"], impact)
        scalars["severity_source"] = source
        return severity, scalars

    def _waiver(
        self,
        waiver: Mapping[str, Any] | None,
        scalars: dict[str, str],
        path: str,
        truncated: set[str],
    ) -> None:
        """Record a present waiver as metadata; it never moves the disposition (decision 5)."""
        scalars["waived"] = "true"
        self.diagnostics.add(
            DiagnosticLevel.WARNING,
            "control_waived",
            "control carries waiver data; the waiver is recorded as metadata and never changes "
            "the disposition",
            path,
            detail="" if waiver is not None else "waiver_data is not an object",
        )
        if waiver is None:
            return
        self._scalar(scalars, "waiver_justification", waiver.get("justification"), path, truncated)
        self._scalar(scalars, "waiver_expiration", waiver.get("expiration_date"), path, truncated)
        run = waiver.get("run")
        if isinstance(run, bool):
            scalars["waiver_run"] = "true" if run else "false"
        skipped = waiver.get("skipped_due_to_waiver")
        if isinstance(skipped, bool):
            scalars["waiver_skipped"] = "true" if skipped else "false"
        else:
            self._scalar(scalars, "waiver_skipped", skipped, path, truncated)

    def _impact_zero(self, path: str, rolled: ObservationDisposition) -> None:
        """Say that a kept copy's impact 0 overrides what its results would read (decision 6)."""
        self.diagnostics.add(
            DiagnosticLevel.INFO,
            "impact_zero_not_applicable",
            "impact is 0, so the control is not applicable whatever its results say",
            path,
            detail=f"results would read {rolled.name}",
        )

    def _identifiers(
        self, control: Mapping[str, Any], tags: Mapping[str, Any], record_id: str, path: str
    ) -> set[str]:
        """Collect CCIs matched whole, and CVE, GHSA, and CWE ids from the id, title, and tags."""
        found: set[str] = set()
        for item in _tag_items(tags.get("cci")):
            text = text_of(item)
            if _CCI.fullmatch(text):
                found.add(text)
            else:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "invalid_cci_list",
                    "cci tag item is not a CCI-###### identifier; ignored",
                    path,
                    detail=quoted(item),
                )
        texts = [record_id, text_of(control.get("title"))]
        for member in ("cve", "cwe"):
            texts.extend(text_of(item) for item in _tag_items(tags.get(member)))
        found.update(extract_identifiers(texts))
        return found

    # Folding

    def _shadow(self) -> None:
        """Drop a control's empty copies wherever the same fold key carries results."""
        for key in sorted(self.folds):
            candidates = self.folds[key]
            if not any(candidate.has_results for candidate in candidates):
                # Every empty copy is kept, so each impact-0 one yields its line here.
                for candidate in candidates:
                    if candidate.disposition_source == "impact_zero":
                        self._impact_zero(candidate.path, ObservationDisposition.ERROR)
                continue
            kept: list[_Candidate] = []
            shadowed: list[_Candidate] = []
            for candidate in candidates:
                if candidate.has_results:
                    kept.append(candidate)
                else:
                    shadowed.append(candidate)
                    self.diagnostics.add(
                        DiagnosticLevel.INFO,
                        "profile_control_shadowed",
                        "control has no results and the same id carries results in another "
                        "profile of this run; it yields no observation",
                        candidate.path,
                    )
            self._hand_over(kept, shadowed)
            self.folds[key] = kept

    # An overlay's waiver or attestation can sit on a wrapper's empty copy while the results sit
    # on the leaf, so a shadowed copy passes its group on instead of losing it, but only a group
    # that no survivor carries. The outermost shadowed carrier passes first, as a wrapper
    # overrides the layers it includes, and content breaks a tie, so document order never
    # decides. A shadowed copy has no results and so no marker, so its attestation is never
    # expired, and an expired one can only be a survivor's own, which the fold keeps first.
    def _hand_over(self, kept: list[_Candidate], shadowed: list[_Candidate]) -> None:
        """Give every survivor the first shadowed carrier's group when none carries its own."""
        shadowed.sort(key=lambda candidate: (candidate.depth, candidate.order))
        for flag, group in (("waived", _WAIVER_KEYS), ("attested", _ATTESTATION_KEYS)):
            if any(flag in candidate.scalars for candidate in kept):
                continue
            carrier = next((candidate for candidate in shadowed if flag in candidate.scalars), None)
            if carrier is None:
                continue
            handed = {name: value for name, value in carrier.scalars.items() if name in group}
            for candidate in kept:
                candidate.scalars.update(handed)
                candidate.truncated |= carrier.truncated & group

    # The fold is a pure function of the candidate set: every choice is a max, a min, or a
    # sort, so document order never reaches the observation (decision 9).
    def _assemble(self, key: _FoldKey, candidates: list[_Candidate]) -> Observation:
        """Fold every candidate that shares an identity into one bounded observation."""
        context_key, record_id, resource_type, resource_id = key
        ordered = sorted(candidates, key=lambda candidate: candidate.order)
        primary = ordered[0]
        path = primary.path
        worst = max(ordered, key=lambda candidate: HDF_DISPOSITION_RANK[candidate.disposition])
        strongest = max(ordered, key=lambda candidate: SEVERITY_RANK[candidate.severity])
        # A waiver or an attestation on any copy is recorded. min keeps the first of equals, so
        # an expired attestation is kept over a current one, and a lapse is never folded away.
        waiver = next((candidate for candidate in ordered if "waived" in candidate.scalars), None)
        attestation = min(
            (candidate for candidate in ordered if "attested" in candidate.scalars),
            key=lambda candidate: candidate.scalars["attested"] != "expired",
            default=None,
        )
        observed = [candidate.observed_at for candidate in ordered if candidate.observed_at]
        observed_at = earliest(observed) if observed else None
        if observed_at is None:
            self.diagnostics.add_fixed(missing_time_diagnostic(self.artifact))

        # truncated names a cut only where the observation writes the value that was cut.
        truncated = primary.truncated - _SEVERITY_KEYS - _WAIVER_KEYS - _ATTESTATION_KEYS
        truncated |= strongest.truncated & _SEVERITY_KEYS
        metadata = {
            name: value
            for name, value in primary.scalars.items()
            if name not in _WAIVER_KEYS and name not in _ATTESTATION_KEYS
        }
        for carrier, group in ((waiver, _WAIVER_KEYS), (attestation, _ATTESTATION_KEYS)):
            if carrier is not None:
                metadata.update(
                    {name: value for name, value in carrier.scalars.items() if name in group}
                )
                truncated |= carrier.truncated & group
        metadata.update(strongest.severity_scalars)
        metadata["disposition_source"] = worst.disposition_source
        for count_key in _ZERO_COUNTS:
            metadata[count_key] = str(sum(candidate.counts[count_key] for candidate in ordered))
        lists: dict[str, set[str]] = {}
        for candidate in ordered:
            truncated |= candidate.truncated & _LIST_KEYS
            for member, items in candidate.lists.items():
                lists.setdefault(member, set()).update(items)
        for member, union in sorted(lists.items()):
            metadata[member] = encode_list(self._cut(sorted(union), member, path, truncated))
        identifiers, identifiers_cut = first_identifiers(
            identifier for candidate in ordered for identifier in candidate.identifiers
        )
        if identifiers_cut or any(candidate.identifiers_cut for candidate in ordered):
            truncated.add("source_identifiers")
            self.diagnostics.add(
                DiagnosticLevel.WARNING, "evidence_truncated", EVIDENCE_TRUNCATED_SUMMARY, path
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
            metadata["truncated"] = encode_list(sorted(truncated))
        foreign = sorted(set(metadata) - HDF_METADATA_KEYS)
        if foreign:
            raise RuntimeError(f"metadata keys outside the fixed vocabulary: {foreign}")

        observation = make_observation(
            artifact=self.artifact,
            source_type=HDF_SOURCE_TYPE,
            source_tool=self.source_tool,
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
        # SECURITY: Every HDF observation passes the per-observation ceiling and the artifact's
        # byte budget before it is kept, as a SARIF observation does (decision 10).
        size = observation_bytes(
            observation,
            ceiling=MAX_OBSERVATION_JSON_BYTES,
            budget=self.limits.max_observation_bytes_per_artifact,
            spent=self.observation_bytes,
        )
        self.observation_bytes += size
        return observation


# *--- Entry Point ---*


# SECURITY: The adapter reads only the already-parsed document. It opens no path, fetches
# nothing, and never reads depends, statistics, code, refs, or source_location.
class HdfAdapter:
    """Parse one bounded InSpec exec-json document into observations and diagnostics."""

    name = "complyroll.hdf"
    version = HDF_PARSER_VERSION
    media_type = HDF_MEDIA_TYPE

    # The limits reach the adapter through its constructor, as they reach SARIF's, so the
    # parse signature the STIG adapters share stays as base.py defines it.
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
            raise AdapterParseError("HDF root must be a JSON object")
        # SECURITY: A checklist's own member is refused under an HDF name, so a document that
        # carries both shapes is read as a checklist or not at all (decision 1).
        if "stigs" in data:
            raise AdapterParseError(
                "HDF document carries a 'stigs' member; a STIG Viewer checklist is read under "
                "a .cklb or .json name"
            )
        # The two other shapes an operator may hold are named, so the refusal says which.
        if "profiles" not in data:
            if "baselines" in data:
                raise AdapterParseError("hdf-libs v3 'baselines' root is not supported")
            if "controls" in data:
                raise AdapterParseError(
                    "'controls' root (json-min or profile export) is not supported"
                )
        profiles = data.get("profiles")
        if not isinstance(profiles, list) or not profiles:
            raise AdapterParseError("HDF profiles must be a non-empty array")
        if len(profiles) > MAX_PROFILES_PER_DOCUMENT:
            raise InputLimitError(
                f"HDF document lists {len(profiles)} profiles; "
                f"maximum is {MAX_PROFILES_PER_DOCUMENT}"
            )
        if not isinstance(data.get("platform"), Mapping):
            raise AdapterParseError("HDF platform must be an object")
        if not text_of(data.get("version")):
            raise AdapterParseError("HDF version must be a non-empty string")
        return _HdfParse(artifact, ingested_at, self.limits).run(data)
