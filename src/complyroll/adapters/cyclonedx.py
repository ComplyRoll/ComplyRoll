# ******************************************************************************
# *Title: CycloneDX Adapter*
# *Author: Kyle Versluis*
# *Description: CycloneDX SBOM adapter: package key, scope and vulnerabilities.*
# ******************************************************************************
"""CycloneDX SBOM source adapter (ADR 0016)."""

# *--- Imports ---*

from __future__ import annotations

import hashlib
import json
import math
import re
import string
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from complyroll.models import Observation, ObservationDisposition, SourceSeverity

from .base import (
    AdapterOutput,
    AdapterParseError,
    ArtifactProvenance,
    DiagnosticLevel,
    ParsedDocument,
)
from .common import (
    EVIDENCE_TRUNCATED_SUMMARY,
    MAX_DESCRIPTION_CHARS,
    MAX_IDENTITY_CHARS,
    MAX_LIST_ITEM_CHARS,
    MAX_LIST_ITEMS,
    MAX_OBSERVATION_JSON_BYTES,
    MAX_TITLE_CHARS,
    SEVERITY_RANK,
    EvidenceParse,
    IdentityRefused,
    clean,
    diagnostic_text,
    encode_list,
    extract_identifiers,
    first_identifiers,
    identity_problem,
    make_observation,
    missing_time_diagnostic,
    observation_bytes,
    quoted,
    sanitize,
)
from .safeio import DEFAULT_LIMITS, IngestLimits, InputLimitError

# *--- Configuration ---*

# The parser version is an observation identity input (ADR 0002), so CycloneDX owns its own:
# a correction here never re-mints another adapter's observations.
CYCLONEDX_PARSER_VERSION = "1"
# NOTE: The media type comes from design B and is unverified; it is recorded in provenance
# only and never read for dispatch.
CYCLONEDX_MEDIA_TYPE = "application/vnd.cyclonedx+json"
CYCLONEDX_SOURCE_TYPE = "cyclonedx"
CYCLONEDX_FALLBACK_TOOL = "cyclonedx"
SCOPE_RECORD_ID = "cyclonedx.bom"
SUPPORTED_SPEC_VERSIONS = frozenset({"1.4", "1.5", "1.6", "1.7"})
MAX_BOM_VERSION = 2**31

BOM_KIND_INVENTORY = "inventory"
BOM_KIND_EMPTY = "empty"
BOM_KIND_MATCHED = "matched"
SCAN_SCOPE_TYPE = "scan"

# A malformed document that carries no vulnerability record is an unreadable inventory, never
# a detection failure (A12), so each structural check of K1 and K2 is a format refusal.
INVENTORY_REFUSAL = "CycloneDX inventory document cannot be read: "
NO_TOOL_SUMMARY = "no tool named; a vulnerability statement without a producer is not a detection"

SCOPE_TITLES = MappingProxyType(
    {
        BOM_KIND_INVENTORY: "{tool} listed {count} components of {subject}",
        BOM_KIND_EMPTY: "{tool} reported no vulnerability records for {subject}",
        BOM_KIND_MATCHED: "{tool} matched {subject}: {count} vulnerability records",
    }
)
INVENTORY_DESCRIPTION = (
    "This document lists components and carries no vulnerability data; it is not a detection "
    "and verifies no coverage clock."
)
UNMATCHED_DESCRIPTION = (
    "This document carries no vulnerability record tied to a component it lists; it does not "
    "show that a match ran and verifies no coverage clock."
)
MATCHED_DESCRIPTION = (
    "The tool matched the components this document lists against its vulnerability data; it is "
    "not evidence that the subject is free of vulnerabilities or that the list is complete."
)
# A VEX file is not a failed detection, so it is refused as a format, never minted (Decision N).
VEX_REFUSAL = (
    "a standalone CycloneDX VEX document cannot be resolved without the BOM it describes; "
    "ComplyRoll does not join artifacts; record its statements as evaluations"
)

PACKAGE_RESOURCE_TYPE = "package"
# The role MAX_LOCATIONS_PER_RESULT plays for SARIF: checked before any fold work (Decision K).
MAX_AFFECTS_PER_VULNERABILITY = 1024
MAX_INSTANCES_PER_PACKAGE = 64
MAX_SCORE_INTEGER = 10**6
MAX_CWE = 99_999
BOM_LINK_PREFIX = "urn:cdx:"
SERIAL_PREFIX = "urn:uuid:"
# The subject's target in the carrier index; a package key is never the empty string.
SUBJECT_TARGET = ""

# Scores are never banded (Decision V): only the vendor's own word sets the display severity.
RATING_SEVERITIES: Mapping[str, SourceSeverity] = MappingProxyType(
    {
        "critical": SourceSeverity.CRITICAL,
        "high": SourceSeverity.HIGH,
        "medium": SourceSeverity.MEDIUM,
        "low": SourceSeverity.LOW,
        "info": SourceSeverity.INFORMATIONAL,
        "none": SourceSeverity.INFORMATIONAL,
        "unknown": SourceSeverity.UNKNOWN,
    }
)
ANALYSIS_STATES = frozenset(
    {
        "resolved",
        "resolved_with_pedigree",
        "exploitable",
        "in_triage",
        "false_positive",
        "not_affected",
    }
)
NOT_FIXED_RESPONSES = frozenset({"will_not_fix", "can_not_fix"})
ANALYSIS_KEPT = "; the disposition stays OPEN until an evaluation is recorded"

# Fixed and snake_case; a foreign key is an adapter bug, raised in assembly (section 19).
CYCLONEDX_METADATA_KEYS = frozenset(
    {
        "subject_ref",
        "package_identity",
        "package_versions",
        "purls",
        "cpes",
        "bom_refs",
        "component_hashes",
        "instances",
        "instances_cut",
        "vulnerability_sources",
        "vulnerability_bom_refs",
        "ratings",
        "severity_source",
        "advisories",
        "recommendation",
        "published",
        "created",
        "updated",
        "analysis_states",
        "analysis_justifications",
        "analysis_responses",
        "analysis_details",
        "analysis_first_issued",
        "analysis_last_updated",
        "affects_statuses",
        "affects_ranges",
        "tool_version",
        "bom_kind",
        "spec_version",
        "serial_number",
        "bom_version",
        "bom_timestamp",
        "tools",
        "subject_type",
        "subject_name",
        "subject_group",
        "subject_version",
        "subject_purl",
        "subject_bom_ref",
        "subject_lineage",
        "component_count",
        "package_count",
        "weak_identity_count",
        "vulnerability_count",
        "affected_count",
        "component_set_sha256",
        "occurrence_count",
        "truncated",
    }
)

# WARN: The package key is an identity input frozen at parser version 1 (ADR 0016). Changing
# any table or rule in this section re-mints every affected package resource.

# Each type maps to (fold the namespace, fold the name), read from the fetched purl type
# definitions: a segment folds exactly when its case_sensitive flag is false (Decision E, A6).
# A true flag, no flag, a prohibited namespace and an unlisted type are all verbatim. golang
# and nuget notes contradict their true flags; verbatim is deliberate (A23).
PURL_CASE_FOLDS: Mapping[str, tuple[bool, bool]] = MappingProxyType(
    {
        "alpm": (True, True),
        "apk": (True, True),
        "bitbucket": (True, True),
        "composer": (True, True),
        "deb": (True, True),
        "github": (True, True),
        "hex": (True, True),
        "oci": (False, True),
        "pypi": (False, True),
        "rpm": (True, False),
        "golang": (False, False),
        "huggingface": (False, False),
        "maven": (False, False),
        "npm": (False, False),
        "swift": (False, False),
        "cargo": (False, False),
        "cocoapods": (False, False),
        "nuget": (False, False),
        "conan": (False, False),
        "docker": (False, False),
        "generic": (False, False),
        "conda": (False, False),
        "gem": (False, False),
        "mlflow": (False, False),
    }
)
# pypi also replaces _ with - in the name. Its dot rule is about distribution file names.
PURL_DASHED_NAME_TYPES = frozenset({"pypi"})
# A qualifier equal to its type's default_value, compared as decoded text, is dropped.
PURL_DEFAULT_QUALIFIERS: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {
        "gem": MappingProxyType({"platform": "ruby"}),
        "maven": MappingProxyType({"type": "jar"}),
    }
)
# Version-like, location and provenance qualifiers never split a package (Decision C).
# NOTE: upstream joined the set on 2026-10-19 (step 1 build note): syft writes it as
# <source>@<version> on deb and as the source RPM file name on rpm, so keeping it re-minted
# a package resource on every upgrade.
PURL_STRIPPED_QUALIFIERS = frozenset(
    {
        "epoch",
        "distro",
        "upstream",
        "file_path",
        "file_name",
        "download_url",
        "vcs_url",
        "repository_url",
        "checksum",
        "package-id",
    }
)
# A tag is a mutable name for one oci artifact; the repository tells same-named images apart.
OCI_STRIPPED_QUALIFIERS = (PURL_STRIPPED_QUALIFIERS - {"repository_url"}) | {"tag"}

PKG_KEY_PREFIX = "pkg:"
COMPONENT_KEY_PREFIX = "component:"
REF_KEY_PREFIX = "ref:"
IMAGE_SCOPE_TYPE = "image"

_ALPHANUMERIC = (string.ascii_letters + string.digits).encode("ascii")
# Clause 5.4: alphanumerics, .-_~ and the colon are never percent-encoded in a purl.
_PURL_SAFE = frozenset(_ALPHANUMERIC + b".-_~:")
# RFC 3986 unreserved characters, for the component: and ref: forms.
_UNRESERVED = frozenset(_ALPHANUMERIC + b"-._~")
_HEX_DIGITS = frozenset(string.hexdigits)
_ASCII_FOLD = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_PURL_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9.-]*")
_QUALIFIER_KEY = re.compile(r"[a-z][a-z0-9._-]*")
_DIGEST = re.compile(r"(?:sha256|sha512):[0-9a-f]+")


# *--- Package Key ---*


# SECURITY: str.lower() reads the interpreter's Unicode database, which differs between 3.11,
# 3.13 and 3.14, so a key built with it could differ per interpreter (E2).
def ascii_fold(text: str) -> str:
    """Lowercase A to Z only; every other character is kept."""
    return text.translate(_ASCII_FOLD)


# surrogatepass keeps a lone surrogate encodable so this never raises; valid UTF-8 never
# holds those octets, so the encoding stays injective.
def _percent_encode(text: str, safe: frozenset[int]) -> str:
    """Percent-encode every UTF-8 octet outside the safe set, with uppercase hex."""
    return "".join(
        chr(octet) if octet in safe else f"%{octet:02X}"
        for octet in text.encode("utf-8", "surrogatepass")
    )


def _decode(text: str) -> str | None:
    """Percent-decode and UTF-8-decode strictly, or None when the text does not decode."""
    head, *escaped = text.split("%")
    try:
        octets = bytearray(head.encode("utf-8"))
        for part in escaped:
            if len(part) < 2 or part[0] not in _HEX_DIGITS or part[1] not in _HEX_DIGITS:
                return None
            octets.append(int(part[:2], 16))
            octets += part[2:].encode("utf-8")
        return octets.decode("utf-8")
    except UnicodeError:
        return None


def _segments(text: str, drop_dots: bool) -> list[str] | None:
    """Split on / first, then decode each segment, dropping empty (and dot) segments."""
    kept: list[str] = []
    for raw in text.split("/"):
        segment = _decode(raw)
        if segment is None or "/" in segment:
            return None
        if segment and not (drop_dots and segment in (".", "..")):
            kept.append(segment)
    return kept


def _qualifiers(purl_type: str, text: str) -> str | None:
    """Apply the ordered qualifier rule of Decision C, or None when the qualifiers do not parse."""
    pairs: list[tuple[str, str]] = []
    for pair in text.split("&"):
        if not pair:
            continue
        raw_key, _, raw_value = pair.partition("=")
        key = ascii_fold(raw_key)
        value = _decode(raw_value)
        if _QUALIFIER_KEY.fullmatch(key) is None or value is None:
            return None
        if value:
            pairs.append((key, value))
    # Duplicates are checked only after the empty-value drop (A7).
    if len({key for key, _ in pairs}) != len(pairs):
        return None
    defaults = PURL_DEFAULT_QUALIFIERS.get(purl_type, {})
    stripped = OCI_STRIPPED_QUALIFIERS if purl_type == "oci" else PURL_STRIPPED_QUALIFIERS
    # purl-how-to-build sorts the built key=value strings, not the keys alone.
    return "&".join(
        sorted(
            f"{key}={_percent_encode(value, _PURL_SAFE)}"
            for key, value in pairs
            if key not in stripped and defaults.get(key) != value
        )
    )


# NOTE: The split order is purl-how-to-parse's. Type rules (deb requiring a namespace, and so
# on) are not enforced, because producer test data breaks them.
def purl_key(purl: str) -> str | None:
    """Return the version-free pkg: key of a purl, or None when it does not parse."""
    remainder, subpath_text, qualifier_text = purl, "", ""
    if "#" in remainder:
        remainder, _, subpath_text = remainder.rpartition("#")
    if "?" in remainder:
        remainder, _, qualifier_text = remainder.rpartition("?")
    scheme, colon, remainder = remainder.partition(":")
    if not colon or ascii_fold(scheme) != "pkg":
        return None
    purl_type, slash, remainder = remainder.lstrip("/").partition("/")
    if not slash or _PURL_TYPE.fullmatch(purl_type) is None:
        return None
    purl_type = ascii_fold(purl_type)
    # The version is removed and never decoded, so nothing in it can change the key.
    remainder = remainder.rpartition("@")[0] if "@" in remainder else remainder
    namespace_text, _, name_text = remainder.rstrip("/").rpartition("/")
    name = _decode(name_text)
    namespace = _segments(namespace_text, drop_dots=False)
    subpath = _segments(subpath_text, drop_dots=True)
    qualifiers = _qualifiers(purl_type, qualifier_text)
    if not name or namespace is None or subpath is None or qualifiers is None:
        return None
    fold_namespace, fold_name = PURL_CASE_FOLDS.get(purl_type, (False, False))
    if fold_namespace:
        namespace = [ascii_fold(segment) for segment in namespace]
    if fold_name:
        name = ascii_fold(name)
    if purl_type in PURL_DASHED_NAME_TYPES:
        name = name.replace("_", "-")
    # The name is one segment, so a decoded / in it is re-encoded and never splits it.
    key = PKG_KEY_PREFIX + purl_type + "/"
    key += "".join(_percent_encode(segment, _PURL_SAFE) + "/" for segment in namespace)
    key += _percent_encode(name, _PURL_SAFE)
    if qualifiers:
        key += "?" + qualifiers
    if subpath:
        key += "#" + "/".join(_percent_encode(segment, _PURL_SAFE) for segment in subpath)
    return key


def ref_key(ref: str) -> str:
    """Return the ref: key of an affects ref that resolves to no unique component."""
    return REF_KEY_PREFIX + _percent_encode(ref, _UNRESERVED)


# Step 2 refuses a component with a non-string name or type as invalid_component before it
# asks for a key (A10); here such a field only reads as empty, so the function never raises.
def package_key(component: Mapping[str, Any]) -> tuple[str, bool, str | None]:
    """Return a component's package key, whether it is the weak form, and its raw purl."""
    raw = component.get("purl")
    if not isinstance(raw, str):
        raw = None
    elif (key := purl_key(raw)) is not None:
        return key, False, raw
    fields = (component.get("type"), component.get("group"), component.get("name"))
    texts = (value if isinstance(value, str) else "" for value in fields)
    fallback = COMPONENT_KEY_PREFIX + "/".join(_percent_encode(text, _UNRESERVED) for text in texts)
    return fallback, True, raw


# *--- Subject Lineage ---*


def digest_shaped(text: str) -> bool:
    """Return whether text is <alg>:<hex> with alg sha256 or sha512 and lowercase hex."""
    return _DIGEST.fullmatch(text) is not None


# The lineage comes from the subject name in every rule, never from the composed scope id
# (S4). A tag is stripped only when the last : follows the last /, so a registry port stays.
def subject_lineage(scope_type: str, name: str) -> str:
    """Return the subject part of a package resource id; for scan, the scope id unchanged."""
    if scope_type != IMAGE_SCOPE_TYPE:
        return name
    written = name
    head, at, digest = name.rpartition("@")
    if at and digest_shaped(digest):
        name = head
    colon = name.rfind(":")
    if colon > name.rfind("/"):
        name = name[:colon]
    # An empty strip would give every such subject one lineage, a merge (R-S2-1).
    return name or written


# *--- Package Resource ---*


# A package key never holds a raw |, so the last | splits it off however the lineage reads.
# The id is refused, never repaired, past the identity cap: step 2 records a returned problem
# as ERROR identity_input_invalid (CONTENT) at its own JSON path.
def package_resource_id(scope_type: str, lineage: str, key: str) -> tuple[str, str | None]:
    """Compose <scope type>:<lineage>|<key> and why it cannot be an identity, or None."""
    resource_id = f"{scope_type}:{lineage}|{key}"
    return resource_id, identity_problem(resource_id, MAX_IDENTITY_CHARS)


def split_package_resource_id(resource_id: str) -> tuple[str, str, str] | None:
    """Split a package resource id at its first : and last |, or None when it has neither."""
    scope_type, colon, rest = resource_id.partition(":")
    lineage, pipe, key = rest.rpartition("|")
    if not colon or not pipe:
        return None
    return scope_type, lineage, key


# *--- Document Shape ---*


# SECURITY: The sniff reads only an already-bounded parse, and stigs is tested first, so a
# document that claims to be a checklist stays a checklist (ADR 0013 decision 1). specVersion
# is not tested, so a wrong version gets the adapter's precise refusal.
def looks_like_cyclonedx(value: object) -> bool:
    """Say whether a parsed bare .json document declares itself a CycloneDX BOM."""
    return (
        isinstance(value, Mapping)
        and "stigs" not in value
        and value.get("bomFormat") == "CycloneDX"
    )


# Only % and the separator are encoded, so the raw separator is the only one left (A4, A5).
def _escape(text: str, separator: str, code: str) -> str:
    return text.replace("%", "%25").replace(separator, code)


def _tool_record(form: str, item: Mapping[str, Any]) -> dict[str, str]:
    """Return one tool's metadata in the one schema of A19, absent fields omitted."""
    members = ("name", "version", "vendor") if form == "legacy" else ("name", "version", "group")
    record = {member: item[member] for member in members if isinstance(item.get(member), str)}
    if form != "legacy":
        if isinstance(item.get("author"), str):
            record["author"] = item["author"]
        manufacturer = item.get("manufacturer")
        if isinstance(manufacturer, Mapping) and isinstance(manufacturer.get("name"), str):
            record["vendor"] = manufacturer["name"]
    return record


def _is_container(subject: Mapping[str, Any]) -> bool:
    """One predicate binds the scope type and the id rule (S2)."""
    if subject.get("type") == "container":
        return True
    purl = subject.get("purl")
    key = purl_key(purl) if isinstance(purl, str) else None
    return key is not None and key.startswith(PKG_KEY_PREFIX + "oci/")


def _image_id(name: str, version: object) -> str:
    """Compose a container subject's scope id from its name and version (Y1)."""
    if ":" in name.rpartition("/")[2] or "@" in name.rpartition("/")[2]:
        return name
    if not isinstance(version, str) or not version.strip():
        return name
    encoded = _escape(version, "/", "%2F")
    return f"{name}@{encoded}" if digest_shaped(version) else f"{name}:{encoded}"


# The key never holds these characters, so encoding them in the version keeps one line per
# component and two different sets from printing one line set (R-S2-2).
def _line_version(version: str) -> str:
    return (
        version.replace("%", "%25").replace("\t", "%09").replace("\n", "%0A").replace("\r", "%0D")
    )


def _text(value: object) -> str | None:
    """Return a string member, or None: a non-string scalar counts as absent (D2)."""
    return value if isinstance(value, str) else None


# *--- Vulnerability Records ---*


@dataclass(frozen=True, slots=True)
class _Carrier:
    """One indexed component: its target (package key, or the subject) and instance facts."""

    target: str
    weak: bool
    bom_ref: str
    version: str | None
    purl: str | None
    cpe: str | None
    hashes: tuple[str, ...]


@dataclass(slots=True)
class _Candidate:
    """One affects entry's contribution to one observation before folding."""

    path: str
    # Content only, never position, so the fold ignores document order (section 20).
    order: tuple[str, ...]
    title: str
    description: str
    severity: SourceSeverity
    severity_source: str
    identifiers: tuple[str, ...]
    identifiers_cut: bool
    scalars: dict[str, str]
    lists: dict[str, tuple[str, ...]]
    carriers: tuple[_Carrier, ...]
    package_identity: str | None
    truncated: set[str]


_FoldKey = tuple[str, str, str]


def _carrier(component: Mapping[str, Any], target: str, weak: bool, bom_ref: str) -> _Carrier:
    """Record one component's instance facts; a non-string member is absent (D2)."""
    hashes = {
        f"{item['alg']}:{item['content']}"
        for item in component.get("hashes", ())
        if isinstance(item.get("alg"), str) and isinstance(item.get("content"), str)
    }
    return _Carrier(
        target,
        weak,
        bom_ref,
        _text(component.get("version")),
        _text(component.get("purl")),
        _text(component.get("cpe")),
        tuple(sorted(hashes)),
    )


# The shape check runs before any field is read, so a wrong type is never repaired or guessed
# (A10). It returns the fixed check text and the JSON path suffix where it failed.
def _shape_problem(item: object) -> tuple[str, str] | None:
    """Say why one vulnerability record cannot be read, or None when its shape is sound."""
    if not isinstance(item, Mapping):
        return "a vulnerability is not an object", ""
    for member in ("affects", "ratings", "references", "advisories"):
        if member not in item:
            continue
        if not isinstance(item[member], list):
            return f"{member} is not an array", f".{member}"
        if not all(isinstance(entry, Mapping) for entry in item[member]):
            return f"an item of {member} is not an object", f".{member}"
    if "cwes" in item and not isinstance(item["cwes"], list):
        return "cwes is not an array", ".cwes"
    for index, entry in enumerate(item.get("affects", ())):
        where = f".affects[{index}]"
        if not isinstance(entry.get("ref"), str):
            return "an affects ref is missing or not a string", f"{where}.ref"
        if "versions" in entry:
            if not isinstance(entry["versions"], list):
                return "affects versions is not an array", f"{where}.versions"
            if not all(isinstance(version, Mapping) for version in entry["versions"]):
                return "an affects version is not an object", f"{where}.versions"
    if "analysis" in item:
        analysis = item["analysis"]
        if not isinstance(analysis, Mapping):
            return "analysis is not an object", ".analysis"
        if "response" in analysis and not isinstance(analysis["response"], list):
            return "analysis.response is not an array", ".analysis.response"
    return None


# SECURITY: bool is refused first and an int is range-checked before any float(), so a
# 400-digit integer never raises OverflowError, and 1e400 (parsed to inf) is refused.
def _rating_score(raw: object) -> str | None:
    """Render a usable score verbatim-ish, or None when it is unusable (section 18)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return str(raw) if abs(raw) <= MAX_SCORE_INTEGER else None
    if isinstance(raw, float) and math.isfinite(raw):
        return repr(raw)
    return None


def _source_name(holder: Mapping[str, Any]) -> str | None:
    source = holder.get("source")
    return _text(source.get("name")) if isinstance(source, Mapping) else None


def _first_line(text: str) -> str:
    """Return the first non-blank line of sanitized text."""
    cleaned, _changed = sanitize(text)
    for line in cleaned.split("\n"):
        if line.strip():
            return line
    return ""


# *--- Core Logic ---*


class _CycloneDxParse(EvidenceParse):
    """One document's parse state: kind, component index, counts and coalesced diagnostics."""

    def __init__(
        self,
        artifact: ArtifactProvenance,
        ingested_at: datetime,
        limits: IngestLimits,
        vulnerabilities: list[Any] | None,
    ) -> None:
        super().__init__(artifact, ingested_at, limits)
        self.vulnerabilities = vulnerabilities or []
        if vulnerabilities is None:
            self.kind = BOM_KIND_INVENTORY
        else:
            self.kind = BOM_KIND_MATCHED if vulnerabilities else BOM_KIND_EMPTY
        self.matched = self.kind == BOM_KIND_MATCHED
        # The vulnerability folds; the scope candidate stays outside them (A13).
        self.folds: dict[_FoldKey, list[_Candidate]] = {}
        self.scalars: dict[str, str] = {}
        self.truncated: set[str] = set()
        # bom-ref to every carrier of it, the subject included; affects resolve through it.
        self.index: dict[str, list[_Carrier]] = {}
        self.component_count = 0
        self.package_keys: set[str] = set()
        self.weak_keys: set[str] = set()
        self.component_lines: set[str] = set()
        self.lineage = ""
        self.serial: str | None = None
        self.bom_version = "1"
        self.tool_version = ""
        # Whether any affects ref resolved through the index, directly or by a same-document
        # BOM-Link: the only evidence that a match ran against this inventory (A1).
        self.resolved_locally = False
        self.tool = ""
        self.scope: tuple[str, str] = ("", "")
        self.observed_at: datetime | None = None

    def run(self, data: Mapping[str, Any]) -> AdapterOutput:
        """Check the document, fold its vulnerabilities, then the scope; fail closed on errors."""
        scope = self._read(data)
        observations: list[Observation] = []
        if not self.diagnostics.has_errors:
            observations = [
                self._assemble_fold(key, items) for key, items in sorted(self.folds.items())
            ]
            if scope is not None:
                observations.append(scope)
            observations.sort(
                key=lambda item: (
                    item.resource.resource_type,
                    item.resource.resource_id,
                    item.source_record_id,
                    item.observation_id,
                )
            )
        # The scope candidate is outside the folds, so it never makes a reading withheld (A13).
        return AdapterOutput(
            tuple(observations),
            self.diagnostics.emit(self.artifact.name),
            withheld=self.diagnostics.has_errors and bool(self.folds),
        )

    # A K1 or K2 document makes no detection claim, so its structural errors are format
    # refusals (A12); on K3 they are CONTENT errors that a failure record can mint.
    def _bom_error(self, check: str, path: str) -> None:
        if not self.matched:
            raise AdapterParseError(INVENTORY_REFUSAL + check)
        self.diagnostics.add(
            DiagnosticLevel.ERROR,
            "invalid_bom",
            "CycloneDX document structure cannot be read",
            path,
            detail=check,
        )

    def _component_error(self, check: str, path: str) -> None:
        if not self.matched:
            raise AdapterParseError(INVENTORY_REFUSAL + check)
        self.diagnostics.add(
            DiagnosticLevel.ERROR,
            "invalid_component",
            "CycloneDX component cannot be read",
            path,
            detail=check,
        )

    def _read(self, data: Mapping[str, Any]) -> Observation | None:
        """Run the document-level checks in the order of section 3, then the scope."""
        metadata: Mapping[str, Any] = {}
        if "metadata" in data:
            if isinstance(data["metadata"], Mapping):
                metadata = data["metadata"]
            else:
                self._bom_error("metadata is not an object", "metadata")
        tools = self._tool_items(metadata)
        subject: Mapping[str, Any] | None = None
        if "component" in metadata:
            if isinstance(metadata["component"], Mapping):
                subject = metadata["component"]
            else:
                self._bom_error("metadata.component is not an object", "metadata.component")
        components: list[Any] = []
        if "components" in data:
            if isinstance(data["components"], list):
                components = data["components"]
            else:
                self._bom_error("components is not an array", "components")
        self._walk(subject, components)
        if self.diagnostics.has_errors:
            return None
        # SECURITY: K4 is decided after indexing and before the tool requirement, so a
        # tool-less VEX file is refused as VEX and never minted as invalid_bom (A9).
        if self.matched and self.component_count == 0:
            raise AdapterParseError(VEX_REFUSAL)
        tool = self._tool(tools)
        if tool is None:
            return None
        scope = self._scope(subject, tool)
        if scope is None:
            return None
        self._document_scalars(data, metadata, tools)
        self.tool, self.scope = tool, scope
        # One document clock for every observation; never a vulnerability's own dates (Q).
        self.observed_at = self._clock(metadata.get("timestamp"), "metadata.timestamp")
        if self.observed_at is None:
            self.diagnostics.add_fixed(missing_time_diagnostic(self.artifact))
        if self.matched:
            self._vulnerabilities(scope)
        if self.diagnostics.has_errors:
            return None
        # A producer finding spelled like the scope record takes the observation (section 10).
        if (SCOPE_RECORD_ID, *scope) in self.folds:
            self.diagnostics.add(
                DiagnosticLevel.INFO,
                "scope_superseded",
                "a vulnerability shares the scope observation's identity; the scope yields to it",
                "metadata.component",
            )
            return None
        return self._assemble(tool, scope, metadata)

    # Tools

    def _tool_items(self, metadata: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
        """Read both tool shapes; a wrong-type container, item or name is an error (A10)."""
        if "tools" not in metadata:
            return []
        tools = metadata["tools"]
        groups: list[tuple[str, list[Any], str]] = []
        if isinstance(tools, list):
            groups.append(("legacy", tools, "metadata.tools"))
        elif isinstance(tools, Mapping):
            for member in ("components", "services"):
                if member not in tools:
                    continue
                path = f"metadata.tools.{member}"
                if isinstance(tools[member], list):
                    groups.append((member, tools[member], path))
                else:
                    self._bom_error(f"{path} is not an array", path)
        else:
            self._bom_error("metadata.tools is neither an array nor an object", "metadata.tools")
        items: list[tuple[str, Mapping[str, Any]]] = []
        for form, values, path in groups:
            for index, item in enumerate(values):
                here = f"{path}[{index}]"
                # SECURITY: A string tool item such as "trivy" never reaches .get (A10).
                if not isinstance(item, Mapping):
                    self._bom_error("a tool is not an object", here)
                elif "name" in item and not isinstance(item["name"], str):
                    self._bom_error("a tool name is not a string", f"{here}.name")
                else:
                    items.append((form, item))
        return items

    def _tool(self, items: list[tuple[str, Mapping[str, Any]]]) -> str | None:
        """Select the tool string of section 4.1, or None when it is refused."""
        applications = [
            item
            for form, item in items
            if form == "components" and item.get("type") == "application"
        ]
        chosen = applications or [item for _, item in items]
        # % and + are encoded before the join, so one tool alpha+beta never reads as two (A5).
        names = sorted(
            {
                _escape(item["name"], "+", "%2B")
                for item in chosen
                if isinstance(item.get("name"), str) and item["name"].strip()
            }
        )
        if not names:
            if self.matched:
                self.diagnostics.add(
                    DiagnosticLevel.ERROR, "invalid_bom", NO_TOOL_SUMMARY, "metadata.tools"
                )
                return None
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "tool_identity_fallback",
                "no tool is named; the tool is the literal cyclonedx",
                "metadata.tools",
            )
            return CYCLONEDX_FALLBACK_TOOL
        tool = "+".join(names)
        versions = {item["version"] for item in chosen if isinstance(item.get("version"), str)}
        self.tool_version = "+".join(sorted(_escape(text, "+", "%2B") for text in versions))
        try:
            for name in names:
                self._require_identity(name, MAX_IDENTITY_CHARS, "tool name", "metadata.tools")
            self._require_identity(tool, MAX_IDENTITY_CHARS, "tool", "metadata.tools")
        except IdentityRefused:
            return None
        if len(names) > 1:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "tool_identity_ambiguous",
                "more than one tool is named; the tool is their sorted join",
                "metadata.tools",
                detail=tool,
            )
        return tool

    # Components

    # The walk is iterative with an explicit stack, so nesting depth costs no recursion; the
    # parse bounds already cap the nodes it can visit.
    def _walk(self, subject: Mapping[str, Any] | None, components: list[Any]) -> None:
        """Index every component at every depth and count all but the subject (D1)."""
        pending: list[tuple[object, str, bool]] = [
            (item, f"components[{index}]", False)
            for index, item in reversed(list(enumerate(components)))
        ]
        if subject is not None:
            pending.append((subject, "metadata.component", True))
        while pending:
            component, path, is_subject = pending.pop()
            children = self._check_component(component, path)
            if children is None:
                continue
            assert isinstance(component, Mapping)
            key, weak, _purl = package_key(component)
            bom_ref = component.get("bom-ref")
            if isinstance(bom_ref, str) and bom_ref:
                target = SUBJECT_TARGET if is_subject else key
                self.index.setdefault(bom_ref, []).append(
                    _carrier(component, target, weak, bom_ref)
                )
            if not is_subject:
                self.component_count += 1
                self.package_keys.add(key)
                if weak:
                    self.weak_keys.add(key)
                version = _line_version(_text(component.get("version")) or "")
                self.component_lines.add(f"{key}\t{version}")
            pending.extend(
                (child, f"{path}.components[{index}]", False)
                for index, child in reversed(list(enumerate(children)))
            )

    def _check_component(self, component: object, path: str) -> list[Any] | None:
        """Return a sound component's children, or None after recording why it is not."""
        if not isinstance(component, Mapping):
            self._component_error("a component is not an object", path)
            return None
        if not isinstance(component.get("name"), str):
            self._component_error("a component name is missing or not a string", f"{path}.name")
            return None
        if "type" in component and not isinstance(component["type"], str):
            self._component_error("a component type is not a string", f"{path}.type")
            return None
        if "hashes" in component:
            hashes = component["hashes"]
            if not isinstance(hashes, list):
                self._component_error("a component hashes member is not an array", f"{path}.hashes")
                return None
            if not all(isinstance(item, Mapping) for item in hashes):
                self._component_error("a component hash is not an object", f"{path}.hashes")
                return None
        children = component.get("components", [])
        if not isinstance(children, list):
            self._component_error(
                "a component components member is not an array", f"{path}.components"
            )
            return None
        return children

    # Subject

    def _scope(self, subject: Mapping[str, Any] | None, tool: str) -> tuple[str, str] | None:
        """Return the scope resource (type, id), or None when the composed id is refused."""
        name = subject.get("name") if subject is not None else None
        if subject is None or not isinstance(name, str) or not name.strip():
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "subject_identity_fallback",
                "metadata.component names no subject; the scope resource is the tool",
                "metadata.component",
            )
            self.scalars["subject_lineage"] = self.lineage = tool
            return SCAN_SCOPE_TYPE, tool
        if _is_container(subject):
            scope_type, resource_id = IMAGE_SCOPE_TYPE, _image_id(name, subject.get("version"))
        else:
            group = subject.get("group")
            encoded = _escape(name, "/", "%2F")
            if isinstance(group, str) and group.strip():
                encoded = _escape(group, "/", "%2F") + "/" + encoded
            scope_type, resource_id = SCAN_SCOPE_TYPE, encoded
        # SECURITY: The composed id is refused whole, never repaired (Y1 amendment).
        try:
            self._require_identity(
                resource_id, MAX_IDENTITY_CHARS, "scope id", "metadata.component"
            )
        except IdentityRefused:
            return None
        self.lineage = lineage = subject_lineage(
            scope_type, name if scope_type == IMAGE_SCOPE_TYPE else resource_id
        )
        for key, member in (
            ("subject_type", "type"),
            ("subject_name", "name"),
            ("subject_group", "group"),
            ("subject_version", "version"),
            ("subject_purl", "purl"),
            ("subject_bom_ref", "bom-ref"),
        ):
            self._scalar(
                self.scalars, key, subject.get(member), "metadata.component", self.truncated
            )
        self._scalar(self.scalars, "subject_lineage", lineage, "metadata.component", self.truncated)
        return scope_type, resource_id

    # Document

    def _document_scalars(
        self,
        data: Mapping[str, Any],
        metadata: Mapping[str, Any],
        tools: list[tuple[str, Mapping[str, Any]]],
    ) -> None:
        """Record the document's own fields and the tool records in the fixed vocabulary."""
        self._scalar(
            self.scalars, "spec_version", data["specVersion"], "specVersion", self.truncated
        )
        serial = data.get("serialNumber")
        if isinstance(serial, str):
            self.serial = serial.removeprefix(SERIAL_PREFIX)
            self._scalar(self.scalars, "serial_number", serial, "serialNumber", self.truncated)
        elif serial is not None:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "serial_number_invalid",
                "serialNumber is not a string; the document has no serial",
                "serialNumber",
            )
        version = data.get("version")
        # bool is an int in Python, so it is refused before the range test (section 18).
        if (
            isinstance(version, int)
            and not isinstance(version, bool)
            and 1 <= version <= MAX_BOM_VERSION
        ):
            self.scalars["bom_version"] = self.bom_version = str(version)
        elif version is not None:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "bom_version_invalid",
                f"version is not an integer from 1 to {MAX_BOM_VERSION}; it reads as 1",
                "version",
            )
        if isinstance(metadata.get("timestamp"), str):
            self._scalar(
                self.scalars,
                "bom_timestamp",
                metadata["timestamp"],
                "metadata.timestamp",
                self.truncated,
            )
        records = {
            json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            for record in (_tool_record(form, item) for form, item in tools)
            if record
        }
        if records:
            kept = self._evidence_list(sorted(records), "tools", "metadata.tools", self.truncated)
            self.scalars["tools"] = encode_list(
                self._cut(sorted(set(kept)), "tools", "metadata.tools", self.truncated)
            )

    def _assemble(
        self, tool: str, scope: tuple[str, str], metadata: Mapping[str, Any]
    ) -> Observation:
        """Build the one scope observation of section 10."""
        scope_type, resource_id = scope
        observed_at = self.observed_at
        if self.kind == BOM_KIND_INVENTORY:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "vulnerabilities_absent",
                "the document carries no vulnerabilities member; it lists components only and "
                "is not a detection",
                "vulnerabilities",
            )
            description = INVENTORY_DESCRIPTION
            disposition = ObservationDisposition.NOT_REVIEWED
        elif self.resolved_locally:
            # A resolved affects record is positive evidence that a match ran (A1).
            description = MATCHED_DESCRIPTION
            disposition = ObservationDisposition.PASS
        else:
            disposition = ObservationDisposition.NOT_REVIEWED
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "match_unverified",
                "no vulnerability record resolves to a component this document lists; the "
                "document does not show that a match ran",
                "vulnerabilities",
            )
            description = UNMATCHED_DESCRIPTION
        count = (
            self.component_count if self.kind == BOM_KIND_INVENTORY else len(self.vulnerabilities)
        )
        title = clean(
            (
                SCOPE_TITLES[self.kind].format(
                    tool=tool, count=count, subject=f"{scope_type}:{resource_id}"
                ),
            ),
            MAX_TITLE_CHARS,
        )
        self._replay(title, "title", "metadata", self.truncated)
        lines = "".join(f"{line}\n" for line in sorted(self.component_lines))
        metadata_out = dict(self.scalars)
        metadata_out.update(
            {
                "bom_kind": self.kind,
                "component_count": str(self.component_count),
                "package_count": str(len(self.package_keys)),
                "weak_identity_count": str(len(self.weak_keys)),
                "vulnerability_count": str(len(self.vulnerabilities)),
                "component_set_sha256": hashlib.sha256(lines.encode("utf-8")).hexdigest(),
                "occurrence_count": "1",
            }
        )
        if self.matched:
            affected = {
                (resource_type, resource_id) for _, resource_type, resource_id in self.folds
            }
            metadata_out["affected_count"] = str(len(affected))
        if self.truncated:
            metadata_out["truncated"] = encode_list(sorted(self.truncated))
        foreign = sorted(set(metadata_out) - CYCLONEDX_METADATA_KEYS)
        if foreign:
            raise RuntimeError(f"metadata keys outside the fixed vocabulary: {foreign}")
        observation = make_observation(
            artifact=self.artifact,
            source_type=CYCLONEDX_SOURCE_TYPE,
            source_tool=tool,
            source_record_id=SCOPE_RECORD_ID,
            resource_id=resource_id,
            resource_type=scope_type,
            observed_at=observed_at,
            ingested_at=self.ingested_at,
            disposition=disposition,
            severity=SourceSeverity.UNKNOWN,
            title=title.text,
            description=description,
            identifiers=(),
            context_key=tool,
            metadata=metadata_out,
        )
        size = observation_bytes(
            observation,
            ceiling=MAX_OBSERVATION_JSON_BYTES,
            budget=self.limits.max_observation_bytes_per_artifact,
            spent=self.observation_bytes,
        )
        self.observation_bytes += size
        return observation

    # Vulnerabilities

    def _vulnerabilities(self, scope: tuple[str, str]) -> None:
        """Check both count bounds, then fold every vulnerability record (sections 8 to 13)."""
        # SECURITY: Both bounds are checked before any fold work (Decision K).
        limit = self.limits.max_results_per_run
        if len(self.vulnerabilities) > limit:
            raise InputLimitError(
                f"CycloneDX document has {len(self.vulnerabilities)} vulnerabilities; "
                f"maximum is {limit}"
            )
        for item in self.vulnerabilities:
            affects = item.get("affects") if isinstance(item, Mapping) else None
            if isinstance(affects, list) and len(affects) > MAX_AFFECTS_PER_VULNERABILITY:
                raise InputLimitError(
                    f"a CycloneDX vulnerability affects {len(affects)} components; maximum is "
                    f"{MAX_AFFECTS_PER_VULNERABILITY}"
                )
        for index, item in enumerate(self.vulnerabilities):
            self._vulnerability(f"vulnerabilities[{index}]", item, scope)

    def _vulnerability(self, path: str, item: object, scope: tuple[str, str]) -> None:
        """Fold one record: one candidate per affects entry, or one on the scope resource."""
        problem = _shape_problem(item)
        if problem is not None:
            check, where = problem
            self.diagnostics.add(
                DiagnosticLevel.ERROR,
                "invalid_vulnerability",
                "CycloneDX vulnerability cannot be read",
                path + where,
                detail=check,
            )
            return
        assert isinstance(item, Mapping)
        record_id = item.get("id")
        if not isinstance(record_id, str) or not record_id.strip():
            self.diagnostics.add(
                DiagnosticLevel.ERROR,
                "vulnerability_id_missing",
                "CycloneDX vulnerability has no id",
                f"{path}.id",
            )
            return
        try:
            self._require_identity(record_id, MAX_IDENTITY_CHARS, "vulnerability id", f"{path}.id")
        except IdentityRefused:
            return
        base = self._facts(path, item, record_id)
        affects = item.get("affects", [])
        if not affects:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "affects_missing",
                "a vulnerability names no affected component; it is recorded on the subject",
                path,
            )
            self._fold((record_id, *scope), self._candidate(base, path, (), None, {}))
            return
        for index, entry in enumerate(affects):
            here = f"{path}.affects[{index}]"
            ref = entry["ref"]
            carriers = self._resolve(ref, here)
            identity: str | None = None
            resource: tuple[str, str] | None = scope
            if carriers is None:
                identity = "ref"
                resource = self._package_resource(scope[0], ref_key(ref), here)
            elif carriers[0].target != SUBJECT_TARGET:
                key = carriers[0].target
                identity = "component" if carriers[0].weak else "purl"
                if carriers[0].weak:
                    self.diagnostics.add(
                        DiagnosticLevel.WARNING,
                        "package_identity_weak",
                        "an affected component has no usable purl; its key is built from its "
                        "type, group and name",
                        here,
                    )
                resource = self._package_resource(scope[0], key, here)
            if resource is None:
                continue
            truncated = set(base.truncated)
            lists = self._affects_lists(entry, carriers or (), here, truncated)
            # A product-level statement sits on the scope resource and names no instance.
            instances = () if carriers is None or identity is None else carriers
            candidate = self._candidate(base, here, instances, identity, lists)
            candidate.truncated = truncated
            self._fold((record_id, *resource), candidate)

    def _candidate(
        self,
        base: _Candidate,
        path: str,
        carriers: tuple[_Carrier, ...],
        identity: str | None,
        lists: dict[str, tuple[str, ...]],
    ) -> _Candidate:
        """Specialize a record's shared facts to one affects entry."""
        merged = {**base.lists, **lists}
        content = {
            "scalars": base.scalars,
            "lists": merged,
            "severity": base.severity.value,
            "severity_source": base.severity_source,
            "identifiers": base.identifiers,
            "identity": identity,
            "carriers": [repr(carrier) for carrier in sorted(carriers, key=repr)],
        }
        order = (base.title, base.description, json.dumps(content, sort_keys=True))
        return _Candidate(
            path,
            order,
            base.title,
            base.description,
            base.severity,
            base.severity_source,
            base.identifiers,
            base.identifiers_cut,
            base.scalars,
            merged,
            carriers,
            identity,
            set(base.truncated),
        )

    def _facts(self, path: str, item: Mapping[str, Any], record_id: str) -> _Candidate:
        """Read the field map of section 9 that every affects entry of a record shares."""
        truncated: set[str] = set()
        written = [
            text
            for text in (_text(item.get("description")), _text(item.get("detail")))
            if text is not None and text.strip()
        ]
        source_text = written[0] if written else ""
        description = self._evidence(
            source_text, MAX_DESCRIPTION_CHARS, "description", f"{path}.description", truncated
        )
        title = self._evidence(
            _first_line(source_text), MAX_TITLE_CHARS, "title", f"{path}.description", truncated
        )
        severity, severity_source, ratings = self._ratings(path, item.get("ratings", ()))
        texts = [record_id]
        texts.extend(
            text for entry in item.get("references", ()) if (text := _text(entry.get("id")))
        )
        found = extract_identifiers(texts)
        for index, cwe in enumerate(item.get("cwes", ())):
            if isinstance(cwe, int) and not isinstance(cwe, bool) and 1 <= cwe <= MAX_CWE:
                found.add(f"CWE-{cwe}")
            else:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "cwe_invalid",
                    f"a cwes item is not an integer from 1 to {MAX_CWE}; it is ignored",
                    f"{path}.cwes[{index}]",
                )
        identifiers, identifiers_cut = first_identifiers(found)
        scalars: dict[str, str] = {}
        for member in ("recommendation", "published", "created", "updated"):
            self._scalar(scalars, member, _text(item.get(member)), f"{path}.{member}", truncated)
        analysis = item.get("analysis", {})
        values: dict[str, list[str | None]] = {
            "vulnerability_sources": [_source_name(item)],
            "vulnerability_bom_refs": [_text(item.get("bom-ref"))],
            "advisories": [_text(entry.get("url")) for entry in item.get("advisories", ())],
            "ratings": list(ratings),
            "analysis_states": [_text(analysis.get("state"))],
            "analysis_justifications": [_text(analysis.get("justification"))],
            "analysis_responses": [_text(entry) for entry in analysis.get("response", ())],
            "analysis_details": [_text(analysis.get("detail"))],
            "analysis_first_issued": [_text(analysis.get("firstIssued"))],
            "analysis_last_updated": [_text(analysis.get("lastUpdated"))],
        }
        self._analysis_codes(f"{path}.analysis", values)
        lists = {
            member: self._evidence_list(
                sorted(text for text in entries if text is not None), member, path, truncated
            )
            for member, entries in values.items()
        }
        return _Candidate(
            path,
            (),
            title,
            description,
            severity,
            severity_source,
            identifiers,
            identifiers_cut,
            scalars,
            lists,
            (),
            None,
            truncated,
        )

    def _ratings(self, path: str, ratings: Any) -> tuple[SourceSeverity, str, tuple[str, ...]]:
        """Return the highest vendor word, its smallest source name and every rating record."""
        records: list[str] = []
        words: list[tuple[SourceSeverity, str]] = []
        for index, rating in enumerate(ratings):
            record: dict[str, str] = {}
            name = _source_name(rating)
            if name is not None:
                record["source"] = name
            for member in ("severity", "method", "vector"):
                text = _text(rating.get(member))
                if text is not None:
                    record[member] = text
            if "score" in rating:
                score = _rating_score(rating["score"])
                if score is None:
                    self.diagnostics.add(
                        DiagnosticLevel.WARNING,
                        "rating_score_invalid",
                        "a rating score is not a finite number in range; it is omitted",
                        f"{path}.ratings[{index}].score",
                    )
                else:
                    record["score"] = score
            if record:
                records.append(
                    json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
                )
            level = RATING_SEVERITIES.get(record.get("severity", ""))
            if level is not None:
                words.append((level, name or ""))
        if not words:
            return SourceSeverity.UNKNOWN, "", tuple(records)
        # A maximum over content, never the first rating (Decision V).
        severity = max((level for level, _ in words), key=SEVERITY_RANK.__getitem__)
        sources = sorted(name for level, name in words if level is severity and name)
        return severity, sources[0] if sources else "", tuple(records)

    # Each kind of supplier claim draws its own warning and never moves the disposition (O).
    def _analysis_codes(self, path: str, values: dict[str, list[str | None]]) -> None:
        state = values["analysis_states"][0]
        if state is not None and state not in ANALYSIS_STATES:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "analysis_state_invalid",
                "an analysis state is outside the CycloneDX enumeration" + ANALYSIS_KEPT,
                f"{path}.state",
            )
        elif state == "not_affected":
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "analysis_not_affected",
                "a supplier states the component is not affected" + ANALYSIS_KEPT,
                f"{path}.state",
            )
        elif state == "false_positive":
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "analysis_false_positive",
                "a supplier states the match is a false positive" + ANALYSIS_KEPT,
                f"{path}.state",
            )
        elif state in ("resolved", "resolved_with_pedigree"):
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "analysis_resolved",
                "a supplier states the vulnerability is resolved" + ANALYSIS_KEPT,
                f"{path}.state",
            )
        elif state == "in_triage":
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "analysis_in_triage",
                "a supplier states the vulnerability is in triage" + ANALYSIS_KEPT,
                f"{path}.state",
            )
        if any(text in NOT_FIXED_RESPONSES for text in values["analysis_responses"]):
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "response_will_not_fix",
                "a supplier responds that it will not or cannot fix" + ANALYSIS_KEPT,
                f"{path}.response",
            )

    def _affects_lists(
        self,
        entry: Mapping[str, Any],
        carriers: tuple[_Carrier, ...],
        path: str,
        truncated: set[str],
    ) -> dict[str, tuple[str, ...]]:
        """Keep an entry's version statements verbatim; ranges are never evaluated."""
        installed = {carrier.version for carrier in carriers if carrier.version is not None}
        statuses: list[str] = []
        ranges: list[str] = []
        for index, item in enumerate(entry.get("versions", ())):
            fields = {member: _text(item.get(member)) for member in ("version", "range", "status")}
            record = {member: text for member, text in fields.items() if text is not None}
            if record:
                statuses.append(
                    json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
                )
            if fields["range"] is not None:
                ranges.append(fields["range"])
            # The scanner contradicting its own match is for an assessor to see (E3).
            if fields["status"] == "unaffected" and fields["version"] in installed:
                self.diagnostics.add(
                    DiagnosticLevel.WARNING,
                    "affects_version_unaffected",
                    "an affects entry marks the installed version unaffected" + ANALYSIS_KEPT,
                    f"{path}.versions[{index}]",
                )
        return {
            "affects_statuses": self._evidence_list(
                sorted(statuses), "affects_statuses", path, truncated
            ),
            "affects_ranges": self._evidence_list(
                sorted(ranges), "affects_ranges", path, truncated
            ),
        }

    # Resolution

    def _resolve(self, ref: str, path: str) -> tuple[_Carrier, ...] | None:
        """Resolve a ref through the index, or None when it takes the ref: fallback (J)."""
        target = ref
        if ref not in self.index:
            fragment = self._local_fragment(ref)
            if fragment is not None:
                target = fragment
        carriers = self.index.get(target)
        # Carriers that share one key are instances of one package and resolve (A15).
        if carriers is not None and len({carrier.target for carrier in carriers}) > 1:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "bom_ref_conflict",
                "a bom-ref is carried by components of different packages; it resolves to none",
                path,
                detail=target,
            )
            carriers = None
        if carriers is None:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "affects_unresolved",
                "an affects ref names no unique component of this document; the finding is "
                "kept on a ref: resource",
                path,
                detail=ref,
            )
            return None
        self.resolved_locally = True
        return tuple(carriers)

    # SECURITY: The link's version is compared as digit text, never int() of producer text,
    # and the fragment is an opaque bom-ref, never URL-decoded (Decision J).
    def _local_fragment(self, ref: str) -> str | None:
        """Return a same-document BOM-Link's fragment, or None for any other ref."""
        if not ref.startswith(BOM_LINK_PREFIX) or self.serial is None:
            return None
        head, mark, fragment = ref[len(BOM_LINK_PREFIX) :].partition("#")
        serial, slash, version = head.partition("/")
        if not mark or not slash or serial != self.serial or version != self.bom_version:
            return None
        return fragment

    def _package_resource(self, scope_type: str, key: str, path: str) -> tuple[str, str] | None:
        """Compose the package resource, refused whole past the identity cap (section 7)."""
        resource_id, _problem = package_resource_id(scope_type, self.lineage, key)
        try:
            self._require_identity(resource_id, MAX_IDENTITY_CHARS, "resource id", path)
        except IdentityRefused:
            return None
        return PACKAGE_RESOURCE_TYPE, resource_id

    def _fold(self, key: _FoldKey, candidate: _Candidate) -> None:
        """Add one candidate to its identity's fold, refusing the artifact past the cap."""
        bucket = self.folds.get(key)
        if bucket is None:
            if len(self.folds) >= self.limits.max_observations_per_artifact:
                raise InputLimitError(
                    f"artifact yields more than "
                    f"{self.limits.max_observations_per_artifact} observations"
                )
            bucket = self.folds[key] = []
        bucket.append(candidate)

    # Fold

    def _instances(self, carriers: list[_Carrier], path: str) -> tuple[list[dict[str, Any]], bool]:
        """Keep each instance's facts together, sorted by (version, bom_ref) and capped (A3)."""
        cut = False
        # Instance cuts are reported, but never under truncated, which cve_may_be_missing reads.
        scratch: set[str] = set()
        records: dict[str, dict[str, Any]] = {}
        for carrier in carriers:
            record: dict[str, Any] = {}
            for member, value in (
                ("bom_ref", carrier.bom_ref),
                ("version", carrier.version),
                ("purl", carrier.purl),
            ):
                cleaned = clean((value,), MAX_LIST_ITEM_CHARS)
                self._replay(cleaned, "instances", path, scratch)
                cut = cut or cleaned.cut > 0
                if cleaned.text:
                    record[member] = cleaned.text
            hashes = carrier.hashes
            if len(hashes) > MAX_LIST_ITEMS:
                hashes, cut = hashes[:MAX_LIST_ITEMS], True
            if hashes:
                cleaned = clean(hashes, MAX_LIST_ITEM_CHARS)
                self._replay(cleaned, "instances", path, scratch)
                cut = cut or cleaned.cut > 0
                record["hashes"] = sorted(set(cleaned.items))
            records[json.dumps(record, ensure_ascii=False, sort_keys=True)] = record
        ordered = sorted(
            records.items(),
            key=lambda pair: (pair[1].get("version", ""), pair[1].get("bom_ref", ""), pair[0]),
        )
        if len(ordered) > MAX_INSTANCES_PER_PACKAGE:
            ordered, cut = ordered[:MAX_INSTANCES_PER_PACKAGE], True
        return [record for _, record in ordered], cut

    # The fold is a pure function of the candidate multiset: every choice is a max, a min or a
    # sorted union, so document order never reaches the observation (section 20).
    def _assemble_fold(self, key: _FoldKey, candidates: list[_Candidate]) -> Observation:
        """Fold every candidate that shares an identity into one OPEN observation."""
        record_id, resource_type, resource_id = key
        ordered = sorted(candidates, key=lambda candidate: candidate.order)
        primary = ordered[0]
        path = primary.path
        truncated: set[str] = set()
        for candidate in ordered:
            truncated |= candidate.truncated
        severity = max((candidate.severity for candidate in ordered), key=SEVERITY_RANK.__getitem__)
        sources = sorted(
            candidate.severity_source
            for candidate in ordered
            if candidate.severity is severity and candidate.severity_source
        )
        metadata = dict(primary.scalars)
        if sources:
            metadata["severity_source"] = sources[0]
        if primary.package_identity is not None:
            metadata["package_identity"] = primary.package_identity
        scope_type, scope_id = self.scope
        self._scalar(metadata, "subject_ref", f"{scope_type}:{scope_id}", path, truncated)
        if "subject_version" in self.scalars:
            metadata["subject_version"] = self.scalars["subject_version"]
        self._scalar(metadata, "tool_version", self.tool_version, path, truncated)
        unions: dict[str, set[str]] = {}
        for candidate in ordered:
            for member, items in candidate.lists.items():
                unions.setdefault(member, set()).update(items)
        carriers = sorted(
            {carrier for candidate in ordered for carrier in candidate.carriers}, key=repr
        )
        carrier_values: dict[str, list[str | None]] = {
            "package_versions": [carrier.version for carrier in carriers],
            "purls": [carrier.purl for carrier in carriers],
            "cpes": [carrier.cpe for carrier in carriers],
            "bom_refs": [carrier.bom_ref for carrier in carriers],
            "component_hashes": [text for carrier in carriers for text in carrier.hashes],
        }
        for member, texts in carrier_values.items():
            kept = self._evidence_list(
                sorted({text for text in texts if text is not None}), member, path, truncated
            )
            unions.setdefault(member, set()).update(kept)
        for member, union in sorted(unions.items()):
            if union:
                metadata[member] = encode_list(self._cut(sorted(union), member, path, truncated))
        if carriers:
            instances, instances_cut = self._instances(carriers, path)
            metadata["instances"] = encode_list(instances)
            if instances_cut:
                metadata["instances_cut"] = "true"
        if len(unions.get("analysis_states", ())) > 1:
            self.diagnostics.add(
                DiagnosticLevel.WARNING,
                "analysis_conflict",
                "one observation folds more than one analysis state" + ANALYSIS_KEPT,
                path,
            )
        if len({carrier.bom_ref for carrier in carriers}) > 1:
            self.diagnostics.add(
                DiagnosticLevel.INFO,
                "package_instances_folded",
                "installs of one package with different bom-refs fold into one observation",
                path,
            )
        identifiers, identifiers_cut = first_identifiers(
            identifier for candidate in ordered for identifier in candidate.identifiers
        )
        if identifiers_cut or any(candidate.identifiers_cut for candidate in ordered):
            truncated.add("source_identifiers")
            self.diagnostics.add(
                DiagnosticLevel.WARNING, "evidence_truncated", EVIDENCE_TRUNCATED_SUMMARY, path
            )
        metadata["occurrence_count"] = str(len(ordered))
        if truncated:
            metadata["truncated"] = encode_list(sorted(truncated))
        foreign = sorted(set(metadata) - CYCLONEDX_METADATA_KEYS)
        if foreign:
            raise RuntimeError(f"metadata keys outside the fixed vocabulary: {foreign}")
        observation = make_observation(
            artifact=self.artifact,
            source_type=CYCLONEDX_SOURCE_TYPE,
            source_tool=self.tool,
            source_record_id=record_id,
            resource_id=resource_id,
            resource_type=resource_type,
            observed_at=self.observed_at,
            ingested_at=self.ingested_at,
            disposition=ObservationDisposition.OPEN,
            severity=severity,
            title=primary.title,
            description=primary.description,
            identifiers=identifiers,
            context_key=self.tool,
            metadata=metadata,
        )
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
# nothing, and never walks dependencies.
class CycloneDxAdapter:
    """Parse one bounded CycloneDX JSON document into observations and diagnostics."""

    name = "complyroll.cyclonedx"
    version = CYCLONEDX_PARSER_VERSION
    media_type = CYCLONEDX_MEDIA_TYPE

    # ParseErrorCase.adapter is a zero-argument callable, so the limits default (A26).
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
            raise AdapterParseError("CycloneDX root must be a JSON object")
        # SECURITY: A checklist's own member is refused, so a document that carries both
        # shapes is read as a checklist or not at all (ADR 0013 decision 1).
        if "stigs" in data:
            raise AdapterParseError(
                "CycloneDX document carries a 'stigs' member; a STIG Viewer checklist is read "
                "under its own name"
            )
        if data.get("bomFormat") != "CycloneDX":
            raise AdapterParseError("JSON has no 'bomFormat' of 'CycloneDX'")
        spec_version = data.get("specVersion")
        # SECURITY: The value is quoted, sanitized and cut before it is echoed (A11).
        if not isinstance(spec_version, str) or spec_version not in SUPPORTED_SPEC_VERSIONS:
            raise AdapterParseError(
                "CycloneDX specVersion "
                + diagnostic_text(quoted(spec_version))
                + " is not supported; this build reads 1.4 to 1.7"
            )
        vulnerabilities: list[Any] | None = None
        if "vulnerabilities" in data:
            # A non-list holds no vulnerability record, so it makes no detection claim (A12).
            if not isinstance(data["vulnerabilities"], list):
                raise AdapterParseError("CycloneDX vulnerabilities is not an array")
            vulnerabilities = data["vulnerabilities"]
        return _CycloneDxParse(artifact, ingested_at, self.limits, vulnerabilities).run(data)
