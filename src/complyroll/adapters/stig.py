"""Hardened CKLB, CKL, XCCDF, and CCI adapters."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

from complyroll.models import (
    Observation,
    ObservationDisposition,
    ResourceRef,
    SourceSeverity,
)

from .base import (
    AdapterOutput,
    AdapterParseError,
    ArtifactProvenance,
    DiagnosticLevel,
    IngestDiagnostic,
    IngestResult,
    ParsedDocument,
)
from .safeio import (
    DEFAULT_LIMITS,
    IngestLimits,
    parse_json_bounded,
    parse_xml_bounded,
    read_bounded,
)

# Each adapter owns its own parser version because the version is an observation identity
# input (ADR 0002). A shared constant would re-mint every unchanged observation whenever
# one parser is corrected.
CKLB_PARSER_VERSION = "1"
CKL_PARSER_VERSION = "1"
XCCDF_PARSER_VERSION = "1"
CCI_PARSER_VERSION = "1"
# Covers the pre-dispatch XML stage, which fails before an adapter has been chosen.
XML_DISPATCH_PARSER_VERSION = "1"

PREFER_REVISION = "5"
CCI_PATTERN = re.compile(r"CCI-\d{6}")
CONTROL_PATTERN = re.compile(r"\b([A-Z]{2})-(\d+)")

# ARF wraps the XCCDF TestResult in an asset-report-collection envelope, so both roots reach the
# XCCDF adapter. `.arf` is the suffix OpenSCAP's ARF output is commonly given and holds the same
# XML, so it dispatches by root element exactly like `.xml` rather than being refused unread.
XCCDF_ROOT_ELEMENTS = frozenset({"Benchmark", "TestResult", "asset-report-collection"})
XML_SUFFIXES = frozenset({".xml", ".arf"})

STATUS_ALIASES = {
    "open": ObservationDisposition.OPEN,
    "not_a_finding": ObservationDisposition.PASS,
    "notafinding": ObservationDisposition.PASS,
    "not_applicable": ObservationDisposition.NOT_APPLICABLE,
    "notapplicable": ObservationDisposition.NOT_APPLICABLE,
    "not_reviewed": ObservationDisposition.NOT_REVIEWED,
    "not reviewed": ObservationDisposition.NOT_REVIEWED,
    "notreviewed": ObservationDisposition.NOT_REVIEWED,
    "fail": ObservationDisposition.OPEN,
    "pass": ObservationDisposition.PASS,
    "notchecked": ObservationDisposition.NOT_REVIEWED,
    "notselected": ObservationDisposition.NOT_APPLICABLE,
    "error": ObservationDisposition.ERROR,
    "unknown": ObservationDisposition.UNKNOWN,
    "informational": ObservationDisposition.NOT_REVIEWED,
    "fixed": ObservationDisposition.PASS,
}

SEVERITY_ALIASES = {
    "critical": SourceSeverity.CRITICAL,
    "high": SourceSeverity.HIGH,
    "medium": SourceSeverity.MEDIUM,
    "low": SourceSeverity.LOW,
    "info": SourceSeverity.INFORMATIONAL,
    "informational": SourceSeverity.INFORMATIONAL,
    "unknown": SourceSeverity.UNKNOWN,
}


def localname(tag: str) -> str:
    return tag.rpartition("}")[2]


def normalize_status(raw: object) -> ObservationDisposition:
    key = str(raw or "").strip().lower().replace("-", "")
    return STATUS_ALIASES.get(
        key,
        STATUS_ALIASES.get(key.replace(" ", ""), ObservationDisposition.NOT_REVIEWED),
    )


def normalize_severity(raw: object) -> SourceSeverity:
    return SEVERITY_ALIASES.get(str(raw or "").strip().lower(), SourceSeverity.UNKNOWN)


def _unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _parse_timestamp(value: object) -> datetime | None:
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


def _make_observation(
    *,
    artifact: ArtifactProvenance,
    source_type: str,
    source_tool: str,
    source_record_id: str,
    resource_id: str,
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
    observation = Observation(
        observation_id="pending",
        source_type=source_type,
        source_tool=source_tool,
        parser_name=artifact.parser_name,
        parser_version=artifact.parser_version,
        source_record_id=source_record_id,
        resource=ResourceRef(resource_id=resource_id, resource_type="host"),
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


def _missing_time_diagnostic(artifact: ArtifactProvenance) -> IngestDiagnostic:
    return IngestDiagnostic(
        DiagnosticLevel.WARNING,
        "source_timestamp_missing",
        "source artifact does not declare an observation timestamp; observed_at is unknown",
        artifact.name,
    )


class CklbAdapter:
    name = "complyroll.cklb"
    version = CKLB_PARSER_VERSION
    media_type = "application/json"

    def parse(
        self,
        document: ParsedDocument,
        artifact: ArtifactProvenance,
        *,
        ingested_at: datetime,
    ) -> AdapterOutput:
        data = document.value
        if not isinstance(data, Mapping):
            raise AdapterParseError("CKLB root must be a JSON object")
        stigs = data.get("stigs")
        if not isinstance(stigs, list) or not stigs:
            raise AdapterParseError("JSON has no non-empty 'stigs' array")

        diagnostics: list[IngestDiagnostic] = []
        raw_target = data.get("target_data")
        target: Mapping[str, object] = raw_target if isinstance(raw_target, Mapping) else {}
        host = _text(target.get("host_name")) or _text(target.get("ip_address"))
        if not host:
            host = Path(artifact.name).stem
            diagnostics.append(
                IngestDiagnostic(
                    DiagnosticLevel.WARNING,
                    "resource_identity_fallback",
                    "host identity is missing; using the artifact filename stem",
                    artifact.name,
                )
            )

        observed_at = None
        for timestamp_key in ("completed_at", "scan_time", "scan_date", "updated_at"):
            observed_at = _parse_timestamp(data.get(timestamp_key))
            if observed_at:
                break
        if observed_at is None:
            diagnostics.append(_missing_time_diagnostic(artifact))

        observations: list[Observation] = []
        for stig_index, stig in enumerate(stigs):
            if not isinstance(stig, Mapping):
                diagnostics.append(
                    IngestDiagnostic(
                        DiagnosticLevel.ERROR,
                        "invalid_stig",
                        "STIG entry must be an object",
                        f"stigs[{stig_index}]",
                    )
                )
                continue
            rules = stig.get("rules")
            if not isinstance(rules, list):
                diagnostics.append(
                    IngestDiagnostic(
                        DiagnosticLevel.ERROR,
                        "invalid_rules",
                        "STIG entry has no rules array",
                        f"stigs[{stig_index}].rules",
                    )
                )
                continue

            context_parts = [
                _text(stig.get("stig_id"))
                or _text(stig.get("uuid"))
                or _text(stig.get("stig_name")),
                _text(stig.get("version")),
                _text(stig.get("release_info")),
            ]
            context_key = "|".join(part for part in context_parts if part) or "cklb"

            for rule_index, rule in enumerate(rules):
                location = f"stigs[{stig_index}].rules[{rule_index}]"
                if not isinstance(rule, Mapping):
                    diagnostics.append(
                        IngestDiagnostic(
                            DiagnosticLevel.ERROR,
                            "invalid_rule",
                            "rule entry must be an object",
                            location,
                        )
                    )
                    continue

                rule_id = _text(rule.get("group_id")) or _text(rule.get("rule_id")) or "?"
                if rule_id == "?":
                    diagnostics.append(
                        IngestDiagnostic(
                            DiagnosticLevel.WARNING,
                            "source_record_id_missing",
                            "rule identifier is missing; using '?'",
                            location,
                        )
                    )
                raw_ccis = rule.get("ccis") or []
                if not isinstance(raw_ccis, list):
                    raw_ccis = []
                    diagnostics.append(
                        IngestDiagnostic(
                            DiagnosticLevel.WARNING,
                            "invalid_cci_list",
                            "rule CCIs must be an array; ignoring the value",
                            f"{location}.ccis",
                        )
                    )
                ccis = _unique(
                    [
                        value
                        for value in raw_ccis
                        if isinstance(value, str) and CCI_PATTERN.fullmatch(value)
                    ]
                )
                metadata = {
                    key: value
                    for key, value in {
                        "rule_id": _text(rule.get("rule_id")),
                        "rule_version": _text(rule.get("rule_version")),
                        "stig_id": _text(stig.get("stig_id")),
                    }.items()
                    if value
                }
                observations.append(
                    _make_observation(
                        artifact=artifact,
                        source_type="cklb",
                        source_tool="stig-viewer-3",
                        source_record_id=rule_id,
                        resource_id=host,
                        observed_at=observed_at,
                        ingested_at=ingested_at,
                        disposition=normalize_status(rule.get("status")),
                        severity=normalize_severity(rule.get("severity")),
                        title=_text(rule.get("rule_title")) or _text(rule.get("group_title")),
                        description=(
                            _text(rule.get("finding_details"))
                            or _text(rule.get("comments"))
                            or _text(rule.get("discussion"))
                        ),
                        identifiers=ccis,
                        context_key=context_key,
                        metadata=metadata,
                    )
                )

        if not observations:
            diagnostics.append(
                IngestDiagnostic(
                    DiagnosticLevel.ERROR,
                    "no_observations",
                    "CKLB contains no usable rules",
                    artifact.name,
                )
            )
        return AdapterOutput(tuple(observations), tuple(diagnostics))


def _ckl_context(root: ET.Element) -> str:
    for element in root.iter():
        if localname(element.tag) in {"STIG_TITLE", "TITLE"} and _text(element.text):
            return _text(element.text)
    return "ckl"


class CklAdapter:
    name = "complyroll.ckl"
    version = CKL_PARSER_VERSION
    media_type = "application/xml"

    def parse(
        self,
        document: ParsedDocument,
        artifact: ArtifactProvenance,
        *,
        ingested_at: datetime,
    ) -> AdapterOutput:
        root = document.value
        if not isinstance(root, ET.Element):
            raise AdapterParseError("CKL adapter requires an XML document")
        if localname(root.tag) not in {"CHECKLIST", "ASSET", "STIGS"}:
            raise AdapterParseError(f"XML root '{localname(root.tag)}' is not a CKL checklist")

        diagnostics: list[IngestDiagnostic] = [_missing_time_diagnostic(artifact)]
        host = ""
        for element in root.iter():
            if localname(element.tag) == "HOST_NAME" and _text(element.text):
                host = _text(element.text)
                break
        if not host:
            host = Path(artifact.name).stem
            diagnostics.append(
                IngestDiagnostic(
                    DiagnosticLevel.WARNING,
                    "resource_identity_fallback",
                    "host identity is missing; using the artifact filename stem",
                    artifact.name,
                )
            )

        observations: list[Observation] = []
        for vuln_index, vuln in enumerate(
            element for element in root.iter() if localname(element.tag) == "VULN"
        ):
            attributes: dict[str, list[str]] = defaultdict(list)
            raw_status = ""
            for child in vuln:
                name = localname(child.tag)
                if name == "STATUS":
                    raw_status = child.text or ""
                elif name == "STIG_DATA":
                    key = value = ""
                    for subelement in child:
                        if localname(subelement.tag) == "VULN_ATTRIBUTE":
                            key = _text(subelement.text)
                        elif localname(subelement.tag) == "ATTRIBUTE_DATA":
                            value = _text(subelement.text)
                    if key and value:
                        attributes[key].append(value)

            rule_id = (attributes.get("Vuln_Num") or ["?"])[0]
            if rule_id == "?":
                diagnostics.append(
                    IngestDiagnostic(
                        DiagnosticLevel.WARNING,
                        "source_record_id_missing",
                        "VULN identifier is missing; using '?'",
                        f"VULN[{vuln_index}]",
                    )
                )
            ccis = _unique(
                [
                    cci
                    for value in attributes.get("CCI_REF", [])
                    for cci in CCI_PATTERN.findall(value)
                ]
            )
            metadata = {
                key: value
                for key, value in {
                    "rule_id": (attributes.get("Rule_ID") or [""])[0],
                    "rule_version": (attributes.get("Rule_Ver") or [""])[0],
                }.items()
                if value
            }
            observations.append(
                _make_observation(
                    artifact=artifact,
                    source_type="ckl",
                    source_tool="stig-viewer-2",
                    source_record_id=rule_id,
                    resource_id=host,
                    observed_at=None,
                    ingested_at=ingested_at,
                    disposition=normalize_status(raw_status),
                    severity=normalize_severity((attributes.get("Severity") or [""])[0]),
                    title=(attributes.get("Rule_Title") or [""])[0],
                    description=(attributes.get("FINDING_DETAILS") or [""])[0],
                    identifiers=ccis,
                    context_key=_ckl_context(root),
                    metadata=metadata,
                )
            )

        if not observations:
            diagnostics.append(
                IngestDiagnostic(
                    DiagnosticLevel.ERROR,
                    "no_observations",
                    "CKL contains no VULN records",
                    artifact.name,
                )
            )
        return AdapterOutput(tuple(observations), tuple(diagnostics))


def _find_text(root: ET.Element, names: set[str]) -> str:
    for element in root.iter():
        if localname(element.tag) in names and _text(element.text):
            return _text(element.text)
    return ""


class XccdfAdapter:
    name = "complyroll.xccdf"
    version = XCCDF_PARSER_VERSION
    media_type = "application/xml"

    def parse(
        self,
        document: ParsedDocument,
        artifact: ArtifactProvenance,
        *,
        ingested_at: datetime,
    ) -> AdapterOutput:
        root = document.value
        if not isinstance(root, ET.Element):
            raise AdapterParseError("XCCDF adapter requires an XML document")
        root_name = localname(root.tag)
        if root_name not in XCCDF_ROOT_ELEMENTS:
            raise AdapterParseError(f"XML root '{root_name}' is not XCCDF or ARF")

        diagnostics: list[IngestDiagnostic] = []
        test_results = [
            element for element in root.iter() if localname(element.tag) == "TestResult"
        ]
        if root_name == "TestResult" and root not in test_results:
            test_results.insert(0, root)
        containers = test_results or [root]
        observations: list[Observation] = []
        timestamp_missing = False

        benchmark_id = root.get("id", "")
        for container in containers:
            host = _find_text(container, {"target", "fqdn"})
            if not host:
                host = Path(artifact.name).stem
                diagnostics.append(
                    IngestDiagnostic(
                        DiagnosticLevel.WARNING,
                        "resource_identity_fallback",
                        "XCCDF target is missing; using the artifact filename stem",
                        artifact.name,
                    )
                )
            observed_at = _parse_timestamp(container.get("end-time")) or _parse_timestamp(
                container.get("start-time")
            )
            if observed_at is None:
                timestamp_missing = True

            context_key = "|".join(
                value for value in (benchmark_id, container.get("id", "")) if value
            ) or "xccdf"
            for result_index, rule_result in enumerate(
                element for element in container.iter() if localname(element.tag) == "rule-result"
            ):
                result = ""
                ccis_list: list[str] = []
                for child in rule_result:
                    name = localname(child.tag)
                    if name == "result":
                        result = child.text or ""
                    elif name == "ident":
                        ccis_list.extend(CCI_PATTERN.findall(child.text or ""))
                ccis = _unique(ccis_list)
                idref = rule_result.get("idref", "?")
                source_record_id = idref.rpartition("_rule_")[2]
                observations.append(
                    _make_observation(
                        artifact=artifact,
                        source_type="xccdf",
                        source_tool="xccdf",
                        source_record_id=source_record_id,
                        resource_id=host,
                        observed_at=observed_at,
                        ingested_at=ingested_at,
                        disposition=normalize_status(result),
                        severity=normalize_severity(rule_result.get("severity", "")),
                        title=idref,
                        description="",
                        identifiers=ccis,
                        context_key=context_key,
                        metadata={"idref": idref, "result_index": str(result_index)},
                    )
                )

        if timestamp_missing:
            diagnostics.append(_missing_time_diagnostic(artifact))
        if not observations:
            diagnostics.append(
                IngestDiagnostic(
                    DiagnosticLevel.ERROR,
                    "no_observations",
                    "XCCDF contains no rule-result records",
                    artifact.name,
                )
            )
        return AdapterOutput(tuple(observations), tuple(diagnostics))


@dataclass(frozen=True, slots=True)
class CciControlMap:
    revision: str
    entries: tuple[tuple[str, tuple[str, ...]], ...]
    _lookup: Mapping[str, tuple[str, ...]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_lookup", MappingProxyType(dict(self.entries)))

    def controls_for(self, identifier: str) -> tuple[str, ...]:
        return self._lookup.get(identifier, ())

    def to_dict(self) -> dict[str, list[str]]:
        return {identifier: list(controls) for identifier, controls in self.entries}


@dataclass(frozen=True, slots=True)
class CciMapResult:
    artifact: ArtifactProvenance | None
    mapping: CciControlMap | None
    diagnostics: tuple[IngestDiagnostic, ...]

    @property
    def errors(self) -> tuple[IngestDiagnostic, ...]:
        return tuple(item for item in self.diagnostics if item.level is DiagnosticLevel.ERROR)

    @property
    def successful(self) -> bool:
        return self.artifact is not None and self.mapping is not None and not self.errors


def _artifact(
    path: Path,
    content: bytes,
    *,
    adapter_name: str,
    adapter_version: str,
    media_type: str,
    ingested_at: datetime,
) -> ArtifactProvenance:
    return ArtifactProvenance.from_bytes(
        path=path,
        content=content,
        media_type=media_type,
        parser_name=adapter_name,
        parser_version=adapter_version,
        ingested_at=ingested_at,
    )


def _error_result(
    *,
    artifact: ArtifactProvenance | None,
    code: str,
    message: str,
    location: str,
) -> IngestResult:
    return IngestResult(
        artifact=artifact,
        observations=(),
        diagnostics=(IngestDiagnostic(DiagnosticLevel.ERROR, code, message, location),),
    )


def ingest_stig_artifact(
    path: Path,
    *,
    ingested_at: datetime | None = None,
    limits: IngestLimits = DEFAULT_LIMITS,
) -> IngestResult:
    """Ingest one CKLB, CKL, XCCDF, or ARF artifact without network access."""

    path = Path(path)
    now = ingested_at or datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("ingested_at must include a timezone")
    try:
        content = read_bounded(path, limits)
    except (OSError, ValueError) as exc:
        return _error_result(
            artifact=None,
            code="artifact_read_failed",
            message=str(exc),
            location=str(path),
        )

    suffix = path.suffix.lower()
    adapter: CklbAdapter | CklAdapter | XccdfAdapter
    document: ParsedDocument
    artifact: ArtifactProvenance
    try:
        if suffix in {".cklb", ".json"}:
            adapter = CklbAdapter()
            artifact = _artifact(
                path,
                content,
                adapter_name=adapter.name,
                adapter_version=adapter.version,
                media_type=adapter.media_type,
                ingested_at=now,
            )
            document = ParsedDocument("json", parse_json_bounded(content, limits))
        elif suffix == ".ckl":
            adapter = CklAdapter()
            artifact = _artifact(
                path,
                content,
                adapter_name=adapter.name,
                adapter_version=adapter.version,
                media_type=adapter.media_type,
                ingested_at=now,
            )
            document = ParsedDocument("xml", parse_xml_bounded(content, limits))
        elif suffix in XML_SUFFIXES:
            root = parse_xml_bounded(content, limits)
            if localname(root.tag) in XCCDF_ROOT_ELEMENTS:
                adapter = XccdfAdapter()
            else:
                adapter = CklAdapter()
            artifact = _artifact(
                path,
                content,
                adapter_name=adapter.name,
                adapter_version=adapter.version,
                media_type=adapter.media_type,
                ingested_at=now,
            )
            document = ParsedDocument("xml", root)
        else:
            artifact = _artifact(
                path,
                content,
                adapter_name="unresolved",
                adapter_version="0",
                media_type="application/octet-stream",
                ingested_at=now,
            )
            return _error_result(
                artifact=artifact,
                code="unsupported_artifact",
                message=f"unrecognized input type: {path.name}",
                location=path.name,
            )
    except (json.JSONDecodeError, ValueError) as exc:
        if suffix in {".cklb", ".json"}:
            name, version = CklbAdapter.name, CklbAdapter.version
            media_type = CklbAdapter.media_type
        elif suffix == ".ckl":
            name, version = CklAdapter.name, CklAdapter.version
            media_type = CklAdapter.media_type
        else:
            name, version = "complyroll.xml-auto", XML_DISPATCH_PARSER_VERSION
            media_type = "application/xml"
        artifact = _artifact(
            path,
            content,
            adapter_name=name,
            adapter_version=version,
            media_type=media_type,
            ingested_at=now,
        )
        return _error_result(
            artifact=artifact,
            code="artifact_parse_failed",
            message=str(exc),
            location=path.name,
        )

    try:
        output = adapter.parse(
            document,
            artifact,
            ingested_at=now,
        )
    except (AdapterParseError, ValueError, TypeError) as exc:
        return _error_result(
            artifact=artifact,
            code="artifact_parse_failed",
            message=str(exc),
            location=path.name,
        )

    observation_ids = Counter(observation.observation_id for observation in output.observations)
    duplicate_ids = sorted(
        observation_id for observation_id, count in observation_ids.items() if count > 1
    )
    diagnostics = output.diagnostics
    if duplicate_ids:
        diagnostics += (
            IngestDiagnostic(
                DiagnosticLevel.ERROR,
                "duplicate_observation_identity",
                f"artifact produced {len(duplicate_ids)} duplicate observation identifier(s)",
                path.name,
            ),
        )
    return IngestResult(artifact, output.observations, diagnostics)


def load_cci_control_map(
    path: Path,
    *,
    prefer_revision: str = PREFER_REVISION,
    ingested_at: datetime | None = None,
    limits: IngestLimits = DEFAULT_LIMITS,
) -> CciMapResult:
    """Load a DISA U_CCI_List.xml mapping with the same revision semantics as stigroll."""

    path = Path(path)
    now = ingested_at or datetime.now(UTC)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("ingested_at must include a timezone")
    try:
        content = read_bounded(path, limits)
    except (OSError, ValueError) as exc:
        return CciMapResult(
            None,
            None,
            (IngestDiagnostic(DiagnosticLevel.ERROR, "cci_read_failed", str(exc), str(path)),),
        )

    artifact = _artifact(
        path,
        content,
        adapter_name="complyroll.cci",
        adapter_version=CCI_PARSER_VERSION,
        media_type="application/xml",
        ingested_at=now,
    )
    try:
        root = parse_xml_bounded(content, limits)
    except ValueError as exc:
        return CciMapResult(
            artifact,
            None,
            (
                IngestDiagnostic(
                    DiagnosticLevel.ERROR,
                    "cci_parse_failed",
                    str(exc),
                    path.name,
                ),
            ),
        )

    per_item: dict[str, dict[str, list[str]]] = {}
    for item in root.iter():
        if localname(item.tag) != "cci_item":
            continue
        cci_id = item.get("id")
        if not cci_id:
            continue
        by_revision: dict[str, list[str]] = defaultdict(list)
        for reference in item.iter():
            if localname(reference.tag) != "reference":
                continue
            for family, number in CONTROL_PATTERN.findall(reference.get("index", "")):
                by_revision[reference.get("version", "")].append(f"{family}-{number}")
        if by_revision:
            per_item[cci_id] = by_revision

    if not per_item:
        return CciMapResult(
            artifact,
            None,
            (
                IngestDiagnostic(
                    DiagnosticLevel.ERROR,
                    "cci_map_empty",
                    "CCI document contains no usable cci_item references",
                    path.name,
                ),
            ),
        )

    list_has_revision = any(prefer_revision in revisions for revisions in per_item.values())
    entries: list[tuple[str, tuple[str, ...]]] = []
    for cci_id, by_revision in per_item.items():
        if prefer_revision in by_revision:
            chosen = by_revision[prefer_revision]
        elif list_has_revision:
            continue
        else:
            chosen = by_revision[max(by_revision)]
        entries.append((cci_id, tuple(sorted(set(chosen)))))

    mapping = CciControlMap(prefer_revision, tuple(sorted(entries)))
    return CciMapResult(artifact, mapping, ())
