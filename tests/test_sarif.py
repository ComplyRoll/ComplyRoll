# ******************************************************************************
# *Title: SARIF Adapter Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the SARIF 2.1.0 adapter (ADR 0011).*
# ******************************************************************************
"""Unit tests for the SARIF adapter: fixture mappings, corners, folds, clocks, refusals."""

# *--- Imports ---*

from __future__ import annotations

import json
import random
import re
import sys
import tempfile
import time
import unittest
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta, timezone
from itertools import permutations
from pathlib import Path
from typing import Any
from unittest import mock

from test_replay import INGESTED_AT, RATIONALE, StoreFixture
from test_reports import summary_counts

from complyroll.adapters import IngestLimits, InputLimitError, ingest_stig_artifact
from complyroll.adapters import sarif as sarif_module
from complyroll.adapters.base import (
    AdapterOutput,
    AdapterParseError,
    ArtifactProvenance,
    DiagnosticLevel,
    IngestDiagnostic,
    IngestResult,
    ParsedDocument,
)
from complyroll.adapters.common import parse_timestamp, text_of
from complyroll.adapters.sarif import (
    MAX_CLOCK_YEAR,
    MAX_DESCRIPTION_CHARS,
    MAX_DIAGNOSTIC_PATHS,
    MAX_IDENTITY_CHARS,
    MAX_LIST_ITEM_CHARS,
    MAX_LIST_ITEMS,
    MAX_LOCATIONS_PER_RESULT,
    MAX_MESSAGE_ARGUMENTS,
    MAX_MESSAGE_PLACEHOLDERS,
    MAX_METADATA_VALUE_CHARS,
    MAX_OBSERVATION_JSON_BYTES,
    MAX_REGION_INTEGER,
    MAX_TITLE_CHARS,
    MAX_URI_CHARS,
    METADATA_KEYS,
    MIN_CLOCK_YEAR,
    SARIF_MEDIA_TYPE,
    SARIF_PARSER_VERSION,
    SARIF_SOURCE_TYPE,
    TRUNCATION_MARKER,
    SarifAdapter,
    _expand_message,
    _flatten_links,
    _quoted,
    _sanitize,
    _sarif_timestamp,
)
from complyroll.correlation import correlate_observations, tracking_id_for
from complyroll.history import (
    HistoryError,
    attest_detection,
    audit_history,
    record_ingest,
    rehydrate_observations,
)
from complyroll.models import Observation, ObservationDisposition, SourceSeverity
from complyroll.policy import CertificationClass
from complyroll.reports import (
    CompiledVdtReport,
    ReportCompileError,
    ReportOptions,
    compile_avi_report,
    compile_avi_report_from_history,
    compile_historical_report,
    compile_historical_report_from_history,
    compile_vdt_report,
    compile_vdt_report_from_history,
)
from complyroll.store import MAX_EVENT_JSON_BYTES, SQLiteEventStore

# *--- Configuration ---*

NOW = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)
FIXTURES = Path(__file__).parent / "fixtures"
SARIF_ATTRIBUTION = ("complyroll.sarif", SARIF_PARSER_VERSION, SARIF_MEDIA_TYPE)

MISSING_CLOCK_MESSAGE = (
    "source artifact does not declare an observation timestamp; observed_at is unknown"
)
NO_OBSERVATIONS_MESSAGE = "SARIF log contains no usable results"
INVALID_CLOCK_MESSAGE = (
    "clock value is not an aware timestamp with a whole-minute offset in the years "
    "1970 to 9000 UTC; ignored"
)
IDENTITY_MESSAGE = "an identity input cannot be used as written"

# Observation ids of every SARIF fixture, in emitted order. Derived by running the adapter;
# the step 3 goldens will carry the same ids as a byte contract.
TRIVY_IDS = (
    "obs-d45792aec4765dc6ba636cfdad05efb765b64ea6a165967597bbeec48515645b",
    "obs-25961fc0953d10e352b0ec08de870bbee884908cd0bab7caf25dfe5d25419da5",
    "obs-5ea3291a292bb631cab60a71b119462521b8c0f7d3f3b24768d5118e80da6a26",
)
GRYPE_IDS = (
    "obs-bb3eeec613ffd640a8264b741eb5ee2c3c60d0deadc218451983a07af20e49cc",
    "obs-8c6fa53fe2ee41b2ebdb8255ad26fa85cc6acc0eacdea7f4a52d71a2775e3603",
)
SEMGREP_IDS = (
    "obs-4d2cecbc01f1d26987474dcc62dfd9181ae535a3801d4497da5df0aa7b750ebf",
    "obs-1c709c8cf32997e15f0d08ebae8d1234f40af69b2b30fdcc139ee27093b2d4d1",
)
CODEQL_IDS = (
    "obs-f83132c858c2cb4e2aa6164ab5a1450d14e4591906686d08a0d7886d71d8647e",
    "obs-3f57637539e35a21cf20f32a100e3bf7d3816cc6db02582af96ab0fbf3e3ace6",
    "obs-bfb476cb4c0fc63036f9e0d60a997a1a8431e9ec89db45314e546ac48aee360b",
)
CHECKOV_IDS = (
    "obs-852a8beb46d5267ed7f90eae54319b562cc66bab1ad9a6cdaee6cd5d56fd1d85",
    "obs-6d8750349283709d33e633d4ac848ee406762006d25ca2d4b243611203648720",
    "obs-5a2ea2b0d3fc739c8bd0750f583bfb1216043536890af21c02a2dfd1f32a55d4",
)
CORNER_IDS = (
    "obs-a34932ef4bdb905d6b13608091ad450a14aa7c7cc191e837f19e6b5a20e760a2",
    "obs-6d8bd5f79803a5cbfc0e656144910cfddee70bec3eea1ff09bd23f1b191d39c3",
    "obs-e93fbe574cad3173e756890483edf6790bb797e27f8b2bab44590a01585148a0",
    "obs-1c891aa1f3d1147430cb497a8aa1ac2e47f8d4767d7eaf36dd7ceb3b9be01461",
    "obs-e455659d3146b8b4752d173d95c812449a334a2978f416df1f10d3bc8472f746",
    "obs-a714ad58dec97a19f51c29dce42a5f1704bc724375ba0b29d424f25d86372126",
    "obs-8facced57f4d715810877fad0f9a4265f29a9910542a5dff6877a4b9c4fc7070",
    "obs-86afbf55709a64cf4e2e5b701c06ba8035f9e584b174d75500f2ab9e5a3525b6",
    "obs-640dbebcb2ca24f97fa9f04c049524d24866df928304dba0e0b7d03814ef18f2",
    "obs-ba8cbbba40541c4b1501b95d4f6ac60fe864935a0a97fbb760e6688f61dbbfa8",
    "obs-18d9be5089ca3e5f5dbde2e8cc583dccff334dfa5d49c774f4c7dd36807b9238",
    "obs-594e523756f6c3976fdd531a7712e7020730ca8008b7203943806aa007c627aa",
    "obs-5c067b31830c74b6f88451f75e727abd15aef972baf9a30e8cb239a2184e4002",
    "obs-da0ccef6f7e6433cd68952e852a64c5c83728f104d7f75c773b582f2c3cae071",
    "obs-f467be4d70a6c31cf4cb2df111ff363a25d740d4c2f4cd2b6bfda43017248790",
    "obs-172f3e4e19501eaa962b22110c26f24db0a4c6ea6f0bdba5290289a50fb37db8",
    "obs-b5050ed4a4f37a50d5fced655798219c63f4bbe5bebcae253a17827770fd0708",
    "obs-a0daf8a745d8b55010b88fdb6a850046b25263f908e93f4e8ef2aab3c58965bf",
    "obs-bc0b3c0f9f0d4d7f53b683b747f2b7a78386e9de8583a346a0884e75bcaa779d",
    "obs-b85ba312c1f1bb4bb54877ecc4796f3abb81b11db32b8fbe92222e21a236bdb5",
    "obs-e9162ca7f3e7b77b0e4042acfa34ee185e5cd9be4d2246263b51d4c420ebfd65",
    "obs-1271df35988a640b03fce8269f7480c14d8faab2d340d591f38019acf3923d0b",
    "obs-d46a23bdd503c76b473365e554d3931f5d868028728e59d881cccfea12ced71f",
    "obs-4ff89f015d95ca3b8e5362fa68cc08cf1f05636f36e4a53a8f7682fb8a75a3f5",
    "obs-af22e0d468242a477c07514422ec58bfc2d2dada4edb6f208e8b1c295d30d038",
    "obs-0e3238db7d8b3c0eae5acfb0bd4e7305c520cb425886e503a194e9a9fd62616a",
    "obs-84c9cae899f1ba809f93072b2f3e4406445c02a406c8643dae9ecff850e7ea5f",
    "obs-0e0538dc84c3dd92eea296334eb83de10f3c11942e2eee8a1900807e4f929115",
)
FIXTURE_IDS = {
    "trivy-image.sarif": TRIVY_IDS,
    "grype-image.sarif": GRYPE_IDS,
    "semgrep-code.sarif": SEMGREP_IDS,
    "codeql-repo.sarif": CODEQL_IDS,
    "checkov-iac.sarif": CHECKOV_IDS,
    "sarif-spec-corners.sarif": CORNER_IDS,
}

# The SARIF goldens: the three tool fixtures compiled with the options below (ADR 0011).
GOLDEN = Path(__file__).parent / "golden"
SARIF_ARTIFACTS = (
    FIXTURES / "trivy-image.sarif",
    FIXTURES / "semgrep-code.sarif",
    FIXTURES / "codeql-repo.sarif",
)
PACKAGE_URI = "https://example.test/cpo"
REPORT_PERIOD_FROM = datetime(2026, 9, 1, tzinfo=UTC)
REPORT_PERIOD_TO = datetime(2026, 9, 30, 23, 59, 59, tzinfo=UTC)
REPORT_AS_OF = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
REPORT_DETECTED_AT = datetime(2026, 9, 1, tzinfo=UTC)
SECOND_INGEST = NOW + timedelta(days=1)
# Tracking ids in golden order: Trivy, CodeQL, Semgrep, each sorted by source record.
GOLDEN_TRACKING_IDS = (
    "case-10f5974d95a33fdf",
    "case-889c19760e425785",
    "case-04716522daa6f550",
    "case-d2b9f5abf1fe44ac",
    "case-5cfbebe8d4b91c27",
    "case-0e3754ea1c369285",
)
# The four ids the plan works by hand, and the split the detection attestation makes.
WORKED_TRACKING_IDS = (
    "case-10f5974d95a33fdf",
    "case-889c19760e425785",
    "case-5cfbebe8d4b91c27",
    "case-d2b9f5abf1fe44ac",
)
CLOCKLESS_TRACKING_IDS = (
    "case-0e3754ea1c369285",
    "case-10f5974d95a33fdf",
    "case-5cfbebe8d4b91c27",
    "case-889c19760e425785",
)
CLOCKED_TRACKING_IDS = ("case-04716522daa6f550", "case-d2b9f5abf1fe44ac")
CORNER_NOLOC_ID = "obs-e9162ca7f3e7b77b0e4042acfa34ee185e5cd9be4d2246263b51d4c420ebfd65"
# Results a rewording may change without moving a fold's primary: the later member of each
# Trivy and Semgrep fold. CodeQL folds nothing, so only its order moves.
REWORDED_RESULTS: dict[str, tuple[int, ...]] = {
    "trivy-image.sarif": (1, 4),
    "semgrep-code.sarif": (1,),
    "codeql-repo.sarif": (),
}

# The saturated log and the two reproductions (plan, Tests section).
RUN_CLOCK = {"startTimeUtc": "2026-09-01T00:00:00Z"}
EXAMPLE_URI = "https://example.test/"
OVER_SCALAR = MAX_METADATA_VALUE_CHARS + 88
OVER_ITEM = MAX_LIST_ITEM_CHARS + 44
OVER_LIST = MAX_LIST_ITEMS + 1
OVER_MESSAGE = 600
LONG_NAME_CHARS = 4_096
REPRODUCTION_A_RESULTS = 2_000
REPRODUCTION_B_NAMES = 300
CUT_LISTS = (
    "fingerprints",
    "image_digests",
    "location_messages",
    "logical_locations",
    "partial_fingerprints",
    "regions",
    "result_kinds",
    "rule_deprecated_ids",
    "rule_tags",
    "run_indexes",
    "suppression_kinds",
    "suppression_statuses",
    "taxa",
)
CUT_TEXT_LISTS = (
    "image_digests",
    "logical_locations",
    "rule_deprecated_ids",
    "rule_tags",
    "suppression_kinds",
    "suppression_statuses",
    "taxa",
)
CUT_SCALARS = (
    "baseline_state",
    "correlation_guid",
    "guid",
    "revision_id",
    "rule_component",
    "rule_name",
    "security_severity",
    "tool_semantic_version",
    "tool_version",
    "uri_base_id",
)
SATURATED_TRUNCATED = tuple(
    sorted(CUT_LISTS + CUT_SCALARS + ("description", "result_kind", "source_identifiers", "title"))
)
# A producer value far past every cap, quoted by a diagnostic or embedded in its path.
ONE_MIB = 1024 * 1024
# The count, the noun, and the separators around a coalesced diagnostic's paths and detail.
DIAGNOSTIC_FRAME_CHARS = 64

# *--- Helpers ---*


def make_run(
    results: Any = (),
    rules: list[dict[str, Any]] | None = None,
    driver: str = "Synth",
    **extra: Any,
) -> dict[str, Any]:
    """Build one run with the given results and optional driver rules."""
    tool: dict[str, Any] = {"name": driver}
    if rules is not None:
        tool["rules"] = rules
    run: dict[str, Any] = {"tool": {"driver": tool}, "results": list(results)}
    run.update(extra)
    return run


def make_result(
    rule_id: str | None = "R1",
    uri: str | None = "src/a.py",
    line: int | None = 1,
    text: str | None = "finding",
    **extra: Any,
) -> dict[str, Any]:
    """Build one result with a single physical location."""
    result: dict[str, Any] = {}
    if text is not None:
        result["message"] = {"text": text}
    if rule_id is not None:
        result["ruleId"] = rule_id
    if uri is not None:
        region = {"startLine": line} if line is not None else {}
        result["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}
        ]
    result.update(extra)
    return result


def make_log(*runs: Any, version: Any = "2.1.0") -> dict[str, Any]:
    """Build a SARIF log around the given runs."""
    return {"version": version, "runs": list(runs)}


def ingest_document(
    payload: Any,
    name: str = "synthetic.sarif",
    limits: IngestLimits | None = None,
    raw: bytes | None = None,
    ingested_at: datetime = NOW,
) -> IngestResult:
    """Write a document to a temporary file and run it through the dispatcher."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / name
        if raw is not None:
            path.write_bytes(raw)
        else:
            path.write_text(json.dumps(payload), encoding="utf-8")
        if limits is None:
            return ingest_stig_artifact(path, ingested_at=ingested_at)
        return ingest_stig_artifact(path, ingested_at=ingested_at, limits=limits)


def ingest_fixture(name: str) -> IngestResult:
    return ingest_stig_artifact(FIXTURES / name, ingested_at=NOW)


def parse_direct(payload: Any, artifact: ArtifactProvenance | None = None) -> AdapterOutput:
    """Run the adapter on an in-memory document, bypassing the file dispatcher."""
    if artifact is None:
        artifact = synthetic_artifact(payload)
    return SarifAdapter().parse(ParsedDocument("json", payload), artifact, ingested_at=NOW)


def synthetic_artifact(payload: Any) -> ArtifactProvenance:
    return ArtifactProvenance.from_bytes(
        path=Path("synthetic.sarif"),
        content=json.dumps(payload).encode("utf-8"),
        media_type=SARIF_MEDIA_TYPE,
        parser_name="complyroll.sarif",
        parser_version=SARIF_PARSER_VERSION,
        ingested_at=NOW,
    )


def only_observation(result: IngestResult | AdapterOutput) -> Observation:
    """Return the single observation a document yields, failing loudly otherwise."""
    if len(result.observations) != 1:
        raise AssertionError(f"expected one observation, got {len(result.observations)}")
    return result.observations[0]


def only_diagnostic(result: IngestResult | AdapterOutput, code: str) -> IngestDiagnostic:
    """Return the single diagnostic carrying the code, failing loudly otherwise."""
    matches = [item for item in result.diagnostics if item.code == code]
    if len(matches) != 1:
        raise AssertionError(f"expected one {code} diagnostic, got {len(matches)}")
    return matches[0]


def diagnostic_codes(result: IngestResult | AdapterOutput) -> list[str]:
    return [item.code for item in result.diagnostics]


def metadata(observation: Observation) -> dict[str, str]:
    return dict(observation.source_metadata)


def evidence_codes(result: IngestResult | AdapterOutput) -> list[str]:
    return [code for code in diagnostic_codes(result) if code.startswith("evidence_")]


def attribution(result: IngestResult) -> tuple[str, str, str]:
    if result.artifact is None:
        raise AssertionError("result carries no artifact provenance")
    return (
        result.artifact.parser_name,
        result.artifact.parser_version,
        result.artifact.media_type,
    )


def by_resource(result: IngestResult | AdapterOutput) -> dict[str, Observation]:
    """Index observations by resource id; every caller has distinct resources."""
    indexed = {item.resource.resource_id: item for item in result.observations}
    if len(indexed) != len(result.observations):
        raise AssertionError("observations do not have distinct resource ids")
    return indexed


def offset_hours(observation: Observation) -> float:
    if observation.observed_at is None:
        raise AssertionError("observation has no observed_at")
    offset = observation.observed_at.utcoffset()
    if offset is None:
        raise AssertionError("observed_at is naive")
    return offset.total_seconds() / 3600


def report_options(*, detected_at: datetime | None = None) -> ReportOptions:
    """Return the golden report options; `detected_at` only where a path takes the flag."""
    return ReportOptions(
        certification_class=CertificationClass.C,
        package_uri=PACKAGE_URI,
        period_from=REPORT_PERIOD_FROM,
        period_to=REPORT_PERIOD_TO,
        as_of=REPORT_AS_OF,
        calendar_timezone="UTC",
        detected_at_attestation=detected_at,
    )


def compile_sarif_golden() -> CompiledVdtReport:
    """Compile the SARIF golden the way the documented command line does."""
    return compile_vdt_report(
        list(SARIF_ARTIFACTS), options=report_options(detected_at=REPORT_DETECTED_AT)
    )


def fixture_payload(name: str) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload


def reordered_and_reworded(name: str, positions: Sequence[int]) -> dict[str, Any]:
    """Copy a fixture with the named results reworded and every run's results reversed."""
    payload = fixture_payload(name)
    for run in payload["runs"]:
        for position in positions:
            message = run["results"][position]["message"]
            message["text"] = f"{message['text']} (reworded copy)"
        run["results"].reverse()
    return payload


def provenance_of(path: Path) -> ArtifactProvenance:
    return ArtifactProvenance.from_bytes(
        path=path,
        content=path.read_bytes(),
        media_type=SARIF_MEDIA_TYPE,
        parser_name="complyroll.sarif",
        parser_version=SARIF_PARSER_VERSION,
        ingested_at=NOW,
    )


def identity_of(observation: Observation) -> tuple[str, str, str, str, str]:
    """Return the fold key, which is what a tracking id and a fingerprint are built from."""
    return (
        observation.source_tool,
        observation.source_record_id,
        observation.resource.resource_type,
        observation.resource.resource_id,
        observation.context_key,
    )


def tracking_id_of(observation: Observation) -> str:
    return tracking_id_for(
        observation.source_type, observation.source_record_id, observation.context_key
    )


def evidence_without_run_indexes(observation: Observation) -> dict[str, str]:
    return {key: value for key, value in metadata(observation).items() if key != "run_indexes"}


def location_less(result: IngestResult) -> Observation:
    """Return the corner observation whose result names no location at all."""
    matches = [item for item in result.observations if item.source_record_id == "CORNER-NOLOC"]
    if len(matches) != 1:
        raise AssertionError(f"expected one CORNER-NOLOC observation, got {len(matches)}")
    return matches[0]


def correlation_json(paths: Sequence[Path]) -> str:
    """Render a `CorrelationResult` as canonical JSON; the type has no serializer of its own."""
    observations: list[Observation] = []
    for path in paths:
        observations.extend(ingest_stig_artifact(path, ingested_at=NOW).observations)
    result = correlate_observations(observations)
    document = {
        "groups": [
            {
                "tracking_id": group.tracking_id,
                "source_type": group.source_type,
                "source_record_id": group.source_record_id,
                "context_key": group.context_key,
                "observations": [item.to_canonical_dict() for item in group.observations],
                "resources": [[ref.resource_id, ref.resource_type] for ref in group.resources],
                "source_identifiers": list(group.source_identifiers),
                "title": group.title,
                "description": group.description,
                "earliest_observed_at": (
                    None
                    if group.earliest_observed_at is None
                    else group.earliest_observed_at.isoformat()
                ),
                "detection_sources": list(group.detection_sources),
                "untimestamped_observation_ids": list(group.untimestamped_observation_ids),
            }
            for group in result.groups
        ],
        "excluded": [item.to_canonical_dict() for item in result.excluded],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def capped_uri(char: str) -> str:
    """Return an absolute uri of exactly MAX_URI_CHARS characters."""
    return EXAMPLE_URI + char * (MAX_URI_CHARS - len(EXAMPLE_URI))


def numbered(char: str, index: int, length: int) -> str:
    """Return distinct text of the given length; the index leads, so it survives any cut."""
    return f"{index:04d}" + char * (length - 4)


def numbered_list(char: str, length: int = OVER_ITEM, count: int = OVER_LIST) -> list[str]:
    return [numbered(char, index, length) for index in range(count)]


def saturated_log() -> dict[str, Any]:
    """Build a log with every identity input at its cap and every evidence member over its cap.

    Sixty-five runs share one driver, automation category, image, rule, and uri, so every
    result folds into one observation whose lists are all cut at MAX_LIST_ITEMS and whose
    scalars are all cut at MAX_METADATA_VALUE_CHARS. Run 0 carries the primary result: the
    first region, MAX_LOCATIONS_PER_RESULT locations, every over-cap member, and one CVE id
    past MAX_LIST_ITEMS. Each other run adds one result with an over-cap kind, so
    `result_kinds` and `run_indexes` saturate.
    """
    driver = "D" * MAX_IDENTITY_CHARS
    automation = "a" * (MAX_IDENTITY_CHARS - 12) + "/" + "b" * 11
    image = "i" * MAX_IDENTITY_CHARS
    uri = "u" * MAX_URI_CHARS
    rule_id = "R" * MAX_IDENTITY_CHARS
    base_id = "B" * OVER_SCALAR
    descriptor = {
        "id": rule_id,
        "name": "N" * OVER_SCALAR,
        "shortDescription": {"text": "T" * (MAX_TITLE_CHARS + 88)},
        "helpUri": capped_uri("h"),
        "deprecatedIds": numbered_list("d"),
        "properties": {"tags": numbered_list("t")},
    }
    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": base_id},
                "region": {"startLine": index + 1, "startColumn": 1},
            },
            "message": {"text": numbered("m", index, OVER_ITEM)},
            "logicalLocations": [{"fullyQualifiedName": numbered("l", index, OVER_ITEM)}],
        }
        for index in range(MAX_LOCATIONS_PER_RESULT)
    ]
    placeholders = " ".join("{" + str(index) + "}" for index in range(MAX_MESSAGE_ARGUMENTS + 8))
    primary = {
        "rule": {"index": 0, "toolComponent": {"index": 0}},
        "kind": "fail",
        "level": "error",
        "message": {
            "text": "x" * (MAX_DESCRIPTION_CHARS + 904) + " " + placeholders,
            "arguments": ["g" * 40] * (MAX_MESSAGE_ARGUMENTS + 8),
        },
        "locations": locations,
        "fingerprints": dict(zip(numbered_list("f"), numbered_list("v"), strict=True)),
        "partialFingerprints": dict(zip(numbered_list("p"), numbered_list("w"), strict=True)),
        "taxa": [{"id": taxon} for taxon in numbered_list("x")],
        "suppressions": [
            {"kind": kind, "status": status}
            for kind, status in zip(numbered_list("k"), numbered_list("s"), strict=True)
        ],
        "guid": "G" * OVER_SCALAR,
        "correlationGuid": "C" * OVER_SCALAR,
        "baselineState": "S" * OVER_SCALAR,
        "properties": {
            "security-severity": "9" * OVER_SCALAR,
            "cve": [f"CVE-2026-{index:05d}" for index in range(OVER_LIST)],
        },
    }
    first_run = {
        "tool": {
            "driver": {
                "name": driver,
                "version": "V" * OVER_SCALAR,
                "semanticVersion": "M" * OVER_SCALAR,
                "informationUri": capped_uri("n"),
            },
            "extensions": [{"name": "E" * OVER_SCALAR, "rules": [descriptor]}],
        },
        "invocations": [RUN_CLOCK],
        "automationDetails": {"id": automation},
        "properties": {"imageName": image, "repoDigests": numbered_list("q")},
        "versionControlProvenance": [
            {"repositoryUri": capped_uri("r"), "revisionId": "Z" * OVER_SCALAR}
        ],
        "originalUriBaseIds": {base_id: {"uri": capped_uri("o")}},
        "results": [primary],
    }
    other_runs = [
        {
            "tool": {"driver": {"name": driver}},
            "invocations": [RUN_CLOCK],
            "automationDetails": {"id": automation},
            "properties": {"imageName": image},
            "results": [
                {
                    "ruleId": rule_id,
                    "kind": numbered("K", index, OVER_SCALAR),
                    "message": {"text": f"run {index}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": 2},
                            }
                        }
                    ],
                }
            ],
        }
        for index in range(1, OVER_LIST)
    ]
    return make_log(first_run, *other_runs)


def diagnostic_bound(message: str) -> int:
    """Return the longest message a coalesced diagnostic with this message's summary can emit."""
    summary = message.partition(" (")[0]
    return (
        len(summary)
        + (MAX_DIAGNOSTIC_PATHS + 1) * MAX_METADATA_VALUE_CHARS
        + DIAGNOSTIC_FRAME_CHARS
    )


def cut_item(text: str, prefix: str = "") -> str:
    """Return a list item's text cut to leave room for its prefix within MAX_LIST_ITEM_CHARS."""
    return text[: MAX_LIST_ITEM_CHARS - len(prefix) - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def cut_detail(text: str) -> str:
    """Return diagnostic text cut at MAX_METADATA_VALUE_CHARS the way the adapter cuts it."""
    return text[: MAX_METADATA_VALUE_CHARS - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def cwe_flood(count: int) -> dict[str, Any]:
    """One rule whose single tag string names CWE-1 through CWE-count, used by one result."""
    tags = " ".join(f"CWE-{number}" for number in range(1, count + 1))
    rules = [{"id": "R1", "properties": {"tags": [tags]}}]
    result = make_result(ruleIndex=0, level="error", text="x", uri="a.py", line=None)
    return make_log(make_run([result], rules=rules, invocations=[RUN_CLOCK]))


FOUR_BYTE_CHAR = "\U0001f600"
PADDING_RUN = re.compile(r"([A-Za-z])\1{19,}")


def four_byte_log(share: float, char: str = FOUR_BYTE_CHAR) -> dict[str, Any]:
    """Return the saturated log with the given share of every padding run swapped to char.

    The caps count characters. UTF-8 spends four bytes on the default, and a quote or a
    backslash in a list item is escaped twice and costs four as well; no kept character costs
    more in canonical JSON, so the same caps allow about four times the plain ASCII bytes.
    """

    def run(match: re.Match[str]) -> str:
        length = len(match.group(0))
        wide = int(length * share)
        return char * wide + match.group(1) * (length - wide)

    def swap(value: Any) -> Any:
        if isinstance(value, str):
            return PADDING_RUN.sub(run, value)
        if isinstance(value, list):
            return [swap(item) for item in value]
        if isinstance(value, dict):
            return {swap(key): swap(item) for key, item in value.items()}
        return value

    return swap(saturated_log())


def reproduction_a() -> dict[str, Any]:
    """Two thousand results of one identity, each with its own 600-character location message."""
    results = []
    for index in range(REPRODUCTION_A_RESULTS):
        result = make_result(line=index + 1, text="same finding")
        result["locations"][0]["message"] = {"text": numbered("m", index, OVER_MESSAGE)}
        results.append(result)
    return make_log(make_run(results, invocations=[RUN_CLOCK]))


def reproduction_b() -> dict[str, Any]:
    """One result carrying three hundred partialFingerprints names of 4,096 characters."""
    names = {numbered("p", index, LONG_NAME_CHARS): "v" for index in range(REPRODUCTION_B_NAMES)}
    return make_log(make_run([make_result(partialFingerprints=names)], invocations=[RUN_CLOCK]))


# *--- Fixture Invariants ---*


class SarifFixtureInvariantTests(unittest.TestCase):
    """Properties every SARIF fixture holds regardless of its producer."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.results = {name: ingest_fixture(name) for name in FIXTURE_IDS}

    def test_every_fixture_is_attributed_to_the_sarif_adapter(self) -> None:
        for name, result in self.results.items():
            with self.subTest(fixture=name):
                self.assertEqual(attribution(result), SARIF_ATTRIBUTION)
                self.assertTrue(result.successful)
                self.assertEqual(result.errors, ())

    def test_every_fixture_yields_its_pinned_observation_ids_in_order(self) -> None:
        for name, expected in FIXTURE_IDS.items():
            with self.subTest(fixture=name):
                observed = tuple(item.observation_id for item in self.results[name].observations)
                self.assertEqual(observed, expected)

    def test_no_fixture_produces_a_duplicate_observation_identity(self) -> None:
        for name, result in self.results.items():
            with self.subTest(fixture=name):
                self.assertNotIn("duplicate_observation_identity", diagnostic_codes(result))
                ids = [item.observation_id for item in result.observations]
                self.assertEqual(len(ids), len(set(ids)))

    def test_every_observation_id_is_derived_from_its_fingerprint(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    self.assertEqual(observation.observation_id, observation.derived_observation_id)
                    self.assertEqual(observation.source_type, SARIF_SOURCE_TYPE)
                    self.assertEqual(observation.parser_name, "complyroll.sarif")
                    self.assertEqual(observation.parser_version, SARIF_PARSER_VERSION)

    def test_every_metadata_key_belongs_to_the_fixed_vocabulary(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    keys = [key for key, _value in observation.source_metadata]
                    self.assertEqual(keys, sorted(keys))
                    self.assertTrue(set(keys) <= METADATA_KEYS, set(keys) - METADATA_KEYS)

    def test_every_observation_round_trips_through_canonical_json_under_the_cap(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    encoded = observation.to_canonical_json()
                    self.assertLessEqual(len(encoded.encode("utf-8")), MAX_OBSERVATION_JSON_BYTES)
                    self.assertEqual(
                        Observation.from_canonical_dict(json.loads(encoded)), observation
                    )

    def test_every_diagnostic_is_located_at_the_artifact_name(self) -> None:
        for name, result in self.results.items():
            for diagnostic in result.diagnostics:
                with self.subTest(fixture=name, code=diagnostic.code):
                    self.assertEqual(diagnostic.location, name)


# *--- Fixture Mapping ---*


class TrivyImageTests(unittest.TestCase):
    """trivy-image.sarif: image resources, security-severity bands, folds, no clock."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture("trivy-image.sarif")
        cls.observations = cls.result.observations

    def test_five_results_fold_into_three_image_observations(self) -> None:
        self.assertEqual(len(self.observations), 3)
        self.assertEqual(
            [
                (item.source_record_id, item.resource.resource_type, item.resource.resource_id)
                for item in self.observations
            ],
            [
                ("CVE-2024-0001", "image", "ghcr.io/example/app:1.4.2/app/requirements.txt"),
                (
                    "CVE-2024-0001",
                    "image",
                    "ghcr.io/example/app:1.4.2/usr/lib/python3.12/site-packages/"
                    "requests-2.31.0.dist-info/METADATA",
                ),
                ("CVE-2024-0002", "image", "ghcr.io/example/app:1.4.2/library/alpine"),
            ],
        )
        self.assertEqual(
            [metadata(item)["occurrence_count"] for item in self.observations], ["2", "1", "2"]
        )

    def test_context_key_and_tool_are_the_driver_name(self) -> None:
        for item in self.observations:
            self.assertEqual(item.context_key, "Trivy")
            self.assertEqual(item.source_tool, "Trivy")

    def test_security_severity_outranks_the_result_level(self) -> None:
        self.assertEqual(
            [item.source_severity for item in self.observations],
            [SourceSeverity.CRITICAL, SourceSeverity.CRITICAL, SourceSeverity.MEDIUM],
        )
        for item, score, level in zip(
            self.observations, ["9.8", "9.8", "5.5"], ["error", "error", "warning"], strict=True
        ):
            fields = metadata(item)
            self.assertEqual(fields["severity_source"], "security-severity")
            self.assertEqual(fields["security_severity"], score)
            self.assertEqual(fields["level"], level)
            self.assertEqual(fields["level_source"], "result")

    def test_every_observation_is_open_with_an_unknown_clock(self) -> None:
        for item in self.observations:
            self.assertIs(item.disposition, ObservationDisposition.OPEN)
            self.assertIsNone(item.observed_at)
        missing = only_diagnostic(self.result, "source_timestamp_missing")
        self.assertIs(missing.level, DiagnosticLevel.WARNING)
        self.assertEqual(missing.message, MISSING_CLOCK_MESSAGE)

    def test_titles_and_identifiers_come_from_the_rule(self) -> None:
        self.assertEqual(
            [item.title for item in self.observations],
            [
                "requests: header leak on cross-origin redirect",
                "requests: header leak on cross-origin redirect",
                "musl: out-of-bounds read in wcsnrtombs",
            ],
        )
        self.assertEqual(
            [item.source_identifiers for item in self.observations],
            [("CVE-2024-0001",), ("CVE-2024-0001",), ("CVE-2024-0002",)],
        )
        self.assertTrue(self.observations[0].description.startswith("Package: requests\n"))
        self.assertIn(
            "Link: [CVE-2024-0001](https://avd.aquasec.com/nvd/cve-2024-0001)",
            self.observations[0].description,
        )

    def test_metadata_keys_present_on_the_first_observation(self) -> None:
        self.assertEqual(
            sorted(metadata(self.observations[0])),
            [
                "image_digests",
                "image_name",
                "level",
                "level_source",
                "location_messages",
                "location_uri",
                "occurrence_count",
                "regions",
                "rule_component",
                "rule_help_uri",
                "rule_name",
                "rule_tags",
                "run_indexes",
                "security_severity",
                "severity_source",
                "tool_information_uri",
                "tool_version",
                "uri_base",
                "uri_base_id",
            ],
        )

    def test_image_and_tool_evidence_is_recorded_verbatim(self) -> None:
        fields = metadata(self.observations[0])
        self.assertEqual(fields["image_name"], "ghcr.io/example/app:1.4.2")
        self.assertEqual(
            fields["image_digests"],
            '["ghcr.io/example/app@sha256:'
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]',
        )
        self.assertEqual(fields["tool_version"], "0.55.2")
        self.assertEqual(fields["tool_information_uri"], "https://github.com/aquasecurity/trivy")
        self.assertEqual(fields["rule_component"], "Trivy")
        self.assertEqual(fields["rule_name"], "LanguageSpecificPackageVulnerability")
        self.assertEqual(fields["rule_help_uri"], "https://avd.aquasec.com/nvd/cve-2024-0001")
        self.assertEqual(fields["rule_tags"], '["CRITICAL","security","vulnerability"]')
        self.assertEqual(fields["uri_base"], "file:///")
        self.assertEqual(fields["uri_base_id"], "ROOTPATH")
        self.assertEqual(fields["run_indexes"], "[0]")
        self.assertEqual(fields["regions"], '["1:1-1:1"]')
        self.assertEqual(metadata(self.observations[2])["rule_name"], "OsPackageVulnerability")
        self.assertEqual(
            metadata(self.observations[2])["rule_tags"], '["MEDIUM","security","vulnerability"]'
        )

    def test_folded_results_keep_every_location_message(self) -> None:
        self.assertEqual(
            metadata(self.observations[0])["location_messages"],
            '["1:1-1:1: app/requirements.txt: requests@2.31.0",'
            '"1:1-1:1: app/requirements.txt: requests@2.31.0 (pinned by app/constraints.txt)"]',
        )
        collapsed = only_diagnostic(self.result, "results_collapsed")
        self.assertIs(collapsed.level, DiagnosticLevel.INFO)
        self.assertEqual(
            collapsed.message,
            "result folded into an observation that shares its identity "
            "(2 occurrences: runs[0].results[1], runs[0].results[4])",
        )

    def test_diagnostics_are_the_missing_clock_and_the_fold_in_order(self) -> None:
        self.assertEqual(
            [(item.level, item.code) for item in self.result.diagnostics],
            [
                (DiagnosticLevel.WARNING, "source_timestamp_missing"),
                (DiagnosticLevel.INFO, "results_collapsed"),
            ],
        )

    def test_tracking_ids_follow_the_record_and_context(self) -> None:
        self.assertEqual(
            [
                tracking_id_for(item.source_type, item.source_record_id, item.context_key)
                for item in self.observations
            ],
            ["case-10f5974d95a33fdf", "case-10f5974d95a33fdf", "case-889c19760e425785"],
        )


class GrypeImageTests(unittest.TestCase):
    """grype-image.sarif: message expansion, logical locations, invocation clock, no level."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture("grype-image.sarif")
        cls.observations = cls.result.observations

    def test_two_results_share_one_file_resource(self) -> None:
        self.assertEqual(
            [
                (item.source_record_id, item.resource.resource_type, item.resource.resource_id)
                for item in self.observations
            ],
            [
                ("CVE-2024-0003-openssl", "file", "lib/apk/db/installed"),
                ("CVE-2024-0004-zlib", "file", "lib/apk/db/installed"),
            ],
        )
        self.assertEqual(
            [metadata(item)["logical_locations"] for item in self.observations],
            ['["lib/apk/db/installed:openssl@3.1.4-r5"]', '["lib/apk/db/installed:zlib@1.3-r2"]'],
        )

    def test_message_arguments_expand_the_rule_message_string(self) -> None:
        self.assertEqual(
            [item.description for item in self.observations],
            [
                "A high vulnerability in openssl version 3.1.4-r5 allows a remote attacker to "
                "read process memory; fixed in 3.1.4-r6.",
                "A medium vulnerability in zlib version 1.3-r2 allows a remote attacker to "
                "read process memory; fixed in 1.3.1-r0.",
            ],
        )
        self.assertEqual(
            [item.title for item in self.observations],
            [
                "CVE-2024-0003 high vulnerability for openssl package",
                "CVE-2024-0004 medium vulnerability for zlib package",
            ],
        )

    def test_security_severity_bands_with_the_default_level_recorded(self) -> None:
        self.assertEqual(
            [item.source_severity for item in self.observations],
            [SourceSeverity.HIGH, SourceSeverity.MEDIUM],
        )
        for item, score in zip(self.observations, ["7.5", "5.3"], strict=True):
            fields = metadata(item)
            self.assertEqual(fields["security_severity"], score)
            self.assertEqual(fields["severity_source"], "security-severity")
            self.assertEqual(fields["level"], "warning")
            self.assertEqual(fields["level_source"], "default")
            self.assertIs(item.disposition, ObservationDisposition.OPEN)

    def test_observed_at_is_the_invocation_start_not_its_end(self) -> None:
        for item in self.observations:
            self.assertEqual(item.observed_at, datetime(2026, 9, 2, 10, 15, tzinfo=UTC))
        self.assertEqual(self.result.diagnostics, ())

    def test_identifiers_and_metadata_keys(self) -> None:
        self.assertEqual(
            [item.source_identifiers for item in self.observations],
            [("CVE-2024-0003",), ("CVE-2024-0004",)],
        )
        self.assertEqual(
            sorted(metadata(self.observations[0])),
            [
                "level",
                "level_source",
                "location_uri",
                "logical_locations",
                "occurrence_count",
                "regions",
                "rule_component",
                "rule_help_uri",
                "rule_name",
                "run_indexes",
                "security_severity",
                "severity_source",
                "tool_information_uri",
                "tool_version",
            ],
        )
        fields = metadata(self.observations[0])
        self.assertEqual(fields["rule_name"], "ApkMatcherExactDirectMatch")
        self.assertEqual(fields["rule_help_uri"], "https://nvd.nist.gov/vuln/detail/CVE-2024-0003")
        self.assertEqual(fields["tool_version"], "0.79.6")
        self.assertEqual(fields["tool_information_uri"], "https://github.com/anchore/grype")
        self.assertEqual(fields["regions"], '["1:1-1:1"]')

    def test_tracking_ids_follow_the_record_and_context(self) -> None:
        self.assertEqual(
            [
                tracking_id_for(item.source_type, item.source_record_id, item.context_key)
                for item in self.observations
            ],
            ["case-373c419fd390c5f4", "case-86dce38f0d8fb5b1"],
        )


class SemgrepCodeTests(unittest.TestCase):
    """semgrep-code.sarif: rule-default levels, placeholder fingerprints, inSource suppression."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture("semgrep-code.sarif")
        cls.observations = cls.result.observations

    def test_three_results_fold_into_two_file_observations(self) -> None:
        self.assertEqual(
            [
                (item.source_record_id, item.resource.resource_type, item.resource.resource_id)
                for item in self.observations
            ],
            [
                (
                    "python.lang.security.audit.exec-detected.exec-detected",
                    "file",
                    "src/app/runner.py",
                ),
                (
                    "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                    "file",
                    "src/app/tasks.py",
                ),
            ],
        )
        self.assertEqual(metadata(self.observations[0])["occurrence_count"], "2")
        self.assertEqual(metadata(self.observations[0])["regions"], '["12:5-12:20","40:5-40:24"]')
        self.assertEqual(metadata(self.observations[1])["regions"], '["27:5-27:58"]')

    def test_rule_default_level_sets_the_severity(self) -> None:
        for item in self.observations:
            fields = metadata(item)
            self.assertIs(item.source_severity, SourceSeverity.MEDIUM)
            self.assertIs(item.disposition, ObservationDisposition.OPEN)
            self.assertEqual(fields["level"], "warning")
            self.assertEqual(fields["level_source"], "rule_default")
            self.assertEqual(fields["severity_source"], "level")
            self.assertNotIn("security_severity", fields)
            self.assertIsNone(item.observed_at)

    def test_titles_descriptions_and_identifiers(self) -> None:
        self.assertEqual(
            [item.title for item in self.observations],
            [
                "Semgrep Finding: python.lang.security.audit.exec-detected.exec-detected",
                "Semgrep Finding: python.lang.security.audit.subprocess-shell-true."
                "subprocess-shell-true",
            ],
        )
        self.assertTrue(self.observations[0].description.startswith("Detected the use of exec()."))
        self.assertTrue(self.observations[1].description.startswith("Found 'subprocess' function"))
        self.assertEqual(
            [item.source_identifiers for item in self.observations], [("CWE-95",), ("CWE-78",)]
        )

    def test_placeholder_fingerprints_and_srcroot_base_leave_no_keys(self) -> None:
        fields = metadata(self.observations[0])
        self.assertNotIn("fingerprints", fields)
        self.assertNotIn("uri_base", fields)
        self.assertEqual(fields["uri_base_id"], "%SRCROOT%")
        self.assertEqual(fields["tool_semantic_version"], "1.90.0")
        self.assertNotIn("tool_version", fields)
        self.assertEqual(
            sorted(fields),
            [
                "level",
                "level_source",
                "location_uri",
                "occurrence_count",
                "regions",
                "rule_component",
                "rule_help_uri",
                "rule_name",
                "rule_tags",
                "run_indexes",
                "severity_source",
                "tool_semantic_version",
                "uri_base_id",
            ],
        )

    def test_in_source_suppression_is_accepted_and_leaves_the_disposition_open(self) -> None:
        fields = metadata(self.observations[1])
        self.assertEqual(fields["suppressed"], "true")
        self.assertEqual(fields["suppression_kinds"], '["inSource"]')
        self.assertNotIn("suppression_statuses", fields)
        self.assertNotIn("suppressed", metadata(self.observations[0]))
        suppressed = only_diagnostic(self.result, "results_suppressed")
        self.assertIs(suppressed.level, DiagnosticLevel.WARNING)
        self.assertEqual(
            suppressed.message,
            "result carries an accepted suppression; its disposition is unchanged "
            "(1 occurrence: runs[0].results[2])",
        )

    def test_diagnostics_in_order(self) -> None:
        self.assertEqual(
            [(item.level, item.code) for item in self.result.diagnostics],
            [
                (DiagnosticLevel.WARNING, "source_timestamp_missing"),
                (DiagnosticLevel.WARNING, "results_suppressed"),
                (DiagnosticLevel.INFO, "results_collapsed"),
            ],
        )
        self.assertEqual(
            only_diagnostic(self.result, "results_collapsed").message,
            "result folded into an observation that shares its identity "
            "(1 occurrence: runs[0].results[1])",
        )

    def test_tracking_ids_follow_the_record_and_context(self) -> None:
        self.assertEqual(
            [
                tracking_id_for(item.source_type, item.source_record_id, item.context_key)
                for item in self.observations
            ],
            ["case-5cfbebe8d4b91c27", "case-0e3754ea1c369285"],
        )


class CodeqlRepoTests(unittest.TestCase):
    """codeql-repo.sarif: extension rules, automation category, repository-prefixed files."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture("codeql-repo.sarif")
        cls.observations = cls.result.observations

    def test_files_are_prefixed_with_the_repository_uri(self) -> None:
        self.assertEqual(
            [
                (item.source_record_id, item.resource.resource_type, item.resource.resource_id)
                for item in self.observations
            ],
            [
                (
                    "js/unused-local-variable",
                    "file",
                    "https://github.com/example/webapp/src/ui/helpers.js",
                ),
                (
                    "js/xss-through-dom",
                    "file",
                    "https://github.com/example/webapp/src/ui/legacy.js",
                ),
                (
                    "js/xss-through-dom",
                    "file",
                    "https://github.com/example/webapp/src/ui/render.js",
                ),
            ],
        )
        for item in self.observations:
            fields = metadata(item)
            self.assertEqual(fields["repository_uri"], "https://github.com/example/webapp")
            self.assertEqual(fields["revision_id"], "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567")

    def test_automation_category_joins_the_context_key(self) -> None:
        for item in self.observations:
            self.assertEqual(item.context_key, "CodeQL|nightly/lint")
            self.assertEqual(item.source_tool, "CodeQL")
            fields = metadata(item)
            self.assertEqual(fields["automation_id"], "nightly/lint/2026-09-01")
            self.assertEqual(fields["automation_category"], "nightly/lint")

    def test_extension_rules_supply_titles_tags_and_identifiers(self) -> None:
        self.assertEqual(
            [item.title for item in self.observations],
            [
                "Unused variable, import, function or class",
                "DOM text reinterpreted as HTML",
                "DOM text reinterpreted as HTML",
            ],
        )
        self.assertEqual(
            [item.source_identifiers for item in self.observations],
            [(), ("CWE-116", "CWE-79"), ("CWE-116", "CWE-79")],
        )
        for item in self.observations:
            self.assertEqual(metadata(item)["rule_component"], "codeql/javascript-queries")
            self.assertEqual(metadata(item)["tool_semantic_version"], "2.19.3")
        self.assertEqual(metadata(self.observations[0])["rule_tags"], '["maintainability"]')
        self.assertEqual(
            metadata(self.observations[1])["rule_tags"],
            '["external/cwe/cwe-079","external/cwe/cwe-116","security"]',
        )

    def test_open_kind_result_is_unknown_with_a_forced_none_level(self) -> None:
        legacy = self.observations[1]
        fields = metadata(legacy)
        self.assertIs(legacy.disposition, ObservationDisposition.UNKNOWN)
        self.assertIs(legacy.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(fields["level"], "none")
        self.assertEqual(fields["level_source"], "forced_none")
        self.assertEqual(fields["result_kind"], "open")
        self.assertEqual(fields["result_kinds"], '["open"]')
        self.assertEqual(fields["security_severity"], "6.1")
        self.assertEqual(fields["severity_source"], "security-severity")
        self.assertEqual(
            legacy.description,
            "Data flow into innerHTML could not be resolved; manual review required.",
        )
        self.assertEqual(fields["regions"], '["120:5-120:42"]')

    def test_fail_results_use_rule_default_levels(self) -> None:
        helpers, render = self.observations[0], self.observations[2]
        self.assertIs(helpers.disposition, ObservationDisposition.OPEN)
        self.assertIs(helpers.source_severity, SourceSeverity.LOW)
        self.assertEqual(metadata(helpers)["level"], "note")
        self.assertEqual(metadata(helpers)["level_source"], "rule_default")
        self.assertEqual(metadata(helpers)["severity_source"], "level")
        self.assertIs(render.disposition, ObservationDisposition.OPEN)
        self.assertIs(render.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(metadata(render)["level"], "warning")
        self.assertEqual(metadata(render)["level_source"], "rule_default")
        self.assertEqual(metadata(render)["security_severity"], "6.1")
        self.assertEqual(
            render.description,
            "DOM text is reinterpreted as HTML without escaping meta-characters.",
        )
        self.assertEqual(helpers.description, "Unused variable legacyCache.")

    def test_fractional_invocation_clock_is_truncated_to_microseconds(self) -> None:
        for item in self.observations:
            self.assertEqual(item.observed_at, datetime(2026, 9, 1, 2, 0, 0, 123456, tzinfo=UTC))

    def test_artifact_index_location_carries_no_uri_base_keys(self) -> None:
        render = metadata(self.observations[2])
        self.assertNotIn("uri_base", render)
        self.assertNotIn("uri_base_id", render)
        self.assertEqual(render["location_uri"], "src/ui/render.js")
        helpers = metadata(self.observations[0])
        self.assertEqual(helpers["uri_base"], "file:///home/runner/work/webapp/webapp/")
        self.assertEqual(helpers["uri_base_id"], "%SRCROOT%")

    def test_partial_fingerprints_and_baseline_state_are_sorted_metadata(self) -> None:
        self.assertEqual(
            metadata(self.observations[0])["partial_fingerprints"],
            '[["primaryLocationLineHash","a04c2f8e11d7b6c3:1"],'
            '["primaryLocationStartColumnFingerprint","2"]]',
        )
        self.assertEqual(
            metadata(self.observations[2])["partial_fingerprints"],
            '[["primaryLocationLineHash","5d1a2e7c9b3f0a41:1"],'
            '["primaryLocationStartColumnFingerprint","13"]]',
        )
        self.assertEqual(
            [metadata(item)["baseline_state"] for item in self.observations],
            ["unchanged", "unchanged", "new"],
        )
        ignored = only_diagnostic(self.result, "baseline_state_ignored")
        self.assertIs(ignored.level, DiagnosticLevel.INFO)
        self.assertEqual(
            ignored.message,
            "baselineState is recorded as metadata and never changes a disposition "
            "(3 occurrences: runs[0].results[0], runs[0].results[1], runs[0].results[2])",
        )
        self.assertEqual(diagnostic_codes(self.result), ["baseline_state_ignored"])

    def test_metadata_keys_present_on_the_open_kind_observation(self) -> None:
        self.assertEqual(
            sorted(metadata(self.observations[1])),
            [
                "automation_category",
                "automation_id",
                "baseline_state",
                "level",
                "level_source",
                "location_uri",
                "occurrence_count",
                "partial_fingerprints",
                "regions",
                "repository_uri",
                "result_kind",
                "result_kinds",
                "revision_id",
                "rule_component",
                "rule_name",
                "rule_tags",
                "run_indexes",
                "security_severity",
                "severity_source",
                "tool_semantic_version",
                "uri_base",
                "uri_base_id",
            ],
        )

    def test_tracking_ids_follow_the_record_and_context(self) -> None:
        self.assertEqual(
            [
                tracking_id_for(item.source_type, item.source_record_id, item.context_key)
                for item in self.observations
            ],
            ["case-04716522daa6f550", "case-d2b9f5abf1fe44ac", "case-d2b9f5abf1fe44ac"],
        )


class CheckovIacTests(unittest.TestCase):
    """checkov-iac.sarif: line-only regions, a rule with no properties, one CVE rule."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture("checkov-iac.sarif")
        cls.observations = cls.result.observations

    def test_three_file_observations_with_line_only_regions(self) -> None:
        self.assertEqual(
            [
                (item.source_record_id, item.resource.resource_type, item.resource.resource_id)
                for item in self.observations
            ],
            [
                ("CKV_AWS_18", "file", "terraform/logs.tf"),
                ("CKV_AWS_18", "file", "terraform/s3.tf"),
                ("CKV_CVE_2024_0005@requests", "file", "app/requirements.txt"),
            ],
        )
        self.assertEqual(
            [metadata(item)["regions"] for item in self.observations],
            ['["1-9"]', '["3-12"]', '["4-4"]'],
        )

    def test_error_level_and_security_severity_both_land_on_high(self) -> None:
        for item in self.observations:
            self.assertIs(item.source_severity, SourceSeverity.HIGH)
            self.assertIs(item.disposition, ObservationDisposition.OPEN)
            self.assertIsNone(item.observed_at)
            self.assertEqual(metadata(item)["level"], "error")
            self.assertEqual(metadata(item)["level_source"], "result")
        self.assertEqual(
            [metadata(item)["severity_source"] for item in self.observations],
            ["level", "level", "security-severity"],
        )
        self.assertEqual(metadata(self.observations[2])["security_severity"], "8.6")
        self.assertNotIn("security_severity", metadata(self.observations[0]))

    def test_titles_identifiers_and_tags(self) -> None:
        self.assertEqual(
            [item.title for item in self.observations],
            [
                "Ensure the S3 bucket has access logging enabled",
                "Ensure the S3 bucket has access logging enabled",
                "requests 2.31.0 is affected by CVE-2024-0005",
            ],
        )
        self.assertEqual(
            [item.description for item in self.observations],
            [item.title for item in self.observations],
        )
        self.assertEqual(
            [item.source_identifiers for item in self.observations],
            [(), (), ("CVE-2024-0005",)],
        )
        self.assertNotIn("rule_tags", metadata(self.observations[0]))
        self.assertEqual(metadata(self.observations[2])["rule_tags"], '["CVE-2024-0005"]')

    def test_metadata_keys_present_on_the_first_observation(self) -> None:
        fields = metadata(self.observations[0])
        self.assertEqual(
            sorted(fields),
            [
                "level",
                "level_source",
                "location_uri",
                "occurrence_count",
                "regions",
                "rule_component",
                "rule_name",
                "run_indexes",
                "severity_source",
                "tool_information_uri",
                "tool_version",
            ],
        )
        self.assertEqual(fields["tool_version"], "3.2.255")
        self.assertEqual(fields["tool_information_uri"], "https://checkov.io")
        self.assertEqual(fields["rule_component"], "Checkov")

    def test_only_diagnostic_is_the_missing_clock(self) -> None:
        self.assertEqual(
            [(item.level, item.code, item.message) for item in self.result.diagnostics],
            [(DiagnosticLevel.WARNING, "source_timestamp_missing", MISSING_CLOCK_MESSAGE)],
        )

    def test_tracking_ids_follow_the_record_and_context(self) -> None:
        self.assertEqual(
            [
                tracking_id_for(item.source_type, item.source_record_id, item.context_key)
                for item in self.observations
            ],
            ["case-5afc337356bc0d2c", "case-5afc337356bc0d2c", "case-d5b30e5f94a42787"],
        )


# *--- Specification Corners ---*


class SarifSpecCornerTests(unittest.TestCase):
    """sarif-spec-corners.sarif, corner by corner, across all three runs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture("sarif-spec-corners.sarif")
        cls.by_record = {}
        for item in cls.result.observations:
            cls.by_record.setdefault(item.source_record_id, []).append(item)

    def corner(self, record: str) -> Observation:
        items = self.by_record[record]
        self.assertEqual(len(items), 1, record)
        return items[0]

    def test_twenty_eight_observations_with_pinned_ids(self) -> None:
        self.assertEqual(
            tuple(item.observation_id for item in self.result.observations), CORNER_IDS
        )
        self.assertEqual(len(self.result.observations), 28)
        self.assertTrue(self.result.successful)

    def test_nine_diagnostics_in_order_all_warnings(self) -> None:
        self.assertEqual(
            [(item.level, item.code) for item in self.result.diagnostics],
            [
                (DiagnosticLevel.WARNING, "source_timestamp_missing"),
                (DiagnosticLevel.WARNING, "invalid_result_kind"),
                (DiagnosticLevel.WARNING, "security_severity_invalid"),
                (DiagnosticLevel.WARNING, "uri_suspicious"),
                (DiagnosticLevel.WARNING, "resource_identity_fallback"),
                (DiagnosticLevel.WARNING, "rule_reference_conflict"),
                (DiagnosticLevel.WARNING, "evidence_sanitized"),
                (DiagnosticLevel.WARNING, "execution_unsuccessful"),
                (DiagnosticLevel.WARNING, "results_unknown"),
            ],
        )

    def test_hierarchical_rule_id_resolves_its_descriptor_prefix(self) -> None:
        item = self.corner("CA5350/md5")
        self.assertEqual(item.title, "Do not use weak cryptographic algorithms")
        self.assertEqual(item.resource.resource_id, "src/rules/hierarchical.py")
        self.assertEqual(metadata(item)["rule_component"], "SpecCorners")
        # The run's one conflict is CORNER-X at results[20]; CA5350/md5 at results[21] adds none.
        self.assertEqual(
            only_diagnostic(self.result, "rule_reference_conflict").message,
            "the rule id string and the resolved descriptor id disagree; the string wins "
            "(1 occurrence: runs[0].results[20]; first: 'CORNER-X' against descriptor 'CORNER-Y')",
        )

    def test_bidi_controls_and_zero_width_spaces_are_stripped_from_evidence(self) -> None:
        item = self.corner("CORNER-BIDI")
        self.assertEqual(item.description, "evidence with a bidi control  and a zero-width space")
        self.assertEqual(
            metadata(item)["location_messages"], '["1: location message with  zero-width space"]'
        )
        sanitized = only_diagnostic(self.result, "evidence_sanitized")
        self.assertEqual(
            sanitized.message,
            "control, format, or separator characters were removed from evidence text "
            "(2 occurrences: runs[0].results[26], runs[0].results[26].locations[0])",
        )

    def test_parent_segment_and_double_slash_uris_are_kept_verbatim(self) -> None:
        self.assertEqual(self.corner("CORNER-DOTDOT").resource.resource_id, "src/../etc/passwd")
        self.assertEqual(
            self.corner("CORNER-SLASHES").resource.resource_id, "//fileserver/share/config.ini"
        )
        suspicious = only_diagnostic(self.result, "uri_suspicious")
        self.assertEqual(
            suspicious.message,
            "location uri has a '..' segment or a '//' prefix; kept verbatim, never opened "
            "(2 occurrences: runs[0].results[13].locations[0].physicalLocation."
            "artifactLocation.uri, runs[0].results[14].locations[0].physicalLocation."
            "artifactLocation.uri)",
        )

    def test_empty_uri_and_no_location_fall_back_to_the_scan_resource(self) -> None:
        for record in ("CORNER-EMPTY-URI", "CORNER-NOLOC"):
            item = self.corner(record)
            self.assertEqual(item.resource.resource_type, "scan")
            self.assertEqual(item.resource.resource_id, "SpecCorners")
            self.assertNotIn("location_uri", metadata(item))
            self.assertNotIn("regions", metadata(item))
        fallback = only_diagnostic(self.result, "resource_identity_fallback")
        self.assertEqual(
            fallback.message,
            "result has no usable location; the driver name is the scan resource "
            "(2 occurrences: runs[0].results[15], runs[0].results[17])",
        )

    def test_third_run_with_only_an_end_time_supplies_that_clock(self) -> None:
        item = self.corner("CORNER-END-ONLY")
        self.assertEqual(item.observed_at, datetime(2026, 9, 3, 12, 0, tzinfo=UTC))
        self.assertEqual(metadata(item)["run_indexes"], "[2]")
        others = [
            metadata(other)["run_indexes"]
            for other in self.result.observations
            if other is not item
        ]
        self.assertEqual(set(others), {"[0]"})

    def test_extension_descriptor_wins_at_the_shadowed_index(self) -> None:
        item = self.corner("CORNER-EXT-WINS")
        self.assertEqual(item.title, "Extension descriptor at the shadowed index")
        self.assertEqual(metadata(item)["rule_component"], "corner-extension")

    def test_first_detection_beats_a_later_last_detection(self) -> None:
        item = self.corner("CORNER-FIRST-LAST")
        self.assertEqual(item.observed_at, datetime(2026, 9, 1, 8, 30, tzinfo=UTC))

    def test_last_detection_only_keeps_its_offset(self) -> None:
        item = self.corner("CORNER-LAST-ONLY")
        self.assertEqual(
            item.observed_at, datetime(2026, 9, 4, 8, 30, tzinfo=timezone(timedelta(hours=2)))
        )
        self.assertEqual(offset_hours(item), 2)

    def test_global_message_string_falls_back_from_the_extension(self) -> None:
        item = self.corner("CORNER-GLOBAL")
        self.assertEqual(item.description, "Global text for CORNER-GLOBAL from the extension.")
        self.assertEqual(metadata(item)["rule_component"], "corner-extension")
        self.assertEqual(metadata(item)["regions"], '["6"]')

    def test_component_referenced_by_guid_resolves(self) -> None:
        item = self.corner("CORNER-GUID")
        self.assertEqual(item.title, "Component referenced by guid")
        self.assertEqual(metadata(item)["rule_component"], "corner-extension")

    def test_every_result_kind_maps_to_its_disposition(self) -> None:
        kinds = {item.resource.resource_id: item for item in self.by_record["CORNER-KINDS"]}
        self.assertEqual(len(kinds), 7)
        expected = {
            "src/kinds/bogus.py": ("bogus", ObservationDisposition.UNKNOWN),
            "src/kinds/fail.py": ("fail", ObservationDisposition.OPEN),
            "src/kinds/informational.py": ("informational", ObservationDisposition.NOT_REVIEWED),
            "src/kinds/not_applicable.py": ("notApplicable", ObservationDisposition.NOT_APPLICABLE),
            "src/kinds/open.py": ("open", ObservationDisposition.UNKNOWN),
            "src/kinds/pass.py": ("pass", ObservationDisposition.PASS),
            "src/kinds/review.py": ("review", ObservationDisposition.NOT_REVIEWED),
        }
        for resource, (kind, disposition) in expected.items():
            with self.subTest(kind=kind):
                item = kinds[resource]
                fields = metadata(item)
                self.assertIs(item.disposition, disposition)
                self.assertEqual(fields["result_kind"], kind)
                self.assertEqual(fields["result_kinds"], json.dumps([kind]))
                self.assertEqual(item.title, "Every result kind")
                self.assertEqual(
                    tracking_id_for(item.source_type, item.source_record_id, item.context_key),
                    "case-c95fdfd862085153",
                )
                if kind == "fail":
                    self.assertIs(item.source_severity, SourceSeverity.MEDIUM)
                    self.assertEqual(fields["level"], "warning")
                    self.assertEqual(fields["level_source"], "rule_default")
                else:
                    self.assertIs(item.source_severity, SourceSeverity.INFORMATIONAL)
                    self.assertEqual(fields["level"], "none")
                    self.assertEqual(fields["level_source"], "forced_none")
        invalid = only_diagnostic(self.result, "invalid_result_kind")
        self.assertEqual(
            invalid.message,
            "result kind is outside the six SARIF values; the disposition is unknown "
            "(1 occurrence: runs[0].results[6]; first: 'bogus')",
        )

    def test_location_link_in_a_message_is_flattened_to_its_text(self) -> None:
        self.assertEqual(self.corner("CORNER-LINK").description, "Taint reaches the sink here.")

    def test_logical_location_only_is_a_logical_resource(self) -> None:
        item = self.corner("CORNER-LOGICAL")
        self.assertEqual(item.resource.resource_type, "logical")
        self.assertEqual(item.resource.resource_id, "com.example.ui.Renderer.render")
        self.assertEqual(metadata(item)["logical_locations"], '["com.example.ui.Renderer.render"]')
        self.assertNotIn("location_uri", metadata(item))

    def test_message_placeholders_expand_once_and_keep_braces(self) -> None:
        item = self.corner("CORNER-MSG")
        self.assertEqual(
            item.description,
            "Found needle inside {braces} at line 3; {2} stays literal and {needle} is braced.",
        )
        self.assertIs(item.source_severity, SourceSeverity.LOW)
        self.assertEqual(metadata(item)["level"], "note")

    def test_invocation_override_promotes_the_level(self) -> None:
        item = self.corner("CORNER-OVERRIDE")
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(metadata(item)["level"], "error")
        self.assertEqual(metadata(item)["level_source"], "invocation_override")

    def test_unusable_security_severity_falls_through_to_the_level(self) -> None:
        item = self.corner("CORNER-SEV-ABC")
        self.assertIs(item.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(metadata(item)["security_severity"], "abc")
        self.assertEqual(metadata(item)["severity_source"], "level")
        invalid = only_diagnostic(self.result, "security_severity_invalid")
        self.assertEqual(
            invalid.message,
            "security-severity is not a finite number above 0 and at most 10; ignored "
            "(1 occurrence: runs[0].results[7]; first: 'abc')",
        )

    def test_result_level_security_severity_overrides_the_rule(self) -> None:
        item = self.corner("CORNER-SEV-OVERRIDE")
        self.assertIs(item.source_severity, SourceSeverity.CRITICAL)
        self.assertEqual(metadata(item)["security_severity"], "9.5")
        self.assertEqual(metadata(item)["severity_source"], "security-severity")

    def test_zero_security_severity_is_unset_and_the_level_decides(self) -> None:
        item = self.corner("CORNER-ZERO-SEV")
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(metadata(item)["security_severity"], "0.0")
        self.assertEqual(metadata(item)["severity_source"], "level")
        self.assertEqual(metadata(item)["level"], "error")

    def test_rejected_suppression_is_recorded_and_not_diagnosed(self) -> None:
        item = self.corner("CORNER-SUPPRESS")
        fields = metadata(item)
        self.assertIs(item.disposition, ObservationDisposition.OPEN)
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(fields["suppressed"], "false")
        self.assertEqual(fields["suppression_kinds"], '["external"]')
        self.assertEqual(fields["suppression_statuses"], '["rejected"]')
        self.assertNotIn("results_suppressed", diagnostic_codes(self.result))

    def test_rule_id_string_wins_over_a_descriptor_that_is_not_its_prefix(self) -> None:
        item = self.corner("CORNER-X")
        self.assertEqual(item.source_record_id, "CORNER-X")
        self.assertEqual(item.title, "Descriptor that is not a prefix of the rule id")
        conflict = only_diagnostic(self.result, "rule_reference_conflict")
        self.assertEqual(
            conflict.message,
            "the rule id string and the resolved descriptor id disagree; the string wins "
            "(1 occurrence: runs[0].results[20]; first: 'CORNER-X' against descriptor "
            "'CORNER-Y')",
        )

    def test_second_run_with_null_results_and_a_failed_invocation_is_skipped(self) -> None:
        unsuccessful = only_diagnostic(self.result, "execution_unsuccessful")
        self.assertEqual(
            unsuccessful.message,
            "invocation reports executionSuccessful false; its results are still read "
            "(1 occurrence: runs[1].invocations[0])",
        )
        unknown = only_diagnostic(self.result, "results_unknown")
        self.assertEqual(
            unknown.message,
            "run declares no results array; its results are unknown and the run is skipped "
            "(1 occurrence: runs[1])",
        )
        self.assertNotIn("OtherScanner", {item.source_tool for item in self.result.observations})
        self.assertEqual({item.context_key for item in self.result.observations}, {"SpecCorners"})

    def test_missing_clock_is_diagnosed_once_for_the_whole_artifact(self) -> None:
        missing = only_diagnostic(self.result, "source_timestamp_missing")
        self.assertEqual(missing.message, MISSING_CLOCK_MESSAGE)
        self.assertEqual(missing.location, "sarif-spec-corners.sarif")


# *--- Rule Resolution ---*

LONE_DESCRIPTOR: dict[str, Any] = {
    "id": "R1",
    "shortDescription": {"text": "Lone descriptor"},
    "defaultConfiguration": {"level": "error"},
    "properties": {"security-severity": "9.1", "tags": ["security", "CWE-79"]},
}
RULE_GUID = "5d0c2b7e-0000-4000-8000-000000000001"
OTHER_RULE_GUID = "5d0c2b7e-0000-4000-8000-000000000002"
OVERRIDE_TO_ERROR: dict[str, Any] = {
    "ruleConfigurationOverrides": [
        {"descriptor": {"index": 0}, "configuration": {"level": "error"}}
    ]
}
THIRD_RULE_GUID = "5d0c2b7e-0000-4000-8000-000000000003"
EXTENSION_GUID = "5d0c2b7e-0000-4000-8000-0000000000e1"


def natural(value: object) -> int | None:
    """Return a non-negative JSON integer, else None, the way the adapter reads an index."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


# The linear scans the run cache replaced, kept as references the cached lookups must match.


def scanned_component(tool: dict[str, Any], reference: Any) -> Any:
    """Resolve a component by scanning: its index, else the first carrying the guid."""
    extensions = tool.get("extensions", [])
    tool_component = reference.get("toolComponent") if isinstance(reference, dict) else None
    if isinstance(tool_component, dict):
        index = natural(tool_component.get("index"))
        if index is not None:
            extension = extensions[index] if index < len(extensions) else None
            return extension if isinstance(extension, dict) else None
        guid = text_of(tool_component.get("guid"))
        if guid:
            for component in [tool["driver"], *extensions]:
                if isinstance(component, dict) and text_of(component.get("guid")) == guid:
                    return component
            return None
    return tool["driver"]


def scanned_rule(rules: list[Any], key: str, value: str) -> tuple[Any, int] | None:
    """Return the one descriptor whose member equals the value, by scanning every rule."""
    matches = [
        (rule, position)
        for position, rule in enumerate(rules)
        if isinstance(rule, dict) and text_of(rule.get(key)) == value
    ]
    return matches[0] if len(matches) == 1 else None


def scanned_string_id(result: dict[str, Any]) -> str:
    reference = result.get("rule")
    string_id = text_of(result.get("ruleId"))
    if not string_id and isinstance(reference, dict):
        string_id = text_of(reference.get("id"))
    return string_id


def scanned_descriptor(component: Any, result: dict[str, Any]) -> tuple[Any, int | None]:
    """Resolve a descriptor by scanning: an index, else a lone guid, else a lone id."""
    if component is None:
        return None, None
    reference = result.get("rule") if isinstance(result.get("rule"), dict) else None
    rules = component.get("rules", [])
    index = natural(reference.get("index")) if reference is not None else None
    if index is None:
        index = natural(result.get("ruleIndex"))
    if index is not None:
        descriptor = rules[index] if index < len(rules) else None
        return (descriptor if isinstance(descriptor, dict) else None), index
    guid = text_of(reference.get("guid")) if reference is not None else ""
    found = scanned_rule(rules, "guid", guid) if guid else None
    string_id = scanned_string_id(result)
    if found is None and string_id:
        found = scanned_rule(rules, "id", string_id)
    return found if found is not None else (None, None)


def scanned_override(tool: dict[str, Any], overrides: list[Any], result: dict[str, Any]) -> str:
    """Return the level the first override naming the result's descriptor sets, or empty text."""
    component = scanned_component(tool, result.get("rule"))
    descriptor, descriptor_index = scanned_descriptor(component, result)
    if descriptor is None:
        return ""
    for override in overrides:
        entry = override if isinstance(override, dict) else None
        target = entry.get("descriptor") if entry is not None else None
        if entry is None or not isinstance(target, dict):
            continue
        if scanned_component(tool, target) is not component:
            continue
        # The entry's reference resolves as a result's would, with no ruleIndex beside it.
        named, position = scanned_descriptor(component, {"rule": target})
        if named is None or position != descriptor_index:
            continue
        configuration = entry.get("configuration")
        level = text_of(configuration.get("level")) if isinstance(configuration, dict) else ""
        if level:
            return level
    return ""


def titled(rules: list[Any], prefix: str) -> list[Any]:
    """Title every descriptor by its position, so a title shows which one resolved."""
    return [
        dict(rule, shortDescription={"text": f"{prefix}{position}"})
        if isinstance(rule, dict)
        else rule
        for position, rule in enumerate(rules)
    ]


def override(level: Any, **descriptor: Any) -> dict[str, Any]:
    return {"descriptor": descriptor, "configuration": {"level": level}}


def level_of(observation: Observation) -> tuple[str, str]:
    fields = metadata(observation)
    return fields["level"], fields["level_source"]


class SarifRuleResolutionTests(unittest.TestCase):
    """Decision 4: rule.index, ruleIndex, rule.guid, then a unique id; identity is the string."""

    def test_rule_id_only_resolves_the_unique_descriptor_sharing_its_id(self) -> None:
        output = ingest_document(make_log(make_run([make_result()], rules=[LONE_DESCRIPTOR])))
        item = only_observation(output)
        fields = metadata(item)
        self.assertEqual(item.source_record_id, "R1")
        self.assertEqual(item.title, "Lone descriptor")
        self.assertEqual(fields["rule_tags"], '["CWE-79","security"]')
        self.assertEqual(fields["level"], "error")
        self.assertEqual(fields["level_source"], "rule_default")
        self.assertEqual(fields["security_severity"], "9.1")
        self.assertIs(item.source_severity, SourceSeverity.CRITICAL)
        self.assertEqual(item.source_identifiers, ("CWE-79",))

    def test_two_descriptors_sharing_the_id_resolve_none(self) -> None:
        rules = [dict(LONE_DESCRIPTOR), dict(LONE_DESCRIPTOR, shortDescription={"text": "Twin"})]
        output = ingest_document(make_log(make_run([make_result()], rules=rules)))
        item = only_observation(output)
        fields = metadata(item)
        self.assertEqual(item.source_record_id, "R1")
        self.assertEqual(item.title, "")
        self.assertNotIn("rule_tags", fields)
        self.assertNotIn("security_severity", fields)
        self.assertEqual(fields["level"], "warning")
        self.assertEqual(fields["level_source"], "default")
        self.assertIs(item.source_severity, SourceSeverity.MEDIUM)

    def test_rule_id_rule_index_and_rule_index_member_yield_the_same_identity(self) -> None:
        forms = [
            make_result(),
            make_result(rule_id=None, rule={"id": "R1"}),
            make_result(rule_id=None, ruleIndex=0),
            make_result(rule_id=None, rule={"index": 0}),
        ]
        # One shared artifact: the digest is an identity input, so the forms must be parsed
        # against the same provenance for their observation ids to be comparable.
        artifact = synthetic_artifact(make_log(make_run(forms, rules=[LONE_DESCRIPTOR])))
        outputs = [
            only_observation(
                parse_direct(make_log(make_run([form], rules=[LONE_DESCRIPTOR])), artifact)
            )
            for form in forms
        ]
        self.assertEqual({item.observation_id for item in outputs}, {outputs[0].observation_id})
        self.assertEqual({item.title for item in outputs}, {"Lone descriptor"})
        self.assertEqual({item.source_record_id for item in outputs}, {"R1"})

    def test_rule_index_member_beats_rule_index_property(self) -> None:
        rules = [
            {"id": "R1", "shortDescription": {"text": "By member"}},
            {"id": "R1", "shortDescription": {"text": "By property"}},
        ]
        output = ingest_document(
            make_log(make_run([make_result(rule={"index": 0}, ruleIndex=1)], rules=rules))
        )
        self.assertEqual(only_observation(output).title, "By member")

    def test_rule_index_out_of_range_resolves_no_descriptor(self) -> None:
        output = ingest_document(
            make_log(make_run([make_result(ruleIndex=7)], rules=[LONE_DESCRIPTOR]))
        )
        item = only_observation(output)
        self.assertEqual(item.title, "")
        self.assertEqual(item.source_record_id, "R1")

    def test_no_rule_reference_at_all_is_an_error_that_withholds_the_result(self) -> None:
        output = ingest_document(make_log(make_run([make_result(rule_id=None)])))
        self.assertEqual(output.observations, ())
        self.assertFalse(output.successful)
        missing = only_diagnostic(output, "rule_id_missing")
        self.assertIs(missing.level, DiagnosticLevel.ERROR)
        self.assertEqual(
            missing.message,
            "no ruleId, rule.id, rule.index, or ruleIndex resolves to a rule identifier "
            "(1 occurrence: runs[0].results[0])",
        )
        self.assertEqual(
            only_diagnostic(output, "no_observations").message, NO_OBSERVATIONS_MESSAGE
        )

    def test_descriptor_id_that_is_not_a_prefix_of_the_string_is_a_conflict(self) -> None:
        output = ingest_document(
            make_log(make_run([make_result(rule_id="R1X", ruleIndex=0)], rules=[LONE_DESCRIPTOR]))
        )
        item = only_observation(output)
        self.assertEqual(item.source_record_id, "R1X")
        self.assertEqual(
            only_diagnostic(output, "rule_reference_conflict").message,
            "the rule id string and the resolved descriptor id disagree; the string wins "
            "(1 occurrence: runs[0].results[0]; first: 'R1X' against descriptor 'R1')",
        )

    def test_hierarchical_string_under_the_descriptor_id_is_not_a_conflict(self) -> None:
        output = ingest_document(
            make_log(
                make_run([make_result(rule_id="R1/sub", ruleIndex=0)], rules=[LONE_DESCRIPTOR])
            )
        )
        item = only_observation(output)
        self.assertEqual(item.source_record_id, "R1/sub")
        self.assertEqual(item.title, "Lone descriptor")
        self.assertNotIn("rule_reference_conflict", diagnostic_codes(output))

    def test_rule_guid_resolves_the_descriptor_under_a_hierarchical_id_without_an_index(
        self,
    ) -> None:
        rules = [
            {
                "id": "CA5350",
                "guid": RULE_GUID,
                "shortDescription": {"text": "Weak cryptography"},
                "defaultConfiguration": {"level": "error"},
            }
        ]
        result = make_result(rule_id="CA5350/md5", rule={"guid": RULE_GUID})
        output = ingest_document(make_log(make_run([result], rules=rules)))
        item = only_observation(output)
        self.assertEqual(item.source_record_id, "CA5350/md5")
        self.assertEqual(item.title, "Weak cryptography")
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(metadata(item)["level_source"], "rule_default")
        self.assertNotIn("rule_reference_conflict", diagnostic_codes(output))

    def test_rule_guid_picks_one_of_two_descriptors_sharing_an_id(self) -> None:
        rules = [
            {
                "id": "CA1711",
                "guid": RULE_GUID,
                "shortDescription": {"text": "First twin"},
                "defaultConfiguration": {"level": "note"},
            },
            {
                "id": "CA1711",
                "guid": OTHER_RULE_GUID,
                "shortDescription": {"text": "Second twin"},
                "defaultConfiguration": {"level": "error"},
            },
        ]
        result = make_result(rule_id="CA1711", rule={"guid": OTHER_RULE_GUID})
        output = ingest_document(make_log(make_run([result], rules=rules)))
        item = only_observation(output)
        self.assertEqual(item.title, "Second twin")
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(metadata(item)["level"], "error")

    def test_rule_guid_no_descriptor_carries_falls_through_to_the_id_match(self) -> None:
        rules = [dict(LONE_DESCRIPTOR, guid=RULE_GUID)]
        result = make_result(rule={"guid": OTHER_RULE_GUID})
        output = ingest_document(make_log(make_run([result], rules=rules)))
        item = only_observation(output)
        self.assertEqual(item.title, "Lone descriptor")
        self.assertIs(item.source_severity, SourceSeverity.CRITICAL)

    def test_rule_guid_alone_supplies_the_identity_from_its_descriptor(self) -> None:
        rules = [dict(LONE_DESCRIPTOR, guid=RULE_GUID)]
        result = make_result(rule_id=None, rule={"guid": RULE_GUID})
        output = ingest_document(make_log(make_run([result], rules=rules)))
        item = only_observation(output)
        self.assertEqual(item.source_record_id, "R1")
        self.assertEqual(item.title, "Lone descriptor")
        self.assertNotIn("rule_id_missing", diagnostic_codes(output))

    def test_rule_guid_in_other_letter_case_names_nothing(self) -> None:
        # Guids compare as exact text (decision 4), so the upper-case spelling of a descriptor's
        # guid names no descriptor: alone it leaves no identity, and beside an id it falls
        # through to that id's own descriptor.
        rules = [
            dict(LONE_DESCRIPTOR, guid=RULE_GUID),
            {"id": "R2", "shortDescription": {"text": "Second descriptor"}},
        ]
        guid_only = make_result(rule_id=None, rule={"guid": RULE_GUID.upper()})
        output = ingest_document(make_log(make_run([guid_only], rules=rules)))
        self.assertEqual(output.observations, ())
        self.assertIn("rule_id_missing", diagnostic_codes(output))
        beside_id = make_result(rule_id="R2", rule={"guid": RULE_GUID.upper()})
        output = ingest_document(make_log(make_run([beside_id], rules=rules)))
        item = only_observation(output)
        self.assertEqual((item.source_record_id, item.title), ("R2", "Second descriptor"))
        self.assertNotIn("rule_reference_conflict", diagnostic_codes(output))

    def test_invocation_override_by_descriptor_id_sets_the_level(self) -> None:
        rules = [{"id": "R1", "defaultConfiguration": {"level": "note"}}]
        invocations = [
            {
                "ruleConfigurationOverrides": [
                    {"descriptor": {"id": "R1"}, "configuration": {"level": "error"}}
                ]
            }
        ]
        output = ingest_document(
            make_log(make_run([make_result(ruleIndex=0)], rules=rules, invocations=invocations))
        )
        fields = metadata(only_observation(output))
        self.assertEqual(fields["level"], "error")
        self.assertEqual(fields["level_source"], "invocation_override")

    def test_override_needs_the_provenance_invocation_index_when_several_invocations(self) -> None:
        rules = [{"id": "R1", "defaultConfiguration": {"level": "note"}}]
        # The override sits on invocation 0, so an un-indexed result that defaulted to 0
        # would wrongly take it; spec 3.48.6 defaults it to -1 beside several invocations.
        invocations = [OVERRIDE_TO_ERROR, {}]
        results = [
            make_result(ruleIndex=0, uri="src/plain.py"),
            make_result(ruleIndex=0, uri="src/indexed.py", provenance={"invocationIndex": 0}),
        ]
        output = ingest_document(make_log(make_run(results, rules=rules, invocations=invocations)))
        items = by_resource(output)
        self.assertEqual(metadata(items["src/plain.py"])["level_source"], "rule_default")
        self.assertEqual(metadata(items["src/plain.py"])["level"], "note")
        self.assertEqual(metadata(items["src/indexed.py"])["level_source"], "invocation_override")
        self.assertEqual(metadata(items["src/indexed.py"])["level"], "error")

    def test_each_invocation_sets_its_own_level_for_one_descriptor(self) -> None:
        rules = [{"id": "R1", "defaultConfiguration": {"level": "note"}}]
        invocations = [
            {"ruleConfigurationOverrides": [override("error", id="R1")]},
            {"ruleConfigurationOverrides": [override("warning", id="R1")]},
        ]
        levels = {0: "error", 1: "warning"}
        # Whichever invocation a result names first, the other keeps its own level.
        for order in ((0, 1), (1, 0)):
            with self.subTest(order=order):
                results = [
                    make_result(
                        ruleIndex=0, uri=f"src/{index}.py", provenance={"invocationIndex": index}
                    )
                    for index in order
                ]
                run = make_run(results, rules=rules, invocations=invocations)
                items = by_resource(ingest_document(make_log(run)))
                for index in order:
                    self.assertEqual(
                        level_of(items[f"src/{index}.py"]), (levels[index], "invocation_override")
                    )

    def test_explicit_negative_invocation_index_applies_no_override(self) -> None:
        rules = [{"id": "R1", "defaultConfiguration": {"level": "note"}}]
        for index in (-1, -2):
            with self.subTest(index=index):
                result = make_result(ruleIndex=0, provenance={"invocationIndex": index})
                run = make_run([result], rules=rules, invocations=[OVERRIDE_TO_ERROR])
                item = only_observation(ingest_document(make_log(run)))
                self.assertIs(item.source_severity, SourceSeverity.LOW)
                self.assertEqual(metadata(item)["level"], "note")
                self.assertEqual(metadata(item)["level_source"], "rule_default")

    def test_null_bool_and_text_invocation_index_count_as_absent(self) -> None:
        rules = [{"id": "R1", "defaultConfiguration": {"level": "note"}}]
        for index in (None, True, "0"):
            with self.subTest(index=index):
                result = make_result(ruleIndex=0, provenance={"invocationIndex": index})
                run = make_run([result], rules=rules, invocations=[OVERRIDE_TO_ERROR])
                item = only_observation(ingest_document(make_log(run)))
                self.assertIs(item.source_severity, SourceSeverity.HIGH)
                self.assertEqual(metadata(item)["level_source"], "invocation_override")

    def test_invocation_index_past_the_invocations_applies_no_override(self) -> None:
        rules = [{"id": "R1", "defaultConfiguration": {"level": "note"}}]
        result = make_result(ruleIndex=0, provenance={"invocationIndex": 1})
        run = make_run([result], rules=rules, invocations=[OVERRIDE_TO_ERROR])
        item = only_observation(ingest_document(make_log(run)))
        self.assertEqual(metadata(item)["level_source"], "rule_default")

    def test_unknown_component_guid_leaves_no_rule_component(self) -> None:
        rules = [{"id": "R1", "shortDescription": {"text": "driver rule"}}]
        output = ingest_document(
            make_log(
                make_run(
                    [make_result(rule={"toolComponent": {"guid": "nope"}, "index": 0})],
                    rules=rules,
                )
            )
        )
        item = only_observation(output)
        self.assertNotIn("rule_component", metadata(item))
        self.assertEqual(item.title, "")

    def test_deprecated_ids_taxa_and_guids_are_metadata_and_identifiers(self) -> None:
        rules = [{"id": "R1", "deprecatedIds": ["OLD-2", "OLD-1"]}]
        output = ingest_document(
            make_log(
                make_run(
                    [
                        make_result(
                            ruleIndex=0,
                            guid="g-1",
                            correlationGuid="c-1",
                            taxa=[{"id": "T1"}, {"id": "T0"}],
                        )
                    ],
                    rules=rules,
                )
            )
        )
        fields = metadata(only_observation(output))
        self.assertEqual(fields["rule_deprecated_ids"], '["OLD-1","OLD-2"]')
        self.assertEqual(fields["taxa"], '["T0","T1"]')
        self.assertEqual(fields["guid"], "g-1")
        self.assertEqual(fields["correlation_guid"], "c-1")

    def test_identifiers_are_gathered_from_rule_id_taxa_properties_and_relationships(self) -> None:
        rules = [
            {
                "id": "GHSA-abcd-1234-wxyz",
                "properties": {"tags": ["external/cwe/cwe-089", "CWE-20"]},
                "relationships": [{"target": {"id": "CWE-79"}}],
            }
        ]
        output = ingest_document(
            make_log(
                make_run(
                    [
                        make_result(
                            rule_id="GHSA-abcd-1234-wxyz",
                            ruleIndex=0,
                            taxa=[{"id": "CVE-2024-99999"}],
                        )
                    ],
                    rules=rules,
                )
            )
        )
        self.assertEqual(
            only_observation(output).source_identifiers,
            ("CVE-2024-99999", "CWE-20", "CWE-79", "CWE-89", "GHSA-abcd-1234-wxyz"),
        )

    def test_mixed_case_ghsa_is_normalized_to_a_lowercase_body(self) -> None:
        output = ingest_document(make_log(make_run([make_result(rule_id="ghsa-AbCd-12Ef-WXYZ")])))
        item = only_observation(output)
        self.assertEqual(item.source_identifiers, ("GHSA-abcd-12ef-wxyz",))
        self.assertEqual(item.source_record_id, "ghsa-AbCd-12Ef-WXYZ")

    def test_identifier_digits_are_ascii_and_a_cve_number_has_four_to_nineteen(self) -> None:
        # The CVE record format's cveId pattern allows 4 to 19 sequence digits; a longer run,
        # or another script's digits, names no identifier rather than a lookalike one.
        taxa = [
            {"id": "CVE-2024-" + "1" * 19},
            {"id": "CVE-2024-" + "2" * 20},
            {"id": "CVE-2024-123"},
            {"id": "CVE-\uff12\uff10\uff12\uff14-\uff11\uff12\uff13\uff14"},
            {"id": "CVE-\u0662\u0660\u0662\u0664-1234"},
            {"id": "CWE-\u0667\u0669"},
        ]
        properties = {"cve": "CVE-2023-\u0661\u0662\u0663\u0664", "cwe": ["CWE-\uff17\uff19"]}
        text = "see [the advisory](\u0661)"
        output = ingest_document(
            make_log(make_run([make_result(text=text, taxa=taxa, properties=properties)]))
        )
        item = only_observation(output)
        self.assertEqual(item.source_identifiers, ("CVE-2024-" + "1" * 19,))
        # A link whose target is not ASCII digits is not a link, so it is kept as written.
        self.assertEqual(item.description, text)

    def test_identifier_letters_are_ascii_so_a_lookalike_names_no_identifier(self) -> None:
        # A case-blind Unicode letter class also matches these four; with ASCII letters only,
        # none of them is read as, or folded into, an identifier letter.
        lookalikes = ("\u0130", "\u0131", "\u017f", "\u212a")
        tags = ["GH\u017fA-abcd-efgh-ijkm", "gh\u017fa-abcd-efgh-ijkm"]
        tags += [f"GHSA-{letter}aaa-bbbb-cccc" for letter in lookalikes]
        tags += [f"GHSA-aaaa-bbbb-ccc{letter}" for letter in lookalikes]
        for tag in tags:
            with self.subTest(tag=tag):
                result = make_result(properties={"tags": [tag]})
                item = only_observation(ingest_document(make_log(make_run([result]))))
                self.assertEqual(item.source_identifiers, ())
        # Before CVE or CWE a lookalike is not an ASCII letter, so it bounds the token the way
        # any other non-ASCII character does.
        for letter in (*lookalikes, "\u00e9"):
            with self.subTest(letter=letter):
                result = make_result(
                    properties={"tags": [f"{letter}CVE-2021-1234", f"{letter}CWE-79"]}
                )
                item = only_observation(ingest_document(make_log(make_run([result]))))
                self.assertEqual(item.source_identifiers, ("CVE-2021-1234", "CWE-79"))

    def test_rule_name_is_the_title_when_the_descriptor_has_no_short_description(self) -> None:
        rules = [{"id": "R1", "name": "InsecureHashRule", "fullDescription": {"text": "Long"}}]
        item = only_observation(ingest_document(make_log(make_run([make_result()], rules=rules))))
        self.assertEqual(item.title, "InsecureHashRule")
        self.assertEqual(metadata(item)["rule_name"], "InsecureHashRule")

    # Each table below pins a run-cached lookup to the linear scan it replaced. Every case
    # resolves twice in one run, so the second answer comes from the cache.

    def test_descriptor_lookup_matches_the_lone_match_scan_it_replaces(self) -> None:
        unique = [{"id": "R1"}, {"id": "R2"}]
        twins = [{"id": "R1", "guid": RULE_GUID}, {"id": "R1", "guid": OTHER_RULE_GUID}]
        shared_guid = [{"id": "R1", "guid": RULE_GUID}, {"id": "R2", "guid": RULE_GUID}]
        cases: dict[str, tuple[list[Any], dict[str, Any], str]] = {
            "unique id": (unique, {"rule_id": "R2"}, "T1"),
            "duplicate id": ([{"id": "R1"}, {"id": "R1"}], {}, ""),
            "triple id": ([{"id": "R1"}, {"id": "R1"}, {"id": "R1"}], {}, ""),
            "non-mapping entries": (["R1", 7, None, [], {"id": "R1"}], {}, "T4"),
            "padded descriptor id": ([{"id": " R1 "}], {}, "T0"),
            "padded rule id": (unique, {"rule_id": " R2 "}, "T1"),
            "rule.id without a ruleId": (unique, {"rule_id": None, "rule": {"id": "R2"}}, "T1"),
            "empty descriptor ids": ([{"id": ""}, {"id": "  "}, {"id": "R1"}], {}, "T2"),
            "index before the lookup": ([{"id": "R1"}, {"id": "R1"}], {"ruleIndex": 1}, "T1"),
            "index before the guid": (
                [{"id": "R1", "guid": RULE_GUID}, {"id": "R1"}],
                {"ruleIndex": 1, "rule": {"guid": RULE_GUID}},
                "T1",
            ),
            "guid picks a twin": (twins, {"rule": {"guid": OTHER_RULE_GUID}}, "T1"),
            "padded guid": (
                [{"id": "R1", "guid": f" {RULE_GUID} "}, {"id": "R1"}],
                {"rule": {"guid": f"{RULE_GUID}  "}},
                "T0",
            ),
            "guid against the id": (
                [{"id": "R1", "guid": RULE_GUID}, {"id": "R2"}],
                {"rule_id": "R2", "rule": {"guid": RULE_GUID}},
                "T0",
            ),
            "duplicate guid falls to the id": (
                shared_guid,
                {"rule_id": "R2", "rule": {"guid": RULE_GUID}},
                "T1",
            ),
            "unknown guid falls to the id": (twins[:1], {"rule": {"guid": THIRD_RULE_GUID}}, "T0"),
            "duplicate guid and id": ([twins[0], twins[0]], {"rule": {"guid": RULE_GUID}}, ""),
            "guid alone": (twins, {"rule_id": None, "rule": {"guid": RULE_GUID}}, "T0"),
            "duplicate guid alone": (
                shared_guid,
                {"rule_id": None, "rule": {"guid": RULE_GUID}},
                "",
            ),
        }
        for name, (rules, extra, title) in cases.items():
            with self.subTest(name):
                results = [make_result(**{"uri": f"src/{copy}.py", **extra}) for copy in range(2)]
                payload = make_log(make_run(results, rules=titled(rules, "T")))
                tool = payload["runs"][0]["tool"]
                descriptor, _index = scanned_descriptor(
                    scanned_component(tool, results[0].get("rule")), results[0]
                )
                scanned = descriptor["shortDescription"]["text"] if descriptor is not None else ""
                self.assertEqual(scanned, title)
                descriptor_id = text_of(descriptor.get("id")) if descriptor is not None else ""
                record_id = scanned_string_id(results[0]) or descriptor_id
                output = parse_direct(payload)
                if record_id:
                    self.assertEqual(
                        [(item.source_record_id, item.title) for item in output.observations],
                        [(record_id, title)] * 2,
                    )
                else:
                    self.assertEqual(output.observations, ())
                    self.assertIn("rule_id_missing", diagnostic_codes(output))

    def test_override_lookup_matches_the_first_match_loop_it_replaces(self) -> None:
        tool = {
            "driver": {"name": "Synth", "rules": [{"id": "R0"}, {"id": "R1"}, {"id": "R2"}]},
            "extensions": [
                {"name": "Ext", "guid": EXTENSION_GUID, "rules": [{"id": "R0"}, {"id": "X1"}]}
            ],
        }
        driver_rule = {"ruleIndex": 1}
        in_extension = {"toolComponent": {"index": 0}}
        cases: dict[str, tuple[list[Any], dict[str, Any], str]] = {
            "equal index": ([override("error", index=1)], driver_rule, "error"),
            # Spec 3.52.4: a reference's id does not take part in the lookup, so the index
            # alone names the descriptor.
            "equal id beside another index": (
                [override("error", index=2, id="R1")],
                driver_rule,
                "",
            ),
            "another descriptor's index": ([override("error", index=2)], driver_rule, ""),
            "another descriptor's id": ([override("error", id="R2")], driver_rule, ""),
            "no level, then a match": (
                [{"descriptor": {"index": 1}}, override("note", index=1)],
                driver_rule,
                "note",
            ),
            "blank level, then a match": (
                [override("  ", index=1), override("note", id="R1")],
                driver_rule,
                "note",
            ),
            "non-text level, then a match": (
                [override(3, index=1), override("note", index=1)],
                driver_rule,
                "note",
            ),
            "first of two matches": (
                [override("note", id="R1"), override("error", index=1)],
                driver_rule,
                "note",
            ),
            "first of two matches, reversed": (
                [override("error", index=1), override("note", id="R1")],
                driver_rule,
                "error",
            ),
            "first of two equal indexes": (
                [override("note", index=1), override("error", index=1)],
                driver_rule,
                "note",
            ),
            "first of two equal ids": (
                [override("note", id="R1"), override("error", id=" R1 ")],
                driver_rule,
                "note",
            ),
            "other rules around a match": (
                [
                    override("none", index=0),
                    override("note", id="R2"),
                    override("error", index=1),
                    override("none", id="R1"),
                ],
                driver_rule,
                "error",
            ),
            "non-mapping entries": (
                [
                    "error",
                    None,
                    {"descriptor": "R1", "configuration": {"level": "error"}},
                    {"descriptor": {"index": 1}, "configuration": "error"},
                    override("note", index=1),
                ],
                driver_rule,
                "note",
            ),
            "padded id": ([override("error", id=" R1 ")], driver_rule, "error"),
            "empty id": ([override("error", id="")], driver_rule, ""),
            "bool index": ([override("error", index=True)], driver_rule, ""),
            "extension entry against a driver rule": (
                [override("error", index=1, toolComponent={"index": 0})],
                driver_rule,
                "",
            ),
            "extension entry by index": (
                [override("error", index=1, toolComponent={"index": 0})],
                {"rule": {"index": 1, **in_extension}},
                "error",
            ),
            "extension entry by component guid": (
                [override("error", id="X1", toolComponent={"guid": EXTENSION_GUID})],
                {"rule": {"index": 1, **in_extension}},
                "error",
            ),
            "extension entry by id": (
                [override("error", id="X1", toolComponent={"index": 0})],
                {"rule_id": "X1", "rule": in_extension},
                "error",
            ),
            "driver entries against an extension rule": (
                [override("error", index=0), override("note", id="R0")],
                {"rule": {"index": 0, **in_extension}},
                "",
            ),
            "unknown component guid": (
                [override("error", index=1, toolComponent={"guid": "nope"})],
                driver_rule,
                "",
            ),
            "component index past the extensions": (
                [override("error", index=1, toolComponent={"index": 5})],
                driver_rule,
                "",
            ),
            # A result with no resolved descriptor takes no override, even one naming its index.
            "index past the rules": (
                [override("error", index=9)],
                {"rule_id": "R9", "ruleIndex": 9},
                "",
            ),
            "id beside an index past the rules": (
                [override("error", id="R9")],
                {"rule_id": "R9", "ruleIndex": 9},
                "",
            ),
            "result resolved by its id": ([override("error", index=2)], {"rule_id": "R2"}, "error"),
            "unresolved result": ([override("error", id="R7")], {"rule_id": "R7"}, ""),
        }
        for name, (overrides, extra, level) in cases.items():
            with self.subTest(name):
                results = [
                    make_result(**{"rule_id": None, "uri": f"src/{copy}.py", **extra})
                    for copy in range(2)
                ]
                self.assertEqual(scanned_override(tool, overrides, results[0]), level)
                invocations = [{"ruleConfigurationOverrides": overrides}]
                run = {"tool": tool, "invocations": invocations, "results": results}
                output = parse_direct(make_log(run))
                expected = (level, "invocation_override") if level else ("warning", "default")
                self.assertEqual([level_of(item) for item in output.observations], [expected] * 2)

    def test_override_naming_the_descriptor_guid_matches_it_first_in_order(self) -> None:
        # Spec 3.52.6 lets a reference name a descriptor by guid, so an override's guid
        # resolves as a result's does: after its index, and before its id.
        tool = {
            "driver": {
                "name": "Synth",
                "rules": [
                    {"id": "R0", "guid": OTHER_RULE_GUID},
                    {"id": "R1", "guid": RULE_GUID},
                    {"id": "R2"},
                ],
            },
            "extensions": [
                {
                    "name": "Ext",
                    "guid": EXTENSION_GUID,
                    "rules": [{"id": "X0", "guid": THIRD_RULE_GUID}],
                }
            ],
        }
        driver_rule = {"ruleIndex": 1}
        cases: dict[str, tuple[list[Any], dict[str, Any], str]] = {
            "guid alone": ([override("error", guid=RULE_GUID)], driver_rule, "error"),
            "padded guid": ([override("error", guid=f" {RULE_GUID} ")], driver_rule, "error"),
            "guid before an index": (
                [override("note", guid=RULE_GUID), override("error", index=1)],
                driver_rule,
                "note",
            ),
            "index before a guid": (
                [override("error", index=1), override("note", guid=RULE_GUID)],
                driver_rule,
                "error",
            ),
            "id before a guid": (
                [override("error", id="R1"), override("note", guid=RULE_GUID)],
                driver_rule,
                "error",
            ),
            "first of two equal guids": (
                [override("note", guid=RULE_GUID), override("error", guid=f" {RULE_GUID} ")],
                driver_rule,
                "note",
            ),
            "another descriptor's guid": (
                [override("error", guid=OTHER_RULE_GUID)],
                driver_rule,
                "",
            ),
            "index over another descriptor's guid": (
                [override("error", index=1, guid=OTHER_RULE_GUID)],
                driver_rule,
                "error",
            ),
            "guid beside another index": (
                [override("error", index=0, guid=RULE_GUID)],
                driver_rule,
                "",
            ),
            "guid over another descriptor's id": (
                [override("error", guid=OTHER_RULE_GUID, id="R1")],
                driver_rule,
                "",
            ),
            "unknown guid falls to the id": (
                [override("error", guid=THIRD_RULE_GUID, id="R1")],
                driver_rule,
                "error",
            ),
            "guid on another component": (
                [override("error", guid=RULE_GUID, toolComponent={"index": 0})],
                driver_rule,
                "",
            ),
            "descriptor without a guid": (
                [override("error", guid=RULE_GUID)],
                {"ruleIndex": 2},
                "",
            ),
            "extension descriptor guid": (
                [override("error", guid=THIRD_RULE_GUID, toolComponent={"guid": EXTENSION_GUID})],
                {"rule": {"index": 0, "toolComponent": {"index": 0}}},
                "error",
            ),
            "result resolved by its guid": (
                [override("error", guid=RULE_GUID)],
                {"rule": {"guid": RULE_GUID}},
                "error",
            ),
        }
        for name, (overrides, extra, level) in cases.items():
            with self.subTest(name):
                results = [
                    make_result(**{"rule_id": None, "uri": f"src/{copy}.py", **extra})
                    for copy in range(2)
                ]
                self.assertEqual(scanned_override(tool, overrides, results[0]), level)
                invocations = [{"ruleConfigurationOverrides": overrides}]
                run = {"tool": tool, "invocations": invocations, "results": results}
                output = parse_direct(make_log(run))
                expected = (level, "invocation_override") if level else ("warning", "default")
                self.assertEqual([level_of(item) for item in output.observations], [expected] * 2)

    def test_override_names_one_descriptor_among_twins_sharing_an_id(self) -> None:
        # Spec 3.19.23 lets descriptors share an id and 3.52.5 EXAMPLE 1 names one of the
        # CA1711 twins by index; an id alone, like a result's, names neither of them.
        tool = {
            "driver": {
                "name": "Synth",
                "rules": [
                    {"id": "CA1711", "defaultConfiguration": {"level": "note"}},
                    {"id": "CA1711", "defaultConfiguration": {"level": "note"}},
                    "CA2000",
                ],
            }
        }
        twin_default = ("note", "rule_default")
        cases: dict[str, tuple[list[Any], dict[str, Any], str, tuple[str, str]]] = {
            "twin by index, first twin": (
                [override("error", index=1, id="CA1711")],
                {"ruleIndex": 0},
                "",
                twin_default,
            ),
            "twin by index, second twin": (
                [override("error", index=1, id="CA1711")],
                {"ruleIndex": 1},
                "error",
                ("error", "invocation_override"),
            ),
            "each twin its own entry": (
                [override("none", index=1, id="CA1711"), override("error", index=0, id="CA1711")],
                {"ruleIndex": 0},
                "error",
                ("error", "invocation_override"),
            ),
            "shared id alone, first twin": (
                [override("error", id="CA1711")],
                {"ruleIndex": 0},
                "",
                twin_default,
            ),
            "shared id alone, second twin": (
                [override("error", id="CA1711")],
                {"ruleIndex": 1},
                "",
                twin_default,
            ),
            "entry that is not a descriptor": (
                [override("error", index=2)],
                {"rule_id": "CA2000", "ruleIndex": 2},
                "",
                ("warning", "default"),
            ),
        }
        for name, (overrides, extra, scanned, expected) in cases.items():
            with self.subTest(name):
                results = [
                    make_result(**{"rule_id": "CA1711", "uri": f"src/{copy}.py", **extra})
                    for copy in range(2)
                ]
                self.assertEqual(scanned_override(tool, overrides, results[0]), scanned)
                invocations = [{"ruleConfigurationOverrides": overrides}]
                run = {"tool": tool, "invocations": invocations, "results": results}
                output = parse_direct(make_log(run))
                self.assertEqual([level_of(item) for item in output.observations], [expected] * 2)

    def test_component_guid_lookup_matches_the_first_match_scan_it_replaces(self) -> None:
        def component(name: str, guid: str | None = None) -> dict[str, Any]:
            rules = [{"id": "R1", "shortDescription": {"text": f"{name} rule"}}]
            entry: dict[str, Any] = {"name": name, "rules": rules}
            if guid is not None:
                entry["guid"] = guid
            return entry

        by_guid = {"guid": EXTENSION_GUID}
        cases: dict[str, tuple[dict[str, Any], list[Any], dict[str, Any], str]] = {
            "lone extension": (
                component("Driver"),
                [component("First", EXTENSION_GUID)],
                by_guid,
                "First",
            ),
            "second extension": (
                component("Driver"),
                [component("First"), component("Second", EXTENSION_GUID)],
                by_guid,
                "Second",
            ),
            "first of two extensions": (
                component("Driver"),
                [component("First", EXTENSION_GUID), component("Second", EXTENSION_GUID)],
                by_guid,
                "First",
            ),
            "driver before an extension": (
                component("Driver", EXTENSION_GUID),
                [component("First", EXTENSION_GUID)],
                by_guid,
                "Driver",
            ),
            "padded guids": (
                component("Driver"),
                [component("First", f" {EXTENSION_GUID} ")],
                {"guid": f"{EXTENSION_GUID} "},
                "First",
            ),
            "non-mapping extensions": (
                component("Driver"),
                ["First", None, component("Third", EXTENSION_GUID)],
                by_guid,
                "Third",
            ),
            "unknown guid": (
                component("Driver", EXTENSION_GUID),
                [component("First", EXTENSION_GUID)],
                {"guid": "nope"},
                "",
            ),
            "blank guid": (
                component("Driver"),
                [component("First", EXTENSION_GUID)],
                {"guid": "  "},
                "Driver",
            ),
            "index before the guid": (
                component("Driver"),
                [component("First", EXTENSION_GUID), component("Second")],
                {"index": 1, "guid": EXTENSION_GUID},
                "Second",
            ),
        }
        for name, (driver, extensions, reference, found) in cases.items():
            with self.subTest(name):
                tool = {"driver": driver, "extensions": extensions}
                results = [
                    make_result(uri=f"src/{copy}.py", rule={"toolComponent": reference})
                    for copy in range(2)
                ]
                scanned = scanned_component(tool, results[0]["rule"])
                self.assertEqual(scanned["name"] if scanned is not None else "", found)
                output = parse_direct(make_log({"tool": tool, "results": results}))
                expected = (found, f"{found} rule") if found else (None, "")
                self.assertEqual(
                    [
                        (metadata(item).get("rule_component"), item.title)
                        for item in output.observations
                    ],
                    [expected] * 2,
                )


# *--- Suppression ---*


def suppressed_document(*suppressions: dict[str, Any]) -> dict[str, Any]:
    return make_log(make_run([make_result(suppressions=list(suppressions))]))


class SarifSuppressionTests(unittest.TestCase):
    """Absent or accepted status counts as accepted; disposition never changes."""

    def test_status_absent_counts_as_accepted(self) -> None:
        output = ingest_document(suppressed_document({"kind": "inSource"}))
        item = only_observation(output)
        fields = metadata(item)
        self.assertEqual(fields["suppressed"], "true")
        self.assertEqual(fields["suppression_kinds"], '["inSource"]')
        self.assertNotIn("suppression_statuses", fields)
        self.assertIs(item.disposition, ObservationDisposition.OPEN)
        self.assertEqual(
            only_diagnostic(output, "results_suppressed").message,
            "result carries an accepted suppression; its disposition is unchanged "
            "(1 occurrence: runs[0].results[0])",
        )

    def test_accepted_status_is_recorded(self) -> None:
        output = ingest_document(suppressed_document({"kind": "external", "status": "accepted"}))
        fields = metadata(only_observation(output))
        self.assertEqual(fields["suppressed"], "true")
        self.assertEqual(fields["suppression_statuses"], '["accepted"]')
        self.assertIn("results_suppressed", diagnostic_codes(output))

    def test_under_review_alone_is_not_suppressed(self) -> None:
        output = ingest_document(suppressed_document({"kind": "external", "status": "underReview"}))
        fields = metadata(only_observation(output))
        self.assertEqual(fields["suppressed"], "false")
        self.assertEqual(fields["suppression_statuses"], '["underReview"]')
        self.assertNotIn("results_suppressed", diagnostic_codes(output))

    def test_rejected_alone_is_not_suppressed(self) -> None:
        output = ingest_document(suppressed_document({"kind": "external", "status": "rejected"}))
        fields = metadata(only_observation(output))
        self.assertEqual(fields["suppressed"], "false")
        self.assertNotIn("results_suppressed", diagnostic_codes(output))

    def test_one_accepted_among_rejected_suppresses_and_lists_both(self) -> None:
        output = ingest_document(
            suppressed_document(
                {"kind": "external", "status": "rejected"},
                {"kind": "inSource", "status": "accepted"},
            )
        )
        fields = metadata(only_observation(output))
        self.assertEqual(fields["suppressed"], "true")
        self.assertEqual(fields["suppression_kinds"], '["external","inSource"]')
        self.assertEqual(fields["suppression_statuses"], '["accepted","rejected"]')
        self.assertIn("results_suppressed", diagnostic_codes(output))

    def test_empty_suppressions_array_leaves_no_keys(self) -> None:
        output = ingest_document(suppressed_document())
        fields = metadata(only_observation(output))
        self.assertNotIn("suppressed", fields)
        self.assertNotIn("suppression_kinds", fields)
        self.assertNotIn("results_suppressed", diagnostic_codes(output))


# *--- Severity ---*


def severity_document(**result_fields: Any) -> dict[str, Any]:
    return make_log(make_run([make_result(**result_fields)]))


def scored(score: Any, **result_fields: Any) -> Observation:
    output = ingest_document(
        severity_document(properties={"security-severity": score}, **result_fields)
    )
    return only_observation(output)


class SarifSeverityTests(unittest.TestCase):
    """security-severity from the first holder that declares it, else the level chain."""

    def test_bands_at_every_threshold(self) -> None:
        cases = [
            (10, SourceSeverity.CRITICAL),
            (9.0, SourceSeverity.CRITICAL),
            (8.99, SourceSeverity.HIGH),
            (7.0, SourceSeverity.HIGH),
            (6.99, SourceSeverity.MEDIUM),
            (4.0, SourceSeverity.MEDIUM),
            (3.99, SourceSeverity.LOW),
            (0.1, SourceSeverity.LOW),
        ]
        for score, severity in cases:
            with self.subTest(score=score):
                item = scored(score)
                self.assertIs(item.source_severity, severity)
                self.assertEqual(metadata(item)["severity_source"], "security-severity")

    def test_result_zero_is_unset_and_the_rule_default_level_decides_without_the_descriptor(
        self,
    ) -> None:
        rules = [
            {
                "id": "R1",
                "defaultConfiguration": {"level": "warning"},
                "properties": {"security-severity": "9.8"},
            }
        ]
        output = ingest_document(
            make_log(make_run([make_result(properties={"security-severity": "0.0"})], rules=rules))
        )
        item = only_observation(output)
        fields = metadata(item)
        self.assertIs(item.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(fields["security_severity"], "0.0")
        self.assertEqual(fields["severity_source"], "level")
        self.assertEqual(fields["level_source"], "rule_default")
        self.assertNotIn("security_severity_invalid", diagnostic_codes(output))

    def test_result_score_is_read_before_the_descriptor_score(self) -> None:
        rules = [{"id": "R1", "properties": {"security-severity": "3.0"}}]
        output = ingest_document(
            make_log(make_run([make_result(properties={"security-severity": "9.5"})], rules=rules))
        )
        item = only_observation(output)
        self.assertIs(item.source_severity, SourceSeverity.CRITICAL)
        self.assertEqual(metadata(item)["security_severity"], "9.5")

    def test_descriptor_score_applies_when_the_result_declares_none(self) -> None:
        rules = [{"id": "R1", "properties": {"security-severity": 7.5}}]
        output = ingest_document(make_log(make_run([make_result()], rules=rules)))
        item = only_observation(output)
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(metadata(item)["security_severity"], "7.5")

    def test_padded_string_score_is_trimmed(self) -> None:
        item = scored(" 7.5 ")
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(metadata(item)["security_severity"], "7.5")

    def test_ascii_decimal_strings_with_or_without_a_fraction_are_scores(self) -> None:
        cases = [
            ("10", SourceSeverity.CRITICAL),
            ("010", SourceSeverity.CRITICAL),
            ("9.80", SourceSeverity.CRITICAL),
            ("7", SourceSeverity.HIGH),
            ("04.5", SourceSeverity.MEDIUM),
            ("004.5", SourceSeverity.MEDIUM),
            ("0.1", SourceSeverity.LOW),
        ]
        for score, severity in cases:
            with self.subTest(score=score):
                item = scored(score)
                self.assertIs(item.source_severity, severity)
                self.assertEqual(metadata(item)["severity_source"], "security-severity")

    def test_scores_outside_the_open_closed_range_are_invalid_and_kept_raw(self) -> None:
        cases: list[tuple[Any, str, str]] = [
            (11, "11", "first: 11"),
            (10.5, "10.5", "first: 10.5"),
            ("-1", "-1", "first: '-1'"),
            ("abc", "abc", "first: 'abc'"),
            ("inf", "inf", "first: 'inf'"),
            (True, "true", "first: True"),
            (None, "null", "first: None"),
            # A numeric string is ASCII decimal: none of Python's other float spellings
            # count, nor another script's digits.
            ("0_9", "0_9", "first: '0_9'"),
            ("1_0", "1_0", "first: '1_0'"),
            ("\u0669.\u0668", "\u0669.\u0668", "first: '\u0669.\u0668'"),
            ("\uff19.\uff18", "\uff19.\uff18", "first: '\uff19.\uff18'"),
            ("1e1", "1e1", "first: '1e1'"),
            (".5", ".5", "first: '.5'"),
            ("9.", "9.", "first: '9.'"),
        ]
        for score, raw, detail in cases:
            with self.subTest(score=score):
                output = ingest_document(severity_document(properties={"security-severity": score}))
                item = only_observation(output)
                fields = metadata(item)
                self.assertEqual(fields["security_severity"], raw)
                self.assertEqual(fields["severity_source"], "level")
                self.assertIs(item.source_severity, SourceSeverity.MEDIUM)
                invalid = only_diagnostic(output, "security_severity_invalid")
                self.assertIs(invalid.level, DiagnosticLevel.WARNING)
                self.assertEqual(
                    invalid.message,
                    "security-severity is not a finite number above 0 and at most 10; ignored "
                    f"(1 occurrence: runs[0].results[0]; {detail})",
                )

    def test_integer_zero_is_unset_like_zero_point_zero(self) -> None:
        output = ingest_document(severity_document(properties={"security-severity": 0}))
        item = only_observation(output)
        self.assertEqual(metadata(item)["security_severity"], "0")
        self.assertEqual(metadata(item)["severity_source"], "level")
        self.assertIs(item.source_severity, SourceSeverity.MEDIUM)
        self.assertNotIn("security_severity_invalid", diagnostic_codes(output))

    def test_integer_score_too_large_for_a_float_is_invalid_and_the_level_decides(self) -> None:
        rules = [{"id": "R1", "defaultConfiguration": {"level": "error"}}]
        for sign in (1, -1):
            huge = sign * 10**400
            scored = {"security-severity": huge}
            runs = {
                "result": make_run([make_result(properties=scored)], rules=rules),
                "descriptor": make_run([make_result()], rules=[dict(rules[0], properties=scored)]),
            }
            for holder, run in runs.items():
                with self.subTest(sign=sign, holder=holder):
                    output = ingest_document(make_log(run))
                    item = only_observation(output)
                    fields = metadata(item)
                    self.assertTrue(output.successful)
                    self.assertIs(item.source_severity, SourceSeverity.HIGH)
                    self.assertEqual(fields["severity_source"], "level")
                    self.assertEqual(fields["level_source"], "rule_default")
                    self.assertEqual(fields["security_severity"], str(huge))
                    invalid = only_diagnostic(output, "security_severity_invalid")
                    self.assertIs(invalid.level, DiagnosticLevel.WARNING)

    def test_oversized_integer_score_is_kept_raw_only_up_to_the_metadata_cap(self) -> None:
        output = ingest_document(severity_document(properties={"security-severity": 10**600}))
        fields = metadata(only_observation(output))
        self.assertEqual(len(fields["security_severity"]), MAX_METADATA_VALUE_CHARS)
        self.assertTrue(fields["security_severity"].endswith(TRUNCATION_MARKER))
        self.assertEqual(fields["truncated"], '["security_severity"]')
        self.assertIn("security_severity_invalid", diagnostic_codes(output))

    def test_integer_score_past_the_parser_digit_limit_refuses_the_artifact(self) -> None:
        limit = sys.get_int_max_str_digits()
        if limit == 0:
            self.skipTest("this interpreter sets no integer digit limit")
        # 5000 digits at CPython's default limit of 4300.
        digits = "9" * (limit + 700)
        text = json.dumps(severity_document(properties={"security-severity": 1}))
        raw = text.replace('"security-severity": 1', f'"security-severity": {digits}')
        self.assertIn(digits, raw)
        output = ingest_document(None, raw=raw.encode("utf-8"))
        self.assertEqual(output.observations, ())
        self.assertFalse(output.successful)
        self.assertIs(only_diagnostic(output, "artifact_parse_failed").level, DiagnosticLevel.ERROR)

    def test_result_level_maps_error_warning_note_and_none(self) -> None:
        cases = [
            ("error", SourceSeverity.HIGH),
            ("warning", SourceSeverity.MEDIUM),
            ("note", SourceSeverity.LOW),
            ("none", SourceSeverity.INFORMATIONAL),
        ]
        for level, severity in cases:
            with self.subTest(level=level):
                item = only_observation(ingest_document(severity_document(level=level)))
                self.assertIs(item.source_severity, severity)
                self.assertEqual(metadata(item)["level"], level)
                self.assertEqual(metadata(item)["level_source"], "result")
                self.assertEqual(metadata(item)["severity_source"], "level")

    def test_level_outside_the_four_values_is_unknown(self) -> None:
        output = ingest_document(severity_document(level="fatal"))
        item = only_observation(output)
        self.assertIs(item.source_severity, SourceSeverity.UNKNOWN)
        self.assertEqual(metadata(item)["level"], "fatal")
        self.assertEqual(
            only_diagnostic(output, "invalid_level").message,
            "effective level is outside error, warning, note, and none; severity unknown "
            "(1 occurrence: runs[0].results[0]; first: 'fatal')",
        )

    def test_no_level_anywhere_defaults_to_warning(self) -> None:
        item = only_observation(ingest_document(severity_document()))
        self.assertIs(item.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(metadata(item)["level"], "warning")
        self.assertEqual(metadata(item)["level_source"], "default")

    def test_pass_kind_forces_level_none_over_an_error_level(self) -> None:
        item = only_observation(ingest_document(severity_document(kind="pass", level="error")))
        self.assertIs(item.disposition, ObservationDisposition.PASS)
        self.assertIs(item.source_severity, SourceSeverity.INFORMATIONAL)
        self.assertEqual(metadata(item)["level"], "none")
        self.assertEqual(metadata(item)["level_source"], "forced_none")

    def test_fail_kind_without_a_level_takes_the_default(self) -> None:
        item = only_observation(ingest_document(severity_document(kind="fail")))
        self.assertIs(item.disposition, ObservationDisposition.OPEN)
        self.assertEqual(metadata(item)["level_source"], "default")
        self.assertEqual(metadata(item)["result_kind"], "fail")

    def test_open_kind_keeps_its_security_severity_band(self) -> None:
        item = scored(8.0, kind="open")
        self.assertIs(item.disposition, ObservationDisposition.UNKNOWN)
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(metadata(item)["level_source"], "forced_none")


# *--- Clocks ---*

EARLY = "2026-09-01T08:30:00Z"
LATE = "2026-09-04T08:30:00Z"


def clocked(
    provenance: dict[str, Any] | None = None, invocations: list[Any] | None = None
) -> IngestResult:
    result = make_result()
    if provenance is not None:
        result["provenance"] = provenance
    run = make_run([result])
    if invocations is not None:
        run["invocations"] = invocations
    return ingest_document(make_log(run))


class SarifClockTests(unittest.TestCase):
    """Detection clocks first, then invocation starts, then ends; earliest wins per tier."""

    def test_first_detection_beats_a_later_last_detection(self) -> None:
        output = clocked({"firstDetectionTimeUtc": EARLY, "lastDetectionTimeUtc": LATE})
        self.assertEqual(only_observation(output).observed_at, parse_timestamp(EARLY))

    def test_last_detection_beats_the_run_clock(self) -> None:
        output = clocked({"lastDetectionTimeUtc": LATE}, [{"startTimeUtc": EARLY}])
        self.assertEqual(only_observation(output).observed_at, parse_timestamp(LATE))

    def test_earliest_start_of_several_invocations_wins(self) -> None:
        output = clocked(None, [{"startTimeUtc": LATE}, {"startTimeUtc": EARLY}])
        self.assertEqual(only_observation(output).observed_at, parse_timestamp(EARLY))

    def test_any_start_beats_an_earlier_end(self) -> None:
        output = clocked(None, [{"endTimeUtc": EARLY}, {"startTimeUtc": LATE}])
        self.assertEqual(only_observation(output).observed_at, parse_timestamp(LATE))

    def test_earliest_end_is_used_when_no_start_exists(self) -> None:
        output = clocked(None, [{"endTimeUtc": LATE}, {"endTimeUtc": EARLY}])
        self.assertEqual(only_observation(output).observed_at, parse_timestamp(EARLY))

    def test_offset_form_is_kept_and_compares_by_instant(self) -> None:
        output = clocked({"firstDetectionTimeUtc": "2026-09-04T08:30:00+02:00"})
        item = only_observation(output)
        self.assertEqual(item.observed_at, datetime(2026, 9, 4, 6, 30, tzinfo=UTC))
        self.assertEqual(offset_hours(item), 2)

    def test_seven_digit_fraction_is_truncated_to_microseconds(self) -> None:
        output = clocked({"firstDetectionTimeUtc": "2026-09-01T02:00:00.1234567Z"})
        self.assertEqual(
            only_observation(output).observed_at,
            datetime(2026, 9, 1, 2, 0, 0, 123456, tzinfo=UTC),
        )

    def test_seconds_bearing_offset_is_invalid_in_sarif_but_parses_in_common(self) -> None:
        value = "2026-09-01T08:30:00+05:30:15"
        self.assertIsNotNone(parse_timestamp(value))
        self.assertIsNone(_sarif_timestamp(value))
        output = clocked(None, [{"startTimeUtc": value}])
        item = only_observation(output)
        self.assertIsNone(item.observed_at)
        invalid = only_diagnostic(output, "source_timestamp_invalid")
        self.assertIs(invalid.level, DiagnosticLevel.WARNING)
        self.assertEqual(
            invalid.message,
            f"{INVALID_CLOCK_MESSAGE} (1 occurrence: runs[0].invocations[0].startTimeUtc)",
        )
        self.assertEqual(
            only_diagnostic(output, "source_timestamp_missing").message, MISSING_CLOCK_MESSAGE
        )

    def test_naive_and_numeric_clocks_are_invalid(self) -> None:
        for value in ("2026-09-01T08:30:00", 1_756_700_000, "yesterday"):
            with self.subTest(value=value):
                output = clocked(None, [{"startTimeUtc": value}])
                self.assertIsNone(only_observation(output).observed_at)
                self.assertIn("source_timestamp_invalid", diagnostic_codes(output))
                self.assertIn("source_timestamp_missing", diagnostic_codes(output))

    def test_null_clock_members_are_silently_absent(self) -> None:
        output = clocked(
            {"firstDetectionTimeUtc": None, "lastDetectionTimeUtc": None},
            [{"startTimeUtc": None, "endTimeUtc": None}],
        )
        self.assertIsNone(only_observation(output).observed_at)
        self.assertNotIn("source_timestamp_invalid", diagnostic_codes(output))
        self.assertIn("source_timestamp_missing", diagnostic_codes(output))

    def test_invalid_detection_clock_falls_back_to_the_run_clock(self) -> None:
        output = clocked({"firstDetectionTimeUtc": "not a clock"}, [{"startTimeUtc": EARLY}])
        self.assertEqual(only_observation(output).observed_at, parse_timestamp(EARLY))
        self.assertEqual(
            only_diagnostic(output, "source_timestamp_invalid").message,
            f"{INVALID_CLOCK_MESSAGE} (1 occurrence: runs[0].results[0].provenance."
            "firstDetectionTimeUtc)",
        )
        self.assertNotIn("source_timestamp_missing", diagnostic_codes(output))

    def test_no_clock_anywhere_leaves_observed_at_unknown_with_one_warning(self) -> None:
        output = clocked()
        self.assertIsNone(only_observation(output).observed_at)
        self.assertEqual(diagnostic_codes(output), ["source_timestamp_missing"])

    def test_sarif_timestamp_accepts_whole_minute_offsets_and_z(self) -> None:
        self.assertEqual(_sarif_timestamp("2026-09-01T08:30:00Z"), parse_timestamp(EARLY))
        self.assertEqual(
            _sarif_timestamp("2026-09-01T08:30:00+05:30"),
            datetime(2026, 9, 1, 8, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        )
        self.assertIsNone(_sarif_timestamp("2026-09-01T08:30:00"))
        self.assertIsNone(_sarif_timestamp(""))

    def test_clocks_outside_the_supported_years_are_invalid(self) -> None:
        provenance = "runs[0].results[0].provenance"
        cases: list[tuple[dict[str, Any] | None, list[Any] | None, str]] = [
            (
                None,
                [{"startTimeUtc": "9999-12-31T23:59:59Z"}],
                "runs[0].invocations[0].startTimeUtc",
            ),
            (
                {"firstDetectionTimeUtc": "0001-01-01T00:00:00+05:00"},
                None,
                f"{provenance}.firstDetectionTimeUtc",
            ),
            (
                {"lastDetectionTimeUtc": "9999-12-31T23:59:59.9999999Z"},
                None,
                f"{provenance}.lastDetectionTimeUtc",
            ),
        ]
        for detection, invocations, path in cases:
            with self.subTest(path=path):
                output = clocked(detection, invocations)
                self.assertIsNone(only_observation(output).observed_at)
                self.assertEqual(
                    only_diagnostic(output, "source_timestamp_invalid").message,
                    f"{INVALID_CLOCK_MESSAGE} (1 occurrence: {path})",
                )
                self.assertIn("source_timestamp_missing", diagnostic_codes(output))

    def test_sarif_timestamp_keeps_1970_through_9000_utc_inclusive(self) -> None:
        self.assertEqual((MIN_CLOCK_YEAR, MAX_CLOCK_YEAR), (1970, 9000))
        kept = ("1970-01-01T00:00:00Z", "9000-12-31T23:59:59Z", "1970-01-01T05:00:00+05:00")
        for value in kept:
            with self.subTest(value=value):
                self.assertIsNotNone(_sarif_timestamp(value))
        # The year is read after conversion to UTC, so an offset can carry an edge across.
        refused = (
            "1969-12-31T23:59:59Z",
            "9001-01-01T00:00:00Z",
            "1970-01-01T04:59:00+05:00",
            "9000-12-31T23:59:59-05:00",
        )
        for value in refused:
            with self.subTest(value=value):
                self.assertIsNone(_sarif_timestamp(value))

    # Spec 3.9 lets hour 24 end a day, and fromisoformat reads it only from Python 3.14, so
    # each case below runs the same on every interpreter the gate covers.

    def test_end_of_day_hour_24_is_the_next_midnight_on_every_interpreter(self) -> None:
        plus_five_thirty = timezone(timedelta(hours=5, minutes=30))
        minus_five = timezone(timedelta(hours=-5))
        cases = [
            ("2026-01-05T24:00Z", datetime(2026, 1, 6, tzinfo=UTC)),
            ("2026-01-05T24:00:00Z", datetime(2026, 1, 6, tzinfo=UTC)),
            ("2026-01-05T24:00:00.000000000Z", datetime(2026, 1, 6, tzinfo=UTC)),
            (" 2026-12-31T24:00:00Z ", datetime(2027, 1, 1, tzinfo=UTC)),
            ("2026-01-05T24:00:00+05:30", datetime(2026, 1, 6, tzinfo=plus_five_thirty)),
            ("2026-01-05T24:00:00-05:00", datetime(2026, 1, 6, tzinfo=minus_five)),
            ("1969-12-31T24:00:00Z", datetime(1970, 1, 1, tzinfo=UTC)),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                parsed = _sarif_timestamp(value)
                self.assertEqual(parsed, expected)
                offset = parsed.utcoffset() if parsed is not None else None
                self.assertEqual(offset, expected.utcoffset())
        output = clocked(
            {"firstDetectionTimeUtc": "2026-01-05T24:00:00Z", "lastDetectionTimeUtc": LATE}
        )
        self.assertEqual(only_observation(output).observed_at, datetime(2026, 1, 6, tzinfo=UTC))
        self.assertNotIn("source_timestamp_invalid", diagnostic_codes(output))

    def test_any_other_hour_24_is_invalid_on_every_interpreter(self) -> None:
        values = (
            "2026-01-05T24:30:00Z",
            "2026-01-05T24:00:01Z",
            "2026-01-05T24:00:00.5Z",
            "2026-01-05T24:00:00.Z",
            "2026-01-05T24:00:00,0Z",
            "2026-01-05T24Z",
            "2026-01-05T24:00",
            "2026-01-05 24:00:00Z",
            "2026-01-05t24:00:00Z",
            "20260105T240000Z",
            "2026-W02-1T24:00Z",
            "2026W021T2400Z",
            "2026-W02T24:00Z",
            "2026W02T2400Z",
            "2026-01-05\n24:00:00Z",
        )
        for value in values:
            with self.subTest(value=value):
                self.assertIsNone(_sarif_timestamp(value))
                output = clocked({"firstDetectionTimeUtc": value, "lastDetectionTimeUtc": LATE})
                self.assertEqual(only_observation(output).observed_at, parse_timestamp(LATE))
                self.assertIn("source_timestamp_invalid", diagnostic_codes(output))

    def test_hour_24_past_the_supported_years_is_refused_without_raising(self) -> None:
        for value in ("9999-12-31T24:00:00Z", "9000-12-31T24:00Z", "9000-12-31T24:00-05:00"):
            with self.subTest(value=value):
                self.assertIsNone(_sarif_timestamp(value))
                output = clocked({"firstDetectionTimeUtc": value})
                self.assertIsNone(only_observation(output).observed_at)
                self.assertIn("source_timestamp_invalid", diagnostic_codes(output))

    def test_leap_seconds_and_date_only_values_are_invalid_on_every_interpreter(self) -> None:
        # Deliberate deviations from spec 3.9, which allows both: the event contract carries
        # an aware instant, and neither form is one on any interpreter.
        for value in ("2026-12-31T23:59:60Z", "2026-01-05T08:30:60+02:00", "2026-01-05"):
            with self.subTest(value=value):
                self.assertIsNone(_sarif_timestamp(value))
                output = clocked({"firstDetectionTimeUtc": value, "lastDetectionTimeUtc": LATE})
                self.assertEqual(only_observation(output).observed_at, parse_timestamp(LATE))
                self.assertIn("source_timestamp_invalid", diagnostic_codes(output))


# *--- Folding ---*

FOLD_POOL = [f"t{number:03d}" for number in range(300)]


def fold_splits() -> list[list[list[str]]]:
    """Return the ways a fold's lists are split among its parts, some chosen at random."""
    pool = FOLD_POOL
    splits = [[pool[: MAX_LIST_ITEMS + 1]], [pool[:40], pool[40:80]]]
    # Copies of one item never crowd a distinct item out of the cut.
    splits.append([pool[:1] * (MAX_LIST_ITEMS + 1) + pool[1:2]])
    sizes = (1, 20, 40, MAX_LIST_ITEMS, MAX_LIST_ITEMS + 1, 150)
    for seed in range(12):
        chooser = random.Random(seed)
        count = chooser.randint(1, 4)
        splits.append([chooser.sample(pool, chooser.choice(sizes)) for _ in range(count)])
    return splits


def own_lists(part: Sequence[str]) -> dict[str, Any]:
    """Carry one part as a result's fingerprints, partial fingerprints, taxa, and suppressions."""
    # A repeated item gains a format character per copy, which cleaning removes, so the copies
    # in every list differ before cleaning and match after it.
    copies: Counter[str] = Counter()
    names: list[str] = []
    for item in part:
        names.append(item + "\u200b" * copies[item])
        copies[item] += 1
    return {
        "fingerprints": {f"n{name}": f"v{name}" for name in names},
        "partialFingerprints": {f"p{name}": f"w{name}" for name in names},
        "taxa": [{"id": name} for name in names],
        "suppressions": [{"kind": f"k{name}", "status": f"s{name}"} for name in names],
    }


def own_list_members(items: Sequence[str]) -> dict[str, Any]:
    """Return the metadata lists that own_lists gives a fold whose items are these."""
    return {
        "fingerprints": [[f"n{item}", f"v{item}"] for item in items],
        "partial_fingerprints": [[f"p{item}", f"w{item}"] for item in items],
        "taxa": list(items),
        "suppression_kinds": [f"k{item}" for item in items],
        "suppression_statuses": [f"s{item}" for item in items],
    }


class SarifFoldTests(unittest.TestCase):
    """Results sharing driver, record, resource, and context fold into one observation."""

    def test_two_results_with_one_identity_fold_and_the_smallest_region_describes(self) -> None:
        results = [
            make_result(line=10, text="later text"),
            make_result(line=2, text="earlier text"),
        ]
        output = ingest_document(make_log(make_run(results)))
        item = only_observation(output)
        fields = metadata(item)
        self.assertEqual(item.description, "earlier text")
        self.assertEqual(fields["occurrence_count"], "2")
        self.assertEqual(fields["regions"], '["2","10"]')
        self.assertEqual(
            only_diagnostic(output, "results_collapsed").message,
            "result folded into an observation that shares its identity "
            "(1 occurrence: runs[0].results[0])",
        )

    def test_smallest_region_picks_the_title_between_two_descriptors(self) -> None:
        rules = [
            {"id": "R1", "shortDescription": {"text": "Title A"}},
            {"id": "R1", "shortDescription": {"text": "Title B"}},
        ]
        results = [make_result(ruleIndex=0, line=9), make_result(ruleIndex=1, line=3)]
        output = ingest_document(make_log(make_run(results, rules=rules)))
        self.assertEqual(only_observation(output).title, "Title B")

    def test_identifiers_cut_per_result_equal_the_cut_of_their_union(self) -> None:
        numbers = list(range(1, 200))
        splits = {
            "interleaved": [numbers[0::3], numbers[1::3], numbers[2::3]],
            "one_result_holds_the_first": [numbers[:70], numbers[70:]],
            "overlapping": [numbers[:130], numbers[60:]],
            "one_result_past_the_cap": [numbers[: MAX_LIST_ITEMS + 1]],
            "exactly_the_cap_together": [numbers[:32], numbers[32:MAX_LIST_ITEMS]],
            "each_under_the_cap_union_over": [numbers[:40], numbers[40:80]],
        }
        for name, parts in splits.items():
            with self.subTest(split=name):
                results = [
                    make_result(line=index + 1, properties={"cwe": [f"CWE-{n}" for n in part]})
                    for index, part in enumerate(parts)
                ]
                output = parse_direct(make_log(make_run(results)))
                item = only_observation(output)
                union = sorted({f"CWE-{n}" for part in parts for n in part})
                self.assertEqual(item.source_identifiers, tuple(union[:MAX_LIST_ITEMS]))
                cut = "source_identifiers" in json.loads(metadata(item).get("truncated", "[]"))
                self.assertEqual(cut, len(union) > MAX_LIST_ITEMS)
                self.assertEqual(
                    "evidence_truncated" in diagnostic_codes(output), len(union) > MAX_LIST_ITEMS
                )

    def test_shared_lists_cut_once_equal_the_cut_of_their_union(self) -> None:
        # Each run carries one part as its descriptor's tags and deprecatedIds and as its
        # repoDigests, in a shuffled order, and every run's result folds into one observation.
        for parts in fold_splits():
            with self.subTest(sizes=[len(part) for part in parts]):
                runs = [
                    make_run(
                        [make_result()],
                        rules=[{"id": "R1", "deprecatedIds": part, "properties": {"tags": part}}],
                        properties={"imageName": "registry.test/app", "repoDigests": part},
                    )
                    for part in parts
                ]
                fields = metadata(only_observation(parse_direct(make_log(*runs))))
                union = sorted({item for part in parts for item in part})
                truncated = json.loads(fields.get("truncated", "[]"))
                for member in ("rule_tags", "rule_deprecated_ids", "image_digests"):
                    self.assertEqual(json.loads(fields[member]), union[:MAX_LIST_ITEMS])
                    self.assertEqual(member in truncated, len(union) > MAX_LIST_ITEMS)

    def test_a_result_s_own_lists_cut_once_equal_the_cut_of_their_union(self) -> None:
        # Each result carries one part as its own lists and fingerprints, in a shuffled order,
        # and every result folds into one observation.
        for parts in fold_splits():
            with self.subTest(sizes=[len(part) for part in parts]):
                results = [
                    make_result(line=index + 1, **own_lists(part))
                    for index, part in enumerate(parts)
                ]
                fields = metadata(only_observation(parse_direct(make_log(make_run(results)))))
                union = sorted({item for part in parts for item in part})
                truncated = json.loads(fields.get("truncated", "[]"))
                for member, items in own_list_members(union[:MAX_LIST_ITEMS]).items():
                    self.assertEqual(json.loads(fields[member]), items)
                    self.assertEqual(member in truncated, len(union) > MAX_LIST_ITEMS)

    def test_result_without_a_region_sorts_before_regioned_results(self) -> None:
        results = [
            make_result(line=1, text="regioned"),
            make_result(line=None, text="no region"),
        ]
        output = ingest_document(make_log(make_run(results)))
        self.assertEqual(only_observation(output).description, "no region")

    def test_at_one_region_the_smaller_description_describes_whatever_the_order(self) -> None:
        # A missing column sorts as zero, and a location's message is no part of the order, so
        # at one region the result's own description decides (decision 9).
        first = make_result(line=3, text="a first")
        first["locations"][0]["message"] = {"text": "z location"}
        second = make_result(line=3, text="z second")
        second["locations"][0]["message"] = {"text": "a location"}
        columned = make_result(line=3, text="0 columned")
        columned["locations"][0]["physicalLocation"]["region"]["startColumn"] = 9
        for results in permutations((first, second, columned)):
            with self.subTest(order=[result["message"]["text"] for result in results]):
                output = ingest_document(make_log(make_run(list(results))))
                self.assertEqual(only_observation(output).description, "a first")

    def test_fold_across_runs_of_one_driver_records_both_run_indexes(self) -> None:
        output = ingest_document(make_log(make_run([make_result()]), make_run([make_result()])))
        item = only_observation(output)
        self.assertEqual(metadata(item)["run_indexes"], "[0,1]")
        self.assertEqual(metadata(item)["occurrence_count"], "2")

    def test_a_fold_across_runs_unions_each_run_s_descriptor_tags(self) -> None:
        # Each run's descriptor is its own, so lists of one length are still distinct lists.
        for first, second in ((["a"], ["b"]), (["x", "y"], ["p", "q"])):
            with self.subTest(tags=(first, second)):
                runs = [
                    make_run([make_result()], rules=[{"id": "R1", "properties": {"tags": tags}}])
                    for tags in (first, second)
                ]
                item = only_observation(ingest_document(make_log(*runs)))
                self.assertEqual(json.loads(metadata(item)["rule_tags"]), sorted([*first, *second]))

    def test_automation_category_splits_otherwise_identical_results(self) -> None:
        output = ingest_document(
            make_log(
                make_run([make_result()]),
                make_run([make_result()], automationDetails={"id": "cat/x/run-1"}),
            )
        )
        self.assertEqual(
            sorted(item.context_key for item in output.observations), ["Synth", "Synth|cat/x"]
        )
        self.assertEqual(len({item.observation_id for item in output.observations}), 2)

    def test_earliest_observed_at_wins_across_folded_results(self) -> None:
        results = [
            make_result(line=1, provenance={"firstDetectionTimeUtc": LATE}),
            make_result(line=2, provenance={"firstDetectionTimeUtc": EARLY}),
        ]
        output = ingest_document(make_log(make_run(results)))
        self.assertEqual(only_observation(output).observed_at, parse_timestamp(EARLY))

    def test_open_kind_outranks_pass_and_the_highest_level_wins(self) -> None:
        results = [
            make_result(line=1, kind="pass"),
            make_result(line=2, kind="fail", level="error"),
            make_result(line=3, kind="fail", level="note"),
        ]
        output = ingest_document(make_log(make_run(results)))
        item = only_observation(output)
        fields = metadata(item)
        self.assertIs(item.disposition, ObservationDisposition.OPEN)
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(fields["result_kind"], "fail")
        self.assertEqual(fields["result_kinds"], '["fail","pass"]')
        # The pass on line 1 is the primary; the level comes from the strongest result.
        self.assertEqual(fields["level"], "error")
        self.assertEqual(fields["level_source"], "result")

    def test_the_primary_describes_and_the_strongest_sets_the_severity(self) -> None:
        rules = [
            {"id": "R1", "shortDescription": {"text": "Pass title"}},
            {"id": "R1", "shortDescription": {"text": "Fail title"}},
        ]
        results = [
            make_result(
                ruleIndex=1,
                line=5,
                text="fail text",
                kind="fail",
                level="error",
                guid="G-FAIL",
                properties={"security-severity": "8.0"},
            ),
            make_result(
                ruleIndex=0, line=1, text="pass text", kind="pass", level="note", guid="G-PASS"
            ),
        ]
        item = only_observation(ingest_document(make_log(make_run(results, rules=rules))))
        fields = metadata(item)
        # The smallest region is the primary: its title, description, and guid describe.
        self.assertEqual(item.title, "Pass title")
        self.assertEqual(item.description, "pass text")
        self.assertEqual(fields["guid"], "G-PASS")
        # The strongest severity decides the level, its source, and the severity.
        self.assertEqual(fields["level"], "error")
        self.assertEqual(fields["level_source"], "result")
        self.assertEqual(fields["severity_source"], "security-severity")
        self.assertEqual(fields["security_severity"], "8.0")
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        # The worst disposition decides the kind.
        self.assertIs(item.disposition, ObservationDisposition.OPEN)
        self.assertEqual(fields["result_kind"], "fail")

    def test_fingerprints_fold_into_sorted_unique_pairs(self) -> None:
        results = [
            make_result(line=1, fingerprints={"x": "9"}, partialFingerprints={"c": "3", "a": "1"}),
            make_result(line=2, fingerprints={"x": "9"}, partialFingerprints={"b": "2", "a": "1"}),
        ]
        output = ingest_document(make_log(make_run(results)))
        fields = metadata(only_observation(output))
        self.assertEqual(fields["fingerprints"], '[["x","9"]]')
        self.assertEqual(fields["partial_fingerprints"], '[["a","1"],["b","2"],["c","3"]]')

    def test_one_accepted_suppression_marks_the_whole_fold(self) -> None:
        results = [
            make_result(line=1),
            make_result(line=2, suppressions=[{"kind": "inSource"}]),
        ]
        output = ingest_document(make_log(make_run(results)))
        self.assertEqual(metadata(only_observation(output))["suppressed"], "true")

    def test_lists_and_identifiers_only_a_later_result_carries_join_the_fold(self) -> None:
        results = [
            make_result(line=1),
            make_result(
                line=2,
                suppressions=[{"kind": "inSource"}],
                taxa=[{"id": "CWE-079"}],
                properties={"tags": ["GHSA-abcd-12ef-wxyz"]},
            ),
        ]
        item = only_observation(ingest_document(make_log(make_run(results))))
        fields = metadata(item)
        self.assertEqual(fields["suppressed"], "true")
        self.assertEqual(fields["suppression_kinds"], '["inSource"]')
        self.assertEqual(fields["taxa"], '["CWE-079"]')
        self.assertEqual(item.source_identifiers, ("CWE-79", "GHSA-abcd-12ef-wxyz"))

    def test_multi_location_result_yields_one_observation_per_uri(self) -> None:
        result = make_result(line=1, text="first")
        result["locations"].append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/a.py"},
                    "region": {"startLine": 5},
                },
                "message": {"text": "again"},
            }
        )
        result["locations"].append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/b.py"},
                    "region": {"startLine": 7},
                }
            }
        )
        output = ingest_document(make_log(make_run([result])))
        items = by_resource(output)
        self.assertEqual(sorted(items), ["src/a.py", "src/b.py"])
        self.assertEqual(metadata(items["src/a.py"])["regions"], '["1","5"]')
        self.assertEqual(metadata(items["src/a.py"])["location_messages"], '["5: again"]')
        self.assertEqual(metadata(items["src/b.py"])["regions"], '["7"]')

    def test_result_order_never_changes_the_canonical_output(self) -> None:
        results = [
            make_result(line=3, text="three", kind="fail", level="note"),
            make_result(line=1, text="one", provenance={"firstDetectionTimeUtc": LATE}),
            make_result(uri="src/b.py", line=2, text="other file", fingerprints={"k": "v"}),
        ]
        artifact = synthetic_artifact(make_log(make_run(results)))
        renderings = set()
        for order in permutations(results):
            output = parse_direct(make_log(make_run(list(order))), artifact)
            renderings.add(tuple(item.to_canonical_json() for item in output.observations))
        self.assertEqual(len(renderings), 1)
        self.assertEqual(len(next(iter(renderings))), 2)

    # Two clocks at each place a clock is read: every order of the two keeps the same text.
    def assert_every_order_keeps(self, spellings: Sequence[str], kept: str) -> None:
        layouts: dict[str, Callable[[Sequence[str]], dict[str, Any]]] = {
            "results": lambda order: make_log(
                make_run([make_result(provenance={"firstDetectionTimeUtc": at}) for at in order])
            ),
            "starts": lambda order: make_log(
                make_run([make_result()], invocations=[{"startTimeUtc": at} for at in order])
            ),
            "ends": lambda order: make_log(
                make_run([make_result()], invocations=[{"endTimeUtc": at} for at in order])
            ),
            "runs": lambda order: make_log(
                *(make_run([make_result()], invocations=[{"startTimeUtc": at}]) for at in order)
            ),
        }
        for name, layout in layouts.items():
            with self.subTest(layout=name):
                artifact = synthetic_artifact(layout(spellings))
                renderings = {
                    only_observation(parse_direct(layout(order), artifact)).to_canonical_json()
                    for order in permutations(spellings)
                }
                self.assertEqual(len(renderings), 1)
                observed = json.loads(next(iter(renderings)))["observed_at"]
                self.assertEqual(observed, kept)

    # One instant under two offsets keeps the spelling whose text sorts first.
    def test_one_instant_under_two_offsets_keeps_one_spelling_in_every_order(self) -> None:
        self.assert_every_order_keeps(
            ("2026-09-01T00:00:00Z", "2026-08-31T17:00:00-07:00"), "2026-08-31T17:00:00-07:00"
        )

    # The instant decides before the text does: 10:00+05:00 is 05:00Z, an hour before 06:00Z,
    # though its text sorts after it, and so do its wall-clock digits.
    def test_the_earlier_instant_wins_where_its_text_sorts_later(self) -> None:
        self.assert_every_order_keeps(
            ("2026-01-01T06:00:00Z", "2026-01-01T10:00:00+05:00"), "2026-01-01T10:00:00+05:00"
        )


# *--- Refusals ---*


class SarifRefusalTests(unittest.TestCase):
    """Malformed logs and unusable identity inputs refuse; the artifact is still attributed."""

    def assert_parse_failed(self, output: IngestResult, message: str) -> None:
        self.assertEqual(output.observations, ())
        self.assertEqual(attribution(output), SARIF_ATTRIBUTION)
        failed = only_diagnostic(output, "artifact_parse_failed")
        self.assertIs(failed.level, DiagnosticLevel.ERROR)
        self.assertEqual(failed.message, message)

    def test_root_that_is_not_an_object_is_refused(self) -> None:
        self.assert_parse_failed(ingest_document([]), "SARIF root must be a JSON object")

    def test_version_other_than_2_1_0_is_refused(self) -> None:
        for version in ("2.0.0", 2.1, None):
            with self.subTest(version=version):
                self.assert_parse_failed(
                    ingest_document(make_log(version=version)),
                    "SARIF version must be the string 2.1.0",
                )

    def test_runs_that_are_not_an_array_are_refused(self) -> None:
        for runs in (None, {}, "runs"):
            with self.subTest(runs=runs):
                self.assert_parse_failed(
                    ingest_document({"version": "2.1.0", "runs": runs}),
                    "SARIF runs must be an array",
                )

    def test_adapter_raises_adapter_parse_error_directly(self) -> None:
        with self.assertRaises(AdapterParseError):
            parse_direct({"version": "2.1.0", "runs": None})

    def test_empty_runs_array_yields_no_observations(self) -> None:
        output = ingest_document(make_log())
        self.assertEqual(output.observations, ())
        self.assertFalse(output.successful)
        self.assertEqual(
            [(item.level, item.code, item.message) for item in output.diagnostics],
            [(DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE)],
        )

    def test_run_that_is_not_an_object_is_an_invalid_run(self) -> None:
        output = ingest_document(make_log("nope"))
        self.assertEqual(
            only_diagnostic(output, "invalid_run").message,
            "run must be an object (1 occurrence: runs[0])",
        )
        self.assertIn("no_observations", diagnostic_codes(output))

    def test_results_that_are_not_an_array_are_an_invalid_run(self) -> None:
        for results in ("x", {"a": 1}, 5):
            with self.subTest(results=results):
                output = ingest_document(
                    make_log({"tool": {"driver": {"name": "Synth"}}, "results": results})
                )
                invalid = only_diagnostic(output, "invalid_run")
                self.assertIs(invalid.level, DiagnosticLevel.ERROR)
                self.assertEqual(
                    invalid.message, "run results must be an array (1 occurrence: runs[0])"
                )
                self.assertEqual(output.observations, ())

    def test_missing_or_blank_driver_name_is_an_invalid_run(self) -> None:
        runs = [
            {"results": [make_result()]},
            {"tool": {}, "results": [make_result()]},
            {"tool": {"driver": {"name": "  "}}, "results": [make_result()]},
            {"tool": {"driver": {"name": 7}}, "results": [make_result()]},
        ]
        for run in runs:
            with self.subTest(run=run):
                output = ingest_document(make_log(run))
                self.assertEqual(
                    only_diagnostic(output, "invalid_run").message,
                    "tool.driver.name is missing, not a string, or empty (1 occurrence: runs[0])",
                )

    def test_result_that_is_not_an_object_is_an_invalid_result(self) -> None:
        output = ingest_document(make_log(make_run([5])))
        invalid = only_diagnostic(output, "invalid_result")
        self.assertIs(invalid.level, DiagnosticLevel.ERROR)
        self.assertEqual(
            invalid.message, "result must be an object (1 occurrence: runs[0].results[0])"
        )

    def test_prohibited_code_points_in_identity_inputs_are_refused(self) -> None:
        cases = [
            (
                make_log(make_run([make_result()], driver="Sy\u200bnth")),
                "runs[0].tool.driver.name; first: driver name contains prohibited code point"
                " U+200B",
            ),
            (
                make_log(make_run([make_result(rule_id="R\x071")])),
                "runs[0].results[0]; first: rule identifier contains prohibited code point U+0007",
            ),
            (
                make_log(make_run([make_result(uri="src/a\u2028.py")])),
                "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri; "
                "first: location uri contains prohibited code point U+2028",
            ),
            (
                make_log(
                    make_run(
                        [
                            make_result(
                                uri=None,
                                locations=[
                                    {"logicalLocations": [{"fullyQualifiedName": "a\u2029b"}]}
                                ],
                            )
                        ]
                    )
                ),
                "runs[0].results[0].locations[0].logicalLocations; "
                "first: logical location name contains prohibited code point U+2029",
            ),
            (
                make_log(make_run([make_result()], automationDetails={"id": "a\tb"})),
                "runs[0].automationDetails.id; "
                "first: automation id contains prohibited code point U+0009",
            ),
        ]
        for document, detail in cases:
            with self.subTest(detail=detail):
                output = ingest_document(document)
                self.assertEqual(output.observations, ())
                self.assertFalse(output.successful)
                refused = only_diagnostic(output, "identity_input_invalid")
                self.assertIs(refused.level, DiagnosticLevel.ERROR)
                self.assertEqual(refused.message, f"{IDENTITY_MESSAGE} (1 occurrence: {detail})")

    def test_lone_surrogate_in_a_rule_id_is_refused_by_the_adapter(self) -> None:
        output = parse_direct(make_log(make_run([make_result(rule_id="R\ud800")])))
        self.assertEqual(output.observations, ())
        self.assertEqual(
            only_diagnostic(output, "identity_input_invalid").message,
            f"{IDENTITY_MESSAGE} (1 occurrence: runs[0].results[0]; "
            "first: rule identifier contains prohibited code point U+D800)",
        )

    def test_identity_inputs_over_their_caps_are_refused_never_cut(self) -> None:
        cases = [
            (
                make_log(make_run([make_result(rule_id="R" * (MAX_IDENTITY_CHARS + 1))])),
                f"runs[0].results[0]; first: rule identifier is {MAX_IDENTITY_CHARS + 1} "
                f"characters; maximum is {MAX_IDENTITY_CHARS}",
            ),
            (
                make_log(make_run([make_result(uri="u" * (MAX_URI_CHARS + 1))])),
                "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri; "
                f"first: location uri is {MAX_URI_CHARS + 1} characters; "
                f"maximum is {MAX_URI_CHARS}",
            ),
            (
                make_log(
                    make_run(
                        [make_result()], properties={"imageName": "i" * (MAX_IDENTITY_CHARS + 1)}
                    )
                ),
                f"runs[0].properties.imageName; first: image name is {MAX_IDENTITY_CHARS + 1} "
                f"characters; maximum is {MAX_IDENTITY_CHARS}",
            ),
            (
                make_log(
                    make_run(
                        [make_result(ruleIndex=0)],
                        rules=[{"id": "R1", "helpUri": "h" * (MAX_URI_CHARS + 1)}],
                    )
                ),
                f"runs[0].results[0].rule.helpUri; first: rule helpUri is {MAX_URI_CHARS + 1} "
                f"characters; maximum is {MAX_URI_CHARS}",
            ),
        ]
        for document, detail in cases:
            with self.subTest(detail=detail[:40]):
                output = ingest_document(document)
                self.assertEqual(output.observations, ())
                self.assertEqual(
                    only_diagnostic(output, "identity_input_invalid").message,
                    f"{IDENTITY_MESSAGE} (1 occurrence: {detail})",
                )

    def test_uri_exactly_at_the_cap_is_accepted_whole(self) -> None:
        uri = "u" * MAX_URI_CHARS
        output = ingest_document(make_log(make_run([make_result(uri=uri)])))
        item = only_observation(output)
        self.assertEqual(item.resource.resource_id, uri)
        self.assertEqual(metadata(item)["location_uri"], uri)
        self.assertNotIn("truncated", metadata(item))

    def test_one_refused_result_withholds_every_observation(self) -> None:
        results = [make_result(uri="src/good.py"), make_result(rule_id="R\x071", uri="src/bad.py")]
        output = ingest_document(make_log(make_run(results)))
        self.assertEqual(output.observations, ())
        self.assertFalse(output.successful)
        self.assertIn("identity_input_invalid", diagnostic_codes(output))

    def test_naive_ingested_at_is_rejected_before_reading(self) -> None:
        with self.assertRaisesRegex(ValueError, "ingested_at must include a timezone"):
            ingest_document(make_log(make_run([make_result()])), ingested_at=datetime(2026, 8, 18))


# *--- Degraded Evidence ---*


class SarifDegradedEvidenceTests(unittest.TestCase):
    """Evidence is cut, sanitized, or coalesced with a diagnostic; identity is never touched."""

    def test_coalesced_diagnostic_lists_at_most_the_path_cap(self) -> None:
        results = [make_result(line=index + 1, baselineState="new") for index in range(7)]
        output = ingest_document(make_log(make_run(results)))
        ignored = only_diagnostic(output, "baseline_state_ignored")
        listed = ", ".join(f"runs[0].results[{index}]" for index in range(MAX_DIAGNOSTIC_PATHS))
        self.assertEqual(
            ignored.message,
            "baselineState is recorded as metadata and never changes a disposition "
            f"(7 occurrences: {listed}, ...)",
        )

    def test_list_values_are_cut_at_the_item_cap_with_the_truncated_key(self) -> None:
        tags = [f"tag-{index:03d}" for index in range(MAX_LIST_ITEMS + 6)]
        rules = [{"id": "R1", "properties": {"tags": tags}}]
        output = ingest_document(make_log(make_run([make_result()], rules=rules)))
        fields = metadata(only_observation(output))
        kept = json.loads(fields["rule_tags"])
        self.assertEqual(len(kept), MAX_LIST_ITEMS)
        self.assertEqual(kept[-1], f"tag-{MAX_LIST_ITEMS - 1:03d}")
        self.assertEqual(fields["truncated"], '["rule_tags"]')
        self.assertEqual(
            only_diagnostic(output, "evidence_truncated").message,
            "evidence text was cut at its cap; the truncated metadata key names the members "
            "(1 occurrence: runs[0].results[0])",
        )

    def test_list_of_exactly_the_item_cap_stays_whole(self) -> None:
        tags = [f"tag-{index:03d}" for index in range(MAX_LIST_ITEMS)]
        rules = [{"id": "R1", "properties": {"tags": tags}}]
        output = ingest_document(make_log(make_run([make_result()], rules=rules)))
        fields = metadata(only_observation(output))
        self.assertEqual(json.loads(fields["rule_tags"]), tags)
        self.assertNotIn("truncated", fields)
        self.assertNotIn("evidence_truncated", diagnostic_codes(output))

    def test_title_and_description_are_cut_with_the_marker(self) -> None:
        rules = [{"id": "R1", "shortDescription": {"text": "t" * (MAX_TITLE_CHARS + 88)}}]
        output = ingest_document(
            make_log(make_run([make_result(text="d" * (MAX_DESCRIPTION_CHARS + 904))], rules=rules))
        )
        item = only_observation(output)
        self.assertEqual(len(item.title), MAX_TITLE_CHARS)
        self.assertEqual(len(item.description), MAX_DESCRIPTION_CHARS)
        self.assertTrue(item.title.endswith(TRUNCATION_MARKER))
        self.assertTrue(item.description.endswith(TRUNCATION_MARKER))
        self.assertEqual(metadata(item)["truncated"], '["description","title"]')
        self.assertEqual(
            only_diagnostic(output, "evidence_truncated").message,
            "evidence text was cut at its cap; the truncated metadata key names the members "
            "(2 occurrences: runs[0].results[0], runs[0].results[0])",
        )

    def test_scalar_metadata_and_list_items_are_cut_at_their_caps(self) -> None:
        run = make_run([make_result()])
        run["tool"]["driver"]["version"] = "v" * (MAX_METADATA_VALUE_CHARS + 88)
        output = ingest_document(make_log(run))
        fields = metadata(only_observation(output))
        self.assertEqual(len(fields["tool_version"]), MAX_METADATA_VALUE_CHARS)
        self.assertEqual(fields["truncated"], '["tool_version"]')

        # The message is cut to leave room for its region prefix: one marker, one cap.
        result = make_result()
        result["locations"][0]["message"] = {"text": "m" * (MAX_LIST_ITEM_CHARS + 44)}
        output = ingest_document(make_log(make_run([result])))
        fields = metadata(only_observation(output))
        messages = json.loads(fields["location_messages"])
        self.assertEqual(len(messages), 1)
        self.assertEqual(len(messages[0]), MAX_LIST_ITEM_CHARS)
        self.assertEqual(messages[0], "1: " + cut_item("m" * (MAX_LIST_ITEM_CHARS + 44), "1: "))
        self.assertEqual(messages[0].count(TRUNCATION_MARKER), 1)
        self.assertEqual(fields["truncated"], '["location_messages"]')

    def test_a_message_that_fits_beside_its_region_prefix_is_kept_whole(self) -> None:
        text = "m" * (MAX_LIST_ITEM_CHARS - len("1: "))
        result = make_result()
        result["locations"][0]["message"] = {"text": text}
        fields = metadata(only_observation(ingest_document(make_log(make_run([result])))))
        self.assertEqual(json.loads(fields["location_messages"]), ["1: " + text])
        self.assertNotIn("truncated", fields)

    def test_region_integers_past_the_signed_32_bit_range_are_absent(self) -> None:
        cases = [
            ({"startLine": MAX_REGION_INTEGER}, f"{MAX_REGION_INTEGER}"),
            ({"startLine": MAX_REGION_INTEGER + 1}, None),
            (
                {
                    "startLine": 5,
                    "startColumn": MAX_REGION_INTEGER + 1,
                    "endLine": MAX_REGION_INTEGER,
                    "endColumn": MAX_REGION_INTEGER + 1,
                },
                f"5-{MAX_REGION_INTEGER}",
            ),
        ]
        for region, expected in cases:
            with self.subTest(region=region):
                result = make_result(text="finding")
                result["locations"][0]["physicalLocation"]["region"] = region
                result["locations"][0]["message"] = {"text": "here"}
                fields = metadata(only_observation(ingest_document(make_log(make_run([result])))))
                if expected is None:
                    self.assertNotIn("regions", fields)
                    self.assertEqual(fields["location_messages"], '["here"]')
                else:
                    self.assertEqual(fields["regions"], json.dumps([expected]))
                    self.assertEqual(fields["location_messages"], json.dumps([f"{expected}: here"]))

    def test_four_thousand_digit_region_integers_leave_no_region_and_no_oversized_item(
        self,
    ) -> None:
        huge = 10**3999
        locations = []
        for index in range(MAX_LIST_ITEMS):
            # Half carry a huge start line; half carry a usable one beside huge columns and ends.
            region = (
                {"startLine": huge + index, "startColumn": 1}
                if index % 2 == 0
                else {
                    "startLine": index,
                    "startColumn": huge,
                    "endLine": huge,
                    "endColumn": huge,
                }
            )
            locations.append(
                {
                    "physicalLocation": {"artifactLocation": {"uri": "src/a.py"}, "region": region},
                    "message": {"text": numbered("m", index, OVER_ITEM)},
                }
            )
        result = make_result(locations=locations)
        output = ingest_document(make_log(make_run([result])))
        self.assertTrue(output.successful)
        fields = metadata(only_observation(output))
        regions = json.loads(fields["regions"])
        self.assertEqual(regions, [str(index) for index in range(1, MAX_LIST_ITEMS, 2)])
        messages = json.loads(fields["location_messages"])
        self.assertEqual(len(messages), MAX_LIST_ITEMS)
        for item in regions + messages:
            self.assertLessEqual(len(item), MAX_LIST_ITEM_CHARS)
        self.assertTrue(all(item.count(TRUNCATION_MARKER) == 1 for item in messages))

    def test_sanitize_strips_controls_and_formats_but_keeps_newlines(self) -> None:
        raw = "bidi \u202e text \u200b here\u2028next\x07"
        self.assertEqual(_sanitize(raw), ("bidi  text  here\nnext", True))
        self.assertEqual(_sanitize("plain text\n"), ("plain text\n", False))
        output = ingest_document(make_log(make_run([make_result(text=raw)])))
        item = only_observation(output)
        self.assertEqual(item.description, "bidi  text  here\nnext")
        self.assertEqual(
            only_diagnostic(output, "evidence_sanitized").message,
            "control, format, or separator characters were removed from evidence text "
            "(1 occurrence: runs[0].results[0])",
        )
        self.assertEqual(
            Observation.from_canonical_dict(json.loads(item.to_canonical_json())), item
        )

    def test_a_diagnostic_quotes_a_bounded_part_of_a_value(self) -> None:
        four = {"a": 1, "b": 2, "c": 3, "d": 4}
        small = ("fatal", "", 11, 10.5, True, None, [7], {"a": [1, "x"]}, {"b": 1, "a": [2]}, four)
        for value in small:
            with self.subTest(value=value):
                self.assertEqual(_quoted(value), repr(value))
        # One member past the four an object shows, and one level past the six it descends.
        nested: Any = 1
        for key in "gfedcba":
            nested = {key: nested}
        self.assertEqual(_quoted({**four, "e": 5}), "{'a': 1, 'b': 2, 'c': 3, 'd': 4, ...}")
        self.assertEqual(_quoted(nested), "{'a': {'b': {'c': {'d': {'e': {'f': {...}}}}}}}")
        text = "q" * ONE_MIB
        self.assertEqual(_quoted(text), repr(text[: MAX_METADATA_VALUE_CHARS + 1]))
        deep: Any = 1
        for _ in range(300):
            deep = {"k": deep}
        containers = {
            "long member": [text],
            "long value": {"k": text},
            "long key": {text: 1},
            "many members": list(range(ONE_MIB)),
            "deep object": deep,
        }
        for name, container in containers.items():
            with self.subTest(container=name):
                self.assertLessEqual(len(_quoted(container)), 2 * MAX_METADATA_VALUE_CHARS)

    def test_non_ascii_letters_survive_in_evidence_and_lists(self) -> None:
        rules = [{"id": "R1", "properties": {"tags": ["caf\u00e9"]}}]
        output = ingest_document(
            make_log(make_run([make_result(text="caf\u00e9 au lait")], rules=rules))
        )
        item = only_observation(output)
        self.assertEqual(item.description, "caf\u00e9 au lait")
        self.assertEqual(metadata(item)["rule_tags"], '["caf\u00e9"]')
        self.assertNotIn("evidence_sanitized", diagnostic_codes(output))

    def test_observation_over_the_json_byte_cap_fails_the_artifact(self) -> None:
        # The ceiling is checked before the budget, so an observation past both names itself.
        document = make_log(make_run([make_result(text="x" * 400)]))
        for budget in (None, 100):
            with self.subTest(budget=budget):
                limits = IngestLimits(max_observation_bytes_per_artifact=budget) if budget else None
                with mock.patch.object(sarif_module, "MAX_OBSERVATION_JSON_BYTES", 500):
                    output = ingest_document(document, limits=limits)
                self.assertEqual(output.observations, ())
                failed = only_diagnostic(output, "artifact_parse_failed")
                self.assertRegex(
                    failed.message,
                    r"^observation obs-[0-9a-f]{64} is \d+ bytes of canonical JSON; "
                    r"maximum is 500$",
                )
                self.assertEqual(attribution(output), SARIF_ATTRIBUTION)

    def test_locations_over_the_cap_fail_the_artifact(self) -> None:
        result = make_result()
        result["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/{index}.py"}}}
            for index in range(MAX_LOCATIONS_PER_RESULT + 1)
        ]
        output = ingest_document(make_log(make_run([result])))
        self.assertEqual(
            only_diagnostic(output, "artifact_parse_failed").message,
            f"runs[0].results[0] carries {MAX_LOCATIONS_PER_RESULT + 1} locations; "
            f"maximum is {MAX_LOCATIONS_PER_RESULT}",
        )

    def test_results_per_run_and_observations_per_artifact_limits_fail_the_artifact(self) -> None:
        results = [make_result(uri=f"src/{index}.py") for index in range(3)]
        output = ingest_document(
            make_log(make_run(results)), limits=IngestLimits(max_results_per_run=2)
        )
        self.assertEqual(
            only_diagnostic(output, "artifact_parse_failed").message,
            "runs[0] contains 3 results; maximum is 2",
        )
        output = ingest_document(
            make_log(make_run(results)), limits=IngestLimits(max_observations_per_artifact=2)
        )
        self.assertEqual(
            only_diagnostic(output, "artifact_parse_failed").message,
            "artifact yields more than 2 observations",
        )

    def test_the_observation_byte_budget_is_the_sum_of_every_observation(self) -> None:
        # Three results fold into three observations. A budget one byte under their sum is
        # larger than any one of them, so only a sum refuses it.
        document = make_log(make_run([make_result(uri=f"src/{index}.py") for index in range(3)]))
        sizes = [
            len(item.to_canonical_json().encode("utf-8"))
            for item in ingest_document(document).observations
        ]
        self.assertEqual(len(sizes), 3)
        self.assertGreater(sum(sizes) - 1, max(sizes))
        output = ingest_document(
            document, limits=IngestLimits(max_observation_bytes_per_artifact=sum(sizes))
        )
        self.assertEqual(len(output.observations), 3)
        budget = sum(sizes) - 1
        output = ingest_document(
            document, limits=IngestLimits(max_observation_bytes_per_artifact=budget)
        )
        self.assertEqual(output.observations, ())
        self.assertEqual(
            only_diagnostic(output, "artifact_parse_failed").message,
            f"artifact yields more than {budget} bytes of observation JSON",
        )
        self.assertEqual(attribution(output), SARIF_ATTRIBUTION)

    def test_the_observation_byte_budget_counts_bytes_not_characters(self) -> None:
        # Canonical JSON keeps non-ASCII text as it is, so each e-acute costs two bytes, and
        # a budget one byte under the observation still passes its character count.
        document = make_log(make_run([make_result(text="\u00e9" * 400)]))
        text = only_observation(ingest_document(document)).to_canonical_json()
        size = len(text.encode("utf-8"))
        self.assertGreaterEqual(size - len(text), 400)
        output = ingest_document(
            document, limits=IngestLimits(max_observation_bytes_per_artifact=size)
        )
        self.assertEqual(len(output.observations), 1)
        budget = size - 1
        output = ingest_document(
            document, limits=IngestLimits(max_observation_bytes_per_artifact=budget)
        )
        self.assertEqual(output.observations, ())
        self.assertEqual(
            only_diagnostic(output, "artifact_parse_failed").message,
            f"artifact yields more than {budget} bytes of observation JSON",
        )

    def test_the_observation_byte_budget_stops_the_fold_where_it_is_passed(self) -> None:
        # The sum is checked as each observation is built, so no fold past the budget runs.
        document = make_log(make_run([make_result(uri=f"src/{index}.py") for index in range(3)]))
        adapter = SarifAdapter(IngestLimits(max_observation_bytes_per_artifact=1))
        assemble = sarif_module._ArtifactParse._assemble
        with mock.patch.object(
            sarif_module._ArtifactParse, "_assemble", autospec=True, side_effect=assemble
        ) as assembler:
            with self.assertRaisesRegex(
                InputLimitError, "^artifact yields more than 1 bytes of observation JSON$"
            ):
                adapter.parse(
                    ParsedDocument("json", document), synthetic_artifact(document), ingested_at=NOW
                )
        self.assertEqual(assembler.call_count, 1)

    def test_json_node_limit_surfaces_as_a_parse_failure(self) -> None:
        output = ingest_document(
            make_log(make_run([make_result()])), limits=IngestLimits(max_json_nodes=5)
        )
        self.assertEqual(
            only_diagnostic(output, "artifact_parse_failed").message,
            "JSON contains more than 5 values",
        )
        self.assertEqual(attribution(output), SARIF_ATTRIBUTION)

    def test_nesting_past_the_depth_limit_surfaces_as_a_parse_failure(self) -> None:
        # A property bag is the one place a producer nests as deep as it likes.
        depth = IngestLimits().max_json_depth
        deep: Any = 1
        for _ in range(depth):
            deep = {"k": deep}
        output = ingest_document(make_log(make_run([make_result(properties=deep)])))
        self.assertEqual(output.observations, ())
        self.assertEqual(
            only_diagnostic(output, "artifact_parse_failed").message,
            f"JSON nesting exceeds {depth} levels",
        )
        self.assertEqual(attribution(output), SARIF_ATTRIBUTION)
        # A million levels is refused too, by the depth cap or by the recursion guard before
        # it, whichever this interpreter's parser reaches first.
        flood = b'{"version": "2.1.0", "runs": [], "properties": ' + b"[" * 1_000_000
        output = ingest_document(None, raw=flood + b"]" * 1_000_000 + b"}")
        self.assertEqual(output.observations, ())
        refused = only_diagnostic(output, "artifact_parse_failed")
        self.assertIs(refused.level, DiagnosticLevel.ERROR)
        self.assertTrue(refused.message.startswith("JSON nesting exceeds "), refused.message)

    def test_a_duplicate_object_key_surfaces_as_a_parse_failure(self) -> None:
        # Two driver names would give one run two identities, so neither is chosen.
        raw = b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "a", "name": "b"}}}]}'
        output = ingest_document(None, raw=raw)
        self.assertEqual(output.observations, ())
        self.assertEqual(
            only_diagnostic(output, "artifact_parse_failed").message,
            "duplicate JSON object key is prohibited: name",
        )
        self.assertEqual(attribution(output), SARIF_ATTRIBUTION)

    def test_message_expansion_substitutes_once_and_keeps_literals(self) -> None:
        arguments = ["A", "B"] + ["C"] * 30 + ["D"]
        self.assertEqual(
            _expand_message("{0} {{x}} {2} {{{0}}} {abc} }} { {32} {31}", arguments),
            ("A {x} C {A} {abc} } { {32} C", False),
        )
        self.assertEqual(_expand_message("{0}", ["{1}-X", "never"]), ("{1}-X", False))
        self.assertEqual(_expand_message("{0}", [7]), ("{0}", False))
        self.assertEqual(_expand_message("{0}", []), ("{0}", False))
        # Only ASCII digits make a placeholder; another script's zero stays literal text.
        self.assertEqual(_expand_message("{\u0660} {0}", ["a"]), ("{\u0660} a", False))
        # The budget is one past the description cap so the caller's cut adds the marker, and
        # an expansion is cut once text is left unproduced at the budget.
        self.assertEqual(
            _expand_message("{0}{0}", ["x" * 3000]), ("x" * (MAX_DESCRIPTION_CHARS + 1), True)
        )
        expanded, cut = _expand_message("{0}{0}", ["y" * (MAX_DESCRIPTION_CHARS + 1)])
        self.assertEqual((len(expanded), cut), (MAX_DESCRIPTION_CHARS + 1, True))
        fits = "z" * (MAX_DESCRIPTION_CHARS + 1)
        self.assertEqual(_expand_message("{0}", [fits]), (fits, False))
        self.assertEqual(_expand_message("{0}", [fits + "z"]), (fits, True))
        self.assertEqual(_expand_message(fits, []), (fits, False))
        self.assertEqual(_expand_message(fits + " ", []), (fits, True))

    def test_message_expansion_stops_at_the_placeholder_cap(self) -> None:
        at_cap = "{0}" * MAX_MESSAGE_PLACEHOLDERS
        self.assertEqual(
            _expand_message(at_cap + "tail", ["a"]),
            ("a" * MAX_MESSAGE_PLACEHOLDERS + "tail", False),
        )
        self.assertEqual(
            _expand_message(at_cap + "{0}tail", ["a"]), ("a" * MAX_MESSAGE_PLACEHOLDERS, True)
        )
        # A placeholder that is kept verbatim still counts, and a literal brace does not.
        self.assertEqual(
            _expand_message(at_cap + "{0}", [7]), ("{0}" * MAX_MESSAGE_PLACEHOLDERS, True)
        )
        self.assertEqual(_expand_message("{" * 2000 + "{x}", []), ("{" * 1000 + "{x}", False))
        # The budget ends the pass before the cap can when each placeholder adds text.
        self.assertEqual(
            _expand_message("{0}" * (MAX_MESSAGE_PLACEHOLDERS + 1), ["abcde"]),
            (("abcde" * MAX_MESSAGE_PLACEHOLDERS)[: MAX_DESCRIPTION_CHARS + 1], True),
        )

    def test_a_cut_expansion_keeps_its_marker_when_cleaning_shortens_it(self) -> None:
        # Stripping or sanitizing can bring the text read back under the cap; the text past
        # the budget was never read, so the description is still marked as cut.
        kept = MAX_DESCRIPTION_CHARS - len(TRUNCATION_MARKER)
        cases = {
            "a" * MAX_DESCRIPTION_CHARS + " " + "b" * 10_000: (
                "a" * kept + TRUNCATION_MARKER,
                ["evidence_truncated"],
            ),
            "a" * 4_000 + "\u200b" * 97 + "b" * 10_000: (
                "a" * 4_000 + TRUNCATION_MARKER,
                ["evidence_sanitized", "evidence_truncated"],
            ),
        }
        for text, (description, codes) in cases.items():
            with self.subTest(length=len(text)):
                output = ingest_document(make_log(make_run([make_result(text=text)])))
                item = only_observation(output)
                self.assertEqual(item.description, description)
                self.assertEqual(metadata(item)["truncated"], '["description"]')
                self.assertEqual(evidence_codes(output), codes)
        # A message read to its end is not cut, even at one past the cap before stripping.
        output = ingest_document(
            make_log(make_run([make_result(text="a" * MAX_DESCRIPTION_CHARS + " ")]))
        )
        item = only_observation(output)
        self.assertEqual(item.description, "a" * MAX_DESCRIPTION_CHARS)
        self.assertNotIn("truncated", metadata(item))
        self.assertEqual(evidence_codes(output), [])

    def test_message_id_resolves_through_the_rule_and_links_flatten(self) -> None:
        rules = [
            {
                "id": "R1",
                "messageStrings": {"hit": {"text": "Found {0} [link here](1)"}},
                "fullDescription": {"text": "Full text"},
            }
        ]
        results = [
            make_result(ruleIndex=0, text=None, message={"id": "hit", "arguments": ["needle"]}),
            make_result(ruleIndex=0, uri="src/b.py", text=None, message={}),
            make_result(ruleIndex=0, uri="src/c.py", text=None),
        ]
        output = ingest_document(make_log(make_run(results, rules=rules)))
        items = by_resource(output)
        self.assertEqual(items["src/a.py"].description, "Found needle link here")
        self.assertEqual(items["src/b.py"].description, "Full text")
        self.assertEqual(items["src/c.py"].description, "Full text")

    def test_link_text_unescapes_brackets_and_backslashes_as_spec_3_11_6_writes_it(self) -> None:
        # The spec's EXAMPLE 1 as printed has no closing bracket, so its link is unterminated;
        # with the bracket its grammar asks for, it renders as the spec says.
        example = r"Prohibited term used in [para\[0\]\\spans\[2\](1)."
        flattened = (
            (
                r"Prohibited term used in [para\[0\]\\spans\[2\]](1).",
                r"Prohibited term used in para[0]\spans[2].",
            ),
            (r"See [a\[b](1) here", "See a[b here"),
            (r"See [a\]b](1) here", "See a]b here"),
            (r"Path [C:\\dir](2) used", r"Path C:\dir used"),
            (r"Path [C:\dir\file](2) used", r"Path C:\dir\file used"),
            (r"See [a[b](1) here", "See [ab here"),
            (r"Keep \[this\] and \\ [here](1)", r"Keep \[this\] and \\ here"),
            (r"See [a](1) and [b", "See a and [b"),
        )
        # URI links, unterminated links, and bracketed text alone stay as written.
        kept = (
            example,
            "See [the docs](https://example.test/a) here",
            "See [open(1) here",
            r"See [open\](1) here",
            "A [bracketed] word",
            "See [too far](1234567890) here",
            "Ends in [a backslash\\",
        )
        cases = (*flattened, *((text, text) for text in kept))
        for text, expected in cases:
            with self.subTest(text=text):
                output = ingest_document(make_log(make_run([make_result(text=text)])))
                self.assertEqual(only_observation(output).description, expected)

    def test_a_bracket_flood_in_link_text_is_read_once(self) -> None:
        # Rereading from each bracket of an abandoned or unlinked text, escaped or not, reads
        # the text once per bracket, for hours.
        escaped = "[" + "\\[" * LINK_FLOOD
        for text in (escaped, escaped + "[", escaped + "]", "[" * LINK_FLOOD):
            with self.subTest(start=text[:3], end=text[-1]):
                started = time.perf_counter()
                flattened = _flatten_links(text)
                self.assertLess(time.perf_counter() - started, SHARED_WORK_CEILING)
                self.assertEqual(flattened, text)

    def test_each_message_id_resolves_to_its_own_template(self) -> None:
        rules = [
            {
                "id": "R1",
                "messageStrings": {"m1": {"text": "one"}, "m2": {"text": "two"}},
                "fullDescription": {"text": "Full text"},
            }
        ]
        results = [
            make_result(uri=f"src/{name}.py", text=None, message={"id": name})
            for name in ("m1", "m2")
        ]
        output = ingest_document(make_log(make_run(results, rules=rules)))
        descriptions = {key: item.description for key, item in by_resource(output).items()}
        self.assertEqual(descriptions, {"src/m1.py": "one", "src/m2.py": "two"})
        # An id that misses the component's table first must not hide one that is in it.
        results = [
            make_result(uri=f"src/{name}.py", text=None, message={"id": name})
            for name in ("missing", "global")
        ]
        run = make_run(results, rules=rules)
        run["tool"]["driver"]["globalMessageStrings"] = {"global": {"text": "Global text"}}
        output = ingest_document(make_log(run))
        descriptions = {key: item.description for key, item in by_resource(output).items()}
        self.assertEqual(
            descriptions, {"src/missing.py": "Full text", "src/global.py": "Global text"}
        )

    def test_result_without_any_message_or_description_has_an_empty_description(self) -> None:
        output = ingest_document(make_log(make_run([make_result(text=None)])))
        self.assertEqual(only_observation(output).description, "")


# *--- Run Diagnostics ---*


class SarifRunDiagnosticTests(unittest.TestCase):
    """Empty, absent, null, failed, and external-property runs each speak once."""

    def test_empty_results_array_is_a_clean_run(self) -> None:
        output = ingest_document(make_log(make_run()))
        self.assertEqual(
            [(item.level, item.code, item.message) for item in output.diagnostics],
            [
                (
                    DiagnosticLevel.INFO,
                    "run_clean",
                    "run reports no results (1 occurrence: runs[0])",
                ),
                (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
            ],
        )
        self.assertFalse(output.successful)

    def test_absent_and_null_results_are_unknown_and_skipped(self) -> None:
        for run in (
            {"tool": {"driver": {"name": "Synth"}}},
            {"tool": {"driver": {"name": "Synth"}}, "results": None},
        ):
            with self.subTest(run=run):
                output = ingest_document(make_log(run))
                unknown = only_diagnostic(output, "results_unknown")
                self.assertIs(unknown.level, DiagnosticLevel.WARNING)
                self.assertEqual(
                    unknown.message,
                    "run declares no results array; its results are unknown and the run is "
                    "skipped (1 occurrence: runs[0])",
                )
                self.assertIn("no_observations", diagnostic_codes(output))

    def test_clean_run_beside_a_productive_run_keeps_the_artifact_successful(self) -> None:
        output = ingest_document(make_log(make_run(), make_run([make_result()])))
        self.assertTrue(output.successful)
        self.assertEqual(metadata(only_observation(output))["run_indexes"], "[1]")
        self.assertIn("run_clean", diagnostic_codes(output))
        self.assertNotIn("no_observations", diagnostic_codes(output))

    def test_failed_invocation_still_reads_its_results(self) -> None:
        output = ingest_document(
            make_log(make_run([make_result()], invocations=[{"executionSuccessful": False}]))
        )
        self.assertEqual(len(output.observations), 1)
        self.assertTrue(output.successful)
        unsuccessful = only_diagnostic(output, "execution_unsuccessful")
        self.assertIs(unsuccessful.level, DiagnosticLevel.WARNING)
        self.assertEqual(
            unsuccessful.message,
            "invocation reports executionSuccessful false; its results are still read "
            "(1 occurrence: runs[0].invocations[0])",
        )

    def test_external_property_files_are_never_opened(self) -> None:
        references = {
            "results": [
                {"location": {"uri": "file:///nonexistent/ext.sarif"}, "itemCount": 1},
                {"location": {"uri": "ext/results.sarif-external-properties"}},
            ]
        }
        payload = make_log(make_run([make_result()], externalPropertyFileReferences=references))
        # The artifact is built first; only the adapter's parse runs with opening refused.
        artifact = synthetic_artifact(payload)
        with (
            mock.patch("builtins.open", side_effect=AssertionError("builtins.open")) as opened,
            mock.patch.object(Path, "open", side_effect=AssertionError("Path.open")) as path_opened,
        ):
            output = parse_direct(payload, artifact)
        opened.assert_not_called()
        path_opened.assert_not_called()
        item = only_observation(output)
        self.assertEqual(item.resource.resource_id, "src/a.py")
        self.assertEqual(item.description, "finding")
        ignored = only_diagnostic(output, "external_properties_ignored")
        self.assertIs(ignored.level, DiagnosticLevel.WARNING)
        self.assertEqual(
            ignored.message,
            "externalPropertyFileReferences is present; external files are never opened "
            "(1 occurrence: runs[0])",
        )

    def test_repo_digests_alone_name_the_image(self) -> None:
        output = ingest_document(
            make_log(make_run([make_result()], properties={"repoDigests": ["img@sha256:abc"]}))
        )
        item = only_observation(output)
        self.assertEqual(item.resource.resource_type, "image")
        self.assertEqual(item.resource.resource_id, "img@sha256:abc/src/a.py")
        self.assertEqual(metadata(item)["image_name"], "img@sha256:abc")
        self.assertEqual(metadata(item)["image_digests"], '["img@sha256:abc"]')

    def test_repo_digests_report_their_cleaning_at_the_run(self) -> None:
        digests = ["sha\x07x", "y" * (MAX_LIST_ITEM_CHARS + 1)]
        properties = {"imageName": "registry.test/app", "repoDigests": digests}
        # Two results share the run's list, which is cleaned once, so each report names the run
        # once however many results carry the list.
        results = [make_result(uri=f"src/{index}.py") for index in range(2)]
        output = ingest_document(make_log(make_run(results, properties=properties)))
        self.assertEqual(len(output.observations), 2)
        for item in output.observations:
            fields = metadata(item)
            kept = json.loads(fields["image_digests"])
            self.assertEqual(kept[0], "shax")
            self.assertEqual(len(kept[1]), MAX_LIST_ITEM_CHARS)
            self.assertTrue(kept[1].endswith(TRUNCATION_MARKER))
            self.assertEqual(fields["truncated"], '["image_digests"]')
        self.assertEqual(
            only_diagnostic(output, "evidence_sanitized").message,
            "control, format, or separator characters were removed from evidence text "
            "(1 occurrence: runs[0])",
        )
        self.assertEqual(
            only_diagnostic(output, "evidence_truncated").message,
            "evidence text was cut at its cap; the truncated metadata key names the members "
            "(1 occurrence: runs[0])",
        )

    def test_unknown_uri_base_id_is_recorded_without_a_base(self) -> None:
        result = make_result()
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "ELSEWHERE"
        output = ingest_document(make_log(make_run([result])))
        fields = metadata(only_observation(output))
        self.assertEqual(fields["uri_base_id"], "ELSEWHERE")
        self.assertNotIn("uri_base", fields)

    def test_each_artifact_index_and_uri_base_id_resolves_to_its_own_uri(self) -> None:
        def located(**artifact_location: Any) -> dict[str, Any]:
            location = {"physicalLocation": {"artifactLocation": artifact_location}}
            return make_result(uri=None, locations=[location])

        indexed = [located(index=0), located(index=1)]
        artifacts = [{"location": {"uri": "a.py"}}, {"location": {"uri": "b.py"}}]
        output = ingest_document(make_log(make_run(indexed, artifacts=artifacts)))
        self.assertEqual(sorted(by_resource(output)), ["a.py", "b.py"])
        based = [located(uri="a.py", uriBaseId="A"), located(uri="b.py", uriBaseId="B")]
        bases = {"A": {"uri": "file:///a/"}, "B": {"uri": "file:///b/"}}
        output = ingest_document(make_log(make_run(based, originalUriBaseIds=bases)))
        self.assertEqual(
            {key: metadata(item)["uri_base"] for key, item in by_resource(output).items()},
            {"a.py": "file:///a/", "b.py": "file:///b/"},
        )

    def test_artifact_index_supplies_the_uri_without_a_base_id(self) -> None:
        result = make_result(uri=None)
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"index": 0}}}]
        output = ingest_document(
            make_log(make_run([result], artifacts=[{"location": {"uri": "from/index.py"}}]))
        )
        item = only_observation(output)
        self.assertEqual(item.resource.resource_id, "from/index.py")
        self.assertNotIn("uri_base_id", metadata(item))


# *--- Tracking Ids ---*


class SarifTrackingIdTests(unittest.TestCase):
    """ADR 0007 tracking ids over SARIF source type, record, and context."""

    def test_pinned_tracking_ids(self) -> None:
        cases = [
            ("CVE-2024-0001", "Trivy", "case-10f5974d95a33fdf"),
            ("CVE-2024-0002", "Trivy", "case-889c19760e425785"),
            (
                "python.lang.security.audit.exec-detected.exec-detected",
                "Semgrep OSS",
                "case-5cfbebe8d4b91c27",
            ),
            ("js/xss-through-dom", "CodeQL|nightly/lint", "case-d2b9f5abf1fe44ac"),
        ]
        for record, context, expected in cases:
            with self.subTest(record=record):
                self.assertEqual(tracking_id_for(SARIF_SOURCE_TYPE, record, context), expected)

    def test_tracking_id_ignores_the_resource_and_the_artifact(self) -> None:
        trivy = ingest_fixture("trivy-image.sarif").observations
        self.assertEqual(
            {
                tracking_id_for(item.source_type, item.source_record_id, item.context_key)
                for item in trivy[:2]
            },
            {"case-10f5974d95a33fdf"},
        )
        self.assertNotEqual(trivy[0].observation_id, trivy[1].observation_id)


# *--- Goldens ---*


class SarifGoldenTests(unittest.TestCase):
    """The SARIF goldens are the stateless compile of the three tool fixtures, byte for byte.

    `tests/golden/vdt-sarif.json` and `vdt-sarif.md` were generated through the command
    line with the options `report_options` names; the compiler reproduces them here, and
    every value they carry traces to a rule in ADR 0011.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = compile_sarif_golden()
        cls.document = cls.report.document

    def test_the_json_golden_is_reproduced_byte_for_byte(self) -> None:
        self.assertEqual(
            self.report.to_json().encode("utf-8"), (GOLDEN / "vdt-sarif.json").read_bytes()
        )

    def test_the_markdown_golden_is_reproduced_byte_for_byte(self) -> None:
        self.assertEqual(
            self.report.to_markdown().encode("utf-8"), (GOLDEN / "vdt-sarif.md").read_bytes()
        )

    def test_compiling_twice_yields_identical_bytes(self) -> None:
        again = compile_sarif_golden()
        self.assertEqual(again.to_json(), self.report.to_json())
        self.assertEqual(again.to_markdown(), self.report.to_markdown())

    def test_the_golden_validates_against_the_official_schema(self) -> None:
        self.assertTrue(self.report.validation.is_valid)
        self.assertEqual(self.report.validation.issues, ())

    def test_the_summary_totals_reconcile_with_the_vulnerabilities(self) -> None:
        counts = summary_counts(self.report.to_markdown())
        reported = len(self.document["vulnerabilities"])
        self.assertEqual(reported, len(GOLDEN_TRACKING_IDS))
        self.assertEqual(counts["Vulnerabilities reported"], reported)
        self.assertEqual(counts["Evaluated"], 0)
        self.assertEqual(counts["Not yet evaluated"], reported)
        self.assertEqual(counts["Overdue"], reported)
        self.assertEqual(counts["Accepted, reported under VER-RPT-AVI"], 0)
        self.assertEqual(counts["Excluded by report period"], 0)
        self.assertEqual(self.document["x-complyroll"]["excludedByPeriod"], 0)
        attestation = self.document["x-complyroll"]["detectionTimeAttestation"]
        self.assertEqual(attestation["detectedAt"], "2026-09-01T00:00:00Z")
        self.assertEqual(attestation["count"], len(attestation["appliedTo"]))
        self.assertEqual(tuple(attestation["appliedTo"]), CLOCKLESS_TRACKING_IDS)

    def test_exactly_one_unresolved_observation_is_warned_about(self) -> None:
        unresolved = [
            item for item in self.report.diagnostics if item.code == "unresolved_observation"
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0].level.value, "warning")
        self.assertEqual(unresolved[0].location, "codeql-repo.sarif")
        self.assertEqual(
            unresolved[0].message,
            "js/xss-through-dom on https://github.com/example/webapp/src/ui/legacy.js has "
            "disposition unknown and was not reported as a vulnerability",
        )
        recorded = [
            item
            for item in self.document["x-complyroll"]["diagnostics"]
            if item["code"] == "unresolved_observation"
        ]
        self.assertEqual(len(recorded), 1)

    def test_every_worked_tracking_id_is_reported_in_golden_order(self) -> None:
        reported = [item["providerTrackingId"] for item in self.document["vulnerabilities"]]
        self.assertEqual(reported, list(GOLDEN_TRACKING_IDS))
        for tracking_id in WORKED_TRACKING_IDS:
            with self.subTest(tracking_id=tracking_id):
                self.assertIn(tracking_id, reported)

    def test_the_golden_attributes_the_sarif_parser_and_its_three_inputs(self) -> None:
        extension = self.document["x-complyroll"]
        self.assertEqual(extension["parserVersions"], {"complyroll.sarif": SARIF_PARSER_VERSION})
        self.assertEqual(
            [
                (item["name"], item["parser"], item["observationCount"])
                for item in extension["artifacts"]
            ],
            [
                ("codeql-repo.sarif", "complyroll.sarif", len(CODEQL_IDS)),
                ("semgrep-code.sarif", "complyroll.sarif", len(SEMGREP_IDS)),
                ("trivy-image.sarif", "complyroll.sarif", len(TRIVY_IDS)),
            ],
        )


# *--- Identity Stability ---*


class SarifIdentityStabilityTests(unittest.TestCase):
    """Identity survives a second ingest, a rename, a reorder, a rewording, and a run swap."""

    def test_identical_bytes_at_a_second_ingest_reproduce_every_id(self) -> None:
        for name, expected in FIXTURE_IDS.items():
            with self.subTest(fixture=name):
                first = ingest_fixture(name).observations
                second = ingest_stig_artifact(
                    FIXTURES / name, ingested_at=SECOND_INGEST
                ).observations
                self.assertEqual([item.observation_id for item in second], list(expected))
                self.assertEqual(
                    [item.fingerprint for item in second], [item.fingerprint for item in first]
                )
                self.assertEqual({item.ingested_at for item in second}, {SECOND_INGEST})

    def test_the_location_less_corner_result_keeps_its_id_under_two_filenames(self) -> None:
        content = (FIXTURES / "sarif-spec-corners.sarif").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            copies = []
            for name in ("first-copy.sarif", "second-copy.sarif"):
                path = Path(directory) / name
                path.write_bytes(content)
                copies.append(ingest_stig_artifact(path, ingested_at=SECOND_INGEST))
        first, second = (location_less(result) for result in copies)
        self.assertEqual(first.source_artifact_name, "first-copy.sarif")
        self.assertEqual(second.source_artifact_name, "second-copy.sarif")
        self.assertEqual(first.observation_id, CORNER_NOLOC_ID)
        self.assertEqual(second.observation_id, first.observation_id)
        self.assertEqual(second.fingerprint, first.fingerprint)
        self.assertEqual(
            (first.resource.resource_type, first.resource.resource_id), ("scan", "SpecCorners")
        )
        # The name is provenance, not identity: every corner id is the pinned one under both.
        for result in copies:
            self.assertEqual(
                [item.observation_id for item in result.observations], list(CORNER_IDS)
            )

    def test_reordered_and_reworded_copies_keep_identity_and_the_chosen_description(self) -> None:
        for name, positions in REWORDED_RESULTS.items():
            with self.subTest(fixture=name):
                original = ingest_fixture(name).observations
                with tempfile.TemporaryDirectory() as directory:
                    copy = Path(directory) / name
                    copy.write_text(json.dumps(reordered_and_reworded(name, positions)))
                    rewritten = ingest_stig_artifact(copy, ingested_at=NOW).observations
                self.assertEqual(
                    sorted(map(identity_of, rewritten)), sorted(map(identity_of, original))
                )
                self.assertEqual(
                    sorted(map(tracking_id_of, rewritten)), sorted(map(tracking_id_of, original))
                )
                self.assertEqual(
                    {identity_of(item): (item.title, item.description) for item in rewritten},
                    {identity_of(item): (item.title, item.description) for item in original},
                )
                # The bytes changed, so the artifact digest and with it every observation id.
                self.assertTrue(
                    {item.observation_id for item in rewritten}.isdisjoint(
                        item.observation_id for item in original
                    )
                )

    def test_reordered_copies_under_the_original_provenance_are_canonically_identical(
        self,
    ) -> None:
        for name, positions in REWORDED_RESULTS.items():
            with self.subTest(fixture=name):
                artifact = provenance_of(FIXTURES / name)
                original = parse_direct(fixture_payload(name), artifact)
                rewritten = parse_direct(reordered_and_reworded(name, positions), artifact)
                self.assertEqual(
                    [item.to_canonical_json() for item in rewritten.observations],
                    [item.to_canonical_json() for item in original.observations],
                )

    def test_swapped_runs_keep_tracking_ids(self) -> None:
        payload = fixture_payload("sarif-spec-corners.sarif")
        payload["runs"].reverse()
        original = ingest_fixture("sarif-spec-corners.sarif").observations
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "swapped.sarif"
            copy.write_text(json.dumps(payload))
            swapped = ingest_stig_artifact(copy, ingested_at=NOW).observations
        self.assertEqual(len(swapped), len(CORNER_IDS))
        self.assertEqual(
            sorted(map(tracking_id_of, swapped)), sorted(map(tracking_id_of, original))
        )
        self.assertEqual(sorted(map(identity_of, swapped)), sorted(map(identity_of, original)))
        # Only the run index evidence moves with the swap.
        self.assertEqual(
            {identity_of(item): evidence_without_run_indexes(item) for item in swapped},
            {identity_of(item): evidence_without_run_indexes(item) for item in original},
        )
        self.assertEqual(
            sorted(metadata(item)["run_indexes"] for item in swapped),
            sorted(
                metadata(item)["run_indexes"].translate({ord("0"): "2", ord("2"): "0"})
                for item in original
            ),
        )

    def test_every_ingest_order_of_the_golden_fixtures_correlates_identically(self) -> None:
        renderings = {correlation_json(order) for order in permutations(SARIF_ARTIFACTS)}
        self.assertEqual(len(renderings), 1)
        document = json.loads(next(iter(renderings)))
        self.assertEqual(
            [group["tracking_id"] for group in document["groups"]], list(GOLDEN_TRACKING_IDS)
        )
        self.assertEqual([item["observation_id"] for item in document["excluded"]], [CODEQL_IDS[1]])


# *--- Path Equivalence ---*


class SarifPathEquivalenceTests(StoreFixture):
    """The persisted path over the three tool fixtures reports the golden bytes (ADR 0010)."""

    def persist(self, order: Sequence[Path] = SARIF_ARTIFACTS) -> None:
        """Record, correlate, and attest the fixtures the way the four commands would."""
        self.ingest(order)
        self.correlate()
        self.attest(detected_at=REPORT_DETECTED_AT)

    def assert_reports_match(self) -> None:
        persisted_options = report_options()
        stateless_options = report_options(detected_at=REPORT_DETECTED_AT)
        vdt = compile_vdt_report_from_history(self.repository, options=persisted_options)
        self.assertEqual(vdt.to_json(), (GOLDEN / "vdt-sarif.json").read_text(encoding="utf-8"))
        self.assertEqual(vdt.to_markdown(), (GOLDEN / "vdt-sarif.md").read_text(encoding="utf-8"))
        pairs = (
            (vdt, compile_vdt_report(list(SARIF_ARTIFACTS), options=stateless_options)),
            (
                compile_avi_report_from_history(self.repository, options=persisted_options),
                compile_avi_report(list(SARIF_ARTIFACTS), options=stateless_options),
            ),
            (
                compile_historical_report_from_history(self.repository, options=persisted_options),
                compile_historical_report(list(SARIF_ARTIFACTS), options=stateless_options),
            ),
        )
        for persisted, stateless in pairs:
            with self.subTest(report=type(persisted).__name__):
                self.assertTrue(persisted.validation.is_valid)
                self.assertEqual(persisted.to_json(), stateless.to_json())
                self.assertEqual(persisted.to_markdown(), stateless.to_markdown())

    def test_history_reports_match_the_stateless_reports_and_the_goldens(self) -> None:
        self.persist()
        self.assert_reports_match()

    def test_reversed_ingest_order_reports_the_same_bytes(self) -> None:
        self.persist(tuple(reversed(SARIF_ARTIFACTS)))
        self.assert_reports_match()

    def test_the_attestation_reaches_only_the_cases_without_a_source_clock(self) -> None:
        self.ingest(SARIF_ARTIFACTS)
        self.correlate()
        outcome = attest_detection(
            self.repository,
            self.tracking_ids(),
            detected_at=REPORT_DETECTED_AT,
            rationale=RATIONALE,
            metadata=self.metadata,
            now=INGESTED_AT,
        )
        self.assertEqual(outcome.attested, CLOCKLESS_TRACKING_IDS)
        self.assertEqual(outcome.not_applicable, CLOCKED_TRACKING_IDS)
        self.assertEqual(outcome.skipped, ())

    def test_store_verify_passes_and_the_audit_finds_no_fault(self) -> None:
        self.persist()
        verifier = SQLiteEventStore.open_for_verification(self.database)
        self.addCleanup(verifier.close)
        integrity = verifier.verify_history()
        self.assertTrue(integrity.ok, integrity.render())
        self.assertEqual(integrity.faults, ())
        self.assertEqual(integrity.checked_events, 28)
        self.assertEqual(audit_history(self.repository), ())

    def test_every_recorded_observation_payload_validates_against_the_contract(self) -> None:
        self.persist()
        recorded = [
            record
            for record in self.repository.read_all()
            if record.event_type == "observation.recorded"
        ]
        self.assertEqual(
            sorted(record.payload["observation_id"] for record in recorded),
            sorted(TRIVY_IDS + SEMGREP_IDS + CODEQL_IDS),
        )
        for record in recorded:
            with self.subTest(observation=record.payload["observation_id"]):
                self.repository.validate_payload(
                    record.event_type, record.payload, event_version=record.event_version
                )

    def test_a_year_9999_run_clock_is_refused_and_every_persisted_step_succeeds(self) -> None:
        payload = json.loads((FIXTURES / "codeql-repo.sarif").read_text(encoding="utf-8"))
        invocation = payload["runs"][0]["invocations"][0]
        del invocation["endTimeUtc"]
        invocation["startTimeUtc"] = "9999-12-31T23:59:59Z"
        path = self.workspace / "year9999.sarif"
        path.write_text(json.dumps(payload), encoding="utf-8")
        result = ingest_stig_artifact(path, ingested_at=INGESTED_AT)
        self.assertIn("source_timestamp_invalid", diagnostic_codes(result))
        self.assertEqual({item.observed_at for item in result.observations}, {None})
        self.ingest([path])
        self.correlate()
        self.attest(detected_at=REPORT_DETECTED_AT)
        persisted = compile_vdt_report_from_history(self.repository, options=report_options())
        stateless = compile_vdt_report(
            [path], options=report_options(detected_at=REPORT_DETECTED_AT)
        )
        golden = json.loads((GOLDEN / "vdt-sarif.json").read_text(encoding="utf-8"))
        codeql_cases = [
            item
            for item in golden["vulnerabilities"]
            if item["detection"]["detectionSource"] == "CodeQL"
        ]
        vulnerabilities = persisted.document["vulnerabilities"]
        self.assertTrue(persisted.validation.is_valid)
        self.assertEqual(len(vulnerabilities), len(codeql_cases))
        self.assertEqual(
            {item["detection"]["detectedAt"] for item in vulnerabilities},
            {"2026-09-01T00:00:00Z"},
        )
        self.assertEqual(persisted.to_json(), stateless.to_json())


# *--- Saturated Caps ---*


class SarifSaturatedCapsTests(StoreFixture):
    """Every cap holds at saturation, and what records on `--db` is what the stateless path sees."""

    def write_log(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.workspace / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def record(self, path: Path) -> IngestResult:
        """Ingest and record one log, the way `complyroll ingest --db` would."""
        result = ingest_stig_artifact(path, ingested_at=INGESTED_AT)
        self.assertEqual(result.errors, ())
        record_ingest(self.repository, result, metadata=self.metadata, ingested_at=INGESTED_AT)
        return result

    def assert_both_paths_agree(
        self, path: Path, observation: Observation, reported: int = 1
    ) -> None:
        rehydrated = rehydrate_observations(self.repository)
        self.assertEqual(
            [item.to_canonical_json() for item in rehydrated], [observation.to_canonical_json()]
        )
        stored = [
            record
            for record in self.repository.read_all()
            if record.event_type == "observation.recorded"
        ]
        self.assertEqual(len(stored), 1)
        # Measured as the store encodes a payload; the default ASCII escapes would count one
        # astral character as twelve bytes rather than four.
        encoded = json.dumps(
            stored[0].payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        self.assertLess(len(encoded.encode("utf-8")), MAX_EVENT_JSON_BYTES)
        persisted = compile_vdt_report_from_history(self.repository, options=report_options())
        stateless = compile_vdt_report([path], options=report_options())
        self.assertTrue(persisted.validation.is_valid)
        self.assertEqual(len(persisted.document["vulnerabilities"]), reported)
        self.assertEqual(persisted.to_json(), stateless.to_json())
        self.assertEqual(persisted.to_markdown(), stateless.to_markdown())

    def assert_refused_on_both_paths(self, path: Path, ceiling: int = 500) -> None:
        with mock.patch.object(sarif_module, "MAX_OBSERVATION_JSON_BYTES", ceiling):
            result = ingest_stig_artifact(path, ingested_at=INGESTED_AT)
            self.assertEqual(result.observations, ())
            failed = only_diagnostic(result, "artifact_parse_failed")
            self.assertRegex(
                failed.message,
                rf"^observation obs-[0-9a-f]{{64}} is \d+ bytes of canonical JSON; "
                rf"maximum is {ceiling}$",
            )
            with self.assertRaisesRegex(HistoryError, "only a successful ingest"):
                record_ingest(
                    self.repository, result, metadata=self.metadata, ingested_at=INGESTED_AT
                )
            with self.assertRaises(ReportCompileError) as caught:
                compile_vdt_report([path], options=report_options())
        self.assertEqual(self.repository.read_all(), ())
        self.assertEqual(
            [
                (item.level.value, item.code, item.message, item.location)
                for item in caught.exception.diagnostics
            ],
            [("error", "artifact_parse_failed", failed.message, path.name)],
        )

    def test_a_log_saturating_every_cap_folds_into_one_bounded_observation(self) -> None:
        path = self.write_log("saturated.sarif", saturated_log())
        result = ingest_stig_artifact(path, ingested_at=INGESTED_AT)
        item = only_observation(result)
        fields = metadata(item)
        self.assertEqual(set(fields), set(METADATA_KEYS))
        self.assertEqual(fields["occurrence_count"], str(OVER_LIST))
        self.assertEqual(json.loads(fields["truncated"]), list(SATURATED_TRUNCATED))
        for member in CUT_LISTS:
            with self.subTest(member=member):
                self.assertEqual(len(json.loads(fields[member])), MAX_LIST_ITEMS)
        for member in CUT_TEXT_LISTS:
            with self.subTest(member=member):
                for text in json.loads(fields[member]):
                    self.assertEqual(len(text), MAX_LIST_ITEM_CHARS)
                    self.assertTrue(text.endswith(TRUNCATION_MARKER))
        for member in ("fingerprints", "partial_fingerprints"):
            with self.subTest(member=member):
                for name, value in json.loads(fields[member]):
                    self.assertEqual((len(name), len(value)), (MAX_LIST_ITEM_CHARS,) * 2)
        for member in CUT_SCALARS:
            with self.subTest(member=member):
                self.assertEqual(len(fields[member]), MAX_METADATA_VALUE_CHARS)
                self.assertTrue(fields[member].endswith(TRUNCATION_MARKER))
        for kind in json.loads(fields["result_kinds"]):
            self.assertLessEqual(len(kind), MAX_METADATA_VALUE_CHARS)
        self.assertEqual(json.loads(fields["run_indexes"]), list(range(MAX_LIST_ITEMS)))
        # Identity inputs sit exactly at their caps and are kept whole, never cut.
        self.assertEqual(len(item.source_tool), MAX_IDENTITY_CHARS)
        self.assertEqual(len(item.source_record_id), MAX_IDENTITY_CHARS)
        self.assertEqual(len(fields["image_name"]), MAX_IDENTITY_CHARS)
        self.assertEqual(len(fields["automation_id"]), MAX_IDENTITY_CHARS)
        self.assertEqual(len(item.context_key), MAX_IDENTITY_CHARS + 1 + MAX_IDENTITY_CHARS - 12)
        self.assertEqual(len(fields["location_uri"]), MAX_URI_CHARS)
        for member in ("repository_uri", "rule_help_uri", "tool_information_uri", "uri_base"):
            self.assertEqual(len(fields[member]), MAX_URI_CHARS)
        self.assertEqual(len(item.title), MAX_TITLE_CHARS)
        self.assertEqual(len(item.description), MAX_DESCRIPTION_CHARS)
        self.assertEqual(
            item.source_identifiers,
            tuple(f"CVE-2026-{index:05d}" for index in range(MAX_LIST_ITEMS)),
        )
        self.assertIs(item.disposition, ObservationDisposition.OPEN)
        self.assertIs(item.source_severity, SourceSeverity.HIGH)
        self.assertEqual(fields["result_kind"], "fail")
        self.assertEqual(fields["severity_source"], "level")
        self.assertEqual(fields["suppressed"], "false")
        self.assertLess(len(item.to_canonical_json().encode("utf-8")), MAX_OBSERVATION_JSON_BYTES)
        self.assertLess(MAX_OBSERVATION_JSON_BYTES, MAX_EVENT_JSON_BYTES)
        self.assertEqual(
            sorted(set(diagnostic_codes(result))),
            [
                "baseline_state_ignored",
                "evidence_truncated",
                "invalid_result_kind",
                "results_collapsed",
                "security_severity_invalid",
            ],
        )
        self.assertIn(
            f"({MAX_LIST_ITEMS} occurrences: runs[1].results[0], runs[10].results[0], ",
            only_diagnostic(result, "results_collapsed").message,
        )

    def test_the_saturated_observation_records_and_replays_below_the_store_cap(self) -> None:
        path = self.write_log("saturated.sarif", saturated_log())
        self.assert_both_paths_agree(path, only_observation(self.record(path)))

    # The caps bound characters, not bytes, so the adapter ceiling is reachable: four-byte text
    # at every cap fails the artifact closed, and just under the ceiling it still records.
    def test_four_byte_text_at_every_cap_fails_closed_at_the_real_ceiling(self) -> None:
        path = self.write_log("four-byte.sarif", four_byte_log(1.0))
        self.assert_refused_on_both_paths(path, ceiling=MAX_OBSERVATION_JSON_BYTES)

    # A quote or backslash in a list item is escaped twice, so ASCII text at every cap passes
    # the ceiling too: each of these logs folds to 931,093 bytes of canonical JSON.
    def test_escaped_ascii_text_at_every_cap_fails_closed_at_the_real_ceiling(self) -> None:
        for char in ('"', "\\"):
            with self.subTest(char=char):
                self.repository = self.open_repository(self.fresh_workspace())
                payload = four_byte_log(1.0, char)
                self.assertTrue(json.dumps(payload, ensure_ascii=False).isascii())
                path = self.write_log("escaped.sarif", payload)
                self.assert_refused_on_both_paths(path, ceiling=MAX_OBSERVATION_JSON_BYTES)

    def test_four_byte_text_just_under_the_ceiling_records_and_replays(self) -> None:
        path = self.write_log("four-byte.sarif", four_byte_log(0.28))
        item = only_observation(self.record(path))
        size = len(item.to_canonical_json().encode("utf-8"))
        self.assertGreater(size, MAX_OBSERVATION_JSON_BYTES - 32 * 1024)
        self.assertLess(size, MAX_OBSERVATION_JSON_BYTES)
        self.assert_both_paths_agree(path, item)

    def test_reproduction_a_two_thousand_results_record_with_cut_lists(self) -> None:
        path = self.write_log("reproduction-a.sarif", reproduction_a())
        result = self.record(path)
        item = only_observation(result)
        fields = metadata(item)
        self.assertEqual(fields["occurrence_count"], str(REPRODUCTION_A_RESULTS))
        self.assertEqual(json.loads(fields["truncated"]), ["location_messages", "regions"])
        regions = json.loads(fields["regions"])
        self.assertEqual(regions, [str(line) for line in range(1, MAX_LIST_ITEMS + 1)])
        messages = json.loads(fields["location_messages"])
        self.assertEqual(len(messages), MAX_LIST_ITEMS)
        for line, message in zip(regions, messages, strict=True):
            self.assertTrue(message.startswith(f"{line}: {int(line) - 1:04d}m"))
            self.assertTrue(message.endswith(TRUNCATION_MARKER))
            self.assertEqual(len(message), MAX_LIST_ITEM_CHARS)
        self.assertIn(
            f"({REPRODUCTION_A_RESULTS - 1} occurrences: runs[0].results[1], ",
            only_diagnostic(result, "results_collapsed").message,
        )
        # Every 600-character message is cut beside its region prefix, and the fold cuts the
        # location_messages and regions lists: one occurrence per result plus two.
        self.assertIn(
            f"({REPRODUCTION_A_RESULTS + 2} occurrences: runs[0].results[0].locations[0], ",
            only_diagnostic(result, "evidence_truncated").message,
        )
        self.assert_both_paths_agree(path, item)

    def test_reproduction_b_three_hundred_long_fingerprint_names_record_with_a_cut_list(
        self,
    ) -> None:
        path = self.write_log("reproduction-b.sarif", reproduction_b())
        result = self.record(path)
        item = only_observation(result)
        fields = metadata(item)
        self.assertEqual(fields["occurrence_count"], "1")
        self.assertEqual(json.loads(fields["truncated"]), ["partial_fingerprints"])
        self.assertNotIn("fingerprints", fields)
        pairs = json.loads(fields["partial_fingerprints"])
        self.assertEqual(
            [name[:4] for name, _value in pairs],
            [f"{index:04d}" for index in range(MAX_LIST_ITEMS)],
        )
        for name, value in pairs:
            self.assertEqual(len(name), MAX_LIST_ITEM_CHARS)
            self.assertTrue(name.endswith(TRUNCATION_MARKER))
            self.assertEqual(value, "v")
        self.assertIn(
            f"({REPRODUCTION_B_NAMES + 1} occurrences: runs[0].results[0], ",
            only_diagnostic(result, "evidence_truncated").message,
        )
        self.assert_both_paths_agree(path, item)

    def test_a_smaller_cap_refuses_both_reproductions_identically_on_both_paths(self) -> None:
        for name, builder in (
            ("reproduction-a.sarif", reproduction_a),
            ("reproduction-b.sarif", reproduction_b),
        ):
            with self.subTest(log=name):
                self.assert_refused_on_both_paths(self.write_log(name, builder()))

    def test_a_cwe_flood_records_its_first_identifiers_and_the_truncation(self) -> None:
        # 59,999 is the skeptic's cwe-flood log; 45,000 tripped the observation ceiling.
        for count in (45_000, 59_999):
            with self.subTest(count=count):
                self.repository = self.open_repository(self.fresh_workspace())
                path = self.write_log(f"cwe-{count}.sarif", cwe_flood(count))
                result = self.record(path)
                item = only_observation(result)
                expected = sorted(f"CWE-{number}" for number in range(1, count + 1))
                self.assertEqual(item.source_identifiers, tuple(expected[:MAX_LIST_ITEMS]))
                self.assertEqual(
                    json.loads(metadata(item)["truncated"]), ["rule_tags", "source_identifiers"]
                )
                self.assertIn(
                    "(2 occurrences: runs[0].results[0], runs[0].results[0])",
                    only_diagnostic(result, "evidence_truncated").message,
                )
                self.assert_both_paths_agree(path, item)

    def assert_quoted_value_records(
        self, name: str, payload: dict[str, Any], code: str, message: str, reported: int = 1
    ) -> None:
        """Record a log whose one diagnostic quotes a 1 MiB value, cut to its bound."""
        path = self.write_log(name, payload)
        result = self.record(path)
        self.assertEqual(only_diagnostic(result, code).message, message)
        for item in result.diagnostics:
            with self.subTest(code=item.code):
                self.assertLessEqual(len(item.message), diagnostic_bound(item.message))
        self.assert_both_paths_agree(path, only_observation(result), reported)

    def test_a_one_mebibyte_kind_is_quoted_within_the_diagnostic_bound(self) -> None:
        kind = "q" * ONE_MIB
        self.assert_quoted_value_records(
            "kind.sarif",
            make_log(make_run([make_result(kind=kind)], invocations=[RUN_CLOCK])),
            "invalid_result_kind",
            "result kind is outside the six SARIF values; the disposition is unknown "
            f"(1 occurrence: runs[0].results[0]; first: {cut_detail(repr(kind))})",
            # An unknown disposition is surfaced as unresolved, never grouped as a vulnerability.
            reported=0,
        )

    def test_a_one_mebibyte_descriptor_id_is_quoted_within_the_diagnostic_bound(self) -> None:
        descriptor_id = "q" * ONE_MIB
        self.assert_quoted_value_records(
            "descriptor-id.sarif",
            make_log(
                make_run(
                    [make_result(ruleIndex=0)],
                    rules=[{"id": descriptor_id}],
                    invocations=[RUN_CLOCK],
                )
            ),
            "rule_reference_conflict",
            "the rule id string and the resolved descriptor id disagree; the string wins "
            "(1 occurrence: runs[0].results[0]; first: "
            f"{cut_detail(repr('R1') + ' against descriptor ' + repr(descriptor_id))})",
        )

    def test_a_one_mebibyte_level_is_quoted_within_the_diagnostic_bound(self) -> None:
        level = "q" * ONE_MIB
        self.assert_quoted_value_records(
            "level.sarif",
            make_log(make_run([make_result(level=level)], invocations=[RUN_CLOCK])),
            "invalid_level",
            "effective level is outside error, warning, note, and none; severity unknown "
            f"(1 occurrence: runs[0].results[0]; first: {cut_detail(repr(level))})",
        )

    def test_a_one_mebibyte_security_severity_is_quoted_within_the_diagnostic_bound(self) -> None:
        score = "q" * ONE_MIB
        self.assert_quoted_value_records(
            "security-severity.sarif",
            make_log(
                make_run(
                    [make_result(properties={"security-severity": score})],
                    invocations=[RUN_CLOCK],
                )
            ),
            "security_severity_invalid",
            "security-severity is not a finite number above 0 and at most 10; ignored "
            f"(1 occurrence: runs[0].results[0]; first: {cut_detail(repr(score))})",
        )

    def test_a_one_mebibyte_uri_base_key_is_cut_in_a_path_and_refused_as_usual(self) -> None:
        # The bell is stripped from the stored path the way evidence text is sanitized.
        base_id = "\u0007" + "B" * ONE_MIB
        result = make_result()
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = base_id
        payload = make_log(
            make_run(
                [result],
                invocations=[RUN_CLOCK],
                originalUriBaseIds={base_id: {"uri": EXAMPLE_URI + "\u0007"}},
            )
        )
        path = self.write_log("uri-base-key.sarif", payload)
        output = ingest_stig_artifact(path, ingested_at=INGESTED_AT)
        self.assertEqual(output.observations, ())
        self.assertFalse(output.successful)
        refused = only_diagnostic(output, "identity_input_invalid")
        self.assertIs(refused.level, DiagnosticLevel.ERROR)
        self.assertEqual(
            refused.message,
            f"{IDENTITY_MESSAGE} (1 occurrence: "
            f"{cut_detail(f'runs[0].originalUriBaseIds.{base_id[1:]}.uri')}; "
            "first: original uri base contains prohibited code point U+0007)",
        )
        for item in output.diagnostics:
            with self.subTest(code=item.code):
                self.assertLessEqual(len(item.message), diagnostic_bound(item.message))
        with self.assertRaisesRegex(HistoryError, "only a successful ingest"):
            record_ingest(self.repository, output, metadata=self.metadata, ingested_at=INGESTED_AT)
        with self.assertRaises(ReportCompileError) as caught:
            compile_vdt_report([path], options=report_options())
        self.assertEqual(self.repository.read_all(), ())
        self.assertEqual(
            sorted(
                (item.level.value, item.code, item.message, item.location)
                for item in caught.exception.diagnostics
            ),
            sorted(
                ("error", item.code, item.message, path.name)
                for item in output.diagnostics
                if item.level is DiagnosticLevel.ERROR
            ),
        )


# *--- Shared Work ---*

# Each timing log is also parsed at SMALL_RESULTS results, which must say the same thing. The
# ceiling is far above the parse time, so only work that grows per result can reach it.
SHARED_WORK_CEILING = 10.0
SMALL_RESULTS = 6
WIDE_RESULTS = 2_000
PLACEHOLDER_FLOOD = 300_000
RULE_FLOOD = 20_000
PADDED_RESULTS = 20_000
LINK_FLOOD = 200_000
SEVERITY_KEYS = 250_000
SHARED_LIST_ITEMS = 200_000
OWN_LIST_ITEMS = 60_000
SHARED_URI_RESULTS = 20
OCCURRENCES = re.compile(r" \((\d+) occurrences?: ")


class CountedObject(dict[str, Any]):
    """A JSON object that counts each member read, so a test can see what a parse re-reads."""

    def __init__(self, reads: Counter[str], label: str, members: dict[str, Any]) -> None:
        super().__init__(members)
        self.reads = reads
        self.label = label

    def get(self, key: str, default: Any = None) -> Any:
        self.reads[f"{self.label}.{key}"] += 1
        return super().get(key, default)

    def __getitem__(self, key: str) -> Any:
        self.reads[f"{self.label}.{key}"] += 1
        return super().__getitem__(key)

    def __contains__(self, key: object) -> bool:
        self.reads[f"{self.label}.{key}"] += 1
        return super().__contains__(key)


def counted_log(reads: Counter[str], copies: int) -> dict[str, Any]:
    """Build a run whose shared objects count their reads, with every result shape repeated."""

    def counted(label: str, **members: Any) -> CountedObject:
        return CountedObject(reads, label, members)

    driver_rules = [
        counted(
            "rule0",
            id="R0",
            name="Zero",
            shortDescription={"text": "Zero title"},
            fullDescription={"text": "Zero [full](1) text"},
            helpUri=EXAMPLE_URI,
            deprecatedIds=["OLD-0"],
            relationships=[{"target": {"id": "CWE-89"}}],
            properties=counted(
                "rule0.properties", **{"tags": ["CWE-79"], "security-severity": "7.5"}
            ),
        ),
        counted("rule1", id="R1", messageStrings={"found": {"text": "Found {0}"}}),
        counted("rule2", id="R2", guid=RULE_GUID, defaultConfiguration={"level": "note"}),
    ]
    extension = counted(
        "extension",
        name="Ext",
        guid=EXTENSION_GUID,
        globalMessageStrings={"shared": {"text": "Shared {0}"}},
        rules=[counted("extension.rule0", id="X0")],
    )
    overrides = [
        counted(
            "override0",
            descriptor=counted("override0.descriptor", index=0),
            configuration={"level": "error"},
        ),
        counted("override1", descriptor=counted("override1.descriptor", id="R1"), configuration={}),
        counted(
            "override2",
            descriptor=counted("override2.descriptor", guid=RULE_GUID),
            configuration={"level": "warning"},
        ),
        counted(
            "override3",
            descriptor=counted(
                "override3.descriptor", id="X0", toolComponent={"guid": EXTENSION_GUID}
            ),
            configuration={"level": "note"},
        ),
    ]
    indexed = {
        "physicalLocation": {
            "artifactLocation": {"index": 0, "uriBaseId": "SRC"},
            "region": {"startLine": 1},
        }
    }
    results = []
    for copy in range(copies):
        results.extend(
            [
                make_result(rule_id=None, uri=f"src/zero-{copy}.py", text=None, ruleIndex=0),
                make_result(
                    uri=f"src/one-{copy}.py",
                    text=None,
                    message={"id": "found", "arguments": [str(copy)]},
                ),
                make_result(
                    rule_id=None, uri=f"src/two-{copy}.py", text=None, rule={"guid": RULE_GUID}
                ),
                make_result(
                    rule_id="X0",
                    uri=f"src/ext-{copy}.py",
                    text=None,
                    rule={"toolComponent": {"guid": EXTENSION_GUID}},
                    message={"id": "shared", "arguments": [str(copy)]},
                ),
                make_result(uri=None, text="indexed", locations=[indexed]),
            ]
        )
    run = {
        "tool": {
            "driver": counted("driver", name="Synth", rules=driver_rules),
            "extensions": [extension],
        },
        "invocations": [counted("invocation", ruleConfigurationOverrides=overrides, **RUN_CLOCK)],
        "artifacts": [
            counted("artifact0", location=counted("artifact0.location", uri="src/indexed.py"))
        ],
        "originalUriBaseIds": counted("bases", SRC=counted("bases.SRC", uri="file:///work/")),
        "results": results,
    }
    return make_log(run)


def shared_reads(copies: int) -> tuple[dict[str, int], AdapterOutput]:
    """Parse the counted run and return every shared member read, with the output."""
    reads: Counter[str] = Counter()
    payload = counted_log(reads, copies)
    artifact = synthetic_artifact(payload)
    reads.clear()
    output = parse_direct(payload, artifact)
    # A result finds its component's rules list in one read, whatever the list's length.
    return {key: count for key, count in reads.items() if not key.endswith(".rules")}, output


def wide_log(results: int) -> dict[str, Any]:
    """One descriptor whose name, tag, and fullDescription are each 1 MiB of non-ASCII text."""
    marked = ("\u00e9" * 1023 + "\u200b") * 1024
    rule = {
        "id": "R1",
        "name": marked,
        "fullDescription": {"text": "\u00e9" * ONE_MIB},
        "properties": {"tags": [marked]},
    }
    located = [make_result(uri=f"src/{index}.py", text=None) for index in range(results)]
    return make_log(make_run(located, rules=[rule], invocations=[RUN_CLOCK]))


def flood_log(results: int, placeholders: int = PLACEHOLDER_FLOOD) -> dict[str, Any]:
    """One template of empty placeholders, expanded by every result with an empty argument."""
    rule = {"id": "R1", "messageStrings": {"flood": {"text": "{0}" * placeholders}}}
    message = {"id": "flood", "arguments": [""]}
    located = [
        make_result(uri=f"src/{index}.py", text=None, message=message) for index in range(results)
    ]
    return make_log(make_run(located, rules=[rule], invocations=[RUN_CLOCK]))


def rule_flood_log(results: int) -> dict[str, Any]:
    """As many rules as results, each result naming its rule by id and each rule overridden."""
    rules = [
        {"id": f"R{index}", "shortDescription": {"text": f"T{index}"}} for index in range(results)
    ]
    overrides = [
        override("note" if index % 2 else "error", id=f"R{index}") for index in range(results)
    ]
    invocation = dict(RUN_CLOCK, ruleConfigurationOverrides=overrides)
    located = [make_result(rule_id=f"R{index}") for index in range(results)]
    return make_log(make_run(located, rules=rules, invocations=[invocation]))


def literal_log(results: int) -> dict[str, Any]:
    """One template of 4 MiB of literal text, expanded by every result with its own argument."""
    rule = {"id": "R1", "messageStrings": {"found": {"text": "Found {0} " + "x" * 4 * ONE_MIB}}}
    located = [
        make_result(
            uri=f"src/{index}.py",
            text=None,
            message={"id": "found", "arguments": [f"item {index}"]},
        )
        for index in range(results)
    ]
    return make_log(make_run(located, rules=[rule], invocations=[RUN_CLOCK]))


def padded_log(results: int) -> dict[str, Any]:
    """Results naming the run's artifact and base, each uri padded by 1 MiB of spaces a side."""
    padding = " " * ONE_MIB
    location = {"physicalLocation": {"artifactLocation": {"index": 0, "uriBaseId": "SRC"}}}
    located = [
        make_result(rule_id=f"R{index}", uri=None, locations=[location]) for index in range(results)
    ]
    return make_log(
        make_run(
            located,
            invocations=[RUN_CLOCK],
            artifacts=[{"location": {"uri": padding + "src/a.py" + padding}}],
            originalUriBaseIds={"SRC": {"uri": padding + "file:///work/" + padding}},
        )
    )


def shared_list_log(results: int) -> dict[str, Any]:
    """A descriptor's tags and deprecatedIds and the run's repoDigests, each one long list."""
    items = [f"t{index:06d}" for index in range(SHARED_LIST_ITEMS)]
    rule = {"id": "R1", "deprecatedIds": items, "properties": {"tags": items}}
    properties = {"imageName": "registry.test/app", "repoDigests": items}
    located = [make_result(uri=f"src/{index}.py", text=None) for index in range(results)]
    return make_log(make_run(located, rules=[rule], invocations=[RUN_CLOCK], properties=properties))


def fan_out_log(items: int) -> dict[str, Any]:
    """One result naming MAX_LOCATIONS_PER_RESULT files, with long lists of its own."""
    locations = [
        {"physicalLocation": {"artifactLocation": {"uri": f"src/{index}.py"}}}
        for index in range(MAX_LOCATIONS_PER_RESULT)
    ]
    part = [f"i{index:06d}" for index in range(items)]
    result = make_result(uri=None, text=None, locations=locations, **own_lists(part))
    return make_log(make_run([result], invocations=[RUN_CLOCK]))


def shared_uri_log(
    artifact_uri: str, base_uri: str, help_uri: str
) -> tuple[dict[str, Any], list[str]]:
    """Results whose three locations each name the run's artifact and base, under one rule."""
    location = {"physicalLocation": {"artifactLocation": {"index": 0, "uriBaseId": "SRC"}}}
    results = [
        make_result(uri=None, text=None, ruleIndex=0, locations=[location] * 3)
        for _ in range(SHARED_URI_RESULTS)
    ]
    run = make_run(
        results,
        rules=[{"id": "R1", "helpUri": help_uri}],
        invocations=[RUN_CLOCK],
        artifacts=[{"location": {"uri": artifact_uri}}],
        originalUriBaseIds={"SRC": {"uri": base_uri}},
    )
    return make_log(run), [artifact_uri, base_uri, help_uri]


def keyed_severity_log(results: int) -> dict[str, Any]:
    """One descriptor whose security-severity is an object of SEVERITY_KEYS members."""
    # The keys come in a scrambled order, so sorting them costs a full sort.
    score = {f"k{index * 7919 % SEVERITY_KEYS}": index for index in range(SEVERITY_KEYS)}
    rule = {"id": "R1", "properties": {"security-severity": score}}
    located = [make_result(uri=f"src/{index}.py", text=None) for index in range(results)]
    return make_log(make_run(located, rules=[rule], invocations=[RUN_CLOCK]))


def timed_parse(payload: Any) -> tuple[AdapterOutput, float]:
    """Parse a document and return the output with the seconds the parse alone took."""
    artifact = synthetic_artifact(payload)
    started = time.perf_counter()
    output = parse_direct(payload, artifact)
    return output, time.perf_counter() - started


def content(observation: Observation) -> tuple[Any, ...]:
    """Return what an observation says, leaving out the ids its artifact digest feeds."""
    return (
        observation.resource,
        observation.source_record_id,
        observation.observed_at,
        observation.disposition,
        observation.source_severity,
        observation.title,
        observation.description,
        observation.source_identifiers,
        observation.source_metadata,
    )


def keyed(output: AdapterOutput) -> dict[tuple[str, str], Observation]:
    return {
        (item.source_record_id, item.resource.resource_id): item for item in output.observations
    }


def diagnostic_shape(output: AdapterOutput) -> list[tuple[str, str]]:
    """Return each diagnostic's code and its message without the occurrence count."""
    return [(item.code, OCCURRENCES.sub(" (", item.message)) for item in output.diagnostics]


def occurrences(output: AdapterOutput) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in output.diagnostics:
        match = OCCURRENCES.search(item.message)
        counts[item.code] = int(match.group(1)) if match is not None else 0
    return counts


class SarifSharedWorkTests(unittest.TestCase):
    """Decision 9: a run's shared tool data is read and cleaned once, not once per result."""

    def assert_scales(
        self, build: Callable[[int], dict[str, Any]], results: int
    ) -> tuple[AdapterOutput, AdapterOutput]:
        """Parse a log inside the ceiling and check it says what its small-scale copy says."""
        large, seconds = timed_parse(build(results))
        self.assertLess(seconds, SHARED_WORK_CEILING)
        small = parse_direct(build(SMALL_RESULTS))
        self.assertEqual(len(large.observations), results)
        observations = keyed(large)
        for key, item in keyed(small).items():
            self.assertEqual(content(observations[key]), content(item))
        # Every result reports the same cleaning, at its own path.
        self.assertEqual(diagnostic_shape(large), diagnostic_shape(small))
        self.assertEqual(
            {code: count * SMALL_RESULTS for code, count in occurrences(large).items()},
            {code: count * results for code, count in occurrences(small).items()},
        )
        return small, large

    def test_a_descriptor_text_is_cleaned_once_however_many_results_use_it(self) -> None:
        rule = {
            "id": "R1",
            "name": "shared-name",
            "shortDescription": {"text": "shared title"},
            "fullDescription": {"text": "shared [full](1) description"},
            "properties": {"tags": ["tag-one", "tag-two"]},
        }
        located = [make_result(uri=f"src/{index}.py", text=None) for index in range(40)]
        payload = make_log(make_run(located, rules=[rule], invocations=[RUN_CLOCK]))
        artifact = synthetic_artifact(payload)
        flatten_links = sarif_module._flatten_links
        with (
            mock.patch.object(sarif_module, "_sanitize", wraps=_sanitize) as sanitize,
            mock.patch.object(sarif_module, "_flatten_links", wraps=flatten_links) as flatten,
        ):
            output = parse_direct(payload, artifact)
        cleaned = Counter(call.args[0] for call in sanitize.call_args_list)
        for text in ("shared-name", "shared title", "shared full description", "tag-one"):
            with self.subTest(text=text):
                self.assertEqual(cleaned[text], 1)
        self.assertEqual(flatten.call_args_list, [mock.call("shared [full](1) description")])
        self.assertEqual(len(output.observations), 40)
        self.assertEqual(
            {
                (item.title, item.description, metadata(item)["rule_name"])
                for item in output.observations
            },
            {("shared title", "shared full description", "shared-name")},
        )
        self.assertEqual(
            {metadata(item)["rule_tags"] for item in output.observations},
            {'["tag-one","tag-two"]'},
        )

    def test_shared_tool_data_is_read_once_however_many_results_use_it(self) -> None:
        few, _output = shared_reads(2)
        many, output = shared_reads(20)
        self.assertEqual(many, few)
        self.assertLessEqual(
            {
                "rule0.shortDescription",
                "rule0.properties.security-severity",
                "rule1.messageStrings",
                "rule2.guid",
                "extension.guid",
                "extension.globalMessageStrings",
                "override1.configuration",
                "override3.descriptor.toolComponent",
                "artifact0.location.uri",
                "bases.SRC.uri",
            },
            set(few),
        )
        items = by_resource(output)
        zero = items["src/zero-19.py"]
        self.assertEqual((zero.title, zero.description), ("Zero title", "Zero full text"))
        self.assertEqual(zero.source_identifiers, ("CWE-79", "CWE-89"))
        self.assertIs(zero.source_severity, SourceSeverity.HIGH)
        self.assertEqual(level_of(zero), ("error", "invocation_override"))
        self.assertEqual(metadata(zero)["rule_help_uri"], EXAMPLE_URI)
        self.assertEqual(items["src/one-19.py"].description, "Found 19")
        self.assertEqual(level_of(items["src/one-19.py"]), ("warning", "default"))
        self.assertEqual(level_of(items["src/two-19.py"]), ("warning", "invocation_override"))
        extension = items["src/ext-19.py"]
        self.assertEqual(extension.description, "Shared 19")
        self.assertEqual(metadata(extension)["rule_component"], "Ext")
        self.assertEqual(level_of(extension), ("note", "invocation_override"))
        self.assertEqual(metadata(items["src/indexed.py"])["uri_base"], "file:///work/")

    def test_shared_text_reports_its_cleaning_at_each_result_in_the_order_found(self) -> None:
        truncated = "evidence text was cut at its cap; the truncated metadata key names the members"
        sanitized = "control, format, or separator characters were removed from evidence text"
        # Each of the two results reports a cleaning once, twice, or three times.
        once = "2 occurrences: runs[0].results[0], runs[0].results[1]"
        thrice = (
            "6 occurrences: runs[0].results[0], runs[0].results[0], runs[0].results[0], "
            "runs[0].results[1], runs[0].results[1], ..."
        )
        twice = (
            "4 occurrences: runs[0].results[0], runs[0].results[0], runs[0].results[1], "
            "runs[0].results[1]"
        )
        marked = ["a\u200bb", "c\u200bd", "e\u200bf"]
        cut_first = ["evidence_truncated", "evidence_sanitized"]
        cases = {
            "cut first": (["x" * OVER_ITEM, *marked], cut_first, once, thrice),
            "sanitized first": (
                [marked[0], "x" * OVER_ITEM, *marked[1:]],
                ["evidence_sanitized", "evidence_truncated"],
                once,
                thrice,
            ),
            # Only the first cut decides the order, so a later cut after sanitizing changes nothing.
            "cut, sanitized, cut": (
                ["x" * OVER_ITEM, marked[0], "y" * OVER_ITEM],
                cut_first,
                twice,
                once,
            ),
        }
        for name, (tags, codes, cut_paths, sanitized_paths) in cases.items():
            with self.subTest(name):
                rules = [{"id": "R1", "properties": {"tags": tags}}]
                located = [make_result(uri=f"src/{copy}.py") for copy in range(2)]
                run = make_run(located, rules=rules, invocations=[RUN_CLOCK])
                output = parse_direct(make_log(run))
                self.assertEqual(diagnostic_codes(output), codes)
                self.assertEqual(
                    only_diagnostic(output, "evidence_truncated").message,
                    f"{truncated} ({cut_paths})",
                )
                self.assertEqual(
                    only_diagnostic(output, "evidence_sanitized").message,
                    f"{sanitized} ({sanitized_paths})",
                )
                self.assertEqual(
                    {metadata(item)["truncated"] for item in output.observations},
                    {'["rule_tags"]'},
                )

    def test_a_one_mib_descriptor_shared_by_many_results_is_cleaned_once(self) -> None:
        small, large = self.assert_scales(wide_log, WIDE_RESULTS)
        item = keyed(small)[("R1", "src/0.py")]
        kept = MAX_DESCRIPTION_CHARS - len(TRUNCATION_MARKER)
        self.assertEqual(item.description, "\u00e9" * kept + TRUNCATION_MARKER)
        self.assertEqual(
            metadata(item)["truncated"], '["description","rule_name","rule_tags","title"]'
        )
        self.assertEqual(
            occurrences(large),
            {"evidence_sanitized": 3 * WIDE_RESULTS, "evidence_truncated": 4 * WIDE_RESULTS},
        )

    def test_a_placeholder_flood_stops_at_the_placeholder_cap(self) -> None:
        small, large = self.assert_scales(flood_log, WIDE_RESULTS)
        # One placeholder past the cap cuts exactly as three hundred thousand do.
        least = keyed(parse_direct(flood_log(SMALL_RESULTS, MAX_MESSAGE_PLACEHOLDERS + 1)))
        self.assertEqual(
            [content(item) for item in keyed(small).values()],
            [content(item) for item in least.values()],
        )
        item = keyed(small)[("R1", "src/0.py")]
        self.assertEqual(item.description, TRUNCATION_MARKER)
        self.assertEqual(metadata(item)["truncated"], '["description"]')
        self.assertEqual(occurrences(large), {"evidence_truncated": WIDE_RESULTS})
        at_cap = parse_direct(flood_log(1, MAX_MESSAGE_PLACEHOLDERS))
        self.assertEqual(only_observation(at_cap).description, "")
        self.assertNotIn("truncated", metadata(only_observation(at_cap)))

    def test_twenty_thousand_rules_resolve_by_id_without_a_scan_per_result(self) -> None:
        _small, large = self.assert_scales(rule_flood_log, RULE_FLOOD)
        items = keyed(large)
        first, last = items[("R0", "src/a.py")], items[(f"R{RULE_FLOOD - 1}", "src/a.py")]
        self.assertEqual((first.title, level_of(first)), ("T0", ("error", "invocation_override")))
        self.assertEqual(
            (last.title, level_of(last)),
            (f"T{RULE_FLOOD - 1}", ("note", "invocation_override")),
        )

    def test_a_four_mib_template_is_read_only_as_far_as_the_budget(self) -> None:
        small, _large = self.assert_scales(literal_log, WIDE_RESULTS)
        expanded = "Found item 5 " + "x" * MAX_DESCRIPTION_CHARS
        self.assertEqual(
            keyed(small)[("R1", "src/5.py")].description,
            expanded[: MAX_DESCRIPTION_CHARS - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER,
        )

    def test_padded_artifact_and_base_uris_are_stripped_once_per_run(self) -> None:
        small, _large = self.assert_scales(padded_log, PADDED_RESULTS)
        fields = metadata(keyed(small)[("R5", "src/a.py")])
        self.assertEqual(
            (fields["location_uri"], fields["uri_base"]), ("src/a.py", "file:///work/")
        )

    def test_a_long_shared_list_is_cut_once_however_many_folds_carry_it(self) -> None:
        small, large = self.assert_scales(shared_list_log, WIDE_RESULTS)
        fields = metadata(keyed(small)[("R1", "registry.test/app/src/0.py")])
        kept = [f"t{index:06d}" for index in range(MAX_LIST_ITEMS)]
        for member in ("rule_tags", "rule_deprecated_ids", "image_digests"):
            self.assertEqual(json.loads(fields[member]), kept)
        self.assertEqual(fields["truncated"], '["image_digests","rule_deprecated_ids","rule_tags"]')
        # Each result's fold cuts its three lists.
        self.assertEqual(occurrences(large), {"evidence_truncated": 3 * WIDE_RESULTS})

    def test_a_result_s_own_lists_are_cut_once_however_many_resources_it_names(self) -> None:
        payload = fan_out_log(OWN_LIST_ITEMS)
        artifact = synthetic_artifact(payload)
        cut = sarif_module._ArtifactParse._cut
        with mock.patch.object(
            sarif_module._ArtifactParse, "_cut", autospec=True, side_effect=cut
        ) as cutter:
            started = time.perf_counter()
            output = parse_direct(payload, artifact)
            seconds = time.perf_counter() - started
        self.assertLess(seconds, SHARED_WORK_CEILING)
        # Every fold sorts and cuts at most one item past the cap, never a whole list.
        longest = max(len(call.args[1]) for call in cutter.call_args_list)
        self.assertEqual(longest, MAX_LIST_ITEMS + 1)
        self.assertEqual(len(output.observations), MAX_LOCATIONS_PER_RESULT)
        kept = own_list_members([f"i{index:06d}" for index in range(MAX_LIST_ITEMS)])
        for item in output.observations:
            fields = metadata(item)
            self.assertEqual({member: json.loads(fields[member]) for member in kept}, kept)
            self.assertEqual(json.loads(fields["truncated"]), sorted(kept))
        # Each fold cuts its five lists.
        self.assertEqual(occurrences(output), {"evidence_truncated": 5 * MAX_LOCATIONS_PER_RESULT})

    def test_a_shared_uri_is_checked_once_however_many_results_use_it(self) -> None:
        payload, uris = shared_uri_log(
            "src/\u00e9.py", "file:///w\u00f6rk/", "https://example.test/\u00e9"
        )
        problem = sarif_module._identity_problem
        with mock.patch.object(sarif_module, "_identity_problem", wraps=problem) as check:
            output = parse_direct(payload)
        checked = Counter(call.args[0] for call in check.call_args_list)
        self.assertEqual([checked[uri] for uri in uris], [1, 1, 1])
        fields = metadata(only_observation(output))
        self.assertEqual(
            (fields["location_uri"], fields["uri_base"], fields["rule_help_uri"]), tuple(uris)
        )
        self.assertEqual(fields["occurrence_count"], str(SHARED_URI_RESULTS))

    def test_a_shared_descriptor_id_is_read_once_however_many_results_name_it(self) -> None:
        # No result writes a ruleId, so each takes the descriptor's id as its rule identifier,
        # and a non-ASCII id takes the slow path of the identity check.
        rule_id = "r\u00e8gle-CVE-2026-0001"
        results = [
            make_result(rule_id=None, uri=f"src/{index}.py", ruleIndex=0)
            for index in range(SHARED_URI_RESULTS)
        ]
        run = make_run(results, rules=[{"id": rule_id}], invocations=[RUN_CLOCK])
        problem = sarif_module._identity_problem
        extract = sarif_module._extract_identifiers
        with (
            mock.patch.object(sarif_module, "_identity_problem", wraps=problem) as check,
            mock.patch.object(sarif_module, "_extract_identifiers", wraps=extract) as scan,
        ):
            output = parse_direct(make_log(run))
        self.assertEqual(Counter(call.args[0] for call in check.call_args_list)[rule_id], 1)
        self.assertEqual(sum(rule_id in call.args[0] for call in scan.call_args_list), 1)
        self.assertEqual(len(output.observations), SHARED_URI_RESULTS)
        for item in output.observations:
            self.assertEqual(item.source_record_id, rule_id)
            self.assertEqual(item.source_identifiers, ("CVE-2026-0001",))

    def test_a_rule_identifier_other_than_the_descriptor_id_is_read_on_its_own(self) -> None:
        # Only a rule identifier equal to the descriptor's id was read with the descriptor, so
        # a hierarchical ruleId and a conflicting one each carry their own identifier.
        cases = {"R1/CVE-2026-0001": False, "CVE-2026-0002": True}
        for rule_id, conflict in cases.items():
            with self.subTest(rule_id=rule_id):
                result = make_result(rule_id=rule_id, ruleIndex=0)
                run = make_run([result], rules=[{"id": "R1"}], invocations=[RUN_CLOCK])
                output = parse_direct(make_log(run))
                item = only_observation(output)
                self.assertEqual(item.source_record_id, rule_id)
                self.assertEqual(item.source_identifiers, (rule_id.rpartition("/")[2],))
                codes = diagnostic_codes(output)
                self.assertEqual("rule_reference_conflict" in codes, conflict)

    def test_a_shared_descriptor_id_checked_once_is_still_refused_at_each_use(self) -> None:
        results = [make_result(rule_id=None, ruleIndex=0) for _ in range(SHARED_URI_RESULTS)]
        run = make_run(results, rules=[{"id": "R\u200b"}], invocations=[RUN_CLOCK])
        problem = sarif_module._identity_problem
        with mock.patch.object(sarif_module, "_identity_problem", wraps=problem) as check:
            output = parse_direct(make_log(run))
        self.assertEqual(Counter(call.args[0] for call in check.call_args_list)["R\u200b"], 1)
        self.assertEqual(output.observations, ())
        listed = ", ".join(f"runs[0].results[{index}]" for index in range(MAX_DIAGNOSTIC_PATHS))
        self.assertEqual(
            only_diagnostic(output, "identity_input_invalid").message,
            f"{IDENTITY_MESSAGE} ({SHARED_URI_RESULTS} occurrences: {listed}, ...; "
            "first: rule identifier contains prohibited code point U+200B)",
        )

    def test_a_shared_suspicious_uri_is_split_once_and_warned_at_each_use(self) -> None:
        payload, uris = shared_uri_log("src/../a.py", "file:///work/", EXAMPLE_URI)
        split = sarif_module._uri_is_suspicious
        with mock.patch.object(sarif_module, "_uri_is_suspicious", wraps=split) as check:
            output = parse_direct(payload)
        self.assertEqual([call.args[0] for call in check.call_args_list], ["src/../a.py"])
        self.assertEqual(metadata(only_observation(output))["location_uri"], "src/../a.py")
        # Each result names the run's artifact from three locations.
        listed = ", ".join(
            f"runs[0].results[{index // 3}].locations[{index % 3}]"
            ".physicalLocation.artifactLocation.uri"
            for index in range(MAX_DIAGNOSTIC_PATHS)
        )
        self.assertEqual(
            only_diagnostic(output, "uri_suspicious").message,
            "location uri has a '..' segment or a '//' prefix; kept verbatim, never opened "
            f"({3 * SHARED_URI_RESULTS} occurrences: {listed}, ...)",
        )

    def test_a_shared_benign_uri_is_split_once_and_never_warned(self) -> None:
        # The memo keeps a clean verdict as well as a suspicious one, and most uris are clean.
        payload, _uris = shared_uri_log("src/a.py", "file:///work/", EXAMPLE_URI)
        split = sarif_module._uri_is_suspicious
        with mock.patch.object(sarif_module, "_uri_is_suspicious", wraps=split) as check:
            output = parse_direct(payload)
        self.assertEqual([call.args[0] for call in check.call_args_list], ["src/a.py"])
        self.assertEqual(metadata(only_observation(output))["location_uri"], "src/a.py")
        self.assertNotIn("uri_suspicious", diagnostic_codes(output))

    def test_a_shared_uri_checked_once_is_still_refused_at_each_use(self) -> None:
        bad = "\u200b"
        paths = {
            "location uri": (
                "runs[0].results[{}].locations[0].physicalLocation.artifactLocation.uri"
            ),
            "original uri base": "runs[0].originalUriBaseIds.SRC.uri",
            "rule helpUri": "runs[0].results[{}].rule.helpUri",
        }
        good = ["src/a.py", "file:///work/", EXAMPLE_URI]
        for position, (what, path) in enumerate(paths.items()):
            with self.subTest(what=what):
                uris = list(good)
                uris[position] += bad
                payload, _uris = shared_uri_log(*uris)
                problem = sarif_module._identity_problem
                with mock.patch.object(sarif_module, "_identity_problem", wraps=problem) as check:
                    output = parse_direct(payload)
                checked = Counter(call.args[0] for call in check.call_args_list)
                self.assertEqual(checked[uris[position]], 1)
                self.assertEqual(output.observations, ())
                listed = ", ".join(path.format(index) for index in range(MAX_DIAGNOSTIC_PATHS))
                self.assertEqual(
                    only_diagnostic(output, "identity_input_invalid").message,
                    f"{IDENTITY_MESSAGE} ({SHARED_URI_RESULTS} occurrences: {listed}, ...; "
                    f"first: {what} contains prohibited code point U+200B)",
                )

    def test_two_shared_uris_of_one_kind_keep_their_own_verdicts(self) -> None:
        # The memo is keyed by the uri text, so a valid uri checked first cannot pass a
        # refused one of the same kind that a later result names; the artifact fails closed.
        bad = "\u200b"
        indexed = [{"physicalLocation": {"artifactLocation": {"index": index}}} for index in (0, 1)]
        based = [
            {"physicalLocation": {"artifactLocation": {"uri": "src/a.py", "uriBaseId": base}}}
            for base in ("A", "B")
        ]
        runs = {
            "location uri": make_run(
                [make_result(uri=None, locations=[location]) for location in indexed],
                invocations=[RUN_CLOCK],
                artifacts=[{"location": {"uri": "src/a.py"}}, {"location": {"uri": f"src/{bad}"}}],
            ),
            "rule helpUri": make_run(
                [make_result(rule_id=rule) for rule in ("R0", "R1")],
                rules=[
                    {"id": "R0", "helpUri": f"{EXAMPLE_URI}a"},
                    {"id": "R1", "helpUri": f"{EXAMPLE_URI}{bad}"},
                ],
                invocations=[RUN_CLOCK],
            ),
            "original uri base": make_run(
                [make_result(uri=None, locations=[location]) for location in based],
                invocations=[RUN_CLOCK],
                originalUriBaseIds={"A": {"uri": "file:///work/"}, "B": {"uri": f"file:///{bad}/"}},
            ),
        }
        paths = {
            "location uri": "runs[0].results[1].locations[0].physicalLocation.artifactLocation.uri",
            "rule helpUri": "runs[0].results[1].rule.helpUri",
            "original uri base": "runs[0].originalUriBaseIds.B.uri",
        }
        for what, run in runs.items():
            with self.subTest(what=what):
                output = parse_direct(make_log(run))
                self.assertEqual(output.observations, ())
                self.assertEqual(
                    only_diagnostic(output, "identity_input_invalid").message,
                    f"{IDENTITY_MESSAGE} (1 occurrence: {paths[what]}; "
                    f"first: {what} contains prohibited code point U+200B)",
                )

    def test_a_wide_object_security_severity_is_quoted_once_in_insertion_order(self) -> None:
        small, _large = self.assert_scales(keyed_severity_log, WIDE_RESULTS)
        listed = ", ".join(f"runs[0].results[{index}]" for index in range(MAX_DIAGNOSTIC_PATHS))
        self.assertEqual(
            only_diagnostic(small, "security_severity_invalid").message,
            "security-severity is not a finite number above 0 and at most 10; ignored "
            f"({SMALL_RESULTS} occurrences: {listed}, ...; "
            "first: {'k0': 0, 'k7919': 1, 'k15838': 2, 'k23757': 3, ...})",
        )


# *--- Entry Point ---*

if __name__ == "__main__":
    unittest.main()
