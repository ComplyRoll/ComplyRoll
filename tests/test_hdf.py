# ******************************************************************************
# *Title: HDF Adapter Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for the HDF (InSpec exec-json) adapter (ADR 0013).*
# ******************************************************************************
"""Unit tests for the HDF adapter: fixture mappings, roll-ups, overlays, folds, refusals."""

# *--- Imports ---*

from __future__ import annotations

import io
import json
import re
import tempfile
import unittest
from collections.abc import Sequence
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta, timezone
from itertools import permutations
from pathlib import Path
from typing import Any
from unittest import mock

from test_replay import INGESTED_AT, RATIONALE, StoreFixture
from test_reports import summary_counts
from test_sarif import (
    GOLDEN,
    REPORT_AS_OF,
    REPORT_DETECTED_AT,
    REPORT_PERIOD_FROM,
    report_options,
)

from complyroll.adapters import IngestLimits, ingest_stig_artifact
from complyroll.adapters import hdf as hdf_module
from complyroll.adapters.base import (
    AdapterOutput,
    ArtifactProvenance,
    DiagnosticLevel,
    IngestDiagnostic,
    IngestResult,
    ParsedDocument,
)
from complyroll.adapters.common import (
    MAX_DESCRIPTION_CHARS,
    MAX_IDENTITY_CHARS,
    MAX_LIST_ITEM_CHARS,
    MAX_LIST_ITEMS,
    MAX_METADATA_VALUE_CHARS,
    MAX_OBSERVATION_JSON_BYTES,
    MAX_TITLE_CHARS,
    TRUNCATION_MARKER,
)
from complyroll.adapters.hdf import (
    HDF_CONVERTER_PLATFORM,
    HDF_CONVERTER_TOOL,
    HDF_DISPOSITION_RANK,
    HDF_MEDIA_TYPE,
    HDF_METADATA_KEYS,
    HDF_NATIVE_TOOL,
    HDF_PARSER_VERSION,
    HDF_SOURCE_TYPE,
    MAX_PROFILES_PER_DOCUMENT,
    HdfAdapter,
)
from complyroll.cli import main
from complyroll.correlation import tracking_id_for
from complyroll.history import (
    attest_detection,
    audit_history,
    correlate_cases,
    fold_all_cases,
    record_ingest,
)
from complyroll.models import Observation, ObservationDisposition, SourceSeverity
from complyroll.reports import (
    CompiledVdtReport,
    ReportCompileError,
    compile_avi_report,
    compile_avi_report_from_history,
    compile_historical_report,
    compile_historical_report_from_history,
    compile_vdt_report,
    compile_vdt_report_from_history,
)
from complyroll.reports.kev import cve_may_be_missing
from complyroll.store import MAX_EVENT_JSON_BYTES, SQLiteEventStore

# *--- Configuration ---*

NOW = datetime(2026, 8, 18, 20, 0, tzinfo=UTC)
SECOND_INGEST = NOW + timedelta(days=1)
FIXTURES = Path(__file__).parent / "fixtures"
HDF_ATTRIBUTION = ("complyroll.hdf", HDF_PARSER_VERSION, HDF_MEDIA_TYPE)

OPEN = ObservationDisposition.OPEN
ERROR = ObservationDisposition.ERROR
UNKNOWN = ObservationDisposition.UNKNOWN
PASS = ObservationDisposition.PASS
NOT_REVIEWED = ObservationDisposition.NOT_REVIEWED
NOT_APPLICABLE = ObservationDisposition.NOT_APPLICABLE

LINUX = "inspec-linux-host.hdf.json"
TRIVY = "saf-trivy-image.hdf.json"
OVERLAY = "inspec-overlay.json"
CORNERS = "hdf-spec-corners.hdf.json"

# Observation ids of every HDF fixture, in emitted order. Derived by running the adapter and
# read field by field against the plan before they were frozen.
LINUX_IDS = (
    "obs-2b1f8b0785e86b295f3a1f4288734b5bfff35163745c4c6f2a88638a5abd5624",
    "obs-425f620e25f521a8aebe4389df2eeab1d59a6ad0a9e02e9d0b13c4386b59020e",
    "obs-651f1a2f92401b66166e7a6e06f424d6193d23a7926456700951453f63fe1fae",
    "obs-e7f152fbf36db492fddc3ee75119906d9025acaf8bdea599cfd99c2a7d15da8f",
    "obs-76866a38e4741201dbedf5dee2ea7fef39c0fadbaf2808e1d3382d9d2515109f",
    "obs-563aaa914602fc585a264393ea9075f806eaf98218f6719a4332e7419bf00731",
)
TRIVY_IDS = (
    "obs-57743407f37bbeba0fbac2295ff639f12c27fd77febc41dfc01dbeba65b39519",
    "obs-a339485bcdccdf6217f93567e0f573f5aae57f9c90b6470afad26f35be765547",
    "obs-a6049562adb7185a3ab4fcf65040462c0bcda7d85cf98ebeafa230fd34305b15",
)
OVERLAY_IDS = (
    "obs-252ca5b9898729a0934843c0d6235316123782a983190f1f6a4248ff04ec6611",
    "obs-db7c8c95b443dd6c9582be4d6025b7ff2f79f720f8c12f68ab35e2bd99aa41a7",
    "obs-2bc344c966195dc16dfe77e68e678a989c68a57529939659fe7ce9acfa456759",
)
CORNER_IDS = (
    "obs-9a9f67c57e3f7ff433c420813ad505572ed24d571f25b43907613b6ab2882168",
    "obs-029ce3fd3b2b1299d9a483a3621af20f95ae8e8e88c4b45dbaf947d268adc5c2",
    "obs-fb62875145a794712cf815dc130e07e5f282a61b0a8e7f4cac85f6c4c21e0cca",
    "obs-9b4107e1f94292e6bc4b95adba6a2c7ff7e5947b4e3b75ad6d76043afbec2d85",
    "obs-f89f8a418f17568c6717e418013f38a79c8b6ed7cddc4d5587e26c679c7cad8c",
    "obs-008ad469f420fc300a900c155f87abe74c5c9af024e5642cb36668341f0ba86b",
    "obs-ac28bf390cff588026464993956ddca265bcae71479296368ba0db25082a9922",
    "obs-53afaf3750a7e0877364c0b1f6dd1794cc09706871ca8244db9b63a5d49cda0f",
)
FIXTURE_IDS = {
    LINUX: LINUX_IDS,
    TRIVY: TRIVY_IDS,
    OVERLAY: OVERLAY_IDS,
    CORNERS: CORNER_IDS,
}
# The CCIs tests/fixtures/cci-list.xml defines; fixtures 1 to 3 use no other.
CCI_LIST_NUMBERS = frozenset({"CCI-000048", "CCI-000366", "CCI-000795", "CCI-003627"})
SYNTHETIC_CCI = re.compile(r"CCI-9000[0-9]{2}")

LINUX_TARGET = "3f0c9a2e-6d4b-4c1e-9a7b-2f1e8d5c4b3a"
TRIVY_TARGET = "registry.example.test/web:1.4.2"
OVERLAY_TARGET = "7d2e4f10-3b6a-4c8d-9e1f-5a6b7c8d9e0f"
CORNERS_TARGET = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
PHOENIX = timezone(timedelta(hours=-7))

# The HDF goldens: fixtures 1 to 3 compiled with test_sarif.py's `report_options` (ADR 0013).
HDF_ARTIFACTS = (FIXTURES / LINUX, FIXTURES / TRIVY, FIXTURES / OVERLAY)
# Tracking ids in golden order, which is source record order: the three converted Trivy
# cases, then the native Linux and overlay cases.
GOLDEN_TRACKING_IDS = (
    "case-1706b7990cce1346",
    "case-057bbe4ee9dde990",
    "case-71446ac59461edb8",
    "case-181b4b18c88fe895",
    "case-db1a983f4e0a849a",
)
# Only the converted document is clockless, so the detection attestation reaches its three
# cases and no other; the attested overlay control keeps the clock of its skipped result.
CLOCKLESS_TRACKING_IDS = (
    "case-057bbe4ee9dde990",
    "case-1706b7990cce1346",
    "case-71446ac59461edb8",
)
CLOCKED_TRACKING_IDS = ("case-181b4b18c88fe895", "case-db1a983f4e0a849a")
# SYN-LNX-0001's five-day window closes at 2026-09-15T21:02:11Z, after the as-of.
NOT_OVERDUE_TRACKING_ID = "case-181b4b18c88fe895"

# The synthetic documents the builders below write.
TARGET = "0b1c2d3e-4f50-4617-8829-3a4b5c6d7e8f"
ROOT = "synthetic-profile"
CLOCK = "2026-09-05T10:00:00Z"
CLOCK_AT = datetime(2026, 9, 5, 10, 0, tzinfo=UTC)
CONTROL_PATH = "profiles[0].controls[0]"
RESULT_PATH = f"{CONTROL_PATH}.results[0]"
IMPACT_SLOT = "@@impact@@"
ATTESTED_MARKER = "Manually verified status provided through attestation"
EXPIRED_MARKER = "Manual verification status provided through attestation has expired"
BACKTRACE = ["./controls/synthetic.rb:3:in `block in synthetic_backtrace_frame'"]

# Every adapter diagnostic summary, spelled out so a rewording is a visible test change.
CONVERTED_SUMMARY = (
    "platform.name is Heimdall Tools; the source tool is heimdall-tools and the resource is "
    "the converter's target"
)
FALLBACK_SUMMARY = (
    "platform.target_id is absent, blank, or not a string; the root profile name is the resource"
)
IDENTITY_SUMMARY = "an identity input cannot be used as written"
NOT_LOADED_SUMMARY = (
    "profile status is not loaded; its controls carry no results and yield error observations"
)
INVALID_IMPACT_SUMMARY = (
    "impact is not a number from 0 to 1; it sets neither applicability nor severity"
)
INVALID_SEVERITY_SUMMARY = "severity tag is not none, low, medium, high, or critical; ignored"
WAIVED_SUMMARY = (
    "control carries waiver data; the waiver is recorded as metadata and never changes the "
    "disposition"
)
ATTESTED_SUMMARY = (
    "control carries attestation data; the attestation is recorded as metadata and never "
    "changes the disposition"
)
IMPACT_ZERO_SUMMARY = "impact is 0, so the control is not applicable whatever its results say"
INVALID_STATUS_SUMMARY = (
    "result status is not passed, failed, skipped, or error; the result is unknown"
)
INVALID_CCI_SUMMARY = "cci tag item is not a CCI-###### identifier; ignored"
SHADOWED_SUMMARY = (
    "control has no results and the same id carries results in another profile of this run; "
    "it yields no observation"
)
COLLAPSED_SUMMARY = "result folded into an observation that shares its identity"
TRUNCATED_SUMMARY = "evidence text was cut at its cap; the truncated metadata key names the members"
SANITIZED_SUMMARY = "control, format, or separator characters were removed from evidence text"
INVALID_CLOCK_SUMMARY = (
    "clock value is not an aware timestamp with a whole-minute offset in the years "
    "1970 to 9000 UTC; ignored"
)
MISSING_CLOCK_MESSAGE = (
    "source artifact does not declare an observation timestamp; observed_at is unknown"
)
NO_OBSERVATIONS_MESSAGE = "HDF document contains no usable controls"
STIGS_MESSAGE = (
    "HDF document carries a 'stigs' member; a STIG Viewer checklist is read under a .cklb or "
    ".json name"
)
CYCLE_SUMMARY = "parent_profile links form a cycle"
DANGLING_SUMMARY = "parent_profile names no profile in this document"

# The maximal observation: every identity input at its cap, every evidence member past it.
OVER_SCALAR = 600
OVER_ITEM = 300
OVER_LIST = 70
OVER_DESCRIPTION = 5_000
MAXIMAL_TRUNCATED = frozenset(
    {
        "attestation_explanation",
        "attestation_frequency",
        "attestation_status",
        "attestation_updated",
        "description",
        "failed_results",
        "failure_messages",
        "group_id",
        "nist_tags",
        "platform_name",
        "platform_release",
        "producer_version",
        "profile_sha256",
        "profile_status",
        "profile_title",
        "profile_version",
        "rule_id",
        "severity_override",
        "severity_tag",
        "source_identifiers",
        "stig_id",
        "title",
        "waiver_expiration",
        "waiver_justification",
        "waiver_skipped",
    }
)

# *--- Helpers ---*


class _Absent:
    """Marks a member a builder leaves out of the document."""

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT: Any = _Absent()


def present(members: dict[str, Any]) -> dict[str, Any]:
    """Return the members that are not ABSENT, in their given order."""
    return {key: value for key, value in members.items() if value is not ABSENT}


def make_result(
    status: Any = "passed",
    code_desc: Any = "Synthetic check",
    start_time: Any = CLOCK,
    **extra: Any,
) -> dict[str, Any]:
    """Build one result; ABSENT leaves a member out."""
    return present({"status": status, "code_desc": code_desc, "start_time": start_time, **extra})


def make_control(
    control_id: Any = "SYN-CTL-0001", results: Any = None, **members: Any
) -> dict[str, Any]:
    """Build one control with InSpec's defaults: impact 0.5, empty tags, and waiver_data {}."""
    if results is None:
        results = [make_result()]
    elif isinstance(results, (list, tuple)):
        results = list(results)
    control = {
        "id": control_id,
        "title": "Synthetic control",
        "desc": "A synthetic control description.",
        "impact": 0.5,
        "tags": {},
        "waiver_data": {},
        "results": results,
    }
    control.update(members)
    return present(control)


def make_profile(name: Any = ROOT, controls: Any = None, **members: Any) -> dict[str, Any]:
    """Build one loaded profile around the given controls."""
    profile = {
        "name": name,
        "status": "loaded",
        "controls": [make_control()] if controls is None else controls,
    }
    profile.update(members)
    return present(profile)


def make_document(
    *profiles: Any,
    target: Any = TARGET,
    platform_name: Any = "synthetic",
    version: Any = "5.22.3",
    **members: Any,
) -> dict[str, Any]:
    """Build an exec-json document around the given profiles."""
    document = {
        "platform": present({"name": platform_name, "release": "1", "target_id": target}),
        "profiles": list(profiles) if profiles else [make_profile()],
        "version": version,
    }
    document.update(members)
    return present(document)


def document_with(*controls: Any, **profile_members: Any) -> dict[str, Any]:
    """Build a one-profile document around the given controls."""
    return make_document(make_profile(controls=list(controls), **profile_members))


def run_control(*results: Any, **control_members: Any) -> AdapterOutput:
    """Parse a document of one control carrying exactly the given results."""
    return parse_direct(document_with(make_control(results=list(results), **control_members)))


def observe(*results: Any, **control_members: Any) -> Observation:
    """Return the one observation a single control with the given results yields."""
    return only_observation(run_control(*results, **control_members))


def ingest_document(
    payload: Any,
    name: str = "synthetic.hdf.json",
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


def ingest_fixture(name: str, **options: Any) -> IngestResult:
    return ingest_stig_artifact(FIXTURES / name, ingested_at=NOW, **options)


def parse_direct(
    payload: Any,
    artifact: ArtifactProvenance | None = None,
    limits: IngestLimits | None = None,
) -> AdapterOutput:
    """Run the adapter on an in-memory document, bypassing the file dispatcher."""
    if artifact is None:
        artifact = synthetic_artifact(payload)
    adapter = HdfAdapter() if limits is None else HdfAdapter(limits)
    return adapter.parse(ParsedDocument("json", payload), artifact, ingested_at=NOW)


def synthetic_artifact(payload: Any) -> ArtifactProvenance:
    return ArtifactProvenance.from_bytes(
        path=Path("synthetic.hdf.json"),
        content=json.dumps(payload).encode("utf-8"),
        media_type=HDF_MEDIA_TYPE,
        parser_name="complyroll.hdf",
        parser_version=HDF_PARSER_VERSION,
        ingested_at=NOW,
    )


def provenance_of(path: Path) -> ArtifactProvenance:
    return ArtifactProvenance.from_bytes(
        path=path,
        content=path.read_bytes(),
        media_type=HDF_MEDIA_TYPE,
        parser_name="complyroll.hdf",
        parser_version=HDF_PARSER_VERSION,
        ingested_at=NOW,
    )


def fixture_payload(name: str) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return payload


def only_observation(result: IngestResult | AdapterOutput) -> Observation:
    """Return the single observation a document yields, failing loudly otherwise."""
    if len(result.observations) != 1:
        raise AssertionError(
            f"expected one observation, got {len(result.observations)}: {result.diagnostics}"
        )
    return result.observations[0]


def only_diagnostic(result: IngestResult | AdapterOutput, code: str) -> IngestDiagnostic:
    """Return the single diagnostic carrying the code, failing loudly otherwise."""
    matches = [item for item in result.diagnostics if item.code == code]
    if len(matches) != 1:
        raise AssertionError(f"expected one {code} diagnostic, got {len(matches)}")
    return matches[0]


def diagnostic_codes(result: IngestResult | AdapterOutput) -> list[str]:
    return [item.code for item in result.diagnostics]


def diagnostic_lines(
    result: IngestResult | AdapterOutput,
) -> list[tuple[DiagnosticLevel, str, str]]:
    return [(item.level, item.code, item.message) for item in result.diagnostics]


def errors_of(result: IngestResult) -> list[tuple[str, str]]:
    return [(item.code, item.message) for item in result.errors]


def metadata(observation: Observation) -> dict[str, str]:
    return dict(observation.source_metadata)


def attribution(result: IngestResult) -> tuple[str, str, str]:
    if result.artifact is None:
        raise AssertionError("result carries no artifact provenance")
    return (
        result.artifact.parser_name,
        result.artifact.parser_version,
        result.artifact.media_type,
    )


def by_record(result: IngestResult | AdapterOutput) -> dict[str, Observation]:
    """Index observations by control id; every caller has distinct ids."""
    indexed = {item.source_record_id: item for item in result.observations}
    if len(indexed) != len(result.observations):
        raise AssertionError("observations do not have distinct control ids")
    return indexed


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


def coalesced(summary: str, *paths: str, count: int | None = None, detail: str = "") -> str:
    """Render the message the shared Diagnostics writes for one code."""
    total = len(paths) if count is None else count
    noun = "occurrence" if total == 1 else "occurrences"
    listed = ", ".join(paths) + (", ..." if total > len(paths) else "")
    first = f"; first: {detail}" if detail else ""
    return f"{summary} ({total} {noun}: {listed}{first})"


def encoded(*items: str) -> str:
    """Encode a list member the way the adapter stores one."""
    return json.dumps(list(items), ensure_ascii=False, separators=(",", ":"))


def counts(**named: int) -> dict[str, str]:
    """Return the six result counts with the named ones set and the total summed."""
    values = {key: named.get(key, 0) for key in ("passed", "failed", "skipped", "error")}
    values["unknown"] = named.get("unknown", 0)
    rendered = {f"{key}_count": str(value) for key, value in values.items()}
    rendered["result_count"] = str(sum(values.values()))
    return rendered


def numbered(char: str, index: int, length: int) -> str:
    """Return distinct text of the given length; the index leads, so it survives any cut."""
    return f"{index:02d}" + char * (length - 2)


def reversed_everywhere(payload: dict[str, Any]) -> dict[str, Any]:
    """Reverse every profile, control, and result list of a fixture payload in place."""
    payload["profiles"].reverse()
    for profile in payload["profiles"]:
        profile["controls"].reverse()
        for control in profile["controls"]:
            control["results"].reverse()
    return payload


def raw_impact(literal: str) -> bytes:
    """Return a one-control document whose impact is the given JSON number literal."""
    text = json.dumps(document_with(make_control(impact=IMPACT_SLOT)))
    return text.replace(json.dumps(IMPACT_SLOT), literal).encode("utf-8")


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Run one CLI invocation and capture its streams."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def maximal_document(char: str) -> dict[str, Any]:
    """Build one control with every identity input at its cap and every member past its cap.

    A root profile with no controls and a leaf under it carry the only control, so
    profile_parent is set. Seventy failed results fill failed_results and failure_messages
    past MAX_LIST_ITEMS with items past MAX_LIST_ITEM_CHARS, seventy CVE ids cut the
    identifiers, and both a waiver and an attestation fill their scalars.
    """
    over = char * OVER_SCALAR
    root = numbered(char, 1, MAX_IDENTITY_CHARS)
    leaf = numbered(char, 2, MAX_IDENTITY_CHARS)
    results = [
        make_result(
            "failed",
            numbered(char, index, OVER_ITEM),
            message=numbered(char, index, OVER_ITEM),
        )
        for index in range(OVER_LIST)
    ]
    control = make_control(
        char * MAX_IDENTITY_CHARS,
        results,
        title=over,
        desc=char * OVER_DESCRIPTION,
        tags={
            "severityoverride": over,
            "severity": over,
            "gid": over,
            "rid": over,
            "stig_id": over,
            "nist": [numbered(char, index, OVER_ITEM) for index in range(OVER_LIST)],
            "cve": [f"CVE-2099-{index:019d}" for index in range(OVER_LIST)],
        },
        waiver_data={
            "justification": over,
            "expiration_date": over,
            "run": True,
            "skipped_due_to_waiver": over,
            "message": over,
        },
        attestation_data={
            "status": over,
            "explanation": over,
            "frequency": over,
            "updated": over,
            "updated_by": "Riley Example",
        },
    )
    profile_members = {"title": over, "version": over, "sha256": over, "status": over}
    return {
        "platform": {"name": over, "release": over, "target_id": char * MAX_IDENTITY_CHARS},
        "profiles": [
            make_profile(root, [], **profile_members),
            make_profile(leaf, [control], parent_profile=root, **profile_members),
        ],
        "version": over,
    }


def compile_hdf_golden(
    artifacts: Sequence[Path] = HDF_ARTIFACTS, *, record_failed_imports: bool = False
) -> CompiledVdtReport:
    """Compile the HDF golden the way the documented command line does."""
    return compile_vdt_report(
        list(artifacts),
        options=report_options(detected_at=REPORT_DETECTED_AT),
        record_failed_imports=record_failed_imports,
    )


# *--- Fixture Invariants ---*


class HdfFixtureInvariantTests(unittest.TestCase):
    """Properties every HDF fixture holds regardless of its producer."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.results = {name: ingest_fixture(name) for name in FIXTURE_IDS}

    def test_every_fixture_is_attributed_to_the_hdf_adapter(self) -> None:
        for name, result in self.results.items():
            with self.subTest(fixture=name):
                self.assertEqual(attribution(result), HDF_ATTRIBUTION)
                self.assertTrue(result.successful, result.errors)
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
                identities = [identity_of(item) for item in result.observations]
                self.assertEqual(len(identities), len(set(identities)))

    def test_every_observation_id_is_derived_from_its_fingerprint(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    self.assertEqual(observation.observation_id, observation.derived_observation_id)
                    self.assertEqual(observation.source_type, HDF_SOURCE_TYPE)
                    self.assertEqual(observation.parser_name, "complyroll.hdf")
                    self.assertEqual(observation.parser_version, HDF_PARSER_VERSION)
                    self.assertEqual(observation.source_artifact_name, name)

    def test_every_metadata_key_belongs_to_the_fixed_vocabulary(self) -> None:
        self.assertEqual(len(HDF_METADATA_KEYS), 38)
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    keys = [key for key, _value in observation.source_metadata]
                    self.assertEqual(keys, sorted(keys))
                    self.assertTrue(set(keys) <= HDF_METADATA_KEYS, set(keys) - HDF_METADATA_KEYS)

    def test_every_observation_round_trips_through_canonical_json_under_the_cap(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.observation_id):
                    encoded_json = observation.to_canonical_json()
                    self.assertLessEqual(
                        len(encoded_json.encode("utf-8")), MAX_OBSERVATION_JSON_BYTES
                    )
                    self.assertEqual(
                        Observation.from_canonical_dict(json.loads(encoded_json)), observation
                    )

    def test_every_diagnostic_is_located_at_the_artifact_name(self) -> None:
        for name, result in self.results.items():
            for diagnostic in result.diagnostics:
                with self.subTest(fixture=name, code=diagnostic.code):
                    self.assertEqual(diagnostic.location, name)

    def test_every_fixture_carries_synthetic_identifiers_only(self) -> None:
        for name, result in self.results.items():
            for observation in result.observations:
                with self.subTest(fixture=name, observation=observation.source_record_id):
                    self.assertRegex(observation.source_record_id, r"^(SYN-|CVE-2099-)")
                    for identifier in observation.source_identifiers:
                        if identifier.startswith("CCI-"):
                            if name == CORNERS:
                                self.assertRegex(identifier, SYNTHETIC_CCI)
                            else:
                                self.assertIn(identifier, CCI_LIST_NUMBERS)
                        elif identifier.startswith("CVE-"):
                            self.assertTrue(identifier.startswith("CVE-2099-"), identifier)


# *--- Fixture Mapping ---*


LINUX_COMMON = {
    "platform_name": "ubuntu",
    "platform_release": "22.04",
    "producer_version": "5.22.3",
    "profile_name": "synthetic-linux-baseline",
    "profile_sha256": "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
    "profile_status": "loaded",
    "profile_title": "Synthetic Linux Baseline",
    "profile_version": "1.4.0",
    "occurrence_count": "1",
    "disposition_source": "results",
}


class InspecLinuxHostTests(unittest.TestCase):
    """inspec-linux-host.hdf.json: a native run, one per-result shape per control."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture(LINUX)
        cls.controls = by_record(cls.result)

    def test_six_controls_yield_six_target_observations_under_the_root_profile(self) -> None:
        self.assertEqual(len(self.result.observations), 6)
        for observation in self.result.observations:
            with self.subTest(control=observation.source_record_id):
                self.assertEqual(observation.source_tool, HDF_NATIVE_TOOL)
                self.assertEqual(
                    (observation.resource.resource_type, observation.resource.resource_id),
                    ("target", LINUX_TARGET),
                )
                self.assertEqual(observation.context_key, "synthetic-linux-baseline")
                self.assertEqual(observation.ingested_at, NOW)

    def test_each_control_reads_its_disposition_and_severity(self) -> None:
        expected = {
            "SYN-LNX-0001": (OPEN, SourceSeverity.MEDIUM),
            "SYN-LNX-0002": (PASS, SourceSeverity.HIGH),
            "SYN-LNX-0003": (NOT_REVIEWED, SourceSeverity.MEDIUM),
            "SYN-LNX-0004": (NOT_APPLICABLE, SourceSeverity.INFORMATIONAL),
            "SYN-LNX-0005": (ERROR, SourceSeverity.HIGH),
            "SYN-LNX-0006": (NOT_REVIEWED, SourceSeverity.LOW),
        }
        self.assertEqual(
            {
                record: (item.disposition, item.source_severity)
                for record, item in self.controls.items()
            },
            expected,
        )

    def test_observed_at_keeps_each_result_clock_as_written(self) -> None:
        for index, record in enumerate(sorted(self.controls), start=11):
            with self.subTest(control=record):
                observed = self.controls[record].observed_at
                self.assertEqual(observed, datetime(2026, 9, 10, 14, 2, index, tzinfo=PHOENIX))
                assert observed is not None
                self.assertEqual(observed.isoformat(), f"2026-09-10T14:02:{index}-07:00")
        self.assertEqual(
            self.controls["SYN-LNX-0001"].observed_at, datetime(2026, 9, 10, 21, 2, 11, tzinfo=UTC)
        )

    def test_the_diagnostics_are_the_impact_zero_trail_and_one_waiver(self) -> None:
        # Controls 1 to 5 carry waiver_data {}, InSpec's default, so only control 6 warns.
        self.assertEqual(
            diagnostic_lines(self.result),
            [
                (
                    DiagnosticLevel.INFO,
                    "impact_zero_not_applicable",
                    coalesced(
                        IMPACT_ZERO_SUMMARY,
                        "profiles[0].controls[3]",
                        detail="results would read OPEN",
                    ),
                ),
                (
                    DiagnosticLevel.WARNING,
                    "control_waived",
                    coalesced(WAIVED_SUMMARY, "profiles[0].controls[5]"),
                ),
            ],
        )

    def test_the_failed_control_carries_its_full_evidence(self) -> None:
        observation = self.controls["SYN-LNX-0001"]
        self.assertEqual(
            observation.title, "The synthd service must restrict its configuration file mode"
        )
        self.assertEqual(
            observation.description,
            "The synthd configuration file must not be writable by other users.",
        )
        self.assertEqual(observation.source_identifiers, ("CCI-000366",))
        self.assertEqual(
            metadata(observation),
            {
                **LINUX_COMMON,
                **counts(failed=1),
                "impact": "0.5",
                "severity_source": "severity",
                "severity_tag": "medium",
                "group_id": "SYN-V-100001",
                "rule_id": "SYN-V-100001r1_rule",
                "stig_id": "SYN-LNX-0001",
                "nist_tags": encoded("CM-6 b"),
                "failed_results": encoded(
                    'File /etc/synthd/synthd.conf is expected not to be more permissive than "0640"'
                ),
                "failure_messages": encoded(
                    'expected File /etc/synthd/synthd.conf not to be more permissive than "0640"'
                ),
            },
        )

    def test_a_null_desc_falls_back_to_the_default_description(self) -> None:
        observation = self.controls["SYN-LNX-0002"]
        self.assertEqual(observation.description, "The synthd service must start at boot.")
        self.assertEqual(observation.source_identifiers, ())
        self.assertEqual(
            metadata(observation),
            {**LINUX_COMMON, **counts(passed=1), "impact": "0.7", "severity_source": "impact"},
        )

    def test_a_skipped_manual_check_reads_not_reviewed(self) -> None:
        self.assertEqual(
            metadata(self.controls["SYN-LNX-0003"]),
            {**LINUX_COMMON, **counts(skipped=1), "impact": "0.5", "severity_source": "impact"},
        )

    def test_impact_zero_reads_not_applicable_beside_a_failed_result(self) -> None:
        self.assertEqual(
            metadata(self.controls["SYN-LNX-0004"]),
            {
                **LINUX_COMMON,
                **counts(failed=1),
                "disposition_source": "impact_zero",
                "impact": "0.0",
                "severity_source": "impact",
                "failed_results": encoded("Package synthd-runtime is expected to be installed"),
                "failure_messages": encoded("expected that Package synthd-runtime is installed"),
            },
        )

    def test_a_check_that_raised_reads_error_and_never_pass(self) -> None:
        observation = self.controls["SYN-LNX-0005"]
        self.assertEqual(observation.disposition, ERROR)
        self.assertEqual(
            metadata(observation),
            {
                **LINUX_COMMON,
                **counts(error=1),
                "impact": "0.7",
                "severity_source": "impact",
                "failed_results": encoded("Synthd plugin policy is expected to require signatures"),
                "failure_messages": encoded(
                    "Synthetic error: undefined local variable or method `synthd_plugin_policy'"
                ),
            },
        )
        # The backtrace is read for presence only; its text reaches nothing.
        self.assertNotIn("load_with_context", observation.to_canonical_json())

    def test_the_waived_control_reads_its_skipped_result(self) -> None:
        observation = self.controls["SYN-LNX-0006"]
        self.assertEqual(
            metadata(observation),
            {
                **LINUX_COMMON,
                **counts(skipped=1),
                "impact": "0.3",
                "severity_source": "impact",
                "waived": "true",
                "waiver_expiration": "2026-09-14",
                "waiver_justification": (
                    "Synthetic waiver: the debug listener is bound to loopback on this test host."
                ),
                "waiver_run": "false",
                "waiver_skipped": "true",
            },
        )
        self.assertNotIn("Skipped control due to waiver", observation.to_canonical_json())
        self.assertEqual(
            [
                item.source_record_id
                for item in self.result.observations
                if "waived" in metadata(item)
            ],
            ["SYN-LNX-0006"],
        )


TRIVY_COMMON = {
    "platform_name": "Heimdall Tools",
    "platform_release": "heimdall_tools@2.6.0",
    "producer_version": "2.6.0",
    "profile_name": "Trivy Vulnerability Scan",
    "profile_title": "Trivy Vulnerability Scan",
    "profile_status": "loaded",
    "occurrence_count": "1",
    "disposition_source": "results",
    "nist_tags": encoded("RA-5", "SI-2"),
    "severity_source": "severity",
    **counts(failed=1),
}


class SafTrivyImageTests(unittest.TestCase):
    """saf-trivy-image.hdf.json: a converted scan, one control per CVE, no clocks."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture(TRIVY)
        cls.controls = by_record(cls.result)

    def test_three_failed_vulnerabilities_yield_three_open_image_observations(self) -> None:
        self.assertEqual(list(self.controls), ["CVE-2099-0001", "CVE-2099-0102", "CVE-2099-0103"])
        for observation in self.result.observations:
            with self.subTest(control=observation.source_record_id):
                self.assertEqual(observation.disposition, OPEN)
                self.assertEqual(observation.source_tool, HDF_CONVERTER_TOOL)
                self.assertEqual(
                    (observation.resource.resource_type, observation.resource.resource_id),
                    ("target", TRIVY_TARGET),
                )
                self.assertEqual(observation.context_key, "Trivy Vulnerability Scan")
                self.assertIsNone(observation.observed_at)

    def test_the_diagnostics_name_the_converter_and_the_missing_clock_once(self) -> None:
        self.assertEqual(
            diagnostic_lines(self.result),
            [
                (
                    DiagnosticLevel.INFO,
                    "converted_document",
                    coalesced(CONVERTED_SUMMARY, "platform"),
                ),
                (DiagnosticLevel.WARNING, "source_timestamp_missing", MISSING_CLOCK_MESSAGE),
            ],
        )

    def test_the_severity_tag_wins_over_the_impact(self) -> None:
        self.assertEqual(
            {record: item.source_severity for record, item in self.controls.items()},
            {
                "CVE-2099-0001": SourceSeverity.HIGH,
                "CVE-2099-0102": SourceSeverity.CRITICAL,
                "CVE-2099-0103": SourceSeverity.CRITICAL,
            },
        )
        self.assertEqual(metadata(self.controls["CVE-2099-0103"])["impact"], "0.5")

    def test_every_control_carries_its_cve_and_its_evidence(self) -> None:
        expected = {
            "CVE-2099-0001": (
                ("CVE-2099-0001", "CWE-79"),
                "0.7",
                "high",
                "Package synthlib 2.4.0 is vulnerable; fixed in 2.4.1",
                "Installed version 2.4.0 of synthlib is affected by CVE-2099-0001",
            ),
            "CVE-2099-0102": (
                ("CVE-2099-0102",),
                "0.9",
                "critical",
                "Package synthcrypt 3.0.8 is vulnerable; fixed in 3.0.9",
                "Installed version 3.0.8 of synthcrypt is affected by CVE-2099-0102",
            ),
            "CVE-2099-0103": (
                ("CVE-2099-0103",),
                "0.5",
                "critical",
                "Package synthzip 1.2.3 is vulnerable; fixed in 1.2.4",
                "Installed version 1.2.3 of synthzip is affected by CVE-2099-0103",
            ),
        }
        for record, (identifiers, impact, tag, failed, message) in expected.items():
            with self.subTest(control=record):
                observation = self.controls[record]
                self.assertEqual(observation.source_identifiers, identifiers)
                self.assertFalse(cve_may_be_missing(observation))
                self.assertEqual(
                    metadata(observation),
                    {
                        **TRIVY_COMMON,
                        "impact": impact,
                        "severity_tag": tag,
                        "failed_results": encoded(failed),
                        "failure_messages": encoded(message),
                    },
                )

    def test_the_description_is_desc_and_the_fix_text_is_never_read(self) -> None:
        observation = self.controls["CVE-2099-0001"]
        self.assertEqual(
            observation.title,
            "CVE-2099-0001: synthlib: synthetic cross-site scripting in the template renderer",
        )
        self.assertEqual(
            observation.description,
            "A synthetic flaw in synthlib's template renderer lets an attacker inject script "
            "into a rendered page.",
        )
        for item in self.result.observations:
            self.assertNotIn("Upgrade synth", item.to_canonical_json())
            # An empty version or sha256 is absent rather than recorded as empty text.
            self.assertNotIn("profile_version", metadata(item))
            self.assertNotIn("profile_sha256", metadata(item))


OVERLAY_PLATFORM = {
    "platform_name": "redhat",
    "platform_release": "9.4",
    "producer_version": "5.22.3",
    "profile_status": "loaded",
    "occurrence_count": "1",
    "disposition_source": "results",
}
OVERLAY_BASELINE = {
    **OVERLAY_PLATFORM,
    "profile_name": "synthetic-rhel-baseline",
    "profile_parent": "synthetic-rhel-overlay",
    "profile_sha256": "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
    "profile_title": "Synthetic RHEL Baseline",
    "profile_version": "1.2.0",
}


class InspecOverlayTests(unittest.TestCase):
    """inspec-overlay.json: a wrapper over a baseline, sniffed from a bare .json name."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture(OVERLAY)
        cls.controls = by_record(cls.result)

    def test_the_bare_json_is_sniffed_to_the_hdf_adapter(self) -> None:
        self.assertEqual(attribution(self.result), HDF_ATTRIBUTION)
        self.assertTrue(self.result.successful, self.result.errors)

    def test_every_observation_sits_under_the_wrapper_context(self) -> None:
        self.assertEqual(list(self.controls), ["SYN-RHL-0001", "SYN-RHL-0002", "SYN-RHL-0100"])
        for observation in self.result.observations:
            with self.subTest(control=observation.source_record_id):
                self.assertEqual(observation.context_key, "synthetic-rhel-overlay")
                self.assertEqual(
                    (observation.resource.resource_type, observation.resource.resource_id),
                    ("target", OVERLAY_TARGET),
                )
                self.assertEqual(observation.source_tool, HDF_NATIVE_TOOL)

    def test_the_diagnostics_are_the_attestation_and_two_shadowed_copies(self) -> None:
        self.assertEqual(
            diagnostic_lines(self.result),
            [
                (
                    DiagnosticLevel.WARNING,
                    "control_attested",
                    coalesced(ATTESTED_SUMMARY, "profiles[1].controls[1]"),
                ),
                (
                    DiagnosticLevel.INFO,
                    "profile_control_shadowed",
                    coalesced(
                        SHADOWED_SUMMARY, "profiles[0].controls[0]", "profiles[0].controls[1]"
                    ),
                ),
            ],
        )

    def test_the_baseline_failure_reads_open_under_the_leaf_profile(self) -> None:
        observation = self.controls["SYN-RHL-0001"]
        self.assertEqual(observation.disposition, OPEN)
        self.assertEqual(observation.source_severity, SourceSeverity.HIGH)
        self.assertEqual(observation.source_identifiers, ("CCI-000048",))
        self.assertEqual(observation.observed_at, datetime(2026, 9, 8, 9, 1, 30, tzinfo=PHOENIX))
        self.assertEqual(
            metadata(observation),
            {
                **OVERLAY_BASELINE,
                **counts(failed=1),
                "impact": "0.7",
                "severity_source": "severity",
                "severity_tag": "high",
                "nist_tags": encoded("AC-8 a"),
                "failed_results": encoded(
                    'Processes synthd users is expected not to include "root"'
                ),
                "failure_messages": encoded('expected ["root"] not to include "root"'),
            },
        )

    def test_the_attested_control_reads_pass_with_its_skipped_clock(self) -> None:
        observation = self.controls["SYN-RHL-0002"]
        self.assertEqual(observation.disposition, PASS)
        self.assertEqual(observation.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(observation.observed_at, datetime(2026, 9, 8, 9, 2, tzinfo=PHOENIX))
        self.assertEqual(
            metadata(observation),
            {
                **OVERLAY_BASELINE,
                **counts(passed=1, skipped=1),
                "impact": "0.5",
                "severity_source": "impact",
                "attested": "true",
                "attestation_status": "passed",
                "attestation_explanation": (
                    "Synthetic attestation: the backup key rotation record for this test host "
                    "was reviewed."
                ),
                "attestation_frequency": "annually",
                "attestation_updated": "2026-09-12",
            },
        )

    def test_neither_the_attester_nor_the_apply_instant_is_recorded(self) -> None:
        for observation in self.result.observations:
            text = observation.to_canonical_json()
            for absent in ("Jordan Example", "Updated By", "16:05"):
                with self.subTest(control=observation.source_record_id, text=absent):
                    self.assertNotIn(absent, text)

    def test_the_wrapper_control_carries_the_wrapper_profile(self) -> None:
        observation = self.controls["SYN-RHL-0100"]
        self.assertEqual(
            (observation.disposition, observation.source_severity), (PASS, SourceSeverity.LOW)
        )
        self.assertEqual(
            metadata(observation),
            {
                **OVERLAY_PLATFORM,
                **counts(passed=1),
                "profile_name": "synthetic-rhel-overlay",
                "profile_sha256": (
                    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
                ),
                "profile_title": "Synthetic RHEL Overlay",
                "profile_version": "2.0.0",
                "impact": "0.3",
                "severity_source": "impact",
            },
        )

    def test_depends_is_never_read(self) -> None:
        artifact = provenance_of(FIXTURES / OVERLAY)
        original = parse_direct(fixture_payload(OVERLAY), artifact)
        stripped = fixture_payload(OVERLAY)
        for profile in stripped["profiles"]:
            del profile["depends"]
        renamed = fixture_payload(OVERLAY)
        renamed["profiles"][0]["depends"][0]["name"] = "synthetic-alias-of-the-baseline"
        for variant in (stripped, renamed):
            output = parse_direct(variant, artifact)
            self.assertEqual(
                [item.to_canonical_json() for item in output.observations],
                [item.to_canonical_json() for item in original.observations],
            )
            self.assertEqual(output.diagnostics, original.diagnostics)


CORNERS_COMMON = {
    "platform_name": "debian",
    "platform_release": "12",
    "producer_version": "5.22.3",
    "profile_name": "synthetic-corners",
    "profile_sha256": "c0ffee00" * 8,
    "profile_status": "loaded",
    "profile_title": "Synthetic HDF Corners",
    "profile_version": "0.9.0",
    "occurrence_count": "1",
    "disposition_source": "results",
}
SKIP_MESSAGE = "Skipping profile: 'synthetic-corners-extra' on unsupported platform: 'debian/12'."


class HdfSpecCornerTests(unittest.TestCase):
    """hdf-spec-corners.hdf.json: every tolerated corner of the format in one document."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = ingest_fixture(CORNERS)
        cls.controls = by_record(cls.result)

    def test_the_corners_are_successful_with_warnings(self) -> None:
        self.assertTrue(self.result.successful, self.result.errors)
        self.assertEqual(
            list(self.controls),
            [f"SYN-CRN-000{index}" for index in range(1, 8)] + ["SYN-CRN-0100"],
        )
        for observation in self.result.observations:
            with self.subTest(control=observation.source_record_id):
                self.assertEqual(
                    (observation.resource.resource_type, observation.resource.resource_id),
                    ("target", CORNERS_TARGET),
                )

    def test_the_diagnostics_are_pinned_in_first_seen_order(self) -> None:
        control = "profiles[0].controls"
        self.assertEqual(
            diagnostic_lines(self.result),
            [
                (
                    DiagnosticLevel.WARNING,
                    "invalid_result_status",
                    coalesced(INVALID_STATUS_SUMMARY, f"{control}[0].results[0]", detail="'bogus'"),
                ),
                (
                    DiagnosticLevel.WARNING,
                    "invalid_impact",
                    coalesced(
                        INVALID_IMPACT_SUMMARY, f"{control}[1]", f"{control}[2]", detail="'0.5'"
                    ),
                ),
                (
                    DiagnosticLevel.WARNING,
                    "invalid_severity_tag",
                    coalesced(INVALID_SEVERITY_SUMMARY, f"{control}[1]", detail="'urgent'"),
                ),
                (
                    DiagnosticLevel.WARNING,
                    "source_timestamp_invalid",
                    coalesced(INVALID_CLOCK_SUMMARY, f"{control}[2].results[0].start_time"),
                ),
                (
                    DiagnosticLevel.WARNING,
                    "evidence_sanitized",
                    coalesced(SANITIZED_SUMMARY, f"{control}[3]"),
                ),
                (
                    DiagnosticLevel.WARNING,
                    "control_waived",
                    coalesced(WAIVED_SUMMARY, f"{control}[6]"),
                ),
                (
                    DiagnosticLevel.WARNING,
                    "control_attested",
                    coalesced(ATTESTED_SUMMARY, f"{control}[6]"),
                ),
                (
                    DiagnosticLevel.WARNING,
                    "profile_not_loaded",
                    coalesced(
                        NOT_LOADED_SUMMARY,
                        "profiles[1]",
                        detail=f"status {'skipped'!r}, status_message {SKIP_MESSAGE!r}",
                    ),
                ),
                (DiagnosticLevel.WARNING, "source_timestamp_missing", MISSING_CLOCK_MESSAGE),
                (
                    DiagnosticLevel.WARNING,
                    "evidence_truncated",
                    coalesced(TRUNCATED_SUMMARY, f"{control}[3]"),
                ),
                (
                    DiagnosticLevel.INFO,
                    "results_collapsed",
                    coalesced(COLLAPSED_SUMMARY, f"{control}[4]"),
                ),
            ],
        )

    def test_a_bogus_status_reads_unknown(self) -> None:
        observation = self.controls["SYN-CRN-0001"]
        self.assertEqual(observation.disposition, UNKNOWN)
        self.assertEqual(observation.source_severity, SourceSeverity.MEDIUM)
        self.assertEqual(observation.observed_at, CLOCK_AT)
        self.assertEqual(
            metadata(observation),
            {**CORNERS_COMMON, **counts(unknown=1), "impact": "0.5", "severity_source": "impact"},
        )

    def test_a_string_impact_and_an_unknown_tag_leave_the_severity_unknown(self) -> None:
        observation = self.controls["SYN-CRN-0002"]
        self.assertEqual(
            (observation.disposition, observation.source_severity), (PASS, SourceSeverity.UNKNOWN)
        )
        # The blank start_time is silent, so the clock is the second result's.
        self.assertEqual(observation.observed_at, datetime(2026, 9, 5, 10, 1, tzinfo=UTC))
        self.assertEqual(
            metadata(observation),
            {
                **CORNERS_COMMON,
                **counts(passed=2),
                "severity_source": "none",
                "severity_tag": "urgent",
            },
        )

    def test_the_override_beats_the_tag_and_a_bool_impact_is_ignored(self) -> None:
        observation = self.controls["SYN-CRN-0003"]
        self.assertEqual(
            (observation.disposition, observation.source_severity),
            (OPEN, SourceSeverity.CRITICAL),
        )
        self.assertIsNone(observation.observed_at)
        self.assertEqual(
            metadata(observation),
            {
                **CORNERS_COMMON,
                **counts(failed=1),
                "severity_source": "severityoverride",
                "severity_override": "critical",
                "severity_tag": "low",
                "failed_results": encoded("Synthetic check with a seconds-bearing offset"),
                "failure_messages": encoded("Synthetic failure with an unusable clock"),
            },
        )

    def test_a_sanitized_title_and_seventy_ccis_cut_to_sixty_four(self) -> None:
        observation = self.controls["SYN-CRN-0004"]
        self.assertEqual(observation.title, "A zerowidth space in the title and seventy CCIs")
        self.assertEqual(
            observation.source_identifiers,
            tuple(f"CCI-9000{index:02d}" for index in range(MAX_LIST_ITEMS)),
        )
        self.assertTrue(cve_may_be_missing(observation))
        self.assertEqual(
            metadata(observation),
            {
                **CORNERS_COMMON,
                **counts(passed=1),
                "impact": "0.5",
                "severity_source": "impact",
                "truncated": encoded("source_identifiers"),
            },
        )

    def test_one_id_twice_in_one_profile_folds_into_one_observation(self) -> None:
        observation = self.controls["SYN-CRN-0005"]
        self.assertEqual(observation.disposition, OPEN)
        self.assertEqual(observation.observed_at, datetime(2026, 9, 5, 10, 4, tzinfo=UTC))
        self.assertEqual(
            metadata(observation),
            {
                **CORNERS_COMMON,
                **counts(passed=1, failed=1),
                "occurrence_count": "2",
                "impact": "0.5",
                "severity_source": "impact",
                "failed_results": encoded("Synthetic first entry fails"),
                "failure_messages": encoded("Synthetic failure in the first entry"),
            },
        )

    def test_a_waiver_and_an_attestation_leave_the_failure_open(self) -> None:
        observation = self.controls["SYN-CRN-0006"]
        self.assertEqual(
            (observation.disposition, observation.source_severity), (OPEN, SourceSeverity.HIGH)
        )
        self.assertEqual(observation.observed_at, datetime(2026, 9, 5, 10, 6, tzinfo=UTC))
        self.assertEqual(
            metadata(observation),
            {
                **CORNERS_COMMON,
                **counts(failed=2),
                "impact": "0.7",
                "severity_source": "impact",
                "waived": "true",
                "waiver_expiration": "2026-12-31",
                "waiver_justification": "Synthetic waiver that still runs the control.",
                "waiver_run": "true",
                "waiver_skipped": "false",
                "attested": "true",
                "attestation_status": "failed",
                "attestation_explanation": "Synthetic attestation that the control still fails.",
                "attestation_frequency": "monthly",
                "attestation_updated": "2026-09-05",
                "failed_results": encoded("Synthetic check that fails under a waiver"),
                "failure_messages": encoded("Synthetic failure under a waiver"),
            },
        )
        self.assertNotIn("Riley Example", observation.to_canonical_json())

    def test_the_converter_error_spelling_reads_error_beside_a_null_waiver(self) -> None:
        observation = self.controls["SYN-CRN-0007"]
        self.assertEqual(observation.disposition, ERROR)
        self.assertEqual(
            metadata(observation),
            {
                **CORNERS_COMMON,
                **counts(error=1),
                "impact": "0.5",
                "severity_source": "impact",
                "failed_results": encoded("Synthetic check the converter marked as an error"),
                "failure_messages": encoded("Synthetic converter error text"),
            },
        )

    def test_a_skipped_profile_yields_an_error_observation_per_control(self) -> None:
        observation = self.controls["SYN-CRN-0100"]
        self.assertEqual(
            (observation.disposition, observation.source_severity),
            (ERROR, SourceSeverity.MEDIUM),
        )
        self.assertEqual(observation.context_key, "synthetic-corners-extra")
        self.assertIsNone(observation.observed_at)
        self.assertEqual(
            metadata(observation),
            {
                **CORNERS_COMMON,
                **counts(),
                "profile_name": "synthetic-corners-extra",
                "profile_sha256": "d00dfeed" * 8,
                "profile_status": "skipped",
                "profile_title": "Synthetic Skipped Profile",
                "profile_version": "0.1.0",
                "disposition_source": "no_results",
                "impact": "0.5",
                "severity_source": "impact",
            },
        )


# *--- Dispositions ---*


class HdfDispositionTests(unittest.TestCase):
    """The per-result and per-control tables, the backtrace rule, and the three deviations."""

    def test_each_known_status_reads_its_disposition_and_count(self) -> None:
        for status, disposition, key in (
            ("failed", OPEN, "failed"),
            ("error", ERROR, "error"),
            ("passed", PASS, "passed"),
            ("skipped", NOT_REVIEWED, "skipped"),
        ):
            with self.subTest(status=status):
                output = run_control(make_result(status))
                observation = only_observation(output)
                self.assertEqual(observation.disposition, disposition)
                self.assertEqual(
                    {
                        name: value
                        for name, value in metadata(observation).items()
                        if name.endswith("_count") and name != "occurrence_count"
                    },
                    counts(**{key: 1}),
                )
                self.assertEqual(metadata(observation)["disposition_source"], "results")
                self.assertEqual(output.diagnostics, ())

    def test_any_other_status_reads_unknown_with_a_warning(self) -> None:
        for status in (ABSENT, None, "", "  ", "Passed", "FAILED", " passed", "bogus", 1, True):
            with self.subTest(status=status):
                output = run_control(make_result(status))
                observation = only_observation(output)
                self.assertEqual(observation.disposition, UNKNOWN)
                self.assertEqual(metadata(observation)["unknown_count"], "1")
                raw = None if status is ABSENT else status
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "invalid_result_status",
                            coalesced(INVALID_STATUS_SUMMARY, RESULT_PATH, detail=repr(raw)),
                        )
                    ],
                )

    def test_the_rank_table_is_pinned(self) -> None:
        self.assertEqual(
            HDF_DISPOSITION_RANK,
            {OPEN: 5, ERROR: 4, UNKNOWN: 3, PASS: 2, NOT_REVIEWED: 1, NOT_APPLICABLE: 0},
        )

    def test_a_control_reads_its_highest_ranked_result(self) -> None:
        for statuses, disposition in (
            (("passed", "failed"), OPEN),
            (("error", "bogus"), ERROR),
            (("bogus", "error"), ERROR),
            (("bogus", "passed"), UNKNOWN),
            (("passed", "skipped"), PASS),
            (("skipped", "passed"), PASS),
            (("skipped", "bogus"), UNKNOWN),
            (("skipped", "skipped"), NOT_REVIEWED),
            (("error", "passed", "skipped"), ERROR),
        ):
            with self.subTest(statuses=statuses):
                observation = observe(*(make_result(status) for status in statuses))
                self.assertEqual(observation.disposition, disposition)
                self.assertEqual(metadata(observation)["result_count"], str(len(statuses)))
                self.assertEqual(metadata(observation)["disposition_source"], "results")

    def test_deviation_a_a_failure_beside_an_error_reads_open(self) -> None:
        # Heimdall reads Profile Error here; a failure the runner observed is never hidden.
        for statuses in (("failed", "error"), ("error", "failed")):
            with self.subTest(statuses=statuses):
                observation = observe(*(make_result(status) for status in statuses))
                self.assertEqual(observation.disposition, OPEN)
                self.assertEqual(
                    (metadata(observation)["failed_count"], metadata(observation)["error_count"]),
                    ("1", "1"),
                )

    def test_deviation_b_a_waiver_never_moves_the_disposition(self) -> None:
        waiver = {"justification": "Synthetic waiver.", "run": True, "skipped_due_to_waiver": False}
        observation = observe(make_result("failed"), waiver_data=waiver)
        self.assertEqual(observation.disposition, OPEN)
        self.assertEqual(metadata(observation)["waived"], "true")

    def test_deviation_c_impact_zero_beside_an_error_reads_not_applicable(self) -> None:
        output = run_control(make_result("error"), impact=0)
        observation = only_observation(output)
        self.assertEqual(observation.disposition, NOT_APPLICABLE)
        self.assertEqual(metadata(observation)["disposition_source"], "impact_zero")
        self.assertEqual(metadata(observation)["error_count"], "1")
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.INFO,
                    "impact_zero_not_applicable",
                    coalesced(IMPACT_ZERO_SUMMARY, CONTROL_PATH, detail="results would read ERROR"),
                )
            ],
        )

    def test_empty_results_read_error_from_no_results(self) -> None:
        output = run_control()
        observation = only_observation(output)
        self.assertEqual(observation.disposition, ERROR)
        self.assertIsNone(observation.observed_at)
        self.assertEqual(metadata(observation)["disposition_source"], "no_results")
        self.assertEqual(metadata(observation)["result_count"], "0")
        self.assertEqual(diagnostic_codes(output), ["source_timestamp_missing"])

    def test_impact_zero_with_no_results_reads_not_applicable(self) -> None:
        output = run_control(impact=0.0)
        self.assertEqual(only_observation(output).disposition, NOT_APPLICABLE)
        self.assertEqual(
            only_diagnostic(output, "impact_zero_not_applicable").message,
            coalesced(IMPACT_ZERO_SUMMARY, CONTROL_PATH, detail="results would read ERROR"),
        )

    def test_a_profile_that_did_not_load_warns_once_with_its_status(self) -> None:
        for status, message in (("skipped", SKIP_MESSAGE), ("failed", ""), (5, ABSENT)):
            with self.subTest(status=status):
                document = make_document(
                    make_profile(
                        controls=[make_control(results=[]), make_control("SYN-CTL-0002", [])],
                        status=status,
                        status_message=message,
                    )
                )
                output = parse_direct(document)
                self.assertEqual([item.disposition for item in output.observations], [ERROR, ERROR])
                raw = None if message is ABSENT else message
                self.assertEqual(
                    only_diagnostic(output, "profile_not_loaded").message,
                    coalesced(
                        NOT_LOADED_SUMMARY,
                        "profiles[0]",
                        detail=f"status {status!r}, status_message {raw!r}",
                    ),
                )
                expected = (
                    "skipped" if status == "skipped" else ("failed" if status == "failed" else None)
                )
                self.assertEqual(metadata(output.observations[0]).get("profile_status"), expected)

    def test_a_loaded_or_absent_profile_status_is_silent(self) -> None:
        for status in ("loaded", ABSENT, None):
            with self.subTest(status=status):
                output = parse_direct(make_document(make_profile(status=status)))
                self.assertEqual(output.diagnostics, ())
                self.assertEqual(only_observation(output).disposition, PASS)

    def test_impact_zero_decides_before_a_profile_that_did_not_load(self) -> None:
        output = parse_direct(
            make_document(
                make_profile(
                    controls=[make_control(results=[], impact=0), make_control("SYN-CTL-0002", [])],
                    status="skipped",
                    status_message=SKIP_MESSAGE,
                )
            )
        )
        self.assertEqual(
            [
                (item.disposition, metadata(item)["disposition_source"])
                for item in output.observations
            ],
            [(NOT_APPLICABLE, "impact_zero"), (ERROR, "no_results")],
        )
        self.assertEqual(
            diagnostic_codes(output),
            ["profile_not_loaded", "impact_zero_not_applicable", "source_timestamp_missing"],
        )

    def test_a_passed_result_that_raised_reads_error(self) -> None:
        output = run_control(make_result("passed", exception="NameError", backtrace=BACKTRACE))
        observation = only_observation(output)
        self.assertEqual(observation.disposition, ERROR)
        self.assertEqual(metadata(observation)["error_count"], "1")
        self.assertEqual(metadata(observation)["passed_count"], "0")
        self.assertEqual(output.diagnostics, ())

    def test_neither_native_errored_shape_reads_pass_or_open(self) -> None:
        for status in ("passed", "failed", "skipped", "bogus", ABSENT):
            with self.subTest(status=status):
                output = run_control(
                    make_result(status, exception="NameError", backtrace=BACKTRACE)
                )
                self.assertEqual(only_observation(output).disposition, ERROR)
                # The backtrace decides first, so an unknown status never warns.
                self.assertEqual(output.diagnostics, ())

    def test_a_raised_failure_still_reads_open_beside_a_plain_failure(self) -> None:
        observation = observe(
            make_result("failed", exception="RuntimeError", backtrace=BACKTRACE),
            make_result("failed"),
        )
        self.assertEqual(observation.disposition, OPEN)
        self.assertEqual(
            (metadata(observation)["error_count"], metadata(observation)["failed_count"]),
            ("1", "1"),
        )

    def test_an_exception_without_a_backtrace_keeps_its_status(self) -> None:
        for status, disposition in (("passed", PASS), ("failed", OPEN), ("skipped", NOT_REVIEWED)):
            for backtrace in (ABSENT, None, False, ""):
                with self.subTest(status=status, backtrace=backtrace):
                    observation = observe(
                        make_result(status, exception="NameError", backtrace=backtrace)
                    )
                    self.assertEqual(observation.disposition, disposition)

    def test_any_other_backtrace_value_reads_error(self) -> None:
        # Presence is what counts: only null, false, and empty text read as absent.
        for backtrace in (BACKTRACE, [], 0, "trace", {}, True):
            with self.subTest(backtrace=backtrace):
                self.assertEqual(
                    observe(make_result("passed", backtrace=backtrace)).disposition, ERROR
                )

    def test_impact_zero_beside_a_raised_check_reads_not_applicable(self) -> None:
        output = run_control(
            make_result("passed", exception="NameError", backtrace=BACKTRACE), impact=0
        )
        self.assertEqual(only_observation(output).disposition, NOT_APPLICABLE)
        self.assertEqual(
            only_diagnostic(output, "impact_zero_not_applicable").message,
            coalesced(IMPACT_ZERO_SUMMARY, CONTROL_PATH, detail="results would read ERROR"),
        )

    def test_the_exception_text_reaches_failure_messages_and_the_backtrace_never_does(
        self,
    ) -> None:
        observation = observe(
            make_result(
                "passed", "Synthetic raised check", exception="NameError", backtrace=BACKTRACE
            )
        )
        self.assertEqual(metadata(observation)["failed_results"], encoded("Synthetic raised check"))
        self.assertEqual(metadata(observation)["failure_messages"], encoded("NameError"))
        text = observation.to_canonical_json()
        self.assertNotIn("synthetic_backtrace_frame", text)
        self.assertNotIn("synthetic.rb", text)

    def test_a_message_is_preferred_to_the_exception_text(self) -> None:
        observation = observe(
            make_result("error", message="Synthetic error text", exception="NameError")
        )
        self.assertEqual(metadata(observation)["failure_messages"], encoded("Synthetic error text"))
        self.assertNotIn("NameError", observation.to_canonical_json())

    def test_passing_and_skipped_results_record_no_failure_text(self) -> None:
        observation = observe(
            make_result("passed", message="Synthetic pass text"),
            make_result("skipped", skip_message="Synthetic skip text"),
        )
        self.assertNotIn("failed_results", metadata(observation))
        self.assertNotIn("failure_messages", metadata(observation))


# *--- Severity ---*


class HdfSeverityTests(unittest.TestCase):
    """Override, then tag, then the impact band, then unknown; never PAIN."""

    def test_the_first_usable_source_decides(self) -> None:
        cases = (
            (
                {"severityoverride": "low", "severity": "high"},
                0.9,
                SourceSeverity.LOW,
                "severityoverride",
            ),
            ({"severity": "high"}, 0.1, SourceSeverity.HIGH, "severity"),
            (
                {"severityoverride": "urgent", "severity": "low"},
                0.9,
                SourceSeverity.LOW,
                "severity",
            ),
            ({"severity": "urgent"}, 0.9, SourceSeverity.CRITICAL, "impact"),
            ({}, 0.5, SourceSeverity.MEDIUM, "impact"),
            ({}, ABSENT, SourceSeverity.UNKNOWN, "none"),
            ({}, None, SourceSeverity.UNKNOWN, "none"),
        )
        for tags, impact, severity, source in cases:
            with self.subTest(tags=tags, impact=impact):
                observation = observe(make_result(), tags=tags, impact=impact)
                self.assertEqual(observation.source_severity, severity)
                self.assertEqual(metadata(observation)["severity_source"], source)

    def test_the_five_names_map_to_their_severities(self) -> None:
        for name, severity in (
            ("none", SourceSeverity.INFORMATIONAL),
            ("low", SourceSeverity.LOW),
            ("medium", SourceSeverity.MEDIUM),
            ("high", SourceSeverity.HIGH),
            ("critical", SourceSeverity.CRITICAL),
        ):
            for member in ("severity", "severityoverride"):
                with self.subTest(name=name, member=member):
                    output = run_control(make_result(), tags={member: name}, impact=ABSENT)
                    self.assertEqual(only_observation(output).source_severity, severity)
                    self.assertEqual(output.diagnostics, ())

    def test_case_and_surrounding_space_are_ignored_and_the_tag_is_stored_stripped(self) -> None:
        for raw in ("HIGH", "High", "hIgH", " high ", "\thigh\n"):
            with self.subTest(raw=raw):
                output = run_control(make_result(), tags={"severity": raw})
                observation = only_observation(output)
                self.assertEqual(observation.source_severity, SourceSeverity.HIGH)
                self.assertEqual(metadata(observation)["severity_tag"], raw.strip())
                self.assertEqual(output.diagnostics, ())

    def test_any_other_tag_warns_and_falls_through(self) -> None:
        for raw, stored in (
            ("urgent", "urgent"),
            ("", None),
            ("   ", None),
            (3, None),
            (["high"], None),
            (True, None),
            ("moderate", "moderate"),
        ):
            with self.subTest(raw=raw):
                output = run_control(make_result(), tags={"severity": raw}, impact=0.7)
                observation = only_observation(output)
                self.assertEqual(observation.source_severity, SourceSeverity.HIGH)
                self.assertEqual(metadata(observation)["severity_source"], "impact")
                self.assertEqual(metadata(observation).get("severity_tag"), stored)
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "invalid_severity_tag",
                            coalesced(INVALID_SEVERITY_SUMMARY, CONTROL_PATH, detail=repr(raw)),
                        )
                    ],
                )

    def test_a_null_tag_is_silent(self) -> None:
        output = run_control(make_result(), tags={"severity": None, "severityoverride": None})
        self.assertEqual(output.diagnostics, ())
        self.assertEqual(metadata(only_observation(output))["severity_source"], "impact")

    def test_the_impact_band_edges_follow_the_inspec_table(self) -> None:
        for impact, severity in (
            (0.09, SourceSeverity.INFORMATIONAL),
            (0.1, SourceSeverity.LOW),
            (0.39, SourceSeverity.LOW),
            (0.4, SourceSeverity.MEDIUM),
            (0.69, SourceSeverity.MEDIUM),
            (0.7, SourceSeverity.HIGH),
            (0.89, SourceSeverity.HIGH),
            (0.9, SourceSeverity.CRITICAL),
            (1, SourceSeverity.CRITICAL),
            (1.0, SourceSeverity.CRITICAL),
        ):
            with self.subTest(impact=impact):
                observation = observe(make_result(), impact=impact)
                self.assertEqual(observation.source_severity, severity)
                self.assertEqual(observation.disposition, PASS)

    def test_a_valid_impact_is_recorded_as_its_json_text(self) -> None:
        for impact, text, disposition in (
            (0.5, "0.5", PASS),
            (1, "1", PASS),
            (1.0, "1.0", PASS),
            (0, "0", NOT_APPLICABLE),
            (0.0, "0.0", NOT_APPLICABLE),
            (-0.0, "0.0", NOT_APPLICABLE),
        ):
            with self.subTest(impact=impact):
                observation = observe(make_result(), impact=impact)
                self.assertEqual(metadata(observation)["impact"], text)
                self.assertEqual(observation.disposition, disposition)

    def test_an_invalid_impact_warns_and_sets_neither_applicability_nor_severity(self) -> None:
        for impact in (
            "0.5",
            "0",
            True,
            False,
            1.5,
            2,
            -1,
            -0.1,
            [0.5],
            {},
            float("inf"),
            float("nan"),
        ):
            with self.subTest(impact=impact):
                output = run_control(make_result("failed"), impact=impact)
                observation = only_observation(output)
                # False equals 0 in Python, and still never reads not applicable.
                self.assertEqual(observation.disposition, OPEN)
                self.assertEqual(observation.source_severity, SourceSeverity.UNKNOWN)
                self.assertNotIn("impact", metadata(observation))
                self.assertEqual(metadata(observation)["severity_source"], "none")
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "invalid_impact",
                            coalesced(INVALID_IMPACT_SUMMARY, CONTROL_PATH, detail=repr(impact)),
                        )
                    ],
                )

    def test_an_invalid_impact_still_lets_a_tag_decide(self) -> None:
        observation = observe(make_result(), impact="0.9", tags={"severity": "low"})
        self.assertEqual(observation.source_severity, SourceSeverity.LOW)
        self.assertEqual(metadata(observation)["severity_source"], "severity")

    def test_out_of_range_json_numbers_warn_through_the_dispatcher(self) -> None:
        huge = "1" + "0" * 399
        widest = "9" * 4_300
        for literal, detail in (
            ("1e400", "inf"),
            ("-1e400", "-inf"),
            (huge, huge),
            ("-" + huge, "-" + huge),
            (
                widest,
                widest[: MAX_METADATA_VALUE_CHARS - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER,
            ),
        ):
            with self.subTest(digits=len(literal)):
                result = ingest_document(None, raw=raw_impact(literal))
                self.assertTrue(result.successful, result.errors)
                observation = only_observation(result)
                self.assertNotIn("impact", metadata(observation))
                self.assertEqual(observation.disposition, PASS)
                self.assertEqual(
                    diagnostic_lines(result),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "invalid_impact",
                            coalesced(INVALID_IMPACT_SUMMARY, CONTROL_PATH, detail=detail),
                        )
                    ],
                )

    def test_an_integer_past_the_parser_digit_limit_is_a_parse_failure(self) -> None:
        result = ingest_document(None, raw=raw_impact("9" * 4_301))
        self.assertEqual(attribution(result), HDF_ATTRIBUTION)
        self.assertEqual(result.observations, ())
        self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])
        self.assertIn("4300 digits", result.errors[0].message)

    def test_the_cli_ingests_a_huge_integer_impact_with_a_warning(self) -> None:
        for literal in ("1" + "0" * 399, "9" * 4_300):
            with self.subTest(digits=len(literal)):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "huge.hdf.json"
                    path.write_bytes(raw_impact(literal))
                    code, out, err = run_cli(
                        ["ingest", str(path), "--db", str(Path(directory) / "x.db")]
                    )
                self.assertEqual(code, 0, err)
                self.assertIn("recorded 1 observation", out)
                self.assertIn("warning: invalid_impact:", err)
                self.assertNotIn("Traceback", out + err)


# *--- Waivers and Attestations ---*


class HdfWaiverAttestationTests(unittest.TestCase):
    """Waivers and attestations are recorded metadata that never move a disposition."""

    def test_absent_null_or_empty_data_means_no_waiver_or_attestation(self) -> None:
        for member in ("waiver_data", "attestation_data"):
            for value in (ABSENT, None, {}, [], "", False, 0):
                with self.subTest(member=member, value=value):
                    output = run_control(make_result("failed"), **{member: value})
                    observation = only_observation(output)
                    self.assertEqual(output.diagnostics, ())
                    self.assertNotIn("waived", metadata(observation))
                    self.assertNotIn("attested", metadata(observation))
                    self.assertEqual(observation.disposition, OPEN)

    def test_a_waiver_is_recorded_with_a_warning_and_the_disposition_unmoved(self) -> None:
        waiver = {
            "justification": "Synthetic waiver justification.",
            "expiration_date": "2026-12-31",
            "run": True,
            "skipped_due_to_waiver": False,
            "message": "Waiver expired on 2026-12-31, evaluating control normally",
        }
        for status, disposition in (("failed", OPEN), ("passed", PASS), ("skipped", NOT_REVIEWED)):
            with self.subTest(status=status):
                output = run_control(make_result(status), waiver_data=waiver)
                observation = only_observation(output)
                self.assertEqual(observation.disposition, disposition)
                recorded = {
                    key: value
                    for key, value in metadata(observation).items()
                    if key.startswith("waive")
                }
                self.assertEqual(
                    recorded,
                    {
                        "waived": "true",
                        "waiver_expiration": "2026-12-31",
                        "waiver_justification": "Synthetic waiver justification.",
                        "waiver_run": "true",
                        "waiver_skipped": "false",
                    },
                )
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "control_waived",
                            coalesced(WAIVED_SUMMARY, CONTROL_PATH),
                        )
                    ],
                )
                # The generated waiver message restates recorded members and is dropped.
                self.assertNotIn("evaluating control normally", observation.to_canonical_json())

    def test_skipped_due_to_waiver_is_recorded_by_its_type(self) -> None:
        for raw, recorded in (
            (True, "true"),
            (False, "false"),
            ("true", "true"),
            (" Yes ", "Yes"),
            (None, None),
            (ABSENT, None),
            (1, None),
        ):
            with self.subTest(raw=raw):
                waiver = present({"justification": "Synthetic.", "skipped_due_to_waiver": raw})
                observation = observe(make_result("skipped"), waiver_data=waiver)
                self.assertEqual(metadata(observation).get("waiver_skipped"), recorded)

    def test_a_waiver_run_flag_is_recorded_only_as_a_bool(self) -> None:
        for raw, recorded in ((True, "true"), (False, "false"), ("false", None), (None, None)):
            with self.subTest(raw=raw):
                observation = observe(make_result(), waiver_data={"run": raw})
                self.assertEqual(metadata(observation).get("waiver_run"), recorded)
                self.assertEqual(metadata(observation)["waived"], "true")

    def test_an_attestation_is_recorded_and_the_marker_result_joins_the_roll_up(self) -> None:
        attestation = {
            "control_id": "SYN-CTL-0001",
            "status": "passed",
            "explanation": "Synthetic attestation explanation.",
            "frequency": "quarterly",
            "updated": "2026-09-04",
            "updated_by": "Riley Example",
        }
        output = run_control(
            make_result("skipped", "No-op"),
            make_result(
                "passed",
                ATTESTED_MARKER,
                "2026-09-06T18:00:00.000Z",
                message="Attestation:\nStatus: passed\nUpdated By: Riley Example",
            ),
            attestation_data=attestation,
        )
        observation = only_observation(output)
        self.assertEqual(observation.disposition, PASS)
        self.assertEqual(observation.observed_at, CLOCK_AT)
        self.assertEqual(
            {
                key: value
                for key, value in metadata(observation).items()
                if key.startswith("attest")
            },
            {
                "attested": "true",
                "attestation_explanation": "Synthetic attestation explanation.",
                "attestation_frequency": "quarterly",
                "attestation_status": "passed",
                "attestation_updated": "2026-09-04",
            },
        )
        self.assertEqual(
            (metadata(observation)["passed_count"], metadata(observation)["skipped_count"]),
            ("1", "1"),
        )
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.WARNING,
                    "control_attested",
                    coalesced(ATTESTED_SUMMARY, CONTROL_PATH),
                )
            ],
        )
        text = observation.to_canonical_json()
        for absent in ("Riley Example", "Updated By", "updated_by", "2026-09-06T18"):
            self.assertNotIn(absent, text)

    def test_an_attested_failure_reads_open_with_no_failure_text(self) -> None:
        observation = observe(
            make_result("skipped", "No-op"),
            make_result("failed", ATTESTED_MARKER, message="Attestation:\nStatus: failed"),
            attestation_data={"status": "failed"},
        )
        self.assertEqual(observation.disposition, OPEN)
        self.assertEqual(metadata(observation)["failed_count"], "1")
        self.assertEqual(metadata(observation)["attested"], "true")
        self.assertNotIn("failed_results", metadata(observation))
        self.assertNotIn("failure_messages", metadata(observation))

    def test_an_expired_attestation_reads_not_reviewed_and_says_expired(self) -> None:
        output = run_control(
            make_result("skipped", "No-op"),
            make_result("skipped", EXPIRED_MARKER, message="Attestation expired"),
            attestation_data={"status": "passed", "frequency": "monthly"},
        )
        observation = only_observation(output)
        self.assertEqual(observation.disposition, NOT_REVIEWED)
        self.assertEqual(metadata(observation)["attested"], "expired")
        self.assertEqual(metadata(observation)["skipped_count"], "2")
        self.assertEqual(
            only_diagnostic(output, "control_attested").message,
            coalesced(ATTESTED_SUMMARY, CONTROL_PATH, detail="expired"),
        )

    def test_an_expired_marker_anywhere_among_the_results_says_expired(self) -> None:
        for trailing in (make_result("passed", ATTESTED_MARKER), make_result("passed")):
            with self.subTest(trailing=trailing["code_desc"]):
                output = run_control(
                    make_result("skipped", "No-op"),
                    make_result("skipped", EXPIRED_MARKER),
                    trailing,
                    attestation_data={"status": "passed"},
                )
                self.assertEqual(metadata(only_observation(output))["attested"], "expired")
                self.assertEqual(
                    only_diagnostic(output, "control_attested").message,
                    coalesced(ATTESTED_SUMMARY, CONTROL_PATH, detail="expired"),
                )

    def test_the_marker_is_an_ordinary_result_without_attestation_data(self) -> None:
        for attestation in (ABSENT, None, {}, [], "", False, 0):
            with self.subTest(attestation=attestation):
                output = run_control(
                    make_result(
                        "failed",
                        ATTESTED_MARKER,
                        "2026-09-05T09:00:00Z",
                        message="Synthetic failure text",
                    ),
                    attestation_data=attestation,
                )
                observation = only_observation(output)
                self.assertEqual(observation.disposition, OPEN)
                self.assertEqual(observation.observed_at, datetime(2026, 9, 5, 9, tzinfo=UTC))
                self.assertEqual(metadata(observation)["failed_results"], encoded(ATTESTED_MARKER))
                self.assertEqual(
                    metadata(observation)["failure_messages"], encoded("Synthetic failure text")
                )
                self.assertNotIn("attested", metadata(observation))
                self.assertEqual(output.diagnostics, ())

    def test_a_non_object_attestation_is_recorded_and_its_marker_lends_nothing(self) -> None:
        results = (
            make_result("skipped", "Synthetic converted check", ""),
            make_result(
                "failed",
                ATTESTED_MARKER,
                "2026-09-05T09:00:00Z",
                message="Updated By: Synthetic Person",
            ),
        )
        for attestation in (["x"], "x", True, 5):
            with self.subTest(attestation=attestation):
                output = run_control(*results, attestation_data=attestation)
                observation = only_observation(output)
                recorded = metadata(observation)
                self.assertEqual(observation.disposition, OPEN)
                self.assertIsNone(observation.observed_at)
                self.assertNotIn("failed_results", recorded)
                self.assertNotIn("failure_messages", recorded)
                self.assertNotIn("Updated By", observation.to_canonical_json())
                self.assertEqual(
                    {key: value for key, value in recorded.items() if key.startswith("attest")},
                    {"attested": "true"},
                )
                self.assertEqual(
                    only_diagnostic(output, "control_attested").message,
                    coalesced(
                        ATTESTED_SUMMARY, CONTROL_PATH, detail="attestation_data is not an object"
                    ),
                )
                self.assertEqual(
                    diagnostic_codes(output), ["control_attested", "source_timestamp_missing"]
                )
        # An empty value is no attestation, so the same marker is an ordinary failure.
        for attestation in ([], ""):
            with self.subTest(attestation=attestation):
                output = run_control(*results, attestation_data=attestation)
                observation = only_observation(output)
                self.assertEqual(observation.observed_at, datetime(2026, 9, 5, 9, tzinfo=UTC))
                self.assertEqual(metadata(observation)["failed_results"], encoded(ATTESTED_MARKER))
                self.assertEqual(
                    metadata(observation)["failure_messages"],
                    encoded("Updated By: Synthetic Person"),
                )
                self.assertNotIn("attested", metadata(observation))
                self.assertEqual(output.diagnostics, ())

    def test_a_non_object_waiver_is_recorded_with_no_member_read(self) -> None:
        for waiver in (["x"], "x", True, 5):
            with self.subTest(waiver=waiver):
                output = run_control(make_result("failed"), waiver_data=waiver)
                observation = only_observation(output)
                self.assertEqual(observation.disposition, OPEN)
                self.assertEqual(
                    {
                        key: value
                        for key, value in metadata(observation).items()
                        if key.startswith("waive")
                    },
                    {"waived": "true"},
                )
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "control_waived",
                            coalesced(
                                WAIVED_SUMMARY, CONTROL_PATH, detail="waiver_data is not an object"
                            ),
                        )
                    ],
                )

    def test_an_expired_marker_under_a_non_object_attestation_names_both(self) -> None:
        output = run_control(
            make_result("skipped", "No-op"),
            make_result("skipped", EXPIRED_MARKER, "2026-09-06T18:00:00Z"),
            attestation_data="x",
        )
        observation = only_observation(output)
        self.assertEqual(observation.disposition, NOT_REVIEWED)
        self.assertEqual(observation.observed_at, CLOCK_AT)
        self.assertEqual(metadata(observation)["attested"], "expired")
        self.assertEqual(
            only_diagnostic(output, "control_attested").message,
            coalesced(
                ATTESTED_SUMMARY, CONTROL_PATH, detail="expired; attestation_data is not an object"
            ),
        )

    def test_a_converted_control_attested_later_stays_clockless(self) -> None:
        output = run_control(
            make_result("failed", "Synthetic converted check", ""),
            make_result("passed", ATTESTED_MARKER, "2026-09-05T18:00:00.000Z"),
            attestation_data={"status": "passed"},
        )
        observation = only_observation(output)
        self.assertIsNone(observation.observed_at)
        self.assertEqual(observation.disposition, OPEN)
        self.assertEqual(diagnostic_codes(output), ["control_attested", "source_timestamp_missing"])

    def test_the_attester_is_never_recorded(self) -> None:
        observation = observe(
            make_result("skipped", "No-op"),
            make_result(
                "passed",
                ATTESTED_MARKER,
                message=(
                    "Attestation:\nStatus: passed\n\nUpdated: 2026-09-05\nUpdated By: Riley Example"
                ),
            ),
            attestation_data={"status": "passed", "updated_by": "Riley Example"},
        )
        text = observation.to_canonical_json()
        self.assertNotIn("Riley Example", text)
        self.assertNotIn("Updated By", text)


# *--- Clocks ---*


class HdfClockTests(unittest.TestCase):
    """observed_at is the earliest kept result start_time, and nothing else."""

    def test_the_earliest_start_time_is_kept(self) -> None:
        observation = observe(
            make_result(start_time="2026-09-05T10:05:00Z"),
            make_result(start_time="2026-09-05T10:01:00Z"),
            make_result(start_time="2026-09-05T10:03:00Z"),
        )
        self.assertEqual(observation.observed_at, datetime(2026, 9, 5, 10, 1, tzinfo=UTC))

    def test_one_instant_in_two_spellings_keeps_one_spelling_in_either_order(self) -> None:
        spellings = ("2026-09-05T10:00:00Z", "2026-09-05T03:00:00-07:00")
        for ordered in (spellings, tuple(reversed(spellings))):
            with self.subTest(order=ordered):
                observation = observe(*(make_result(start_time=clock) for clock in ordered))
                assert observation.observed_at is not None
                self.assertEqual(observation.observed_at, CLOCK_AT)
                self.assertEqual(observation.observed_at.isoformat(), "2026-09-05T03:00:00-07:00")

    def test_a_blank_or_null_start_time_is_silently_absent(self) -> None:
        for start_time in ("", "   ", None, ABSENT):
            with self.subTest(start_time=start_time):
                output = run_control(make_result(start_time=start_time))
                self.assertIsNone(only_observation(output).observed_at)
                self.assertEqual(diagnostic_codes(output), ["source_timestamp_missing"])

    def test_an_unusable_clock_warns_at_its_start_time_path(self) -> None:
        for start_time in (
            "2026-09-05T10:00:00+05:30:15",
            "2026-09-05T10:00:00",
            "9001-01-01T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "2026-09-05T24:00:01Z",
            "2026-09-05T24:30:00Z",
            "not a clock",
            1757066400,
        ):
            with self.subTest(start_time=start_time):
                output = run_control(make_result(start_time=start_time))
                self.assertIsNone(only_observation(output).observed_at)
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "source_timestamp_invalid",
                            coalesced(INVALID_CLOCK_SUMMARY, f"{RESULT_PATH}.start_time"),
                        ),
                        (
                            DiagnosticLevel.WARNING,
                            "source_timestamp_missing",
                            MISSING_CLOCK_MESSAGE,
                        ),
                    ],
                )

    def test_an_unusable_clock_beside_a_usable_one_keeps_the_usable_one(self) -> None:
        output = run_control(
            make_result(start_time="2026-09-05T10:00:00+05:30:15"),
            make_result(start_time="2026-09-05T10:02:00Z"),
        )
        self.assertEqual(
            only_observation(output).observed_at, datetime(2026, 9, 5, 10, 2, tzinfo=UTC)
        )
        self.assertEqual(diagnostic_codes(output), ["source_timestamp_invalid"])

    def test_hour_24_with_zero_minutes_names_the_next_midnight(self) -> None:
        for start_time in ("2026-09-05T24:00:00Z", "2026-09-05T24:00Z", "2026-09-05T24:00:00.000Z"):
            with self.subTest(start_time=start_time):
                output = run_control(make_result(start_time=start_time))
                self.assertEqual(
                    only_observation(output).observed_at, datetime(2026, 9, 6, tzinfo=UTC)
                )
                self.assertEqual(output.diagnostics, ())

    def test_no_document_clock_stands_in_and_the_warning_comes_once(self) -> None:
        output = parse_direct(
            document_with(
                make_control("SYN-CTL-0001", [make_result()]),
                make_control("SYN-CTL-0002", [make_result(start_time="")]),
                make_control("SYN-CTL-0003", [make_result(start_time=None)]),
            )
        )
        self.assertEqual([item.observed_at for item in output.observations], [CLOCK_AT, None, None])
        self.assertEqual(
            diagnostic_lines(output),
            [(DiagnosticLevel.WARNING, "source_timestamp_missing", MISSING_CLOCK_MESSAGE)],
        )

    def test_an_attestation_result_clock_is_never_kept_even_when_earlier(self) -> None:
        observation = observe(
            make_result("skipped", "No-op", "2026-09-05T10:05:00Z"),
            make_result("passed", ATTESTED_MARKER, "2026-09-05T09:00:00Z"),
            attestation_data={"status": "passed"},
        )
        self.assertEqual(observation.observed_at, datetime(2026, 9, 5, 10, 5, tzinfo=UTC))

    def test_an_attestation_result_clock_is_never_parsed(self) -> None:
        output = run_control(
            make_result("skipped", "No-op"),
            make_result("passed", ATTESTED_MARKER, "not a clock"),
            attestation_data={"status": "passed"},
        )
        self.assertNotIn("source_timestamp_invalid", diagnostic_codes(output))


# *--- Identifiers ---*


class HdfIdentifierTests(unittest.TestCase):
    """CCIs matched whole; CVE, GHSA, and CWE ids from the id, title, and tags; NIST never."""

    def test_cci_items_are_matched_whole_and_ascii_only(self) -> None:
        bad = (
            "CCI-00036",
            "CCI-0003660",
            "cci-000366",
            "CCI-٠٠٠٣٦٦",
            "xCCI-000366",
            "CCI-000366x",
            366,
            None,
        )
        output = run_control(make_result(), tags={"cci": [" CCI-000366 ", *bad]})
        self.assertEqual(only_observation(output).source_identifiers, ("CCI-000366",))
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.WARNING,
                    "invalid_cci_list",
                    coalesced(
                        INVALID_CCI_SUMMARY,
                        *[CONTROL_PATH] * 5,
                        count=len(bad),
                        detail="'CCI-00036'",
                    ),
                )
            ],
        )

    def test_a_string_cci_tag_is_one_item(self) -> None:
        output = run_control(make_result(), tags={"cci": "CCI-000366"})
        self.assertEqual(only_observation(output).source_identifiers, ("CCI-000366",))
        self.assertEqual(output.diagnostics, ())

    def test_cve_ghsa_and_cwe_ids_come_from_the_id_title_and_tags(self) -> None:
        observation = observe(
            make_result("failed"),
            control_id="CVE-2099-0001",
            title="Synthetic flaw also tracked as ghsa-ABCD-efgh-2345",
            tags={"cve": ["cve-2099-0002"], "cwe": ["CWE-079", "CWE-20"]},
        )
        self.assertEqual(
            observation.source_identifiers,
            ("CVE-2099-0001", "CVE-2099-0002", "CWE-20", "CWE-79", "GHSA-abcd-efgh-2345"),
        )

    def test_the_description_and_results_are_never_mined(self) -> None:
        observation = observe(
            make_result("failed", "CVE-2099-0003 in the check", message="CVE-2099-0004"),
            desc="The description names CVE-2099-0005.",
        )
        self.assertEqual(observation.source_identifiers, ())

    def test_non_ascii_digits_never_become_an_identifier(self) -> None:
        observation = observe(
            make_result(),
            control_id="CVE-2099-٠٠٠١",
            tags={"cwe": ["CWE-٧٩"]},
        )
        self.assertEqual(observation.source_identifiers, ())

    def test_nist_gid_rid_and_stig_id_are_metadata_only(self) -> None:
        observation = observe(
            make_result(),
            tags={
                "nist": ["AC-2", "CM-6 b"],
                "gid": "SYN-V-100001",
                "rid": "SYN-V-100001r1_rule",
                "stig_id": "SYN-CTL-0001",
            },
        )
        self.assertEqual(observation.source_identifiers, ())
        self.assertEqual(metadata(observation)["nist_tags"], encoded("AC-2", "CM-6 b"))
        self.assertEqual(
            (
                metadata(observation)["group_id"],
                metadata(observation)["rule_id"],
                metadata(observation)["stig_id"],
            ),
            ("SYN-V-100001", "SYN-V-100001r1_rule", "SYN-CTL-0001"),
        )
        # The three STIG ids are scalars, so an array, a number, or a bool is dropped unnamed.
        dropped = run_control(
            make_result(), tags={"gid": ["SYN-V-100001"], "rid": 100001, "stig_id": True}
        )
        self.assertFalse(
            {"group_id", "rule_id", "stig_id"} & set(metadata(only_observation(dropped)))
        )
        self.assertEqual(diagnostic_codes(dropped), [])

    def test_seventy_ccis_are_cut_to_sixty_four_and_the_cut_is_named(self) -> None:
        ccis = [f"CCI-9000{index:02d}" for index in range(70)]
        output = run_control(make_result(), tags={"cci": list(reversed(ccis))})
        observation = only_observation(output)
        self.assertEqual(observation.source_identifiers, tuple(ccis[:MAX_LIST_ITEMS]))
        self.assertEqual(metadata(observation)["truncated"], encoded("source_identifiers"))
        self.assertTrue(cve_may_be_missing(observation))
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.WARNING,
                    "evidence_truncated",
                    coalesced(TRUNCATED_SUMMARY, CONTROL_PATH),
                )
            ],
        )

    def test_sixty_four_ccis_and_a_cve_lose_the_cve_and_say_so(self) -> None:
        ccis = [f"CCI-9000{index:02d}" for index in range(MAX_LIST_ITEMS)]
        observation = observe(make_result("failed"), tags={"cci": ccis, "cve": ["CVE-2099-0001"]})
        self.assertEqual(observation.source_identifiers, tuple(ccis))
        self.assertNotIn("CVE-2099-0001", observation.source_identifiers)
        self.assertTrue(cve_may_be_missing(observation))

    def test_sixty_four_ccis_and_no_cve_still_say_a_cve_may_be_missing(self) -> None:
        # The cut item sorts after every CVE, so the kept list cannot show whether one was cut.
        ccis = [f"CCI-9000{index:02d}" for index in range(MAX_LIST_ITEMS)]
        for tags in ({"cwe": ["CWE-79"]}, {"cve": ["GHSA-abcd-efgh-2345"]}):
            with self.subTest(tags=tags):
                observation = observe(make_result("failed"), tags={"cci": ccis, **tags})
                self.assertEqual(observation.source_identifiers, tuple(ccis))
                self.assertEqual(metadata(observation)["truncated"], encoded("source_identifiers"))
                self.assertTrue(cve_may_be_missing(observation))

    def test_sixty_four_ccis_alone_are_not_cut(self) -> None:
        ccis = [f"CCI-9000{index:02d}" for index in range(MAX_LIST_ITEMS)]
        output = run_control(make_result(), tags={"cci": ccis})
        observation = only_observation(output)
        self.assertEqual(observation.source_identifiers, tuple(ccis))
        self.assertNotIn("truncated", metadata(observation))
        self.assertFalse(cve_may_be_missing(observation))
        self.assertEqual(output.diagnostics, ())


# *--- Overlays ---*


def layered_control(control_id: str, results: list[Any], **members: Any) -> dict[str, Any]:
    """Build one overlay control; every layer writes the same content, only results differ."""
    return make_control(
        control_id, results, title=f"Synthetic overlay control {control_id}", **members
    )


LEAF_RESULTS = {
    "SYN-OVL-0001": ([make_result("failed")], {}),
    "SYN-OVL-0002": ([make_result("passed")], {}),
    "SYN-OVL-0003": ([make_result("passed"), make_result("failed")], {}),
    "SYN-OVL-0004": ([make_result("failed")], {"impact": 0}),
    "SYN-OVL-0005": ([make_result("skipped")], {}),
}


def three_layer_document() -> dict[str, Any]:
    """Rebuild the real wrapper, middle, and leaf overlay shape synthetically."""

    def layer(name: str, with_results: bool, **members: Any) -> dict[str, Any]:
        controls = [
            layered_control(record, results if with_results else [], **extra)
            for record, (results, extra) in LEAF_RESULTS.items()
        ]
        return make_profile(name, controls, **members)

    return make_document(
        layer("synthetic-wrapper", False, depends=[{"name": "synthetic-middle"}]),
        layer(
            "synthetic-middle",
            False,
            parent_profile="synthetic-wrapper",
            depends=[{"name": "synthetic-leaf-alias"}],
        ),
        layer("synthetic-leaf", True, parent_profile="synthetic-middle"),
    )


class HdfOverlayTests(unittest.TestCase):
    """Profiles resolve to their root by parent_profile; empty copies are shadowed."""

    def test_the_three_layer_overlay_yields_the_leaf_results_under_the_wrapper(self) -> None:
        output = parse_direct(three_layer_document())
        controls = by_record(output)
        self.assertEqual(
            {record: item.disposition for record, item in controls.items()},
            {
                "SYN-OVL-0001": OPEN,
                "SYN-OVL-0002": PASS,
                "SYN-OVL-0003": OPEN,
                "SYN-OVL-0004": NOT_APPLICABLE,
                "SYN-OVL-0005": NOT_REVIEWED,
            },
        )
        for observation in output.observations:
            with self.subTest(control=observation.source_record_id):
                self.assertEqual(observation.context_key, "synthetic-wrapper")
                self.assertEqual(metadata(observation)["profile_name"], "synthetic-leaf")
                self.assertEqual(metadata(observation)["profile_parent"], "synthetic-middle")
                self.assertEqual(metadata(observation)["occurrence_count"], "1")
        # The middle layer's depends names the leaf by an alias, which is never read.
        self.assertNotIn(DiagnosticLevel.WARNING, {item.level for item in output.diagnostics})
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.INFO,
                    "impact_zero_not_applicable",
                    coalesced(
                        IMPACT_ZERO_SUMMARY,
                        "profiles[2].controls[3]",
                        detail="results would read OPEN",
                    ),
                ),
                (
                    DiagnosticLevel.INFO,
                    "profile_control_shadowed",
                    coalesced(
                        SHADOWED_SUMMARY,
                        "profiles[0].controls[0]",
                        "profiles[1].controls[0]",
                        "profiles[0].controls[1]",
                        "profiles[1].controls[1]",
                        "profiles[0].controls[2]",
                        count=10,
                    ),
                ),
            ],
        )

    def test_the_layer_order_in_the_document_does_not_matter(self) -> None:
        document = three_layer_document()
        artifact = synthetic_artifact(document)
        original = parse_direct(document, artifact)
        document["profiles"].reverse()
        reordered = parse_direct(document, artifact)
        self.assertEqual(
            [item.to_canonical_json() for item in reordered.observations],
            [item.to_canonical_json() for item in original.observations],
        )

    def test_a_wrapper_control_with_results_stays_in_the_wrapper(self) -> None:
        output = parse_direct(
            make_document(
                make_profile("synthetic-wrapper", [make_control("SYN-CTL-0100", [make_result()])]),
                make_profile(
                    "synthetic-leaf",
                    [make_control("SYN-CTL-0001", [make_result("failed")])],
                    parent_profile="synthetic-wrapper",
                ),
            )
        )
        controls = by_record(output)
        self.assertEqual(metadata(controls["SYN-CTL-0100"])["profile_name"], "synthetic-wrapper")
        self.assertNotIn("profile_parent", metadata(controls["SYN-CTL-0100"]))
        self.assertEqual(metadata(controls["SYN-CTL-0001"])["profile_name"], "synthetic-leaf")
        self.assertEqual({item.context_key for item in output.observations}, {"synthetic-wrapper"})

    def test_two_roots_give_one_id_two_contexts(self) -> None:
        output = parse_direct(
            make_document(
                make_profile("synthetic-first", [make_control(results=[make_result("failed")])]),
                make_profile("synthetic-second", [make_control(results=[make_result("passed")])]),
            )
        )
        self.assertEqual(
            [(item.context_key, item.disposition) for item in output.observations],
            [("synthetic-first", OPEN), ("synthetic-second", PASS)],
        )
        self.assertEqual(len({tracking_id_of(item) for item in output.observations}), 2)
        self.assertEqual(output.diagnostics, ())

    def test_a_cycle_is_refused_at_the_profile_that_closes_it(self) -> None:
        output = parse_direct(
            make_document(
                make_profile("synthetic-a", parent_profile="synthetic-b"),
                make_profile("synthetic-b", parent_profile="synthetic-a"),
            )
        )
        self.assertEqual(output.observations, ())
        self.assertEqual(
            diagnostic_lines(output),
            [
                (DiagnosticLevel.ERROR, "invalid_profile", coalesced(CYCLE_SUMMARY, "profiles[1]")),
                (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
            ],
        )

    def test_a_profile_that_names_itself_as_parent_is_a_cycle(self) -> None:
        output = parse_direct(make_document(make_profile(ROOT, parent_profile=ROOT)))
        self.assertEqual(
            diagnostic_lines(output)[0],
            (DiagnosticLevel.ERROR, "invalid_profile", coalesced(CYCLE_SUMMARY, "profiles[0]")),
        )

    def test_a_parent_that_names_no_profile_withholds_every_observation(self) -> None:
        for parent in ("synthetic-nobody", "", "   ", 5, []):
            with self.subTest(parent=parent):
                output = parse_direct(
                    make_document(
                        make_profile(ROOT),
                        make_profile("synthetic-orphan", parent_profile=parent),
                    )
                )
                self.assertEqual(output.observations, ())
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.ERROR,
                            "invalid_profile",
                            coalesced(DANGLING_SUMMARY, "profiles[1]"),
                        )
                    ],
                )

    def test_a_null_parent_makes_a_root(self) -> None:
        output = parse_direct(make_document(make_profile(ROOT, parent_profile=None)))
        self.assertEqual(only_observation(output).context_key, ROOT)
        self.assertNotIn("profile_parent", metadata(only_observation(output)))

    def test_a_repeated_profile_name_is_refused_at_the_second_profile(self) -> None:
        output = parse_direct(make_document(make_profile(ROOT), make_profile(f" {ROOT} ")))
        self.assertEqual(output.observations, ())
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.ERROR,
                    "invalid_profile",
                    coalesced("profile name is carried by two profiles", "profiles[1]"),
                )
            ],
        )

    def test_an_all_empty_chain_yields_one_error_observation(self) -> None:
        output = parse_direct(
            make_document(
                make_profile("synthetic-wrapper", [make_control(results=[])]),
                make_profile(
                    "synthetic-leaf", [make_control(results=[])], parent_profile="synthetic-wrapper"
                ),
            )
        )
        observation = only_observation(output)
        self.assertEqual(observation.disposition, ERROR)
        self.assertEqual(metadata(observation)["disposition_source"], "no_results")
        self.assertEqual(metadata(observation)["occurrence_count"], "2")
        self.assertEqual(
            diagnostic_codes(output), ["source_timestamp_missing", "results_collapsed"]
        )

    def test_a_child_of_a_refused_profile_is_skipped_silently(self) -> None:
        refused = "synthetic\u0000profile"
        output = parse_direct(
            make_document(
                make_profile(refused),
                make_profile("synthetic-child", parent_profile=refused),
            )
        )
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.ERROR,
                    "identity_input_invalid",
                    coalesced(
                        IDENTITY_SUMMARY,
                        "profiles[0].name",
                        detail="profile name contains prohibited code point U+0000",
                    ),
                ),
                (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
            ],
        )

    def test_each_impact_zero_line_names_a_leaf_copy_that_yields_an_observation(self) -> None:
        records = ("SYN-OVL-0101", "SYN-OVL-0102", "SYN-OVL-0103")

        def layer(name: str, with_results: bool, **members: Any) -> dict[str, Any]:
            controls = [
                layered_control(record, [make_result("failed")] if with_results else [], impact=0)
                for record in records
            ]
            return make_profile(name, controls, **members)

        output = parse_direct(
            make_document(
                layer("synthetic-wrapper", False),
                layer("synthetic-middle", False, parent_profile="synthetic-wrapper"),
                layer("synthetic-leaf", True, parent_profile="synthetic-middle"),
            )
        )
        self.assertEqual(
            [item.disposition for item in output.observations], [NOT_APPLICABLE] * len(records)
        )
        self.assertEqual(
            only_diagnostic(output, "impact_zero_not_applicable").message,
            coalesced(
                IMPACT_ZERO_SUMMARY,
                *(f"profiles[2].controls[{index}]" for index in range(len(records))),
                detail="results would read OPEN",
            ),
        )

    def test_an_impact_zero_line_stays_when_the_artifact_fails_closed(self) -> None:
        # An ERROR withholds every observation but no diagnostic, so both emission sites still
        # write the line, and it then names a copy that yields nothing.
        malformed = make_control("SYN-CTL-0002", results=["Synthetic text"])
        for results, rolled in (([make_result("failed")], "OPEN"), ([], "ERROR")):
            with self.subTest(rolled=rolled):
                output = parse_direct(
                    document_with(make_control(results=results, impact=0), malformed)
                )
                self.assertEqual(output.observations, ())
                self.assertEqual(
                    sorted(diagnostic_codes(output)),
                    ["impact_zero_not_applicable", "invalid_control"],
                )
                self.assertEqual(
                    only_diagnostic(output, "impact_zero_not_applicable").message,
                    coalesced(
                        IMPACT_ZERO_SUMMARY,
                        "profiles[0].controls[0]",
                        detail=f"results would read {rolled}",
                    ),
                )
                self.assertEqual(
                    only_diagnostic(output, "invalid_control").message,
                    coalesced("result must be an object", "profiles[0].controls[1].results[0]"),
                )

    def test_the_leaf_copy_impact_governs_over_empty_impact_zero_layers(self) -> None:
        output = parse_direct(
            make_document(
                make_profile("synthetic-wrapper", [layered_control("SYN-OVL-0001", [], impact=0)]),
                make_profile(
                    "synthetic-middle",
                    [layered_control("SYN-OVL-0001", [], impact=0)],
                    parent_profile="synthetic-wrapper",
                ),
                make_profile(
                    "synthetic-leaf",
                    [layered_control("SYN-OVL-0001", [make_result("failed")], impact=0.5)],
                    parent_profile="synthetic-middle",
                ),
            )
        )
        observation = only_observation(output)
        self.assertEqual(observation.disposition, OPEN)
        self.assertEqual(metadata(observation)["disposition_source"], "results")
        self.assertEqual(metadata(observation)["impact"], "0.5")
        self.assertEqual(diagnostic_codes(output), ["profile_control_shadowed"])

    def test_a_copy_whose_results_are_all_malformed_still_shadows_an_empty_copy(self) -> None:
        output = parse_direct(
            make_document(
                make_profile("synthetic-root", [make_control(results=[])]),
                make_profile(
                    "synthetic-overlay",
                    [make_control(results=[1])],
                    parent_profile="synthetic-root",
                ),
                target=ABSENT,
                platform_name="linux",
            )
        )
        self.assertEqual(output.observations, ())
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.WARNING,
                    "resource_identity_fallback",
                    coalesced(FALLBACK_SUMMARY, "platform"),
                ),
                (
                    DiagnosticLevel.ERROR,
                    "invalid_control",
                    coalesced("result must be an object", "profiles[1].controls[0].results[0]"),
                ),
                (
                    DiagnosticLevel.INFO,
                    "profile_control_shadowed",
                    coalesced(SHADOWED_SUMMARY, "profiles[0].controls[0]"),
                ),
            ],
        )

    def test_a_copy_whose_results_are_all_malformed_is_never_shadowed(self) -> None:
        output = parse_direct(
            make_document(
                make_profile("synthetic-root", [make_control(results=[1])]),
                make_profile(
                    "synthetic-overlay",
                    [make_control(results=[make_result()])],
                    parent_profile="synthetic-root",
                ),
                target=ABSENT,
                platform_name="linux",
            )
        )
        self.assertEqual(output.observations, ())
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.WARNING,
                    "resource_identity_fallback",
                    coalesced(FALLBACK_SUMMARY, "platform"),
                ),
                (
                    DiagnosticLevel.ERROR,
                    "invalid_control",
                    coalesced("result must be an object", "profiles[0].controls[0].results[0]"),
                ),
            ],
        )


HANDOVER_WAIVER = {
    "justification": "Synthetic wrapper waiver.",
    "expiration_date": "2026-12-31",
    "run": True,
    "skipped_due_to_waiver": False,
}
HANDOVER_ATTESTATION = {
    "status": "passed",
    "explanation": "Synthetic wrapper attestation.",
    "frequency": "annually",
    "updated": "2026-09-04",
    "updated_by": "Riley Example",
}


def chain_of(*controls: dict[str, Any]) -> dict[str, Any]:
    """Chain one profile per control copy, root first, each the parent of the next."""
    names = ("synthetic-wrapper", "synthetic-middle")[: len(controls) - 1] + ("synthetic-leaf",)
    profiles: list[dict[str, Any]] = []
    parent: Any = ABSENT
    for name, control in zip(names, controls, strict=True):
        profiles.append(make_profile(name, [control], parent_profile=parent))
        parent = name
    return make_document(*profiles)


def group_of(observation: Observation, prefix: str) -> dict[str, str]:
    """Return the metadata members whose key starts with the prefix."""
    return {key: value for key, value in metadata(observation).items() if key.startswith(prefix)}


class HdfShadowHandoverTests(unittest.TestCase):
    """A shadowed copy hands its waiver or attestation group to the copies that survive."""

    def test_a_waiver_on_the_empty_root_copy_reaches_the_leaf_observation(self) -> None:
        for status, disposition in (("failed", OPEN), ("passed", PASS), ("skipped", NOT_REVIEWED)):
            with self.subTest(status=status):
                leaf = make_control(results=[make_result(status)])
                output = parse_direct(
                    chain_of(make_control(results=[], waiver_data=HANDOVER_WAIVER), leaf)
                )
                observation = only_observation(output)
                baseline = only_observation(parse_direct(chain_of(make_control(results=[]), leaf)))
                self.assertEqual(observation.disposition, disposition)
                self.assertEqual(baseline.disposition, disposition)
                self.assertEqual(
                    group_of(observation, "waive"),
                    {
                        "waived": "true",
                        "waiver_expiration": "2026-12-31",
                        "waiver_justification": "Synthetic wrapper waiver.",
                        "waiver_run": "true",
                        "waiver_skipped": "false",
                    },
                )
                self.assertEqual(metadata(observation)["profile_name"], "synthetic-leaf")
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "control_waived",
                            coalesced(WAIVED_SUMMARY, "profiles[0].controls[0]"),
                        ),
                        (
                            DiagnosticLevel.INFO,
                            "profile_control_shadowed",
                            coalesced(SHADOWED_SUMMARY, "profiles[0].controls[0]"),
                        ),
                    ],
                )

    def test_an_attestation_on_the_empty_root_copy_reaches_the_leaf_observation(self) -> None:
        leaf = make_control(
            results=[
                make_result("skipped", "No-op", "2026-09-05T10:00:00Z"),
                make_result("passed", ATTESTED_MARKER, "2026-09-04T08:00:00Z"),
            ]
        )
        output = parse_direct(
            chain_of(make_control(results=[], attestation_data=HANDOVER_ATTESTATION), leaf)
        )
        observation = only_observation(output)
        baseline = only_observation(parse_direct(chain_of(make_control(results=[]), leaf)))
        self.assertEqual(observation.disposition, PASS)
        self.assertEqual(baseline.disposition, PASS)
        self.assertEqual(
            group_of(observation, "attest"),
            {
                "attested": "true",
                "attestation_explanation": "Synthetic wrapper attestation.",
                "attestation_frequency": "annually",
                "attestation_status": "passed",
                "attestation_updated": "2026-09-04",
            },
        )
        self.assertNotIn("Riley Example", observation.to_canonical_json())
        # The marker rule reads the copy's own attestation_data. The leaf has none, so its
        # marker is an ordinary result and lends its clock, as it does with no attestation.
        self.assertEqual(observation.observed_at, datetime(2026, 9, 4, 8, tzinfo=UTC))
        self.assertEqual(baseline.observed_at, observation.observed_at)
        own = only_observation(
            parse_direct(
                chain_of(
                    make_control(results=[]), {**leaf, "attestation_data": HANDOVER_ATTESTATION}
                )
            )
        )
        self.assertEqual(own.observed_at, datetime(2026, 9, 5, 10, tzinfo=UTC))
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.WARNING,
                    "control_attested",
                    coalesced(ATTESTED_SUMMARY, "profiles[0].controls[0]"),
                ),
                (
                    DiagnosticLevel.INFO,
                    "profile_control_shadowed",
                    coalesced(SHADOWED_SUMMARY, "profiles[0].controls[0]"),
                ),
            ],
        )

    def test_the_outermost_shadowed_carrier_hands_over_each_group(self) -> None:
        # By content the middle copy sorts first, so only the layer order picks the wrapper's
        # waiver. Each group is chosen on its own, so the attestation comes from the middle.
        wrapper = make_control(
            results=[], waiver_data={"justification": "Synthetic wrapper waiver."}
        )
        middle = make_control(
            results=[],
            waiver_data={"justification": "Synthetic middle waiver."},
            attestation_data={"status": "passed", "explanation": "Synthetic middle attestation."},
        )
        document = chain_of(wrapper, middle, make_control(results=[make_result("failed")]))
        artifact = synthetic_artifact(document)
        rendered = set()
        for profiles in permutations(document["profiles"]):
            with self.subTest(order=[profile["name"] for profile in profiles]):
                observation = only_observation(
                    parse_direct({**document, "profiles": list(profiles)}, artifact)
                )
                self.assertEqual(observation.disposition, OPEN)
                self.assertEqual(
                    group_of(observation, "waive"),
                    {"waived": "true", "waiver_justification": "Synthetic wrapper waiver."},
                )
                self.assertEqual(
                    group_of(observation, "attest"),
                    {
                        "attested": "true",
                        "attestation_explanation": "Synthetic middle attestation.",
                        "attestation_status": "passed",
                    },
                )
                rendered.add(observation.to_canonical_json())
        self.assertEqual(len(rendered), 1)

    def test_a_survivor_attestation_is_kept_over_a_shadowed_one(self) -> None:
        # A shadowed copy has no results and so no marker, so its attestation always reads
        # "true", and an expired attestation can only be a survivor's own.
        shadowed = make_control(
            results=[],
            attestation_data={"status": "passed", "explanation": "Synthetic shadowed text."},
        )
        for marker, status, attested in (
            (EXPIRED_MARKER, "skipped", "expired"),
            (ATTESTED_MARKER, "passed", "true"),
        ):
            with self.subTest(attested=attested):
                leaf = make_control(
                    results=[make_result("skipped", "No-op"), make_result(status, marker)],
                    attestation_data={"status": "passed", "explanation": "Synthetic leaf text."},
                )
                observation = only_observation(parse_direct(chain_of(shadowed, leaf)))
                self.assertEqual(
                    group_of(observation, "attest"),
                    {
                        "attested": attested,
                        "attestation_explanation": "Synthetic leaf text.",
                        "attestation_status": "passed",
                    },
                )

    def test_a_non_object_member_on_a_shadowed_copy_is_recorded_with_no_member_read(
        self,
    ) -> None:
        leaf = make_control(results=[make_result("failed")])
        for member, prefix, flag, code, summary in (
            ("waiver_data", "waive", "waived", "control_waived", WAIVED_SUMMARY),
            ("attestation_data", "attest", "attested", "control_attested", ATTESTED_SUMMARY),
        ):
            for value in ("Synthetic text", ["Synthetic item"], True, 1):
                with self.subTest(member=member, value=value):
                    output = parse_direct(
                        chain_of(make_control(results=[], **{member: value}), leaf)
                    )
                    observation = only_observation(output)
                    self.assertEqual(group_of(observation, prefix), {flag: "true"})
                    self.assertEqual(observation.disposition, OPEN)
                    self.assertEqual(
                        only_diagnostic(output, code).message,
                        coalesced(
                            summary,
                            "profiles[0].controls[0]",
                            detail=f"{member} is not an object",
                        ),
                    )

    def test_truncated_names_a_cut_group_key_only_from_the_chosen_carrier(self) -> None:
        cut = {"justification": "J" * OVER_SCALAR}
        kept = {"justification": "Synthetic waiver."}
        for wrapper, middle, leaf, named in (
            (cut, kept, {}, True),
            (kept, cut, {}, False),
            (cut, cut, kept, False),
        ):
            with self.subTest(wrapper=len(wrapper["justification"]), leaf=bool(leaf)):
                observation = only_observation(
                    parse_direct(
                        chain_of(
                            make_control(results=[], waiver_data=wrapper),
                            make_control(results=[], waiver_data=middle),
                            make_control(results=[make_result("failed")], waiver_data=leaf),
                        )
                    )
                )
                justification = metadata(observation)["waiver_justification"]
                self.assertEqual(justification.endswith(TRUNCATION_MARKER), named)
                self.assertEqual(
                    "waiver_justification"
                    in json.loads(metadata(observation).get("truncated", "[]")),
                    named,
                )

    def test_a_carrier_hands_over_the_cuts_of_its_group_and_no_other(self) -> None:
        # The wrapper's title, description, gid, and nist list are cut as well, but they stay
        # on the shadowed copy, so truncated names only the waiver key the survivor now writes.
        wrapper = make_control(
            results=[],
            title="T" * OVER_SCALAR,
            desc="D" * OVER_DESCRIPTION,
            tags={
                "gid": "G" * OVER_SCALAR,
                "nist": [numbered("N", index, OVER_ITEM) for index in range(OVER_LIST)],
            },
            waiver_data={"justification": "J" * OVER_SCALAR},
        )
        leaf = make_control(results=[make_result("failed")], tags={"nist": ["SYN-NIST-001"]})
        observation = only_observation(parse_direct(chain_of(wrapper, leaf)))
        self.assertEqual(json.loads(metadata(observation)["truncated"]), ["waiver_justification"])
        self.assertTrue(metadata(observation)["waiver_justification"].endswith(TRUNCATION_MARKER))
        self.assertEqual(observation.title, "Synthetic control")
        self.assertEqual(observation.description, "A synthetic control description.")
        self.assertEqual(json.loads(metadata(observation)["nist_tags"]), ["SYN-NIST-001"])
        self.assertNotIn("gid", metadata(observation))

    def test_a_survivor_group_never_blocks_the_other_group_handover(self) -> None:
        # Each group is decided on its own: a leaf's own waiver keeps the wrapper's waiver out
        # and still takes the wrapper's attestation, and the reverse.
        own_waiver = {"justification": "Synthetic leaf waiver."}
        own_attestation = {"status": "failed", "explanation": "Synthetic leaf attestation."}
        handed_waiver = {
            "waived": "true",
            "waiver_expiration": "2026-12-31",
            "waiver_justification": "Synthetic wrapper waiver.",
            "waiver_run": "true",
            "waiver_skipped": "false",
        }
        handed_attestation = {
            "attested": "true",
            "attestation_explanation": "Synthetic wrapper attestation.",
            "attestation_frequency": "annually",
            "attestation_status": "passed",
            "attestation_updated": "2026-09-04",
        }
        for leaf_members, wrapper_members, waiver, attestation in (
            (
                {"waiver_data": own_waiver},
                {"attestation_data": HANDOVER_ATTESTATION},
                {"waived": "true", "waiver_justification": "Synthetic leaf waiver."},
                handed_attestation,
            ),
            (
                {"attestation_data": own_attestation},
                {"waiver_data": HANDOVER_WAIVER},
                handed_waiver,
                {
                    "attested": "true",
                    "attestation_explanation": "Synthetic leaf attestation.",
                    "attestation_status": "failed",
                },
            ),
        ):
            with self.subTest(leaf=sorted(leaf_members)):
                leaf = make_control(results=[make_result("failed")], **leaf_members)
                observation = only_observation(
                    parse_direct(chain_of(make_control(results=[], **wrapper_members), leaf))
                )
                self.assertEqual(observation.disposition, OPEN)
                self.assertEqual(group_of(observation, "waive"), waiver)
                self.assertEqual(group_of(observation, "attest"), attestation)

    def test_with_two_leaves_a_shadowed_group_is_used_only_when_no_leaf_carries_one(
        self,
    ) -> None:
        root = make_profile(
            "synthetic-root",
            [make_control(results=[], waiver_data={"justification": "Synthetic root waiver."})],
        )

        def leaf(name: str, **members: Any) -> dict[str, Any]:
            control = make_control(results=[make_result("failed")], **members)
            return make_profile(name, [control], parent_profile="synthetic-root")

        for own, expected in (
            (ABSENT, "Synthetic root waiver."),
            ({"justification": "Synthetic leaf waiver."}, "Synthetic leaf waiver."),
        ):
            document = make_document(
                root, leaf("synthetic-leaf-a"), leaf("synthetic-leaf-b", waiver_data=own)
            )
            artifact = synthetic_artifact(document)
            for profiles in permutations(document["profiles"]):
                with self.subTest(expected=expected, order=[item["name"] for item in profiles]):
                    observation = only_observation(
                        parse_direct({**document, "profiles": list(profiles)}, artifact)
                    )
                    self.assertEqual(metadata(observation)["waiver_justification"], expected)
                    self.assertEqual(metadata(observation)["occurrence_count"], "2")

    def test_a_shadowed_copy_without_a_group_contributes_nothing(self) -> None:
        leaf = make_control(results=[make_result("failed")])
        rich = make_control(
            results=[],
            title="Synthetic wrapper title CVE-2099-0001",
            desc="Synthetic wrapper description.",
            impact=0.9,
            tags={"severity": "critical", "nist": ["SYN-NIST-001"], "cci": ["CCI-000366"]},
        )
        artifact = synthetic_artifact(chain_of(rich, leaf))
        plain = only_observation(parse_direct(chain_of(make_control(results=[]), leaf), artifact))
        observation = only_observation(parse_direct(chain_of(rich, leaf), artifact))
        self.assertEqual(observation.to_canonical_json(), plain.to_canonical_json())
        self.assertNotIn("waived", metadata(observation))
        self.assertNotIn("attested", metadata(observation))

    def test_reversed_profiles_controls_and_results_give_the_same_bytes(self) -> None:
        # Two waived copies share the wrapper's depth, so content alone breaks their tie.
        def document() -> dict[str, Any]:
            wrapper = make_profile(
                "synthetic-wrapper",
                [
                    make_control(results=[], waiver_data={"justification": "Synthetic B."}),
                    make_control(results=[], waiver_data={"justification": "Synthetic A."}),
                    make_control(results=[], attestation_data={"status": "passed"}),
                ],
            )
            leaf = make_profile(
                "synthetic-leaf",
                [make_control(results=[make_result("failed"), make_result("passed")])],
                parent_profile="synthetic-wrapper",
            )
            return make_document(wrapper, leaf)

        artifact = synthetic_artifact(document())
        original = only_observation(parse_direct(document(), artifact))
        reversed_output = only_observation(parse_direct(reversed_everywhere(document()), artifact))
        self.assertEqual(metadata(original)["waiver_justification"], "Synthetic A.")
        self.assertEqual(metadata(original)["attested"], "true")
        self.assertEqual(reversed_output.to_canonical_json(), original.to_canonical_json())


# *--- Folding ---*


class HdfFoldTests(unittest.TestCase):
    """Candidates sharing an identity fold by content, never by document position."""

    def test_one_id_twice_folds_with_counts_summed(self) -> None:
        output = parse_direct(
            document_with(
                make_control(results=[make_result("failed")]),
                make_control(results=[make_result("passed"), make_result("skipped")]),
            )
        )
        observation = only_observation(output)
        self.assertEqual(observation.disposition, OPEN)
        self.assertEqual(metadata(observation)["occurrence_count"], "2")
        self.assertEqual(
            {key: metadata(observation)[key] for key in counts()},
            counts(failed=1, passed=1, skipped=1),
        )
        self.assertEqual(diagnostic_codes(output), ["results_collapsed"])

    def test_list_members_merge_and_the_union_is_cut_at_sixty_four(self) -> None:
        first = [f"SYN-NIST-{index:03d}" for index in range(40)]
        second = [f"SYN-NIST-{index:03d}" for index in range(30, 80)]
        output = parse_direct(
            document_with(
                make_control(tags={"nist": first}),
                make_control(tags={"nist": second}),
            )
        )
        observation = only_observation(output)
        union = sorted(set(first) | set(second))
        self.assertEqual(metadata(observation)["nist_tags"], encoded(*union[:MAX_LIST_ITEMS]))
        self.assertEqual(metadata(observation)["truncated"], encoded("nist_tags"))
        self.assertEqual(diagnostic_codes(output), ["evidence_truncated", "results_collapsed"])

    def test_the_primary_is_chosen_by_content_not_position(self) -> None:
        first = make_control(title="Synthetic title B", desc="Synthetic description B.")
        second = make_control(title="Synthetic title A", desc="Synthetic description A.")
        for controls in ((first, second), (second, first)):
            with self.subTest(first_title=controls[0]["title"]):
                observation = only_observation(parse_direct(document_with(*controls)))
                self.assertEqual(observation.title, "Synthetic title A")
                self.assertEqual(observation.description, "Synthetic description A.")

    def test_the_worst_disposition_and_the_strongest_severity_win(self) -> None:
        strong = make_control(results=[make_result("passed")], tags={"severity": "critical"})
        weak = make_control(results=[make_result("failed")], impact=0.1)
        for controls in ((strong, weak), (weak, strong)):
            with self.subTest(first=controls[0]["results"][0]["status"]):
                observation = only_observation(parse_direct(document_with(*controls)))
                self.assertEqual(observation.disposition, OPEN)
                self.assertEqual(observation.source_severity, SourceSeverity.CRITICAL)
                self.assertEqual(metadata(observation)["severity_tag"], "critical")
                self.assertEqual(metadata(observation)["severity_source"], "severity")
                self.assertEqual(metadata(observation)["impact"], "0.5")

    def test_the_fold_takes_the_earliest_clock_of_every_candidate(self) -> None:
        observation = only_observation(
            parse_direct(
                document_with(
                    make_control(results=[make_result(start_time="2026-09-05T10:04:00Z")]),
                    make_control(results=[make_result(start_time="2026-09-05T10:02:00Z")]),
                )
            )
        )
        self.assertEqual(observation.observed_at, datetime(2026, 9, 5, 10, 2, tzinfo=UTC))

    def test_reversed_profiles_controls_and_results_give_identical_observations(self) -> None:
        for name in FIXTURE_IDS:
            with self.subTest(fixture=name):
                artifact = provenance_of(FIXTURES / name)
                original = parse_direct(fixture_payload(name), artifact)
                reversed_output = parse_direct(reversed_everywhere(fixture_payload(name)), artifact)
                self.assertEqual(
                    [item.observation_id for item in reversed_output.observations],
                    list(FIXTURE_IDS[name]),
                )
                self.assertEqual(
                    [item.to_canonical_json() for item in reversed_output.observations],
                    [item.to_canonical_json() for item in original.observations],
                )

    def test_a_waiver_on_either_copy_is_recorded_whatever_the_order(self) -> None:
        waived = make_control(
            results=[make_result("failed")],
            waiver_data={"justification": "Synthetic waiver justification."},
        )
        plain = make_control(results=[make_result("failed")])
        artifact = synthetic_artifact(document_with(waived, plain))
        rendered = set()
        for controls in ((waived, plain), (plain, waived)):
            with self.subTest(first_waived="waiver_data" in controls[0]):
                output = parse_direct(document_with(*controls), artifact)
                observation = only_observation(output)
                self.assertEqual(metadata(observation)["waived"], "true")
                self.assertEqual(
                    metadata(observation)["waiver_justification"],
                    "Synthetic waiver justification.",
                )
                self.assertEqual(
                    only_diagnostic(output, "control_waived").level, DiagnosticLevel.WARNING
                )
                rendered.add(observation.to_canonical_json())
        self.assertEqual(len(rendered), 1)

    def test_an_attested_copy_keeps_its_attestation_when_its_title_sorts_later(self) -> None:
        attested = make_control(
            title="Synthetic title B",
            results=[make_result("skipped", "No-op"), make_result("passed", ATTESTED_MARKER)],
            attestation_data={"status": "passed", "explanation": "Synthetic explanation."},
        )
        plain = make_control(title="Synthetic title A", results=[make_result("passed")])
        for controls in ((attested, plain), (plain, attested)):
            with self.subTest(first_title=controls[0]["title"]):
                observation = only_observation(parse_direct(document_with(*controls)))
                self.assertEqual(observation.title, "Synthetic title A")
                self.assertEqual(
                    {
                        key: value
                        for key, value in metadata(observation).items()
                        if key.startswith("attest")
                    },
                    {
                        "attested": "true",
                        "attestation_explanation": "Synthetic explanation.",
                        "attestation_status": "passed",
                    },
                )

    def test_a_waiver_on_one_of_two_leaf_profiles_is_recorded(self) -> None:
        # The waived leaf's profile name sorts later, so it is never the primary.
        root = make_profile("synthetic-root", [make_control(results=[])])
        first = make_profile(
            "synthetic-leaf-a",
            [make_control(results=[make_result("passed")])],
            parent_profile="synthetic-root",
        )
        second = make_profile(
            "synthetic-leaf-b",
            [
                make_control(
                    results=[make_result("failed")],
                    waiver_data={"justification": "Synthetic waiver justification."},
                )
            ],
            parent_profile="synthetic-root",
        )
        for profiles in ((root, first, second), (root, second, first)):
            with self.subTest(first_leaf=profiles[1]["name"]):
                observation = only_observation(parse_direct(make_document(*profiles)))
                self.assertEqual(metadata(observation)["profile_name"], "synthetic-leaf-a")
                self.assertEqual(metadata(observation)["waived"], "true")
                self.assertEqual(
                    metadata(observation)["waiver_justification"],
                    "Synthetic waiver justification.",
                )
                self.assertEqual(observation.disposition, OPEN)

    def test_a_waiver_group_comes_whole_from_the_first_waived_copy(self) -> None:
        # Copy B sorts first by its expiration, while copy A's justification sorts first, so a
        # member-by-member choice would pair one copy's justification with the other's date.
        copy_a = make_control(
            waiver_data={
                "justification": "Synthetic justification A.",
                "expiration_date": "2026-12-31",
            }
        )
        copy_b = make_control(
            waiver_data={
                "justification": "Synthetic justification B.",
                "expiration_date": "2026-01-31",
            }
        )
        plain = make_control()
        artifact = synthetic_artifact(document_with(copy_a, copy_b, plain))
        rendered = set()
        for controls in permutations((copy_a, copy_b, plain)):
            with self.subTest(order=[control.get("waiver_data") for control in controls]):
                observation = only_observation(parse_direct(document_with(*controls), artifact))
                self.assertEqual(
                    {
                        key: value
                        for key, value in metadata(observation).items()
                        if key.startswith("waive")
                    },
                    {
                        "waived": "true",
                        "waiver_expiration": "2026-01-31",
                        "waiver_justification": "Synthetic justification B.",
                    },
                )
                rendered.add(observation.to_canonical_json())
        self.assertEqual(len(rendered), 1)

    def test_an_expired_attestation_wins_over_a_current_one_with_its_own_members(self) -> None:
        current = make_control(
            results=[make_result("skipped", "No-op"), make_result("passed", ATTESTED_MARKER)],
            attestation_data={"status": "passed", "explanation": "Synthetic current."},
        )
        lapsed = make_control(
            results=[make_result("skipped", "No-op"), make_result("skipped", EXPIRED_MARKER)],
            attestation_data={"status": "failed", "explanation": "Synthetic lapsed."},
        )
        for controls in ((current, lapsed), (lapsed, current)):
            with self.subTest(first=controls[0]["attestation_data"]["explanation"]):
                observation = only_observation(parse_direct(document_with(*controls)))
                self.assertEqual(
                    {
                        key: value
                        for key, value in metadata(observation).items()
                        if key.startswith("attest")
                    },
                    {
                        "attested": "expired",
                        "attestation_explanation": "Synthetic lapsed.",
                        "attestation_status": "failed",
                    },
                )

    def test_a_cut_waiver_on_a_later_copy_is_named_in_truncated(self) -> None:
        plain = make_control(title="Synthetic title A")
        waived = make_control(
            title="Synthetic title B", waiver_data={"justification": "J" * OVER_SCALAR}
        )
        for controls in ((plain, waived), (waived, plain)):
            with self.subTest(first_title=controls[0]["title"]):
                output = parse_direct(document_with(*controls))
                observation = only_observation(output)
                self.assertEqual(observation.title, "Synthetic title A")
                self.assertEqual(
                    len(metadata(observation)["waiver_justification"]), MAX_METADATA_VALUE_CHARS
                )
                self.assertEqual(
                    metadata(observation)["truncated"], encoded("waiver_justification")
                )

    def test_a_text_that_spells_the_cut_marker_folds_the_same_either_way(self) -> None:
        # Both copies write the same justification, and only one was cut, so the cut keys are
        # the one difference left for the order to decide on.
        spelled = "J" * (MAX_METADATA_VALUE_CHARS - len(TRUNCATION_MARKER)) + TRUNCATION_MARKER
        spelling = make_control(waiver_data={"justification": spelled})
        cut = make_control(waiver_data={"justification": "J" * OVER_SCALAR})
        artifact = synthetic_artifact(document_with(spelling, cut))
        rendered = set()
        for controls in ((spelling, cut), (cut, spelling)):
            with self.subTest(first_cut=controls[0] is cut):
                observation = only_observation(parse_direct(document_with(*controls), artifact))
                self.assertEqual(metadata(observation)["waiver_justification"], spelled)
                self.assertNotIn("truncated", metadata(observation))
                rendered.add(observation.to_canonical_json())
        self.assertEqual(len(rendered), 1)

    def test_a_cut_title_on_a_later_copy_is_not_named(self) -> None:
        plain = make_control(title="Synthetic title A")
        long = make_control(title="Z" * (MAX_TITLE_CHARS + 50))
        for controls in ((plain, long), (long, plain)):
            with self.subTest(first_title=controls[0]["title"][:17]):
                observation = only_observation(parse_direct(document_with(*controls)))
                self.assertEqual(observation.title, "Synthetic title A")
                self.assertNotIn("truncated", metadata(observation))

    def test_identifiers_cut_only_by_the_fold_are_named_and_warned(self) -> None:
        first = [f"CCI-{index:06d}" for index in range(1, 41)]
        second = [f"CCI-{index:06d}" for index in range(41, 81)]
        output = parse_direct(
            document_with(
                make_control(tags={"cci": first}),
                make_control(
                    results=[make_result("failed")],
                    tags={"cci": second, "cve": ["CVE-2099-0001"]},
                ),
            )
        )
        observation = only_observation(output)
        self.assertEqual(observation.source_identifiers, tuple((first + second)[:MAX_LIST_ITEMS]))
        self.assertNotIn("CVE-2099-0001", observation.source_identifiers)
        self.assertEqual(metadata(observation).get("truncated"), encoded("source_identifiers"))
        self.assertTrue(cve_may_be_missing(observation))
        self.assertIn("evidence_truncated", diagnostic_codes(output))

    def test_identifiers_that_fill_the_cap_exactly_across_copies_are_not_cut(self) -> None:
        first = [f"CCI-{index:06d}" for index in range(1, 33)]
        second = [f"CCI-{index:06d}" for index in range(33, 65)]
        output = parse_direct(
            document_with(
                make_control(tags={"cci": first}),
                make_control(results=[make_result("failed")], tags={"cci": second}),
            )
        )
        observation = only_observation(output)
        self.assertEqual(observation.source_identifiers, tuple(first + second))
        self.assertNotIn("truncated", metadata(observation))
        self.assertNotIn("evidence_truncated", diagnostic_codes(output))

    def test_a_list_cut_on_a_later_copy_is_named(self) -> None:
        cut = make_control(
            title="Synthetic title B",
            results=[make_result("failed", "F" * (MAX_LIST_ITEM_CHARS + 50))],
        )
        clean = make_control(title="Synthetic title A", results=[make_result("passed")])
        for controls in ((cut, clean), (clean, cut)):
            with self.subTest(first_title=controls[0]["title"]):
                output = parse_direct(document_with(*controls))
                observation = only_observation(output)
                self.assertEqual(observation.title, "Synthetic title A")
                self.assertEqual(metadata(observation)["truncated"], encoded("failed_results"))
                self.assertEqual(
                    diagnostic_codes(output), ["evidence_truncated", "results_collapsed"]
                )

    def test_the_disposition_source_comes_from_the_worst_copy(self) -> None:
        for results, disposition, source in (
            (([make_result("passed")], [make_result("failed")]), OPEN, "results"),
            (([], []), ERROR, "no_results"),
        ):
            zero = make_control(title="Synthetic title A", results=results[0], impact=0)
            other = make_control(title="Synthetic title B", results=results[1])
            for controls in ((zero, other), (other, zero)):
                with self.subTest(source=source, first_title=controls[0]["title"]):
                    observation = only_observation(parse_direct(document_with(*controls)))
                    self.assertEqual(observation.title, "Synthetic title A")
                    self.assertEqual(observation.disposition, disposition)
                    self.assertEqual(metadata(observation)["disposition_source"], source)

    def test_equal_instants_keep_the_same_clock_whatever_the_primary(self) -> None:
        for titles in (
            ("Synthetic title A", "Synthetic title B"),
            ("Synthetic title B", "Synthetic title A"),
        ):
            with self.subTest(titles=titles):
                observation = only_observation(
                    parse_direct(
                        document_with(
                            make_control(
                                title=titles[0],
                                results=[make_result(start_time="2026-09-05T10:00:00Z")],
                            ),
                            make_control(
                                title=titles[1],
                                results=[make_result(start_time="2026-09-05T03:00:00-07:00")],
                            ),
                        )
                    )
                )
                assert observation.observed_at is not None
                self.assertEqual(observation.observed_at.isoformat(), "2026-09-05T03:00:00-07:00")

    def test_the_title_orders_the_copies_before_the_description(self) -> None:
        first = make_control(title="Synthetic title A", desc="Synthetic description Z.")
        second = make_control(title="Synthetic title B", desc="Synthetic description A.")
        for controls in ((first, second), (second, first)):
            with self.subTest(first_title=controls[0]["title"]):
                observation = only_observation(parse_direct(document_with(*controls)))
                self.assertEqual(observation.title, "Synthetic title A")
                self.assertEqual(observation.description, "Synthetic description Z.")


# *--- Identity Stability ---*


class HdfIdentityStabilityTests(unittest.TestCase):
    """The artifact digest is a fingerprint input, so each claim names its layer."""

    def test_a_second_ingest_reproduces_every_id(self) -> None:
        for name, expected in FIXTURE_IDS.items():
            with self.subTest(fixture=name):
                result = ingest_stig_artifact(FIXTURES / name, ingested_at=SECOND_INGEST)
                self.assertEqual(
                    tuple(item.observation_id for item in result.observations), expected
                )
                self.assertEqual(
                    {item.ingested_at for item in result.observations}, {SECOND_INGEST}
                )

    def test_identical_bytes_under_two_names_keep_every_id(self) -> None:
        documents = {
            "target": (FIXTURES / LINUX).read_bytes(),
            "fallback": json.dumps(make_document(target=ABSENT)).encode("utf-8"),
        }
        for label, content in documents.items():
            with self.subTest(resource=label):
                with tempfile.TemporaryDirectory() as directory:
                    copies = []
                    for name in ("first-copy.hdf.json", "second-copy.hdf.json"):
                        path = Path(directory) / name
                        path.write_bytes(content)
                        copies.append(ingest_stig_artifact(path, ingested_at=NOW))
                first, second = copies
                self.assertTrue(first.observations)
                self.assertEqual(
                    [item.observation_id for item in first.observations],
                    [item.observation_id for item in second.observations],
                )
                self.assertEqual(
                    {item.source_artifact_name for item in second.observations},
                    {"second-copy.hdf.json"},
                )

    def test_a_reorder_reword_or_profile_bump_keeps_identity_and_moves_the_ids(self) -> None:
        # The baseline is the fixture re-serialized the way each edited copy is written.
        baseline = ingest_document(fixture_payload(LINUX), name=LINUX).observations

        def reorder(profile: dict[str, Any]) -> None:
            profile["controls"].reverse()

        def reword(profile: dict[str, Any]) -> None:
            for control in profile["controls"]:
                control["title"] = f"{control['title']} (reworded copy)"

        def bump(profile: dict[str, Any]) -> None:
            profile["version"] = "1.5.0"

        def rehash(profile: dict[str, Any]) -> None:
            profile["sha256"] = "f" * 64

        for edit in (reorder, reword, bump, rehash):
            with self.subTest(edit=edit.__name__):
                payload = fixture_payload(LINUX)
                edit(payload["profiles"][0])
                rewritten = ingest_document(payload, name=LINUX).observations
                self.assertEqual(
                    sorted(map(identity_of, rewritten)), sorted(map(identity_of, baseline))
                )
                self.assertEqual(
                    sorted(map(tracking_id_of, rewritten)), sorted(map(tracking_id_of, baseline))
                )
                self.assertTrue(
                    {item.observation_id for item in rewritten}.isdisjoint(
                        item.observation_id for item in baseline
                    )
                )

    def test_a_target_change_moves_identity_but_keeps_the_tracking_ids(self) -> None:
        original = ingest_fixture(LINUX).observations
        payload = fixture_payload(LINUX)
        payload["platform"]["target_id"] = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b"
        moved = ingest_document(payload, name=LINUX).observations
        self.assertTrue(set(map(identity_of, moved)).isdisjoint(map(identity_of, original)))
        self.assertTrue(
            {item.observation_id for item in moved}.isdisjoint(
                item.observation_id for item in original
            )
        )
        # A tracking id carries no resource member, so the case is the same case.
        self.assertEqual(sorted(map(tracking_id_of, moved)), sorted(map(tracking_id_of, original)))

    def test_an_absent_or_blank_target_falls_back_to_the_root_profile(self) -> None:
        for target in (ABSENT, None, "", "   ", 5, ["host"]):
            with self.subTest(target=target):
                output = parse_direct(
                    make_document(
                        make_profile(
                            controls=[make_control("SYN-CTL-0001"), make_control("SYN-CTL-0002")]
                        ),
                        target=target,
                    )
                )
                self.assertEqual(
                    [
                        (item.resource.resource_type, item.resource.resource_id)
                        for item in output.observations
                    ],
                    [("scan", ROOT), ("scan", ROOT)],
                )
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.WARNING,
                            "resource_identity_fallback",
                            coalesced(FALLBACK_SUMMARY, "platform"),
                        )
                    ],
                )

    def test_a_target_is_stripped_before_it_names_the_resource(self) -> None:
        observation = only_observation(parse_direct(make_document(target=f"  {TARGET}\n")))
        self.assertEqual(
            (observation.resource.resource_type, observation.resource.resource_id),
            ("target", TARGET),
        )


# *--- Refusals ---*


class HdfRefusalTests(unittest.TestCase):
    """Unusable roots fail at the dispatcher; unusable identity inputs fail the artifact."""

    def assert_parse_failure(self, result: IngestResult, message: str) -> None:
        self.assertEqual(attribution(result), HDF_ATTRIBUTION)
        self.assertFalse(result.successful)
        self.assertEqual(result.observations, ())
        self.assertEqual(errors_of(result), [("artifact_parse_failed", message)])
        self.assertEqual(result.errors[0].location, "synthetic.hdf.json")

    def test_each_unusable_root_is_refused_with_its_own_message(self) -> None:
        platform = {"name": "synthetic", "target_id": TARGET}
        cases = (
            ([], "HDF root must be a JSON object"),
            ("synthetic", "HDF root must be a JSON object"),
            (
                {"baselines": [], "platform": platform, "version": "1"},
                "hdf-libs v3 'baselines' root is not supported",
            ),
            (
                {"baselines": [], "controls": []},
                "hdf-libs v3 'baselines' root is not supported",
            ),
            (
                {"name": ROOT, "title": "Synthetic profile export", "controls": [make_control()]},
                "'controls' root (json-min or profile export) is not supported",
            ),
            ({"platform": platform, "version": "1"}, "HDF profiles must be a non-empty array"),
            (
                {"profiles": [], "baselines": [], "platform": platform, "version": "1"},
                "HDF profiles must be a non-empty array",
            ),
            (make_document(profiles={}), "HDF profiles must be a non-empty array"),
            (make_document(profiles=None), "HDF profiles must be a non-empty array"),
            (make_document(profiles="synthetic"), "HDF profiles must be a non-empty array"),
            (make_document(platform=ABSENT), "HDF platform must be an object"),
            (make_document(platform=[]), "HDF platform must be an object"),
            (make_document(platform=None), "HDF platform must be an object"),
            (make_document(version=ABSENT), "HDF version must be a non-empty string"),
            (make_document(version=""), "HDF version must be a non-empty string"),
            (make_document(version="   "), "HDF version must be a non-empty string"),
            (make_document(version=5), "HDF version must be a non-empty string"),
            # A 'stigs' member refuses the document whatever its value and whatever else it
            # carries, ahead of every other check.
            (make_document(stigs=[]), STIGS_MESSAGE),
            (make_document(stigs=None), STIGS_MESSAGE),
            ({"stigs": [], "baselines": []}, STIGS_MESSAGE),
            (make_document(stigs={}, version=ABSENT), STIGS_MESSAGE),
        )
        for payload, message in cases:
            with self.subTest(message=message, payload=str(payload)[:60]):
                self.assert_parse_failure(ingest_document(payload), message)

    def test_a_checklist_under_the_hdf_suffix_is_refused_for_its_stigs_member(self) -> None:
        raw = (FIXTURES / "ubuntu-host.cklb").read_bytes()
        self.assert_parse_failure(ingest_document(None, raw=raw), STIGS_MESSAGE)

    def test_each_unusable_profile_is_an_error_at_its_path(self) -> None:
        null_controls = make_profile()
        null_controls["controls"] = None
        cases = (
            (5, "profile must be an object"),
            ([], "profile must be an object"),
            (make_profile(name=ABSENT), "profile name is missing, not a string, or empty"),
            (make_profile(name=""), "profile name is missing, not a string, or empty"),
            (make_profile(name="  "), "profile name is missing, not a string, or empty"),
            (make_profile(name=5), "profile name is missing, not a string, or empty"),
            (make_profile(controls="synthetic"), "profile controls must be an array"),
            (null_controls, "profile controls must be an array"),
            (make_profile(controls=ABSENT), "profile controls must be an array"),
        )
        for profile, summary in cases:
            with self.subTest(summary=summary, profile=str(profile)[:60]):
                output = parse_direct(make_document(profile))
                self.assertEqual(output.observations, ())
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.ERROR,
                            "invalid_profile",
                            coalesced(summary, "profiles[0]"),
                        ),
                        (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
                    ],
                )

    def test_a_profile_with_no_controls_yields_no_observations(self) -> None:
        output = parse_direct(make_document(make_profile(controls=[])))
        self.assertEqual(
            diagnostic_lines(output),
            [(DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE)],
        )

    def test_each_unusable_control_is_an_error_at_its_path(self) -> None:
        null_results = make_control()
        null_results["results"] = None
        cases = (
            (5, "control must be an object"),
            ("SYN-CTL-0001", "control must be an object"),
            (make_control(ABSENT), "control id is missing, not a string, or empty"),
            (make_control(""), "control id is missing, not a string, or empty"),
            (make_control("   "), "control id is missing, not a string, or empty"),
            (make_control(5), "control id is missing, not a string, or empty"),
            (make_control(results="synthetic"), "control results must be an array"),
            (make_control(results=ABSENT), "control results must be an array"),
            (null_results, "control results must be an array"),
        )
        for control, summary in cases:
            with self.subTest(summary=summary, control=str(control)[:60]):
                output = parse_direct(document_with(control))
                self.assertEqual(output.observations, ())
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.ERROR,
                            "invalid_control",
                            coalesced(summary, CONTROL_PATH),
                        ),
                        (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
                    ],
                )

    def test_a_result_that_is_not_an_object_withholds_the_artifact(self) -> None:
        for result in (5, "passed", None, []):
            with self.subTest(result=result):
                output = run_control(make_result(), result)
                self.assertEqual(output.observations, ())
                self.assertEqual(
                    diagnostic_lines(output),
                    [
                        (
                            DiagnosticLevel.ERROR,
                            "invalid_control",
                            coalesced("result must be an object", f"{CONTROL_PATH}.results[1]"),
                        )
                    ],
                )

    def test_one_bad_control_withholds_every_observation(self) -> None:
        output = parse_direct(
            document_with(make_control("SYN-CTL-0001"), make_control("SYN-CTL-\u0000"))
        )
        self.assertEqual(output.observations, ())
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.ERROR,
                    "identity_input_invalid",
                    coalesced(
                        IDENTITY_SUMMARY,
                        "profiles[0].controls[1].id",
                        detail="control id contains prohibited code point U+0000",
                    ),
                )
            ],
        )

    def test_a_control_id_is_refused_whole_past_its_cap(self) -> None:
        accepted = only_observation(run_control(make_result(), id="S" * MAX_IDENTITY_CHARS))
        self.assertEqual(accepted.source_record_id, "S" * MAX_IDENTITY_CHARS)
        output = run_control(make_result(), id="S" * (MAX_IDENTITY_CHARS + 1))
        self.assertEqual(output.observations, ())
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.ERROR,
                    "identity_input_invalid",
                    coalesced(
                        IDENTITY_SUMMARY,
                        f"{CONTROL_PATH}.id",
                        detail=f"control id is {MAX_IDENTITY_CHARS + 1} characters; maximum is "
                        f"{MAX_IDENTITY_CHARS}",
                    ),
                ),
                (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
            ],
        )

    def test_a_control_id_is_stripped_and_never_repaired(self) -> None:
        self.assertEqual(
            only_observation(run_control(make_result(), id="  SYN-CTL-0001\t")).source_record_id,
            "SYN-CTL-0001",
        )

    def test_a_format_character_in_a_profile_name_is_refused(self) -> None:
        output = parse_direct(make_document(make_profile("synthetic​profile")))
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.ERROR,
                    "identity_input_invalid",
                    coalesced(
                        IDENTITY_SUMMARY,
                        "profiles[0].name",
                        detail="profile name contains prohibited code point U+200B",
                    ),
                ),
                (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
            ],
        )

    def test_a_refused_target_skips_every_profile(self) -> None:
        output = parse_direct(make_document(target="synthetic host"))
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.ERROR,
                    "identity_input_invalid",
                    coalesced(
                        IDENTITY_SUMMARY,
                        "platform.target_id",
                        detail="target_id contains prohibited code point U+2028",
                    ),
                ),
                (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
            ],
        )
        # The converter line is written before the target is read, so a converted document
        # keeps it beside the refusal.
        converted = parse_direct(
            make_document(platform_name=HDF_CONVERTER_PLATFORM, target="synthetic\u2028host")
        )
        self.assertEqual(converted.observations, ())
        self.assertEqual(
            diagnostic_lines(converted),
            [
                (
                    DiagnosticLevel.INFO,
                    "converted_document",
                    coalesced(CONVERTED_SUMMARY, "platform"),
                ),
                *diagnostic_lines(output),
            ],
        )

    def test_a_profile_name_is_refused_whole_past_its_cap(self) -> None:
        name = "P" * MAX_IDENTITY_CHARS
        accepted = only_observation(parse_direct(make_document(make_profile(name))))
        self.assertEqual(accepted.context_key, name)
        output = parse_direct(make_document(make_profile(name + "P")))
        self.assertEqual(output.observations, ())
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.ERROR,
                    "identity_input_invalid",
                    coalesced(
                        IDENTITY_SUMMARY,
                        "profiles[0].name",
                        detail=f"profile name is {MAX_IDENTITY_CHARS + 1} characters; maximum is "
                        f"{MAX_IDENTITY_CHARS}",
                    ),
                ),
                (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
            ],
        )

    def test_a_target_id_is_refused_whole_past_its_cap(self) -> None:
        target = "T" * MAX_IDENTITY_CHARS
        accepted = only_observation(parse_direct(make_document(target=target)))
        self.assertEqual(
            (accepted.resource.resource_type, accepted.resource.resource_id), ("target", target)
        )
        output = parse_direct(make_document(target=target + "T"))
        self.assertEqual(output.observations, ())
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.ERROR,
                    "identity_input_invalid",
                    coalesced(
                        IDENTITY_SUMMARY,
                        "platform.target_id",
                        detail=f"target_id is {MAX_IDENTITY_CHARS + 1} characters; maximum is "
                        f"{MAX_IDENTITY_CHARS}",
                    ),
                ),
                (DiagnosticLevel.ERROR, "no_observations", NO_OBSERVATIONS_MESSAGE),
            ],
        )


# *--- Degraded Evidence ---*


class HdfDegradedEvidenceTests(unittest.TestCase):
    """Evidence text is sanitized and cut, never refused, and every cut is named."""

    def test_a_format_character_in_a_title_is_removed(self) -> None:
        output = run_control(make_result(), title="Synthetic​ title")
        observation = only_observation(output)
        self.assertEqual(observation.title, "Synthetic title")
        self.assertNotIn("truncated", metadata(observation))
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.WARNING,
                    "evidence_sanitized",
                    coalesced(SANITIZED_SUMMARY, CONTROL_PATH),
                )
            ],
        )

    def test_a_line_separator_becomes_a_newline(self) -> None:
        observation = observe(make_result(), desc="First line second line")
        self.assertEqual(observation.description, "First line\nsecond line")

    def test_a_null_in_a_failure_message_is_removed(self) -> None:
        output = run_control(make_result("failed", message="Synthetic\u0000 failure"))
        self.assertEqual(
            metadata(only_observation(output))["failure_messages"], encoded("Synthetic failure")
        )
        self.assertEqual(diagnostic_codes(output), ["evidence_sanitized"])

    def test_an_over_cap_description_and_title_are_cut_with_the_marker(self) -> None:
        output = run_control(
            make_result(), title="T" * (MAX_TITLE_CHARS + 88), desc="D" * OVER_DESCRIPTION
        )
        observation = only_observation(output)
        self.assertEqual(len(observation.title), MAX_TITLE_CHARS)
        self.assertTrue(observation.title.endswith(TRUNCATION_MARKER))
        self.assertEqual(len(observation.description), MAX_DESCRIPTION_CHARS)
        self.assertTrue(observation.description.endswith(TRUNCATION_MARKER))
        self.assertEqual(metadata(observation)["truncated"], encoded("description", "title"))
        self.assertEqual(
            only_diagnostic(output, "evidence_truncated").message,
            coalesced(TRUNCATED_SUMMARY, CONTROL_PATH, CONTROL_PATH),
        )

    def test_an_over_cap_tag_list_and_item_are_cut(self) -> None:
        items = [numbered("n", index, 20) for index in range(300)]
        observation = observe(make_result(), tags={"nist": items})
        kept = json.loads(metadata(observation)["nist_tags"])
        self.assertEqual(kept, sorted(items)[:MAX_LIST_ITEMS])
        self.assertEqual(metadata(observation)["truncated"], encoded("nist_tags"))
        observation = observe(make_result(), tags={"nist": ["n" * OVER_ITEM]})
        (item,) = json.loads(metadata(observation)["nist_tags"])
        self.assertEqual(len(item), MAX_LIST_ITEM_CHARS)
        self.assertTrue(item.endswith(TRUNCATION_MARKER))

    def test_an_over_cap_scalar_is_cut_and_named(self) -> None:
        observation = observe(make_result(), tags={"gid": "G" * OVER_SCALAR})
        self.assertEqual(len(metadata(observation)["group_id"]), MAX_METADATA_VALUE_CHARS)
        self.assertEqual(metadata(observation)["truncated"], encoded("group_id"))

    def test_truncated_names_every_member_that_was_cut(self) -> None:
        observation = observe(
            make_result("failed", "C" * OVER_ITEM, message="M" * OVER_ITEM),
            title="T" * OVER_SCALAR,
            desc="D" * OVER_DESCRIPTION,
            tags={"nist": ["N" * OVER_ITEM], "rid": "R" * OVER_SCALAR},
            waiver_data={"justification": "J" * OVER_SCALAR},
        )
        self.assertEqual(
            metadata(observation)["truncated"],
            encoded(
                "description",
                "failed_results",
                "failure_messages",
                "nist_tags",
                "rule_id",
                "title",
                "waiver_justification",
            ),
        )

    def test_repeated_list_items_are_counted_once_before_the_cap(self) -> None:
        output = run_control(
            *[make_result("failed", "same check", message="same msg")] * (MAX_LIST_ITEMS + 1),
            make_result("failed", "zz other check", message="zz other msg"),
            tags={"nist": ["AC-2"] * (MAX_LIST_ITEMS + 1) + ["SI-4"]},
        )
        recorded = metadata(only_observation(output))
        self.assertEqual(recorded["failed_results"], encoded("same check", "zz other check"))
        self.assertEqual(recorded["failure_messages"], encoded("same msg", "zz other msg"))
        self.assertEqual(recorded["nist_tags"], encoded("AC-2", "SI-4"))
        self.assertNotIn("truncated", recorded)

    def test_only_the_descriptions_entry_labelled_default_stands_in_for_desc(self) -> None:
        entries = [
            "not an object",
            {"label": "check", "data": "Synthetic check text."},
            {"label": "default", "data": "Synthetic default text."},
            {"label": "fix", "data": "Synthetic fix text."},
        ]
        for desc in (None, ""):
            with self.subTest(desc=desc):
                observation = observe(make_result(), desc=desc, descriptions=entries)
                self.assertEqual(observation.description, "Synthetic default text.")
        observation = observe(
            make_result(), desc=None, descriptions=[{"label": "fix", "data": "Synthetic fix text."}]
        )
        self.assertEqual(observation.description, "")
        self.assertNotIn("Synthetic fix text.", observation.to_canonical_json())

    def test_a_blank_or_non_string_desc_falls_back_to_the_default_entry(self) -> None:
        entries = [{"label": "default", "data": "Synthetic default text."}]
        for desc in ("", "  \n\t ", 5, ["x"]):
            with self.subTest(desc=desc):
                observation = observe(make_result(), desc=desc, descriptions=entries)
                self.assertEqual(observation.description, "Synthetic default text.")


# *--- Bounds ---*


class HdfBoundsTests(unittest.TestCase):
    """Every bound fails the artifact closed, attributed to HDF with its exact message."""

    def assert_bound(self, result: IngestResult, message: str, location: str = LINUX) -> None:
        self.assertEqual(attribution(result), HDF_ATTRIBUTION)
        self.assertFalse(result.successful)
        self.assertEqual(result.observations, ())
        self.assertEqual(
            [(item.code, item.message, item.location) for item in result.errors],
            [("artifact_parse_failed", message, location)],
        )

    def test_the_parse_bounds_are_attributed_to_hdf(self) -> None:
        for limits, message in (
            (IngestLimits(max_json_nodes=50), "JSON contains more than 50 values"),
            (IngestLimits(max_json_depth=3), "JSON nesting exceeds 3 levels"),
        ):
            with self.subTest(message=message):
                self.assert_bound(ingest_fixture(LINUX, limits=limits), message)

    def test_more_than_sixty_four_profiles_are_refused(self) -> None:
        def profiles(count: int) -> list[dict[str, Any]]:
            return [make_profile(f"synthetic-profile-{index:02d}") for index in range(count)]

        accepted = ingest_document(make_document(*profiles(MAX_PROFILES_PER_DOCUMENT)))
        self.assertTrue(accepted.successful, accepted.errors)
        self.assertEqual(len(accepted.observations), MAX_PROFILES_PER_DOCUMENT)
        self.assert_bound(
            ingest_document(make_document(*profiles(MAX_PROFILES_PER_DOCUMENT + 1))),
            "HDF document lists 65 profiles; maximum is 64",
            "synthetic.hdf.json",
        )

    def test_the_per_profile_and_per_control_counts_are_bounded(self) -> None:
        self.assert_bound(
            ingest_fixture(LINUX, limits=IngestLimits(max_results_per_run=5)),
            "profiles[0] contains 6 controls; maximum is 5",
        )
        document = document_with(make_control(results=[make_result()] * 3))
        self.assert_bound(
            ingest_document(document, limits=IngestLimits(max_results_per_run=2)),
            "profiles[0].controls[0] contains 3 results; maximum is 2",
            "synthetic.hdf.json",
        )
        # Each bound admits a count equal to it.
        accepted = ingest_fixture(LINUX, limits=IngestLimits(max_results_per_run=6))
        self.assertTrue(accepted.successful, accepted.errors)
        self.assertEqual(len(accepted.observations), 6)
        accepted = ingest_document(
            document_with(make_control(results=[make_result()] * 2)),
            limits=IngestLimits(max_results_per_run=2),
        )
        self.assertTrue(accepted.successful, accepted.errors)
        self.assertEqual(len(accepted.observations), 1)

    def test_the_observation_count_is_bounded(self) -> None:
        self.assert_bound(
            ingest_fixture(LINUX, limits=IngestLimits(max_observations_per_artifact=5)),
            "artifact yields more than 5 observations",
        )
        accepted = ingest_fixture(LINUX, limits=IngestLimits(max_observations_per_artifact=6))
        self.assertEqual(len(accepted.observations), 6)

    def test_the_per_observation_ceiling_is_the_module_constant(self) -> None:
        with mock.patch.object(hdf_module, "MAX_OBSERVATION_JSON_BYTES", 500):
            result = ingest_fixture(LINUX)
        self.assertEqual(attribution(result), HDF_ATTRIBUTION)
        self.assertEqual(result.observations, ())
        self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])
        self.assertRegex(
            result.errors[0].message,
            r"^observation obs-[0-9a-f]{64} is [0-9]+ bytes of canonical JSON; maximum is 500$",
        )

    def test_the_observation_byte_budget_is_the_sum_of_every_observation(self) -> None:
        sizes = [
            len(item.to_canonical_json().encode("utf-8"))
            for item in ingest_fixture(LINUX).observations
        ]
        self.assertGreater(sum(sizes) - 1, max(sizes))
        accepted = ingest_fixture(
            LINUX, limits=IngestLimits(max_observation_bytes_per_artifact=sum(sizes))
        )
        self.assertEqual(len(accepted.observations), 6)
        budget = sum(sizes) - 1
        self.assert_bound(
            ingest_fixture(LINUX, limits=IngestLimits(max_observation_bytes_per_artifact=budget)),
            f"artifact yields more than {budget} bytes of observation JSON",
        )

    def test_a_maximal_observation_fits_under_both_ceilings(self) -> None:
        # Four-byte text and the two characters JSON escapes cost the most bytes per cap.
        for char in ("\U0001f600", '"', "\\"):
            with self.subTest(char=repr(char)):
                result = ingest_document(maximal_document(char))
                self.assertTrue(result.successful, result.errors)
                observation = only_observation(result)
                self.assertEqual(
                    diagnostic_codes(result),
                    [
                        "evidence_truncated",
                        "profile_not_loaded",
                        "invalid_severity_tag",
                        "control_waived",
                        "control_attested",
                    ],
                )
                recorded = metadata(observation)
                self.assertEqual(set(recorded), HDF_METADATA_KEYS)
                self.assertEqual(set(json.loads(recorded["truncated"])), MAXIMAL_TRUNCATED)
                self.assertEqual(len(observation.title), MAX_TITLE_CHARS)
                self.assertEqual(len(observation.description), MAX_DESCRIPTION_CHARS)
                self.assertEqual(len(observation.source_identifiers), MAX_LIST_ITEMS)
                self.assertEqual(len(observation.source_record_id), MAX_IDENTITY_CHARS)
                self.assertEqual(len(observation.resource.resource_id), MAX_IDENTITY_CHARS)
                self.assertEqual(len(observation.context_key), MAX_IDENTITY_CHARS)
                for key in MAXIMAL_TRUNCATED - {
                    "description",
                    "failed_results",
                    "failure_messages",
                    "nist_tags",
                    "source_identifiers",
                    "title",
                }:
                    self.assertEqual(len(recorded[key]), MAX_METADATA_VALUE_CHARS, key)
                for key in ("failed_results", "failure_messages", "nist_tags"):
                    items = json.loads(recorded[key])
                    self.assertEqual(len(items), MAX_LIST_ITEMS, key)
                    self.assertEqual({len(item) for item in items}, {MAX_LIST_ITEM_CHARS}, key)
                size = len(observation.to_canonical_json().encode("utf-8"))
                self.assertLess(size, MAX_OBSERVATION_JSON_BYTES)
                self.assertLess(MAX_OBSERVATION_JSON_BYTES, MAX_EVENT_JSON_BYTES)

    def test_a_key_outside_the_vocabulary_is_a_programming_error(self) -> None:
        with mock.patch.object(hdf_module, "HDF_METADATA_KEYS", frozenset()):
            with self.assertRaisesRegex(
                RuntimeError, r"^metadata keys outside the fixed vocabulary: \['disposition_source'"
            ):
                parse_direct(make_document())


# *--- Converter ---*


class HdfConverterTests(unittest.TestCase):
    """The converter platform name is compared exactly and named once per artifact."""

    def test_the_identity_literals_are_pinned(self) -> None:
        self.assertEqual(HDF_CONVERTER_PLATFORM, "Heimdall Tools")
        self.assertEqual(HDF_NATIVE_TOOL, "inspec")
        self.assertEqual(HDF_CONVERTER_TOOL, "heimdall-tools")
        self.assertEqual(HDF_SOURCE_TYPE, "hdf")
        self.assertEqual(HDF_PARSER_VERSION, "1")
        self.assertEqual(HDF_MEDIA_TYPE, "application/json")
        self.assertEqual(
            (HdfAdapter.name, HdfAdapter.version, HdfAdapter.media_type), HDF_ATTRIBUTION
        )
        self.assertEqual(MAX_PROFILES_PER_DOCUMENT, 64)

    def test_only_the_exact_converter_name_marks_a_converted_document(self) -> None:
        for name in (
            "heimdall tools",
            "HEIMDALL TOOLS",
            " Heimdall Tools",
            "Heimdall Tools ",
            "Heimdall  Tools",
            "Heimdall_Tools",
        ):
            with self.subTest(name=name):
                output = parse_direct(make_document(platform_name=name))
                self.assertEqual(only_observation(output).source_tool, HDF_NATIVE_TOOL)
                self.assertEqual(output.diagnostics, ())

    def test_a_converted_document_is_named_once_per_artifact(self) -> None:
        output = parse_direct(
            make_document(
                make_profile(
                    controls=[make_control(f"CVE-2099-000{index}") for index in range(1, 4)]
                ),
                platform_name=HDF_CONVERTER_PLATFORM,
            )
        )
        self.assertEqual({item.source_tool for item in output.observations}, {HDF_CONVERTER_TOOL})
        self.assertEqual(
            diagnostic_lines(output),
            [
                (
                    DiagnosticLevel.INFO,
                    "converted_document",
                    coalesced(CONVERTED_SUMMARY, "platform"),
                )
            ],
        )

    def test_a_converted_document_without_a_target_falls_back_to_the_scan(self) -> None:
        output = parse_direct(make_document(platform_name=HDF_CONVERTER_PLATFORM, target=""))
        observation = only_observation(output)
        self.assertEqual(
            (observation.resource.resource_type, observation.resource.resource_id), ("scan", ROOT)
        )
        self.assertEqual(
            diagnostic_codes(output), ["converted_document", "resource_identity_fallback"]
        )


# *--- Goldens ---*


class HdfGoldenTests(unittest.TestCase):
    """The HDF goldens are the stateless compile of fixtures 1 to 3, byte for byte.

    `tests/golden/vdt-hdf.json` and `vdt-hdf.md` were generated through the command line with
    the options `report_options` names; the compiler reproduces them here, whatever order the
    three fixtures arrive in.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = compile_hdf_golden()
        cls.document = cls.report.document

    def reported_ids(self) -> list[str]:
        return [item["providerTrackingId"] for item in self.document["vulnerabilities"]]

    def test_the_json_golden_is_reproduced_byte_for_byte(self) -> None:
        self.assertEqual(
            self.report.to_json().encode("utf-8"), (GOLDEN / "vdt-hdf.json").read_bytes()
        )

    def test_the_markdown_golden_is_reproduced_byte_for_byte(self) -> None:
        self.assertEqual(
            self.report.to_markdown().encode("utf-8"), (GOLDEN / "vdt-hdf.md").read_bytes()
        )

    def test_compiling_twice_yields_identical_bytes(self) -> None:
        again = compile_hdf_golden()
        self.assertEqual(again.to_json(), self.report.to_json())
        self.assertEqual(again.to_markdown(), self.report.to_markdown())

    def test_every_order_of_the_three_fixtures_yields_the_golden_bytes(self) -> None:
        golden_json = (GOLDEN / "vdt-hdf.json").read_bytes()
        golden_markdown = (GOLDEN / "vdt-hdf.md").read_bytes()
        for order in permutations(HDF_ARTIFACTS):
            with self.subTest(order=[path.name for path in order]):
                report = compile_hdf_golden(order)
                self.assertEqual(report.to_json().encode("utf-8"), golden_json)
                self.assertEqual(report.to_markdown().encode("utf-8"), golden_markdown)

    def test_the_golden_validates_against_the_official_schema(self) -> None:
        self.assertTrue(self.report.validation.is_valid)
        self.assertEqual(self.report.validation.issues, ())

    def test_the_summary_totals_reconcile_with_the_vulnerabilities(self) -> None:
        counts = summary_counts(self.report.to_markdown())
        vulnerabilities = self.document["vulnerabilities"]
        overdue = [
            item["providerTrackingId"]
            for item in vulnerabilities
            if item["overdueStatus"]["isOverdue"]
        ]
        self.assertEqual(len(vulnerabilities), len(GOLDEN_TRACKING_IDS))
        self.assertEqual(counts["Vulnerabilities reported"], len(vulnerabilities))
        self.assertEqual(counts["Evaluated"], 0)
        self.assertEqual(counts["Not yet evaluated"], len(vulnerabilities))
        self.assertEqual(
            overdue, [item for item in GOLDEN_TRACKING_IDS if item != NOT_OVERDUE_TRACKING_ID]
        )
        self.assertEqual(counts["Overdue"], len(overdue))
        self.assertEqual(counts["Accepted, reported under VER-RPT-AVI"], 0)
        self.assertEqual(counts["Excluded by report period"], 0)
        self.assertEqual(self.document["x-complyroll"]["excludedByPeriod"], 0)
        attestation = self.document["x-complyroll"]["detectionTimeAttestation"]
        self.assertEqual(attestation["detectedAt"], "2026-09-01T00:00:00Z")
        self.assertEqual(attestation["count"], len(attestation["appliedTo"]))
        self.assertEqual(tuple(attestation["appliedTo"]), CLOCKLESS_TRACKING_IDS)

    def test_detection_times_come_from_a_native_clock_or_the_attestation(self) -> None:
        detections = {
            item["providerTrackingId"]: (
                item["detection"]["detectedAt"],
                item["x-complyroll"]["detectedAtSource"],
                item["detection"]["detectionSource"],
            )
            for item in self.document["vulnerabilities"]
        }
        attested = ("2026-09-01T00:00:00Z", "attestation", HDF_CONVERTER_TOOL)
        self.assertEqual(
            detections,
            {
                "case-1706b7990cce1346": attested,
                "case-057bbe4ee9dde990": attested,
                "case-71446ac59461edb8": attested,
                "case-181b4b18c88fe895": ("2026-09-10T21:02:11Z", "artifact", HDF_NATIVE_TOOL),
                "case-db1a983f4e0a849a": ("2026-09-08T16:01:30Z", "artifact", HDF_NATIVE_TOOL),
            },
        )
        for detected_at, _, _ in detections.values():
            with self.subTest(detected_at=detected_at):
                instant = datetime.fromisoformat(detected_at)
                self.assertGreaterEqual(instant, REPORT_PERIOD_FROM)
                self.assertLessEqual(instant, REPORT_AS_OF)

    def test_exactly_one_unresolved_observation_is_warned_about(self) -> None:
        unresolved = [
            item for item in self.report.diagnostics if item.code == "unresolved_observation"
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0].level.value, "warning")
        self.assertEqual(unresolved[0].location, LINUX)
        self.assertEqual(
            unresolved[0].message,
            f"SYN-LNX-0005 on {LINUX_TARGET} has disposition error and was not reported as a "
            "vulnerability",
        )
        recorded = [
            item
            for item in self.document["x-complyroll"]["diagnostics"]
            if item["code"] == "unresolved_observation"
        ]
        self.assertEqual(len(recorded), 1)

    def test_only_the_open_observations_are_reported(self) -> None:
        linux = by_record(ingest_fixture(LINUX))
        overlay = by_record(ingest_fixture(OVERLAY))
        reported = {
            observation_id
            for item in self.document["vulnerabilities"]
            for observation_id in item["x-complyroll"]["observationIds"]
        }
        self.assertEqual(reported, {*TRIVY_IDS, LINUX_IDS[0], OVERLAY_IDS[0]})
        # The errored native check is neither PASS nor OPEN, and it is not a vulnerability.
        self.assertEqual(linux["SYN-LNX-0005"].disposition, ERROR)
        self.assertNotIn(linux["SYN-LNX-0005"].observation_id, reported)
        # The attested overlay control reads PASS from its attestation result.
        attested = overlay["SYN-RHL-0002"]
        self.assertEqual(attested.disposition, PASS)
        self.assertEqual(metadata(attested)["attested"], "true")
        self.assertNotIn(attested.observation_id, reported)

    def test_no_attestation_author_or_updated_by_line_reaches_the_report(self) -> None:
        names = {
            control["attestation_data"]["updated_by"]
            for profile in fixture_payload(OVERLAY)["profiles"]
            for control in profile["controls"]
            if control.get("attestation_data")
        }
        self.assertEqual(len(names), 1)
        for rendering in (self.report.to_json(), self.report.to_markdown()):
            for text in (*names, "Updated By", "SYN-RHL-0002"):
                with self.subTest(text=text):
                    self.assertNotIn(text, rendering)

    def test_every_golden_tracking_id_is_a_fixture_case_in_golden_order(self) -> None:
        self.assertEqual(self.reported_ids(), list(GOLDEN_TRACKING_IDS))
        open_observations = sorted(
            (
                item
                for name in (LINUX, TRIVY, OVERLAY)
                for item in ingest_fixture(name).observations
                if item.disposition is OPEN
            ),
            key=lambda item: (item.source_type, item.source_record_id, item.context_key),
        )
        self.assertEqual(
            [tracking_id_of(item) for item in open_observations], list(GOLDEN_TRACKING_IDS)
        )

    def test_the_golden_attributes_the_hdf_parser_and_its_three_inputs(self) -> None:
        extension = self.document["x-complyroll"]
        self.assertEqual(extension["parserVersions"], {"complyroll.hdf": HDF_PARSER_VERSION})
        self.assertEqual(
            [
                (item["name"], item["parser"], item["observationCount"])
                for item in extension["artifacts"]
            ],
            [
                (LINUX, "complyroll.hdf", len(LINUX_IDS)),
                (OVERLAY, "complyroll.hdf", len(OVERLAY_IDS)),
                (TRIVY, "complyroll.hdf", len(TRIVY_IDS)),
            ],
        )


# *--- Path Equivalence ---*


class HdfPathEquivalenceTests(StoreFixture):
    """The persisted path over fixtures 1 to 3 reports the golden bytes (ADR 0010)."""

    def persist(self, order: Sequence[Path] = HDF_ARTIFACTS) -> None:
        """Record, correlate, and attest the fixtures the way the four commands would."""
        self.ingest(order)
        self.correlate()
        self.attest(detected_at=REPORT_DETECTED_AT)

    def assert_reports_match(self) -> None:
        persisted_options = report_options()
        stateless_options = report_options(detected_at=REPORT_DETECTED_AT)
        vdt = compile_vdt_report_from_history(self.repository, options=persisted_options)
        self.assertEqual(vdt.to_json(), (GOLDEN / "vdt-hdf.json").read_text(encoding="utf-8"))
        self.assertEqual(vdt.to_markdown(), (GOLDEN / "vdt-hdf.md").read_text(encoding="utf-8"))
        pairs = (
            (vdt, compile_vdt_report(list(HDF_ARTIFACTS), options=stateless_options)),
            (
                compile_avi_report_from_history(self.repository, options=persisted_options),
                compile_avi_report(list(HDF_ARTIFACTS), options=stateless_options),
            ),
            (
                compile_historical_report_from_history(self.repository, options=persisted_options),
                compile_historical_report(list(HDF_ARTIFACTS), options=stateless_options),
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
        self.persist(tuple(reversed(HDF_ARTIFACTS)))
        self.assert_reports_match()

    def test_every_ingest_order_reports_the_golden_bytes_from_history(self) -> None:
        golden_json = (GOLDEN / "vdt-hdf.json").read_text(encoding="utf-8")
        golden_markdown = (GOLDEN / "vdt-hdf.md").read_text(encoding="utf-8")
        for order in permutations(HDF_ARTIFACTS):
            with self.subTest(order=[path.name for path in order]):
                repository = self.open_repository(self.fresh_workspace())
                for path in order:
                    record_ingest(
                        repository,
                        ingest_stig_artifact(path, ingested_at=INGESTED_AT),
                        metadata=self.metadata,
                        ingested_at=INGESTED_AT,
                    )
                correlate_cases(repository, metadata=self.metadata, now=INGESTED_AT)
                attest_detection(
                    repository,
                    tuple(case.tracking_id for case in fold_all_cases(repository)),
                    detected_at=REPORT_DETECTED_AT,
                    rationale=RATIONALE,
                    metadata=self.metadata,
                    now=INGESTED_AT,
                )
                report = compile_vdt_report_from_history(repository, options=report_options())
                self.assertEqual(report.to_json(), golden_json)
                self.assertEqual(report.to_markdown(), golden_markdown)

    def test_the_attestation_reaches_only_the_cases_without_a_source_clock(self) -> None:
        self.ingest(HDF_ARTIFACTS)
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

    def test_a_cve_title_is_stored_as_written_and_reported_with_one_prefix(self) -> None:
        # The case keeps the converter's title, which already leads with the CVE id, and the
        # report renders it as it stands rather than naming the id twice.
        self.persist()
        title = "CVE-2099-0001: synthlib: synthetic cross-site scripting in the template renderer"
        created = {
            record.payload["sourceRecordId"]: record.payload
            for record in self.repository.read_all()
            if record.event_type == "case.created"
        }
        self.assertEqual(created["CVE-2099-0001"]["title"], title)
        report = compile_vdt_report_from_history(self.repository, options=report_options())
        descriptions = {
            item["vulnerabilityDescription"] for item in report.document["vulnerabilities"]
        }
        self.assertIn(title, descriptions)
        self.assertNotIn("CVE-2099-0001: CVE-2099-0001", report.to_json())
        self.assertNotIn("CVE-2099-0001: CVE-2099-0001", report.to_markdown())

    def test_without_the_attestation_both_paths_stop_on_the_converted_cases(self) -> None:
        self.ingest(HDF_ARTIFACTS)
        self.correlate()
        for label, compile_report in (
            (
                "persisted",
                lambda: compile_vdt_report_from_history(self.repository, options=report_options()),
            ),
            (
                "stateless",
                lambda: compile_vdt_report(list(HDF_ARTIFACTS), options=report_options()),
            ),
        ):
            with self.subTest(path=label):
                with self.assertRaises(ReportCompileError) as caught:
                    compile_report()
                diagnostics = caught.exception.diagnostics
                self.assertEqual([item.code for item in diagnostics], ["detection_time_missing"])
                for tracking_id in CLOCKLESS_TRACKING_IDS:
                    self.assertIn(tracking_id, diagnostics[0].message)
                for tracking_id in CLOCKED_TRACKING_IDS:
                    self.assertNotIn(tracking_id, diagnostics[0].message)

    def test_store_verify_passes_and_the_audit_finds_no_fault(self) -> None:
        self.persist()
        verifier = SQLiteEventStore.open_for_verification(self.database)
        self.addCleanup(verifier.close)
        integrity = verifier.verify_history()
        self.assertTrue(integrity.ok, integrity.render())
        self.assertEqual(integrity.faults, ())
        # Three artifacts, twelve observations, five cases each created and linked once, and
        # three detection attestations.
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
            sorted(LINUX_IDS + TRIVY_IDS + OVERLAY_IDS),
        )
        for record in recorded:
            with self.subTest(observation=record.payload["observation_id"]):
                self.repository.validate_payload(
                    record.event_type, record.payload, event_version=record.event_version
                )


# *--- Entry Point ---*

if __name__ == "__main__":
    unittest.main()
