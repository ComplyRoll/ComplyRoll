# ******************************************************************************
# *Title: Detection Failure Tests*
# *Author: Kyle Versluis*
# *Description: Unit tests for detection process failure records (ADR 0014).*
# ******************************************************************************
"""Unit tests for detection failures: classes, reasons, vocabulary, records, diagnostics."""

# *--- Imports ---*

from __future__ import annotations

import ast
import hashlib
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback
import unittest
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, NamedTuple
from unittest import mock

from test_sarif import make_log, make_result, make_run

import complyroll
from complyroll.adapters import (
    DEFAULT_LIMITS,
    DETECTION_FAILURE_SOURCE_TYPE,
    FAILURE_DIAGNOSTIC_CAP,
    CycloneDxAdapter,
    FailureClass,
    FailureClassification,
    IngestLimits,
    InputLimitError,
    UnmintableReason,
    UnsafeXmlError,
    classify_ingest,
    failure_diagnostics,
    ingest_stig_artifact,
    system_observation_for,
)
from complyroll.adapters import failures as failures_module
from complyroll.adapters import stig as stig_module
from complyroll.adapters.base import (
    AdapterParseError,
    ArtifactProvenance,
    DiagnosticLevel,
    IngestDiagnostic,
    IngestResult,
    ParsedDocument,
)
from complyroll.adapters.categories import prohibited_category
from complyroll.adapters.common import (
    MAX_METADATA_VALUE_CHARS,
    MAX_OBSERVATION_JSON_BYTES,
    TRUNCATION_MARKER,
    diagnostic_text,
    encode_list,
)
from complyroll.adapters.failures import (
    CLASS_CODES,
    CONTENT_CODES,
    DETECTION_FAILURE_RECORDED,
    EXECUTION_UNSUCCESSFUL,
    FAILURE_DIAGNOSTICS_TRUNCATED,
    PARSE_CODES,
    UNMINTABLE_CODES,
    failure_class_for_codes,
)
from complyroll.adapters.hdf import HdfAdapter
from complyroll.adapters.sarif import SarifAdapter
from complyroll.adapters.stig import CklAdapter, CklbAdapter, XccdfAdapter
from complyroll.models import (
    RESERVED_SOURCE_TYPE_PREFIX,
    Observation,
    ObservationDisposition,
    ObservationOrigin,
    ResourceRef,
    SourceSeverity,
)

# *--- Configuration ---*

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=3)
AS_OF = datetime(2026, 9, 2, 0, 0, tzinfo=UTC)
INVOKED = datetime(2026, 8, 31, 9, 30, tzinfo=UTC)
DIGEST = "0123456789abcdef" * 4
OTHER_DIGEST = "fedcba9876543210" * 4
REFERENCE = f"sha256:{DIGEST}"
NAME = "synthetic.cklb"
ADAPTERS = Path(failures_module.__file__).resolve().parent
FIXTURES = Path(__file__).parent / "fixtures"
SOURCE_ROOT = Path(complyroll.__file__).resolve().parents[1]

ERROR = DiagnosticLevel.ERROR
WARNING = DiagnosticLevel.WARNING
INFO = DiagnosticLevel.INFO
EXECUTION = FailureClass.EXECUTION
PARSE = FailureClass.PARSE
CONTENT = FailureClass.CONTENT

# The content-class record of DIGEST as of AS_OF. Read field by field against the plan's
# identity table, and recomputed from the payload in its own test, before it was frozen.
PINNED_RECORD_ID = "obs-e3aa066d30e057ddcb8dcbbe30ce7f2b92e828dfd354027369fe7b1d1d648081"

# A rule STIG Viewer would write. checklist() gives it a host and a clock, so no warning
# joins the diagnostics a test counts.
GOOD_RULE: dict[str, Any] = {
    "group_id": "V-000001",
    "rule_id": "SV-000001r1_rule",
    "status": "open",
    "severity": "high",
    "rule_title": "synthetic rule",
}

# Emitters that pass a level through rather than choose one. Diagnostics.emit re-renders the
# levels its add calls chose, and failure_diagnostics can only lower a level.
PASS_THROUGH_LEVELS = frozenset({("common.py", "emit"), ("failures.py", "failure_diagnostics")})

# The source types every shipped adapter mints today; the walk may find more, never fewer.
SHIPPED_SOURCE_TYPES = frozenset({"cklb", "ckl", "xccdf", "hdf", "sarif", "cyclonedx"})

# *--- Helpers ---*


def provenance(
    digest: str = DIGEST,
    *,
    name: str = NAME,
    ingested_at: datetime = NOW,
    parser_name: str = "complyroll.cklb",
    parser_version: str = "1",
    media_type: str = "application/json",
) -> ArtifactProvenance:
    """Build the provenance of a synthetic artifact."""
    return ArtifactProvenance(
        artifact_id=f"artifact-sha256-{digest}",
        name=name,
        source_path=f"/synthetic/{name}",
        digest_sha256=digest,
        size_bytes=2048,
        media_type=media_type,
        parser_name=parser_name,
        parser_version=parser_version,
        ingested_at=ingested_at,
    )


PROVENANCE = provenance()


def error(code: str, location: str | None = NAME, message: str = "synthetic") -> IngestDiagnostic:
    return IngestDiagnostic(ERROR, code, message, location)


def warning(code: str, location: str | None = NAME, message: str = "synthetic") -> IngestDiagnostic:
    return IngestDiagnostic(WARNING, code, message, location)


def info(code: str, location: str | None = NAME, message: str = "synthetic") -> IngestDiagnostic:
    return IngestDiagnostic(INFO, code, message, location)


def reading(
    *diagnostics: IngestDiagnostic,
    artifact: ArtifactProvenance = PROVENANCE,
    digestless: bool = False,
    observations: tuple[Observation, ...] = (),
    format_rejected: bool = False,
    failed_execution_at: datetime | None = None,
    withheld: bool = False,
) -> IngestResult:
    """Build one reading by hand, with the artifact unless it is digestless."""
    return IngestResult(
        None if digestless else artifact,
        observations,
        diagnostics,
        format_rejected=format_rejected,
        failed_execution_at=failed_execution_at,
        withheld=withheld,
    )


def artifact_observation() -> Observation:
    """Build one artifact-bound finding for a reading that carries observations."""
    return Observation(
        observation_id="obs-synthetic",
        source_type="cklb",
        source_tool="stig-viewer-3",
        parser_name="complyroll.cklb",
        parser_version="1",
        source_record_id="V-000001",
        resource=ResourceRef("host-a", "host"),
        observed_at=NOW,
        ingested_at=NOW,
        disposition=ObservationDisposition.OPEN,
        source_artifact_digest=DIGEST,
        source_artifact_name=NAME,
    )


def content_failure(artifact: ArtifactProvenance = PROVENANCE) -> IngestResult:
    """Return a checklist reading whose rules were all unusable."""
    return reading(
        error("invalid_rule", "stigs[0].rules[0]"), error("no_observations"), artifact=artifact
    )


def mint(result: IngestResult, *, name: str = NAME, observed_at: datetime = AS_OF) -> Observation:
    """Classify a reading and build its system record."""
    classification = classify_ingest(result)
    if classification is None:
        raise AssertionError("the reading is not a failure")
    return system_observation_for(result, classification, name=name, observed_at=observed_at)


def metadata(observation: Observation) -> dict[str, str]:
    return dict(observation.source_metadata)


def prohibited(text: str) -> list[str]:
    """Name every code point diagnostic_text should have removed or mapped."""
    return [
        f"U+{ord(char):04X}"
        for char in text
        if prohibited_category(char) is not None and char not in "\t\n"
    ]


def ingest_bytes(
    name: str, content: bytes, *, limits: IngestLimits = DEFAULT_LIMITS
) -> IngestResult:
    """Write bytes to a temporary file and run them through the dispatcher."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / name
        path.write_bytes(content)
        return ingest_stig_artifact(path, ingested_at=NOW, limits=limits)


def ingest_json(name: str, payload: Any, *, limits: IngestLimits = DEFAULT_LIMITS) -> IngestResult:
    return ingest_bytes(name, json.dumps(payload).encode("utf-8"), limits=limits)


def checklist(
    *rules: Any, host: str = "host-a", stig: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build a CKLB with a host and a clock around one STIG entry of the given rules."""
    entry = {"stig_id": "SYN_STIG", "version": "1", "release_info": "R1"} if stig is None else stig
    return {
        "target_data": {"host_name": host},
        "completed_at": "2026-08-01T00:00:00Z",
        "stigs": [{**entry, "rules": list(rules)}],
    }


def hdf_document() -> dict[str, Any]:
    """Load the synthetic InSpec fixture, which imports cleanly, for a test to damage."""
    document: dict[str, Any] = json.loads(
        (FIXTURES / "inspec-linux-host.hdf.json").read_text(encoding="utf-8")
    )
    return document


def failed_log(invocations: list[dict[str, Any]], *, findings: int = 1) -> dict[str, Any]:
    """Build a SARIF log of one run with the given invocations and findings."""
    results = [make_result(line=line) for line in range(1, findings + 1)]
    return make_log(make_run(results, invocations=invocations))


def raw_order(item: IngestDiagnostic) -> tuple[str, str, str, str]:
    return (item.code, item.location or "", item.message, item.level.value)


class Unresolved(AssertionError):
    """A level, code, or source type the walk could not resolve to literal text."""


class ErrorSite(NamedTuple):
    module: str
    line: int
    function: str
    code: str


def callee(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def receiver(call: ast.Call) -> str:
    """Return the last name of the object a method is called on, such as diagnostics."""
    if not isinstance(call.func, ast.Attribute):
        return ""
    value = call.func.value
    if isinstance(value, ast.Attribute):
        return value.attr
    if isinstance(value, ast.Name):
        return value.id
    return ""


def keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def level_member(node: ast.expr) -> str | None:
    """Return X for a literal DiagnosticLevel.X, else None."""
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "DiagnosticLevel"
    ):
        return node.attr
    return None


class SourceWalk:
    """Resolve literal text passed through module constants and helper parameters.

    A Name is resolved as a parameter of its enclosing function by walking every call site
    of that function, or as a module-level string constant. Anything else raises Unresolved,
    so no site is ever skipped silently.
    """

    def __init__(self, sources: dict[str, str]) -> None:
        self.parents: dict[ast.AST, ast.AST] = {}
        self.module_of: dict[ast.AST, str] = {}
        self.constants: dict[str, set[str]] = {}
        self.functions: dict[str, list[ast.FunctionDef]] = {}
        self.calls: list[tuple[str, ast.Call]] = []
        for module, text in sorted(sources.items()):
            tree = ast.parse(text, filename=module)
            for node in ast.walk(tree):
                self.module_of[node] = module
                for child in ast.iter_child_nodes(node):
                    self.parents[child] = node
                if isinstance(node, ast.FunctionDef):
                    self.functions.setdefault(node.name, []).append(node)
                elif isinstance(node, ast.Call):
                    self.calls.append((module, node))
            for statement in tree.body:
                target: ast.expr | None = None
                if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                    target = statement.targets[0]
                elif isinstance(statement, ast.AnnAssign):
                    target = statement.target
                value = getattr(statement, "value", None)
                if (
                    isinstance(target, ast.Name)
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    self.constants.setdefault(target.id, set()).add(value.value)

    def enclosing(self, node: ast.AST) -> ast.FunctionDef | None:
        current = self.parents.get(node)
        while current is not None and not isinstance(current, ast.FunctionDef):
            current = self.parents.get(current)
        return current

    def resolve(self, node: ast.expr, depth: int = 0) -> set[str]:
        where = f"{self.module_of[node]}:{node.lineno} {ast.unparse(node)}"
        if depth > 8:
            raise Unresolved(f"{where}: helper chain too deep")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.Name):
            function = self.enclosing(node)
            if function is not None and node.id in self._parameters(function):
                return self._resolve_parameter(function, node.id, depth, where)
            if node.id in self.constants:
                return set(self.constants[node.id])
        raise Unresolved(f"{where}: not a literal, a module constant, or a helper parameter")

    @staticmethod
    def _parameters(function: ast.FunctionDef) -> list[str]:
        arguments = function.args
        return [item.arg for item in arguments.posonlyargs + arguments.args + arguments.kwonlyargs]

    def _resolve_parameter(
        self, function: ast.FunctionDef, name: str, depth: int, where: str
    ) -> set[str]:
        arguments = function.args
        positional = [item.arg for item in arguments.posonlyargs + arguments.args]
        sites = [call for _module, call in self.calls if callee(call) == function.name]
        if not sites:
            raise Unresolved(f"{where}: {function.name} has no call site")
        values: set[str] = set()
        for call in sites:
            argument = keyword(call, name)
            if argument is None and name in positional:
                index = positional.index(name)
                if isinstance(call.func, ast.Attribute) and positional[0] in {"self", "cls"}:
                    index -= 1
                if any(isinstance(item, ast.Starred) for item in call.args):
                    raise Unresolved(f"{where}: a call site passes *args")
                if index < len(call.args):
                    argument = call.args[index]
            if argument is None:
                argument = self._default(function, name)
            if argument is None:
                raise Unresolved(f"{where}: a call site at line {call.lineno} omits {name}")
            values |= self.resolve(argument, depth + 1)
        return values

    @staticmethod
    def _default(function: ast.FunctionDef, name: str) -> ast.expr | None:
        arguments = function.args
        positional = arguments.posonlyargs + arguments.args
        offset = len(positional) - len(arguments.defaults)
        for index, item in enumerate(positional):
            if item.arg == name and index >= offset:
                return arguments.defaults[index - offset]
        for item, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
            if item.arg == name:
                return default
        return None

    def error_sites(self) -> list[ErrorSite]:
        """Return every ERROR emission site with each literal code it can emit."""
        sites: list[ErrorSite] = []
        for module, call in self.calls:
            level = call.args[0] if call.args else keyword(call, "level")
            if level is None:
                continue
            function = self.enclosing(call)
            function_name = function.name if function is not None else "<module>"
            member = level_member(level)
            if member is None:
                emits = callee(call) == "IngestDiagnostic" or (
                    callee(call) == "add" and receiver(call) == "diagnostics"
                )
                if emits and (module, function_name) not in PASS_THROUGH_LEVELS:
                    raise Unresolved(
                        f"{module}:{call.lineno}: level {ast.unparse(level)} is not literal"
                    )
                continue
            if member != "ERROR":
                continue
            code = call.args[1] if len(call.args) > 1 else keyword(call, "code")
            if code is None:
                raise Unresolved(f"{module}:{call.lineno}: an ERROR with no code")
            for value in sorted(self.resolve(code)):
                sites.append(ErrorSite(module, call.lineno, function_name, value))
        return sites

    def source_types(self) -> tuple[set[str], set[str]]:
        """Return the source types artifact-bound builds use, and the modules that build SYSTEM.

        A call that passes origin=ObservationOrigin.SYSTEM is the only one the reserved prefix
        is allowed on, so it is reported by module rather than resolved.
        """
        values: set[str] = set()
        system_modules: set[str] = set()
        for module, call in self.calls:
            source_type = keyword(call, "source_type")
            if source_type is None:
                continue
            origin = keyword(call, "origin")
            if origin is not None and ast.unparse(origin) == "ObservationOrigin.SYSTEM":
                system_modules.add(module)
                continue
            values |= self.resolve(source_type)
        return values, system_modules


def adapter_walk() -> SourceWalk:
    """Walk every module of the adapter package that is imported by these tests."""
    return SourceWalk(
        {path.name: path.read_text(encoding="utf-8") for path in sorted(ADAPTERS.glob("*.py"))}
    )


def parse_error_sites() -> set[tuple[str, int]]:
    """Return every raise of AdapterParseError in the adapter package, by file and line."""
    sites: set[tuple[str, int]] = set()
    for path in sorted(ADAPTERS.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Raise) or node.exc is None:
                continue
            raised = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if isinstance(raised, ast.Name) and raised.id == "AdapterParseError":
                sites.add((path.name, node.lineno))
    return sites


class ParseErrorCase(NamedTuple):
    adapter: Callable[[], Any]
    document: ParsedDocument
    message: str
    # The dispatcher route that reaches the site, or None when only a direct parse can.
    file_name: str | None = None
    content: bytes = b""


CDX_INVENTORY = "CycloneDX inventory document cannot be read: "
# The members of an object-form metadata.tools, each checked to be an array (section 4.1).
TOOL_CONTAINERS = ("components", "services")
CDX_MALFORMED_INVENTORIES: tuple[tuple[dict[str, Any], str], ...] = (
    ({"metadata": "x"}, "metadata is not an object"),
    ({"metadata": {"tools": "trivy"}}, "metadata.tools is neither an array nor an object"),
    ({"metadata": {"tools": {"components": {}}}}, "metadata.tools.components is not an array"),
    ({"metadata": {"tools": {"services": "x"}}}, "metadata.tools.services is not an array"),
    ({"metadata": {"tools": ["trivy"]}}, "a tool is not an object"),
    ({"metadata": {"tools": [{"name": 7}]}}, "a tool name is not a string"),
    ({"metadata": {"component": []}}, "metadata.component is not an object"),
    (
        {"metadata": {"component": {"type": "container"}}},
        "a component name is missing or not a string",
    ),
    ({"components": {}}, "components is not an array"),
    ({"components": ["x"]}, "a component is not an object"),
    ({"components": [{"type": "library"}]}, "a component name is missing or not a string"),
    ({"components": [{"name": "a", "type": 1}]}, "a component type is not a string"),
    ({"components": [{"name": "a", "hashes": {}}]}, "a component hashes member is not an array"),
    ({"components": [{"name": "a", "hashes": ["x"]}]}, "a component hash is not an object"),
    (
        {"components": [{"name": "a", "components": {}}]},
        "a component components member is not an array",
    ),
    # A nested component with no name is refused like a top-level one (R-S2-3).
    (
        {"components": [{"name": "a", "components": [{"type": "library"}]}]},
        "a component name is missing or not a string",
    ),
    (
        {"metadata": {"component": {"name": "s", "components": [{"type": "library"}]}}},
        "a component name is missing or not a string",
    ),
)

CDX_IDENTITY = "CycloneDX inventory identity cannot be used as written: "
# One refused input per identity the adapter checks on K1 and K2, keyed by its name (CL-5).
CDX_REFUSED_IDENTITIES: tuple[tuple[dict[str, Any], str], ...] = (
    ({"tools": [{"name": "sy\u0000ft"}]}, "tool name contains prohibited code point U+0000"),
    (
        {"tools": [{"name": "a" * 300}, {"name": "b" * 300}]},
        "tool is 601 characters; maximum is 512",
    ),
    (
        {"component": {"type": "container", "name": "x" * 600}},
        "scope id is 600 characters; maximum is 512",
    ),
)


def _cdx_case(message: str, **members: Any) -> ParseErrorCase:
    """Build a CycloneDX 1.6 refusal case reachable under a .cdx.json name."""
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", **members}
    return ParseErrorCase(
        CycloneDxAdapter,
        ParsedDocument("json", document),
        message,
        "synthetic.cdx.json",
        json.dumps(document).encode("utf-8"),
    )


PARSE_ERROR_CASES = (
    ParseErrorCase(
        CklbAdapter,
        ParsedDocument("json", []),
        "CKLB root must be a JSON object",
        "synthetic.cklb",
        b"[]",
    ),
    ParseErrorCase(
        CklbAdapter,
        ParsedDocument("json", {}),
        "JSON has no non-empty 'stigs' array",
        "synthetic.cklb",
        b"{}",
    ),
    ParseErrorCase(CklAdapter, ParsedDocument("json", {}), "CKL adapter requires an XML document"),
    ParseErrorCase(
        CklAdapter,
        ParsedDocument("xml", ET.Element("synthetic")),
        "XML root 'synthetic' is not a CKL checklist",
        "synthetic.ckl",
        b"<synthetic/>",
    ),
    ParseErrorCase(
        XccdfAdapter, ParsedDocument("json", {}), "XCCDF adapter requires an XML document"
    ),
    ParseErrorCase(
        XccdfAdapter,
        ParsedDocument("xml", ET.Element("synthetic")),
        "XML root 'synthetic' is not XCCDF or ARF",
    ),
    ParseErrorCase(
        HdfAdapter,
        ParsedDocument("json", []),
        "HDF root must be a JSON object",
        "synthetic.hdf.json",
        b"[]",
    ),
    ParseErrorCase(
        HdfAdapter,
        ParsedDocument("json", {"stigs": []}),
        "HDF document carries a 'stigs' member; a STIG Viewer checklist is read under a .cklb "
        "or .json name",
        "synthetic.hdf.json",
        b'{"stigs": []}',
    ),
    ParseErrorCase(
        HdfAdapter,
        ParsedDocument("json", {"baselines": []}),
        "hdf-libs v3 'baselines' root is not supported",
        "synthetic.hdf.json",
        b'{"baselines": []}',
    ),
    ParseErrorCase(
        HdfAdapter,
        ParsedDocument("json", {"controls": []}),
        "'controls' root (json-min or profile export) is not supported",
        "synthetic.hdf.json",
        b'{"controls": []}',
    ),
    ParseErrorCase(
        HdfAdapter,
        ParsedDocument("json", {"profiles": []}),
        "HDF profiles must be a non-empty array",
        "synthetic.hdf.json",
        b'{"profiles": []}',
    ),
    ParseErrorCase(
        HdfAdapter,
        ParsedDocument("json", {"profiles": [{}], "version": "1"}),
        "HDF platform must be an object",
        "synthetic.hdf.json",
        b'{"profiles": [{}], "version": "1"}',
    ),
    ParseErrorCase(
        HdfAdapter,
        ParsedDocument("json", {"profiles": [{}], "platform": {}}),
        "HDF version must be a non-empty string",
        "synthetic.hdf.json",
        b'{"profiles": [{}], "platform": {}}',
    ),
    ParseErrorCase(
        SarifAdapter,
        ParsedDocument("json", []),
        "SARIF root must be a JSON object",
        "synthetic.sarif",
        b"[]",
    ),
    ParseErrorCase(
        SarifAdapter,
        ParsedDocument("json", {"version": "2.0.0"}),
        "SARIF version must be the string 2.1.0",
        "synthetic.sarif",
        b'{"version": "2.0.0"}',
    ),
    ParseErrorCase(
        SarifAdapter,
        ParsedDocument("json", {"version": "2.1.0", "runs": {}}),
        "SARIF runs must be an array",
        "synthetic.sarif",
        b'{"version": "2.1.0", "runs": {}}',
    ),
    ParseErrorCase(
        CycloneDxAdapter,
        ParsedDocument("json", []),
        "CycloneDX root must be a JSON object",
        "synthetic.cdx.json",
        b"[]",
    ),
    ParseErrorCase(
        CycloneDxAdapter,
        ParsedDocument("json", {"stigs": []}),
        "CycloneDX document carries a 'stigs' member; a STIG Viewer checklist is read under its "
        "own name",
        "synthetic.cdx.json",
        b'{"stigs": []}',
    ),
    ParseErrorCase(
        CycloneDxAdapter,
        ParsedDocument("json", {}),
        "JSON has no 'bomFormat' of 'CycloneDX'",
        "synthetic.cdx.json",
        b"{}",
    ),
    _cdx_case(
        "CycloneDX specVersion '1.3' is not supported; this build reads 1.4 to 1.7",
        specVersion="1.3",
    ),
    # A standalone VEX: every ref names the subject, the only component (A9, Decision N).
    _cdx_case(
        "a standalone CycloneDX VEX document cannot be resolved without the BOM it describes; "
        "ComplyRoll does not join artifacts; record its statements as evaluations",
        metadata={"component": {"type": "application", "name": "p", "bom-ref": "product-ABC"}},
        vulnerabilities=[{"id": "CVE-2021-44228", "affects": [{"ref": "product-ABC"}]}],
    ),
    *(
        _cdx_case("CycloneDX vulnerabilities is not an array", vulnerabilities=value)
        for value in (None, {}, "none")
    ),
    # Every structural check of a document with no vulnerability record, once as K1 and once
    # as K2 (A12).
    *(
        _cdx_case(CDX_INVENTORY + check, **members, **extra)
        for members, check in CDX_MALFORMED_INVENTORIES
        for extra in ({}, {"vulnerabilities": []})
    ),
    # Every identity input of a K1 or K2 document, once as K1 and once as K2 (A12, CL-5).
    *(
        _cdx_case(CDX_IDENTITY + check, metadata=metadata, **extra)
        for metadata, check in CDX_REFUSED_IDENTITIES
        for extra in ({}, {"vulnerabilities": []})
    ),
)

# *--- Classes ---*


class ClassificationTests(unittest.TestCase):
    def test_a_reading_without_an_error_or_a_failed_invocation_is_not_a_failure(self) -> None:
        self.assertIsNone(classify_ingest(reading()))
        self.assertIsNone(
            classify_ingest(
                reading(
                    warning("resource_identity_fallback"),
                    info("run_clean"),
                    observations=(artifact_observation(),),
                )
            )
        )

    def test_a_failed_invocation_without_an_error_is_an_execution_side_record(self) -> None:
        result = reading(
            warning(EXECUTION_UNSUCCESSFUL),
            observations=(artifact_observation(),),
            failed_execution_at=INVOKED,
        )
        self.assertEqual(
            classify_ingest(result),
            FailureClassification(
                EXECUTION, None, ("execution_unsuccessful",), side_record=True, clock=INVOKED
            ),
        )

    def test_a_failed_invocation_with_an_error_is_the_execution_class(self) -> None:
        result = reading(
            error("no_observations"), warning(EXECUTION_UNSUCCESSFUL), failed_execution_at=INVOKED
        )
        self.assertEqual(
            classify_ingest(result),
            FailureClassification(
                EXECUTION, None, ("execution_unsuccessful", "no_observations"), clock=INVOKED
            ),
        )

    def test_an_unparsable_reading_is_the_parse_class(self) -> None:
        self.assertEqual(
            classify_ingest(reading(error("artifact_parse_failed"))),
            FailureClassification(PARSE, None, ("artifact_parse_failed",)),
        )

    def test_each_content_code_is_the_content_class(self) -> None:
        for code in sorted(CONTENT_CODES):
            with self.subTest(code=code):
                result = reading(error(code), error("no_observations"))
                self.assertEqual(
                    classify_ingest(result),
                    FailureClassification(CONTENT, None, tuple(sorted({code, "no_observations"}))),
                )

    def test_a_sole_no_observations_is_the_content_class(self) -> None:
        self.assertEqual(
            classify_ingest(reading(error("no_observations"))),
            FailureClassification(CONTENT, None, ("no_observations",)),
        )

    def test_codes_are_the_sorted_distinct_error_codes_only(self) -> None:
        result = reading(
            error("no_observations"),
            error("invalid_rule", "stigs[0].rules[1]"),
            error("invalid_rule", "stigs[0].rules[0]"),
            warning("resource_identity_fallback"),
            info("results_collapsed"),
        )
        classification = classify_ingest(result)
        self.assertIsNotNone(classification)
        assert classification is not None
        self.assertEqual(classification.codes, ("invalid_rule", "no_observations"))

    def test_classification_never_reads_message_or_location_text(self) -> None:
        plain = reading(error("invalid_rule"))
        noisy = reading(
            IngestDiagnostic(
                ERROR,
                "invalid_rule",
                "execution_unsuccessful artifact_parse_failed run_clean",
                "unsupported_artifact",
            )
        )
        self.assertEqual(classify_ingest(noisy), classify_ingest(plain))


class PrecedenceTests(unittest.TestCase):
    def test_execution_takes_precedence_over_parse(self) -> None:
        result = reading(error("artifact_parse_failed"), warning(EXECUTION_UNSUCCESSFUL))
        self.assertEqual(
            classify_ingest(result),
            FailureClassification(
                EXECUTION, None, ("artifact_parse_failed", "execution_unsuccessful")
            ),
        )

    def test_execution_takes_precedence_over_content(self) -> None:
        result = reading(error("invalid_run"), warning(EXECUTION_UNSUCCESSFUL))
        self.assertEqual(
            classify_ingest(result),
            FailureClassification(EXECUTION, None, ("execution_unsuccessful", "invalid_run")),
        )

    def test_parse_takes_precedence_over_content(self) -> None:
        result = reading(error("invalid_rule"), error("artifact_parse_failed"))
        self.assertEqual(
            classify_ingest(result),
            FailureClassification(PARSE, None, ("artifact_parse_failed", "invalid_rule")),
        )

    def test_the_class_read_back_from_the_codes_is_the_class_minted(self) -> None:
        # A stored record keeps its class and its codes side by side, so the audit reads the
        # class back from the codes. Every class code alone, and every mix of one code of
        # each class, with and without a failed invocation, mints the class it names.
        mixes = [frozenset({code}) for code in sorted(CLASS_CODES)]
        mixes += [
            frozenset(pair)
            for pair in itertools.combinations(
                ("artifact_parse_failed", "invalid_rule", "no_observations"), 2
            )
        ]
        mixes.append(frozenset({"artifact_parse_failed", "invalid_rule", "no_observations"}))
        mixes.append(frozenset())
        checked = 0
        for errors in mixes:
            for executed in (False, True):
                diagnostics = [error(code) for code in sorted(errors)]
                if executed:
                    diagnostics.append(warning(EXECUTION_UNSUCCESSFUL))
                classification = classify_ingest(reading(*diagnostics))
                if classification is None or classification.failure_class is None:
                    continue
                with self.subTest(errors=sorted(errors), executed=executed):
                    self.assertIs(
                        failure_class_for_codes(classification.codes),
                        classification.failure_class,
                    )
                    checked += 1
        self.assertEqual(checked, 2 * (len(CLASS_CODES) + 4) + 1)
        # Codes that name no class are no minted reading's, so no class is read back.
        for codes in ((), ("artifact_read_failed",), tuple(sorted(UNMINTABLE_CODES))):
            with self.subTest(codes=codes):
                with self.assertRaises(ValueError):
                    failure_class_for_codes(codes)

    def test_a_partial_reading_takes_precedence_over_execution(self) -> None:
        result = reading(
            error("invalid_rule"),
            warning(EXECUTION_UNSUCCESSFUL),
            failed_execution_at=INVOKED,
            observations=(artifact_observation(),),
        )
        self.assertEqual(
            classify_ingest(result),
            FailureClassification.unmintable(UnmintableReason.PARTIAL_READING, ["invalid_rule"]),
        )

    def test_every_unmintable_reason_takes_precedence_over_execution(self) -> None:
        # Each reading also reports a failed invocation with its clock, which would make it
        # the execution class if no reason applied first.
        failed = (warning(EXECUTION_UNSUCCESSFUL),)
        cases = (
            (
                reading(error("artifact_parse_failed"), *failed, digestless=True),
                UnmintableReason.NO_DIGEST,
                "artifact_parse_failed",
            ),
            (
                reading(error("unsupported_artifact"), *failed),
                UnmintableReason.UNSUPPORTED,
                "unsupported_artifact",
            ),
            (
                reading(error("artifact_parse_failed"), *failed, format_rejected=True),
                UnmintableReason.FORMAT_REJECTED,
                "artifact_parse_failed",
            ),
            (
                reading(
                    error("duplicate_observation_identity"),
                    *failed,
                    observations=(artifact_observation(),),
                ),
                UnmintableReason.DUPLICATE_IDENTITY,
                "duplicate_observation_identity",
            ),
            (
                reading(error("invalid_rule"), *failed, observations=(artifact_observation(),)),
                UnmintableReason.PARTIAL_READING,
                "invalid_rule",
            ),
            (
                reading(error("invalid_result"), *failed, withheld=True),
                UnmintableReason.PARTIAL_READING,
                "invalid_result",
            ),
            (
                reading(error("synthetic_unknown"), *failed),
                UnmintableReason.UNKNOWN_CODE,
                "synthetic_unknown",
            ),
        )
        for result, reason, code in cases:
            with self.subTest(reason=reason.value, withheld=result.withheld):
                executed = replace(result, failed_execution_at=INVOKED)
                self.assertEqual(
                    classify_ingest(executed), FailureClassification.unmintable(reason, [code])
                )

    def test_a_sarif_log_withholding_findings_beside_a_failed_invocation_is_partial(
        self,
    ) -> None:
        invocation = {"executionSuccessful": False, "startTimeUtc": "2026-08-31T09:30:00Z"}
        log = make_log(make_run([make_result()], invocations=[invocation]), make_run([7]))
        result = ingest_json("synthetic.sarif", log)
        self.assertEqual(result.observations, ())
        self.assertTrue(result.withheld)
        self.assertEqual(result.failed_execution_at, INVOKED)
        self.assertEqual(
            classify_ingest(result),
            FailureClassification.unmintable(UnmintableReason.PARTIAL_READING, ["invalid_result"]),
        )


class UnmintableReasonTests(unittest.TestCase):
    def assert_refused(
        self, result: IngestResult, reason: UnmintableReason, codes: tuple[str, ...]
    ) -> None:
        classification = classify_ingest(result)
        self.assertEqual(classification, FailureClassification(None, reason, codes))
        assert classification is not None
        self.assertFalse(classification.mintable)

    def test_a_reading_without_an_artifact_has_no_digest(self) -> None:
        self.assert_refused(
            reading(error("artifact_read_failed"), digestless=True),
            UnmintableReason.NO_DIGEST,
            ("artifact_read_failed",),
        )
        self.assert_refused(
            reading(error("artifact_parse_failed"), digestless=True),
            UnmintableReason.NO_DIGEST,
            ("artifact_parse_failed",),
        )

    def test_an_unsupported_artifact_is_refused(self) -> None:
        self.assert_refused(
            reading(error("unsupported_artifact")),
            UnmintableReason.UNSUPPORTED,
            ("unsupported_artifact",),
        )

    def test_a_format_rejection_is_refused(self) -> None:
        self.assert_refused(
            reading(error("artifact_parse_failed"), format_rejected=True),
            UnmintableReason.FORMAT_REJECTED,
            ("artifact_parse_failed",),
        )

    def test_a_duplicate_identity_is_refused(self) -> None:
        self.assert_refused(
            reading(
                error("duplicate_observation_identity"), observations=(artifact_observation(),)
            ),
            UnmintableReason.DUPLICATE_IDENTITY,
            ("duplicate_observation_identity",),
        )

    def test_a_partial_reading_is_refused(self) -> None:
        self.assert_refused(
            reading(error("invalid_rule"), observations=(artifact_observation(),)),
            UnmintableReason.PARTIAL_READING,
            ("invalid_rule",),
        )

    def test_a_code_outside_every_class_is_refused(self) -> None:
        self.assert_refused(
            reading(error("synthetic_unknown"), error("invalid_rule")),
            UnmintableReason.UNKNOWN_CODE,
            ("invalid_rule", "synthetic_unknown"),
        )

    def test_an_unmintable_code_no_earlier_reason_names_is_an_unknown_code(self) -> None:
        for code in sorted(UNMINTABLE_CODES - {"unsupported_artifact"}):
            if code == "duplicate_observation_identity":
                continue
            with self.subTest(code=code):
                self.assert_refused(
                    reading(error(code), error("no_observations")),
                    UnmintableReason.UNKNOWN_CODE,
                    tuple(sorted({code, "no_observations"})),
                )

    # The clean_scan reason is retired (ADR 0015 decision 1): a clean SARIF run folds an
    # observation, so no adapter reading pairs no_observations with an INFO run_clean any more.
    # The classifier stays total over synthetic readings and reads codes alone: a run_clean
    # note at any level changes nothing.
    def test_a_run_clean_note_no_longer_names_a_reason(self) -> None:
        cases = {
            "info beside no_observations": (
                reading(error("no_observations"), info("run_clean")),
                FailureClassification(CONTENT, None, ("no_observations",)),
            ),
            "results unknown": (
                reading(error("no_observations"), info("run_clean"), warning("results_unknown")),
                FailureClassification(CONTENT, None, ("no_observations",)),
            ),
            "failed invocation": (
                reading(
                    error("no_observations"), info("run_clean"), warning(EXECUTION_UNSUCCESSFUL)
                ),
                FailureClassification(
                    EXECUTION, None, ("execution_unsuccessful", "no_observations")
                ),
            ),
            "another error": (
                reading(error("no_observations"), info("run_clean"), error("invalid_run")),
                FailureClassification(CONTENT, None, ("invalid_run", "no_observations")),
            ),
            "a warning, not an info": (
                reading(error("no_observations"), warning("run_clean")),
                FailureClassification(CONTENT, None, ("no_observations",)),
            ),
        }
        for label, (result, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(classify_ingest(result), expected)

    def test_reasons_apply_in_the_documented_order(self) -> None:
        duplicate = "duplicate_observation_identity"
        cases = (
            (
                "no_digest before unsupported",
                reading(error("unsupported_artifact"), digestless=True),
                UnmintableReason.NO_DIGEST,
            ),
            (
                "unsupported before format_rejected",
                reading(error("unsupported_artifact"), format_rejected=True),
                UnmintableReason.UNSUPPORTED,
            ),
            (
                "format_rejected before duplicate_identity",
                reading(error("artifact_parse_failed"), error(duplicate), format_rejected=True),
                UnmintableReason.FORMAT_REJECTED,
            ),
            (
                "duplicate_identity before partial_reading",
                reading(error(duplicate), observations=(artifact_observation(),)),
                UnmintableReason.DUPLICATE_IDENTITY,
            ),
            (
                "partial_reading before unknown_code",
                reading(error("synthetic_unknown"), observations=(artifact_observation(),)),
                UnmintableReason.PARTIAL_READING,
            ),
            (
                "unknown_code before any class",
                reading(error("no_observations"), error("cci_map_empty"), info("run_clean")),
                UnmintableReason.UNKNOWN_CODE,
            ),
        )
        for label, result, reason in cases:
            with self.subTest(label):
                classification = classify_ingest(result)
                assert classification is not None
                self.assertIs(classification.reason, reason)

    def test_read_elsewhere_is_assigned_by_the_caller_and_keeps_the_codes(self) -> None:
        for result in (
            reading(error("artifact_parse_failed")),
            reading(warning(EXECUTION_UNSUCCESSFUL), observations=(artifact_observation(),)),
        ):
            classification = classify_ingest(result)
            assert classification is not None
            self.assertIsNot(classification.reason, UnmintableReason.READ_ELSEWHERE)
            refused = classification.read_elsewhere()
            self.assertEqual(
                refused,
                FailureClassification(None, UnmintableReason.READ_ELSEWHERE, classification.codes),
            )
            self.assertFalse(refused.mintable)


class FailureClassificationTests(unittest.TestCase):
    def test_exactly_one_of_a_class_and_a_reason_is_named(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one"):
            FailureClassification(None, None, ())
        with self.assertRaisesRegex(ValueError, "exactly one"):
            FailureClassification(PARSE, UnmintableReason.NO_DIGEST, ())

    def test_the_class_and_the_reason_must_be_their_enums(self) -> None:
        with self.assertRaises(TypeError):
            FailureClassification("parse", None, ())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            FailureClassification(None, "no_digest", ())  # type: ignore[arg-type]

    def test_codes_are_a_sorted_distinct_tuple_of_text(self) -> None:
        with self.assertRaises(TypeError):
            FailureClassification(PARSE, None, ["artifact_parse_failed"])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            FailureClassification(PARSE, None, (1,))  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "sorted and distinct"):
            FailureClassification(CONTENT, None, ("no_observations", "invalid_rule"))
        with self.assertRaisesRegex(ValueError, "sorted and distinct"):
            FailureClassification(CONTENT, None, ("invalid_rule", "invalid_rule"))

    def test_only_an_execution_failure_is_a_side_record_or_carries_a_clock(self) -> None:
        with self.assertRaisesRegex(ValueError, "only an execution failure"):
            FailureClassification(PARSE, None, ("artifact_parse_failed",), side_record=True)
        with self.assertRaisesRegex(ValueError, "only an execution failure"):
            FailureClassification(CONTENT, None, ("no_observations",), clock=INVOKED)
        with self.assertRaisesRegex(ValueError, "only an execution failure"):
            FailureClassification(None, UnmintableReason.NO_DIGEST, (), clock=INVOKED)

    def test_an_execution_failure_names_execution_unsuccessful(self) -> None:
        with self.assertRaisesRegex(ValueError, "execution failure names execution_unsuccessful"):
            FailureClassification(EXECUTION, None, ("invalid_run",))
        with self.assertRaisesRegex(ValueError, "execution failure names execution_unsuccessful"):
            FailureClassification(EXECUTION, None, ("no_observations",), clock=INVOKED)
        accepted = FailureClassification(
            EXECUTION, None, (EXECUTION_UNSUCCESSFUL,), side_record=True, clock=INVOKED
        )
        self.assertTrue(accepted.side_record)

    def test_a_classification_carries_at_least_one_code(self) -> None:
        for failure_class, reason in (
            (EXECUTION, None),
            (PARSE, None),
            (CONTENT, None),
            (None, UnmintableReason.NO_DIGEST),
            (None, UnmintableReason.READ_ELSEWHERE),
        ):
            with self.subTest(failure_class=failure_class, reason=reason):
                with self.assertRaisesRegex(ValueError, "at least one code"):
                    FailureClassification(failure_class, reason, ())
        with self.assertRaisesRegex(ValueError, "at least one code"):
            FailureClassification.unmintable(UnmintableReason.UNKNOWN_CODE, [])

    def test_side_record_is_a_bool(self) -> None:
        for value in (1, "yes", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "side_record must be a bool"):
                    FailureClassification(
                        EXECUTION,
                        None,
                        (EXECUTION_UNSUCCESSFUL,),
                        side_record=value,  # type: ignore[arg-type]
                    )

    def test_a_clock_is_an_aware_datetime(self) -> None:
        with self.assertRaisesRegex(ValueError, "clock must carry a UTC offset"):
            FailureClassification(
                EXECUTION, None, (EXECUTION_UNSUCCESSFUL,), clock=INVOKED.replace(tzinfo=None)
            )
        with self.assertRaisesRegex(TypeError, "clock must be a datetime or None"):
            FailureClassification(
                EXECUTION,
                None,
                (EXECUTION_UNSUCCESSFUL,),
                clock="2026-08-31T09:30:00Z",  # type: ignore[arg-type]
            )
        offset = INVOKED.astimezone(timezone(timedelta(hours=-7)))
        self.assertEqual(
            FailureClassification(EXECUTION, None, (EXECUTION_UNSUCCESSFUL,), clock=offset).clock,
            offset,
        )

    def test_a_refusal_sorts_and_deduplicates_its_codes(self) -> None:
        refused = FailureClassification.unmintable(
            UnmintableReason.UNKNOWN_CODE, ["b_code", "a_code", "b_code"]
        )
        self.assertEqual(refused.codes, ("a_code", "b_code"))
        self.assertFalse(refused.mintable)
        self.assertTrue(FailureClassification(PARSE, None, ("artifact_parse_failed",)).mintable)


# *--- Dispatcher Readings ---*


class DispatcherClassificationTests(unittest.TestCase):
    def classify(self, result: IngestResult) -> FailureClassification:
        classification = classify_ingest(result)
        self.assertIsNotNone(classification)
        assert classification is not None
        return classification

    def test_unusable_checklist_rules_are_the_content_class(self) -> None:
        result = ingest_json(NAME, checklist(1, "rule"))
        self.assertEqual(
            self.classify(result),
            FailureClassification(CONTENT, None, ("invalid_rule", "no_observations")),
        )

    def test_a_ckl_without_vulnerabilities_is_the_content_class(self) -> None:
        result = ingest_bytes("synthetic.ckl", b"<CHECKLIST/>")
        self.assertEqual([item.code for item in result.errors], ["no_observations"])
        self.assertEqual(
            self.classify(result), FailureClassification(CONTENT, None, ("no_observations",))
        )

    def test_a_truncated_checklist_is_the_parse_class(self) -> None:
        result = ingest_bytes(NAME, b'{"stigs": [')
        self.assertEqual(
            self.classify(result), FailureClassification(PARSE, None, ("artifact_parse_failed",))
        )

    def test_a_missing_file_has_no_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = ingest_stig_artifact(Path(directory) / "absent.cklb", ingested_at=NOW)
        self.assertIs(self.classify(result).reason, UnmintableReason.NO_DIGEST)

    def test_an_unrecognized_name_is_unsupported(self) -> None:
        result = ingest_bytes("synthetic.txt", b"plain text")
        self.assertIs(self.classify(result).reason, UnmintableReason.UNSUPPORTED)

    def test_a_repeated_rule_is_a_duplicate_identity(self) -> None:
        result = ingest_json(NAME, checklist(GOOD_RULE, GOOD_RULE))
        self.assertTrue(result.observations)
        self.assertEqual(
            self.classify(result),
            FailureClassification(
                None, UnmintableReason.DUPLICATE_IDENTITY, ("duplicate_observation_identity",)
            ),
        )

    def test_a_checklist_with_one_usable_rule_is_a_partial_reading(self) -> None:
        result = ingest_json(NAME, checklist(GOOD_RULE, 1))
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(
            self.classify(result),
            FailureClassification(None, UnmintableReason.PARTIAL_READING, ("invalid_rule",)),
        )

    def test_a_sarif_log_with_one_unusable_result_is_a_partial_reading(self) -> None:
        log = make_log(make_run([make_result()]), make_run([7]))
        result = ingest_json("synthetic.sarif", log)
        self.assertEqual(result.observations, ())
        self.assertTrue(result.withheld)
        self.assertEqual(
            self.classify(result),
            FailureClassification(None, UnmintableReason.PARTIAL_READING, ("invalid_result",)),
        )

    def test_an_hdf_document_with_one_unusable_control_is_a_partial_reading(self) -> None:
        document = hdf_document()
        document["profiles"][0]["controls"].append(7)
        result = ingest_json("synthetic.hdf.json", document)
        self.assertEqual(result.observations, ())
        self.assertTrue(result.withheld)
        self.assertEqual(
            self.classify(result),
            FailureClassification(None, UnmintableReason.PARTIAL_READING, ("invalid_control",)),
        )

    def test_a_tool_less_matched_bom_is_the_content_class(self) -> None:
        # A vulnerability statement without a producer is not a detection (Decision I), and
        # the scope candidate is outside the folds, so nothing is withheld (A13).
        result = ingest_json(
            "synthetic.cdx.json",
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "a"}],
                "vulnerabilities": [{"id": "CVE-2026-0001"}],
            },
        )
        self.assertFalse(result.withheld)
        self.assertEqual(
            self.classify(result), FailureClassification(CONTENT, None, ("invalid_bom",))
        )

    def test_a_reading_with_nothing_to_withhold_is_not_withheld(self) -> None:
        unusable = hdf_document()
        unusable["profiles"][0]["controls"] = [7]
        cases = {
            "sarif without a usable result": ("synthetic.sarif", make_log(make_run([7]))),
            "hdf without a usable control": ("synthetic.hdf.json", unusable),
            "a successful sarif log": ("synthetic.sarif", make_log(make_run([make_result()]))),
            "a successful hdf document": ("synthetic.hdf.json", hdf_document()),
        }
        for label, (name, payload) in cases.items():
            with self.subTest(label):
                result = ingest_json(name, payload)
                self.assertFalse(result.withheld)
                if result.errors:
                    self.assertIsNot(self.classify(result).reason, UnmintableReason.PARTIAL_READING)

    def test_an_empty_container_array_is_rejected_only_where_the_adapter_requires_it(self) -> None:
        no_profiles = hdf_document()
        no_profiles["profiles"] = []
        no_controls = hdf_document()
        for profile in no_controls["profiles"]:
            profile["controls"] = []
        content = FailureClassification(CONTENT, None, ("no_observations",))
        cases = {
            "hdf with no profiles": ("synthetic.hdf.json", no_profiles, None),
            "hdf profiles with no controls": ("synthetic.hdf.json", no_controls, content),
            "sarif with no runs": ("synthetic.sarif", make_log(), content),
        }
        for label, (name, payload, expected) in cases.items():
            with self.subTest(label):
                result = ingest_json(name, payload)
                self.assertIs(result.format_rejected, expected is None)
                if expected is None:
                    self.assertIs(self.classify(result).reason, UnmintableReason.FORMAT_REJECTED)
                else:
                    self.assertEqual(self.classify(result), expected)

    # A clean SARIF run is a PASS observation of its scope (ADR 0015 decision 1), so the
    # reading succeeds and there is no failure to classify.
    def test_a_clean_sarif_run_is_a_successful_reading(self) -> None:
        result = ingest_json("synthetic.sarif", make_log(make_run([])))
        self.assertTrue(result.successful)
        self.assertEqual([item.source_record_id for item in result.observations], ["sarif.run"])
        self.assertIsNone(classify_ingest(result))

    def test_a_clean_run_beside_a_run_without_results_is_a_successful_reading(self) -> None:
        unknown = make_run([])
        del unknown["results"]
        result = ingest_json("synthetic.sarif", make_log(make_run([]), unknown))
        self.assertIn("results_unknown", [item.code for item in result.diagnostics])
        self.assertTrue(result.successful)
        self.assertIsNone(classify_ingest(result))

    def test_a_clean_run_beside_a_refused_run_is_a_partial_reading(self) -> None:
        # The clean run's observation is withheld by the other run's ERROR, exactly as a
        # finding would be, so the reading is refused rather than minted beside it.
        invalid = make_run([])
        invalid["results"] = "none"
        result = ingest_json("synthetic.sarif", make_log(make_run([]), invalid))
        self.assertTrue(result.withheld)
        self.assertEqual(
            self.classify(result),
            FailureClassification(None, UnmintableReason.PARTIAL_READING, ("invalid_run",)),
        )

    def test_a_clean_run_with_a_failed_invocation_is_the_execution_class(self) -> None:
        run = make_run([], invocations=[{"executionSuccessful": False}])
        result = ingest_json("synthetic.sarif", make_log(run))
        self.assertEqual(
            self.classify(result),
            FailureClassification(EXECUTION, None, ("execution_unsuccessful", "no_observations")),
        )

    def test_a_clean_run_under_an_unverified_invocation_is_the_content_class(self) -> None:
        # The invocation declares neither success nor failure, so the run is not failed and
        # its empty results claim nothing: the log held no usable content (ADR 0015).
        run = make_run([], invocations=[{"startTimeUtc": "2026-09-01T00:00:00Z"}])
        result = ingest_json("synthetic.sarif", make_log(run))
        self.assertEqual(
            [item.code for item in result.diagnostics],
            ["run_clean", "execution_unverified", "no_observations", "clean_run_unverified"],
        )
        self.assertIsNone(result.failed_execution_at)
        self.assertEqual(
            self.classify(result),
            FailureClassification(CONTENT, None, ("clean_run_unverified", "no_observations")),
        )

    def test_the_recorded_unverified_failure_names_its_cause(self) -> None:
        # The failure record keeps codes, not messages, so the code is what names the cause.
        run = make_run([], invocations=[{}])
        record = mint(ingest_json("synthetic.sarif", make_log(run)), name="synthetic.sarif")
        self.assertEqual(metadata(record)["failure.class"], "content")
        self.assertEqual(
            json.loads(metadata(record)["failure.codes"]),
            ["clean_run_unverified", "no_observations"],
        )

    def test_the_recorded_failed_invocation_does_not_name_the_unverified_cause(self) -> None:
        run = make_run([], invocations=[{"executionSuccessful": False}])
        record = mint(ingest_json("synthetic.sarif", make_log(run)), name="synthetic.sarif")
        self.assertEqual(metadata(record)["failure.class"], "execution")
        self.assertEqual(
            json.loads(metadata(record)["failure.codes"]),
            ["execution_unsuccessful", "no_observations"],
        )

    def test_a_failed_invocation_beside_an_unverified_empty_run_names_both(self) -> None:
        # The failed invocation decides the class; the other run's cause stays in the codes.
        failed = make_run([], invocations=[{"executionSuccessful": False}])
        unverified = make_run([], driver="Other", invocations=[{}])
        result = ingest_json("synthetic.sarif", make_log(failed, unverified))
        self.assertEqual(
            self.classify(result),
            FailureClassification(
                EXECUTION,
                None,
                ("clean_run_unverified", "execution_unsuccessful", "no_observations"),
            ),
        )

    def test_a_productive_run_beside_an_unverified_empty_run_is_a_successful_reading(
        self,
    ) -> None:
        run = make_run([], invocations=[{}])
        result = ingest_json("synthetic.sarif", make_log(run, make_run([make_result()])))
        self.assertTrue(result.successful)
        self.assertIn("execution_unverified", [item.code for item in result.diagnostics])
        self.assertIsNone(classify_ingest(result))


# *--- Structured Fields ---*


class StructuredFieldTests(unittest.TestCase):
    def assert_parse_failure(self, result: IngestResult, *, rejected: bool) -> None:
        self.assertIsNotNone(result.artifact)
        self.assertEqual([item.code for item in result.errors], ["artifact_parse_failed"])
        self.assertIs(result.format_rejected, rejected)
        self.assertIsNone(result.failed_execution_at)
        classification = classify_ingest(result)
        assert classification is not None
        if rejected:
            self.assertIs(classification.reason, UnmintableReason.FORMAT_REJECTED)
        else:
            self.assertIs(classification.failure_class, PARSE)

    def test_every_parse_error_site_is_a_case(self) -> None:
        raised: set[tuple[str, int]] = set()
        for case in PARSE_ERROR_CASES:
            with self.subTest(message=case.message):
                # assertRaises drops the traceback, and the raise site is what is counted.
                try:
                    case.adapter().parse(case.document, PROVENANCE, ingested_at=NOW)
                except AdapterParseError as exception:
                    self.assertEqual(str(exception), case.message)
                    frame = traceback.extract_tb(exception.__traceback__)[-1]
                    raised.add((Path(frame.filename).name, frame.lineno))
                else:
                    self.fail("no AdapterParseError was raised")
        self.assertEqual(raised, parse_error_sites())

    # The two CycloneDX helpers are one raise site each, so the site gate above cannot see a
    # dropped check; this one counts the checks themselves, once as K1 and once as K2 (A12).
    def test_every_cyclonedx_inventory_check_is_a_case_as_k1_and_k2(self) -> None:
        tree = ast.parse((ADAPTERS / "cyclonedx.py").read_text(encoding="utf-8"))
        texts: set[str] = set()
        patterns: set[str] = set()
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"_bom_error", "_component_error"}
            ):
                continue
            check = node.args[0]
            if isinstance(check, ast.Constant) and isinstance(check.value, str):
                texts.add(check.value)
            else:
                assert isinstance(check, ast.JoinedStr)
                patterns.add(
                    "".join(
                        re.escape(part.value) if isinstance(part, ast.Constant) else "[a-z.]+"
                        for part in check.values
                    )
                )
        cases: dict[str, set[str]] = {"K1": set(), "K2": set()}
        for case in PARSE_ERROR_CASES:
            value = case.document.value
            if case.adapter is not CycloneDxAdapter or not case.message.startswith(CDX_INVENTORY):
                continue
            kind = "K2" if isinstance(value, dict) and "vulnerabilities" in value else "K1"
            cases[kind].add(case.message.removeprefix(CDX_INVENTORY))
        self.assertEqual(cases["K1"], cases["K2"])
        expanded: set[str] = set()
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                matched = {text for text in cases["K1"] - texts if re.fullmatch(pattern, text)}
                # The f-string is the tool container check, met once per container member.
                self.assertEqual(
                    matched,
                    {f"metadata.tools.{member} is not an array" for member in TOOL_CONTAINERS},
                )
                expanded |= matched
        self.assertEqual(cases["K1"], texts | expanded)

    # Each _identity call names its input; each name is refused as K1 and as K2 (CL-5).
    def test_every_cyclonedx_inventory_identity_is_a_case_as_k1_and_k2(self) -> None:
        tree = ast.parse((ADAPTERS / "cyclonedx.py").read_text(encoding="utf-8"))
        names = {
            node.args[1].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_identity"
            and isinstance(node.args[1], ast.Constant)
        }
        cases: dict[str, set[str]] = {"K1": set(), "K2": set()}
        for case in PARSE_ERROR_CASES:
            value = case.document.value
            if case.adapter is not CycloneDxAdapter or not case.message.startswith(CDX_IDENTITY):
                continue
            kind = "K2" if "vulnerabilities" in value else "K1"
            check = case.message.removeprefix(CDX_IDENTITY)
            # The longest name that leads the check, so "tool name" is never read as "tool".
            cases[kind].add(max((n for n in names if check.startswith(n + " ")), key=len))
        self.assertEqual(names, {"tool name", "tool", "scope id"})
        self.assertEqual(cases["K1"], names)
        self.assertEqual(cases["K2"], names)

    # One check text is met on four roads into the walk, so the text gate cannot see a road
    # dropped: the subject, the component list and a child of each are each a case (D1, R-S2-3).
    def test_every_road_into_the_component_name_check_is_a_case(self) -> None:
        roads: set[tuple[str, bool]] = set()
        for case in PARSE_ERROR_CASES:
            value = case.document.value
            if case.message != CDX_INVENTORY + "a component name is missing or not a string":
                continue
            if "component" in value.get("metadata", {}):
                road, holder = "subject", value["metadata"]["component"]
            else:
                road, holder = "components", value["components"][0]
            # A holder that has its name refuses a child, so the case is the nested road.
            if isinstance(holder.get("name"), str):
                road += " nested"
            roads.add((road, "vulnerabilities" in value))
        expected = ("subject", "subject nested", "components", "components nested")
        self.assertEqual(roads, {(road, k2) for road in expected for k2 in (False, True)})

    def test_every_non_list_vulnerabilities_shape_is_a_case(self) -> None:
        shapes = {
            type(case.document.value["vulnerabilities"]).__name__
            for case in PARSE_ERROR_CASES
            if case.message == "CycloneDX vulnerabilities is not an array"
        }
        self.assertEqual(shapes, {"NoneType", "dict", "str"})

    def test_each_reachable_parse_error_is_a_format_rejection(self) -> None:
        for case in PARSE_ERROR_CASES:
            if case.file_name is None:
                continue
            with self.subTest(message=case.message):
                result = ingest_bytes(case.file_name, case.content)
                self.assert_parse_failure(result, rejected=True)
                self.assertEqual(result.errors[0].message, case.message)

    def test_a_non_xml_document_is_a_format_rejection_of_each_xml_adapter(self) -> None:
        routes = (
            ("synthetic.ckl", "not an element", "CKL adapter requires an XML document"),
            (
                "synthetic.xml",
                SimpleNamespace(tag="Benchmark"),
                "XCCDF adapter requires an XML document",
            ),
        )
        for name, document, message in routes:
            with self.subTest(name=name):
                with mock.patch.object(stig_module, "parse_xml_bounded", return_value=document):
                    result = ingest_bytes(name, b"<synthetic/>")
                self.assert_parse_failure(result, rejected=True)
                self.assertEqual(result.errors[0].message, message)

    def test_only_an_adapter_parse_error_is_a_format_rejection(self) -> None:
        routes: tuple[tuple[type[Any], str, bytes], ...] = (
            (CklbAdapter, NAME, b"{}"),
            (CklAdapter, "synthetic.ckl", b"<CHECKLIST/>"),
            (XccdfAdapter, "synthetic.xml", b"<Benchmark/>"),
            (SarifAdapter, "synthetic.sarif", b"{}"),
            (HdfAdapter, "synthetic.hdf.json", b"{}"),
            (CycloneDxAdapter, "synthetic.cdx.json", b"{}"),
        )
        raised: tuple[tuple[Exception, bool], ...] = (
            (AdapterParseError("synthetic refusal"), True),
            (InputLimitError("synthetic bound"), False),
            (UnsafeXmlError("synthetic declaration"), False),
            (ValueError("synthetic value"), False),
            (TypeError("synthetic type"), False),
        )
        for adapter, name, content in routes:
            for exception, rejected in raised:
                with self.subTest(adapter=adapter.__name__, raised=type(exception).__name__):
                    with mock.patch.object(adapter, "parse", side_effect=exception):
                        result = ingest_bytes(name, content)
                    self.assertEqual(result.artifact.parser_name, adapter.name)  # type: ignore[union-attr]
                    self.assert_parse_failure(result, rejected=rejected)

    def test_a_truncated_file_is_not_a_format_rejection(self) -> None:
        truncated = {
            NAME: b'{"stigs": [',
            "synthetic.json": b'{"profiles": [',
            "synthetic.ckl": b"<CHECKLIST><ASSET>",
            "synthetic.xml": b"<Benchmark><TestResult>",
            "synthetic.sarif": b'{"version": "2.1.0", "runs": [',
            "synthetic.hdf.json": b'{"profiles": [',
        }
        for name, content in truncated.items():
            with self.subTest(name=name):
                self.assert_parse_failure(ingest_bytes(name, content), rejected=False)

    def test_an_input_limit_is_not_a_format_rejection(self) -> None:
        profiles = {"profiles": [{}] * 65, "platform": {}, "version": "1"}
        two_results = failed_log([], findings=2)
        cases = {
            "an HDF profile bound inside the adapter": (
                "synthetic.hdf.json",
                profiles,
                DEFAULT_LIMITS,
                "HDF document lists 65 profiles; maximum is 64",
            ),
            "a SARIF result bound inside the adapter": (
                "synthetic.sarif",
                two_results,
                IngestLimits(max_results_per_run=1),
                "runs[0] contains 2 results; maximum is 1",
            ),
            "a JSON depth bound before the adapter": (
                NAME,
                {"stigs": [[[[1]]]]},
                IngestLimits(max_json_depth=2),
                "JSON nesting exceeds 2 levels",
            ),
        }
        for label, (name, payload, limits, message) in cases.items():
            with self.subTest(label):
                result = ingest_json(name, payload, limits=limits)
                self.assert_parse_failure(result, rejected=False)
                self.assertEqual(result.errors[0].message, message)

    def test_an_artifact_over_the_byte_bound_has_no_digest(self) -> None:
        result = ingest_json(NAME, checklist(GOOD_RULE), limits=IngestLimits(max_artifact_bytes=8))
        self.assertIsNone(result.artifact)
        self.assertFalse(result.format_rejected)
        classification = classify_ingest(result)
        assert classification is not None
        self.assertIs(classification.reason, UnmintableReason.NO_DIGEST)

    def test_unsafe_xml_is_not_a_format_rejection(self) -> None:
        declaration = b'<?xml version="1.0"?><!DOCTYPE CHECKLIST [<!ENTITY a "b">]>'
        for name, root in (("synthetic.ckl", b"<CHECKLIST/>"), ("synthetic.xml", b"<Benchmark/>")):
            with self.subTest(name=name):
                self.assert_parse_failure(ingest_bytes(name, declaration + root), rejected=False)

    def test_an_xccdf_benchmark_without_a_test_result_is_a_format_rejection(self) -> None:
        result = ingest_bytes("synthetic.xml", b'<Benchmark id="xccdf_synthetic_benchmark"/>')
        self.assertTrue(result.format_rejected)
        self.assertEqual([item.code for item in result.errors], ["no_observations"])
        self.assertEqual(
            classify_ingest(result),
            FailureClassification(None, UnmintableReason.FORMAT_REJECTED, ("no_observations",)),
        )

    def test_an_xccdf_test_result_without_rule_results_is_not_a_format_rejection(self) -> None:
        result = ingest_bytes(
            "synthetic.xml", b'<Benchmark id="b"><TestResult id="t"/></Benchmark>'
        )
        self.assertFalse(result.format_rejected)
        self.assertEqual(
            classify_ingest(result), FailureClassification(CONTENT, None, ("no_observations",))
        )

    def test_a_benchmark_with_stray_rule_results_still_imports(self) -> None:
        result = ingest_bytes(
            "synthetic.xml",
            b'<Benchmark id="b"><rule-result idref="xccdf_synthetic_rule_1">'
            b"<result>fail</result></rule-result></Benchmark>",
        )
        self.assertTrue(result.format_rejected)
        self.assertTrue(result.successful)
        self.assertIsNone(classify_ingest(result))

    def test_a_successful_reading_sets_neither_field(self) -> None:
        for name, payload in ((NAME, checklist(GOOD_RULE)), ("synthetic.sarif", failed_log([]))):
            with self.subTest(name=name):
                result = ingest_json(name, payload)
                self.assertTrue(result.successful)
                self.assertFalse(result.format_rejected)
                self.assertIsNone(result.failed_execution_at)
                self.assertIsNone(classify_ingest(result))

    def test_neither_field_reaches_the_serialized_reading(self) -> None:
        plain = reading(error("artifact_parse_failed"))
        flagged = replace(plain, format_rejected=True, failed_execution_at=INVOKED)
        self.assertEqual(flagged.to_dict(), plain.to_dict())
        self.assertEqual(
            set(flagged.to_dict()), {"successful", "artifact", "diagnostics", "observations"}
        )
        self.assertEqual(flagged.to_canonical_json(), plain.to_canonical_json())


# *--- Failed Invocation Clock ---*


class FailedInvocationClockTests(unittest.TestCase):
    def ingest(self, invocations: list[dict[str, Any]]) -> IngestResult:
        return ingest_json("synthetic.sarif", failed_log(invocations))

    def test_a_failed_invocation_start_is_the_clock(self) -> None:
        result = self.ingest(
            [
                {
                    "executionSuccessful": False,
                    "startTimeUtc": "2026-08-31T09:30:00Z",
                    "endTimeUtc": "2026-08-31T10:45:00Z",
                }
            ]
        )
        self.assertTrue(result.observations)
        self.assertEqual(result.failed_execution_at, INVOKED)
        self.assertEqual(
            classify_ingest(result),
            FailureClassification(
                EXECUTION, None, ("execution_unsuccessful",), side_record=True, clock=INVOKED
            ),
        )

    def test_a_failed_invocation_end_is_the_clock_when_it_declares_no_start(self) -> None:
        result = self.ingest([{"executionSuccessful": False, "endTimeUtc": "2026-08-31T09:30:00Z"}])
        self.assertEqual(result.failed_execution_at, INVOKED)

    def test_a_failed_invocation_without_clocks_leaves_the_record_as_of(self) -> None:
        result = self.ingest([{"executionSuccessful": False}])
        self.assertIsNone(result.failed_execution_at)
        record = mint(result)
        self.assertEqual(record.observed_at, AS_OF)
        self.assertEqual(metadata(record)["failure.clock"], "as-of")

    def test_the_earliest_failed_start_wins_over_ends_and_successful_invocations(self) -> None:
        result = self.ingest(
            [
                {"executionSuccessful": True, "startTimeUtc": "2026-08-31T08:00:00Z"},
                {"executionSuccessful": False, "startTimeUtc": "2026-08-31T12:00:00Z"},
                {
                    "executionSuccessful": False,
                    "startTimeUtc": "2026-08-31T09:30:00Z",
                    "endTimeUtc": "2026-08-31T09:45:00Z",
                },
                {"executionSuccessful": False, "endTimeUtc": "2026-08-31T07:00:00Z"},
            ]
        )
        self.assertEqual(result.failed_execution_at, INVOKED)

    def test_the_earliest_failed_end_wins_when_no_failed_start_is_declared(self) -> None:
        result = self.ingest(
            [
                {"executionSuccessful": True, "startTimeUtc": "2026-08-31T08:00:00Z"},
                {"executionSuccessful": False, "endTimeUtc": "2026-08-31T12:00:00Z"},
                {"executionSuccessful": False, "endTimeUtc": "2026-08-31T09:30:00Z"},
            ]
        )
        self.assertEqual(result.failed_execution_at, INVOKED)

    def test_the_earliest_failed_start_across_runs_wins(self) -> None:
        late = make_run(
            [make_result()],
            invocations=[{"executionSuccessful": False, "startTimeUtc": "2026-08-31T11:00:00Z"}],
        )
        early = make_run(
            [make_result(line=2)],
            invocations=[{"executionSuccessful": False, "startTimeUtc": "2026-08-31T09:30:00Z"}],
        )
        result = ingest_json("synthetic.sarif", make_log(late, early))
        self.assertEqual(result.failed_execution_at, INVOKED)

    def test_the_clock_is_kept_when_the_log_fails_closed(self) -> None:
        run = make_run(
            invocations=[{"executionSuccessful": False, "startTimeUtc": "2026-08-31T09:30:00Z"}]
        )
        run["results"] = {}
        result = ingest_json("synthetic.sarif", make_log(run))
        self.assertFalse(result.observations)
        self.assertEqual(result.failed_execution_at, INVOKED)
        self.assertEqual(
            classify_ingest(result),
            FailureClassification(
                EXECUTION,
                None,
                ("execution_unsuccessful", "invalid_run", "no_observations"),
                clock=INVOKED,
            ),
        )

    def test_the_clock_is_kept_when_the_run_identity_is_refused(self) -> None:
        for refused in ("scan/\u200b", "scan/\u0007"):
            with self.subTest(automation_id=refused):
                run = make_run(
                    [],
                    invocations=[
                        {"executionSuccessful": False, "startTimeUtc": "2026-08-31T09:30:00Z"}
                    ],
                    automationDetails={"id": refused},
                )
                result = ingest_json("synthetic.sarif", make_log(run))
                self.assertIn("identity_input_invalid", [item.code for item in result.errors])
                self.assertEqual(result.failed_execution_at, INVOKED)
                classification = classify_ingest(result)
                self.assertEqual(
                    classification,
                    FailureClassification(
                        EXECUTION,
                        None,
                        ("execution_unsuccessful", "identity_input_invalid", "no_observations"),
                        clock=INVOKED,
                    ),
                )
                self.assertEqual(mint(result).observed_at, INVOKED)

    def test_the_clock_is_kept_when_the_run_driver_is_refused(self) -> None:
        # The invocations are read before the driver check, so a run with no usable driver
        # keeps its failed invocation's clock and class, as a run refused later does.
        invalid, refused = "invalid_run", "identity_input_invalid"
        shapes: dict[str, tuple[dict[str, Any] | None, str]] = {
            "no tool": (None, invalid),
            "no driver": ({}, invalid),
            "driver not an object": ({"driver": "Synth"}, invalid),
            "no driver name": ({"driver": {"version": "1"}}, invalid),
            "blank driver name": ({"driver": {"name": ""}}, invalid),
            "driver name not a string": ({"driver": {"name": 5}}, invalid),
            "zero-width driver name": ({"driver": {"name": "Synth\u200b"}}, refused),
            "control driver name": ({"driver": {"name": "Synth\u0007"}}, refused),
        }
        for shape, (tool, code) in shapes.items():
            with self.subTest(shape=shape):
                run = make_run(
                    [],
                    invocations=[
                        {"executionSuccessful": False, "startTimeUtc": "2026-08-31T09:30:00Z"}
                    ],
                )
                if tool is None:
                    del run["tool"]
                else:
                    run["tool"] = tool
                result = ingest_json("synthetic.sarif", make_log(run))
                self.assertIn(code, [item.code for item in result.errors])
                self.assertEqual(result.failed_execution_at, INVOKED)
                self.assertEqual(
                    classify_ingest(result),
                    FailureClassification(
                        EXECUTION,
                        None,
                        ("execution_unsuccessful", code, "no_observations"),
                        clock=INVOKED,
                    ),
                )
                self.assertEqual(mint(result).observed_at, INVOKED)

    def test_an_earlier_failure_in_a_driverless_run_sets_the_clock(self) -> None:
        # The clock is the earliest failed invocation across the log's runs, so a driverless
        # run's earlier failure wins over a later one in a run with a usable driver.
        later = make_run(
            [],
            invocations=[{"executionSuccessful": False, "startTimeUtc": "2026-08-31T11:00:00Z"}],
        )
        driverless = make_run(
            [],
            invocations=[{"executionSuccessful": False, "startTimeUtc": "2026-08-31T09:30:00Z"}],
        )
        del driverless["tool"]
        result = ingest_json("synthetic.sarif", make_log(later, driverless))
        self.assertIn("invalid_run", [item.code for item in result.errors])
        self.assertEqual(result.failed_execution_at, INVOKED)
        classification = classify_ingest(result)
        assert classification is not None
        self.assertIs(classification.failure_class, EXECUTION)
        self.assertEqual(classification.clock, INVOKED)
        self.assertEqual(mint(result).observed_at, INVOKED)

    def test_the_end_clock_is_kept_when_the_run_driver_is_refused(self) -> None:
        # A failed invocation that declares only its end keeps that end as the clock when
        # its run is refused at the driver, as a declared start is kept.
        invalid, refused = "invalid_run", "identity_input_invalid"
        shapes: dict[str, tuple[dict[str, Any] | None, str]] = {
            "no tool": (None, invalid),
            "blank driver name": ({"driver": {"name": ""}}, invalid),
            "zero-width driver name": ({"driver": {"name": "Synth\u200b"}}, refused),
            "control driver name": ({"driver": {"name": "Synth\u0007"}}, refused),
        }
        for shape, (tool, code) in shapes.items():
            with self.subTest(shape=shape):
                run = make_run(
                    [],
                    invocations=[
                        {"executionSuccessful": False, "endTimeUtc": "2026-08-31T09:30:00Z"}
                    ],
                )
                if tool is None:
                    del run["tool"]
                else:
                    run["tool"] = tool
                result = ingest_json("synthetic.sarif", make_log(run))
                self.assertIn(code, [item.code for item in result.errors])
                self.assertEqual(result.failed_execution_at, INVOKED)
                self.assertEqual(
                    classify_ingest(result),
                    FailureClassification(
                        EXECUTION,
                        None,
                        ("execution_unsuccessful", code, "no_observations"),
                        clock=INVOKED,
                    ),
                )
                self.assertEqual(mint(result).observed_at, INVOKED)

    def test_an_earlier_failed_end_in_a_driverless_run_sets_the_clock(self) -> None:
        # With no usable failed start in the log, the earliest failed end across its runs is
        # the clock, so a driverless run's earlier end wins over a later one in a run with a
        # usable driver, in either run order. The later run's failed start is unusable.
        later = make_run(
            [],
            invocations=[
                {
                    "executionSuccessful": False,
                    "startTimeUtc": "not a clock",
                    "endTimeUtc": "2026-08-31T11:00:00Z",
                }
            ],
        )
        driverless = make_run(
            [],
            invocations=[{"executionSuccessful": False, "endTimeUtc": "2026-08-31T09:30:00Z"}],
        )
        del driverless["tool"]
        orders = {"driverless last": (later, driverless), "driverless first": (driverless, later)}
        for order, runs in orders.items():
            with self.subTest(order=order):
                result = ingest_json("synthetic.sarif", make_log(*runs))
                codes = [item.code for item in result.diagnostics]
                self.assertIn("invalid_run", codes)
                self.assertIn("source_timestamp_invalid", codes)
                self.assertEqual(result.failed_execution_at, INVOKED)
                classification = classify_ingest(result)
                assert classification is not None
                self.assertIs(classification.failure_class, EXECUTION)
                self.assertEqual(classification.clock, INVOKED)
                self.assertEqual(mint(result).observed_at, INVOKED)

    def test_external_properties_are_named_before_the_failed_invocations(self) -> None:
        # Both are read before the driver check, in the order they were read before it.
        run = make_run(
            [],
            invocations=[{"executionSuccessful": False, "startTimeUtc": "2026-08-31T09:30:00Z"}],
            externalPropertyFileReferences={"results": [{"location": {"uri": "r.sarif"}}]},
        )
        result = ingest_json("synthetic.sarif", make_log(run))
        self.assertEqual(
            [
                item.code
                for item in result.diagnostics
                if item.code in {"external_properties_ignored", EXECUTION_UNSUCCESSFUL}
            ],
            ["external_properties_ignored", EXECUTION_UNSUCCESSFUL],
        )

    def test_a_run_refused_at_its_driver_names_its_external_properties(self) -> None:
        # The warning is read before the driver check too, so a refused run reports it ahead of
        # its failed invocations, and reports it when it declares no invocations at all.
        failed = [{"executionSuccessful": False, "startTimeUtc": "2026-08-31T09:30:00Z"}]
        shapes: dict[str, dict[str, Any] | None] = {
            "no tool": None,
            "driver not an object": {"driver": "Synth"},
            "blank driver name": {"driver": {"name": ""}},
            "zero-width driver name": {"driver": {"name": "Synth\u200b"}},
        }
        for shape, tool in shapes.items():
            for invocations in (failed, []):
                with self.subTest(shape=shape, invocations=len(invocations)):
                    run = make_run([], invocations=invocations, externalPropertyFileReferences={})
                    if tool is None:
                        del run["tool"]
                    else:
                        run["tool"] = tool
                    result = ingest_json("synthetic.sarif", make_log(run))
                    expected = ["external_properties_ignored"]
                    if invocations:
                        expected.append(EXECUTION_UNSUCCESSFUL)
                    self.assertEqual(
                        [
                            item.code
                            for item in result.diagnostics
                            if item.code in {"external_properties_ignored", EXECUTION_UNSUCCESSFUL}
                        ],
                        expected,
                    )

    def test_a_refused_run_still_reports_an_unusable_clock(self) -> None:
        # The clock is read before the driver and identity checks, so a refused run's unusable
        # clock is named once, as an accepted run's is.
        for refusal in (
            {"automationDetails": {"id": "scan/\u200b"}},
            {"tool": {"driver": {"name": ""}}},
            {"tool": {"driver": {"name": "Synth\u200b"}}},
        ):
            with self.subTest(refusal=refusal):
                run = make_run(
                    [],
                    invocations=[{"executionSuccessful": False, "startTimeUtc": "not a clock"}],
                    **refusal,
                )
                result = ingest_json("synthetic.sarif", make_log(run))
                self.assertIsNone(result.failed_execution_at)
                self.assertEqual(
                    [item.code for item in result.diagnostics].count("source_timestamp_invalid"),
                    1,
                )

    def test_collecting_the_failed_clock_adds_no_diagnostic(self) -> None:
        invocation = {
            "executionSuccessful": False,
            "startTimeUtc": "not a clock",
            "endTimeUtc": "2026-08-31T09:30:00Z",
        }
        failed = self.ingest([invocation])
        succeeded = self.ingest([{**invocation, "executionSuccessful": True}])
        self.assertEqual(failed.failed_execution_at, INVOKED)
        self.assertIsNone(succeeded.failed_execution_at)
        invalid = [item for item in failed.diagnostics if item.code == "source_timestamp_invalid"]
        self.assertEqual(len(invalid), 1)
        self.assertIn("(1 occurrence:", invalid[0].message)
        self.assertEqual(
            [item for item in failed.diagnostics if item.code != EXECUTION_UNSUCCESSFUL],
            list(succeeded.diagnostics),
        )
        # The two logs differ in bytes, so only the digest-bound ids may differ.
        self.assertEqual(
            [(item.source_record_id, item.observed_at) for item in failed.observations],
            [(item.source_record_id, item.observed_at) for item in succeeded.observations],
        )
        self.assertEqual(failed.observations[0].observed_at, INVOKED)


# *--- System Record ---*


class SystemRecordTests(unittest.TestCase):
    def test_every_field_follows_the_identity_table(self) -> None:
        record = mint(content_failure())
        self.assertEqual(record.source_type, "complyroll.detection-process")
        self.assertEqual(record.source_tool, "complyroll")
        self.assertEqual(record.parser_name, "complyroll.detection-failures")
        self.assertEqual(record.parser_version, "1")
        self.assertEqual(record.source_record_id, "detection-process-failure")
        self.assertEqual(record.resource, ResourceRef(REFERENCE, "artifact"))
        self.assertEqual(record.context_key, REFERENCE)
        self.assertIs(record.disposition, ObservationDisposition.OPEN)
        self.assertIs(record.source_severity, SourceSeverity.UNKNOWN)
        self.assertEqual(record.source_identifiers, ())
        self.assertEqual(record.evidence_ids, (REFERENCE,))
        self.assertEqual(
            record.title,
            f"source artifact {REFERENCE} did not yield complete detection results (VDR-CSO-FAV)",
        )
        self.assertEqual(record.description, "")
        self.assertIs(record.origin, ObservationOrigin.SYSTEM)
        self.assertEqual(record.source_artifact_name, "")
        self.assertEqual(record.source_artifact_digest, "")
        self.assertEqual(record.observed_at, AS_OF)
        self.assertEqual(record.ingested_at, NOW)
        self.assertEqual(record.observation_id, record.derived_observation_id)

    def test_the_metadata_follows_the_metadata_table(self) -> None:
        record = mint(content_failure())
        self.assertEqual(
            record.source_metadata,
            (
                ("artifact.mediaType", "application/json"),
                ("artifact.name", NAME),
                ("artifact.parser", "complyroll.cklb"),
                ("artifact.parserVersion", "1"),
                ("artifact.sha256", DIGEST),
                ("artifact.sizeBytes", "2048"),
                ("failure.class", "content"),
                ("failure.clock", "as-of"),
                ("failure.codes", '["invalid_rule","no_observations"]'),
                ("failure.rule", "VDR-CSO-FAV"),
            ),
        )
        self.assertNotIn("truncated", metadata(record))

    def test_the_record_id_is_derived_from_the_identity_payload(self) -> None:
        payload = json.dumps(
            [
                "system",
                "complyroll.detection-process",
                "complyroll",
                "complyroll.detection-failures",
                "1",
                "detection-process-failure",
                "artifact",
                REFERENCE,
                REFERENCE,
                "2026-09-02T00:00:00+00:00",
            ],
            separators=(",", ":"),
            ensure_ascii=True,
        )
        expected = f"obs-{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"
        record = mint(content_failure())
        self.assertEqual(record.observation_id, expected)
        self.assertEqual(record.observation_id, PINNED_RECORD_ID)

    def test_the_id_ignores_the_ingest_time_the_name_the_parser_and_the_class(self) -> None:
        pinned = mint(content_failure()).observation_id
        variants = {
            "ingest time": mint(content_failure(provenance(ingested_at=LATER))),
            "artifact name": mint(content_failure(provenance(name="renamed.json"))),
            "caller name": mint(content_failure(), name="another-name.cklb"),
            "failed parser": mint(
                content_failure(
                    provenance(
                        parser_name="complyroll.hdf",
                        parser_version="2",
                        media_type="application/vnd.synthetic+json",
                    )
                )
            ),
            "parse class": mint(reading(error("artifact_parse_failed"))),
            "execution class": mint(reading(error("invalid_run"), warning(EXECUTION_UNSUCCESSFUL))),
        }
        for label, record in variants.items():
            with self.subTest(label):
                self.assertEqual(record.observation_id, pinned)
                self.assertEqual(record.fingerprint, pinned.removeprefix("obs-"))

    def test_the_id_tracks_the_digest_and_the_as_of_instant(self) -> None:
        pinned = mint(content_failure()).observation_id
        self.assertNotEqual(mint(content_failure(provenance(OTHER_DIGEST))).observation_id, pinned)
        self.assertNotEqual(mint(content_failure(), observed_at=LATER).observation_id, pinned)
        phoenix = timezone(timedelta(hours=-7))
        self.assertEqual(
            mint(content_failure(), observed_at=AS_OF.astimezone(phoenix)).observation_id, pinned
        )

    def test_an_execution_failure_is_observed_at_its_declared_clock(self) -> None:
        result = reading(
            error("no_observations"), warning(EXECUTION_UNSUCCESSFUL), failed_execution_at=INVOKED
        )
        first = mint(result, observed_at=AS_OF)
        second = mint(result, observed_at=LATER)
        self.assertEqual(first.observed_at, INVOKED)
        self.assertEqual(first.observation_id, second.observation_id)
        self.assertEqual(metadata(first)["failure.clock"], "invocation")
        self.assertEqual(metadata(first)["failure.class"], "execution")
        self.assertEqual(
            metadata(first)["failure.codes"], '["execution_unsuccessful","no_observations"]'
        )

    def test_an_execution_failure_without_a_clock_is_observed_as_of(self) -> None:
        record = mint(reading(error("no_observations"), warning(EXECUTION_UNSUCCESSFUL)))
        self.assertEqual(record.observed_at, AS_OF)
        self.assertEqual(metadata(record)["failure.clock"], "as-of")

    def test_a_side_record_names_only_the_failed_invocation(self) -> None:
        result = reading(
            warning(EXECUTION_UNSUCCESSFUL),
            observations=(artifact_observation(),),
            failed_execution_at=INVOKED,
        )
        record = mint(result)
        self.assertEqual(metadata(record)["failure.codes"], '["execution_unsuccessful"]')
        self.assertEqual(metadata(record)["failure.class"], "execution")
        self.assertEqual(record.observed_at, INVOKED)

    def test_the_record_round_trips_through_its_canonical_form(self) -> None:
        results = (
            content_failure(),
            reading(error("artifact_parse_failed")),
            reading(
                error("invalid_run"), warning(EXECUTION_UNSUCCESSFUL), failed_execution_at=INVOKED
            ),
            reading(warning(EXECUTION_UNSUCCESSFUL), observations=(artifact_observation(),)),
        )
        for result in results:
            record = mint(result)
            with self.subTest(codes=metadata(record)["failure.codes"]):
                rebuilt = Observation.from_canonical_dict(record.to_canonical_dict())
                self.assertEqual(rebuilt, record)
                self.assertEqual(rebuilt.to_canonical_json(), record.to_canonical_json())

    def test_the_worst_case_record_stays_under_the_observation_bound(self) -> None:
        diagnostics = [error(code) for code in sorted(CLASS_CODES)]
        result = reading(*diagnostics, warning(EXECUTION_UNSUCCESSFUL), failed_execution_at=INVOKED)
        record = mint(result, name="\U0001f600" * 600)
        values = metadata(record)
        self.assertEqual(len(values["artifact.name"]), MAX_METADATA_VALUE_CHARS)
        self.assertEqual(
            json.loads(values["failure.codes"]), sorted(CLASS_CODES | {EXECUTION_UNSUCCESSFUL})
        )
        # Every vocabulary code at once is wider than any mintable reading, and still fits.
        vocabulary = sorted(CLASS_CODES | UNMINTABLE_CODES | {EXECUTION_UNSUCCESSFUL})
        widest = replace(
            record,
            source_metadata=tuple(
                sorted({**values, "failure.codes": encode_list(vocabulary)}.items())
            ),
        )
        for candidate in (record, widest):
            size = len(candidate.to_canonical_json().encode("utf-8"))
            self.assertLess(size, MAX_OBSERVATION_JSON_BYTES)

    def test_minting_refuses_an_unmintable_or_foreign_classification(self) -> None:
        result = content_failure()
        classification = classify_ingest(result)
        assert classification is not None
        refusals = (
            classify_ingest(reading(error("artifact_parse_failed"), format_rejected=True)),
            classification.read_elsewhere(),
            FailureClassification(PARSE, None, ("artifact_parse_failed",)),
            FailureClassification(CONTENT, None, ("no_observations",)),
        )
        for refused in refusals:
            assert refused is not None
            with self.subTest(refused=refused):
                with self.assertRaises(ValueError):
                    system_observation_for(result, refused, name=NAME, observed_at=AS_OF)
                with self.assertRaises(ValueError):
                    failure_diagnostics(result, refused, name=NAME)
        digestless = reading(error("no_observations"), digestless=True)
        with self.assertRaises(ValueError):
            system_observation_for(digestless, classification, name=NAME, observed_at=AS_OF)

    def test_minting_refuses_a_name_that_is_not_text_and_a_naive_instant(self) -> None:
        result = content_failure()
        classification = classify_ingest(result)
        assert classification is not None
        for name in (None, b"synthetic.cklb"):
            with self.subTest(name=name):
                with self.assertRaises(TypeError):
                    system_observation_for(
                        result,
                        classification,
                        name=name,  # type: ignore[arg-type]
                        observed_at=AS_OF,
                    )
                with self.assertRaises(TypeError):
                    failure_diagnostics(result, classification, name=name)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            system_observation_for(
                result, classification, name=NAME, observed_at=AS_OF.replace(tzinfo=None)
            )


# *--- Failure Diagnostics ---*


class FailureDiagnosticsTests(unittest.TestCase):
    def render(self, result: IngestResult, name: str = NAME) -> tuple[IngestDiagnostic, ...]:
        classification = classify_ingest(result)
        assert classification is not None
        return failure_diagnostics(result, classification, name=name)

    def test_diagnostics_are_ordered_demoted_and_closed_by_the_recorded_notice(self) -> None:
        result = reading(
            warning("source_timestamp_missing", message="no clock"),
            error("no_observations", message="nothing usable"),
            error("invalid_rule", "stigs[0].rules[1]", "bad rule"),
            error("invalid_rule", "stigs[0].rules[0]", "second"),
            error("invalid_rule", "stigs[0].rules[0]", "first"),
            info("results_collapsed", message="collapsed"),
        )
        rendered = self.render(result)
        self.assertEqual(
            [(item.level, item.code, item.location, item.message) for item in rendered],
            [
                (WARNING, "invalid_rule", "stigs[0].rules[0]", "first"),
                (WARNING, "invalid_rule", "stigs[0].rules[0]", "second"),
                (WARNING, "invalid_rule", "stigs[0].rules[1]", "bad rule"),
                (WARNING, "no_observations", NAME, "nothing usable"),
                (INFO, "results_collapsed", NAME, "collapsed"),
                (WARNING, "source_timestamp_missing", NAME, "no clock"),
                (
                    WARNING,
                    "detection_failure_recorded",
                    NAME,
                    f"recorded a detection process failure of class content for source "
                    f"artifact {REFERENCE} (VDR-CSO-FAV)",
                ),
            ],
        )

    def test_the_raw_level_breaks_the_last_tie(self) -> None:
        # The raw ERROR sorts before the INFO ("error" < "info") and only then is demoted,
        # so a sort on the demoted level, or on no level, would put the INFO first in at
        # least one input order.
        tied = (
            info("invalid_rule", "stigs[0]", "same"),
            error("invalid_rule", "stigs[0]", "same"),
        )
        for order in (tied, tied[::-1]):
            with self.subTest([item.level.value for item in order]):
                rendered = self.render(reading(*order))
                self.assertEqual(
                    [(item.level, item.code) for item in rendered[:2]],
                    [(WARNING, "invalid_rule"), (INFO, "invalid_rule")],
                )

    def test_a_missing_location_sorts_before_every_location_of_its_code(self) -> None:
        # A missing location is keyed as the empty string. Keyed as a placeholder text, it
        # would sort after this name, which starts with a digit, and not keyed at all, it
        # could not be compared with a location.
        tied = (
            error("invalid_rule", "2026-08-host.cklb", "located"),
            error("invalid_rule", None, "unlocated"),
        )
        for order in (tied, tied[::-1]):
            with self.subTest([item.location for item in order]):
                rendered = self.render(reading(*order))
                self.assertEqual(
                    [(item.location, item.message) for item in rendered[:2]],
                    [(NAME, "unlocated"), ("2026-08-host.cklb", "located")],
                )

    def test_every_error_is_demoted_to_a_warning_under_the_same_code(self) -> None:
        result = ingest_json(NAME, checklist(1, "rule", None))
        rendered = self.render(result)
        self.assertNotIn(ERROR, [item.level for item in rendered])
        self.assertEqual(
            [(item.code, item.location, item.message) for item in rendered[:-1]],
            [
                (item.code, item.location, item.message)
                for item in sorted(result.diagnostics, key=raw_order)
            ],
        )

    def test_the_cap_keeps_sixty_two_entries_and_names_what_it_dropped(self) -> None:
        for source_count, dropped in ((62, 0), (63, 1), (70, 8)):
            with self.subTest(source_count=source_count):
                result = ingest_json(NAME, checklist(*([1] * (source_count - 1))))
                self.assertEqual(len(result.diagnostics), source_count)
                rendered = self.render(result)
                self.assertLessEqual(len(rendered), 64)
                kept = sorted(result.diagnostics, key=raw_order)[:62]
                self.assertEqual(
                    [(item.code, item.location) for item in rendered[: len(kept)]],
                    [(item.code, item.location) for item in kept],
                )
                notices = [item for item in rendered if item.code == FAILURE_DIAGNOSTICS_TRUNCATED]
                if dropped:
                    self.assertEqual(len(rendered), 64)
                    self.assertEqual(
                        rendered[-2],
                        IngestDiagnostic(
                            WARNING,
                            "failure_diagnostics_truncated",
                            f"{dropped} further diagnostic(s) of the failed reading were "
                            "dropped; the first 62 are kept",
                            NAME,
                        ),
                    )
                    self.assertEqual(len(notices), 1)
                else:
                    self.assertEqual(len(rendered), 63)
                    self.assertEqual(notices, [])
                self.assertEqual(rendered[-1].code, DETECTION_FAILURE_RECORDED)
        # Checked last, so a moved cap fails on the rendered entries first.
        self.assertEqual(FAILURE_DIAGNOSTIC_CAP, 62)

    def test_a_missing_location_becomes_the_name(self) -> None:
        result = reading(error("invalid_rule", None, "no location"), error("no_observations", ""))
        rendered = self.render(result, name="caller-name.cklb")
        self.assertEqual([item.location for item in rendered], ["caller-name.cklb"] * 3)

    def test_messages_locations_and_the_name_pass_diagnostic_text(self) -> None:
        hostile = "zero\u200bwidth\x1b[31m\x07bell\u2028line\ud800"
        name = "name\u200b\x1b" + "n" * 600
        result = reading(
            error("invalid_rule", hostile, hostile), error("no_observations", None, "m" * 700)
        )
        rendered = self.render(result, name=name)
        self.assertEqual(rendered[0].message, "zerowidth[31mbell\nline")
        self.assertEqual(rendered[0].location, "zerowidth[31mbell\nline")
        self.assertEqual(rendered[1].message, "m" * 498 + TRUNCATION_MARKER)
        self.assertEqual(rendered[1].location, diagnostic_text(name))
        self.assertEqual(rendered[-1].location, diagnostic_text(name))
        for item in rendered:
            with self.subTest(code=item.code):
                self.assertEqual(prohibited(item.message), [])
                self.assertEqual(prohibited(item.location or ""), [])
                self.assertLessEqual(len(item.message), MAX_METADATA_VALUE_CHARS)
                self.assertLessEqual(len(item.location or ""), MAX_METADATA_VALUE_CHARS)

    def test_a_side_record_contributes_only_the_recorded_notice(self) -> None:
        result = reading(
            warning(EXECUTION_UNSUCCESSFUL),
            warning("resource_identity_fallback"),
            observations=(artifact_observation(),),
            failed_execution_at=INVOKED,
        )
        self.assertEqual(
            self.render(result),
            (
                IngestDiagnostic(
                    WARNING,
                    "detection_failure_recorded",
                    "recorded a detection process failure of class execution for source "
                    f"artifact {REFERENCE} (VDR-CSO-FAV)",
                    NAME,
                ),
            ),
        )


# *--- Vocabulary ---*


class VocabularyWalkTests(unittest.TestCase):
    sites: list[ErrorSite]

    @classmethod
    def setUpClass(cls) -> None:
        cls.sites = adapter_walk().error_sites()

    def test_every_error_code_is_in_exactly_one_set(self) -> None:
        self.assertGreater(len(self.sites), 20)
        for site in self.sites:
            with self.subTest(site=f"{site.module}:{site.line}", code=site.code):
                self.assertEqual((site.code in CLASS_CODES) + (site.code in UNMINTABLE_CODES), 1)

    def test_every_vocabulary_code_has_an_emission_site(self) -> None:
        self.assertEqual({site.code for site in self.sites}, CLASS_CODES | UNMINTABLE_CODES)

    def test_the_sets_partition_the_vocabulary(self) -> None:
        self.assertEqual(CLASS_CODES & UNMINTABLE_CODES, frozenset())
        self.assertEqual(PARSE_CODES & CONTENT_CODES, frozenset())
        self.assertEqual(CLASS_CODES, PARSE_CODES | CONTENT_CODES)
        self.assertNotIn(EXECUTION_UNSUCCESSFUL, CLASS_CODES | UNMINTABLE_CODES)

    def test_clean_run_unverified_is_a_content_code_raised_once_by_the_sarif_reading(self) -> None:
        self.assertIn("clean_run_unverified", CONTENT_CODES)
        sites = [site for site in self.sites if site.code == "clean_run_unverified"]
        self.assertEqual([(site.module, site.function) for site in sites], [("sarif.py", "run")])

    def test_the_unmintable_reasons_are_the_six_checked_and_read_elsewhere(self) -> None:
        # clean_scan left the vocabulary with ADR 0015 decision 1: the SARIF adapter folds an
        # observation at every run_clean site unless the run's invocation failed, which the
        # execution class claims first, or is unverified, which raises clean_run_unverified.
        self.assertEqual(
            [reason.value for reason in UnmintableReason],
            [
                "no_digest",
                "unsupported",
                "format_rejected",
                "duplicate_identity",
                "partial_reading",
                "unknown_code",
                "read_elsewhere",
            ],
        )
        self.assertFalse(hasattr(UnmintableReason, "CLEAN_SCAN"))

    def test_helper_passed_codes_resolve_through_their_call_sites(self) -> None:
        helper = {site.code for site in self.sites if site.function == "_error_result"}
        self.assertEqual(
            helper, {"artifact_read_failed", "unsupported_artifact", "artifact_parse_failed"}
        )
        shared = {site.code for site in self.sites if site.module == "common.py"}
        self.assertEqual(shared, {"identity_input_invalid"})

    def test_the_walk_finds_a_new_site_and_a_helper_passed_code(self) -> None:
        source = (
            "SYNTHETIC = 'syn_constant'\n"
            "def helper(summary, *, code, level_note='x'):\n"
            "    IngestDiagnostic(DiagnosticLevel.ERROR, code, summary)\n"
            "def caller(self):\n"
            "    helper('a', code='syn_helper')\n"
            "    helper('b', code=SYNTHETIC)\n"
            "    self.diagnostics.add(DiagnosticLevel.ERROR, 'syn_add', 'm', 'p')\n"
            "    IngestDiagnostic(level=DiagnosticLevel.ERROR, code='syn_keyword', message='m')\n"
            "    IngestDiagnostic(DiagnosticLevel.WARNING, 'syn_warning', 'm')\n"
        )
        sites = SourceWalk({"synthetic.py": source}).error_sites()
        self.assertEqual(
            sorted(site.code for site in sites),
            ["syn_add", "syn_constant", "syn_helper", "syn_keyword"],
        )

    def test_the_walk_fails_on_anything_it_cannot_resolve(self) -> None:
        cases = {
            "a computed code": (
                "def f(x):\n    IngestDiagnostic(DiagnosticLevel.ERROR, x.upper(), 'm')\nf('a')\n"
            ),
            "a local variable": (
                "def f():\n    code = 'x'\n    IngestDiagnostic(DiagnosticLevel.ERROR, code, 'm')\n"
            ),
            "a helper with no call site": (
                "def helper(code):\n    IngestDiagnostic(DiagnosticLevel.ERROR, code, 'm')\n"
            ),
            "a helper passed a variable": (
                "def helper(code):\n    IngestDiagnostic(DiagnosticLevel.ERROR, code, 'm')\n"
                "def caller(value):\n    helper(value.name)\n"
            ),
            "a helper call that omits the code": (
                "def helper(summary, code=None):\n"
                "    IngestDiagnostic(DiagnosticLevel.ERROR, code, summary)\n"
                "def caller():\n    helper('m')\n"
            ),
            "a level that is not literal": (
                "def f(level):\n    IngestDiagnostic(level, 'x', 'm')\n"
            ),
            "an added level that is not literal": (
                "def f(self, level):\n    self.diagnostics.add(level, 'x', 'm', 'p')\n"
            ),
            "an error with no code": "IngestDiagnostic(DiagnosticLevel.ERROR)\n",
        }
        for label, source in cases.items():
            with self.subTest(label), self.assertRaises(Unresolved):
                SourceWalk({"synthetic.py": source}).error_sites()


# *--- Reserved Prefix ---*


class ReservedPrefixTests(unittest.TestCase):
    def test_no_artifact_bound_build_uses_the_reserved_prefix(self) -> None:
        source_types, system_modules = adapter_walk().source_types()
        self.assertLessEqual(SHIPPED_SOURCE_TYPES, source_types)
        for source_type in sorted(source_types):
            with self.subTest(source_type=source_type):
                self.assertFalse(source_type.startswith(RESERVED_SOURCE_TYPE_PREFIX))
        self.assertEqual(system_modules, {"failures.py"})

    def test_no_adapter_source_type_constant_uses_the_reserved_prefix(self) -> None:
        walk = adapter_walk()
        constants = {
            name: values
            for name, values in walk.constants.items()
            if name.endswith("_SOURCE_TYPE") and name != "DETECTION_FAILURE_SOURCE_TYPE"
        }
        self.assertIn("SARIF_SOURCE_TYPE", constants)
        for name, values in sorted(constants.items()):
            with self.subTest(name=name):
                self.assertFalse(
                    any(value.startswith(RESERVED_SOURCE_TYPE_PREFIX) for value in values)
                )

    def test_the_record_is_the_one_system_observation_under_the_prefix(self) -> None:
        self.assertTrue(DETECTION_FAILURE_SOURCE_TYPE.startswith(RESERVED_SOURCE_TYPE_PREFIX))
        record = mint(content_failure())
        self.assertIs(record.origin, ObservationOrigin.SYSTEM)
        with self.assertRaisesRegex(ValueError, "reserved"):
            replace(
                record,
                origin=ObservationOrigin.ARTIFACT,
                source_artifact_digest=DIGEST,
                source_artifact_name=NAME,
            )


# *--- Import Boundary ---*


class ImportBoundaryTests(unittest.TestCase):
    def test_the_failures_module_loads_no_report_module(self) -> None:
        program = (
            "import json, sys\n"
            "import complyroll.adapters.failures as failures\n"
            "loaded = sorted(name for name in sys.modules\n"
            "    if name == 'complyroll.reports' or name.startswith('complyroll.reports.'))\n"
            "print(json.dumps({'file': failures.__file__, 'reports': loaded}))\n"
        )
        environment = {**os.environ, "PYTHONPATH": str(SOURCE_ROOT)}
        completed = subprocess.run(
            [sys.executable, "-c", program],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=environment,
            timeout=120,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        loaded = json.loads(completed.stdout)
        self.assertEqual(Path(loaded["file"]).resolve(), Path(failures_module.__file__).resolve())
        self.assertEqual(loaded["reports"], [])


# *--- Hostile Inputs ---*


class HostileInputTests(unittest.TestCase):
    def test_a_checklist_spelling_the_record_identity_is_an_artifact_reading(self) -> None:
        rule = {**GOOD_RULE, "group_id": "detection-process-failure"}
        result = ingest_json(NAME, checklist(rule, host=REFERENCE, stig={"stig_id": REFERENCE}))
        self.assertTrue(result.successful)
        self.assertIsNone(classify_ingest(result))
        (observation,) = result.observations
        self.assertIs(observation.origin, ObservationOrigin.ARTIFACT)
        self.assertEqual(observation.source_type, "cklb")
        self.assertEqual(observation.source_record_id, "detection-process-failure")
        self.assertEqual(observation.context_key, REFERENCE)
        self.assertEqual(observation.resource, ResourceRef(REFERENCE, "host"))
        record = mint(content_failure(), observed_at=observation.observed_at or AS_OF)
        self.assertNotEqual(observation.observation_id, record.observation_id)
        self.assertNotEqual(observation.fingerprint, record.fingerprint)

    def test_a_sarif_driver_named_complyroll_is_an_artifact_reading(self) -> None:
        result = ingest_json(
            "synthetic.sarif", make_log(make_run([make_result()], driver="complyroll"))
        )
        self.assertTrue(result.successful)
        self.assertIsNone(classify_ingest(result))
        for observation in result.observations:
            with self.subTest(observation=observation.observation_id):
                self.assertIs(observation.origin, ObservationOrigin.ARTIFACT)
                self.assertEqual(observation.source_type, "sarif")
                self.assertFalse(observation.source_type.startswith(RESERVED_SOURCE_TYPE_PREFIX))

    def test_a_hostile_artifact_name_is_bounded_and_escaped(self) -> None:
        name = "bad\u200b\x1b[31m\x07\u2028name.cklb"
        result = ingest_json(name, checklist(1))
        assert result.artifact is not None
        self.assertEqual(result.artifact.name, name)
        classification = classify_ingest(result)
        assert classification is not None
        record = system_observation_for(
            result, classification, name=result.artifact.name, observed_at=AS_OF
        )
        self.assertEqual(metadata(record)["artifact.name"], "bad[31m\nname.cklb")
        self.assertNotIn("name", record.title)
        self.assertEqual(record.description, "")
        rendered = failure_diagnostics(result, classification, name=result.artifact.name)
        self.assertIn(name, [item.location for item in result.diagnostics])
        for item in rendered:
            with self.subTest(code=item.code):
                self.assertEqual(prohibited(item.message), [])
                self.assertEqual(prohibited(item.location or ""), [])
        long_name = "\u200b" + "x" * 600
        bounded = metadata(mint(content_failure(), name=long_name))["artifact.name"]
        self.assertEqual(len(bounded), MAX_METADATA_VALUE_CHARS)
        self.assertTrue(bounded.endswith(TRUNCATION_MARKER))
        self.assertEqual(prohibited(bounded), [])


# *--- Entry Point ---*

if __name__ == "__main__":
    unittest.main()
