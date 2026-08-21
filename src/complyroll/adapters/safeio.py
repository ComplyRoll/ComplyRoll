"""Bounded, network-free parsing helpers for untrusted source artifacts."""

from __future__ import annotations

import json
import stat
import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class IngestLimits:
    max_artifact_bytes: int = 32 * 1024 * 1024
    max_json_depth: int = 128
    max_json_nodes: int = 500_000
    max_xml_depth: int = 128
    max_xml_elements: int = 500_000


DEFAULT_LIMITS = IngestLimits()


class InputLimitError(ValueError):
    """An input exceeded an explicit resource bound."""


class UnsafeXmlError(ValueError):
    """XML contained a prohibited declaration."""


def read_bounded(path: Path, limits: IngestLimits = DEFAULT_LIMITS) -> bytes:
    """Read a regular file into memory, refusing anything larger than the artifact bound."""

    limit = limits.max_artifact_bytes
    status = path.stat()
    if not stat.S_ISREG(status.st_mode):
        raise ValueError(f"artifact is not a regular file: {path}")
    if status.st_size > limit:
        raise InputLimitError(f"artifact is {status.st_size} bytes; maximum is {limit} bytes")

    chunks: list[bytes] = []
    total = 0
    with path.open("rb") as handle:
        while total <= limit:
            chunk = handle.read(limit + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    if total > limit:
        raise InputLimitError(f"artifact is larger than {limit} bytes; maximum is {limit} bytes")
    return b"".join(chunks)


def parse_json_bounded(content: bytes, limits: IngestLimits = DEFAULT_LIMITS) -> Any:
    def reject_nonstandard_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant is prohibited: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key is prohibited: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("utf-8-sig"),
            parse_constant=reject_nonstandard_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"JSON must be UTF-8: {exc}") from exc
    except RecursionError as exc:
        raise InputLimitError("JSON nesting exceeds the parser's safe recursion limit") from exc

    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_json_nodes:
            raise InputLimitError(f"JSON contains more than {limits.max_json_nodes} values")
        if depth > limits.max_json_depth:
            raise InputLimitError(f"JSON nesting exceeds {limits.max_json_depth} levels")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value


def _qualified_name(name: str) -> str:
    """Convert expat's ``uri}local`` name to ElementTree's ``{uri}local`` convention."""

    return f"{{{name}" if "}" in name else name


def parse_xml_bounded(content: bytes, limits: IngestLimits = DEFAULT_LIMITS) -> ET.Element:
    """Parse XML with declaration rejection and bounds enforced inside the parser.

    Prohibited declarations are refused by expat's own handlers rather than by scanning the
    source bytes, so the guard holds for every encoding expat auto-detects and never rejects a
    document that merely quotes ``<!DOCTYPE`` inside character data or a comment.
    """

    builder = ET.TreeBuilder()
    root: ET.Element | None = None
    depth = 0
    elements = 0

    def reject_doctype(
        name: str,
        system_id: str | None,
        public_id: str | None,
        has_internal_subset: bool,
    ) -> None:
        raise UnsafeXmlError("DOCTYPE declarations are prohibited")

    def reject_entity(
        name: str,
        is_parameter_entity: bool,
        value: str | None,
        base: str | None,
        system_id: str | None,
        public_id: str | None,
        notation_name: str | None,
    ) -> None:
        raise UnsafeXmlError("ENTITY declarations are prohibited")

    def reject_external_entity(
        context: str | None,
        base: str | None,
        system_id: str | None,
        public_id: str | None,
    ) -> bool:
        raise UnsafeXmlError("external entity references are prohibited")

    def start_element(name: str, attributes: dict[str, str]) -> None:
        nonlocal root, depth, elements
        elements += 1
        depth += 1
        if elements > limits.max_xml_elements:
            raise InputLimitError(f"XML contains more than {limits.max_xml_elements} elements")
        if depth > limits.max_xml_depth:
            raise InputLimitError(f"XML nesting exceeds {limits.max_xml_depth} levels")
        element = builder.start(
            _qualified_name(name),
            {_qualified_name(key): value for key, value in attributes.items()},
        )
        if root is None:
            root = element

    def end_element(name: str) -> None:
        nonlocal depth
        depth -= 1
        builder.end(_qualified_name(name))

    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    parser.StartDoctypeDeclHandler = reject_doctype
    parser.EntityDeclHandler = reject_entity
    parser.ExternalEntityRefHandler = reject_external_entity
    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.CharacterDataHandler = builder.data

    try:
        parser.Parse(content, True)
        builder.close()
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError(f"malformed XML: {exc}") from exc

    if root is None:
        raise ValueError("XML document has no root element")
    return root
