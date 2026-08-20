"""Bounded, network-free parsing helpers for untrusted source artifacts."""

from __future__ import annotations

import io
import json
import xml.etree.ElementTree as ET
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
    size = path.stat().st_size
    if size > limits.max_artifact_bytes:
        raise InputLimitError(
            f"artifact is {size} bytes; maximum is {limits.max_artifact_bytes} bytes"
        )
    content = path.read_bytes()
    if len(content) > limits.max_artifact_bytes:
        raise InputLimitError(
            f"artifact is {len(content)} bytes; maximum is {limits.max_artifact_bytes} bytes"
        )
    return content


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


def parse_xml_bounded(content: bytes, limits: IngestLimits = DEFAULT_LIMITS) -> ET.Element:
    declaration_probe = content.upper()
    if b"<!DOCTYPE" in declaration_probe or b"<!ENTITY" in declaration_probe:
        raise UnsafeXmlError("DOCTYPE and ENTITY declarations are prohibited")

    depth = 0
    elements = 0
    root: ET.Element | None = None
    try:
        iterator = ET.iterparse(io.BytesIO(content), events=("start", "end"))
        for event, element in iterator:
            if event == "start":
                elements += 1
                depth += 1
                if root is None:
                    root = element
                if elements > limits.max_xml_elements:
                    raise InputLimitError(
                        f"XML contains more than {limits.max_xml_elements} elements"
                    )
                if depth > limits.max_xml_depth:
                    raise InputLimitError(f"XML nesting exceeds {limits.max_xml_depth} levels")
            else:
                depth -= 1
    except ET.ParseError as exc:
        raise ValueError(f"malformed XML: {exc}") from exc

    if root is None:
        raise ValueError("XML document has no root element")
    return root
