# ******************************************************************************
# *Title: Bounded JSON Sources*
# *Author: Kyle Versluis*
# *Description: One bounded JSON parser for the non-artifact JSON inputs.*
# ******************************************************************************
"""Parse a JSON input that is not an artifact, refusing it in its reader's own words.

The rule source, a schema document, an evaluations file and a report `validate` reads
each refuse the same inputs, as their reader's own error with their reader's own subject
and bounds. Artifacts are parsed by `adapters.safeio.parse_json_bounded`, which reads a
UTF-8 byte order mark and words its refusals for an ingest diagnostic.
"""

# *--- Imports ---*

from __future__ import annotations

import json
import re
import sys
from typing import Any

from complyroll.store.sqlite import shown

# *--- Configuration ---*

# json.loads decodes the escape of a lone surrogate, such as "\\ud800", into text that
# no UTF-8 encoder will accept.
_LONE_SURROGATE = re.compile("[\\ud800-\\udfff]")


# *--- Parsing ---*


def parse_json_source(
    content: bytes,
    *,
    subject: str,
    error: type[ValueError],
    max_values: int,
    max_depth: int,
    reject_lone_surrogates: bool = False,
) -> Any:
    """Return the JSON value `content` holds, or raise `error` naming `subject`.

    Duplicate keys, non-standard constants, malformed or non-UTF-8 text, an integer past
    the interpreter's digit limit, more than `max_values` values and more than `max_depth`
    levels are refused. A lone surrogate is refused only when the reader asks.
    """

    def reject_nonstandard_constant(value: str) -> None:
        raise error(f"non-standard JSON constant is prohibited: {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                # SECURITY: The key is untrusted text bound for a terminal, so it is quoted and cut.
                raise error(f"duplicate JSON object key is prohibited: {shown(key)}")
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("utf-8"),
            parse_constant=reject_nonstandard_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except UnicodeDecodeError as exc:
        raise error(f"{subject} must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise error(f"{subject} contains malformed JSON: {exc}") from exc
    except error:
        # The hooks above raise it, and it is a ValueError too.
        raise
    except ValueError as exc:
        # The one other ValueError json.loads raises: an integer past the digit limit.
        limit = sys.get_int_max_str_digits()
        message = f"{subject} contains an integer longer than {limit} digits"
        raise error(message) from exc
    except RecursionError as exc:
        raise error(f"{subject} exceeds the safe JSON recursion limit") from exc

    values_seen = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        values_seen += 1
        if values_seen > max_values:
            raise error(f"{subject} contains more than {max_values} JSON values")
        if depth > max_depth:
            raise error(f"{subject} exceeds {max_depth} levels of JSON nesting")
        # SECURITY: A lone surrogate survives json.loads and fails a later write as a
        # traceback; a reader that writes what it read refuses it at parse, as safeio does.
        if isinstance(current, str):
            if reject_lone_surrogates:
                _reject_lone_surrogate(current, "string", subject, error)
        elif isinstance(current, dict):
            for key, item in current.items():
                if reject_lone_surrogates:
                    _reject_lone_surrogate(key, "object key", subject, error)
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return value


def _reject_lone_surrogate(text: str, kind: str, subject: str, error: type[ValueError]) -> None:
    found = _LONE_SURROGATE.search(text)
    if found is not None:
        raise error(
            f"{subject} contains a lone surrogate code point in a JSON {kind}: "
            f"U+{ord(found.group()):04X}"
        )


__all__ = ["parse_json_source"]
