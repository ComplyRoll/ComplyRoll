# ******************************************************************************
# *Title: Report Diagnostic Code Tests*
# *Author: Kyle Versluis*
# *Description: Hold every code the report compiler mints to its closed set.*
# ******************************************************************************
"""Tests for `REPORT_DIAGNOSTIC_CODES`, the closed set of report diagnostic codes (CL-71).

A report prints its diagnostics in its JSON and on standard error, so their codes are part
of the report's contract, as `AUDIT_FAULT_CODES` is part of `store verify`'s. The set is
checked against the source rather than at run time: every `ReportDiagnostic` the
`complyroll.reports` package builds names a code in the set, and every code in the set is
built somewhere. An ingest diagnostic a report carries keeps its adapter's code, so the
sites that copy one are named here as pass-throughs, not resolved.
"""

# *--- Imports ---*

from __future__ import annotations

import ast
import importlib
import unittest
from pathlib import Path

from complyroll.reports import REPORT_DIAGNOSTIC_CODES

# *--- Fixtures ---*

REPORTS = Path(__file__).parent.parent / "src" / "complyroll" / "reports"
#: The functions that copy an ingest diagnostic's code into a report diagnostic.
PASS_THROUGH = frozenset(
    {
        ("replay", "_ingest_diagnostics"),
        ("vdt", "_collect_diagnostics"),
        ("vdt", "_record_detection_failure"),
    }
)


# *--- Helpers ---*


def _code_argument(call: ast.Call) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == "code":
            return keyword.value
    return call.args[1] if len(call.args) > 1 else None


def _local_codes(function: ast.AST, name: str) -> list[object]:
    """Return every value a function assigns to a local name, as constants or None."""
    values: list[object] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            values.append(node.value.value if isinstance(node.value, ast.Constant) else None)
    return values


def scan() -> tuple[dict[str, list[str]], set[tuple[str, str]], list[str]]:
    """Return each resolved code's sites, the pass-through sites, and what did not resolve."""
    codes: dict[str, list[str]] = {}
    passed: set[tuple[str, str]] = set()
    unresolved: list[str] = []
    for path in sorted(REPORTS.glob("*.py")):
        name = (
            "complyroll.reports" if path.stem == "__init__" else f"complyroll.reports.{path.stem}"
        )
        module = importlib.import_module(name)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ReportDiagnostic"
            ):
                continue
            site = f"{path.name}:{node.lineno}"
            function: ast.AST | None = parents.get(node)
            while function is not None and not isinstance(function, ast.FunctionDef):
                function = parents.get(function)
            argument = _code_argument(node)
            found: list[object]
            if isinstance(argument, ast.Constant):
                found = [argument.value]
            elif isinstance(argument, ast.Name) and hasattr(module, argument.id):
                found = [getattr(module, argument.id)]
            elif isinstance(argument, ast.Name) and function is not None:
                found = _local_codes(function, argument.id) or [None]
            elif (
                isinstance(argument, ast.Attribute)
                and argument.attr == "code"
                and isinstance(function, ast.FunctionDef)
            ):
                passed.add((path.stem, function.name))
                continue
            else:
                found = [None]
            for value in found:
                if isinstance(value, str):
                    codes.setdefault(value, []).append(site)
                else:
                    unresolved.append(site)
    return codes, passed, unresolved


# *--- Tests ---*


class ReportDiagnosticCodeTests(unittest.TestCase):
    """Every code a report diagnostic carries is one the closed set publishes."""

    def test_the_set_is_sorted_and_has_no_repeat(self) -> None:
        self.assertEqual(list(REPORT_DIAGNOSTIC_CODES), sorted(set(REPORT_DIAGNOSTIC_CODES)))

    def test_every_site_names_a_code_in_the_set(self) -> None:
        codes, _, unresolved = scan()
        self.assertEqual(unresolved, [])
        self.assertLessEqual(set(codes), set(REPORT_DIAGNOSTIC_CODES), msg=codes)

    def test_every_code_in_the_set_is_built_somewhere(self) -> None:
        codes, _, _ = scan()
        self.assertEqual(set(REPORT_DIAGNOSTIC_CODES) - set(codes), set())

    def test_only_the_named_sites_pass_an_ingest_code_through(self) -> None:
        _, passed, _ = scan()
        self.assertEqual(passed, PASS_THROUGH)


if __name__ == "__main__":
    unittest.main()
