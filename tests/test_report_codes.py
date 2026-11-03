# ******************************************************************************
# *Title: Report Diagnostic Code Tests*
# *Author: Kyle Versluis*
# *Description: Hold every code a ReportDiagnostic carries to its closed set.*
# ******************************************************************************
"""Tests for `REPORT_DIAGNOSTIC_CODES`, the closed set of diagnostic codes (CL-71).

A report prints its diagnostics in its JSON and on standard error, and the CLI prints its own
refusals as the same `level: code: message` line, so their codes are part of the contract, as
`AUDIT_FAULT_CODES` is part of `store verify`'s. The set is checked against the source rather
than at run time. Every `ReportDiagnostic` built anywhere in `src/complyroll`, and every line
the source writes as text in that form (`warning: attestation_not_applicable: ...`), names a
code in the set, and every code in the set is built or written somewhere. The scan finds the
constructor by its name, by an alias it is imported as, and as an attribute
(`vdt.ReportDiagnostic`), and it treats any `replace(..., code=...)` call, `dataclasses.replace`
included, as a site of its own. `store verify` prints audit faults and the store's integrity
faults from their own records (`fault.code`), so those codes are outside this set.

A code resolves when it is a string literal, a module-level name bound to one, a local the
function assigns only literals to, or a parameter every call in the same module fills with
one of those. An ingest diagnostic the report carries keeps its adapter's code, so the sites
that copy `item.code` are named below as pass-throughs.

Limits: a code that reaches a site any other way does not resolve and fails the test, so a
new indirection has to be resolved here or named; a parameter filled from another module, a
dictionary lookup or a return value is such a case. Construction the AST cannot see, through
`getattr`, `**kwargs` or `exec`, is not scanned at all.
"""

# *--- Imports ---*

from __future__ import annotations

import ast
import importlib
import re
import unittest
from pathlib import Path

from complyroll.reports import REPORT_DIAGNOSTIC_CODES

# *--- Fixtures ---*

SOURCE = Path(__file__).parent.parent / "src" / "complyroll"
CONSTRUCTOR = "ReportDiagnostic"
#: A diagnostic line written as text rather than built: `warning: <code>: ...`.
TEXT_LINE = re.compile(r"^(?:error|warning|info): ([a-z][a-z0-9_]*): ")
#: The functions that copy an ingest diagnostic's code into a report diagnostic.
PASS_THROUGH = frozenset(
    {
        ("complyroll.cli", "_as_report_diagnostics"),
        ("complyroll.reports.replay", "_ingest_diagnostics"),
        ("complyroll.reports.vdt", "_collect_diagnostics"),
        ("complyroll.reports.vdt", "_record_detection_failure"),
    }
)


# *--- Helpers ---*


def _module_name(path: Path) -> str:
    parts = path.relative_to(SOURCE.parent).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _aliases(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Return the names the constructor and `dataclasses.replace` are bound to in a module."""
    constructors, replacers = {CONSTRUCTOR}, {"replace"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == CONSTRUCTOR:
                    constructors.add(alias.asname or alias.name)
                if alias.name == "replace" and node.module == "dataclasses":
                    replacers.add(alias.asname or alias.name)
    return constructors, replacers


def _code_argument(call: ast.Call, position: int) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == "code":
            return keyword.value
    return call.args[position] if len(call.args) > position else None


def _calls_to(tree: ast.Module, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name
    ]


def _resolve(
    expression: ast.expr | None,
    function: ast.FunctionDef | None,
    module: object,
    tree: ast.Module,
    depth: int = 0,
) -> list[object]:
    """Return every value a code expression can take, None where it cannot be told."""
    if isinstance(expression, ast.Constant):
        return [expression.value]
    if not isinstance(expression, ast.Name) or depth > 3:
        return [None]
    name = expression.id
    parameters = [] if function is None else [item.arg for item in function.args.args]
    if name in parameters:
        assert function is not None
        position = parameters.index(name)
        found: list[object] = []
        calls = _calls_to(tree, function.name)
        for call in calls:
            argument = None
            for keyword in call.keywords:
                if keyword.arg == name:
                    argument = keyword.value
            if argument is None and len(call.args) > position:
                argument = call.args[position]
            found.extend(_resolve(argument, None, module, tree, depth + 1))
        return found or [None]
    if function is None:
        return [getattr(module, name, None)]
    assigned = [
        node.value
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    if any(
        isinstance(node, (ast.For, ast.comprehension))
        and isinstance(node.target, ast.Name)
        and node.target.id == name
        for node in ast.walk(function)
    ):
        return [None]
    if assigned:
        return [item.value if isinstance(item, ast.Constant) else None for item in assigned]
    return [getattr(module, name, None)]


def _text_lines(tree: ast.Module) -> set[tuple[int, str]]:
    """Return each diagnostic line a module writes as text, as its line and its code."""
    found: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        text = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr) and node.values:
            head = node.values[0]
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                text = head.value
        matched = None if text is None else TEXT_LINE.match(text)
        if matched is not None:
            found.add((node.lineno, matched.group(1)))
    return found


def _site(
    node: ast.Call, constructors: set[str], replacers: set[str]
) -> tuple[bool, ast.expr | None]:
    """Return whether a call sets a diagnostic's code, and the expression that sets it."""
    func = node.func
    called = (
        func.id
        if isinstance(func, ast.Name)
        else func.attr
        if isinstance(func, ast.Attribute)
        else ""
    )
    if called in constructors or called == CONSTRUCTOR:
        return True, _code_argument(node, 1)
    is_replace = called in replacers or called == "replace"
    if is_replace and any(keyword.arg == "code" for keyword in node.keywords):
        return True, _code_argument(node, len(node.args) + 1)
    return False, None


def scan(
    root: Path = SOURCE,
) -> tuple[dict[str, list[str]], set[tuple[str, str]], list[str]]:
    """Return each resolved code's sites, the pass-through sites, and what did not resolve."""
    codes: dict[str, list[str]] = {}
    passed: set[tuple[str, str]] = set()
    unresolved: list[str] = []
    for path in sorted(root.rglob("*.py")):
        name = _module_name(path)
        module = importlib.import_module(name)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constructors, replacers = _aliases(tree)
        for line, code in _text_lines(tree):
            codes.setdefault(code, []).append(f"{path.relative_to(root)}:{line}")
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            is_site, argument = _site(node, constructors, replacers)
            if not is_site:
                continue
            site = f"{path.relative_to(root)}:{node.lineno}"
            function: ast.AST | None = parents.get(node)
            while function is not None and not isinstance(function, ast.FunctionDef):
                function = parents.get(function)
            if (
                isinstance(argument, ast.Attribute)
                and argument.attr == "code"
                and isinstance(function, ast.FunctionDef)
            ):
                passed.add((name, function.name))
                continue
            for value in _resolve(argument, function, module, tree):
                if isinstance(value, str):
                    codes.setdefault(value, []).append(site)
                else:
                    unresolved.append(site)
    return codes, passed, unresolved


# *--- Tests ---*


class ReportDiagnosticCodeTests(unittest.TestCase):
    """Every code a diagnostic carries is one the closed set publishes."""

    def test_the_set_is_sorted_and_has_no_repeat(self) -> None:
        self.assertEqual(list(REPORT_DIAGNOSTIC_CODES), sorted(set(REPORT_DIAGNOSTIC_CODES)))

    def test_every_site_names_a_code_in_the_set(self) -> None:
        codes, _, unresolved = scan()
        self.assertEqual(unresolved, [])
        self.assertEqual(set(codes) - set(REPORT_DIAGNOSTIC_CODES), set(), msg=codes)

    def test_every_code_in_the_set_is_built_somewhere(self) -> None:
        codes, _, _ = scan()
        self.assertEqual(set(REPORT_DIAGNOSTIC_CODES) - set(codes), set())

    def test_only_the_named_sites_pass_an_ingest_code_through(self) -> None:
        _, passed, _ = scan()
        self.assertEqual(passed, PASS_THROUGH)


class ScanReachTests(unittest.TestCase):
    """The scan finds a code however it reaches a diagnostic, the 6a audit's three escapes too."""

    def scan_text(self, text: str) -> tuple[dict[str, list[str]], list[str]]:
        tree = ast.parse(text)
        constructors, replacers = _aliases(tree)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        codes: dict[str, list[str]] = {}
        unresolved: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            is_site, argument = _site(node, constructors, replacers)
            if not is_site:
                continue
            function: ast.AST | None = parents.get(node)
            while function is not None and not isinstance(function, ast.FunctionDef):
                function = parents.get(function)
            for value in _resolve(argument, function, object(), tree):
                if isinstance(value, str):
                    codes.setdefault(value, []).append(str(node.lineno))
                else:
                    unresolved.append(str(node.lineno))
        return codes, unresolved

    def test_a_replace_that_sets_a_code_is_a_site(self) -> None:
        codes, _ = self.scan_text(
            "import dataclasses\n"
            "from dataclasses import replace as swap\n"
            "def f(d):\n"
            "    dataclasses.replace(d, code='one')\n"
            "    swap(d, code='two')\n"
            "    replace(d, message='not a code')\n"
        )
        self.assertEqual(set(codes), {"one", "two"})

    def test_an_aliased_or_attribute_constructor_is_a_site(self) -> None:
        codes, _ = self.scan_text(
            "from complyroll.reports import ReportDiagnostic as Note\n"
            "from complyroll.reports import vdt\n"
            "def f():\n"
            "    Note(level, 'one', 'm')\n"
            "    vdt.ReportDiagnostic(level=level, code='two', message='m')\n"
        )
        self.assertEqual(set(codes), {"one", "two"})

    def test_a_parameter_resolves_through_its_callers_alone(self) -> None:
        codes, unresolved = self.scan_text(
            "def note(code):\n"
            "    if code is None:\n"
            "        code = 'stale_case'\n"
            "    return ReportDiagnostic(level=level, code=code, message='m')\n"
            "def caller():\n"
            "    note('from_caller')\n"
            "    note(code=other)\n"
        )
        self.assertEqual(set(codes), {"from_caller"})
        self.assertEqual(len(unresolved), 1)

    def test_a_parameter_no_caller_fills_does_not_resolve(self) -> None:
        _, unresolved = self.scan_text(
            "def note(code):\n"
            "    if code is None:\n"
            "        code = 'stale_case'\n"
            "    return ReportDiagnostic(level=level, code=code, message='m')\n"
        )
        self.assertEqual(len(unresolved), 1)

    def test_a_loop_variable_does_not_resolve(self) -> None:
        _, unresolved = self.scan_text(
            "def f(items):\n    for code in items:\n        ReportDiagnostic(level, code, 'm')\n"
        )
        self.assertEqual(len(unresolved), 1)


if __name__ == "__main__":
    unittest.main()
