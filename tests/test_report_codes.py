# ******************************************************************************
# *Title: Report Diagnostic Code Tests*
# *Author: Kyle Versluis*
# *Description: Hold every code a ReportDiagnostic carries to its closed set.*
# ******************************************************************************
"""Tests for `REPORT_DIAGNOSTIC_CODES`, the closed set of diagnostic codes (CL-71).

A report prints its diagnostics in its JSON and on standard error, and the CLI prints its own
refusals and a writer's warnings as the same `level: code: message` line, so their codes are part
of the contract, as `AUDIT_FAULT_CODES` is part of `store verify`'s. The set is checked against
the source rather than at run time, so what follows is what a reader of the source can tell, not
a proof about every run. `store verify` prints audit faults and the store's integrity faults from
their own records (`fault.code`), so those codes are outside this set.

What is held. Every `ReportDiagnostic` built in `src/complyroll`, every `IngestDiagnostic` built
outside `complyroll.adapters`, by its name, an import alias or as an attribute
(`vdt.ReportDiagnostic`), and every `replace(..., code=...)`, `dataclasses.replace` and
`copy.replace` included, names a code in the set or fails. So does every string that opens a line
in the `level: code:` form (`warning: attestation_not_applicable: ...`), or ends just after it
(`print("warning: unlisted:", message)`). Every code in the set is built or written somewhere. A
site's code resolves when it is:

- a string literal, or a module-level name bound to one and rebound by no `global` statement;
- a local whose every binding in the function is a plain assignment of a literal;
- a parameter of a function that nothing outside its module imports or calls and that its own
  module only calls by name, filled by every such call with one of these. A plain assignment of a
  literal to the parameter in the body adds that literal to what it can be.

What fails, and so has to be resolved here or named. Any other binding of the local or parameter
(`+=`, `:=`, a loop, unpacking, `with`, `except`, `import`, a nested scope), a closure, a lambda's
parameter, a dictionary lookup, a conditional or a return value. A parameter its module passes as
a value, or that another module imports or reaches as an attribute. The constructor used as a
value (`Maker = ReportDiagnostic`, `partial(ReportDiagnostic, ...)`, a subclass). A `replace` used
as a value, or called with `**`. A constructor call with `*`, or that leaves its code to `**`. A
string that opens a line with a level and leaves the rest open (`f"warning: {code}: ..."`,
`"warning: "`, `"warning: %s: ..."`), unless its function is named below as writing free text. A
diagnostic an adapter mints keeps its own code when a report carries it, and a stored one read back
keeps the code it was stored with, so the sites that copy a code (`item.code`,
`_text(entry, "code")`) are named below too.

What still passes, because nothing here sees it. This is what has been found, not a closed list:
a shape not named anywhere in this docstring may pass too. `getattr(vdt, "ReportDiagnostic")`,
`vars(module)[...]`, `operator.attrgetter`, `globals()` and
`exec`; `type(item)(...)` and `item.__class__(...)`; `object.__setattr__(item, "code", ...)`; a
module-level name rebound with `setattr` or from another module; a line whose level is itself
interpolated (`f"{level}: unlisted: ..."`, as `ReportDiagnostic.render` writes every line) or split
so that no one string opens with the level (`"warn" + "ing: unlisted: ..."`,
`print("warning:", "unlisted:", message)`); a code outside the `[a-z][a-z0-9_]*` grammar in a text
line, or a level spelled another way (`Warning: `), which do not match the form at all; a
module-level name rebound after its use or read from the environment; a class-body name that
shadows a module name; `cls(...)` in a classmethod; a decorator that injects the argument; and a
caller through a star import.

What is over-counted. Any string constant that opens in the `level: code:` form counts as a line
the source writes, wherever it stands and whether or not it is ever printed, because a line held
in a name and printed later has to be seen. So an unlisted one fails even if nothing prints it, and
an unused one can keep a listed code counted as built.
"""

# *--- Imports ---*

from __future__ import annotations

import ast
import functools
import importlib
import re
import unittest
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from complyroll.reports import REPORT_DIAGNOSTIC_CODES

# *--- Fixtures ---*

SOURCE = Path(__file__).parent.parent / "src" / "complyroll"
CONSTRUCTOR = "ReportDiagnostic"
#: Held everywhere but in an adapter, whose ingest codes a report carries as its adapter's.
INGEST_CONSTRUCTOR = "IngestDiagnostic"
ADAPTERS = "complyroll.adapters"
REPLACERS = frozenset({"replace", "__replace__"})
#: A diagnostic line written as text rather than built: `warning: <code>: ...`, or a string that
#: ends after the code because the message is another argument.
TEXT_LINE = re.compile(r"^(?:error|warning|info): ([a-z][a-z0-9_]*):(?: |$)")
#: A string that opens a line with a level and leaves what follows it to be filled in.
OPEN_LINE = re.compile(r"^(?:error|warning|info): (?:%|\{|$)")
#: The functions that copy a code a diagnostic already carries: an ingest diagnostic's into a
#: report diagnostic, and a stored diagnostic's as the fold reads it back.
PASS_THROUGH = frozenset(
    {
        ("complyroll.cli", "_as_report_diagnostics"),
        ("complyroll.history.fold", "_diagnostics"),
        ("complyroll.reports.replay", "_ingest_diagnostics"),
        ("complyroll.reports.vdt", "_collect_diagnostics"),
        ("complyroll.reports.vdt", "_record_detection_failure"),
    }
)
#: The functions that write a line opening with a level whose rest is no report code: the audit's
#: and the store's faults, which print from their own records, and `stigroll`'s free text.
FREE_TEXT = frozenset(
    {
        ("complyroll.cli", "verify"),
        ("complyroll.compat.stigroll", "main"),
    }
)

Function = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


# *--- Helpers ---*


@dataclass(frozen=True)
class Module:
    """One parsed module, what its names hold at run time, and each node's parent."""

    name: str
    label: str
    tree: ast.Module
    value: object
    parents: dict[ast.AST, ast.AST]


def module_of(name: str, label: str, tree: ast.Module, value: object) -> Module:
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    return Module(name, label, tree, value, parents)


def _module_name(path: Path) -> str:
    parts = path.relative_to(SOURCE.parent).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _is_adapter(name: str) -> bool:
    return name == ADAPTERS or name.startswith(f"{ADAPTERS}.")


def _aliases(module: Module) -> tuple[set[str], set[str]]:
    """Return the names the constructors and `dataclasses.replace` are bound to in a module."""
    classes = {CONSTRUCTOR} if _is_adapter(module.name) else {CONSTRUCTOR, INGEST_CONSTRUCTOR}
    constructors, replacers = set(classes), set(REPLACERS)
    for node in ast.walk(module.tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in classes:
                    constructors.add(alias.asname or alias.name)
                if alias.name == "replace" and node.module in ("dataclasses", "copy"):
                    replacers.add(alias.asname or alias.name)
    return constructors, replacers


def _enclosing(node: ast.AST, module: Module) -> Function | None:
    current = module.parents.get(node)
    while current is not None and not isinstance(current, Function):
        current = module.parents.get(current)
    return current


def _parameters(function: Function) -> list[str]:
    """Return the names a function binds on entry, positional ones first and in order."""
    args = function.args
    named = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    extras = [item for item in (args.vararg, args.kwarg) if item is not None]
    return [item.arg for item in (*named, *extras)]


def _literal_assignment(node: ast.AST, name: str) -> ast.Constant | None:
    """Return the literal when a node is `name = <literal>`, with or without an annotation."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target: ast.expr = node.targets[0]
    elif isinstance(node, ast.AnnAssign):
        target = node.target
    else:
        return None
    named = isinstance(target, ast.Name) and target.id == name
    return node.value if named and isinstance(node.value, ast.Constant) else None


def _binds_otherwise(node: ast.AST, name: str, function: Function, literal: set[ast.AST]) -> bool:
    """Say whether a node binds `name` in a way the scan cannot read as a literal."""
    if isinstance(node, ast.Name):
        return node.id == name and not isinstance(node.ctx, ast.Load) and node not in literal
    if isinstance(node, ast.arg):
        return node.arg == name and node not in _own_arguments(function)
    if isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar):
        return node.name == name
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    if isinstance(node, ast.alias):
        return (node.asname or node.name) == name
    if isinstance(node, ast.Global | ast.Nonlocal):
        return name in node.names
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return node.name == name and node is not function
    return False


def _own_arguments(function: Function) -> list[ast.arg]:
    args = function.args
    named = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    return [*named, *(item for item in (args.vararg, args.kwarg) if item is not None)]


def _bindings(function: Function, name: str) -> tuple[list[object], bool]:
    """Return the literals a function assigns a name, and whether anything else binds it."""
    literals: list[object] = []
    targets: set[ast.AST] = set()
    for node in ast.walk(function):
        constant = _literal_assignment(node, name)
        if constant is not None:
            literals.append(constant.value)
            assign = node
            assert isinstance(assign, ast.Assign | ast.AnnAssign)
            targets.add(assign.targets[0] if isinstance(assign, ast.Assign) else assign.target)
    other = any(_binds_otherwise(node, name, function, targets) for node in ast.walk(function))
    return literals, other


def _is_called(node: ast.AST, module: Module) -> bool:
    parent = module.parents.get(node)
    return isinstance(parent, ast.Call) and parent.func is node


def _reached_otherwise(function: Function, modules: Sequence[Module], module: Module) -> bool:
    """Say whether a function can be reached by anything but a call by name in its own module."""
    assert not isinstance(function, ast.Lambda)
    name = function.name
    for other in modules:
        for node in ast.walk(other.tree):
            if isinstance(node, ast.Attribute) and node.attr == name:
                return True
            if other is module:
                loaded = isinstance(node, ast.Name) and node.id == name
                if loaded and not _is_called(node, module):
                    return True
            elif isinstance(node, ast.ImportFrom):
                if any(alias.name == name for alias in node.names):
                    return True
    return False


def _argument_for(call: ast.Call, name: str, position: int | None) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    if position is None or any(isinstance(item, ast.Starred) for item in call.args):
        return None
    return call.args[position] if len(call.args) > position else None


def _from_callers(
    function: Function, name: str, module: Module, modules: Sequence[Module], depth: int
) -> list[object]:
    """Return what every call in a function's module can fill one of its parameters with."""
    if isinstance(function, ast.Lambda) or _reached_otherwise(function, modules, module):
        return [None]
    args = function.args
    ordered = [item.arg for item in (*args.posonlyargs, *args.args)]
    position = ordered.index(name) if name in ordered else None
    found: list[object] = []
    for node in ast.walk(module.tree):
        called = isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        if called and node.func.id == function.name:
            argument = _argument_for(node, name, position)
            found.extend(_resolve(argument, node, module, modules, depth + 1))
    return found or [None]


def _closes_over(name: str, node: ast.AST, module: Module) -> bool:
    """Say whether a function outside the innermost one around a node binds `name`."""
    function = _enclosing(node, module)
    outer = None if function is None else _enclosing(function, module)
    while outer is not None:
        if name in _parameters(outer) or any(_bindings(outer, name)):
            return True
        outer = _enclosing(outer, module)
    return False


def _resolve(
    expression: ast.expr | None,
    site: ast.AST,
    module: Module,
    modules: Sequence[Module],
    depth: int = 0,
) -> list[object]:
    """Return every value a code expression at a site can take, None where it cannot be told."""
    if isinstance(expression, ast.Constant):
        return [expression.value]
    if not isinstance(expression, ast.Name) or depth > 3:
        return [None]
    name = expression.id
    function = _enclosing(site, module)
    if function is not None:
        literals, other = _bindings(function, name)
        if other or _closes_over(name, site, module):
            return [None]
        if name in _parameters(function):
            return [*literals, *_from_callers(function, name, module, modules, depth)]
        if literals:
            return literals
    rebound = any(
        isinstance(node, ast.Global) and name in node.names for node in ast.walk(module.tree)
    )
    return [None] if rebound else [getattr(module.value, name, None)]


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
    if called in constructors:
        return True, _argument_for(node, "code", 1)
    if called in replacers:
        if any(keyword.arg == "code" for keyword in node.keywords):
            return True, _argument_for(node, "code", None)
        return any(keyword.arg is None for keyword in node.keywords), None
    return False, None


def _is_type_use(node: ast.AST, module: Module, annotations: set[ast.AST]) -> bool:
    """Say whether a use of a class only names its type, in an annotation or `isinstance`."""
    if node in annotations:
        return True
    parent = module.parents.get(node)
    if isinstance(parent, ast.Tuple):
        parent = module.parents.get(parent)
    return (
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Name)
        and parent.func.id == "isinstance"
    )


def _value_uses(module: Module, constructors: set[str], replacers: set[str]) -> list[str]:
    """Return each place the constructor or a `replace` stands as a value rather than a call."""
    annotations: set[ast.AST] = set()
    for node in ast.walk(module.tree):
        for annotation in (getattr(node, "annotation", None), getattr(node, "returns", None)):
            if isinstance(annotation, ast.AST):
                annotations.update(ast.walk(annotation))
    # `.replace` is everywhere on strings, so a bare name is held only as `replace` or an alias.
    imported = (replacers - REPLACERS) | {"replace"}
    found: list[str] = []
    for node in ast.walk(module.tree):
        is_class = (isinstance(node, ast.Name) and node.id in constructors) or (
            isinstance(node, ast.Attribute) and node.attr in constructors
        )
        is_replace = (isinstance(node, ast.Name) and node.id in imported) or (
            isinstance(node, ast.Attribute) and node.attr in REPLACERS
        )
        if is_replace and _is_called(node, module):
            continue
        if is_class and (_is_called(node, module) or _is_type_use(node, module, annotations)):
            continue
        if is_class or is_replace:
            found.append(f"{module.label}:{node.lineno}")
    return found


def _copies_a_code(argument: ast.expr | None) -> bool:
    """Say whether a code expression copies one a diagnostic carries or a store holds."""
    if isinstance(argument, ast.Attribute):
        return argument.attr == "code"
    if not isinstance(argument, ast.Call) or len(argument.args) != 2:
        return False
    key = argument.args[1]
    return isinstance(key, ast.Constant) and key.value == "code"


def _text_lines(module: Module) -> tuple[set[tuple[int, str]], set[tuple[str, str]], list[str]]:
    """Return each line a module opens as text: its code, its free-text writers, open ones."""
    found: set[tuple[int, str]] = set()
    free: set[tuple[str, str]] = set()
    opened: list[str] = []
    for node in ast.walk(module.tree):
        text = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.JoinedStr) and node.values:
            head = node.values[0]
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                text = head.value
        if text is None:
            continue
        matched = TEXT_LINE.match(text)
        if matched is not None:
            found.add((node.lineno, matched.group(1)))
        elif OPEN_LINE.match(text) is not None:
            function = _enclosing(node, module)
            owner = (module.name, getattr(function, "name", ""))
            if owner in FREE_TEXT:
                free.add(owner)
            else:
                opened.append(f"{module.label}:{node.lineno}")
    return found, free, opened


@dataclass(frozen=True)
class Scan:
    """Each resolved code's sites, the named sites each kind reached, and what did not resolve."""

    codes: dict[str, list[str]]
    passed: set[tuple[str, str]]
    free: set[tuple[str, str]]
    unresolved: list[str]


def scan_modules(modules: Sequence[Module]) -> Scan:
    """Scan parsed modules together, since a parameter's callers can be in any of them."""
    result = Scan({}, set(), set(), [])
    for module in modules:
        constructors, replacers = _aliases(module)
        lines, free, opened = _text_lines(module)
        for line, code in lines:
            result.codes.setdefault(code, []).append(f"{module.label}:{line}")
        result.free.update(free)
        result.unresolved.extend(opened)
        result.unresolved.extend(_value_uses(module, constructors, replacers))
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.Call):
                continue
            is_site, argument = _site(node, constructors, replacers)
            if not is_site:
                continue
            site = f"{module.label}:{node.lineno}"
            function = _enclosing(node, module)
            if _copies_a_code(argument) and isinstance(function, ast.FunctionDef):
                result.passed.add((module.name, function.name))
                continue
            for value in _resolve(argument, node, module, modules):
                if isinstance(value, str):
                    result.codes.setdefault(value, []).append(site)
                else:
                    result.unresolved.append(site)
    return result


@functools.cache
def scan() -> Scan:
    """Scan every module under `src/complyroll`, once per test run, since the tests only read."""
    modules = []
    for path in sorted(SOURCE.rglob("*.py")):
        name = _module_name(path)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        modules.append(
            module_of(name, str(path.relative_to(SOURCE)), tree, importlib.import_module(name))
        )
    return scan_modules(modules)


# *--- Tests ---*


class ReportDiagnosticCodeTests(unittest.TestCase):
    """Every code a diagnostic carries is one the closed set publishes."""

    def test_the_set_is_sorted_and_has_no_repeat(self) -> None:
        self.assertEqual(list(REPORT_DIAGNOSTIC_CODES), sorted(set(REPORT_DIAGNOSTIC_CODES)))

    def test_every_site_names_a_code_in_the_set(self) -> None:
        result = scan()
        self.assertEqual(result.unresolved, [])
        self.assertEqual(set(result.codes) - set(REPORT_DIAGNOSTIC_CODES), set(), msg=result.codes)

    def test_every_code_in_the_set_is_built_somewhere(self) -> None:
        self.assertEqual(set(REPORT_DIAGNOSTIC_CODES) - set(scan().codes), set())

    def test_only_the_named_sites_pass_an_ingest_code_through(self) -> None:
        self.assertEqual(scan().passed, PASS_THROUGH)

    def test_only_the_named_functions_write_free_text(self) -> None:
        self.assertEqual(scan().free, FREE_TEXT)

    def test_the_writer_warnings_are_in_the_set(self) -> None:
        # The CLI used to prefix these with `f"warning: {warning}"`, so nothing saw them.
        codes = scan().codes
        for code in (
            "identification_retained",
            "disposition_retained",
            "failure_held_by_another_stream",
            "reduction_retained",
        ):
            with self.subTest(code=code):
                self.assertIn(code, REPORT_DIAGNOSTIC_CODES)
                self.assertTrue(any("history/writers.py" in site for site in codes[code]))


class ScanReachTests(unittest.TestCase):
    """The scan finds a code however it reaches a diagnostic, each audit escape among them."""

    def scan_text(self, text: str, **others: str) -> tuple[dict[str, list[str]], list[str]]:
        """Scan one source, beside others named by keyword that may call into it."""
        modules = [module_of("first", "first", ast.parse(text), object())]
        modules += [
            module_of(name, name, ast.parse(source), object()) for name, source in others.items()
        ]
        result = scan_modules(modules)
        return result.codes, result.unresolved

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

    def test_a_parameter_resolves_through_its_callers_and_its_literal_assignments(self) -> None:
        codes, unresolved = self.scan_text(
            "def note(code):\n"
            "    if code is None:\n"
            "        code = 'stale_case'\n"
            "    return ReportDiagnostic(level=level, code=code, message='m')\n"
            "def caller():\n"
            "    note('from_caller')\n"
            "    note(code=other)\n"
        )
        self.assertEqual(set(codes), {"from_caller", "stale_case"})
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

    def test_a_binding_other_than_a_literal_does_not_resolve(self) -> None:
        for binding in (
            "code = other",
            "code += '_more'",
            "(code := other)",
            "code, rest = pair",
            "with thing as code: pass",
            "import code",
        ):
            with self.subTest(binding=binding):
                _, unresolved = self.scan_text(
                    "def f():\n"
                    "    code = 'listed'\n"
                    f"    {binding}\n"
                    "    ReportDiagnostic(level, code, 'm')\n"
                )
                self.assertTrue(unresolved)

    def test_a_parameter_rebound_other_than_by_a_literal_does_not_resolve(self) -> None:
        for binding in ("code = other", "code += '_more'", "(code := other)"):
            with self.subTest(binding=binding):
                _, unresolved = self.scan_text(
                    "def note(code):\n"
                    f"    {binding}\n"
                    "    return ReportDiagnostic(level, code, 'm')\n"
                    "note('listed')\n"
                )
                self.assertTrue(unresolved)

    def test_a_keyword_only_parameter_is_a_parameter(self) -> None:
        codes, unresolved = self.scan_text(
            "code = 'module_value'\n"
            "def note(*, code):\n"
            "    return ReportDiagnostic(level, code, 'm')\n"
            "note(code='from_caller')\n"
        )
        self.assertEqual((set(codes), unresolved), ({"from_caller"}, []))

    def test_a_caller_resolves_its_argument_in_its_own_scope(self) -> None:
        # Read as a module name, a caller's local would borrow the module's value.
        modules = [
            module_of(
                "first",
                "first",
                ast.parse(
                    "def note(code):\n"
                    "    return ReportDiagnostic(level, code, 'm')\n"
                    "def caller(code):\n"
                    "    note(code)\n"
                ),
                type("Value", (), {"code": "module_value"}),
            )
        ]
        result = scan_modules(modules)
        self.assertEqual(set(result.codes), set())
        self.assertTrue(result.unresolved)

    def test_a_closure_does_not_resolve(self) -> None:
        modules = [
            module_of(
                "first",
                "first",
                ast.parse(
                    "def outer(code):\n"
                    "    def inner():\n"
                    "        ReportDiagnostic(level, code, 'm')\n"
                    "outer('listed')\n"
                ),
                type("Value", (), {"code": "module_value"}),
            )
        ]
        result = scan_modules(modules)
        self.assertEqual(set(result.codes), set())
        self.assertTrue(result.unresolved)

    def test_a_lambda_parameter_does_not_resolve(self) -> None:
        _, unresolved = self.scan_text("note = lambda code: ReportDiagnostic(level, code, 'm')\n")
        self.assertTrue(unresolved)

    def test_any_other_expression_does_not_resolve(self) -> None:
        for expression in ("CODES['one']", "'one' if flag else 'two'", "code_of()", "item.other"):
            with self.subTest(expression=expression):
                _, unresolved = self.scan_text(f"ReportDiagnostic(level, {expression}, 'm')\n")
                self.assertTrue(unresolved)

    def test_a_parameter_filled_from_another_module_does_not_resolve(self) -> None:
        for name, other in (
            ("imported", "from first import note\nnote('unlisted')\n"),
            ("attribute", "import first\nfirst.note('unlisted')\n"),
        ):
            with self.subTest(name):
                _, unresolved = self.scan_text(
                    "def note(code):\n"
                    "    return ReportDiagnostic(level, code, 'm')\n"
                    "note('listed')\n",
                    other=other,
                )
                self.assertTrue(unresolved)

    def test_a_parameter_whose_function_is_passed_as_a_value_does_not_resolve(self) -> None:
        _, unresolved = self.scan_text(
            "def note(code):\n"
            "    return ReportDiagnostic(level, code, 'm')\n"
            "note('listed')\n"
            "handler = note\n"
        )
        self.assertTrue(unresolved)

    def test_the_constructor_as_a_value_does_not_resolve(self) -> None:
        for source in (
            "Maker = ReportDiagnostic\n",
            "partial(ReportDiagnostic, code='unlisted')\n",
            "partial(vdt.ReportDiagnostic, code='unlisted')\n",
            "class Sub(ReportDiagnostic): pass\n",
        ):
            with self.subTest(source=source):
                self.assertTrue(self.scan_text(source)[1])

    def test_the_constructor_as_a_type_is_not_a_value(self) -> None:
        _, unresolved = self.scan_text(
            "from dataclasses import dataclass\n"
            "def f(item: ReportDiagnostic) -> list[ReportDiagnostic]:\n"
            "    found: tuple[ReportDiagnostic, ...] = ()\n"
            "    isinstance(item, ReportDiagnostic)\n"
            "    return isinstance(item, (int, vdt.ReportDiagnostic))\n"
        )
        self.assertEqual(unresolved, [])

    def test_a_replace_with_double_star_or_as_a_value_does_not_resolve(self) -> None:
        for source in (
            "from dataclasses import replace\nreplace(d, **{'code': 'unlisted'})\n",
            "import dataclasses\ndataclasses.replace(d, **changes)\n",
            "from dataclasses import replace\npartial(replace, code='unlisted')\n",
            "import dataclasses\nalias = dataclasses.replace\n",
        ):
            with self.subTest(source=source):
                self.assertTrue(self.scan_text(source)[1])

    def test_a_star_argument_does_not_resolve(self) -> None:
        for call in (
            "ReportDiagnostic(*args)",
            "ReportDiagnostic(level, *rest)",
            "ReportDiagnostic(*args, 'unlisted', 'm')",
            "ReportDiagnostic(**fields)",
        ):
            with self.subTest(call=call):
                self.assertTrue(self.scan_text(f"{call}\n")[1])

    def test_a_line_left_open_after_its_level_does_not_resolve(self) -> None:
        for source in (
            "say(f'warning: {code}: m')\n",
            "say('warning: ' + code)\n",
            "say('error: %s: m' % code)\n",
            "say('info: {}: m'.format(code))\n",
        ):
            with self.subTest(source=source):
                codes, unresolved = self.scan_text(source)
                self.assertEqual((codes, len(unresolved) > 0), ({}, True))

    def test_a_named_free_text_writer_is_not_an_open_line(self) -> None:
        module = module_of(
            "complyroll.compat.stigroll",
            "stigroll",
            ast.parse("def main():\n    say(f'warning: {path} not found')\n"),
            object(),
        )
        result = scan_modules([module])
        self.assertEqual(result.unresolved, [])
        self.assertEqual(result.free, {("complyroll.compat.stigroll", "main")})

    def test_a_line_with_a_literal_code_counts_wherever_it_stands(self) -> None:
        # Held in a name and printed later it still has to be seen, so any constant counts.
        codes, _ = self.scan_text("NOT_PRINTED = 'warning: held_line: m'\n")
        self.assertEqual(set(codes), {"held_line"})

    def test_a_line_that_ends_after_its_code_is_a_line(self) -> None:
        # The message is the next argument, so the string never carries a space after the colon.
        codes, _ = self.scan_text("print('warning: unlisted_line:', message)\n")
        self.assertEqual(set(codes), {"unlisted_line"})

    def test_every_level_opens_a_line(self) -> None:
        for level in ("error", "warning", "info"):
            with self.subTest(level=level):
                codes, _ = self.scan_text(f"NOTE = '{level}: one_code: m'\n")
                self.assertEqual(set(codes), {"one_code"})

    def test_an_except_or_match_capture_does_not_resolve(self) -> None:
        for binding in (
            "try:\n        pass\n    except Exception as code:\n        pass",
            "match thing:\n        case code:\n            pass",
            "match thing:\n        case [*code]:\n            pass",
        ):
            with self.subTest(binding=binding):
                _, unresolved = self.scan_text(
                    "def f(thing):\n"
                    "    code = 'listed'\n"
                    f"    {binding}\n"
                    "    ReportDiagnostic(level, code, 'm')\n"
                )
                self.assertTrue(unresolved)

    def test_a_nested_definition_of_the_name_does_not_resolve(self) -> None:
        for definition in ("def code(): pass", "class code: pass"):
            with self.subTest(definition=definition):
                _, unresolved = self.scan_text(
                    "def f():\n"
                    "    code = 'listed'\n"
                    f"    {definition}\n"
                    "    ReportDiagnostic(level, code, 'm')\n"
                )
                self.assertTrue(unresolved)

    def test_a_match_rest_capture_does_not_resolve(self) -> None:
        _, unresolved = self.scan_text(
            "def f(thing):\n"
            "    code = 'listed'\n"
            "    match thing:\n"
            "        case {**code}:\n"
            "            pass\n"
            "    ReportDiagnostic(level, code, 'm')\n"
        )
        self.assertTrue(unresolved)

    def test_a_copy_replace_alias_is_a_site(self) -> None:
        codes, _ = self.scan_text(
            "from copy import replace as swap\ndef f(d):\n    swap(d, code='one')\n"
        )
        self.assertEqual(set(codes), {"one"})

    def test_a_dunder_replace_is_a_site(self) -> None:
        codes, _ = self.scan_text("def f(d):\n    d.__replace__(code='one')\n")
        self.assertEqual(set(codes), {"one"})

    def test_an_ingest_diagnostic_outside_the_adapters_is_held(self) -> None:
        for source in (
            "IngestDiagnostic(level, 'one', 'm')\n",
            "from complyroll.adapters import IngestDiagnostic as Note\nNote(level, code='one')\n",
            "adapters.IngestDiagnostic(level, code='one', message='m')\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(set(self.scan_text(source)[0]), {"one"})
        self.assertTrue(self.scan_text("Maker = IngestDiagnostic\n")[1])

    def test_an_ingest_diagnostic_in_an_adapter_keeps_its_own_code(self) -> None:
        source = (
            "IngestDiagnostic(level, 'adapter_code', 'm')\n"
            "adapters.IngestDiagnostic(level, 'adapter_code', 'm')\n"
            "Maker = IngestDiagnostic\n"
        )
        for name in ("complyroll.adapters", "complyroll.adapters.sarif"):
            with self.subTest(name=name):
                result = scan_modules([module_of(name, name, ast.parse(source), object())])
                self.assertEqual((result.codes, result.unresolved), ({}, []))

    def test_a_code_read_back_from_a_store_is_a_named_copy_not_a_new_code(self) -> None:
        module = module_of(
            "first",
            "first",
            ast.parse(
                "def read(entry):\n"
                "    return IngestDiagnostic(level, code=_text(entry, 'code'), message='m')\n"
            ),
            object(),
        )
        result = scan_modules([module])
        self.assertEqual((result.codes, result.unresolved), ({}, []))
        self.assertEqual(result.passed, {("first", "read")})

    def test_a_code_read_any_other_way_does_not_resolve(self) -> None:
        for expression in ("entry['code']", "_text(entry, 'other')", "_text(entry)"):
            with self.subTest(expression=expression):
                _, unresolved = self.scan_text(
                    f"def read(entry):\n    return IngestDiagnostic(level, {expression}, 'm')\n"
                )
                self.assertTrue(unresolved)

    def test_a_module_name_rebound_by_a_global_statement_does_not_resolve(self) -> None:
        modules = [
            module_of(
                "first",
                "first",
                ast.parse(
                    "CODE = 'listed'\n"
                    "def rebind():\n"
                    "    global CODE\n"
                    "    CODE = 'unlisted'\n"
                    "ReportDiagnostic(level, CODE, 'm')\n"
                ),
                type("Value", (), {"CODE": "listed"}),
            )
        ]
        self.assertTrue(scan_modules(modules).unresolved)


if __name__ == "__main__":
    unittest.main()
