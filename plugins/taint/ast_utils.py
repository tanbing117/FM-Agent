"""AST utility functions for Python source analysis.

Extracted from TaintPlugin helpers in src/plugins/taint.py.
These operate on Python AST nodes and are theory-agnostic.
"""

import ast
import re
import textwrap
from typing import Optional


def python_calls(source: str) -> list:
    """Return all ast.Call nodes in the function body."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return []
    return [node.func for node in ast.walk(tree) if isinstance(node, ast.Call)]


def python_function(source: str):
    """Return the first FunctionDef/AsyncFunctionDef node in the source."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return None
    return next(
        (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ),
        None,
    )


def call_terminal(call: ast.Call) -> str:
    """Extract the terminal function name from a call expression."""
    return ast.unparse(call.func).lower().rsplit(".", 1)[-1]


def scope_nodes(scope) -> list:
    """Recursively collect all AST nodes in a scope, stopping at child functions."""
    nodes = []

    def collect(node):
        if node is not scope and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            return
        nodes.append(node)
        for child in ast.iter_child_nodes(node):
            collect(child)

    collect(scope)
    return nodes


def block_terminates(body: list) -> bool:
    """Check whether a statement block always terminates (raise/return/full-if)."""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Raise, ast.Return)):
        return True
    return (
        isinstance(last, ast.If)
        and block_terminates(last.body)
        and block_terminates(last.orelse)
    )


def compact_expr(value) -> str:
    """Normalize an AST node or string to a compact lowercase form."""
    if isinstance(value, ast.AST):
        value = ast.unparse(value)
    return re.sub(r"\s+", "", str(value or "")).lower()


def node_parents(nodes: list) -> dict:
    """Build a mapping from each node to its parent among the given nodes."""
    node_set = set(nodes)
    return {
        child: parent
        for parent in nodes
        for child in ast.iter_child_nodes(parent)
        if child in node_set
    }


def control_context(nodes: list, operation: ast.AST) -> dict:
    """Track which branch (body/orelse etc.) an operation sits in for each node."""
    parents = node_parents(nodes)
    context = {}
    child = operation
    while child in parents:
        parent = parents[child]
        branch = None
        if isinstance(parent, ast.If):
            branch = "body" if child in parent.body else "orelse" if child in parent.orelse else None
        elif isinstance(parent, (ast.For, ast.AsyncFor, ast.While)):
            branch = "body" if child in parent.body else "orelse" if child in parent.orelse else None
        elif isinstance(parent, ast.Try):
            if child in parent.body:
                branch = "body"
            elif child in parent.orelse:
                branch = "orelse"
            elif child in parent.finalbody:
                branch = "finalbody"
            elif child in parent.handlers:
                branch = f"handler:{parent.handlers.index(child)}"
        if branch is not None:
            context[parent] = branch
        child = parent
    return context


def same_control_context(nodes: list, left: ast.AST, right: ast.AST) -> bool:
    return control_context(nodes, left) == control_context(nodes, right)


def operation_dominates_sink(nodes: list, operation: ast.AST, sink: ast.AST) -> bool:
    """Check whether an operation's control context covers the sink's."""
    op_ctx = control_context(nodes, operation)
    sink_ctx = control_context(nodes, sink)
    return all(sink_ctx.get(parent) == branch for parent, branch in op_ctx.items())


def boolean_param_condition(test: ast.AST) -> Optional[tuple[str, bool, bool]]:
    """Return how a simple boolean-param test evaluates for True and False."""
    if isinstance(test, ast.Name):
        return test.id, True, False
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        condition = boolean_param_condition(test.operand)
        if condition is not None:
            name, when_true, when_false = condition
            return name, not when_true, not when_false
    if (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Name)
        and test.func.id == "bool"
        and len(test.args) == 1
        and not test.keywords
    ):
        return boolean_param_condition(test.args[0])
    if isinstance(test, ast.Compare) and len(test.ops) == len(test.comparators) == 1:
        left, right = test.left, test.comparators[0]
        if isinstance(right, ast.Name) and isinstance(left, ast.Constant):
            left, right = right, left
        if not (
            isinstance(left, ast.Name)
            and isinstance(right, ast.Constant)
            and isinstance(right.value, bool)
        ):
            return None
        op = test.ops[0]
        if isinstance(op, (ast.Eq, ast.Is)):
            return left.id, True == right.value, False == right.value
        if isinstance(op, (ast.NotEq, ast.IsNot)):
            return left.id, True != right.value, False != right.value
    return None


def default_enabled_params(scope: ast.AST) -> set[str]:
    """Find parameters whose default value is True."""
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return set()
    positional = [*scope.args.posonlyargs, *scope.args.args]
    defaults = [None] * (len(positional) - len(scope.args.defaults)) + list(scope.args.defaults)
    pairs = [*zip(positional, defaults), *zip(scope.args.kwonlyargs, scope.args.kw_defaults)]
    return {
        arg.arg for arg, default in pairs
        if isinstance(default, ast.Constant) and default.value is True
    }


def scan_guard_attributes(test: ast.AST, result_name: str) -> set[str]:
    """Collect attribute names checked for scan-result status."""
    attributes = {
        node.id.lower() for node in ast.walk(test) if isinstance(node, ast.Name)
    }
    for node in ast.walk(test):
        if not isinstance(node, ast.Attribute):
            continue
        root = node.value
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and (not result_name or root.id == result_name):
            attributes.add(node.attr.lower())
    return attributes


def scan_exception_is_fail_open(nodes: list, scan_assignment: ast.AST) -> bool:
    """Check whether a scan operation's exceptions are handled fail-open."""
    for node in nodes:
        if not isinstance(node, ast.Try):
            continue
        if not any(
            any(candidate is scan_assignment for candidate in ast.walk(statement))
            for statement in node.body
        ):
            continue
        if any(not block_terminates(handler.body) for handler in node.handlers):
            return True
    return False


def source_backed_call_terminal(call_expr, tree: ast.AST) -> Optional[str]:
    """Verify a call_expr string matches an actual AST call and return its terminal."""
    if not isinstance(call_expr, str) or not call_expr.strip():
        return None
    try:
        modeled = ast.parse(call_expr.strip(), mode="eval").body
    except SyntaxError:
        return None
    if not isinstance(modeled, ast.Call):
        return None
    modeled_expr = compact_expr(modeled)
    if not any(
        isinstance(node, ast.Call) and compact_expr(node) == modeled_expr
        for node in ast.walk(tree)
    ):
        return None
    return call_terminal(modeled)


def function_params(unit) -> list:
    """Parse Python function parameter names from a FunctionUnit."""
    if unit.id.language.lower() != "python":
        return list(unit.params)
    function = python_function(unit.source)
    if function is None:
        return list(unit.params)
    params = [*function.args.posonlyargs, *function.args.args]
    return [arg.arg for arg in params if arg.arg not in {"self", "cls"}]
