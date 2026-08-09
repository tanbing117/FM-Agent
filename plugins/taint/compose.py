"""Call-site composition helpers for Taint plugin.

Extracted from TaintPlugin compose_calls and its helper functions in taint.py.
"""

import ast
import re
import textwrap
from typing import Optional

from .ast_utils import call_terminal, compact_expr, operation_dominates_sink, python_function, scope_nodes


def match_call_site(caller_call_sites, callee_name):
    """Find the caller's LLM-recorded call_site facts for a callee (by name)."""
    for cs in caller_call_sites or []:
        c = (cs.get("callee") or "")
        if c == callee_name or c.endswith("." + callee_name) or c.split(".")[-1] == callee_name:
            return cs
    return None


def has_call_operation(source: str, function_name: str, language: str) -> bool:
    """Reject regex call-graph edges caused by declarations and comments."""
    if language.lower() == "python":
        from .ast_utils import python_calls as _python_calls
        return any(
            (isinstance(call, ast.Name) and call.id == function_name)
            or (isinstance(call, ast.Attribute) and call.attr == function_name)
            for call in _python_calls(source)
        )
    uncommented = re.sub(r"(?m)(#|//).*?$", "", source)
    return bool(re.search(rf"\b{re.escape(function_name)}\s*\(", uncommented))


def has_same_name_body_call(source: str, function_name: str, language: str) -> bool:
    """Only a bare same-name call is recursion; member dispatch is ambiguous."""
    if language.lower() == "python":
        from .ast_utils import python_calls as _python_calls
        return any(
            isinstance(call, ast.Name) and call.id == function_name
            for call in _python_calls(source)
        )
    uncommented = re.sub(r"(?m)(#|//).*?$", "", source)
    return len(re.findall(rf"\b{re.escape(function_name)}\s*\(", uncommented)) > 1


def source_validated_must_scan_inputs(source: str) -> set[str]:
    from .normalize import source_must_scan_contracts
    return {
        contract["input_expr"]
        for contract in source_must_scan_contracts(source).values()
    }


def call_actual_for_param(call: ast.Call, function: ast.AST, param_name: str):
    params = [
        arg.arg for arg in [*function.args.posonlyargs, *function.args.args]
        if arg.arg not in {"self", "cls"}
    ]
    if param_name not in params:
        return None
    keyword = next((item.value for item in call.keywords if item.arg == param_name), None)
    if keyword is not None:
        return keyword
    position = params.index(param_name)
    return call.args[position] if position < len(call.args) else None


def propagate_source_validated_callee_guard(
    caller_source: str,
    callee_source: str,
    callee_name: str,
    caller_sinks: list,
) -> None:
    validated_inputs = source_validated_must_scan_inputs(callee_source)
    callee_function = python_function(callee_source)
    if not validated_inputs or callee_function is None:
        return
    try:
        tree = ast.parse(textwrap.dedent(caller_source))
    except SyntaxError:
        return
    scopes = [tree, *(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )]
    callee_terminal = callee_name.lower().rsplit(".", 1)[-1]
    for scope in scopes:
        nodes = scope_nodes(scope)
        helper_calls = [
            node for node in nodes
            if isinstance(node, ast.Call) and call_terminal(node) == callee_terminal
        ]
        if not helper_calls:
            continue
        for sink in caller_sinks:
            if (
                not isinstance(sink, dict)
                or sink.get("_via")
                or sink.get("sink_kind") != "deserialize"
                or not isinstance(sink.get("arg_expr"), str)
            ):
                continue
            expected_callee = str(sink.get("callee") or "").lower().rsplit(".", 1)[-1]
            sink_calls = [
                node for node in nodes
                if isinstance(node, ast.Call)
                and call_terminal(node) == expected_callee
                and node.args
                and compact_expr(node.args[0]) == compact_expr(sink["arg_expr"])
            ]
            for helper_call in helper_calls:
                for input_expr in validated_inputs:
                    actual = call_actual_for_param(helper_call, callee_function, input_expr)
                    if actual is None or compact_expr(actual) != compact_expr(sink["arg_expr"]):
                        continue
                    if any(
                        helper_call.lineno < sink_call.lineno
                        and operation_dominates_sink(nodes, helper_call, sink_call)
                        for sink_call in sink_calls
                    ):
                        sink["_validation_guard_coverage"] = "must"
                        break
                if sink.get("_validation_guard_coverage") == "must":
                    break
