"""Taint sink normalization — filter model hallucinations and correct known shapes.

Extracted from TaintPlugin._normalize_operation_sinks and its helper functions.
"""

import ast
import re
import textwrap

from .ast_utils import (
    block_terminates,
    boolean_param_condition,
    call_terminal,
    compact_expr,
    control_context,
    default_enabled_params,
    operation_dominates_sink,
    same_control_context,
    scan_exception_is_fail_open,
    scan_guard_attributes,
    scope_nodes,
    source_backed_call_terminal,
)


def is_static_config_pseudosource(source_record: dict, source: str) -> bool:
    """Recognize application constants (config.NAME) independent of model label."""
    expr = source_record.get("expr")
    if not isinstance(expr, str) or re.fullmatch(
        r"config\.[A-Za-z_][A-Za-z0-9_]*", expr.strip()
    ) is None:
        return False
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return False
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and compact_expr(node) == compact_expr(expr)
    ]
    return bool(matches) and all(isinstance(node.ctx, ast.Load) for node in matches)


def source_proven_sink_kinds(source: str) -> set[str]:
    """Return sink families backed by concrete operations in the function source."""
    source_lower = source.lower()
    proven = set()
    markers = {
        "sql_query": (".execute(", ".executemany(", ".raw(", " raw("),
        "shell_command": (
            "os.system(", "exec(", "eval(", "shell=true", "shell = true",
        ),
        "subprocess_argv": (
            "subprocess.run(", "subprocess.call(", "subprocess.popen(",
            "check_call(", "check_output(",
        ),
        "fs_path": (
            "open(", ".read_text(", ".write_text(", ".unlink(", "send_file(",
            "shutil.", "os.remove(", "os.rename(", "os.replace(",
        ),
        "http_url_ssrf": (
            "requests.get(", "requests.post(", "requests.request(", "httpx.get(",
            "httpx.post(", "httpx.request(", "urlopen(", "urllib.request(",
        ),
        "redirect_location": ("redirect(", "redirectresponse("),
        "html_output": (
            "render_template(", "render_template_string(", "document.write(",
            ".innerhtml", "dangerouslysetinnerhtml", "httpresponse(",
            "make_response(", "response.write(", "markup(", "mark_safe(",
        ),
        "template_source": ("render_template_string(", "template(", "from_string("),
        "deserialize": (
            "pickle.load", "torch.load(", "torch_load(", "yaml.load(",
            "scan_file_path(",
        ),
        "code_eval": ("exec(", "eval("),
        "xpath": (".xpath(", "xpath(", "findall("),
    }
    for sink_kind, operations in markers.items():
        if any(operation in source_lower for operation in operations):
            proven.add(sink_kind)
    if "search_filter" in source_lower and (
        ".search(" in source_lower or "ldap_search(" in source_lower
    ):
        proven.add("ldap")
    return proven


def path_escape_flows(payload: dict, sink: dict) -> list:
    """Keep flows where a tainted segment is joined beneath a distinct root."""
    sources = {
        item.get("id"): item.get("expr")
        for item in (payload.get("taint_sources") or [])
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("expr"), str)
    }
    arg_expr = str(sink.get("arg_expr") or "")
    compact_arg = re.sub(r"\s+", "", arg_expr)
    kept = []
    for flow in sink.get("flows") or []:
        if not isinstance(flow, dict):
            continue
        source_ref = flow.get("source")
        source_expr = None
        if isinstance(source_ref, str) and source_ref.startswith("param:"):
            source_expr = source_ref[len("param:"):]
        elif isinstance(source_ref, str) and source_ref.startswith("source:"):
            source_expr = sources.get(source_ref[len("source:"):])
        if not isinstance(source_expr, str) or not source_expr.strip():
            continue
        compact_source = re.sub(r"\s+", "", source_expr.strip())
        position = compact_arg.find(compact_source)
        if position <= 0:
            continue
        prefix = compact_arg[:position]
        if any(marker in prefix for marker in ("/", "join(", "joinpath(", "{")):
            kept.append(flow)
    return kept


def source_scan_coverage(scope: ast.AST, nodes: list, operation: ast.AST, sink: ast.AST):
    """Prove scan coverage relative to the protected sink's control path."""
    op_ctx = control_context(nodes, operation)
    sink_ctx = control_context(nodes, sink)
    default_enabled = default_enabled_params(scope)
    bypass_param = None
    for parent, branch in op_ctx.items():
        sink_branch = sink_ctx.get(parent)
        if sink_branch is not None:
            if sink_branch != branch:
                return None
            continue
        if isinstance(parent, ast.If):
            condition = boolean_param_condition(parent.test)
            if condition is None:
                return None
            name, when_true, when_false = condition
            in_body = branch == "body"
            executes_when_enabled = when_true if in_body else not when_true
            executes_when_disabled = when_false if in_body else not when_false
            if (
                name not in default_enabled
                or not executes_when_enabled
                or executes_when_disabled
                or bypass_param not in (None, name)
            ):
                return None
            bypass_param = name
        else:
            return None
    if bypass_param is not None:
        return "default", bypass_param
    return "must", ""


def source_backed_scan_guards(source: str, sinks: list) -> tuple[dict, set]:
    """Map deserialize sink ids to dominating fail-closed source scan facts."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return {}, set()
    scopes = [tree, *(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )]
    guarded = {}
    observed = set()
    for sink in sinks:
        if not isinstance(sink, dict) or sink.get("sink_kind") != "deserialize":
            continue
        sink_id = sink.get("id")
        expected_arg = compact_expr(sink.get("arg_expr"))
        expected_callee = source_backed_call_terminal(
            sink.get("call_expr"), tree
        ) or str(sink.get("callee") or "").lower().rsplit(".", 1)[-1]
        if not isinstance(sink_id, str) or not expected_arg or "scan" in expected_callee:
            continue
        for scope in scopes:
            nodes = scope_nodes(scope)
            sink_calls = [
                node for node in nodes
                if isinstance(node, ast.Call)
                and call_terminal(node) == expected_callee
                and node.args
                and compact_expr(node.args[0]) == expected_arg
            ]
            for sink_call in sink_calls:
                scan_calls = [
                    node for node in nodes
                    if isinstance(node, ast.Call)
                    and "scan" in call_terminal(node)
                    and node.args
                    and compact_expr(node.args[0]) == expected_arg
                ]
                if scan_calls:
                    observed.add(sink_id)
                for assignment in nodes:
                    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                        continue
                    value = assignment.value
                    if not isinstance(value, ast.Call) or "scan" not in call_terminal(value):
                        continue
                    if not value.args or compact_expr(value.args[0]) != expected_arg:
                        continue
                    targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
                    result_names = [target.id for target in targets if isinstance(target, ast.Name)]
                    if not result_names or assignment.lineno >= sink_call.lineno:
                        continue
                    if scan_exception_is_fail_open(nodes, assignment):
                        continue
                    coverage = source_scan_coverage(scope, nodes, assignment, sink_call)
                    if coverage is None:
                        continue
                    for guard in nodes:
                        if not isinstance(guard, ast.If):
                            continue
                        if not (assignment.lineno < guard.lineno < sink_call.lineno):
                            continue
                        attributes = scan_guard_attributes(guard.test, result_names[0])
                        rejects_unsafe = any(
                            marker in attribute
                            for attribute in attributes
                            for marker in ("infect", "unsafe", "malicious", "threat", "virus")
                        )
                        rejects_error = any(
                            marker in attribute
                            for attribute in attributes
                            for marker in ("err", "error", "fail")
                        )
                        if (
                            rejects_unsafe
                            and rejects_error
                            and block_terminates(guard.body)
                            and same_control_context(nodes, assignment, guard)
                        ):
                            guarded[sink_id] = {
                                "expr": ast.unparse(value),
                                "input_expr": ast.unparse(value.args[0]),
                                "coverage": coverage[0],
                                "bypass_param": coverage[1],
                            }
                            break
                    if sink_id in guarded:
                        break
    return guarded, observed


def source_must_scan_contracts(source: str) -> dict[str, dict]:
    """Derive unconditional fail-closed content-scan contracts from source."""
    try:
        tree = ast.parse(textwrap.dedent(source))
    except SyntaxError:
        return {}
    scopes = [tree, *(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )]
    proven = {}
    for scope in scopes:
        nodes = scope_nodes(scope)
        for assignment in nodes:
            if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                continue
            value = assignment.value
            if not isinstance(value, ast.Call) or "scan" not in call_terminal(value):
                continue
            if not value.args or control_context(nodes, assignment):
                continue
            targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
            result_names = [target.id for target in targets if isinstance(target, ast.Name)]
            if not result_names or scan_exception_is_fail_open(nodes, assignment):
                continue
            for guard in nodes:
                if not isinstance(guard, ast.If) or guard.lineno <= assignment.lineno:
                    continue
                if not same_control_context(nodes, assignment, guard):
                    continue
                attributes = scan_guard_attributes(guard.test, result_names[0])
                rejects_unsafe = any(
                    marker in attribute
                    for attribute in attributes
                    for marker in ("infect", "unsafe", "malicious", "threat", "virus")
                )
                rejects_error = any(
                    marker in attribute
                    for attribute in attributes
                    for marker in ("err", "error", "fail")
                )
                if rejects_unsafe and rejects_error and block_terminates(guard.body):
                    input_expr = ast.unparse(value.args[0])
                    proven[compact_expr(input_expr)] = {
                        "expr": ast.unparse(value),
                        "input_expr": input_expr,
                    }
                    break
    return proven


def _normalize_source_backed_scan_guards(guards: list, sinks: list, source: str) -> None:
    """AST-back scan guard facts, correcting failure_mode and coverage."""
    analysis = source_backed_scan_guards(source, sinks)
    guarded, observed = analysis
    unsafe_sink_ids = {
        sink.get("id") for sink in sinks
        if isinstance(sink, dict)
        and sink.get("sink_kind") == "deserialize"
        and "scan" not in str(sink.get("callee") or "").lower()
        and isinstance(sink.get("id"), str)
    }
    for guard in guards:
        if not isinstance(guard, dict) or guard.get("guard_kind") != "content_scan":
            continue
        protected = set(guard.get("protects_sink_ids") or []) & unsafe_sink_ids
        if (
            protected
            and not protected.issubset(guarded)
            and isinstance(guard.get("expr"), str)
        ):
            guard["failure_mode"] = "open"
    for sink in sinks:
        if not isinstance(sink, dict) or sink.get("id") not in guarded:
            continue
        sink_id = sink["id"]
        proof = guarded[sink_id]
        guard = next((
            candidate for candidate in guards
            if isinstance(candidate, dict)
            and candidate.get("guard_kind") == "content_scan"
            and sink_id in (candidate.get("protects_sink_ids") or [])
        ), None)
        if guard is None:
            guard = {"id": f"G_SOURCE_{sink_id}", "guard_kind": "content_scan"}
            guards.append(guard)
        protected = list(guard.get("protects_sink_ids") or [])
        if sink_id not in protected:
            protected.append(sink_id)
        guard.update({
            "expr": proof["expr"],
            "input_expr": proof["input_expr"],
            "protects_sink_ids": protected,
            "endorses": ["serialized_blob"],
            "coverage": proof["coverage"],
            "failure_mode": "closed",
            "bypass_param": proof["bypass_param"],
            "confidence": "high",
        })
        if proof["coverage"] == "must":
            sink["_validation_guard_coverage"] = "must"
        else:
            sink.pop("_validation_guard_coverage", None)


def _normalize_operation_sinks(payload: dict, source: str) -> dict:
    """Discard LLM sink guesses that have no matching operation in the source."""
    normalized = dict(payload)
    sources = payload.get("taint_sources") or []
    static_config_ids = {
        source_record.get("id")
        for source_record in sources
        if isinstance(source_record, dict)
        and is_static_config_pseudosource(source_record, source)
        and isinstance(source_record.get("id"), str)
    }
    normalized_sources = []
    for source_record in sources:
        if not isinstance(source_record, dict):
            normalized_sources.append(source_record)
            continue
        if source_record.get("id") in static_config_ids:
            continue
        item = dict(source_record)
        if item.get("source_kind") == "fs_path":
            item["source_kind"] = "untrusted_param"
        elif item.get("source_kind") == "file_read":
            item["source_kind"] = "file"
        normalized_sources.append(item)
    normalized["taint_sources"] = normalized_sources
    guards = [
        dict(guard) if isinstance(guard, dict) else guard
        for guard in (payload.get("validation_guards") or [])
    ]
    scan_match = re.search(r"scan_file_path\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)", source)
    scan_input = scan_match.group(1) if scan_match else None
    if scan_input:
        source_failure_mode = "closed" if "scan_err" in source else "open"
        scan_guards = [
            guard for guard in guards
            if isinstance(guard, dict) and guard.get("guard_kind") == "content_scan"
        ]
        for guard in scan_guards:
            guard["input_expr"] = scan_input
            guard["failure_mode"] = source_failure_mode
            if source_failure_mode == "closed" and not guard.get("bypass_param"):
                guard["coverage"] = "must"
        if not scan_guards and "scan" in str(payload.get("function") or "").lower():
            guards.append({
                "id": "G_SOURCE_SCAN",
                "guard_kind": "content_scan",
                "expr": f"scan_file_path({scan_input})",
                "input_expr": scan_input,
                "protects_sink_ids": [],
                "endorses": ["serialized_blob"],
                "coverage": "must",
                "failure_mode": source_failure_mode,
                "bypass_param": "",
                "confidence": "high",
            })
    normalized["validation_guards"] = guards
    kept = []
    source_proven_kinds = source_proven_sink_kinds(source)
    for raw_sink in payload.get("sinks") or []:
        if not isinstance(raw_sink, dict):
            kept.append(raw_sink)
            continue
        sink = dict(raw_sink)
        if sink.get("_via"):
            kept.append(sink)
            continue
        kind = sink.get("sink_kind")
        call = str(sink.get("call_expr") or sink.get("callee") or "").lower()
        source_lower = source.lower()
        if kind == "code_eval" and "exec(" in call:
            sink["sink_kind"] = "shell_command"
            sink["arg_context"] = "shell_command_text"
            kind = "shell_command"
        if kind == "code_eval" and not any(
            marker in call for marker in ("exec(", "eval(")
        ):
            continue
        if kind == "unknown_external":
            continue
        if kind not in source_proven_kinds:
            continue
        ldap_arg = str(sink.get("arg_expr") or "").lower()
        if kind == "ldap" and any(
            marker in ldap_arg for marker in ("base_dn", "search_base", "search_scope")
        ):
            continue
        if kind == "fs_path":
            sink["flows"] = path_escape_flows(normalized, sink)
            if not sink["flows"]:
                continue
        if kind == "deserialize" and any(
            marker in call for marker in ("safetensors", "gguf")
        ):
            continue
        if kind == "deserialize":
            deserialize_markers = tuple(
                marker for marker in (
                    "pickle", "torch.load", "torch_load", "yaml.load", "scan_file_path"
                )
                if marker in call
            )
            if not deserialize_markers or not any(
                marker in source_lower for marker in deserialize_markers
            ):
                continue
        if static_config_ids:
            sink["flows"] = [
                flow for flow in (sink.get("flows") or [])
                if not isinstance(flow, dict)
                or flow.get("source") not in {
                    f"source:{source_id}" for source_id in static_config_ids
                }
            ]
        kept.append(sink)

    for compact_input, contract in source_must_scan_contracts(source).items():
        scan_sink_ids = [
            sink["id"]
            for sink in kept
            if isinstance(sink, dict)
            and isinstance(sink.get("id"), str)
            and sink.get("sink_kind") == "deserialize"
            and "scan" in str(sink.get("callee") or "").lower()
            and compact_expr(sink.get("arg_expr")) == compact_input
        ]
        matching_guards = [
            guard for guard in guards
            if isinstance(guard, dict)
            and guard.get("guard_kind") == "content_scan"
            and compact_expr(guard.get("input_expr")) == compact_input
        ]
        if not matching_guards:
            matching_guards = [{
                "id": f"G_SOURCE_SCAN_{len(guards)}",
                "guard_kind": "content_scan",
            }]
            guards.extend(matching_guards)
        for guard in matching_guards:
            protected = list(guard.get("protects_sink_ids") or [])
            guard.update({
                "expr": contract["expr"],
                "input_expr": contract["input_expr"],
                "protects_sink_ids": [*protected, *(
                    sink_id for sink_id in scan_sink_ids if sink_id not in protected
                )],
                "endorses": ["serialized_blob"],
                "coverage": "must",
                "failure_mode": "closed",
                "bypass_param": "",
                "confidence": "high",
            })

    _normalize_source_backed_scan_guards(guards, kept, source)
    has_deserialize = any(
        isinstance(sink, dict) and sink.get("sink_kind") == "deserialize"
        for sink in kept
    )
    scan_guard = next((
        guard for guard in guards
        if isinstance(guard, dict)
        and guard.get("guard_kind") == "content_scan"
        and "serialized_blob" in (guard.get("endorses") or [])
        and isinstance(guard.get("input_expr"), str)
    ), None)
    function_name = str(payload.get("function") or "").lower()
    if (
        not has_deserialize
        and scan_guard is not None
        and "scan" in function_name
        and "scan_file_path(" in source
    ):
        input_expr = scan_guard["input_expr"]
        source_record = next((
            item for item in normalized["taint_sources"]
            if isinstance(item, dict)
            and item.get("expr") == input_expr
            and isinstance(item.get("id"), str)
        ), None)
        source_ref = (
            f"source:{source_record['id']}" if source_record
            else f"param:{input_expr}"
        )
        sink_id = "K_SCAN_ACCEPT"
        kept.append({
            "id": sink_id,
            "sink_kind": "deserialize",
            "callee": "scan_file_path",
            "call_expr": f"scan_file_path({input_expr})",
            "arg_position": 0,
            "arg_expr": input_expr,
            "arg_context": "serialized_blob",
            "flows": [{"source": source_ref, "sanitizers": []}],
        })
        protected = scan_guard.get("protects_sink_ids")
        scan_guard["protects_sink_ids"] = [
            *(
                protected
                if isinstance(protected, list)
                else []
            ),
            sink_id,
        ]

    by_id = {
        sink["id"]: sink
        for sink in kept
        if isinstance(sink, dict) and isinstance(sink.get("id"), str)
    }
    for guard in guards:
        if not isinstance(guard, dict) or guard.get("guard_kind") != "content_scan":
            continue
        if guard.get("confidence") != "high" or guard.get("failure_mode") != "closed":
            continue
        input_expr = guard.get("input_expr")
        if not isinstance(input_expr, str):
            continue
        scan_pos = source.find(f"scan_file_path({input_expr})")
        if scan_pos < 0:
            continue
        protected = guard.get("protects_sink_ids")
        protected_ids = list(protected) if isinstance(protected, list) else []
        for sink in kept:
            if not isinstance(sink, dict) or sink.get("sink_kind") != "deserialize":
                continue
            sink_id = sink.get("id")
            if not isinstance(sink_id, str) or sink.get("arg_expr") != input_expr:
                continue
            sink_pos = source.find(str(sink.get("call_expr") or ""))
            if sink_pos > scan_pos and sink_id not in protected_ids:
                protected_ids.append(sink_id)
        guard["protects_sink_ids"] = protected_ids
    for guard in guards:
        if not isinstance(guard, dict):
            continue
        if guard.get("confidence") != "high" or guard.get("failure_mode") != "closed":
            continue
        if guard.get("guard_kind") not in {
            "schema_validation", "deserialization_allowlist", "content_scan",
        }:
            continue
        guard_expr = guard.get("expr")
        if not isinstance(guard_expr, str) or not guard_expr:
            continue
        guard_pos = source.find(guard_expr)
        if guard_pos < 0:
            continue
        for sink_id in guard.get("protects_sink_ids") or []:
            if not isinstance(sink_id, str):
                continue
            sink = by_id.get(sink_id)
            if not sink or guard.get("input_expr") != sink.get("arg_expr"):
                continue
            if sink.get("arg_context") not in (guard.get("endorses") or []):
                continue
            sink_pos = source.find(str(sink.get("call_expr") or ""))
            if sink_pos > guard_pos:
                if guard.get("coverage") == "must":
                    sink["_validation_guard_coverage"] = "must"
                elif (
                    guard.get("coverage") == "default"
                    and sink.get("_validation_guard_coverage") != "must"
                ):
                    sink.pop("_validation_guard_coverage", None)

    normalized["sinks"] = kept
    return normalized
