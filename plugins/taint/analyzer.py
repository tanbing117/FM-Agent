"""Taint analysis logic — SPI methods extracted from TaintPlugin class.

Prompts / reasoner / validation are in their own modules.
AST helpers are in ast_utils.py. Normalization is in normalize.py.
Composition helpers are in compose.py.
"""

import re
from typing import Dict, List, Optional

from .taint_prompts import _extract_taint_json, _system_prompt, _user_prompt
from .taint_reasoner import classify as taint_classify, validate, instantiate_sink
from .taint_validation import (
    call_args_from_bindings,
    merge_call_args_with_bindings,
    source_rel_from_extracted,
    validation_guard_coverage,
    validation_guard_coverage_for_call,
)
from .compose import (
    match_call_site,
    has_call_operation,
    has_same_name_body_call,
    propagate_source_validated_callee_guard,
)
from .normalize import _normalize_operation_sinks


def build_taint_prompt(source: str, signature_line: str, language: str,
                       callee_summaries_text: str = None) -> List[Dict[str, str]]:
    """Build system + user prompt for taint signature derivation."""
    numbered = "\n".join(
        f"Line {i+1}: {ln}" for i, ln in enumerate(source.splitlines())
    )
    return [
        {"role": "system", "content": _system_prompt(language)},
        {"role": "user", "content": _user_prompt(
            numbered, signature_line, language, callee_summaries_text)},
    ]


def parse_taint_response(source: str, raw_response: str) -> Optional[dict]:
    """Parse LLM response, normalize sinks, validate schema."""
    payload = _extract_taint_json(raw_response)
    if payload is None or not isinstance(payload, dict):
        return None
    payload = _normalize_operation_sinks(payload, source)
    if validate(payload) is not None:
        return None
    return payload


def summarize_taint(payload: dict, fn_name: str) -> str:
    """Concise callee summary for caller prompts."""
    if not payload:
        return f"{fn_name}: (no taint facts)"
    parts = []
    for k in (payload.get("sinks") or []):
        srcs = ",".join((fl.get("source") or "?") for fl in (k.get("flows") or []))
        parts.append(f"{k.get('sink_kind')}({k.get('arg_context')})<-{{{srcs}}}")
    rets = payload.get("return_flows") or []
    if rets:
        rs = ",".join((fl.get("source") or "?")
                      for r in rets for fl in (r.get("flows") or []))
        if rs:
            parts.append(f"return<-{{{rs}}}")
    for guard in payload.get("validation_guards") or []:
        if not isinstance(guard, dict):
            continue
        parts.append(
            f"guard:{guard.get('guard_kind')}({guard.get('input_expr')})"
            f"[{guard.get('coverage')}/{guard.get('failure_mode')}]"
        )
    summary = f"{fn_name}: " + ("; ".join(parts) if parts else "(no sinks)")
    return summary[:4096]


def compose_taint_calls(
    caller_payload: dict,
    resolved_calls: list,
    source: str,
    language: str,
    base_name_fn,
    program: dict,
) -> dict:
    """Instantiate callee sinks/sanitizers at caller call sites.

    Returns updated payload with composed sinks, sanitizers, taint_bindings.
    """
    payload = _normalize_operation_sinks(caller_payload, source)
    caller_call_sites = payload.get("call_sites") or []
    composed_sinks = list(payload.get("sinks") or [])
    composed_sanitizers = list(payload.get("sanitizers") or [])
    composed_bindings = list(payload.get("taint_bindings") or [])

    for rc in resolved_calls:
        cf = rc.get("callee_facts", {})
        callee_name = rc.get("callee_name", "")
        if cf.get("status") != "ok" or not cf.get("payload"):
            continue
        if not has_call_operation(source, callee_name, language):
            continue
        if (
            callee_name == base_name_fn
            and not has_same_name_body_call(source, callee_name, language)
        ):
            continue

        callee_source = rc.get("callee_source", "")
        callee_payload = _normalize_operation_sinks(cf["payload"], callee_source)
        propagate_source_validated_callee_guard(source, callee_source, callee_name, composed_sinks)

        cs = match_call_site(caller_call_sites, callee_name)
        if cs:
            call_id = cs.get("id") or callee_name
            param_to_actual = {
                a.get("param_name"): (a.get("flows") or [])
                for a in (cs.get("args") or []) if a.get("param_name")
            }
            for formal, actual_expr in (rc.get("arg_bindings") or {}).items():
                p = formal[len("param:"):] if formal.startswith("param:") else formal
                if p not in param_to_actual:
                    param_to_actual[p] = [
                        {"source": f"unknown:{call_id}:{actual_expr}", "sanitizers": []}
                    ]
        else:
            call_id = callee_name
            param_to_actual = {}
            for formal, actual_expr in (rc.get("arg_bindings") or {}).items():
                p = formal[len("param:"):] if formal.startswith("param:") else formal
                param_to_actual[p] = [
                    {"source": f"unknown:{call_id}:{actual_expr}", "sanitizers": []}
                ]

        sanitizer_id_map = {}
        for sanitizer in callee_payload.get("sanitizers") or []:
            if not isinstance(sanitizer, dict) or not isinstance(sanitizer.get("id"), str):
                continue
            old_id = sanitizer["id"]
            new_id = f"{call_id}::{old_id}"
            sanitizer_id_map[old_id] = new_id
            reanchored = dict(sanitizer)
            reanchored["id"] = new_id
            composed_sanitizers.append(reanchored)

        for ksink in callee_payload.get("sinks") or []:
            inst = instantiate_sink(ksink, call_id, param_to_actual, sanitizer_id_map)
            args = (cs or {}).get("args")
            if cs and isinstance(args, (list, tuple)):
                call_args = merge_call_args_with_bindings(args, rc.get("arg_bindings", {}))
                coverage = validation_guard_coverage_for_call(callee_payload, ksink, call_args)
            else:
                call_args = call_args_from_bindings(rc.get("arg_bindings", {}))
                coverage = (
                    validation_guard_coverage_for_call(callee_payload, ksink, call_args)
                    if call_args else validation_guard_coverage(callee_payload, ksink)
                )
            if coverage in {"must", "default"}:
                inst["_validation_guard_coverage"] = coverage
            composed_sinks.append(inst)

        for return_flow in callee_payload.get("return_flows") or []:
            if cs and cs.get("return_expr"):
                inst_flows = instantiate_sink(return_flow, call_id, param_to_actual, {})
                composed_bindings.append({
                    "bind_target": cs["return_expr"],
                    "flows": inst_flows.get("flows", []),
                    "_via": callee_name,
                })

    payload["sinks"] = composed_sinks
    payload["sanitizers"] = composed_sanitizers
    payload["taint_bindings"] = composed_bindings
    return payload


def check_taint(payload: dict, param_status: dict, is_entrypoint: bool) -> dict:
    """Deterministic taint classification over composed facts."""
    return taint_classify(payload, param_status=param_status)
