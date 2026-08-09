"""Stage 6 replace: Taint analysis driver (derive → compose → check → write).

Shares the same orchestration pattern as IFC (derive_all → compose_all →
check_all → write_results), but with taint-specific prompt/reasoner/validation.
"""

import json
import os
from typing import Dict, List

from plugins.ifc.artifacts import load_program_index, load_order
from plugins.ifc.callgraph import base_name, load_units_from_extracted
from plugins.ifc.analyzer import _source_rel_from_extracted as _ifc_source_rel

from .analyzer import (
    build_taint_prompt,
    check_taint,
    compose_taint_calls,
    parse_taint_response,
    summarize_taint,
)
from .taint_reasoner import VULNERABLE, SANITIZED, POLYMORPHIC, SAFE, ERROR


def _derive_taint(source: str, signature_line: str, language: str,
                  callee_summaries_text: str, model: str, max_iter: int = 5) -> dict:
    """Derive a taint signature via LLM, with format-correction retries."""
    from src.llm_client import _openrouter_client, _retry_create

    messages = build_taint_prompt(
        source, signature_line, language,
        callee_summaries_text if callee_summaries_text else None,
    )

    for _ in range(max_iter):
        try:
            response, _ = _retry_create(_openrouter_client, model, messages)
        except Exception:
            return {"status": "error", "payload": None, "confidence": 0.0}

        payload = parse_taint_response(source, response)
        if payload is not None:
            return {"status": "ok", "payload": payload, "confidence": 1.0}

        messages = messages + [
            {"role": "assistant", "content": response or ""},
            {"role": "user", "content": "Your output was not in the required format. "
                                         "Re-emit ONLY the requested structured block."},
        ]

    return {"status": "error", "payload": None, "confidence": 0.0,
            "error": "no valid taint abstraction after retries"}


def replace_generate_specs_and_verification(proj_dir: str) -> None:
    """Taint analysis: derive → compose → check → write."""

    try:
        from config import LLM_MODEL
        model = LLM_MODEL
    except Exception:
        model = "deepseek-chat"

    work_dir = os.path.join(proj_dir, "fm_agent")
    ifc_dir = os.path.join(work_dir, "ifc")
    results_dir = os.path.join(work_dir, "taint_results")
    os.makedirs(results_dir, exist_ok=True)

    program, entrypoints = load_program_index(
        os.path.join(ifc_dir, "program_index.json")
    )
    order_data = load_order(os.path.join(ifc_dir, "bottom_up_order.json"))
    ordered = order_data.get("order", [])
    cycles = order_data.get("cycles", [])
    unreachable = order_data.get("unreachable", [])

    units = load_units_from_extracted(work_dir)
    source_by_fn = {(u.id.rel, u.id.name): u for u in units}

    calls_by_fn: Dict[tuple, list] = {}
    for caller_key, calls in program.get("calls_by_caller", {}).items():
        try:
            rel, name = caller_key.split("::", 1)
        except ValueError:
            continue
        cid = (rel, name)
        calls_by_fn.setdefault(cid, []).extend(calls)

    all_refs = ordered + [
        item for cycle in cycles for item in cycle
    ] + list(unreachable)

    # ---- Pass 1: derive + compose (bottom-up) ----
    facts_by_fn: Dict[tuple, dict] = {}
    for ref in all_refs:
        fn_key = (ref["rel"], ref["name"])
        fn_unit = source_by_fn.get(fn_key)
        if fn_unit is None:
            facts_by_fn[fn_key] = {
                "status": "error", "payload": None, "confidence": 0.0,
            }
            continue

        callee_summaries_text = ""
        lines = []
        for cs in calls_by_fn.get(fn_key, []):
            callee_key = (cs.get("callee_rel"), cs.get("callee_name"))
            cf = facts_by_fn.get(callee_key)
            if cf and cf.get("status") == "ok" and cf.get("payload"):
                lines.append(summarize_taint(
                    cf["payload"], cs["callee_name"]
                ))
        if lines:
            callee_summaries_text = "\n".join(lines)

        facts = _derive_taint(
            fn_unit.source, fn_unit.signature_line,
            fn_unit.id.language, callee_summaries_text, model,
        )

        if facts.get("status") == "ok" and facts.get("payload"):
            resolved = [
                {
                    "callee_name": cs.get("callee_name"),
                    "arg_bindings": cs.get("arg_bindings", {}),
                    "callee_facts": facts_by_fn.get(
                        (cs.get("callee_rel"), cs.get("callee_name")), {}
                    ),
                    "callee_source": (
                        source_by_fn.get(
                            (cs.get("callee_rel"), cs.get("callee_name"))
                        ).source
                        if source_by_fn.get(
                            (cs.get("callee_rel"), cs.get("callee_name"))
                        ) else ""
                    ),
                }
                for cs in calls_by_fn.get(fn_key, [])
                if (cs.get("callee_rel"), cs.get("callee_name")) in facts_by_fn
            ]
            if resolved:
                facts["payload"] = compose_taint_calls(
                    facts["payload"], resolved,
                    fn_unit.source, fn_unit.id.language,
                    base_name(fn_unit.id.name), program,
                )

        facts_by_fn[fn_key] = facts

    # ---- Pass 2: check + write ----
    counts: Dict[str, int] = {}
    results = []
    _COLOR = {
        VULNERABLE: "\033[31m", SANITIZED: "\033[33m",
        POLYMORPHIC: "\033[36m", SAFE: "\033[32m", ERROR: "\033[35m",
    }

    for ref in all_refs:
        fn_key = (ref["rel"], ref["name"])
        fn_unit = source_by_fn.get(fn_key)
        facts = facts_by_fn[fn_key]
        is_entrypoint = f"{ref['rel']}::{ref['name']}" in entrypoints

        if facts.get("status") == "error" or not facts.get("payload"):
            verdict = ERROR
        else:
            result = check_taint(facts["payload"], None, is_entrypoint)
            verdict = result.get("verdict", ERROR)

        counts[verdict] = counts.get(verdict, 0) + 1

        print(f"  {ref['rel']}: {_COLOR.get(verdict, '')}{verdict}\033[0m")

        out = {
            "function": ref["name"],
            "rel": ref["rel"],
            "verdict": verdict,
        }
        out_path = os.path.join(
            results_dir,
            ref["rel"].replace("/", "__") + "__" + ref["name"] + ".json",
        )
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        results.append({
            "function": ref["rel"], "name": ref["name"], "verdict": verdict,
        })

    summary = {
        "total": len(results),
        "vulnerable": counts.get(VULNERABLE, 0),
        "sanitized": counts.get(SANITIZED, 0),
        "polymorphic": counts.get(POLYMORPHIC, 0),
        "safe": counts.get(SAFE, 0),
        "errors": counts.get(ERROR, 0),
        "results": results,
    }
    with open(os.path.join(results_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    parts = [
        f"VULNERABLE={counts.get(VULNERABLE, 0)}",
        f"SANITIZED={counts.get(SANITIZED, 0)}",
        f"SAFE={counts.get(SAFE, 0)}",
    ]
    if counts.get(POLYMORPHIC, 0):
        parts.append(f"POLYMORPHIC={counts[POLYMORPHIC]}")
    if counts.get(ERROR, 0):
        parts.append(f"ERROR={counts[ERROR]}")
    print(f"[taint] Done. {' '.join(parts)}")
