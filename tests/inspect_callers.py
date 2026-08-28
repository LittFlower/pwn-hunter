"""Export decompiled callers for selected imported symbols.

This is a read-only headless IDA diagnostic used while extending PwnHunter's
function models.  Set ``PWN_HUNTER_INSPECT_SYMBOLS`` to a comma-separated list
and ``PWN_HUNTER_INSPECT_RESULT`` to the output JSON path.
Set ``PWN_HUNTER_INSPECT_INCLUDE_TARGET=1`` to export matching internal
functions as well as their callers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_name
import ida_nalt
import ida_pro
import ida_typeinf
import idautils


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pwnhunter.rules import normalize_symbol
from pwnhunter.ida_adapter import CtreeExtractor, prepare_analysis_types
from pwnhunter.ir import Assignment, Call, Expr, Return
from pwnhunter.summaries import SummaryBuilder


def expression_payload(expression: Expr) -> dict[str, object]:
    """Serialize the compact expression facts useful during model audits."""

    return {
        "kind": expression.kind,
        "key": expression.key,
        "text": expression.text,
        "callee": expression.callee,
        "value": expression.value,
        "op": expression.op,
        "offset": expression.offset,
        "bits": expression.bits,
        "signed": expression.signed,
        "is_pointer": expression.is_pointer,
        "children": [expression_payload(child) for child in expression.children],
    }


def value_ref_payload(value) -> dict[str, object]:
    """Serialize address and scalar templates from a function summary."""

    return {
        "argument": value.argument,
        "constant": value.constant,
        "offset": value.offset,
        "scalar_op": value.scalar_op,
        "bits": value.bits,
        "signed": value.signed,
        "text": value.text,
        "operands": [value_ref_payload(child) for child in value.operands],
    }


def statement_payload(statement: object) -> dict[str, object]:
    base = {
        "order": statement.order,
        "ea": statement.ea,
        "text": statement.text,
        "block_id": statement.block_id,
        "guards": [
            expression_payload(guard)
            for guard in getattr(statement, "guards", ())
        ],
    }
    if isinstance(statement, Call):
        return {
            **base,
            "kind": "call",
            "name": statement.name,
            "args": [expression_payload(argument) for argument in statement.args],
        }
    if isinstance(statement, Assignment):
        return {
            **base,
            "kind": "assignment",
            "target": expression_payload(statement.target),
            "value": expression_payload(statement.value),
        }
    if isinstance(statement, Return):
        return {
            **base,
            "kind": "return",
            "value": expression_payload(statement.value),
        }
    return {**base, "kind": type(statement).__name__}


def microcode_call_payloads(cfunc: ida_hexrays.cfunc_t) -> list[dict[str, object]]:
    """Serialize low-level call arguments that ctree may cosmetically hide."""

    result: list[dict[str, object]] = []
    mba = cfunc.mba
    class Visitor(ida_hexrays.minsn_visitor_t):
        def __init__(self):
            super().__init__(mba)

        def visit_minsn(self) -> int:
            instruction = self.curins
            if instruction.opcode in {ida_hexrays.m_call, ida_hexrays.m_icall}:
                try:
                    callinfo = instruction.d.f
                    arguments = []
                    for argument in callinfo.args:
                        try:
                            rendered = argument.dstr()
                        except Exception:
                            rendered = str(argument)
                        arguments.append(
                            {
                                "type": int(argument.t),
                                "size": int(argument.size),
                                "text": rendered,
                            }
                        )
                    try:
                        rendered_instruction = instruction.dstr()
                    except Exception:
                        rendered_instruction = str(instruction)
                    result.append(
                        {
                            "ea": int(instruction.ea),
                            "opcode": int(instruction.opcode),
                            "text": rendered_instruction,
                            "arguments": arguments,
                        }
                    )
                except Exception as exception:
                    result.append(
                        {
                            "ea": int(instruction.ea),
                            "opcode": int(instruction.opcode),
                            "error": str(exception),
                        }
                    )
            return 0

    mba.for_all_insns(Visitor())
    return result


def function_type_payload(
    cfunc: ida_hexrays.cfunc_t, function_ea: int
) -> dict[str, object]:
    """Expose stored versus Hex-Rays-inferred argument counts."""

    def argument_count(tif: ida_typeinf.tinfo_t) -> int | None:
        details = ida_typeinf.func_type_data_t()
        if tif.is_func() and tif.get_func_details(details):
            return int(details.size())
        return None

    stored = ida_typeinf.tinfo_t()
    stored_count = (
        argument_count(stored)
        if ida_nalt.get_tinfo(stored, function_ea)
        else None
    )
    inferred = ida_typeinf.tinfo_t()
    inferred_count = (
        argument_count(inferred)
        if cfunc.get_func_type(inferred)
        else None
    )
    return {
        "stored_arguments": stored_count,
        "inferred_arguments": inferred_count,
        "ida_guessed": bool(ida_nalt.is_type_guessed_by_ida(function_ea)),
        "hexrays_guessed": bool(
            ida_nalt.is_func_guessed_by_hexrays(function_ea)
        ),
        "hexrays_determined": bool(
            ida_nalt.is_type_determined_by_hexrays(function_ea)
        ),
    }


def reverse_callers(target_ea: int, depth: int = 2) -> set[int]:
    """Return functions that directly or through an import thunk reach target."""

    callers: set[int] = set()
    frontier = {target_ea}
    visited = {target_ea}
    for _ in range(depth):
        next_frontier: set[int] = set()
        for ea in frontier:
            for reference in idautils.XrefsTo(ea):
                if not reference.iscode:
                    continue
                function = ida_funcs.get_func(reference.frm)
                if function is None:
                    continue
                callers.add(function.start_ea)
                if function.start_ea not in visited:
                    visited.add(function.start_ea)
                    next_frontier.add(function.start_ea)
        frontier = next_frontier
    return callers


def main() -> None:
    ida_auto.auto_wait()
    if os.environ.get("PWN_HUNTER_INSPECT_PREPARE_TYPES") == "1":
        prepare_analysis_types()
    requested = {
        normalize_symbol(item)
        for item in os.environ.get("PWN_HUNTER_INSPECT_SYMBOLS", "").split(",")
        if item.strip()
    }
    output_path = Path(
        os.environ.get("PWN_HUNTER_INSPECT_RESULT", "/tmp/pwnhunter-callers.json")
    )
    entries: list[dict[str, object]] = []
    matched: set[str] = set()
    include_target = os.environ.get("PWN_HUNTER_INSPECT_INCLUDE_TARGET") == "1"
    targets: dict[str, set[int]] = {name: set() for name in requested}
    for ea, raw_name in idautils.Names():
        name = normalize_symbol(raw_name)
        if name in requested:
            targets[name].add(ea)
    # IDA's Names() iterator can omit autogenerated sub_* labels even though
    # get_func_name() exposes them. Include function starts so diagnostics can
    # inspect internal wrappers without renaming the database.
    for function_ea in idautils.Functions():
        name = normalize_symbol(ida_funcs.get_func_name(function_ea))
        if name in requested:
            targets[name].add(function_ea)

    target_pairs = [
        (name, target_ea)
        for name in sorted(requested)
        for target_ea in sorted(targets[name])
    ]
    for name, target_ea in target_pairs:
        matched.add(name)
        function_eas = reverse_callers(target_ea)
        if include_target:
            function = ida_funcs.get_func(target_ea)
            if function is not None:
                function_eas.add(function.start_ea)
        for function_ea in sorted(function_eas):
            function_name = ida_funcs.get_func_name(function_ea)
            try:
                cfunc = ida_hexrays.decompile(function_ea)
                if cfunc is None:
                    raise RuntimeError("Hex-Rays returned no cfunc")
                pseudocode = str(cfunc)
                function_ir = CtreeExtractor(cfunc).extract()
                buffers = [
                    {
                        "key": buffer.key,
                        "name": buffer.name,
                        "storage": buffer.storage,
                        "capacity": buffer.capacity,
                        "precise": buffer.precise,
                        "physical_capacity": buffer.physical_capacity,
                        "trailing_nul_sentinel": buffer.trailing_nul_sentinel,
                    }
                    for buffer in function_ir.buffers.values()
                ]
                stack_slots = [
                    {
                        "key": slot.key,
                        "name": slot.name,
                        "offset": slot.offset,
                        "width": slot.width,
                        "type_kind": slot.type_kind,
                    }
                    for slot in function_ir.stack_slots.values()
                ]
                calls = [
                    {
                        "name": statement.name,
                        "ea": statement.ea,
                        "args": [
                            {
                                "kind": argument.kind,
                                "key": argument.key,
                                "text": argument.text,
                                "offset": argument.offset,
                            }
                            for argument in statement.args
                        ],
                    }
                    for statement in function_ir.statements
                    if isinstance(statement, Call)
                ]
                statements = [
                    statement_payload(statement)
                    for statement in function_ir.statements
                ]
                conditions = [
                    {
                        "order": condition.order,
                        "ea": condition.ea,
                        "block_id": condition.block_id,
                        "text": condition.text,
                        "expression": expression_payload(condition.expression),
                    }
                    for condition in function_ir.conditions
                ]
                microcode_calls = microcode_call_payloads(cfunc)
                parameters = list(function_ir.parameters)
                parameter_taint_origins = {
                    key: sorted(arguments)
                    for key, arguments in SummaryBuilder._parameter_taint_origins(
                        function_ir
                    ).items()
                }
                type_info = function_type_payload(cfunc, function_ea)
                summary = SummaryBuilder().build([function_ir]).lookup(
                    function_ir.name, function_ir.ea
                )
                allocation_summary = (
                    {
                        "allocator": summary.allocation.allocator,
                        "sizes": [
                            value_ref_payload(value)
                            for value in summary.allocation.sizes
                        ],
                    }
                    if summary is not None and summary.allocation is not None
                    else None
                )
                error = None
            except Exception as exception:
                pseudocode = ""
                buffers = []
                stack_slots = []
                calls = []
                statements = []
                conditions = []
                microcode_calls = []
                parameters = []
                parameter_taint_origins = {}
                type_info = {}
                allocation_summary = None
                error = str(exception)
            entries.append(
                {
                    "symbol": name,
                    "import_ea": target_ea,
                    "function_ea": function_ea,
                    "function": function_name,
                    "pseudocode": pseudocode,
                    "buffers": buffers,
                    "stack_slots": stack_slots,
                    "calls": calls,
                    "statements": statements,
                    "conditions": conditions,
                    "microcode_calls": microcode_calls,
                    "parameters": parameters,
                    "parameter_taint_origins": parameter_taint_origins,
                    "type_info": type_info,
                    "allocation_summary": allocation_summary,
                    "error": error,
                }
            )
    output_path.write_text(
        json.dumps(
            {
                "requested": sorted(requested),
                "matched": sorted(matched),
                "missing": sorted(requested - matched),
                "callers": entries,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    ida_pro.qexit(0 if matched == requested else 2)


if __name__ == "__main__":
    main()
