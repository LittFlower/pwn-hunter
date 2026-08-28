"""Export decompiler evidence for independent manual corpus labeling."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import ida_pro
import idautils


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pwnhunter.ida_adapter import CandidateSelector, CtreeExtractor, ScanConfig
from pwnhunter.ir import Assignment, Call, Return


def selected_functions() -> tuple[list[int], str, int]:
    all_functions = list(idautils.Functions())
    usable = []
    for ea in all_functions:
        function = ida_funcs.get_func(ea)
        name = ida_funcs.get_func_name(ea) or ""
        if function is None:
            continue
        if function.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
            continue
        if name.startswith("."):
            continue
        usable.append(int(ea))
    limit = int(os.environ.get("PWN_GT_ALL_LIMIT", "300"))
    if len(all_functions) <= limit:
        return usable, "all-nonlibrary", len(all_functions)
    candidates = CandidateSelector(ScanConfig.from_environment()).discover()
    return [candidate.ea for candidate in candidates], "ranked-candidates", len(all_functions)


def main() -> int:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is unavailable")
    addresses, mode, total = selected_functions()
    output = {}
    failures = []
    for ea in addresses:
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc is None:
                continue
            ir = CtreeExtractor(cfunc).extract()
            statements = []
            for statement in ir.statements:
                item = {
                    "type": type(statement).__name__,
                    "ea": hex(statement.ea),
                    "block": statement.block_id,
                    "text": statement.text,
                }
                if isinstance(statement, Call):
                    item.update(
                        {
                            "callee": statement.name,
                            "callee_ea": (
                                hex(statement.callee_ea)
                                if statement.callee_ea is not None
                                else None
                            ),
                            "arguments": [argument.text for argument in statement.args],
                            "target": (
                                statement.target.text
                                if statement.target is not None
                                else None
                            ),
                        }
                    )
                elif isinstance(statement, Assignment):
                    item.update(
                        {"target": statement.target.text, "value": statement.value.text}
                    )
                elif isinstance(statement, Return):
                    item["value"] = statement.value.text
                statements.append(item)
            output[hex(ea)] = {
                "name": ir.name,
                "pseudocode": ida_lines.tag_remove(str(cfunc)),
                "statements": statements,
                "conditions": [
                    {
                        "ea": hex(condition.ea),
                        "block": condition.block_id,
                        "text": condition.text,
                    }
                    for condition in ir.conditions
                ],
                "cfg_source": ir.cfg_source,
                "microcode_blocks": ir.microcode_blocks,
            }
        except Exception as error:
            failures.append({"ea": hex(ea), "error": repr(error)})
    result = {
        "mode": mode,
        "total_functions": total,
        "exported_functions": len(output),
        "failures": failures,
        "functions": output,
    }
    Path(os.environ["PWN_HUNTER_RESULT"]).write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    return 0 if not failures else 2


try:
    exit_code = main()
except Exception:
    import traceback

    traceback.print_exc()
    exit_code = 1
ida_pro.qexit(exit_code)
