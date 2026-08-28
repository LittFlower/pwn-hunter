"""IDA Pro 9.x adapter and user interface."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import os
from pathlib import Path
import re
import time
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_fixup
import ida_gdl
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_name
import ida_nalt
import ida_segment
import ida_typeinf
import idautils

from .converters import known_converter_findings
from .engine import Analyzer
from .ir import (
    Assignment,
    BasicBlock,
    BufferInfo,
    Call,
    Condition,
    Expr,
    Finding,
    FunctionIR,
    Return,
    Severity,
    StackSlot,
)
from .rules import (
    FORTIFIED_DESTINATION_SPECS,
    SCAN_SEED_NAMES,
    looks_like_bundled_runtime_source,
    normalize_symbol,
)
from .summaries import SummaryBuilder, SummaryIndex


_BINARY_OPS = {
    ida_hexrays.cot_add: "add",
    ida_hexrays.cot_sub: "sub",
    ida_hexrays.cot_mul: "mul",
    ida_hexrays.cot_sdiv: "div",
    ida_hexrays.cot_udiv: "div",
    ida_hexrays.cot_smod: "mod",
    ida_hexrays.cot_umod: "mod",
    ida_hexrays.cot_shl: "shl",
    ida_hexrays.cot_sshr: "shr",
    ida_hexrays.cot_ushr: "shr",
    ida_hexrays.cot_band: "and",
    ida_hexrays.cot_bor: "or",
    ida_hexrays.cot_xor: "xor",
    ida_hexrays.cot_land: "logical_and",
    ida_hexrays.cot_lor: "logical_or",
    ida_hexrays.cot_eq: "eq",
    ida_hexrays.cot_ne: "ne",
    ida_hexrays.cot_sge: "sge",
    ida_hexrays.cot_uge: "uge",
    ida_hexrays.cot_sle: "sle",
    ida_hexrays.cot_ule: "ule",
    ida_hexrays.cot_sgt: "sgt",
    ida_hexrays.cot_ugt: "ugt",
    ida_hexrays.cot_slt: "slt",
    ida_hexrays.cot_ult: "ult",
}

_COMPOUND_ASSIGNMENT_OPS = {
    ida_hexrays.cot_asgbor: "or",
    ida_hexrays.cot_asgxor: "xor",
    ida_hexrays.cot_asgband: "and",
    ida_hexrays.cot_asgadd: "add",
    ida_hexrays.cot_asgsub: "sub",
    ida_hexrays.cot_asgmul: "mul",
    ida_hexrays.cot_asgsshr: "shr",
    ida_hexrays.cot_asgushr: "shr",
    ida_hexrays.cot_asgshl: "shl",
    ida_hexrays.cot_asgsdiv: "div",
    ida_hexrays.cot_asgudiv: "div",
    ida_hexrays.cot_asgsmod: "mod",
    ida_hexrays.cot_asgumod: "mod",
}

_ASSIGNMENT_OPS = {ida_hexrays.cot_asg, *_COMPOUND_ASSIGNMENT_OPS}

_UNARY_PRESERVE_KEY = {
    ida_hexrays.cot_cast,
    ida_hexrays.cot_ref,
    ida_hexrays.cot_ptr,
}


_IFUNC_COPY_CACHE: dict[int, bool] = {}

# Hex-Rays can render some compiler builtins with their source-level argument
# list even though the machine call still carries a hidden object-size value.
# Correct only known incomplete prototypes before decompilation; complete user
# or loader types are left untouched.
_REQUIRED_ANALYSIS_PROTOTYPES: dict[str, tuple[int, str]] = {
    "__strncpy_chk": (
        4,
        "char *__strncpy_chk(char *destination, const char *source, "
        "size_t count, size_t destination_capacity);",
    ),
}

_PRIMED_FORTIFY_WRAPPERS: set[tuple[str, int]] = set()


def prepare_analysis_types() -> tuple[int, ...]:
    """Stabilize known fortify ABI and its immediate local wrappers.

    Besides correcting incomplete imported prototypes, decompile only local
    functions that directly call a fortify entry point.  Hex-Rays then stores
    their inferred parameter list before ordinary callers are extracted.  The
    scope is intentionally narrow: priming the entire call graph changes
    unrelated lvar recovery and creates corpus regressions.
    """

    changed: list[int] = []
    fortify_targets: set[int] = set()
    for ea, raw_name in idautils.Names():
        normalized = normalize_symbol(raw_name)
        if normalized in FORTIFIED_DESTINATION_SPECS:
            fortify_targets.add(int(ea))
        specification = _REQUIRED_ANALYSIS_PROTOTYPES.get(normalized)
        if specification is None:
            continue
        required_arguments, declaration = specification
        existing = ida_typeinf.tinfo_t()
        details = ida_typeinf.func_type_data_t()
        if (
            ida_nalt.get_tinfo(existing, ea)
            and existing.is_func()
            and existing.get_func_details(details)
            and int(details.size()) >= required_arguments
        ):
            continue

        corrected = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(
            corrected,
            ida_typeinf.get_idati(),
            declaration,
            ida_typeinf.PT_SIL,
        ):
            continue
        if not ida_typeinf.apply_tinfo(
            ea, corrected, ida_typeinf.TINFO_DEFINITE
        ):
            continue
        changed.append(int(ea))
        for reference in idautils.XrefsTo(ea):
            function = ida_funcs.get_func(reference.frm)
            if function is not None:
                try:
                    ida_hexrays.mark_cfunc_dirty(int(function.start_ea))
                except Exception:
                    pass

    if not ida_hexrays.init_hexrays_plugin():
        return tuple(sorted(set(changed)))

    input_key = ida_nalt.get_input_file_path() or "<unknown-input>"
    corrected = set(changed)
    affected: set[int] = set(changed)
    for target_ea in sorted(fortify_targets):
        for reference in idautils.XrefsTo(target_ea):
            if not reference.iscode:
                continue
            wrapper = ida_funcs.get_func(reference.frm)
            if wrapper is None or wrapper.flags & (
                ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK
            ):
                continue
            wrapper_ea = int(wrapper.start_ea)
            cache_key = (input_key, wrapper_ea)
            if cache_key in _PRIMED_FORTIFY_WRAPPERS and target_ea not in corrected:
                continue
            if target_ea in corrected:
                try:
                    ida_hexrays.mark_cfunc_dirty(wrapper_ea)
                except Exception:
                    pass
            try:
                cfunc = ida_hexrays.decompile(wrapper_ea)
            except Exception:
                cfunc = None
            if cfunc is None:
                continue
            _PRIMED_FORTIFY_WRAPPERS.add(cache_key)
            affected.add(wrapper_ea)
            for caller_reference in idautils.XrefsTo(wrapper_ea):
                if not caller_reference.iscode:
                    continue
                caller = ida_funcs.get_func(caller_reference.frm)
                if caller is None:
                    continue
                caller_ea = int(caller.start_ea)
                affected.add(caller_ea)
                try:
                    ida_hexrays.mark_cfunc_dirty(caller_ea)
                except Exception:
                    pass
    return tuple(sorted(affected))


def _instruction_text(ea: int) -> str:
    try:
        return ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "").lower()
    except Exception:
        return ""


def _is_copy_implementation(ea: int) -> bool:
    """Fingerprint a SysV x86-64 ``(dst, src, length)`` copy primitive."""

    function = ida_funcs.get_func(ea)
    if function is None:
        return False
    lines = [_instruction_text(item) for item in idautils.FuncItems(function.start_ea)]
    has_copy_loop = any(re.search(r"\brep(?:e)?\s+movs[bqwd]?\b", line) for line in lines)
    returns_destination = any(
        re.search(r"\bmov\s+(?:r|e)ax\s*,\s*(?:r|e)di\b", line)
        or re.search(r"\blea\s+rax\s*,\s*\[rdi(?:\s*\+\s*rdx)?\]", line)
        for line in lines
    )
    length_to_counter = any(
        re.search(r"\bmov\s+(?:r|e)cx\s*,\s*(?:r|e)dx\b", line)
        for line in lines
    )
    if has_copy_loop and returns_destination and length_to_counter:
        return True

    # Modern glibc resolver candidates are usually AVX/AVX-512 routines, not
    # REP MOVS loops.  Require repeated reads from RSI and writes through RDI,
    # plus an RDX-controlled length and the conventional destination return.
    # This excludes memset (RSI is a scalar byte) and comparison/search code
    # (which does not write through RDI).
    source_reads = sum("[rsi" in line for line in lines)
    destination_writes = sum(
        bool(
            re.search(
                r"^\w+\s+(?:(?:byte|word|dword|qword|xmmword|ymmword|zmmword)\s+ptr\s+)?\[rdi",
                line.strip(),
            )
        )
        for line in lines
    )
    length_uses = sum(bool(re.search(r"\brdx\b|\bedx\b", line)) for line in lines)
    return (
        returns_destination
        and source_reads >= 2
        and destination_writes >= 2
        and length_uses >= 2
    )


def _is_memory_copy_ifunc(ea: int) -> bool:
    """Identify a stripped IRELATIVE memcpy/memmove/mempcpy-like thunk.

    IRELATIVE relocations do not retain the original symbol.  We therefore
    expose only the shared memory-copy semantics and require independent
    agreement between the thunk target, GOT fixup, and multiple resolver
    implementation candidates.
    """

    ea = int(ea)
    cached = _IFUNC_COPY_CACHE.get(ea)
    if cached is not None:
        return cached
    _IFUNC_COPY_CACHE[ea] = False
    try:
        function = ida_funcs.get_func(ea)
        if function is None or not (function.flags & ida_funcs.FUNC_THUNK):
            return False
        entry = ida_funcs.func_entry_info_t()
        if not ida_funcs.get_func_entry_info(entry, ea):
            return False
        target = ida_funcs.calc_thunk_function_target(entry)
        if not isinstance(target, tuple) or len(target) < 2:
            return False
        resolver, got_slot = int(target[0]), int(target[1])
        if resolver == ida_idaapi.BADADDR or got_slot == ida_idaapi.BADADDR:
            return False

        fixup = ida_fixup.fixup_data_t()
        if not ida_fixup.get_fixup(fixup, got_slot) or int(fixup.off) != resolver:
            return False

        implementations: set[int] = set()
        for item in idautils.FuncItems(resolver):
            for reference in idautils.DataRefsFrom(item):
                segment = ida_segment.getseg(reference)
                candidate = ida_funcs.get_func(reference)
                if (
                    segment is not None
                    and segment.perm & ida_segment.SEGPERM_EXEC
                    and candidate is not None
                ):
                    implementations.add(int(candidate.start_ea))
        if sum(_is_copy_implementation(item) for item in implementations) < 2:
            return False
        _IFUNC_COPY_CACHE[ea] = True
        return True
    except Exception:
        return False


class CtreeExtractor:
    def __init__(self, cfunc: ida_hexrays.cfunc_t):
        self.cfunc = cfunc
        self.function_ea = int(cfunc.entry_ea)
        self.lvars = list(cfunc.get_lvars())
        self.buffers: dict[str, BufferInfo] = {}
        self._stack_layout: dict[str, tuple[int, int]] = {}
        self._stack_slots: dict[str, StackSlot] = {}
        self.statements: list[Call | Assignment | Return] = []
        self.conditions: list[Condition] = []
        self._guards_by_call_item: dict[tuple[str, int], list[Expr]] = {}
        self._guards_by_assignment_item: dict[tuple[str, int], list[Expr]] = {}
        self._guards_by_return_item: dict[tuple[str, int], list[Expr]] = {}
        self._ctree_indices_ready = False
        self.blocks: dict[int, BasicBlock] = {}
        self.entry_block: int | None = None
        self.cfg_source = ""
        self._micro_ea_blocks: dict[int, int] = {}
        self._microcode_blocks = 0
        self._order = 0
        # Building Hex-Rays' microcode graph can refine lvar types in place.
        # Capture source-level stack object widths before requesting that graph.
        self._collect_stack_buffers()
        self._collect_cfg()

    def extract(self) -> FunctionIR:
        extractor = self
        try:
            # citem_t.index is unique within cfunc_t.treeitems, but the SDK
            # only guarantees it after the function has been printed.
            self.cfunc.get_pseudocode()
            self._ctree_indices_ready = True
        except Exception:
            self._ctree_indices_ready = False

        class Visitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, expression):
                extractor._visit_expression(expression)
                return 0

            def visit_insn(self, instruction):
                extractor._visit_instruction(instruction)
                return 0

        Visitor().apply_to(self.cfunc.body, None)
        self._refine_initialized_stack_spans()
        self._mark_stack_guard_sentinels()
        raw_name = (
            ida_funcs.get_func_name(self.function_ea)
            or f"sub_{self.function_ea:X}"
        )
        name = normalize_symbol(raw_name)
        return FunctionIR(
            ea=self.function_ea,
            name=name,
            parameters=self._function_parameters(),
            buffers=self.buffers,
            stack_slots=self._stack_slots,
            statements=self.statements,
            blocks=self.blocks,
            entry_block=self.entry_block,
            conditions=self.conditions,
            microcode_blocks=self._microcode_block_count(),
            cfg_source=self.cfg_source,
        )

    def _collect_cfg(self) -> None:
        if self._collect_microcode_cfg():
            return
        function = ida_funcs.get_func(self.function_ea)
        if function is None:
            return
        try:
            flowchart = ida_gdl.FlowChart(function)
            raw_blocks = list(flowchart)
            for block in raw_blocks:
                block_id = int(block.id)
                self.blocks[block_id] = BasicBlock(
                    id=block_id,
                    start_ea=int(block.start_ea),
                    end_ea=int(block.end_ea),
                    predecessors=tuple(int(item.id) for item in block.preds()),
                    successors=tuple(int(item.id) for item in block.succs()),
                )
            if raw_blocks:
                self.entry_block = int(raw_blocks[0].id)
                self.cfg_source = "disassembly"
        except Exception:
            self.blocks.clear()
            self.entry_block = None
            self.cfg_source = ""

    def _collect_microcode_cfg(self) -> bool:
        try:
            mba = self.cfunc.mba
            mba.build_graph()
            blocks: dict[int, BasicBlock] = {}
            for index in range(int(mba.qty)):
                block = mba.get_mblock(index)
                block_id = int(block.serial)
                blocks[block_id] = BasicBlock(
                    id=block_id,
                    start_ea=int(block.start),
                    end_ea=int(block.end),
                    predecessors=tuple(int(item) for item in block.predset),
                    successors=tuple(int(item) for item in block.succset),
                )
                instruction = block.head
                while instruction is not None:
                    ea = int(instruction.ea)
                    if ea != ida_idaapi.BADADDR:
                        self._micro_ea_blocks.setdefault(ea, block_id)
                    instruction = instruction.next
            if not blocks:
                return False
            self.blocks = blocks
            self.entry_block = min(blocks)
            self._microcode_blocks = len(blocks)
            self.cfg_source = "microcode"
            return True
        except Exception:
            self._micro_ea_blocks.clear()
            self._microcode_blocks = 0
            return False

    def _microcode_block_count(self) -> int:
        return self._microcode_blocks

    def _function_parameters(self) -> tuple[str, ...]:
        try:
            return tuple(self._variable_key(int(index)) for index in self.cfunc.argidx)
        except Exception:
            return tuple(
                self._variable_key(index)
                for index, variable in enumerate(self.lvars)
                if bool(variable.is_arg_var)
            )

    def _collect_stack_buffers(self) -> None:
        stack_starts: list[int] = []
        for variable in self.lvars:
            try:
                if variable.is_stk_var() and not bool(variable.is_arg_var):
                    offset = int(variable.get_stkoff())
                    if offset >= 0:
                        stack_starts.append(offset)
            except Exception:
                continue
        stack_starts = sorted(set(stack_starts))

        for index, variable in enumerate(self.lvars):
            try:
                if variable.is_stk_var() and not bool(variable.is_arg_var):
                    offset = int(variable.get_stkoff())
                    width = int(variable.width)
                    if offset >= 0 and width > 0:
                        key = self._variable_key(index)
                        self._stack_layout[key] = (offset, width)
                        if variable.tif.is_ptr():
                            type_kind = "pointer"
                        elif variable.tif.is_integral() or variable.tif.is_enum():
                            type_kind = "integer"
                        elif variable.tif.is_array() or variable.tif.is_udt():
                            type_kind = "aggregate"
                        else:
                            type_kind = "other"
                        self._stack_slots[key] = StackSlot(
                            key=key,
                            name=variable.name or f"v{index}",
                            offset=offset,
                            width=width,
                            type_kind=type_kind,
                        )
                is_pointer = variable.tif.is_ptr()
                structural_type = variable.tif.is_array() or variable.tif.is_udt()
                candidate = (
                    variable.is_stk_var()
                    and not bool(variable.is_arg_var)
                    and not is_pointer
                    and (structural_type or variable.is_used_byref())
                )
                if not candidate:
                    continue
                capacity = int(variable.width)
                if capacity <= 0:
                    capacity = None
                physical_capacity = capacity
                stack_offset = int(variable.get_stkoff())
                following = [offset for offset in stack_starts if offset > stack_offset]
                if following:
                    span = min(following) - stack_offset
                    if 0 < span < (1 << 24):
                        physical_capacity = max(capacity or 0, span)
                key = self._variable_key(index)
                self.buffers[key] = BufferInfo(
                    key=key,
                    name=variable.name or f"v{index}",
                    storage="stack",
                    capacity=capacity,
                    precise=structural_type,
                    physical_capacity=physical_capacity,
                )
            except Exception:
                # Malformed or partial types should not abort a binary scan.
                continue

    def _refine_initialized_stack_spans(self) -> None:
        """Recover arrays that Hex-Rays split into zeroed scalar fragments.

        Optimized code commonly clears a source array as adjacent QWORD/QWORD/
        WORD stores.  Hex-Rays then declares only the first fragment as an
        array and the rest as independent scalars, producing false sprintf and
        read overflows.  A contiguous run in the real stack layout, with every
        fragment explicitly zero-initialized, is strong evidence for the
        compiler-allocated aggregate.  The recovered span is only a physical
        upper bound; it never creates a new writable object on its own.
        """

        zeroed: set[str] = set()
        for statement in self.statements:
            if not isinstance(statement, Assignment) or statement.target.key is None:
                continue
            value = statement.value.unwrapped()
            if value.kind == "const" and value.value == 0:
                zeroed.add(statement.target.key)

        by_offset = {
            offset: (key, width)
            for key, (offset, width) in self._stack_layout.items()
        }
        for key, buffer in tuple(self.buffers.items()):
            layout = self._stack_layout.get(key)
            if (
                buffer.storage != "stack"
                or not buffer.precise
                or buffer.capacity is None
                or layout is None
                or key not in zeroed
            ):
                continue
            start, _ = layout
            end = start + buffer.capacity
            fragments = 0
            while end in by_offset:
                next_key, width = by_offset[end]
                if next_key not in zeroed or width <= 0:
                    break
                end += width
                fragments += 1
            recovered = end - start
            if fragments >= 2 and recovered > (buffer.physical_capacity or 0):
                self.buffers[key] = replace(buffer, physical_capacity=recovered)

    def _mark_stack_guard_sentinels(self) -> None:
        """Mark arrays immediately followed by glibc's x86 stack guard.

        Linux x86-64 stack-protector prologues load the guard from ``FS:0x28``.
        glibc deliberately clears its least-significant byte, so on this
        little-endian target an exact-capacity byte input followed by a
        C-string consumer encounters a deterministic NUL at the next address.
        Require both the characteristic load and exact lvar adjacency; merely
        seeing stack-protector code elsewhere in a function is insufficient.
        """

        canary_keys: set[str] = set()
        for statement in self.statements:
            if (
                not isinstance(statement, Assignment)
                or statement.target.key is None
            ):
                continue
            value = statement.value.unwrapped()
            if (
                value.kind == "call"
                and normalize_symbol(value.callee or "") == "__readfsqword"
                and value.children
                and value.children[0].kind == "const"
                and value.children[0].value == 0x28
            ):
                canary_keys.add(statement.target.key)
        if not canary_keys:
            return

        by_offset = {
            offset: key for key, (offset, _width) in self._stack_layout.items()
        }
        for key, buffer in tuple(self.buffers.items()):
            layout = self._stack_layout.get(key)
            if (
                buffer.storage != "stack"
                or buffer.capacity is None
                or layout is None
            ):
                continue
            offset, _width = layout
            following_key = by_offset.get(offset + buffer.capacity)
            if following_key in canary_keys:
                self.buffers[key] = replace(
                    buffer, trailing_nul_sentinel=True
                )

    def _visit_expression(self, expression: ida_hexrays.cexpr_t) -> None:
        self._order += 1
        ea = self._usable_ea(expression.ea)
        try:
            if expression.op in _ASSIGNMENT_OPS:
                target = self._convert(expression.x)
                value = self._convert(expression.y)
                if expression.op in _COMPOUND_ASSIGNMENT_OPS:
                    key = None
                    offset = 0
                    if (
                        expression.op
                        in {ida_hexrays.cot_asgadd, ida_hexrays.cot_asgsub}
                        and target.is_pointer is True
                        and target.key is not None
                        and value.kind == "const"
                        and value.value is not None
                    ):
                        delta = value.value * self._pointed_object_size(expression.x)
                        if expression.op == ida_hexrays.cot_asgsub:
                            delta = -delta
                        key = target.key
                        offset = target.offset + delta
                    value = Expr(
                        kind="op",
                        text=self._text(expression),
                        key=key,
                        op=_COMPOUND_ASSIGNMENT_OPS[expression.op],
                        children=(target, value),
                        offset=offset,
                        bits=target.bits,
                        signed=target.signed,
                        is_pointer=target.is_pointer,
                    )
                self.statements.append(
                    Assignment(
                        order=self._order,
                        ea=ea,
                        target=target,
                        value=value,
                        text=self._text(expression),
                        block_id=self._block_for_ea(ea),
                        guards=tuple(
                            self._guards_by_assignment_item.get(
                                self._ctree_item_key(expression), ()
                            )
                        ),
                    )
                )
            elif expression.op == ida_hexrays.cot_call:
                name, callee_ea = self._callee_identity(expression.x)
                target = None if name else self._convert(expression.x)
                self.statements.append(
                    Call(
                        order=self._order,
                        ea=ea,
                        name=name or "indirect_call",
                        args=tuple(self._convert(argument) for argument in expression.a),
                        text=self._text(expression),
                        callee_ea=callee_ea,
                        block_id=self._block_for_ea(ea),
                        guards=tuple(
                            self._guards_by_call_item.get(
                                self._ctree_item_key(expression), ()
                            )
                        ),
                        target=target,
                    )
                )
        except Exception:
            print(
                f"[PwnHunter] Failed to normalize expression at 0x{ea:X}\n"
                f"{traceback.format_exc()}"
            )

    def _visit_instruction(self, instruction: ida_hexrays.cinsn_t) -> None:
        self._collect_condition(instruction)
        if instruction.op != ida_hexrays.cit_return:
            return
        self._order += 1
        ea = self._usable_ea(instruction.ea)
        try:
            value = instruction.creturn.expr
            self.statements.append(
                Return(
                    order=self._order,
                    ea=ea,
                    value=self._convert(value),
                    text=self._instruction_text(instruction),
                    block_id=self._block_for_ea(ea),
                    guards=tuple(
                        self._guards_by_return_item.get(
                            self._ctree_item_key(instruction), ()
                        )
                    ),
                )
            )
        except Exception:
            print(
                f"[PwnHunter] Failed to normalize return at 0x{ea:X}\n"
                f"{traceback.format_exc()}"
            )

    def _collect_condition(self, instruction: ida_hexrays.cinsn_t) -> None:
        expression = None
        guarded_body = None
        alternate_body = None
        try:
            if instruction.op == ida_hexrays.cit_if:
                expression = instruction.cif.expr
                guarded_body = instruction.cif.ithen
                alternate_body = instruction.cif.ielse
            elif instruction.op == ida_hexrays.cit_while:
                expression = instruction.cwhile.expr
                guarded_body = instruction.cwhile.body
            elif instruction.op == ida_hexrays.cit_do:
                expression = instruction.cdo.expr
                guarded_body = instruction.cdo.body
            elif instruction.op == ida_hexrays.cit_for:
                expression = instruction.cfor.expr
                guarded_body = instruction.cfor.body
        except Exception:
            return
        if expression is None:
            return
        ea = self._usable_ea(expression.ea)
        converted = self._convert(expression)
        self.conditions.append(
            Condition(
                ea=ea,
                block_id=self._block_for_ea(ea),
                expression=converted,
                text=self._text(expression),
                order=self._order,
            )
        )
        self._record_short_circuit_guards(expression)
        if guarded_body is not None:
            self._record_guarded_calls(guarded_body, converted)
        if alternate_body is not None:
            self._record_guarded_calls(
                alternate_body,
                Analyzer._negate_guard_expression(converted),
            )

    def _record_guarded_calls(
        self, body: ida_hexrays.cinsn_t, guard: Expr
    ) -> None:
        """Attach a normalized path predicate to statements in a ctree body.

        This deliberately records source containment rather than guessing from
        condition addresses.  Hex-Rays frequently assigns BADADDR to compound
        refcount conditions, so their address maps to the function entry and
        cannot be associated with the protected ``free`` through the CFG.
        """

        self._record_guarded_items(body, guard)

    def _record_short_circuit_guards(
        self, expression: ida_hexrays.cexpr_t
    ) -> None:
        """Bind predicates that gate evaluation inside a condition.

        The right operand of ``a && b`` runs under ``a``; the right operand
        of ``a || b`` runs under ``!a``.  Ternary arms similarly inherit the
        condition polarity.  These are evaluation facts, not CFG-wide facts,
        so attach them directly to the ctree items in the gated subtree.
        """

        extractor = self
        pending: list[tuple[ida_hexrays.cexpr_t, Expr]] = []

        class ShortCircuitCollector(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, item):
                if item.op == ida_hexrays.cot_land:
                    pending.append((item.y, extractor._convert(item.x)))
                elif item.op == ida_hexrays.cot_lor:
                    pending.append(
                        (
                            item.y,
                            Analyzer._negate_guard_expression(
                                extractor._convert(item.x)
                            ),
                        )
                    )
                elif item.op == ida_hexrays.cot_tern:
                    condition = extractor._convert(item.x)
                    pending.append((item.y, condition))
                    pending.append(
                        (
                            item.z,
                            Analyzer._negate_guard_expression(condition),
                        )
                    )
                return 0

        ShortCircuitCollector().apply_to(expression, None)
        for gated_expression, guard in pending:
            self._record_guarded_items(gated_expression, guard)

    def _record_guarded_items(self, root, guard: Expr) -> None:
        extractor = self

        class CallCollector(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)

            def visit_expr(self, expression):
                guard_map = None
                if expression.op == ida_hexrays.cot_call:
                    guard_map = extractor._guards_by_call_item
                elif expression.op in _ASSIGNMENT_OPS:
                    guard_map = extractor._guards_by_assignment_item
                if guard_map is not None:
                    item_key = extractor._ctree_item_key(expression)
                    guards = guard_map.setdefault(item_key, [])
                    if guard not in guards:
                        guards.append(guard)
                return 0

            def visit_insn(self, instruction):
                if instruction.op == ida_hexrays.cit_return:
                    item_key = extractor._ctree_item_key(instruction)
                    guards = extractor._guards_by_return_item.setdefault(
                        item_key, []
                    )
                    if guard not in guards:
                        guards.append(guard)
                return 0

        CallCollector().apply_to(root, None)

    def _ctree_item_key(self, item) -> tuple[str, int]:
        if self._ctree_indices_ready:
            try:
                return "item", int(item.index)
            except Exception:
                pass
        return "ea", self._usable_ea(item.ea)

    def _convert(self, expression: ida_hexrays.cexpr_t | None) -> Expr:
        if expression is None:
            return Expr(kind="unknown")
        op = expression.op
        text = self._text(expression)

        if op == ida_hexrays.cot_var:
            index = int(expression.v.idx)
            name = self.lvars[index].name if index < len(self.lvars) else f"v{index}"
            bits, signed = self._type_facts(expression)
            return Expr(
                kind="var",
                text=name,
                key=self._variable_key(index),
                bits=bits,
                signed=signed,
                is_pointer=self._pointer_fact(expression),
            )

        if op == ida_hexrays.cot_num:
            bits, signed = self._type_facts(expression)
            value = int(expression.numval())
            if re.fullmatch(r"-\d+", text.strip()):
                value = int(text.strip(), 10)
            elif signed is True and bits and value & (1 << (bits - 1)):
                value -= 1 << bits
            return Expr(
                kind="const",
                text=text,
                value=value,
                bits=bits,
                signed=signed,
                is_pointer=False,
            )

        if op == ida_hexrays.cot_sizeof:
            try:
                size = int(expression.x.type.get_size())
            except Exception:
                size = 0
            if size > 0:
                return Expr(kind="const", text=text, value=size, is_pointer=False)

        if op == ida_hexrays.cot_str:
            value = str(expression.string or "")
            return Expr(kind="string", text=text, string=value)

        if op == ida_hexrays.cot_obj:
            return self._convert_object(expression, text)

        if op == ida_hexrays.cot_helper:
            return Expr(kind="helper", text=text, callee=str(expression.helper or ""))

        if op == ida_hexrays.cot_call:
            name, callee_ea = self._callee_identity(expression.x)
            arguments = tuple(self._convert(argument) for argument in expression.a)
            bits, signed = self._type_facts(expression)
            return Expr(
                kind="call",
                text=text,
                callee=name or "indirect_call",
                callee_ea=callee_ea,
                children=arguments,
                bits=bits,
                signed=signed,
                is_pointer=self._pointer_fact(expression),
            )

        if op in _UNARY_PRESERVE_KEY:
            child = self._convert(expression.x)
            kinds = {
                ida_hexrays.cot_cast: "cast",
                ida_hexrays.cot_ref: "address",
                ida_hexrays.cot_ptr: "deref",
            }
            loaded_global_pointer = (
                op == ida_hexrays.cot_cast
                and expression.type.is_ptr()
                and child.kind in {"index", "member", "deref"}
                and bool(child.key and child.key.startswith("g:"))
            )
            bits, signed = self._type_facts(expression)
            return Expr(
                kind=kinds[op],
                text=text,
                key=(
                    None
                    if loaded_global_pointer
                    or (op == ida_hexrays.cot_ptr and expression.type.is_ptr())
                    else child.key
                ),
                children=(child,),
                offset=child.offset,
                bits=bits,
                signed=signed,
                is_pointer=self._pointer_fact(expression),
            )

        if op == ida_hexrays.cot_idx:
            base = self._convert(expression.x)
            index = self._convert(expression.y)
            offset = base.offset
            index_value = index.value if index.kind == "const" else None
            if index_value is not None:
                offset += index_value * self._pointed_object_size(expression.x)
            bits, signed = self._type_facts(expression)
            return Expr(
                kind="index",
                text=text,
                # Loading an element from a pointer table yields a pointer to
                # another object. Treating the table itself as that object's
                # capacity caused noisy heap-write reports in menu challenges.
                key=None if expression.type.is_ptr() else base.key,
                children=(base, index),
                offset=offset,
                bits=bits,
                signed=signed,
                is_pointer=self._pointer_fact(expression),
            )

        if op in {ida_hexrays.cot_memref, ida_hexrays.cot_memptr}:
            base = self._convert(expression.x)
            bits, signed = self._type_facts(expression)
            try:
                container_type = ida_typeinf.remove_pointer(expression.x.type)
                member_offset = 0 if container_type.is_union() else int(expression.m)
            except Exception:
                member_offset = int(expression.m)
            return Expr(
                kind="member",
                text=text,
                key=None if expression.type.is_ptr() else base.key,
                children=(base,),
                offset=base.offset + member_offset,
                bits=bits,
                signed=signed,
                is_pointer=self._pointer_fact(expression),
            )

        if op in _BINARY_OPS:
            left = self._convert(expression.x)
            right = self._convert(expression.y)
            key = None
            offset = 0
            if op in {ida_hexrays.cot_add, ida_hexrays.cot_sub}:
                key, offset = self._pointer_arithmetic(expression, left, right)
            bits, signed = self._type_facts(expression)
            return Expr(
                kind="op",
                text=text,
                key=key,
                op=_BINARY_OPS[op],
                children=(left, right),
                offset=offset,
                bits=bits,
                signed=signed,
                is_pointer=self._pointer_fact(expression),
            )

        if op == ida_hexrays.cot_tern:
            bits, signed = self._type_facts(expression)
            return Expr(
                kind="op",
                text=text,
                op="ternary",
                children=(
                    self._convert(expression.x),
                    self._convert(expression.y),
                    self._convert(expression.z),
                ),
                bits=bits,
                signed=signed,
                is_pointer=self._pointer_fact(expression),
            )

        children = tuple(
            self._convert(child)
            for child in (expression.x, expression.y, expression.z)
            if child is not None
        )
        bits, signed = self._type_facts(expression)
        return Expr(
            kind="op",
            text=text,
            op=expression.opname,
            children=children,
            bits=bits,
            signed=signed,
            is_pointer=self._pointer_fact(expression),
        )

    def _convert_object(self, expression: ida_hexrays.cexpr_t, text: str) -> Expr:
        ea = int(expression.obj_ea)
        value = self._read_string(ea) if expression.is_cstr() else None
        if value is not None:
            return Expr(kind="string", text=text, string=value)

        name = ida_name.get_ea_name(ea) or f"obj_{ea:X}"
        key = f"g:{ea:X}"
        try:
            flags = ida_bytes.get_flags(ea)
            structural_type = expression.type.is_array() or expression.type.is_udt()
            if not ida_bytes.is_code(flags) and structural_type:
                capacity = int(expression.type.get_size())
                if capacity <= 1:
                    capacity = int(ida_bytes.get_item_size(ea))
                if 1 < capacity < (1 << 48):
                    self.buffers.setdefault(
                        key,
                        BufferInfo(
                            key=key,
                            name=name,
                            storage="global",
                            capacity=capacity,
                            precise=True,
                        ),
                    )
        except Exception:
            pass
        bits, signed = self._type_facts(expression)
        return Expr(
            kind="global",
            text=text or name,
            key=key,
            bits=bits,
            signed=signed,
            is_pointer=self._pointer_fact(expression),
        )

    @staticmethod
    def _pointer_fact(expression: ida_hexrays.cexpr_t) -> bool | None:
        """Return Hex-Rays' result-type pointer fact when available."""

        try:
            return bool(expression.type.is_ptr())
        except Exception:
            return None

    @staticmethod
    def _type_facts(expression: ida_hexrays.cexpr_t) -> tuple[int | None, bool | None]:
        try:
            tif = expression.type
            size = int(tif.get_size())
            bits = size * 8 if size > 0 else None
            if tif.is_integral() or tif.is_enum():
                if tif.is_signed():
                    return bits, True
                if tif.is_unsigned():
                    return bits, False
            if tif.is_ptr():
                return bits, False
            return bits, None
        except Exception:
            return None, None

    def _callee_identity(
        self, expression: ida_hexrays.cexpr_t | None
    ) -> tuple[str, int | None]:
        current = expression
        while current is not None and current.op in _UNARY_PRESERVE_KEY:
            current = current.x
        if current is None:
            return "", None
        if current.op == ida_hexrays.cot_obj:
            ea = int(current.obj_ea)
            if _is_memory_copy_ifunc(ea):
                return "memcpy_like", ea
            name = ida_funcs.get_func_name(ea) or ida_name.get_ea_name(ea)
            return normalize_symbol(name or ""), ea
        if current.op == ida_hexrays.cot_helper:
            return normalize_symbol(str(current.helper or "")), None
        return "", None

    def _callee_name(self, expression: ida_hexrays.cexpr_t | None) -> str:
        return self._callee_identity(expression)[0]

    def _pointer_arithmetic(
        self, expression: ida_hexrays.cexpr_t, left: Expr, right: Expr
    ) -> tuple[str | None, int]:
        try:
            result_is_pointer = bool(expression.type.is_ptr())
            left_is_pointer = bool(expression.x.type.is_ptr())
            right_is_pointer = bool(expression.y.type.is_ptr())
        except Exception:
            result_is_pointer = False
            left_is_pointer = False
            right_is_pointer = False
        if not result_is_pointer:
            return None, 0
        if (
            left_is_pointer
            and left.kind != "deref"
            and left.key
            and right.kind == "const"
            and right.value is not None
        ):
            scale = self._pointed_object_size(expression.x)
            delta = right.value * scale
            if expression.op == ida_hexrays.cot_sub:
                delta = -delta
            return left.key, left.offset + delta
        if (
            expression.op == ida_hexrays.cot_add
            and right_is_pointer
            and right.key
            and left.kind == "const"
            and left.value is not None
        ):
            scale = self._pointed_object_size(expression.y)
            return right.key, right.offset + left.value * scale
        if left_is_pointer and left.kind != "deref" and left.key:
            # Preserve the base object for ``*((byte *)buffer + index)``.
            # The dynamic displacement remains in the expression children;
            # ``offset`` contains only the known constant portion.
            return left.key, left.offset
        if expression.op == ida_hexrays.cot_add and right_is_pointer and right.key:
            return right.key, right.offset
        return None, 0

    @staticmethod
    def _pointed_object_size(expression: ida_hexrays.cexpr_t) -> int:
        try:
            size = int(expression.type.get_ptrarr_objsize())
            return size if size > 0 else 1
        except Exception:
            return 1

    @staticmethod
    def _variable_key(index: int) -> str:
        return f"v:{index}"

    def _text(self, expression: ida_hexrays.cexpr_t) -> str:
        try:
            return ida_lines.tag_remove(expression.print1(self.cfunc))
        except Exception:
            return expression.opname

    def _instruction_text(self, instruction: ida_hexrays.cinsn_t) -> str:
        try:
            return ida_lines.tag_remove(instruction.print1(self.cfunc))
        except Exception:
            return "return"

    def _usable_ea(self, ea: int) -> int:
        return self.function_ea if ea == ida_idaapi.BADADDR else int(ea)

    def _block_for_ea(self, ea: int) -> int | None:
        if ea in self._micro_ea_blocks:
            return self._micro_ea_blocks[ea]
        for block_id, block in self.blocks.items():
            if block.start_ea <= ea < block.end_ea:
                return block_id
        preceding = [
            block
            for block in self.blocks.values()
            if block.start_ea != ida_idaapi.BADADDR and block.start_ea <= ea
        ]
        if preceding:
            return max(preceding, key=lambda block: block.start_ea).id
        return self.entry_block

    @staticmethod
    def _read_string(ea: int) -> str | None:
        try:
            string_type = ida_nalt.get_str_type(ea)
            length = ida_bytes.get_max_strlit_length(
                ea,
                string_type,
                ida_bytes.ALOPT_IGNHEADS | ida_bytes.ALOPT_IGNCLT,
            )
            raw = ida_bytes.get_strlit_contents(ea, length, string_type)
            if raw is None:
                return None
            return raw.rstrip(b"\x00").decode("utf-8", errors="replace")
        except Exception:
            return None


@dataclass(slots=True)
class ScanConfig:
    """Bounds for a competition-friendly scan."""

    max_functions: int = 240
    max_seconds: float = 25.0
    max_function_bytes: int = 65536
    caller_depth: int = 2
    callee_depth: int = 1
    max_string_seeds: int = 240

    @classmethod
    def from_environment(cls) -> "ScanConfig":
        defaults = cls()

        def integer(name: str, default: int) -> int:
            try:
                return max(1, int(os.environ.get(name, str(default))))
            except ValueError:
                return default

        def floating(name: str, default: float) -> float:
            try:
                return max(1.0, float(os.environ.get(name, str(default))))
            except ValueError:
                return default

        return cls(
            max_functions=integer(
                "PWN_HUNTER_MAX_FUNCTIONS", defaults.max_functions
            ),
            max_seconds=floating("PWN_HUNTER_MAX_SECONDS", defaults.max_seconds),
            max_function_bytes=integer(
                "PWN_HUNTER_MAX_FUNCTION_BYTES", defaults.max_function_bytes
            ),
            caller_depth=integer("PWN_HUNTER_CALLER_DEPTH", defaults.caller_depth),
            callee_depth=integer("PWN_HUNTER_CALLEE_DEPTH", defaults.callee_depth),
            max_string_seeds=integer(
                "PWN_HUNTER_MAX_STRING_SEEDS", defaults.max_string_seeds
            ),
        )


@dataclass(slots=True)
class ScanCandidate:
    ea: int
    score: int = 0
    reasons: set[str] = field(default_factory=set)


@dataclass(slots=True)
class ScanStats:
    total_functions: int = 0
    selected_functions: int = 0
    scanned_functions: int = 0
    cached_functions: int = 0
    skipped_large: int = 0
    failures: int = 0
    timed_out: bool = False
    cancelled: bool = False
    elapsed_seconds: float = 0.0
    summary_count: int = 0
    summary_iterations: int = 0
    summary_recomputed: int = 0
    summary_seconds: float = 0.0
    microcode_functions: int = 0
    microcode_blocks: int = 0
    finding_sites: int = 0
    filtered_runtime_sites: int = 0


_PROMPT_STRING = re.compile(
    r"(?:please\s+(?:enter|input)\s+)?"
    r"(?:choice|index|size|content|data|username|user|password|name)\s*[:?]?",
    re.IGNORECASE,
)

_MENU_ACTION = re.compile(
    r"(?:^|\n)\s*\d+\s*[.)]\s*(?:add|edit|delete|show|view|create|login|register)",
    re.IGNORECASE,
)


def _interaction_string_score(text: str) -> int:
    """Prefer challenge UI text over library symbols and diagnostics."""

    stripped = text.strip()
    lowered = stripped.lower()
    if not stripped or len(stripped) > 256:
        return 0
    if any(marker in stripped for marker in ("../", "\\", "::")):
        return 0
    if "%" in stripped or "_" in stripped:
        return 0
    if re.search(
        r"(?:\b(?:read|write|open|stat|scandir)\s+failed\b|"
        r"\bfailed\s+to\s+(?:read|write|open|stat|scan)\b)",
        lowered,
    ):
        return 130
    if "login failed" in lowered or "login successful" in lowered:
        return 150
    if _MENU_ACTION.search(stripped) or ("menu" in lowered and len(stripped) < 80):
        return 140
    if _PROMPT_STRING.fullmatch(stripped):
        return 135
    if re.search(r"\b(?:invalid|wrong)\s+(?:index|size|choice|password|username)\b", lowered):
        return 120
    if re.search(r"\bflag\s*[:{?]", lowered):
        return 120
    if (
        len(stripped) < 56
        and re.fullmatch(
            r"(?:please\s+)?(?:login|register|add|edit|delete|show|view)(?:\s+\w+)?[.!:?]?",
            lowered,
        )
    ):
        return 100
    return 0


class CandidateSelector:
    """Rank functions without paying the cost of decompiling the whole IDB."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.candidates: dict[int, ScanCandidate] = {}
        self.total_functions = 0
        self.skipped_large = 0
        self._skipped_large_eas: set[int] = set()

    def discover(self) -> list[ScanCandidate]:
        functions = list(idautils.Functions())
        self.total_functions = len(functions)

        seed_targets: set[int] = set()
        for ea, raw_name in idautils.Names():
            if normalize_symbol(raw_name) in SCAN_SEED_NAMES:
                seed_targets.add(int(ea))

        for target in seed_targets:
            for xref in idautils.XrefsTo(target):
                self._add_containing(xref.frm, 120, "dangerous API caller")

        ranked_strings: list[tuple[int, str, list[object]]] = []
        for value in idautils.Strings():
            text = str(value)
            score = _interaction_string_score(text)
            if not score:
                continue
            xrefs = list(idautils.XrefsTo(value.ea))
            if not xrefs:
                continue
            ranked_strings.append((score, text, xrefs))

        ranked_strings.sort(key=lambda item: (-item[0], len(item[1]), item[1]))
        best_string_score = ranked_strings[0][0] if ranked_strings else 0
        score_floor = max(100, best_string_score - 20)
        ranked_strings = [
            item for item in ranked_strings if item[0] >= score_floor
        ]
        for score, text, xrefs in ranked_strings[: self.config.max_string_seeds]:
            reason = f"interactive string: {text[:48]}"
            for xref in xrefs:
                self._add_containing(xref.frm, score, reason)

        for ea in functions:
            name = normalize_symbol(ida_funcs.get_func_name(ea))
            if name in {"main", "wmain", "WinMain", "start", "_start"}:
                self._add(ea, 80, "entry function")
        try:
            self._add_containing(ida_ida.inf_get_start_ea(), 70, "program entry")
        except Exception:
            pass

        initial = set(self.candidates)
        frontier = initial
        for depth in range(self.config.caller_depth):
            next_frontier: set[int] = set()
            for ea in frontier:
                interactive_lineage = any(
                    "interactive" in reason
                    for reason in self.candidates[ea].reasons
                )
                score = (
                    max(105, 125 - depth * 10)
                    if interactive_lineage
                    else max(35, 70 - depth * 15)
                )
                reason = (
                    "interactive caller graph"
                    if interactive_lineage
                    else "caller graph"
                )
                for reference in idautils.CodeRefsTo(ea, False):
                    caller = self._function_start(reference)
                    if caller is None:
                        continue
                    existed = caller in self.candidates
                    if self._add(caller, score, reason):
                        if not existed:
                            next_frontier.add(caller)
            frontier = next_frontier

        # Caller expansion commonly reaches menu handlers or thin parsing
        # wrappers that were not direct API/string seeds.  Their immediate
        # helpers are just as important to interprocedural summaries as the
        # callees of the original seeds (for example, input -> parser ->
        # output-parameter chains), so start callee expansion from the whole
        # discovered caller neighborhood.
        frontier = set(self.candidates)
        for depth in range(self.config.callee_depth):
            next_frontier = set()
            for ea in frontier:
                interactive_lineage = any(
                    "interactive" in reason
                    for reason in self.candidates[ea].reasons
                )
                score = (
                    max(105, 125 - depth * 10)
                    if interactive_lineage
                    else max(25, 50 - depth * 10)
                )
                reason = (
                    "interactive callee graph"
                    if interactive_lineage
                    else "callee graph"
                )
                for target in self._direct_callees(ea):
                    existed = target in self.candidates
                    if self._add(target, score, reason):
                        if not existed:
                            next_frontier.add(target)
            frontier = next_frontier

        # A malformed or highly obfuscated binary may expose no useful names
        # or strings. Keep the entry neighborhood as a deterministic fallback.
        if not self.candidates:
            for ea in functions[: self.config.max_functions]:
                self._add(ea, 1, "fallback")

        ranked = sorted(
            self.candidates.values(),
            key=lambda item: (-item.score, self._function_size(item.ea), item.ea),
        )
        return ranked[: self.config.max_functions]

    def _add_containing(self, ea: int, score: int, reason: str) -> bool:
        start = self._function_start(ea)
        return bool(start is not None and self._add(start, score, reason))

    def _add(self, ea: int, score: int, reason: str) -> bool:
        function = ida_funcs.get_func(ea)
        if function is None:
            return False
        start = int(function.start_ea)
        if function.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
            return False
        # Some loaders represent PLT/import veneers as ordinary functions
        # named `.symbol` instead of setting FUNC_THUNK. They add noise and
        # never contain a challenge vulnerability themselves.
        if (ida_funcs.get_func_name(start) or "").startswith("."):
            return False
        if int(function.end_ea - function.start_ea) > self.config.max_function_bytes:
            if start not in self._skipped_large_eas:
                self._skipped_large_eas.add(start)
                self.skipped_large += 1
            return False
        candidate = self.candidates.setdefault(start, ScanCandidate(start))
        candidate.score = max(candidate.score, score)
        candidate.reasons.add(reason)
        return True

    @staticmethod
    def _function_start(ea: int) -> int | None:
        function = ida_funcs.get_func(ea)
        return int(function.start_ea) if function is not None else None

    @staticmethod
    def _function_size(ea: int) -> int:
        function = ida_funcs.get_func(ea)
        return int(function.end_ea - function.start_ea) if function else 0

    @staticmethod
    def _direct_callees(ea: int) -> set[int]:
        result: set[int] = set()
        for instruction_ea in idautils.FuncItems(ea):
            for target in idautils.CodeRefsFrom(instruction_ea, False):
                function = ida_funcs.get_func(target)
                if function is not None:
                    result.add(int(function.start_ea))
        return result
class IDAScanner:
    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig.from_environment()
        self.analyzer = Analyzer()
        self.chooser: FindingsChooser | None = None
        self.last_stats = ScanStats()
        self.last_candidates: list[ScanCandidate] = []
        self.last_summaries = SummaryIndex()
        self.last_runtime_functions: frozenset[int] = frozenset()
        self._ir_cache: dict[int, FunctionIR] = {}

    def scan_current_function(self) -> list[Finding]:
        ida_auto.auto_wait()
        if prepare_analysis_types():
            self.clear_cache()
        function = ida_funcs.get_func(ida_kernwin.get_screen_ea())
        if function is None:
            ida_kernwin.warning("PwnHunter: place the cursor inside a function")
            return []
        function_ea = int(function.start_ea)
        ir = self._extract_function(function_ea)
        findings = self.analyzer.analyze_function(ir) if ir is not None else []
        if ir is not None:
            findings.extend(known_converter_findings([ir], self._input_path()))
        self._show_findings(findings, "PwnHunter - Current Function")
        return findings

    def scan_all(self) -> list[Finding]:
        return self.scan_quick(show_ui=True)

    def scan_quick(self, show_ui: bool = True) -> list[Finding]:
        ida_auto.auto_wait()
        if prepare_analysis_types():
            self.clear_cache()
        started = time.monotonic()
        selector = CandidateSelector(self.config)
        candidates = selector.discover()
        self.last_candidates = candidates
        return self._scan_candidates(
            candidates,
            started=started,
            total_functions=selector.total_functions,
            skipped_large=selector.skipped_large,
            show_ui=show_ui,
            mode="Quick",
        )

    def scan_deep(self, show_ui: bool = True) -> list[Finding]:
        ida_auto.auto_wait()
        if prepare_analysis_types():
            self.clear_cache()
        started = time.monotonic()
        all_functions = list(idautils.Functions())
        candidates: list[ScanCandidate] = []
        skipped_large = 0
        for ea in all_functions:
            function = ida_funcs.get_func(ea)
            if not self._should_scan(function):
                continue
            if int(function.end_ea - function.start_ea) > self.config.max_function_bytes:
                skipped_large += 1
                continue
            candidates.append(ScanCandidate(int(ea), 1, {"deep scan"}))
            if len(candidates) >= self.config.max_functions:
                break
        return self._scan_candidates(
            candidates,
            started=started,
            total_functions=len(all_functions),
            skipped_large=skipped_large,
            show_ui=show_ui,
            mode="Deep",
        )

    def _scan_candidates(
        self,
        candidates: list[ScanCandidate],
        *,
        started: float,
        total_functions: int,
        skipped_large: int,
        show_ui: bool,
        mode: str,
    ) -> list[Finding]:
        functions: list[FunctionIR] = []
        stats = ScanStats(
            total_functions=total_functions,
            selected_functions=len(candidates),
            skipped_large=skipped_large,
        )
        if show_ui:
            ida_kernwin.show_wait_box(f"PwnHunter: preparing {mode.lower()} scan...")
        try:
            for index, candidate in enumerate(candidates, 1):
                if time.monotonic() - started >= self.config.max_seconds:
                    stats.timed_out = True
                    break
                if show_ui and ida_kernwin.user_cancelled():
                    stats.cancelled = True
                    break
                if show_ui and (index == 1 or index % 10 == 0):
                    ida_kernwin.replace_wait_box(
                        f"PwnHunter: analyzing candidate {index}/{len(candidates)}"
                    )
                try:
                    cached = candidate.ea in self._ir_cache
                    ir = self._extract_function(candidate.ea)
                    if ir is not None:
                        functions.append(ir)
                        stats.scanned_functions += 1
                        stats.cached_functions += int(cached)
                        if ir.microcode_blocks:
                            stats.microcode_functions += 1
                            stats.microcode_blocks += ir.microcode_blocks
                except Exception:
                    stats.failures += 1
                    print(
                        f"[PwnHunter] Failed to scan 0x{candidate.ea:X}\n"
                        f"{traceback.format_exc()}"
                    )
        finally:
            if show_ui:
                ida_kernwin.hide_wait_box()

        summary_started = time.monotonic()
        summary_builder = SummaryBuilder()
        summaries = summary_builder.build(functions)
        self.last_summaries = summaries
        stats.summary_count = len(summaries.by_ea)
        stats.summary_iterations = summary_builder.last_iterations
        stats.summary_recomputed = summary_builder.last_recomputed
        stats.summary_seconds = time.monotonic() - summary_started
        analyzer = Analyzer.for_program(functions, summaries)
        findings = [
            finding
            for function in functions
            for finding in analyzer.analyze_function(function)
        ]
        findings.extend(known_converter_findings(functions, self._input_path()))
        findings = sorted(
            {finding.fingerprint: finding for finding in findings}.values(),
            key=lambda finding: (-int(finding.severity), finding.ea, finding.rule_id),
        )
        protected = {
            candidate.ea
            for candidate in candidates
            if any(
                reason.startswith("interactive string:")
                for reason in candidate.reasons
            )
        }
        runtime_functions = self._static_runtime_functions(protected)
        self.last_runtime_functions = frozenset(runtime_functions)
        before_runtime_filter = len(findings)
        findings = [
            finding
            for finding in findings
            if finding.function_ea not in runtime_functions
        ]
        stats.filtered_runtime_sites = before_runtime_filter - len(findings)
        stats.finding_sites = len(findings)
        findings = self._cluster_findings(findings)
        stats.elapsed_seconds = time.monotonic() - started
        self.last_stats = stats

        suffixes = []
        if stats.timed_out:
            suffixes.append("budget reached")
        if stats.cancelled:
            suffixes.append("cancelled")
        suffix = f" ({', '.join(suffixes)})" if suffixes else ""
        if show_ui:
            self._show_findings(
                findings, f"PwnHunter {mode} - {len(findings)} Findings{suffix}"
            )
        print(
            f"[PwnHunter] {mode} scan selected {stats.selected_functions}/"
            f"{stats.total_functions} functions, analyzed {stats.scanned_functions}, "
            f"used microcode for {stats.microcode_functions} functions/"
            f"{stats.microcode_blocks} blocks, built {stats.summary_count} summaries, "
            f"recomputed {stats.summary_recomputed} summaries in "
            f"{stats.summary_iterations} rounds/{stats.summary_seconds:.2f}s, "
            f"found {len(findings)} candidate groups/{stats.finding_sites} sites "
            f"({stats.filtered_runtime_sites} static-runtime sites filtered) "
            f"in {stats.elapsed_seconds:.2f}s; {stats.failures} failures."
        )
        return findings

    @staticmethod
    def _static_runtime_functions(protected: set[int]) -> set[int]:
        """Recover stripped static runtime/library functions from strings.

        Assertion paths left by glibc, OpenSSL, Rust and Go provide strong
        seeds.  Runtime code may delegate to helpers that carry no strings, so
        propagate only along direct callee edges.  Business functions call
        libraries in the opposite direction; keeping the closure one-way and
        excluding the interaction-ranked neighborhood prevents that boundary
        from being crossed back into challenge code.
        """

        seeds: set[int] = set()
        for value in idautils.Strings():
            text = str(value)
            if not looks_like_bundled_runtime_source(text):
                continue
            for xref in idautils.XrefsTo(value.ea):
                function = ida_funcs.get_func(xref.frm)
                if function is None:
                    continue
                start = int(function.start_ea)
                # Strong runtime source evidence wins even when the same
                # function also references a generic diagnostic such as
                # "read failed".  The protected set is applied to descendants
                # so an actual challenge interaction root remains a boundary.
                seeds.add(start)

        runtime = set(seeds)
        frontier = set(seeds)
        while frontier:
            next_frontier: set[int] = set()
            for ea in frontier:
                for target in CandidateSelector._direct_callees(ea):
                    if target in protected or target in runtime:
                        continue
                    function = ida_funcs.get_func(target)
                    if function is None:
                        continue
                    runtime.add(target)
                    next_frontier.add(target)
            frontier = next_frontier
        return runtime

    @staticmethod
    def _input_path() -> Path:
        return Path(ida_nalt.get_input_file_path())

    @staticmethod
    def _cluster_findings(findings: list[Finding]) -> list[Finding]:
        """Collapse semantically identical sites while preserving their EAs."""

        grouped: dict[tuple[str, int, str, str, str], list[Finding]] = {}
        for finding in findings:
            grouped.setdefault(finding.semantic_fingerprint, []).append(finding)
        result: list[Finding] = []
        for group in grouped.values():
            primary = min(group, key=lambda finding: finding.ea)
            addresses = tuple(sorted({finding.ea for finding in group}))
            result.append(
                replace(
                    primary,
                    occurrences=len(addresses),
                    related_eas=tuple(ea for ea in addresses if ea != primary.ea),
                )
            )
        return sorted(
            result,
            key=lambda finding: (-int(finding.severity), finding.ea, finding.rule_id),
        )

    def _extract_function(self, ea: int) -> FunctionIR | None:
        if ea in self._ir_cache:
            return self._ir_cache[ea]
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            return None
        ir = CtreeExtractor(cfunc).extract()
        self._ir_cache[ea] = ir
        return ir

    def _scan_function(self, ea: int) -> list[Finding]:
        ir = self._extract_function(ea)
        return self.analyzer.analyze_function(ir) if ir is not None else []

    def clear_cache(self) -> None:
        self._ir_cache.clear()

    def _show_findings(self, findings: list[Finding], title: str) -> None:
        self.chooser = FindingsChooser(findings, title)
        self.chooser.Show(False)

    @staticmethod
    def _should_scan(function: ida_funcs.func_t | None) -> bool:
        if function is None:
            return False
        return not bool(function.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK))


class FindingsChooser(ida_kernwin.Choose):
    def __init__(self, findings: list[Finding], title: str):
        super().__init__(
            title,
            [
                ["Severity", 9],
                ["Confidence", 10],
                ["Category", 22],
                ["Address", 16],
                ["Sites", 7],
                ["Function", 24],
                ["Summary", 55],
                ["Evidence", 70],
            ],
            flags=ida_kernwin.Choose.CH_RESTORE,
        )
        self.findings = findings

    def OnGetSize(self):
        return len(self.findings)

    def OnGetLine(self, index):
        finding = self.findings[index]
        return [
            finding.severity.label,
            finding.confidence,
            finding.category,
            f"0x{finding.ea:X}",
            str(finding.occurrences),
            finding.function_name,
            finding.summary,
            finding.evidence,
        ]

    def OnGetLineAttr(self, index):
        severity = self.findings[index].severity
        colors = {
            Severity.CRITICAL: 0x9090FF,
            Severity.HIGH: 0xB0B0FF,
            Severity.MEDIUM: 0xA0D8FF,
            Severity.LOW: 0xD0E8FF,
        }
        color = colors.get(severity)
        return [color, 0] if color is not None else None

    def OnSelectLine(self, index):
        ida_kernwin.jumpto(self.findings[index].ea)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)
