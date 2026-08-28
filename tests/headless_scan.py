"""IDA -S integration-test driver. Not loaded by the plugin itself."""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_pro
import idautils


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pwnhunter.ida_adapter import CtreeExtractor, prepare_analysis_types  # noqa: E402
from pwnhunter.engine import Analyzer  # noqa: E402
from pwnhunter.ir import Assignment, Call  # noqa: E402
from pwnhunter.rules import normalize_symbol  # noqa: E402
from pwnhunter.summaries import SummaryBuilder  # noqa: E402


EXPECTED_FINDINGS = {
    ("BUF-003", "mmap_overflow"),
    ("BUF-003", "aligned_alloc_overflow"),
    ("BUF-003", "disabled_fortified_copy_overflow"),
    ("STR-001", "wrapped_fortified_read_unterminated"),
    ("BUF-003", "disabled_fortified_strncpy_overflow"),
    ("BUF-007", "fortified_strncpy_wrapper"),
    ("STR-001", "fortified_strncpy_unterminated_destination"),
    ("STR-001", "unterminated_printf_argument"),
    ("STR-001", "format_string_argument_wrapper"),
    ("STR-001", "oversized_precision_printf_argument"),
    ("STR-001", "oversized_strnlen"),
    ("STR-001", "bounded_length_wrapper"),
    ("STR-001", "oversized_strncmp"),
    ("STR-001", "unsafe_dynamic_precision_wrapper"),
    ("BUF-012", "dynamic_heap_off_by_one"),
    ("BUF-012", "reallocarray_off_by_one"),
    ("BUF-013", "dynamic_heap_source_overread"),
    ("BUF-013", "output_wrapper"),
    ("BUF-007", "fortified_copy_source_overread"),
    ("BUF-007", "memcmp_first_source_overread"),
    ("BUF-007", "memcmp_second_source_overread"),
    ("BUF-007", "compare_bytes_wrapper"),
    ("BUF-007", "memchr_source_overread"),
    ("BUF-007", "bcmp_first_source_overread"),
    ("BUF-007", "writev_first_source_overread"),
    ("BUF-007", "writev_second_source_overread"),
    ("BUF-007", "writev_iovec_array_overread"),
    ("BUF-007", "writev_wrapper"),
    ("BUF-003", "readv_first_destination_overflow"),
    ("BUF-003", "readv_second_destination_overflow"),
    ("BUF-007", "readv_iovec_array_overread"),
    ("BUF-003", "readv_wrapper"),
    ("STR-001", "readv_unterminated_printf"),
    ("BUF-007", "sendmsg_payload_source_overread"),
    ("BUF-007", "sendmsg_control_source_overread"),
    ("BUF-007", "sendmsg_header_overread"),
    ("BUF-003", "recvmsg_payload_destination_overflow"),
    ("BUF-003", "recvmsg_wrapper"),
    ("STR-001", "recvmsg_unterminated_printf"),
    ("FMT-001", "stateful_strtok_format"),
    ("STR-001", "unterminated_strtok_input"),
    ("BUF-004", "strtod_length"),
    ("STR-001", "unterminated_strtod_input"),
    ("STR-001", "unterminated_strcpy_source"),
    ("BUF-002", "disabled_fortified_strcpy_overflow"),
    ("BUF-002", "disabled_fortified_sprintf_overflow"),
    ("STR-001", "fortified_sprintf_unterminated_source"),
    ("BUF-003", "wrapped_offset_destination_overflow"),
    ("BUF-003", "wrapped_scalar_length_overflow"),
    ("BUF-007", "output_offset_inner"),
    ("BUF-003", "wrapped_negative_offset_underflow"),
    ("INIT-002", "short_read_tail_leak"),
    ("INT-005", "allocation_addition_wrap"),
    ("INT-005", "scalar_allocation_summary_overflow"),
    ("BUF-003", "scalar_allocation_capacity_overflow"),
    ("INT-003", "allocation_multiplication"),
    ("INT-003", "unchecked_io_length_product"),
    ("INT-003", "unchecked_io_length_shift"),
    ("INT-003", "unchecked_dynamic_io_length_shift"),
    ("IDX-001", "compound_guard_redefinition"),
    ("ERR-001", "unchecked_error_result_allocation"),
    ("ERR-001", "unchecked_error_output_field_allocation"),
    ("ERR-001", "unchecked_status_output_field_allocation"),
    ("ERR-001", "unchecked_ternary_status_output_allocation"),
    ("ERR-001", "unchecked_boolean_status_output_allocation"),
    ("ERR-001", "unchecked_phi_status_output_allocation"),
    ("ERR-001", "unchecked_unknown_phi_status_output_allocation"),
    ("ERR-001", "direct_read_may_not_write_allocation"),
    ("ERR-001", "nested_read_may_not_write_allocation"),
    ("ERR-001", "unproven_dynamic_error_output_allocation"),
    ("ERR-001", "redefined_dynamic_error_output_allocation"),
    ("ERR-001", "readonly_error_output_allocation"),
    ("LIFE-003", "delete_callback_slot"),
    ("LIFE-007", "trigger_callback_slot"),
}


def main() -> int:
    output = os.environ.get(
        "PWN_HUNTER_RESULT", str(PROJECT_ROOT / "tests" / "headless-result.json")
    )
    ida_auto.auto_wait()
    prepare_analysis_types()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is unavailable")

    functions = []
    failures = []
    for ea in idautils.Functions():
        try:
            flags = ida_funcs.get_func_flags(ea)
            if flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
                continue
            cfunc = ida_hexrays.decompile(ea)
            if cfunc is not None:
                functions.append(CtreeExtractor(cfunc).extract())
        except Exception:
            failures.append({"ea": ea, "traceback": traceback.format_exc()})

    findings = Analyzer.analyze_program(functions)
    by_name = {function.name: function for function in functions}
    summaries = SummaryBuilder().build(functions)
    scalar_allocation_summary = summaries.lookup("scalar_allocation_inner")
    scalar_sizes = (
        scalar_allocation_summary.allocation.sizes
        if scalar_allocation_summary is not None
        and scalar_allocation_summary.allocation is not None
        else ()
    )
    if not (
        len(scalar_sizes) == 1
        and scalar_sizes[0].scalar_op == "add"
        and scalar_sizes[0].offset == 0
        and scalar_sizes[0].bits == 64
        and scalar_sizes[0].signed is False
    ):
        failures.append(
            {
                "function": "scalar_allocation_inner",
                "error": "typed scalar allocation summary was not retained",
            }
        )
    error_reader_summary = summaries.lookup("error_return_reader")
    if not (
        error_reader_summary is not None
        and error_reader_summary.return_error_sentinel == -1
        and error_reader_summary.return_success_upper is not None
        and error_reader_summary.return_success_upper.argument == 1
    ):
        failures.append(
            {
                "function": "error_return_reader",
                "error": "input error/success return contract was not retained",
            }
        )
    callback_ir = by_name.get("create_callback_slot")
    callback_guarded_assignments = (
        [
            statement
            for statement in callback_ir.statements
            if isinstance(statement, Assignment) and statement.guards
        ]
        if callback_ir is not None
        else []
    )
    if len(callback_guarded_assignments) < 2:
        failures.append(
            {
                "function": "create_callback_slot",
                "error": "ctree item guards were not retained on both assignments",
            }
        )
    callback_allocations = (
        [
            statement
            for statement in callback_ir.statements
            if isinstance(statement, Assignment)
            and statement.value.unwrapped().kind == "call"
            and statement.value.unwrapped().callee == "calloc"
        ]
        if callback_ir is not None
        else []
    )
    if not callback_allocations or any(
        statement.guards for statement in callback_allocations
    ):
        failures.append(
            {
                "function": "create_callback_slot",
                "error": "unguarded calloc assignment collided with a guarded ctree item",
            }
        )

    else_ir = by_name.get("else_guarded_store")
    else_index_stores = (
        [
            statement
            for statement in else_ir.statements
            if isinstance(statement, Assignment)
            and statement.target.kind in {"index", "deref"}
            and any(guard.op in {"slt", "ult"} for guard in statement.guards)
        ]
        if else_ir is not None
        else []
    )
    if not else_index_stores:
        failures.append(
            {
                "function": "else_guarded_store",
                "error": "else-branch index store lacks a negative-polarity guard",
            }
        )

    short_circuit_ir = by_name.get("short_circuit_guarded_read")
    guarded_dynamic_reads = (
        [
            statement
            for statement in short_circuit_ir.statements
            if isinstance(statement, Call)
            and statement.name == "read"
            and len(statement.args) > 2
            and statement.args[2].kind == "var"
            and any(
                any(
                    comparison.op in {"slt", "ult", "sle", "ule", "eq"}
                    and Analyzer._value_matches_keys(
                        comparison.children[0],
                        statement.args[2].dependencies(),
                    )
                    for comparison in Analyzer._conjunctive_comparison_leaves(
                        guard
                    )
                )
                for guard in statement.guards
            )
        ]
        if short_circuit_ir is not None
        else []
    )
    if not guarded_dynamic_reads:
        failures.append(
            {
                "function": "short_circuit_guarded_read",
                "error": "right-hand read lacks its short-circuit upper-bound guard",
            }
        )

    compound_ir = by_name.get("compound_guard_redefinition")
    compound_updates = (
        [
            statement
            for statement in compound_ir.statements
            if isinstance(statement, Assignment)
            and statement.target.kind == "var"
            and statement.value.op == "add"
            and statement.target.key in statement.value.dependencies()
        ]
        if compound_ir is not None
        else []
    )
    if not compound_updates:
        failures.append(
            {
                "function": "compound_guard_redefinition",
                "error": "compound index update was not normalized as an assignment",
            }
        )

    dynamic_shift_ir = by_name.get("unchecked_dynamic_io_length_shift")
    extracted_shifts = (
        [
            node.unwrapped()
            for statement in dynamic_shift_ir.statements
            if isinstance(statement, Call)
            and statement.name == "read"
            and len(statement.args) > 2
            for node in Analyzer._walk_expression(statement.args[2])
            if node.unwrapped().op == "shl"
        ]
        if dynamic_shift_ir is not None
        else []
    )
    if not any(node.bits == 32 for node in extracted_shifts):
        failures.append(
            {
                "function": "unchecked_dynamic_io_length_shift",
                "error": "Hex-Rays dynamic shift was not retained as a 32-bit shl",
            }
        )

    c23_ir = by_name.get("isoc23_scanf_length")
    c23_calls = (
        [
            (statement.name, normalize_symbol(statement.name))
            for statement in c23_ir.statements
            if isinstance(statement, Call)
        ]
        if c23_ir is not None
        else []
    )
    if not any(normalized == "scanf" for _, normalized in c23_calls):
        failures.append(
            {
                "function": "isoc23_scanf_length",
                "error": f"C23 scanf callee was not normalized: {c23_calls!r}",
            }
        )

    observed = {(finding.rule_id, finding.function_name) for finding in findings}
    error_result_findings = [
        finding
        for finding in findings
        if finding.rule_id == "ERR-001"
        and finding.function_name == "unchecked_error_result_allocation"
    ]
    if not any(
        finding.callee == "malloc"
        and "source=error_return_reader" in finding.evidence
        and "wrapper=error_return_allocator" in finding.evidence
        and "error_sentinel=-1" in finding.evidence
        for finding in error_result_findings
    ):
        failures.append(
            {
                "function": "unchecked_error_result_allocation",
                "error": "wrapped error sentinel did not reach wrapped allocation",
            }
        )
    if any(
        finding.rule_id == "INT-002"
        and finding.function_name == "unchecked_error_result_allocation"
        for finding in findings
    ):
        failures.append(
            {
                "function": "unchecked_error_result_allocation",
                "error": "specific ERR-001 was duplicated by generic INT-002",
            }
        )
    if any(
        finding.rule_id == "ERR-001"
        and finding.function_name == "checked_error_result_allocation"
        for finding in findings
    ):
        failures.append(
            {
                "function": "checked_error_result_allocation",
                "error": "SIZE_MAX rejection did not suppress ERR-001",
            }
        )
    output_summary = summaries.lookup("error_count_output_outer")
    output_effects = output_summary.error_outputs if output_summary else ()
    if not any(
        effect.destination.argument == 0
        and effect.destination.offset == 0
        and effect.error_sentinel == -1
        and effect.bits == 64
        and effect.success_upper is not None
        and effect.success_upper.argument == 2
        for effect in output_effects
    ):
        failures.append(
            {
                "function": "error_count_output_outer",
                "error": "nested output error-return contract was not summarized",
            }
        )
    output_field_findings = [
        finding
        for finding in findings
        if finding.rule_id == "ERR-001"
        and finding.function_name == "unchecked_error_output_field_allocation"
    ]
    if not any(
        finding.callee == "malloc"
        and "source=error_count_output_outer" in finding.evidence
        and "wrapper=error_return_allocator" in finding.evidence
        and "converted_value=error_output_record.count" in finding.evidence
        for finding in output_field_findings
    ):
        failures.append(
            {
                "function": "unchecked_error_output_field_allocation",
                "error": "output-parameter error sentinel did not reach the exact record field",
            }
        )
    if any(
        finding.rule_id == "INT-005"
        and finding.function_name == "unchecked_error_output_field_allocation"
        for finding in findings
    ):
        failures.append(
            {
                "function": "unchecked_error_output_field_allocation",
                "error": "successful output bound did not suppress generic allocation overflow",
            }
        )
    if any(
        finding.rule_id == "ERR-001"
        and finding.function_name == "checked_error_output_field_allocation"
        for finding in findings
    ):
        failures.append(
            {
                "function": "checked_error_output_field_allocation",
                "error": "exact output-field SIZE_MAX rejection did not suppress ERR-001",
            }
        )
    status_summary = summaries.lookup("error_count_status_outer")
    status_effects = status_summary.error_outputs if status_summary else ()
    inner_status_summary = summaries.lookup("error_count_status_output")
    inner_status_effects = (
        inner_status_summary.error_outputs if inner_status_summary else ()
    )
    if not any(
        effect.destination.argument == 0
        and effect.error_sentinel == -1
        and effect.success_upper is not None
        and effect.success_upper.argument == 2
        and effect.sentinel_return_values == ((1 << 32) - 1,)
        for effect in status_effects
    ):
        failures.append(
            {
                "function": "error_count_status_outer",
                "error": (
                    "status/output relationship did not cross the returning "
                    f"wrapper: inner={inner_status_effects!r}; "
                    f"outer={status_effects!r}"
                ),
            }
        )
    for wrapper_name, expected_statuses in {
        # arm64 returns a 32-bit C int through W0; Hex-Rays exposes the raw
        # zero-extended bit pattern in these wrappers. Caller comparisons
        # reinterpret it at their recovered width and signedness.
        "error_count_ternary_status": ((1 << 32) - 7,),
        "error_count_boolean_status": (1,),
        "error_count_phi_status": ((1 << 32) - 11,),
        "error_count_unknown_phi_status": (
            (1 << 32) - 17,
            (1 << 32) - 13,
        ),
    }.items():
        conditional_summary = summaries.lookup(wrapper_name)
        conditional_effects = (
            conditional_summary.error_outputs if conditional_summary else ()
        )
        if not any(
            effect.destination.argument == 0
            and effect.error_sentinel == -1
            and effect.success_upper is not None
            and effect.success_upper.argument == 2
            and effect.sentinel_return_values == expected_statuses
            for effect in conditional_effects
        ):
            failures.append(
                {
                    "function": wrapper_name,
                    "error": (
                        "conditional/phi status mapping was not preserved: "
                        f"expected={expected_statuses!r}; "
                        f"effects={conditional_effects!r}"
                    ),
                }
            )
    overwritten_summary = summaries.lookup("error_output_overwritten")
    if overwritten_summary is not None and overwritten_summary.error_outputs:
        failures.append(
            {
                "function": "error_output_overwritten",
                "error": "memset did not clobber the earlier output error contract",
            }
        )
    dynamic_unproven_summary = summaries.lookup(
        "error_output_dynamic_unproven"
    )
    zero_capable_read_summary = summaries.lookup("zero_capable_output_read")
    zero_capable_read_writes = (
        zero_capable_read_summary.writes
        if zero_capable_read_summary
        else ()
    )
    if not any(
        normalize_symbol(effect.sink) in {"read", "__read_chk"}
        and not effect.must_write
        and effect.destination.argument == 0
        for effect in zero_capable_read_writes
    ):
        failures.append(
            {
                "function": "zero_capable_output_read",
                "error": (
                    "the read wrapper did not retain a may-write-only "
                    f"summary: writes={zero_capable_read_writes!r}"
                ),
            }
        )
    for wrapper_name in {
        "error_output_direct_read_may_not_write",
        "error_output_nested_read_may_not_write",
    }:
        may_write_summary = summaries.lookup(wrapper_name)
        may_write_effects = (
            may_write_summary.error_outputs if may_write_summary else ()
        )
        if not may_write_effects:
            failures.append(
                {
                    "function": wrapper_name,
                    "error": (
                        "a zero/error-returning read incorrectly erased "
                        "the earlier output error contract"
                    ),
                }
            )
    dynamic_memset_summary = summaries.lookup("dynamic_output_memset")
    dynamic_memset_writes = (
        dynamic_memset_summary.writes if dynamic_memset_summary else ()
    )
    if not any(
        normalize_symbol(effect.sink) in {"memset", "__memset_chk"}
        and effect.must_write
        and len(effect.lengths) == 1
        and effect.lengths[0].argument == 1
        for effect in dynamic_memset_writes
    ):
        failures.append(
            {
                "function": "dynamic_output_memset",
                "error": (
                    "the deterministic dynamic write did not retain its "
                    "must-write length through the helper summary: "
                    f"writes={dynamic_memset_writes!r}"
                ),
            }
        )
    dynamic_unproven_effects = (
        dynamic_unproven_summary.error_outputs
        if dynamic_unproven_summary
        else ()
    )
    if not dynamic_unproven_effects:
        failures.append(
            {
                "function": "error_output_dynamic_unproven",
                "error": (
                    "a zero-capable dynamic memset incorrectly erased the "
                    "output error contract"
                ),
            }
        )
    dynamic_bounded_summary = summaries.lookup(
        "error_output_dynamic_bounded"
    )
    if (
        dynamic_bounded_summary is not None
        and dynamic_bounded_summary.error_outputs
    ):
        failures.append(
            {
                "function": "error_output_dynamic_bounded",
                "error": (
                    "complementary dynamic/fixed memset branches did not "
                    "clobber the output error contract"
                ),
            }
        )
    dynamic_accepted_summary = summaries.lookup(
        "error_output_dynamic_after_reject"
    )
    if (
        dynamic_accepted_summary is not None
        and dynamic_accepted_summary.error_outputs
    ):
        failures.append(
            {
                "function": "error_output_dynamic_after_reject",
                "error": (
                    "the accepted path after an early clobber/return did "
                    "not recover its dynamic write lower bound"
                ),
            }
        )
    dynamic_terminating_summary = summaries.lookup(
        "error_output_dynamic_after_abort"
    )
    if (
        dynamic_terminating_summary is not None
        and dynamic_terminating_summary.error_outputs
    ):
        failures.append(
            {
                "function": "error_output_dynamic_after_abort",
                "error": (
                    "a noreturn rejection path incorrectly retained the "
                    "output error contract"
                ),
            }
        )
    dynamic_terminating_ir = by_name.get(
        "error_output_dynamic_after_abort"
    )
    terminating_shape = False
    if dynamic_terminating_ir is not None:
        abort_calls = [
            statement
            for statement in dynamic_terminating_ir.statements
            if isinstance(statement, Call)
            and normalize_symbol(statement.name) == "abort"
            and statement.guards
        ]
        dynamic_calls = [
            statement
            for statement in dynamic_terminating_ir.statements
            if isinstance(statement, Call)
            and normalize_symbol(statement.name) == "dynamic_output_memset"
            and not statement.guards
        ]
        terminating_shape = any(
            abort_call.order < dynamic_call.order
            for abort_call in abort_calls
            for dynamic_call in dynamic_calls
        )
    if not terminating_shape:
        failures.append(
            {
                "function": "error_output_dynamic_after_abort",
                "error": (
                    "real ctree no longer contains a guarded abort followed "
                    "by an unguarded dynamic write"
                ),
            }
        )
    dynamic_redefined_summary = summaries.lookup(
        "error_output_dynamic_redefined_after_reject"
    )
    dynamic_redefined_effects = (
        dynamic_redefined_summary.error_outputs
        if dynamic_redefined_summary
        else ()
    )
    dynamic_redefined_ir = by_name.get(
        "error_output_dynamic_redefined_after_reject"
    )
    redefinition_shape = False
    if dynamic_redefined_ir is not None:
        for condition in dynamic_redefined_ir.conditions:
            guarded_keys = condition.expression.dependencies()
            for assignment in dynamic_redefined_ir.statements:
                if (
                    not isinstance(assignment, Assignment)
                    or assignment.order <= condition.order
                    or assignment.target.key not in guarded_keys
                ):
                    continue
                for call in dynamic_redefined_ir.statements:
                    if (
                        not isinstance(call, Call)
                        or call.order <= assignment.order
                        or normalize_symbol(call.name)
                        != "dynamic_output_memset"
                        or len(call.args) < 2
                        or assignment.target.key
                        not in call.args[1].dependencies()
                    ):
                        continue
                    if any(
                        assignment.target.key in guard.dependencies()
                        for guard in call.guards
                    ):
                        redefinition_shape = True
    if not redefinition_shape:
        failures.append(
            {
                "function": "error_output_dynamic_redefined_after_reject",
                "error": (
                    "real ctree no longer contains a guarded length, its "
                    "redefinition, and a later same-value dynamic write"
                ),
            }
        )
    if not dynamic_redefined_effects:
        failures.append(
            {
                "function": "error_output_dynamic_redefined_after_reject",
                "error": (
                    "a reassigned dynamic length incorrectly reused the "
                    "earlier lower-bound guard"
                ),
            }
        )
    dynamic_three_way_summary = summaries.lookup(
        "error_output_dynamic_three_way"
    )
    dynamic_three_way_ir = by_name.get("error_output_dynamic_three_way")
    if (
        dynamic_three_way_summary is not None
        and dynamic_three_way_summary.error_outputs
    ):
        failures.append(
            {
                "function": "error_output_dynamic_three_way",
                "error": (
                    "the three-way all-path overwrite retained its output "
                    "error contract: "
                    f"statements={getattr(dynamic_three_way_ir, 'statements', ())!r}; "
                    f"blocks={getattr(dynamic_three_way_ir, 'blocks', {})!r}"
                ),
            }
        )
    readonly_summary = summaries.lookup("error_output_readonly")
    readonly_effects = readonly_summary.error_outputs if readonly_summary else ()
    if not readonly_effects:
        failures.append(
            {
                "function": "error_output_readonly",
                "error": "memcmp incorrectly clobbered the output error contract",
            }
        )
    if any(
        finding.rule_id in {"ERR-001", "INT-005"}
        and finding.function_name == "overwritten_error_output_allocation"
        for finding in findings
    ):
        failures.append(
            {
                "function": "overwritten_error_output_allocation",
                "error": "caller retained an error/overflow finding after exact memset overwrite",
            }
        )
    dynamic_unproven_findings = [
        finding
        for finding in findings
        if finding.rule_id == "ERR-001"
        and finding.function_name
        == "unproven_dynamic_error_output_allocation"
    ]
    if not any(
        "source=error_output_dynamic_unproven" in finding.evidence
        and "converted_value=error_output_record.count" in finding.evidence
        for finding in dynamic_unproven_findings
    ):
        failures.append(
            {
                "function": "unproven_dynamic_error_output_allocation",
                "error": (
                    "the unresolved dynamic memset lost its caller-side "
                    "ERR-001 chain"
                ),
            }
        )
    for caller_name, source_name in {
        "direct_read_may_not_write_allocation": (
            "error_output_direct_read_may_not_write"
        ),
        "nested_read_may_not_write_allocation": (
            "error_output_nested_read_may_not_write"
        ),
    }.items():
        may_write_findings = [
            finding
            for finding in findings
            if finding.rule_id == "ERR-001"
            and finding.function_name == caller_name
        ]
        if not any(
            f"source={source_name}" in finding.evidence
            and "converted_value=error_output_record.count"
            in finding.evidence
            for finding in may_write_findings
        ):
            failures.append(
                {
                    "function": caller_name,
                    "error": (
                        "the may-write read wrapper lost its caller-side "
                        f"ERR-001 chain: source={source_name}"
                    ),
                }
            )
    if any(
        finding.rule_id in {"ERR-001", "INT-005"}
        and finding.function_name
        == "bounded_dynamic_error_output_allocation"
        for finding in findings
    ):
        failures.append(
            {
                "function": "bounded_dynamic_error_output_allocation",
                "error": (
                    "the all-path dynamic overwrite retained an error or "
                    "overflow finding"
                ),
            }
        )
    dynamic_redefined_findings = [
        finding
        for finding in findings
        if finding.rule_id == "ERR-001"
        and finding.function_name
        == "redefined_dynamic_error_output_allocation"
    ]
    if not any(
        "source=error_output_dynamic_redefined_after_reject"
        in finding.evidence
        and "converted_value=error_output_record.count" in finding.evidence
        for finding in dynamic_redefined_findings
    ):
        failures.append(
            {
                "function": "redefined_dynamic_error_output_allocation",
                "error": (
                    "the reassigned-length wrapper lost its caller-side "
                    "ERR-001 chain"
                ),
            }
        )
    if any(
        finding.rule_id in {"ERR-001", "INT-005"}
        and finding.function_name
        in {
            "accepted_dynamic_error_output_allocation",
            "terminating_dynamic_error_output_allocation",
            "three_way_dynamic_error_output_allocation",
        }
        for finding in findings
    ):
        failures.append(
            {
                "function": "guarded_dynamic_error_output_callers",
                "error": (
                    "an all-path early-return or three-way overwrite "
                    "retained an error/overflow finding"
                ),
            }
        )
    readonly_findings = [
        finding
        for finding in findings
        if finding.rule_id == "ERR-001"
        and finding.function_name == "readonly_error_output_allocation"
    ]
    if not any(
        "source=error_output_readonly" in finding.evidence
        and "converted_value=error_output_record.count" in finding.evidence
        for finding in readonly_findings
    ):
        failures.append(
            {
                "function": "readonly_error_output_allocation",
                "error": "read-only memcmp wrapper lost the output error contract",
            }
        )
    unchecked_status_findings = [
        finding
        for finding in findings
        if finding.rule_id == "ERR-001"
        and finding.function_name == "unchecked_status_output_field_allocation"
    ]
    if not any(
        "source=error_count_status_outer" in finding.evidence
        and "converted_value=error_output_record.count" in finding.evidence
        for finding in unchecked_status_findings
    ):
        failures.append(
            {
                "function": "unchecked_status_output_field_allocation",
                "error": "ignored status did not preserve the output error finding",
            }
        )
    if any(
        finding.rule_id == "ERR-001"
        and finding.function_name == "checked_status_output_field_allocation"
        for finding in findings
    ):
        failures.append(
            {
                "function": "checked_status_output_field_allocation",
                "error": "checked wrapper status did not exclude its output sentinel",
            }
        )
    conditional_checked_callers = {
        "checked_ternary_status_output_allocation",
        "nonnegative_ternary_status_output_allocation",
        "checked_boolean_status_output_allocation",
        "checked_phi_status_output_allocation",
        "checked_unknown_phi_status_output_allocation",
    }
    if any(
        finding.rule_id in {"ERR-001", "INT-005"}
        and finding.function_name in conditional_checked_callers
        for finding in findings
    ):
        failures.append(
            {
                "function": "conditional_status_output_callers",
                "error": (
                    "a checked conditional/phi status did not exclude its "
                    "output sentinel or successful upper-bound noise"
                ),
            }
        )
    if any(
        finding.rule_id == "INT-005"
        and finding.function_name
        in {
            "unchecked_status_output_field_allocation",
            "checked_status_output_field_allocation",
        }
        for finding in findings
    ):
        failures.append(
            {
                "function": "error_count_status_outer",
                "error": (
                    "status-output successful bound did not suppress "
                    "generic addition overflow"
                ),
            }
        )
    if ("INIT-002", "checked_full_read_output") in observed:
        failures.append(
            {
                "function": "checked_full_read_output",
                "error": "full-read equality guard did not suppress INIT-002",
            }
        )
    if ("INT-005", "checked_allocation_addition") in observed:
        failures.append(
            {
                "function": "checked_allocation_addition",
                "error": "allocation upper-bound guard did not suppress INT-005",
            }
        )
    if ("INT-005", "bounded_read_result_allocation") in observed:
        failures.append(
            {
                "function": "bounded_read_result_allocation",
                "error": "bounded read return became arbitrary unsigned size",
            }
        )
    if any(
        rule_id in {"BUF-003", "BUF-004"}
        and function_name == "scalar_allocation_capacity_exact"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "scalar_allocation_capacity_exact",
                "error": "composed scalar allocation rejected exact capacity",
            }
        )
    if any(
        rule_id in {"BUF-003", "BUF-004"}
        and function_name == "wrapped_scalar_length_exact"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "wrapped_scalar_length_exact",
                "error": "scalar wrapper length rejected exact capacity",
            }
        )
    scalar_length_findings = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-003"
        and finding.function_name == "wrapped_scalar_length_overflow"
    ]
    if not any(
        "length=33" in finding.evidence
        and "wrapper=scalar_length_read_wrapper" in finding.evidence
        for finding in scalar_length_findings
    ):
        failures.append(
            {
                "function": "wrapped_scalar_length_overflow",
                "error": "scalar length expression was lost across wrapper",
            }
        )
    if ("INT-003", "checked_calloc_implicit_product") in observed:
        failures.append(
            {
                "function": "checked_calloc_implicit_product",
                "error": "calloc's checked implicit product was reported as overflow",
            }
        )
    if any(
        rule_id in {"BUF-012", "INT-002", "INT-003"}
        and function_name == "safe_reallocarray_fill"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "safe_reallocarray_fill",
                "error": "exact reallocarray fill was not proven safe",
            }
        )
    if any(
        rule_id in {"BUF-003", "BUF-004"}
        and function_name == "active_fortified_copy_abort"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "active_fortified_copy_abort",
                "error": "active fortify destination check did not fail closed",
            }
        )
    if any(
        rule_id in {"BUF-003", "BUF-004", "STR-001"}
        and function_name == "active_fortified_read_abort"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "active_fortified_read_abort",
                "error": "active fortified input did not make its later string consumer unreachable",
            }
        )
    if any(
        rule_id in {"BUF-003", "BUF-004", "BUF-007", "STR-001"}
        and function_name == "active_fortified_strncpy_abort"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "active_fortified_strncpy_abort",
                "error": "bounded fortified wrapper did not fail closed before source/destination access",
            }
        )
    if any(
        rule_id in {"BUF-007", "BUF-013"}
        and function_name == "safe_memcmp_exact"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "safe_memcmp_exact",
                "error": "exact memcmp source ranges were reported as overreads",
            }
        )
    if any(
        rule_id in {"BUF-007", "BUF-013", "INIT-002"}
        and function_name == "memchr_exact_source"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "memchr_exact_source",
                "error": "exact memchr source range was reported as an overread",
            }
        )
    if any(
        rule_id in {"BUF-007", "BUF-013", "INIT-002"}
        and function_name == "writev_exact_source"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "writev_exact_source",
                "error": "initialized exact writev payload was reported",
            }
        )
    if any(
        rule_id in {"BUF-003", "BUF-004", "BUF-007", "STR-001"}
        and function_name == "readv_exact_destination"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "readv_exact_destination",
                "error": "exact readv destination or descriptor was reported",
            }
        )
    if any(
        rule_id in {"BUF-007", "BUF-013", "INIT-002"}
        and function_name == "sendmsg_exact_source"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "sendmsg_exact_source",
                "error": "initialized exact sendmsg payload was reported",
            }
        )
    sendmsg_payload_findings = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-007"
        and finding.function_name == "sendmsg_payload_source_overread"
    ]
    if not any(
        "iovec_index=0" in finding.evidence
        and "message_index=0" in finding.evidence
        and "message_component=msg_iov" in finding.evidence
        for finding in sendmsg_payload_findings
    ):
        failures.append(
            {
                "function": "sendmsg_payload_source_overread",
                "error": "nested sendmsg iovec payload was not recovered",
            }
        )
    recvmsg_wrapper_findings = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-003"
        and finding.function_name == "recvmsg_wrapper"
    ]
    if not any(
        "message_component=msg_iov" in finding.evidence
        and "wrapper=recvmsg_wrapper" in finding.evidence
        for finding in recvmsg_wrapper_findings
    ):
        failures.append(
            {
                "function": "recvmsg_wrapper",
                "error": "recvmsg message effect did not cross its wrapper",
            }
        )
    if any(
        rule_id in {"BUF-003", "BUF-004"}
        and function_name == "wrapped_offset_destination_exact"
        for rule_id, function_name in observed
    ):
        failures.append(
            {
                "function": "wrapped_offset_destination_exact",
                "error": "constant wrapper offset rejected an exact-fit tail",
            }
        )
    offset_writes = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-003"
        and finding.function_name == "wrapped_offset_destination_overflow"
    ]
    if not any(
        "available_capacity=8" in finding.evidence
        and "wrapper=input_offset_wrapper" in finding.evidence
        for finding in offset_writes
    ):
        failures.append(
            {
                "function": "wrapped_offset_destination_overflow",
                "error": "destination offset was lost across the wrapper",
            }
        )
    offset_reads = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-007"
        and finding.function_name == "output_offset_inner"
    ]
    if not any(
        "source=source + 16" in finding.evidence
        and "available_physical_capacity=8" in finding.evidence
        and "wrapper=output_offset_outer" in finding.evidence
        for finding in offset_reads
    ):
        failures.append(
            {
                "function": "output_offset_inner",
                "error": "nested source offsets were not composed",
            }
        )
    negative_offsets = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-003"
        and finding.function_name == "wrapped_negative_offset_underflow"
    ]
    if not any("start_offset=-1" in finding.evidence for finding in negative_offsets):
        failures.append(
            {
                "function": "wrapped_negative_offset_underflow",
                "error": "negative wrapper offset was not reported as underflow",
            }
        )
    split_iovec_findings = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-007"
        and finding.function_name == "writev_second_source_overread"
    ]
    if not any(
        "iovec_index=1" in finding.evidence
        and "descriptor array" not in finding.summary
        for finding in split_iovec_findings
    ):
        failures.append(
            {
                "function": "writev_second_source_overread",
                "error": "split iovec tail was not recovered as the second payload",
            }
        )
    descriptor_findings = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-007"
        and finding.function_name == "writev_iovec_array_overread"
    ]
    if not any(
        "descriptor array" in finding.summary
        and "iovec_count=2" in finding.evidence
        for finding in descriptor_findings
    ):
        failures.append(
            {
                "function": "writev_iovec_array_overread",
                "error": "one-element iovec descriptor overread was not retained",
            }
        )
    split_readv_findings = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-003"
        and finding.function_name == "readv_second_destination_overflow"
    ]
    if not any(
        "iovec_index=1" in finding.evidence
        and "descriptor array" not in finding.summary
        for finding in split_readv_findings
    ):
        failures.append(
            {
                "function": "readv_second_destination_overflow",
                "error": "split readv iovec tail was not recovered as payload 1",
            }
        )
    readv_descriptor_findings = [
        finding
        for finding in findings
        if finding.rule_id == "BUF-007"
        and finding.function_name == "readv_iovec_array_overread"
    ]
    if not any(
        "descriptor array" in finding.summary
        and "iovec_count=2" in finding.evidence
        for finding in readv_descriptor_findings
    ):
        failures.append(
            {
                "function": "readv_iovec_array_overread",
                "error": "readv descriptor-array overread was not retained",
            }
        )
    stateful_formats = [
        finding
        for finding in findings
        if finding.rule_id == "FMT-001"
        and finding.function_name == "stateful_strtok_format"
    ]
    if not any(finding.confidence == "High" for finding in stateful_formats):
        failures.append(
            {
                "function": "stateful_strtok_format",
                "error": "strtok continuation lost external-input confidence",
            }
        )
    if any(
        finding.rule_id == "FMT-001"
        and finding.function_name == "clean_strtok_reset"
        and finding.confidence == "High"
        for finding in findings
    ):
        failures.append(
            {
                "function": "clean_strtok_reset",
                "error": "clean strtok reset inherited the prior hostile session",
            }
        )
    if any(
        finding.rule_id in {"BUF-004", "INT-001", "INT-002"}
        and finding.function_name == "constant_strtod_length"
        for finding in findings
    ):
        failures.append(
            {
                "function": "constant_strtod_length",
                "error": "constant strtod conversion was treated as hostile",
            }
        )
    if any(
        finding.rule_id == "STR-001"
        and finding.function_name == "terminated_strcpy_source"
        for finding in findings
    ):
        failures.append(
            {
                "function": "terminated_strcpy_source",
                "error": "zero-terminated short input was treated as unterminated",
            }
        )
    if any(
        finding.rule_id in {"BUF-002", "BUF-003", "BUF-004"}
        and finding.function_name == "active_fortified_strcpy_abort"
        for finding in findings
    ):
        failures.append(
            {
                "function": "active_fortified_strcpy_abort",
                "error": "active fortified strcpy did not fail closed",
            }
        )
    if any(
        finding.rule_id in {"BUF-002", "BUF-003", "BUF-004"}
        and finding.function_name == "active_fortified_sprintf_abort"
        for finding in findings
    ):
        failures.append(
            {
                "function": "active_fortified_sprintf_abort",
                "error": "active fortified sprintf did not fail closed",
            }
        )
    if any(
        finding.rule_id == "STR-001"
        and finding.function_name == "bounded_printf_argument"
        for finding in findings
    ):
        failures.append(
            {
                "function": "bounded_printf_argument",
                "error": "bounded printf string precision was treated as unbounded",
            }
        )
    if any(
        finding.rule_id == "STR-001"
        and finding.function_name == "bounded_strnlen_exact"
        for finding in findings
    ):
        failures.append(
            {
                "function": "bounded_strnlen_exact",
                "error": "exact-capacity strnlen was treated as an overread",
            }
        )
    if any(
        finding.rule_id == "STR-001"
        and finding.function_name == "short_peer_strncmp"
        for finding in findings
    ):
        failures.append(
            {
                "function": "short_peer_strncmp",
                "error": "short literal peer did not bound strncmp's source read",
            }
        )
    if any(
        finding.rule_id == "STR-001"
        and finding.function_name == "guarded_dynamic_precision_wrapper"
        for finding in findings
    ):
        failures.append(
            {
                "function": "guarded_dynamic_precision_wrapper",
                "error": "guarded dynamic printf precision was not bounded",
            }
        )
    if ("INT-003", "safe_narrow_calloc_product") in observed:
        failures.append(
            {
                "function": "safe_narrow_calloc_product",
                "error": "32-bit calloc factors were not proven safe in size_t",
            }
        )
    if ("INT-003", "safe_wide_io_length_product") in observed:
        failures.append(
            {
                "function": "safe_wide_io_length_product",
                "error": "widened I/O length multiplication was not proven safe",
            }
        )
    if ("INT-003", "safe_wide_io_length_shift") in observed:
        failures.append(
            {
                "function": "safe_wide_io_length_shift",
                "error": "widened I/O length shift was not proven safe",
            }
        )
    if ("INT-003", "safe_wide_dynamic_io_length_shift") in observed:
        failures.append(
            {
                "function": "safe_wide_dynamic_io_length_shift",
                "error": "guarded wide dynamic I/O shift was not proven safe",
            }
        )
    if ("INT-003", "safe_guarded_signed_io_product") in observed:
        failures.append(
            {
                "function": "safe_guarded_signed_io_product",
                "error": "guarded signed I/O product was not proven safe",
            }
        )
    missing_expected = sorted(EXPECTED_FINDINGS - observed)

    payload = {
        "findings": [
            {
                "rule_id": finding.rule_id,
                "function": finding.function_name,
                "severity": finding.severity.label,
                "confidence": finding.confidence,
                "summary": finding.summary,
                "evidence": finding.evidence,
            }
            for finding in findings
        ],
        "failures": failures,
        "missing_expected": [
            {"rule_id": rule_id, "function": function_name}
            for rule_id, function_name in missing_expected
        ],
    }
    Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if failures:
        return 2
    return 3 if missing_expected else 0


try:
    exit_code = main()
except Exception:
    traceback.print_exc()
    exit_code = 1
ida_pro.qexit(exit_code)
