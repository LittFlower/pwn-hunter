from __future__ import annotations

from dataclasses import replace
import unittest

from pwnhunter import (
    Analyzer,
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
    SummaryBuilder,
)
from pwnhunter.rules import (
    format_cstring_read_arguments,
    looks_like_bundled_runtime_source,
    normalize_symbol,
)


def var(name: str) -> Expr:
    return Expr(kind="var", text=name, key=name)


def const(value: int) -> Expr:
    return Expr(kind="const", text=str(value), value=value)


def string(value: str) -> Expr:
    return Expr(kind="string", text=repr(value), string=value)


def call_expr(name: str, *args: Expr) -> Expr:
    return Expr(kind="call", text=f"{name}(...)", callee=name, children=args)


def pointer_offset(name: str, offset: int, dynamic: Expr | None = None) -> Expr:
    displacement = dynamic if dynamic is not None else const(abs(offset))
    operator = "add" if offset >= 0 else "sub"
    sign = "+" if offset >= 0 else "-"
    return Expr(
        kind="op",
        text=f"{name} {sign} {displacement.text}",
        key=name,
        op=operator,
        children=(var(name), displacement),
        offset=offset if dynamic is None else 0,
        bits=64,
        signed=False,
        is_pointer=True,
    )


def function(*statements, buffers=()) -> FunctionIR:
    return FunctionIR(
        ea=0x1000,
        name="vuln",
        buffers={buffer.key: buffer for buffer in buffers},
        statements=list(statements),
    )


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = Analyzer()
        self.stack32 = BufferInfo("buf", "buf", "stack", 32)

    def rule_ids(self, ir: FunctionIR) -> list[str]:
        return [finding.rule_id for finding in self.analyzer.analyze_function(ir)]

    def test_symbol_normalization(self):
        self.assertEqual(normalize_symbol("j_printf@@GLIBC_2.2.5"), "printf")
        self.assertEqual(normalize_symbol("_read"), "read")
        self.assertEqual(normalize_symbol("_puts"), "puts")
        self.assertEqual(normalize_symbol("__isoc99_scanf"), "scanf")
        self.assertEqual(
            normalize_symbol("j_reallocarray@@GLIBC_2.26"), "reallocarray"
        )
        self.assertEqual(normalize_symbol("__libc_reallocarray"), "reallocarray")
        self.assertEqual(normalize_symbol("__isoc23_scanf"), "scanf")
        self.assertEqual(normalize_symbol("__isoc23_strtoull"), "strtoull")
        self.assertEqual(normalize_symbol("___strcpy_chk"), "__strcpy_chk")

    def test_literal_format_cstring_argument_mapping(self):
        self.assertEqual(
            format_cstring_read_arguments("printf", "%d:%*s"),
            ((3, None, None),),
        )
        self.assertEqual(
            format_cstring_read_arguments("printf", "%% %2$s %.8s"),
            ((2, None, None), (1, 8, None)),
        )
        self.assertEqual(
            format_cstring_read_arguments("printf", "%.*s %s"),
            ((2, None, 1), (3, None, None)),
        )
        self.assertEqual(
            format_cstring_read_arguments("sprintf", "%s"),
            ((2, None, None),),
        )
        self.assertEqual(
            format_cstring_read_arguments("__printf_chk", "%s"),
            ((2, None, None),),
        )
        self.assertEqual(
            format_cstring_read_arguments("asprintf", "%s"),
            ((2, None, None),),
        )
        self.assertEqual(
            format_cstring_read_arguments("__asprintf_chk", "%s"),
            ((3, None, None),),
        )

    def test_static_runtime_source_markers_are_narrow(self):
        self.assertTrue(
            looks_like_bundled_runtime_source(
                "../sysdeps/unix/sysv/linux/ifaddrs.c"
            )
        )
        self.assertTrue(
            looks_like_bundled_runtime_source("../crypto/x509/x509_trust.c")
        )
        self.assertTrue(
            looks_like_bundled_runtime_source("nss_dns/dns-host.c")
        )
        self.assertTrue(
            looks_like_bundled_runtime_source("unsupported label source")
        )
        self.assertTrue(looks_like_bundled_runtime_source("malloc.c"))
        self.assertTrue(looks_like_bundled_runtime_source("wfileops.c"))
        self.assertTrue(
            looks_like_bundled_runtime_source(
                "/rustc/hash/library/std/src/sys/pal/unix/fs.rs"
            )
        )
        self.assertFalse(looks_like_bundled_runtime_source("src/main.c"))
        self.assertFalse(looks_like_bundled_runtime_source("challenge/malloc.c.old"))
        self.assertFalse(looks_like_bundled_runtime_source("unsupported label"))

    def test_unterminated_scan_and_followup_copy_share_semantic_root(self):
        common = dict(
            category="Unterminated C string",
            severity=Severity.HIGH,
            confidence="High",
            function_ea=0x1000,
            function_name="convert",
        )
        scan = Finding(
            rule_id="STR-001",
            ea=0x1010,
            callee="strlen",
            summary="unterminated input reaches strlen",
            evidence="buffer=ptr",
            **common,
        )
        copy = Finding(
            rule_id="STR-002",
            ea=0x1020,
            callee="memcpy",
            summary="strlen result reaches memcpy",
            evidence="source=ptr",
            **common,
        )
        self.assertEqual(scan.semantic_fingerprint, copy.semantic_fingerprint)

    def test_tainted_format_string(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(32))),
            Call(2, 0x1020, "printf", (var("buf"),)),
            buffers=(self.stack32,),
        )
        findings = self.analyzer.analyze_function(ir)
        fmt = next(finding for finding in findings if finding.rule_id == "FMT-001")
        self.assertEqual(fmt.confidence, "High")

    def test_literal_format_is_safe(self):
        ir = function(Call(1, 0x1010, "printf", (string("%s"), var("buf"))))
        self.assertNotIn("FMT-001", self.rule_ids(ir))

    def test_strtok_continuation_retains_external_input_taint(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buffer"), const(32))),
            Assignment(
                2,
                0x1020,
                var("command"),
                call_expr("strtok", var("buffer"), string(" ")),
            ),
            Assignment(
                3,
                0x1030,
                var("argument"),
                call_expr("strtok", const(0), string(" ")),
            ),
            Call(4, 0x1040, "printf", (var("argument"),)),
            buffers=(self.stack32,),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "FMT-001"
        )
        self.assertEqual(finding.confidence, "High")
        self.assertIn("attacker-controlled", finding.summary)

    def test_clean_strtok_reset_does_not_inherit_old_taint(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buffer"), const(32))),
            Assignment(
                2,
                0x1020,
                var("hostile"),
                call_expr("strtok", var("buffer"), string(" ")),
            ),
            Assignment(
                3,
                0x1030,
                var("reset"),
                call_expr("strtok", string("literal text"), string(" ")),
            ),
            Assignment(
                4,
                0x1040,
                var("safe"),
                call_expr("strtok", const(0), string(" ")),
            ),
            Call(5, 0x1050, "printf", (var("safe"),)),
            buffers=(self.stack32,),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "FMT-001"
        )
        self.assertEqual(finding.confidence, "Medium")
        self.assertIn("non-literal", finding.summary)

    def test_strtok_continuation_format_effect_crosses_wrapper(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="print_second_token",
            parameters=("input",),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    var("first"),
                    call_expr("strtok", var("input"), string(" ")),
                ),
                Assignment(
                    2,
                    0x2020,
                    var("second"),
                    call_expr("strtok", const(0), string(" ")),
                ),
                Call(3, 0x2030, "printf", (var("second"),)),
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={"buffer": self.stack32},
            statements=[
                Call(
                    1,
                    0x3010,
                    "read",
                    (const(0), var("buffer"), const(32)),
                ),
                Call(
                    2,
                    0x3020,
                    "print_second_token",
                    (var("buffer"),),
                    callee_ea=wrapper.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(
            item
            for item in findings
            if item.rule_id == "FMT-001" and item.function_name == "caller"
        )
        self.assertIn("via print_second_token", finding.summary)

    def test_strtok_continuation_return_taint_crosses_wrapper(self):
        tokenizer = FunctionIR(
            ea=0x2000,
            name="second_token",
            parameters=("input",),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    var("first"),
                    call_expr("strtok", var("input"), string(" ")),
                ),
                Assignment(
                    2,
                    0x2020,
                    var("second"),
                    call_expr("strtok", const(0), string(" ")),
                ),
                Return(3, 0x2030, var("second")),
            ],
        )
        token_call = Expr(
            kind="call",
            text="second_token(buffer)",
            callee="second_token",
            callee_ea=tokenizer.ea,
            children=(var("buffer"),),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={
                "buffer": BufferInfo("buffer", "buffer", "stack", 32)
            },
            statements=[
                Call(
                    1,
                    0x3010,
                    "read",
                    (const(0), var("buffer"), const(32)),
                ),
                Assignment(2, 0x3020, var("token"), token_call),
                Call(3, 0x3030, "printf", (var("token"),)),
            ],
        )
        findings = Analyzer.analyze_program([tokenizer, caller])
        finding = next(
            item
            for item in findings
            if item.rule_id == "FMT-001" and item.function_name == "caller"
        )
        self.assertEqual(finding.confidence, "High")

    def test_clean_strtok_reset_return_is_not_attacker_controlled(self):
        tokenizer = FunctionIR(
            ea=0x2000,
            name="reset_and_tokenize",
            parameters=("input",),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    var("hostile"),
                    call_expr("strtok", var("input"), string(" ")),
                ),
                Assignment(
                    2,
                    0x2020,
                    var("reset"),
                    call_expr("strtok", string("literal text"), string(" ")),
                ),
                Assignment(
                    3,
                    0x2030,
                    var("safe"),
                    call_expr("strtok", const(0), string(" ")),
                ),
                Return(4, 0x2040, var("safe")),
            ],
        )
        token_call = Expr(
            kind="call",
            text="reset_and_tokenize(buffer)",
            callee="reset_and_tokenize",
            callee_ea=tokenizer.ea,
            children=(var("buffer"),),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={
                "buffer": BufferInfo("buffer", "buffer", "stack", 32)
            },
            statements=[
                Call(
                    1,
                    0x3010,
                    "read",
                    (const(0), var("buffer"), const(32)),
                ),
                Assignment(2, 0x3020, var("token"), token_call),
                Call(3, 0x3030, "printf", (var("token"),)),
            ],
        )
        findings = Analyzer.analyze_program([tokenizer, caller])
        finding = next(
            item
            for item in findings
            if item.rule_id == "FMT-001" and item.function_name == "caller"
        )
        self.assertEqual(finding.confidence, "Medium")

    def test_direct_strtok_continuation_return_keeps_parameter_origin(self):
        tokenizer = FunctionIR(
            ea=0x2000,
            name="second_token",
            parameters=("input",),
            statements=[
                Call(
                    1,
                    0x2010,
                    "strtok",
                    (var("input"), string(" ")),
                ),
                Return(
                    2,
                    0x2020,
                    call_expr("strtok", const(0), string(" ")),
                ),
            ],
        )
        summaries = SummaryBuilder().build([tokenizer])
        summary = summaries.lookup("second_token", tokenizer.ea)
        self.assertIsNotNone(summary)
        self.assertEqual(summary.return_taint_arguments, (0,))

    def test_strtok_scans_unterminated_raw_input(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(8))),
            Call(2, 0x1020, "strtok", (var("buf"), string(","))),
            buffers=(BufferInfo("buf", "buf", "stack", 8),),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_strtok_after_fgets_has_a_terminator(self):
        ir = function(
            Call(1, 0x1010, "fgets", (var("buf"), const(8), var("stream"))),
            Call(2, 0x1020, "strtok", (var("buf"), string(","))),
            buffers=(BufferInfo("buf", "buf", "stack", 8),),
        )
        self.assertNotIn("STR-001", self.rule_ids(ir))

    def test_strtod_result_taints_a_later_length(self):
        parsed = Expr(kind="var", text="parsed", key="parsed")
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=64,
            signed=False,
        )
        converted = Expr(
            kind="cast",
            text="(size_t)parsed",
            key="parsed",
            children=(parsed,),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("text"), const(31))),
            Assignment(
                2,
                0x1020,
                parsed,
                call_expr("strtod", var("text"), const(0)),
            ),
            Assignment(3, 0x1030, count, converted),
            Call(4, 0x1040, "read", (const(0), var("destination"), count)),
            buffers=(
                BufferInfo("text", "text", "stack", 32),
                BufferInfo("destination", "destination", "stack", 32),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-004"
        )
        self.assertEqual(finding.confidence, "Medium")
        self.assertIn("attacker-influenced", finding.summary)

    def test_constant_strtod_result_is_not_tainted(self):
        parsed = Expr(kind="var", text="parsed", key="parsed")
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=64,
            signed=False,
        )
        converted = Expr(
            kind="cast",
            text="(size_t)parsed",
            key="parsed",
            children=(parsed,),
            bits=64,
            signed=False,
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                parsed,
                call_expr("strtod", string("12.5"), const(0)),
            ),
            Assignment(2, 0x1020, count, converted),
            Call(3, 0x1030, "read", (const(0), var("destination"), count)),
            buffers=(
                BufferInfo("destination", "destination", "stack", 32),
            ),
        )
        self.assertNotIn("BUF-004", self.rule_ids(ir))

    def test_strtod_scans_unterminated_raw_input(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(8))),
            Call(2, 0x1020, "strtod", (var("buf"), const(0))),
            buffers=(BufferInfo("buf", "buf", "stack", 8),),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_strcpy_scans_unterminated_source(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(2, 0x1020, "strcpy", (var("destination"), var("source"))),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        findings = self.analyzer.analyze_function(ir)
        finding = next(item for item in findings if item.rule_id == "STR-001")
        self.assertEqual(finding.callee, "strcpy")
        self.assertEqual(finding.ea, 0x1020)

    def test_zeroed_tail_before_short_strcpy_source_is_safe(self):
        ir = function(
            Assignment(1, 0x1008, var("source"), const(0)),
            Call(2, 0x1010, "read", (const(0), var("source"), const(7))),
            Call(3, 0x1020, "strcpy", (var("destination"), var("source"))),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        self.assertNotIn("STR-001", self.rule_ids(ir))

    def test_stpcpy_scans_unterminated_source(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(2, 0x1020, "stpcpy", (var("destination"), var("source"))),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_fortified_strcpy_still_scans_its_source(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "__strcpy_chk",
                (var("destination"), var("source"), const(32)),
            ),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        findings = self.analyzer.analyze_function(ir)
        self.assertIn("STR-001", [item.rule_id for item in findings])
        self.assertNotIn("BUF-002", [item.rule_id for item in findings])

    def test_active_fortified_strcpy_suppresses_destination_overflow(self):
        ir = function(
            Call(
                1,
                0x1010,
                "__strcpy_chk",
                (var("destination"), string("0123456789"), const(8)),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        self.assertNotIn("BUF-002", self.rule_ids(ir))

    def test_disabled_fortified_strcpy_falls_back_to_unbounded_write(self):
        disabled = Expr(
            kind="const",
            text="SIZE_MAX",
            value=(1 << 64) - 1,
            bits=64,
            signed=False,
        )
        ir = function(
            Call(
                1,
                0x1010,
                "__strcpy_chk",
                (var("destination"), string("0123456789"), disabled),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-002"
        )
        self.assertEqual(finding.confidence, "High")
        self.assertIn("literal requires 11 bytes", finding.evidence)

    def test_tainted_fortified_strcpy_capacity_falls_back(self):
        capacity = Expr(
            kind="var",
            text="object_size",
            key="object_size",
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), capacity, const(8))),
            Call(
                2,
                0x1020,
                "__strcpy_chk",
                (var("destination"), var("source"), capacity),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        self.assertIn("BUF-002", self.rule_ids(ir))

    def test_other_fortified_string_writes_follow_object_size(self):
        disabled = Expr(
            kind="const",
            text="SIZE_MAX",
            value=(1 << 64) - 1,
            bits=64,
            signed=False,
        )
        destination = BufferInfo("destination", "destination", "stack", 8)
        for name in ("__stpcpy_chk", "__strcat_chk"):
            with self.subTest(name=name, check="active"):
                active = function(
                    Call(
                        1,
                        0x1010,
                        name,
                        (var("destination"), var("source"), const(8)),
                    ),
                    buffers=(destination,),
                )
                self.assertNotIn("BUF-002", self.rule_ids(active))
            with self.subTest(name=name, check="disabled"):
                fallback = function(
                    Call(
                        1,
                        0x1010,
                        name,
                        (var("destination"), var("source"), disabled),
                    ),
                    buffers=(destination,),
                )
                self.assertIn("BUF-002", self.rule_ids(fallback))

    def test_fortified_strcpy_wrapper_preserves_object_size(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="checked_copy",
            parameters=("destination", "source", "object_size"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "__strcpy_chk",
                    (
                        var("destination"),
                        var("source"),
                        var("object_size"),
                    ),
                )
            ],
        )
        disabled = Expr(
            kind="const",
            text="SIZE_MAX",
            value=(1 << 64) - 1,
            bits=64,
            signed=False,
        )

        def caller(ea: int, name: str, capacity: Expr) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Call(
                        1,
                        ea + 0x10,
                        "checked_copy",
                        (
                            var("destination"),
                            string("0123456789"),
                            capacity,
                        ),
                        callee_ea=wrapper.ea,
                    )
                ],
                buffers={
                    "destination": BufferInfo(
                        "destination",
                        "destination",
                        "stack",
                        8,
                    )
                },
            )

        safe = caller(0x3000, "safe_checked_copy", const(8))
        unsafe = caller(0x4000, "disabled_checked_copy", disabled)
        findings = Analyzer.analyze_program([wrapper, safe, unsafe])
        safe_rules = [
            item.rule_id
            for item in findings
            if item.function_name == safe.name
        ]
        unsafe_rules = [
            item.rule_id
            for item in findings
            if item.function_name == unsafe.name
        ]
        self.assertNotIn("BUF-002", safe_rules)
        self.assertIn("BUF-002", unsafe_rules)

    def test_strcat_scans_unterminated_destination_and_source(self):
        destination = function(
            Call(1, 0x1010, "read", (const(0), var("destination"), const(8))),
            Call(2, 0x1020, "strcat", (var("destination"), string("x"))),
            buffers=(BufferInfo("destination", "destination", "stack", 8),),
        )
        source = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(2, 0x1020, "strcat", (var("destination"), var("source"))),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        self.assertIn("STR-001", self.rule_ids(destination))
        self.assertIn("STR-001", self.rule_ids(source))

    def test_strdup_scans_unterminated_source(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(2, 0x1020, "strdup", (var("source"),)),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_bounded_single_string_scans_respect_object_capacity(self):
        def candidate(name: str, maximum: int) -> FunctionIR:
            return function(
                Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
                Call(2, 0x1020, name, (var("source"), const(maximum))),
                buffers=(BufferInfo("source", "source", "stack", 8),),
            )

        for name in ("strnlen", "strndup"):
            with self.subTest(name=name, maximum=8):
                self.assertNotIn("STR-001", self.rule_ids(candidate(name, 8)))
            with self.subTest(name=name, maximum=9):
                findings = self.analyzer.analyze_function(candidate(name, 9))
                finding = next(
                    item for item in findings if item.rule_id == "STR-001"
                )
                self.assertEqual(finding.callee, name)
                self.assertIn("read_limit=9", finding.evidence)

    def test_guarded_dynamic_strnlen_limit_is_safe(self):
        maximum = Expr(
            kind="var",
            text="maximum",
            key="maximum",
            bits=64,
            signed=False,
        )
        upper = Expr(
            kind="op",
            text="maximum <= 8",
            op="ule",
            children=(maximum, const(8)),
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "strnlen",
                (var("source"), maximum),
                guards=(upper,),
            ),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        self.assertNotIn("STR-001", self.rule_ids(ir))

    def test_symbolic_heap_capacity_bounds_strnlen(self):
        size = Expr(
            kind="var",
            text="size",
            key="size",
            bits=64,
            signed=False,
        )

        def candidate(maximum: Expr) -> FunctionIR:
            return function(
                Assignment(1, 0x1010, var("source"), call_expr("malloc", size)),
                Call(2, 0x1020, "read", (const(0), var("source"), size)),
                Call(3, 0x1030, "strnlen", (var("source"), maximum)),
            )

        self.assertNotIn("STR-001", self.rule_ids(candidate(size)))
        oversized = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
            bits=64,
            signed=False,
        )
        self.assertIn("STR-001", self.rule_ids(candidate(oversized)))

    def test_symbolic_calloc_product_bounds_strnlen(self):
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=64,
            signed=False,
        )
        maximum = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=64,
            signed=False,
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                var("source"),
                call_expr("calloc", count, const(16)),
            ),
            Call(2, 0x1020, "read", (const(0), var("source"), maximum)),
            Call(3, 0x1030, "strnlen", (var("source"), maximum)),
        )
        self.assertNotIn("STR-001", self.rule_ids(ir))

    def test_bounded_comparison_uses_count_or_peer_terminator(self):
        buffer = BufferInfo("source", "source", "stack", 4)

        def candidate(name: str, peer: str, maximum: int) -> FunctionIR:
            return function(
                Call(1, 0x1010, "read", (const(0), var("source"), const(4))),
                Call(
                    2,
                    0x1020,
                    name,
                    (var("source"), string(peer), const(maximum)),
                ),
                buffers=(buffer,),
            )

        for name in ("strncmp", "strncasecmp"):
            with self.subTest(name=name, proof="count"):
                self.assertNotIn(
                    "STR-001", self.rule_ids(candidate(name, "ABCDEFGH", 4))
                )
            with self.subTest(name=name, proof="peer"):
                self.assertNotIn(
                    "STR-001", self.rule_ids(candidate(name, "X", 100))
                )
            with self.subTest(name=name, proof="neither"):
                self.assertIn(
                    "STR-001", self.rule_ids(candidate(name, "ABCD", 100))
                )

    def test_bounded_cstring_summary_keeps_limit_and_internal_sink(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="bounded_length",
            parameters=("data", "maximum"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "strnlen",
                    (var("data"), var("maximum")),
                )
            ],
        )

        def caller(ea: int, name: str, maximum: int) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Call(
                        1,
                        ea + 0x10,
                        "read",
                        (const(0), var("data"), const(8)),
                    ),
                    Call(
                        2,
                        ea + 0x20,
                        "bounded_length",
                        (var("data"), const(maximum)),
                        callee_ea=wrapper.ea,
                    ),
                ],
                buffers={"data": BufferInfo("data", "data", "stack", 8)},
            )

        safe = caller(0x3000, "safe_bounded_length", 8)
        unsafe = caller(0x4000, "unsafe_bounded_length", 9)
        findings = Analyzer.analyze_program([wrapper, safe, unsafe])
        self.assertFalse(
            any(
                item.rule_id == "STR-001"
                and item.summary.endswith("via bounded_length")
                and "read_limit=8" in item.evidence
                for item in findings
            )
        )
        finding = next(
            item
            for item in findings
            if item.rule_id == "STR-001"
            and item.function_name == "bounded_length"
        )
        self.assertEqual(finding.ea, 0x2040)
        self.assertEqual(finding.callee, "strnlen")
        self.assertIn("read_limit=9", finding.evidence)

    def test_bounded_comparison_summary_keeps_literal_peer_bound(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="has_short_prefix",
            parameters=("data", "maximum"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "strncmp",
                    (var("data"), string("X"), var("maximum")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="check_prefix",
            statements=[
                Call(1, 0x3010, "read", (const(0), var("data"), const(4))),
                Call(
                    2,
                    0x3020,
                    "has_short_prefix",
                    (var("data"), const(100)),
                    callee_ea=wrapper.ea,
                ),
            ],
            buffers={"data": BufferInfo("data", "data", "stack", 4)},
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertFalse(any(item.rule_id == "STR-001" for item in findings))

    def test_strcpy_consumer_summary_keeps_internal_sink_address(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="copy_string",
            parameters=("destination", "source"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "strcpy",
                    (var("destination"), var("source")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="receive_string",
            statements=[
                Call(1, 0x3010, "read", (const(0), var("source"), const(8))),
                Call(
                    2,
                    0x3020,
                    "copy_string",
                    (var("destination"), var("source")),
                    callee_ea=wrapper.ea,
                ),
            ],
            buffers={
                "source": BufferInfo("source", "source", "stack", 8),
            },
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(item for item in findings if item.rule_id == "STR-001")
        self.assertEqual(finding.ea, 0x2040)
        self.assertEqual(finding.function_name, "copy_string")

    def test_literal_printf_scans_unterminated_string_argument(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "printf",
                (string("value=%s"), var("source")),
            ),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "STR-001"
        )
        self.assertEqual(finding.ea, 0x1020)
        self.assertEqual(finding.callee, "printf")
        self.assertIn("reach printf %s", finding.summary)

    def test_literal_sprintf_uses_its_later_string_argument(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "sprintf",
                (var("destination"), string("value=%s"), var("source")),
            ),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_static_printf_precision_bounds_string_read(self):
        def candidate(precision: int) -> FunctionIR:
            return function(
                Call(
                    1,
                    0x1010,
                    "read",
                    (const(0), var("source"), const(8)),
                ),
                Call(
                    2,
                    0x1020,
                    "printf",
                    (string(f"%.{precision}s"), var("source")),
                ),
                buffers=(BufferInfo("source", "source", "stack", 8),),
            )

        self.assertNotIn("STR-001", self.rule_ids(candidate(8)))
        findings = self.analyzer.analyze_function(candidate(9))
        finding = next(item for item in findings if item.rule_id == "STR-001")
        self.assertIn("format_precision=9", finding.evidence)

    def test_dynamic_precision_consumes_argument_before_later_string(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "printf",
                (
                    string("%.*s %s"),
                    const(8),
                    string("safe"),
                    var("source"),
                ),
            ),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_dynamic_printf_precision_needs_nonnegative_capacity_guard(self):
        precision = Expr(
            kind="var",
            text="precision",
            key="precision",
            bits=32,
            signed=True,
        )
        lower = Expr(
            kind="op",
            text="precision >= 0",
            op="sge",
            children=(precision, const(0)),
        )
        upper = Expr(
            kind="op",
            text="precision <= 8",
            op="sle",
            children=(precision, const(8)),
        )

        def candidate(guards: tuple[Expr, ...]) -> FunctionIR:
            return function(
                Call(
                    1,
                    0x1010,
                    "read",
                    (const(0), var("source"), const(8)),
                ),
                Call(
                    2,
                    0x1020,
                    "printf",
                    (string("%.*s"), precision, var("source")),
                    guards=guards,
                ),
                buffers=(BufferInfo("source", "source", "stack", 8),),
            )

        self.assertNotIn("STR-001", self.rule_ids(candidate((lower, upper))))
        self.assertIn("STR-001", self.rule_ids(candidate((upper,))))

    def test_negative_dynamic_printf_precision_is_unbounded(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "printf",
                (string("%.*s"), const(-1), var("source")),
            ),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "STR-001"
        )
        self.assertIn("format_precision=-1", finding.evidence)

    def test_format_string_consumer_summary_keeps_internal_sink(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="display_value",
            parameters=("source",),
            statements=[
                Call(
                    1,
                    0x2040,
                    "printf",
                    (string("value=%s"), var("source")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="receive_value",
            statements=[
                Call(1, 0x3010, "read", (const(0), var("source"), const(8))),
                Call(
                    2,
                    0x3020,
                    "display_value",
                    (var("source"),),
                    callee_ea=wrapper.ea,
                ),
            ],
            buffers={
                "source": BufferInfo("source", "source", "stack", 8),
            },
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(item for item in findings if item.rule_id == "STR-001")
        self.assertEqual(finding.ea, 0x2040)
        self.assertEqual(finding.function_name, "display_value")
        self.assertEqual(finding.callee, "printf %s")

    def test_static_format_precision_crosses_wrapper_summary(self):
        def wrapper(ea: int, name: str, precision: int) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                parameters=("source",),
                statements=[
                    Call(
                        1,
                        ea + 0x40,
                        "printf",
                        (string(f"%.{precision}s"), var("source")),
                    )
                ],
            )

        safe_wrapper = wrapper(0x2000, "bounded_display", 8)
        unsafe_wrapper = wrapper(0x2100, "oversized_display", 9)
        caller = FunctionIR(
            ea=0x3000,
            name="receive_value",
            statements=[
                Call(1, 0x3010, "read", (const(0), var("source"), const(8))),
                Call(
                    2,
                    0x3020,
                    "bounded_display",
                    (var("source"),),
                    callee_ea=safe_wrapper.ea,
                ),
                Call(
                    3,
                    0x3030,
                    "oversized_display",
                    (var("source"),),
                    callee_ea=unsafe_wrapper.ea,
                ),
            ],
            buffers={
                "source": BufferInfo("source", "source", "stack", 8),
            },
        )
        findings = Analyzer.analyze_program(
            [safe_wrapper, unsafe_wrapper, caller]
        )
        string_findings = [
            item for item in findings if item.rule_id == "STR-001"
        ]
        self.assertFalse(
            any(item.function_name == safe_wrapper.name for item in string_findings)
        )
        finding = next(
            item
            for item in string_findings
            if item.function_name == unsafe_wrapper.name
        )
        self.assertIn("format_precision=9", finding.evidence)

    def test_dynamic_format_precision_crosses_wrapper_summary(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="dynamic_display",
            parameters=("precision", "source"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "printf",
                    (
                        string("%.*s"),
                        var("precision"),
                        var("source"),
                    ),
                )
            ],
        )

        def caller(ea: int, name: str, precision: int) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Call(
                        1,
                        ea + 0x10,
                        "read",
                        (const(0), var("source"), const(8)),
                    ),
                    Call(
                        2,
                        ea + 0x20,
                        "dynamic_display",
                        (const(precision), var("source")),
                        callee_ea=wrapper.ea,
                    ),
                ],
                buffers={
                    "source": BufferInfo("source", "source", "stack", 8),
                },
            )

        safe = caller(0x3000, "safe_dynamic_display", 8)
        unsafe = caller(0x4000, "unsafe_dynamic_display", 9)
        findings = Analyzer.analyze_program([wrapper, safe, unsafe])
        string_findings = [
            item for item in findings if item.rule_id == "STR-001"
        ]
        self.assertEqual(len(string_findings), 1)
        self.assertEqual(string_findings[0].function_name, wrapper.name)
        self.assertIn("format_precision=9", string_findings[0].evidence)

    def test_bounded_numeric_sprintf_into_split_lvar_is_safe(self):
        split = BufferInfo("buf", "buf", "stack", 8, physical_capacity=40)
        ir = function(
            Call(1, 0x1010, "sprintf", (var("buf"), string("%1.17g"), var("number"))),
            buffers=(split,),
        )
        self.assertNotIn("BUF-002", self.rule_ids(ir))

    def test_general_double_format_fits_recovered_25_byte_span(self):
        split = BufferInfo("buf", "buf", "stack", 8, physical_capacity=25)
        ir = function(
            Call(1, 0x1010, "sprintf", (var("buf"), string("%1.17g"), var("number"))),
            buffers=(split,),
        )
        self.assertNotIn("BUF-002", self.rule_ids(ir))

    def test_unbounded_string_sprintf_remains_a_candidate(self):
        ir = function(
            Call(1, 0x1010, "sprintf", (var("buf"), string("%s"), var("input"))),
            buffers=(self.stack32,),
        )
        self.assertIn("BUF-002", self.rule_ids(ir))

    def test_active_fortified_sprintf_suppresses_destination_overflow(self):
        ir = function(
            Call(
                1,
                0x1010,
                "__sprintf_chk",
                (
                    var("destination"),
                    const(0),
                    const(8),
                    string("0123456789"),
                ),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        self.assertNotIn("BUF-002", self.rule_ids(ir))

    def test_disabled_fortified_sprintf_falls_back_to_unbounded_write(self):
        disabled = Expr(
            kind="const",
            text="SIZE_MAX",
            value=(1 << 64) - 1,
            bits=64,
            signed=False,
        )
        ir = function(
            Call(
                1,
                0x1010,
                "__sprintf_chk",
                (
                    var("destination"),
                    const(0),
                    disabled,
                    string("0123456789"),
                ),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-002"
        )
        self.assertEqual(finding.confidence, "High")
        self.assertIn("literal output requires 11 bytes", finding.evidence)

    def test_escaped_percent_sprintf_has_exact_output_size(self):
        safe = function(
            Call(
                1,
                0x1010,
                "sprintf",
                (var("destination"), string("100%%")),
            ),
            buffers=(BufferInfo("destination", "destination", "stack", 5),),
        )
        unsafe = function(
            Call(
                1,
                0x1010,
                "sprintf",
                (var("destination"), string("100%%")),
            ),
            buffers=(BufferInfo("destination", "destination", "stack", 4),),
        )
        self.assertNotIn("BUF-002", self.rule_ids(safe))
        self.assertIn("BUF-002", self.rule_ids(unsafe))

    def test_fortified_sprintf_keeps_string_source_termination_check(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "__sprintf_chk",
                (
                    var("destination"),
                    const(0),
                    const(32),
                    string("%s"),
                    var("source"),
                ),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 32),
                BufferInfo("source", "source", "stack", 8),
            ),
        )
        rules = self.rule_ids(ir)
        self.assertIn("STR-001", rules)
        self.assertNotIn("BUF-002", rules)

    def test_sprintf_wrapper_preserves_literal_format_context(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="render_number",
            parameters=("destination", "number"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "sprintf",
                    (
                        var("destination"),
                        string("%1.17g"),
                        var("number"),
                    ),
                )
            ],
        )

        def caller(ea: int, name: str, capacity: int) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Call(
                        1,
                        ea + 0x10,
                        "render_number",
                        (var("destination"), var("number")),
                        callee_ea=wrapper.ea,
                    )
                ],
                buffers={
                    "destination": BufferInfo(
                        "destination",
                        "destination",
                        "stack",
                        capacity,
                    )
                },
            )

        safe = caller(0x3000, "safe_render_number", 25)
        unsafe = caller(0x4000, "unsafe_render_number", 8)
        findings = Analyzer.analyze_program([wrapper, safe, unsafe])
        self.assertFalse(
            any(
                item.rule_id == "BUF-002"
                and item.function_name == safe.name
                for item in findings
            )
        )
        self.assertTrue(
            any(
                item.rule_id == "BUF-002"
                and item.function_name == unsafe.name
                for item in findings
            )
        )

    def test_sprintf_wrapper_uses_bounded_literal_return_summary(self):
        message = FunctionIR(
            ea=0x1800,
            name="status_message",
            parameters=("status",),
            statements=[
                Return(1, 0x1810, string("OK")),
                Return(2, 0x1820, string("Not Implemented")),
            ],
        )
        message_call = Expr(
            kind="call",
            text="status_message(status)",
            callee="status_message",
            callee_ea=message.ea,
            children=(var("status"),),
        )
        wrapper = FunctionIR(
            ea=0x2000,
            name="render_status",
            parameters=("destination", "status"),
            statements=[
                Assignment(1, 0x2010, var("message"), message_call),
                Call(
                    2,
                    0x2020,
                    "sprintf",
                    (
                        var("destination"),
                        string("status=%d:%s"),
                        var("status"),
                        var("message"),
                    ),
                ),
            ],
        )

        def caller(ea: int, name: str, capacity: int) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Call(
                        1,
                        ea + 0x10,
                        "render_status",
                        (var("destination"), const(501)),
                        callee_ea=wrapper.ea,
                    )
                ],
                buffers={
                    "destination": BufferInfo(
                        "destination", "destination", "stack", capacity
                    )
                },
            )

        safe = caller(0x3000, "safe_status", 64)
        unsafe = caller(0x4000, "unsafe_status", 16)
        summaries = SummaryBuilder().build([message, wrapper, safe, unsafe])
        message_summary = summaries.lookup(message.name, message.ea)
        self.assertIsNotNone(message_summary)
        self.assertEqual(message_summary.return_cstring_max, 15)

        findings = Analyzer.analyze_program([message, wrapper, safe, unsafe])
        self.assertFalse(
            any(
                item.rule_id == "BUF-002"
                and item.function_name == safe.name
                for item in findings
            )
        )
        self.assertTrue(
            any(
                item.rule_id == "BUF-002"
                and item.function_name == unsafe.name
                for item in findings
            )
        )

    def test_unknown_string_return_path_does_not_suppress_sprintf(self):
        message = FunctionIR(
            ea=0x1800,
            name="maybe_status_message",
            parameters=("fallback",),
            statements=[
                Return(1, 0x1810, string("OK")),
                Return(2, 0x1820, var("fallback")),
            ],
        )
        wrapper = FunctionIR(
            ea=0x2000,
            name="render_maybe_status",
            parameters=("destination", "fallback"),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    var("message"),
                    Expr(
                        kind="call",
                        text="maybe_status_message(fallback)",
                        callee="maybe_status_message",
                        callee_ea=message.ea,
                        children=(var("fallback"),),
                    ),
                ),
                Call(
                    2,
                    0x2020,
                    "sprintf",
                    (
                        var("destination"),
                        string("%s"),
                        var("message"),
                    ),
                ),
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="unknown_status_caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    "render_maybe_status",
                    (var("destination"), var("fallback")),
                    callee_ea=wrapper.ea,
                )
            ],
            buffers={
                "destination": BufferInfo(
                    "destination", "destination", "stack", 4096
                )
            },
        )
        summaries = SummaryBuilder().build([message, wrapper, caller])
        message_summary = summaries.lookup(message.name, message.ea)
        self.assertTrue(
            message_summary is None
            or message_summary.return_cstring_max is None
        )
        findings = Analyzer.analyze_program([message, wrapper, caller])
        self.assertTrue(
            any(
                item.rule_id == "BUF-002"
                and item.function_name == caller.name
                for item in findings
            )
        )

    def test_fortified_sprintf_wrapper_preserves_object_size(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="checked_render",
            parameters=("destination", "object_size"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "__sprintf_chk",
                    (
                        var("destination"),
                        const(0),
                        var("object_size"),
                        string("0123456789"),
                    ),
                )
            ],
        )
        disabled = Expr(
            kind="const",
            text="SIZE_MAX",
            value=(1 << 64) - 1,
            bits=64,
            signed=False,
        )

        def caller(ea: int, name: str, capacity: Expr) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Call(
                        1,
                        ea + 0x10,
                        "checked_render",
                        (var("destination"), capacity),
                        callee_ea=wrapper.ea,
                    )
                ],
                buffers={
                    "destination": BufferInfo(
                        "destination",
                        "destination",
                        "stack",
                        8,
                    )
                },
            )

        safe = caller(0x3000, "safe_checked_render", const(8))
        unsafe = caller(0x4000, "disabled_checked_render", disabled)
        findings = Analyzer.analyze_program([wrapper, safe, unsafe])
        self.assertFalse(
            any(
                item.rule_id == "BUF-002"
                and item.function_name == safe.name
                for item in findings
            )
        )
        self.assertTrue(
            any(
                item.rule_id == "BUF-002"
                and item.function_name == unsafe.name
                for item in findings
            )
        )

    def test_fortified_vsprintf_follows_object_size(self):
        disabled = Expr(
            kind="const",
            text="SIZE_MAX",
            value=(1 << 64) - 1,
            bits=64,
            signed=False,
        )
        destination = BufferInfo("destination", "destination", "stack", 8)
        active = function(
            Call(
                1,
                0x1010,
                "__vsprintf_chk",
                (
                    var("destination"),
                    const(0),
                    const(8),
                    string("0123456789"),
                    var("arguments"),
                ),
            ),
            buffers=(destination,),
        )
        fallback = function(
            Call(
                1,
                0x1010,
                "__vsprintf_chk",
                (
                    var("destination"),
                    const(0),
                    disabled,
                    string("0123456789"),
                    var("arguments"),
                ),
            ),
            buffers=(destination,),
        )
        self.assertNotIn("BUF-002", self.rule_ids(active))
        self.assertIn("BUF-002", self.rule_ids(fallback))

    def test_constant_stack_overflow(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(128))),
            buffers=(self.stack32,),
        )
        self.assertIn("BUF-003", self.rule_ids(ir))

    def test_exact_stack_bound_is_not_reported(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(32))),
            buffers=(self.stack32,),
        )
        self.assertNotIn("BUF-003", self.rule_ids(ir))
        self.assertNotIn("BUF-004", self.rule_ids(ir))

    def test_unresolved_ifunc_copy_into_precise_stack_array_is_reported(self):
        ir = function(
            Call(1, 0x1010, "memcpy_like", (var("buf"), var("src"), var("size"))),
            buffers=(self.stack32,),
        )
        self.assertIn("BUF-004", self.rule_ids(ir))

    def test_ifunc_copy_with_visible_capacity_guard_is_not_reported(self):
        guard = Expr(
            kind="op",
            text="size <= 32",
            op="ule",
            children=(var("size"), const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="guarded_copy",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    1,
                    0x1020,
                    "memcpy_like",
                    (var("buf"), var("src"), var("size")),
                )
            ],
            conditions=[Condition(0x1010, None, guard, guard.text)],
        )
        self.assertNotIn("BUF-004", self.rule_ids(ir))

    def test_ifunc_copy_disjunctive_guard_does_not_prove_bound(self):
        size = Expr(kind="var", text="size", key="size", bits=64, signed=False)
        guard = Expr(
            kind="op",
            text="size <= 32 || trusted != 0",
            op="logical_or",
            children=(
                Expr(
                    kind="op",
                    text="size <= 32",
                    op="ule",
                    children=(size, const(32)),
                ),
                Expr(
                    kind="op",
                    text="trusted != 0",
                    op="ne",
                    children=(var("trusted"), const(0)),
                ),
            ),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="disjunctive_copy_guard",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    2,
                    0x1020,
                    "memcpy_like",
                    (var("buf"), var("src"), size),
                    block_id=1,
                    guards=(guard,),
                )
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text, order=1)],
        )
        self.assertIn("BUF-004", self.rule_ids(ir))

    def test_ifunc_copy_guard_is_killed_by_length_redefinition(self):
        size = Expr(kind="var", text="size", key="size", bits=64, signed=False)
        guard = Expr(
            kind="op",
            text="size <= 32",
            op="ule",
            children=(size, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="redefined_copy_guard",
            buffers={"buf": self.stack32},
            statements=[
                Assignment(
                    2,
                    0x1010,
                    size,
                    call_expr("attacker_size"),
                    block_id=1,
                    guards=(guard,),
                ),
                Call(
                    3,
                    0x1020,
                    "memcpy_like",
                    (var("buf"), var("src"), size),
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x100C, successors=(1, 2)),
                1: BasicBlock(1, 0x100C, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text, order=1)],
        )
        self.assertIn("BUF-004", self.rule_ids(ir))

    def test_ifunc_guard_before_merge_does_not_bless_copy_length(self):
        size = Expr(kind="var", text="size", key="size", bits=64, signed=False)
        guard = Expr(
            kind="op",
            text="size <= 32",
            op="ule",
            children=(size, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="merged_copy",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    1,
                    0x1040,
                    "memcpy_like",
                    (var("buf"), var("src"), size),
                    block_id=3,
                )
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        self.assertIn("BUF-004", self.rule_ids(ir))

    def test_rejected_ifunc_length_path_proves_copy_bound(self):
        size = Expr(kind="var", text="size", key="size", bits=64, signed=False)
        rejection = Expr(
            kind="op",
            text="size > 32",
            op="ugt",
            children=(size, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="validated_copy",
            buffers={"buf": self.stack32},
            statements=[
                Return(1, 0x1020, const(0), block_id=1, guards=(rejection,)),
                Call(
                    2,
                    0x1030,
                    "memcpy_like",
                    (var("buf"), var("src"), size),
                    block_id=2,
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, rejection, rejection.text)],
        )
        self.assertNotIn("BUF-004", self.rule_ids(ir))

    def test_normal_memcpy_keeps_dynamic_untainted_length_quiet(self):
        ir = function(
            Call(1, 0x1010, "memcpy", (var("buf"), var("src"), var("size"))),
            buffers=(self.stack32,),
        )
        self.assertNotIn("BUF-004", self.rule_ids(ir))

    def test_physical_stack_span_disproves_split_lvar_read_overflow(self):
        split = BufferInfo(
            "buf",
            "buf",
            "stack",
            16,
            physical_capacity=4104,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(4096))),
            buffers=(split,),
        )
        self.assertNotIn("BUF-003", self.rule_ids(ir))

    def test_physical_stack_span_disproves_split_lvar_literal_copy_overflow(self):
        split = BufferInfo(
            "buf",
            "buf",
            "stack",
            16,
            physical_capacity=1032,
        )
        destination = Expr(
            kind="address",
            text="&buf[13]",
            key="buf",
            children=(var("buf"),),
            offset=13,
        )
        ir = function(
            Call(1, 0x1010, "strcpy", (destination, string("in-addr"))),
            buffers=(split,),
        )
        self.assertNotIn("BUF-002", self.rule_ids(ir))

    def test_split_lvar_span_does_not_trigger_unresolved_ifunc_fallback(self):
        split = BufferInfo(
            "buf",
            "buf",
            "stack",
            7,
            physical_capacity=4088,
        )
        ir = function(
            Call(1, 0x1010, "memcpy_like", (var("buf"), var("src"), var("size"))),
            buffers=(split,),
        )
        self.assertNotIn("BUF-004", self.rule_ids(ir))

    def test_dynamic_copy_guard_uses_physical_stack_span_as_disproof(self):
        size = Expr(kind="var", text="size", key="size", bits=64, signed=False)
        guard = Expr(
            kind="op",
            text="size <= 383",
            op="ule",
            children=(size, const(383)),
        )
        split = BufferInfo(
            "buf",
            "buf",
            "stack",
            288,
            precise=True,
            physical_capacity=392,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="guarded_split_copy",
            buffers={"buf": split},
            statements=[
                Call(
                    2,
                    0x1020,
                    "memcpy",
                    (var("buf"), var("src"), size),
                    block_id=1,
                    guards=(guard,),
                )
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text, order=1)],
        )
        self.assertNotIn("BUF-004", self.rule_ids(ir))

        too_large_guard = replace(
            guard,
            text="size <= 512",
            children=(size, const(512)),
        )
        too_large_call = replace(
            ir.statements[0],
            guards=(too_large_guard,),
        )
        too_large = replace(
            ir,
            name="oversized_split_copy",
            statements=[too_large_call],
            conditions=[
                Condition(0x1008, 0, too_large_guard, too_large_guard.text, order=1)
            ],
        )
        self.assertIn("BUF-004", self.rule_ids(too_large))

    def test_dynamic_bound_does_not_make_imprecise_scalar_an_overflow(self):
        size = Expr(kind="var", text="size", key="size", bits=64, signed=False)
        guard = Expr(
            kind="op",
            text="size <= 383",
            op="ule",
            children=(size, const(383)),
        )
        fragment = BufferInfo(
            "dest",
            "dest",
            "stack",
            8,
            precise=False,
            physical_capacity=8,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="imprecise_dynamic_copy",
            buffers={"dest": fragment},
            statements=[
                Call(
                    2,
                    0x1020,
                    "memcpy",
                    (var("dest"), var("src"), size),
                    block_id=1,
                    guards=(guard,),
                )
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text, order=1)],
        )
        self.assertNotIn("BUF-004", self.rule_ids(ir))

    def test_imprecise_stack_capacity_does_not_claim_bounded_overflow(self):
        fragment = BufferInfo("buf", "buf", "stack", 16, precise=False)
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(4096))),
            buffers=(fragment,),
        )
        self.assertNotIn("BUF-003", self.rule_ids(ir))

    def test_attacker_controlled_length(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("input"), const(16))),
            Assignment(
                2,
                0x1020,
                var("size"),
                call_expr("atoi", var("input")),
            ),
            Call(3, 0x1030, "read", (const(0), var("buf"), var("size"))),
            buffers=(self.stack32, BufferInfo("input", "input", "stack", 16)),
        )
        findings = self.analyzer.analyze_function(ir)
        overflow = next(finding for finding in findings if finding.rule_id == "BUF-004")
        self.assertIn("attacker-influenced", overflow.summary)

    def test_heap_allocation_size_is_tracked(self):
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(16))),
            Call(2, 0x1020, "memcpy", (var("ptr"), var("src"), const(64))),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-003"
        )
        self.assertEqual(finding.category, "Heap buffer overflow")

    def test_fortified_memcpy_still_detects_source_overread(self):
        ir = function(
            Assignment(1, 0x1010, var("source"), call_expr("malloc", const(8))),
            Call(
                2,
                0x1020,
                "__memcpy_chk",
                (var("destination"), var("source"), const(16), const(16)),
            ),
            buffers=(BufferInfo("destination", "destination", "stack", 16),),
        )
        findings = self.analyzer.analyze_function(ir)
        self.assertTrue(any(item.rule_id == "BUF-007" for item in findings))
        self.assertFalse(
            any(item.rule_id in {"BUF-003", "BUF-004"} for item in findings)
        )

    def test_active_fortify_check_suppresses_destination_overflow(self):
        ir = function(
            Call(
                1,
                0x1010,
                "__memcpy_chk",
                (var("destination"), var("source"), const(16), const(8)),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
                BufferInfo("source", "source", "stack", 16),
            ),
        )
        self.assertFalse(
            any(
                item.rule_id in {"BUF-003", "BUF-004"}
                for item in self.analyzer.analyze_function(ir)
            )
        )

    def test_disabled_fortify_check_falls_back_to_memcpy_bounds(self):
        disabled = Expr(
            kind="const",
            text="SIZE_MAX",
            value=(1 << 64) - 1,
            bits=64,
            signed=False,
        )
        ir = function(
            Call(
                1,
                0x1010,
                "__memcpy_chk",
                (var("destination"), var("source"), const(16), disabled),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
                BufferInfo("source", "source", "stack", 16),
            ),
        )
        self.assertIn("BUF-003", self.rule_ids(ir))

    def test_fortified_memcpy_propagates_source_taint(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "__memcpy_chk",
                (var("destination"), var("source"), const(8), const(16)),
            ),
            Call(3, 0x1030, "printf", (var("destination"),)),
            buffers=(
                BufferInfo("destination", "destination", "stack", 16),
                BufferInfo("source", "source", "stack", 8),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "FMT-001"
        )
        self.assertEqual(finding.confidence, "High")

    def test_bounded_fortify_wrapper_preserves_fail_closed_capacity(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="checked_copy",
            parameters=("destination", "source", "length", "object_size"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "__memcpy_chk",
                    (
                        var("destination"),
                        var("source"),
                        var("length"),
                        var("object_size"),
                    ),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="active_checked_copy",
            statements=[
                Call(
                    1,
                    0x3010,
                    "checked_copy",
                    (var("destination"), var("source"), const(16), const(8)),
                    callee_ea=wrapper.ea,
                )
            ],
            buffers={
                "destination": BufferInfo(
                    "destination", "destination", "stack", 8
                ),
                "source": BufferInfo("source", "source", "stack", 8),
            },
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertFalse(
            any(
                item.rule_id in {"BUF-003", "BUF-004", "BUF-007"}
                for item in findings
            )
        )

    def test_bounded_fortify_wrapper_disabled_check_falls_back(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="checked_copy",
            parameters=("destination", "source", "length", "object_size"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "__memcpy_chk",
                    (
                        var("destination"),
                        var("source"),
                        var("length"),
                        var("object_size"),
                    ),
                )
            ],
        )
        disabled = Expr(
            kind="const",
            text="SIZE_MAX",
            value=(1 << 64) - 1,
            bits=64,
            signed=False,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="disabled_checked_copy",
            statements=[
                Call(
                    1,
                    0x3010,
                    "checked_copy",
                    (var("destination"), var("source"), const(16), disabled),
                    callee_ea=wrapper.ea,
                )
            ],
            buffers={
                "destination": BufferInfo(
                    "destination", "destination", "stack", 8
                ),
                "source": BufferInfo("source", "source", "stack", 16),
            },
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        overflow = next(item for item in findings if item.rule_id == "BUF-003")
        self.assertIn("via checked_copy", overflow.summary)

    def test_bounded_fortify_wrapper_keeps_reachable_source_overread(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="checked_copy",
            parameters=("destination", "source", "length", "object_size"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "__memcpy_chk",
                    (
                        var("destination"),
                        var("source"),
                        var("length"),
                        var("object_size"),
                    ),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="checked_copy_source_overread",
            statements=[
                Call(
                    1,
                    0x3010,
                    "checked_copy",
                    (var("destination"), var("source"), const(16), const(16)),
                    callee_ea=wrapper.ea,
                )
            ],
            buffers={
                "destination": BufferInfo(
                    "destination", "destination", "stack", 16
                ),
                "source": BufferInfo("source", "source", "stack", 8),
            },
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        overreads = [item for item in findings if item.rule_id == "BUF-007"]
        self.assertEqual(len(overreads), 1)
        overread = overreads[0]
        self.assertEqual(overread.function_name, wrapper.name)
        self.assertIn("via checked_copy", overread.summary)

    def test_fortified_strncpy_tracks_unterminated_destination(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "__strncpy_chk",
                (var("destination"), var("source"), const(8), const(8)),
            ),
            Call(3, 0x1030, "strlen", (var("destination"),)),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
                BufferInfo("source", "source", "stack", 8),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "STR-001"
        )
        self.assertEqual(finding.ea, 0x1020)
        self.assertIn("__strncpy_chk", finding.summary)

    def test_aborting_fortified_strncpy_has_no_later_string_state(self):
        ir = function(
            Call(
                1,
                0x1010,
                "__strncpy_chk",
                (var("destination"), var("source"), const(16), const(8)),
            ),
            Call(2, 0x1020, "strlen", (var("destination"),)),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
                BufferInfo("source", "source", "stack", 8),
            ),
        )
        self.assertFalse(
            any(
                item.rule_id in {"BUF-003", "BUF-004", "BUF-007", "STR-001"}
                for item in self.analyzer.analyze_function(ir)
            )
        )

    def test_active_read_chk_suppresses_destination_overflow(self):
        ir = function(
            Call(
                1,
                0x1010,
                "__read_chk",
                (const(0), var("destination"), const(16), const(8)),
            ),
            buffers=(BufferInfo("destination", "destination", "stack", 8),),
        )
        rules = self.rule_ids(ir)
        self.assertNotIn("BUF-003", rules)
        self.assertNotIn("INT-002", rules)

    def test_aborting_read_chk_makes_later_string_consumer_unreachable(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("destination"), const(8))),
            Call(
                2,
                0x1020,
                "__read_chk",
                (const(0), var("destination"), const(16), const(8)),
            ),
            Call(3, 0x1030, "strlen", (var("destination"),)),
            buffers=(BufferInfo("destination", "destination", "stack", 8),),
        )
        self.assertFalse(
            any(
                item.rule_id == "STR-001"
                for item in self.analyzer.analyze_function(ir)
            )
        )

    def test_read_chk_wrapper_propagates_unterminated_string_state(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="checked_read",
            parameters=("fd", "destination", "length", "object_size"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "__read_chk",
                    (
                        var("fd"),
                        var("destination"),
                        var("length"),
                        var("object_size"),
                    ),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="checked_read_string_caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    "checked_read",
                    (const(0), var("destination"), const(8), const(8)),
                    callee_ea=wrapper.ea,
                ),
                Call(2, 0x3020, "strlen", (var("destination"),)),
            ],
            buffers={
                "destination": BufferInfo(
                    "destination", "destination", "stack", 8
                )
            },
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(item for item in findings if item.rule_id == "STR-001")
        self.assertEqual(finding.function_name, caller.name)
        self.assertEqual(finding.ea, 0x3020)

    def test_exact_input_before_stack_guard_nul_is_not_unterminated(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("text"), const(8))),
            Call(2, 0x1020, "atoi", (var("text"),)),
            buffers=(
                BufferInfo(
                    "text",
                    "text",
                    "stack",
                    8,
                    trailing_nul_sentinel=True,
                ),
            ),
        )
        self.assertNotIn("STR-001", self.rule_ids(ir))

    def test_overflow_can_overwrite_stack_guard_nul_sentinel(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("text"), const(9))),
            Call(2, 0x1020, "atoi", (var("text"),)),
            buffers=(
                BufferInfo(
                    "text",
                    "text",
                    "stack",
                    8,
                    trailing_nul_sentinel=True,
                ),
            ),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_input_wrapper_respects_callers_stack_guard_nul_sentinel(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="read_eight",
            parameters=("destination",),
            statements=[
                Call(
                    1,
                    0x2010,
                    "read",
                    (const(0), var("destination"), const(8)),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="guarded_numeric_input",
            statements=[
                Call(
                    1,
                    0x3010,
                    "read_eight",
                    (var("text"),),
                    callee_ea=wrapper.ea,
                ),
                Call(2, 0x3020, "atoi", (var("text"),)),
            ],
            buffers={
                "text": BufferInfo(
                    "text",
                    "text",
                    "stack",
                    8,
                    trailing_nul_sentinel=True,
                )
            },
        )
        self.assertFalse(
            any(
                item.rule_id == "STR-001"
                for item in Analyzer.analyze_program([wrapper, caller])
            )
        )

    def test_aborting_read_chk_wrapper_does_not_export_string_state(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="checked_read",
            parameters=("fd", "destination", "length", "object_size"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "__read_chk",
                    (
                        var("fd"),
                        var("destination"),
                        var("length"),
                        var("object_size"),
                    ),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="aborting_checked_read_string_caller",
            statements=[
                Call(1, 0x3005, "read", (const(0), var("destination"), const(8))),
                Call(
                    2,
                    0x3010,
                    "checked_read",
                    (const(0), var("destination"), const(16), const(8)),
                    callee_ea=wrapper.ea,
                ),
                Call(3, 0x3020, "strlen", (var("destination"),)),
            ],
            buffers={
                "destination": BufferInfo(
                    "destination", "destination", "stack", 8
                )
            },
        )
        self.assertFalse(
            any(
                item.rule_id == "STR-001"
                for item in Analyzer.analyze_program([wrapper, caller])
            )
        )

    def test_direct_fortify_model_overrides_visible_implementation_summary(self):
        implementation = FunctionIR(
            ea=0x1800,
            name="__read_chk",
            parameters=("fd", "destination", "length", "object_size"),
            statements=[
                Call(
                    1,
                    0x1810,
                    "read",
                    (var("fd"), var("destination"), var("length")),
                )
            ],
        )
        wrapper = FunctionIR(
            ea=0x2000,
            name="checked_read",
            parameters=("fd", "destination", "length", "object_size"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "__read_chk",
                    (
                        var("fd"),
                        var("destination"),
                        var("length"),
                        var("object_size"),
                    ),
                    callee_ea=implementation.ea,
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="visible_read_chk_implementation_caller",
            statements=[
                Call(1, 0x3005, "read", (const(0), var("destination"), const(8))),
                Call(
                    2,
                    0x3010,
                    "checked_read",
                    (const(0), var("destination"), const(16), const(8)),
                    callee_ea=wrapper.ea,
                ),
                Call(3, 0x3020, "strlen", (var("destination"),)),
            ],
            buffers={
                "destination": BufferInfo(
                    "destination", "destination", "stack", 8
                )
            },
        )
        findings = Analyzer.analyze_program([implementation, wrapper, caller])
        self.assertFalse(
            any(
                item.function_name == caller.name
                and item.rule_id in {"BUF-003", "BUF-004", "STR-001"}
                for item in findings
            )
        )

    def test_fgets_chk_restores_terminated_string_state(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("destination"), const(8))),
            Call(
                2,
                0x1020,
                "__fgets_chk",
                (var("destination"), const(8), const(8), var("stream")),
            ),
            Call(3, 0x1030, "strlen", (var("destination"),)),
            buffers=(BufferInfo("destination", "destination", "stack", 8),),
        )
        self.assertFalse(
            any(
                item.rule_id == "STR-001"
                for item in self.analyzer.analyze_function(ir)
            )
        )

    def test_disabled_read_chk_falls_back_to_read_bounds(self):
        disabled = Expr(
            kind="const", text="-1LL", value=-1, bits=64, signed=False
        )
        ir = function(
            Call(
                1,
                0x1010,
                "__read_chk",
                (const(0), var("destination"), const(16), disabled),
            ),
            buffers=(BufferInfo("destination", "destination", "stack", 8),),
        )
        self.assertIn("BUF-003", self.rule_ids(ir))

    def test_read_chk_marks_destination_as_external_input(self):
        ir = function(
            Call(
                1,
                0x1010,
                "__read_chk",
                (const(0), var("destination"), const(8), const(16)),
            ),
            Call(2, 0x1020, "printf", (var("destination"),)),
            buffers=(BufferInfo("destination", "destination", "stack", 16),),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "FMT-001"
        )
        self.assertEqual(finding.confidence, "High")

    def test_isoc23_scanf_taints_integer_output(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        ir = function(
            Call(1, 0x1010, "__isoc23_scanf", (string("%u"), count)),
            Call(2, 0x1020, "read", (const(0), var("destination"), count)),
            buffers=(BufferInfo("destination", "destination", "stack", 32),),
        )
        self.assertIn("BUF-004", self.rule_ids(ir))

    def test_aligned_alloc_size_is_tracked(self):
        ir = function(
            Assignment(
                1,
                0x1010,
                var("ptr"),
                call_expr("aligned_alloc", const(16), const(32)),
            ),
            Call(2, 0x1020, "read", (const(0), var("ptr"), const(64))),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-003"
        )
        self.assertIn("capacity=32", finding.evidence)

    def test_symbolic_reallocarray_capacity_is_tracked(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        widened = Expr(
            kind="cast",
            text="(size_t)count",
            children=(count,),
            bits=64,
            signed=False,
        )
        product = Expr(
            kind="op",
            text="(size_t)count * 16",
            op="mul",
            children=(widened, const(16)),
            bits=64,
            signed=False,
        )
        enlarged = Expr(
            kind="op",
            text="(size_t)count * 16 + 1",
            op="add",
            children=(product, const(1)),
            bits=64,
            signed=False,
        )
        allocation = Expr(
            kind="call",
            text="reallocarray(old, count, 16)",
            callee="reallocarray",
            children=(var("old"), count, const(16)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Assignment(2, 0x1020, var("ptr"), allocation),
            Call(3, 0x1030, "read", (const(0), var("ptr"), enlarged)),
        )
        findings = self.analyzer.analyze_function(ir)
        overflow = next(item for item in findings if item.rule_id == "BUF-012")
        self.assertIn("allocator=reallocarray", overflow.evidence)
        self.assertIn("guaranteed_excess=1", overflow.evidence)
        self.assertFalse(any(item.rule_id == "INT-003" for item in findings))

    def test_exact_reallocarray_capacity_is_safe(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        widened = Expr(
            kind="cast",
            text="(size_t)count",
            children=(count,),
            bits=64,
            signed=False,
        )
        product = Expr(
            kind="op",
            text="(size_t)count * 16",
            op="mul",
            children=(widened, const(16)),
            bits=64,
            signed=False,
        )
        allocation = Expr(
            kind="call",
            callee="reallocarray",
            children=(var("old"), count, const(16)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Assignment(2, 0x1020, var("ptr"), allocation),
            Call(3, 0x1030, "read", (const(0), var("ptr"), product)),
        )
        rules = self.rule_ids(ir)
        self.assertNotIn("BUF-012", rules)
        self.assertNotIn("INT-003", rules)

    def test_reallocarray_capacity_flows_through_wrapper_summary(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="resize_records",
            parameters=("old", "count"),
            statements=[
                Return(
                    1,
                    0x2010,
                    Expr(
                        kind="call",
                        callee="reallocarray",
                        children=(var("old"), var("count"), const(16)),
                        bits=64,
                        signed=False,
                    ),
                )
            ],
        )
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        widened = Expr(
            kind="cast",
            text="(size_t)count",
            children=(count,),
            bits=64,
            signed=False,
        )
        product = Expr(
            kind="op",
            text="(size_t)count * 16",
            op="mul",
            children=(widened, const(16)),
            bits=64,
            signed=False,
        )
        enlarged = Expr(
            kind="op",
            text="(size_t)count * 16 + 1",
            op="add",
            children=(product, const(1)),
            bits=64,
            signed=False,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="resize_and_fill",
            statements=[
                Call(1, 0x3010, "read", (const(0), count, const(4))),
                Assignment(
                    2,
                    0x3020,
                    var("ptr"),
                    Expr(
                        kind="call",
                        callee="resize_records",
                        callee_ea=wrapper.ea,
                        children=(var("old"), count),
                        bits=64,
                        signed=False,
                    ),
                ),
                Call(3, 0x3030, "read", (const(0), var("ptr"), enlarged)),
            ],
        )
        finding = next(
            item
            for item in Analyzer.analyze_program([wrapper, caller])
            if item.rule_id == "BUF-012"
        )
        self.assertEqual(finding.function_name, "resize_and_fill")
        self.assertIn("allocator=reallocarray", finding.evidence)

    def test_symbolic_malloc_additive_overflow_is_proven(self):
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Call(2, 0x1020, "read", (const(0), var("ptr"), enlarged)),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-012"
        )
        self.assertIn("guaranteed_excess=1", finding.evidence)

    def test_symbolic_calloc_product_capacity_excess_is_proven(self):
        count = var("count")
        product = Expr(
            kind="op",
            text="count * 4",
            op="mul",
            children=(count, const(4)),
        )
        enlarged = Expr(
            kind="op",
            text="count * 4 + 8",
            op="add",
            children=(product, const(8)),
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                var("ptr"),
                call_expr("calloc", count, const(4)),
            ),
            Call(2, 0x1020, "recv", (const(0), var("ptr"), enlarged)),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-012"
        )
        self.assertIn("guaranteed_excess=8", finding.evidence)

    def test_symbolic_allocation_accounts_for_destination_offset(self):
        size = var("size")
        advanced = Expr(
            kind="op",
            text="ptr + 8",
            key="ptr",
            op="add",
            children=(var("ptr"), const(8)),
            offset=8,
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Call(2, 0x1020, "read", (const(0), advanced, size)),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-012"
        )
        self.assertIn("destination_offset=8", finding.evidence)

    def test_symbolic_allocation_safe_affine_bounds_are_not_reported(self):
        size = var("size")
        allocation_with_slack = Expr(
            kind="op",
            text="size + 8",
            op="add",
            children=(size, const(8)),
        )
        shortened = Expr(
            kind="op",
            text="size - 1",
            op="sub",
            children=(size, const(1)),
        )
        advanced = Expr(
            kind="op",
            text="ptr + 1",
            key="ptr",
            op="add",
            children=(var("ptr"), const(1)),
            offset=1,
        )
        cases = (
            function(
                Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
                Call(2, 0x1020, "read", (const(0), var("ptr"), size)),
            ),
            function(
                Assignment(
                    1,
                    0x1010,
                    var("ptr"),
                    call_expr("malloc", allocation_with_slack),
                ),
                Call(2, 0x1020, "read", (const(0), var("ptr"), size)),
            ),
            function(
                Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
                Call(2, 0x1020, "read", (const(0), advanced, shortened)),
            ),
        )
        for ir in cases:
            with self.subTest(statements=ir.statements):
                self.assertNotIn("BUF-012", self.rule_ids(ir))

    def test_symbolic_allocation_follows_pointer_alias(self):
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Assignment(2, 0x1020, var("alias"), var("ptr")),
            Call(3, 0x1030, "read", (const(0), var("alias"), enlarged)),
        )
        self.assertIn("BUF-012", self.rule_ids(ir))

    def test_symbolic_allocation_rejects_pointer_and_size_redefinitions(self):
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        pointer_redefined = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Assignment(2, 0x1020, var("ptr"), call_expr("lookup")),
            Call(3, 0x1030, "read", (const(0), var("ptr"), enlarged)),
        )
        size_redefined = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Assignment(2, 0x1020, size, const(4)),
            Call(3, 0x1030, "read", (const(0), var("ptr"), enlarged)),
        )
        self.assertNotIn("BUF-012", self.rule_ids(pointer_redefined))
        self.assertNotIn("BUF-012", self.rule_ids(size_redefined))

    def test_non_dominating_symbolic_allocation_is_not_reported(self):
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="conditional_allocation",
            statements=[
                Assignment(
                    1,
                    0x1010,
                    var("ptr"),
                    call_expr("malloc", size),
                    block_id=1,
                ),
                Call(
                    2,
                    0x1040,
                    "read",
                    (const(0), var("ptr"), enlarged),
                    block_id=3,
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
        )
        self.assertNotIn("BUF-012", self.rule_ids(ir))

    def test_branch_pointer_redefinition_makes_symbolic_capacity_ambiguous(self):
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="ambiguous_pointer",
            statements=[
                Assignment(
                    1,
                    0x1008,
                    var("ptr"),
                    call_expr("malloc", size),
                    block_id=0,
                ),
                Assignment(
                    2,
                    0x1020,
                    var("ptr"),
                    call_expr("lookup"),
                    block_id=1,
                ),
                Call(
                    3,
                    0x1050,
                    "read",
                    (const(0), var("ptr"), enlarged),
                    block_id=3,
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1040, 0x1060, predecessors=(1, 2)),
            },
            entry_block=0,
        )
        self.assertNotIn("BUF-012", self.rule_ids(ir))

    def test_symbolic_mmap_request_does_not_ignore_page_rounding(self):
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                var("mapping"),
                call_expr(
                    "mmap",
                    const(0),
                    size,
                    const(3),
                    const(0x22),
                    const(-1),
                    const(0),
                ),
            ),
            Call(2, 0x1020, "read", (const(0), var("mapping"), enlarged)),
        )
        self.assertNotIn("BUF-012", self.rule_ids(ir))

    def test_output_api_checks_constant_source_capacity(self):
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(16))),
            Call(2, 0x1020, "write", (const(1), var("ptr"), const(32))),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("available_source_capacity=16", finding.evidence)

    def test_memcmp_checks_first_source_capacity(self):
        ir = function(
            Call(
                1,
                0x1010,
                "memcmp",
                (var("left"), var("right"), const(16)),
            ),
            buffers=(
                BufferInfo("left", "left", "stack", 8),
                BufferInfo("right", "right", "stack", 16),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("source=left", finding.evidence)

    def test_memcmp_checks_second_source_capacity(self):
        ir = function(
            Call(
                1,
                0x1010,
                "memcmp",
                (var("left"), var("right"), const(16)),
            ),
            buffers=(
                BufferInfo("left", "left", "stack", 16),
                BufferInfo("right", "right", "stack", 8),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("source=right", finding.evidence)

    def test_memcmp_exact_source_capacities_are_safe(self):
        ir = function(
            Call(
                1,
                0x1010,
                "memcmp",
                (var("left"), var("right"), const(16)),
            ),
            buffers=(
                BufferInfo("left", "left", "stack", 16),
                BufferInfo("right", "right", "stack", 16),
            ),
        )
        self.assertNotIn("BUF-007", self.rule_ids(ir))

    def test_bcmp_checks_both_source_capacities(self):
        ir = function(
            Call(
                1,
                0x1010,
                "bcmp",
                (var("left"), var("right"), const(16)),
            ),
            buffers=(
                BufferInfo("left", "left", "stack", 8),
                BufferInfo("right", "right", "stack", 7),
            ),
        )
        findings = [
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        ]
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("source=left" in item.evidence for item in findings))
        self.assertTrue(any("source=right" in item.evidence for item in findings))

    def test_memchr_checks_source_capacity_and_wrapper(self):
        finder = FunctionIR(
            ea=0x2000,
            name="find_byte",
            parameters=("source", "needle", "count"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "memchr",
                    (var("source"), var("needle"), var("count")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="search_input",
            statements=[
                Call(
                    1,
                    0x3010,
                    "find_byte",
                    (var("source"), const(ord("A")), const(9)),
                    callee_ea=finder.ea,
                )
            ],
            buffers={"source": BufferInfo("source", "source", "stack", 8)},
        )
        findings = Analyzer.analyze_program([finder, caller])
        finding = next(item for item in findings if item.rule_id == "BUF-007")
        self.assertEqual(finding.ea, 0x2040)
        self.assertEqual(finding.function_name, "find_byte")
        self.assertIn("wrapper=find_byte", finding.evidence)

    def test_exact_memchr_does_not_disclose_short_read_tail(self):
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("source"), const(8))),
            Call(
                2,
                0x1020,
                "memchr",
                (var("source"), const(ord("A")), const(8)),
            ),
            buffers=(BufferInfo("source", "source", "stack", 8),),
        )
        self.assertNotIn("INIT-002", self.rule_ids(ir))

    def test_fixed_byte_read_uses_literal_storage_capacity(self):
        safe = function(
            Call(1, 0x1010, "memchr", (string("ABC"), const(0), const(4)))
        )
        unsafe = function(
            Call(1, 0x1010, "memchr", (string("ABC"), const(0), const(5)))
        )
        early_terminating = function(
            Call(
                1,
                0x1010,
                "strncpy",
                (var("destination"), string("ABC"), const(100)),
            )
        )
        self.assertNotIn("BUF-007", self.rule_ids(safe))
        self.assertIn("BUF-007", self.rule_ids(unsafe))
        self.assertNotIn("BUF-007", self.rule_ids(early_terminating))

    @staticmethod
    def iovec_field(owner: str, label: str, offset: int) -> Expr:
        return Expr(
            kind="member",
            text=f"{owner}.{label}",
            key=owner,
            children=(var(owner),),
            offset=offset,
            bits=64,
            signed=False,
        )

    @staticmethod
    def iovec_address(owner: str, bits: int = 64) -> Expr:
        return Expr(
            kind="address",
            text=f"&{owner}",
            key=owner,
            children=(var(owner),),
            bits=bits,
            signed=False,
        )

    def test_writev_checks_descriptor_and_payload_ranges(self):
        base = self.iovec_field("vector", "iov_base", 0)
        length = self.iovec_field("vector", "iov_len", 8)

        def candidate(source_length: int, count: int) -> FunctionIR:
            return function(
                Assignment(1, 0x1008, base, var("source")),
                Assignment(2, 0x100C, length, const(source_length)),
                Call(
                    3,
                    0x1010,
                    "writev",
                    (const(1), self.iovec_address("vector"), const(count)),
                ),
                buffers=(
                    BufferInfo("vector", "vector", "stack", 16),
                    BufferInfo("source", "source", "stack", 8),
                ),
            )

        payload_findings = self.analyzer.analyze_function(candidate(9, 1))
        payload = next(
            item for item in payload_findings if item.rule_id == "BUF-007"
        )
        self.assertIn("source=source", payload.evidence)
        self.assertIn("iovec_index=0", payload.evidence)

        descriptor_findings = self.analyzer.analyze_function(candidate(8, 2))
        descriptor = next(
            item for item in descriptor_findings if item.rule_id == "BUF-007"
        )
        self.assertIn("descriptor array", descriptor.summary)
        self.assertIn("descriptor_size=16", descriptor.evidence)

        self.assertNotIn("BUF-007", self.rule_ids(candidate(8, 1)))

    def test_writev_uses_32_bit_iovec_layout(self):
        vector = self.iovec_address("vector", bits=32)
        ir = function(
            Call(1, 0x1010, "writev", (const(1), vector, const(2))),
            buffers=(BufferInfo("vector", "vector", "stack", 8),),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("descriptor_size=8", finding.evidence)

    def test_writev_recovers_hexrays_split_iovec_tail(self):
        ir = FunctionIR(
            ea=0x1000,
            name="split_iovec",
            buffers={
                "vector": BufferInfo("vector", "vector", "stack", 16),
                "first": BufferInfo("first", "first", "stack", 16),
                "second": BufferInfo("second", "second", "stack", 8),
            },
            stack_slots={
                "vector": StackSlot("vector", "vector", 0, 16, "aggregate"),
                "second_base": StackSlot(
                    "second_base", "second_base", 16, 8, "pointer"
                ),
                "second_length": StackSlot(
                    "second_length", "second_length", 24, 8, "integer"
                ),
            },
            statements=[
                Assignment(
                    1,
                    0x1004,
                    self.iovec_field("vector", "iov_base", 0),
                    var("first"),
                ),
                Assignment(
                    2,
                    0x1008,
                    self.iovec_field("vector", "iov_len", 8),
                    const(16),
                ),
                Assignment(3, 0x100C, var("second_base"), var("second")),
                Assignment(4, 0x1010, var("second_length"), const(9)),
                Call(
                    5,
                    0x1018,
                    "writev",
                    (const(1), self.iovec_address("vector"), const(2)),
                ),
            ],
        )
        findings = [
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        ]
        self.assertEqual(len(findings), 1)
        self.assertNotIn("descriptor array", findings[0].summary)
        self.assertIn("source=second", findings[0].evidence)
        self.assertIn("iovec_index=1", findings[0].evidence)

    def test_writev_does_not_treat_adjacent_array_as_split_pointer_field(self):
        ir = FunctionIR(
            ea=0x1000,
            name="one_iovec",
            buffers={
                "vector": BufferInfo("vector", "vector", "stack", 16),
                "adjacent": BufferInfo("adjacent", "adjacent", "stack", 8),
            },
            stack_slots={
                "vector": StackSlot("vector", "vector", 0, 16, "aggregate"),
                "adjacent": StackSlot(
                    "adjacent", "adjacent", 16, 8, "aggregate"
                ),
                "scalar": StackSlot("scalar", "scalar", 24, 8, "integer"),
            },
            statements=[
                Assignment(
                    1,
                    0x1004,
                    self.iovec_field("vector", "iov_base", 0),
                    var("adjacent"),
                ),
                Assignment(
                    2,
                    0x1008,
                    self.iovec_field("vector", "iov_len", 8),
                    const(8),
                ),
                Assignment(3, 0x100C, var("adjacent"), const(0)),
                Assignment(4, 0x1010, var("scalar"), const(8)),
                Call(
                    5,
                    0x1018,
                    "writev",
                    (const(1), self.iovec_address("vector"), const(2)),
                ),
            ],
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("descriptor array", finding.summary)

    def test_writev_rejects_count_above_iov_max_before_reading(self):
        ir = function(
            Call(
                1,
                0x1010,
                "writev",
                (const(1), self.iovec_address("vector"), const(1025)),
            ),
            buffers=(BufferInfo("vector", "vector", "stack", 16),),
        )
        self.assertNotIn("BUF-007", self.rule_ids(ir))

    def test_iovec_total_above_ssize_max_fails_before_payload_io(self):
        def candidate(name: str, payload: str) -> FunctionIR:
            return function(
                Assignment(
                    1,
                    0x1008,
                    self.iovec_field("vector", "iov_base", 0),
                    var(payload),
                ),
                Assignment(
                    2,
                    0x100C,
                    self.iovec_field("vector", "iov_len", 8),
                    const(1 << 63),
                ),
                Call(
                    3,
                    0x1010,
                    name,
                    (const(0), self.iovec_address("vector"), const(1)),
                ),
                buffers=(
                    BufferInfo("vector", "vector", "stack", 16),
                    BufferInfo(payload, payload, "stack", 8),
                ),
            )

        self.assertNotIn("BUF-007", self.rule_ids(candidate("writev", "source")))
        readv_rules = self.rule_ids(candidate("readv", "destination"))
        self.assertNotIn("BUF-003", readv_rules)
        self.assertNotIn("BUF-007", readv_rules)

    def test_writev_wrapper_preserves_internal_sink(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="scatter_output",
            parameters=("vectors", "count"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "writev",
                    (const(1), var("vectors"), var("count")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="send_record",
            statements=[
                Assignment(
                    1,
                    0x3010,
                    self.iovec_field("vector", "iov_base", 0),
                    var("source"),
                ),
                Assignment(
                    2,
                    0x3018,
                    self.iovec_field("vector", "iov_len", 8),
                    const(9),
                ),
                Call(
                    3,
                    0x3020,
                    "scatter_output",
                    (self.iovec_address("vector"), const(1)),
                    callee_ea=wrapper.ea,
                ),
            ],
            buffers={
                "vector": BufferInfo("vector", "vector", "stack", 16),
                "source": BufferInfo("source", "source", "stack", 8),
            },
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(item for item in findings if item.rule_id == "BUF-007")
        self.assertEqual(finding.ea, 0x2040)
        self.assertEqual(finding.function_name, "scatter_output")
        self.assertIn("wrapper=scatter_output", finding.evidence)

    def test_writev_reports_short_input_tail_disclosure(self):
        ir = function(
            Call(1, 0x1004, "read", (const(0), var("source"), const(8))),
            Assignment(
                2,
                0x1008,
                self.iovec_field("vector", "iov_base", 0),
                var("source"),
            ),
            Assignment(
                3,
                0x100C,
                self.iovec_field("vector", "iov_len", 8),
                const(8),
            ),
            Call(
                4,
                0x1010,
                "writev",
                (const(1), self.iovec_address("vector"), const(1)),
            ),
            buffers=(
                BufferInfo("vector", "vector", "stack", 16),
                BufferInfo("source", "source", "stack", 8),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "INIT-002"
        )
        self.assertEqual(finding.callee, "writev")

    def test_writev_rejects_branch_ambiguous_iovec_source(self):
        base = self.iovec_field("vector", "iov_base", 0)
        length = self.iovec_field("vector", "iov_len", 8)
        ir = FunctionIR(
            ea=0x1000,
            name="ambiguous_vector",
            statements=[
                Assignment(1, 0x1010, length, const(9), block_id=0),
                Assignment(2, 0x1020, base, var("left"), block_id=1),
                Assignment(3, 0x1030, base, var("right"), block_id=2),
                Call(
                    4,
                    0x1040,
                    "writev",
                    (const(1), self.iovec_address("vector"), const(1)),
                    block_id=3,
                ),
            ],
            buffers={
                "vector": BufferInfo("vector", "vector", "stack", 16),
                "left": BufferInfo("left", "left", "stack", 8),
                "right": BufferInfo("right", "right", "stack", 8),
            },
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, successors=(1, 2)),
                1: BasicBlock(1, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1040, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
        )
        self.assertNotIn("BUF-007", self.rule_ids(ir))

    def test_readv_checks_descriptor_and_payload_ranges(self):
        base = self.iovec_field("vector", "iov_base", 0)
        length = self.iovec_field("vector", "iov_len", 8)

        def candidate(destination_length: int, count: int) -> FunctionIR:
            return function(
                Assignment(1, 0x1008, base, var("destination")),
                Assignment(2, 0x100C, length, const(destination_length)),
                Call(
                    3,
                    0x1010,
                    "readv",
                    (const(0), self.iovec_address("vector"), const(count)),
                ),
                buffers=(
                    BufferInfo("vector", "vector", "stack", 16),
                    BufferInfo("destination", "destination", "stack", 8),
                ),
            )

        payload_findings = self.analyzer.analyze_function(candidate(9, 1))
        payload = next(
            item for item in payload_findings if item.rule_id == "BUF-003"
        )
        self.assertEqual(payload.callee, "readv")
        self.assertIn("destination=destination", payload.evidence)
        self.assertIn("iovec_index=0", payload.evidence)

        descriptor_findings = self.analyzer.analyze_function(candidate(8, 2))
        descriptor = next(
            item for item in descriptor_findings if item.rule_id == "BUF-007"
        )
        self.assertIn("descriptor array", descriptor.summary)
        self.assertIn("descriptor_size=16", descriptor.evidence)

        safe_rules = self.rule_ids(candidate(8, 1))
        self.assertNotIn("BUF-003", safe_rules)
        self.assertNotIn("BUF-007", safe_rules)

    def test_readv_recovers_hexrays_split_iovec_tail(self):
        ir = FunctionIR(
            ea=0x1000,
            name="split_readv_iovec",
            buffers={
                "vector": BufferInfo("vector", "vector", "stack", 16),
                "first": BufferInfo("first", "first", "stack", 16),
                "second": BufferInfo("second", "second", "stack", 8),
            },
            stack_slots={
                "vector": StackSlot("vector", "vector", 0, 16, "aggregate"),
                "second_base": StackSlot(
                    "second_base", "second_base", 16, 8, "pointer"
                ),
                "second_length": StackSlot(
                    "second_length", "second_length", 24, 8, "integer"
                ),
            },
            statements=[
                Assignment(
                    1,
                    0x1004,
                    self.iovec_field("vector", "iov_base", 0),
                    var("first"),
                ),
                Assignment(
                    2,
                    0x1008,
                    self.iovec_field("vector", "iov_len", 8),
                    const(16),
                ),
                Assignment(3, 0x100C, var("second_base"), var("second")),
                Assignment(4, 0x1010, var("second_length"), const(9)),
                Call(
                    5,
                    0x1018,
                    "readv",
                    (const(0), self.iovec_address("vector"), const(2)),
                ),
            ],
        )
        findings = self.analyzer.analyze_function(ir)
        payload = next(item for item in findings if item.rule_id == "BUF-003")
        self.assertNotIn("descriptor array", payload.summary)
        self.assertIn("destination=second", payload.evidence)
        self.assertIn("iovec_index=1", payload.evidence)
        self.assertFalse(
            any(
                item.rule_id == "BUF-007"
                and "descriptor array" in item.summary
                for item in findings
            )
        )

    def test_readv_wrapper_preserves_internal_sink(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="scatter_input",
            parameters=("vectors", "count"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "readv",
                    (const(0), var("vectors"), var("count")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="receive_record",
            statements=[
                Assignment(
                    1,
                    0x3010,
                    self.iovec_field("vector", "iov_base", 0),
                    var("destination"),
                ),
                Assignment(
                    2,
                    0x3018,
                    self.iovec_field("vector", "iov_len", 8),
                    const(9),
                ),
                Call(
                    3,
                    0x3020,
                    "scatter_input",
                    (self.iovec_address("vector"), const(1)),
                    callee_ea=wrapper.ea,
                ),
            ],
            buffers={
                "vector": BufferInfo("vector", "vector", "stack", 16),
                "destination": BufferInfo(
                    "destination", "destination", "stack", 8
                ),
            },
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(item for item in findings if item.rule_id == "BUF-003")
        self.assertEqual(finding.ea, 0x2040)
        self.assertEqual(finding.function_name, "scatter_input")
        self.assertIn("wrapper=scatter_input", finding.evidence)

    def test_readv_full_payload_is_may_unterminated(self):
        ir = function(
            Assignment(1, 0x1004, var("destination"), const(0)),
            Assignment(
                2,
                0x1008,
                self.iovec_field("vector", "iov_base", 0),
                var("destination"),
            ),
            Assignment(
                3,
                0x100C,
                self.iovec_field("vector", "iov_len", 8),
                const(8),
            ),
            Call(
                4,
                0x1010,
                "readv",
                (const(0), self.iovec_address("vector"), const(1)),
            ),
            Call(5, 0x1020, "printf", (string("%s"), var("destination"))),
            buffers=(
                BufferInfo("vector", "vector", "stack", 16),
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_readv_payload_is_external_input_taint(self):
        ir = function(
            Assignment(
                1,
                0x1008,
                self.iovec_field("vector", "iov_base", 0),
                var("destination"),
            ),
            Assignment(
                2,
                0x100C,
                self.iovec_field("vector", "iov_len", 8),
                const(8),
            ),
            Call(
                3,
                0x1010,
                "readv",
                (const(0), self.iovec_address("vector"), const(1)),
            ),
            Call(4, 0x1020, "printf", (var("destination"),)),
            buffers=(
                BufferInfo("vector", "vector", "stack", 16),
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "FMT-001"
        )
        self.assertEqual(finding.confidence, "High")

    def test_readv_wrapper_preserves_unterminated_payload(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="scatter_input",
            parameters=("vectors", "count"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "readv",
                    (const(0), var("vectors"), var("count")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="print_record",
            buffers={
                "vector": BufferInfo("vector", "vector", "stack", 16),
                "destination": BufferInfo(
                    "destination", "destination", "stack", 8
                ),
            },
            statements=[
                Assignment(1, 0x3004, var("destination"), const(0)),
                Assignment(
                    2,
                    0x3008,
                    self.iovec_field("vector", "iov_base", 0),
                    var("destination"),
                ),
                Assignment(
                    3,
                    0x300C,
                    self.iovec_field("vector", "iov_len", 8),
                    const(8),
                ),
                Call(
                    4,
                    0x3010,
                    "scatter_input",
                    (self.iovec_address("vector"), const(1)),
                    callee_ea=wrapper.ea,
                ),
                Call(
                    5,
                    0x3020,
                    "printf",
                    (string("%s"), var("destination")),
                ),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertTrue(
            any(
                item.rule_id == "STR-001"
                and item.function_name == "print_record"
                for item in findings
            )
        )

    def test_readv_wrapper_preserves_trusted_file_handle(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="file_scatter_input",
            parameters=("handle", "vectors", "count"),
            statements=[
                Call(
                    1,
                    0x2040,
                    "readv",
                    (var("handle"), var("vectors"), var("count")),
                )
            ],
        )

        def caller(name: str, trusted: bool) -> FunctionIR:
            statements: list[Assignment | Call] = []
            order = 1
            if trusted:
                statements.append(
                    Call(
                        order,
                        0x3010,
                        "strcpy",
                        (var("file_object"), string("/proc/self/maps")),
                    )
                )
                order += 1
            statements.extend(
                [
                    Assignment(
                        order,
                        0x3020,
                        self.iovec_field("vector", "iov_base", 0),
                        var("destination"),
                    ),
                    Assignment(
                        order + 1,
                        0x3028,
                        self.iovec_field("vector", "iov_len", 8),
                        const(8),
                    ),
                    Call(
                        order + 2,
                        0x3030,
                        "file_scatter_input",
                        (
                            var("file_object"),
                            self.iovec_address("vector"),
                            const(1),
                        ),
                        callee_ea=wrapper.ea,
                    ),
                    Call(
                        order + 3,
                        0x3040,
                        "printf",
                        (var("destination"),),
                    ),
                ]
            )
            return FunctionIR(
                ea=0x3000 if trusted else 0x4000,
                name=name,
                statements=statements,
                buffers={
                    "vector": BufferInfo("vector", "vector", "stack", 16),
                    "destination": BufferInfo(
                        "destination", "destination", "stack", 8
                    ),
                },
            )

        trusted = caller("trusted_readv", True)
        unknown = caller("unknown_readv", False)
        findings = Analyzer.analyze_program([wrapper, trusted, unknown])
        self.assertFalse(
            any(
                item.rule_id == "FMT-001"
                and item.confidence == "High"
                and item.function_name == trusted.name
                for item in findings
            )
        )
        self.assertTrue(
            any(
                item.rule_id == "FMT-001"
                and item.confidence == "High"
                and item.function_name == unknown.name
                for item in findings
            )
        )

    @staticmethod
    def message_field(owner: str, label: str, offset: int) -> Expr:
        return Expr(
            kind="member",
            text=f"{owner}.{label}",
            key=owner,
            children=(var(owner),),
            offset=offset,
            bits=64,
            signed=False,
        )

    def test_sendmsg_checks_header_iovec_and_payload_ranges(self):
        ir = function(
            Assignment(
                1,
                0x1004,
                self.message_field("message", "msg_iov", 16),
                self.iovec_address("vector"),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("message", "msg_iovlen", 24),
                const(1),
            ),
            Assignment(
                3,
                0x100C,
                self.iovec_field("vector", "iov_base", 0),
                var("source"),
            ),
            Assignment(
                4,
                0x1010,
                self.iovec_field("vector", "iov_len", 8),
                const(9),
            ),
            Call(
                5,
                0x1020,
                "sendmsg",
                (const(1), self.iovec_address("message"), const(0)),
            ),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("vector", "vector", "stack", 16),
                BufferInfo("source", "source", "stack", 8),
            ),
        )
        findings = self.analyzer.analyze_function(ir)
        payload = next(item for item in findings if item.rule_id == "BUF-007")
        self.assertEqual(payload.callee, "sendmsg")
        self.assertIn("message_component=msg_iov", payload.evidence)
        self.assertIn("iovec_index=0", payload.evidence)
        self.assertNotIn("msghdr object", payload.summary)

        short_header = function(
            Call(
                1,
                0x1020,
                "sendmsg",
                (const(1), self.iovec_address("message"), const(0)),
            ),
            buffers=(BufferInfo("message", "message", "stack", 48),),
        )
        header = next(
            item
            for item in self.analyzer.analyze_function(short_header)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("msghdr object", header.summary)
        self.assertIn("message_stride=56", header.evidence)

    def test_sendmsg_checks_name_and_control_source_ranges(self):
        ir = function(
            Assignment(
                1,
                0x1004,
                self.message_field("message", "msg_name", 0),
                var("address"),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("message", "msg_namelen", 8),
                const(17),
            ),
            Assignment(
                3,
                0x100C,
                self.message_field("message", "msg_control", 32),
                var("control"),
            ),
            Assignment(
                4,
                0x1010,
                self.message_field("message", "msg_controllen", 40),
                const(9),
            ),
            Call(
                5,
                0x1020,
                "sendmsg",
                (const(1), self.iovec_address("message"), const(0)),
            ),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("address", "address", "stack", 16),
                BufferInfo("control", "control", "stack", 8),
            ),
        )
        findings = [
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        ]
        self.assertEqual(len(findings), 2)
        evidence = "\n".join(item.evidence for item in findings)
        self.assertIn("message_component=msg_name", evidence)
        self.assertIn("message_component=msg_control", evidence)

    def test_recvmsg_checks_payload_and_propagates_input_state(self):
        ir = function(
            Assignment(1, 0x1002, var("destination"), const(0)),
            Assignment(
                2,
                0x1004,
                self.message_field("message", "msg_iov", 16),
                self.iovec_address("vector"),
            ),
            Assignment(
                3,
                0x1008,
                self.message_field("message", "msg_iovlen", 24),
                const(1),
            ),
            Assignment(
                4,
                0x100C,
                self.iovec_field("vector", "iov_base", 0),
                var("destination"),
            ),
            Assignment(
                5,
                0x1010,
                self.iovec_field("vector", "iov_len", 8),
                const(8),
            ),
            Call(
                6,
                0x1020,
                "recvmsg",
                (const(0), self.iovec_address("message"), const(0)),
            ),
            Call(7, 0x1030, "printf", (var("destination"),)),
            Call(8, 0x1040, "printf", (string("%s"), var("destination"))),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("vector", "vector", "stack", 16),
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        findings = self.analyzer.analyze_function(ir)
        format_finding = next(
            item for item in findings if item.rule_id == "FMT-001"
        )
        self.assertEqual(format_finding.confidence, "High")
        self.assertTrue(any(item.rule_id == "STR-001" for item in findings))

        overflowing = function(
            Assignment(
                1,
                0x1004,
                self.message_field("message", "msg_iov", 16),
                self.iovec_address("vector"),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("message", "msg_iovlen", 24),
                const(1),
            ),
            Assignment(
                3,
                0x100C,
                self.iovec_field("vector", "iov_base", 0),
                var("destination"),
            ),
            Assignment(
                4,
                0x1010,
                self.iovec_field("vector", "iov_len", 8),
                const(9),
            ),
            Call(
                5,
                0x1020,
                "recvmsg",
                (const(0), self.iovec_address("message"), const(0)),
            ),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("vector", "vector", "stack", 16),
                BufferInfo("destination", "destination", "stack", 8),
            ),
        )
        overflow = next(
            item
            for item in self.analyzer.analyze_function(overflowing)
            if item.rule_id == "BUF-003"
        )
        self.assertEqual(overflow.callee, "recvmsg")
        self.assertIn("message_component=msg_iov", overflow.evidence)

        received = Expr(
            kind="var", text="received", key="received", bits=64, signed=True
        )
        recv_result = Expr(
            kind="call",
            text="recvmsg(fd, &message, 0)",
            callee="recvmsg",
            children=(
                var("fd"),
                self.iovec_address("message"),
                const(0),
            ),
            bits=64,
            signed=True,
        )
        tainted_length = function(
            Assignment(1, 0x2010, received, recv_result),
            Call(
                2,
                0x2020,
                "memcpy",
                (var("destination"), var("source"), received),
            ),
            buffers=(
                BufferInfo("destination", "destination", "stack", 8),
                BufferInfo("source", "source", "stack", 8),
            ),
        )
        length_finding = next(
            item
            for item in self.analyzer.analyze_function(tainted_length)
            if item.rule_id == "BUF-004"
        )
        self.assertIn("attacker-influenced length", length_finding.summary)

    def test_recvmsg_checks_name_and_control_destination_ranges(self):
        ir = function(
            Assignment(
                1,
                0x1004,
                self.message_field("message", "msg_name", 0),
                var("address"),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("message", "msg_namelen", 8),
                const(17),
            ),
            Assignment(
                3,
                0x100C,
                self.message_field("message", "msg_control", 32),
                var("control"),
            ),
            Assignment(
                4,
                0x1010,
                self.message_field("message", "msg_controllen", 40),
                const(9),
            ),
            Call(
                5,
                0x1020,
                "recvmsg",
                (const(0), self.iovec_address("message"), const(0)),
            ),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("address", "address", "stack", 16),
                BufferInfo("control", "control", "stack", 8),
            ),
        )
        findings = [
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-003"
        ]
        self.assertEqual(len(findings), 2)
        evidence = "\n".join(item.evidence for item in findings)
        self.assertIn("message_component=msg_name", evidence)
        self.assertIn("message_component=msg_control", evidence)

    def test_message_linux_clamps_and_fail_closed_ordering(self):
        clamped_name = function(
            Assignment(
                1,
                0x1004,
                self.message_field("message", "msg_name", 0),
                var("address"),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("message", "msg_namelen", 8),
                const(1000),
            ),
            Call(
                3,
                0x1020,
                "sendmsg",
                (const(1), self.iovec_address("message"), const(0)),
            ),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("address", "address", "stack", 128),
            ),
        )
        self.assertNotIn("BUF-007", self.rule_ids(clamped_name))

        invalid_vector_count = function(
            Assignment(
                1,
                0x1004,
                self.message_field("message", "msg_iovlen", 24),
                const(1025),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("message", "msg_control", 32),
                var("control"),
            ),
            Assignment(
                3,
                0x100C,
                self.message_field("message", "msg_controllen", 40),
                const(9),
            ),
            Call(
                4,
                0x1020,
                "sendmsg",
                (const(1), self.iovec_address("message"), const(0)),
            ),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("control", "control", "stack", 8),
            ),
        )
        self.assertNotIn("BUF-007", self.rule_ids(invalid_vector_count))

        control_only = function(
            Assignment(
                1,
                0x1004,
                self.message_field("message", "msg_iovlen", 24),
                const(0),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("message", "msg_control", 32),
                var("control"),
            ),
            Assignment(
                3,
                0x100C,
                self.message_field("message", "msg_controllen", 40),
                const(9),
            ),
            Call(
                4,
                0x1020,
                "sendmsg",
                (const(1), self.iovec_address("message"), const(0)),
            ),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("control", "control", "stack", 8),
            ),
        )
        control_finding = next(
            item
            for item in self.analyzer.analyze_function(control_only)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("message_component=msg_control", control_finding.evidence)

        negative_name_length = function(
            Assignment(
                1,
                0x1004,
                self.message_field("message", "msg_name", 0),
                var("address"),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("message", "msg_namelen", 8),
                const(-1),
            ),
            Assignment(
                3,
                0x100C,
                self.message_field("message", "msg_control", 32),
                var("control"),
            ),
            Assignment(
                4,
                0x1010,
                self.message_field("message", "msg_controllen", 40),
                const(9),
            ),
            Call(
                5,
                0x1020,
                "sendmsg",
                (const(1), self.iovec_address("message"), const(0)),
            ),
            buffers=(
                BufferInfo("message", "message", "stack", 56),
                BufferInfo("address", "address", "stack", 16),
                BufferInfo("control", "control", "stack", 8),
            ),
        )
        self.assertNotIn("BUF-007", self.rule_ids(negative_name_length))

    def test_recvmsg_wrapper_preserves_internal_sink(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="receive_message",
            parameters=("message",),
            statements=[
                Call(
                    1,
                    0x2040,
                    "recvmsg",
                    (const(0), var("message"), const(0)),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="receive_record",
            buffers={
                "message": BufferInfo("message", "message", "stack", 56),
                "vector": BufferInfo("vector", "vector", "stack", 16),
                "destination": BufferInfo(
                    "destination", "destination", "stack", 8
                ),
            },
            statements=[
                Assignment(
                    1,
                    0x3010,
                    self.message_field("message", "msg_iov", 16),
                    self.iovec_address("vector"),
                ),
                Assignment(
                    2,
                    0x3014,
                    self.message_field("message", "msg_iovlen", 24),
                    const(1),
                ),
                Assignment(
                    3,
                    0x3018,
                    self.iovec_field("vector", "iov_base", 0),
                    var("destination"),
                ),
                Assignment(
                    4,
                    0x301C,
                    self.iovec_field("vector", "iov_len", 8),
                    const(9),
                ),
                Call(
                    5,
                    0x3020,
                    "receive_message",
                    (self.iovec_address("message"),),
                    callee_ea=wrapper.ea,
                ),
            ],
        )
        finding = next(
            item
            for item in Analyzer.analyze_program([wrapper, caller])
            if item.rule_id == "BUF-003"
        )
        self.assertEqual(finding.ea, 0x2040)
        self.assertEqual(finding.function_name, "receive_message")
        self.assertIn("wrapper=receive_message", finding.evidence)

    def test_sendmmsg_checks_second_message_and_caps_vlen(self):
        ir = function(
            Assignment(
                1,
                0x1004,
                self.message_field("messages", "msg_iov", 64 + 16),
                self.iovec_address("vector"),
            ),
            Assignment(
                2,
                0x1008,
                self.message_field("messages", "msg_iovlen", 64 + 24),
                const(1),
            ),
            Assignment(
                3,
                0x100C,
                self.iovec_field("vector", "iov_base", 0),
                var("source"),
            ),
            Assignment(
                4,
                0x1010,
                self.iovec_field("vector", "iov_len", 8),
                const(9),
            ),
            Call(
                5,
                0x1020,
                "sendmmsg",
                (const(1), self.iovec_address("messages"), const(2), const(0)),
            ),
            buffers=(
                BufferInfo("messages", "messages", "stack", 128),
                BufferInfo("vector", "vector", "stack", 16),
                BufferInfo("source", "source", "stack", 8),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertEqual(finding.callee, "sendmmsg")
        self.assertIn("message_index=1", finding.evidence)

        short_msg_len = function(
            Call(
                1,
                0x1020,
                "sendmmsg",
                (const(1), self.iovec_address("messages"), const(1), const(0)),
            ),
            buffers=(BufferInfo("messages", "messages", "stack", 56),),
        )
        short_findings = self.analyzer.analyze_function(short_msg_len)
        msg_len = next(
            item for item in short_findings if item.rule_id == "BUF-003"
        )
        self.assertIn("msg_len slot", msg_len.summary)
        self.assertFalse(
            any(item.rule_id == "BUF-007" for item in short_findings)
        )

        exact_msg_len = function(
            Call(
                1,
                0x1020,
                "sendmmsg",
                (const(1), self.iovec_address("messages"), const(1), const(0)),
            ),
            buffers=(BufferInfo("messages", "messages", "stack", 60),),
        )
        self.assertFalse(self.analyzer.analyze_function(exact_msg_len))

        capped = function(
            Call(
                1,
                0x1020,
                "sendmmsg",
                (
                    const(1),
                    self.iovec_address("messages"),
                    const(1025),
                    const(0),
                ),
            ),
            buffers=(BufferInfo("messages", "messages", "heap", 64),),
        )
        header = next(
            item
            for item in self.analyzer.analyze_function(capped)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("mmsghdr array", header.summary)
        self.assertIn("message_count=1024", header.evidence)

        uncapped_receive = function(
            Call(
                1,
                0x1030,
                "recvmmsg",
                (
                    const(0),
                    self.iovec_address("messages"),
                    const(1025),
                    const(0),
                    const(0),
                ),
            ),
            buffers=(BufferInfo("messages", "messages", "heap", 64),),
        )
        receive_header = next(
            item
            for item in self.analyzer.analyze_function(uncapped_receive)
            if item.rule_id == "BUF-007"
        )
        self.assertEqual(receive_header.callee, "recvmmsg")
        self.assertIn("message_count=1025", receive_header.evidence)

    def test_sendmsg_uses_32_bit_msghdr_layout(self):
        ir = function(
            Call(
                1,
                0x1010,
                "sendmsg",
                (const(1), self.iovec_address("message", bits=32), const(0)),
            ),
            buffers=(BufferInfo("message", "message", "stack", 24),),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("message_stride=28", finding.evidence)

    def test_memcmp_wrapper_exports_both_source_reads(self):
        comparer = FunctionIR(
            ea=0x2000,
            name="compare_bytes",
            parameters=("left", "right", "count"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "memcmp",
                    (var("left"), var("right"), var("count")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={
                "left": BufferInfo("left", "left", "stack", 16),
                "right": BufferInfo("right", "right", "stack", 8),
            },
            statements=[
                Call(
                    1,
                    0x3010,
                    "compare_bytes",
                    (var("left"), var("right"), const(16)),
                    callee_ea=comparer.ea,
                )
            ],
        )
        findings = Analyzer.analyze_program([comparer, caller])
        finding = next(item for item in findings if item.rule_id == "BUF-007")
        self.assertEqual(finding.function_name, "compare_bytes")
        self.assertIn("source=right", finding.evidence)
        self.assertIn("wrapper=compare_bytes", finding.evidence)

    def test_symbolic_memcmp_source_overread_is_proven(self):
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        ir = function(
            Assignment(1, 0x1010, var("left"), call_expr("malloc", size)),
            Call(
                2,
                0x1020,
                "memcmp",
                (var("left"), var("right"), enlarged),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-013"
        )
        self.assertIn("guaranteed_excess=1", finding.evidence)

    def test_tainted_signed_memcmp_length_is_reported(self):
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=32,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(
                2,
                0x1020,
                "memcmp",
                (var("left"), var("right"), count),
            ),
        )
        self.assertIn("INT-002", self.rule_ids(ir))

    def test_symbolic_output_api_overread_is_proven(self):
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Call(2, 0x1020, "write", (const(1), var("ptr"), enlarged)),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-013"
        )
        self.assertIn("guaranteed_excess=1", finding.evidence)

    def test_symbolic_fwrite_product_overread_is_proven(self):
        count = var("count")
        enlarged_count = Expr(
            kind="op",
            text="count + 1",
            op="add",
            children=(count, const(1)),
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                var("ptr"),
                call_expr("calloc", count, const(4)),
            ),
            Call(
                2,
                0x1020,
                "fwrite",
                (var("ptr"), const(4), enlarged_count, var("stream")),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-013"
        )
        self.assertIn("guaranteed_excess=4", finding.evidence)

    def test_symbolic_source_offset_is_included_in_overread(self):
        size = var("size")
        advanced = Expr(
            kind="op",
            text="ptr + 8",
            key="ptr",
            op="add",
            children=(var("ptr"), const(8)),
            offset=8,
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Call(2, 0x1020, "send", (const(3), advanced, size, const(0))),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-013"
        )
        self.assertIn("source_offset=8", finding.evidence)

    def test_exact_symbolic_output_bound_is_not_reported(self):
        size = var("size")
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Call(2, 0x1020, "write", (const(1), var("ptr"), size)),
        )
        self.assertNotIn("BUF-013", self.rule_ids(ir))

    def test_output_wrapper_exports_symbolic_source_read(self):
        emitter = FunctionIR(
            ea=0x2000,
            name="emit_bytes",
            parameters=("source", "count"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "write",
                    (const(1), var("source"), var("count")),
                )
            ],
        )
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            statements=[
                Assignment(
                    1,
                    0x3010,
                    var("ptr"),
                    call_expr("malloc", size),
                ),
                Call(
                    2,
                    0x3020,
                    "emit_bytes",
                    (var("ptr"), enlarged),
                    callee_ea=emitter.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([emitter, caller])
        finding = next(item for item in findings if item.rule_id == "BUF-013")
        self.assertEqual(finding.function_name, "emit_bytes")
        self.assertIn("wrapper=emit_bytes", finding.evidence)

    def test_dynamic_output_source_bound_above_capacity_is_reported(self):
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=64,
            signed=False,
        )
        upper = Expr(
            kind="op",
            text="count <= 48",
            op="ule",
            children=(count, const(48)),
        )
        ir = function(
            Call(
                1,
                0x1010,
                "write",
                (const(1), var("source"), count),
                guards=(upper,),
            ),
            buffers=(BufferInfo("source", "source", "stack", 24),),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertEqual(finding.confidence, "Medium")
        self.assertIn("visible_upper_bound=48", finding.evidence)

    def test_dynamic_fwrite_uses_guarded_byte_count_product(self):
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=64,
            signed=False,
        )
        upper = Expr(
            kind="op",
            text="count <= 16",
            op="ule",
            children=(count, const(16)),
        )
        ir = function(
            Call(
                1,
                0x1010,
                "fwrite",
                (var("source"), const(2), count, var("stream")),
                guards=(upper,),
            ),
            buffers=(BufferInfo("source", "source", "stack", 24),),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-007"
        )
        self.assertIn("visible_upper_bound=32", finding.evidence)

    def test_zero_sized_fwrite_is_safe_with_dynamic_count(self):
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=64,
            signed=False,
        )
        upper = Expr(
            kind="op",
            text="count <= 48",
            op="ule",
            children=(count, const(48)),
        )
        ir = function(
            Call(
                1,
                0x1010,
                "fwrite",
                (var("source"), const(0), count, var("stream")),
                guards=(upper,),
            ),
            buffers=(BufferInfo("source", "source", "stack", 1),),
        )
        self.assertNotIn("BUF-007", self.rule_ids(ir))

    def test_chunked_output_wrapper_exports_aggregate_source_read(self):
        done = var("done")
        chunk = var("chunk")
        total = var("total")
        source_at_done = Expr(
            kind="op",
            text="source + done",
            op="add",
            children=(var("source"), done),
        )
        remaining = Expr(
            kind="op",
            text="total - done",
            op="sub",
            children=(total, done),
        )
        advance = Expr(
            kind="op",
            text="done + chunk",
            op="add",
            children=(done, chunk),
        )
        loop_guard = Expr(
            kind="op",
            text="done < total",
            op="ult",
            children=(done, total),
        )
        emitter = FunctionIR(
            ea=0x2000,
            name="emit_chunks",
            parameters=("source", "total"),
            statements=[
                Assignment(1, 0x2010, done, const(0)),
                Assignment(2, 0x2020, chunk, remaining),
                Assignment(3, 0x2030, chunk, const(8)),
                Call(
                    4,
                    0x2040,
                    "write",
                    (const(1), source_at_done, chunk),
                    guards=(loop_guard,),
                ),
                Assignment(5, 0x2050, done, advance),
            ],
        )
        preview = Expr(
            kind="var",
            text="preview",
            key="preview",
            bits=64,
            signed=False,
        )
        preview_guard = Expr(
            kind="op",
            text="preview <= 48",
            op="ule",
            children=(preview, const(48)),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="preview_draft",
            buffers={
                "draft": BufferInfo("draft", "draft", "stack", 24),
            },
            statements=[
                Call(
                    1,
                    0x3010,
                    "emit_chunks",
                    (var("draft"), preview),
                    callee_ea=emitter.ea,
                    guards=(preview_guard,),
                )
            ],
        )
        summary = SummaryBuilder().build([emitter]).lookup(
            emitter.name, emitter.ea
        )
        self.assertIsNotNone(summary)
        self.assertEqual(len(summary.reads), 1)
        self.assertEqual(summary.reads[0].source.argument, 0)
        self.assertEqual(summary.reads[0].lengths[0].argument, 1)

        finding = next(
            item
            for item in Analyzer.analyze_program([emitter, caller])
            if item.rule_id == "BUF-007"
        )
        self.assertEqual(finding.function_name, emitter.name)
        self.assertEqual(finding.ea, 0x2040)
        self.assertIn("visible_upper_bound=48", finding.evidence)
        self.assertIn("wrapper=emit_chunks", finding.evidence)

    def test_chunked_output_wrapper_requires_matching_progress_advance(self):
        done = var("done")
        chunk = var("chunk")
        total = var("total")
        loop_guard = Expr(
            kind="op",
            text="done < total",
            op="ult",
            children=(done, total),
        )
        emitter = FunctionIR(
            ea=0x2000,
            name="nonaccumulating_emitter",
            parameters=("source", "total"),
            statements=[
                Assignment(1, 0x2010, done, const(0)),
                Assignment(
                    2,
                    0x2020,
                    chunk,
                    Expr(
                        kind="op",
                        text="total - done",
                        op="sub",
                        children=(total, done),
                    ),
                ),
                Call(
                    3,
                    0x2030,
                    "write",
                    (
                        const(1),
                        Expr(
                            kind="op",
                            text="source + done",
                            op="add",
                            children=(var("source"), done),
                        ),
                        chunk,
                    ),
                    guards=(loop_guard,),
                ),
                Assignment(
                    4,
                    0x2040,
                    done,
                    Expr(
                        kind="op",
                        text="done + 1",
                        op="add",
                        children=(done, const(1)),
                    ),
                ),
            ],
        )
        summary = SummaryBuilder().build([emitter]).lookup(
            emitter.name, emitter.ea
        )
        self.assertTrue(summary is None or not summary.reads)

    def test_output_wrapper_keeps_caller_cfg_for_symbolic_source(self):
        emitter = FunctionIR(
            ea=0x2000,
            name="emit_bytes",
            parameters=("source", "count"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "write",
                    (const(1), var("source"), var("count")),
                )
            ],
        )
        size = var("size")
        enlarged = Expr(
            kind="op",
            text="size + 1",
            op="add",
            children=(size, const(1)),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="conditional_caller",
            statements=[
                Assignment(
                    1,
                    0x3010,
                    var("ptr"),
                    call_expr("malloc", size),
                    block_id=1,
                ),
                Call(
                    2,
                    0x3040,
                    "emit_bytes",
                    (var("ptr"), enlarged),
                    callee_ea=emitter.ea,
                    block_id=3,
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x3000, 0x3010, successors=(1, 2)),
                1: BasicBlock(1, 0x3010, 0x3020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x3020, 0x3030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x3030, 0x3050, predecessors=(1, 2)),
            },
            entry_block=0,
        )
        self.assertNotIn(
            "BUF-013",
            [
                finding.rule_id
                for finding in Analyzer.analyze_program([emitter, caller])
            ],
        )

    def test_short_input_followed_by_fixed_output_reports_tail_disclosure(self):
        buffer = BufferInfo("buf", "buf", "stack", 32)
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(32))),
            Call(2, 0x1020, "write", (const(1), var("buf"), const(32))),
            buffers=(buffer,),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "INIT-002"
        )
        self.assertIn("input return value does not bound", finding.evidence)

    def test_malloc_short_input_tail_disclosure_is_reported(self):
        size = var("size")
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", size)),
            Call(2, 0x1020, "read", (const(0), var("ptr"), size)),
            Call(3, 0x1030, "send", (const(3), var("ptr"), size, const(0))),
        )
        self.assertIn("INIT-002", self.rule_ids(ir))

    def test_calloc_and_memset_preinitialization_suppress_tail_disclosure(self):
        stack = BufferInfo("buf", "buf", "stack", 32)
        calloc_ir = function(
            Assignment(
                1,
                0x1010,
                var("ptr"),
                call_expr("calloc", const(1), const(32)),
            ),
            Call(2, 0x1020, "read", (const(0), var("ptr"), const(32))),
            Call(3, 0x1030, "write", (const(1), var("ptr"), const(32))),
        )
        memset_ir = function(
            Call(
                1,
                0x1010,
                "memset",
                (var("buf"), const(0), const(32)),
            ),
            Call(2, 0x1020, "read", (const(0), var("buf"), const(32))),
            Call(3, 0x1030, "write", (const(1), var("buf"), const(32))),
            buffers=(stack,),
        )
        self.assertNotIn("INIT-002", self.rule_ids(calloc_ir))
        self.assertNotIn("INIT-002", self.rule_ids(memset_ir))

    def test_output_bounded_by_input_result_has_no_tail_disclosure(self):
        buffer = BufferInfo("buf", "buf", "stack", 32)
        received = Expr(
            kind="var", text="received", key="received", bits=64, signed=True
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                received,
                call_expr("read", const(0), var("buf"), const(32)),
            ),
            Call(
                2,
                0x1010,
                "read",
                (const(0), var("buf"), const(32)),
                text="read(...)",
            ),
            Call(3, 0x1020, "write", (const(1), var("buf"), received)),
            buffers=(buffer,),
        )
        self.assertNotIn("INIT-002", self.rule_ids(ir))

    def test_ignored_input_result_still_reports_fixed_output_tail(self):
        buffer = BufferInfo("buf", "buf", "stack", 32)
        received = Expr(
            kind="var", text="received", key="received", bits=64, signed=True
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                received,
                call_expr("read", const(0), var("buf"), const(32)),
            ),
            Call(
                2,
                0x1010,
                "read",
                (const(0), var("buf"), const(32)),
                text="read(...)",
            ),
            Call(3, 0x1020, "write", (const(1), var("buf"), const(32))),
            buffers=(buffer,),
        )
        self.assertIn("INIT-002", self.rule_ids(ir))

    def test_full_input_result_guard_suppresses_tail_disclosure(self):
        buffer = BufferInfo("buf", "buf", "stack", 32)
        received = Expr(
            kind="var", text="received", key="received", bits=64, signed=True
        )
        full = Expr(
            kind="op",
            text="received == 32",
            op="eq",
            children=(received, const(32)),
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                received,
                call_expr("read", const(0), var("buf"), const(32)),
            ),
            Call(
                2,
                0x1010,
                "read",
                (const(0), var("buf"), const(32)),
                text="read(...)",
            ),
            Call(
                3,
                0x1020,
                "write",
                (const(1), var("buf"), const(32)),
                guards=(full,),
            ),
            buffers=(buffer,),
        )
        self.assertNotIn("INIT-002", self.rule_ids(ir))

    def test_multiple_input_writes_are_not_modeled_as_one_short_tail(self):
        buffer = BufferInfo("buf", "buf", "stack", 32)
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("buf"), const(32))),
            Call(2, 0x1020, "read", (const(0), var("buf"), const(32))),
            Call(3, 0x1030, "write", (const(1), var("buf"), const(32))),
            buffers=(buffer,),
        )
        self.assertNotIn("INIT-002", self.rule_ids(ir))

    def test_prior_inline_buffer_store_suppresses_tail_disclosure(self):
        buffer = BufferInfo("buf", "buf", "stack", 32)
        first_byte = Expr(
            kind="deref",
            text="*buf",
            key="buf",
            children=(var("buf"),),
            bits=8,
        )
        ir = function(
            Assignment(1, 0x1008, first_byte, const(0)),
            Call(2, 0x1010, "read", (const(0), var("buf"), const(32))),
            Call(3, 0x1020, "write", (const(1), var("buf"), const(32))),
            buffers=(buffer,),
        )
        self.assertNotIn("INIT-002", self.rule_ids(ir))

    def test_output_wrapper_exports_short_input_tail_disclosure(self):
        emitter = FunctionIR(
            ea=0x2000,
            name="emit_bytes",
            parameters=("source", "count"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "write",
                    (const(1), var("source"), var("count")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={"buf": BufferInfo("buf", "buf", "stack", 32)},
            statements=[
                Call(1, 0x3010, "read", (const(0), var("buf"), const(32))),
                Call(
                    2,
                    0x3020,
                    "emit_bytes",
                    (var("buf"), const(32)),
                    callee_ea=emitter.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([emitter, caller])
        finding = next(item for item in findings if item.rule_id == "INIT-002")
        self.assertEqual(finding.function_name, "emit_bytes")
        self.assertIn("wrapper=emit_bytes", finding.evidence)

    def test_memcpy_checks_source_capacity(self):
        ir = function(
            Assignment(1, 0x1010, var("src"), call_expr("malloc", const(16))),
            Assignment(2, 0x1020, var("dst"), call_expr("malloc", const(64))),
            Call(3, 0x1030, "memcpy", (var("dst"), var("src"), const(32))),
        )
        self.assertIn("BUF-007", self.rule_ids(ir))

    def test_memcpy_source_read_summary_survives_unknown_destination(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="store_message",
            parameters=("src", "count"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "memcpy",
                    (Expr(kind="deref", text="slots[i]"), var("src"), var("count")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            statements=[
                Assignment(1, 0x3010, var("src"), call_expr("malloc", const(16))),
                Call(
                    2,
                    0x3020,
                    "store_message",
                    (var("src"), const(32)),
                    callee_ea=wrapper.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(item for item in findings if item.rule_id == "BUF-007")
        self.assertEqual(finding.ea, 0x2010)
        self.assertEqual(finding.function_name, "store_message")

    def test_sibling_named_fields_flag_structured_copy_mismatch(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="store_message",
            parameters=("count", "src"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "memcpy",
                    (Expr(kind="deref", text="slots[i]"), var("src"), var("count")),
                )
            ],
        )
        message_node = Expr(kind="var", text="message_node", key="message_node")
        length_node = Expr(kind="var", text="length_node", key="length_node")
        source = Expr(kind="var", text="source", key="source", bits=64, signed=False)
        length = Expr(kind="var", text="length", key="length", bits=32, signed=True)
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            statements=[
                Assignment(
                    1,
                    0x3010,
                    message_node,
                    call_expr("lookup", var("root"), string("message")),
                ),
                Assignment(
                    2,
                    0x3020,
                    length_node,
                    call_expr("lookup", var("root"), string("length")),
                ),
                Assignment(
                    3,
                    0x3030,
                    source,
                    Expr(
                        kind="deref",
                        text="message_node->value",
                        children=(message_node,),
                        bits=64,
                        signed=False,
                    ),
                ),
                Assignment(
                    4,
                    0x3040,
                    length,
                    Expr(
                        kind="deref",
                        text="length_node->valueint",
                        children=(length_node,),
                        bits=32,
                        signed=True,
                    ),
                ),
                Call(
                    5,
                    0x3050,
                    "store_message",
                    (length, source),
                    callee_ea=wrapper.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(item for item in findings if item.rule_id == "BUF-009")
        self.assertEqual(finding.ea, 0x2010)
        self.assertEqual(finding.function_name, "store_message")

    def test_full_recv_then_strcmp_may_be_unterminated(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=False)
        ir = function(
            Call(1, 0x1010, "read", (const(0), size, const(4))),
            Assignment(2, 0x1020, var("ptr"), call_expr("malloc", size)),
            Call(3, 0x1030, "recv", (const(3), var("ptr"), size, const(0))),
            Call(4, 0x1040, "strcmp", (var("ptr"), string("admin"))),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_explicit_nul_after_full_recv_proves_termination(self):
        byte = Expr(
            kind="index",
            text="ptr[15]",
            key="ptr",
            children=(var("ptr"), const(15)),
            offset=15,
            bits=8,
            signed=False,
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(16))),
            Call(2, 0x1020, "recv", (const(3), var("ptr"), const(16), const(0))),
            Assignment(3, 0x1030, byte, const(0)),
            Call(4, 0x1040, "strcmp", (var("ptr"), string("admin"))),
        )
        self.assertNotIn("STR-001", self.rule_ids(ir))

    def test_calloc_tail_zero_survives_short_read(self):
        safe = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("calloc", const(1), const(16))),
            Call(2, 0x1020, "recv", (const(3), var("ptr"), const(15), const(0))),
            Call(3, 0x1030, "strlen", (var("ptr"),)),
        )
        full = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("calloc", const(1), const(16))),
            Call(2, 0x1020, "recv", (const(3), var("ptr"), const(16), const(0))),
            Call(3, 0x1030, "strlen", (var("ptr"),)),
        )
        self.assertNotIn("STR-001", self.rule_ids(safe))
        self.assertIn("STR-001", self.rule_ids(full))

    def test_iconv_output_is_not_assumed_terminated(self):
        out_pointer = Expr(kind="address", text="&cursor", key="cursor")
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(64))),
            Assignment(2, 0x1020, var("cursor"), var("ptr")),
            Call(
                3,
                0x1030,
                "iconv",
                (var("cd"), var("input"), var("inleft"), out_pointer, var("outleft")),
            ),
            Call(4, 0x1040, "strlen", (var("ptr"),)),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_cstring_consumer_summary_keeps_internal_sink_address(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="authenticate",
            parameters=("data",),
            statements=[Call(1, 0x2040, "strcmp", (var("data"), string("admin")))],
        )
        size = Expr(kind="var", text="size", key="size", bits=32, signed=False)
        caller = FunctionIR(
            ea=0x3000,
            name="receive_request",
            statements=[
                Call(1, 0x3010, "read", (const(0), size, const(4))),
                Assignment(2, 0x3020, var("ptr"), call_expr("malloc", size)),
                Call(3, 0x3030, "recv", (const(3), var("ptr"), size, const(0))),
                Call(4, 0x3040, "authenticate", (var("ptr"),), callee_ea=wrapper.ea),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(item for item in findings if item.rule_id == "STR-001")
        self.assertEqual(finding.ea, 0x2040)
        self.assertEqual(finding.function_name, "authenticate")

    def test_strncpy_requires_a_later_explicit_terminator(self):
        destination = BufferInfo("path", "path", "stack", 32)
        terminator = Expr(
            kind="index",
            text="path[31]",
            key="path",
            children=(var("path"), const(31)),
            offset=31,
            bits=8,
            signed=False,
        )
        unsafe = function(
            Call(1, 0x1010, "strncpy", (var("path"), var("input"), var("count"))),
            Call(2, 0x1020, "fopen", (var("path"), string("rb"))),
            buffers=(destination,),
        )
        safe = function(
            Call(1, 0x1010, "strncpy", (var("path"), var("input"), var("count"))),
            Assignment(2, 0x1018, terminator, const(0)),
            Call(3, 0x1020, "fopen", (var("path"), string("rb"))),
            buffers=(destination,),
        )
        self.assertIn("STR-001", self.rule_ids(unsafe))
        self.assertNotIn("STR-001", self.rule_ids(safe))

    def test_two_stage_inline_window_recv_is_reported(self):
        owner = var("connection")

        def slot(index: int, pointer: bool = False) -> Expr:
            return Expr(
                kind="index",
                text=f"connection[{index}]",
                key=None if pointer else "connection",
                children=(owner, const(index)),
                offset=index * 4,
                bits=64 if pointer else 32,
                signed=False,
            )

        header_used = slot(2)
        content_length = slot(3)
        body_received = slot(4)
        body_pointer = slot(5, pointer=True)
        header_base = Expr(
            kind="op",
            text="connection + 28",
            key="connection",
            op="add",
            children=(owner, const(28)),
            offset=28,
        )
        first_destination = Expr(
            kind="op",
            text="connection + header_used + 28",
            op="add",
            children=(owner, header_used, const(28)),
        )
        first_length = Expr(
            kind="op",
            text="4096 - header_used",
            op="sub",
            children=(const(4096), header_used),
        )
        second_destination = Expr(
            kind="op",
            text="body_pointer + body_received",
            op="add",
            children=(body_pointer, body_received),
        )
        second_length = Expr(
            kind="op",
            text="content_length - body_received",
            op="sub",
            children=(content_length, body_received),
            bits=32,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "recv", (const(3), first_destination, first_length, const(0))),
            Assignment(
                2,
                0x1020,
                var("cursor"),
                call_expr("strstr", header_base, string("\\r\\n\\r\\n")),
            ),
            Assignment(3, 0x1030, body_pointer, var("cursor")),
            Assignment(4, 0x1040, var("parsed"), call_expr("parse_length", owner)),
            Assignment(5, 0x1050, content_length, var("parsed")),
            Call(6, 0x1060, "recv", (const(3), second_destination, second_length, const(0))),
        )
        findings = [
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-008"
        ]
        self.assertEqual([item.ea for item in findings], [0x1060])
        self.assertFalse(
            any(
                item.rule_id == "INT-002" and item.ea == 0x1060
                for item in self.analyzer.analyze_function(ir)
            )
        )

    def test_inline_window_capacity_guard_requires_the_sink_path(self):
        owner = var("connection")
        total_expr = Expr(
            kind="index",
            text="connection[3]",
            key="connection",
            children=(owner, const(3)),
            offset=12,
            bits=32,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="connection[3] <= 4096",
            op="ule",
            children=(total_expr, const(4096)),
        )
        sink = Call(
            2,
            0x1020,
            "recv",
            (var("fd"), var("destination"), total_expr, const(0)),
            block_id=1,
            guards=(guard,),
        )
        guarded = FunctionIR(
            ea=0x1000,
            name="guarded_inline_window",
            statements=[sink],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text, order=1)],
        )
        merged_sink = replace(sink, block_id=3, guards=())
        merged = FunctionIR(
            ea=0x2000,
            name="merged_inline_window",
            statements=[merged_sink],
            blocks={
                0: BasicBlock(0, 0x2000, 0x2010, successors=(1, 2)),
                1: BasicBlock(1, 0x2010, 0x2020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x2020, 0x2030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x2030, 0x2050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x2008, 0, guard, guard.text, order=1)],
        )
        total = ("connection", 12)
        self.assertTrue(
            self.analyzer._total_has_capacity_guard(guarded, sink, total, 4096)
        )
        self.assertFalse(
            self.analyzer._total_has_capacity_guard(
                merged, merged_sink, total, 4096
            )
        )

    def test_remaining_capacity_recv_is_not_a_protocol_window_overflow(self):
        used = var("used")
        destination = Expr(
            kind="op",
            text="buf + used",
            key="buf",
            op="add",
            children=(var("buf"), used),
        )
        remaining = Expr(
            kind="op",
            text="64 - used",
            op="sub",
            children=(const(64), used),
        )
        ir = function(
            Call(1, 0x1010, "recv", (const(3), destination, remaining, const(0))),
            buffers=(BufferInfo("buf", "buf", "stack", 64),),
        )
        self.assertNotIn("BUF-008", self.rule_ids(ir))

    def test_casted_heap_allocation_size_is_tracked(self):
        allocation = Expr(
            kind="cast",
            text="(char *)malloc(16)",
            children=(call_expr("malloc", const(16)),),
            bits=64,
            signed=False,
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), allocation),
            Call(2, 0x1020, "memcpy", (var("ptr"), var("src"), const(64))),
        )
        self.assertIn("BUF-003", self.rule_ids(ir))

    def test_mmap_page_capacity_is_tracked_as_mapped_storage(self):
        allocation = call_expr(
            "mmap",
            const(0),
            const(4096),
            const(3),
            const(0x22),
            const(-1),
            const(0),
        )
        ir = function(
            Assignment(1, 0x1010, var("mapping"), allocation),
            Call(2, 0x1020, "read", (const(0), var("mapping"), const(8192))),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "BUF-003"
        )
        self.assertEqual(finding.category, "Mapped buffer overflow")

    def test_mmap_capacity_is_rounded_to_a_page(self):
        allocation = call_expr(
            "mmap",
            const(0),
            const(256),
            const(3),
            const(0x22),
            const(-1),
            const(0),
        )
        ir = function(
            Assignment(1, 0x1010, var("mapping"), allocation),
            Call(2, 0x1020, "read", (const(0), var("mapping"), const(512))),
        )
        self.assertNotIn("BUF-003", self.rule_ids(ir))

    def test_anonymous_mmap_length_validator_excludes_crash_only_path(self):
        allocation = call_expr(
            "mmap",
            const(0),
            const(4096),
            const(7),
            const(0x22),
            const(-1),
            const(0),
        )
        raw_read = call_expr("read", const(0), var("mapping"), const(4096))
        scan = call_expr("strlen", var("mapping"))
        acceptance = Expr(
            kind="op",
            op="logical_and",
            children=(
                Expr(
                    kind="op",
                    op="ule",
                    children=(var("received"), const(135)),
                ),
                Expr(
                    kind="op",
                    op="eq",
                    children=(var("received"), var("length")),
                ),
            ),
        )
        ir = function(
            Assignment(1, 0x1010, var("mapping"), allocation),
            Assignment(2, 0x1020, var("received"), raw_read),
            Call(3, 0x1020, "read", raw_read.children),
            Assignment(4, 0x1030, var("length"), scan),
            Call(5, 0x1030, "strlen", scan.children),
            Call(
                6,
                0x1040,
                "mprotect",
                (var("mapping"), const(4096), const(5)),
                guards=(acceptance,),
            ),
        )
        self.assertNotIn("STR-001", self.rule_ids(ir))

    def test_full_anonymous_mmap_read_without_acceptance_is_unterminated(self):
        allocation = call_expr(
            "mmap",
            const(0),
            const(4096),
            const(3),
            const(0x22),
            const(-1),
            const(0),
        )
        ir = function(
            Assignment(1, 0x1010, var("mapping"), allocation),
            Call(2, 0x1020, "read", (const(0), var("mapping"), const(4096))),
            Call(3, 0x1030, "strlen", (var("mapping"),)),
        )
        self.assertIn("STR-001", self.rule_ids(ir))

    def test_global_heap_capacity_flows_across_functions(self):
        global_slot = Expr(kind="global", text="items", key="g:items")
        setup = FunctionIR(
            ea=0x1000,
            name="setup",
            statements=[
                Assignment(1, 0x1010, global_slot, call_expr("malloc", const(16)))
            ],
        )
        use = FunctionIR(
            ea=0x2000,
            name="edit",
            statements=[
                Call(1, 0x2010, "memcpy", (global_slot, var("src"), const(64)))
            ],
        )
        findings = Analyzer.analyze_program([setup, use])
        self.assertTrue(
            any(
                finding.rule_id == "BUF-003" and finding.function_name == "edit"
                for finding in findings
            )
        )

    def test_recorded_allocation_size_increment_is_reported(self):
        table = Expr(kind="global", text="records", key="g:records")
        index = var("index")
        record_base = var("record_base")
        record_address = Expr(
            kind="address",
            text="&records[index]",
            children=(
                Expr(
                    kind="index",
                    text="records[index]",
                    children=(table, index),
                ),
            ),
        )
        size_field = Expr(
            kind="deref",
            text="record_base->size",
            key="record_base",
            children=(record_base,),
            bits=32,
        )
        pointer_field = Expr(
            kind="deref",
            text="record_base->pointer",
            key="record_base",
            children=(record_base,),
            offset=8,
            bits=64,
        )
        setup = FunctionIR(
            ea=0x1000,
            name="create",
            statements=[
                Assignment(1, 0x1010, record_base, record_address),
                Assignment(2, 0x1020, size_field, var("requested")),
                Assignment(
                    3,
                    0x1030,
                    pointer_field,
                    call_expr("malloc", var("requested")),
                ),
            ],
        )
        selected_pointer = Expr(
            kind="deref",
            text="records[index].pointer",
            children=(table, index),
            bits=64,
        )
        selected_size = Expr(
            kind="deref",
            text="records[index].size",
            children=(table, index),
            bits=32,
        )
        enlarged_size = Expr(
            kind="op",
            text="records[index].size + 64",
            op="add",
            children=(selected_size, const(64)),
        )
        edit = FunctionIR(
            ea=0x2000,
            name="edit",
            statements=[
                Call(
                    1,
                    0x2010,
                    "read",
                    (const(0), selected_pointer, enlarged_size),
                )
            ],
        )
        findings = Analyzer.analyze_program([setup, edit])
        overflow = next(item for item in findings if item.rule_id == "BUF-010")
        self.assertEqual(overflow.function_name, "edit")
        self.assertIn("positive_increment=64", overflow.evidence)

    def test_unrelated_record_size_and_allocation_do_not_form_capacity(self):
        table = Expr(kind="global", text="records", key="g:records")
        record_base = var("record_base")
        setup = FunctionIR(
            ea=0x1000,
            name="create",
            statements=[
                Assignment(
                    1,
                    0x1010,
                    record_base,
                    Expr(kind="address", children=(table,)),
                ),
                Assignment(
                    2,
                    0x1020,
                    Expr(kind="deref", key="record_base", children=(record_base,)),
                    var("advertised"),
                ),
                Assignment(
                    3,
                    0x1030,
                    Expr(
                        kind="deref",
                        key="record_base",
                        children=(record_base,),
                        offset=8,
                    ),
                    call_expr("malloc", var("actual")),
                ),
            ],
        )
        selected_pointer = Expr(
            kind="deref", children=(table, var("index")), bits=64
        )
        selected_size = Expr(
            kind="deref", children=(table, var("index")), bits=32
        )
        edit = FunctionIR(
            ea=0x2000,
            name="edit",
            statements=[
                Call(
                    1,
                    0x2010,
                    "read",
                    (
                        const(0),
                        selected_pointer,
                        Expr(
                            kind="op",
                            op="add",
                            children=(selected_size, const(64)),
                        ),
                    ),
                )
            ],
        )
        self.assertNotIn(
            "BUF-010",
            {item.rule_id for item in Analyzer.analyze_program([setup, edit])},
        )

    def test_conflicting_allocation_sizes_become_unknown(self):
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(16))),
            Assignment(2, 0x1020, var("ptr"), call_expr("malloc", const(64))),
            Call(3, 0x1030, "memcpy", (var("ptr"), var("src"), const(32))),
        )
        self.assertNotIn("BUF-003", self.rule_ids(ir))

    def test_scanf_width_accounts_for_null_terminator(self):
        unsafe = function(
            Call(1, 0x1010, "scanf", (string("%32s"), var("buf"))),
            buffers=(self.stack32,),
        )
        safe = function(
            Call(1, 0x1010, "scanf", (string("%31s"), var("buf"))),
            buffers=(self.stack32,),
        )
        self.assertIn("BUF-005", self.rule_ids(unsafe))
        self.assertNotIn("BUF-005", self.rule_ids(safe))

    def test_physical_stack_span_disproves_split_lvar_scanf_overflow(self):
        split = BufferInfo(
            "buf",
            "buf",
            "stack",
            16,
            physical_capacity=4104,
        )
        ir = function(
            Call(1, 0x1010, "scanf", (string("%4095s"), var("buf"))),
            buffers=(split,),
        )
        self.assertNotIn("BUF-005", self.rule_ids(ir))

    def test_imprecise_stack_buffer_still_reports_unbounded_scanf(self):
        fragment = BufferInfo("buf", "buf", "stack", 16, precise=False)
        ir = function(
            Call(1, 0x1010, "scanf", (string("%s"), var("buf"))),
            buffers=(fragment,),
        )
        self.assertIn("BUF-005", self.rule_ids(ir))

    def test_scanf_tracks_non_string_output_arguments(self):
        ir = function(
            Call(
                1,
                0x1010,
                "scanf",
                (string("%d %32s"), var("number"), var("buf")),
            ),
            buffers=(self.stack32,),
        )
        self.assertIn("BUF-005", self.rule_ids(ir))

    def test_use_after_free(self):
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(32))),
            Call(2, 0x1020, "free", (var("ptr"),)),
            Call(3, 0x1030, "puts", (var("ptr"),)),
        )
        self.assertIn("LIFE-002", self.rule_ids(ir))

    def test_double_free(self):
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(32))),
            Call(2, 0x1020, "free", (var("ptr"),)),
            Call(3, 0x1030, "free", (var("ptr"),)),
        )
        self.assertIn("LIFE-001", self.rule_ids(ir))

    def test_alias_use_after_free(self):
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(32))),
            Assignment(2, 0x1020, var("alias"), var("ptr")),
            Call(3, 0x1030, "free", (var("ptr"),)),
            Call(4, 0x1040, "puts", (var("alias"),)),
        )
        self.assertIn("LIFE-002", self.rule_ids(ir))

    def test_indirect_call_target_uses_freed_object(self):
        callback = Expr(
            kind="member",
            text="ptr->callback",
            children=(var("ptr"),),
            offset=40,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="invoke_after_free",
            statements=[
                Assignment(
                    1,
                    0x1004,
                    var("ptr"),
                    call_expr("malloc", const(64)),
                    block_id=0,
                ),
                Call(2, 0x1010, "free", (var("ptr"),), block_id=0),
                Call(
                    3,
                    0x1020,
                    "indirect_call",
                    (),
                    block_id=0,
                    target=callback,
                ),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1030)},
            entry_block=0,
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "LIFE-002"
        )
        self.assertEqual(0x1020, finding.ea)
        self.assertIn("indirect_call", finding.summary)

    def test_copying_dangling_pointer_is_not_a_dereference(self):
        ir = function(
            Assignment(1, 0x1010, var("ptr"), call_expr("malloc", const(32))),
            Call(2, 0x1020, "free", (var("ptr"),)),
            Assignment(3, 0x1030, var("alias"), var("ptr")),
        )
        self.assertNotIn("LIFE-002", self.rule_ids(ir))

    def test_raw_free_bypassing_refcount_guard(self):
        owner = var("owner")
        loaded_value = Expr(
            kind="deref",
            text="owner->value",
            children=(owner,),
        )
        pointee = Expr(
            kind="deref",
            text="*ptr",
            key="ptr",
            children=(var("ptr"),),
        )
        decrement = Expr(
            kind="op",
            text="--*ptr",
            op="predec",
            children=(pointee,),
        )
        guard = Expr(
            kind="op",
            text="--*ptr <= 0",
            op="sle",
            children=(decrement, const(0)),
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), loaded_value),
            Call(2, 0x1020, "free", (var("ptr"),)),
            Call(3, 0x1030, "free", (var("ptr"),), guards=(guard,)),
        )
        findings = self.analyzer.analyze_function(ir)
        bypass = next(item for item in findings if item.rule_id == "LIFE-006")
        self.assertEqual(bypass.ea, 0x1020)
        self.assertIn("0x1030", bypass.evidence)

    def test_disjunctive_refcount_guard_is_not_treated_as_protocol(self):
        loaded_value = Expr(
            kind="deref",
            text="owner->value",
            children=(var("owner"),),
        )
        pointee = Expr(
            kind="deref", text="*ptr", key="ptr", children=(var("ptr"),)
        )
        decrement_guard = Expr(
            kind="op",
            text="--*ptr <= 0",
            op="sle",
            children=(
                Expr(kind="op", op="predec", children=(pointee,)),
                const(0),
            ),
        )
        disjunctive_guard = Expr(
            kind="op",
            text="force || --*ptr <= 0",
            op="logical_or",
            children=(var("force"), decrement_guard),
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), loaded_value),
            Call(2, 0x1020, "free", (var("ptr"),)),
            Call(
                3,
                0x1030,
                "free",
                (var("ptr"),),
                guards=(disjunctive_guard,),
            ),
        )
        self.assertNotIn("LIFE-006", self.rule_ids(ir))

    def test_consistently_refcounted_releases_are_not_reported(self):
        loaded_value = Expr(
            kind="deref",
            text="owner->value",
            children=(var("owner"),),
        )
        pointee = Expr(
            kind="deref", text="*ptr", key="ptr", children=(var("ptr"),)
        )
        guard = Expr(
            kind="op",
            text="--*ptr == 0",
            op="eq",
            children=(
                Expr(kind="op", op="predec", children=(pointee,)),
                const(0),
            ),
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), loaded_value),
            Call(2, 0x1020, "free", (var("ptr"),), guards=(guard,)),
            Call(3, 0x1030, "free", (var("ptr"),), guards=(guard,)),
        )
        self.assertNotIn("LIFE-006", self.rule_ids(ir))

    def test_refcount_rule_does_not_merge_separate_pointer_loads(self):
        loaded_value = Expr(
            kind="deref",
            text="owner->value",
            children=(var("owner"),),
        )
        pointee = Expr(
            kind="deref", text="*ptr", key="ptr", children=(var("ptr"),)
        )
        guard = Expr(
            kind="op",
            op="eq",
            children=(
                Expr(kind="op", op="predec", children=(pointee,)),
                const(0),
            ),
        )
        ir = function(
            Assignment(1, 0x1010, var("ptr"), loaded_value),
            Call(2, 0x1020, "free", (var("ptr"),)),
            Assignment(3, 0x1030, var("ptr"), loaded_value),
            Call(4, 0x1040, "free", (var("ptr"),), guards=(guard,)),
        )
        self.assertNotIn("LIFE-006", self.rule_ids(ir))

    def test_bounded_write_wrapper_is_propagated(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="read_into",
            parameters=("dst", "count"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "read",
                    (const(0), var("dst"), var("count")),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    1,
                    0x3010,
                    "read_into",
                    (var("buf"), const(128)),
                    callee_ea=wrapper.ea,
                )
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        overflow = next(item for item in findings if item.rule_id == "BUF-003")
        self.assertEqual(overflow.function_name, "caller")
        self.assertIn("via read_into", overflow.summary)

    def test_nested_write_wrappers_reach_fixed_point(self):
        first = FunctionIR(
            ea=0x2000,
            name="first",
            parameters=("dst", "count"),
            statements=[
                Call(1, 0x2010, "read", (const(0), var("dst"), var("count")))
            ],
        )
        second = FunctionIR(
            ea=0x2100,
            name="second",
            parameters=("dst", "count"),
            statements=[
                Call(
                    1,
                    0x2110,
                    "first",
                    (var("dst"), var("count")),
                    callee_ea=first.ea,
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    1,
                    0x3010,
                    "second",
                    (var("buf"), const(64)),
                    callee_ea=second.ea,
                )
            ],
        )
        findings = Analyzer.analyze_program([first, second, caller])
        self.assertTrue(
            any(
                item.rule_id == "BUF-003" and item.function_name == "caller"
                for item in findings
            )
        )

    def test_inline_output_parameter_taint_reaches_nested_parser_caller(self):
        byte = Expr(kind="var", text="byte", key="byte", bits=8, signed=True)
        reader = FunctionIR(
            ea=0x2000,
            name="read_bytewise",
            parameters=("destination",),
            statements=[
                Call(1, 0x2010, "read", (const(0), byte, const(1))),
                Assignment(
                    2,
                    0x2020,
                    Expr(
                        kind="deref",
                        text="*destination",
                        key="destination",
                        children=(var("destination"),),
                        bits=8,
                    ),
                    byte,
                ),
            ],
        )
        parsed = Expr(
            kind="var", text="parsed", key="parsed", bits=32, signed=True
        )
        parser = FunctionIR(
            ea=0x2100,
            name="parse_decimal",
            parameters=("source", "output"),
            statements=[
                Assignment(
                    1,
                    0x2110,
                    parsed,
                    Expr(
                        kind="deref",
                        text="*source",
                        children=(var("source"),),
                        bits=8,
                        signed=True,
                    ),
                ),
                Assignment(
                    2,
                    0x2120,
                    Expr(
                        kind="deref",
                        text="*output",
                        key="output",
                        children=(var("output"),),
                        bits=32,
                        signed=True,
                    ),
                    parsed,
                ),
            ],
        )
        input_integer = FunctionIR(
            ea=0x2200,
            name="input_integer",
            parameters=("output",),
            statements=[
                Call(
                    1,
                    0x2210,
                    "read_bytewise",
                    (var("buffer"),),
                    callee_ea=reader.ea,
                ),
                Call(
                    2,
                    0x2220,
                    "parse_decimal",
                    (var("buffer"), var("output")),
                    callee_ea=parser.ea,
                ),
            ],
        )
        wide = Expr(kind="var", text="wide", key="wide", bits=32, signed=True)
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=8, signed=False
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    "input_integer",
                    (wide,),
                    callee_ea=input_integer.ea,
                ),
                Assignment(2, 0x3020, narrow, wide),
            ],
        )
        findings = Analyzer.analyze_program(
            [reader, parser, input_integer, caller]
        )
        self.assertTrue(
            any(
                item.rule_id == "INT-001" and item.function_name == "caller"
                for item in findings
            )
        )

    def test_conditional_output_taint_does_not_make_trusted_source_external(self):
        parsed = Expr(
            kind="var", text="parsed", key="parsed", bits=32, signed=True
        )
        parser = FunctionIR(
            ea=0x2100,
            name="parse_value",
            parameters=("source", "output"),
            statements=[
                Assignment(
                    1,
                    0x2110,
                    parsed,
                    Expr(
                        kind="deref",
                        text="*source",
                        children=(var("source"),),
                        bits=8,
                        signed=True,
                    ),
                ),
                Assignment(
                    2,
                    0x2120,
                    Expr(
                        kind="deref",
                        text="*output",
                        key="output",
                        children=(var("output"),),
                        bits=32,
                        signed=True,
                    ),
                    parsed,
                ),
            ],
        )
        wide = Expr(kind="var", text="wide", key="wide", bits=32, signed=True)
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=8, signed=False
        )
        caller = FunctionIR(
            ea=0x3000,
            name="trusted_caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    "parse_value",
                    (var("literal_data"), wide),
                    callee_ea=parser.ea,
                ),
                Assignment(2, 0x3020, narrow, wide),
            ],
        )
        findings = Analyzer.analyze_program([parser, caller])
        self.assertFalse(
            any(item.rule_id.startswith("INT-") for item in findings)
        )

    def test_fixed_proc_metadata_read_does_not_taint_wrapper_output(self):
        scratch = Expr(
            kind="var", text="scratch", key="scratch", bits=32, signed=True
        )
        parsed = Expr(
            kind="var", text="parsed", key="parsed", bits=32, signed=True
        )
        reader = FunctionIR(
            ea=0x2200,
            name="file_reader",
            parameters=("handle", "output"),
            statements=[
                Call(
                    1,
                    0x2210,
                    "read",
                    (var("handle"), scratch, const(4)),
                ),
                Assignment(2, 0x2220, parsed, scratch),
                Assignment(
                    3,
                    0x2230,
                    Expr(
                        kind="deref",
                        text="*output",
                        key="output",
                        children=(var("output"),),
                        bits=32,
                        signed=True,
                    ),
                    parsed,
                ),
            ],
        )
        wide = Expr(kind="var", text="wide", key="wide", bits=32, signed=True)
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=8, signed=False
        )
        caller = FunctionIR(
            ea=0x3000,
            name="runtime_metadata",
            statements=[
                Call(
                    1,
                    0x3010,
                    "strcpy",
                    (var("file_object"), string("/proc/self/maps")),
                ),
                Call(
                    2,
                    0x3020,
                    "file_reader",
                    (var("file_object"), wide),
                    callee_ea=reader.ea,
                ),
                Assignment(3, 0x3030, narrow, wide),
            ],
        )
        findings = Analyzer.analyze_program([reader, caller])
        self.assertFalse(
            any(item.rule_id.startswith("INT-") for item in findings)
        )

    def test_unknown_file_read_still_taints_wrapper_output(self):
        scratch = Expr(
            kind="var", text="scratch", key="scratch", bits=32, signed=True
        )
        reader = FunctionIR(
            ea=0x2200,
            name="file_reader",
            parameters=("handle", "output"),
            statements=[
                Call(
                    1,
                    0x2210,
                    "read",
                    (var("handle"), scratch, const(4)),
                ),
                Assignment(
                    2,
                    0x2220,
                    Expr(
                        kind="deref",
                        text="*output",
                        key="output",
                        children=(var("output"),),
                        bits=32,
                        signed=True,
                    ),
                    scratch,
                ),
            ],
        )
        wide = Expr(kind="var", text="wide", key="wide", bits=32, signed=True)
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=8, signed=False
        )
        caller = FunctionIR(
            ea=0x3000,
            name="unknown_file",
            statements=[
                Call(
                    1,
                    0x3010,
                    "file_reader",
                    (var("file_object"), wide),
                    callee_ea=reader.ea,
                ),
                Assignment(2, 0x3020, narrow, wide),
            ],
        )
        findings = Analyzer.analyze_program([reader, caller])
        self.assertTrue(
            any(
                item.rule_id == "INT-001" and item.function_name == "unknown_file"
                for item in findings
            )
        )

    def test_looping_read_wrapper_preserves_total_length_and_call_guard(self):
        progress = var("progress")
        destination = Expr(
            kind="op",
            text="destination + progress",
            op="add",
            children=(var("destination"), progress),
        )
        remaining = Expr(
            kind="op",
            text="count - progress",
            op="sub",
            children=(var("count"), progress),
        )
        wrapper = FunctionIR(
            ea=0x2200,
            name="read_exact",
            parameters=("destination", "count"),
            statements=[
                Assignment(1, 0x2210, progress, const(0)),
                Call(2, 0x2220, "read", (const(0), destination, remaining)),
            ],
        )
        upper_guard = Expr(
            kind="op",
            text="input_count <= 232",
            op="ule",
            children=(var("input_count"), const(232)),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    1,
                    0x3010,
                    "read_exact",
                    (var("buf"), var("input_count")),
                    callee_ea=wrapper.ea,
                    guards=(upper_guard,),
                )
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        overflow = next(
            item
            for item in findings
            if item.rule_id == "BUF-004" and item.function_name == "caller"
        )
        self.assertIn("via read_exact", overflow.summary)
        self.assertIn("visible_upper_bound=232", overflow.evidence)

    def test_wrapper_preserves_constant_destination_offset(self):
        wrapper = FunctionIR(
            ea=0x2200,
            name="read_tail",
            parameters=("destination",),
            statements=[
                Call(
                    1,
                    0x2220,
                    "read",
                    (const(0), pointer_offset("destination", 24), const(16)),
                )
            ],
        )

        def caller(ea: int, capacity: int) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=f"caller_{capacity}",
                buffers={
                    "buffer": BufferInfo(
                        "buffer", "buffer", "stack", capacity
                    )
                },
                statements=[
                    Call(
                        1,
                        ea + 0x10,
                        "read_tail",
                        (var("buffer"),),
                        callee_ea=wrapper.ea,
                    )
                ],
            )

        unsafe = caller(0x3000, 32)
        safe = caller(0x4000, 40)
        summary = SummaryBuilder().build([wrapper]).lookup(
            wrapper.name, wrapper.ea
        )
        self.assertIsNotNone(summary)
        self.assertEqual(summary.writes[0].destination.argument, 0)
        self.assertEqual(summary.writes[0].destination.offset, 24)

        findings = Analyzer.analyze_program([wrapper, unsafe, safe])
        overflow = next(
            item
            for item in findings
            if item.rule_id == "BUF-003"
            and item.function_name == unsafe.name
        )
        self.assertIn("available_capacity=8", overflow.evidence)
        self.assertIn("via read_tail", overflow.summary)
        self.assertFalse(
            any(
                item.rule_id in {"BUF-003", "BUF-004"}
                and item.function_name == safe.name
                for item in findings
            )
        )

    def test_scalar_addition_is_exported_without_pointer_offset(self):
        size = Expr(
            kind="var",
            text="size",
            key="size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        enlarged = Expr(
            kind="op",
            text="size + 16",
            # Retain a base key to emulate an imprecise producer and verify
            # that the explicit type fact, not the key alone, gates address
            # displacement summaries.
            key="size",
            op="add",
            children=(size, const(16)),
            offset=16,
            bits=64,
            signed=False,
            is_pointer=False,
        )
        wrapper = FunctionIR(
            ea=0x2200,
            name="allocate_record",
            parameters=("size", "output"),
            statements=[
                Call(1, 0x2208, "read", (const(0), var("output"), const(1))),
                Return(
                    2,
                    0x2210,
                    call_expr("malloc", enlarged),
                )
            ],
        )
        summary = SummaryBuilder().build([wrapper]).lookup(
            wrapper.name, wrapper.ea
        )
        self.assertIsNotNone(summary)
        self.assertIsNotNone(summary.allocation)
        size_ref = summary.allocation.sizes[0]
        self.assertEqual(size_ref.scalar_op, "add")
        self.assertEqual(size_ref.offset, 0)
        resolved = size_ref.resolve((size, var("output")))
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.op, "add")
        self.assertEqual(resolved.offset, 0)
        self.assertIsNone(resolved.key)
        self.assertFalse(resolved.is_pointer)

    def test_allocation_wrapper_preserves_scalar_addition_overflow(self):
        parameter = Expr(
            kind="var",
            text="size",
            key="size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        enlarged = Expr(
            kind="op",
            text="size + 16",
            op="add",
            children=(parameter, const(16)),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        wrapper = FunctionIR(
            ea=0x2200,
            name="allocate_record",
            parameters=("size",),
            statements=[
                Return(1, 0x2210, call_expr("malloc", enlarged))
            ],
        )
        caller_size = Expr(
            kind="var",
            text="caller_size",
            key="caller_size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        allocation = Expr(
            kind="call",
            text="allocate_record(caller_size)",
            callee=wrapper.name,
            callee_ea=wrapper.ea,
            children=(caller_size,),
            bits=64,
            signed=False,
            is_pointer=True,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="allocation_caller",
            statements=[
                Call(1, 0x3010, "read", (const(0), caller_size, const(8))),
                Assignment(2, 0x3020, var("pointer"), allocation),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        overflow = next(
            item
            for item in findings
            if item.rule_id == "INT-005"
            and item.function_name == caller.name
        )
        self.assertIn("positive_increment=16", overflow.evidence)

    def test_bounded_read_result_does_not_become_arbitrary_size_overflow(self):
        parameter = Expr(
            kind="var",
            text="size",
            key="size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        enlarged = Expr(
            kind="op",
            text="size + 16",
            op="add",
            children=(parameter, const(16)),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        wrapper = FunctionIR(
            ea=0x2200,
            name="allocate_record",
            parameters=("size",),
            statements=[
                Return(1, 0x2210, call_expr("malloc", enlarged))
            ],
        )
        result = Expr(
            kind="var",
            text="result",
            key="result",
            bits=64,
            signed=True,
            is_pointer=False,
        )
        input_result = Expr(
            kind="call",
            text="read(0, buffer, 4096)",
            callee="read",
            children=(const(0), var("buffer"), const(4096)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        allocation = Expr(
            kind="call",
            text="allocate_record(result)",
            callee=wrapper.name,
            callee_ea=wrapper.ea,
            children=(result,),
            bits=64,
            signed=False,
            is_pointer=True,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="bounded_result_caller",
            statements=[
                Assignment(1, 0x3010, result, input_result),
                Assignment(2, 0x3020, var("pointer"), allocation),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertFalse(
            any(
                item.rule_id == "INT-005"
                and item.function_name == caller.name
                for item in findings
            )
        )

    def test_wrapped_read_success_bound_is_separate_from_error_sentinel(self):
        destination = Expr(
            kind="var",
            text="destination",
            key="destination",
            bits=64,
            signed=False,
            is_pointer=True,
        )
        limit = Expr(
            kind="var", text="limit", key="limit", bits=64, signed=False
        )
        reader = FunctionIR(
            ea=0x2200,
            name="bounded_reader",
            parameters=("destination", "limit"),
            statements=[
                Return(
                    1,
                    0x2210,
                    Expr(
                        kind="call",
                        text="read(0, destination, limit)",
                        callee="read",
                        children=(const(0), destination, limit),
                        bits=64,
                        signed=True,
                    ),
                )
            ],
        )
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        wrapped_result = Expr(
            kind="call",
            text="bounded_reader(buffer, 32)",
            callee=reader.name,
            callee_ea=reader.ea,
            children=(var("buffer"), const(32)),
            bits=64,
            signed=True,
        )
        enlarged = Expr(
            kind="op",
            text="count + 16",
            op="add",
            children=(count, const(16)),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="wrapped_result_caller",
            statements=[
                Assignment(1, 0x3010, count, wrapped_result),
                Assignment(
                    2,
                    0x3020,
                    var("pointer"),
                    call_expr("malloc", enlarged),
                ),
            ],
        )
        findings = Analyzer.analyze_program([reader, caller])
        caller_rules = {
            item.rule_id
            for item in findings
            if item.function_name == caller.name
        }
        self.assertIn("ERR-001", caller_rules)
        self.assertNotIn("INT-005", caller_rules)

    def test_layered_bounded_read_result_stays_bounded(self):
        inner_size = Expr(
            kind="var",
            text="size",
            key="size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        inner = FunctionIR(
            ea=0x2200,
            name="inner_record",
            parameters=("size",),
            statements=[
                Return(
                    1,
                    0x2210,
                    call_expr(
                        "malloc",
                        Expr(
                            kind="op",
                            text="size + 16",
                            op="add",
                            children=(inner_size, const(16)),
                            bits=64,
                            signed=False,
                            is_pointer=False,
                        ),
                    ),
                )
            ],
        )
        outer_size = Expr(
            kind="var",
            text="size",
            key="size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        outer = FunctionIR(
            ea=0x2300,
            name="outer_record",
            parameters=("size",),
            statements=[
                Return(
                    1,
                    0x2310,
                    Expr(
                        kind="call",
                        text="inner_record(size + 8)",
                        callee=inner.name,
                        callee_ea=inner.ea,
                        children=(
                            Expr(
                                kind="op",
                                text="size + 8",
                                op="add",
                                children=(outer_size, const(8)),
                                bits=64,
                                signed=False,
                                is_pointer=False,
                            ),
                        ),
                        is_pointer=True,
                    ),
                )
            ],
        )
        result = Expr(
            kind="var",
            text="result",
            key="result",
            bits=64,
            signed=True,
            is_pointer=False,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="layered_bounded_result",
            statements=[
                Assignment(
                    1,
                    0x3010,
                    result,
                    Expr(
                        kind="call",
                        text="read(0, buffer, 4096)",
                        callee="read",
                        children=(const(0), var("buffer"), const(4096)),
                        bits=64,
                        signed=True,
                        is_pointer=False,
                    ),
                ),
                Assignment(
                    2,
                    0x3020,
                    var("pointer"),
                    Expr(
                        kind="call",
                        text="outer_record(result)",
                        callee=outer.name,
                        callee_ea=outer.ea,
                        children=(result,),
                        is_pointer=True,
                    ),
                ),
            ],
        )
        findings = Analyzer.analyze_program([inner, outer, caller])
        self.assertFalse(
            any(
                item.rule_id == "INT-005"
                and item.function_name == caller.name
                for item in findings
            )
        )

    def test_scalar_allocation_summary_composes_across_layers(self):
        size = Expr(
            kind="var",
            text="size",
            key="size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        inner = FunctionIR(
            ea=0x2200,
            name="inner_allocate",
            parameters=("size",),
            statements=[
                Return(
                    1,
                    0x2210,
                    call_expr(
                        "malloc",
                        Expr(
                            kind="op",
                            text="size + 16",
                            op="add",
                            children=(size, const(16)),
                            bits=64,
                            signed=False,
                            is_pointer=False,
                        ),
                    ),
                )
            ],
        )
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        adjusted = Expr(
            kind="op",
            text="count + 8",
            op="add",
            children=(count, const(8)),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        outer = FunctionIR(
            ea=0x2300,
            name="outer_allocate",
            parameters=("count",),
            statements=[
                Return(
                    1,
                    0x2310,
                    Expr(
                        kind="call",
                        text="inner_allocate(count + 8)",
                        callee=inner.name,
                        callee_ea=inner.ea,
                        children=(adjusted,),
                        is_pointer=True,
                    ),
                )
            ],
        )
        builder = SummaryBuilder()
        summary = builder.build([inner, outer]).lookup(outer.name, outer.ea)
        self.assertIsNotNone(summary)
        self.assertIsNotNone(summary.allocation)
        resolved = summary.allocation.sizes[0].resolve((const(4),))
        self.assertIsNotNone(resolved)
        self.assertEqual(self.analyzer._eval_int(resolved), 28)
        self.assertEqual(resolved.offset, 0)
        self.assertFalse(resolved.is_pointer)
        self.assertEqual(builder.last_iterations, 2)
        self.assertEqual(builder.last_recomputed, 3)

    def test_scalar_allocation_summary_preserves_narrowing_cast(self):
        size = Expr(
            kind="var",
            text="size",
            key="size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        narrowed = Expr(
            kind="cast",
            text="(unsigned short)size",
            children=(size,),
            bits=16,
            signed=False,
            is_pointer=False,
        )
        enlarged = Expr(
            kind="op",
            text="(unsigned short)size + 32",
            op="add",
            children=(narrowed, const(32)),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        wrapper = FunctionIR(
            ea=0x2200,
            name="narrow_allocate",
            parameters=("size",),
            statements=[
                Return(1, 0x2210, call_expr("malloc", enlarged))
            ],
        )
        caller_size = Expr(
            kind="var",
            text="caller_size",
            key="caller_size",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        allocation = Expr(
            kind="call",
            text="narrow_allocate(caller_size)",
            callee=wrapper.name,
            callee_ea=wrapper.ea,
            children=(caller_size,),
            is_pointer=True,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="narrow_allocation_caller",
            statements=[
                Call(1, 0x3010, "read", (const(0), caller_size, const(8))),
                Assignment(2, 0x3020, var("pointer"), allocation),
            ],
        )
        summary = SummaryBuilder().build([wrapper]).lookup(
            wrapper.name, wrapper.ea
        )
        self.assertEqual(
            summary.allocation.sizes[0].operands[0].scalar_op,
            "cast",
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertFalse(
            any(
                item.rule_id == "INT-005"
                and item.function_name == caller.name
                for item in findings
            )
        )

    def test_wrapper_preserves_scalar_length_addition(self):
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        enlarged = Expr(
            kind="op",
            text="count + 8",
            op="add",
            children=(count, const(8)),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        wrapper = FunctionIR(
            ea=0x2200,
            name="read_with_header",
            parameters=("destination", "count"),
            statements=[
                Call(
                    1,
                    0x2210,
                    "read",
                    (const(0), var("destination"), enlarged),
                )
            ],
        )

        def caller(ea: int, requested: int) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=f"scalar_length_{requested}",
                buffers={"buffer": self.stack32},
                statements=[
                    Call(
                        1,
                        ea + 0x10,
                        wrapper.name,
                        (var("buffer"), const(requested)),
                        callee_ea=wrapper.ea,
                    )
                ],
            )

        safe = caller(0x3000, 24)
        unsafe = caller(0x4000, 25)
        findings = Analyzer.analyze_program([wrapper, safe, unsafe])
        self.assertFalse(
            any(
                item.rule_id in {"BUF-003", "BUF-004"}
                and item.function_name == safe.name
                for item in findings
            )
        )
        overflow = next(
            item
            for item in findings
            if item.rule_id == "BUF-003"
            and item.function_name == unsafe.name
        )
        self.assertIn("length=33", overflow.evidence)
        self.assertIn("via read_with_header", overflow.summary)

    def test_wrapper_preserves_scalar_length_multiplication_width(self):
        count = Expr(
            kind="var",
            text="count",
            key="count",
            bits=32,
            signed=False,
            is_pointer=False,
        )
        scaled = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=32,
            signed=False,
            is_pointer=False,
        )
        wrapper = FunctionIR(
            ea=0x2200,
            name="scaled_read",
            parameters=("destination", "count"),
            statements=[
                Call(
                    1,
                    0x2210,
                    "read",
                    (const(0), var("destination"), scaled),
                )
            ],
        )
        caller_count = Expr(
            kind="var",
            text="caller_count",
            key="caller_count",
            bits=32,
            signed=False,
            is_pointer=False,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="scaled_read_caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    "read",
                    (const(0), caller_count, const(4)),
                ),
                Call(
                    2,
                    0x3020,
                    wrapper.name,
                    (var("destination"), caller_count),
                    callee_ea=wrapper.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        overflow = next(
            item
            for item in findings
            if item.rule_id == "INT-003"
            and item.function_name == caller.name
        )
        self.assertIn("bits=32", overflow.evidence)
        self.assertIn("via scaled_read", overflow.summary)

    def test_wrapper_reports_ranges_starting_before_object(self):
        reader = FunctionIR(
            ea=0x2200,
            name="read_before",
            parameters=("destination",),
            statements=[
                Call(
                    1,
                    0x2220,
                    "read",
                    (const(0), pointer_offset("destination", -1), const(1)),
                )
            ],
        )
        emitter = FunctionIR(
            ea=0x2300,
            name="write_before",
            parameters=("source",),
            statements=[
                Call(
                    1,
                    0x2320,
                    "write",
                    (const(1), pointer_offset("source", -1), const(1)),
                )
            ],
        )
        zero_length = FunctionIR(
            ea=0x2400,
            name="zero_before",
            parameters=("destination",),
            statements=[
                Call(
                    1,
                    0x2420,
                    "read",
                    (const(0), pointer_offset("destination", -1), const(0)),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="negative_offset_caller",
            buffers={
                "buffer": BufferInfo("buffer", "buffer", "stack", 32)
            },
            statements=[
                Call(
                    1,
                    0x3010,
                    "read_before",
                    (var("buffer"),),
                    callee_ea=reader.ea,
                ),
                Call(
                    2,
                    0x3020,
                    "write_before",
                    (var("buffer"),),
                    callee_ea=emitter.ea,
                ),
                Call(
                    3,
                    0x3030,
                    "zero_before",
                    (var("buffer"),),
                    callee_ea=zero_length.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program(
            [reader, emitter, zero_length, caller]
        )
        destination = next(
            item for item in findings if item.rule_id == "BUF-003"
        )
        source = next(item for item in findings if item.rule_id == "BUF-007")
        self.assertIn("start_offset=-1", destination.evidence)
        self.assertIn("start_offset=-1", source.evidence)
        self.assertFalse(
            any("zero_before" in item.summary for item in findings)
        )

    def test_wrapper_preserves_constant_source_offset_across_layers(self):
        emitter = FunctionIR(
            ea=0x2200,
            name="emit_tail",
            parameters=("source",),
            statements=[
                Call(
                    1,
                    0x2220,
                    "write",
                    (const(1), pointer_offset("source", 8), const(9)),
                )
            ],
        )
        outer = FunctionIR(
            ea=0x2300,
            name="emit_nested_tail",
            parameters=("source",),
            statements=[
                Call(
                    1,
                    0x2320,
                    "emit_tail",
                    (pointer_offset("source", 8),),
                    callee_ea=emitter.ea,
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="nested_offset_caller",
            buffers={
                "source": BufferInfo("source", "source", "stack", 24)
            },
            statements=[
                Call(
                    1,
                    0x3010,
                    "emit_nested_tail",
                    (var("source"),),
                    callee_ea=outer.ea,
                )
            ],
        )
        summary = SummaryBuilder().build([emitter, outer]).lookup(
            outer.name, outer.ea
        )
        self.assertIsNotNone(summary)
        self.assertEqual(summary.reads[0].source.offset, 16)
        finding = next(
            item
            for item in Analyzer.analyze_program([emitter, outer, caller])
            if item.rule_id == "BUF-007"
        )
        self.assertEqual(finding.function_name, emitter.name)
        self.assertIn("available_source_capacity=8", finding.evidence)
        self.assertIn("wrapper=emit_nested_tail", finding.evidence)

    def test_dynamic_wrapper_pointer_offset_is_not_collapsed_to_zero(self):
        wrapper = FunctionIR(
            ea=0x2200,
            name="dynamic_tail_reader",
            parameters=("destination", "skip"),
            statements=[
                Call(
                    1,
                    0x2220,
                    "read",
                    (
                        const(0),
                        pointer_offset(
                            "destination", 0, dynamic=var("skip")
                        ),
                        const(16),
                    ),
                )
            ],
        )
        summary = SummaryBuilder().build([wrapper]).lookup(
            wrapper.name, wrapper.ea
        )
        self.assertTrue(summary is None or not summary.writes)

    def test_offset_input_wrapper_preserves_taint_region(self):
        wrapper = FunctionIR(
            ea=0x2200,
            name="read_payload_tail",
            parameters=("destination",),
            statements=[
                Call(
                    1,
                    0x2220,
                    "read",
                    (const(0), pointer_offset("destination", 8), const(8)),
                )
            ],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="format_payload_tail",
            buffers={
                "buffer": BufferInfo("buffer", "buffer", "stack", 16)
            },
            statements=[
                Call(
                    1,
                    0x3010,
                    "read_payload_tail",
                    (var("buffer"),),
                    callee_ea=wrapper.ea,
                ),
                Call(
                    2,
                    0x3020,
                    "printf",
                    (pointer_offset("buffer", 8),),
                ),
            ],
        )
        finding = next(
            item
            for item in Analyzer.analyze_program([wrapper, caller])
            if item.rule_id == "FMT-001"
        )
        self.assertEqual(finding.confidence, "High")

    def test_looping_read_wrapper_accepts_guard_within_capacity(self):
        progress = var("progress")
        wrapper = FunctionIR(
            ea=0x2200,
            name="read_exact",
            parameters=("destination", "count"),
            statements=[
                Call(
                    1,
                    0x2220,
                    "read",
                    (
                        const(0),
                        Expr(
                            kind="op",
                            op="add",
                            children=(progress, var("destination")),
                        ),
                        Expr(
                            kind="op",
                            op="sub",
                            children=(var("count"), progress),
                        ),
                    ),
                )
            ],
        )
        safe_guard = Expr(
            kind="op",
            op="ule",
            children=(var("input_count"), const(32)),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    1,
                    0x3010,
                    "read_exact",
                    (var("buf"), var("input_count")),
                    callee_ea=wrapper.ea,
                    guards=(safe_guard,),
                )
            ],
        )
        self.assertNotIn(
            "BUF-004",
            {item.rule_id for item in Analyzer.analyze_program([wrapper, caller])},
        )

    def test_free_wrapper_updates_lifetime(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="destroy",
            parameters=("ptr",),
            statements=[Call(1, 0x2010, "free", (var("ptr"),))],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            statements=[
                Assignment(1, 0x3010, var("ptr"), call_expr("malloc", const(32))),
                Call(2, 0x3020, "destroy", (var("ptr"),), callee_ea=wrapper.ea),
                Call(3, 0x3030, "puts", (var("ptr"),)),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertTrue(
            any(
                item.rule_id == "LIFE-002" and item.function_name == "caller"
                for item in findings
            )
        )

    def test_allocator_wrapper_preserves_capacity(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="allocate",
            parameters=("count",),
            statements=[
                Return(1, 0x2010, call_expr("malloc", var("count")))
            ],
        )
        allocation = Expr(
            kind="call",
            text="allocate(16)",
            callee="allocate",
            callee_ea=wrapper.ea,
            children=(const(16),),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            statements=[
                Assignment(1, 0x3010, var("ptr"), allocation),
                Call(2, 0x3020, "read", (const(0), var("ptr"), const(64))),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertTrue(
            any(
                item.rule_id == "BUF-003" and item.category == "Heap buffer overflow"
                for item in findings
            )
        )

    def test_mmap_wrapper_preserves_mapped_capacity(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="map_region",
            parameters=("count",),
            statements=[
                Return(
                    1,
                    0x2010,
                    call_expr(
                        "mmap",
                        const(0),
                        var("count"),
                        const(3),
                        const(0x22),
                        const(-1),
                        const(0),
                    ),
                )
            ],
        )
        allocation = Expr(
            kind="call",
            text="map_region(4096)",
            callee="map_region",
            callee_ea=wrapper.ea,
            children=(const(4096),),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            statements=[
                Assignment(1, 0x3010, var("mapping"), allocation),
                Call(2, 0x3020, "read", (const(0), var("mapping"), const(8192))),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertTrue(
            any(
                item.rule_id == "BUF-003"
                and item.category == "Mapped buffer overflow"
                for item in findings
            )
        )

    def test_format_wrapper_is_propagated(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="log_message",
            parameters=("message",),
            statements=[Call(1, 0x2010, "printf", (var("message"),))],
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x3010, "read", (const(0), var("buf"), const(32))),
                Call(
                    2,
                    0x3020,
                    "log_message",
                    (var("buf"),),
                    callee_ea=wrapper.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        finding = next(
            item
            for item in findings
            if item.rule_id == "FMT-001" and item.function_name == "caller"
        )
        self.assertIn("via log_message", finding.summary)

    def test_retained_global_slot_after_free(self):
        table = Expr(kind="global", text="chunks", key="g:4000")
        slot = Expr(kind="deref", text="chunks[index]", children=(table, var("index")))
        ir = function(Call(1, 0x1010, "free", (slot,)))
        self.assertIn("LIFE-003", self.rule_ids(ir))

    def test_indirect_call_through_retained_freed_global_slot(self):
        table = Expr(kind="global", text="slots", key="g:slots")
        slot = Expr(
            kind="index",
            text="slots[index]",
            children=(table, var("index")),
        )
        release = FunctionIR(
            ea=0x2000,
            name="delete_slot",
            statements=[Call(1, 0x2010, "free", (slot,))],
        )
        callback = Expr(
            kind="member",
            text="object->callback",
            children=(var("object"),),
            offset=40,
        )
        trigger = FunctionIR(
            ea=0x3000,
            name="trigger_slot",
            statements=[
                Assignment(1, 0x3010, var("object"), slot),
                Call(
                    2,
                    0x3020,
                    "indirect_call",
                    (),
                    target=callback,
                ),
            ],
        )
        findings = Analyzer.analyze_program([release, trigger])
        finding = next(
            item
            for item in findings
            if item.rule_id == "LIFE-007"
            and item.function_name == "trigger_slot"
        )
        self.assertEqual(0x3020, finding.ea)
        self.assertIn("release_sites=0x2010", finding.evidence)

    def test_indirect_call_after_cleared_global_slot_is_not_reported(self):
        table = Expr(kind="global", text="slots", key="g:slots")
        slot = Expr(
            kind="index",
            text="slots[index]",
            children=(table, var("index")),
        )
        release = FunctionIR(
            ea=0x2000,
            name="delete_slot",
            statements=[
                Call(1, 0x2010, "free", (slot,)),
                Assignment(2, 0x2020, slot, const(0)),
            ],
        )
        trigger = FunctionIR(
            ea=0x3000,
            name="trigger_slot",
            statements=[
                Assignment(1, 0x3010, var("object"), slot),
                Call(
                    2,
                    0x3020,
                    "indirect_call",
                    (),
                    target=Expr(
                        kind="member",
                        text="object->callback",
                        children=(var("object"),),
                        offset=40,
                    ),
                ),
            ],
        )
        findings = Analyzer.analyze_program([release, trigger])
        self.assertFalse(any(item.rule_id == "LIFE-007" for item in findings))

    def test_cleared_global_slot_after_free(self):
        table = Expr(kind="global", text="chunks", key="g:4000")
        slot = Expr(kind="deref", text="chunks[index]", children=(table, var("index")))
        ir = function(
            Call(1, 0x1010, "free", (slot,)),
            Assignment(2, 0x1020, slot, const(0)),
        )
        self.assertNotIn("LIFE-003", self.rule_ids(ir))

    def test_retained_global_slot_after_derived_munmap_wrapper(self):
        release = FunctionIR(
            ea=0x2000,
            name="pool_release",
            parameters=("ptr",),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    var("page"),
                    Expr(
                        kind="op",
                        text="ptr & -4096",
                        op="and",
                        children=(var("ptr"), const(-4096)),
                    ),
                ),
                Assignment(
                    2,
                    0x2018,
                    Expr(kind="deref", text="*ptr", children=(var("ptr"),)),
                    const(0),
                ),
                Call(3, 0x2020, "munmap", (var("page"), const(4096))),
            ],
        )
        table = Expr(kind="global", text="slots", key="g:slots")
        slot = Expr(
            kind="index",
            text="slots[index]",
            children=(table, var("index")),
        )
        caller = FunctionIR(
            ea=0x3000,
            name="delete_slot",
            statements=[
                Assignment(1, 0x3010, var("object"), slot),
                Call(
                    2,
                    0x3020,
                    "pool_release",
                    (var("object"),),
                    callee_ea=release.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([release, caller])
        finding = next(
            item
            for item in findings
            if item.rule_id == "LIFE-003" and item.function_name == "delete_slot"
        )
        self.assertEqual(0x3020, finding.ea)
        self.assertIn("pool_release may release it", finding.evidence)

    def test_custom_release_of_global_sentinel_is_not_a_dangling_slot(self):
        release = FunctionIR(
            ea=0x2000,
            name="pool_release",
            parameters=("ptr",),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    var("page"),
                    Expr(
                        kind="op",
                        text="ptr & -4096",
                        op="and",
                        children=(var("ptr"), const(-4096)),
                    ),
                ),
                Assignment(
                    2,
                    0x2018,
                    Expr(kind="deref", text="*ptr", children=(var("ptr"),)),
                    const(0),
                ),
                Call(3, 0x2020, "munmap", (var("page"), const(4096))),
            ],
        )
        sentinel = Expr(kind="global", text="empty", key="g:empty")
        caller = FunctionIR(
            ea=0x3000,
            name="release_temporary",
            statements=[
                Assignment(1, 0x3010, var("temporary"), sentinel),
                Call(
                    2,
                    0x3020,
                    "pool_release",
                    (var("temporary"),),
                    callee_ea=release.ea,
                ),
            ],
        )
        findings = Analyzer.analyze_program([release, caller])
        self.assertFalse(
            any(
                item.rule_id == "LIFE-003"
                and item.function_name == "release_temporary"
                for item in findings
            )
        )

    def test_malloc_strong_update_kills_retained_global_provenance(self):
        slot = Expr(kind="global", text="chunks[index]", key="g:4000")
        ir = function(
            Assignment(1, 0x1010, var("ptr"), slot),
            Assignment(2, 0x1020, var("ptr"), call_expr("malloc", const(32))),
            Call(3, 0x1030, "free", (var("ptr"),)),
        )
        self.assertNotIn("LIFE-003", self.rule_ids(ir))

    def test_nested_condition_visit_order_keeps_global_free_origin(self):
        table = Expr(kind="global", text="slots", key="g:slots")
        loaded = Expr(
            kind="index",
            text="slots[index]",
            children=(table, var("index")),
        )
        # Hex-Rays CV_FAST may assign the nested free a lower visit order even
        # though its machine address follows the slot load.
        ir = function(
            Call(1, 0x1030, "free", (var("ptr"),)),
            Assignment(2, 0x1020, var("ptr"), loaded),
        )
        self.assertIn("LIFE-003", self.rule_ids(ir))

    def test_global_slot_free_does_not_mark_index_as_dangling(self):
        blocks = {
            0: BasicBlock(0, 0x1000, 0x1010, (), (1, 2)),
            1: BasicBlock(1, 0x1010, 0x1020, (0,), (2,)),
            2: BasicBlock(2, 0x1020, 0x1040, (0, 1), ()),
        }
        table = Expr(kind="global", text="slots", key="g:slots")
        index = Expr(
            kind="var", text="index", key="index", bits=32, signed=False
        )
        slot = Expr(
            kind="deref",
            text="slots[index]",
            children=(table, index),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="replace_slot",
            parameters=("index",),
            statements=[
                Call(1, 0x1014, "free", (slot,), block_id=1),
                Call(
                    2,
                    0x1024,
                    "printf",
                    (string("index=%u"), index),
                    block_id=2,
                ),
            ],
            blocks=blocks,
            entry_block=0,
        )
        rule_ids = self.rule_ids(ir)
        self.assertIn("LIFE-003", rule_ids)
        self.assertNotIn("LIFE-005", rule_ids)

    def test_global_slot_use_after_optional_free_is_still_reported(self):
        blocks = {
            0: BasicBlock(0, 0x1000, 0x1010, (), (1, 2)),
            1: BasicBlock(1, 0x1010, 0x1020, (0,), (2,)),
            2: BasicBlock(2, 0x1020, 0x1040, (0, 1), ()),
        }
        table = Expr(kind="global", text="slots", key="g:slots")
        slot = Expr(
            kind="deref",
            text="slots[index]",
            children=(table, var("index")),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="show_slot",
            statements=[
                Call(1, 0x1014, "free", (slot,), block_id=1),
                Call(2, 0x1024, "puts", (slot,), block_id=2),
            ],
            blocks=blocks,
            entry_block=0,
        )
        self.assertIn("LIFE-005", self.rule_ids(ir))

    def test_lookup_result_munmap_does_not_free_lookup_parameters(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="release_lookup_result",
            parameters=("table", "index"),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    var("result"),
                    call_expr("lookup", var("table"), var("index")),
                ),
                Call(2, 0x2020, "munmap", (var("result"), const(4096))),
            ],
            blocks={0: BasicBlock(0, 0x2000, 0x2030)},
            entry_block=0,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    "release_lookup_result",
                    (var("table"), var("index")),
                    callee_ea=wrapper.ea,
                    block_id=0,
                ),
                Call(2, 0x3020, "puts", (var("table"),), block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x3000, 0x3030)},
            entry_block=0,
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertFalse(
            any(
                finding.rule_id == "LIFE-005"
                and finding.function_name == "caller"
                for finding in findings
            )
        )

    def test_wrapper_returning_local_input_is_a_source(self):
        input_buffer = BufferInfo("input", "input", "stack", 16)
        wrapper = FunctionIR(
            ea=0x2000,
            name="read_number",
            buffers={"input": input_buffer},
            statements=[
                Call(1, 0x2010, "read", (const(0), var("input"), const(16))),
                Return(2, 0x2020, call_expr("atoi", var("input"))),
            ],
        )
        number_call = Expr(
            kind="call",
            text="read_number()",
            callee="read_number",
            callee_ea=wrapper.ea,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="caller",
            buffers={"buf": self.stack32},
            statements=[
                Assignment(1, 0x3010, var("count"), number_call),
                Call(2, 0x3020, "read", (const(0), var("buf"), var("count"))),
            ],
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        overflow = next(
            item
            for item in findings
            if item.rule_id == "BUF-004" and item.function_name == "caller"
        )
        self.assertIn("attacker-influenced", overflow.summary)

    def test_cfg_optional_free_is_not_definite_double_free(self):
        blocks = {
            0: BasicBlock(0, 0x1000, 0x1010, (), (1, 2)),
            1: BasicBlock(1, 0x1010, 0x1020, (0,), (3,)),
            2: BasicBlock(2, 0x1020, 0x1030, (0,), (3,)),
            3: BasicBlock(3, 0x1030, 0x1040, (1, 2), ()),
        }
        ir = FunctionIR(
            ea=0x1000,
            name="branch_free",
            statements=[
                Assignment(
                    1,
                    0x1004,
                    var("ptr"),
                    call_expr("malloc", const(32)),
                    block_id=0,
                ),
                Call(2, 0x1014, "free", (var("ptr"),), block_id=1),
                Call(3, 0x1034, "free", (var("ptr"),), block_id=3),
            ],
            blocks=blocks,
            entry_block=0,
        )
        rule_ids = self.rule_ids(ir)
        self.assertIn("LIFE-004", rule_ids)
        self.assertNotIn("LIFE-001", rule_ids)

    def test_cfg_free_on_all_branches_is_definite(self):
        blocks = {
            0: BasicBlock(0, 0x1000, 0x1010, (), (1, 2)),
            1: BasicBlock(1, 0x1010, 0x1020, (0,), (3,)),
            2: BasicBlock(2, 0x1020, 0x1030, (0,), (3,)),
            3: BasicBlock(3, 0x1030, 0x1040, (1, 2), ()),
        }
        ir = FunctionIR(
            ea=0x1000,
            name="branch_free",
            statements=[
                Assignment(
                    1,
                    0x1004,
                    var("ptr"),
                    call_expr("malloc", const(32)),
                    block_id=0,
                ),
                Call(2, 0x1014, "free", (var("ptr"),), block_id=1),
                Call(3, 0x1024, "free", (var("ptr"),), block_id=2),
                Call(4, 0x1034, "free", (var("ptr"),), block_id=3),
            ],
            blocks=blocks,
            entry_block=0,
        )
        self.assertIn("LIFE-001", self.rule_ids(ir))

    def test_cfg_possible_uaf_has_separate_rule(self):
        blocks = {
            0: BasicBlock(0, 0x1000, 0x1010, (), (1, 2)),
            1: BasicBlock(1, 0x1010, 0x1020, (0,), (3,)),
            2: BasicBlock(2, 0x1020, 0x1030, (0,), (3,)),
            3: BasicBlock(3, 0x1030, 0x1040, (1, 2), ()),
        }
        ir = FunctionIR(
            ea=0x1000,
            name="branch_uaf",
            statements=[
                Assignment(
                    1,
                    0x1004,
                    var("ptr"),
                    call_expr("malloc", const(32)),
                    block_id=0,
                ),
                Call(2, 0x1014, "free", (var("ptr"),), block_id=1),
                Call(3, 0x1034, "puts", (var("ptr"),), block_id=3),
            ],
            blocks=blocks,
            entry_block=0,
        )
        rule_ids = self.rule_ids(ir)
        self.assertIn("LIFE-005", rule_ids)
        self.assertNotIn("LIFE-002", rule_ids)

    def test_free_of_loaded_field_does_not_free_its_owner(self):
        owner = var("owner")
        field = Expr(
            kind="deref",
            text="*(owner + 16)",
            key="owner",
            children=(
                Expr(
                    kind="op",
                    text="owner + 16",
                    key="owner",
                    op="add",
                    children=(owner, const(16)),
                ),
            ),
        )
        owner_word = Expr(
            kind="deref",
            text="*owner",
            key="owner",
            children=(owner,),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="release_field",
            statements=[
                Call(1, 0x1010, "free", (field,), block_id=0),
                Assignment(2, 0x1020, var("value"), owner_word, block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1030)},
            entry_block=0,
        )
        self.assertNotIn("LIFE-002", self.rule_ids(ir))

    def test_nested_global_field_and_outer_object_are_distinct(self):
        global_owner = Expr(kind="global", text="current", key="g:current")
        outer = Expr(
            kind="deref",
            text="*current",
            key="g:current",
            children=(global_owner,),
        )
        inner = Expr(
            kind="deref",
            text="(*current)->value",
            key="g:current",
            children=(
                Expr(
                    kind="op",
                    text="*current + 32",
                    key="g:current",
                    op="add",
                    children=(outer, const(32)),
                ),
            ),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="release_transaction",
            statements=[
                Assignment(1, 0x1010, var("child"), inner, block_id=0),
                Call(2, 0x1020, "free", (var("child"),), block_id=0),
                Call(3, 0x1030, "free", (outer,), block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1040)},
            entry_block=0,
        )
        rule_ids = self.rule_ids(ir)
        self.assertNotIn("LIFE-001", rule_ids)
        self.assertNotIn("LIFE-004", rule_ids)

    def test_realloc_argument_is_used_before_possible_release(self):
        realloc_expr = call_expr("realloc", var("ptr"), const(64))
        ir = FunctionIR(
            ea=0x1000,
            name="grow",
            statements=[
                Assignment(1, 0x1010, var("grown"), realloc_expr, block_id=0),
                Call(
                    2,
                    0x1010,
                    "realloc",
                    (var("ptr"), const(64)),
                    block_id=0,
                ),
                Call(3, 0x1020, "puts", (var("ptr"),), block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1030)},
            entry_block=0,
        )
        findings = self.analyzer.analyze_function(ir)
        self.assertFalse(
            any(item.rule_id == "LIFE-005" and item.ea == 0x1010 for item in findings)
        )
        self.assertTrue(
            any(item.rule_id == "LIFE-005" and item.ea == 0x1020 for item in findings)
        )

    def test_reallocarray_argument_is_used_before_possible_release(self):
        realloc_expr = call_expr(
            "reallocarray", var("ptr"), var("count"), const(16)
        )
        ir = FunctionIR(
            ea=0x1000,
            name="grow_array",
            statements=[
                Assignment(1, 0x1010, var("grown"), realloc_expr, block_id=0),
                Call(
                    2,
                    0x1010,
                    "reallocarray",
                    (var("ptr"), var("count"), const(16)),
                    block_id=0,
                ),
                Call(3, 0x1020, "puts", (var("ptr"),), block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1030)},
            entry_block=0,
        )
        findings = self.analyzer.analyze_function(ir)
        self.assertFalse(
            any(item.rule_id == "LIFE-005" and item.ea == 0x1010 for item in findings)
        )
        self.assertTrue(
            any(item.rule_id == "LIFE-005" and item.ea == 0x1020 for item in findings)
        )

    def test_munmap_backed_custom_release_is_modeled_as_possible(self):
        header = Expr(
            kind="op",
            text="pointer - 1",
            op="sub",
            children=(var("pointer"), const(1)),
            key="pointer",
        )
        wrapper = FunctionIR(
            ea=0x2000,
            name="custom_release",
            parameters=("arena", "pointer"),
            statements=[
                Assignment(1, 0x2010, var("header"), header),
                Call(2, 0x2020, "munmap", (var("header"), const(4096))),
            ],
            blocks={0: BasicBlock(0, 0x2000, 0x2030)},
            entry_block=0,
        )
        caller = FunctionIR(
            ea=0x1000,
            name="hidden_check",
            statements=[
                Call(1, 0x1010, "custom_release", (var("arena"), var("chunk")), callee_ea=0x2000),
                Call(2, 0x1020, "printf", (string("%d"), var("chunk"))),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1030)},
            entry_block=0,
        )
        findings = Analyzer.analyze_program([caller, wrapper])
        self.assertTrue(
            any(
                finding.rule_id == "LIFE-005"
                and finding.function_name == "hidden_check"
                for finding in findings
            )
        )

    def test_direct_munmap_is_a_possible_release(self):
        ir = FunctionIR(
            ea=0x1000,
            name="mapped_uaf",
            statements=[
                Assignment(
                    1,
                    0x1010,
                    var("mapping"),
                    call_expr(
                        "mmap",
                        const(0),
                        const(4096),
                        const(3),
                        const(0x22),
                        const(-1),
                        const(0),
                    ),
                    block_id=0,
                ),
                Call(
                    2,
                    0x1020,
                    "munmap",
                    (var("mapping"), const(4096)),
                    block_id=0,
                ),
                Call(3, 0x1030, "puts", (var("mapping"),), block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1040)},
            entry_block=0,
        )
        findings = self.analyzer.analyze_function(ir)
        self.assertTrue(
            any(item.rule_id == "LIFE-005" and item.ea == 0x1030 for item in findings)
        )

    def test_repeated_direct_munmap_is_not_allocator_double_free(self):
        ir = FunctionIR(
            ea=0x1000,
            name="unmap_twice",
            statements=[
                Assignment(
                    1,
                    0x1010,
                    var("mapping"),
                    call_expr(
                        "mmap",
                        const(0),
                        const(4096),
                        const(3),
                        const(0x22),
                        const(-1),
                        const(0),
                    ),
                    block_id=0,
                ),
                Call(2, 0x1020, "munmap", (var("mapping"), const(4096)), block_id=0),
                Call(3, 0x1030, "munmap", (var("mapping"), const(4096)), block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1040)},
            entry_block=0,
        )
        self.assertNotIn("LIFE-004", self.rule_ids(ir))

    def test_linked_list_release_loop_refreshes_cursor_generation(self):
        next_pointer = Expr(
            kind="deref",
            text="cursor->next",
            key="cursor",
            children=(var("cursor"),),
            offset=24,
            bits=64,
            signed=False,
        )
        current_size = Expr(
            kind="deref",
            text="current->size",
            key="current",
            children=(var("current"),),
            offset=8,
            bits=64,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="drain_list",
            parameters=("cursor",),
            statements=[
                Assignment(1, 0x1010, var("next"), next_pointer, block_id=1),
                Assignment(2, 0x1014, var("current"), var("cursor"), block_id=1),
                Assignment(3, 0x1018, var("cursor"), var("next"), block_id=1),
                Assignment(4, 0x101C, var("size"), current_size, block_id=1),
                Call(5, 0x1020, "free", (var("current"),), block_id=2),
                Return(6, 0x1030, const(0), block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1008, successors=(1,)),
                1: BasicBlock(
                    1,
                    0x1010,
                    0x1020,
                    predecessors=(0, 2),
                    successors=(2, 3),
                ),
                2: BasicBlock(
                    2,
                    0x1020,
                    0x1028,
                    predecessors=(1,),
                    successors=(1,),
                ),
                3: BasicBlock(3, 0x1030, 0x1038, predecessors=(1,)),
            },
            entry_block=0,
        )
        self.assertFalse(
            {"LIFE-001", "LIFE-002", "LIFE-004", "LIFE-005"}
            & set(self.rule_ids(ir))
        )

    def test_linked_list_release_loop_still_reports_post_free_use(self):
        next_pointer = Expr(
            kind="deref",
            text="cursor->next",
            key="cursor",
            children=(var("cursor"),),
            offset=24,
            bits=64,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="unsafe_drain_list",
            parameters=("cursor",),
            statements=[
                Assignment(1, 0x1010, var("next"), next_pointer, block_id=1),
                Assignment(2, 0x1014, var("current"), var("cursor"), block_id=1),
                Assignment(3, 0x1018, var("cursor"), var("next"), block_id=1),
                Call(4, 0x1020, "free", (var("current"),), block_id=2),
                Call(5, 0x1024, "puts", (var("current"),), block_id=2),
                Return(6, 0x1030, const(0), block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1008, successors=(1,)),
                1: BasicBlock(
                    1,
                    0x1010,
                    0x1020,
                    predecessors=(0, 2),
                    successors=(2, 3),
                ),
                2: BasicBlock(
                    2,
                    0x1020,
                    0x1028,
                    predecessors=(1,),
                    successors=(1,),
                ),
                3: BasicBlock(3, 0x1030, 0x1038, predecessors=(1,)),
            },
            entry_block=0,
        )
        findings = self.analyzer.analyze_function(ir)
        self.assertTrue(
            any(item.rule_id == "LIFE-002" and item.ea == 0x1024 for item in findings)
        )

    def test_unknown_call_result_strong_update_prevents_possible_double_free(self):
        wrapper = FunctionIR(
            ea=0x2000,
            name="custom_release",
            parameters=("pointer",),
            statements=[
                Call(1, 0x2010, "munmap", (var("pointer"), const(4096)))
            ],
            blocks={0: BasicBlock(0, 0x2000, 0x2020)},
            entry_block=0,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="replace_twice",
            statements=[
                Assignment(1, 0x3010, var("ptr"), call_expr("first_lookup"), block_id=0),
                Call(
                    2,
                    0x3020,
                    "custom_release",
                    (var("ptr"),),
                    callee_ea=wrapper.ea,
                    block_id=0,
                ),
                Assignment(3, 0x3030, var("ptr"), call_expr("second_lookup"), block_id=0),
                Call(
                    4,
                    0x3040,
                    "custom_release",
                    (var("ptr"),),
                    callee_ea=wrapper.ea,
                    block_id=0,
                ),
            ],
            blocks={0: BasicBlock(0, 0x3000, 0x3050)},
            entry_block=0,
        )
        findings = Analyzer.analyze_program([wrapper, caller])
        self.assertFalse(
            any(
                finding.rule_id == "LIFE-004"
                and finding.function_name == "replace_twice"
                for finding in findings
            )
        )

    def test_signed_attacker_length_reaching_read(self):
        signed_size = Expr(
            kind="var", text="size", key="size", bits=32, signed=True
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), var("input"), const(16))),
            Assignment(2, 0x1020, signed_size, var("input")),
            Call(3, 0x1030, "read", (const(0), var("buf"), signed_size)),
            buffers=(self.stack32, BufferInfo("input", "input", "stack", 16)),
        )
        self.assertIn("INT-002", self.rule_ids(ir))

    def test_positive_bounded_io_update_preserves_remaining_capacity(self):
        owner = var("record")
        cursor = Expr(
            kind="index",
            text="record[2]",
            key="record",
            children=(owner, const(2)),
            offset=8,
            bits=32,
            signed=True,
        )
        destination = Expr(
            kind="op",
            text="record + record[2] + 28",
            key="record",
            op="add",
            children=(owner, cursor, const(28)),
        )
        remaining = Expr(
            kind="op",
            text="64 - record[2]",
            op="sub",
            children=(const(64), cursor),
            bits=32,
            signed=True,
        )
        result = Expr(
            kind="var", text="result", key="result", bits=64, signed=True
        )
        recv_result = Expr(
            kind="call",
            text="recv(fd, record + record[2] + 28, 64 - record[2], 0)",
            callee="recv",
            children=(var("fd"), destination, remaining, const(0)),
            bits=64,
            signed=True,
        )
        nonpositive = Expr(
            kind="op",
            text="result <= 0",
            op="sle",
            children=(result, const(0)),
        )
        update = Assignment(
            6,
            0x1030,
            cursor,
            Expr(
                kind="op",
                text="record[2] += result",
                op="add",
                children=(cursor, result),
                bits=32,
                signed=True,
            ),
            block_id=2,
        )
        sink = Call(
            8,
            0x1050,
            "recv",
            (var("fd"), destination, remaining, const(0)),
            block_id=3,
        )
        statements = [
            Assignment(1, 0x1010, result, recv_result, block_id=0),
            Call(
                2,
                0x1010,
                "recv",
                (var("fd"), destination, remaining, const(0)),
                block_id=0,
            ),
            Return(4, 0x1020, const(0), block_id=1, guards=(nonpositive,)),
            update,
            sink,
        ]
        safe = FunctionIR(
            ea=0x1000,
            name="bounded_receive_cursor",
            statements=statements,
            blocks={
                0: BasicBlock(0, 0x1000, 0x1018, successors=(1, 2)),
                1: BasicBlock(1, 0x1018, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1040, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1040, 0x1060, predecessors=(2,)),
            },
            entry_block=0,
            conditions=[Condition(0x1018, 0, nonpositive, nonpositive.text, order=3)],
        )
        self.assertFalse(
            any(
                finding.rule_id == "INT-002" and finding.ea == sink.ea
                for finding in self.analyzer.analyze_function(safe)
            )
        )

        unchecked = replace(
            safe,
            name="unchecked_receive_cursor",
            statements=[
                replace(statement, block_id=0, guards=())
                for statement in statements
                if not isinstance(statement, Return)
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1060)},
            conditions=[],
        )
        self.assertTrue(
            any(
                finding.rule_id == "INT-002" and finding.ea == sink.ea
                for finding in self.analyzer.analyze_function(unchecked)
            )
        )

        cursor_address = Expr(
            kind="address",
            text="&record[2]",
            key="record",
            children=(cursor,),
        )
        hostile = replace(
            safe,
            name="hostile_receive_cursor",
            statements=[
                Call(0, 0x1004, "read", (const(0), cursor_address, const(4))),
                *statements,
            ],
        )
        self.assertTrue(
            any(
                finding.rule_id == "INT-002" and finding.ea == sink.ea
                for finding in self.analyzer.analyze_function(hostile)
            )
        )

        wide_record_store = Expr(
            kind="deref",
            text="*(_OWORD *)record",
            key="record",
            children=(owner,),
            offset=0,
            bits=128,
            signed=False,
        )
        clobbered = replace(
            safe,
            name="clobbered_receive_cursor",
            statements=[
                *statements[:3],
                Assignment(5, 0x1028, wide_record_store, const(0), block_id=2),
                *statements[3:],
            ],
        )
        self.assertTrue(
            any(
                finding.rule_id == "INT-002" and finding.ea == sink.ea
                for finding in self.analyzer.analyze_function(clobbered)
            )
        )

    def test_dominating_positive_check_suppresses_signed_send_length(self):
        blocks = {
            0: BasicBlock(0, 0x1000, 0x1010, (), (1, 2)),
            1: BasicBlock(1, 0x1010, 0x1020, (0,), (3,)),
            2: BasicBlock(2, 0x1020, 0x1030, (0,), (3,)),
            3: BasicBlock(3, 0x1030, 0x1040, (1, 2), ()),
        }
        length = Expr(kind="var", text="length", key="length", bits=32, signed=True)
        guard = Expr(
            kind="op",
            text="length > 0",
            op="sgt",
            children=(length, const(0)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="forward",
            statements=[
                Call(1, 0x1004, "read", (const(0), length, const(4)), block_id=0),
                Call(
                    2,
                    0x1014,
                    "send",
                    (var("fd"), var("buf"), length, const(0)),
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks=blocks,
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        self.assertNotIn("INT-002", self.rule_ids(ir))

    def test_input_call_success_does_not_bound_its_output_buffer_value(self):
        size = Expr(
            kind="var", text="size", key="size", bits=32, signed=False
        )
        size_address = Expr(
            kind="address",
            text="&size",
            key="size",
            children=(size,),
            bits=64,
            signed=False,
        )
        input_call = Expr(
            kind="call",
            text="read(0, &size, 4)",
            callee="read",
            children=(const(0), size_address, const(4)),
            bits=64,
            signed=True,
        )
        success = Expr(
            kind="op",
            text="read(0, &size, 4) == 4",
            op="eq",
            children=(input_call, const(4)),
        )
        unsafe = FunctionIR(
            ea=0x1000,
            name="unchecked_short_circuit_read",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1010, "read", (const(0), size_address, const(4))),
                Call(
                    3,
                    0x1030,
                    "read",
                    (const(0), var("buf"), size),
                    guards=(success,),
                ),
            ],
            conditions=[Condition(0x1020, None, success, success.text, order=2)],
        )
        self.assertIn("BUF-004", self.rule_ids(unsafe))

        upper = Expr(
            kind="op",
            text="size <= 32",
            op="ule",
            children=(size, const(32)),
        )
        bounded_guard = Expr(
            kind="op",
            text="read(0, &size, 4) == 4 && size <= 32",
            op="logical_and",
            children=(success, upper),
        )
        safe = replace(
            unsafe,
            name="checked_short_circuit_read",
            statements=[
                unsafe.statements[0],
                replace(unsafe.statements[1], guards=(bounded_guard,)),
            ],
            conditions=[
                Condition(0x1020, None, bounded_guard, bounded_guard.text, order=2)
            ],
        )
        self.assertNotIn("BUF-004", self.rule_ids(safe))

    def test_positive_check_before_merge_does_not_bless_signed_length(self):
        length = Expr(kind="var", text="length", key="length", bits=32, signed=True)
        guard = Expr(
            kind="op",
            text="length > 0",
            op="sgt",
            children=(length, const(0)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="merged_send",
            statements=[
                Call(1, 0x1004, "read", (const(0), length, const(4)), block_id=0),
                Call(
                    2,
                    0x1040,
                    "send",
                    (var("fd"), var("buf"), length, const(0)),
                    block_id=3,
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        self.assertIn("INT-002", self.rule_ids(ir))

    def test_subtraction_can_underflow_at_memcpy_size(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=True)
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        subtraction = Expr(
            kind="op",
            text="size - 1",
            op="sub",
            children=(size, const(1)),
            bits=32,
            signed=True,
        )
        blocks = {
            0: BasicBlock(0, 0x1000, 0x1020, (), (1, 2)),
            1: BasicBlock(1, 0x1020, 0x1030, (0,), (2,)),
            2: BasicBlock(2, 0x1030, 0x1040, (0, 1), ()),
        }
        upper_guard = Expr(
            kind="op",
            text="size <= 4096",
            op="sle",
            children=(size, const(4096)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="copy_request",
            parameters=("size", "source"),
            statements=[
                Assignment(1, 0x1010, count, var("fallback"), block_id=0),
                Assignment(2, 0x1024, count, subtraction, block_id=1),
                Call(
                    3,
                    0x1034,
                    "memcpy",
                    (var("destination"), var("source"), count),
                    block_id=2,
                ),
                Assignment(
                    4,
                    0x1040,
                    Expr(kind="global", text="sizes[index]", key="g:sizes"),
                    size,
                    block_id=2,
                ),
            ],
            blocks=blocks,
            entry_block=0,
            conditions=[Condition(0x1008, 0, upper_guard, upper_guard.text)],
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "INT-004"
        )
        self.assertEqual(finding.ea, 0x1034)

    def test_positive_lower_guard_suppresses_subtraction_underflow(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=True)
        subtraction = Expr(
            kind="op",
            text="size - 1",
            op="sub",
            children=(size, const(1)),
            bits=32,
            signed=True,
        )
        positive = Expr(
            kind="op",
            text="size > 0",
            op="sgt",
            children=(size, const(0)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="guarded_copy",
            parameters=("size",),
            statements=[
                Call(
                    1,
                    0x1020,
                    "memcpy",
                    (var("destination"), var("source"), subtraction),
                )
            ],
            conditions=[Condition(0x1010, None, positive, positive.text)],
        )
        self.assertNotIn("INT-004", self.rule_ids(ir))

    def test_non_dominating_lower_guard_does_not_hide_subtraction_underflow(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=True)
        subtraction = Expr(
            kind="op",
            text="size - 1",
            op="sub",
            children=(size, const(1)),
            bits=32,
            signed=True,
        )
        positive = Expr(
            kind="op",
            text="size > 0",
            op="sgt",
            children=(size, const(0)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="branch_local_guard",
            parameters=("size",),
            statements=[
                Call(
                    1,
                    0x1040,
                    "memcpy",
                    (var("destination"), var("source"), subtraction),
                    block_id=3,
                )
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1010, 1, positive, positive.text)],
        )
        self.assertIn("INT-004", self.rule_ids(ir))

    def test_dominating_branch_node_does_not_prove_merge_path_lower_bound(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=True)
        subtraction = Expr(
            kind="op",
            text="size - 1",
            op="sub",
            children=(size, const(1)),
            bits=32,
            signed=True,
        )
        positive = Expr(
            kind="op",
            text="size > 0",
            op="sgt",
            children=(size, const(0)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="merged_guard",
            parameters=("size",),
            statements=[
                Call(
                    1,
                    0x1040,
                    "memcpy",
                    (var("destination"), var("source"), subtraction),
                    block_id=3,
                )
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, positive, positive.text)],
        )
        self.assertIn("INT-004", self.rule_ids(ir))

    def test_call_path_lower_guard_suppresses_subtraction_underflow(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=True)
        subtraction = Expr(
            kind="op",
            text="size - 1",
            op="sub",
            children=(size, const(1)),
            bits=32,
            signed=True,
        )
        positive = Expr(
            kind="op",
            text="size > 0",
            op="sgt",
            children=(size, const(0)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="path_guarded_copy",
            parameters=("size",),
            statements=[
                Call(
                    1,
                    0x1020,
                    "memcpy",
                    (var("destination"), var("source"), subtraction),
                    block_id=1,
                    guards=(positive,),
                )
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, positive, positive.text)],
        )
        self.assertNotIn("INT-004", self.rule_ids(ir))

    def test_rejected_lower_bound_path_suppresses_subtraction_underflow(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=True)
        subtraction = Expr(
            kind="op",
            text="size - 1",
            op="sub",
            children=(size, const(1)),
            bits=32,
            signed=True,
        )
        rejection = Expr(
            kind="op",
            text="size <= 0",
            op="sle",
            children=(size, const(0)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="validated_subtraction",
            parameters=("size",),
            statements=[
                Return(1, 0x1020, const(0), block_id=1, guards=(rejection,)),
                Call(
                    2,
                    0x1030,
                    "memcpy",
                    (var("destination"), var("source"), subtraction),
                    block_id=2,
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, rejection, rejection.text)],
        )
        self.assertNotIn("INT-004", self.rule_ids(ir))

    def test_never_defined_send_length_is_reported(self):
        length = Expr(
            kind="var", text="length", key="length", bits=32, signed=True
        )
        ir = FunctionIR(
            ea=0x1000,
            name="send_response",
            parameters=("socket", "buffer"),
            statements=[
                Call(
                    1,
                    0x1010,
                    "send",
                    (var("socket"), var("buffer"), length, const(0)),
                )
            ],
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "INIT-001"
        )
        self.assertEqual(finding.ea, 0x1010)

    def test_defined_or_parameter_send_length_is_not_reported(self):
        length = Expr(
            kind="var", text="length", key="length", bits=32, signed=True
        )
        defined = FunctionIR(
            ea=0x1000,
            name="send_response",
            parameters=("socket", "buffer"),
            statements=[
                Assignment(1, 0x1010, length, call_expr("strlen", var("buffer"))),
                Call(
                    2,
                    0x1020,
                    "send",
                    (var("socket"), var("buffer"), length, const(0)),
                ),
            ],
        )
        parameter = FunctionIR(
            ea=0x2000,
            name="send_response",
            parameters=("socket", "buffer", "length"),
            statements=[
                Call(
                    1,
                    0x2010,
                    "send",
                    (var("socket"), var("buffer"), length, const(0)),
                )
            ],
        )
        self.assertNotIn("INIT-001", self.rule_ids(defined))
        self.assertNotIn("INIT-001", self.rule_ids(parameter))

    def test_input_api_split_stack_length_is_not_called_uninitialized(self):
        # Hex-Rays can split a structure-wide receive into adjacent scalar
        # lvars; absence of a scalar assignment alone is not proof that a
        # recv/read length was uninitialized.
        length = Expr(
            kind="var", text="header.length", key="length", bits=32, signed=False
        )
        ir = FunctionIR(
            ea=0x1000,
            name="receive_payload",
            parameters=("socket",),
            statements=[
                Call(
                    1,
                    0x1010,
                    "recv",
                    (var("socket"), var("header"), const(16), const(0)),
                ),
                Call(
                    2,
                    0x1020,
                    "recv",
                    (var("socket"), var("payload"), length, const(0)),
                ),
            ],
        )
        self.assertNotIn("INIT-001", self.rule_ids(ir))

    def test_tainted_integer_truncation(self):
        wide = Expr(kind="var", text="wide", key="wide", bits=64, signed=False)
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=16, signed=False
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), wide, const(8))),
            Assignment(2, 0x1020, narrow, wide),
        )
        self.assertIn("INT-001", self.rule_ids(ir))

    def test_constant_mask_proves_narrow_value_fits(self):
        wide = Expr(kind="var", text="wide", key="wide", bits=64, signed=True)
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=32, signed=True
        )
        masked = Expr(
            kind="op",
            text="wide & 3",
            op="and",
            children=(wide, const(3)),
            bits=64,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), wide, const(8))),
            Assignment(2, 0x1020, narrow, masked),
        )
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_wide_output_aggregate_lane_is_not_integer_truncation(self):
        wide = Expr(
            kind="var", text="wide_result", key="wide", bits=128, signed=False
        )
        low = Expr(kind="var", text="low", key="low", bits=64, signed=False)
        high = Expr(
            kind="deref",
            text="*((uint64_t *)&wide_result + 1)",
            key="wide",
            children=(
                Expr(
                    kind="address",
                    text="&wide_result",
                    key="wide",
                    children=(wide,),
                    bits=64,
                    signed=False,
                ),
            ),
            offset=8,
            bits=64,
            signed=False,
        )
        ir = function(
            Call(
                1,
                0x1010,
                "fill_pair",
                (
                    Expr(
                        kind="address",
                        text="&wide_result",
                        key="wide",
                        children=(wide,),
                    ),
                ),
            ),
            Assignment(2, 0x1020, low, wide),
            Assignment(3, 0x1030, var("high"), high),
            Call(4, 0x1040, "read", (const(0), wide, const(16))),
        )
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_pointer_cast_inside_tainted_length_load_is_not_truncation(self):
        aggregate = Expr(
            kind="var",
            text="stack_object",
            key="stack_object",
            bits=288,
            signed=False,
        )
        pointer = Expr(
            kind="cast",
            text="(unsigned int *)stack_object",
            children=(aggregate,),
            bits=64,
            signed=False,
        )
        length = Expr(
            kind="deref",
            text="*(unsigned int *)stack_object",
            key="stack_object",
            children=(pointer,),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), aggregate, const(4))),
            Call(2, 0x1020, "read", (const(0), var("destination"), length)),
            buffers=(BufferInfo("destination", "destination", "stack", 32),),
        )
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_unsigned_read_result_with_negative_one_check_is_safe(self):
        result = Expr(
            kind="var", text="result", key="result", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buf, 32)",
            callee="read",
            children=(var("fd"), var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        sentinel = Expr(
            kind="op",
            text="result == -1",
            op="eq",
            children=(result, const(-1)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="checked_read_result",
            statements=[
                Assignment(1, 0x1010, result, read_result, block_id=0),
                Return(3, 0x1030, const(0), block_id=1, guards=(sentinel,)),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, successors=(1, 2)),
                1: BasicBlock(1, 0x1020, 0x1040, predecessors=(0,)),
                2: BasicBlock(2, 0x1040, 0x1050, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1018, 0, sentinel, sentinel.text, order=2)],
        )
        self.assertNotIn("INT-002", self.rule_ids(ir))

    def test_read_result_used_before_negative_one_check_remains_unsafe(self):
        result = Expr(
            kind="var", text="result", key="result", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buf, 32)",
            callee="read",
            children=(var("fd"), var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        sentinel = Expr(
            kind="op",
            text="result == -1",
            op="eq",
            children=(result, const(-1)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="late_read_result_check",
            statements=[
                Assignment(1, 0x1010, result, read_result),
                Call(2, 0x1020, "consume", (result,)),
                Return(4, 0x1040, const(0), guards=(sentinel,)),
            ],
            conditions=[Condition(0x1030, None, sentinel, sentinel.text, order=3)],
        )
        self.assertIn("INT-002", self.rule_ids(ir))

    def test_unchecked_read_error_reaching_allocation_has_specific_rule(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buf, 32)",
            callee="read",
            children=(var("fd"), var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        ir = function(
            Assignment(1, 0x1010, count, read_result),
            Assignment(2, 0x1020, var("allocation"), call_expr("malloc", count)),
        )
        findings = self.analyzer.analyze_function(ir)
        error = next(item for item in findings if item.rule_id == "ERR-001")
        self.assertEqual(error.ea, 0x1020)
        self.assertEqual(error.callee, "malloc")
        self.assertIn("converted_sentinel=18446744073709551615", error.evidence)
        self.assertNotIn("INT-002", [item.rule_id for item in findings])

    def test_assigned_bounded_call_is_one_error_size_sink(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, input, 32)",
            callee="read",
            children=(var("fd"), var("input"), const(32)),
            bits=64,
            signed=True,
        )
        copy = Expr(
            kind="call",
            text="memcpy(destination, source, count)",
            callee="memcpy",
            children=(var("destination"), var("source"), count),
        )
        ir = function(
            Assignment(1, 0x1010, count, read_result),
            Assignment(2, 0x1020, var("result"), copy),
            Call(
                3,
                0x101C,
                "memcpy",
                (var("destination"), var("source"), count),
                text=copy.text,
            ),
        )
        findings = [
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "ERR-001"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ea, 0x1020)
        self.assertEqual(findings[0].callee, "memcpy")

    def test_error_return_contract_crosses_reader_and_allocator_wrappers(self):
        fd = Expr(kind="var", text="fd", key="fd", bits=32, signed=True)
        destination = Expr(
            kind="var",
            text="destination",
            key="destination",
            bits=64,
            signed=False,
            is_pointer=True,
        )
        limit = Expr(
            kind="var", text="limit", key="limit", bits=64, signed=False
        )
        reader = FunctionIR(
            ea=0x2000,
            name="receive_wrapper",
            parameters=("fd", "destination", "limit"),
            statements=[
                Return(
                    1,
                    0x2010,
                    Expr(
                        kind="call",
                        text="read(fd, destination, limit)",
                        callee="read",
                        children=(fd, destination, limit),
                        bits=64,
                        signed=True,
                    ),
                )
            ],
        )
        size = Expr(
            kind="var", text="size", key="size", bits=64, signed=False
        )
        allocator = FunctionIR(
            ea=0x2100,
            name="allocate_wrapper",
            parameters=("size",),
            statements=[Return(1, 0x2110, call_expr("malloc", size))],
        )
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        wrapped_read = Expr(
            kind="call",
            text="receive_wrapper(fd, buf, 32)",
            callee="receive_wrapper",
            callee_ea=reader.ea,
            children=(fd, var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        wrapped_allocation = Expr(
            kind="call",
            text="allocate_wrapper(count)",
            callee="allocate_wrapper",
            callee_ea=allocator.ea,
            children=(count,),
            bits=64,
            signed=False,
            is_pointer=True,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="wrapper_caller",
            statements=[
                Assignment(1, 0x3010, count, wrapped_read),
                Assignment(2, 0x3020, var("allocation"), wrapped_allocation),
            ],
        )
        summaries = SummaryBuilder().build([reader, allocator, caller])
        reader_summary = summaries.lookup(reader.name, reader.ea)
        self.assertIsNotNone(reader_summary)
        self.assertEqual(reader_summary.return_error_sentinel, -1)
        self.assertEqual(reader_summary.return_success_upper.argument, 2)
        finding = next(
            item
            for item in Analyzer.analyze_program([reader, allocator, caller])
            if item.rule_id == "ERR-001"
        )
        self.assertEqual(finding.function_name, caller.name)
        self.assertEqual(finding.callee, "malloc")
        self.assertIn("source=receive_wrapper", finding.evidence)
        self.assertIn("wrapper=allocate_wrapper", finding.evidence)

    def test_error_return_summary_composes_through_two_reader_layers(self):
        parameters = tuple(var(name) for name in ("fd", "destination", "limit"))
        inner = FunctionIR(
            ea=0x2200,
            name="inner_reader",
            parameters=tuple(item.key for item in parameters),
            statements=[
                Return(
                    1,
                    0x2210,
                    Expr(
                        kind="call",
                        text="read(fd, destination, limit)",
                        callee="read",
                        children=parameters,
                        bits=64,
                        signed=True,
                    ),
                )
            ],
        )
        outer = FunctionIR(
            ea=0x2300,
            name="outer_reader",
            parameters=inner.parameters,
            statements=[
                Return(
                    1,
                    0x2310,
                    Expr(
                        kind="call",
                        text="inner_reader(fd, destination, limit)",
                        callee="inner_reader",
                        callee_ea=inner.ea,
                        children=parameters,
                        bits=64,
                        signed=True,
                    ),
                )
            ],
        )
        summaries = SummaryBuilder().build([outer, inner])
        summary = summaries.lookup(outer.name, outer.ea)
        self.assertIsNotNone(summary)
        self.assertEqual(summary.return_error_sentinel, -1)
        self.assertEqual(summary.return_success_upper.argument, 2)

    def test_size_max_rejection_suppresses_error_return_flow(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buf, 32)",
            callee="read",
            children=(var("fd"), var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        sentinel = Expr(
            kind="op",
            text="count == SIZE_MAX",
            op="eq",
            children=(count, const((1 << 64) - 1)),
            bits=1,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="checked_unsigned_read",
            statements=[
                Assignment(1, 0x1010, count, read_result, block_id=0),
                Return(3, 0x1030, const(0), block_id=1, guards=(sentinel,)),
                Assignment(
                    4,
                    0x1040,
                    var("allocation"),
                    call_expr("malloc", count),
                    block_id=2,
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, successors=(1, 2)),
                1: BasicBlock(1, 0x1020, 0x1040, predecessors=(0,)),
                2: BasicBlock(2, 0x1040, 0x1050, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1018, 0, sentinel, sentinel.text, order=2)],
        )
        rules = self.rule_ids(ir)
        self.assertNotIn("ERR-001", rules)
        self.assertNotIn("INT-002", rules)

        accepted = Expr(
            kind="op",
            text="count != -1",
            op="ne",
            children=(count, const(-1)),
            bits=1,
            signed=False,
        )
        accepted_ir = FunctionIR(
            ea=0x1100,
            name="accepted_unsigned_read",
            statements=[
                Assignment(1, 0x1110, count, read_result),
                Assignment(
                    3,
                    0x1130,
                    var("allocation"),
                    call_expr("malloc", count),
                    guards=(accepted,),
                ),
            ],
            conditions=[Condition(0x1120, None, accepted, accepted.text, order=2)],
        )
        accepted_rules = self.rule_ids(accepted_ir)
        self.assertNotIn("ERR-001", accepted_rules)
        self.assertNotIn("INT-002", accepted_rules)

    def test_signed_negative_rejection_before_conversion_is_safe(self):
        result = Expr(
            kind="var", text="result", key="result", bits=64, signed=True
        )
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buf, 32)",
            callee="read",
            children=(var("fd"), var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        negative = Expr(
            kind="op",
            text="result < 0",
            op="slt",
            children=(result, const(0)),
            bits=1,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="checked_signed_read",
            statements=[
                Assignment(1, 0x1010, result, read_result, block_id=0),
                Return(3, 0x1030, const(0), block_id=1, guards=(negative,)),
                Assignment(4, 0x1040, count, result, block_id=2),
                Assignment(
                    5,
                    0x1050,
                    var("allocation"),
                    call_expr("malloc", count),
                    block_id=2,
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, successors=(1, 2)),
                1: BasicBlock(1, 0x1020, 0x1040, predecessors=(0,)),
                2: BasicBlock(2, 0x1040, 0x1060, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1018, 0, negative, negative.text, order=2)],
        )
        rules = self.rule_ids(ir)
        self.assertNotIn("ERR-001", rules)
        self.assertNotIn("INT-002", rules)

    def test_error_return_follows_alias_but_not_redefined_target(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        alias = Expr(
            kind="var", text="alias", key="alias", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buf, 32)",
            callee="read",
            children=(var("fd"), var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        aliased = function(
            Assignment(1, 0x1010, count, read_result),
            Assignment(2, 0x1020, alias, count),
            Call(3, 0x1030, "memcpy", (var("dst"), var("src"), alias)),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(aliased)
            if item.rule_id == "ERR-001"
        )
        self.assertEqual(finding.callee, "memcpy")

        redefined = function(
            Assignment(1, 0x1010, count, read_result),
            Assignment(2, 0x1020, count, const(8)),
            Assignment(3, 0x1030, var("allocation"), call_expr("malloc", count)),
        )
        self.assertNotIn("ERR-001", self.rule_ids(redefined))

    def test_late_error_check_does_not_protect_earlier_size_sink(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buf, 32)",
            callee="read",
            children=(var("fd"), var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        sentinel = Expr(
            kind="op",
            text="count == SIZE_MAX",
            op="eq",
            children=(count, const((1 << 64) - 1)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="late_size_check",
            statements=[
                Assignment(1, 0x1010, count, read_result),
                Assignment(2, 0x1020, var("allocation"), call_expr("malloc", count)),
                Return(4, 0x1040, const(0), guards=(sentinel,)),
            ],
            conditions=[Condition(0x1030, None, sentinel, sentinel.text, order=3)],
        )
        findings = self.analyzer.analyze_function(ir)
        self.assertTrue(
            any(item.rule_id == "ERR-001" and item.ea == 0x1020 for item in findings)
        )

    def test_explicit_unsigned_cast_error_reaching_array_index_is_detected(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buf, 32)",
            callee="read",
            children=(var("fd"), var("buf"), const(32)),
            bits=64,
            signed=True,
        )
        cast_result = Expr(
            kind="cast",
            text="(size_t)read(fd, buf, 32)",
            children=(read_result,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        indexed = Expr(
            kind="index",
            text="table[count]",
            key="table",
            children=(var("table"), count),
            bits=8,
            signed=False,
        )
        ir = function(
            Assignment(1, 0x1010, count, cast_result),
            Assignment(2, 0x1020, var("value"), indexed),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "ERR-001"
        )
        self.assertEqual(finding.callee, "array index")
        self.assertEqual(finding.ea, 0x1020)

    def test_error_return_tracks_exact_record_field_not_sibling_guard(self):
        record = Expr(
            kind="var",
            text="record",
            key="record",
            bits=64,
            signed=False,
            is_pointer=True,
        )
        count = Expr(
            kind="member",
            text="record->count",
            key="record",
            children=(record,),
            offset=8,
            bits=64,
            signed=False,
            is_pointer=False,
        )
        status = replace(
            count,
            text="record->status",
            offset=16,
        )
        read_result = Expr(
            kind="call",
            text="read(fd, buffer, 32)",
            callee="read",
            children=(var("fd"), var("buffer"), const(32)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        sibling_guard = Expr(
            kind="op",
            text="record->status != -1",
            op="ne",
            children=(status, const(-1)),
            bits=1,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="record_error_size",
            statements=[
                Assignment(1, 0x1010, count, read_result),
                Assignment(
                    3,
                    0x1030,
                    var("allocation"),
                    call_expr("malloc", count),
                    guards=(sibling_guard,),
                ),
            ],
            conditions=[
                Condition(
                    0x1020,
                    None,
                    sibling_guard,
                    sibling_guard.text,
                    order=2,
                )
            ],
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "ERR-001"
        )
        self.assertEqual(finding.ea, 0x1030)
        self.assertIn("converted_value=record->count", finding.evidence)

    def test_exact_record_field_guard_and_redefinition_are_safe(self):
        record = Expr(
            kind="var",
            text="record",
            key="record",
            bits=64,
            signed=False,
            is_pointer=True,
        )
        count = Expr(
            kind="member",
            text="record->count",
            key="record",
            children=(record,),
            offset=8,
            bits=64,
            signed=False,
            is_pointer=False,
        )
        read_result = Expr(
            kind="call",
            text="recv(fd, buffer, 32, 0)",
            callee="recv",
            children=(var("fd"), var("buffer"), const(32), const(0)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        accepted = Expr(
            kind="op",
            text="record->count != -1",
            op="ne",
            children=(count, const(-1)),
            bits=1,
            signed=False,
        )
        guarded = FunctionIR(
            ea=0x1000,
            name="guarded_record_error",
            statements=[
                Assignment(1, 0x1010, count, read_result),
                Assignment(
                    3,
                    0x1030,
                    var("allocation"),
                    call_expr("malloc", count),
                    guards=(accepted,),
                ),
            ],
            conditions=[Condition(0x1020, None, accepted, accepted.text, order=2)],
        )
        self.assertNotIn("ERR-001", self.rule_ids(guarded))

        redefined = function(
            Assignment(1, 0x1010, count, read_result),
            Assignment(2, 0x1020, count, const(16)),
            Assignment(3, 0x1030, var("allocation"), call_expr("malloc", count)),
        )
        self.assertNotIn("ERR-001", self.rule_ids(redefined))

        sibling = replace(count, text="record->status", offset=16)
        sibling_write = function(
            Assignment(1, 0x1010, count, read_result),
            Assignment(2, 0x1020, sibling, const(0)),
            Assignment(3, 0x1030, var("allocation"), call_expr("malloc", count)),
        )
        self.assertIn("ERR-001", self.rule_ids(sibling_write))

    def test_error_return_record_field_flows_through_scalar_alias(self):
        record = Expr(
            kind="var", text="record", key="record", is_pointer=True
        )
        field = Expr(
            kind="member",
            text="record->count",
            key="record",
            children=(record,),
            offset=8,
            bits=64,
            signed=False,
            is_pointer=False,
        )
        alias = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        source = Expr(
            kind="call",
            text="read(fd, buffer, 64)",
            callee="read",
            children=(var("fd"), var("buffer"), const(64)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        ir = function(
            Assignment(1, 0x1010, field, source),
            Assignment(2, 0x1020, alias, field),
            Call(3, 0x1030, "memcpy", (var("dst"), var("src"), alias)),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "ERR-001"
        )
        self.assertEqual(finding.callee, "memcpy")

    def test_error_output_parameter_reaches_caller_allocation(self):
        output = Expr(
            kind="var",
            text="output",
            key="output",
            bits=64,
            signed=False,
            is_pointer=True,
        )
        destination = Expr(
            kind="var",
            text="destination",
            key="destination",
            bits=64,
            signed=False,
            is_pointer=True,
        )
        limit = Expr(
            kind="var", text="limit", key="limit", bits=64, signed=False
        )
        output_slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        read_result = Expr(
            kind="call",
            text="read(0, destination, limit)",
            callee="read",
            children=(const(0), destination, limit),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        wrapper = FunctionIR(
            ea=0x2000,
            name="read_count_output",
            parameters=("output", "destination", "limit"),
            statements=[Assignment(1, 0x2010, output_slot, read_result)],
        )
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        count_address = Expr(
            kind="address",
            text="&count",
            key="count",
            children=(count,),
            bits=64,
            signed=False,
            is_pointer=True,
        )
        enlarged = Expr(
            kind="op",
            text="count + 16",
            op="add",
            children=(count, const(16)),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="output_caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    wrapper.name,
                    (count_address, var("buffer"), const(32)),
                    callee_ea=wrapper.ea,
                ),
                Assignment(
                    2,
                    0x3020,
                    var("allocation"),
                    call_expr("malloc", enlarged),
                ),
            ],
        )
        summaries = SummaryBuilder().build([wrapper, caller])
        summary = summaries.lookup(wrapper.name, wrapper.ea)
        self.assertIsNotNone(summary)
        self.assertEqual(len(summary.error_outputs), 1)
        self.assertEqual(summary.error_outputs[0].destination.argument, 0)
        self.assertEqual(summary.error_outputs[0].error_sentinel, -1)
        self.assertEqual(summary.error_outputs[0].success_upper.argument, 2)
        findings = Analyzer.analyze_program([wrapper, caller])
        caller_rules = {
            item.rule_id
            for item in findings
            if item.function_name == caller.name
        }
        self.assertIn("ERR-001", caller_rules)
        self.assertNotIn("INT-005", caller_rules)
        self.assertFalse(
            any(
                item.rule_id == "INT-002"
                and item.function_name == wrapper.name
                for item in findings
            )
        )

    def test_error_output_summary_composes_into_record_field(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        destination = Expr(
            kind="var", text="destination", key="destination", is_pointer=True
        )
        limit = Expr(
            kind="var", text="limit", key="limit", bits=64, signed=False
        )
        inner = FunctionIR(
            ea=0x2000,
            name="inner_count_output",
            parameters=("output", "destination", "limit"),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    Expr(
                        kind="deref",
                        text="*output",
                        key="output",
                        children=(output,),
                        bits=64,
                        signed=False,
                        is_pointer=False,
                    ),
                    Expr(
                        kind="call",
                        text="recv(0, destination, limit, 0)",
                        callee="recv",
                        children=(const(0), destination, limit, const(0)),
                        bits=64,
                        signed=True,
                        is_pointer=False,
                    ),
                )
            ],
        )
        outer = FunctionIR(
            ea=0x2100,
            name="outer_count_output",
            parameters=inner.parameters,
            statements=[
                Call(
                    1,
                    0x2110,
                    inner.name,
                    (output, destination, limit),
                    callee_ea=inner.ea,
                )
            ],
        )
        record = Expr(
            kind="var", text="record", key="record", is_pointer=True
        )
        count_field = Expr(
            kind="member",
            text="record->count",
            key="record",
            children=(record,),
            offset=8,
            bits=64,
            signed=False,
            is_pointer=False,
        )
        field_address = Expr(
            kind="address",
            text="&record->count",
            key="record",
            children=(count_field,),
            bits=64,
            signed=False,
            is_pointer=True,
        )
        enlarged_count = Expr(
            kind="op",
            text="record->count + 16",
            op="add",
            children=(count_field, const(16)),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        caller = FunctionIR(
            ea=0x3000,
            name="record_output_caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    outer.name,
                    (field_address, var("buffer"), const(64)),
                    callee_ea=outer.ea,
                ),
                Assignment(
                    2,
                    0x3020,
                    var("allocation"),
                    call_expr("malloc", enlarged_count),
                ),
            ],
        )
        summaries = SummaryBuilder().build([outer, inner, caller])
        outer_summary = summaries.lookup(outer.name, outer.ea)
        self.assertIsNotNone(outer_summary)
        self.assertEqual(len(outer_summary.error_outputs), 1)
        findings = Analyzer.analyze_program([outer, inner, caller])
        finding = next(
            item
            for item in findings
            if item.rule_id == "ERR-001"
            and item.function_name == caller.name
        )
        self.assertIn("converted_value=record->count", finding.evidence)
        self.assertFalse(
            any(
                item.rule_id == "INT-005"
                and item.function_name == caller.name
                for item in findings
            )
        )

    def test_conditional_or_overwritten_error_output_is_not_exported(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        source = Expr(
            kind="call",
            text="read(0, buffer, 32)",
            callee="read",
            children=(const(0), var("buffer"), const(32)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        guard = Expr(kind="var", text="enabled", key="enabled")
        conditional = FunctionIR(
            ea=0x2000,
            name="conditional_output",
            parameters=("output",),
            statements=[
                Assignment(1, 0x2010, slot, source, guards=(guard,))
            ],
        )
        overwritten = FunctionIR(
            ea=0x2100,
            name="overwritten_output",
            parameters=("output",),
            statements=[
                Assignment(1, 0x2110, slot, source),
                Assignment(2, 0x2120, slot, const(0)),
            ],
        )
        summaries = SummaryBuilder().build([conditional, overwritten])
        conditional_summary = summaries.lookup(conditional.name)
        overwritten_summary = summaries.lookup(overwritten.name)
        self.assertTrue(
            conditional_summary is None or not conditional_summary.error_outputs
        )
        self.assertTrue(
            overwritten_summary is None or not overwritten_summary.error_outputs
        )

        producer = FunctionIR(
            ea=0x2200,
            name="direct_output",
            parameters=("output",),
            statements=[Assignment(1, 0x2210, slot, source)],
        )
        outer = FunctionIR(
            ea=0x2300,
            name="overwriting_outer_output",
            parameters=("output",),
            statements=[
                Call(
                    1,
                    0x2310,
                    producer.name,
                    (output,),
                    callee_ea=producer.ea,
                ),
                Assignment(2, 0x2320, slot, const(0)),
            ],
        )
        nested_summaries = SummaryBuilder().build([producer, outer])
        producer_summary = nested_summaries.lookup(producer.name)
        outer_summary = nested_summaries.lookup(outer.name)
        self.assertIsNotNone(producer_summary)
        self.assertTrue(producer_summary.error_outputs)
        self.assertTrue(outer_summary is None or not outer_summary.error_outputs)

    def test_error_output_call_clobbers_are_field_and_path_sensitive(self):
        output = Expr(
            kind="var",
            text="output",
            key="output",
            bits=64,
            signed=False,
            is_pointer=True,
        )
        slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        source = Expr(
            kind="call",
            text="read(0, buffer, 32)",
            callee="read",
            children=(const(0), var("buffer"), const(32)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        conversion = Assignment(1, 0x2010, slot, source)

        def summary_for(
            name: str,
            *following: Assignment | Call,
            blocks: dict[int, BasicBlock] | None = None,
        ):
            first = (
                replace(conversion, block_id=0)
                if blocks is not None
                else conversion
            )
            candidate = FunctionIR(
                ea=0x2000,
                name=name,
                parameters=("output",),
                statements=[first, *following],
                blocks=blocks or {},
                entry_block=0 if blocks is not None else None,
            )
            return SummaryBuilder().build([candidate]).lookup(
                candidate.name, candidate.ea
            )

        overwritten = summary_for(
            "memset_overwrites_error_output",
            Call(2, 0x2020, "memset", (output, const(0), const(8))),
        )
        self.assertTrue(overwritten is None or not overwritten.error_outputs)

        readonly = summary_for(
            "memcmp_preserves_error_output",
            Call(2, 0x2020, "memcmp", (output, var("peer"), const(8))),
        )
        self.assertIsNotNone(readonly)
        self.assertTrue(readonly.error_outputs)

        zero_write = summary_for(
            "zero_memset_preserves_error_output",
            Call(2, 0x2020, "memset", (output, const(0), const(0))),
        )
        self.assertIsNotNone(zero_write)
        self.assertTrue(zero_write.error_outputs)

        zero_capable_read = summary_for(
            "read_may_leave_error_output_unchanged",
            Call(2, 0x2020, "read", (const(0), output, const(8))),
        )
        self.assertIsNotNone(zero_capable_read)
        self.assertTrue(zero_capable_read.error_outputs)

        zero_conversion_scanf = summary_for(
            "scanf_may_leave_error_output_unchanged",
            Call(2, 0x2020, "scanf", (string("%zu"), output)),
        )
        self.assertIsNotNone(zero_conversion_scanf)
        self.assertTrue(zero_conversion_scanf.error_outputs)

        for may_write_name, arguments in (
            ("recv", (const(0), output, const(8), const(0))),
            ("fread", (output, const(1), const(8), var("stream"))),
            ("getrandom", (output, const(8), const(0))),
            ("snprintf", (output, const(8), string("%s"), string("x"))),
            ("strncat", (output, string("x"), const(8))),
        ):
            with self.subTest(may_write=may_write_name):
                may_write = summary_for(
                    f"{may_write_name}_may_leave_error_output_unchanged",
                    Call(2, 0x2020, may_write_name, arguments),
                )
                self.assertIsNotNone(may_write)
                self.assertTrue(may_write.error_outputs)

        sibling_pointer = Expr(
            kind="op",
            text="output + 8",
            key="output",
            op="add",
            children=(output, const(8)),
            offset=8,
            bits=64,
            signed=False,
            is_pointer=True,
        )
        sibling = summary_for(
            "sibling_memset_preserves_error_output",
            Call(
                2,
                0x2020,
                "memset",
                (sibling_pointer, const(0), const(8)),
            ),
        )
        self.assertIsNotNone(sibling)
        self.assertTrue(sibling.error_outputs)

        overlapping_pointer = replace(
            sibling_pointer,
            text="output + 4",
            children=(output, const(4)),
            offset=4,
        )
        overlapping = summary_for(
            "overlapping_memset_kills_error_output",
            Call(
                2,
                0x2020,
                "memset",
                (overlapping_pointer, const(0), const(8)),
            ),
        )
        self.assertTrue(overlapping is None or not overlapping.error_outputs)

        unknown = summary_for(
            "unknown_pointer_call_kills_error_output",
            Call(2, 0x2020, "mutate_output", (output,)),
        )
        self.assertTrue(unknown is None or not unknown.error_outputs)

        inspected_reader = FunctionIR(
            ea=0x2050,
            name="inspected_readonly_output",
            parameters=("output",),
        )
        known_readonly_wrapper = FunctionIR(
            ea=0x2060,
            name="known_readonly_call_preserves_error_output",
            parameters=("output",),
            statements=[
                conversion,
                Call(
                    2,
                    0x2070,
                    inspected_reader.name,
                    (output,),
                    callee_ea=inspected_reader.ea,
                ),
            ],
        )
        known_readonly = SummaryBuilder().build(
            [inspected_reader, known_readonly_wrapper]
        ).lookup(known_readonly_wrapper.name, known_readonly_wrapper.ea)
        self.assertIsNotNone(known_readonly)
        self.assertTrue(known_readonly.error_outputs)

        may_write_reader = FunctionIR(
            ea=0x2080,
            name="zero_capable_read_wrapper",
            parameters=("output",),
            statements=[
                Call(1, 0x2088, "read", (const(0), output, const(8)))
            ],
        )
        may_write_outer = FunctionIR(
            ea=0x2090,
            name="nested_zero_capable_read_preserves_error_output",
            parameters=("output",),
            statements=[
                conversion,
                Call(
                    2,
                    0x2098,
                    may_write_reader.name,
                    (output,),
                    callee_ea=may_write_reader.ea,
                ),
            ],
        )
        may_write_summaries = SummaryBuilder().build(
            [may_write_reader, may_write_outer]
        )
        may_write_reader_summary = may_write_summaries.lookup(
            may_write_reader.name, may_write_reader.ea
        )
        may_write_outer_summary = may_write_summaries.lookup(
            may_write_outer.name, may_write_outer.ea
        )
        self.assertIsNotNone(may_write_reader_summary)
        self.assertTrue(may_write_reader_summary.writes)
        self.assertFalse(may_write_reader_summary.writes[0].must_write)
        self.assertIsNotNone(may_write_outer_summary)
        self.assertTrue(may_write_outer_summary.error_outputs)

        before = FunctionIR(
            ea=0x2100,
            name="error_output_replaces_older_clean_store",
            parameters=("output",),
            statements=[
                Assignment(1, 0x2110, slot, const(0)),
                replace(conversion, order=2, ea=0x2120),
            ],
        )
        before_summary = SummaryBuilder().build([before]).lookup(
            before.name, before.ea
        )
        self.assertIsNotNone(before_summary)
        self.assertTrue(before_summary.error_outputs)

        producer = FunctionIR(
            ea=0x2200,
            name="nested_error_output_producer",
            parameters=("output",),
            statements=[conversion],
        )
        nested_after_clean = FunctionIR(
            ea=0x2300,
            name="nested_error_replaces_clean_output",
            parameters=("output",),
            statements=[
                Assignment(1, 0x2310, slot, const(0)),
                Call(
                    2,
                    0x2320,
                    producer.name,
                    (output,),
                    callee_ea=producer.ea,
                ),
            ],
        )
        nested_summary = SummaryBuilder().build(
            [producer, nested_after_clean]
        ).lookup(nested_after_clean.name, nested_after_clean.ea)
        self.assertIsNotNone(nested_summary)
        self.assertTrue(nested_summary.error_outputs)

        flag = Expr(kind="var", text="flag", key="flag")
        branch_blocks = {
            0: BasicBlock(0, 0x2000, 0x2018, successors=(1, 2)),
            1: BasicBlock(1, 0x2020, 0x2030, predecessors=(0,)),
            2: BasicBlock(2, 0x2030, 0x2040, predecessors=(0,)),
        }
        first_branch = Call(
            2,
            0x2020,
            "memset",
            (output, const(0), const(8)),
            block_id=1,
            guards=(flag,),
        )
        partial = summary_for(
            "one_branch_preserves_error_output",
            first_branch,
            blocks=branch_blocks,
        )
        self.assertIsNotNone(partial)
        self.assertTrue(partial.error_outputs)

        second_branch = replace(
            first_branch,
            order=3,
            ea=0x2030,
            block_id=2,
            guards=(replace(flag, text="!flag"),),
        )
        complete = summary_for(
            "both_branches_kill_error_output",
            first_branch,
            second_branch,
            blocks=branch_blocks,
        )
        self.assertTrue(complete is None or not complete.error_outputs)

    def test_checked_redefined_or_clobbered_error_output_is_safe(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        wrapper = FunctionIR(
            ea=0x2000,
            name="read_output_for_safe_callers",
            parameters=("output",),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    slot,
                    Expr(
                        kind="call",
                        text="read(0, buffer, 32)",
                        callee="read",
                        children=(const(0), var("buffer"), const(32)),
                        bits=64,
                        signed=True,
                        is_pointer=False,
                    ),
                )
            ],
        )
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        count_address = Expr(
            kind="address",
            text="&count",
            key="count",
            children=(count,),
            bits=64,
            signed=False,
            is_pointer=True,
        )
        accepted = Expr(
            kind="op",
            text="count != SIZE_MAX",
            op="ne",
            children=(count, const((1 << 64) - 1)),
            bits=1,
            signed=False,
        )

        checked = FunctionIR(
            ea=0x3000,
            name="checked_output_caller",
            statements=[
                Call(
                    1,
                    0x3010,
                    wrapper.name,
                    (count_address,),
                    callee_ea=wrapper.ea,
                ),
                Assignment(
                    3,
                    0x3030,
                    var("allocation"),
                    call_expr("malloc", count),
                    guards=(accepted,),
                ),
            ],
            conditions=[Condition(0x3020, None, accepted, accepted.text, order=2)],
        )
        redefined = FunctionIR(
            ea=0x3100,
            name="redefined_output_caller",
            statements=[
                Call(
                    1,
                    0x3110,
                    wrapper.name,
                    (count_address,),
                    callee_ea=wrapper.ea,
                ),
                Assignment(2, 0x3120, count, const(16)),
                Assignment(
                    3,
                    0x3130,
                    var("allocation"),
                    call_expr("malloc", count),
                ),
            ],
        )
        clobbered = FunctionIR(
            ea=0x3200,
            name="clobbered_output_caller",
            statements=[
                Call(
                    1,
                    0x3210,
                    wrapper.name,
                    (count_address,),
                    callee_ea=wrapper.ea,
                ),
                Call(2, 0x3220, "mutate_count", (count_address,)),
                Assignment(
                    3,
                    0x3230,
                    var("allocation"),
                    call_expr("malloc", count),
                ),
            ],
        )
        findings = Analyzer.analyze_program(
            [wrapper, checked, redefined, clobbered]
        )
        safe_callers = {
            checked.name,
            redefined.name,
            clobbered.name,
        }
        self.assertFalse(
            any(
                item.rule_id == "ERR-001"
                and item.function_name in safe_callers
                for item in findings
            )
        )

    def test_dynamic_error_output_clobber_requires_a_positive_lower_bound(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        source = Expr(
            kind="call",
            text="read(0, buffer, 32)",
            callee="read",
            children=(const(0), var("buffer"), const(32)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        origin = Assignment(1, 0x4010, slot, source, block_id=0)
        length = Expr(
            kind="var",
            text="length",
            key="length",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        enough = Expr(
            kind="op",
            text="length >= 8",
            op="uge",
            children=(length, const(8)),
            bits=1,
            signed=False,
            is_pointer=False,
        )
        short = Expr(
            kind="op",
            text="length < 8",
            op="ult",
            children=(length, const(8)),
            bits=1,
            signed=False,
            is_pointer=False,
        )

        unknown = FunctionIR(
            ea=0x4000,
            name="unknown_dynamic_memset_preserves_error_output",
            parameters=("output", "length"),
            statements=[
                replace(origin, block_id=None),
                Call(2, 0x4020, "memset", (output, const(0), length)),
            ],
        )
        unknown_summary = SummaryBuilder().build([unknown]).lookup(
            unknown.name, unknown.ea
        )
        self.assertIsNotNone(unknown_summary)
        self.assertTrue(unknown_summary.error_outputs)

        branch_blocks = {
            0: BasicBlock(0, 0x4000, 0x4018, successors=(1, 2)),
            1: BasicBlock(1, 0x4020, 0x4030, predecessors=(0,)),
            2: BasicBlock(2, 0x4030, 0x4040, predecessors=(0,)),
        }
        bounded = FunctionIR(
            ea=0x4100,
            name="guarded_dynamic_memset_clobbers_error_output",
            parameters=("output", "length"),
            statements=[
                replace(origin, ea=0x4110),
                Call(
                    2,
                    0x4120,
                    "memset",
                    (output, const(0), length),
                    block_id=1,
                    guards=(enough,),
                ),
                Call(
                    3,
                    0x4130,
                    "memset",
                    (output, const(0), const(8)),
                    block_id=2,
                    guards=(short,),
                ),
            ],
            blocks=branch_blocks,
            entry_block=0,
            conditions=[Condition(0x4118, 0, enough, enough.text, order=1)],
        )
        bounded_summary = SummaryBuilder().build([bounded]).lookup(
            bounded.name, bounded.ea
        )
        self.assertTrue(
            bounded_summary is None or not bounded_summary.error_outputs
        )

        clearer = FunctionIR(
            ea=0x4200,
            name="dynamic_memset_wrapper",
            parameters=("output", "length"),
            statements=[
                Call(1, 0x4210, "memset", (output, const(0), length))
            ],
        )
        clearer_summary = SummaryBuilder().build([clearer]).lookup(
            clearer.name, clearer.ea
        )
        self.assertIsNotNone(clearer_summary)
        self.assertEqual(len(clearer_summary.writes), 1)
        self.assertTrue(clearer_summary.writes[0].must_write)

        nested_unknown = FunctionIR(
            ea=0x4300,
            name="nested_unknown_dynamic_memset_preserves_error_output",
            parameters=("output", "length"),
            statements=[
                replace(origin, ea=0x4310, block_id=None),
                Call(
                    2,
                    0x4320,
                    clearer.name,
                    (output, length),
                    callee_ea=clearer.ea,
                ),
            ],
        )
        nested_unknown_summary = SummaryBuilder().build(
            [clearer, nested_unknown]
        ).lookup(nested_unknown.name, nested_unknown.ea)
        self.assertIsNotNone(nested_unknown_summary)
        self.assertTrue(nested_unknown_summary.error_outputs)

        nested_bounded = FunctionIR(
            ea=0x4400,
            name="nested_guarded_dynamic_memset_clobbers_error_output",
            parameters=("output", "length"),
            statements=[
                replace(origin, ea=0x4410),
                Call(
                    2,
                    0x4420,
                    clearer.name,
                    (output, length),
                    callee_ea=clearer.ea,
                    block_id=1,
                    guards=(enough,),
                ),
                Call(
                    3,
                    0x4430,
                    clearer.name,
                    (output, const(8)),
                    callee_ea=clearer.ea,
                    block_id=2,
                    guards=(short,),
                ),
            ],
            blocks=branch_blocks,
            entry_block=0,
            conditions=[Condition(0x4418, 0, enough, enough.text, order=1)],
        )
        nested_bounded_summary = SummaryBuilder().build(
            [clearer, nested_bounded]
        ).lookup(nested_bounded.name, nested_bounded.ea)
        self.assertTrue(
            nested_bounded_summary is None
            or not nested_bounded_summary.error_outputs
        )

    def test_dynamic_clobber_recovers_terminating_path_guards(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        source = Expr(
            kind="call",
            text="read(0, buffer, 32)",
            callee="read",
            children=(const(0), var("buffer"), const(32)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        length = Expr(
            kind="var",
            text="length",
            key="length",
            bits=64,
            signed=False,
            is_pointer=False,
        )
        short = Expr(
            kind="op",
            text="length < 8",
            op="ult",
            children=(length, const(8)),
            bits=1,
            signed=False,
            is_pointer=False,
        )
        enough = replace(short, text="length >= 8", op="uge")
        flag = Expr(
            kind="var",
            text="flag",
            key="flag",
            bits=32,
            signed=False,
            is_pointer=False,
        )
        flag_set = Expr(
            kind="op",
            text="flag != 0",
            op="ne",
            children=(flag, const(0)),
            bits=1,
            signed=False,
            is_pointer=False,
        )
        rejected = Expr(
            kind="op",
            text="length < 8 || flag != 0",
            op="logical_or",
            children=(short, flag_set),
            bits=1,
            signed=False,
            is_pointer=False,
        )
        blocks = {
            0: BasicBlock(0, 0x5000, 0x5018, successors=(1, 2)),
            1: BasicBlock(1, 0x5020, 0x5030, predecessors=(0,)),
            2: BasicBlock(2, 0x5030, 0x5040, predecessors=(0,)),
        }

        def candidate(
            name: str,
            ea: int,
            return_guard: Expr,
            *continuation: Assignment | Call,
        ) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                parameters=("output", "length", "flag"),
                statements=[
                    Assignment(1, ea + 0x10, slot, source, block_id=0),
                    Call(
                        2,
                        ea + 0x20,
                        "memset",
                        (output, const(0), const(8)),
                        block_id=1,
                        guards=(return_guard,),
                    ),
                    Return(
                        3,
                        ea + 0x28,
                        const(0),
                        block_id=1,
                        guards=(return_guard,),
                    ),
                    *continuation,
                ],
                blocks=blocks,
                entry_block=0,
                conditions=[
                    Condition(
                        ea + 0x18,
                        0,
                        return_guard,
                        return_guard.text,
                        order=1,
                    )
                ],
            )

        accepted = candidate(
            "terminating_guard_proves_dynamic_clobber",
            0x5000,
            short,
            Call(
                4,
                0x5040,
                "memset",
                (output, const(0), length),
                block_id=2,
            ),
        )
        accepted_summary = SummaryBuilder().build([accepted]).lookup(
            accepted.name, accepted.ea
        )
        self.assertTrue(
            accepted_summary is None or not accepted_summary.error_outputs
        )

        terminating = FunctionIR(
            ea=0x5080,
            name="noreturn_guard_proves_dynamic_clobber",
            parameters=("output", "length"),
            statements=[
                Assignment(1, 0x5090, slot, source, block_id=0),
                Call(
                    2,
                    0x50A0,
                    "abort",
                    (),
                    block_id=1,
                    guards=(short,),
                ),
                Call(
                    3,
                    0x50B0,
                    "memset",
                    (output, const(0), length),
                    block_id=2,
                ),
            ],
            blocks=blocks,
            entry_block=0,
            conditions=[Condition(0x5098, 0, short, short.text, order=1)],
        )
        terminating_summary = SummaryBuilder().build([terminating]).lookup(
            terminating.name, terminating.ea
        )
        self.assertTrue(
            terminating_summary is None
            or not terminating_summary.error_outputs
        )

        compound = candidate(
            "compound_terminating_guard_proves_dynamic_clobber",
            0x5100,
            rejected,
            Call(
                4,
                0x5140,
                "memset",
                (output, const(0), length),
                block_id=2,
            ),
        )
        compound_summary = SummaryBuilder().build([compound]).lookup(
            compound.name, compound.ea
        )
        self.assertTrue(
            compound_summary is None or not compound_summary.error_outputs
        )

        partial_redefinition = candidate(
            "unrelated_guard_redefinition_keeps_length_bound",
            0x5180,
            rejected,
            Assignment(4, 0x51B8, flag, const(0), block_id=2),
            Call(
                5,
                0x51C0,
                "memset",
                (output, const(0), length),
                block_id=2,
            ),
        )
        partial_redefinition_summary = SummaryBuilder().build(
            [partial_redefinition]
        ).lookup(partial_redefinition.name, partial_redefinition.ea)
        self.assertTrue(
            partial_redefinition_summary is None
            or not partial_redefinition_summary.error_outputs
        )

        redefined = candidate(
            "redefined_terminating_guard_preserves_error_output",
            0x5200,
            short,
            Assignment(4, 0x5238, length, var("replacement"), block_id=2),
            Call(
                5,
                0x5240,
                "memset",
                (output, const(0), length),
                block_id=2,
            ),
        )
        redefined_summary = SummaryBuilder().build([redefined]).lookup(
            redefined.name, redefined.ea
        )
        self.assertIsNotNone(redefined_summary)
        self.assertTrue(redefined_summary.error_outputs)

        one = replace(short, text="length < 1", children=(length, const(1)))
        predecessor = candidate(
            "unlabelled_successor_proves_dynamic_clobber",
            0x5300,
            one,
            Call(
                4,
                0x5340,
                "memset",
                (output, const(0), length),
                block_id=2,
            ),
        )
        predecessor = replace(
            predecessor,
            statements=[
                predecessor.statements[0],
                predecessor.statements[1],
                predecessor.statements[3],
            ],
        )
        predecessor_summary = SummaryBuilder().build([predecessor]).lookup(
            predecessor.name, predecessor.ea
        )
        self.assertTrue(
            predecessor_summary is None
            or not predecessor_summary.error_outputs
        )

        middle = Expr(
            kind="op",
            text="length != 0 && length < 8",
            op="logical_and",
            children=(
                replace(short, text="length != 0", op="ne", children=(length, const(0))),
                short,
            ),
            bits=1,
            signed=False,
            is_pointer=False,
        )
        zero = Expr(
            kind="op",
            text="length == 0",
            op="eq",
            children=(length, const(0)),
            bits=1,
            signed=False,
            is_pointer=False,
        )
        three_way_blocks = {
            0: BasicBlock(0, 0x5400, 0x5418, successors=(1, 2, 3)),
            1: BasicBlock(1, 0x5420, 0x5430, predecessors=(0,)),
            2: BasicBlock(2, 0x5430, 0x5440, predecessors=(0,)),
            3: BasicBlock(3, 0x5440, 0x5450, predecessors=(0,)),
        }
        three_way = FunctionIR(
            ea=0x5400,
            name="three_way_dynamic_clobber",
            parameters=("output", "length"),
            statements=[
                Assignment(1, 0x5410, slot, source, block_id=0),
                Call(
                    2,
                    0x5420,
                    "memset",
                    (output, const(0), length),
                    block_id=1,
                    guards=(enough,),
                ),
                Call(
                    3,
                    0x5430,
                    "memset",
                    (output, const(0), length),
                    block_id=2,
                    guards=(middle,),
                ),
                Call(
                    4,
                    0x5440,
                    "memset",
                    (output, const(0), const(8)),
                    block_id=3,
                    guards=(zero,),
                ),
            ],
            blocks=three_way_blocks,
            entry_block=0,
        )
        three_way_summary = SummaryBuilder().build([three_way]).lookup(
            three_way.name, three_way.ea
        )
        self.assertTrue(
            three_way_summary is None or not three_way_summary.error_outputs
        )

    def test_output_error_status_guard_controls_caller_finding(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        destination = Expr(
            kind="var", text="destination", key="destination", is_pointer=True
        )
        limit = Expr(
            kind="var", text="limit", key="limit", bits=64, signed=False
        )
        result = Expr(
            kind="var", text="result", key="result", bits=64, signed=True
        )
        output_slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        read_result = Expr(
            kind="call",
            text="read(0, destination, limit)",
            callee="read",
            children=(const(0), destination, limit),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        converted = Expr(
            kind="cast",
            text="(size_t)result",
            children=(result,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        failed = Expr(
            kind="op",
            text="result < 0",
            op="slt",
            children=(result, const(0)),
            bits=1,
            signed=False,
        )
        wrapper = FunctionIR(
            ea=0x2000,
            name="status_count_output",
            parameters=("output", "destination", "limit"),
            statements=[
                Assignment(1, 0x2010, result, read_result, block_id=0),
                Assignment(2, 0x2020, output_slot, converted, block_id=0),
                Return(4, 0x2040, const(-1), block_id=1, guards=(failed,)),
                Return(5, 0x2050, const(0), block_id=2),
            ],
            blocks={
                0: BasicBlock(0, 0x2000, 0x2030, successors=(1, 2)),
                1: BasicBlock(1, 0x2030, 0x2048, predecessors=(0,)),
                2: BasicBlock(2, 0x2048, 0x2060, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x2030, 0, failed, failed.text, order=3)],
        )
        summary = SummaryBuilder().build([wrapper]).lookup(
            wrapper.name, wrapper.ea
        )
        self.assertIsNotNone(summary)
        self.assertEqual(len(summary.error_outputs), 1)
        self.assertEqual(
            summary.error_outputs[0].sentinel_return_values,
            (-1,),
        )

        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        count_address = Expr(
            kind="address",
            text="&count",
            key="count",
            children=(count,),
            bits=64,
            signed=False,
            is_pointer=True,
        )
        status = Expr(
            kind="var", text="status", key="status", bits=32, signed=True
        )
        arguments = (count_address, var("buffer"), const(32))
        status_call = Expr(
            kind="call",
            text="status_count_output(&count, buffer, 32)",
            callee=wrapper.name,
            callee_ea=wrapper.ea,
            children=arguments,
            bits=32,
            signed=True,
            is_pointer=False,
        )
        accepted = Expr(
            kind="op",
            text="status == 0",
            op="eq",
            children=(status, const(0)),
            bits=1,
            signed=False,
        )
        ineffective = replace(
            accepted,
            text="status != 7",
            op="ne",
            children=(status, const(7)),
        )

        def caller(name: str, ea: int, guard: Expr | None) -> FunctionIR:
            sink_guards = (guard,) if guard is not None else ()
            conditions = (
                [Condition(ea + 0x20, None, guard, guard.text, order=3)]
                if guard is not None
                else []
            )
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Assignment(1, ea + 0x10, status, status_call),
                    Call(
                        2,
                        ea + 0x10,
                        wrapper.name,
                        arguments,
                        text=status_call.text,
                        callee_ea=wrapper.ea,
                    ),
                    Assignment(
                        4,
                        ea + 0x30,
                        var("allocation"),
                        call_expr("malloc", count),
                        guards=sink_guards,
                    ),
                ],
                conditions=conditions,
            )

        checked = caller("checked_status_output", 0x3000, accepted)
        unchecked = caller("unchecked_status_output", 0x3100, None)
        weakly_checked = caller("weak_status_output", 0x3200, ineffective)
        findings = Analyzer.analyze_program(
            [wrapper, checked, unchecked, weakly_checked]
        )
        reported = {
            item.function_name
            for item in findings
            if item.rule_id == "ERR-001"
        }
        self.assertNotIn(checked.name, reported)
        self.assertIn(unchecked.name, reported)
        self.assertIn(weakly_checked.name, reported)

        inline_accepted = replace(
            accepted,
            text="status_count_output(&count, buffer, 32) == 0",
            children=(status_call, const(0)),
        )
        inline_ineffective = replace(
            inline_accepted,
            text="status_count_output(&count, buffer, 32) != 7",
            op="ne",
            children=(status_call, const(7)),
        )

        def inline_caller(name: str, ea: int, guard: Expr) -> FunctionIR:
            enlarged = Expr(
                kind="op",
                text="count + 16",
                op="add",
                children=(count, const(16)),
                bits=64,
                signed=False,
                is_pointer=False,
            )
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Assignment(
                        2,
                        ea + 0x30,
                        var("allocation"),
                        call_expr("malloc", enlarged),
                        guards=(guard,),
                    ),
                    Call(
                        10,
                        ea + 0x10,
                        wrapper.name,
                        arguments,
                        text=status_call.text,
                        callee_ea=wrapper.ea,
                    ),
                ],
                conditions=[
                    Condition(ea + 0x20, None, guard, guard.text, order=1)
                ],
            )

        inline_checked = inline_caller(
            "inline_checked_status_output", 0x3300, inline_accepted
        )
        inline_weak = inline_caller(
            "inline_weak_status_output", 0x3400, inline_ineffective
        )
        inline_findings = Analyzer.analyze_program(
            [wrapper, inline_checked, inline_weak]
        )
        inline_rules = {
            function_name: {
                item.rule_id
                for item in inline_findings
                if item.function_name == function_name
            }
            for function_name in {inline_checked.name, inline_weak.name}
        }
        self.assertNotIn("ERR-001", inline_rules[inline_checked.name])
        self.assertNotIn("INT-005", inline_rules[inline_checked.name])
        self.assertIn("ERR-001", inline_rules[inline_weak.name])
        self.assertNotIn("INT-005", inline_rules[inline_weak.name])

    def test_output_error_status_relation_only_crosses_return_passthrough(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        sentinel_guard = Expr(
            kind="op",
            text="*output == SIZE_MAX",
            op="eq",
            children=(slot, const((1 << 64) - 1)),
            bits=1,
            signed=False,
        )
        inner = FunctionIR(
            ea=0x2000,
            name="inner_status_output",
            parameters=("output",),
            statements=[
                Assignment(
                    1,
                    0x2010,
                    slot,
                    Expr(
                        kind="call",
                        text="read(0, buffer, 32)",
                        callee="read",
                        children=(const(0), var("buffer"), const(32)),
                        bits=64,
                        signed=True,
                        is_pointer=False,
                    ),
                ),
                Return(
                    3,
                    0x2030,
                    const(-1),
                    guards=(sentinel_guard,),
                ),
                Return(4, 0x2040, const(0)),
            ],
        )
        inner_call = Expr(
            kind="call",
            text="inner_status_output(output)",
            callee=inner.name,
            callee_ea=inner.ea,
            children=(output,),
            bits=32,
            signed=True,
            is_pointer=False,
        )
        forwarding = FunctionIR(
            ea=0x2100,
            name="forwarding_status_output",
            parameters=("output",),
            statements=[
                Call(
                    1,
                    0x2110,
                    inner.name,
                    (output,),
                    text=inner_call.text,
                    callee_ea=inner.ea,
                ),
                Return(2, 0x2110, inner_call),
            ],
        )
        remapped = replace(
            forwarding,
            ea=0x2200,
            name="remapped_status_output",
            statements=[
                replace(
                    forwarding.statements[0],
                    ea=0x2210,
                ),
                Return(2, 0x2220, const(0)),
            ],
        )
        summaries = SummaryBuilder().build([inner, forwarding, remapped])
        forwarded = summaries.lookup(forwarding.name, forwarding.ea)
        mapped = summaries.lookup(remapped.name, remapped.ea)
        self.assertIsNotNone(forwarded)
        self.assertIsNotNone(mapped)
        self.assertEqual(
            forwarded.error_outputs[0].sentinel_return_values,
            (-1,),
        )
        self.assertEqual(
            mapped.error_outputs[0].sentinel_return_values,
            (0,),
        )

        raw = replace(
            inner,
            ea=0x2300,
            name="raw_void_output",
            statements=[inner.statements[0]],
        )
        checking_call = Call(
            1,
            0x2410,
            raw.name,
            (output,),
            text="raw_void_output(output)",
            callee_ea=raw.ea,
        )
        checking = FunctionIR(
            ea=0x2400,
            name="checking_nested_output",
            parameters=("output",),
            statements=[
                checking_call,
                Return(
                    3,
                    0x2430,
                    const(-1),
                    guards=(sentinel_guard,),
                ),
                Return(4, 0x2440, const(0)),
            ],
        )
        nested = SummaryBuilder().build([raw, checking]).lookup(
            checking.name, checking.ea
        )
        self.assertIsNotNone(nested)
        self.assertEqual(
            nested.error_outputs[0].sentinel_return_values,
            (-1,),
        )

    def test_output_error_status_relation_evaluates_conditional_returns(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        read_result = Expr(
            kind="call",
            text="read(0, buffer, 32)",
            callee="read",
            children=(const(0), var("buffer"), const(32)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        sentinel_guard = Expr(
            kind="op",
            text="*output == SIZE_MAX",
            op="eq",
            children=(slot, const((1 << 64) - 1)),
            bits=1,
            signed=False,
        )
        ternary_return = Expr(
            kind="op",
            text="*output == SIZE_MAX ? -5 : 0",
            op="ternary",
            children=(sentinel_guard, const(-5), const(0)),
            bits=32,
            signed=True,
            is_pointer=False,
        )
        direct = FunctionIR(
            ea=0x2500,
            name="ternary_status_output",
            parameters=("output",),
            statements=[
                Assignment(1, 0x2510, slot, read_result),
                Return(2, 0x2520, ternary_return),
            ],
        )
        boolean = replace(
            direct,
            ea=0x2600,
            name="boolean_status_output",
            statements=[
                replace(direct.statements[0], ea=0x2610),
                Return(2, 0x2620, sentinel_guard),
            ],
        )

        direct_call = Expr(
            kind="call",
            text="ternary_status_output(output)",
            callee=direct.name,
            callee_ea=direct.ea,
            children=(output,),
            bits=32,
            signed=True,
            is_pointer=False,
        )
        status = Expr(
            kind="var", text="status", key="status", bits=32, signed=True
        )
        failed = Expr(
            kind="op",
            text="status < 0",
            op="slt",
            children=(status, const(0)),
            bits=1,
            signed=False,
        )
        mapped_return = Expr(
            kind="op",
            text="status < 0 ? -7 : 0",
            op="ternary",
            children=(failed, const(-7), const(0)),
            bits=32,
            signed=True,
            is_pointer=False,
        )
        nested = FunctionIR(
            ea=0x2700,
            name="nested_ternary_status_output",
            parameters=("output",),
            statements=[
                Assignment(1, 0x2710, status, direct_call),
                Call(
                    2,
                    0x2710,
                    direct.name,
                    (output,),
                    text=direct_call.text,
                    callee_ea=direct.ea,
                ),
                Return(3, 0x2720, mapped_return),
            ],
        )
        call_failed = replace(
            failed,
            text="ternary_status_output(output) < 0",
            children=(direct_call, const(0)),
        )
        late_boolean = FunctionIR(
            ea=0x2750,
            name="late_ctree_boolean_status_output",
            parameters=("output",),
            statements=[
                Return(1, 0x2760, call_failed),
                Call(
                    3,
                    0x2758,
                    direct.name,
                    (output,),
                    text=direct_call.text,
                    callee_ea=direct.ea,
                ),
            ],
        )
        call_nonnegative = replace(
            call_failed,
            text="ternary_status_output(output) >= 0",
            op="sge",
        )
        late_branch = FunctionIR(
            ea=0x2780,
            name="late_ctree_branch_status_output",
            parameters=("output",),
            statements=[
                Return(1, 0x2790, const(0), guards=(call_nonnegative,)),
                Return(3, 0x2798, const(-7), guards=(call_failed,)),
                Call(
                    7,
                    0x2788,
                    direct.name,
                    (output,),
                    text=direct_call.text,
                    callee_ea=direct.ea,
                ),
            ],
            conditions=[
                Condition(
                    0x278C,
                    None,
                    call_nonnegative,
                    call_nonnegative.text,
                    0,
                )
            ],
        )
        flag = Expr(
            kind="var", text="flag", key="flag", bits=32, signed=True
        )
        unknown_mapping = replace(
            direct,
            ea=0x2800,
            name="unknown_ternary_status_output",
            statements=[
                replace(direct.statements[0], ea=0x2810),
                Return(
                    2,
                    0x2820,
                    replace(
                        ternary_return,
                        text="flag ? -9 : 0",
                        children=(flag, const(-9), const(0)),
                    ),
                ),
            ],
        )
        mapped = Expr(
            kind="var", text="mapped", key="mapped", bits=32, signed=True
        )
        optional_assignment = replace(
            direct,
            ea=0x2900,
            name="optional_assignment_status_output",
            statements=[
                replace(direct.statements[0], ea=0x2910),
                Assignment(2, 0x2920, mapped, const(-3)),
                Assignment(3, 0x2930, mapped, const(0), guards=(flag,)),
                Return(4, 0x2940, mapped),
            ],
        )
        abi_mapping = replace(
            direct,
            ea=0x2A00,
            name="abi_ternary_status_output",
            statements=[
                replace(direct.statements[0], ea=0x2A10),
                Return(
                    2,
                    0x2A20,
                    replace(
                        ternary_return,
                        text="*output == SIZE_MAX ? 0xFFFFFFF9 : 0",
                        children=(
                            sentinel_guard,
                            const((1 << 32) - 7),
                            const(0),
                        ),
                    ),
                ),
            ],
        )

        summaries = SummaryBuilder().build(
            [
                direct,
                boolean,
                nested,
                late_boolean,
                late_branch,
                unknown_mapping,
                optional_assignment,
                abi_mapping,
            ]
        )
        direct_summary = summaries.lookup(direct.name, direct.ea)
        boolean_summary = summaries.lookup(boolean.name, boolean.ea)
        nested_summary = summaries.lookup(nested.name, nested.ea)
        late_boolean_summary = summaries.lookup(
            late_boolean.name, late_boolean.ea
        )
        late_branch_summary = summaries.lookup(late_branch.name, late_branch.ea)
        unknown_summary = summaries.lookup(
            unknown_mapping.name, unknown_mapping.ea
        )
        optional_summary = summaries.lookup(
            optional_assignment.name, optional_assignment.ea
        )
        abi_summary = summaries.lookup(abi_mapping.name, abi_mapping.ea)
        self.assertIsNotNone(direct_summary)
        self.assertIsNotNone(boolean_summary)
        self.assertIsNotNone(nested_summary)
        self.assertIsNotNone(late_boolean_summary)
        self.assertIsNotNone(late_branch_summary)
        self.assertIsNotNone(unknown_summary)
        self.assertIsNotNone(optional_summary)
        self.assertIsNotNone(abi_summary)
        self.assertEqual(
            direct_summary.error_outputs[0].sentinel_return_values,
            (-5,),
        )
        self.assertEqual(
            boolean_summary.error_outputs[0].sentinel_return_values,
            (1,),
        )
        self.assertEqual(
            nested_summary.error_outputs[0].sentinel_return_values,
            (-7,),
        )
        self.assertEqual(
            late_boolean_summary.error_outputs[0].sentinel_return_values,
            (1,),
        )
        self.assertEqual(
            late_branch_summary.error_outputs[0].sentinel_return_values,
            (-7,),
        )
        self.assertEqual(
            unknown_summary.error_outputs[0].sentinel_return_values,
            (-9, 0),
        )
        self.assertEqual(
            optional_summary.error_outputs[0].sentinel_return_values,
            (-3, 0),
        )
        self.assertEqual(
            abi_summary.error_outputs[0].sentinel_return_values,
            ((1 << 32) - 7,),
        )

        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        count_address = Expr(
            kind="address",
            text="&count",
            key="count",
            children=(count,),
            bits=64,
            signed=False,
            is_pointer=True,
        )
        caller_arguments = (count_address,)
        caller_result = replace(
            direct_call,
            text="nested_ternary_status_output(&count)",
            callee=nested.name,
            callee_ea=nested.ea,
            children=caller_arguments,
        )
        accepted = Expr(
            kind="op",
            text="status == 0",
            op="eq",
            children=(status, const(0)),
            bits=1,
            signed=False,
        )

        def caller(name: str, ea: int, checked: bool) -> FunctionIR:
            sink_guards = (accepted,) if checked else ()
            return FunctionIR(
                ea=ea,
                name=name,
                statements=[
                    Assignment(1, ea + 0x10, status, caller_result),
                    Call(
                        2,
                        ea + 0x10,
                        nested.name,
                        caller_arguments,
                        text=caller_result.text,
                        callee_ea=nested.ea,
                    ),
                    Assignment(
                        4,
                        ea + 0x30,
                        var("allocation"),
                        call_expr("malloc", count),
                        guards=sink_guards,
                    ),
                ],
                conditions=(
                    [Condition(ea + 0x20, None, accepted, accepted.text, 3)]
                    if checked
                    else []
                ),
            )

        checked = caller("checked_nested_ternary_status", 0x3000, True)
        unchecked = caller("unchecked_nested_ternary_status", 0x3100, False)
        findings = Analyzer.analyze_program(
            [direct, nested, checked, unchecked]
        )
        reported = {
            finding.function_name
            for finding in findings
            if finding.rule_id == "ERR-001"
        }
        self.assertNotIn(checked.name, reported)
        self.assertIn(unchecked.name, reported)

        abi_result = replace(
            caller_result,
            text="abi_ternary_status_output(&count)",
            callee=abi_mapping.name,
            callee_ea=abi_mapping.ea,
        )
        sign_mask = Expr(
            kind="const",
            text="0x80000000",
            value=1 << 31,
            bits=32,
            signed=False,
            is_pointer=False,
        )
        sign_bit = Expr(
            kind="op",
            text="abi_ternary_status_output(&count) & 0x80000000",
            op="and",
            children=(abi_result, sign_mask),
            bits=32,
            signed=False,
            is_pointer=False,
        )
        nonnegative = Expr(
            kind="op",
            text="(abi_ternary_status_output(&count) & 0x80000000) == 0",
            op="eq",
            children=(sign_bit, const(0)),
            bits=1,
            signed=False,
            is_pointer=False,
        )
        bit_checked = FunctionIR(
            ea=0x3200,
            name="bit_checked_abi_status",
            statements=[
                Assignment(
                    2,
                    0x3230,
                    var("allocation"),
                    call_expr("malloc", count),
                    guards=(nonnegative,),
                ),
                Call(
                    10,
                    0x3210,
                    abi_mapping.name,
                    caller_arguments,
                    text=abi_result.text,
                    callee_ea=abi_mapping.ea,
                ),
            ],
            conditions=[
                Condition(0x3220, None, nonnegative, nonnegative.text, 1)
            ],
        )
        bit_findings = Analyzer.analyze_program([abi_mapping, bit_checked])
        self.assertFalse(
            any(
                finding.rule_id == "ERR-001"
                and finding.function_name == bit_checked.name
                for finding in bit_findings
            )
        )

    def test_output_error_status_relation_merges_guarded_assignments(self):
        output = Expr(
            kind="var", text="output", key="output", is_pointer=True
        )
        slot = Expr(
            kind="deref",
            text="*output",
            key="output",
            children=(output,),
            bits=64,
            signed=False,
            is_pointer=False,
        )
        producer = Expr(
            kind="call",
            text="read(0, buffer, 32)",
            callee="read",
            children=(const(0), var("buffer"), const(32)),
            bits=64,
            signed=True,
            is_pointer=False,
        )
        mapped = Expr(
            kind="var", text="mapped", key="mapped", bits=32, signed=True
        )
        sentinel = Expr(
            kind="op",
            text="*output == SIZE_MAX",
            op="eq",
            children=(slot, const((1 << 64) - 1)),
            bits=1,
            signed=False,
        )
        not_sentinel = replace(
            sentinel,
            text="*output != SIZE_MAX",
            op="ne",
        )
        flag = Expr(
            kind="var", text="flag", key="flag", bits=32, signed=True
        )
        flag_set = Expr(
            kind="op",
            text="flag != 0",
            op="ne",
            children=(flag, const(0)),
            bits=1,
            signed=False,
        )
        flag_clear = replace(
            flag_set,
            text="flag == 0",
            op="eq",
        )

        def wrapper(
            name: str,
            ea: int,
            definitions: list[Assignment],
        ) -> FunctionIR:
            return FunctionIR(
                ea=ea,
                name=name,
                parameters=("output", "flag"),
                statements=[
                    Assignment(1, ea + 0x10, slot, producer),
                    *definitions,
                    Return(10, ea + 0x60, mapped),
                ],
            )

        known = wrapper(
            "known_phi_status_output",
            0x3300,
            [
                Assignment(2, 0x3320, mapped, const(-11), guards=(sentinel,)),
                Assignment(3, 0x3330, mapped, const(0), guards=(not_sentinel,)),
            ],
        )
        unknown = wrapper(
            "unknown_phi_status_output",
            0x3400,
            [
                Assignment(2, 0x3420, mapped, const(-13), guards=(flag_set,)),
                Assignment(3, 0x3430, mapped, const(-17), guards=(flag_clear,)),
            ],
        )
        optional = wrapper(
            "optional_phi_status_output",
            0x3500,
            [
                Assignment(2, 0x3520, mapped, const(-3)),
                Assignment(3, 0x3530, mapped, const(0), guards=(flag_set,)),
            ],
        )
        incomplete = wrapper(
            "incomplete_phi_status_output",
            0x3600,
            [Assignment(2, 0x3620, mapped, const(-19), guards=(flag_set,))],
        )
        sequential = wrapper(
            "sequential_status_output",
            0x3700,
            [
                Assignment(2, 0x3720, mapped, const(-23)),
                Assignment(3, 0x3730, mapped, const(0)),
            ],
        )
        lower = FunctionIR(
            ea=0x3800,
            name="raw_status_output",
            parameters=("output",),
            statements=[
                Assignment(1, 0x3810, slot, producer),
                Return(
                    2,
                    0x3820,
                    const((1 << 32) - 1),
                    guards=(sentinel,),
                ),
                Return(3, 0x3830, const(0), guards=(not_sentinel,)),
            ],
        )
        lower_call = Expr(
            kind="call",
            text="raw_status_output(output)",
            callee=lower.name,
            callee_ea=lower.ea,
            children=(output,),
            bits=32,
            signed=True,
            is_pointer=False,
        )
        lower_sign = Expr(
            kind="op",
            text="raw_status_output(output) & 0x80000000",
            op="and",
            children=(
                lower_call,
                Expr(
                    kind="const",
                    text="0x80000000",
                    value=1 << 31,
                    bits=32,
                    signed=False,
                    is_pointer=False,
                ),
            ),
            bits=32,
            signed=False,
            is_pointer=False,
        )
        lower_failed = Expr(
            kind="op",
            text="(raw_status_output(output) & 0x80000000) != 0",
            op="ne",
            children=(lower_sign, const(0)),
            bits=1,
            signed=False,
        )
        lower_succeeded = replace(
            lower_failed,
            text="(raw_status_output(output) & 0x80000000) == 0",
            op="eq",
        )
        nested = FunctionIR(
            ea=0x3900,
            name="nested_phi_status_output",
            parameters=("output",),
            statements=[
                Assignment(1, 0x3920, mapped, const(-11), guards=(lower_failed,)),
                Assignment(3, 0x3930, mapped, const(0), guards=(lower_succeeded,)),
                Call(
                    7,
                    0x3910,
                    lower.name,
                    (output,),
                    text=lower_call.text,
                    callee_ea=lower.ea,
                ),
                Return(10, 0x3940, mapped),
            ],
            conditions=[
                Condition(0x3918, None, lower_failed, lower_failed.text, 0)
            ],
        )

        summaries = SummaryBuilder().build(
            [known, unknown, optional, incomplete, sequential, lower, nested]
        )

        def statuses(function: FunctionIR) -> tuple[int, ...]:
            summary = summaries.lookup(function.name, function.ea)
            self.assertIsNotNone(summary)
            self.assertEqual(len(summary.error_outputs), 1)
            return summary.error_outputs[0].sentinel_return_values

        self.assertEqual(statuses(known), (-11,))
        self.assertEqual(statuses(unknown), (-17, -13))
        self.assertEqual(statuses(optional), (-3, 0))
        self.assertEqual(statuses(incomplete), ())
        self.assertEqual(statuses(sequential), (0,))
        self.assertEqual(statuses(nested), (-11,))

    def test_unsigned_subtraction_clamped_before_use_is_safe(self):
        end = Expr(kind="var", text="end", key="end", bits=64, signed=True)
        cursor = Expr(
            kind="var", text="cursor", key="cursor", bits=64, signed=True
        )
        remaining = Expr(
            kind="var", text="remaining", key="remaining", bits=64, signed=False
        )
        limit = Expr(
            kind="var", text="limit", key="limit", bits=64, signed=False
        )
        difference = Expr(
            kind="op",
            text="end - cursor",
            op="sub",
            children=(end, cursor),
            bits=64,
            signed=True,
        )
        clamp_guard = Expr(
            kind="op",
            text="limit < end - cursor",
            op="ult",
            children=(limit, difference),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="clamped_remaining",
            statements=[
                Call(1, 0x1010, "read", (const(0), cursor, const(8)), block_id=0),
                Assignment(2, 0x1020, remaining, difference, block_id=0),
                Assignment(
                    3,
                    0x1030,
                    remaining,
                    limit,
                    block_id=0,
                    guards=(clamp_guard,),
                ),
                Call(4, 0x1040, "read", (const(0), var("buf"), remaining), block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1050)},
            entry_block=0,
            conditions=[Condition(0x1028, 0, clamp_guard, clamp_guard.text, order=2)],
        )
        self.assertNotIn("INT-002", self.rule_ids(ir))

        disjunctive_guard = replace(
            clamp_guard,
            text="force || limit < end - cursor",
            op="logical_or",
            children=(var("force"), clamp_guard),
        )
        not_always_clamped = replace(
            ir,
            name="conditionally_clamped_remaining",
            statements=[
                ir.statements[0],
                ir.statements[1],
                replace(ir.statements[2], guards=(disjunctive_guard,)),
                ir.statements[3],
            ],
            conditions=[
                Condition(
                    0x1028,
                    0,
                    disjunctive_guard,
                    disjunctive_guard.text,
                    order=2,
                )
            ],
        )
        self.assertIn("INT-002", self.rule_ids(not_always_clamped))

    def test_guarded_affine_value_fits_narrow_target(self):
        degree = Expr(
            kind="var", text="degree", key="degree", bits=32, signed=False
        )
        loop_count = Expr(
            kind="var", text="loop_count", key="loop_count", bits=8, signed=True
        )
        plus_one = Expr(
            kind="op",
            text="degree + 1",
            op="add",
            children=(degree, const(1)),
            bits=32,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="degree <= 16",
            op="ule",
            children=(degree, const(16)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="bounded_degree",
            statements=[
                Call(1, 0x1010, "read", (const(0), degree, const(4))),
                Assignment(2, 0x1030, loop_count, plus_one),
            ],
            conditions=[Condition(0x1020, None, guard, guard.text)],
        )
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_affine_guard_before_merge_does_not_bless_narrowing(self):
        degree = Expr(
            kind="var", text="degree", key="degree", bits=32, signed=False
        )
        loop_count = Expr(
            kind="var", text="loop_count", key="loop_count", bits=8, signed=True
        )
        plus_one = Expr(
            kind="op",
            text="degree + 1",
            op="add",
            children=(degree, const(1)),
            bits=32,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="degree <= 16",
            op="ule",
            children=(degree, const(16)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="merged_degree",
            statements=[
                Call(1, 0x1004, "read", (const(0), degree, const(4)), block_id=0),
                Assignment(2, 0x1040, loop_count, plus_one, block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        self.assertIn("INT-001", self.rule_ids(ir))

    def test_assignment_path_affine_guard_proves_narrowing(self):
        degree = Expr(
            kind="var", text="degree", key="degree", bits=32, signed=False
        )
        loop_count = Expr(
            kind="var", text="loop_count", key="loop_count", bits=8, signed=True
        )
        plus_one = Expr(
            kind="op",
            text="degree + 1",
            op="add",
            children=(degree, const(1)),
            bits=32,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="degree <= 16",
            op="ule",
            children=(degree, const(16)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="guarded_degree_path",
            statements=[
                Call(1, 0x1004, "read", (const(0), degree, const(4)), block_id=0),
                Assignment(
                    2,
                    0x1020,
                    loop_count,
                    plus_one,
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_guarded_unsigned_alias_suppresses_integer_and_index_noise(self):
        wide = Expr(kind="var", text="wide", key="wide", bits=64, signed=True)
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=32, signed=False
        )
        index = Expr(
            kind="var", text="index", key="index", bits=32, signed=False
        )
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="index < 32",
            op="ult",
            children=(index, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="guarded_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    1,
                    0x1010,
                    "read",
                    (const(0), wide, const(8)),
                    block_id=0,
                ),
                Assignment(2, 0x1020, narrow, wide, block_id=0),
                Assignment(3, 0x1030, index, narrow, block_id=0),
                Assignment(
                    4,
                    0x1040,
                    target,
                    const(65),
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1038, successors=(1, 2)),
                1: BasicBlock(1, 0x1038, 0x1050, predecessors=(0,)),
                2: BasicBlock(2, 0x1050, 0x1060, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1038, 0, guard, guard.text, order=3)],
        )
        rule_ids = self.rule_ids(ir)
        self.assertNotIn("INT-001", rule_ids)
        self.assertNotIn("INT-002", rule_ids)
        self.assertNotIn("IDX-001", rule_ids)
        self.assertNotIn("IDX-002", rule_ids)

    def test_short_circuit_upper_guard_protects_condition_index(self):
        wide = Expr(kind="var", text="wide", key="wide", bits=64, signed=True)
        index = Expr(
            kind="var", text="index", key="index", bits=32, signed=False
        )
        table_access = Expr(
            kind="index",
            text="table[index]",
            key="g:table",
            children=(
                Expr(kind="global", text="table", key="g:table"),
                index,
            ),
            bits=64,
            signed=False,
        )
        bound = Expr(
            kind="op",
            text="index < 16",
            op="ult",
            children=(index, const(16)),
        )
        loaded = Expr(
            kind="op",
            text="table[index] != 0",
            op="ne",
            children=(table_access, const(0)),
        )
        guarded_condition = Expr(
            kind="op",
            text="index < 16 && table[index] != 0",
            op="logical_and",
            children=(bound, loaded),
        )
        base = FunctionIR(
            ea=0x1000,
            name="short_circuit_index",
            statements=[
                Call(1, 0x1010, "read", (const(0), wide, const(8)), block_id=0),
                Assignment(2, 0x1020, index, wide, block_id=0),
                Assignment(4, 0x1040, var("value"), table_access, block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1050)},
            entry_block=0,
            conditions=[
                Condition(
                    0x1030,
                    0,
                    guarded_condition,
                    guarded_condition.text,
                    order=3,
                )
            ],
        )
        rule_ids = self.rule_ids(base)
        self.assertNotIn("INT-001", rule_ids)
        self.assertNotIn("INT-002", rule_ids)

        reversed_condition = replace(
            guarded_condition,
            text="table[index] != 0 && index < 16",
            children=(loaded, bound),
        )
        unsafe = replace(
            base,
            name="late_short_circuit_guard",
            conditions=[
                Condition(
                    0x1030,
                    0,
                    reversed_condition,
                    reversed_condition.text,
                    order=3,
                )
            ],
        )
        unsafe_rules = self.rule_ids(unsafe)
        self.assertIn("INT-001", unsafe_rules)
        self.assertIn("INT-002", unsafe_rules)

    def test_narrowed_menu_choice_used_only_for_control_is_not_reported(self):
        wide = Expr(kind="var", text="wide", key="wide", bits=64, signed=True)
        choice = Expr(
            kind="var", text="choice", key="choice", bits=32, signed=True
        )
        is_exit = Expr(
            kind="op",
            text="choice == 4",
            op="eq",
            children=(choice, const(4)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="menu_dispatch",
            statements=[
                Call(1, 0x1010, "read", (const(0), wide, const(8)), block_id=0),
                Assignment(2, 0x1020, choice, wide, block_id=0),
                Assignment(3, 0x1030, var("exit_selected"), is_exit, block_id=0),
            ],
            blocks={0: BasicBlock(0, 0x1000, 0x1040)},
            entry_block=0,
            conditions=[Condition(0x1038, 0, is_exit, is_exit.text, order=4)],
        )
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_unsigned_alias_guard_before_merge_does_not_suppress_conversion(self):
        wide = Expr(kind="var", text="wide", key="wide", bits=64, signed=True)
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=32, signed=False
        )
        index = Expr(
            kind="var", text="index", key="index", bits=32, signed=False
        )
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="index < 32",
            op="ult",
            children=(index, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="merged_converted_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(
                    1,
                    0x1004,
                    "read",
                    (const(0), wide, const(8)),
                    block_id=0,
                ),
                Assignment(2, 0x1010, narrow, wide, block_id=0),
                Assignment(3, 0x1020, index, narrow, block_id=0),
                Assignment(4, 0x1050, target, const(65), block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1030, successors=(1, 2)),
                1: BasicBlock(1, 0x1030, 0x1040, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1040, 0x1050, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1050, 0x1060, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1028, 0, guard, guard.text, order=3)],
        )
        rule_ids = self.rule_ids(ir)
        self.assertIn("INT-001", rule_ids)
        self.assertIn("INT-002", rule_ids)

    def test_bounded_read_return_narrowing_is_proven_safe(self):
        result = Expr(
            kind="var", text="result", key="result", bits=32, signed=True
        )
        read_result = Expr(
            kind="call",
            text="read(0, buf, 4096)",
            callee="read",
            children=(const(0), var("buf"), const(4096)),
            bits=64,
            signed=True,
        )
        ir = function(Assignment(1, 0x1010, result, read_result))
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_guarded_dynamic_recv_return_narrowing_is_proven_safe(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=False)
        result = Expr(
            kind="var", text="result", key="result", bits=32, signed=True
        )
        recv_result = Expr(
            kind="call",
            text="recv(fd, buf, size, 0)",
            callee="recv",
            children=(var("fd"), var("buf"), size, const(0)),
            bits=64,
            signed=True,
        )
        guard = Expr(
            kind="op",
            text="size > 2048",
            op="ugt",
            children=(size, const(2048)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="guarded_recv",
            statements=[
                Call(
                    1,
                    0x1004,
                    "read",
                    (const(0), size, const(4)),
                    block_id=0,
                ),
                Return(2, 0x1020, const(0), block_id=1, guards=(guard,)),
                Assignment(3, 0x1030, result, recv_result, block_id=2),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1018, 0, guard, guard.text, order=1)],
        )
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_dynamic_recv_guard_before_merge_does_not_bless_narrowing(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=False)
        result = Expr(
            kind="var", text="result", key="result", bits=16, signed=True
        )
        recv_result = Expr(
            kind="call",
            text="recv(fd, buf, size, 0)",
            callee="recv",
            children=(var("fd"), var("buf"), size, const(0)),
            bits=64,
            signed=True,
        )
        guard = Expr(
            kind="op",
            text="size <= 2048",
            op="ule",
            children=(size, const(2048)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="merged_recv_guard",
            statements=[
                Call(
                    1,
                    0x1004,
                    "read",
                    (const(0), size, const(4)),
                    block_id=0,
                ),
                Assignment(2, 0x1040, result, recv_result, block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text, order=1)],
        )
        self.assertIn("INT-001", self.rule_ids(ir))

    def test_dynamic_recv_guard_on_stale_alias_does_not_bless_narrowing(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=False)
        checked = Expr(
            kind="var", text="checked", key="checked", bits=32, signed=False
        )
        result = Expr(
            kind="var", text="result", key="result", bits=16, signed=True
        )
        recv_result = Expr(
            kind="call",
            text="recv(fd, buf, size, 0)",
            callee="recv",
            children=(var("fd"), var("buf"), size, const(0)),
            bits=64,
            signed=True,
        )
        guard = Expr(
            kind="op",
            text="checked <= 2048",
            op="ule",
            children=(checked, const(2048)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="stale_alias_recv_guard",
            statements=[
                Call(
                    1,
                    0x1004,
                    "read",
                    (const(0), size, const(4)),
                    block_id=0,
                ),
                Assignment(2, 0x1008, checked, size, block_id=0),
                Assignment(
                    4,
                    0x1018,
                    size,
                    call_expr("attacker_size"),
                    block_id=1,
                    guards=(guard,),
                ),
                Assignment(
                    5,
                    0x1020,
                    result,
                    recv_result,
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1010, 0, guard, guard.text, order=3)],
        )
        self.assertIn("INT-001", self.rule_ids(ir))

    def test_width_limited_scanf_strlen_fits_narrow_target(self):
        pointer = var("allocated")
        alias = var("text")
        length = Expr(
            kind="call",
            text="strlen(text)",
            callee="strlen",
            children=(alias,),
            bits=64,
            signed=False,
        )
        narrow = Expr(
            kind="global",
            text="stored_length",
            key="g:stored_length",
            bits=32,
            signed=False,
        )
        ir = function(
            Assignment(
                1,
                0x1010,
                pointer,
                call_expr("calloc", const(256), const(1)),
            ),
            Assignment(2, 0x1020, alias, pointer),
            Call(
                3,
                0x1030,
                "fscanf",
                (var("stream"), string("%255s"), pointer),
            ),
            Assignment(4, 0x1040, narrow, length),
        )
        self.assertNotIn("INT-001", self.rule_ids(ir))

    def test_uninitialized_scanf_destination_does_not_prove_strlen_bound(self):
        pointer = var("allocated")
        length = Expr(
            kind="call",
            text="strlen(allocated)",
            callee="strlen",
            children=(pointer,),
            bits=64,
            signed=False,
        )
        narrow = Expr(
            kind="global",
            text="stored_length",
            key="g:stored_length",
            bits=32,
            signed=False,
        )
        ir = function(
            Assignment(1, 0x1010, pointer, call_expr("malloc", const(256))),
            Call(
                2,
                0x1020,
                "fscanf",
                (var("stream"), string("%255s"), pointer),
            ),
            Assignment(3, 0x1030, narrow, length),
        )
        self.assertIn("INT-001", self.rule_ids(ir))

    def test_tainted_index_does_not_taint_trusted_table_value(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=False)
        table = Expr(kind="global", text="sizes", key="g:sizes")
        loaded = Expr(
            kind="index",
            text="sizes[index]",
            key="g:sizes",
            children=(table, index),
            bits=32,
            signed=False,
        )
        product = Expr(
            kind="op",
            text="size * 4",
            op="mul",
            children=(var("size"), const(4)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), index, const(4))),
            Assignment(2, 0x1020, var("size"), loaded),
            Call(3, 0x1030, "malloc", (product,)),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_inline_input_region_does_not_taint_record_metadata(self):
        owner = var("connection")
        fd = Expr(
            kind="deref",
            text="*connection",
            key="connection",
            children=(owner,),
            offset=0,
            bits=32,
            signed=True,
        )
        cursor = Expr(
            kind="index",
            text="connection[2]",
            key="connection",
            children=(owner, const(2)),
            offset=8,
            bits=32,
            signed=True,
        )
        payload_word = Expr(
            kind="index",
            text="connection[7]",
            key="connection",
            children=(owner, const(7)),
            offset=28,
            bits=32,
            signed=True,
        )
        destination = Expr(
            kind="op",
            text="connection + connection[2] + 28",
            key="connection",
            op="add",
            children=(owner, cursor, const(28)),
        )
        remaining = Expr(
            kind="op",
            text="64 - connection[2]",
            op="sub",
            children=(const(64), cursor),
            bits=32,
            signed=True,
        )
        word_index = Expr(
            kind="op",
            text="*connection / 32",
            op="div",
            children=(fd, const(32)),
            bits=32,
            signed=True,
        )
        bit_store = Expr(
            kind="index",
            text="bits[*connection / 32]",
            key="bits",
            children=(var("bits"), word_index),
            bits=32,
            signed=False,
        )
        parsed = Expr(
            kind="var", text="parsed", key="parsed", bits=32, signed=True
        )
        ir = FunctionIR(
            ea=0x1000,
            name="field_sensitive_record",
            buffers={"bits": BufferInfo("bits", "bits", "stack", 128)},
            statements=[
                Call(
                    1,
                    0x1010,
                    "recv",
                    (var("fd"), destination, remaining, const(0)),
                ),
                Assignment(2, 0x1020, bit_store, const(1)),
                Call(3, 0x1030, "send", (var("fd"), var("buf"), cursor, const(0))),
                Assignment(4, 0x1040, parsed, payload_word),
                Call(5, 0x1050, "send", (var("fd"), var("buf"), parsed, const(0))),
            ],
        )
        findings = self.analyzer.analyze_function(ir)
        self.assertFalse(
            any(
                finding.rule_id == "IDX-001" and finding.ea == 0x1020
                for finding in findings
            )
        )
        self.assertFalse(
            any(
                finding.rule_id == "INT-002" and finding.ea == 0x1030
                for finding in findings
            )
        )
        self.assertTrue(
            any(
                finding.rule_id == "INT-002" and finding.ea == 0x1050
                for finding in findings
            )
        )

    def test_dynamic_input_index_conservatively_taints_the_owner(self):
        owner = var("record")
        dynamic_slot = Expr(
            kind="index",
            text="record[index]",
            key="record",
            children=(owner, var("index")),
            bits=8,
            signed=False,
        )
        metadata = Expr(
            kind="deref",
            text="*record",
            key="record",
            children=(owner,),
            bits=32,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), dynamic_slot, const(1))),
            Call(2, 0x1020, "send", (var("fd"), var("buf"), metadata, const(0))),
        )
        self.assertIn("INT-002", self.rule_ids(ir))

    def test_signed_guard_does_not_bound_unsigned_global_table_index(self):
        index = Expr(
            kind="var", text="index", key="index", bits=8, signed=False
        )
        signed_index = Expr(
            kind="cast",
            text="(signed char)index",
            key="index",
            children=(index,),
            bits=8,
            signed=True,
        )
        guard = Expr(
            kind="op",
            text="(signed char)index <= 63",
            op="sle",
            children=(signed_index, const(63)),
        )
        table = Expr(kind="global", text="table", key="g:table")
        address = Expr(
            kind="op",
            text="table + index",
            op="add",
            children=(table, index),
            bits=64,
            signed=False,
        )
        loaded = Expr(
            kind="deref",
            text="table[index]",
            children=(address,),
            bits=64,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="mismatched_index",
            statements=[
                Call(1, 0x1010, "read", (const(0), index, const(1))),
                Assignment(2, 0x1030, var("value"), loaded),
            ],
            conditions=[Condition(0x1020, None, guard, guard.text)],
        )
        self.assertIn("IDX-003", self.rule_ids(ir))

    def test_signed_index_guard_before_merge_does_not_authorize_table_access(self):
        index = Expr(
            kind="var", text="index", key="index", bits=8, signed=False
        )
        signed_index = Expr(
            kind="cast",
            text="(signed char)index",
            key="index",
            children=(index,),
            bits=8,
            signed=True,
        )
        guard = Expr(
            kind="op",
            text="(signed char)index <= 63",
            op="sle",
            children=(signed_index, const(63)),
        )
        table = Expr(kind="global", text="table", key="g:table")
        loaded = Expr(
            kind="deref",
            text="table[index]",
            children=(
                Expr(
                    kind="op",
                    text="table + index",
                    op="add",
                    children=(table, index),
                    bits=64,
                    signed=False,
                ),
            ),
            bits=64,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="merged_signed_guard",
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(1)), block_id=0),
                Assignment(2, 0x1040, var("value"), loaded, block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        self.assertNotIn("IDX-003", self.rule_ids(ir))

    def test_assignment_path_signed_guard_reports_table_mismatch(self):
        index = Expr(
            kind="var", text="index", key="index", bits=8, signed=False
        )
        signed_index = Expr(
            kind="cast",
            text="(signed char)index",
            key="index",
            children=(index,),
            bits=8,
            signed=True,
        )
        guard = Expr(
            kind="op",
            text="(signed char)index <= 63",
            op="sle",
            children=(signed_index, const(63)),
        )
        table = Expr(kind="global", text="table", key="g:table")
        loaded = Expr(
            kind="deref",
            text="table[index]",
            children=(
                Expr(
                    kind="op",
                    text="table + index",
                    op="add",
                    children=(table, index),
                    bits=64,
                    signed=False,
                ),
            ),
            bits=64,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="guarded_signed_table",
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(1)), block_id=0),
                Assignment(
                    2,
                    0x1020,
                    var("value"),
                    loaded,
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        self.assertIn("IDX-003", self.rule_ids(ir))

    def test_unsigned_global_index_guard_is_safe(self):
        index = Expr(
            kind="var", text="index", key="index", bits=8, signed=False
        )
        guard = Expr(
            kind="op",
            text="index <= 63",
            op="ule",
            children=(index, const(63)),
        )
        table = Expr(kind="global", text="table", key="g:table")
        loaded = Expr(
            kind="deref",
            text="table[index]",
            children=(
                Expr(
                    kind="op",
                    op="add",
                    children=(table, index),
                    bits=64,
                    signed=False,
                ),
            ),
            bits=64,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="unsigned_guard",
            statements=[
                Call(1, 0x1010, "read", (const(0), index, const(1))),
                Assignment(2, 0x1030, var("value"), loaded),
            ],
            conditions=[Condition(0x1020, None, guard, guard.text)],
        )
        self.assertNotIn("IDX-003", self.rule_ids(ir))

    def test_signed_nonnegative_guard_makes_narrow_global_index_safe(self):
        index = Expr(
            kind="var", text="index", key="index", bits=8, signed=False
        )
        signed_index = Expr(
            kind="cast",
            text="(signed char)index",
            key="index",
            children=(index,),
            bits=8,
            signed=True,
        )
        lower = Expr(
            kind="op", op="sge", children=(signed_index, const(0))
        )
        upper = Expr(
            kind="op", op="sle", children=(signed_index, const(63))
        )
        guard = Expr(
            kind="op",
            op="logical_and",
            children=(lower, upper),
        )
        table = Expr(kind="global", text="table", key="g:table")
        loaded = Expr(
            kind="deref",
            text="table[index]",
            children=(
                Expr(
                    kind="op",
                    op="add",
                    children=(table, index),
                    bits=64,
                    signed=False,
                ),
            ),
            bits=64,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="signed_guarded_index",
            statements=[
                Call(1, 0x1010, "read", (const(0), index, const(1))),
                Assignment(2, 0x1030, var("value"), loaded),
            ],
            conditions=[Condition(0x1020, None, guard, guard.text)],
        )
        self.assertNotIn("IDX-003", self.rule_ids(ir))

    def test_dynamic_loop_with_persistent_stack_index_overflows(self):
        total = Expr(
            kind="var", text="total", key="total", bits=32, signed=True
        )
        slot = Expr(kind="var", text="slot", key="slot", bits=32, signed=True)
        target = Expr(
            kind="index",
            text="results[slot]",
            key="results",
            children=(var("results"), slot),
            bits=8,
        )
        dynamic_bound = Expr(
            kind="op",
            text="cursor < count",
            op="slt",
            children=(var("cursor"), var("count")),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="collect_results",
            buffers={"results": BufferInfo("results", "results", "stack", 8)},
            statements=[
                Assignment(1, 0x1010, total, const(0), block_id=0),
                Assignment(
                    2,
                    0x1020,
                    slot,
                    Expr(
                        kind="op",
                        text="total++",
                        op="postinc",
                        children=(total,),
                        bits=32,
                        signed=True,
                    ),
                    block_id=1,
                ),
                Assignment(3, 0x1030, target, const(65), block_id=1),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, (), (1,)),
                1: BasicBlock(1, 0x1020, 0x1040, (0, 2), (2,)),
                2: BasicBlock(2, 0x1040, 0x1050, (1,), (1, 3)),
                3: BasicBlock(3, 0x1050, 0x1060, (2,), ()),
            },
            entry_block=0,
            conditions=[Condition(0x1040, 2, dynamic_bound, dynamic_bound.text)],
        )
        self.assertIn("BUF-011", self.rule_ids(ir))

    def test_persistent_stack_index_with_capacity_guard_is_safe(self):
        total = Expr(
            kind="var", text="total", key="total", bits=32, signed=True
        )
        slot = Expr(kind="var", text="slot", key="slot", bits=32, signed=True)
        target = Expr(
            kind="index",
            text="results[slot]",
            key="results",
            children=(var("results"), slot),
            bits=8,
        )
        dynamic_bound = Expr(
            kind="op",
            op="slt",
            children=(var("cursor"), var("count")),
        )
        capacity_bound = Expr(
            kind="op", op="slt", children=(total, const(8))
        )
        guard = Expr(
            kind="op",
            op="logical_and",
            children=(dynamic_bound, capacity_bound),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="bounded_results",
            buffers={"results": BufferInfo("results", "results", "stack", 8)},
            statements=[
                Assignment(1, 0x1010, total, const(0), block_id=0),
                Assignment(
                    2,
                    0x1020,
                    slot,
                    Expr(
                        kind="op",
                        op="postinc",
                        children=(total,),
                        bits=32,
                        signed=True,
                    ),
                    block_id=1,
                ),
                Assignment(3, 0x1030, target, const(65), block_id=1),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, (), (1,)),
                1: BasicBlock(1, 0x1020, 0x1040, (0, 2), (2,)),
                2: BasicBlock(2, 0x1040, 0x1050, (1,), (1, 3)),
                3: BasicBlock(3, 0x1050, 0x1060, (2,), ()),
            },
            entry_block=0,
            conditions=[Condition(0x1040, 2, guard, "guard")],
        )
        self.assertNotIn("BUF-011", self.rule_ids(ir))
        disjunctive = replace(
            guard,
            op="logical_or",
            text="cursor < count || total < 8",
        )
        not_actually_bounded = replace(
            ir,
            name="disjunctive_results",
            conditions=[Condition(0x1040, 2, disjunctive, disjunctive.text)],
        )
        self.assertIn("BUF-011", self.rule_ids(not_actually_bounded))

    def test_fixed_small_loop_does_not_trigger_accumulating_index_rule(self):
        total = Expr(
            kind="var", text="total", key="total", bits=32, signed=True
        )
        slot = Expr(kind="var", text="slot", key="slot", bits=32, signed=True)
        target = Expr(
            kind="index",
            text="results[slot]",
            key="results",
            children=(var("results"), slot),
            bits=8,
        )
        fixed_bound = Expr(
            kind="op", op="slt", children=(var("cursor"), const(4))
        )
        ir = FunctionIR(
            ea=0x1000,
            name="fixed_results",
            buffers={"results": BufferInfo("results", "results", "stack", 8)},
            statements=[
                Assignment(1, 0x1010, total, const(0), block_id=0),
                Assignment(
                    2,
                    0x1020,
                    slot,
                    Expr(
                        kind="op",
                        op="postinc",
                        children=(total,),
                        bits=32,
                        signed=True,
                    ),
                    block_id=1,
                ),
                Assignment(3, 0x1030, target, const(65), block_id=1),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, (), (1,)),
                1: BasicBlock(1, 0x1020, 0x1040, (0, 2), (2,)),
                2: BasicBlock(2, 0x1040, 0x1050, (1,), (1, 3)),
                3: BasicBlock(3, 0x1050, 0x1060, (2,), ()),
            },
            entry_block=0,
            conditions=[Condition(0x1040, 2, fixed_bound, "cursor < 4")],
        )
        self.assertNotIn("BUF-011", self.rule_ids(ir))

    def test_tainted_allocation_multiplication(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        product = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=64,
            signed=False,
        )
        allocation = Expr(
            kind="call",
            text="malloc(count * 16)",
            callee="malloc",
            children=(product,),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Assignment(2, 0x1020, var("ptr"), allocation),
        )
        self.assertIn("INT-003", self.rule_ids(ir))

    def test_narrow_calloc_factors_fit_size_t_product(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        allocation = Expr(
            kind="call",
            text="calloc(count, 16)",
            callee="calloc",
            children=(count, const(16)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Assignment(2, 0x1020, var("ptr"), allocation),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_two_32_bit_calloc_factors_fit_64_bit_size_t(self):
        rows = Expr(kind="var", text="rows", key="rows", bits=32, signed=False)
        columns = Expr(
            kind="var", text="columns", key="columns", bits=32, signed=False
        )
        allocation = Expr(
            kind="call",
            text="calloc(rows, columns)",
            callee="calloc",
            children=(rows, columns),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), rows, const(4))),
            Call(2, 0x1020, "read", (const(0), columns, const(4))),
            Assignment(3, 0x1030, var("ptr"), allocation),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_calloc_checks_implicit_64_bit_product(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        allocation = Expr(
            kind="call",
            text="calloc(count, 16)",
            callee="calloc",
            children=(count, const(16)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Assignment(2, 0x1020, var("ptr"), allocation),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_explicit_product_before_calloc_can_still_overflow(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        product = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=64,
            signed=False,
        )
        allocation = Expr(
            kind="call",
            text="calloc(1, count * 16)",
            callee="calloc",
            children=(const(1), product),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Assignment(2, 0x1020, var("ptr"), allocation),
        )
        self.assertIn("INT-003", self.rule_ids(ir))

    def test_guarded_allocation_product_is_proven_safe(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        guard = Expr(
            kind="op",
            text="count <= 1024",
            op="ule",
            children=(count, const(1024)),
        )
        product = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=64,
            signed=False,
        )
        allocation = Expr(
            kind="call",
            text="malloc(count * 16)",
            callee="malloc",
            children=(product,),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Assignment(
                2,
                0x1020,
                var("ptr"),
                allocation,
                guards=(guard,),
            ),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_32_bit_intermediate_product_can_wrap_before_malloc_widening(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        product = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=32,
            signed=False,
        )
        allocation = Expr(
            kind="call",
            text="malloc(count * 16)",
            callee="malloc",
            children=(product,),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Assignment(2, 0x1020, var("ptr"), allocation),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "INT-003"
        )
        self.assertIn("bits=32", finding.evidence)

    def test_widened_32_bit_factor_product_is_safe(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        widened = Expr(
            kind="cast",
            text="(size_t)count",
            children=(count,),
            bits=64,
            signed=False,
        )
        product = Expr(
            kind="op",
            text="(size_t)count * 16",
            op="mul",
            children=(widened, const(16)),
            bits=64,
            signed=False,
        )
        allocation = Expr(
            kind="call",
            text="malloc((size_t)count * 16)",
            callee="malloc",
            children=(product,),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Assignment(2, 0x1020, var("ptr"), allocation),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_32_bit_io_length_product_can_wrap(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        product = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(2, 0x1020, "read", (const(0), var("destination"), product)),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "INT-003"
        )
        self.assertIn("bits=32", finding.evidence)

    def test_widened_32_bit_io_length_product_is_safe(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        widened = Expr(
            kind="cast",
            text="(size_t)count",
            children=(count,),
            bits=64,
            signed=False,
        )
        product = Expr(
            kind="op",
            text="(size_t)count * 16",
            op="mul",
            children=(widened, const(16)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(2, 0x1020, "read", (const(0), var("destination"), product)),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_signed_wide_product_of_unsigned_32_bit_value_is_nonnegative(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        product = Expr(
            kind="op",
            text="16LL * count",
            op="mul",
            children=(const(16), count),
            bits=64,
            signed=True,
        )
        enlarged = Expr(
            kind="op",
            text="16LL * count + 1",
            op="add",
            children=(product, const(1)),
            bits=64,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(2, 0x1020, "read", (const(0), var("destination"), enlarged)),
        )
        rules = self.rule_ids(ir)
        self.assertNotIn("INT-002", rules)
        self.assertNotIn("INT-003", rules)

    def test_guarded_64_bit_io_length_product_is_safe(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        guard = Expr(
            kind="op",
            text="count <= 1024",
            op="ule",
            children=(count, const(1024)),
        )
        product = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Call(
                2,
                0x1020,
                "read",
                (const(0), var("destination"), product),
                guards=(guard,),
            ),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_reaching_mask_bounds_io_length_product(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        masked = Expr(
            kind="var", text="masked", key="masked", bits=64, signed=False
        )
        mask = Expr(
            kind="op",
            text="count & 0xFFFF",
            op="and",
            children=(count, const((1 << 16) - 1)),
            bits=64,
            signed=False,
        )
        product = Expr(
            kind="op",
            text="masked * 16",
            op="mul",
            children=(masked, const(16)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Assignment(2, 0x1020, masked, mask),
            Call(3, 0x1030, "read", (const(0), var("destination"), product)),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_32_bit_io_length_left_shift_can_wrap(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        shifted = Expr(
            kind="op",
            text="count << 4",
            op="shl",
            children=(count, const(4)),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(2, 0x1020, "read", (const(0), var("destination"), shifted)),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "INT-003"
        )
        self.assertIn("count << 4", finding.evidence)
        self.assertIn("bits=32", finding.evidence)

    def test_widened_32_bit_io_length_left_shift_is_safe(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        widened = Expr(
            kind="cast",
            text="(size_t)count",
            children=(count,),
            bits=64,
            signed=False,
        )
        shifted = Expr(
            kind="op",
            text="(size_t)count << 4",
            op="shl",
            children=(widened, const(4)),
            bits=64,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(2, 0x1020, "read", (const(0), var("destination"), shifted)),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_guarded_signed_io_length_product_is_safe(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=True
        )
        positive = Expr(
            kind="op",
            text="count > 0",
            op="sgt",
            children=(count, const(0)),
        )
        bounded = Expr(
            kind="op",
            text="count <= 1024",
            op="sle",
            children=(count, const(1024)),
        )
        guard = Expr(
            kind="op",
            text="count > 0 && count <= 1024",
            op="logical_and",
            children=(positive, bounded),
        )
        product = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=64,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Call(
                2,
                0x1020,
                "read",
                (const(0), var("destination"), product),
                guards=(guard,),
            ),
        )
        rules = self.rule_ids(ir)
        self.assertNotIn("INT-002", rules)
        self.assertNotIn("INT-003", rules)

    def test_signed_io_product_uses_signed_maximum(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=True
        )
        positive = Expr(
            kind="op", op="sgt", children=(count, const(0))
        )
        bounded = Expr(
            kind="op",
            op="sle",
            children=(count, const((1 << 63) - 1)),
        )
        guard = Expr(
            kind="op",
            op="logical_and",
            children=(positive, bounded),
        )
        product = Expr(
            kind="op",
            text="count * 2",
            op="mul",
            children=(count, const(2)),
            bits=64,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Call(
                2,
                0x1020,
                "read",
                (const(0), var("destination"), product),
                guards=(guard,),
            ),
        )
        self.assertIn("INT-003", self.rule_ids(ir))

    def test_signed_guard_does_not_bound_unsigned_io_product(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        signed_count = Expr(
            kind="cast",
            text="(int)count",
            children=(count,),
            bits=32,
            signed=True,
        )
        positive = Expr(
            kind="op", op="sgt", children=(signed_count, const(0))
        )
        bounded = Expr(
            kind="op", op="sle", children=(signed_count, const(1024))
        )
        guard = Expr(
            kind="op",
            op="logical_and",
            children=(positive, bounded),
        )
        product = Expr(
            kind="op",
            text="count * 16",
            op="mul",
            children=(count, const(16)),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(
                2,
                0x1020,
                "read",
                (const(0), var("destination"), product),
                guards=(guard,),
            ),
        )
        self.assertIn("INT-003", self.rule_ids(ir))

    def test_signed_narrowing_cast_can_make_left_shift_undefined(self):
        count = Expr(
            kind="var", text="count", key="count", bits=64, signed=False
        )
        narrowed = Expr(
            kind="cast",
            text="(int)count",
            children=(count,),
            bits=32,
            signed=True,
        )
        shifted = Expr(
            kind="op",
            text="(int)count << 0",
            op="shl",
            children=(narrowed, const(0)),
            bits=32,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(8))),
            Call(2, 0x1020, "read", (const(0), var("destination"), shifted)),
        )
        self.assertIn("INT-003", self.rule_ids(ir))

    def test_out_of_range_shift_count_is_reported(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        shifted = Expr(
            kind="op",
            text="count << 32",
            op="shl",
            children=(count, const(32)),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Assignment(2, 0x1020, var("pointer"), call_expr("malloc", shifted)),
        )
        self.assertIn("INT-003", self.rule_ids(ir))

    def test_tainted_dynamic_io_shift_is_reported(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        shift = Expr(
            kind="var", text="shift", key="shift", bits=32, signed=False
        )
        shifted = Expr(
            kind="op",
            text="count << shift",
            op="shl",
            children=(count, shift),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(2, 0x1020, "read", (const(0), shift, const(4))),
            Call(3, 0x1030, "read", (const(0), var("destination"), shifted)),
        )
        self.assertIn("INT-003", self.rule_ids(ir))

    def test_guarded_wide_dynamic_io_shift_is_safe(self):
        count = Expr(
            kind="var", text="count", key="count", bits=32, signed=False
        )
        shift = Expr(
            kind="var", text="shift", key="shift", bits=32, signed=False
        )
        widened = Expr(
            kind="cast",
            text="(size_t)count",
            children=(count,),
            bits=64,
            signed=False,
        )
        shifted = Expr(
            kind="op",
            text="(size_t)count << shift",
            op="shl",
            children=(widened, shift),
            bits=64,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="shift <= 4",
            op="ule",
            children=(shift, const(4)),
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), count, const(4))),
            Call(2, 0x1020, "read", (const(0), shift, const(4))),
            Call(
                3,
                0x1030,
                "read",
                (const(0), var("destination"), shifted),
                guards=(guard,),
            ),
        )
        self.assertNotIn("INT-003", self.rule_ids(ir))

    def test_tainted_allocation_addition_overflow(self):
        size = Expr(
            kind="var", text="size", key="size", bits=32, signed=False
        )
        enlarged = Expr(
            kind="op",
            text="size + 32",
            op="add",
            children=(size, const(32)),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), size, const(4))),
            Assignment(
                2,
                0x1020,
                var("ptr"),
                call_expr("malloc", enlarged),
            ),
        )
        finding = next(
            item
            for item in self.analyzer.analyze_function(ir)
            if item.rule_id == "INT-005"
        )
        self.assertIn("positive_increment=32", finding.evidence)
        self.assertIn("bits=32", finding.evidence)

    def test_allocation_addition_upper_bound_guard_proves_safe(self):
        size = Expr(
            kind="var", text="size", key="size", bits=32, signed=False
        )
        increment = 32
        safe_maximum = (1 << 32) - 1 - increment
        guard = Expr(
            kind="op",
            text="size <= safe_maximum",
            op="ule",
            children=(size, const(safe_maximum)),
        )
        enlarged = Expr(
            kind="op",
            text="size + 32",
            op="add",
            children=(size, const(increment)),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), size, const(4))),
            Assignment(
                2,
                0x1020,
                var("ptr"),
                call_expr("malloc", enlarged),
                guards=(guard,),
            ),
        )
        self.assertNotIn("INT-005", self.rule_ids(ir))

    def test_narrow_or_masked_value_cannot_wrap_wider_allocation_addition(self):
        narrow = Expr(
            kind="var", text="narrow", key="narrow", bits=16, signed=False
        )
        promoted = Expr(
            kind="op",
            text="narrow + 32",
            op="add",
            children=(narrow, const(32)),
            bits=32,
            signed=False,
        )
        wide = Expr(kind="var", text="wide", key="wide", bits=32, signed=False)
        masked = Expr(
            kind="op",
            text="wide & 0xFFFF",
            op="and",
            children=(wide, const((1 << 16) - 1)),
            bits=32,
            signed=False,
        )
        masked_addition = Expr(
            kind="op",
            text="(wide & 0xFFFF) + 32",
            op="add",
            children=(masked, const(32)),
            bits=32,
            signed=False,
        )
        narrow_ir = function(
            Call(1, 0x1010, "read", (const(0), narrow, const(2))),
            Assignment(
                2,
                0x1020,
                var("ptr"),
                call_expr("malloc", promoted),
            ),
        )
        masked_ir = function(
            Call(1, 0x1010, "read", (const(0), wide, const(4))),
            Assignment(
                2,
                0x1020,
                var("ptr"),
                call_expr("malloc", masked_addition),
            ),
        )
        self.assertNotIn("INT-005", self.rule_ids(narrow_ir))
        self.assertNotIn("INT-005", self.rule_ids(masked_ir))

    def test_unsigned_narrowing_cast_bounds_allocation_addition(self):
        wide = Expr(kind="var", text="wide", key="wide", bits=64, signed=False)
        narrowed = Expr(
            kind="cast",
            text="(unsigned short)wide",
            children=(wide,),
            bits=16,
            signed=False,
        )
        enlarged = Expr(
            kind="op",
            text="(unsigned short)wide + 32",
            op="add",
            children=(narrowed, const(32)),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), wide, const(8))),
            Assignment(
                2,
                0x1020,
                var("ptr"),
                call_expr("malloc", enlarged),
            ),
        )
        self.assertNotIn("INT-005", self.rule_ids(ir))

    def test_reaching_mask_assignment_bounds_allocation_addition(self):
        wide = Expr(kind="var", text="wide", key="wide", bits=32, signed=False)
        masked = Expr(
            kind="var", text="masked", key="masked", bits=32, signed=False
        )
        mask_expression = Expr(
            kind="op",
            text="wide & 0xFFFF",
            op="and",
            children=(wide, const((1 << 16) - 1)),
            bits=32,
            signed=False,
        )
        enlarged = Expr(
            kind="op",
            text="masked + 32",
            op="add",
            children=(masked, const(32)),
            bits=32,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), wide, const(4))),
            Assignment(2, 0x1020, masked, mask_expression),
            Assignment(
                3,
                0x1030,
                var("ptr"),
                call_expr("malloc", enlarged),
            ),
        )
        self.assertNotIn("INT-005", self.rule_ids(ir))

    def test_signed_allocation_addition_is_not_modeled_as_unsigned_wrap(self):
        size = Expr(kind="var", text="size", key="size", bits=32, signed=True)
        enlarged = Expr(
            kind="op",
            text="size + 32",
            op="add",
            children=(size, const(32)),
            bits=32,
            signed=True,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), size, const(4))),
            Assignment(
                2,
                0x1020,
                var("ptr"),
                call_expr("malloc", enlarged),
            ),
        )
        self.assertNotIn("INT-005", self.rule_ids(ir))

    def test_attacker_controlled_inline_index(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=True)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        ir = function(
            Call(1, 0x1010, "read", (const(0), index, const(4))),
            Assignment(2, 0x1020, target, const(65)),
            buffers=(self.stack32,),
        )
        self.assertIn("IDX-001", self.rule_ids(ir))

    def test_dynamic_pointer_store_recovers_index_and_kills_stale_guard(self):
        index = Expr(
            kind="var", text="index", key="index", bits=32, signed=False
        )
        base = Expr(
            kind="cast",
            text="(unsigned char *)buf",
            key="buf",
            children=(var("buf"),),
            bits=64,
            signed=False,
        )
        address = Expr(
            kind="op",
            text="(unsigned char *)buf + index",
            key="buf",
            op="add",
            children=(base, index),
            bits=64,
            signed=False,
        )
        target = Expr(
            kind="deref",
            text="*((unsigned char *)buf + index)",
            key="buf",
            children=(address,),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="index < 32",
            op="ult",
            children=(index, const(32)),
        )
        incremented = Expr(
            kind="op",
            text="index += 32",
            key="index",
            op="add",
            children=(index, const(32)),
            offset=32,
            bits=32,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="dynamic_pointer_store",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1010, "read", (const(0), index, const(4)), block_id=0),
                Assignment(
                    3,
                    0x1030,
                    index,
                    incremented,
                    block_id=1,
                    guards=(guard,),
                ),
                Assignment(
                    4,
                    0x1040,
                    target,
                    const(65),
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, successors=(1, 2)),
                1: BasicBlock(1, 0x1020, 0x1050, predecessors=(0,)),
                2: BasicBlock(2, 0x1050, 0x1060, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1020, 0, guard, guard.text, order=2)],
        )
        self.assertIn("IDX-001", self.rule_ids(ir))

    def test_signed_index_with_only_upper_guard(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=True)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="index > 31",
            op="sgt",
            children=(index, const(31)),
            bits=8,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="indexed",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1010, "read", (const(0), index, const(4))),
                Assignment(2, 0x1020, target, const(65)),
            ],
            conditions=[Condition(0x1018, None, guard, guard.text)],
        )
        self.assertIn("IDX-002", self.rule_ids(ir))

    def test_unsigned_comparison_rejects_negative_promoted_index(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=True)
        unsigned_index = Expr(
            kind="cast",
            text="(unsigned)index",
            key="index",
            children=(index,),
            bits=32,
            signed=False,
        )
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="(unsigned)index <= 31",
            op="ule",
            children=(unsigned_index, const(31)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="unsigned_guarded_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1010, "read", (const(0), index, const(4))),
                Assignment(2, 0x1020, target, const(65)),
            ],
            conditions=[Condition(0x1018, None, guard, guard.text)],
        )
        self.assertNotIn("IDX-002", self.rule_ids(ir))

    def test_index_guard_before_merge_does_not_bless_inline_store(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=True)
        unsigned_index = Expr(
            kind="cast",
            text="(unsigned)index",
            key="index",
            children=(index,),
            bits=32,
            signed=False,
        )
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="(unsigned)index <= 31",
            op="ule",
            children=(unsigned_index, const(31)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="merged_index_guard",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Assignment(2, 0x1040, target, const(65), block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1020, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1020, 0x1030, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1030, 0x1050, predecessors=(1, 2)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        self.assertIn("IDX-001", self.rule_ids(ir))

    def test_assignment_path_index_guard_proves_inline_store_bounds(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=True)
        unsigned_index = Expr(
            kind="cast",
            text="(unsigned)index",
            key="index",
            children=(index,),
            bits=32,
            signed=False,
        )
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="(unsigned)index <= 31",
            op="ule",
            children=(unsigned_index, const(31)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="guarded_index_path",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Assignment(
                    2,
                    0x1020,
                    target,
                    const(65),
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1030, predecessors=(0,)),
                2: BasicBlock(2, 0x1030, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text)],
        )
        rule_ids = self.rule_ids(ir)
        self.assertNotIn("IDX-001", rule_ids)
        self.assertNotIn("IDX-002", rule_ids)

    def test_rejected_index_path_proves_inline_store_bounds(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=False)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        rejection = Expr(
            kind="op",
            text="index >= 32",
            op="uge",
            children=(index, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="validated_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Return(2, 0x1020, const(0), block_id=1, guards=(rejection,)),
                Assignment(3, 0x1030, target, const(65), block_id=2),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, rejection, rejection.text)],
        )
        self.assertNotIn("IDX-001", self.rule_ids(ir))

    def test_rejected_index_guard_follows_an_unmodified_reaching_alias(self):
        raw = Expr(kind="var", text="raw", key="raw", bits=32, signed=False)
        index = Expr(kind="var", text="index", key="index", bits=64, signed=True)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        rejection = Expr(
            kind="op",
            text="raw > 15",
            op="ugt",
            children=(raw, const(15)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="validated_index_alias",
            buffers={"buf": BufferInfo("buf", "buf", "stack", 16)},
            statements=[
                Call(1, 0x1004, "read", (const(0), raw, const(4)), block_id=0),
                Assignment(
                    2,
                    0x1008,
                    index,
                    Expr(
                        kind="cast",
                        text="(int)raw",
                        key="raw",
                        children=(raw,),
                        bits=64,
                        signed=True,
                    ),
                    block_id=0,
                ),
                Return(3, 0x1020, const(0), block_id=1, guards=(rejection,)),
                Assignment(4, 0x1030, target, const(65), block_id=2),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1010, 0, rejection, rejection.text, order=2)],
        )
        rule_ids = self.rule_ids(ir)
        self.assertNotIn("IDX-001", rule_ids)
        self.assertNotIn("IDX-002", rule_ids)

    def test_rejected_compound_index_path_proves_inline_store_bounds(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=False)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        rejection = Expr(
            kind="op",
            text="index >= 32 || slot == 0",
            op="logical_or",
            children=(
                Expr(
                    kind="op",
                    text="index >= 32",
                    op="uge",
                    children=(index, const(32)),
                ),
                Expr(
                    kind="op",
                    text="slot == 0",
                    op="eq",
                    children=(var("slot"), const(0)),
                ),
            ),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="validated_compound_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Call(
                    2,
                    0x1020,
                    "exit",
                    (const(0),),
                    block_id=1,
                    guards=(rejection,),
                ),
                Assignment(3, 0x1030, target, const(65), block_id=2),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, rejection, rejection.text)],
        )
        self.assertNotIn("IDX-001", self.rule_ids(ir))

    def test_rejected_compound_guard_keeps_unmodified_index_fact(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=False)
        slot = Expr(
            kind="member",
            text="state.slot",
            key="state",
            offset=8,
            bits=64,
            signed=False,
        )
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        rejection = Expr(
            kind="op",
            text="index >= 32 || state.slot == 0",
            op="logical_or",
            children=(
                Expr(
                    kind="op",
                    text="index >= 32",
                    op="uge",
                    children=(index, const(32)),
                ),
                Expr(
                    kind="op",
                    text="state.slot == 0",
                    op="eq",
                    children=(slot, const(0)),
                ),
            ),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="validated_index_with_cleared_slot",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Call(
                    2,
                    0x1020,
                    "exit",
                    (const(0),),
                    block_id=1,
                    guards=(rejection,),
                ),
                Assignment(3, 0x1030, slot, const(0), block_id=2),
                Assignment(4, 0x1038, target, const(65), block_id=2),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1040, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, rejection, rejection.text)],
        )
        self.assertNotIn("IDX-001", self.rule_ids(ir))

    def test_nested_rejected_path_does_not_negate_each_guard_independently(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=False)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        outer = Expr(
            kind="op",
            text="enabled != 0",
            op="ne",
            children=(var("enabled"), const(0)),
        )
        rejection = Expr(
            kind="op",
            text="index >= 32",
            op="uge",
            children=(index, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="nested_rejected_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Return(
                    2,
                    0x1020,
                    const(0),
                    block_id=2,
                    guards=(outer, rejection),
                ),
                Assignment(3, 0x1030, target, const(65), block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 3)),
                1: BasicBlock(1, 0x1010, 0x1018, predecessors=(0,), successors=(2, 3)),
                2: BasicBlock(2, 0x1018, 0x1028, predecessors=(1,)),
                3: BasicBlock(3, 0x1028, 0x1040, predecessors=(0, 1)),
            },
            entry_block=0,
            conditions=[
                Condition(0x1008, 0, outer, outer.text, order=1),
                Condition(0x1014, 1, rejection, rejection.text, order=1),
            ],
        )
        self.assertIn("IDX-001", self.rule_ids(ir))

    def test_assignment_path_guard_is_killed_by_index_redefinition(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=False)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="index < 32",
            op="ult",
            children=(index, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="redefined_guarded_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Assignment(
                    3,
                    0x1020,
                    index,
                    call_expr("attacker_index"),
                    block_id=1,
                    guards=(guard,),
                ),
                Assignment(
                    4,
                    0x1030,
                    target,
                    const(65),
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1040, predecessors=(0,)),
                2: BasicBlock(2, 0x1040, 0x1050, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text, order=2)],
        )
        self.assertIn("IDX-001", self.rule_ids(ir))

    def test_assignment_path_guard_is_killed_by_field_redefinition(self):
        index = Expr(
            kind="member",
            text="state.index",
            key="state",
            offset=8,
            bits=32,
            signed=False,
        )
        target = Expr(
            kind="index",
            text="buf[state.index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="state.index < 32",
            op="ult",
            children=(index, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="redefined_guarded_field",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Assignment(
                    3,
                    0x1020,
                    index,
                    call_expr("attacker_index"),
                    block_id=1,
                    guards=(guard,),
                ),
                Assignment(
                    4,
                    0x1030,
                    target,
                    const(65),
                    block_id=1,
                    guards=(guard,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1040, predecessors=(0,)),
                2: BasicBlock(2, 0x1040, 0x1050, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, guard, guard.text, order=2)],
        )
        self.assertIn("IDX-001", self.rule_ids(ir))

    def test_negative_else_guard_is_killed_by_index_redefinition(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=False)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        rejection = Expr(
            kind="op",
            text="index >= 32",
            op="uge",
            children=(index, const(32)),
        )
        accepted = self.analyzer._negate_guard_expression(rejection)
        ir = FunctionIR(
            ea=0x1000,
            name="redefined_else_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Assignment(
                    3,
                    0x1020,
                    index,
                    call_expr("attacker_index"),
                    block_id=1,
                    guards=(accepted,),
                ),
                Assignment(
                    4,
                    0x1030,
                    target,
                    const(65),
                    block_id=1,
                    guards=(accepted,),
                ),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1040, predecessors=(0,)),
                2: BasicBlock(2, 0x1040, 0x1050, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, rejection, rejection.text, order=2)],
        )
        self.assertIn("IDX-001", self.rule_ids(ir))

    def test_rejected_guard_is_killed_by_index_redefinition(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=False)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        rejection = Expr(
            kind="op",
            text="index >= 32",
            op="uge",
            children=(index, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="redefined_rejected_index",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1004, "read", (const(0), index, const(4)), block_id=0),
                Return(2, 0x1020, const(0), block_id=1, guards=(rejection,)),
                Assignment(
                    3,
                    0x1030,
                    index,
                    call_expr("attacker_index"),
                    block_id=2,
                ),
                Assignment(4, 0x1040, target, const(65), block_id=2),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1010, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,)),
                2: BasicBlock(2, 0x1028, 0x1050, predecessors=(0,)),
            },
            entry_block=0,
            conditions=[Condition(0x1008, 0, rejection, rejection.text, order=1)],
        )
        self.assertIn("IDX-001", self.rule_ids(ir))

    def test_unsigned_source_fact_survives_promoted_signed_index(self):
        unsigned_index = Expr(
            kind="var", text="index", key="index", bits=32, signed=False
        )
        promoted_index = Expr(
            kind="var", text="(int)index", key="index", bits=64, signed=True
        )
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), promoted_index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="index > 31",
            op="ugt",
            children=(unsigned_index, const(31)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="unsigned_indexed",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1010, "read", (const(0), unsigned_index, const(4))),
                Assignment(2, 0x1020, unsigned_index, unsigned_index),
                Assignment(3, 0x1030, target, const(65)),
            ],
            conditions=[Condition(0x1028, None, guard, guard.text)],
        )
        rule_ids = self.rule_ids(ir)
        self.assertNotIn("IDX-001", rule_ids)
        self.assertNotIn("IDX-002", rule_ids)

    def test_constant_inline_store_oob(self):
        target = Expr(
            kind="index",
            text="buf[40]",
            key="buf",
            children=(var("buf"), const(40)),
            offset=40,
            bits=8,
            signed=False,
        )
        ir = function(
            Assignment(1, 0x1010, target, const(65)),
            buffers=(self.stack32,),
        )
        self.assertIn("BUF-006", self.rule_ids(ir))

    def test_loaded_global_pointer_is_not_a_global_buffer_alias(self):
        global_slot = BufferInfo("g:table", "table", "global", 8)
        slot_load = Expr(
            kind="index",
            text="table[0]",
            key="g:table",
            children=(Expr(kind="global", text="table", key="g:table"), const(0)),
            bits=64,
            signed=False,
        )
        pointer = Expr(
            kind="cast",
            text="(vector *)(table[0] + 32)",
            key="g:table",
            children=(
                Expr(
                    kind="op",
                    text="table[0] + 32",
                    key="g:table",
                    op="add",
                    children=(slot_load, const(32)),
                    offset=32,
                ),
            ),
            offset=32,
        )
        target = Expr(
            kind="deref",
            text="*cursor",
            key="cursor",
            children=(var("cursor"),),
            bits=128,
        )
        ir = function(
            Assignment(1, 0x1010, var("cursor"), pointer),
            Assignment(2, 0x1020, target, var("vector")),
            buffers=(global_slot,),
        )
        self.assertNotIn("BUF-006", self.rule_ids(ir))

    def test_inline_self_store_is_not_an_overflow(self):
        fragment = BufferInfo("buf", "buf", "stack", 7)
        target = Expr(
            kind="deref",
            text="*(_QWORD *)&buf[index - 8]",
            key="buf",
            children=(var("buf"), var("index")),
            offset=-8,
            bits=64,
        )
        ir = function(Assignment(1, 0x1010, target, target), buffers=(fragment,))
        self.assertNotIn("BUF-006", self.rule_ids(ir))

    def test_dominating_heap_allocation_proves_inline_underflow(self):
        target = Expr(
            kind="deref",
            text="*(ptr - 1)",
            key="ptr",
            children=(
                Expr(
                    kind="op",
                    text="ptr - 1",
                    key="ptr",
                    op="sub",
                    children=(var("ptr"), const(1)),
                    offset=-1,
                ),
            ),
            offset=-1,
            bits=8,
            signed=False,
        )
        ir = FunctionIR(
            ea=0x1000,
            name="heap_underflow",
            statements=[
                Assignment(
                    1,
                    0x1010,
                    var("ptr"),
                    call_expr("malloc", const(16)),
                    block_id=0,
                ),
                Assignment(2, 0x1020, target, const(65), block_id=1),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1018, successors=(1,)),
                1: BasicBlock(1, 0x1018, 0x1030, predecessors=(0,)),
            },
            entry_block=0,
        )
        self.assertIn("BUF-006", self.rule_ids(ir))

    def test_disjoint_heap_capacity_does_not_taint_reused_lvar_store(self):
        target = Expr(
            kind="deref",
            text="*(result - 2)",
            key="result",
            children=(
                Expr(
                    kind="op",
                    text="result - 2",
                    key="result",
                    op="sub",
                    children=(var("result"), const(2)),
                    offset=-2,
                ),
            ),
            offset=-2,
            bits=16,
            signed=False,
        )
        unrelated_value = Expr(
            kind="op",
            text="padding + base",
            op="add",
            children=(var("padding"), var("base")),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="branch_reused_result",
            statements=[
                Assignment(
                    1,
                    0x1010,
                    var("allocation"),
                    call_expr("malloc", const(64)),
                    block_id=1,
                ),
                Assignment(2, 0x1020, var("result"), var("allocation"), block_id=1),
                Assignment(3, 0x1030, var("result"), unrelated_value, block_id=2),
                Assignment(4, 0x1040, target, var("padding"), block_id=2),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1008, successors=(1, 2)),
                1: BasicBlock(1, 0x1010, 0x1028, predecessors=(0,), successors=(3,)),
                2: BasicBlock(2, 0x1030, 0x1048, predecessors=(0,), successors=(3,)),
                3: BasicBlock(3, 0x1050, 0x1060, predecessors=(1, 2)),
            },
            entry_block=0,
        )
        self.assertNotIn("BUF-006", self.rule_ids(ir))

    def test_imprecise_split_lvar_does_not_claim_constant_oob(self):
        target = Expr(
            kind="index",
            text="fragment[40]",
            key="fragment",
            children=(var("fragment"), const(40)),
            offset=40,
            bits=8,
            signed=False,
        )
        fragment = BufferInfo("fragment", "fragment", "stack", 8, precise=False)
        ir = function(Assignment(1, 0x1010, target, const(65)), buffers=(fragment,))
        self.assertNotIn("BUF-006", self.rule_ids(ir))

    def test_storing_global_pointer_does_not_make_base_alias_global(self):
        global_object = BufferInfo("global", "global", "global", 2)
        pointer = var("ptr")
        slot = Expr(
            kind="index",
            text="ptr[1]",
            key="ptr",
            children=(pointer, const(1)),
            offset=8,
            bits=64,
            signed=False,
        )
        global_address = Expr(kind="address", text="&global", key="global")
        ir = function(
            Assignment(1, 0x1010, slot, global_address),
            Call(2, 0x1020, "memset", (pointer, const(0), const(4096))),
            buffers=(global_object,),
        )
        self.assertNotIn("BUF-003", self.rule_ids(ir))

    def test_non_dominating_index_check_is_not_accepted(self):
        index = Expr(kind="var", text="index", key="index", bits=32, signed=True)
        target = Expr(
            kind="index",
            text="buf[index]",
            key="buf",
            children=(var("buf"), index),
            bits=8,
            signed=False,
        )
        guard = Expr(
            kind="op",
            text="index < 32",
            op="slt",
            children=(index, const(32)),
        )
        ir = FunctionIR(
            ea=0x1000,
            name="indexed",
            buffers={"buf": self.stack32},
            statements=[
                Call(1, 0x1010, "read", (const(0), index, const(4)), block_id=0),
                Assignment(2, 0x1040, target, const(65), block_id=3),
            ],
            blocks={
                0: BasicBlock(0, 0x1000, 0x1020, (), (1, 2)),
                1: BasicBlock(1, 0x1020, 0x1030, (0,), (3,)),
                2: BasicBlock(2, 0x1030, 0x1040, (0,), (3,)),
                3: BasicBlock(3, 0x1040, 0x1050, (1, 2), ()),
            },
            entry_block=0,
            conditions=[Condition(0x1020, 1, guard, guard.text)],
        )
        rule_ids = self.rule_ids(ir)
        self.assertIn("IDX-001", rule_ids)
        self.assertNotIn("IDX-002", rule_ids)


if __name__ == "__main__":
    unittest.main()
