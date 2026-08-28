from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from pwnhunter.converters import (
    KnownConverterModule,
    discover_known_converter_modules,
    known_converter_findings,
)
from pwnhunter.ir import Assignment, Call, Expr, FunctionIR


def var(name: str) -> Expr:
    return Expr(kind="var", text=name, key=name)


def global_var(name: str) -> Expr:
    return Expr(kind="global", text=name, key=name)


def address(expression: Expr) -> Expr:
    return Expr(
        kind="address",
        text=f"&{expression.text}",
        key=expression.key,
        children=(expression,),
    )


def call_expression(name: str, *args: Expr) -> Expr:
    return Expr(kind="call", text=f"{name}(...)", callee=name, children=args)


def string(value: str) -> Expr:
    return Expr(kind="string", text=repr(value), string=value)


class ConverterTests(unittest.TestCase):
    def setUp(self):
        self.module = KnownConverterModule(
            converter="ISO-2022-CN-EXT",
            path=Path("/fixture/ISO-2022-CN-EXT.so"),
            sha256="a" * 64,
            build_id="fixture",
            issue="CVE-2024-2961",
            distribution="Ubuntu",
            version="2.39-0ubuntu8",
            fixed_version="2.39-0ubuntu8.1",
        )

    def converter_function(self, converter: str = "ISO-2022-CN-EXT") -> FunctionIR:
        return FunctionIR(
            ea=0x1800,
            name="convert",
            statements=[
                Assignment(
                    1,
                    0x1810,
                    var("cd"),
                    call_expression("iconv_open", string(converter), string("UTF-8")),
                ),
                Assignment(2, 0x1820, var("inbuf"), global_var("g:chunks")),
                Call(
                    3,
                    0x1A1E,
                    "iconv",
                    (
                        var("cd"),
                        address(var("inbuf")),
                        address(var("inleft")),
                        address(var("outbuf")),
                        address(var("outleft")),
                    ),
                ),
            ],
        )

    def test_exact_module_and_attacker_input_report_call_site(self):
        producer = FunctionIR(
            ea=0x1500,
            name="edit",
            statements=[
                Call(1, 0x1510, "read", (var("fd"), global_var("g:chunks"), var("n")))
            ],
        )
        findings = known_converter_findings(
            [producer, self.converter_function()],
            "/fixture/pwn",
            modules=(self.module,),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "CVT-001")
        self.assertEqual(findings[0].ea, 0x1A1E)
        self.assertEqual(findings[0].confidence, "High")
        self.assertIn("external-input", findings[0].evidence)

    def test_other_converter_is_not_reported(self):
        findings = known_converter_findings(
            [self.converter_function("UTF-16")],
            "/fixture/pwn",
            modules=(self.module,),
        )
        self.assertEqual(findings, [])

    def test_digest_mismatch_fails_closed(self):
        data = b"\x7fELF" + b"ISO-2022-CN-EXT//from_iso2022cn_ext_loop"
        manifest = {
            "schema_version": 1,
            "modules": [
                {
                    "converter": "ISO-2022-CN-EXT",
                    "filenames": ["ISO-2022-CN-EXT.so"],
                    "size": len(data),
                    "sha256": "0" * 64,
                    "markers": ["ISO-2022-CN-EXT//", "from_iso2022cn_ext_loop"],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pwn").write_bytes(b"\x7fELF")
            (root / "ISO-2022-CN-EXT.so").write_bytes(data)
            self.assertEqual(
                discover_known_converter_modules(root / "pwn", manifest=manifest), ()
            )


if __name__ == "__main__":
    unittest.main()
