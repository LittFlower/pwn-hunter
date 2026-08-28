"""Offline correlation of iconv call sites with known vulnerable sidecars.

The conversion routine is loaded at runtime and therefore is not part of the
service IDB.  This module deliberately requires an exact module digest before
reporting a known vulnerability; a converter name or a broad glibc version is
not sufficient evidence on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .ir import Assignment, Call, Expr, Finding, FunctionIR, Severity
from .rules import INPUT_WRITES, normalize_symbol


_MANIFEST = Path(__file__).with_name("known_converter_modules.json")


@dataclass(frozen=True, slots=True)
class KnownConverterModule:
    converter: str
    path: Path
    sha256: str
    build_id: str
    issue: str
    distribution: str
    version: str
    fixed_version: str


def _load_manifest(path: Path = _MANIFEST) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {"schema_version": 1, "modules": []}
    if payload.get("schema_version") != 1 or not isinstance(
        payload.get("modules"), list
    ):
        return {"schema_version": 1, "modules": []}
    return payload


def discover_known_converter_modules(
    binary_path: str | Path,
    *,
    manifest: Mapping[str, object] | None = None,
) -> tuple[KnownConverterModule, ...]:
    """Return exact-digest matches next to ``binary_path``.

    Size, ELF magic, converter-specific markers, and SHA-256 must all agree.
    The digest is the security boundary; the other checks make malformed
    manifests and accidental filename matches fail closed.
    """

    directory = Path(binary_path).resolve().parent
    entries = (manifest if manifest is not None else _load_manifest()).get(
        "modules", []
    )
    if not isinstance(entries, list):
        return ()

    matches: list[KnownConverterModule] = []
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            continue
        filenames = raw_entry.get("filenames", [])
        markers = raw_entry.get("markers", [])
        expected_size = raw_entry.get("size")
        expected_digest = str(raw_entry.get("sha256", "")).lower()
        if (
            not isinstance(filenames, list)
            or not isinstance(markers, list)
            or not isinstance(expected_size, int)
            or len(expected_digest) != 64
        ):
            continue
        for filename in filenames:
            # Manifest filenames are basenames, never paths supplied by a
            # scanned binary.  This also prevents a future manifest typo from
            # escaping the companion directory.
            if not isinstance(filename, str) or Path(filename).name != filename:
                continue
            candidate = directory / filename
            try:
                if candidate.stat().st_size != expected_size:
                    continue
                data = candidate.read_bytes()
            except OSError:
                continue
            if not data.startswith(b"\x7fELF"):
                continue
            try:
                marker_bytes = [marker.encode("ascii") for marker in markers]
            except (AttributeError, UnicodeEncodeError):
                continue
            if any(marker not in data for marker in marker_bytes):
                continue
            digest = hashlib.sha256(data).hexdigest()
            if digest != expected_digest:
                continue
            matches.append(
                KnownConverterModule(
                    converter=str(raw_entry.get("converter", "")),
                    path=candidate,
                    sha256=digest,
                    build_id=str(raw_entry.get("build_id", "")),
                    issue=str(raw_entry.get("issue", "")),
                    distribution=str(raw_entry.get("distribution", "")),
                    version=str(raw_entry.get("version", "")),
                    fixed_version=str(raw_entry.get("fixed_version", "")),
                )
            )
    return tuple(matches)


def _charset_name(expression: Expr | None) -> str | None:
    if expression is None or expression.string is None:
        return None
    # iconv accepts suffixes such as //TRANSLIT and treats encoding names
    # case-insensitively.  Punctuation variants are normalized as glibc does.
    base = expression.string.split("//", 1)[0]
    return "".join(character for character in base.upper() if character.isalnum())


def _external_input_globals(functions: Iterable[FunctionIR]) -> set[str]:
    result: set[str] = set()
    for function in functions:
        for statement in function.statements:
            if not isinstance(statement, Call):
                continue
            name = normalize_symbol(statement.name)
            for index in INPUT_WRITES.get(name, ()):
                if index >= len(statement.args):
                    continue
                result.update(
                    dependency
                    for dependency in statement.args[index].dependencies()
                    if dependency.startswith("g:")
                )
    return result


def _function_taint(function: FunctionIR, global_taint: set[str]) -> set[str]:
    """Compute the small taint slice needed for iconv's input pointer."""

    tainted = set(global_taint)
    for _ in range(max(2, len(function.statements) + 1)):
        before = len(tainted)
        for statement in function.statements:
            if isinstance(statement, Call):
                name = normalize_symbol(statement.name)
                for index in INPUT_WRITES.get(name, ()):
                    if index < len(statement.args):
                        tainted.update(statement.args[index].dependencies())
            elif isinstance(statement, Assignment) and statement.target.key:
                if statement.value.dependencies() & tainted:
                    tainted.add(statement.target.key)
        if len(tainted) == before:
            break
    return tainted


def _call_expression(expression: Expr) -> Expr | None:
    value = expression.unwrapped()
    return value if value.kind == "call" else None


def known_converter_findings(
    functions: list[FunctionIR],
    binary_path: str | Path,
    *,
    modules: tuple[KnownConverterModule, ...] | None = None,
) -> list[Finding]:
    """Correlate exact known-vulnerable modules with their service call sites."""

    known = modules
    if known is None:
        known = discover_known_converter_modules(binary_path)
    if not known:
        return []

    by_charset = {
        "".join(
            character
            for character in item.converter.upper()
            if character.isalnum()
        ): item
        for item in known
    }
    global_taint = _external_input_globals(functions)
    findings: list[Finding] = []
    for function in functions:
        tainted = _function_taint(function, global_taint)
        descriptors: dict[str, KnownConverterModule] = {}
        for statement in sorted(function.statements, key=lambda item: item.order):
            if isinstance(statement, Assignment) and statement.target.key:
                value = _call_expression(statement.value)
                if (
                    value is not None
                    and normalize_symbol(value.callee or "") == "iconv_open"
                ):
                    charset = _charset_name(
                        value.children[0] if value.children else None
                    )
                    module = by_charset.get(charset or "")
                    if module is not None:
                        descriptors[statement.target.key] = module
                    else:
                        descriptors.pop(statement.target.key, None)
                elif statement.target.key in descriptors:
                    descriptors.pop(statement.target.key, None)
                continue
            if (
                not isinstance(statement, Call)
                or normalize_symbol(statement.name) != "iconv"
            ):
                continue
            descriptor = statement.args[0] if statement.args else None
            module = descriptors.get(descriptor.key if descriptor else "")
            if module is None:
                continue
            input_expression = statement.args[1] if len(statement.args) > 1 else None
            attacker_reachable = bool(
                input_expression and input_expression.dependencies() & tainted
            )
            confidence = "High" if attacker_reachable else "Medium"
            severity = Severity.CRITICAL if attacker_reachable else Severity.HIGH
            reachability = (
                "input storage depends on an external-input write"
                if attacker_reachable
                else "external control of the input buffer was not proven"
            )
            findings.append(
                Finding(
                    rule_id="CVT-001",
                    category="Heap buffer overflow",
                    severity=severity,
                    confidence=confidence,
                    ea=statement.ea,
                    function_ea=function.ea,
                    function_name=function.name,
                    callee="iconv",
                    summary=(
                        f"known-vulnerable {module.converter} converter is "
                        "reached by iconv"
                    ),
                    evidence=(
                        f"{module.issue}; {module.path.name} sha256={module.sha256}; "
                        f"{module.distribution} glibc {module.version} "
                        f"(fixed in {module.fixed_version}); {reachability}"
                    ),
                )
            )
    return findings
