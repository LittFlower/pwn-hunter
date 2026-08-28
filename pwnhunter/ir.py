"""Small, IDA-independent intermediate representation used by the analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import TypeAlias


Key: TypeAlias = str


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass(frozen=True, slots=True)
class Expr:
    """Normalized expression.

    ``key`` identifies the underlying object when known. References, array
    accesses, casts, and simple pointer arithmetic retain their base key.
    """

    kind: str
    text: str = ""
    key: Key | None = None
    value: int | None = None
    string: str | None = None
    callee: str | None = None
    op: str | None = None
    children: tuple["Expr", ...] = ()
    offset: int = 0
    callee_ea: int | None = None
    bits: int | None = None
    signed: bool | None = None
    # ``None`` means the producer could not recover a reliable type fact.
    # Keeping this separate from ``key`` prevents scalar arithmetic such as
    # ``size + 16`` from being mistaken for an address into ``size``.
    is_pointer: bool | None = None

    def dependencies(self) -> set[Key]:
        result: set[Key] = set()
        if self.key is not None:
            result.add(self.key)
        for child in self.children:
            result.update(child.dependencies())
        return result

    def unwrapped(self) -> "Expr":
        """Remove value-preserving casts inserted by Hex-Rays."""

        current = self
        while current.kind == "cast" and current.children:
            current = current.children[0]
        return current


@dataclass(frozen=True, slots=True)
class BufferInfo:
    key: Key
    name: str
    storage: str
    capacity: int | None
    precise: bool = True
    # Hex-Rays occasionally splits one compiler-allocated stack object into
    # several source-level lvars (or gives the leading fragment a tiny type).
    # ``physical_capacity`` is the byte span up to the next non-overlapping
    # stack location.  It is only used to disprove a reported overwrite; the
    # semantic/type capacity above remains the value used to find candidates.
    physical_capacity: int | None = None
    # Some Linux x86 stack-protected functions place the saved stack guard
    # immediately after a byte array.  glibc clears the guard's low byte, so
    # an exact full-object input is followed by a machine-level NUL sentinel
    # even though that byte is outside the source-language array.  This is an
    # exploitability disproof for an otherwise unbounded C-string scan; it is
    # never counted as additional writable capacity.
    trailing_nul_sentinel: bool = False


@dataclass(frozen=True, slots=True)
class StackSlot:
    """Decompiler lvar occupying a concrete byte range in the stack frame.

    Hex-Rays can split one source aggregate into several lvars.  BufferInfo
    deliberately describes source-level objects, while these slots retain the
    machine layout needed by narrowly constrained aggregate recovery rules.
    """

    key: Key
    name: str
    offset: int
    width: int
    type_kind: str = "other"


@dataclass(frozen=True, slots=True)
class Call:
    order: int
    ea: int
    name: str
    args: tuple[Expr, ...]
    text: str = ""
    callee_ea: int | None = None
    origin: str = ""
    block_id: int | None = None
    # Source-level conditions whose positive branch contains this call.  The
    # microcode CFG alone cannot recover side effects embedded in a Hex-Rays
    # condition when that condition has BADADDR (common for ``--*ref <= 0``).
    guards: tuple[Expr, ...] = ()
    # Non-None for calls through a function pointer.  Direct-call summaries
    # continue to use name/callee_ea; the target expression exists so
    # lifetime analysis can see dereferences such as obj->callback(...).
    target: Expr | None = None


@dataclass(frozen=True, slots=True)
class Assignment:
    order: int
    ea: int
    target: Expr
    value: Expr
    text: str = ""
    block_id: int | None = None
    # Source-level conditions whose positive branch contains this write.
    # This mirrors Call.guards so conversion/range proofs do not treat a
    # branch condition as globally true after a CFG merge.
    guards: tuple[Expr, ...] = ()


@dataclass(frozen=True, slots=True)
class Return:
    order: int
    ea: int
    value: Expr
    text: str = ""
    block_id: int | None = None
    guards: tuple[Expr, ...] = ()


Statement: TypeAlias = Call | Assignment | Return


@dataclass(frozen=True, slots=True)
class BasicBlock:
    id: int
    start_ea: int
    end_ea: int
    predecessors: tuple[int, ...] = ()
    successors: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class Condition:
    ea: int
    block_id: int | None
    expression: Expr
    text: str = ""
    order: int = 0


@dataclass(slots=True)
class FunctionIR:
    ea: int
    name: str
    buffers: dict[Key, BufferInfo] = field(default_factory=dict)
    stack_slots: dict[Key, StackSlot] = field(default_factory=dict)
    statements: list[Statement] = field(default_factory=list)
    parameters: tuple[Key, ...] = ()
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    entry_block: int | None = None
    conditions: list[Condition] = field(default_factory=list)
    microcode_blocks: int = 0
    cfg_source: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    category: str
    severity: Severity
    confidence: str
    ea: int
    function_ea: int
    function_name: str
    callee: str
    summary: str
    evidence: str
    occurrences: int = 1
    related_eas: tuple[int, ...] = ()

    @property
    def fingerprint(self) -> tuple[str, int, str]:
        return self.rule_id, self.ea, self.evidence

    @property
    def semantic_fingerprint(self) -> tuple[str, int, str, str, str]:
        rule_id = self.rule_id
        callee = self.callee
        summary = self.summary
        evidence = self.evidence
        if self.rule_id in {"STR-001", "STR-002"}:
            # A missing terminator commonly appears first at strlen/strcmp and
            # then again when the computed length reaches memcpy.  Present the
            # chain as one vulnerability root while retaining every concrete
            # sink address in ``related_eas``.
            rule_id = "STR-CHAIN"
            callee = ""
            summary = "unterminated C-string chain"
            evidence = ""
        if self.rule_id in {"LIFE-002", "LIFE-004", "LIFE-005"}:
            # One dangling object can be consumed by many later calls. Keep
            # every address, but show a single lifecycle group per object.
            callee = ""
            summary = summary.split(" before ", 1)[0]
        return (
            rule_id,
            self.function_ea,
            callee,
            summary,
            evidence,
        )
