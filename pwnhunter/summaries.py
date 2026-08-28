"""Interprocedural summaries for small CTF-style wrapper functions.

The summary layer deliberately models effects instead of copying pseudocode.
That keeps it deterministic and allows a caller to be checked with the same
buffer and lifetime rules that are used for libc calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import operator

from .ir import Assignment, Call, Expr, FunctionIR, Return
from .rules import (
    ALLOC_SPECS,
    BOUNDED_CSTRING_READ_SPECS,
    BOUNDED_MULTI_READ_SPECS,
    BOUNDED_READ_SPECS,
    BOUNDED_WRITE_SPECS,
    COPY_SPECS,
    CSTRING_READ_ARGUMENTS,
    ERROR_SENTINEL_RETURNS,
    FORTIFIED_DESTINATION_SPECS,
    FORMAT_ARGUMENTS,
    FREE_NAMES,
    INPUT_WRITES,
    IOVEC_READ_SPECS,
    IOVEC_WRITE_SPECS,
    MESSAGE_READ_SPECS,
    MESSAGE_WRITE_SPECS,
    RETURN_SOURCES,
    SCANF_SPECS,
    STATEFUL_TAINT_RETURNS,
    SUCCESS_RETURN_LENGTH_SPECS,
    TAINT_PASSTHROUGH_RETURNS,
    UNBOUNDED_WRITE_SPECS,
    format_cstring_read_arguments,
    normalize_symbol,
)


# These APIs write exactly the requested byte count whenever the call returns.
# Other bounded writers (read/recv/snprintf/strncat/...) expose only a maximum:
# they can legitimately write zero bytes and therefore cannot prove that an
# earlier output sentinel was destroyed.
_DETERMINISTIC_BOUNDED_WRITE_NAMES = frozenset(
    {
        "memcpy",
        "memmove",
        "memset",
        "bcopy",
        "__memcpy_chk",
        "__memmove_chk",
        "__mempcpy_chk",
        "__memset_chk",
        "__strncpy_chk",
        "memcpy_like",
        "strncpy",
    }
)

# These effects describe an upper bound on bytes that may be written, not a
# prefix that every normal execution overwrites.  read/recv can return 0 or an
# error, scanf can perform zero conversions, and formatting/string operations
# can receive a zero bound.  They remain write/taint summaries, but cannot kill
# an older error-output definition merely from their requested capacity.
_MAY_WRITE_ONLY_NAMES = frozenset(
    (
        set(BOUNDED_WRITE_SPECS)
        | set(COPY_SPECS)
        | set(INPUT_WRITES)
        | set(SCANF_SPECS)
    )
    - set(_DETERMINISTIC_BOUNDED_WRITE_NAMES)
)

_NORETURN_NAMES = frozenset(
    {
        "abort",
        "exit",
        "quick_exit",
        "__assert_fail",
        "__fortify_fail",
        "__stack_chk_fail",
    }
)


@dataclass(frozen=True, slots=True)
class ValueRef:
    """A value expressed in terms of a wrapper argument or a constant."""

    argument: int | None = None
    constant: int | None = None
    # Constant byte displacement from an argument that is used as an address.
    # Dynamic pointer arithmetic is never collapsed into offset zero.
    offset: int = 0
    # Proven maximum byte length (excluding the terminating NUL) of a
    # C-string value that does not otherwise depend on a wrapper argument.
    cstring_max: int | None = None
    text: str = ""
    # Scalar expression template. Address displacement remains represented by
    # ``argument + offset`` above; keeping scalar operators separate prevents
    # integer arithmetic from acquiring object-location semantics.
    scalar_op: str | None = None
    operands: tuple["ValueRef", ...] = ()
    bits: int | None = None
    signed: bool | None = None

    def resolve(self, arguments: tuple[Expr, ...]) -> Expr | None:
        if self.scalar_op is not None:
            children = tuple(
                child
                for operand in self.operands
                if (child := operand.resolve(arguments)) is not None
            )
            if len(children) != len(self.operands):
                return None
            kind = "cast" if self.scalar_op == "cast" else "op"
            return Expr(
                kind=kind,
                text=self._render_scalar(children),
                op=None if kind == "cast" else self.scalar_op,
                children=children,
                bits=self.bits,
                signed=self.signed,
                is_pointer=False,
            )
        if self.argument is not None:
            if 0 <= self.argument < len(arguments):
                expression = arguments[self.argument]
                if self.offset == 0:
                    return expression
                if expression.key is None:
                    return None
                displacement = Expr(
                    kind="const",
                    text=str(abs(self.offset)),
                    value=abs(self.offset),
                    bits=expression.bits,
                    signed=False,
                )
                operator = "add" if self.offset > 0 else "sub"
                sign = "+" if self.offset > 0 else "-"
                return Expr(
                    kind="op",
                    text=(
                        f"{expression.text or expression.key} "
                        f"{sign} {abs(self.offset)}"
                    ),
                    key=expression.key,
                    op=operator,
                    children=(expression, displacement),
                    offset=expression.offset + self.offset,
                    bits=expression.bits,
                    signed=False,
                    is_pointer=True,
                )
            return None
        if self.constant is not None:
            return Expr(
                kind="const",
                text=self.text or str(self.constant),
                value=self.constant,
                bits=self.bits,
                signed=self.signed,
                is_pointer=False,
            )
        if self.cstring_max is not None:
            return Expr(
                kind="string",
                text=self.text or f"<C string <= {self.cstring_max} bytes>",
                string="X" * self.cstring_max,
            )
        return None

    def _render_scalar(self, children: tuple[Expr, ...]) -> str:
        rendered = []
        for child in children:
            text = child.text or child.key or "<value>"
            rendered.append(f"({text})" if child.kind == "op" else text)
        if self.scalar_op == "cast":
            if self.bits is None:
                cast_name = "scalar"
            elif self.signed is True:
                cast_name = f"int{self.bits}"
            elif self.signed is False:
                cast_name = f"uint{self.bits}"
            else:
                cast_name = f"scalar{self.bits}"
            value = rendered[0] if rendered else "<value>"
            return f"({cast_name}){value}"
        symbols = {"add": "+", "sub": "-", "mul": "*", "shl": "<<"}
        symbol = symbols.get(self.scalar_op or "", self.scalar_op or "?")
        return f" {symbol} ".join(rendered)


@dataclass(frozen=True, slots=True)
class WriteEffect:
    sink: str
    destination: ValueRef
    lengths: tuple[ValueRef, ...] = ()
    source: ValueRef | None = None
    unbounded: bool = False
    # True only when every normal exit from the summarized wrapper executes a
    # deterministic writer for exactly ``lengths`` bytes.  Ordinary write
    # summaries are may-effects; reusing them as strong clobbers can otherwise
    # erase an error-output contract when the callee writes zero bytes or only
    # on one branch.
    must_write: bool = False
    # ``taints_destination`` is an unconditional external-input source (for
    # example read/recv).  ``taint_sources`` models ordinary data dependence:
    # the destination is tainted only when at least one resolved source is.
    # Keeping the two forms separate prevents a custom memcpy/parser wrapper
    # from becoming an input source merely because it writes through a
    # parameter.
    taints_destination: bool = False
    taint_sources: tuple[ValueRef, ...] = ()
    # File-backed reads are external by default, but their descriptor/stream
    # provenance is retained so a caller can prove that the bytes came from a
    # fixed trusted kernel resource (for example ``/proc/self/maps``).  This
    # is deliberately separate from ``taint_sources``: a descriptor need not
    # itself be attacker-tainted for the bytes read through it to be hostile.
    input_handles: tuple[ValueRef, ...] = ()
    # Compiler-provided destination object size for an unbounded fortify
    # wrapper.  Preserve it through summaries so callers can distinguish an
    # active fail-closed check from SIZE_MAX or attacker-controlled fallback.
    fortify_capacity: ValueRef | None = None
    # Preserve a literal sprintf-family format and any variadic values that
    # can be expressed in wrapper arguments. This lets the caller reuse the
    # ordinary format-size proof instead of treating every wrapper as either
    # harmless or blindly unbounded.
    format_text: str | None = None
    format_arguments: tuple[ValueRef | None, ...] = ()


@dataclass(frozen=True, slots=True)
class ReadEffect:
    """A byte-range read expressed in terms of wrapper arguments."""

    sink: str
    source: ValueRef
    lengths: tuple[ValueRef, ...]
    sink_ea: int
    function_ea: int
    function_name: str
    # Preserve the compiler-supplied object size for fortified copies.  When
    # the requested length exceeds this trusted capacity, libc aborts before
    # reading the source as well as before writing the destination.
    fortify_capacity: ValueRef | None = None


@dataclass(frozen=True, slots=True)
class CStringReadEffect:
    """A C-string read of one wrapper argument, optionally byte-bounded."""

    sink: str
    value: ValueRef
    sink_ea: int
    function_ea: int
    function_name: str
    maximum: ValueRef | None = None
    # Pairwise bounded comparisons also stop when the peer reaches its NUL.
    # Keep that independent upper bound so callers can discharge the read
    # with either the explicit count or the peer string's proven length.
    peer_maximum: ValueRef | None = None


@dataclass(frozen=True, slots=True)
class IovecReadEffect:
    """A scatter/gather output expressed in wrapper arguments."""

    sink: str
    vectors: ValueRef
    count: ValueRef
    sink_ea: int
    function_ea: int
    function_name: str


@dataclass(frozen=True, slots=True)
class IovecWriteEffect:
    """A scatter/gather input expressed in wrapper arguments."""

    sink: str
    vectors: ValueRef
    count: ValueRef
    sink_ea: int
    function_ea: int
    function_name: str
    # A fixed descriptor is an unconditional external source.  When the
    # descriptor is a wrapper argument, preserve it so callers can discharge
    # reads from a fixed trusted /proc/self pseudo-file.
    taints_destination: bool = True
    input_handles: tuple[ValueRef, ...] = ()


@dataclass(frozen=True, slots=True)
class MessageReadEffect:
    """A sendmsg/sendmmsg operation expressed in wrapper arguments."""

    sink: str
    messages: ValueRef
    count: ValueRef
    batched: bool
    sink_ea: int
    function_ea: int
    function_name: str


@dataclass(frozen=True, slots=True)
class MessageWriteEffect:
    """A recvmsg/recvmmsg operation expressed in wrapper arguments."""

    sink: str
    messages: ValueRef
    count: ValueRef
    batched: bool
    sink_ea: int
    function_ea: int
    function_name: str


@dataclass(frozen=True, slots=True)
class FormatEffect:
    sink: str
    format_value: ValueRef


@dataclass(frozen=True, slots=True)
class AllocationEffect:
    allocator: str
    sizes: tuple[ValueRef, ...]


@dataclass(frozen=True, slots=True)
class ErrorOutputEffect:
    """An unsigned output slot populated from an integral error-return API."""

    destination: ValueRef
    error_sentinel: int
    bits: int
    success_upper: ValueRef | None = None
    # Constant wrapper return values that cover every path on which the
    # destination still contains ``error_sentinel``.  A caller guard that
    # excludes all of them proves that the output error value is unreachable.
    sentinel_return_values: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    ea: int
    name: str
    writes: tuple[WriteEffect, ...] = ()
    reads: tuple[ReadEffect, ...] = ()
    cstring_reads: tuple[CStringReadEffect, ...] = ()
    iovec_reads: tuple[IovecReadEffect, ...] = ()
    iovec_writes: tuple[IovecWriteEffect, ...] = ()
    message_reads: tuple[MessageReadEffect, ...] = ()
    message_writes: tuple[MessageWriteEffect, ...] = ()
    formats: tuple[FormatEffect, ...] = ()
    frees: tuple[ValueRef, ...] = ()
    possible_frees: tuple[ValueRef, ...] = ()
    allocation: AllocationEffect | None = None
    error_outputs: tuple[ErrorOutputEffect, ...] = ()
    returns_external_input: bool = False
    return_taint_arguments: tuple[int, ...] = ()
    # Integral input-return contract retained through thin wrappers.
    return_error_sentinel: int | None = None
    return_success_upper: ValueRef | None = None
    # Maximum byte length, excluding NUL, when every observed return path is
    # a literal C string or calls another function with the same proof.
    return_cstring_max: int | None = None

    @property
    def has_effects(self) -> bool:
        return bool(
            self.writes
            or self.reads
            or self.cstring_reads
            or self.iovec_reads
            or self.iovec_writes
            or self.message_reads
            or self.message_writes
            or self.formats
            or self.frees
            or self.possible_frees
            or self.allocation
            or self.error_outputs
            or self.returns_external_input
            or self.return_taint_arguments
            or self.return_error_sentinel is not None
            or self.return_success_upper is not None
            or self.return_cstring_max is not None
        )


@dataclass(slots=True)
class SummaryIndex:
    by_ea: dict[int, FunctionSummary] = field(default_factory=dict)
    by_name: dict[str, FunctionSummary] = field(default_factory=dict)
    known_eas: set[int] = field(default_factory=set)
    known_names: set[str] = field(default_factory=set)

    @classmethod
    def from_summaries(cls, summaries: list[FunctionSummary]) -> "SummaryIndex":
        result = cls()
        for summary in summaries:
            result.known_eas.add(summary.ea)
            result.known_names.add(normalize_symbol(summary.name))
            if not summary.has_effects:
                continue
            result.by_ea[summary.ea] = summary
            result.by_name[normalize_symbol(summary.name)] = summary
        return result

    def lookup(self, name: str, ea: int | None = None) -> FunctionSummary | None:
        if ea is not None and ea in self.by_ea:
            return self.by_ea[ea]
        return self.by_name.get(normalize_symbol(name))

    def knows(self, name: str, ea: int | None = None) -> bool:
        return bool(
            (ea is not None and ea in self.known_eas)
            or normalize_symbol(name) in self.known_names
        )


class SummaryBuilder:
    """Infer summaries to a fixed point over the extracted call graph."""

    def __init__(self) -> None:
        self.last_iterations = 0
        self.last_recomputed = 0

    def build(self, functions: list[FunctionIR]) -> SummaryIndex:
        if not functions:
            self.last_iterations = 0
            self.last_recomputed = 0
            return SummaryIndex()

        functions_by_ea = {function.ea: function for function in functions}
        functions_by_name = {
            normalize_symbol(function.name): function.ea
            for function in functions
        }
        reverse_callers: dict[int, set[int]] = {
            function.ea: set() for function in functions
        }
        for function in functions:
            for name, callee_ea in self._summary_dependencies(function):
                target_ea = (
                    callee_ea
                    if callee_ea in functions_by_ea
                    else functions_by_name.get(normalize_symbol(name))
                )
                if target_ea is not None:
                    reverse_callers[target_ea].add(function.ea)

        index = SummaryIndex()
        current: dict[int, FunctionSummary] = {}
        dirty = set(functions_by_ea)
        limit = max(3, len(functions) + 1)
        self.last_iterations = 0
        self.last_recomputed = 0
        for iteration in range(1, limit + 1):
            self.last_iterations = iteration
            ordered_dirty = [
                function for function in functions if function.ea in dirty
            ]
            self.last_recomputed += len(ordered_dirty)
            updates = {
                function.ea: self._summarize(function, index)
                for function in ordered_dirty
            }
            changed = {
                ea
                for ea, summary in updates.items()
                if current.get(ea) != summary
            }
            current.update(updates)
            summaries = [
                current[function.ea]
                for function in functions
                if function.ea in current
            ]
            index = SummaryIndex.from_summaries(summaries)
            if not changed:
                break
            dirty = {
                caller
                for ea in changed
                for caller in reverse_callers.get(ea, ())
            }
            if not dirty:
                break
        return index

    @classmethod
    def _summary_dependencies(
        cls, function: FunctionIR
    ) -> set[tuple[str, int | None]]:
        """Return internal-call identities that can affect a summary."""

        result: set[tuple[str, int | None]] = set()

        def visit(expression: Expr) -> None:
            value = expression.unwrapped()
            if value.kind == "call":
                result.add((value.callee or "", value.callee_ea))
            for child in expression.children:
                visit(child)

        for statement in function.statements:
            if isinstance(statement, Call):
                result.add((statement.name, statement.callee_ea))
                if statement.target is not None:
                    visit(statement.target)
                for argument in statement.args:
                    visit(argument)
            elif isinstance(statement, Assignment):
                visit(statement.target)
                visit(statement.value)
            elif isinstance(statement, Return):
                visit(statement.value)
        return result

    def _summarize(
        self, function: FunctionIR, index: SummaryIndex
    ) -> FunctionSummary:
        writes: set[WriteEffect] = set()
        reads: set[ReadEffect] = set()
        cstring_reads: set[CStringReadEffect] = set()
        iovec_reads: set[IovecReadEffect] = set()
        iovec_writes: set[IovecWriteEffect] = set()
        message_reads: set[MessageReadEffect] = set()
        message_writes: set[MessageWriteEffect] = set()
        formats: set[FormatEffect] = set()
        frees: set[ValueRef] = set()
        possible_frees: set[ValueRef] = set()
        allocation: AllocationEffect | None = None
        direct_error_events = self._direct_error_output_effects(
            function, index
        )
        direct_error_outputs = {
            effect for _, effect in direct_error_events
        }
        direct_error_statements = {
            statement for statement, _ in direct_error_events
        }
        error_outputs = set(direct_error_outputs)
        error_output_events: list[
            tuple[Assignment | Call, ErrorOutputEffect]
        ] = list(direct_error_events)
        writes.update(
            WriteEffect(
                sink="error_output",
                destination=effect.destination,
                taints_destination=True,
            )
            for effect in error_outputs
        )
        returns_external_input = False
        return_taint_arguments: set[int] = set()
        local_allocations: dict[str, AllocationEffect] = {}
        local_tainted = self._local_taint(function, index)
        local_cstring_bounds = self._local_cstring_bounds(function, index)
        parameter_origins = self._parameter_origins(function)
        parameter_taint_origins = self._parameter_taint_origins(function)
        stateful_tainted_keys = self._stateful_tainted_keys(function)
        tokenizer_argument_sessions: dict[str, set[int]] = {}
        tokenizer_external_sessions: dict[str, bool] = {}

        def advance_tokenizer(
            name: str, arguments: tuple[Expr, ...]
        ) -> tuple[bool, set[int]] | None:
            input_index = STATEFUL_TAINT_RETURNS.get(name)
            if input_index is None or input_index >= len(arguments):
                return None
            source = arguments[input_index].unwrapped()
            argument_origins: set[int] = set()
            external = False
            for argument in arguments:
                argument_origins.update(
                    self._taint_origin_arguments(
                        argument, parameter_taint_origins
                    )
                )
                external |= bool(argument.dependencies() & local_tainted)
            if source.kind == "const" and source.value == 0:
                argument_origins.update(
                    tokenizer_argument_sessions.get(name, ())
                )
                external |= tokenizer_external_sessions.get(name, False)
            tokenizer_argument_sessions[name] = argument_origins
            tokenizer_external_sessions[name] = external
            return external, argument_origins

        for statement in sorted(function.statements, key=lambda item: item.order):
            if isinstance(statement, Assignment):
                value = statement.value.unwrapped()
                if value.kind == "call":
                    advance_tokenizer(
                        normalize_symbol(value.callee or ""), value.children
                    )
                if statement.target.key:
                    effect = self._allocation_for_expr(statement.value, function, index)
                    if effect is not None:
                        local_allocations[statement.target.key] = effect
                if statement not in direct_error_statements:
                    self._collect_inline_taint_write(
                        statement,
                        writes,
                        local_tainted,
                        parameter_origins,
                        parameter_taint_origins,
                    )
                continue

            if isinstance(statement, Return):
                value = statement.value
                unwrapped = value.unwrapped()
                tokenizer_taint = (
                    advance_tokenizer(
                        normalize_symbol(unwrapped.callee or ""),
                        unwrapped.children,
                    )
                    if unwrapped.kind == "call"
                    else None
                )
                effect = self._allocation_for_expr(value, function, index)
                if effect is None and value.key:
                    effect = local_allocations.get(value.key)
                if effect is not None:
                    allocation = effect

                external, arguments = self._return_taint(
                    value,
                    function,
                    index,
                    local_tainted,
                    parameter_taint_origins,
                    stateful_tainted_keys,
                )
                returns_external_input |= external
                return_taint_arguments.update(arguments)
                if tokenizer_taint is not None:
                    tokenizer_external, tokenizer_arguments = tokenizer_taint
                    returns_external_input |= tokenizer_external
                    return_taint_arguments.update(tokenizer_arguments)
                continue

            advance_tokenizer(
                normalize_symbol(statement.name), statement.args
            )
            self._collect_call_effects(
                function,
                statement,
                index,
                writes,
                reads,
                cstring_reads,
                iovec_reads,
                iovec_writes,
                message_reads,
                message_writes,
                formats,
                frees,
                possible_frees,
                error_outputs,
                error_output_events,
                local_tainted,
                parameter_taint_origins,
                stateful_tainted_keys,
                local_cstring_bounds,
            )
            if normalize_symbol(statement.name) == "munmap" and statement.args:
                for argument_index in self._origin_arguments(
                    statement.args[0], parameter_origins
                ):
                    possible_frees.add(ValueRef(argument=argument_index))

        error_outputs = set(
            self._surviving_error_output_effects(
                function,
                index,
                error_output_events,
            )
        )
        output_contract_counts = {
            destination: sum(
                effect.destination == destination for effect in error_outputs
            )
            for destination in {
                effect.destination for effect in error_outputs
            }
        }
        error_outputs = {
            effect
            for effect in error_outputs
            if output_contract_counts[effect.destination] == 1
        }
        valid_error_destinations = {
            effect.destination for effect in error_outputs
        }
        writes = {
            effect
            for effect in writes
            if effect.sink != "error_output"
            or effect.destination in valid_error_destinations
        }

        conditional_handles, has_unconditional_input = self._input_profile(
            function,
            index,
            parameter_taint_origins,
        )
        if conditional_handles and not has_unconditional_input:
            # The local taint fixed point intentionally treats every raw read
            # as hostile.  Before exporting a wrapper summary, refine effects
            # when every hostile source is a file read whose handle can be
            # expressed in terms of wrapper parameters.  This preserves the
            # handle through reader -> parser/output wrapper chains.
            writes = {
                replace(
                    effect,
                    taints_destination=False,
                    input_handles=conditional_handles,
                )
                if effect.taints_destination
                else effect
                for effect in writes
            }

        return_error_sentinel, return_success_upper = self._return_integer_range(
            function, index
        )
        return FunctionSummary(
            ea=function.ea,
            name=function.name,
            writes=tuple(sorted(writes, key=repr)),
            reads=tuple(sorted(reads, key=repr)),
            cstring_reads=tuple(sorted(cstring_reads, key=repr)),
            iovec_reads=tuple(sorted(iovec_reads, key=repr)),
            iovec_writes=tuple(sorted(iovec_writes, key=repr)),
            message_reads=tuple(sorted(message_reads, key=repr)),
            message_writes=tuple(sorted(message_writes, key=repr)),
            formats=tuple(sorted(formats, key=repr)),
            frees=tuple(sorted(frees, key=repr)),
            possible_frees=tuple(sorted(possible_frees, key=repr)),
            allocation=allocation,
            error_outputs=tuple(sorted(error_outputs, key=repr)),
            returns_external_input=returns_external_input,
            return_taint_arguments=tuple(sorted(return_taint_arguments)),
            return_error_sentinel=return_error_sentinel,
            return_success_upper=return_success_upper,
            return_cstring_max=self._return_cstring_max(
                function, index, local_cstring_bounds
            ),
        )

    def _collect_call_effects(
        self,
        function: FunctionIR,
        call: Call,
        index: SummaryIndex,
        writes: set[WriteEffect],
        reads: set[ReadEffect],
        cstring_reads: set[CStringReadEffect],
        iovec_reads: set[IovecReadEffect],
        iovec_writes: set[IovecWriteEffect],
        message_reads: set[MessageReadEffect],
        message_writes: set[MessageWriteEffect],
        formats: set[FormatEffect],
        frees: set[ValueRef],
        possible_frees: set[ValueRef],
        error_outputs: set[ErrorOutputEffect],
        error_output_events: list[
            tuple[Assignment | Call, ErrorOutputEffect]
        ],
        local_tainted: set[str],
        parameter_taint_origins: dict[str, set[int]],
        stateful_tainted_keys: frozenset[str],
        local_cstring_bounds: dict[str, int],
    ) -> None:
        name = normalize_symbol(call.name)

        iovec_spec = IOVEC_READ_SPECS.get(name)
        if iovec_spec is not None:
            vector_index, count_index = iovec_spec
            vectors = self._argument_ref(function, call, vector_index)
            count = self._argument_ref(function, call, count_index)
            if vectors is not None and count is not None:
                iovec_reads.add(
                    IovecReadEffect(
                        name,
                        vectors,
                        count,
                        call.ea,
                        function.ea,
                        function.name,
                    )
                )

        iovec_write_spec = IOVEC_WRITE_SPECS.get(name)
        if iovec_write_spec is not None:
            vector_index, count_index = iovec_write_spec
            vectors = self._argument_ref(function, call, vector_index)
            count = self._argument_ref(function, call, count_index)
            handle = self._argument_ref(function, call, 0)
            conditional_handle = bool(
                handle is not None and handle.argument is not None
            )
            if vectors is not None and count is not None:
                iovec_writes.add(
                    IovecWriteEffect(
                        name,
                        vectors,
                        count,
                        call.ea,
                        function.ea,
                        function.name,
                        taints_destination=not conditional_handle,
                        input_handles=(
                            (handle,) if conditional_handle and handle else ()
                        ),
                    )
                )

        message_read_spec = MESSAGE_READ_SPECS.get(name)
        if message_read_spec is not None:
            message_index, count_index = message_read_spec
            messages = self._argument_ref(function, call, message_index)
            count = (
                self._argument_ref(function, call, count_index)
                if count_index is not None
                else ValueRef(constant=1, text="1")
            )
            if messages is not None and count is not None:
                message_reads.add(
                    MessageReadEffect(
                        name,
                        messages,
                        count,
                        count_index is not None,
                        call.ea,
                        function.ea,
                        function.name,
                    )
                )

        message_write_spec = MESSAGE_WRITE_SPECS.get(name)
        if message_write_spec is not None:
            message_index, count_index = message_write_spec
            messages = self._argument_ref(function, call, message_index)
            count = (
                self._argument_ref(function, call, count_index)
                if count_index is not None
                else ValueRef(constant=1, text="1")
            )
            if messages is not None and count is not None:
                message_writes.add(
                    MessageWriteEffect(
                        name,
                        messages,
                        count,
                        count_index is not None,
                        call.ea,
                        function.ea,
                        function.name,
                    )
                )

        if name in COPY_SPECS:
            destination_index, source_index, length_indexes = COPY_SPECS[name]
            self._add_direct_write(
                function,
                call,
                name,
                destination_index,
                length_indexes,
                writes,
                source_index=source_index,
                taints_destination=False,
            )
            source = self._argument_ref(function, call, source_index)
            lengths = tuple(
                ref
                for argument_index in length_indexes
                if (ref := self._argument_ref(function, call, argument_index))
                is not None
            )
            if source is not None and len(lengths) == len(length_indexes):
                fortify_capacity = self._argument_ref(
                    function,
                    call,
                    FORTIFIED_DESTINATION_SPECS.get(name),
                )
                reads.add(
                    ReadEffect(
                        name,
                        source,
                        lengths,
                        call.ea,
                        function.ea,
                        function.name,
                        fortify_capacity,
                    )
                )
        elif name in BOUNDED_WRITE_SPECS:
            destination_index, length_indexes = BOUNDED_WRITE_SPECS[name]
            self._add_direct_write(
                function,
                call,
                name,
                destination_index,
                length_indexes,
                writes,
                taints_destination=destination_index in INPUT_WRITES.get(name, ()),
            )
        elif name in BOUNDED_READ_SPECS:
            source_index, length_indexes = BOUNDED_READ_SPECS[name]
            source = self._argument_ref(function, call, source_index)
            lengths = tuple(
                ref
                for argument_index in length_indexes
                if (ref := self._argument_ref(function, call, argument_index))
                is not None
            )
            if source is None or len(lengths) != len(length_indexes):
                loop_refs = self._loop_accumulating_range_refs(
                    function, call, source_index, length_indexes
                )
                if loop_refs is not None:
                    source, lengths = loop_refs
            if source is not None and len(lengths) == len(length_indexes):
                reads.add(
                    ReadEffect(
                        name,
                        source,
                        lengths,
                        call.ea,
                        function.ea,
                        function.name,
                    )
                )
        elif name in BOUNDED_MULTI_READ_SPECS:
            source_indexes, length_indexes = BOUNDED_MULTI_READ_SPECS[name]
            lengths = tuple(
                ref
                for argument_index in length_indexes
                if (ref := self._argument_ref(function, call, argument_index))
                is not None
            )
            if len(lengths) == len(length_indexes):
                for source_index in source_indexes:
                    source = self._argument_ref(function, call, source_index)
                    if source is not None:
                        reads.add(
                            ReadEffect(
                                name,
                                source,
                                lengths,
                                call.ea,
                                function.ea,
                                function.name,
                            )
                        )

        unbounded = UNBOUNDED_WRITE_SPECS.get(name)
        if unbounded is not None:
            destination_index, source_index = unbounded
            destination = self._argument_ref(function, call, destination_index)
            source = self._argument_ref(function, call, source_index)
            fortify_capacity = self._argument_ref(
                function,
                call,
                FORTIFIED_DESTINATION_SPECS.get(name),
            )
            format_index = FORMAT_ARGUMENTS.get(name)
            format_expression = (
                call.args[format_index]
                if format_index is not None and format_index < len(call.args)
                else None
            )
            format_text = (
                format_expression.string
                if format_expression is not None
                else None
            )
            format_arguments = (
                tuple(
                    self._argument_ref_with_cstring_bound(
                        function,
                        call,
                        argument_index,
                        index,
                        local_cstring_bounds,
                    )
                    for argument_index in range(format_index + 1, len(call.args))
                )
                if format_text is not None and format_index is not None
                else ()
            )
            if destination is not None:
                writes.add(
                    WriteEffect(
                        sink=name,
                        destination=destination,
                        source=source,
                        unbounded=True,
                        taints_destination=destination_index in INPUT_WRITES.get(name, ()),
                        taint_sources=(source,) if source is not None else (),
                        fortify_capacity=fortify_capacity,
                        format_text=format_text,
                        format_arguments=format_arguments,
                    )
                )

        format_index = FORMAT_ARGUMENTS.get(name)
        format_value = self._argument_ref(function, call, format_index)
        if format_value is None and format_index is not None:
            format_expression = (
                call.args[format_index]
                if format_index < len(call.args)
                else None
            )
            if (
                format_expression is not None
                and format_expression.dependencies() & stateful_tainted_keys
            ):
                origins = self._taint_origin_arguments(
                    format_expression, parameter_taint_origins
                )
                if len(origins) == 1:
                    format_value = ValueRef(argument=next(iter(origins)))
        if format_value is not None:
            formats.add(FormatEffect(name, format_value))

        for argument_index in CSTRING_READ_ARGUMENTS.get(name, ()):
            value = self._argument_ref(function, call, argument_index)
            if value is not None:
                cstring_reads.add(
                    CStringReadEffect(
                        name,
                        value,
                        call.ea,
                        function.ea,
                        function.name,
                    )
                )
        bounded_cstring = BOUNDED_CSTRING_READ_SPECS.get(name)
        if bounded_cstring is not None:
            (
                source_indexes,
                maximum_index,
                stops_at_peer_nul,
            ) = bounded_cstring
            maximum_ref = self._argument_ref(function, call, maximum_index)
            if maximum_ref is not None:
                for argument_index in source_indexes:
                    value = self._argument_ref(function, call, argument_index)
                    peer_maximum = None
                    if stops_at_peer_nul:
                        peer_bounds = [
                            bound + 1
                            for peer_index in source_indexes
                            if peer_index != argument_index
                            and peer_index < len(call.args)
                            and (
                                bound := self._cstring_bound_for_expr(
                                    call.args[peer_index],
                                    index,
                                    local_cstring_bounds,
                                )
                            )
                            is not None
                        ]
                        if peer_bounds:
                            peer_bound = min(peer_bounds)
                            peer_maximum = ValueRef(
                                constant=peer_bound,
                                text=str(peer_bound),
                            )
                    if value is not None:
                        cstring_reads.add(
                            CStringReadEffect(
                                name,
                                value,
                                call.ea,
                                function.ea,
                                function.name,
                                maximum_ref,
                                peer_maximum,
                            )
                        )
        format_index = FORMAT_ARGUMENTS.get(name)
        format_expression = (
            call.args[format_index]
            if format_index is not None and format_index < len(call.args)
            else None
        )
        if (
            format_expression is not None
            and format_expression.string is not None
        ):
            for (
                argument_index,
                maximum,
                maximum_index,
            ) in format_cstring_read_arguments(
                name, format_expression.string
            ):
                value = self._argument_ref(function, call, argument_index)
                maximum_ref = (
                    ValueRef(constant=maximum, text=str(maximum))
                    if maximum is not None
                    else self._argument_ref(function, call, maximum_index)
                )
                if value is not None and (
                    maximum_index is None or maximum_ref is not None
                ):
                    cstring_reads.add(
                        CStringReadEffect(
                            f"{name} %s",
                            value,
                            call.ea,
                            function.ea,
                            function.name,
                            maximum_ref,
                        )
                    )

        if name in FREE_NAMES:
            free_value = self._argument_ref(function, call, 0)
            if (
                free_value is not None
                and free_value.offset == 0
                and free_value.scalar_op is None
            ):
                frees.add(free_value)

        # A recognized libc/fortify semantic model is authoritative even when
        # the binary also contains a decompilable implementation (fixtures,
        # static libc, or an interposed symbol).  Composing that body as well
        # would duplicate the effect and, critically, could unwrap
        # ``__read_chk`` into a plain ``read`` that has lost its object-size
        # guard.
        if (
            name in COPY_SPECS
            or name in BOUNDED_WRITE_SPECS
            or name in BOUNDED_READ_SPECS
            or name in BOUNDED_MULTI_READ_SPECS
            or name in BOUNDED_CSTRING_READ_SPECS
            or name in IOVEC_READ_SPECS
            or name in IOVEC_WRITE_SPECS
            or name in MESSAGE_READ_SPECS
            or name in MESSAGE_WRITE_SPECS
            or name in UNBOUNDED_WRITE_SPECS
            or name in FORMAT_ARGUMENTS
            or name in SCANF_SPECS
            or name in CSTRING_READ_ARGUMENTS
            or name in ALLOC_SPECS
            or name in FREE_NAMES
        ):
            return

        nested = index.lookup(call.name, call.callee_ea)
        if nested is None:
            return
        for effect in nested.writes:
            destination = self._compose_ref(effect.destination, call, function)
            lengths = tuple(
                ref
                for value in effect.lengths
                if (ref := self._compose_ref(value, call, function)) is not None
            )
            source = (
                self._compose_ref(effect.source, call, function)
                if effect.source is not None
                else None
            )
            fortify_capacity = (
                self._compose_ref(effect.fortify_capacity, call, function)
                if effect.fortify_capacity is not None
                else None
            )
            format_arguments = tuple(
                (
                    self._compose_ref(value, call, function)
                    if value is not None
                    else None
                )
                for value in effect.format_arguments
            )
            taints_destination, taint_sources = self._compose_taint_sources(
                effect,
                call,
                local_tainted,
                parameter_taint_origins,
            )
            taints_destination, input_handles = self._compose_input_handles(
                effect,
                call,
                function,
                parameter_taint_origins,
                taints_destination,
            )
            if destination is not None and len(lengths) == len(effect.lengths):
                writes.add(
                    WriteEffect(
                        sink=effect.sink,
                        destination=destination,
                        lengths=lengths,
                        source=source,
                        unbounded=effect.unbounded,
                        must_write=(
                            effect.must_write
                            and self._statement_is_unconditional(
                                function,
                                self._call_at_logical_execution_point(
                                    function, call
                                ),
                            )
                        ),
                        taints_destination=taints_destination,
                        taint_sources=taint_sources,
                        input_handles=input_handles,
                        fortify_capacity=fortify_capacity,
                        format_text=effect.format_text,
                        format_arguments=format_arguments,
                    )
                )
        for effect in nested.reads:
            source = self._compose_ref(effect.source, call, function)
            lengths = tuple(
                ref
                for value in effect.lengths
                if (ref := self._compose_ref(value, call, function)) is not None
            )
            fortify_capacity = (
                self._compose_ref(effect.fortify_capacity, call, function)
                if effect.fortify_capacity is not None
                else None
            )
            if source is not None and len(lengths) == len(effect.lengths):
                reads.add(
                    ReadEffect(
                        effect.sink,
                        source,
                        lengths,
                        effect.sink_ea,
                        effect.function_ea,
                        effect.function_name,
                        fortify_capacity,
                    )
                )
        for effect in nested.cstring_reads:
            value = self._compose_ref(effect.value, call, function)
            maximum = (
                self._compose_ref(effect.maximum, call, function)
                if effect.maximum is not None
                else None
            )
            peer_maximum = (
                self._compose_ref(effect.peer_maximum, call, function)
                if effect.peer_maximum is not None
                else None
            )
            if value is not None:
                cstring_reads.add(
                    CStringReadEffect(
                        effect.sink,
                        value,
                        effect.sink_ea,
                        effect.function_ea,
                        effect.function_name,
                        maximum,
                        peer_maximum,
                    )
                )
        for effect in nested.iovec_reads:
            vectors = self._compose_ref(effect.vectors, call, function)
            count = self._compose_ref(effect.count, call, function)
            if vectors is not None and count is not None:
                iovec_reads.add(
                    IovecReadEffect(
                        effect.sink,
                        vectors,
                        count,
                        effect.sink_ea,
                        effect.function_ea,
                        effect.function_name,
                    )
                )
        for effect in nested.iovec_writes:
            vectors = self._compose_ref(effect.vectors, call, function)
            count = self._compose_ref(effect.count, call, function)
            taints_destination, input_handles = self._compose_input_handles(
                effect,
                call,
                function,
                parameter_taint_origins,
                effect.taints_destination,
            )
            if vectors is not None and count is not None:
                iovec_writes.add(
                    IovecWriteEffect(
                        effect.sink,
                        vectors,
                        count,
                        effect.sink_ea,
                        effect.function_ea,
                        effect.function_name,
                        taints_destination=taints_destination,
                        input_handles=input_handles,
                    )
                )
        for effect in nested.message_reads:
            messages = self._compose_ref(effect.messages, call, function)
            count = self._compose_ref(effect.count, call, function)
            if messages is not None and count is not None:
                message_reads.add(
                    MessageReadEffect(
                        effect.sink,
                        messages,
                        count,
                        effect.batched,
                        effect.sink_ea,
                        effect.function_ea,
                        effect.function_name,
                    )
                )
        for effect in nested.message_writes:
            messages = self._compose_ref(effect.messages, call, function)
            count = self._compose_ref(effect.count, call, function)
            if messages is not None and count is not None:
                message_writes.add(
                    MessageWriteEffect(
                        effect.sink,
                        messages,
                        count,
                        effect.batched,
                        effect.sink_ea,
                        effect.function_ea,
                        effect.function_name,
                    )
                )
        for effect in nested.formats:
            value = self._compose_ref(effect.format_value, call, function)
            if value is not None:
                formats.add(FormatEffect(effect.sink, value))
        output_call = self._call_at_logical_execution_point(function, call)
        if self._statement_is_unconditional(function, output_call):
            forwards_return = self._call_return_is_forwarded(function, call)
            for effect in nested.error_outputs:
                destination = self._compose_ref(
                    effect.destination, call, function
                )
                success_upper = (
                    self._compose_ref(effect.success_upper, call, function)
                    if effect.success_upper is not None
                    else None
                )
                if destination is not None:
                    target = self._error_output_parameter_expression(
                        function, destination, effect.bits
                    )
                    sentinel_returns = (
                        effect.sentinel_return_values
                        if forwards_return
                        else (
                            self._sentinel_return_values(
                                function,
                                output_call,
                                target,
                                Expr(
                                    kind="call",
                                    text=call.text,
                                    callee=call.name,
                                    callee_ea=call.callee_ea,
                                    children=call.args,
                                ),
                                effect.error_sentinel,
                                effect.sentinel_return_values,
                            )
                            if target is not None
                            else ()
                        )
                    )
                    error_outputs.add(
                        composed_effect := ErrorOutputEffect(
                            destination=destination,
                            error_sentinel=effect.error_sentinel,
                            bits=effect.bits,
                            success_upper=success_upper,
                            sentinel_return_values=sentinel_returns,
                        )
                    )
                    error_output_events.append((output_call, composed_effect))
        for value in nested.frees:
            composed = self._compose_ref(value, call, function)
            if composed is not None:
                frees.add(composed)
        for value in nested.possible_frees:
            composed = self._compose_ref(value, call, function)
            if composed is not None:
                possible_frees.add(composed)

    @staticmethod
    def _error_output_parameter_expression(
        function: FunctionIR,
        destination: ValueRef,
        bits: int,
    ) -> Expr | None:
        argument = destination.argument
        if (
            argument is None
            or argument < 0
            or argument >= len(function.parameters)
        ):
            return None
        key = function.parameters[argument]
        pointer = Expr(
            kind="var",
            text=key,
            key=key,
            bits=64,
            signed=False,
            is_pointer=True,
        )
        return Expr(
            kind="deref",
            text=(
                f"*{key}"
                if destination.offset == 0
                else f"*({key} + {destination.offset})"
            ),
            key=key,
            children=(pointer,),
            offset=destination.offset,
            bits=bits,
            signed=False,
            is_pointer=False,
        )

    def _call_at_logical_execution_point(
        self,
        function: FunctionIR,
        call: Call,
    ) -> Call:
        """Place ctree calls before the condition/return they evaluate.

        Hex-Rays visits guarded bodies before calls embedded in an ``if``
        condition, and may likewise visit a return expression before its
        nested call. The source expression still executes first; use that
        order when proving an output effect unconditional and relating it to
        later return statuses.
        """

        matching_calls = [
            statement
            for statement in function.statements
            if isinstance(statement, Call)
            and self._call_expression_matches(
                Expr(
                    kind="call",
                    callee=statement.name,
                    callee_ea=statement.callee_ea,
                    children=statement.args,
                ),
                call,
            )
        ]
        if len(matching_calls) != 1:
            return call

        conditions = [
            condition
            for condition in function.conditions
            if self._expression_contains_call(condition.expression, call)
        ]
        if len(conditions) == 1:
            condition = conditions[0]
            return replace(
                call,
                order=min(call.order, condition.order),
                block_id=(
                    condition.block_id
                    if condition.block_id is not None
                    else call.block_id
                ),
            )

        returns = [
            statement
            for statement in function.statements
            if isinstance(statement, Return)
            and self._expression_contains_call(statement.value, call)
        ]
        if len(returns) == 1:
            returned = returns[0]
            return replace(
                call,
                order=min(call.order, returned.order - 1),
                block_id=(
                    returned.block_id
                    if returned.block_id is not None
                    else call.block_id
                ),
            )
        return call

    @classmethod
    def _expression_contains_call(cls, expression: Expr, call: Call) -> bool:
        if cls._call_expression_matches(expression, call):
            return True
        return any(
            cls._expression_contains_call(child, call)
            for child in expression.children
        )

    def _call_return_is_forwarded(
        self,
        function: FunctionIR,
        call: Call,
    ) -> bool:
        """Prove that a wrapper returns this nested call without remapping it."""

        returns = [
            statement
            for statement in function.statements
            if isinstance(statement, Return)
        ]
        return bool(
            len(returns) == 1
            and self._expression_is_call_result(
                returns[0].value,
                function,
                call,
                returns[0].order,
            )
        )

    def _expression_is_call_result(
        self,
        expression: Expr,
        function: FunctionIR,
        call: Call,
        before_order: int,
        seen: frozenset[str] = frozenset(),
    ) -> bool:
        original = expression
        if original.kind == "cast" and original.children:
            return self._expression_is_call_result(
                original.children[0], function, call, before_order, seen
            )
        value = expression.unwrapped()
        if value.kind == "call":
            return self._call_expression_matches(value, call)
        if (
            value.kind not in {"var", "global"}
            or value.key is None
            or value.key in seen
        ):
            return False
        assignments = [
            statement
            for statement in function.statements
            if isinstance(statement, Assignment)
            and statement.order < before_order
            and statement.target.kind in {"var", "global"}
            and statement.target.key == value.key
            and statement.target.offset == 0
        ]
        if not assignments:
            return False
        reaching = max(assignments, key=lambda statement: statement.order)
        return self._expression_is_call_result(
            reaching.value,
            function,
            call,
            reaching.order,
            seen | {value.key},
        )

    @classmethod
    def _call_expression_matches(cls, expression: Expr, call: Call) -> bool:
        value = expression.unwrapped()
        if value.kind != "call":
            return False
        return cls._same_call_expressions(
            value,
            Expr(
                kind="call",
                callee=call.name,
                callee_ea=call.callee_ea,
                children=call.args,
            ),
        )

    @classmethod
    def _same_call_expressions(cls, left: Expr, right: Expr) -> bool:
        left = left.unwrapped()
        right = right.unwrapped()
        if left.kind != "call" or right.kind != "call":
            return False
        if (
            left.callee_ea is not None
            and right.callee_ea is not None
            and left.callee_ea != right.callee_ea
        ):
            return False
        if normalize_symbol(left.callee or "") != normalize_symbol(
            right.callee or ""
        ):
            return False
        return tuple(
            cls._expression_identity(argument) for argument in left.children
        ) == tuple(
            cls._expression_identity(argument) for argument in right.children
        )

    @classmethod
    def _expression_identity(cls, expression: Expr) -> object:
        value = expression.unwrapped()
        if value.kind == "const":
            return "const", value.value
        if value.kind in {"var", "global", "address"}:
            return value.kind, value.key, value.offset
        return (
            value.kind,
            value.op,
            value.key,
            value.offset,
            tuple(cls._expression_identity(child) for child in value.children),
        )

    @staticmethod
    def _parameter_origins(function: FunctionIR) -> dict[str, set[int]]:
        origins = {
            key: {index} for index, key in enumerate(function.parameters)
        }
        assignments = [
            statement
            for statement in function.statements
            if isinstance(statement, Assignment)
            and statement.target.kind == "var"
            and statement.target.key
        ]
        for _ in range(max(2, len(assignments) + 1)):
            changed = False
            for assignment in assignments:
                inherited: set[int] = set()
                # A call result or a pointer loaded from a field is not an
                # alias of every argument/base used to compute it.  Treating
                # arbitrary dependencies as aliases made lookup helpers such
                # as linear_hash_get(a1, a2) turn a later munmap(result) into a
                # bogus "callee may free a1/a2" summary.
                value = assignment.value.unwrapped()
                alias_dependencies = (
                    {value.key}
                    if value.key is not None
                    and value.kind in {"var", "global", "address", "op"}
                    else set()
                )
                for dependency in alias_dependencies:
                    inherited.update(origins.get(dependency, ()))
                target = assignment.target.key
                merged = origins.get(target, set()) | inherited
                if merged != origins.get(target, set()):
                    origins[target] = merged
                    changed = True
            if not changed:
                break
        return origins

    @staticmethod
    def _parameter_taint_origins(function: FunctionIR) -> dict[str, set[int]]:
        """Track which input parameters can influence each local value.

        This relation is intentionally broader than pointer aliasing: a load
        through a parameter and arithmetic performed on that load remain data
        dependent on the parameter.  It is used only for conditional taint
        summaries, never for buffer capacities or lifetime ownership.
        """

        origins = {
            key: {index} for index, key in enumerate(function.parameters)
        }
        statements = sorted(function.statements, key=lambda item: item.order)
        assignments = [
            statement for statement in statements
            if isinstance(statement, Assignment)
        ]
        for _ in range(max(2, len(assignments) + 1)):
            changed = False
            tokenizer_sessions: dict[str, set[int]] = {}

            def advance_tokenizer(
                name: str, arguments: tuple[Expr, ...]
            ) -> set[int] | None:
                input_index = STATEFUL_TAINT_RETURNS.get(name)
                if input_index is None or input_index >= len(arguments):
                    return None
                inherited: set[int] = set()
                for argument in arguments:
                    for dependency in argument.dependencies():
                        inherited.update(origins.get(dependency, ()))
                source = arguments[input_index].unwrapped()
                if source.kind == "const" and source.value == 0:
                    inherited.update(tokenizer_sessions.get(name, ()))
                tokenizer_sessions[name] = inherited
                return inherited

            for statement in statements:
                if isinstance(statement, Call):
                    advance_tokenizer(
                        normalize_symbol(statement.name), statement.args
                    )
                    continue
                if not isinstance(statement, Assignment):
                    continue
                assignment = statement
                if (
                    assignment.target.kind != "var"
                    or not assignment.target.key
                ):
                    continue
                inherited: set[int] = set()
                for dependency in assignment.value.dependencies():
                    inherited.update(origins.get(dependency, ()))
                value = assignment.value.unwrapped()
                if value.kind == "call":
                    stateful = advance_tokenizer(
                        normalize_symbol(value.callee or ""), value.children
                    )
                    if stateful is not None:
                        inherited.update(stateful)
                target = assignment.target.key
                merged = origins.get(target, set()) | inherited
                if merged != origins.get(target, set()):
                    origins[target] = merged
                    changed = True
            if not changed:
                break
        return origins

    @staticmethod
    def _taint_origin_arguments(
        expression: Expr, origins: dict[str, set[int]]
    ) -> set[int]:
        result: set[int] = set()
        for dependency in expression.dependencies():
            result.update(origins.get(dependency, ()))
        return result

    @staticmethod
    def _stateful_tainted_keys(function: FunctionIR) -> frozenset[str]:
        """Return locals derived from a stateful tokenizer result."""

        assignments = [
            statement
            for statement in function.statements
            if isinstance(statement, Assignment)
            and statement.target.kind == "var"
            and statement.target.key
        ]
        result = {
            assignment.target.key
            for assignment in assignments
            if (
                (value := assignment.value.unwrapped()).kind == "call"
                and normalize_symbol(value.callee or "")
                in STATEFUL_TAINT_RETURNS
            )
        }
        for _ in range(max(2, len(assignments) + 1)):
            before = len(result)
            for assignment in assignments:
                if assignment.value.dependencies() & result:
                    result.add(assignment.target.key)
            if len(result) == before:
                break
        return frozenset(result)

    def _collect_inline_taint_write(
        self,
        assignment: Assignment,
        writes: set[WriteEffect],
        local_tainted: set[str],
        parameter_origins: dict[str, set[int]],
        parameter_taint_origins: dict[str, set[int]],
    ) -> None:
        """Summarize stores through an output parameter.

        Hex-Rays represents small readers and hand-written parsers as ordinary
        assignments (``*(dst + i) = byte`` / ``*out = parsed``), so API-only
        summaries miss them.  Require one unambiguous destination parameter;
        the stored value is then either an external source or conditionally
        dependent on one or more input parameters.
        """

        target = assignment.target.unwrapped()
        if target.kind not in {"deref", "index", "member"}:
            return

        destination_arguments: set[int] = set()
        if target.key is not None:
            destination_arguments.update(parameter_origins.get(target.key, ()))
        if not destination_arguments:
            for dependency in target.dependencies():
                destination_arguments.update(parameter_origins.get(dependency, ()))
        if len(destination_arguments) != 1:
            return

        external = bool(assignment.value.dependencies() & local_tainted)
        source_arguments = self._taint_origin_arguments(
            assignment.value, parameter_taint_origins
        )
        if not external and not source_arguments:
            return

        destination_argument = next(iter(destination_arguments))
        writes.add(
            WriteEffect(
                sink="inline_store",
                destination=ValueRef(argument=destination_argument),
                taints_destination=external,
                taint_sources=(
                    ()
                    if external
                    else tuple(
                        ValueRef(argument=index)
                        for index in sorted(source_arguments)
                    )
                ),
            )
        )

    def _compose_taint_sources(
        self,
        effect: WriteEffect,
        call: Call,
        local_tainted: set[str],
        parameter_taint_origins: dict[str, set[int]],
    ) -> tuple[bool, tuple[ValueRef, ...]]:
        """Lift a callee output-taint relation into its caller."""

        external = effect.taints_destination
        arguments: set[int] = set()
        for source in effect.taint_sources:
            expression = source.resolve(call.args)
            if expression is None:
                continue
            if expression.dependencies() & local_tainted:
                external = True
                continue
            arguments.update(
                self._taint_origin_arguments(expression, parameter_taint_origins)
            )
        if external:
            return True, ()
        return False, tuple(
            ValueRef(argument=index) for index in sorted(arguments)
        )

    def _compose_input_handles(
        self,
        effect: WriteEffect | IovecWriteEffect,
        call: Call,
        function: FunctionIR,
        parameter_taint_origins: dict[str, set[int]],
        already_external: bool,
    ) -> tuple[bool, tuple[ValueRef, ...]]:
        """Lift file-input handle provenance into the current wrapper."""

        if already_external or not effect.input_handles:
            return already_external, ()
        arguments: set[int] = set()
        for handle in effect.input_handles:
            expression = handle.resolve(call.args)
            if expression is None:
                return True, ()
            refs = self._parameter_refs_for_expression(
                expression, function, parameter_taint_origins
            )
            if not refs:
                # A fixed descriptor or an opaque local handle is still an
                # external source; only caller-expressible handles can later
                # be discharged by trusted-resource proof.
                return True, ()
            arguments.update(ref.argument for ref in refs if ref.argument is not None)
        return False, tuple(
            ValueRef(argument=index) for index in sorted(arguments)
        )

    def _input_profile(
        self,
        function: FunctionIR,
        index: SummaryIndex,
        parameter_taint_origins: dict[str, set[int]],
    ) -> tuple[tuple[ValueRef, ...], bool]:
        """Describe the external sources responsible for local taint.

        ``read`` and ``pread`` are the only handle-sensitive sources for now.
        Socket and stdio APIs remain unconditional because their surrounding
        abstractions do not provide a stable file-descriptor proof in the IR.
        """

        handles: set[ValueRef] = set()
        unconditional = False
        for statement in function.statements:
            if not isinstance(statement, Call):
                continue
            name = normalize_symbol(statement.name)
            if name in INPUT_WRITES or name in RETURN_SOURCES:
                if name in {"read", "pread"} and statement.args:
                    refs = self._parameter_refs_for_expression(
                        statement.args[0], function, parameter_taint_origins
                    )
                    if refs:
                        handles.update(refs)
                    else:
                        unconditional = True
                else:
                    unconditional = True

            nested = index.lookup(statement.name, statement.callee_ea)
            if nested is None:
                continue
            if nested.returns_external_input:
                unconditional = True
            for effect in nested.writes:
                if effect.taints_destination:
                    unconditional = True
                    continue
                for handle in effect.input_handles:
                    expression = handle.resolve(statement.args)
                    if expression is None:
                        unconditional = True
                        continue
                    refs = self._parameter_refs_for_expression(
                        expression, function, parameter_taint_origins
                    )
                    if refs:
                        handles.update(refs)
                    else:
                        unconditional = True
        return tuple(sorted(handles, key=repr)), unconditional

    def _parameter_refs_for_expression(
        self,
        expression: Expr,
        function: FunctionIR,
        parameter_taint_origins: dict[str, set[int]],
    ) -> tuple[ValueRef, ...]:
        direct = self._expr_ref(expression, function)
        if direct is not None and direct.argument is not None:
            return (direct,)
        arguments = self._taint_origin_arguments(
            expression, parameter_taint_origins
        )
        return tuple(
            ValueRef(argument=index) for index in sorted(arguments)
        )

    @staticmethod
    def _origin_arguments(
        expression: Expr, origins: dict[str, set[int]]
    ) -> set[int]:
        result: set[int] = set()
        value = expression.unwrapped()
        dependencies = (
            {value.key}
            if value.key is not None
            and value.kind in {"var", "global", "address", "op"}
            else set()
        )
        for dependency in dependencies:
            result.update(origins.get(dependency, ()))
        return result

    def _add_direct_write(
        self,
        function: FunctionIR,
        call: Call,
        name: str,
        destination_index: int,
        length_indexes: tuple[int, ...],
        writes: set[WriteEffect],
        source_index: int | None = None,
        taints_destination: bool = False,
    ) -> None:
        destination = self._argument_ref(function, call, destination_index)
        lengths = tuple(
            ref
            for argument_index in length_indexes
            if (ref := self._argument_ref(function, call, argument_index)) is not None
        )
        source = self._argument_ref(function, call, source_index)
        fortify_capacity = self._argument_ref(
            function,
            call,
            FORTIFIED_DESTINATION_SPECS.get(name),
        )
        if destination is None or len(lengths) != len(length_indexes):
            loop_refs = self._loop_accumulating_range_refs(
                function, call, destination_index, length_indexes
            )
            if loop_refs is not None:
                destination, lengths = loop_refs
        if destination is not None and len(lengths) == len(length_indexes):
            writes.add(
                WriteEffect(
                    sink=name,
                    destination=destination,
                    lengths=lengths,
                    source=source,
                    must_write=(
                        name in _DETERMINISTIC_BOUNDED_WRITE_NAMES
                        and self._statement_is_unconditional(function, call)
                    ),
                    taints_destination=taints_destination,
                    taint_sources=(source,) if source is not None else (),
                    fortify_capacity=fortify_capacity,
                )
            )

    def _loop_accumulating_range_refs(
        self,
        function: FunctionIR,
        call: Call,
        range_index: int,
        length_indexes: tuple[int, ...],
    ) -> tuple[ValueRef, tuple[ValueRef, ...]] | None:
        """Normalize cumulative ``sink(base + done, chunk)`` wrappers.

        Exact-read helpers commonly advance a local progress counter while
        repeatedly asking an input/output API for some remaining byte count.
        Neither range argument is necessarily a direct parameter reference,
        but the loop's aggregate effect is ``range(base, total)``.  This is
        used for destination writes and source reads alike.
        """

        if len(length_indexes) != 1:
            return None
        if (
            range_index >= len(call.args)
            or length_indexes[0] >= len(call.args)
        ):
            return None

        range_expr = call.args[range_index].unwrapped()
        length_expr = call.args[length_indexes[0]].unwrapped()
        if range_expr.op != "add" or len(range_expr.children) != 2:
            return None

        base_ref: ValueRef | None = None
        progress_key: str | None = None
        for child in range_expr.children:
            value = child.unwrapped()
            candidate = self._expr_ref(child, function)
            if candidate is not None:
                base_ref = candidate
                continue
            if value.kind == "var" and value.key not in function.parameters:
                progress_key = value.key
        if progress_key is None or base_ref is None:
            return None

        # Canonical exact-read loop: sink(base + done, total - done).
        if length_expr.op == "sub" and len(length_expr.children) == 2:
            total_expr, remaining_progress = length_expr.children
            total_ref = self._expr_ref(total_expr, function)
            if (
                total_ref is not None
                and remaining_progress.unwrapped().key == progress_key
            ):
                return base_ref, (total_ref,)

        # Chunked emitters often spell the remaining count through a local:
        # chunk = total - done; chunk = min(chunk, limit);
        # sink(base + done, chunk); done += chunk.
        if length_expr.kind != "var" or length_expr.key in function.parameters:
            return None
        chunk_key = length_expr.key
        if chunk_key is None:
            return None

        progress_assignments = [
            statement
            for statement in function.statements
            if isinstance(statement, Assignment)
            and statement.target.key == progress_key
        ]
        if not any(
            (value := statement.value.unwrapped()).kind == "const"
            and value.value == 0
            for statement in progress_assignments
        ):
            return None
        if not any(
            (value := statement.value.unwrapped()).op == "add"
            and len(value.children) == 2
            and {child.unwrapped().key for child in value.children}
            == {progress_key, chunk_key}
            for statement in progress_assignments
        ):
            return None

        total_ref: ValueRef | None = None
        for guard in call.guards:
            comparison = guard.unwrapped()
            if len(comparison.children) != 2:
                continue
            left, right = comparison.children
            if (
                comparison.op in {"slt", "ult"}
                and left.unwrapped().key == progress_key
            ):
                total_ref = self._expr_ref(right, function)
            elif (
                comparison.op in {"sgt", "ugt"}
                and right.unwrapped().key == progress_key
            ):
                total_ref = self._expr_ref(left, function)
            if total_ref is not None:
                break
        if total_ref is None:
            return None

        chunk_assignments = [
            statement
            for statement in function.statements
            if isinstance(statement, Assignment)
            and statement.target.key == chunk_key
        ]

        def is_remaining(expression: Expr) -> bool:
            value = expression.unwrapped()
            return bool(
                value.op == "sub"
                and len(value.children) == 2
                and self._expr_ref(value.children[0], function) == total_ref
                and value.children[1].unwrapped().key == progress_key
            )

        if not any(is_remaining(statement.value) for statement in chunk_assignments):
            return None
        if any(
            not is_remaining(statement.value)
            and not (
                (value := statement.value.unwrapped()).kind == "const"
                and value.value is not None
                and value.value > 0
            )
            for statement in chunk_assignments
        ):
            return None
        return base_ref, (total_ref,)

    def _allocation_for_expr(
        self, expression: Expr, function: FunctionIR, index: SummaryIndex
    ) -> AllocationEffect | None:
        expression = expression.unwrapped()
        if expression.kind != "call":
            return None
        name = normalize_symbol(expression.callee or "")
        size_indexes = ALLOC_SPECS.get(name)
        if size_indexes:
            refs = tuple(
                ref
                for argument_index in size_indexes
                if (
                    ref := self._expr_ref(
                        expression.children[argument_index], function
                    )
                )
                is not None
            )
            if len(refs) == len(size_indexes):
                return AllocationEffect(name, refs)

        nested = index.lookup(expression.callee or "", expression.callee_ea)
        if nested is None or nested.allocation is None:
            return None
        refs = tuple(
            ref
            for value in nested.allocation.sizes
            if (
                ref := self._compose_expr_ref(value, expression.children, function)
            )
            is not None
        )
        if len(refs) != len(nested.allocation.sizes):
            return None
        return AllocationEffect(nested.allocation.allocator, refs)

    def _return_taint(
        self,
        expression: Expr,
        function: FunctionIR,
        index: SummaryIndex,
        local_tainted: set[str],
        parameter_taint_origins: dict[str, set[int]],
        stateful_tainted_keys: frozenset[str],
    ) -> tuple[bool, set[int]]:
        expression = expression.unwrapped()
        if expression.kind != "call":
            ref = self._expr_ref(expression, function)
            external = bool(expression.dependencies() & local_tainted)
            arguments = (
                {ref.argument}
                if ref is not None and ref.argument is not None
                else set()
            )
            if expression.dependencies() & stateful_tainted_keys:
                arguments.update(
                    self._taint_origin_arguments(
                        expression, parameter_taint_origins
                    )
                )
            return external, arguments

        name = normalize_symbol(expression.callee or "")
        if name in RETURN_SOURCES:
            return True, set()
        arguments: set[int] = set()
        external = False
        if name in TAINT_PASSTHROUGH_RETURNS:
            for child in expression.children:
                external |= bool(child.dependencies() & local_tainted)
                ref = self._expr_ref(child, function)
                if ref is not None and ref.argument is not None:
                    arguments.add(ref.argument)
                if child.dependencies() & stateful_tainted_keys:
                    arguments.update(
                        self._taint_origin_arguments(
                            child, parameter_taint_origins
                        )
                    )

        nested = index.lookup(expression.callee or "", expression.callee_ea)
        if nested is not None:
            for argument_index in nested.return_taint_arguments:
                if argument_index >= len(expression.children):
                    continue
                child = expression.children[argument_index]
                external |= bool(
                    child.dependencies() & local_tainted
                )
                ref = self._expr_ref(child, function)
                if ref is not None and ref.argument is not None:
                    arguments.add(ref.argument)
                if child.dependencies() & stateful_tainted_keys:
                    arguments.update(
                        self._taint_origin_arguments(
                            child, parameter_taint_origins
                        )
                    )
            return external or nested.returns_external_input, arguments
        return external, arguments

    def _local_taint(
        self, function: FunctionIR, index: SummaryIndex
    ) -> set[str]:
        tainted: set[str] = set()

        def expression_is_tainted(expression: Expr) -> bool:
            if expression.dependencies() & tainted:
                return True
            if expression.kind != "call":
                return any(expression_is_tainted(child) for child in expression.children)
            name = normalize_symbol(expression.callee or "")
            if name in RETURN_SOURCES:
                return True
            if name in TAINT_PASSTHROUGH_RETURNS:
                return any(expression_is_tainted(child) for child in expression.children)
            nested = index.lookup(expression.callee or "", expression.callee_ea)
            if nested is None:
                return False
            if nested.returns_external_input:
                return True
            return any(
                argument_index < len(expression.children)
                and expression_is_tainted(expression.children[argument_index])
                for argument_index in nested.return_taint_arguments
            )

        statements = sorted(function.statements, key=lambda item: item.order)
        for _ in range(max(3, len(statements) + 1)):
            before = len(tainted)
            tokenizer_sessions: dict[str, bool] = {}

            def advance_tokenizer(
                name: str, arguments: tuple[Expr, ...]
            ) -> bool | None:
                input_index = STATEFUL_TAINT_RETURNS.get(name)
                if input_index is None or input_index >= len(arguments):
                    return None
                source = arguments[input_index].unwrapped()
                other_tainted = any(
                    expression_is_tainted(argument)
                    for index, argument in enumerate(arguments)
                    if index != input_index
                )
                if source.kind == "const" and source.value == 0:
                    result = tokenizer_sessions.get(name, False) or other_tainted
                else:
                    result = expression_is_tainted(source) or other_tainted
                tokenizer_sessions[name] = result
                return result

            for statement in statements:
                if isinstance(statement, Assignment):
                    value = statement.value.unwrapped()
                    tokenizer_tainted = (
                        advance_tokenizer(
                            normalize_symbol(value.callee or ""), value.children
                        )
                        if value.kind == "call"
                        else None
                    )
                    if statement.target.key and (
                        tokenizer_tainted is True
                        or expression_is_tainted(statement.value)
                    ):
                        tainted.add(statement.target.key)
                    continue
                if not isinstance(statement, Call):
                    continue
                name = normalize_symbol(statement.name)
                advance_tokenizer(name, statement.args)
                for argument_index in INPUT_WRITES.get(name, ()):
                    if argument_index < len(statement.args):
                        key = statement.args[argument_index].key
                        if key:
                            tainted.add(key)
                scanf = SCANF_SPECS.get(name)
                if scanf is not None:
                    _, first_output, source_index = scanf
                    source_tainted = source_index is None or (
                        source_index < len(statement.args)
                        and expression_is_tainted(statement.args[source_index])
                    )
                    if source_tainted:
                        for argument in statement.args[first_output:]:
                            if argument.key:
                                tainted.add(argument.key)
                copy = COPY_SPECS.get(name)
                if copy is not None:
                    destination_index, source_index, _ = copy
                    if (
                        destination_index < len(statement.args)
                        and source_index < len(statement.args)
                        and expression_is_tainted(statement.args[source_index])
                    ):
                        destination = statement.args[destination_index]
                        if destination.key:
                            tainted.add(destination.key)
                nested = index.lookup(statement.name, statement.callee_ea)
                if nested is not None:
                    for effect in nested.writes:
                        destination_tainted = effect.taints_destination or any(
                            (source := value.resolve(statement.args)) is not None
                            and expression_is_tainted(source)
                            for value in effect.taint_sources
                        )
                        if not destination_tainted:
                            continue
                        destination = effect.destination.resolve(statement.args)
                        if destination is not None and destination.key:
                            tainted.add(destination.key)
            if len(tainted) == before:
                break
        return tainted

    def _argument_ref(
        self, function: FunctionIR, call: Call, index: int | None
    ) -> ValueRef | None:
        if index is None or index < 0 or index >= len(call.args):
            return None
        return self._expr_ref(call.args[index], function)

    def _argument_ref_with_cstring_bound(
        self,
        function: FunctionIR,
        call: Call,
        argument_index: int,
        summaries: SummaryIndex,
        local_bounds: dict[str, int],
    ) -> ValueRef | None:
        direct = self._argument_ref(function, call, argument_index)
        if direct is not None:
            return direct
        bound = self._cstring_bound_for_expr(
            call.args[argument_index], summaries, local_bounds
        )
        if bound is None:
            return None
        return ValueRef(cstring_max=bound)

    def _local_cstring_bounds(
        self, function: FunctionIR, summaries: SummaryIndex
    ) -> dict[str, int]:
        """Prove finite C-string bounds for local assignment results.

        Every assignment seen for a local must be bounded.  This deliberately
        sacrifices some path precision: an unknown overwrite invalidates the
        fact instead of letting a convenient literal assignment hide it.
        """

        assignments: dict[str, list[Expr]] = {}
        for statement in function.statements:
            if not isinstance(statement, Assignment):
                continue
            target = statement.target.unwrapped()
            if target.kind == "var" and target.key:
                assignments.setdefault(target.key, []).append(statement.value)

        result: dict[str, int] = {}
        for _ in range(max(2, len(assignments) + 1)):
            changed = False
            for key, values in assignments.items():
                bounds = [
                    self._cstring_bound_for_expr(value, summaries, result)
                    for value in values
                ]
                if any(bound is None for bound in bounds):
                    continue
                maximum = max(bound for bound in bounds if bound is not None)
                if result.get(key) != maximum:
                    result[key] = maximum
                    changed = True
            if not changed:
                break
        return result

    def _return_cstring_max(
        self,
        function: FunctionIR,
        summaries: SummaryIndex,
        local_bounds: dict[str, int],
    ) -> int | None:
        returns = [
            statement.value
            for statement in function.statements
            if isinstance(statement, Return)
        ]
        if not returns:
            return None
        bounds = [
            self._cstring_bound_for_expr(value, summaries, local_bounds)
            for value in returns
        ]
        if any(bound is None for bound in bounds):
            return None
        return max(bound for bound in bounds if bound is not None)

    def _direct_error_output_effects(
        self,
        function: FunctionIR,
        summaries: SummaryIndex,
    ) -> tuple[tuple[Assignment, ErrorOutputEffect], ...]:
        """Export one unconditional unsigned output populated by ``-1`` API."""

        candidates: list[tuple[Assignment, ErrorOutputEffect]] = []
        for statement in function.statements:
            if not isinstance(statement, Assignment):
                continue
            destination = self._output_parameter_ref(statement.target, function)
            if destination is None:
                continue
            target = statement.target.unwrapped()
            if (
                target.signed is not False
                or target.bits is None
                or target.bits <= 0
                or target.bits > 128
            ):
                continue
            producer = statement.value
            if (
                producer.kind == "cast"
                and producer.children
                and producer.signed is False
                and producer.bits == target.bits
            ):
                producer = producer.children[0]
            if (
                producer.signed is not True
                or producer.bits != target.bits
                or not self._statement_is_unconditional(function, statement)
            ):
                continue
            contract = self._integer_return_effect(
                producer, function, summaries
            )
            if contract is None:
                continue
            sentinel, success_upper = contract
            candidates.append(
                (
                    statement,
                    ErrorOutputEffect(
                        destination=destination,
                        error_sentinel=sentinel,
                        bits=target.bits,
                        success_upper=success_upper,
                        sentinel_return_values=self._sentinel_return_values(
                            function,
                            statement,
                            target,
                            producer,
                            sentinel,
                        ),
                    ),
                )
            )
        return tuple(candidates)

    def _surviving_error_output_effects(
        self,
        function: FunctionIR,
        summaries: SummaryIndex,
        events: list[tuple[Assignment | Call, ErrorOutputEffect]],
    ) -> tuple[ErrorOutputEffect, ...]:
        """Keep error outputs whose exact slot has no later strong clobber."""

        survivors: set[ErrorOutputEffect] = set()
        for origin, effect in events:
            clobbers: list[Assignment | Call] = []
            for statement in function.statements:
                if (
                    statement is origin
                    or isinstance(statement, Return)
                    or (
                        isinstance(statement, Call)
                        and isinstance(origin, Call)
                        and statement.ea == origin.ea
                        and self._call_expression_matches(
                            Expr(
                                kind="call",
                                callee=statement.name,
                                callee_ea=statement.callee_ea,
                                children=statement.args,
                            ),
                            origin,
                        )
                    )
                ):
                    continue
                ranges: tuple[tuple[int, int | None, int | None], ...]
                if isinstance(statement, Assignment):
                    destination = self._output_parameter_ref(
                        statement.target, function
                    )
                    if destination is None:
                        continue
                    width = (
                        max(1, statement.target.bits // 8)
                        if statement.target.bits is not None
                        and statement.target.bits > 0
                        else None
                    )
                    ranges = (
                        self._output_write_range(destination, width),
                    )
                else:
                    ranges = self._call_output_write_ranges(
                        function, statement, summaries
                    )
                if any(
                    self._output_range_overlaps_effect(candidate, effect)
                    for candidate in ranges
                ):
                    clobbers.append(statement)
            if not self._output_is_clobbered_on_all_paths(
                function, origin, clobbers
            ):
                survivors.add(effect)
        return tuple(sorted(survivors, key=repr))

    def _output_is_clobbered_on_all_paths(
        self,
        function: FunctionIR,
        origin: Assignment | Call,
        clobbers: list[Assignment | Call],
    ) -> bool:
        terminators = [
            statement
            for statement in function.statements
            if isinstance(statement, Call)
            and normalize_symbol(statement.name) in _NORETURN_NAMES
            and statement is not origin
        ]
        if not clobbers and not terminators:
            return False
        if (
            not function.blocks
            or function.entry_block is None
            or origin.block_id not in function.blocks
            or any(
                statement.block_id not in function.blocks
                for statement in (*clobbers, *terminators)
            )
        ):
            has_clobber = any(
                statement.order > origin.order
                and self._statement_is_unconditional(function, statement)
                for statement in clobbers
            )
            has_terminator = any(
                statement.order > origin.order
                and self._statement_is_unconditional(function, statement)
                for statement in terminators
            )
            return has_clobber or has_terminator

        origin_block = origin.block_id
        clobber_blocks: set[int] = set()
        for statement in clobbers:
            block_id = statement.block_id
            if block_id is None:
                continue
            if block_id != origin_block:
                clobber_blocks.add(block_id)
                continue
            if statement.order > origin.order and (
                not statement.guards
                or self._statement_is_unconditional(function, statement)
            ):
                clobber_blocks.add(block_id)
        terminator_blocks: set[int] = set()
        for statement in terminators:
            block_id = statement.block_id
            if block_id is None:
                continue
            block = function.blocks[block_id]
            if block_id == origin_block:
                if statement.order > origin.order and (
                    not statement.guards
                    or self._statement_is_unconditional(function, statement)
                ):
                    terminator_blocks.add(block_id)
            elif not block.successors:
                terminator_blocks.add(block_id)
        if origin_block in clobber_blocks or origin_block in terminator_blocks:
            return True

        frontier = list(function.blocks[origin_block].successors)
        if not frontier:
            return False
        visited: set[int] = set()
        while frontier:
            block_id = frontier.pop()
            if (
                block_id in visited
                or block_id in clobber_blocks
                or block_id in terminator_blocks
            ):
                continue
            visited.add(block_id)
            block = function.blocks[block_id]
            if not block.successors:
                return False
            frontier.extend(block.successors)
        return True

    def _call_output_write_ranges(
        self,
        function: FunctionIR,
        call: Call,
        summaries: SummaryIndex,
    ) -> tuple[tuple[int, int | None, int | None], ...]:
        """Return wrapper-parameter ranges a call strongly overwrites."""

        name = normalize_symbol(call.name)
        nested = summaries.lookup(call.name, call.callee_ea)
        ranges: set[tuple[int, int | None, int | None]] = set()

        if nested is not None:
            for error in nested.error_outputs:
                destination = self._compose_ref(
                    error.destination, call, function
                )
                if destination is not None:
                    ranges.add(
                        self._output_write_range(
                            destination,
                            max(1, error.bits // 8),
                        )
                    )
            for write in nested.writes:
                if write.sink == "error_output":
                    continue
                destination = self._compose_ref(
                    write.destination, call, function
                )
                if destination is None:
                    continue
                write_name = normalize_symbol(write.sink)
                if write_name in _MAY_WRITE_ONLY_NAMES:
                    continue
                if write_name in _DETERMINISTIC_BOUNDED_WRITE_NAMES:
                    width = (
                        self._resolved_guaranteed_write_width(
                            write, call, function
                        )
                        if write.must_write
                        else 0
                    )
                else:
                    width = self._resolved_write_width(write, call)
                ranges.add(
                    self._output_write_range(
                        destination,
                        width,
                    )
                )

        write_indexes: dict[int, int | None] = {}
        for index in INPUT_WRITES.get(name, ()):
            write_indexes[index] = self._direct_call_write_width(
                name, call
            )
        if name in COPY_SPECS:
            destination_index, _, _ = COPY_SPECS[name]
            write_indexes[destination_index] = self._direct_call_write_width(
                name, call
            )
        if name in BOUNDED_WRITE_SPECS:
            destination_index, _ = BOUNDED_WRITE_SPECS[name]
            write_indexes[destination_index] = self._direct_call_write_width(
                name, call
            )
        if name in UNBOUNDED_WRITE_SPECS:
            destination_index, _ = UNBOUNDED_WRITE_SPECS[name]
            write_indexes[destination_index] = None
        if name in SCANF_SPECS:
            _, first_output, _ = SCANF_SPECS[name]
            for index in range(first_output, len(call.args)):
                write_indexes[index] = None

        if name in _DETERMINISTIC_BOUNDED_WRITE_NAMES:
            deterministic_spec = COPY_SPECS.get(name)
            if deterministic_spec is not None:
                destination_index, _, length_indexes = deterministic_spec
            else:
                destination_index, length_indexes = BOUNDED_WRITE_SPECS[name]
            write_indexes[destination_index] = self._guaranteed_write_width(
                function,
                call,
                tuple(
                    call.args[index]
                    for index in length_indexes
                    if index < len(call.args)
                ),
                expected_factors=len(length_indexes),
            )
        elif name in _MAY_WRITE_ONLY_NAMES:
            write_indexes.clear()

        for index, width in write_indexes.items():
            destination = self._argument_ref(function, call, index)
            if destination is not None and destination.argument is not None:
                ranges.add(self._output_write_range(destination, width))

        if (
            nested is None
            and not summaries.knows(call.name, call.callee_ea)
            and not self._has_known_call_semantics(name)
        ):
            for argument in call.args:
                if argument.is_pointer is not True:
                    continue
                destination = self._expr_ref(argument, function)
                if destination is not None and destination.argument is not None:
                    ranges.add((destination.argument, None, None))
        if name in FREE_NAMES:
            for argument in call.args:
                destination = self._expr_ref(argument, function)
                if destination is not None and destination.argument is not None:
                    ranges.add((destination.argument, None, None))
        return tuple(sorted(ranges, key=repr))

    @staticmethod
    def _output_write_range(
        destination: ValueRef,
        width: int | None,
    ) -> tuple[int, int | None, int | None]:
        argument = destination.argument
        if argument is None:
            return -1, None, None
        start = destination.offset
        end = start + width if width is not None and width >= 0 else None
        return argument, start, end

    @staticmethod
    def _output_range_overlaps_effect(
        candidate: tuple[int, int | None, int | None],
        effect: ErrorOutputEffect,
    ) -> bool:
        argument, start, end = candidate
        if effect.destination.argument != argument:
            return False
        if start is None:
            return True
        effect_start = effect.destination.offset
        effect_end = effect_start + max(1, effect.bits // 8)
        if end is None:
            return start < effect_end
        return start < effect_end and effect_start < end

    def _resolved_write_width(
        self,
        effect: WriteEffect,
        call: Call,
    ) -> int | None:
        if not effect.lengths:
            return None
        values = [
            self._literal_integer(resolved)
            for reference in effect.lengths
            if (resolved := reference.resolve(call.args)) is not None
        ]
        if len(values) != len(effect.lengths) or any(
            value is None or value < 0 for value in values
        ):
            return None
        width = 1
        for value in values:
            if value is not None:
                width *= value
        return width

    def _direct_call_write_width(
        self,
        name: str,
        call: Call,
    ) -> int | None:
        indexes: tuple[int, ...] = ()
        if name in COPY_SPECS:
            _, _, indexes = COPY_SPECS[name]
        elif name in BOUNDED_WRITE_SPECS:
            _, indexes = BOUNDED_WRITE_SPECS[name]
        values = [
            self._literal_integer(call.args[index])
            for index in indexes
            if index < len(call.args)
        ]
        if not indexes or len(values) != len(indexes) or any(
            value is None or value < 0 for value in values
        ):
            return None
        width = 1
        for value in values:
            if value is not None:
                width *= value
        return width

    def _resolved_guaranteed_write_width(
        self,
        effect: WriteEffect,
        call: Call,
        function: FunctionIR,
    ) -> int:
        resolved = tuple(
            expression
            for reference in effect.lengths
            if (expression := reference.resolve(call.args)) is not None
        )
        return self._guaranteed_write_width(
            function,
            call,
            resolved,
            expected_factors=len(effect.lengths),
        )

    def _guaranteed_write_width(
        self,
        function: FunctionIR,
        call: Call,
        lengths: tuple[Expr, ...],
        *,
        expected_factors: int,
    ) -> int:
        """Return the byte prefix a deterministic writer must overwrite.

        A requested byte count and a guaranteed byte count are different
        facts.  In particular, an unresolved ``memset(dst, 0, n)`` may write
        zero bytes; it must not inherit the old ``None == unbounded`` range
        convention used for may-write summaries.  Literal values and positive
        path lower bounds are multiplied only when every factor is known.
        """

        if expected_factors == 0 or len(lengths) != expected_factors:
            return 0
        width = 1
        for expression in lengths:
            lower, _ = self._integer_interval_on_path(
                expression, function, call
            )
            if lower is None or lower < 0:
                return 0
            width *= lower
        return width

    def _integer_interval_on_path(
        self,
        expression: Expr,
        function: FunctionIR,
        statement: Assignment | Call,
        seen: frozenset[object] = frozenset(),
    ) -> tuple[int | None, int | None]:
        """Conservatively bound an integer expression on one ctree path."""

        value = expression.unwrapped()
        identity = self._expression_identity(value)
        if identity in seen:
            return None, None
        seen = seen | {identity}

        if value.kind == "const" and value.value is not None:
            return value.value, value.value

        type_bounds = self._integer_type_bounds(expression)
        path_guards = self._summary_path_guard_expressions(
            function, statement
        )
        if value.kind in {"var", "global", "deref", "member", "index"}:
            lower, upper = type_bounds or (None, None)
            guard_lower, guard_upper = self._path_comparison_bounds(
                value, path_guards
            )
            if guard_lower is not None:
                lower = guard_lower if lower is None else max(lower, guard_lower)
            if guard_upper is not None:
                upper = guard_upper if upper is None else min(upper, guard_upper)
            if lower is not None and upper is not None and lower > upper:
                return None, None
            return lower, upper

        if value.kind != "op" or len(value.children) != 2:
            return type_bounds or (None, None)
        left = self._integer_interval_on_path(
            value.children[0], function, statement, seen
        )
        right = self._integer_interval_on_path(
            value.children[1], function, statement, seen
        )
        if None in left or None in right:
            return type_bounds or (None, None)
        left_lower, left_upper = left
        right_lower, right_upper = right
        assert left_lower is not None and left_upper is not None
        assert right_lower is not None and right_upper is not None

        candidates: tuple[int, ...] | None = None
        if value.op == "add":
            candidates = (
                left_lower + right_lower,
                left_upper + right_upper,
            )
        elif value.op == "sub":
            candidates = (
                left_lower - right_upper,
                left_upper - right_lower,
            )
        elif value.op == "mul":
            products = tuple(
                left_value * right_value
                for left_value in (left_lower, left_upper)
                for right_value in (right_lower, right_upper)
            )
            candidates = (min(products), max(products))
        elif value.op == "shl" and 0 <= right_lower == right_upper < 128:
            candidates = (
                left_lower << right_lower,
                left_upper << right_upper,
            )
        if candidates is None:
            return type_bounds or (None, None)

        lower, upper = candidates
        if type_bounds is not None and (
            lower < type_bounds[0] or upper > type_bounds[1]
        ):
            # Modular wrap destroys a useful lower bound.  Falling back to the
            # complete result type interval is safe and still proves zero for
            # ordinary unsigned byte counts.
            return type_bounds
        guard_lower, guard_upper = self._path_comparison_bounds(
            value, path_guards
        )
        if guard_lower is not None:
            lower = max(lower, guard_lower)
        if guard_upper is not None:
            upper = min(upper, guard_upper)
        return (None, None) if lower > upper else (lower, upper)

    @staticmethod
    def _integer_type_bounds(expression: Expr) -> tuple[int, int] | None:
        if expression.bits is None or not 0 < expression.bits <= 128:
            return None
        if expression.signed is False:
            return 0, (1 << expression.bits) - 1
        if expression.signed is True:
            high = (1 << (expression.bits - 1)) - 1
            return -(1 << (expression.bits - 1)), high
        return None

    @classmethod
    def _path_comparison_bounds(
        cls,
        expression: Expr,
        guards: tuple[Expr, ...],
    ) -> tuple[int | None, int | None]:
        lower_bounds: list[int] = []
        upper_bounds: list[int] = []
        reverse = {
            "slt": "sgt",
            "ult": "ugt",
            "sle": "sge",
            "ule": "uge",
            "sgt": "slt",
            "ugt": "ult",
            "sge": "sle",
            "uge": "ule",
        }
        identity = cls._expression_identity(expression)
        for guard in guards:
            for comparison in cls._conjunctive_comparison_leaves(guard):
                if len(comparison.children) != 2:
                    continue
                left, right = comparison.children
                left_matches = cls._expression_identity(left) == identity
                right_matches = cls._expression_identity(right) == identity
                if left_matches == right_matches:
                    continue
                constant = right if left_matches else left
                constant_value = cls._literal_integer(constant)
                if constant_value is None:
                    continue
                operation = comparison.op or ""
                if right_matches:
                    operation = reverse.get(operation, operation)
                if operation not in {"eq", "ne"}:
                    if expression.signed is True and not operation.startswith("s"):
                        continue
                    if expression.signed is False and not operation.startswith("u"):
                        continue
                    if expression.signed is None:
                        continue
                if operation == "eq":
                    lower_bounds.append(constant_value)
                    upper_bounds.append(constant_value)
                elif operation == "ne":
                    type_bounds = cls._integer_type_bounds(expression)
                    if type_bounds is None:
                        continue
                    if constant_value == type_bounds[0]:
                        lower_bounds.append(type_bounds[0] + 1)
                    elif constant_value == type_bounds[1]:
                        upper_bounds.append(type_bounds[1] - 1)
                elif operation in {"sge", "uge"}:
                    lower_bounds.append(constant_value)
                elif operation in {"sgt", "ugt"}:
                    lower_bounds.append(constant_value + 1)
                elif operation in {"sle", "ule"}:
                    upper_bounds.append(constant_value)
                elif operation in {"slt", "ult"}:
                    upper_bounds.append(constant_value - 1)
        return (
            max(lower_bounds) if lower_bounds else None,
            min(upper_bounds) if upper_bounds else None,
        )

    @classmethod
    def _summary_path_guard_expressions(
        cls,
        function: FunctionIR,
        statement: Assignment | Call,
    ) -> tuple[Expr, ...]:
        """Recover predicates that are still true at a summary statement.

        Ctree containment supplies the ordinary positive/negative branch
        guards.  A validation branch that terminates instead proves the
        complement on continuation.  Only terminal branches are negated, and
        every predicate is discarded (or reduced conjunct-by-conjunct) after
        a relevant reaching definition changes.
        """

        candidates: list[Expr] = []
        for guard in statement.guards:
            origins = [
                condition.order
                for condition in function.conditions
                if condition.order < statement.order
                and (
                    cls._expression_identity(condition.expression)
                    == cls._expression_identity(guard)
                    or cls._expression_identity(
                        cls._negate_guard(condition.expression)
                    )
                    == cls._expression_identity(guard)
                )
            ]
            surviving = (
                cls._summary_guard_after_redefinitions(
                    function,
                    guard,
                    max(origins),
                    statement.order,
                )
                if origins
                else guard
            )
            if surviving is not None:
                candidates.append(surviving)

        candidates.extend(
            cls._summary_direct_predecessor_guards(function, statement)
        )
        for item in function.statements:
            if item.order >= statement.order:
                continue
            terminating = isinstance(item, Return) or (
                isinstance(item, Call)
                and normalize_symbol(item.name) in _NORETURN_NAMES
            )
            if not terminating:
                continue
            guards = tuple(
                guard
                for guard in item.guards
                if not cls._guard_is_constant_true(guard)
            )
            if not guards:
                continue
            rejected = cls._guard_conjunction(guards)
            accepted = cls._summary_guard_after_redefinitions(
                function,
                cls._negate_guard(rejected),
                item.order,
                statement.order,
            )
            if accepted is not None:
                candidates.append(accepted)

        result: list[Expr] = []
        identities: set[object] = set()
        for candidate in candidates:
            identity = cls._expression_identity(candidate)
            if identity in identities:
                continue
            identities.add(identity)
            result.append(candidate)
        return tuple(result)

    @classmethod
    def _summary_direct_predecessor_guards(
        cls,
        function: FunctionIR,
        statement: Assignment | Call,
    ) -> tuple[Expr, ...]:
        """Recover one unmerged branch edge when Hex-Rays labels its sibling."""

        if statement.block_id is None:
            return ()
        target = function.blocks.get(statement.block_id)
        if target is None or len(target.predecessors) != 1:
            return ()
        predecessor_id = target.predecessors[0]
        predecessor = function.blocks.get(predecessor_id)
        if (
            predecessor is None
            or len(predecessor.successors) != 2
            or statement.block_id not in predecessor.successors
        ):
            return ()
        sibling_id = next(
            successor
            for successor in predecessor.successors
            if successor != statement.block_id
        )

        def branch_polarity(block_id: int, condition: Expr) -> int:
            polarity = 0
            condition_identity = cls._expression_identity(condition)
            negative_identity = cls._expression_identity(
                cls._negate_guard(condition)
            )
            for item in function.statements:
                if item.block_id != block_id:
                    continue
                for guard in item.guards:
                    identity = cls._expression_identity(guard)
                    if identity == condition_identity:
                        polarity |= 1
                    if identity == negative_identity:
                        polarity |= 2
            return polarity

        result: list[Expr] = []
        for condition in function.conditions:
            if condition.block_id != predecessor_id:
                continue
            target_polarity = branch_polarity(
                statement.block_id, condition.expression
            )
            sibling_polarity = branch_polarity(
                sibling_id, condition.expression
            )
            inferred: Expr | None = None
            if target_polarity == 1 and sibling_polarity != 1:
                inferred = condition.expression
            elif target_polarity == 2 and sibling_polarity != 2:
                inferred = cls._negate_guard(condition.expression)
            elif sibling_polarity == 1 and target_polarity == 0:
                inferred = cls._negate_guard(condition.expression)
            elif sibling_polarity == 2 and target_polarity == 0:
                inferred = condition.expression
            if inferred is None:
                continue
            surviving = cls._summary_guard_after_redefinitions(
                function,
                inferred,
                condition.order,
                statement.order,
            )
            if surviving is not None:
                result.append(surviving)
        return tuple(result)

    @classmethod
    def _summary_guard_after_redefinitions(
        cls,
        function: FunctionIR,
        guard: Expr,
        after_order: int,
        before_order: int,
    ) -> Expr | None:
        value = guard.unwrapped()
        if value.op == "logical_and":
            children = tuple(
                surviving
                for child in value.children
                if (
                    surviving := cls._summary_guard_after_redefinitions(
                        function,
                        child,
                        after_order,
                        before_order,
                    )
                )
                is not None
            )
            if not children:
                return None
            if len(children) == 1:
                return children[0]
            return replace(
                value,
                text=" && ".join(
                    f"({child.text})" for child in children if child.text
                ),
                children=children,
            )
        return (
            None
            if cls._summary_guard_redefined_between(
                function, value, after_order, before_order
            )
            else value
        )

    @staticmethod
    def _summary_guard_redefined_between(
        function: FunctionIR,
        guard: Expr,
        after_order: int,
        before_order: int,
    ) -> bool:
        locations: set[tuple[str, str, int]] = set()

        def visit(expression: Expr) -> None:
            value = expression.unwrapped()
            if value.key is not None:
                if value.kind in {"var", "global"}:
                    locations.add((value.kind, value.key, value.offset))
                elif value.kind in {"deref", "member", "index"}:
                    locations.add(("memory", value.key, value.offset))
            for child in value.children:
                visit(child)

        visit(guard)
        if not locations:
            return False
        for item in function.statements:
            if (
                not isinstance(item, Assignment)
                or not after_order < item.order < before_order
            ):
                continue
            target = item.target.unwrapped()
            if target.key is None:
                continue
            if target.kind in {"var", "global"}:
                location = (target.kind, target.key, target.offset)
            elif target.kind in {"deref", "member", "index"}:
                location = ("memory", target.key, target.offset)
            else:
                continue
            if location in locations:
                return True
            if (
                target.kind in {"var", "global"}
                and target.offset == 0
                and any(
                    owner == target.key
                    for _, owner, _ in locations
                )
            ):
                return True
        return False

    @staticmethod
    def _guard_is_constant_true(guard: Expr) -> bool:
        value = guard.unwrapped()
        return bool(
            value.kind == "const"
            and value.value is not None
            and value.value != 0
        )

    @staticmethod
    def _conjunctive_comparison_leaves(expression: Expr) -> tuple[Expr, ...]:
        value = expression.unwrapped()
        if value.op == "logical_and":
            return tuple(
                leaf
                for child in value.children
                for leaf in SummaryBuilder._conjunctive_comparison_leaves(child)
            )
        if value.op == "logical_or":
            return ()
        if value.op in {
            "sge",
            "uge",
            "sle",
            "ule",
            "sgt",
            "ugt",
            "slt",
            "ult",
            "eq",
            "ne",
        }:
            return (value,)
        return ()

    @staticmethod
    def _has_known_call_semantics(name: str) -> bool:
        return bool(
            name in ALLOC_SPECS
            or name in BOUNDED_CSTRING_READ_SPECS
            or name in BOUNDED_MULTI_READ_SPECS
            or name in BOUNDED_READ_SPECS
            or name in BOUNDED_WRITE_SPECS
            or name in COPY_SPECS
            or name in CSTRING_READ_ARGUMENTS
            or name in ERROR_SENTINEL_RETURNS
            or name in FORMAT_ARGUMENTS
            or name in FREE_NAMES
            or name in INPUT_WRITES
            or name in IOVEC_READ_SPECS
            or name in IOVEC_WRITE_SPECS
            or name in MESSAGE_READ_SPECS
            or name in MESSAGE_WRITE_SPECS
            or name in RETURN_SOURCES
            or name in SCANF_SPECS
            or name in STATEFUL_TAINT_RETURNS
            or name in SUCCESS_RETURN_LENGTH_SPECS
            or name in TAINT_PASSTHROUGH_RETURNS
            or name in UNBOUNDED_WRITE_SPECS
        )

    def _sentinel_return_values(
        self,
        function: FunctionIR,
        output: Assignment | Call,
        target: Expr,
        producer: Expr,
        sentinel: int,
        producer_values: tuple[int, ...] | None = None,
    ) -> tuple[int, ...]:
        """Return statuses possible while an output retains its sentinel.

        The proof is intentionally relational and small: all normal returns
        reachable under the hypothetical sentinel must be integral constants.
        Guards attached to earlier returns are negated for later continuation,
        matching the common ``if (count == SIZE_MAX) return -1; return 0``
        wrapper. Unknown predicates keep a return reachable; they never make a
        status/output relationship look stronger than the extracted CFG.
        """

        returns = sorted(
            (
                statement
                for statement in function.statements
                if isinstance(statement, Return)
                and statement.order > output.order
            ),
            key=lambda statement: statement.order,
        )
        if not returns:
            return ()
        source_values = (
            (sentinel,) if producer_values is None else producer_values
        )
        statuses: set[int] = set()
        for current in returns:
            guards = list(current.guards)
            for earlier in returns:
                if earlier.order >= current.order or not earlier.guards:
                    continue
                rejected = self._guard_conjunction(earlier.guards)
                guards.append(self._negate_guard(rejected))
            if any(
                self._expression_truth_for_output_sentinel(
                    guard,
                    function,
                    current.order,
                    target,
                    producer,
                    sentinel,
                    target.bits,
                    source_values,
                )
                is False
                for guard in guards
            ):
                continue
            values = self._constant_values_for_output_sentinel(
                current.value,
                function,
                current.order,
                target,
                producer,
                sentinel,
                target.bits,
                source_values,
            )
            if values is None:
                return ()
            statuses.update(values)
        return tuple(sorted(statuses)) if statuses else ()

    @staticmethod
    def _guard_conjunction(guards: tuple[Expr, ...]) -> Expr:
        if len(guards) == 1:
            return guards[0]
        return Expr(
            kind="op",
            text=" && ".join(f"({guard.text})" for guard in guards),
            op="logical_and",
            children=guards,
            bits=1,
            signed=False,
            is_pointer=False,
        )

    @classmethod
    def _negate_guard(cls, expression: Expr) -> Expr:
        value = expression.unwrapped()
        negated = {
            "sge": "slt",
            "uge": "ult",
            "sle": "sgt",
            "ule": "ugt",
            "sgt": "sle",
            "ugt": "ule",
            "slt": "sge",
            "ult": "uge",
            "eq": "ne",
            "ne": "eq",
        }
        if value.op in {"logical_and", "logical_or"}:
            return replace(
                value,
                text=f"!({value.text})" if value.text else "",
                op=(
                    "logical_or"
                    if value.op == "logical_and"
                    else "logical_and"
                ),
                children=tuple(cls._negate_guard(child) for child in value.children),
            )
        if value.op in negated:
            return replace(
                value,
                text=f"!({value.text})" if value.text else "",
                op=negated[value.op],
            )
        return Expr(
            kind="op",
            text=f"!({value.text})" if value.text else "",
            op="logical_not",
            children=(value,),
            bits=1,
            signed=False,
            is_pointer=False,
        )

    def _expression_truth_for_output_sentinel(
        self,
        expression: Expr,
        function: FunctionIR,
        before_order: int,
        target: Expr,
        producer: Expr,
        sentinel: int,
        output_bits: int | None,
        producer_values: tuple[int, ...],
        seen: frozenset[str] = frozenset(),
    ) -> bool | None:
        values = self._constant_values_for_output_sentinel(
            expression,
            function,
            before_order,
            target,
            producer,
            sentinel,
            output_bits,
            producer_values,
            seen,
        )
        if values is None:
            return None
        truths = {value != 0 for value in values}
        return next(iter(truths)) if len(truths) == 1 else None

    def _constant_values_for_output_sentinel(
        self,
        expression: Expr,
        function: FunctionIR,
        before_order: int,
        target: Expr,
        producer: Expr,
        sentinel: int,
        output_bits: int | None,
        producer_values: tuple[int, ...],
        seen: frozenset[str] = frozenset(),
    ) -> frozenset[int] | None:
        """Evaluate a small integral expression under the output error case.

        Hex-Rays commonly folds status mappings into a ternary return or a
        boolean comparison. Preserve the finite set of results without
        pretending that unrelated scalar expressions are known.
        """

        original = expression
        if original.kind == "cast" and original.children:
            values = self._constant_values_for_output_sentinel(
                original.children[0],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            if values is None:
                return None
            return frozenset(
                self._cast_integer_constant(
                    value, original.bits, original.signed
                )
                for value in values
            )

        value = expression.unwrapped()
        stored = target.unwrapped()
        source = producer.unwrapped()
        if self._same_value_storage(value, stored):
            if output_bits is None or output_bits <= 0 or output_bits > 128:
                return None
            return frozenset({sentinel & ((1 << output_bits) - 1)})
        if self._same_value_storage(value, source) or (
            value.kind == "call"
            and source.kind == "call"
            and self._same_call_expressions(value, source)
        ):
            return (
                frozenset(
                    self._cast_integer_constant(
                        item, value.bits, value.signed
                    )
                    for item in producer_values
                )
                if producer_values
                else None
            )
        if value.kind == "const" and value.value is not None:
            return frozenset({value.value})

        if (
            value.kind in {"var", "global"}
            and value.key is not None
            and value.key not in seen
        ):
            assignment_values = self._scalar_assignment_values_for_sentinel(
                value,
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            if assignment_values is not None:
                return assignment_values

        children = value.children
        if value.op in {"logical_not", "lnot"} and len(children) == 1:
            child_values = self._constant_values_for_output_sentinel(
                children[0],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            if child_values is None:
                return frozenset({0, 1})
            return frozenset(0 if item else 1 for item in child_values)

        if value.op in {"logical_and", "logical_or"} and len(children) == 2:
            left_values = self._constant_values_for_output_sentinel(
                children[0],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            right_values = self._constant_values_for_output_sentinel(
                children[1],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            if left_values is None or right_values is None:
                return frozenset({0, 1})
            if value.op == "logical_and":
                return frozenset(
                    int(bool(left) and bool(right))
                    for left in left_values
                    for right in right_values
                )
            return frozenset(
                int(bool(left) or bool(right))
                for left in left_values
                for right in right_values
            )

        binary = {
            "and": operator.and_,
            "or": operator.or_,
            "xor": operator.xor,
            "add": operator.add,
            "sub": operator.sub,
            "mul": operator.mul,
            "shl": operator.lshift,
            "shr": operator.rshift,
        }
        operation = binary.get(value.op or "")
        if operation is not None and len(children) == 2:
            left_values = self._constant_values_for_output_sentinel(
                children[0],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            right_values = self._constant_values_for_output_sentinel(
                children[1],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            if (
                left_values is None
                or right_values is None
                or len(left_values) * len(right_values) > 64
            ):
                return None
            results: set[int] = set()
            for left in left_values:
                for right in right_values:
                    if value.op in {"shl", "shr"} and (
                        right < 0
                        or (
                            value.bits is not None
                            and value.bits > 0
                            and right >= value.bits
                        )
                    ):
                        return None
                    try:
                        result = operation(left, right)
                    except (OverflowError, ValueError):
                        return None
                    results.add(
                        self._cast_integer_constant(
                            result, value.bits, value.signed
                        )
                    )
            return frozenset(results)

        comparisons = {
            "sge",
            "uge",
            "sle",
            "ule",
            "sgt",
            "ugt",
            "slt",
            "ult",
            "eq",
            "ne",
        }
        if value.op in comparisons and len(children) == 2:
            left_values = self._constant_values_for_output_sentinel(
                children[0],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            right_values = self._constant_values_for_output_sentinel(
                children[1],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            if left_values is None or right_values is None:
                return frozenset({0, 1})
            results: set[int] = set()
            for left in left_values:
                for right in right_values:
                    result = self._integer_comparison(
                        value.op,
                        left,
                        right,
                        children[0].bits or output_bits,
                        children[0].signed is False,
                    )
                    if result is None:
                        return frozenset({0, 1})
                    results.add(int(result))
            return frozenset(results)

        if value.op in {"ternary", "tern", "?:"} and len(children) == 3:
            condition = self._expression_truth_for_output_sentinel(
                children[0],
                function,
                before_order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen,
            )
            if condition is True:
                indexes = (1,)
            elif condition is False:
                indexes = (2,)
            else:
                indexes = (1, 2)
            results: set[int] = set()
            for index in indexes:
                branch_values = self._constant_values_for_output_sentinel(
                    children[index],
                    function,
                    before_order,
                    target,
                    producer,
                    sentinel,
                    output_bits,
                    producer_values,
                    seen,
                )
                if branch_values is None:
                    return None
                results.update(branch_values)
            return frozenset(results)
        return None

    def _scalar_assignment_values_for_sentinel(
        self,
        scalar: Expr,
        function: FunctionIR,
        before_order: int,
        target: Expr,
        producer: Expr,
        sentinel: int,
        output_bits: int | None,
        producer_values: tuple[int, ...],
        seen: frozenset[str],
    ) -> frozenset[int] | None:
        """Merge finite scalar definitions that cover every relevant path."""

        assignments = sorted(
            (
                statement
                for statement in function.statements
                if isinstance(statement, Assignment)
                and statement.order < before_order
                and statement.target.kind in {"var", "global"}
                and statement.target.key == scalar.key
                and statement.target.offset == scalar.offset == 0
            ),
            key=lambda statement: statement.order,
        )
        if not assignments:
            return None

        candidates: list[tuple[Assignment, bool | None, Expr | None]] = []
        for assignment in assignments:
            guard = (
                self._guard_conjunction(assignment.guards)
                if assignment.guards
                else None
            )
            truth = (
                True
                if guard is None
                else self._expression_truth_for_output_sentinel(
                    guard,
                    function,
                    assignment.order,
                    target,
                    producer,
                    sentinel,
                    output_bits,
                    producer_values,
                    seen | {scalar.key},
                )
            )
            if truth is not False:
                candidates.append((assignment, truth, guard))
        if not candidates:
            return None

        definite = [
            candidate for candidate in candidates if candidate[1] is True
        ]
        if definite:
            base = max(definite, key=lambda candidate: candidate[0].order)
            relevant = [
                candidate
                for candidate in candidates
                if candidate is base
                or (
                    candidate[0].order > base[0].order
                    and candidate[1] is None
                )
            ]
        else:
            guarded = [
                candidate for candidate in candidates if candidate[2] is not None
            ]
            if not any(
                self._guards_are_complementary(left[2], right[2])
                for index, left in enumerate(guarded)
                for right in guarded[index + 1 :]
            ):
                return None
            relevant = candidates

        results: set[int] = set()
        for assignment, _, _ in relevant:
            values = self._constant_values_for_output_sentinel(
                assignment.value,
                function,
                assignment.order,
                target,
                producer,
                sentinel,
                output_bits,
                producer_values,
                seen | {scalar.key},
            )
            if values is None:
                return None
            results.update(values)
        return frozenset(results) if results else None

    @classmethod
    def _guards_are_complementary(
        cls,
        left: Expr | None,
        right: Expr | None,
    ) -> bool:
        if left is None or right is None:
            return False
        return bool(
            cls._expression_identity(cls._negate_guard(left))
            == cls._expression_identity(right)
            or cls._expression_identity(cls._negate_guard(right))
            == cls._expression_identity(left)
        )

    @staticmethod
    def _cast_integer_constant(
        value: int,
        bits: int | None,
        signed: bool | None,
    ) -> int:
        if signed is None or bits is None or bits <= 0 or bits > 128:
            return value
        modulus = 1 << bits
        result = value & (modulus - 1)
        if signed is True and result & (1 << (bits - 1)):
            result -= modulus
        return result

    @staticmethod
    def _same_value_storage(left: Expr, right: Expr) -> bool:
        left = left.unwrapped()
        right = right.unwrapped()
        if left.key is None or right.key is None:
            return False
        scalar_kinds = {"var", "global"}
        memory_kinds = {"deref", "member", "index"}
        if left.kind in scalar_kinds and right.kind in scalar_kinds:
            return left.key == right.key and left.offset == right.offset == 0
        if left.kind in memory_kinds and right.kind in memory_kinds:
            return left.key == right.key and left.offset == right.offset
        return False

    @staticmethod
    def _integer_comparison(
        operation: str,
        left: int,
        right: int,
        bits: int | None,
        unsigned: bool,
    ) -> bool | None:
        typed_unsigned = operation.startswith("u") or unsigned
        if bits is not None and 0 < bits <= 128:
            mask = (1 << bits) - 1
            left &= mask
            right &= mask
            if not typed_unsigned:
                sign = 1 << (bits - 1)
                modulus = 1 << bits
                if left & sign:
                    left -= modulus
                if right & sign:
                    right -= modulus
        elif typed_unsigned:
            return None
        predicates = {
            "eq": operator.eq,
            "ne": operator.ne,
            "slt": operator.lt,
            "ult": operator.lt,
            "sle": operator.le,
            "ule": operator.le,
            "sgt": operator.gt,
            "ugt": operator.gt,
            "sge": operator.ge,
            "uge": operator.ge,
        }
        predicate = predicates.get(operation)
        return None if predicate is None else predicate(left, right)

    @classmethod
    def _output_parameter_ref(
        cls,
        expression: Expr,
        function: FunctionIR,
    ) -> ValueRef | None:
        """Map one exact pointee lvalue to a wrapper parameter and offset."""

        target = expression.unwrapped()
        if (
            target.kind not in {"deref", "member", "index"}
            or target.key not in function.parameters
        ):
            return None
        if target.kind == "index" and (
            len(target.children) < 2
            or cls._literal_integer(target.children[1]) is None
        ):
            return None
        if target.kind == "deref" and target.children:
            address = target.children[0].unwrapped()
            direct = bool(
                address.kind == "var" and address.key == target.key
            )
            pointer = cls._constant_parameter_pointer(address, function)
            if not direct and pointer is None:
                return None
        return ValueRef(
            argument=function.parameters.index(target.key),
            offset=target.offset,
        )

    @classmethod
    def _statement_is_unconditional(
        cls,
        function: FunctionIR,
        statement: Assignment | Call,
    ) -> bool:
        """Prove that a statement executes before every function exit."""

        if statement.guards:
            return False
        if (
            not function.blocks
            or function.entry_block is None
            or statement.block_id not in function.blocks
        ):
            return not any(
                isinstance(item, Return)
                and item.order < statement.order
                and not (
                    isinstance(statement, Call)
                    and cls._call_is_unique_return_value(
                        function, item, statement
                    )
                )
                for item in function.statements
            )
        blocks = set(function.blocks)
        dominators = {block_id: set(blocks) for block_id in blocks}
        dominators[function.entry_block] = {function.entry_block}
        changed = True
        while changed:
            changed = False
            for block_id, block in function.blocks.items():
                if block_id == function.entry_block:
                    continue
                predecessors = [
                    dominators[predecessor]
                    for predecessor in block.predecessors
                    if predecessor in dominators
                ]
                incoming = (
                    set.intersection(*predecessors)
                    if predecessors
                    else set()
                )
                updated = {block_id} | incoming
                if updated != dominators[block_id]:
                    dominators[block_id] = updated
                    changed = True
        exits = [
            block_id
            for block_id, block in function.blocks.items()
            if not block.successors
        ]
        if not exits or any(
            statement.block_id not in dominators[block_id]
            for block_id in exits
        ):
            return False
        return not any(
            isinstance(item, Return)
            and item.block_id == statement.block_id
            and item.order < statement.order
            and not (
                isinstance(statement, Call)
                and cls._call_is_unique_return_value(
                    function, item, statement
                )
            )
            for item in function.statements
        )

    @classmethod
    def _call_is_unique_return_value(
        cls,
        function: FunctionIR,
        returned: Return,
        call: Call,
    ) -> bool:
        if not cls._call_expression_matches(returned.value, call):
            return False
        return sum(
            isinstance(statement, Call)
            and cls._call_expression_matches(returned.value, statement)
            for statement in function.statements
        ) == 1

    def _return_integer_range(
        self,
        function: FunctionIR,
        summaries: SummaryIndex,
    ) -> tuple[int | None, ValueRef | None]:
        """Preserve a -1 input error and successful upper bound through wrappers."""

        returns = [
            statement.value
            for statement in function.statements
            if isinstance(statement, Return)
        ]
        if not returns:
            return None, None
        effects = [
            self._integer_return_effect(value, function, summaries)
            for value in returns
        ]
        if any(effect is None for effect in effects):
            return None, None
        resolved = [effect for effect in effects if effect is not None]
        sentinels = {sentinel for sentinel, _ in resolved}
        if len(sentinels) != 1:
            return None, None
        uppers = [upper for _, upper in resolved]
        upper = (
            uppers[0]
            if (
                uppers
                and uppers[0] is not None
                and all(item == uppers[0] for item in uppers)
            )
            else None
        )
        return next(iter(sentinels)), upper

    def _integer_return_effect(
        self,
        expression: Expr,
        function: FunctionIR,
        summaries: SummaryIndex,
        seen: frozenset[str] = frozenset(),
    ) -> tuple[int, ValueRef | None] | None:
        original = expression
        if original.kind == "cast":
            if original.signed is not True or not original.children:
                return None
            return self._integer_return_effect(
                original.children[0], function, summaries, seen
            )
        value = expression.unwrapped()
        if value.kind == "call":
            name = normalize_symbol(value.callee or "")
            if name in ERROR_SENTINEL_RETURNS:
                indexes = SUCCESS_RETURN_LENGTH_SPECS.get(name)
                upper = None
                if indexes is not None:
                    refs = [
                        self._expr_ref(value.children[index], function)
                        for index in indexes
                        if index < len(value.children)
                    ]
                    if len(refs) == len(indexes) and len(refs) == 1:
                        upper = refs[0]
                elif name in {"getchar", "getc", "fgetc"}:
                    upper = ValueRef(constant=255, text="255", bits=32, signed=True)
                return -1, upper
            nested = summaries.lookup(value.callee or "", value.callee_ea)
            if nested is None or nested.return_error_sentinel is None:
                return None
            upper = (
                self._compose_expr_ref(
                    nested.return_success_upper,
                    value.children,
                    function,
                )
                if nested.return_success_upper is not None
                else None
            )
            return nested.return_error_sentinel, upper
        if value.kind not in {"var", "global"} or value.key is None:
            return None
        if value.key in seen:
            return None
        assignments = [
            statement
            for statement in function.statements
            if isinstance(statement, Assignment)
            and statement.target.kind in {"var", "global"}
            and statement.target.key == value.key
            and statement.target.offset == 0
        ]
        if len(assignments) != 1:
            return None
        return self._integer_return_effect(
            assignments[0].value,
            function,
            summaries,
            seen | {value.key},
        )

    @staticmethod
    def _cstring_bound_for_expr(
        expression: Expr,
        summaries: SummaryIndex,
        local_bounds: dict[str, int],
    ) -> int | None:
        value = expression.unwrapped()
        if value.kind == "string" and value.string is not None:
            return len(value.string.encode("utf-8"))
        if value.kind == "var" and value.key is not None:
            return local_bounds.get(value.key)
        if value.kind == "call":
            summary = summaries.lookup(value.callee or "", value.callee_ea)
            if summary is not None:
                return summary.return_cstring_max
        return None

    def _expr_ref(self, expression: Expr, function: FunctionIR) -> ValueRef | None:
        original = expression
        if original.kind == "cast" and original.is_pointer is False:
            scalar_cast = self._parameter_scalar_expression(original, function)
            if scalar_cast is not None:
                return scalar_cast
        value = expression.unwrapped()
        if value.kind == "const" and value.value is not None:
            return ValueRef(
                constant=value.value,
                text=value.text,
                bits=value.bits,
                signed=value.signed,
            )
        if value.kind == "string" and value.string is not None:
            return ValueRef(
                cstring_max=len(value.string.encode("utf-8")),
                text=value.text,
            )
        if value.kind == "var" and value.key in function.parameters:
            return ValueRef(argument=function.parameters.index(value.key))
        pointer = self._constant_parameter_pointer(value, function)
        if pointer is not None:
            argument, offset = pointer
            return ValueRef(argument=argument, offset=offset)
        scalar = self._parameter_scalar_expression(original, function)
        if scalar is not None:
            return scalar
        return None

    @classmethod
    def _parameter_scalar_expression(
        cls,
        expression: Expr,
        function: FunctionIR,
        depth: int = 0,
    ) -> ValueRef | None:
        """Build a small, typed scalar template over wrapper parameters.

        Only affine integer forms are exported: casts, addition/subtraction,
        multiplication by a literal, and shifting by a literal. This covers
        common allocation/length wrappers without exporting arbitrary callee
        computations as caller-side pseudocode.
        """

        if depth > 8:
            return None
        value = expression
        if value.kind == "cast" and len(value.children) == 1:
            if value.is_pointer is not False:
                return None
            child = cls._parameter_scalar_expression(
                value.children[0], function, depth + 1
            )
            if child is None:
                return None
            return ValueRef(
                scalar_op="cast",
                operands=(child,),
                bits=value.bits,
                signed=value.signed,
                text=value.text,
            )
        value = value.unwrapped()
        if (
            value.kind == "var"
            and value.key in function.parameters
            and value.is_pointer is not True
        ):
            return ValueRef(argument=function.parameters.index(value.key))
        if value.kind == "const" and value.value is not None:
            return ValueRef(
                constant=value.value,
                text=value.text,
                bits=value.bits,
                signed=value.signed,
            )
        if value.is_pointer is not False:
            return None
        if (
            value.kind != "op"
            or value.op not in {"add", "sub", "mul", "shl"}
            or len(value.children) != 2
        ):
            return None
        left, right = value.children
        if value.op in {"mul", "shl"} and cls._literal_integer(right) is None:
            if value.op != "mul" or cls._literal_integer(left) is None:
                return None
        operands = tuple(
            ref
            for child in value.children
            if (
                ref := cls._parameter_scalar_expression(
                    child, function, depth + 1
                )
            )
            is not None
        )
        if len(operands) != len(value.children):
            return None
        if not any(cls._value_ref_uses_argument(ref) for ref in operands):
            return None
        return ValueRef(
            scalar_op=value.op,
            operands=operands,
            bits=value.bits,
            signed=value.signed,
            text=value.text,
        )

    @classmethod
    def _value_ref_uses_argument(cls, value: ValueRef) -> bool:
        return value.argument is not None or any(
            cls._value_ref_uses_argument(child) for child in value.operands
        )

    @classmethod
    def _constant_parameter_pointer(
        cls, expression: Expr, function: FunctionIR
    ) -> tuple[int, int] | None:
        """Return a parameter and exact byte offset for address arithmetic.

        Hex-Rays retains the base key even when the other operand is dynamic.
        Requiring a structurally constant displacement prevents ``dst + i``
        from becoming the unsound summary reference ``dst + 0``.
        """

        value = expression.unwrapped()
        if value.kind == "address" and value.children:
            lvalue = value.children[0].unwrapped()
            if lvalue.key not in function.parameters:
                return None
            if lvalue.kind == "index" and (
                len(lvalue.children) < 2
                or cls._literal_integer(lvalue.children[1]) is None
            ):
                return None
            # ``&parameter`` addresses the callee's local parameter slot, not
            # the caller object denoted by the parameter value.  Member,
            # index, and dereference lvalues instead address pointee storage.
            if lvalue.kind not in {"member", "index", "deref"}:
                return None
            return function.parameters.index(lvalue.key), lvalue.offset
        if value.kind != "op" or value.op not in {"add", "sub"}:
            return None
        if value.is_pointer is not True:
            return None
        if value.key not in function.parameters:
            return None
        base_children = [
            child
            for child in value.children
            if value.key in child.dependencies()
        ]
        if len(base_children) != 1:
            return None
        if any(
            cls._literal_integer(child) is None
            for child in value.children
            if child is not base_children[0]
        ):
            return None
        base = base_children[0].unwrapped()
        if base.kind != "var" and cls._constant_parameter_pointer(
            base, function
        ) is None:
            return None
        return function.parameters.index(value.key), value.offset

    @classmethod
    def _literal_integer(cls, expression: Expr) -> int | None:
        value = expression.unwrapped()
        if value.kind == "const" and value.value is not None:
            return value.value
        return None

    def _compose_ref(
        self, value: ValueRef, call: Call, function: FunctionIR
    ) -> ValueRef | None:
        return self._compose_expr_ref(value, call.args, function)

    def _compose_expr_ref(
        self,
        value: ValueRef,
        arguments: tuple[Expr, ...],
        function: FunctionIR,
    ) -> ValueRef | None:
        expression = value.resolve(arguments)
        if expression is None:
            return None
        return self._expr_ref(expression, function)
