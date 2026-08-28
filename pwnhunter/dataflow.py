"""CFG-aware object lifetime dataflow.

The analysis keeps separate may-free and must-free sets. This distinction is
important for menu challenges: a free on only one branch must not be reported
as an unconditional double free after the branches merge.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ir import Assignment, Call, Expr, Finding, FunctionIR, Return, Severity
from .rules import ALLOC_SPECS, FREE_NAMES, REALLOC_NAMES, normalize_symbol
from .summaries import SummaryIndex


@dataclass(slots=True)
class LifetimeState:
    reachable: bool = False
    objects: dict[str, frozenset[str]] = field(default_factory=dict)
    may_freed: frozenset[str] = frozenset()
    must_freed: frozenset[str] = frozenset()

    def copy(self) -> "LifetimeState":
        return LifetimeState(
            reachable=self.reachable,
            objects=dict(self.objects),
            may_freed=self.may_freed,
            must_freed=self.must_freed,
        )


class LifecycleDataflow:
    def __init__(self, summaries: SummaryIndex):
        self.summaries = summaries

    def analyze(self, function: FunctionIR) -> list[Finding]:
        if not function.blocks or function.entry_block is None:
            return []

        statements = self._statements_by_block(function)
        loop_cursor_refreshes = self._loop_cursor_refreshes(function)
        in_states: dict[int, LifetimeState] = {}
        out_states: dict[int, LifetimeState] = {}
        entry_seed = LifetimeState(reachable=True)
        limit = max(8, len(function.blocks) * 16)

        for _ in range(limit):
            changed = False
            for block_id in self._reverse_postorder(function):
                block = function.blocks[block_id]
                incoming = [
                    out_states[pred]
                    for pred in block.predecessors
                    if pred in out_states and out_states[pred].reachable
                ]
                if block_id == function.entry_block:
                    incoming.insert(0, entry_seed)
                merged = self._merge(incoming)
                transferred, _ = self._transfer(
                    function,
                    statements.get(block_id, ()),
                    merged,
                    loop_cursor_refreshes,
                    emit=False,
                )
                if in_states.get(block_id) != merged:
                    in_states[block_id] = merged
                    changed = True
                if out_states.get(block_id) != transferred:
                    out_states[block_id] = transferred
                    changed = True
            if not changed:
                break

        findings: list[Finding] = []
        for block_id in self._reverse_postorder(function):
            incoming = in_states.get(block_id)
            if incoming is None or not incoming.reachable:
                continue
            _, block_findings = self._transfer(
                function,
                statements.get(block_id, ()),
                incoming,
                loop_cursor_refreshes,
                emit=True,
            )
            findings.extend(block_findings)
        return list({finding.fingerprint: finding for finding in findings}.values())

    def _transfer(
        self,
        function: FunctionIR,
        statements: tuple[Assignment | Call | Return, ...],
        incoming: LifetimeState,
        loop_cursor_refreshes: dict[int, frozenset[str]],
        *,
        emit: bool,
    ) -> tuple[LifetimeState, list[Finding]]:
        state = incoming.copy()
        findings: list[Finding] = []
        if not state.reachable:
            return state, findings

        for statement in statements:
            if isinstance(statement, Return):
                self._check_expression_use(
                    function, statement, statement.value, state, findings, emit
                )
                continue

            if isinstance(statement, Assignment):
                for cursor_key in loop_cursor_refreshes.get(
                    statement.order, frozenset()
                ):
                    cursor_tokens = state.objects.get(
                        cursor_key, frozenset({f"external:{cursor_key}"})
                    )
                    # This is the loop header of the canonical
                    # next=current->next; current=cursor; cursor=next;
                    # release(current) traversal.  The backedge carries the
                    # next node, not the node released in the prior
                    # iteration, even though Hex-Rays reuses one lvar.
                    state.may_freed = state.may_freed - cursor_tokens
                    state.must_freed = state.must_freed - cursor_tokens
                self._check_expression_use(
                    function, statement, statement.value, state, findings, emit
                )
                if statement.target.key is None:
                    continue
                target = statement.target.key
                value = statement.value
                if self._is_allocation(value):
                    allocation = value.unwrapped()
                    if (
                        normalize_symbol(allocation.callee or "") in REALLOC_NAMES
                        and allocation.children
                    ):
                        old_tokens = self._tokens_for(allocation.children[0], state)
                        state.may_freed = state.may_freed | old_tokens
                    token = f"alloc@{statement.ea:X}:{target}"
                    state.objects[target] = frozenset({token})
                    state.may_freed = state.may_freed - {token}
                    state.must_freed = state.must_freed - {token}
                elif value.unwrapped().kind in {"deref", "member", "index"}:
                    # Loading a pointer from ``owner->field`` aliases the
                    # field value, not the owner object itself.  Keeping a
                    # distinct location token prevents free(owner->field)
                    # from making a later read of another owner field look
                    # like a use-after-free of owner.
                    state.objects[target] = self._tokens_for(value, state)
                elif value.key:
                    state.objects[target] = self._tokens_for(value, state)
                elif value.kind in {"call", "op", "deref", "member", "index"}:
                    # An overwrite with an independently produced value starts
                    # a new object generation even when the callee is an
                    # unknown/custom allocator.  Reusing ``external:<lvar>``
                    # across such assignments made separate loop iterations
                    # look like double frees, while still allowing an
                    # immediate use after the assignment/free pair to fire.
                    state.objects[target] = frozenset(
                        {f"assign@{statement.ea:X}:{target}"}
                    )
                else:
                    state.objects.pop(target, None)
                continue

            free_arguments, possible_free_arguments = self._free_arguments(statement)
            if free_arguments or possible_free_arguments:
                for argument in free_arguments:
                    tokens = self._tokens_for(argument, state)
                    definite = tokens & state.must_freed
                    possible = tokens & state.may_freed
                    if emit and definite:
                        findings.append(
                            self._finding(
                                function,
                                statement,
                                "LIFE-001",
                                "Double free",
                                Severity.HIGH,
                                "High",
                                f"{argument.text or argument.key} is freed on every incoming path",
                                "CFG must-free state proves a repeated free",
                            )
                        )
                    elif emit and possible:
                        findings.append(
                            self._finding(
                                function,
                                statement,
                                "LIFE-004",
                                "Possible double free",
                                Severity.MEDIUM,
                                "Medium",
                                f"{argument.text or argument.key} may already be freed",
                                "CFG may-free state; feasibility depends on the branch path",
                            )
                        )
                    state.may_freed = state.may_freed | tokens
                    state.must_freed = state.must_freed | tokens
                for argument in possible_free_arguments:
                    tokens = self._tokens_for(argument, state)
                    already_freed = tokens & (state.may_freed | state.must_freed)
                    if (
                        emit
                        and already_freed
                        and normalize_symbol(statement.name) != "munmap"
                    ):
                        findings.append(
                            self._finding(
                                function,
                                statement,
                                "LIFE-004",
                                "Possible double free",
                                Severity.MEDIUM,
                                "Medium",
                                f"{argument.text or argument.key} may already be freed",
                                "callee may release this argument on a feasible branch",
                            )
                        )
                    state.may_freed = state.may_freed | tokens
                continue

            if statement.target is not None:
                self._check_expression_use(
                    function,
                    statement,
                    statement.target,
                    state,
                    findings,
                    emit,
                )
            for argument in statement.args:
                self._check_expression_use(
                    function, statement, argument, state, findings, emit
                )

        return state, findings

    def _check_expression_use(
        self,
        function: FunctionIR,
        statement: Assignment | Call | Return,
        expression: Expr,
        state: LifetimeState,
        findings: list[Finding],
        emit: bool,
    ) -> None:
        if not emit:
            return
        candidates = [
            (
                key,
                state.objects.get(key, frozenset({f"external:{key}"})),
            )
            for key in sorted(
                expression.dependencies()
                if isinstance(statement, Call)
                else self._dereferenced_keys(expression)
            )
        ]
        value = expression.unwrapped()
        if isinstance(statement, Call) and value.kind in {
            "deref",
            "member",
            "index",
        }:
            candidates.append(
                (value.text or "<loaded pointer>", self._tokens_for(value, state))
            )
        seen: set[frozenset[str]] = set()
        for key, tokens in candidates:
            if tokens in seen:
                continue
            seen.add(tokens)
            definite = tokens & state.must_freed
            possible = tokens & state.may_freed
            callee = normalize_symbol(statement.name) if isinstance(statement, Call) else ""
            if definite:
                findings.append(
                    self._finding(
                        function,
                        statement,
                        "LIFE-002",
                        "Use after free",
                        Severity.HIGH,
                        "High",
                        f"freed object {key} reaches {callee or 'an expression'}",
                        "CFG must-free state proves the object is dangling",
                    )
                )
            elif possible:
                findings.append(
                    self._finding(
                        function,
                        statement,
                        "LIFE-005",
                        "Possible use after free",
                        Severity.MEDIUM,
                        "Medium",
                        f"object {key} may be freed before {callee or 'this expression'}",
                        "CFG may-free state; feasibility depends on the branch path",
                    )
                )

    def _free_arguments(self, call: Call) -> tuple[list[Expr], list[Expr]]:
        result: list[Expr] = []
        possible: list[Expr] = []
        name = normalize_symbol(call.name)
        if name in FREE_NAMES and call.args:
            result.append(call.args[0])
        elif name == "munmap" and call.args:
            # Unlike free(), munmap() reports failure and can leave the
            # mapping live.  Model the successful path without claiming a
            # must-free fact across all paths.
            possible.append(call.args[0])
        summary = self.summaries.lookup(call.name, call.callee_ea)
        if summary is not None:
            result.extend(
                argument
                for value in summary.frees
                if (argument := value.resolve(call.args)) is not None
            )
            possible.extend(
                argument
                for value in summary.possible_frees
                if (argument := value.resolve(call.args)) is not None
            )
        definite_keys = {argument.key for argument in result if argument.key}
        possible = [
            argument for argument in possible if argument.key not in definite_keys
        ]
        return result, possible

    def _loop_cursor_refreshes(
        self, function: FunctionIR
    ) -> dict[int, frozenset[str]]:
        """Find linked-list release loops whose cursor advances before free."""

        if not function.blocks:
            return {}
        assignments = [
            item for item in function.statements if isinstance(item, Assignment)
        ]
        calls = [item for item in function.statements if isinstance(item, Call)]
        result: dict[int, set[str]] = {}

        for load in assignments:
            loaded = load.value.unwrapped()
            if (
                load.block_id is None
                or load.target.key is None
                or load.target.kind not in {"var", "global"}
                or loaded.kind not in {"deref", "member", "index"}
                or not self._block_on_cycle(function, load.block_id)
            ):
                continue
            next_key = load.target.key
            for cursor_key in loaded.dependencies():
                snapshots = [
                    item
                    for item in assignments
                    if item.block_id == load.block_id
                    and load.order < item.order
                    and item.target.key not in {None, cursor_key, next_key}
                    and item.target.kind in {"var", "global"}
                    and item.value.unwrapped().key == cursor_key
                ]
                for snapshot in snapshots:
                    current_key = snapshot.target.key
                    if current_key is None:
                        continue
                    advances = [
                        item
                        for item in assignments
                        if item.block_id == load.block_id
                        and item.order > snapshot.order
                        and item.target.key == cursor_key
                        and item.target.kind in {"var", "global"}
                        and item.value.unwrapped().key == next_key
                    ]
                    if not advances:
                        continue
                    advance = min(advances, key=lambda item: item.order)
                    releases = []
                    for call in calls:
                        if call.block_id is None or call.order <= advance.order:
                            continue
                        definite, possible = self._free_arguments(call)
                        if not any(
                            current_key in argument.dependencies()
                            for argument in (*definite, *possible)
                        ):
                            continue
                        if self._block_reaches(
                            function, load.block_id, call.block_id
                        ) and self._block_reaches(
                            function, call.block_id, load.block_id
                        ):
                            releases.append(call)
                    if releases:
                        result.setdefault(load.order, set()).add(cursor_key)
        return {
            order: frozenset(keys) for order, keys in result.items()
        }

    @classmethod
    def _block_on_cycle(cls, function: FunctionIR, block_id: int) -> bool:
        block = function.blocks.get(block_id)
        return bool(
            block
            and any(
                cls._block_reaches(function, successor, block_id)
                for successor in block.successors
            )
        )

    @staticmethod
    def _block_reaches(
        function: FunctionIR, start: int, destination: int
    ) -> bool:
        pending = [start]
        visited: set[int] = set()
        while pending:
            block_id = pending.pop()
            if block_id == destination:
                return True
            if block_id in visited or block_id not in function.blocks:
                continue
            visited.add(block_id)
            pending.extend(function.blocks[block_id].successors)
        return False

    def _is_allocation(self, expression: Expr) -> bool:
        expression = expression.unwrapped()
        if expression.kind != "call":
            return False
        if normalize_symbol(expression.callee or "") in ALLOC_SPECS:
            return True
        summary = self.summaries.lookup(expression.callee or "", expression.callee_ea)
        return bool(summary and summary.allocation)

    @classmethod
    def _tokens_for(cls, expression: Expr, state: LifetimeState) -> frozenset[str]:
        value = expression.unwrapped()
        dependencies = value.dependencies()
        if value.kind in {"deref", "member", "index"}:
            # Address/index operands identify a loaded pointer location, not
            # the containing object.  Preserve the full expression shape for
            # globals too: ``global->child`` and ``global`` are distinct
            # allocations even though both depend on the same global base.
            return frozenset(
                {f"external:location:{cls._expression_identity(value)}"}
            )
        else:
            keys = [value.key] if value.key else sorted(dependencies)
        tokens: set[str] = set()
        for key in keys:
            if key is None:
                continue
            tokens.update(state.objects.get(key, frozenset({f"external:{key}"})))
        return frozenset(tokens)

    @classmethod
    def _expression_identity(cls, expression: Expr) -> str:
        value = expression.unwrapped()
        children = ",".join(cls._expression_identity(child) for child in value.children)
        return (
            f"{value.kind}:{value.key or ''}:{value.offset}:"
            f"{value.op or ''}:{value.value!r}({children})"
        )

    @classmethod
    def _dereferenced_keys(cls, expression: Expr) -> set[str]:
        if expression.kind == "address":
            return set()
        if expression.kind in {"deref", "member", "index"}:
            return expression.dependencies()
        result: set[str] = set()
        for child in expression.children:
            result.update(cls._dereferenced_keys(child))
        return result

    @staticmethod
    def _merge(states: list[LifetimeState]) -> LifetimeState:
        reachable = [state for state in states if state.reachable]
        if not reachable:
            return LifetimeState()
        common_keys = set(reachable[0].objects)
        for state in reachable[1:]:
            common_keys.intersection_update(state.objects)
        objects = {
            key: frozenset().union(*(state.objects[key] for state in reachable))
            for key in common_keys
        }
        may_freed = frozenset().union(*(state.may_freed for state in reachable))
        must_freed = reachable[0].must_freed
        for state in reachable[1:]:
            must_freed = must_freed & state.must_freed
        return LifetimeState(True, objects, may_freed, must_freed)

    @staticmethod
    def _statements_by_block(
        function: FunctionIR,
    ) -> dict[int, tuple[Assignment | Call | Return, ...]]:
        grouped: dict[int, list[Assignment | Call | Return]] = {}
        fallback = function.entry_block
        for statement in function.statements:
            block_id = statement.block_id
            if block_id is None:
                block_id = fallback
            if block_id is None:
                continue
            grouped.setdefault(block_id, []).append(statement)

        def statement_key(statement: Assignment | Call | Return) -> tuple[int, int, int]:
            # Calls execute before their enclosing assignment receives the
            # return value.  This matters for realloc: the input pointer is a
            # valid call argument and only becomes possibly freed after the
            # call has completed.
            priority = 0 if isinstance(statement, Call) else 1
            return statement.ea, priority, statement.order

        return {
            block_id: tuple(sorted(items, key=statement_key))
            for block_id, items in grouped.items()
        }

    @staticmethod
    def _reverse_postorder(function: FunctionIR) -> list[int]:
        entry = function.entry_block
        if entry is None:
            return sorted(function.blocks)
        visited: set[int] = set()
        postorder: list[int] = []

        def visit(block_id: int) -> None:
            if block_id in visited or block_id not in function.blocks:
                return
            visited.add(block_id)
            for successor in function.blocks[block_id].successors:
                visit(successor)
            postorder.append(block_id)

        visit(entry)
        for block_id in function.blocks:
            visit(block_id)
        return list(reversed(postorder))

    @staticmethod
    def _finding(
        function: FunctionIR,
        statement: Assignment | Call | Return,
        rule_id: str,
        category: str,
        severity: Severity,
        confidence: str,
        summary: str,
        evidence: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            ea=statement.ea,
            function_ea=function.ea,
            function_name=function.name,
            callee=(
                normalize_symbol(statement.name) if isinstance(statement, Call) else ""
            ),
            summary=summary,
            evidence=evidence,
        )
