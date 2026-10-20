"""
FEATURE 5 - Automatic Reproduction & Minimization
=================================================
When a case produces a confirmed authorization violation, this module attempts
AST-aware delta debugging: it repeatedly removes scalar selections from the
query, re-executes each candidate against the *same* live target, and keeps a
removal only if the violation still reproduces.

If minimization cannot make further progress the original query is retained and
the failure is reported honestly (``reproducible`` still records whether the
original query re-executed successfully).
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from graphql import FieldNode, OperationDefinitionNode, parse, print_ast

from app.security.recon.executor import LiveExecutor
from app.security.recon.models import GeneratedTest, TestExecution
from app.security.recon.oracle import object_owner

ProbeResult = Dict[str, Any]
Predicate = Callable[[ProbeResult], bool]


def _compact(ast) -> str:
    text = print_ast(ast)
    return re.sub(r"\n\s*\n", "\n", text).strip()


def _walk_candidates(selection_set, coord: Tuple[int, ...], out: List[Tuple[Tuple[int, ...], int]]) -> None:
    if len(getattr(selection_set, "selections", ())) > 1:
        for index, sel in enumerate(selection_set.selections):
            if isinstance(sel, FieldNode) and not sel.selection_set:
                out.append((coord, index))
    for index, sel in enumerate(selection_set.selections):
        if isinstance(sel, FieldNode) and sel.selection_set:
            _walk_candidates(sel.selection_set, coord + (index,), out)


def _enumerate(ast) -> List[Tuple[Tuple[int, ...], int]]:
    out: List[Tuple[Tuple[int, ...], int]] = []
    for defn in ast.definitions:
        if isinstance(defn, OperationDefinitionNode) and defn.selection_set:
            _walk_candidates(defn.selection_set, (), out)
    return out


def _get_set(ast, coord: Tuple[int, ...]):
    current = None
    for defn in ast.definitions:
        if isinstance(defn, OperationDefinitionNode) and defn.selection_set:
            current = defn.selection_set
            break
    for index in coord:
        current = current.selections[index].selection_set
    return current


def _remove(ast, coord: Tuple[int, ...], child_index: int) -> None:
    target = _get_set(ast, coord)
    target.selections = tuple(s for i, s in enumerate(target.selections) if i != child_index)


def _owner_mismatch(probe: ProbeResult, caller_id: Optional[int]) -> bool:
    obj = probe.get("gateway_object")
    if probe.get("gateway_decision") == "ALLOW" and obj is not None:
        owner = object_owner(obj)
        if caller_id is None:
            return True
        return owner is not None and owner != caller_id
    return False


def make_predicate(test: GeneratedTest, execution: TestExecution) -> Predicate:
    """Build the 'still reproduces' predicate appropriate to the observed class."""
    if execution.reason_class == "CONFIRMED_VULNERABILITY":
        if test.is_mutation:
            return lambda r: bool(r.get("state_changed"))
        return lambda r: _owner_mismatch(r, test.caller_id)

    if execution.reason_class == "ORACLE_FALSE_POSITIVE":
        return lambda r: r.get("gateway_decision") == "DENY"

    if execution.insecure_leaked:
        def _fixture(r: ProbeResult) -> bool:
            obj = r.get("fixture_object")
            if r.get("fixture_status") == 200 and obj is not None:
                owner = object_owner(obj)
                return test.caller_id is None or owner is None or owner != test.caller_id
            return False
        return _fixture

    return lambda r: False


class Reproducer:
    def __init__(self, executor: LiveExecutor):
        self.executor = executor

    async def validate(self, test: GeneratedTest) -> bool:
        """Re-execute the original query once and confirm the finding still holds."""
        result = await self.executor.probe(
            test.query,
            test.variables,
            test.caller_id,
            test.caller_role,
            is_mutation=test.is_mutation,
            target_object_id=test.target_object_id,
        )
        if test.is_mutation:
            return bool(result.get("state_changed"))
        if result.get("gateway_decision") == "ALLOW" and result.get("gateway_object") is not None:
            return True
        return result.get("fixture_status") == 200 and result.get("fixture_object") is not None

    async def minimize(
        self,
        test: GeneratedTest,
        predicate: Predicate,
        max_attempts: int = 30,
    ) -> Tuple[Optional[str], int, bool]:
        """
        Returns ``(minimized_query, attempts, improved)``.

        ``improved`` is True only if the AST was actually reduced while still
        reproducing. On failure the caller keeps the original query.
        """
        try:
            current = _compact(parse(test.query))
        except Exception:
            return None, 0, False

        attempts = 0
        progress = True
        while progress and attempts < max_attempts:
            progress = False
            candidates = _enumerate(parse(current))
            for coord, child_index in candidates:
                if attempts >= max_attempts:
                    break
                try:
                    trial_ast = parse(current)
                    _remove(trial_ast, coord, child_index)
                    trial = _compact(trial_ast)
                except Exception:
                    continue
                attempts += 1
                result = await self.executor.probe(
                    trial,
                    test.variables,
                    test.caller_id,
                    test.caller_role,
                    is_mutation=test.is_mutation,
                    target_object_id=test.target_object_id,
                )
                if predicate(result):
                    current = trial
                    progress = True
                    break

        improved = current != _compact(parse(test.query))
        return current, attempts, improved


def validate_reproduction(executor: LiveExecutor, test: GeneratedTest, predicate: Predicate) -> Dict[str, Any]:
    """
    Synchronous-friendly summary contract used by callers/tests describing what
    a reproduction attempt must record (never fabricates a positive result).
    """
    return {
        "test_id": test.test_id,
        "original_query": test.query,
        "caller_id": test.caller_id,
        "target_object_id": test.target_object_id,
        "expected": f"{test.expected_decision} ({test.expected_reason})",
        "has_predicate": predicate is not None,
    }
