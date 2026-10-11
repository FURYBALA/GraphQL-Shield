"""
AST-Driven Context-Sensitive Taint Propagation Engine

Implements query-level taint propagation over incoming GraphQL ASTs using the
Phase 2 Security Graph and Phase 3 Taint Model.

Key Capabilities:
1. Ingests full GraphQL operations (named/anonymous operations, field arguments,
   operation variables, aliases, named fragment spreads, and inline fragments).
2. Traverses the query AST context-sensitively, tracking:
   - schema_path: Schema canonical field path (e.g. "user.resources")
   - response_path: Client response path respecting aliases (e.g. "myUser.myResources")
   - parent and target GraphQL types resolved from the Security Graph
   - client-supplied identifier arguments (literals or resolved variables)
   - taint tags flowing into and out of each step
3. Evaluates boundary evidence for each sensitive sink encountered.
4. Identifies DIRECT_BOLA_CANDIDATE, INDIRECT_BOLA_CANDIDATE, VERIFIED_PROTECTED_PATH,
   and SAFE_UNPROTECTED_PATH with explicit uncertainties and explainable rationale.
5. Cycle-safe and recursion-bounded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dc_field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from graphql import (
    ArgumentNode as GraphQLArgumentNode,
    BooleanValueNode,
    EnumValueNode,
    FieldNode as GraphQLFieldNode,
    FloatValueNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    IntValueNode,
    ListValueNode,
    ObjectValueNode,
    OperationDefinitionNode,
    StringValueNode,
    VariableNode,
)

from app.security.graphql_parser import parse_query
from app.security.security_graph import (
    Cardinality,
    FieldNode,
    SecurityGraph,
    TypeKind,
    TypeNode,
    get_security_graph,
)
from app.security.taint_model import (
    AnalysisFinding,
    BoundaryClassification,
    BoundaryEvidence,
    BoundaryScope,
    CandidateKind,
    PropagationContext,
    SensitiveSink,
    SensitivityLevel,
    SinkKind,
    TaintAnalysisModel,
    TaintSource,
    TaintSourceKind,
    TaintTag,
)


# =============================================================================
# 1. PROPAGATION STEP AND REPORT DATA STRUCTURES
# =============================================================================

@dataclass
class PropagationStep:
    """Represents a single evaluated hop in the GraphQL AST traversal tree."""
    step_index: int
    operation_name: Optional[str]
    operation_type: str                   # "query", "mutation"
    schema_path: str                      # Canonical schema path, e.g. "user.resource"
    response_path: str                    # Client response path with aliases, e.g. "u.myRes"
    field_name: str                       # Schema field name, e.g. "resource"
    response_name: str                    # Alias or field name
    parent_type: str                      # e.g. "UserType"
    target_type: str                      # e.g. "ResourceType"
    target_kind: str                      # "OBJECT", "SCALAR", etc.
    is_collection: bool                   # True if list return
    arguments: Dict[str, Any]             # Resolved argument values
    source_variables: List[str]           # Variables referenced in this step
    relevant_id_arguments: Dict[str, Any] # e.g. {"id": 102}
    taint_source: Optional[TaintSource]   # Source introduced on this step (if any)
    incoming_taint_tags: List[str]
    outgoing_taint_tags: List[str]
    boundary_evidence: BoundaryEvidence
    sensitive_sink: Optional[SensitiveSink]
    finding: Optional[AnalysisFinding]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "operation_name": self.operation_name,
            "operation_type": self.operation_type,
            "schema_path": self.schema_path,
            "response_path": self.response_path,
            "field_name": self.field_name,
            "response_name": self.response_name,
            "parent_type": self.parent_type,
            "target_type": self.target_type,
            "target_kind": self.target_kind,
            "is_collection": self.is_collection,
            "arguments": self.arguments,
            "source_variables": self.source_variables,
            "relevant_id_arguments": self.relevant_id_arguments,
            "taint_source": self.taint_source.to_dict() if self.taint_source else None,
            "incoming_taint_tags": self.incoming_taint_tags,
            "outgoing_taint_tags": self.outgoing_taint_tags,
            "boundary_evidence": self.boundary_evidence.to_dict(),
            "sensitive_sink": self.sensitive_sink.to_dict() if self.sensitive_sink else None,
            "finding": self.finding.to_dict() if self.finding else None,
        }


@dataclass
class QueryAnalysisReport:
    """Comprehensive, deterministic analysis report for a GraphQL operation."""
    query: str
    operation_name: Optional[str]
    operation_type: str
    is_valid_query: bool
    total_fields_analyzed: int
    max_depth_reached: int
    has_cycles: bool
    taint_sources_identified: List[TaintSource]
    propagation_steps: List[PropagationStep]
    findings: List[AnalysisFinding]
    error_message: Optional[str] = None

    @property
    def direct_bola_candidates(self) -> List[AnalysisFinding]:
        return [f for f in self.findings if f.candidate_kind == CandidateKind.DIRECT_BOLA_CANDIDATE]

    @property
    def indirect_bola_candidates(self) -> List[AnalysisFinding]:
        return [f for f in self.findings if f.candidate_kind == CandidateKind.INDIRECT_BOLA_CANDIDATE]

    @property
    def verified_protected_paths(self) -> List[AnalysisFinding]:
        return [f for f in self.findings if f.candidate_kind == CandidateKind.VERIFIED_PROTECTED_PATH]

    @property
    def safe_unprotected_paths(self) -> List[AnalysisFinding]:
        return [f for f in self.findings if f.candidate_kind == CandidateKind.SAFE_UNPROTECTED_PATH]

    def summary(self) -> Dict[str, Any]:
        return {
            "is_valid_query": self.is_valid_query,
            "operation_type": self.operation_type,
            "operation_name": self.operation_name,
            "total_fields_analyzed": self.total_fields_analyzed,
            "max_depth_reached": self.max_depth_reached,
            "has_cycles": self.has_cycles,
            "total_findings": len(self.findings),
            "direct_bola_candidates_count": len(self.direct_bola_candidates),
            "indirect_bola_candidates_count": len(self.indirect_bola_candidates),
            "verified_protected_paths_count": len(self.verified_protected_paths),
            "safe_unprotected_paths_count": len(self.safe_unprotected_paths),
            "taint_sources_count": len(self.taint_sources_identified),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "query": self.query,
            "operation_name": self.operation_name,
            "operation_type": self.operation_type,
            "is_valid_query": self.is_valid_query,
            "error_message": self.error_message,
            "taint_sources_identified": [s.to_dict() for s in self.taint_sources_identified],
            "propagation_steps": [s.to_dict() for s in self.propagation_steps],
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


# =============================================================================
# 2. LITERAL & VALUE UNWRAPPING HELPER
# =============================================================================

def resolve_ast_value(value_node: Any, variables: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
    """
    Extracts a Python value from a GraphQL AST ValueNode.

    Returns:
      (resolved_value, referenced_variable_name_or_None)
    """
    if isinstance(value_node, VariableNode):
        var_name = value_node.name.value
        return variables.get(var_name), var_name
    if isinstance(value_node, IntValueNode):
        try:
            return int(value_node.value), None
        except (ValueError, TypeError):
            return value_node.value, None
    if isinstance(value_node, FloatValueNode):
        try:
            return float(value_node.value), None
        except (ValueError, TypeError):
            return value_node.value, None
    if isinstance(value_node, (StringValueNode, BooleanValueNode, EnumValueNode)):
        return value_node.value, None
    if isinstance(value_node, ListValueNode):
        items = [resolve_ast_value(v, variables)[0] for v in value_node.values]
        return items, None
    if isinstance(value_node, ObjectValueNode):
        obj = {
            f.name.value: resolve_ast_value(f.value, variables)[0]
            for f in value_node.fields
        }
        return obj, None
    return None, None


# =============================================================================
# 3. TAINT PROPAGATION ENGINE
# =============================================================================

class TaintPropagationEngine:
    """
    AST-driven context-sensitive taint propagation engine.

    Integrates:
    - Phase 2 Security Graph for precise schema types and relationships.
    - Phase 3 Taint Analysis Model for sources, sinks, contexts, and boundaries.
    """

    def __init__(
        self,
        security_graph: Optional[SecurityGraph] = None,
        taint_model: Optional[TaintAnalysisModel] = None,
        boundary_evaluator: Optional[Callable[[PropagationContext, Optional[TaintSource], SensitiveSink], BoundaryEvidence]] = None,
        max_traversal_depth: int = 8,
    ):
        self.graph = security_graph or get_security_graph()
        self.taint_model = taint_model or TaintAnalysisModel(self.graph)
        self.boundary_evaluator = boundary_evaluator
        self.max_traversal_depth = max_traversal_depth

    def analyze_document(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None,
    ) -> QueryAnalysisReport:
        """
        Parses and evaluates a GraphQL document, propagating taint through all
        operations, fields, variables, and fragments.
        """
        variables = variables or {}
        ast = parse_query(query)
        if not ast:
            return QueryAnalysisReport(
                query=query,
                operation_name=operation_name,
                operation_type="unknown",
                is_valid_query=False,
                total_fields_analyzed=0,
                max_depth_reached=0,
                has_cycles=False,
                taint_sources_identified=[],
                propagation_steps=[],
                findings=[],
                error_message="GraphQL syntax error: unable to parse document AST",
            )

        # 1. Collect named fragments
        fragments: Dict[str, FragmentDefinitionNode] = {}
        for definition in ast.definitions:
            if isinstance(definition, FragmentDefinitionNode):
                fragments[definition.name.value] = definition

        # 2. Locate target operation
        target_op: Optional[OperationDefinitionNode] = None
        for definition in ast.definitions:
            if isinstance(definition, OperationDefinitionNode):
                if operation_name:
                    if definition.name and definition.name.value == operation_name:
                        target_op = definition
                        break
                else:
                    target_op = definition
                    break

        if not target_op:
            return QueryAnalysisReport(
                query=query,
                operation_name=operation_name,
                operation_type="unknown",
                is_valid_query=False,
                total_fields_analyzed=0,
                max_depth_reached=0,
                has_cycles=False,
                taint_sources_identified=[],
                propagation_steps=[],
                findings=[],
                error_message=f"No executable operation found matching name '{operation_name}'",
            )

        op_name = target_op.name.value if target_op.name else None
        op_type = target_op.operation.value.lower()
        root_type_name = self.graph.root_operations.get(op_type, "Query")

        # 3. Context state accumulator
        steps: List[PropagationStep] = []
        findings: List[AnalysisFinding] = []
        identified_sources: List[TaintSource] = []
        state = {
            "step_counter": 0,
            "max_depth": 0,
            "has_cycles": False,
        }

        # 4. Recursive traversal
        if target_op.selection_set:
            self._traverse_selection_set(
                selection_set=target_op.selection_set,
                parent_type=root_type_name,
                schema_path="",
                response_path="",
                depth=0,
                incoming_taint=set(),
                visited_types_on_branch=set(),
                fragment_stack=set(),
                op_name=op_name,
                op_type=op_type,
                variables=variables,
                fragments=fragments,
                steps=steps,
                findings=findings,
                identified_sources=identified_sources,
                state=state,
            )

        return QueryAnalysisReport(
            query=query,
            operation_name=op_name,
            operation_type=op_type,
            is_valid_query=True,
            total_fields_analyzed=len(steps),
            max_depth_reached=state["max_depth"],
            has_cycles=state["has_cycles"],
            taint_sources_identified=identified_sources,
            propagation_steps=steps,
            findings=findings,
        )

    # -------------------------------------------------------------------------
    # AST Recursive Traversal
    # -------------------------------------------------------------------------

    def _traverse_selection_set(
        self,
        selection_set: Any,
        parent_type: str,
        schema_path: str,
        response_path: str,
        depth: int,
        incoming_taint: Set[str],
        visited_types_on_branch: Set[str],
        fragment_stack: Set[str],
        op_name: Optional[str],
        op_type: str,
        variables: Dict[str, Any],
        fragments: Dict[str, FragmentDefinitionNode],
        steps: List[PropagationStep],
        findings: List[AnalysisFinding],
        identified_sources: List[TaintSource],
        state: Dict[str, Any],
    ) -> None:
        if depth > self.max_traversal_depth:
            state["has_cycles"] = True
            return

        state["max_depth"] = max(state["max_depth"], depth)

        for selection in selection_set.selections:
            if isinstance(selection, GraphQLFieldNode):
                self._visit_field(
                    node=selection,
                    parent_type=parent_type,
                    schema_path=schema_path,
                    response_path=response_path,
                    depth=depth,
                    incoming_taint=incoming_taint,
                    visited_types_on_branch=visited_types_on_branch,
                    fragment_stack=fragment_stack,
                    op_name=op_name,
                    op_type=op_type,
                    variables=variables,
                    fragments=fragments,
                    steps=steps,
                    findings=findings,
                    identified_sources=identified_sources,
                    state=state,
                )
            elif isinstance(selection, FragmentSpreadNode):
                frag_name = selection.name.value
                if frag_name in fragment_stack:
                    # Circular fragment reference detected; safely stop loop
                    continue
                if frag_name in fragments:
                    frag_def = fragments[frag_name]
                    target_frag_type = frag_def.type_condition.name.value if frag_def.type_condition else parent_type
                    self._traverse_selection_set(
                        selection_set=frag_def.selection_set,
                        parent_type=target_frag_type,
                        schema_path=schema_path,
                        response_path=response_path,
                        depth=depth,
                        incoming_taint=incoming_taint,
                        visited_types_on_branch=visited_types_on_branch,
                        fragment_stack=fragment_stack | {frag_name},
                        op_name=op_name,
                        op_type=op_type,
                        variables=variables,
                        fragments=fragments,
                        steps=steps,
                        findings=findings,
                        identified_sources=identified_sources,
                        state=state,
                    )
            elif isinstance(selection, InlineFragmentNode):
                target_frag_type = selection.type_condition.name.value if selection.type_condition else parent_type
                self._traverse_selection_set(
                    selection_set=selection.selection_set,
                    parent_type=target_frag_type,
                    schema_path=schema_path,
                    response_path=response_path,
                    depth=depth,
                    incoming_taint=incoming_taint,
                    visited_types_on_branch=visited_types_on_branch,
                    fragment_stack=fragment_stack,
                    op_name=op_name,
                    op_type=op_type,
                    variables=variables,
                    fragments=fragments,
                    steps=steps,
                    findings=findings,
                    identified_sources=identified_sources,
                    state=state,
                )

    def _visit_field(
        self,
        node: GraphQLFieldNode,
        parent_type: str,
        schema_path: str,
        response_path: str,
        depth: int,
        incoming_taint: Set[str],
        visited_types_on_branch: Set[str],
        fragment_stack: Set[str],
        op_name: Optional[str],
        op_type: str,
        variables: Dict[str, Any],
        fragments: Dict[str, FragmentDefinitionNode],
        steps: List[PropagationStep],
        findings: List[AnalysisFinding],
        identified_sources: List[TaintSource],
        state: Dict[str, Any],
    ) -> None:
        field_name = node.name.value
        response_name = node.alias.value if node.alias else field_name

        curr_schema_path = f"{schema_path}.{field_name}" if schema_path else field_name
        curr_response_path = f"{response_path}.{response_name}" if response_path else response_name

        # Resolve field definition from the Security Graph
        field_def: Optional[FieldNode] = self.graph.get_field(parent_type, field_name)
        target_type_node: Optional[TypeNode] = self.graph.resolve_field_return_type(parent_type, field_name)

        target_type_name = target_type_node.name if target_type_node else (
            field_def.base_type if field_def else "Unknown"
        )
        target_kind = target_type_node.kind.value if target_type_node else "UNKNOWN"
        is_coll = field_def.is_list if field_def else False

        # Parse and resolve arguments
        resolved_args: Dict[str, Any] = {}
        src_variables: List[str] = []
        id_args: Dict[str, Any] = {}
        introduced_source: Optional[TaintSource] = None
        new_taint_tags = set(incoming_taint)

        for arg in node.arguments:
            arg_name = arg.name.value
            val, var_name = resolve_ast_value(arg.value, variables)
            resolved_args[arg_name] = val
            if var_name:
                src_variables.append(var_name)

            # Check if argument is recognized as a taint source
            source_id = f"source:{parent_type}.{field_name}.{arg_name}"
            registered_source = self.taint_model.sources.get(source_id)

            if registered_source and registered_source.is_identifier_candidate:
                introduced_source = registered_source
                id_args[arg_name] = val
                new_taint_tags.add(registered_source.taint_tag.value)
                if registered_source not in identified_sources:
                    identified_sources.append(registered_source)

        # Build Propagation Context
        primary_id_arg = next(iter(id_args.keys()), None)
        ctx = self.taint_model.create_context(
            operation=op_type,
            field_path=curr_schema_path,
            parent_type=parent_type,
            field_name=field_name,
            target_type=target_type_name,
            argument_name=primary_id_arg,
            carried_tags=list(new_taint_tags),
        )

        # Check if target is a sensitive sink
        sink: Optional[SensitiveSink] = self.taint_model.sinks.get(f"sink:{target_type_name}")
        if not sink and is_coll:
            sink = self.taint_model.sinks.get(f"sink:{parent_type}.{field_name}")

        # Evaluate boundary evidence
        finding: Optional[AnalysisFinding] = None
        if sink:
            if self.boundary_evaluator:
                evidence = self.boundary_evaluator(ctx, introduced_source, sink)
            else:
                evidence = self.taint_model._default_static_evidence(ctx, introduced_source, sink)

            finding = self.taint_model.evaluate_candidate(ctx, introduced_source, sink, evidence)
            findings.append(finding)
        else:
            evidence = BoundaryEvidence(
                classification=BoundaryClassification.NO_BOUNDARY_IDENTIFIED,
                scope=BoundaryScope.UNKNOWN,
                mechanism="UNCLASSIFIED_SINK",
                principal_bound=False,
                target_bound=False,
                mandatory_on_path=False,
                covers_operation=False,
                uncertainty_reasons=("Field does not resolve to a protected domain entity sink.",),
            )
            # If at root and unclassified (e.g. health check), record as SAFE_UNPROTECTED_PATH
            if depth == 0 and not introduced_source:
                dummy_sink = SensitiveSink(
                    sink_id=f"sink:public:{target_type_name}",
                    target_type=target_type_name,
                    target_field=field_name,
                    sink_kind=SinkKind.PROTECTED_OBJECT_LOOKUP,
                    sensitivity_level=SensitivityLevel.LOW,
                    expected_owner_type=None,
                )
                safe_finding = AnalysisFinding(
                    finding_id=f"finding:{curr_schema_path}:public",
                    candidate_kind=CandidateKind.SAFE_UNPROTECTED_PATH,
                    taint_source=None,
                    propagation_context=ctx,
                    sensitive_sink=dummy_sink,
                    boundary_evidence=evidence,
                    risk_assessment="LOW",
                    explanation=f"Public or infrastructure field '{curr_schema_path}' does not require BOLA authorization.",
                    assumptions_and_uncertainties=(),
                )
                findings.append(safe_finding)
                finding = safe_finding

        # Record Step
        state["step_counter"] += 1
        step = PropagationStep(
            step_index=state["step_counter"],
            operation_name=op_name,
            operation_type=op_type,
            schema_path=curr_schema_path,
            response_path=curr_response_path,
            field_name=field_name,
            response_name=response_name,
            parent_type=parent_type,
            target_type=target_type_name,
            target_kind=target_kind,
            is_collection=is_coll,
            arguments=resolved_args,
            source_variables=src_variables,
            relevant_id_arguments=id_args,
            taint_source=introduced_source,
            incoming_taint_tags=list(incoming_taint),
            outgoing_taint_tags=list(new_taint_tags),
            boundary_evidence=evidence,
            sensitive_sink=sink,
            finding=finding,
        )
        steps.append(step)

        # Check cyclic type on this branch
        is_cyclic = target_type_name in visited_types_on_branch
        if is_cyclic:
            state["has_cycles"] = True

        # Recurse into selection set if object type has selections
        if node.selection_set and target_type_node and target_type_node.kind in (TypeKind.OBJECT, TypeKind.INTERFACE):
            new_visited = visited_types_on_branch | {target_type_name}
            self._traverse_selection_set(
                selection_set=node.selection_set,
                parent_type=target_type_name,
                schema_path=curr_schema_path,
                response_path=curr_response_path,
                depth=depth + 1,
                incoming_taint=new_taint_tags,
                visited_types_on_branch=new_visited,
                fragment_stack=fragment_stack,
                op_name=op_name,
                op_type=op_type,
                variables=variables,
                fragments=fragments,
                steps=steps,
                findings=findings,
                identified_sources=identified_sources,
                state=state,
            )


# -----------------------------------------------------------------------------
# Convenience Functions & Offline API
# -----------------------------------------------------------------------------

def analyze_query_taint(
    query: str,
    variables: Optional[Dict[str, Any]] = None,
    operation_name: Optional[str] = None,
    boundary_evaluator: Optional[Callable] = None,
) -> QueryAnalysisReport:
    """Convenience entry point analyzing an incoming query string with the default graph."""
    engine = TaintPropagationEngine(boundary_evaluator=boundary_evaluator)
    return engine.analyze_document(query=query, variables=variables, operation_name=operation_name)
