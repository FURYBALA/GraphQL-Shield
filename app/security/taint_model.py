"""
GraphQL Taint and Authorization Boundary Modeling Module

Defines formal analysis concepts for:
"Authorization-Aware Context-Sensitive Taint Analysis for Direct and Indirect GraphQL BOLA"

This module establishes typed data structures and semantics for:
1. Taint Sources: Client-controlled GraphQL arguments and variables.
2. Propagation Contexts: Context-sensitive path tracking distinguishing entry points,
   nested hops, collection traversals, and repeated types.
3. Authorization Boundaries: Evidence-based classification of access-control checks
   (VERIFIED_BOUNDARY, UNVERIFIED_BOUNDARY, NO_BOUNDARY_IDENTIFIED).
4. Sensitive Sinks: Protected domain objects, relationship collections, and attributes.
5. Analysis Findings: Candidate direct/indirect BOLA paths with explicit uncertainties,
   avoiding premature or unevidenced vulnerability claims.

Design principles:
- Structural foundation: Built directly upon the Security Graph G = (V, E).
- Strict evidence requirement: Never labels a check "verified" without concrete proof of
  principal binding, target binding, and mandatory path coverage.
- Context-sensitivity: Path tracking differentiates the same field reached via different routes.
- Fail-closed / cautious classification: Distinguishes candidates with uncertainties from confirmed bugs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dc_field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from app.security.security_graph import (
    Cardinality,
    EdgeType,
    FieldNode,
    SecurityGraph,
    TypeKind,
    TypeNode,
)


# =============================================================================
# 1. ENUMERATIONS AND CLASSIFICATIONS
# =============================================================================

class TaintSourceKind(str, Enum):
    """Origin of a client-controlled taint source."""
    FIELD_ARGUMENT = "FIELD_ARGUMENT"  # An inline or query field argument
    VARIABLE = "VARIABLE"              # A GraphQL variable passed in operation envelope


class TaintTag(str, Enum):
    """Semantic tag associated with tainted data."""
    UNTRUSTED_IDENTIFIER = "UNTRUSTED_IDENTIFIER"  # Argument/var naming indicates entity ID (id, owner_id)
    UNTRUSTED_PARAMETER = "UNTRUSTED_PARAMETER"    # General client-supplied query parameter


class BoundaryClassification(str, Enum):
    """
    Evidence-based classification of an authorization boundary.
    Represents analysis status, NOT an absolute runtime guarantee.
    """
    VERIFIED_BOUNDARY = "VERIFIED_BOUNDARY"
    # Concrete evidence establishes: principal-bound, target-bound, mandatory enforcement.

    UNVERIFIED_BOUNDARY = "UNVERIFIED_BOUNDARY"
    # Check claimed or suspected (e.g. name hints, parent-only check), but lacks static proof
    # of target binding, mandatory path coverage, or child relationship isolation.

    NO_BOUNDARY_IDENTIFIED = "NO_BOUNDARY_IDENTIFIED"
    # No authorization check or tenancy guard found on this path step.


class BoundaryScope(str, Enum):
    """Scope of entity protection enforced by a boundary."""
    OBJECT_LEVEL = "OBJECT_LEVEL"              # Enforces authorization on specific instance
    RELATIONSHIP_LEVEL = "RELATIONSHIP_LEVEL"  # Enforces authorization on navigation edge/association
    FIELD_LEVEL = "FIELD_LEVEL"                # Restricts access to specific scalar field
    GLOBAL_ROLE = "GLOBAL_ROLE"                # Enforces caller global role (e.g. Admin override)
    UNKNOWN = "UNKNOWN"


class SinkKind(str, Enum):
    """Nature of protected data exposed at a sink."""
    PROTECTED_OBJECT_LOOKUP = "PROTECTED_OBJECT_LOOKUP"  # Direct object retrieval by ID
    RELATIONSHIP_COLLECTION = "RELATIONSHIP_COLLECTION"  # Collection traversal returning owned entities
    NESTED_OBJECT_ACCESS = "NESTED_OBJECT_ACCESS"        # Reading child object through association
    SENSITIVE_ATTRIBUTE = "SENSITIVE_ATTRIBUTE"          # Specific sensitive field (e.g. secret, log)


class SensitivityLevel(str, Enum):
    """Severity classification of the protected sink."""
    HIGH = "HIGH"      # Domain entity or sensitive data (notes, finances, accounts)
    MEDIUM = "MEDIUM"  # Internal metadata or operational metrics
    LOW = "LOW"        # Public or unclassified resources


class CandidateKind(str, Enum):
    """Classification of a path analysis finding."""
    DIRECT_BOLA_CANDIDATE = "DIRECT_BOLA_CANDIDATE"
    # Untrusted client identifier directly reaches protected object without verified boundary.

    INDIRECT_BOLA_CANDIDATE = "INDIRECT_BOLA_CANDIDATE"
    # Untrusted input reaches relationship path traversing to another object without verified boundary.

    VERIFIED_PROTECTED_PATH = "VERIFIED_PROTECTED_PATH"
    # Path reaches protected sink with complete verified authorization boundary evidence.

    SAFE_UNPROTECTED_PATH = "SAFE_UNPROTECTED_PATH"
    # Path reaches public/unrestricted sink (e.g. health check).


# =============================================================================
# 2. CORE ANALYSIS DATA STRUCTURES
# =============================================================================

@dataclass(frozen=True)
class TaintSource:
    """Represents a client-controlled input that may influence object selection."""
    source_id: str                   # Stable ID, e.g. "source:Query.resource.id"
    name: str                        # Argument or variable name (e.g. "id", "resId")
    source_kind: TaintSourceKind     # FIELD_ARGUMENT or VARIABLE
    parent_field_id: str             # "field:Query.resource"
    argument_name: str               # "id"
    raw_type: str                    # "Int!"
    base_type: str                   # "Int"
    taint_tag: TaintTag              # UNTRUSTED_IDENTIFIER or UNTRUSTED_PARAMETER
    is_identifier_candidate: bool    # True if name/type matches entity ID patterns
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "name": self.name,
            "source_kind": self.source_kind.value,
            "parent_field_id": self.parent_field_id,
            "argument_name": self.argument_name,
            "raw_type": self.raw_type,
            "base_type": self.base_type,
            "taint_tag": self.taint_tag.value,
            "is_identifier_candidate": self.is_identifier_candidate,
            "description": self.description,
        }


@dataclass(frozen=True)
class PropagationContext:
    """
    Context-sensitive path tracker.

    Ensures that the same type or field reached through different paths
    (e.g., Query.resource vs Query.user.resources vs Query.user.resource)
    is evaluated in its distinct execution and relationship context.
    """
    operation: str                     # "query", "mutation"
    field_path: str                    # Dotted path: "resource", "user.resources", "user.resource"
    parent_type: str                   # "Query", "UserType"
    field_name: str                    # "resource", "resources"
    target_type: str                   # "ResourceType"
    argument_name: Optional[str]       # "id" if parameterized, else None
    cardinality: Cardinality           # ONE_TO_ONE, ONE_TO_MANY
    step_depth: int                    # 0 for root operation, 1 for hop, etc.
    is_collection: bool = False        # True if list return
    requires_arguments: bool = False   # True if has non-null arguments
    carried_taint_tags: Tuple[str, ...] = dc_field(default_factory=tuple)

    @property
    def context_id(self) -> str:
        return f"ctx:{self.operation}:{self.field_path}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "context_id": self.context_id,
            "operation": self.operation,
            "field_path": self.field_path,
            "parent_type": self.parent_type,
            "field_name": self.field_name,
            "target_type": self.target_type,
            "argument_name": self.argument_name,
            "cardinality": self.cardinality.value,
            "step_depth": self.step_depth,
            "is_collection": self.is_collection,
            "requires_arguments": self.requires_arguments,
            "carried_taint_tags": list(self.carried_taint_tags),
        }


@dataclass(frozen=True)
class BoundaryEvidence:
    """
    Structured evidence supporting an authorization boundary classification.

    A boundary is ONLY verified if static evidence confirms all critical properties:
    - Binds the authenticated principal (principal_bound)
    - Applies specifically to target entity/relationship (target_bound)
    - Mandatory on the path (mandatory_on_path)
    - Covers the requested operation (covers_operation)
    """
    classification: BoundaryClassification
    scope: BoundaryScope
    mechanism: str                    # e.g., "GATEWAY_PRE_EXECUTION_POLICY", "RESOLVER_OWNERSHIP_CHECK"
    principal_bound: bool              # Uses authenticated caller's identity (e.g. user_id)
    target_bound: bool                 # Applies to target entity/relationship
    mandatory_on_path: bool            # Cannot be bypassed on this path
    covers_operation: bool             # Covers query reads
    policy_enforced: Optional[str] = None  # e.g. "OWNER_MATCH", "ADMIN_OVERRIDE"
    uncertainty_reasons: Tuple[str, ...] = dc_field(default_factory=tuple)

    @property
    def is_verified(self) -> bool:
        return (
            self.classification == BoundaryClassification.VERIFIED_BOUNDARY
            and self.principal_bound
            and self.target_bound
            and self.mandatory_on_path
            and self.covers_operation
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification.value,
            "scope": self.scope.value,
            "mechanism": self.mechanism,
            "principal_bound": self.principal_bound,
            "target_bound": self.target_bound,
            "mandatory_on_path": self.mandatory_on_path,
            "covers_operation": self.covers_operation,
            "policy_enforced": self.policy_enforced,
            "is_verified": self.is_verified,
            "uncertainty_reasons": list(self.uncertainty_reasons),
        }


@dataclass(frozen=True)
class SensitiveSink:
    """Represents a protected data node where unauthorized access exposes information."""
    sink_id: str                       # e.g. "sink:ResourceType", "sink:ResourceType.name"
    target_type: str                   # "ResourceType"
    target_field: Optional[str]        # None if whole object, or field name
    sink_kind: SinkKind
    sensitivity_level: SensitivityLevel
    expected_owner_type: Optional[str] # e.g. "UserType" or "User"
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_id": self.sink_id,
            "target_type": self.target_type,
            "target_field": self.target_field,
            "sink_kind": self.sink_kind.value,
            "sensitivity_level": self.sensitivity_level.value,
            "expected_owner_type": self.expected_owner_type,
            "description": self.description,
        }


@dataclass(frozen=True)
class AnalysisFinding:
    """
    Result of evaluating a path from source to sink in a specific propagation context.

    Carefully documents evidence, classification, and unresolved assumptions without
    jumping to conclusions.
    """
    finding_id: str
    candidate_kind: CandidateKind
    taint_source: Optional[TaintSource]
    propagation_context: PropagationContext
    sensitive_sink: SensitiveSink
    boundary_evidence: BoundaryEvidence
    risk_assessment: str               # "HIGH", "MEDIUM", "LOW"
    explanation: str
    assumptions_and_uncertainties: Tuple[str, ...] = dc_field(default_factory=tuple)
    explicit_response_path: Optional[str] = None

    @property
    def schema_path(self) -> str:
        return self.propagation_context.field_path

    @property
    def response_path(self) -> str:
        return self.explicit_response_path or self.propagation_context.field_path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "candidate_kind": self.candidate_kind.value,
            "schema_path": self.schema_path,
            "response_path": self.response_path,
            "taint_source": self.taint_source.to_dict() if self.taint_source else None,
            "propagation_context": self.propagation_context.to_dict(),
            "sensitive_sink": self.sensitive_sink.to_dict(),
            "boundary_evidence": self.boundary_evidence.to_dict(),
            "risk_assessment": self.risk_assessment,
            "explanation": self.explanation,
            "assumptions_and_uncertainties": list(self.assumptions_and_uncertainties),
        }


# =============================================================================
# 3. TAINT ANALYSIS MODEL ENGINE
# =============================================================================

class TaintAnalysisModel:
    """
    Constructs and evaluates Taint Sources, Sensitive Sinks, and Boundary Evidence
    derived from a GraphQL Security Graph G = (V, E).
    """

    def __init__(self, security_graph: SecurityGraph):
        self._graph = security_graph
        self._sources: Dict[str, TaintSource] = {}
        self._sinks: Dict[str, SensitiveSink] = {}
        self._identify_sources()
        self._identify_sinks()

    @property
    def security_graph(self) -> SecurityGraph:
        return self._graph

    @property
    def sources(self) -> Dict[str, TaintSource]:
        """All identified taint sources on the schema."""
        return dict(self._sources)

    @property
    def sinks(self) -> Dict[str, SensitiveSink]:
        """All identified sensitive sinks on the schema."""
        return dict(self._sinks)

    # -------------------------------------------------------------------------
    # Source & Sink Identification
    # -------------------------------------------------------------------------

    def _identify_sources(self) -> None:
        """Discovers taint sources from all field arguments on root and child fields."""
        for field in self._graph.fields.values():
            for arg_name, arg in field.arguments.items():
                source_id = f"source:{field.parent_type}.{field.name}.{arg_name}"
                is_id = arg.is_identifier_candidate
                tag = TaintTag.UNTRUSTED_IDENTIFIER if is_id else TaintTag.UNTRUSTED_PARAMETER

                src = TaintSource(
                    source_id=source_id,
                    name=arg_name,
                    source_kind=TaintSourceKind.FIELD_ARGUMENT,
                    parent_field_id=field.id,
                    argument_name=arg_name,
                    raw_type=arg.raw_type,
                    base_type=arg.base_type,
                    taint_tag=tag,
                    is_identifier_candidate=is_id,
                    description=f"Client argument '{arg_name}' on {field.parent_type}.{field.name}",
                )
                self._sources[source_id] = src

    def _identify_sinks(self) -> None:
        """Discovers sensitive sinks from domain object types and collections."""
        # Non-sensitive / infrastructure types
        exempt_types = {"Query", "Mutation", "Subscription", "HealthCheckType", "String", "Int", "Boolean", "Float", "ID"}

        for type_node in self._graph.types.values():
            if type_node.name in exempt_types:
                continue

            if type_node.kind == TypeKind.OBJECT:
                # 1. Whole-object sink
                sink_id = f"sink:{type_node.name}"
                self._sinks[sink_id] = SensitiveSink(
                    sink_id=sink_id,
                    target_type=type_node.name,
                    target_field=None,
                    sink_kind=SinkKind.PROTECTED_OBJECT_LOOKUP,
                    sensitivity_level=SensitivityLevel.HIGH,
                    expected_owner_type="User" if "user" not in type_node.name.lower() else type_node.name,
                    description=f"Protected domain object {type_node.name}",
                )

                # 2. Collection sinks on fields
                for field_name in type_node.fields:
                    f = self._graph.get_field(type_node.name, field_name)
                    if f and f.is_list and f.base_kind == TypeKind.OBJECT:
                        coll_sink_id = f"sink:{type_node.name}.{field_name}"
                        self._sinks[coll_sink_id] = SensitiveSink(
                            sink_id=coll_sink_id,
                            target_type=f.base_type,
                            target_field=field_name,
                            sink_kind=SinkKind.RELATIONSHIP_COLLECTION,
                            sensitivity_level=SensitivityLevel.HIGH,
                            expected_owner_type=type_node.name,
                            description=f"Collection traversal {type_node.name}.{field_name} returning [{f.base_type}]",
                        )

    # -------------------------------------------------------------------------
    # Context Construction & Path Evaluation
    # -------------------------------------------------------------------------

    def create_context(
        self,
        operation: str,
        field_path: str,
        parent_type: str,
        field_name: str,
        target_type: str,
        argument_name: Optional[str] = None,
        carried_tags: Sequence[str] = (),
    ) -> PropagationContext:
        """Constructs an explicit PropagationContext for a specific path step."""
        f = self._graph.get_field(parent_type, field_name)
        cardinality = Cardinality.ONE_TO_MANY if (f and f.is_list) else Cardinality.ONE_TO_ONE
        is_coll = f.is_list if f else False
        req_args = any(a.is_required for a in f.arguments.values()) if f else False
        depth = len(field_path.split(".")) - 1

        return PropagationContext(
            operation=operation,
            field_path=field_path,
            parent_type=parent_type,
            field_name=field_name,
            target_type=target_type,
            argument_name=argument_name,
            cardinality=cardinality,
            step_depth=depth,
            is_collection=is_coll,
            requires_arguments=req_args,
            carried_taint_tags=tuple(sorted(carried_tags)),
        )

    def evaluate_candidate(
        self,
        context: PropagationContext,
        source: Optional[TaintSource],
        sink: SensitiveSink,
        boundary_evidence: BoundaryEvidence,
        response_path: Optional[str] = None,
    ) -> AnalysisFinding:
        """
        Synthesizes a formal AnalysisFinding from context, source, sink, and boundary evidence.

        Classification logic:
        1. If boundary evidence is verified -> VERIFIED_PROTECTED_PATH (Risk: LOW)
        2. If unverified or missing boundary:
           a. If step_depth == 0 (direct root lookup with untrusted ID) -> DIRECT_BOLA_CANDIDATE (Risk: HIGH)
           b. If step_depth > 0 (nested hop or collection traversal) -> INDIRECT_BOLA_CANDIDATE (Risk: HIGH/MEDIUM)
        """
        finding_id = f"finding:{context.field_path}:{sink.sink_id}"
        uncertainties = list(boundary_evidence.uncertainty_reasons)

        if boundary_evidence.is_verified:
            candidate_kind = CandidateKind.VERIFIED_PROTECTED_PATH
            risk = "LOW"
            explanation = (
                f"Path '{context.field_path}' reaches protected sink '{sink.sink_id}' with verified "
                f"authorization boundary via mechanism '{boundary_evidence.mechanism}' "
                f"(policy: {boundary_evidence.policy_enforced})."
            )
        else:
            if context.step_depth == 0:
                candidate_kind = CandidateKind.DIRECT_BOLA_CANDIDATE
                risk = "HIGH"
                explanation = (
                    f"Direct BOLA Candidate: Client parameter '{source.name if source else 'input'}' "
                    f"directly influences lookup of protected sink '{sink.sink_id}' on path '{context.field_path}', "
                    f"but authorization boundary status is '{boundary_evidence.classification.value}'."
                )
            else:
                candidate_kind = CandidateKind.INDIRECT_BOLA_CANDIDATE
                risk = "HIGH" if context.is_collection or source else "MEDIUM"
                explanation = (
                    f"Indirect BOLA Candidate: Nested path '{context.field_path}' navigates to protected sink "
                    f"'{sink.sink_id}' through relationship step '{context.parent_type}.{context.field_name}'. "
                    f"Boundary status on this step is '{boundary_evidence.classification.value}'."
                )

            # Record non-verified caveats
            if not boundary_evidence.principal_bound:
                uncertainties.append("Boundary does not bind or verify authenticated principal identity.")
            if not boundary_evidence.target_bound:
                uncertainties.append("Boundary does not prove target object or relationship ownership.")
            if not boundary_evidence.mandatory_on_path:
                uncertainties.append("Boundary is not statically proven mandatory on this execution path.")

        return AnalysisFinding(
            finding_id=finding_id,
            candidate_kind=candidate_kind,
            taint_source=source,
            propagation_context=context,
            sensitive_sink=sink,
            boundary_evidence=boundary_evidence,
            risk_assessment=risk,
            explanation=explanation,
            assumptions_and_uncertainties=tuple(sorted(set(uncertainties))),
            explicit_response_path=response_path,
        )

    # -------------------------------------------------------------------------
    # High-Level Evaluation Helpers
    # -------------------------------------------------------------------------

    def analyze_path(
        self,
        path_tuples: Sequence[Tuple[str, str]],
        operation: str = "query",
        boundary_evaluator: Optional[callable] = None,
    ) -> List[AnalysisFinding]:
        """
        Analyzes a sequence of (field_name, target_type) hops from the root.

        Args:
            path_tuples: List of (field_name, target_type) steps, e.g.
                         [('user', 'UserType'), ('resources', 'ResourceType')]
            operation: Operation name, default "query".
            boundary_evaluator: Optional callable(ctx, source, sink) -> BoundaryEvidence.
                                If None, defaults to default static evidence generator.
        """
        findings: List[AnalysisFinding] = []
        if not path_tuples:
            return findings

        current_parent = self._graph.root_operations.get(operation, "Query")
        accumulated_path: List[str] = []
        carried_tags: Set[str] = set()

        for field_name, target_type in path_tuples:
            accumulated_path.append(field_name)
            dotted_path = ".".join(accumulated_path)

            field_node = self._graph.get_field(current_parent, field_name)
            arg_name = "id" if (field_node and field_node.has_id_argument) else None

            # Check taint source on this step
            source: Optional[TaintSource] = None
            if arg_name:
                source_id = f"source:{current_parent}.{field_name}.{arg_name}"
                source = self._sources.get(source_id)
                if source:
                    carried_tags.add(source.taint_tag.value)

            ctx = self.create_context(
                operation=operation,
                field_path=dotted_path,
                parent_type=current_parent,
                field_name=field_name,
                target_type=target_type,
                argument_name=arg_name,
                carried_tags=list(carried_tags),
            )

            # Check if target is a sensitive sink
            sink = self._sinks.get(f"sink:{target_type}")
            if not sink and field_node and field_node.is_list:
                sink = self._sinks.get(f"sink:{current_parent}.{field_name}")

            if sink:
                if boundary_evaluator:
                    evidence = boundary_evaluator(ctx, source, sink)
                else:
                    evidence = self._default_static_evidence(ctx, source, sink)

                finding = self.evaluate_candidate(ctx, source, sink, evidence)
                findings.append(finding)

            current_parent = target_type

        return findings

    def _default_static_evidence(
        self,
        context: PropagationContext,
        source: Optional[TaintSource],
        sink: SensitiveSink,
    ) -> BoundaryEvidence:
        """
        Default conservative static evidence model.

        Reflects known architecture:
        - If the gateway intercepts (field has ID argument or is known protected root),
          boundary is unverified statically unless verified at runtime.
        - Unparameterized collections have NO_BOUNDARY_IDENTIFIED at the field level.
        """
        if context.is_collection and not context.argument_name:
            return BoundaryEvidence(
                classification=BoundaryClassification.NO_BOUNDARY_IDENTIFIED,
                scope=BoundaryScope.RELATIONSHIP_LEVEL,
                mechanism="UNCONSTRAINED_COLLECTION_RESOLVER",
                principal_bound=False,
                target_bound=False,
                mandatory_on_path=False,
                covers_operation=False,
                policy_enforced=None,
                uncertainty_reasons=(
                    "Collection navigation has no field-level identifier argument.",
                    "Resolver-level tenancy filtering unverified statically.",
                    "Parent object authorization does not prove child collection ownership.",
                ),
            )

        if context.argument_name:
            return BoundaryEvidence(
                classification=BoundaryClassification.UNVERIFIED_BOUNDARY,
                scope=BoundaryScope.OBJECT_LEVEL,
                mechanism="CANDIDATE_GATEWAY_INTERCEPTION",
                principal_bound=True,
                target_bound=False,  # Unverified statically until runtime lookup matches
                mandatory_on_path=True,
                covers_operation=True,
                policy_enforced="UNKNOWN_POLICY",
                uncertainty_reasons=(
                    "Runtime database ownership match required to verify boundary.",
                    "Static schema analysis alone cannot verify entity instance ownership.",
                ),
            )

        return BoundaryEvidence(
            classification=BoundaryClassification.NO_BOUNDARY_IDENTIFIED,
            scope=BoundaryScope.UNKNOWN,
            mechanism="NONE",
            principal_bound=False,
            target_bound=False,
            mandatory_on_path=False,
            covers_operation=False,
            policy_enforced=None,
            uncertainty_reasons=("No boundary mechanism detected on path step.",),
        )

    # -------------------------------------------------------------------------
    # Summaries & Serialization
    # -------------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Provides a statistical summary of taint model dimensions."""
        return {
            "total_sources": len(self._sources),
            "identifier_sources": sum(1 for s in self._sources.values() if s.is_identifier_candidate),
            "total_sinks": len(self._sinks),
            "sinks_by_kind": {
                k.value: sum(1 for s in self._sinks.values() if s.sink_kind == k)
                for k in SinkKind
                if any(s.sink_kind == k for s in self._sinks.values())
            },
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary(),
            "sources": {k: v.to_dict() for k, v in sorted(self._sources.items())},
            "sinks": {k: v.to_dict() for k, v in sorted(self._sinks.items())},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
