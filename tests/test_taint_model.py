"""
Tests for GraphQL Taint and Authorization Boundary Modeling (Phase 3)

Verifies:
1. Taint source identification from field arguments and candidates.
2. Sensitive sink identification (object lookups and collections).
3. Context-sensitive propagation contexts across paths.
4. Direct BOLA candidate classification on unverified root lookups.
5. Indirect BOLA candidate classification on unconstrained relationship traversals.
6. Negative case: Verified authorization boundary produces VERIFIED_PROTECTED_PATH (not vulnerable).
7. Non-inheritance rule: Parent object authorization does not automatically authorize child collections.
8. Boundary evidence classification states (VERIFIED, UNVERIFIED, NO_BOUNDARY).
9. Context differentiation on cyclic paths (User -> Post -> User).
10. Uncertainty and assumption tracking on all findings.
11. Deterministic JSON serialization of taint models.
"""

from typing import List
import pytest
import strawberry

from app.graphql.schema import schema as active_schema
from app.security.security_graph import Cardinality, SecurityGraph
from app.security.taint_model import (
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


# Module-level synthetic types for cyclic testing
@strawberry.type
class CyclicPost:
    id: int
    author: "CyclicUser"

@strawberry.type
class CyclicUser:
    id: int
    posts: List[CyclicPost]

@strawberry.type
class CyclicQuery:
    @strawberry.field
    def user(self, id: int) -> CyclicUser:
        raise NotImplementedError


# =============================================================================
# 1. LIVE SCHEMA SOURCE & SINK IDENTIFICATION TESTS
# =============================================================================

def test_01_source_identification_live_schema():
    """Identifies all client-controlled arguments on the active schema."""
    graph = SecurityGraph.from_schema(active_schema)
    model = TaintAnalysisModel(graph)

    sources = model.sources
    assert len(sources) >= 3

    assert "source:Query.user.id" in sources
    assert "source:Query.resource.id" in sources
    assert "source:UserType.resource.id" in sources

    src = sources["source:Query.resource.id"]
    assert src.name == "id"
    assert src.source_kind == TaintSourceKind.FIELD_ARGUMENT
    assert src.base_type == "Int"
    assert src.taint_tag == TaintTag.UNTRUSTED_IDENTIFIER
    assert src.is_identifier_candidate is True


def test_02_sink_identification_live_schema():
    """Identifies domain object sinks and relationship collection sinks."""
    graph = SecurityGraph.from_schema(active_schema)
    model = TaintAnalysisModel(graph)

    sinks = model.sinks

    # Protected object sinks
    assert "sink:UserType" in sinks
    assert "sink:ResourceType" in sinks
    assert sinks["sink:ResourceType"].sink_kind == SinkKind.PROTECTED_OBJECT_LOOKUP
    assert sinks["sink:ResourceType"].sensitivity_level == SensitivityLevel.HIGH

    # Collection sinks
    assert "sink:UserType.resources" in sinks
    assert sinks["sink:UserType.resources"].sink_kind == SinkKind.RELATIONSHIP_COLLECTION
    assert sinks["sink:UserType.resources"].target_type == "ResourceType"

    # Infrastructure types are excluded from sensitive sinks
    assert "sink:HealthCheckType" not in sinks
    assert "sink:String" not in sinks


# =============================================================================
# 2. CONTEXT-SENSITIVE PROPAGATION TESTS
# =============================================================================

def test_03_propagation_context_construction():
    """Builds distinct propagation contexts differentiating path depth and cardinality."""
    graph = SecurityGraph.from_schema(active_schema)
    model = TaintAnalysisModel(graph)

    # Direct context: resource
    ctx_direct = model.create_context(
        operation="query",
        field_path="resource",
        parent_type="Query",
        field_name="resource",
        target_type="ResourceType",
        argument_name="id",
        carried_tags=["UNTRUSTED_IDENTIFIER"],
    )
    assert ctx_direct.context_id == "ctx:query:resource"
    assert ctx_direct.step_depth == 0
    assert ctx_direct.cardinality == Cardinality.ONE_TO_ONE
    assert ctx_direct.is_collection is False
    assert ctx_direct.carried_taint_tags == ("UNTRUSTED_IDENTIFIER",)

    # Nested collection context: user.resources
    ctx_nested = model.create_context(
        operation="query",
        field_path="user.resources",
        parent_type="UserType",
        field_name="resources",
        target_type="ResourceType",
        argument_name=None,
    )
    assert ctx_nested.context_id == "ctx:query:user.resources"
    assert ctx_nested.step_depth == 1
    assert ctx_nested.cardinality == Cardinality.ONE_TO_MANY
    assert ctx_nested.is_collection is True


# =============================================================================
# 3. CANDIDATE CLASSIFICATION & BOUNDARY EVIDENCE TESTS
# =============================================================================

def test_04_direct_candidate_classification_unverified():
    """Direct root lookup with unverified boundary yields DIRECT_BOLA_CANDIDATE."""
    graph = SecurityGraph.from_schema(active_schema)
    model = TaintAnalysisModel(graph)

    findings = model.analyze_path([("resource", "ResourceType")])
    assert len(findings) == 1
    f = findings[0]

    assert f.candidate_kind == CandidateKind.DIRECT_BOLA_CANDIDATE
    assert f.risk_assessment == "HIGH"
    assert f.propagation_context.field_path == "resource"
    assert f.boundary_evidence.classification == BoundaryClassification.UNVERIFIED_BOUNDARY
    assert f.boundary_evidence.is_verified is False
    assert len(f.assumptions_and_uncertainties) > 0


def test_05_indirect_candidate_classification():
    """Nested collection traversal yields INDIRECT_BOLA_CANDIDATE."""
    graph = SecurityGraph.from_schema(active_schema)
    model = TaintAnalysisModel(graph)

    findings = model.analyze_path([("user", "UserType"), ("resources", "ResourceType")])
    assert len(findings) == 2

    # Step 1: user
    assert findings[0].propagation_context.field_path == "user"
    assert findings[0].candidate_kind == CandidateKind.DIRECT_BOLA_CANDIDATE

    # Step 2: user.resources (indirect)
    step2 = findings[1]
    assert step2.propagation_context.field_path == "user.resources"
    assert step2.candidate_kind == CandidateKind.INDIRECT_BOLA_CANDIDATE
    assert step2.boundary_evidence.classification == BoundaryClassification.NO_BOUNDARY_IDENTIFIED
    assert step2.risk_assessment == "HIGH"  # High risk due to unconstrained collection traversal


def test_06_verified_boundary_negative_case():
    """Negative case: A verified authorization boundary produces VERIFIED_PROTECTED_PATH (not vulnerable)."""
    graph = SecurityGraph.from_schema(active_schema)
    model = TaintAnalysisModel(graph)

    def verified_evaluator(ctx, src, sink):
        return BoundaryEvidence(
            classification=BoundaryClassification.VERIFIED_BOUNDARY,
            scope=BoundaryScope.OBJECT_LEVEL,
            mechanism="GATEWAY_PRE_EXECUTION_POLICY",
            principal_bound=True,
            target_bound=True,
            mandatory_on_path=True,
            covers_operation=True,
            policy_enforced="OWNER_MATCH",
            uncertainty_reasons=(),
        )

    findings = model.analyze_path([("resource", "ResourceType")], boundary_evaluator=verified_evaluator)
    assert len(findings) == 1
    f = findings[0]

    assert f.candidate_kind == CandidateKind.VERIFIED_PROTECTED_PATH
    assert f.risk_assessment == "LOW"
    assert f.boundary_evidence.is_verified is True
    assert "verified authorization boundary" in f.explanation
    assert len(f.assumptions_and_uncertainties) == 0


def test_07_parent_check_does_not_imply_child_authorization():
    """Non-inheritance rule: Verifying parent object does NOT mark child collection as safe."""
    graph = SecurityGraph.from_schema(active_schema)
    model = TaintAnalysisModel(graph)

    def hybrid_evaluator(ctx, src, sink):
        if ctx.field_path == "user":
            # Parent user is verified
            return BoundaryEvidence(
                classification=BoundaryClassification.VERIFIED_BOUNDARY,
                scope=BoundaryScope.OBJECT_LEVEL,
                mechanism="USER_IDENTITY_VERIFICATION",
                principal_bound=True,
                target_bound=True,
                mandatory_on_path=True,
                covers_operation=True,
                policy_enforced="OWNER_MATCH",
            )
        else:
            # Child collection has no verified tenancy guard
            return BoundaryEvidence(
                classification=BoundaryClassification.NO_BOUNDARY_IDENTIFIED,
                scope=BoundaryScope.RELATIONSHIP_LEVEL,
                mechanism="UNVERIFIED_COLLECTION_RESOLVER",
                principal_bound=False,
                target_bound=False,
                mandatory_on_path=False,
                covers_operation=False,
                uncertainty_reasons=("Parent check on User does not statically verify child Resources tenancy.",),
            )

    findings = model.analyze_path([("user", "UserType"), ("resources", "ResourceType")], boundary_evaluator=hybrid_evaluator)
    assert len(findings) == 2

    # Parent is safe
    assert findings[0].candidate_kind == CandidateKind.VERIFIED_PROTECTED_PATH
    assert findings[0].boundary_evidence.is_verified is True

    # Child is STILL flagged as an indirect candidate because parent check does not imply child security
    assert findings[1].candidate_kind == CandidateKind.INDIRECT_BOLA_CANDIDATE
    assert findings[1].boundary_evidence.is_verified is False
    assert "Parent check on User does not statically verify child Resources tenancy." in findings[1].assumptions_and_uncertainties


# =============================================================================
# 4. SYNTHETIC & CYCLIC SCHEMA TESTS
# =============================================================================

def test_08_cyclic_path_context_sensitivity():
    """Cycle User -> Post -> User context distinguishes root User from nested User."""
    synth_schema = strawberry.Schema(query=CyclicQuery)
    graph = SecurityGraph.from_schema(synth_schema)
    model = TaintAnalysisModel(graph)

    # Path: Query.user -> CyclicUser -> CyclicPost -> CyclicUser (cycle back to User)
    findings = model.analyze_path([
        ("user", "CyclicUser"),
        ("posts", "CyclicPost"),
        ("author", "CyclicUser"),
    ])

    assert len(findings) == 3

    # Step 1: Root user
    assert findings[0].propagation_context.field_path == "user"
    assert findings[0].propagation_context.step_depth == 0
    assert findings[0].propagation_context.parent_type == "CyclicQuery"

    # Step 2: posts
    assert findings[1].propagation_context.field_path == "user.posts"
    assert findings[1].propagation_context.step_depth == 1
    assert findings[1].propagation_context.parent_type == "CyclicUser"

    # Step 3: author (cycle back to User type, but distinct context)
    assert findings[2].propagation_context.field_path == "user.posts.author"
    assert findings[2].propagation_context.step_depth == 2
    assert findings[2].propagation_context.parent_type == "CyclicPost"
    assert findings[2].propagation_context.target_type == "CyclicUser"


def test_09_boundary_evidence_strict_verification():
    """BoundaryEvidence.is_verified is False if any required dimension is unconfirmed."""
    # Missing principal_bound
    e1 = BoundaryEvidence(
        classification=BoundaryClassification.VERIFIED_BOUNDARY,
        scope=BoundaryScope.OBJECT_LEVEL,
        mechanism="TEST",
        principal_bound=False,  # Fails!
        target_bound=True,
        mandatory_on_path=True,
        covers_operation=True,
    )
    assert e1.is_verified is False

    # Missing target_bound
    e2 = BoundaryEvidence(
        classification=BoundaryClassification.VERIFIED_BOUNDARY,
        scope=BoundaryScope.OBJECT_LEVEL,
        mechanism="TEST",
        principal_bound=True,
        target_bound=False,  # Fails!
        mandatory_on_path=True,
        covers_operation=True,
    )
    assert e2.is_verified is False

    # Classification is UNVERIFIED
    e3 = BoundaryEvidence(
        classification=BoundaryClassification.UNVERIFIED_BOUNDARY,  # Fails!
        scope=BoundaryScope.OBJECT_LEVEL,
        mechanism="TEST",
        principal_bound=True,
        target_bound=True,
        mandatory_on_path=True,
        covers_operation=True,
    )
    assert e3.is_verified is False


def test_10_deterministic_model_serialization():
    """TaintAnalysisModel serializes to deterministic JSON."""
    graph = SecurityGraph.from_schema(active_schema)
    model1 = TaintAnalysisModel(graph)
    model2 = TaintAnalysisModel(graph)

    json1 = model1.to_json(indent=2)
    json2 = model2.to_json(indent=2)

    assert json1 == json2
    assert hash(json1) == hash(json2)
