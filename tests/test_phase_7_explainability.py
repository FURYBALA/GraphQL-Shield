"""
Phase 7 Regression and Unit Tests: Explainability and Authorization-Boundary Analysis

Verifies:
1. AST variable default coercion in taint propagation engine.
2. Explicit client variables overriding AST defaults in taint engine.
3. Preservation of both canonical schema path and aliased response path on AnalysisFinding.
4. Path attribution and relationship identification on nested collection traversals.
5. Structured boundary evidence exposure (principal_bound, target_bound, mandatory, covers_operation).
6. Correlation status distinguishing static candidates from confirmed runtime violations.
7. Behavioral compatibility: audit-only taint analysis preserves gateway authorization decisions.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_access_token
from app.security.security_graph import get_security_graph
from app.security.taint_engine import analyze_query_taint
from app.security.taint_model import (
    BoundaryClassification,
    CandidateKind,
    TaintAnalysisModel,
)
from app.security.taint_correlation import (
    CorrelationStatus,
    correlate_path_decision,
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def alice_token():
    return create_access_token(user_id=101, role="user")


@pytest.fixture(scope="module")
def bob_token():
    return create_access_token(user_id=102, role="user")


# =============================================================================
# 1. VARIABLE DEFAULTS & COERCION IN TAINT ENGINE
# =============================================================================

def test_taint_engine_extracts_ast_variable_default_when_omitted():
    """Taint propagation engine coerces AST default value when variable omitted by client."""
    query = "query GetDoc($docId: Int = 102) { resource(id: $docId) { id name } }"
    report = analyze_query_taint(query, variables={})

    assert report.is_valid_query is True
    assert len(report.propagation_steps) >= 1
    step = report.propagation_steps[0]
    assert step.schema_path == "resource"
    assert step.arguments.get("id") == 102
    assert step.relevant_id_arguments.get("id") == 102
    assert len(report.findings) >= 1
    finding = report.findings[0]
    assert finding.candidate_kind == CandidateKind.DIRECT_BOLA_CANDIDATE
    assert finding.taint_source is not None
    assert finding.taint_source.argument_name == "id"


def test_taint_engine_explicit_variable_overrides_ast_default():
    """Client-provided variable value takes precedence over AST default value."""
    query = "query GetDoc($docId: Int = 102) { resource(id: $docId) { id name } }"
    report = analyze_query_taint(query, variables={"docId": 105})

    assert report.is_valid_query is True
    step = report.propagation_steps[0]
    assert step.arguments.get("id") == 105
    assert step.relevant_id_arguments.get("id") == 105


# =============================================================================
# 2. PATH ATTRIBUTION: SCHEMA PATH VS RESPONSE PATH
# =============================================================================

def test_finding_preserves_both_schema_and_response_paths_under_alias():
    """AnalysisFinding exposes canonical schema path and aliased client response path."""
    query = "query { stolenDoc: resource(id: 102) { secretName: name } }"
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    assert len(report.findings) >= 1
    finding = report.findings[0]
    assert finding.schema_path == "resource"
    assert finding.response_path == "stolenDoc"
    assert finding.candidate_kind == CandidateKind.DIRECT_BOLA_CANDIDATE

    d = finding.to_dict()
    assert d["schema_path"] == "resource"
    assert d["response_path"] == "stolenDoc"


def test_nested_collection_traversal_path_attribution():
    """Indirect traversal identifies both parent root candidate and nested relationship candidate."""
    query = "query { user(id: 102) { resources { id name } } }"
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    assert len(report.findings) == 2

    # Root finding on User
    f_root = next(f for f in report.findings if f.schema_path == "user")
    assert f_root.candidate_kind == CandidateKind.DIRECT_BOLA_CANDIDATE
    assert f_root.sensitive_sink.target_type == "UserType"

    # Nested finding on User.resources collection
    f_nested = next(f for f in report.findings if f.schema_path == "user.resources")
    assert f_nested.candidate_kind == CandidateKind.INDIRECT_BOLA_CANDIDATE
    assert f_nested.sensitive_sink.target_type == "ResourceType"
    assert f_nested.propagation_context.parent_type == "UserType"
    assert f_nested.propagation_context.field_name == "resources"
    assert f_nested.propagation_context.is_collection is True


# =============================================================================
# 3. BOUNDARY EVIDENCE & CORRELATION
# =============================================================================

def test_boundary_evidence_strict_properties_and_uncertainties():
    """Boundary evidence explicitly exposes principal_bound, target_bound, and uncertainty reasons."""
    query = "query { resource(id: 102) { id } }"
    report = analyze_query_taint(query)

    assert len(report.findings) >= 1
    finding = report.findings[0]
    evidence = finding.boundary_evidence

    # Gateway interceptor binds principal but cannot statically verify target object ownership
    assert evidence.is_verified is False
    assert evidence.principal_bound is True
    assert evidence.target_bound is False
    assert evidence.mandatory_on_path is True
    assert len(evidence.uncertainty_reasons) >= 1
    assert any("ownership" in u.lower() for u in evidence.uncertainty_reasons)


def test_correlation_distinguishes_candidate_from_confirmed_violation():
    """Correlation status distinguishes candidate finding from confirmed runtime violation."""
    query = "query { resource(id: 102) { id name } }"
    report = analyze_query_taint(query)

    # Bob's resource (102) requested by Alice (101) -> Denied at runtime
    alice_runtime_denial = {
        "decision": "DENY",
        "reason": "OWNERSHIP_MISMATCH",
        "risk_score": 90,
        "risk_level": "HIGH",
    }
    corr_denied = correlate_path_decision(
        path="resource",
        object_type="Resource",
        object_id=102,
        runtime_result=alice_runtime_denial,
        taint_report=report,
    )
    assert corr_denied.status == CorrelationStatus.TRUE_POSITIVE_BLOCKED
    assert corr_denied.static_candidate_kind == "DIRECT_BOLA_CANDIDATE"
    assert "blocked" in corr_denied.rationale.lower()

    # Bob's resource (102) requested by Bob (102) -> Allowed at runtime
    bob_runtime_allow = {
        "decision": "ALLOW",
        "reason": "OWNER_MATCH",
        "risk_score": 0,
        "risk_level": "LOW",
    }
    corr_allowed = correlate_path_decision(
        path="resource",
        object_type="Resource",
        object_id=102,
        runtime_result=bob_runtime_allow,
        taint_report=report,
    )
    assert corr_allowed.status == CorrelationStatus.RUNTIME_PROTECTED_ALLOWED
    assert corr_allowed.static_candidate_kind == "DIRECT_BOLA_CANDIDATE"
    assert "valid principal access" in corr_allowed.rationale.lower()


# =============================================================================
# 4. BEHAVIORAL COMPATIBILITY (AUDIT-ONLY MODE)
# =============================================================================

def test_behavioral_compatibility_audit_only_preserves_gateway_decisions(client, alice_token, bob_token):
    """Audit-only taint analysis does not alter existing HTTP 200/403/401 gateway responses."""
    # 1. Legitimate request -> HTTP 200
    res_legit = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"query": "query { resource(id: 101) { id name } }"}
    )
    assert res_legit.status_code == 200
    assert "data" in res_legit.json()

    # 2. Unauthorized cross-user request (BOLA) -> HTTP 403
    res_bola = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"query": "query { resource(id: 102) { id name } }"}
    )
    assert res_bola.status_code == 403
    assert "OWNERSHIP_MISMATCH" in str(res_bola.json())

    # 3. Missing authentication -> HTTP 403 (FastAPI HTTPBearer default)
    res_noauth = client.post(
        "/graphql",
        json={"query": "query { resource(id: 101) { id name } }"}
    )
    assert res_noauth.status_code == 403

    # 4. Invalid authentication token -> HTTP 401
    res_invalid = client.post(
        "/graphql",
        headers={"Authorization": "Bearer invalid.token.payload"},
        json={"query": "query { resource(id: 101) { id name } }"}
    )
    assert res_invalid.status_code == 401
