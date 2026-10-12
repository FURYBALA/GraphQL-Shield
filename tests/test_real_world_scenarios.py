"""
Real-World Security Scenarios & Use Cases Test Suite
Validates the GraphQL BOLA Security Gateway against:
1. Hoppscotch-inspired collection IDOR (GHSA-m5pg-r4jp-qq75)
2. Multi-tenant SaaS document isolation
3. Team workspace nested collection traversals with field aliases
4. Project/issue resource authorization layers (Auth vs Object vs Relationship)
5. Audit-only mode behavioral compatibility and false-alarm prevention
"""

import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_access_token
from app.security.scenario_lab import execute_controlled_scenario, get_all_real_world_scenarios
from app.security.taint_engine import analyze_query_taint
from app.security.taint_model import CandidateKind
from app.security.taint_correlation import CorrelationStatus, correlate_path_decision


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def alice_token():
    return create_access_token(user_id=101, role="user")


@pytest.fixture(scope="module")
def bob_token():
    return create_access_token(user_id=102, role="user")


@pytest.fixture(scope="module")
def charlie_admin_token():
    return create_access_token(user_id=103, role="admin")


# =============================================================================
# 1. CASE STUDY A: HOPPSCOTCH COLLECTION IDOR (GHSA-m5pg-r4jp-qq75 PATTERN)
# =============================================================================

def test_hoppscotch_idor_direct_collection_denied(client, alice_token):
    """
    Hoppscotch Case Study: Alice attempts to access Bob's private collection by ID.
    The gateway must deny unauthorized access pre-execution with HTTP 403.
    """
    query = "query GetCollection($id: Int!) { resource(id: $id) { id name objectType } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"query": query, "variables": {"id": 102}},
    )
    assert response.status_code == 403
    data = response.json()
    assert "detail" in data
    assert data["detail"]["decision"] == "DENY"
    assert data["detail"]["reason"] == "OWNERSHIP_MISMATCH"
    assert data["detail"]["user_id"] == 101
    assert data["detail"]["object_id"] == 102
    assert data["detail"]["risk_level"] == "HIGH"


def test_hoppscotch_idor_legitimate_owner_allowed(client, bob_token):
    """
    Hoppscotch Case Study: Bob accesses his own collection by ID.
    The gateway must permit access with HTTP 200 and return data.
    """
    query = "query GetCollection($id: Int!) { resource(id: $id) { id name } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"query": query, "variables": {"id": 102}},
    )
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert data["data"]["resource"]["id"] == 102
    assert data["data"]["resource"]["name"] == "Bob's Financial Record"


def test_hoppscotch_idor_admin_override_allowed(client, charlie_admin_token):
    """
    Hoppscotch Case Study: Admin Charlie accesses Bob's collection under ADMIN_OVERRIDE.
    """
    query = "query { resource(id: 102) { id name } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {charlie_admin_token}"},
        json={"query": query},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["resource"]["id"] == 102


# =============================================================================
# 2. USE CASE 2: TEAM WORKSPACE NESTED COLLECTIONS & ALIASES
# =============================================================================

def test_team_workspace_nested_collection_traversal_denied(client, alice_token):
    """
    Alice traverses from Bob's user node into his resources collection using client aliases.
    Must be blocked pre-execution with HTTP 403.
    """
    query = "query { targetUser: user(id: 102) { userDocs: resources { id name } } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"query": query},
    )
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["decision"] == "DENY"
    assert data["detail"]["reason"] == "OWNERSHIP_MISMATCH"


def test_nested_parameterized_lookup_under_own_node_denied(client, alice_token):
    """
    Alice queries her own user node (101) but requests Bob's resource (102) in nested field.
    Must be detected and blocked with NESTED_AUTHORIZATION_VIOLATION.
    """
    query = "query { user(id: 101) { resource(id: 102) { id name } } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"query": query},
    )
    assert response.status_code == 403
    data = response.json()
    assert data["detail"]["decision"] == "DENY"
    assert data["detail"]["reason"] == "NESTED_AUTHORIZATION_VIOLATION"


def test_alias_path_attribution_schema_vs_response_path():
    """
    Verifies that taint analysis distinguishes canonical schema path from client response path.
    """
    query = "query { stolenCollection: resource(id: 102) { docName: name } }"
    report = analyze_query_taint(query)
    assert report.is_valid_query is True
    assert len(report.findings) >= 1
    f = report.findings[0]
    assert f.schema_path == "resource"
    assert f.response_path == "stolenCollection"
    assert f.candidate_kind == CandidateKind.DIRECT_BOLA_CANDIDATE


# =============================================================================
# 3. USE CASE 1: MULTI-TENANT SAAS DOCUMENT MANAGEMENT
# =============================================================================

def test_saas_multi_tenant_cross_tenant_document_denied(client, alice_token):
    """Alice attempts cross-tenant document access; verified blocked."""
    query = "query { resource(id: 102) { id name } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"query": query},
    )
    assert response.status_code == 403


def test_saas_multi_tenant_variable_default_coercion_denied(client, alice_token):
    """Alice omits variables and relies on AST default target: Int = 102 to reach Bob's doc."""
    query = "query GetDoc($target: Int = 102) { resource(id: $target) { id name } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"query": query},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["object_id"] == 102


def test_saas_multi_tenant_legitimate_document_access(client, alice_token):
    """Alice accesses her own document (101); verified HTTP 200."""
    query = "query { resource(id: 101) { id name } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"query": query},
    )
    assert response.status_code == 200
    assert response.json()["data"]["resource"]["id"] == 101


# =============================================================================
# 4. USE CASE 3: AUTHENTICATION VS OBJECT VS RELATIONSHIP AUTHORIZATION
# =============================================================================

def test_unauthenticated_request_rejected_by_auth_boundary(client):
    """Missing Authorization header must be rejected by HTTPBearer auth boundary."""
    query = "query { resource(id: 102) { id name } }"
    response = client.post("/graphql", json={"query": query})
    assert response.status_code == 403  # FastAPI HTTPBearer returns 403 when header missing


def test_invalid_token_rejected_by_auth_boundary(client):
    """Malformed or invalid JWT token must be rejected with HTTP 401."""
    query = "query { resource(id: 102) { id name } }"
    response = client.post(
        "/graphql",
        headers={"Authorization": "Bearer invalid.jwt.signature"},
        json={"query": query},
    )
    assert response.status_code == 401


# =============================================================================
# 5. AUDIT-ONLY BEHAVIORAL COMPATIBILITY & FALSE-ALARM PREVENTION
# =============================================================================

def test_false_alarm_prevention_on_legitimate_tainted_input():
    """
    Verifies that static taint candidate on legitimate access is resolved by correlation
    to RUNTIME_PROTECTED_ALLOWED rather than causing an unauthorized block.
    """
    query = "query { resource(id: 101) { id name } }"
    report = analyze_query_taint(query)
    assert len(report.findings) >= 1

    runtime_allow = {
        "decision": "ALLOW",
        "reason": "OWNER_MATCH",
        "risk_score": 10,
        "risk_level": "LOW",
    }
    corr = correlate_path_decision(
        path="resource",
        object_type="Resource",
        object_id=101,
        runtime_result=runtime_allow,
        taint_report=report,
    )
    assert corr.status == CorrelationStatus.RUNTIME_PROTECTED_ALLOWED
    assert "valid principal access" in corr.rationale.lower()


def test_scenario_lab_module_execution():
    """Verifies that all 4 controlled scenarios execute cleanly via get_all_real_world_scenarios."""
    scenarios = get_all_real_world_scenarios()
    assert len(scenarios) == 4
    for s in scenarios:
        assert "scenario_id" in s
        assert "name" in s
        assert "gateway_enforcement" in s
        assert "path_attribution" in s
        assert "boundary_evidence" in s
        assert "correlation" in s
        # Ensure actual execution occurred
        assert s["gateway_enforcement"]["http_status_code"] in (200, 403)
        assert s["gateway_enforcement"]["decision"] in ("ALLOW", "DENY")
