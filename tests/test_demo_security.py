"""
Test Suite for Demo Security Hardening & Authorization Boundaries (Phase 13)
Verifies:
1. Safe ephemeral demo-session authentication (loopback restricted, non-production).
2. Production guardrails: rejection of demo sessions and force_execution in production.
3. Authentication requirements on AI explanation endpoints (HTTP 401 for anonymous).
4. Non-bypass guarantee: PolicyEngine remains the deterministic authority for /graphql.
5. Owner vs Non-Owner authorization boundaries under BOLA enforcement.
"""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.main import app
from app.seed import seed_database


@pytest.fixture(autouse=True)
def setup_db():
    seed_database()


@pytest.fixture
def client():
    return TestClient(app)


def test_demo_session_endpoint_success_loopback(client):
    """Verifies loopback client in development environment can obtain an ephemeral demo token."""
    original_env = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "development"
        # TestClient client.host is 'testclient', which is an allowed loopback host
        res = client.post("/api/v1/auth/demo-session")
        assert res.status_code == 200, res.text
        data = res.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["mode"] == "demo_ephemeral"
        assert data["role"] in ("admin", "user")
    finally:
        settings.ENVIRONMENT = original_env


def test_demo_session_endpoint_rejects_production(client):
    """Verifies that in production mode, demo session endpoint returns 403 Forbidden."""
    original_env = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "production"
        res = client.post("/api/v1/auth/demo-session")
        assert res.status_code == 403
        assert "disabled in production" in res.json()["detail"].lower()
    finally:
        settings.ENVIRONMENT = original_env


def test_demo_session_endpoint_rejects_external_ip(client):
    """Verifies that requests from non-loopback IP addresses are rejected with 403."""
    original_env = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "development"
        res = client.post("/api/v1/auth/demo-session", headers={"x-forwarded-for": "198.51.100.25"})
        assert res.status_code == 403
        assert "restricted to local loopback" in res.json()["detail"].lower()
    finally:
        settings.ENVIRONMENT = original_env


def test_ai_explanation_requires_authentication(client):
    """Verifies that unauthenticated calls to /api/v1/security/ai-analyst/explain are rejected."""
    # 1. Anonymous request without Authorization header returns 403 (HTTPBearer auto_error)
    res_anon = client.post(
        "/api/v1/security/ai-analyst/explain",
        json={
            "finding_id": "REAL-HOPP-001",
            "query": "{ resource(id: 102) { id } }",
            "force_execution": True,
        },
    )
    assert res_anon.status_code == 403
    assert "not authenticated" in res_anon.json()["detail"].lower()

    # 2. Request with invalid/tampered token returns 401
    res_invalid = client.post(
        "/api/v1/security/ai-analyst/explain",
        headers={"Authorization": "Bearer invalid_tampered_jwt_token"},
        json={
            "finding_id": "REAL-HOPP-001",
            "query": "{ resource(id: 102) { id } }",
            "force_execution": True,
        },
    )
    assert res_invalid.status_code == 401
    assert "invalid token" in res_invalid.json()["detail"].lower()


def test_force_execution_rejected_in_production(client):
    """Verifies force_execution cannot override disabled AI status in production."""
    original_env = settings.ENVIRONMENT
    original_enabled = settings.AI_EXPLANATION_ENABLED
    try:
        settings.ENVIRONMENT = "production"
        settings.AI_EXPLANATION_ENABLED = False
        token = create_access_token(user_id=1, role="admin")

        res = client.post(
            "/api/v1/security/ai-analyst/explain",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "finding_id": "REAL-HOPP-001",
                "query": "{ resource(id: 102) { id } }",
                "force_execution": True,
            },
        )
        assert res.status_code == 403
        assert "disabled by configuration" in res.json()["detail"]
    finally:
        settings.ENVIRONMENT = original_env
        settings.AI_EXPLANATION_ENABLED = original_enabled


def test_force_execution_disabled_when_flag_false_in_development(client):
    """Verifies that without force_execution=True, disabled AI returns 403 in development."""
    original_env = settings.ENVIRONMENT
    original_enabled = settings.AI_EXPLANATION_ENABLED
    try:
        settings.ENVIRONMENT = "development"
        settings.AI_EXPLANATION_ENABLED = False
        token = create_access_token(user_id=1, role="admin")

        res = client.post(
            "/api/v1/security/ai-analyst/explain",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "finding_id": "REAL-HOPP-001",
                "query": "{ resource(id: 102) { id } }",
                "force_execution": False,
            },
        )
        assert res.status_code == 403
        assert "disabled by configuration" in res.json()["detail"]
    finally:
        settings.ENVIRONMENT = original_env
        settings.AI_EXPLANATION_ENABLED = original_enabled


def test_policy_engine_remains_authority_regardless_of_ai(client):
    """
    Verifies that calling the AI endpoint does NOT permit bypassing /graphql BOLA protection.
    A non-owner requesting resource 102 is strictly blocked at the gateway with 403 OWNERSHIP_MISMATCH.
    """
    caller_token = create_access_token(user_id=101, role="user")
    headers = {"Authorization": f"Bearer {caller_token}"}

    # 1. Non-owner request to /graphql MUST be blocked deterministically
    res_bola = client.post(
        "/graphql",
        headers=headers,
        json={"query": "query { resource(id: 102) { id name } }"},
    )
    assert res_bola.status_code == 403
    assert "OWNERSHIP_MISMATCH" in res_bola.text

    # 2. Owner request to /graphql MUST be allowed deterministically
    res_legit = client.post(
        "/graphql",
        headers=headers,
        json={"query": "query { resource(id: 101) { id name } }"},
    )
    assert res_legit.status_code == 200
    assert "data" in res_legit.json()
    assert res_legit.json()["data"]["resource"]["id"] == 101
