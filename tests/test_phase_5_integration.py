import os
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.core.security import create_access_token
from app.database import get_db_connection
from app.seed import seed_database
from app.security.audit import get_taint_audit_records, clear_taint_audit_records
from app.security.taint_correlation import sanitize_variables, CorrelationStatus


client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    original_url = settings.DATABASE_URL
    original_mode = getattr(settings, "TAINT_ANALYSIS_MODE", "audit_only")
    settings.DATABASE_URL = "sqlite:///./test_shield_p5.db"
    settings.TAINT_ANALYSIS_MODE = "audit_only"
    clear_taint_audit_records()
    seed_database()
    yield
    settings.TAINT_ANALYSIS_MODE = original_mode
    settings.DATABASE_URL = original_url
    db_file = "test_shield_p5.db"
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except PermissionError:
            pass


def test_01_audit_only_preserves_legitimate_allow():
    """Legitimate owner request returns HTTP 200 with GraphQL data in audit-only mode."""
    token = create_access_token(user_id=101, role="user")
    query = "query { resource(id: 101) { id name } }"
    res = client.post(
        "/graphql",
        json={"query": query},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "data" in data
    assert data["data"]["resource"]["id"] == 101

    # Check taint audit records were created
    records = get_taint_audit_records()
    assert len(records) >= 1
    rec = [r for r in records if r.get("object_id") == 101][-1]
    assert rec["runtime_decision"] == "ALLOW"
    assert rec["correlation_status"] == CorrelationStatus.RUNTIME_PROTECTED_ALLOWED.value
    assert rec["mode"] == "audit_only"


def test_02_audit_only_preserves_direct_bola_deny():
    """Direct BOLA request returns HTTP 403 while recording TRUE_POSITIVE_BLOCKED taint audit."""
    token = create_access_token(user_id=101, role="user")
    query = "query { resource(id: 102) { id name } }"
    res = client.post(
        "/graphql",
        json={"query": query},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert detail["decision"] == "DENY"
    assert detail["reason"] == "OWNERSHIP_MISMATCH"

    records = get_taint_audit_records()
    assert len(records) >= 1
    rec = [r for r in records if r.get("object_id") == 102][-1]
    assert rec["runtime_decision"] == "DENY"
    assert rec["correlation_status"] == CorrelationStatus.TRUE_POSITIVE_BLOCKED.value
    assert rec["finding_category"] == "DIRECT_BOLA_CANDIDATE"


def test_03_audit_only_preserves_nested_bola_deny():
    """Nested collection traversal to victim object returns HTTP 403 with taint audit."""
    token = create_access_token(user_id=101, role="user")
    query = "query { user(id: 102) { resources { id name } } }"
    res = client.post(
        "/graphql",
        json={"query": query},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert detail["decision"] == "DENY"

    records = get_taint_audit_records()
    assert len(records) >= 1
    rec = [r for r in records if r.get("object_id") == 102][-1]
    assert rec["runtime_decision"] == "DENY"
    assert rec["correlation_status"] == CorrelationStatus.TRUE_POSITIVE_BLOCKED.value


def test_04_unauthenticated_request_rejected():
    """Missing or invalid JWT returns 403/401 without executing analyzer or crashing."""
    query = "query { resource(id: 101) { id name } }"
    # Missing auth header -> HTTP 403 (HTTPBearer default)
    res1 = client.post("/graphql", json={"query": query})
    assert res1.status_code == 403

    # Invalid token -> HTTP 401
    res2 = client.post(
        "/graphql",
        json={"query": query},
        headers={"Authorization": "Bearer invalid_garbage_token"},
    )
    assert res2.status_code == 401
    assert "Invalid token" in res2.json()["detail"]


def test_05_mode_switching_disabled():
    """When mode is 'disabled', static analysis is bypassed and no taint audits are stored."""
    settings.TAINT_ANALYSIS_MODE = "disabled"
    clear_taint_audit_records()

    token = create_access_token(user_id=101, role="user")

    # Allowed request
    res_allow = client.post(
        "/graphql",
        json={"query": "query { resource(id: 101) { id name } }"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_allow.status_code == 200

    # Denied request
    res_deny = client.post(
        "/graphql",
        json={"query": "query { resource(id: 102) { id name } }"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_deny.status_code == 403

    # Zero taint audit records logged when disabled
    assert len(get_taint_audit_records()) == 0


def test_06_analyzer_exception_fail_safe():
    """Simulated internal analyzer exception fails safely to normal runtime authorization."""
    token = create_access_token(user_id=101, role="user")

    with patch(
        "app.security.enforcement.analyze_query_taint",
        side_effect=RuntimeError("Simulated AST parser crash"),
    ):
        # Legitimate query still succeeds (200)
        res_allow = client.post(
            "/graphql",
            json={"query": "query { resource(id: 101) { id name } }"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_allow.status_code == 200

        # Attack query is still blocked by runtime gateway (403)
        res_deny = client.post(
            "/graphql",
            json={"query": "query { resource(id: 102) { id name } }"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_deny.status_code == 403


def test_07_malformed_query_fail_safe():
    """Malformed GraphQL query does not cause internal 500 error."""
    token = create_access_token(user_id=101, role="user")
    res = client.post(
        "/graphql",
        json={"query": "query { resource(id: 101 { id }"},
        headers={"Authorization": f"Bearer {token}"},
    )
    # Fast-fails or GraphQL parser returns 200 with syntax error
    assert res.status_code in (200, 400)
    if res.status_code == 200:
        assert "errors" in res.json()


def test_08_secret_sanitization_in_variables():
    """Sensitive keys (passwords, tokens, api keys) are masked with [REDACTED]."""
    raw_vars = {
        "userId": 101,
        "password": "super_secret_password_123",
        "authToken": "bearer_ey1234567890",
        "nested": {
            "api_key": "sk-secret-live-12345",
            "normalField": "public_value",
        },
    }
    sanitized = sanitize_variables(raw_vars)

    assert sanitized["userId"] == 101
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["authToken"] == "[REDACTED]"
    assert sanitized["nested"]["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["normalField"] == "public_value"


def test_09_admin_taint_audit_endpoint():
    """Admin users can retrieve taint audit logs; non-admins receive HTTP 403."""
    # Run a test query to populate taint logs
    token_user = create_access_token(user_id=101, role="user")
    client.post(
        "/graphql",
        json={"query": "query { resource(id: 101) { name } }"},
        headers={"Authorization": f"Bearer {token_user}"},
    )

    # User attempts to view taint logs -> 403
    res_user = client.get(
        "/api/v1/security/taint-audit",
        headers={"Authorization": f"Bearer {token_user}"},
    )
    assert res_user.status_code == 403

    # Admin views taint logs -> 200
    token_admin = create_access_token(user_id=103, role="admin")
    res_admin = client.get(
        "/api/v1/security/taint-audit",
        headers={"Authorization": f"Bearer {token_admin}"},
    )
    assert res_admin.status_code == 200
    data = res_admin.json()
    assert data["mode"] == "audit_only"
    assert isinstance(data["records"], list)
    assert len(data["records"]) >= 1


def test_10_aliased_query_in_audit_mode():
    """Aliased BOLA queries maintain correct response alias mapping and are blocked."""
    token = create_access_token(user_id=101, role="user")
    query = "query { victimRes: resource(id: 102) { name } }"
    res = client.post(
        "/graphql",
        json={"query": query},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
    records = get_taint_audit_records()
    assert any(r.get("object_id") == 102 and r.get("correlation_status") == "TRUE_POSITIVE_BLOCKED" for r in records)


def test_11_fragment_query_in_audit_mode():
    """Fragment-driven queries are analyzed context-sensitively in audit mode."""
    token = create_access_token(user_id=101, role="user")
    query = """
    query {
        resource(id: 102) {
            ...ResInfo
        }
    }
    fragment ResInfo on ResourceType {
        id
        name
    }
    """
    res = client.post(
        "/graphql",
        json={"query": query},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
    records = get_taint_audit_records()
    assert any(r.get("object_id") == 102 and r.get("correlation_status") == "TRUE_POSITIVE_BLOCKED" for r in records)
