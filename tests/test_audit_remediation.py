"""
Automated Remediation Verification Suite
========================================
Tests verifying the 5 critical and high-severity research-validity remediations (examiner-guided):
  1. Live HTTP Gateway Execution (Method B Live Gateway vs. Direct Policy Baseline).
  2. End-to-End Real Mutation Safety Verification (State Before/After, Tamper Prevention, NOT_TESTED for queries).
  3. Metric Disentanglement (Separate Target Object, AST Path, and Binary Detection Metrics).
  4. Explicit Multi-Tenant ABAC Boundary Enforcement (caller_tenant_id vs target_tenant_id).
  5. Statistical Precision (Scientific notation for small McNemar p-values, no 0.000000 truncation).
  6. Research Write Route Hardening (Admin JWT enforcement in production mode).
"""

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.main import app
from app.security.authorization import AuthorizationContext, PolicyEngine
from app.security.research.api import require_research_write_access
from app.security.research.evaluator import (
    calculate_metrics,
    compute_mcnemar_test,
    evaluate_case_method_b,
    evaluate_case_method_b_live_gateway,
    verify_mutation_safety,
)
from app.security.research.models import ConfusionMatrix, TestCaseRecord


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. LIVE HTTP GATEWAY EXECUTION
# =============================================================================

def test_live_http_gateway_execution_blocked_bola():
    """
    Critical 1 Remediation:
    Method B Live Gateway sends actual HTTP requests over /graphql via TestClient,
    returning true HTTP 403 status code, audit decision, and latency.
    """
    test_case = TestCaseRecord(
        id="AUDIT-TEST-01",
        dataset_id="ds_test",
        name="Live Gateway BOLA Test",
        category="DIRECT_BOLA",
        syntax_type="BASIC",
        caller_user_id=102,       # Bob (user)
        caller_role="user",
        caller_tenant_id="tenant_b",
        target_tenant_id="tenant_a",
        query="query { resource(id: 101) { id name } }", # Alice's resource
        variables={"id": 101},
        operation_name=None,
        target_object_id=101,
        target_object_type="Resource",
        true_owner_id=101,
        ground_truth_security="VULNERABLE",
        ground_truth_attack_type="DIRECT_BOLA",
        expected_gateway_decision="DENY",
        split="held_out",
        provenance="audit_test",
    )

    gw_sec, gw_atk, gw_dec, gw_reason, gw_resp, gw_status, gw_lat, gw_conc, gw_conc_reason = (
        evaluate_case_method_b_live_gateway(test_case)
    )

    assert gw_sec == "VULNERABLE"
    assert gw_atk in ("DIRECT_BOLA", "INDIRECT_BOLA")
    assert gw_dec == "DENY"
    assert gw_reason == "TENANT_ISOLATION_VIOLATION"
    assert gw_status == 403
    assert gw_lat > 0.0
    assert gw_conc is True
    assert gw_conc_reason is None


def test_live_http_gateway_execution_authorized_owner():
    """Live Gateway allows legitimate owner access with HTTP 200."""
    test_case = TestCaseRecord(
        id="AUDIT-TEST-02",
        dataset_id="ds_test",
        name="Live Gateway Authorized Test",
        category="OWNERSHIP_EDGE",
        syntax_type="BASIC",
        caller_user_id=101,       # Alice (user)
        caller_role="user",
        caller_tenant_id="tenant-1",
        target_tenant_id="tenant-1",
        query="query { resource(id: 101) { id name } }", # Alice's own resource
        variables={"id": 101},
        operation_name=None,
        target_object_id=101,
        target_object_type="Resource",
        true_owner_id=101,
        ground_truth_security="BENIGN",
        ground_truth_attack_type="NONE",
        expected_gateway_decision="ALLOW",
        split="held_out",
        provenance="audit_test",
    )

    gw_sec, gw_atk, gw_dec, gw_reason, gw_resp, gw_status, gw_lat, gw_conc, gw_conc_reason = (
        evaluate_case_method_b_live_gateway(test_case)
    )

    assert gw_sec == "BENIGN"
    assert gw_atk == "NONE"
    assert gw_dec == "ALLOW"
    assert gw_status == 200
    assert gw_lat > 0.0
    assert gw_conc is True


# =============================================================================
# 2. REAL MUTATION SAFETY VERIFICATION
# =============================================================================

def test_verify_mutation_safety_unauthorized_blocked():
    """
    Critical 2 Remediation:
    verify_mutation_safety executes the actual GraphQL mutation against /graphql,
    compares state before and after, confirms tamper prevention, and preserves state.
    """
    mutation_case = TestCaseRecord(
        id="AUDIT-MUT-01",
        dataset_id="ds_test",
        name="Unauthorized Mutation Test",
        category="MUTATION",
        syntax_type="MUTATION",
        caller_user_id=102,       # Bob
        caller_role="user",
        caller_tenant_id="tenant_b",
        target_tenant_id="tenant_a",
        query='mutation { updateResource(id: 101, name: "Tampered Alice Resource") { id name } }',
        variables={"id": 101, "name": "Tampered Alice Resource"},
        operation_name="updateResource",
        target_object_id=101,
        target_object_type="Resource",
        true_owner_id=101,
        ground_truth_security="VULNERABLE",
        ground_truth_attack_type="DIRECT_BOLA",
        expected_gateway_decision="DENY",
        split="held_out",
        provenance="audit_test",
    )

    result = verify_mutation_safety(mutation_case, eval_decision="DENY")

    assert result["tested"] is True
    assert result["status"] == "TESTED"
    assert result["http_status"] == 403
    assert result["unauthorized_tampering_prevented"] is True
    assert result["state_preserved"] is True
    assert result["before_state"] is not None
    assert result["after_state"] is not None
    assert result["before_state"] == result["after_state"]


def test_verify_mutation_safety_query_case_marked_not_tested():
    """
    Critical 2 Remediation:
    Non-mutation queries must be marked tested=False and status='NOT_TESTED',
    never falsely reported as verified mutation safety checks.
    """
    query_case = TestCaseRecord(
        id="AUDIT-QRY-01",
        dataset_id="ds_test",
        name="Query Case - Not Mutation",
        category="DIRECT_BOLA",
        syntax_type="BASIC",
        caller_user_id=102,
        caller_role="user",
        caller_tenant_id="tenant_b",
        target_tenant_id="tenant_a",
        query="query { resource(id: 101) { id name } }",
        variables={"id": 101},
        operation_name="resource",
        target_object_id=101,
        target_object_type="Resource",
        true_owner_id=101,
        ground_truth_security="VULNERABLE",
        ground_truth_attack_type="DIRECT_BOLA",
        expected_gateway_decision="DENY",
        split="held_out",
        provenance="audit_test",
    )

    result = verify_mutation_safety(query_case, eval_decision="DENY")

    assert result["tested"] is False
    assert result["status"] == "NOT_TESTED"
    assert result["is_mutation"] is False


# =============================================================================
# 3. METRIC DISENTANGLEMENT & ATTRIBUTION REPORTING
# =============================================================================

def test_metric_disentanglement_separate_attribution_fields():
    """
    High 3 Remediation:
    Verify that binary detection metrics (accuracy, precision, recall, f1)
    and attribution metrics (exact_path_attribution_rate, target_object_match_rate,
    mutation_tamper_prevention_rate, evidence_provenance_completeness) are
    independently tracked and reported.
    """
    cm = ConfusionMatrix(tp=40, fp=5, tn=50, fn=5)

    metrics = calculate_metrics(
        cm=cm,
        total_cases=100,
        evaluated_cases=100,
        excluded_cases=0,
        inconclusive_cases=0,
        latency_ms=12.5,
        path_exact_match_rate=0.85,
        path_root_match_rate=0.92,
        target_object_match_rate=0.95,
        evidence_provenance_completeness=0.98,
        mutation_tamper_prevention_rate=1.0,
        total_mutations_tested=10,
        total_mutations_protected=10,
    )

    # Binary detection metrics
    assert metrics.accuracy == pytest.approx(0.90, rel=1e-3)
    assert metrics.precision == pytest.approx(40 / 45, rel=1e-3)
    assert metrics.recall == pytest.approx(40 / 45, rel=1e-3)

    # Disentangled attribution metrics
    assert metrics.path_exact_match_rate == 0.85
    assert metrics.path_root_match_rate == 0.92
    assert metrics.target_object_match_rate == 0.95
    assert metrics.evidence_provenance_completeness == 0.98
    assert metrics.mutation_tamper_prevention_rate == 1.0
    assert metrics.total_mutations_tested == 10
    assert metrics.total_mutations_protected == 10


# =============================================================================
# 4. EXPLICIT MULTI-TENANT ABAC BOUNDARY ENFORCEMENT
# =============================================================================

def test_multi_tenant_abac_cross_tenant_denied():
    """
    High 4 Remediation:
    Multi-tenant isolation checks enforce that requests from tenant_b attempting
    to access tenant_a resources are blocked with TENANT_ISOLATION_VIOLATION (HTTP 403).
    """
    engine = PolicyEngine()

    ctx = AuthorizationContext(
        user_id=102,
        role="user",
        operation="query",
        object_type="Resource",
        object_id=101,
        path="resource",
        owner_id=101,
        metadata={
            "caller_tenant_id": "tenant_b",
            "resource_tenant_id": "tenant_a",
        }
    )

    decision = engine.evaluate(ctx)
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "TENANT_ISOLATION_VIOLATION"
    assert decision["risk_score"] >= 80


def test_multi_tenant_abac_admin_cross_tenant_allowed():
    """Authorized ADMIN can access cross-tenant resources for system maintenance."""
    engine = PolicyEngine()

    ctx = AuthorizationContext(
        user_id=999,
        role="ADMIN",
        operation="query",
        object_type="Resource",
        object_id=101,
        path="resource",
        owner_id=101,
        metadata={
            "caller_tenant_id": "system_admin_tenant",
            "resource_tenant_id": "tenant_a",
        }
    )

    decision = engine.evaluate(ctx)
    assert decision["decision"] == "ALLOW"
    assert decision["reason"] == "SUPERADMIN_CROSS_TENANT_OVERRIDE"


# =============================================================================
# 5. STATISTICAL PRECISION (MCNEMAR SCIENTIFIC NOTATION)
# =============================================================================

def test_mcnemar_statistical_precision_no_zero_truncation():
    """
    High 5 Remediation:
    Small p-values (< 0.0001) must format as scientific notation (e.g., '2.2000e-05'),
    never as truncated '0.000000', preserving both raw float and exact display string.
    """
    # 25 discordant cases where classifier B is correct and classifier A is wrong
    preds_a = [{"case_id": f"c_{i}", "classification_outcome": "FN"} for i in range(25)]
    preds_b = [{"case_id": f"c_{i}", "classification_outcome": "TP"} for i in range(25)]

    test_res = compute_mcnemar_test(preds_a, preds_b)

    raw_p = test_res["p_value"]
    formatted_p = test_res["p_value_formatted"]

    assert raw_p < 0.0001
    assert raw_p > 0.0
    assert formatted_p != "0.000000"
    assert "e-" in formatted_p or formatted_p.startswith("0.0000")
    assert float(formatted_p) == pytest.approx(raw_p, rel=1e-3)


# =============================================================================
# 6. RESEARCH WRITE API PRODUCTION HARDENING
# =============================================================================

def test_research_write_production_hardening_requires_admin_token(monkeypatch):
    """
    Production Hardening Remediation:
    When ENVIRONMENT == 'production', research write endpoints require valid admin token;
    unauthenticated or non-admin requests are strictly rejected.
    """
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    # Mock unauthenticated request
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/research/experiments/run",
        "headers": [],
        "client": ("127.0.0.1", 50000),
    }
    req = Request(scope=scope)

    # 1. Unauthenticated request in production raises 403
    with pytest.raises(HTTPException) as excinfo:
        require_research_write_access(req)
    assert excinfo.value.status_code == 403
    assert "Authentication required" in excinfo.value.detail

    # 2. Regular user token in production raises 403
    user_token = create_access_token(user_id=102, role="user")
    user_scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/research/experiments/run",
        "headers": [(b"authorization", f"Bearer {user_token}".encode())],
        "client": ("127.0.0.1", 50000),
    }
    user_req = Request(scope=user_scope)
    with pytest.raises(HTTPException) as excinfo:
        require_research_write_access(user_req)
    assert excinfo.value.status_code == 403
    assert "Admin role required" in excinfo.value.detail

    # 3. Admin token in production succeeds
    admin_token = create_access_token(user_id=999, role="admin")
    admin_scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/research/experiments/run",
        "headers": [(b"authorization", f"Bearer {admin_token}".encode())],
        "client": ("127.0.0.1", 50000),
    }
    admin_req = Request(scope=admin_scope)
    auth_data = require_research_write_access(admin_req)
    assert auth_data["role"] == "admin"


# =============================================================================
# 7. TENANT IDENTITY INTEGRITY & HEADER DEFENSE TESTS
# =============================================================================

def test_tenant_header_override_rejected(client):
    """
    Tenant A JWT + Tenant B header:
    The gateway MUST reject the untrusted header override with HTTP 403 (TENANT_HEADER_MISMATCH).
    A caller-controlled header cannot allow a user from Tenant A to claim Tenant B.
    """
    token_tenant_a = create_access_token(user_id=101, role="user", tenant_id="tenant-1")

    # Alice (Tenant 1) attempts to pass header asserting she belongs to Tenant 2
    resp = client.post(
        "/graphql",
        json={"query": "query { resource(id: 101) { id name } }"},
        headers={
            "Authorization": f"Bearer {token_tenant_a}",
            "X-Tenant-Id": "tenant-2",
        }
    )

    assert resp.status_code == 403
    data = resp.json()
    detail = data.get("detail", {})
    assert detail.get("error") == "TENANT_HEADER_MISMATCH"
    assert "Untrusted header override rejected" in detail.get("reason", "")


def test_tenant_header_matching_enforced(client):
    """
    Tenant A JWT + Tenant A header:
    The header matches the authenticated token tenant.
    Enforces Tenant A permissions:
      - Alice accessing Alice's resource (101) is ALLOWED (HTTP 200).
      - Alice attempting to access Bob's resource (102, Tenant 2) is DENIED (HTTP 403 TENANT_ISOLATION_VIOLATION).
    """
    token_tenant_a = create_access_token(user_id=101, role="user", tenant_id="tenant-1")

    # 1. Access Alice's own resource in Tenant 1 -> ALLOW
    resp_own = client.post(
        "/graphql",
        json={"query": "query { resource(id: 101) { id name } }"},
        headers={
            "Authorization": f"Bearer {token_tenant_a}",
            "X-Tenant-Id": "tenant-1",
        }
    )
    assert resp_own.status_code == 200
    assert "data" in resp_own.json()

    # 2. Access Bob's resource in Tenant 2 -> DENIED with TENANT_ISOLATION_VIOLATION
    resp_bob = client.post(
        "/graphql",
        json={"query": "query { resource(id: 102) { id name } }"},
        headers={
            "Authorization": f"Bearer {token_tenant_a}",
            "X-Tenant-Id": "tenant-1",
        }
    )
    assert resp_bob.status_code == 403
    detail = resp_bob.json().get("detail", {})
    assert detail.get("reason") == "TENANT_ISOLATION_VIOLATION"


def test_missing_tenant_claim_fallback_and_fail_closed(client):
    """
    Missing tenant claim:
    - Known seed user (101) without tenant claim resolves to documented fallback (tenant-1).
    - Unmapped user (9999) without tenant claim in JWT fails closed:
        - Arbitrary header assertion -> DENIED HTTP 403 (TENANT_UNAUTHORIZED_HEADER).
        - Accessing tenant resource -> DENIED HTTP 403 (TENANT_CONTEXT_MISSING).
    """
    # 1. Documented fallback for user 101 without explicit tenant_id claim
    token_user_101 = create_access_token(user_id=101, role="user")
    resp_101 = client.post(
        "/graphql",
        json={"query": "query { resource(id: 101) { id name } }"},
        headers={"Authorization": f"Bearer {token_user_101}"}
    )
    assert resp_101.status_code == 200

    # 2. Unmapped user 9999 without tenant claim attempting header assertion -> fail closed
    token_unmapped = create_access_token(user_id=9999, role="user")
    resp_unmapped_hdr = client.post(
        "/graphql",
        json={"query": "query { resource(id: 101) { id name } }"},
        headers={
            "Authorization": f"Bearer {token_unmapped}",
            "X-Tenant-Id": "tenant-1",
        }
    )
    assert resp_unmapped_hdr.status_code == 403
    assert resp_unmapped_hdr.json()["detail"]["error"] == "TENANT_UNAUTHORIZED_HEADER"

    # 3. PolicyEngine evaluates missing tenant claim on tenant-scoped resource -> TENANT_CONTEXT_MISSING
    from app.security.authorization import PolicyEngine, AuthorizationContext
    engine = PolicyEngine()
    ctx = AuthorizationContext(
        user_id=9999,
        role="user",
        operation="query",
        object_type="Resource",
        object_id=101,
        path="resource",
        owner_id=101,
        metadata={"resource_tenant_id": "tenant-1"}  # caller has no tenant
    )
    decision = engine.evaluate(ctx)
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "TENANT_CONTEXT_MISSING"


def test_admin_cross_tenant_access_documented_policy_and_audit(client):
    """
    Administrator cross-tenant access:
    Allowed only under the documented admin policy (SUPERADMIN_CROSS_TENANT_OVERRIDE)
    and the decision is persistently recorded in the audit log.
    """
    from app.database import get_db_connection

    admin_token = create_access_token(user_id=103, role="admin", tenant_id="tenant-admin")

    # Admin accesses Alice's resource (Tenant 1)
    resp = client.post(
        "/graphql",
        json={"query": "query { resource(id: 101) { id name } }"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    assert "data" in resp.json()

    # Verify decision is persistently recorded in audit_logs
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, role, decision, reason, object_id
            FROM audit_logs
            WHERE user_id = 103 AND object_id = 101
            ORDER BY id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        assert row is not None
        assert row["user_id"] == 103
        assert row["role"] == "admin"
        assert row["decision"] == "ALLOW"
        assert row["reason"] == "SUPERADMIN_CROSS_TENANT_OVERRIDE"
    finally:
        conn.close()


def test_production_route_guard_live_http_client(monkeypatch, client):
    """
    Verify production route guard over real HTTP requests via TestClient:
    Rejects unauthenticated and non-admin requests, enforcing admin authentication.
    """
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    # 1. Unauthenticated request -> HTTP 403
    res_unauth = client.post(
        "/api/v1/research/experiments/run",
        json={"dataset_id": "ds_benchmark_v1", "include_ablations": False}
    )
    assert res_unauth.status_code == 403
    assert "Authentication required" in res_unauth.json()["detail"]

    # 2. Non-admin user request -> HTTP 403
    user_token = create_access_token(user_id=101, role="user")
    res_user = client.post(
        "/api/v1/research/experiments/run",
        json={"dataset_id": "ds_benchmark_v1", "include_ablations": False},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert res_user.status_code == 403
    assert "Admin role required" in res_user.json()["detail"]

    # 3. Invalid token -> HTTP 401
    res_invalid = client.post(
        "/api/v1/research/experiments/run",
        json={"dataset_id": "ds_benchmark_v1", "include_ablations": False},
        headers={"Authorization": "Bearer invalid_tampered_token"}
    )
    assert res_invalid.status_code == 401


def test_generalization_corpus_v2_live_gateway_held_out_execution():
    """
    Runs the expanded generalization corpus v2 through the genuine live gateway (Method B-Live).
    Verifies that all 60 cases across tuning, held_out, and adversarial splits execute over HTTP,
    evaluating real HTTP 403/200 outcomes and reporting real metrics.
    """
    from app.security.research.evaluator import run_full_experiment

    exp = run_full_experiment("ds_generalization_v2", include_ablations=False)
    assert exp is not None

    m_live = next((m for m in exp["method_runs"] if m["method_id"] == "method_gateway_live"), None)
    assert m_live is not None

    metrics = m_live["metrics"]
    assert metrics["total_cases"] == 60
    assert metrics["evaluated_cases"] >= 56
    assert metrics["accuracy"] is not None and metrics["accuracy"] > 0.85
    assert metrics["mean_latency_ms"] is not None and metrics["mean_latency_ms"] > 0.0

    # Ensure confusion matrix is populated from real HTTP responses
    cm = m_live["confusion_matrix"]
    assert cm["tp"] > 0
    assert cm["tn"] > 0

