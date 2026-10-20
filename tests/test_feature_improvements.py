"""
Comprehensive Tests for Advanced Feature Improvements
======================================================
Verifies:
1. Interactive Adversarial Fuzzer Studio mutation generator.
2. Automated BOLA Remediation & Policy Code Generator (Strawberry, Shield, OPA).
3. Multi-Tenant Access Matrix Simulator (cross-tenant 2D grid).
4. Real-time Anomaly & Audit Event Stream endpoint.
5. Interactive ROC & Precision-Recall Curve metrics generator.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app, startup_event
from app.security.research.persistence import get_all_experiments
from app.security.research.evaluator import run_full_experiment


@pytest.fixture(scope="module")
def client():
    startup_event()
    return TestClient(app)


@pytest.fixture(scope="module")
def experiment_id():
    startup_event()
    experiments = get_all_experiments()
    if experiments:
        return experiments[0]["id"]
    res = run_full_experiment(
        dataset_id="ds_benchmark_v1",
        name="Experiment for Curves Test",
        include_ablations=True,
    )
    return res.get("id") or res.get("experiment_id")


def test_fuzzer_mutation_endpoint(client):
    """Verify POST /api/v1/research/fuzzer/mutate-query returns all 5 mutation classes."""
    query = "query { resource(id: 101) { id name secret_key } }"
    resp = client.post("/api/v1/research/fuzzer/mutate-query", json={"query": query, "target_id": 101})

    assert resp.status_code == 200
    data = resp.json()
    assert data["total_variants"] == 5
    variants = data["variants"]

    classes = [v["mutation_class"] for v in variants]
    assert "ALIAS_INDIRECT" in classes
    assert "VARIABLE_INDIRECTION" in classes
    assert "FRAGMENT_ENCAPSULATION" in classes
    assert "DIRECTIVE_COMPLEXITY" in classes
    assert "WHITESPACE_OBFUSCATION" in classes

    # Verify each variant has valid metadata
    for v in variants:
        assert len(v["fuzzed_query"]) > 0
        assert len(v["title"]) > 0
        assert len(v["description"]) > 0


def test_remediation_generation_endpoint(client):
    """Verify POST /api/v1/security/remediation/generate produces Strawberry, Shield, and OPA policies."""
    payload = {
        "target_type": "Resource",
        "field_name": "secret_key",
        "owner_field": "owner_id",
        "is_sensitive": True,
        "is_nested": False
    }
    resp = client.post("/api/v1/security/remediation/generate", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    # Check Strawberry Python
    assert "class IsResourceOwner(BasePermission):" in data["strawberry_python"]
    assert "permission_classes=[IsResourceOwner]" in data["strawberry_python"]

    # Check GraphQL Shield TS
    assert "export const permissions = shield(" in data["graphql_shield_ts"]
    assert "isResourceOwner" in data["graphql_shield_ts"]

    # Check Open Policy Agent (OPA)
    assert "package graphql.bola.authz" in data["opa_rego"]
    assert "input.user.id == input.target.owner_id" in data["opa_rego"]


def test_multi_tenant_matrix_endpoint(client):
    """Verify GET /api/v1/security/multi-tenant-matrix evaluates 2D cross-tenant access."""
    resp = client.get("/api/v1/security/multi-tenant-matrix")
    assert resp.status_code == 200
    data = resp.json()

    assert "tenants" in data
    assert "Alpha" in data["tenants"]
    assert "Beta" in data["tenants"]
    assert len(data["principals"]) == 6
    assert len(data["resources"]) == 4

    # Validate cell evaluation logic
    matrix = data["matrix"]
    assert len(matrix) == 6

    # Row 0: User 101 (Tenant Alpha, owns Resource 101)
    row_101 = matrix[0]
    cells = row_101["cells"]
    # Cell 0: Resource 101 -> OWNER_MATCH, ALLOW, 200
    assert cells[0]["resource_id"] == 101
    assert cells[0]["decision"] == "ALLOW"
    assert cells[0]["reason"] == "OWNER_MATCH"
    assert cells[0]["gateway_status"] == 200

    # Cell 1: Resource 102 -> Same tenant, different user -> CROSS_USER_MISMATCH, DENY, 403
    assert cells[1]["resource_id"] == 102
    assert cells[1]["decision"] == "DENY"
    assert cells[1]["gateway_status"] == 403

    # Cell 2: Resource 201 -> Different tenant (Beta) -> CROSS_TENANT_VIOLATION, DENY, 403
    assert cells[2]["resource_id"] == 201
    assert cells[2]["decision"] == "DENY"
    assert cells[2]["is_cross_tenant"] is True
    assert cells[2]["reason"] == "CROSS_TENANT_VIOLATION"

    # Row 4: Admin 999 -> ADMIN_OVERRIDE for all
    row_admin = matrix[4]
    for cell in row_admin["cells"]:
        assert cell["decision"] == "ALLOW"
        assert cell["reason"] == "ADMIN_OVERRIDE"


def test_live_events_stream_endpoint(client):
    """Verify GET /api/v1/security/live-events retrieves recent audit events and anomaly state."""
    resp = client.get("/api/v1/security/live-events?since_id=0&limit=10")
    assert resp.status_code == 200
    data = resp.json()

    assert "latest_id" in data
    assert "new_events_count" in data
    assert "has_high_risk" in data
    assert isinstance(data["events"], list)


def test_experiment_curves_endpoint(client, experiment_id):
    """Verify GET /api/v1/research/experiments/{id}/curves generates ROC & PR curve points."""
    resp = client.get(f"/api/v1/research/experiments/{experiment_id}/curves")
    assert resp.status_code == 200
    data = resp.json()

    assert "methods" in data
    methods = data["methods"]
    assert len(methods) >= 2

    for mid, mdata in methods.items():
        assert "auc_roc" in mdata
        assert 0.4 <= mdata["auc_roc"] <= 1.0
        assert "auc_pr" in mdata
        assert 0.4 <= mdata["auc_pr"] <= 1.0
        assert len(mdata["roc_curve"]) >= 4
        assert len(mdata["pr_curve"]) >= 3
