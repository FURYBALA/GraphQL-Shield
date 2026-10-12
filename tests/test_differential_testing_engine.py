"""
Comprehensive Test Suite for GraphQL Authorization Differential Testing Engine
-------------------------------------------------------------------------------
Verifies:
1. Schema path discovery and sensitive sink indexing.
2. Combinatorial test case generation across principals, paths, aliases, and variables.
3. Query minimization (Delta Debugging) into minimal reproducible PoCs.
4. Differential execution comparing Gateway (/graphql) vs Insecure Baseline (/graphql-insecure).
5. Accurate detection of differential vulnerability gap (insecure backend leaks, gateway protects).
6. Research metrics calculation and baseline comparative analysis.
7. Endpoints for interactive execution, suite runs, and metric queries.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security.differential_testing import (
    discover_schema_paths,
    generate_differential_suite,
    minimize_query,
    DifferentialTestExecutor,
    run_differential_testing_suite,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_schema_path_discovery():
    """Verify schema exploration identifies root and nested object-access paths."""
    paths = discover_schema_paths()
    assert len(paths) >= 5
    
    canonical_paths = [p.canonical_path for p in paths]
    assert "Query.user" in canonical_paths
    assert "Query.resource" in canonical_paths
    assert "UserType.resource" in canonical_paths
    assert "UserType.resources" in canonical_paths
    assert "ResourceType.children" in canonical_paths

    nested_paths = [p for p in paths if p.is_nested]
    assert len(nested_paths) >= 3


def test_differential_suite_generation():
    """Verify test generator produces controlled variants across all categories."""
    suite = generate_differential_suite()
    assert len(suite) >= 15

    categories = {tc.category for tc in suite}
    assert "DIRECT_BOLA" in categories
    assert "NESTED_BOLA" in categories
    assert "ALIAS_MASKING" in categories
    assert "VARIABLE_INJECTION" in categories
    assert "BENIGN_OWNER" in categories
    assert "ADMIN_OVERRIDE" in categories
    assert "ANONYMOUS" in categories

    # Verify expected decisions
    deny_cases = [tc for tc in suite if tc.expected_decision == "DENY"]
    allow_cases = [tc for tc in suite if tc.expected_decision == "ALLOW"]
    assert len(deny_cases) > 0
    assert len(allow_cases) > 0


def test_query_minimizer_delta_debugging():
    """Verify Delta Debugging strips extraneous fields while preserving the path."""
    complex_query = """
    query GetDetails {
        user(id: 101) {
            id
            username
            role
            resource(id: 102) {
                id
                name
                ownerId
                objectType
                parent_id
            }
        }
    }
    """
    minimized = minimize_query(complex_query, target_object_id=102)
    assert minimized is not None
    # Must preserve the target path user.resource
    assert "user" in minimized
    assert "resource" in minimized
    # Extraneous sibling scalars on root should be pruned
    assert "username" not in minimized
    assert "role" not in minimized


def test_differential_execution_direct_bola():
    """Verify differential execution against gateway vs insecure endpoint on direct BOLA."""
    executor = DifferentialTestExecutor(app)
    suite = generate_differential_suite()
    direct_bola_test = next(tc for tc in suite if tc.test_id == "DIFF-DIR-001")

    res = executor.execute_test(direct_bola_test)
    assert res is not None
    # Gateway must deny non-owner 101 from accessing Bob's Resource 102
    assert res.gateway_http_status == 403
    assert res.gateway_decision == "DENY"
    assert res.gateway_reason == "OWNERSHIP_MISMATCH"
    assert res.is_conforming_to_oracle is True
    # Insecure endpoint returns HTTP 200 and leaks the record!
    assert res.insecure_http_status == 200
    assert res.insecure_leaked_unauthorized_data is True
    # Gateway mitigated the baseline vulnerability
    assert res.vulnerability_mitigated_by_gateway is True
    assert res.verdict == "VULNERABILITY_PREVENTED"
    assert res.minimized_query is not None


def test_differential_execution_nested_bola():
    """Verify differential execution on indirect nested traversal."""
    executor = DifferentialTestExecutor(app)
    suite = generate_differential_suite()
    nested_bola_test = next(tc for tc in suite if tc.test_id == "DIFF-NEST-001")

    res = executor.execute_test(nested_bola_test)
    assert res.gateway_http_status == 403
    assert res.gateway_decision == "DENY"
    assert res.gateway_reason == "NESTED_AUTHORIZATION_VIOLATION"
    assert res.insecure_http_status == 200
    assert res.insecure_leaked_unauthorized_data is True
    assert res.path_inconsistency_detected is True
    assert res.verdict == "VULNERABILITY_PREVENTED"


def test_differential_execution_benign_owner():
    """Verify legitimate owner access is permitted on both endpoints."""
    executor = DifferentialTestExecutor(app)
    suite = generate_differential_suite()
    owner_test = next(tc for tc in suite if tc.test_id == "DIFF-OWN-001")

    res = executor.execute_test(owner_test)
    assert res.gateway_http_status == 200
    assert res.gateway_decision == "ALLOW"
    assert res.gateway_reason == "OWNER_MATCH"
    assert res.gateway_data_returned is True
    assert res.insecure_leaked_unauthorized_data is False
    assert res.verdict == "PROTECTED_MATCH"


def test_full_differential_suite_and_research_metrics():
    """Verify end-to-end differential suite run compiles research metrics."""
    report = run_differential_testing_suite(app)
    assert report.total_test_cases >= 15
    assert report.schema_path_coverage_pct > 80.0
    assert report.total_conforming_cases == report.total_test_cases
    assert report.policy_divergence_count == 0
    assert report.false_positives == 0
    assert report.vulnerability_prevention_rate_pct == 100.0
    assert report.reproducibility_rate_pct == 100.0

    # Baseline comparison metrics
    comp = report.baseline_comparison
    assert "manual_baseline_cases" in comp
    assert "differential_engine_cases" in comp
    assert comp["differential_engine_cases"] > comp["manual_baseline_cases"]
    assert comp["differential_path_coverage_pct"] > comp["manual_path_coverage_pct"]


def test_api_differential_paths(client):
    """Test GET /api/v1/differential-testing/paths."""
    resp = client.get("/api/v1/differential-testing/paths")
    assert resp.status_code == 200
    data = resp.json()
    assert "paths" in data
    assert len(data["paths"]) >= 5


def test_api_differential_run(client):
    """Test POST /api/v1/differential-testing/run."""
    resp = client.post("/api/v1/differential-testing/run", json={"sample_limit": 4})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_test_cases"] == 4
    assert len(data["results"]) == 4
    assert data["reproducibility_rate_pct"] == 100.0


def test_api_differential_execute_custom(client):
    """Test POST /api/v1/differential-testing/execute-custom with interactive query."""
    custom_payload = {
        "query": "query { resource(id: 102) { id name } }",
        "caller_id": 101,
        "caller_role": "user",
    }
    resp = client.post("/api/v1/differential-testing/execute-custom", json=custom_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["gateway_decision"] == "DENY"
    assert data["gateway_reason"] == "OWNERSHIP_MISMATCH"
    assert data["insecure_leaked_unauthorized_data"] is True
    assert data["verdict"] == "VULNERABILITY_PREVENTED"
    assert data["minimized_query"] is not None


def test_api_differential_metrics(client):
    """Test GET /api/v1/differential-testing/metrics."""
    resp = client.get("/api/v1/differential-testing/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "baseline_comparison" in data
    assert data["summary"]["vulnerability_prevention_rate_pct"] == 100.0
