"""
Test Suite for Evidence-Grounded AI Security Analyst (Phase 10)
Verifies:
1. Evidence extraction, indexing (E1..E11), and sanitization.
2. Deterministic Mock generation with valid citations.
3. Automated grounding validation: detection of hallucinated citations, decision contradictions, and path mismatches.
4. AI Service behavior under enabled and disabled states.
5. Endpoints for status and advisory explanation.
6. Absolute non-interference: AI generation never alters gateway decisions or database state.
"""

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.main import app
from app.security.ai_analyst import (
    AIExplanationRequest,
    AIExplanationResponse,
    AIAnalystService,
    EvidencePackage,
    FlawedMockAIProvider,
    MockAIProvider,
)
from app.security.ai_analyst.evidence import sanitize_variables


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token():
    return create_access_token(user_id=1, role="ADMIN")


@pytest.fixture
def user_token():
    return create_access_token(user_id=101, role="user")


@pytest.fixture
def sample_evidence_package():
    return EvidencePackage.from_scenario_or_finding(
        finding_id="TEST-FINDING-001",
        query="query { doc: resource(id: 102) { id name } }",
        variables={"id": 102, "token": "sensitive_jwt_token_secret"},
        canonical_path="Query.resource",
        response_path="doc",
        caller_id=101,
        caller_role="user",
        target_type="Resource",
        target_id=102,
        owner_id=102,
        decision="DENY",
        reason="OWNERSHIP_MISMATCH",
        risk_score=85,
        risk_level="HIGH",
        correlation_status="TRUE_POSITIVE_BLOCKED",
        candidate_kind="DIRECT_BOLA",
        taint_source_arg="id",
        sensitive_sink_type="Resource",
        boundary_verified=True,
    )


# -----------------------------------------------------------------------------
# 1. Evidence Packaging & Sanitization Tests
# -----------------------------------------------------------------------------

def test_evidence_package_indexing_and_sanitization(sample_evidence_package):
    pkg = sample_evidence_package
    
    # Verify indexing E1 through E11
    assert "E1" in pkg.evidence_items
    assert "E2" in pkg.evidence_items
    assert "E3" in pkg.evidence_items
    assert "E6" in pkg.evidence_items
    assert "E7" in pkg.evidence_items
    assert "E8" in pkg.evidence_items
    assert "E11" in pkg.evidence_items

    # Verify alias detection
    assert pkg.is_alias_masked is True
    assert pkg.canonical_schema_path == "Query.resource"
    assert pkg.client_response_path == "doc"

    # Verify token scrubbed in variables
    assert pkg.variables_sanitized["token"] == "[REDACTED]"
    assert pkg.variables_sanitized["id"] == 102

    # Verify prompt formatting delimiters
    formatted = pkg.format_for_prompt()
    assert "--- BEGIN VERIFIABLE SECURITY EVIDENCE PACKAGE ---" in formatted
    assert "--- END VERIFIABLE SECURITY EVIDENCE PACKAGE ---" in formatted
    assert "[E1]" in formatted
    assert "[E8]" in formatted


# -----------------------------------------------------------------------------
# 2. Mock Provider & Grounded Explanations
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mock_provider_blocked_scenario(sample_evidence_package):
    provider = MockAIProvider()
    resp = await provider.generate_explanation(
        package=sample_evidence_package,
        system_prompt="Test system prompt",
        user_prompt="Test user prompt",
    )

    assert isinstance(resp, AIExplanationResponse)
    assert resp.is_grounded is True
    assert resp.grounding_score >= 0.90
    assert "Direct Broken Object-Level Authorization" in resp.attack_pattern
    assert "Query.resource" == resp.canonical_path
    assert len(resp.validation_warnings) == 0
    assert len(resp.evidence_references) > 0
    assert "E8" in resp.evidence_references
    assert "E6" in resp.evidence_references


@pytest.mark.asyncio
async def test_mock_provider_benign_allowed_scenario():
    pkg = EvidencePackage.from_scenario_or_finding(
        finding_id="TEST-FINDING-002",
        query="query { resource(id: 101) { id name } }",
        variables={"id": 101},
        canonical_path="Query.resource",
        response_path="resource",
        caller_id=101,
        caller_role="user",
        target_type="Resource",
        target_id=101,
        owner_id=101,
        decision="ALLOW",
        reason="OWNER_MATCH",
        risk_score=10,
        risk_level="LOW",
        correlation_status="RUNTIME_PROTECTED_ALLOWED",
        candidate_kind="DIRECT_BOLA",
        taint_source_arg="id",
        sensitive_sink_type="Resource",
        boundary_verified=True,
    )

    provider = MockAIProvider()
    resp = await provider.generate_explanation(pkg, "sys", "usr")
    assert resp.is_grounded is True
    assert "Resource Owner Access" in resp.attack_pattern
    assert "allowed" in resp.summary.lower() or "authorized" in resp.summary.lower()
    assert len(resp.validation_warnings) == 0


# -----------------------------------------------------------------------------
# 3. Grounding Verification & Flawed Model Defect Rejection (RQ3)
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_grounding_rejects_hallucinated_citations(sample_evidence_package):
    flawed_provider = FlawedMockAIProvider(inject_hallucinated_citations=True)
    resp = await flawed_provider.generate_explanation(sample_evidence_package, "sys", "usr")

    # Verification must flag E99 and E100
    assert any("E99" in w for w in resp.validation_warnings)
    assert any("E100" in w for w in resp.validation_warnings)
    assert resp.grounding_score < 1.0


@pytest.mark.asyncio
async def test_grounding_rejects_decision_contradictions(sample_evidence_package):
    # Sample package has decision="DENY"
    flawed_provider = FlawedMockAIProvider(inject_decision_contradiction=True)
    resp = await flawed_provider.generate_explanation(sample_evidence_package, "sys", "usr")

    assert resp.is_grounded is False
    assert any("contradicts gateway decision" in w for w in resp.validation_warnings)
    assert resp.grounding_score <= 0.60


@pytest.mark.asyncio
async def test_grounding_detects_path_mismatch(sample_evidence_package):
    flawed_provider = FlawedMockAIProvider(inject_path_mismatch=True)
    resp = await flawed_provider.generate_explanation(sample_evidence_package, "sys", "usr")

    assert any("Path mismatch" in w for w in resp.validation_warnings)
    assert resp.canonical_path != sample_evidence_package.canonical_schema_path


# -----------------------------------------------------------------------------
# 4. Service & Endpoint Integration
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_service_disabled_by_default(sample_evidence_package):
    service = AIAnalystService()
    # Default settings has AI_EXPLANATION_ENABLED = False
    with pytest.raises(Exception) as excinfo:
        await service.generate_explanation(
            request=AIExplanationRequest(evidence_package=sample_evidence_package),
            force_execution=False,
        )
    assert "AI Analyst is disabled by configuration" in str(excinfo.value)


@pytest.mark.asyncio
async def test_service_force_execution_override(sample_evidence_package):
    service = AIAnalystService()
    resp = await service.generate_explanation(
        request=AIExplanationRequest(evidence_package=sample_evidence_package),
        force_execution=True,
    )
    assert isinstance(resp, AIExplanationResponse)
    assert resp.is_grounded is True


def test_ai_status_endpoint(client, user_token):
    # Unauthenticated rejected (401 Unauthorized or 403 Forbidden)
    unauth_resp = client.get("/api/v1/security/ai-analyst/status")
    assert unauth_resp.status_code in (401, 403)

    # Authenticated returns configuration without secrets
    resp = client.get(
        "/api/v1/security/ai-analyst/status",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "enabled" in data
    assert "provider" in data
    assert "model" in data
    assert data["advisory_only"] is True
    assert "api_key" not in data  # Never expose raw API key!


def test_ai_explain_endpoint_when_disabled(client, user_token):
    # Request when disabled without force_execution returns 403
    resp = client.post(
        "/api/v1/security/ai-analyst/explain",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "finding_id": "SCENARIO-HOPPSCOTCH-COLLECTION-IDOR",
            "query": "query { resource(id: 2) { id name } }",
        },
    )
    assert resp.status_code == 403
    assert "AI Analyst is disabled" in resp.json()["detail"]


# -----------------------------------------------------------------------------
# 5. Gateway Non-Interference Verification
# -----------------------------------------------------------------------------

def test_ai_analyst_never_alters_gateway_decisions(client, user_token):
    """Verifies gateway enforcement operates strictly independently of the AI analyst."""
    # Alice (101) requesting Bob's resource (102) must still receive HTTP 403 Forbidden
    resp = client.post(
        "/graphql",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"query": "query { resource(id: 102) { id name } }"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["detail"]["decision"] == "DENY"
    assert data["detail"]["reason"] == "OWNERSHIP_MISMATCH"


# -----------------------------------------------------------------------------
# 6. Real-LLM Controlled Evaluation Protocol Tests (Phase 10.2)
# -----------------------------------------------------------------------------

def test_fixed_evaluation_set_has_independent_ground_truth():
    """Verifies the 4-scenario evaluation set defines independent ground truths."""
    from scripts.evaluate_real_llm_explanations import FIXED_EVALUATION_SET, BLINDED_RUBRIC_SPEC

    assert len(FIXED_EVALUATION_SET) == 4
    scenario_ids = [gt.scenario_id for gt in FIXED_EVALUATION_SET]
    assert "REAL-HOPP-001" in scenario_ids
    assert "REAL-HOPP-002" in scenario_ids
    assert "REAL-NEST-001" in scenario_ids
    assert "REAL-SAAS-003" in scenario_ids

    # Verify both ALLOW and DENY are represented
    decisions = {gt.expected_gateway_decision for gt in FIXED_EVALUATION_SET}
    assert decisions == {"ALLOW", "DENY"}

    # Verify independent ground-truth fields are complete
    for gt in FIXED_EVALUATION_SET:
        assert gt.expected_canonical_path.startswith("Query.")
        assert len(gt.required_factual_elements) >= 3
        assert len(gt.forbidden_claims) >= 2
        assert gt.expected_remediation_intent

    # Verify rubric sums to 10 points
    total_rubric_points = sum(d["max_points"] for d in BLINDED_RUBRIC_SPEC["dimensions"])
    assert total_rubric_points == 10


@pytest.mark.asyncio
async def test_evaluate_scenario_explanation_against_ground_truth():
    """Verifies the evaluation harness correctly measures decision consistency and required facts."""
    from scripts.evaluate_real_llm_explanations import FIXED_EVALUATION_SET, evaluate_scenario_explanation
    from app.security.ai_analyst.providers import MockAIProvider

    gt = FIXED_EVALUATION_SET[0]  # REAL-HOPP-001 (DENY)
    pkg = EvidencePackage.from_scenario_or_finding(
        finding_id=gt.scenario_id,
        query="query { resource(id: 102) { id } }",
        variables={"id": 102},
        canonical_path="Query.resource",
        response_path="resource",
        caller_id=101,
        caller_role="user",
        target_type="Resource",
        target_id=102,
        owner_id=102,
        decision="DENY",
        reason="OWNERSHIP_MISMATCH",
        risk_score=90,
        risk_level="HIGH",
        correlation_status="TRUE_POSITIVE_BLOCKED",
        candidate_kind="DIRECT_BOLA",
        taint_source_arg="id",
        sensitive_sink_type="Resource",
        boundary_verified=True,
    )

    mock_provider = MockAIProvider()
    resp = await mock_provider.generate_explanation(pkg, "sys", "usr")
    eval_result = await evaluate_scenario_explanation(gt, resp)

    assert eval_result["decision_consistent"] is True
    assert eval_result["path_correct"] is True
    assert eval_result["citation_metrics"]["invalid_count"] == 0
    assert eval_result["required_fact_coverage"]["coverage_rate_pct"] == 100.0
    assert len(eval_result["contradictions_detected"]) == 0

