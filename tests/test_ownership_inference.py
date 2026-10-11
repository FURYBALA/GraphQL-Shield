"""
Tests for Schema-Aware Ownership Inference Engine.

These tests verify:
  - Correct inference of ownership patterns from the real Strawberry schema
  - Unknown relationships are not treated as ownership
  - Explicit ownership rules override inferred rules
  - Fail-closed behavior when inference is uncertain
  - Full backward compatibility with existing BOLA demos
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.graphql.schema import schema
from app.security.ownership_inference import (
    OwnershipInferenceEngine,
    OwnershipRule,
    inference_engine,
    normalize_type_name,
)
from app.core.security import create_access_token
from app.database import get_db_connection
from app.seed import seed_database
from app.config import settings
import os

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = "sqlite:///./test_inference.db"
    seed_database()
    yield
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except PermissionError:
            pass
    settings.DATABASE_URL = original_url


# ===================== INFERENCE ENGINE UNIT TESTS =====================

def test_01_infer_owner_field():
    """TEST 1: ResourceType has owner_id field -> inferred as ownership to User."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(schema)
    owner_rules = [r for r in report.rules if r.source_type == "ResourceType" and "owner" in r.source_field.lower()]
    assert len(owner_rules) >= 1, "Should find at least one owner-related rule on ResourceType"
    rule = owner_rules[0]
    assert rule.target_type == "User" or rule.target_type == "UserType"
    assert rule.confidence in ("HIGH", "MEDIUM")


def test_02_infer_owner_id_scalar():
    """TEST 2: ResourceType.owner_id is a scalar ID matching ownership pattern."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(schema)
    scalar_rules = [r for r in report.rules if r.source_field == "owner_id" and r.pattern == "OWNER_FIELD"]
    assert len(scalar_rules) >= 1, "Should detect owner_id as an ownership scalar field"


def test_03_infer_collection_relationship():
    """TEST 3: UserType.resources is a collection of ResourceType."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(schema)
    collection_rules = [r for r in report.rules if r.source_field == "resources" and r.pattern == "COLLECTION"]
    assert len(collection_rules) >= 1, "Should detect resources collection on UserType"
    rule = collection_rules[0]
    assert rule.target_type == "ResourceType"


def test_04_unknown_relationship_not_ownership():
    """TEST 4: A field like 'username' should NOT be treated as ownership."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(schema)
    bad_rules = [r for r in report.rules if r.source_field == "username"]
    assert len(bad_rules) == 0, "'username' must not be inferred as an ownership field"


def test_05_explicit_ownership_overrides_inferred():
    """TEST 5: The DB ownership lookup (explicit) always takes precedence."""
    # The existing get_object_owner function returns the real DB owner.
    # Even if inference says Resource->User, the DB owner_id is authoritative.
    from app.security.ownership import get_object_owner
    owner = get_object_owner("Resource", 101)
    assert owner == 101, "DB lookup must return the actual owner"
    owner2 = get_object_owner("Resource", 102)
    assert owner2 == 102, "DB lookup must return the actual owner"


def test_06_inference_uncertainty_fails_closed():
    """TEST 6: If inference cannot determine ownership, get_owner_type_for returns None."""
    engine = OwnershipInferenceEngine()
    engine.build_from_strawberry_schema(schema)
    rule = engine.get_owner_type_for("CompletelyUnknownType")
    assert rule is None, "Unknown types must return None (fail-closed)"


# ===================== BACKWARD COMPATIBILITY TESTS =====================

def test_07_direct_bola_still_403():
    """TEST 7: Direct BOLA still returns HTTP 403."""
    token = create_access_token(user_id=101, role="user")
    query = {"query": "{ resource(id: 102) { id name } }"}
    res = client.post("/graphql", json=query, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert res.json()["detail"]["reason"] == "OWNERSHIP_MISMATCH"


def test_08_nested_bola_still_403():
    """TEST 8: Nested BOLA still returns HTTP 403."""
    token = create_access_token(user_id=101, role="user")
    query = {"query": "{ user(id: 101) { username resource(id: 102) { name } } }"}
    res = client.post("/graphql", json=query, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert res.json()["detail"]["reason"] == "NESTED_AUTHORIZATION_VIOLATION"


def test_09_legitimate_owner_still_200():
    """TEST 9: Legitimate owner access still returns HTTP 200."""
    token = create_access_token(user_id=101, role="user")
    query = {"query": "{ resource(id: 101) { id name } }"}
    res = client.post("/graphql", json=query, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert "data" in res.json()


def test_10_invalid_jwt_still_401():
    """TEST 10: Invalid JWT still returns HTTP 401."""
    query = {"query": "{ resource(id: 101) { id name } }"}
    res = client.post("/graphql", json=query, headers={"Authorization": "Bearer invalid"})
    assert res.status_code == 401


@patch('app.security.risk_engine.get_db_connection')
def test_11_risk_scoring_unchanged(mock_db):
    """TEST 11: Risk scoring still works correctly."""
    mock_db.return_value.cursor.return_value.fetchone.return_value = (0,)
    from app.security.authorization import AuthorizationContext, PolicyEngine
    engine = PolicyEngine()
    ctx = AuthorizationContext(
        user_id=101, role="user", operation="query",
        object_type="Resource", object_id=102, path="resource",
        owner_id=102, metadata={}
    )
    result = engine.evaluate(ctx)
    assert result["decision"] == "DENY"
    assert result["risk_score"] >= 80
    assert result["risk_level"] == "HIGH"


def test_12_audit_logging_unchanged():
    """TEST 12: Audit logging still records events correctly."""
    token = create_access_token(user_id=101, role="user")
    # Trigger an ALLOW
    client.post("/graphql", json={"query": "{ resource(id: 101) { id name } }"}, headers={"Authorization": f"Bearer {token}"})
    # Trigger a DENY
    client.post("/graphql", json={"query": "{ resource(id: 102) { id name } }"}, headers={"Authorization": f"Bearer {token}"})
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT decision FROM audit_logs ORDER BY id DESC LIMIT 2")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    assert "DENY" in rows
    assert "ALLOW" in rows


# ===================== ENDPOINT & INTEGRATION TESTS =====================

def test_13_schema_ownership_endpoint_admin():
    """The schema-ownership endpoint returns inferred rules for ADMIN."""
    token = create_access_token(user_id=103, role="admin")
    res = client.get("/api/v1/security/schema-ownership", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "analyzed"
    assert data["types_analyzed"] > 0
    assert data["relationships_detected"] > 0
    assert len(data["rules"]) > 0


def test_14_schema_ownership_endpoint_denied_for_user():
    """The schema-ownership endpoint is denied for non-admin users."""
    token = create_access_token(user_id=101, role="user")
    res = client.get("/api/v1/security/schema-ownership", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


def test_15_inference_not_repeated():
    """Inference engine build is idempotent -- second call is a no-op."""
    engine = OwnershipInferenceEngine()
    report1 = engine.build_from_strawberry_schema(schema)
    report2 = engine.build_from_strawberry_schema(schema)
    assert report1 is report2, "Second call must return the cached report"


# ===================== PATTERN TESTS ON A SYNTHETIC SCHEMA =====================

import strawberry as strawberry_lib
from typing import List as TypingList, Optional as TypingOptional


@strawberry_lib.type
class User:
    id: int
    username: str
    posts: TypingList["Article"]


@strawberry_lib.type
class Article:
    id: int
    title: str
    owner: TypingOptional[User]
    created_by: str


@strawberry_lib.type
class Query:
    @strawberry_lib.field
    def user(self, id: int) -> TypingOptional[User]:
        raise NotImplementedError

    @strawberry_lib.field
    def article(self, id: int) -> TypingOptional[Article]:
        raise NotImplementedError


SYNTHETIC_SCHEMA = strawberry_lib.Schema(query=Query)


def test_16_pattern_a_owner_object_reference():
    """TEST 16 (Pattern A): type Article { owner: User } -> Article.owner -> User."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(SYNTHETIC_SCHEMA)
    rules = [r for r in report.rules if r.source_type == "Article" and r.source_field == "owner"]
    assert len(rules) == 1
    rule = rules[0]
    assert rule.target_type == "User"
    assert rule.pattern == "OWNER_FIELD"
    assert rule.confidence == "HIGH"
    assert "owner" in rule.inference_reason


def test_17_pattern_b_user_collection():
    """TEST 17 (Pattern B): type User { posts: [Article] } -> User.posts -> Article."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(SYNTHETIC_SCHEMA)
    rules = [r for r in report.rules if r.source_type == "User" and r.source_field == "posts"]
    assert len(rules) == 1
    assert rules[0].target_type == "Article"
    assert rules[0].pattern == "COLLECTION"


def test_18_ambiguous_relationship_rejected():
    """TEST 18: 'created_by: String' matches a name pattern but is not an identifier."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(SYNTHETIC_SCHEMA)
    accepted = [r for r in report.rules if r.source_field == "created_by"]
    rejected = [r for r in report.rejected if r.source_field == "created_by"]
    assert len(accepted) == 0, "String ownership marker must not become an accepted rule"
    assert len(rejected) == 1, "String ownership marker must be recorded as ambiguous"
    assert rejected[0].category == "AMBIGUOUS"


# ===================== FAIL-CLOSED BEHAVIOR =====================

def test_19_unknown_ownership_fails_closed():
    """TEST 19: Unknown object type -> UNKNOWN_OWNERSHIP -> DENY (fail closed)."""
    from app.security.ownership import resolve_ownership
    from app.security.authorization import AuthorizationContext, PolicyEngine

    resolution = resolve_ownership("Widget", 1)
    assert resolution.status == "UNKNOWN_OWNERSHIP"
    assert resolution.owner_id is None
    assert resolution.rule is None

    with patch('app.security.risk_engine.get_db_connection') as mock_db:
        mock_db.return_value.cursor.return_value.fetchone.return_value = (0,)
        result = PolicyEngine().evaluate(AuthorizationContext(
            user_id=101, role="user", operation="query",
            object_type="Widget", object_id=1, path="widget",
            owner_id=resolution.owner_id,
            metadata={"ownership_status": resolution.status},
        ))
    assert result["decision"] == "DENY"
    assert result["reason"] == "UNKNOWN_OWNERSHIP"
    assert result["risk_level"] == "HIGH"


def test_19b_unknown_ownership_blocked_at_gateway():
    """TEST 19b: A query for a type with no ownership rule is blocked with HTTP 403."""
    token = create_access_token(user_id=101, role="user")
    res = client.post(
        "/graphql",
        json={"query": "{ widget(id: 1) { name } }"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
    assert res.json()["detail"]["reason"] == "UNKNOWN_OWNERSHIP"
    assert res.json()["detail"]["risk_level"] == "HIGH"


# ===================== PRIORITY: EXPLICIT RULES =====================

def test_20_explicit_rule_overrides_inferred_rule():
    """TEST 20: An explicitly registered rule always wins over the inferred one."""
    engine = OwnershipInferenceEngine()
    engine.build_from_strawberry_schema(schema)

    inferred = engine.get_owner_type_for("Resource")
    assert inferred is not None and inferred.source == "INFERRED"

    explicit = OwnershipRule(
        source_type="ResourceType",
        source_field="owner_id",
        target_type="User",
        owner_field="id",
        confidence="HIGH",
        inference_reason="explicitly configured ownership rule",
        pattern="OWNER_FIELD",
    )
    engine.add_explicit_rule(explicit)

    chosen = engine.get_owner_type_for("Resource")
    assert chosen is explicit
    assert chosen.source == "EXPLICIT"
    assert chosen.inference_reason == "explicitly configured ownership rule"


def test_20b_explicit_rule_can_enable_unmodeled_type():
    """TEST 20b: A type with no inferred rule becomes resolvable once explicitly configured."""
    engine = OwnershipInferenceEngine()
    engine.build_from_strawberry_schema(schema)
    assert engine.get_owner_type_for("Widget") is None

    engine.add_explicit_rule(OwnershipRule(
        source_type="Widget",
        source_field="owner_id",
        target_type="User",
        owner_field="id",
        confidence="HIGH",
        inference_reason="explicitly configured ownership rule",
        pattern="OWNER_FIELD",
    ))
    assert engine.get_owner_type_for("Widget") is not None


# ===================== REPORT INTEGRITY =====================

def test_21_report_counts_match_rules():
    """TEST 21: Reported counts must be derived from the actual analysis."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(schema)

    assert report.types_analyzed == len(report.analyzed_types)
    assert report.relationships_detected == len(report.rules)
    assert report.high_confidence + report.medium_confidence + report.low_confidence == len(report.rules)
    assert report.ambiguous == len(report.rejected)
    assert report.analysis_time_ms >= 0


def test_22_inference_not_repeated_per_request():
    """TEST 22: The model is built once; request handling never re-analyzes the schema."""
    from app.security.ownership_inference import ensure_inference_ready

    engine = OwnershipInferenceEngine()
    first = engine.build_from_strawberry_schema(schema)
    with patch.object(OwnershipInferenceEngine, "_analyze_type") as analyze_spy:
        second = engine.build_from_strawberry_schema(schema)
        assert analyze_spy.call_count == 0, "Cached build must not re-analyze the schema"
    assert first is second

    live = ensure_inference_ready()
    snapshot = live.report
    snapshot_rules = live.rules
    for _ in range(50):
        resolve = _resolve_owner_safely()
    assert live.report is snapshot, "Report object must stay stable across requests"
    assert live.rules == snapshot_rules


def _resolve_owner_safely():
    from app.security.ownership import resolve_ownership
    return resolve_ownership("Resource", 101)


def test_23_endpoint_payload_contains_full_report():
    """TEST 23: The inspection endpoint returns the complete, explainable report."""
    token = create_access_token(user_id=103, role="admin")
    res = client.get("/api/v1/security/schema-ownership", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "analyzed"
    assert data["analyzed_types"]
    assert data["priority"][0].startswith("1.")
    assert data["priority"][-1].startswith("3.")
    assert isinstance(data["rejected"], list)
    rule = data["rules"][0]
    for key in ("source_type", "source_field", "target_type", "confidence", "reason", "pattern", "source"):
        assert key in rule


def test_24_pattern_d_nested_chain_present():
    """TEST 24 (Pattern D): User.resources -> ResourceType and ResourceType.owner_id -> User."""
    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(schema)
    chain_out = [r for r in report.rules
                 if normalize_type_name(r.source_type) == "user" and r.pattern == "COLLECTION"]
    chain_in = [r for r in report.rules
                if normalize_type_name(r.source_type) == "resource" and r.pattern == "OWNER_FIELD"]
    assert chain_out and chain_in
    assert chain_out[0].target_type == "ResourceType"
    assert chain_in[0].target_type in ("User", "UserType")


# ===================== INFERENCE REPORT =====================

def _load_report_module():
    import importlib.util
    import os as _os
    path = _os.path.abspath(_os.path.join(
        _os.path.dirname(__file__), "..", "scripts", "generate_inference_report.py"))
    spec = importlib.util.spec_from_file_location("generate_inference_report", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_25_report_numbers_match_real_schema_analysis():
    """TEST 25: Report counts are derived from the live schema analysis, not hard-coded."""
    module = _load_report_module()
    report = module.build_report()

    reference = OwnershipInferenceEngine().build_from_strawberry_schema(schema)
    summary = report["summary"]

    assert summary["graphql_types_analyzed"] == reference.types_analyzed
    assert summary["candidate_relationships_detected"] == reference.relationships_detected
    assert summary["accepted_rules"] == len(reference.rules)
    assert summary["high_confidence_rules"] == reference.high_confidence
    assert summary["medium_confidence_rules"] == reference.medium_confidence
    assert summary["rejected_or_ambiguous_relationships"] == len(reference.rejected)
    assert len(report["accepted_rules"]) == len(reference.rules)
    assert len(report["analyzed_types"]) == reference.types_analyzed

    for rule in report["accepted_rules"]:
        for key in ("source_type", "source_field", "target_type",
                    "confidence", "pattern", "reason"):
            assert key in rule and rule[key]
    assert report["priority"][-1].startswith("3.")
