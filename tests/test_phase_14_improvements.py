"""
Unit and Integration Tests for Phase 14 Hardening and Enhancements
-------------------------------------------------------------------
Tests:
1. In-memory TTL ownership cache hit, expiration, and invalidation.
2. Asynchronous audit queue worker, background persistence, and thread-safe flushing.
3. AST visitor hardening: fragment cycle defense and inline fragment extraction.
4. Multi-tenant ABAC isolation and collaborator authorization rules.
5. Ollama LLM provider interface and safe offline fallback.
6. Offline CI/CD GraphQL query security linter CLI execution.
"""

import pytest
import time
from app.config import settings
from app.security.ownership import resolve_ownership, clear_ownership_cache, _OWNERSHIP_CACHE
from app.security.audit import (
    start_audit_worker,
    stop_audit_worker,
    flush_audit_logs,
    log_decision,
)
from app.security.object_extractor import normalize_query
from app.security.authorization import AuthorizationContext, PolicyEngine
from app.security.ai_analyst.evidence import EvidencePackage
from app.security.ai_analyst.providers import OllamaLLMProvider
from scripts.lint_graphql_queries import lint_query


@pytest.fixture(autouse=True)
def clean_cache_and_audit():
    clear_ownership_cache()
    yield
    clear_ownership_cache()


def test_ownership_cache_hit_and_invalidation():
    """Verify ownership lookups populate the in-memory cache and invalidate properly."""
    clear_ownership_cache()
    assert len(_OWNERSHIP_CACHE) == 0

    # First lookup (database query + cache insert)
    owner1 = resolve_ownership("Resource", 101)
    assert owner1.owner_id == 101
    assert ("resource", 101) in _OWNERSHIP_CACHE

    # Second lookup (served directly from cache)
    owner2 = resolve_ownership("Resource", 101)
    assert owner2.owner_id == 101

    # Invalidate cache
    clear_ownership_cache()
    assert len(_OWNERSHIP_CACHE) == 0


def test_async_audit_queue_logging_and_flush():
    """Verify asynchronous non-blocking audit logging queue and flush behavior."""
    orig_setting = settings.ASYNC_AUDIT_LOGGING
    try:
        settings.ASYNC_AUDIT_LOGGING = True
        start_audit_worker()

        # Log event into async queue
        log_decision(
            user_id=101,
            role="user",
            operation="query",
            object_type="Resource",
            object_id=101,
            path="async_test_resource",
            decision="ALLOW",
            reason="OWNER_MATCH",
            risk_score=10,
            risk_level="LOW",
        )

        # Flush queue
        flush_audit_logs()

        # Shutdown worker cleanly
        stop_audit_worker()
    finally:
        settings.ASYNC_AUDIT_LOGGING = orig_setting


def test_ast_fragment_cycle_defense():
    """Verify cyclic fragment definitions are bounded and do not cause infinite recursion."""
    cyclic_query = """
    fragment FragA on User {
        id
        ...FragA
    }
    query {
        user(id: 101) {
            ...FragA
        }
    }
    """
    # normalize_query must terminate safely without RecursionError
    result = normalize_query(cyclic_query)
    assert isinstance(result, dict)
    assert "objects" in result


def test_ast_inline_fragment_traversal():
    """Verify inline fragment type conditions (... on Type) are parsed correctly."""
    query = """
    query {
        user(id: 101) {
            ... on User {
                id
                name
            }
        }
    }
    """
    result = normalize_query(query)
    assert isinstance(result, dict)
    user_objects = [o for o in result.get("objects", []) if o.get("type") == "User"]
    assert len(user_objects) > 0


def test_multi_tenant_isolation_deny():
    """Verify cross-tenant access is denied with TENANT_ISOLATION_VIOLATION and HIGH risk."""
    engine = PolicyEngine()
    ctx = AuthorizationContext(
        user_id=101,
        role="user",
        operation="query",
        object_type="Resource",
        object_id=102,
        path="resource",
        owner_id=101,  # Same user ID but different tenant!
        metadata={
            "caller_tenant_id": "tenant-alpha",
            "resource_tenant_id": "tenant-beta",
        },
    )
    decision = engine.evaluate(ctx)
    assert decision["decision"] == "DENY"
    assert decision["reason"] == "TENANT_ISOLATION_VIOLATION"
    assert decision["risk_score"] >= 80
    assert decision["risk_level"] == "HIGH"


def test_multi_tenant_superadmin_override():
    """Verify super-admin role can access cross-tenant resources."""
    engine = PolicyEngine()
    ctx = AuthorizationContext(
        user_id=999,
        role="SUPERADMIN",
        operation="query",
        object_type="Resource",
        object_id=102,
        path="resource",
        owner_id=102,
        metadata={
            "caller_tenant_id": "tenant-alpha",
            "resource_tenant_id": "tenant-beta",
        },
    )
    decision = engine.evaluate(ctx)
    assert decision["decision"] == "ALLOW"
    assert decision["reason"] == "SUPERADMIN_CROSS_TENANT_OVERRIDE"


def test_abac_collaborator_match():
    """Verify collaborator list in metadata grants access under Policy 4b."""
    engine = PolicyEngine()
    ctx = AuthorizationContext(
        user_id=205,
        role="user",
        operation="query",
        object_type="Resource",
        object_id=101,
        path="resource",
        owner_id=101,  # Owner is 101, caller is 205
        metadata={
            "collaborator_ids": [204, 205, 206],
        },
    )
    decision = engine.evaluate(ctx)
    assert decision["decision"] == "ALLOW"
    assert decision["reason"] == "COLLABORATOR_MATCH"


@pytest.mark.asyncio
async def test_ollama_provider_offline_fallback():
    """Verify Ollama provider safely falls back to grounded mock when daemon is offline."""
    provider = OllamaLLMProvider(
        api_base="http://127.0.0.1:59999",  # unreachable port
        model="llama3.1:8b",
        timeout_seconds=0.5,
    )
    package = EvidencePackage.from_scenario_or_finding(
        finding_id="TEST-OLLAMA-001",
        query="query { user(id: 102) { id name } }",
        variables={"id": 102},
        canonical_path="Query.user",
        response_path="user",
        caller_id=101,
        caller_role="user",
        target_type="User",
        target_id=102,
        owner_id=102,
        decision="DENY",
        reason="OWNERSHIP_MISMATCH",
        risk_score=80,
        risk_level="HIGH",
        correlation_status="TRUE_POSITIVE_BLOCKED",
        candidate_kind="DIRECT_BOLA",
        taint_source_arg="id",
        sensitive_sink_type="UserType",
        boundary_verified=True,
    )
    resp = await provider.generate_explanation(
        package=package,
        system_prompt="Test system prompt",
        user_prompt="Test user prompt",
    )
    assert resp is not None
    assert resp.model_metadata.get("provider") == "mock"
    assert "ollama_error" in resp.model_metadata
    assert resp.is_grounded is True


def test_cli_linter_bola_detection():
    """Verify CLI linter detects BOLA candidates in unmitigated queries."""
    res = lint_query("query { user(id: 10) { id name } }")
    assert res["is_valid"] is True
    assert res["passed"] is False
    assert res["risk_level"] == "HIGH"
    assert len(res["direct_bola_candidates"]) > 0


def test_cli_linter_clean_query():
    """Verify CLI linter passes safe/benign queries."""
    res = lint_query("query { __typename }")
    assert res["is_valid"] is True
    assert res["passed"] is True
    assert res["risk_level"] == "LOW"
    assert len(res["direct_bola_candidates"]) == 0


def test_cli_linter_alias_masking():
    """Verify CLI linter flags alias-cloaked fields."""
    res = lint_query("query { maskedUser: user(id: 10) { id } }")
    assert res["is_valid"] is True
    assert any(a["response_name"] == "maskedUser" for a in res["alias_masking_detected"])
