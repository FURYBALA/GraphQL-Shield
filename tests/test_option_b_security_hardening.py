"""
Tests for Option B: GraphQL Security Engine Hardening
======================================================
1. Batched query multiplexing defense (rate limits, batch size limits, cross-batch BOLA detection)
2. Directive-aware AST extraction and taint analysis (@skip and @include)
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token
from app.security.object_extractor import normalize_query
from app.security.taint_engine import analyze_query_taint

client = TestClient(app)

def test_batch_multiplexing_size_limit():
    """Batched requests exceeding MAX_BATCH_SIZE (10) must be rejected with 400."""
    user1_token = create_access_token(user_id=1, role="user")
    batch_payload = [{"query": "query { resources { id } }"}] * 15

    res = client.post(
        "/graphql",
        json=batch_payload,
        headers={"Authorization": f"Bearer {user1_token}"}
    )
    assert res.status_code == 400
    assert "BATCH_SIZE_EXCEEDED" in res.text


def test_batch_multiplexing_unauthorized_detection():
    """If ANY query in a batch accesses an unauthorized object, the batch must be blocked with 403."""
    bob_token = create_access_token(user_id=102, role="user")

    # Bob (102) owns resource 102, but does NOT own resource 101 (owned by Alice 101)
    batch_payload = [
        {"query": "query { resource(id: 102) { id name } }"},  # Authorized for Bob (102)
        {"query": "query { resource(id: 101) { id name } }"},  # BOLA violation (owned by Alice 101)
    ]

    res = client.post(
        "/graphql",
        json=batch_payload,
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert res.status_code == 403
    data = res.json()
    assert data["detail"]["error"] == "BATCH_AUTHORIZATION_DENIED"
    assert data["detail"]["object_id"] == 101
    assert data["detail"]["batch_index"] == 1


def test_batch_multiplexing_authorized_allowed():
    """A batch containing only authorized operations must be processed."""
    alice_token = create_access_token(user_id=101, role="user")

    batch_payload = [
        {"query": "query { resource(id: 101) { id name } }"},
    ]

    res = client.post(
        "/graphql",
        json=batch_payload,
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    # Gateway middleware permits it (status 200)
    assert res.status_code == 200


def test_directive_aware_skip_literal():
    """Fields with @skip(if: true) must be pruned from extracted target objects."""
    q_skipped = "query { resource(id: 102) @skip(if: true) { id } }"
    norm_skipped = normalize_query(q_skipped)
    assert len(norm_skipped["objects"]) == 0

    q_not_skipped = "query { resource(id: 102) @skip(if: false) { id } }"
    norm_not_skipped = normalize_query(q_not_skipped)
    assert len(norm_not_skipped["objects"]) == 1
    assert norm_not_skipped["objects"][0]["id"] == 102


def test_directive_aware_include_variable():
    """Fields with @include(if: $var) must be pruned when the variable is false."""
    q = "query CheckResource($inc: Boolean!) { resource(id: 102) @include(if: $inc) { id } }"
    
    # When $inc is False -> pruned
    norm_false = normalize_query(q, {"inc": False})
    assert len(norm_false["objects"]) == 0

    # When $inc is True -> extracted
    norm_true = normalize_query(q, {"inc": True})
    assert len(norm_true["objects"]) == 1
    assert norm_true["objects"][0]["id"] == 102


def test_directive_aware_taint_engine_pruning():
    """Taint analysis engine must skip paths marked with @skip(if: true)."""
    q_skipped = """
    query {
        resource(id: 102) @skip(if: true) {
            id
            name
        }
    }
    """
    report_skipped = analyze_query_taint(q_skipped)
    # No fields should be traversed under the skipped root
    assert report_skipped.total_fields_analyzed == 0
