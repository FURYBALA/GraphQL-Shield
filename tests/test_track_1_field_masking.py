"""
Tests for Track 1: Field-Level Granular Authorization & Partial Redaction
========================================================================
Verifies that:
1. Object owners can access their own sensitive fields (secretKey).
2. Administrators can access sensitive fields.
3. Non-owners querying sensitive fields have those fields masked to null,
   while non-sensitive sibling fields (id, name) resolve normally,
   accompanied by an RFC-compliant GraphQL error extension.
"""

import pytest
from app.graphql.schema import schema
from app.core.security import create_access_token
from app.graphql.types import ResourceType
from app.config import settings

def test_field_level_masking_owner_allowed():
    """Object owner (101) querying resource 101 secretKey receives full secret."""
    class DummyState:
        current_user = {"user_id": 101, "role": "user"}

    class DummyRequest:
        state = DummyState()

    context = {"request": DummyRequest()}
    query = """
    query {
        resource(id: 101) {
            id
            name
            secretKey
        }
    }
    """
    result = schema.execute_sync(query, context_value=context)
    assert result.errors is None
    assert result.data is not None
    assert result.data["resource"]["id"] == 101
    assert result.data["resource"]["secretKey"] is not None
    assert "sk_live_token_101_101" in result.data["resource"]["secretKey"]


def test_field_level_masking_admin_allowed():
    """Administrator querying resource 101 secretKey receives full secret."""
    class DummyState:
        current_user = {"user_id": 999, "role": "admin"}

    class DummyRequest:
        state = DummyState()

    context = {"request": DummyRequest()}
    query = """
    query {
        resource(id: 101) {
            id
            name
            secretKey
        }
    }
    """
    result = schema.execute_sync(query, context_value=context)
    assert result.errors is None
    assert result.data["resource"]["secretKey"] is not None


def test_field_level_masking_non_owner_redacted():
    """Non-owner (102) querying resource 101 secretKey has it redacted to null with error."""
    class DummyState:
        current_user = {"user_id": 102, "role": "user"}

    class DummyRequest:
        state = DummyState()

    context = {"request": DummyRequest()}
    query = """
    query {
        resource(id: 101) {
            id
            name
            secretKey
        }
    }
    """
    result = schema.execute_sync(query, context_value=context)
    # Crucial RFC guarantee: data is NOT completely null; non-sensitive sibling fields resolve!
    assert result.data is not None
    assert result.data["resource"]["id"] == 101
    assert result.data["resource"]["name"] == "Alice's Secret Note"
    # The sensitive field is masked to null
    assert result.data["resource"]["secretKey"] is None

    # Error array contains exact field path and structured extension
    assert result.errors is not None
    assert len(result.errors) == 1
    err = result.errors[0]
    assert "Field-level authorization denied" in err.message
    assert err.path == ["resource", "secretKey"]
    assert err.extensions["code"] == "FIELD_AUTHORIZATION_DENIED"
    assert err.extensions["field"] == "secretKey"
    assert err.extensions["caller_id"] == 102
    assert err.extensions["object_owner_id"] == 101


def test_field_level_masking_config_toggle(monkeypatch):
    """When ENABLE_FIELD_LEVEL_REDACTION is False, redaction is bypassed."""
    monkeypatch.setattr(settings, "ENABLE_FIELD_LEVEL_REDACTION", False)

    class DummyState:
        current_user = {"user_id": 102, "role": "user"}

    class DummyRequest:
        state = DummyState()

    context = {"request": DummyRequest()}
    query = """
    query {
        resource(id: 101) {
            secretKey
        }
    }
    """
    result = schema.execute_sync(query, context_value=context)
    assert result.errors is None
    assert result.data["resource"]["secretKey"] is not None
