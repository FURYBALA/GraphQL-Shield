"""
Regression test for GraphQL variable default values in authorization gateway (CORPUS-018).

Verifies that variable default values declared in GraphQL operation headers
(e.g., query GetDoc($target: Int = 102)) are properly extracted and enforced
by the gateway rather than bypassing object-level authorization checks.
"""

import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app.core.security import create_access_token
from app.seed import seed_database
from app.security.object_extractor import normalize_query


client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = "sqlite:///./test_shield_regression.db"
    seed_database()
    yield
    settings.DATABASE_URL = original_url
    db_file = "test_shield_regression.db"
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except PermissionError:
            pass


def test_normalize_query_extracts_variable_default_value():
    """Object extractor must extract object IDs from variable default values when variables map is empty."""
    query = "query GetDoc($target: Int = 102) { resource(id: $target) { name } }"
    normalized = normalize_query(query, variables={})
    assert normalized is not None
    assert len(normalized["objects"]) == 1
    obj = normalized["objects"][0]
    assert obj["id"] == 102
    assert obj["type"] == "Resource"
    assert obj["path"] == "resource"


def test_normalize_query_explicit_variable_overrides_default_value():
    """Explicit variable value provided in request must take precedence over default value."""
    query = "query GetDoc($target: Int = 102) { resource(id: $target) { name } }"
    normalized = normalize_query(query, variables={"target": 101})
    assert normalized is not None
    assert len(normalized["objects"]) == 1
    obj = normalized["objects"][0]
    assert obj["id"] == 101
    assert obj["type"] == "Resource"


def test_gateway_blocks_bola_via_variable_default():
    """Alice attempting to access Bob's resource 102 via variable default must be blocked with HTTP 403."""
    alice_token = create_access_token(user_id=101, role="user")
    query = "query GetDoc($target: Int = 102) { resource(id: $target) { id name } }"
    res = client.post(
        "/graphql",
        json={"query": query, "variables": {}},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert detail["decision"] == "DENY"
    assert detail["user_id"] == 101
    assert detail["object_id"] == 102


def test_gateway_allows_legitimate_variable_default():
    """Alice accessing her own resource 101 via variable default must be allowed with HTTP 200."""
    alice_token = create_access_token(user_id=101, role="user")
    query = "query GetMyDoc($target: Int = 101) { resource(id: $target) { id name } }"
    res = client.post(
        "/graphql",
        json={"query": query, "variables": {}},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["resource"]["id"] == 101
    assert data["resource"]["name"] == "Alice's Secret Note"
