"""Second target: the same gateway in front of the main FastAPI application's /graphql-insecure endpoint.

Starts the FastAPI app with uvicorn in a subprocess on a throw-away, freshly seeded SQLite file, so the
project's own shield.db is never touched. Run with  python -m pytest -q  (no servers need to be running).
"""
import json
import os
import socket
import subprocess
import sys
import time

import pytest
import requests

from attacks.corpus_fastapi import ATTACKS, BENIGN, VICTIM_CANARIES
from attacks.runner import reset_backend, run_case, target_config
from common.auth import SERVICE_TOKEN, verify_jwt
from gateway.enforcer import Shield
from gateway.schema_analyzer import OwnershipModel, fetch_schema

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
POLICY = json.load(open(os.path.join(os.path.dirname(__file__), "..", "gateway", "policy_fastapi.json")))
TARGET = target_config(POLICY)
JWT_SECRET = "ownership-gateway-test-secret"


class NullStore:
    def log_request(self, **_): pass
    def log_alert(self, *_): pass


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def backend_url(tmp_path_factory):
    db = tmp_path_factory.mktemp("fastapi_target") / "target.db"
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{db.as_posix()}", "JWT_SECRET": JWT_SECRET, "ENVIRONMENT": "development"}
    subprocess.run([sys.executable, "-m", "app.seed"], cwd=REPO_ROOT, env=env, check=True, capture_output=True)
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
                            cwd=REPO_ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            if requests.get(url + "/health", timeout=1).ok:
                break
        except requests.RequestException:
            pass
        time.sleep(0.25)
    else:
        proc.kill()
        pytest.fail("FastAPI app did not start")
    yield url
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture(scope="module")
def model(backend_url):
    return OwnershipModel(fetch_schema(backend_url + TARGET["graphql_path"], SERVICE_TOKEN), POLICY)


def make_shield(model, backend_url, mode):
    return Shield(model, backend_url + TARGET["graphql_path"], {**POLICY, "mode": mode}, NullStore())


def login(backend_url, user):
    from attacks.corpus_fastapi import CREDENTIALS
    r = requests.post(backend_url + TARGET["login_path"], json={"username": user, "password": CREDENTIALS[user]}, timeout=5)
    token = r.json()[TARGET["token_field"]]
    claims = verify_jwt(token, JWT_SECRET.encode())
    assert claims is not None
    return claims, f"Bearer {token}"


def send(shield, backend_url, body, user):
    claims, header = login(backend_url, user)
    return shield.handle(body, claims, header)


# ---------------------------------------------------------------- inference on an unseen schema
def test_schema_inference_on_fastapi_app(model):
    assert model.owned_types == {"UserType": "id", "ResourceType": "ownerId"}
    assert model.inferred_by == {"UserType": "principal", "ResourceType": "heuristic"}
    assert model.lookup_fields == {"UserType": "user", "ResourceType": "resource"}
    assert model.id_arguments["mutation"] == {"updateResource": {"id": "ResourceType"},
                                              "deleteResource": {"id": "ResourceType"},
                                              "transferOwnership": {"id": "ResourceType"}}
    assert model.node_field is None


def test_app_jwt_maps_to_gateway_claims(backend_url):
    claims, _ = login(backend_url, "bob")
    assert claims == {"uid": "102", "role": "user"}
    assert verify_jwt(_.split(" ", 1)[1], b"wrong-secret") is None


# ---------------------------------------------------------------- end-to-end
@pytest.mark.parametrize("case", ATTACKS, ids=[a["id"] for a in ATTACKS])
def test_attack_succeeds_without_protection(case, model, backend_url):
    """Sanity check: every attack really is exploitable on the unprotected endpoint."""
    reset_backend(backend_url, TARGET)
    result, _ = send(make_shield(model, backend_url, "off"), backend_url, case["body"], "bob")
    leaked = any(c in json.dumps(result) for c in VICTIM_CANARIES)
    if "verify" in case:
        d = requests.post(backend_url + TARGET["graphql_path"], json={"query": case["verify"]["query"]}).json()["data"]
        assert case["verify"]["tampered"](d)
    else:
        assert leaked


@pytest.mark.parametrize("case", ATTACKS, ids=[a["id"] for a in ATTACKS])
def test_attack_prevented_in_shield_mode(case, model, backend_url):
    reset_backend(backend_url, TARGET)
    result, _ = send(make_shield(model, backend_url, "shield"), backend_url, case["body"], "bob")
    text = json.dumps(result)
    assert not any(c in text for c in VICTIM_CANARIES), text
    if "verify" in case:
        d = requests.post(backend_url + TARGET["graphql_path"], json={"query": case["verify"]["query"]}).json()["data"]
        assert not case["verify"]["tampered"](d)


@pytest.mark.parametrize("case", BENIGN, ids=[b["id"] for b in BENIGN])
def test_benign_allowed_in_shield_mode(case, model, backend_url):
    reset_backend(backend_url, TARGET)
    result, status = send(make_shield(model, backend_url, "shield"), backend_url, case["body"], case["user"])
    assert status == 200 and case["expect"] in json.dumps(result), result


def test_injected_fields_are_stripped(model, backend_url):
    reset_backend(backend_url, TARGET)
    result, _ = send(make_shield(model, backend_url, "shield"), backend_url, {"query": "{ resource(id: 102) { name } }"}, "bob")
    assert result == {"data": {"resource": {"name": "Bob's Financial Record"}}}


def test_runner_reports_the_same_through_http(model, backend_url):
    """run_case() against the backend directly uses the target's own GraphQL path and login."""
    reset_backend(backend_url, TARGET)
    f01 = next(a for a in ATTACKS if a["id"] == "F01")
    r = run_case(f01, backend_url, backend_url, target=TARGET)
    assert r["succeeded"] and "Alice's Secret Note" in r["leaked"]


def test_reset_seed_refuses_proxied_requests(backend_url):
    r = requests.post(backend_url + TARGET["reset_path"], headers={"X-Forwarded-For": "203.0.113.9"}, timeout=5)
    assert r.status_code == 403
