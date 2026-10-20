"""Automated tests: run with  python -m pytest -q  (no servers need to be running)."""
import json
import os
import threading

import pytest
from werkzeug.serving import make_server

from attacks.corpus import ATTACKS, BENIGN, VICTIM_CANARIES
from backend.app import app as backend_app, reset as backend_reset
from common.auth import SERVICE_TOKEN, issue_token, verify_token
from gateway.enforcer import Shield
from gateway.schema_analyzer import OwnershipModel, fetch_schema


POLICY = json.load(open(os.path.join(os.path.dirname(__file__), "..", "gateway", "policy.json")))
USERS = {"alice": ("1", "patient"), "bob": ("2", "patient"), "carol": ("3", "patient"), "admin": ("9", "admin")}


class NullStore:
    def log_request(self, **_): pass
    def log_alert(self, *_): pass


@pytest.fixture(scope="module")
def backend_url():
    server = make_server("127.0.0.1", 0, backend_app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module")
def model(backend_url):
    return OwnershipModel(fetch_schema(backend_url + "/graphql", SERVICE_TOKEN), POLICY)


def make_shield(model, backend_url, mode):
    return Shield(model, backend_url + "/graphql", {**POLICY, "mode": mode}, NullStore())


def send(shield, case_body, user):
    uid, role = USERS[user]
    tok = issue_token(uid, role)
    return shield.handle(case_body, {"uid": uid, "role": role}, f"Bearer {tok}")


def reset():
    with backend_reset.__globals__["app"].test_request_context():
        backend_reset()


# ---------------------------------------------------------------- unit tests
def test_token_roundtrip_and_forgery():
    t = issue_token("2", "patient")
    assert verify_token(t) == {"uid": "2", "role": "patient"}
    assert verify_token(t[:-2] + "00") is None


def test_schema_inference(model):
    assert model.owned_types == {"User": "id", "MedicalRecord": "patientId", "Invoice": "patientId"}
    assert model.lookup_fields == {"User": "user", "MedicalRecord": "record", "Invoice": "invoice"}
    assert model.id_arguments["mutation"] == {"updateRecord": {"id": "MedicalRecord"},
                                              "payInvoice": {"invoiceId": "Invoice"},
                                              "deleteInvoice": {"id": "Invoice"}}
    assert model.node_field == "node"


# ---------------------------------------------------------------- end-to-end
@pytest.mark.parametrize("case", ATTACKS, ids=[a["id"] for a in ATTACKS])
def test_attack_prevented_in_shield_mode(case, model, backend_url):
    reset()
    shield = make_shield(model, backend_url, "shield")
    result, _ = send(shield, case["body"], "bob")
    text = json.dumps(result)
    assert not any(c in text for c in VICTIM_CANARIES), text
    if "verify" in case:
        import requests
        d = requests.post(backend_url + "/graphql", json={"query": case["verify"]["query"]},
                          headers={"Authorization": f"Bearer {SERVICE_TOKEN}"}).json()["data"]
        assert not case["verify"]["tampered"](d)


@pytest.mark.parametrize("case", ATTACKS, ids=[a["id"] for a in ATTACKS])
def test_attack_succeeds_without_protection(case, model, backend_url):
    """Sanity check: every attack really is exploitable on the unprotected backend."""
    reset()
    result, _ = send(make_shield(model, backend_url, "off"), case["body"], "bob")
    leaked = any(c in json.dumps(result) for c in VICTIM_CANARIES)
    assert leaked or "verify" in case


@pytest.mark.parametrize("case", BENIGN, ids=[b["id"] for b in BENIGN])
def test_benign_allowed_in_shield_mode(case, model, backend_url):
    reset()
    result, status = send(make_shield(model, backend_url, "shield"), case["body"], case["user"])
    assert status == 200 and case["expect"] in json.dumps(result)


def test_injected_fields_are_stripped(model, backend_url):
    reset()
    result, _ = send(make_shield(model, backend_url, "shield"), {"query": '{ record(id: "201") { diagnosis } }'}, "bob")
    assert result == {"data": {"record": {"diagnosis": "CANARY-BOB-DIAG-201 Seasonal flu"}}}


def test_reserved_alias_rejected(model, backend_url):
    result, _ = send(make_shield(model, backend_url, "shield"), {"query": '{ record(id: "201") { __gs_owner: doctor } }'}, "bob")
    assert result["data"] is None


def test_depth_limit(model, backend_url):
    deep = "{ me { records { patient { records { patient { records { patient { records { patient { name } } } } } } } } } }"
    result, _ = send(make_shield(model, backend_url, "shield"), {"query": deep}, "bob")
    assert "depth" in result["errors"][0]["message"]


def test_enumeration_lockout(model, backend_url):
    reset()
    shield = make_shield(model, backend_url, "shield")
    a03 = next(a for a in ATTACKS if a["id"] == "A03")
    send(shield, a03["body"], "bob")                     # 5 foreign objects -> alert + lockout
    _, status = send(shield, {"query": "{ me { name } }"}, "bob")
    assert status == 429
