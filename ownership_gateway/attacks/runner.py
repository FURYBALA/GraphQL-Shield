"""Sends corpus cases to the backend (unprotected) or the gateway and judges the outcome.

A *target* describes the protected backend (see "target" in gateway/policy*.json). The default is
ClinicHub; gateway/policy_fastapi.json points the same gateway at the main FastAPI application.
"""
import importlib
import time

import requests

from common.auth import SERVICE_TOKEN

DEFAULT_TARGET = {
    "name": "ClinicHub (deliberately vulnerable demo backend)",
    "graphql_path": "/graphql",      # backend GraphQL endpoint (the gateway itself always serves /graphql)
    "login_path": "/login",
    "token_field": "token",
    "reset_path": "/reset",          # null when the backend cannot restore its seed data
    "corpus": "attacks.corpus",
    "results_dir": "results",
}

_tokens = {}


def target_config(policy):
    return {**DEFAULT_TARGET, **policy.get("target", {})}


def load_corpus(target=DEFAULT_TARGET):
    return importlib.import_module(target["corpus"])


def reset_backend(backend, target=DEFAULT_TARGET):
    if target.get("reset_path"):
        requests.post(backend + target["reset_path"], timeout=5)


def token_for(backend, user, target=DEFAULT_TARGET):
    key = (backend, user)
    if key not in _tokens:
        creds = load_corpus(target).CREDENTIALS
        r = requests.post(backend + target["login_path"], json={"username": user, "password": creds[user]}, timeout=5)
        _tokens[key] = r.json()[target["token_field"]]
    return _tokens[key]


def run_case(case, url, backend, user=None, target=DEFAULT_TARGET):
    corpus = load_corpus(target)
    user = user or getattr(corpus, "ATTACKER", "bob")
    endpoint = url + (target["graphql_path"] if url == backend else "/graphql")
    t0 = time.perf_counter()
    r = requests.post(endpoint, json=case["body"], timeout=10,
                      headers={"Authorization": f"Bearer {token_for(backend, user, target)}", "X-GS-Test-Case": case["id"]})
    latency = (time.perf_counter() - t0) * 1000
    leaked = [c for c in corpus.VICTIM_CANARIES if c in r.text]
    tampered = False
    if "verify" in case:
        v = requests.post(backend + target["graphql_path"], json={"query": case["verify"]["query"]},
                          headers={"Authorization": f"Bearer {SERVICE_TOKEN}"}, timeout=5).json()
        tampered = case["verify"]["tampered"](v["data"])
    try:
        body = r.json()
    except ValueError:
        body = r.text
    return {"response": body, "status": r.status_code, "text": r.text, "leaked": leaked, "tampered": tampered,
            "succeeded": bool(leaked or tampered), "latency_ms": round(latency, 2)}
