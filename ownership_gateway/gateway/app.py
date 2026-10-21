"""GraphQLShield gateway: a reverse proxy that sits in front of the GraphQL backend.

Run:  python -m gateway.app       (listens on :5000; backend must be on :5001)
      GS_POLICY=policy_fastapi.json GS_BACKEND=http://127.0.0.1:8000 GS_JWT_SECRET=<app JWT_SECRET> python -m gateway.app
                                    (protects the main FastAPI app's /graphql-insecure endpoint instead of ClinicHub)
  POST /graphql          protected GraphQL endpoint (clients talk to this instead of the backend)
  POST /login            passthrough to the backend login
  GET  /dashboard        security dashboard + attack lab
  GET  /api/...          JSON used by the dashboard and the evaluator
"""
import json
import os
import time

import requests
from flask import Flask, jsonify, render_template, request

from attacks.runner import load_corpus, reset_backend, run_case, target_config
from common.auth import SERVICE_TOKEN, claims_from_header
from .enforcer import MODES, Shield
from .schema_analyzer import OwnershipModel, fetch_schema
from .store import Store

BACKEND = os.environ.get("GS_BACKEND", "http://127.0.0.1:5001")
HERE = os.path.dirname(__file__)
GATEWAY_URL = f"http://127.0.0.1:{os.environ.get('GS_PORT', '5000')}"

app = Flask(__name__)
policy = json.load(open(os.path.join(HERE, os.environ.get("GS_POLICY", "policy.json"))))
target = target_config(policy)
corpus = load_corpus(target)
ATTACKS, BENIGN = corpus.ATTACKS, corpus.BENIGN
store = Store(os.environ.get("GS_DB", os.path.join(HERE, "events.db")))
shield = None


def init_shield():
    """Introspect the backend (retrying while it starts) and build the ownership model."""
    global shield
    for _ in range(30):
        try:
            schema = fetch_schema(BACKEND + target["graphql_path"], SERVICE_TOKEN)
            break
        except requests.RequestException:
            time.sleep(0.5)
    else:
        raise SystemExit("backend not reachable at " + BACKEND)
    shield = Shield(OwnershipModel(schema, policy), BACKEND + target["graphql_path"], policy, store)


@app.post("/graphql")
def graphql_proxy():
    auth = request.headers.get("Authorization")
    claims = claims_from_header(auth)
    if not claims:
        return jsonify({"errors": [{"message": "Unauthenticated"}]}), 401
    result, status = shield.handle(request.get_json(force=True), claims, auth, request.headers.get("X-GS-Test-Case"))
    return jsonify(result), status


@app.post("/login")
def login():
    r = requests.post(BACKEND + target["login_path"], json=request.get_json(force=True), timeout=5)
    body = r.json()
    if isinstance(body, dict) and target["token_field"] in body:
        body.setdefault("token", body[target["token_field"]])  # the dashboard always reads "token"
    return jsonify(body), r.status_code


@app.get("/")
@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.get("/api/stats")
def api_stats():
    return jsonify({**store.stats(), "mode": shield.mode, "modes": MODES,
                    "locked_users": [u for u, t in shield.locked_until.items() if t > time.time()]})


@app.get("/api/logs")
def api_logs():
    return jsonify(store.recent(int(request.args.get("limit", 50))))


@app.get("/api/alerts")
def api_alerts():
    return jsonify(store.alerts())


@app.get("/api/target")
def api_target():
    return jsonify({"name": target["name"], "backend": BACKEND, "attacker": getattr(corpus, "ATTACKER", "bob"),
                    "credentials": corpus.CREDENTIALS, "console": getattr(corpus, "CONSOLE", {})})


@app.get("/api/schema-model")
def api_schema_model():
    return jsonify(shield.model.summary())


@app.get("/api/results")
def api_results():
    path = os.path.join(HERE, "..", "eval", target["results_dir"], "results.json")
    if not os.path.exists(path):
        return jsonify({"error": "run  python -m eval.run_eval  first"}), 404
    return jsonify(json.load(open(path)))


@app.post("/api/mode")
def api_mode():
    mode = request.get_json(force=True).get("mode")
    if mode not in MODES:
        return jsonify({"error": f"mode must be one of {MODES}"}), 400
    shield.mode = mode
    shield.reset_detector()
    return jsonify({"mode": mode})


@app.post("/api/reset")
def api_reset():
    """Restore backend seed data, forget lockouts/cache; optionally clear logs."""
    reset_backend(BACKEND, target)
    shield.reset_detector()
    shield.owner_cache.clear()
    if request.args.get("logs") == "1":
        store.clear()
    return jsonify({"ok": True})


# ------------------------------------------------------------------ attack lab
@app.get("/api/cases")
def api_cases():
    strip = lambda c: {k: v for k, v in c.items() if k != "verify"}
    return jsonify({"attacks": [strip(c) for c in ATTACKS], "benign": [strip(c) for c in BENIGN]})


@app.post("/api/attack/<case_id>")
def api_attack(case_id):
    case = next((c for c in ATTACKS if c["id"] == case_id), None)
    if case is None:
        return jsonify({"error": "unknown case"}), 404
    api_reset()
    direct = run_case(case, BACKEND, BACKEND, target=target)
    reset_backend(BACKEND, target)  # undo any damage the direct (unprotected) run did
    gateway = run_case(case, GATEWAY_URL, BACKEND, target=target)
    for r in (direct, gateway):
        r.pop("text")
    return jsonify({"case": {k: v for k, v in case.items() if k != "verify"}, "mode": shield.mode,
                    "direct": direct, "gateway": gateway})


if __name__ == "__main__":
    init_shield()
    app.run(port=int(os.environ.get("GS_PORT", 5000)), threaded=True)
