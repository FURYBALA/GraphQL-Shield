"""
End-to-end live proof for GraphQL Shield.

This script drives the REAL running application over HTTP (no direct policy-unit
calls) and asserts, for each scenario, that:

  1. the HTTP response reflects the deterministic policy decision, and
  2. the decision was persisted as an audit event retrievable via the ADMIN API.

Usage:
  1. Start a fresh database and server:
       del shield.db && python -m app.seed
       uvicorn app.main:app
  2. Run:
       python scripts/e2e_live_proof.py

Exit code 0 = all checks passed; 1 = at least one check failed.
"""

import json
import os
import sys

import httpx

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

BASE_URL = os.environ.get("SHIELD_BASE_URL", "http://localhost:8000")

_results = []


def _line(title=""):
    if title:
        print("\n" + "=" * 70)
        print(title)
        print("=" * 70)
    else:
        print("-" * 70)


def _record(name, ok, detail=""):
    _results.append((name, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" -> {detail}" if detail else ""))


def _gql(client, token, query):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    res = client.post("/graphql", json={"query": query}, headers=headers)
    try:
        body = res.json()
    except Exception:
        body = {"_raw": res.text}
    return res.status_code, body


def _is_denied(status, body):
    return status == 403 or ("errors" in body)


def main():
    _line("GRAPHQL SHIELD - END-TO-END LIVE HTTP PROOF")
    print(f"Target base URL: {BASE_URL}")

    client = httpx.Client(base_url=BASE_URL, timeout=15.0)

    _line("STEP 0 - Health check")
    try:
        health = client.get("/health")
    except httpx.ConnectError:
        print(f"FATAL: cannot connect to {BASE_URL}. Start the server first.")
        return 1
    _record("health endpoint reachable", health.status_code == 200, f"HTTP {health.status_code}")
    if health.status_code != 200:
        return 1

    _line("STEP 1 - Authenticate (real login over HTTP)")
    r = client.post("/api/v1/auth/login", json={"username": "balanilavan", "password": "balan123"})
    alice_token = r.json().get("access_token")
    _record("balanilavan (user 101) login", bool(alice_token), f"HTTP {r.status_code}")

    r = client.post("/api/v1/auth/login", json={"username": "kapilesh", "password": "kapilesh123"})
    admin_token = r.json().get("access_token")
    _record("kapilesh (admin 103) login", bool(admin_token), f"HTTP {r.status_code}")

    if not alice_token or not admin_token:
        return 1

    # ------------------------------------------------------------------ S1
    _line("STEP 2 - Scenario A: legitimate access (balanilavan -> own resource 101)")
    status, body = _gql(client, alice_token, "{ resource(id: 101) { id name } }")
    print(f"HTTP {status}: {json.dumps(body)}")
    ok_a = status == 200 and "errors" not in body and body.get("data", {}).get("resource", {}).get("id") == 101
    _record("legit access allowed (HTTP 200 + data)", ok_a, f"HTTP {status}")

    # ------------------------------------------------------------------ S2
    _line("STEP 3 - Scenario B: BOLA attack (balanilavan -> chinmayanand's resource 102)")
    status, body = _gql(client, alice_token, "{ resource(id: 102) { id name } }")
    print(f"HTTP {status}: {json.dumps(body)}")
    ok_b = _is_denied(status, body)
    _record("BOLA direct access denied", ok_b, f"HTTP {status}")

    # ------------------------------------------------------------------ S3
    _line("STEP 4 - Scenario C: nested BOLA (balanilavan -> nested resource 102)")
    status, body = _gql(client, alice_token, "{ user(id: 101) { username resource(id: 102) { name } } }")
    print(f"HTTP {status}: {json.dumps(body)}")
    ok_c = _is_denied(status, body)
    _record("nested BOLA denied", ok_c, f"HTTP {status}")

    # ------------------------------------------------------------------ S4
    _line("STEP 5 - Scenario D: invalid JWT")
    status, body = _gql(client, "invalid.token.123", "{ resource(id: 101) { id name } }")
    print(f"HTTP {status}: {json.dumps(body)}")
    ok_d = status in (401, 403)
    _record("invalid JWT rejected (401/403)", ok_d, f"HTTP {status}")

    # ------------------------------------------------------------------ Audit
    _line("STEP 6 - Persisted audit evidence (ADMIN API)")
    r = client.get("/api/v1/audit-logs", headers={"Authorization": f"Bearer {admin_token}"})
    logs = r.json().get("logs", []) if r.status_code == 200 else []
    _record("audit-logs endpoint accessible to admin", r.status_code == 200, f"HTTP {r.status_code}, {len(logs)} rows")

    allow_101 = any(l.get("decision") == "ALLOW" and l.get("object_id") == 101 for l in logs)
    deny_mismatch = any(l.get("decision") == "DENY" and l.get("reason") == "OWNERSHIP_MISMATCH" for l in logs)
    deny_nested = any(l.get("decision") == "DENY" and l.get("reason") == "NESTED_AUTHORIZATION_VIOLATION" for l in logs)

    _record("persisted ALLOW for own resource 101", allow_101)
    _record("persisted DENY / OWNERSHIP_MISMATCH", deny_mismatch)
    _record("persisted DENY / NESTED_AUTHORIZATION_VIOLATION", deny_nested)

    print("\nPersisted audit rows (most recent first):")
    for l in logs[:10]:
        print(
            "  user={uid} obj={oid} decision={dec} reason={rsn} risk={lvl}".format(
                uid=l.get("user_id"),
                oid=l.get("object_id"),
                dec=l.get("decision"),
                rsn=l.get("reason"),
                lvl=l.get("risk_level"),
            )
        )

    # ------------------------------------------------------------------ Summary
    _line("SUMMARY")
    passed = sum(1 for _, ok, _ in _results if ok)
    total = len(_results)
    for name, ok, detail in _results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"\n{passed}/{total} checks passed")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
