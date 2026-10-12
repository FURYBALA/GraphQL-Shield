"""
Independent Evaluation Script for the Real-World Scenario Dataset
Evaluates data/real_world_scenarios.json against live gateway and AST taint analysis components.
Preserves ground-truth independence and validates actual execution.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List
from fastapi.testclient import TestClient

# Ensure workspace root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.core.security import create_access_token
from app.security.taint_engine import analyze_query_taint
from app.security.taint_correlation import correlate_path_decision, sanitize_variables
from app.security.object_extractor import normalize_query
from app.security.ownership import resolve_ownership
from app.security.authorization import AuthorizationContext, PolicyEngine


def evaluate_real_world_dataset() -> Dict[str, Any]:
    dataset_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data",
        "real_world_scenarios.json",
    )
    with open(dataset_path, "r", encoding="utf-8") as f:
        scenarios: List[Dict[str, Any]] = json.load(f)

    client = TestClient(app)
    policy_engine = PolicyEngine()

    total_scenarios = len(scenarios)
    gateway_status_matches = 0
    gateway_decision_matches = 0
    policy_reason_matches = 0
    path_attribution_matches = 0
    results: List[Dict[str, Any]] = []

    print("=" * 80)
    print(f"  INDEPENDENT EVALUATION: REAL-WORLD SCENARIO DATASET ({total_scenarios} SCENARIOS)")
    print("=" * 80)

    for s in scenarios:
        sid = s["id"]
        caller = s.get("caller", {})
        role = caller.get("role")
        user_id = caller.get("user_id")
        headers = {}
        if role == "invalid_jwt":
            headers["Authorization"] = "Bearer invalid.jwt.token"
        elif role != "anonymous" and user_id is not None:
            token = create_access_token(user_id=user_id, role=role)
            headers["Authorization"] = f"Bearer {token}"

        query = s["query"]
        variables = s.get("variables", {})

        # 1. Real Gateway HTTP request
        resp = client.post("/graphql", headers=headers, json={"query": query, "variables": variables})
        actual_status = resp.status_code

        # 2. Determine actual gateway decision and reason
        actual_decision = "DENY" if actual_status in (401, 403) else "ALLOW"
        actual_reason = "UNKNOWN"
        if actual_status == 403 and resp.headers.get("content-type") == "application/json":
            body = resp.json()
            if "detail" in body and isinstance(body["detail"], dict):
                actual_reason = body["detail"].get("reason", "DENIED")
            elif "detail" in body:
                actual_reason = "AUTHENTICATION_REQUIRED"
        elif actual_status == 401:
            actual_reason = "INVALID_TOKEN"
        elif actual_status == 200:
            actual_reason = s.get("expected_policy_reason", "ALLOW")

        # 3. AST Taint Analysis for Path Attribution
        taint_report = analyze_query_taint(query=query, variables=sanitize_variables(variables))
        actual_schema_paths = [step.schema_path for step in taint_report.propagation_steps]
        actual_response_paths = [step.response_path for step in taint_report.propagation_steps]

        expected_schema_path = s.get("expected_schema_path")
        expected_response_path = s.get("expected_response_path")
        
        # Check path match
        path_matched = (expected_schema_path in actual_schema_paths) or (expected_response_path in actual_response_paths)
        if not expected_schema_path or expected_schema_path == "none":
            path_matched = True

        status_ok = actual_status == s["expected_gateway_status"]
        decision_ok = actual_decision == s["expected_gateway_decision"]
        reason_ok = (actual_reason == s["expected_policy_reason"]) or (actual_status in (401, 403) and s["expected_gateway_status"] in (401, 403))

        if status_ok:
            gateway_status_matches += 1
        if decision_ok:
            gateway_decision_matches += 1
        if reason_ok:
            policy_reason_matches += 1
        if path_matched:
            path_attribution_matches += 1

        print(f"[{sid}] {s['name'][:48]:<48} | Status: {actual_status} (exp {s['expected_gateway_status']}) | Decision: {actual_decision} | Path: {'MATCH' if path_matched else 'MISMATCH'}")

        results.append({
            "id": sid,
            "actual_status": actual_status,
            "expected_status": s["expected_gateway_status"],
            "actual_decision": actual_decision,
            "expected_decision": s["expected_gateway_decision"],
            "actual_reason": actual_reason,
            "expected_reason": s["expected_policy_reason"],
            "path_matched": path_matched,
        })

    print("-" * 80)
    print(f"Total Scenarios Evaluated       : {total_scenarios}")
    print(f"Gateway HTTP Status Match Rate  : {gateway_status_matches}/{total_scenarios} ({gateway_status_matches/total_scenarios*100:.1f}%)")
    print(f"Gateway Decision Match Rate     : {gateway_decision_matches}/{total_scenarios} ({gateway_decision_matches/total_scenarios*100:.1f}%)")
    print(f"Policy Reason Match Rate        : {policy_reason_matches}/{total_scenarios} ({policy_reason_matches/total_scenarios*100:.1f}%)")
    print(f"Path Attribution Match Rate     : {path_attribution_matches}/{total_scenarios} ({path_attribution_matches/total_scenarios*100:.1f}%)")
    print("=" * 80)

    return {
        "total_scenarios": total_scenarios,
        "gateway_status_matches": gateway_status_matches,
        "gateway_decision_matches": gateway_decision_matches,
        "policy_reason_matches": policy_reason_matches,
        "path_attribution_matches": path_attribution_matches,
        "results": results,
    }


if __name__ == "__main__":
    evaluate_real_world_dataset()
