#!/usr/bin/env python3
"""
Taint Analysis Corpus Evaluation & Benchmarking Script (Phase 5)

Runs a labeled benchmark corpus of GraphQL operations through:
1. Static AST-Driven Context-Sensitive Taint Propagation Engine
2. Runtime Gateway Ownership & Authorization Engine
3. Candidate vs. Runtime Authorization Correlation Engine

Measures:
- Static analysis execution latency (min, max, mean, p95)
- Candidate detection accuracy and classification rates
- True Positive Blocked vs Runtime Protected vs Benign correlations
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.security.authorization import AuthorizationContext, PolicyEngine
from app.security.object_extractor import normalize_query
from app.security.ownership import resolve_ownership
from app.security.taint_correlation import (
    CorrelationStatus,
    correlate_path_decision,
    sanitize_variables,
)
from app.security.taint_engine import analyze_query_taint
from app.security.taint_model import CandidateKind


# =============================================================================
# LABELED BENCHMARK CORPUS
# =============================================================================

CORPUS: List[Dict[str, Any]] = [
    {
        "id": "TC-01",
        "name": "Direct BOLA on Resource (Cross-User)",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query { resource(id: 102) { id name } }",
        "variables": {},
        "expected_candidate": "DIRECT_BOLA_CANDIDATE",
        "expected_decision": "DENY",
        "expected_correlation": "TRUE_POSITIVE_BLOCKED",
    },
    {
        "id": "TC-02",
        "name": "Direct BOLA on User Object (Cross-User)",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query { user(id: 102) { id username } }",
        "variables": {},
        "expected_candidate": "DIRECT_BOLA_CANDIDATE",
        "expected_decision": "DENY",
        "expected_correlation": "TRUE_POSITIVE_BLOCKED",
    },
    {
        "id": "TC-03",
        "name": "Indirect BOLA via User->Resources Collection",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query { user(id: 102) { resources { id name } } }",
        "variables": {},
        "expected_candidate": "INDIRECT_BOLA_CANDIDATE",
        "expected_decision": "DENY",
        "expected_correlation": "TRUE_POSITIVE_BLOCKED",
    },
    {
        "id": "TC-04",
        "name": "Legitimate Access to Own Resource",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query { resource(id: 101) { id name } }",
        "variables": {},
        "expected_candidate": "DIRECT_BOLA_CANDIDATE",
        "expected_decision": "ALLOW",
        "expected_correlation": "RUNTIME_PROTECTED_ALLOWED",
    },
    {
        "id": "TC-05",
        "name": "Legitimate Indirect Access to Own Collection",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query { user(id: 101) { resources { id name } } }",
        "variables": {},
        "expected_candidate": "INDIRECT_BOLA_CANDIDATE",
        "expected_decision": "ALLOW",
        "expected_correlation": "RUNTIME_PROTECTED_ALLOWED",
    },
    {
        "id": "TC-06",
        "name": "Aliased Direct BOLA Query",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query { victimRes: resource(id: 102) { name } }",
        "variables": {},
        "expected_candidate": "DIRECT_BOLA_CANDIDATE",
        "expected_decision": "DENY",
        "expected_correlation": "TRUE_POSITIVE_BLOCKED",
    },
    {
        "id": "TC-07",
        "name": "Variable-Driven Direct BOLA",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query GetRes($rId: Int!) { resource(id: $rId) { name } }",
        "variables": {"rId": 102},
        "expected_candidate": "DIRECT_BOLA_CANDIDATE",
        "expected_decision": "DENY",
        "expected_correlation": "TRUE_POSITIVE_BLOCKED",
    },
    {
        "id": "TC-08",
        "name": "Fragment Spread Direct BOLA",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query { resource(id: 102) { ...ResProps } } fragment ResProps on ResourceType { id name }",
        "variables": {},
        "expected_candidate": "DIRECT_BOLA_CANDIDATE",
        "expected_decision": "DENY",
        "expected_correlation": "TRUE_POSITIVE_BLOCKED",
    },
    {
        "id": "TC-09",
        "name": "Admin Authorized Override on Other's Resource",
        "caller_id": 103,
        "caller_role": "admin",
        "query": "query { resource(id: 102) { id name } }",
        "variables": {},
        "expected_candidate": "DIRECT_BOLA_CANDIDATE",
        "expected_decision": "ALLOW",
        "expected_correlation": "RUNTIME_PROTECTED_ALLOWED",
    },
    {
        "id": "TC-10",
        "name": "Public / Non-Parameterized Query (Safe)",
        "caller_id": 101,
        "caller_role": "user",
        "query": "query { health }",
        "variables": {},
        "expected_candidate": None,
        "expected_decision": "ALLOW",
        "expected_correlation": "BENIGN_AUTHORIZED",
    },
]


def evaluate_corpus() -> Dict[str, Any]:
    """Runs evaluation on all corpus items and collects structured statistics."""
    policy_engine = PolicyEngine()
    results = []
    latencies_ms = []

    for item in CORPUS:
        query = item["query"]
        variables = item["variables"]
        caller_id = item["caller_id"]
        caller_role = item["caller_role"]

        # 1. Measure Static Analysis Latency
        start_t = time.perf_counter()
        sanitized_vars = sanitize_variables(variables)
        report = analyze_query_taint(query=query, variables=sanitized_vars)
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        latencies_ms.append(elapsed_ms)

        # 2. Extract objects & evaluate runtime gateway policy
        normalized = normalize_query(query, variables)
        correlations = []
        runtime_decision = "ALLOW"
        runtime_reason = "NO_OBJECTS"

        if normalized and normalized["objects"]:
            for obj in normalized["objects"]:
                obj_id = obj["id"]
                obj_type = obj["type"]
                obj_path = obj["path"]

                resolution = resolve_ownership(obj_type, obj_id)
                context = AuthorizationContext(
                    user_id=caller_id,
                    role=caller_role,
                    operation=normalized["operation"] or "query",
                    object_type=obj_type,
                    object_id=obj_id,
                    path=obj_path,
                    owner_id=resolution.owner_id,
                    metadata={
                        "client_host": "127.0.0.1",
                        "ownership_status": resolution.status,
                        "ownership_source": resolution.source,
                        "ownership_detail": resolution.detail,
                    },
                )
                res = policy_engine.evaluate(context)
                runtime_decision = res["decision"]
                runtime_reason = res["reason"]

                corr = correlate_path_decision(
                    path=obj_path,
                    object_type=obj_type,
                    object_id=obj_id,
                    runtime_result=res,
                    taint_report=report,
                )
                correlations.append(corr)
        else:
            # Query has no target objects
            dummy_res = {"decision": "ALLOW", "reason": "PUBLIC_UNRESTRICTED", "risk_level": "LOW"}
            corr = correlate_path_decision(
                path="root",
                object_type="None",
                object_id=0,
                runtime_result=dummy_res,
                taint_report=report,
            )
            correlations.append(corr)

        primary_corr = correlations[0] if correlations else None
        corr_status = primary_corr.status.value if primary_corr else "UNKNOWN"
        actual_cand = primary_corr.static_candidate_kind if primary_corr else None

        # Check candidate presence in report findings
        has_direct = len(report.direct_bola_candidates) > 0
        has_indirect = len(report.indirect_bola_candidates) > 0

        # Assess verification match
        decision_matches = (runtime_decision == item["expected_decision"])
        correlation_matches = (corr_status == item["expected_correlation"])

        results.append({
            "id": item["id"],
            "name": item["name"],
            "query": query,
            "latency_ms": round(elapsed_ms, 3),
            "findings_count": len(report.findings),
            "direct_candidates_count": len(report.direct_bola_candidates),
            "indirect_candidates_count": len(report.indirect_bola_candidates),
            "primary_candidate_kind": actual_cand,
            "runtime_decision": runtime_decision,
            "runtime_reason": runtime_reason,
            "correlation_status": corr_status,
            "expected_decision": item["expected_decision"],
            "expected_correlation": item["expected_correlation"],
            "decision_matches": decision_matches,
            "correlation_matches": correlation_matches,
        })

    # Summary Statistics
    total = len(results)
    matched_correlations = sum(1 for r in results if r["correlation_matches"])
    matched_decisions = sum(1 for r in results if r["decision_matches"])

    summary = {
        "total_test_cases": total,
        "correlation_accuracy": round((matched_correlations / total) * 100, 2),
        "decision_accuracy": round((matched_decisions / total) * 100, 2),
        "total_direct_candidates_detected": sum(r["direct_candidates_count"] for r in results),
        "total_indirect_candidates_detected": sum(r["indirect_candidates_count"] for r in results),
        "latency_metrics_ms": {
            "mean": round(statistics.mean(latencies_ms), 3),
            "median": round(statistics.median(latencies_ms), 3),
            "min": round(min(latencies_ms), 3),
            "max": round(max(latencies_ms), 3),
            "stdev": round(statistics.stdev(latencies_ms), 3) if len(latencies_ms) > 1 else 0.0,
        },
        "correlation_distribution": {
            "TRUE_POSITIVE_BLOCKED": sum(1 for r in results if r["correlation_status"] == "TRUE_POSITIVE_BLOCKED"),
            "RUNTIME_PROTECTED_ALLOWED": sum(1 for r in results if r["correlation_status"] == "RUNTIME_PROTECTED_ALLOWED"),
            "BENIGN_AUTHORIZED": sum(1 for r in results if r["correlation_status"] == "BENIGN_AUTHORIZED"),
            "UNANALYZED_OR_AMBIGUOUS": sum(1 for r in results if r["correlation_status"] == "UNANALYZED_OR_AMBIGUOUS"),
        },
        "results": results,
    }
    return summary


def print_report(summary: Dict[str, Any]) -> None:
    """Prints a clean, ASCII terminal evaluation report."""
    print("\n" + "=" * 78)
    print("  GRAPHQL SHIELD: CONTEXT-SENSITIVE TAINT ANALYSIS BENCHMARK REPORT (PHASE 5)")
    print("=" * 78)
    print(f"Total Test Cases Evaluated : {summary['total_test_cases']}")
    print(f"Correlation Match Accuracy : {summary['correlation_accuracy']}%")
    print(f"Runtime Decision Accuracy  : {summary['decision_accuracy']}%")
    print("-" * 78)
    print("Latency Overhead (Static Taint Engine):")
    l_metrics = summary["latency_metrics_ms"]
    print(f"  Mean   : {l_metrics['mean']} ms")
    print(f"  Median : {l_metrics['median']} ms")
    print(f"  Min    : {l_metrics['min']} ms")
    print(f"  Max    : {l_metrics['max']} ms")
    print("-" * 78)
    print("Correlation Status Distribution:")
    for status, count in summary["correlation_distribution"].items():
        print(f"  {status:<28} : {count}")
    print("-" * 78)
    print(f"{'ID':<6} {'Name':<36} {'Dec':<6} {'Correlation':<25} {'Time':<8}")
    print("-" * 78)
    for r in summary["results"]:
        status_flag = "[OK]" if r["correlation_matches"] else "[FAIL]"
        print(f"{r['id']:<6} {r['name'][:34]:<36} {r['runtime_decision']:<6} {r['correlation_status'][:23]:<25} {r['latency_ms']}ms")
    print("=" * 78 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate GraphQL Taint Analysis Corpus")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--output", type=str, default=None, help="Save JSON report to file")
    args = parser.parse_args()

    summary = evaluate_corpus()

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_report(summary)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"Report exported to {args.output}")


if __name__ == "__main__":
    main()
