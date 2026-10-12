#!/usr/bin/env python3
"""
CI/CD GraphQL Query Security Linter CLI
----------------------------------------
Statically audits GraphQL queries before deployment to detect:
1. Direct Broken Object-Level Authorization (BOLA) candidates
2. Indirect Nested BOLA candidates
3. Field alias masking / cloaking
4. Dangerous AST depth and cyclic fragment expansions
5. Unmitigated sensitive sink exposures

Usage:
    python scripts/lint_graphql_queries.py --query "query { document(id: 10) { secretData } }"
    python scripts/lint_graphql_queries.py --file path/to/query.graphql --fail-on-risk
    python scripts/lint_graphql_queries.py --dir path/to/queries --json
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any, Dict, List, Optional

# Ensure workspace root is in path
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from app.security.object_extractor import normalize_query
from app.security.taint_engine import analyze_query_taint, QueryAnalysisReport


def lint_query(
    query_str: str,
    source_name: str = "inline_query",
    max_depth_threshold: int = 15,
) -> Dict[str, Any]:
    """
    Statically analyzes a single GraphQL query for security risks and vulnerabilities.
    """
    result: Dict[str, Any] = {
        "source": source_name,
        "is_valid": False,
        "has_cycles": False,
        "max_depth": 0,
        "depth_exceeded": False,
        "direct_bola_candidates": [],
        "indirect_bola_candidates": [],
        "alias_masking_detected": [],
        "risk_level": "LOW",
        "passed": True,
        "errors": [],
    }

    # 1. AST Structural & Fragment Validation
    try:
        norm_result = normalize_query(query_str)
    except Exception as exc:
        result["errors"].append(f"AST Parsing / Normalization Error: {exc}")
        result["passed"] = False
        result["risk_level"] = "HIGH"
        return result

    result["is_valid"] = True

    # 2. Context-Sensitive AST Taint Engine Analysis
    try:
        report: QueryAnalysisReport = analyze_query_taint(query=query_str)
    except Exception as exc:
        result["errors"].append(f"Taint Engine Error: {exc}")
        result["passed"] = False
        result["risk_level"] = "HIGH"
        return result

    if not report.is_valid_query:
        result["is_valid"] = False
        result["errors"].append(report.error_message or "Invalid GraphQL query syntax.")
        result["passed"] = False
        result["risk_level"] = "HIGH"
        return result

    result["has_cycles"] = report.has_cycles
    result["max_depth"] = report.max_depth_reached

    if report.max_depth_reached > max_depth_threshold:
        result["depth_exceeded"] = True
        result["errors"].append(
            f"Query depth ({report.max_depth_reached}) exceeds safe threshold ({max_depth_threshold})."
        )
        result["passed"] = False
        result["risk_level"] = "MEDIUM"

    if report.has_cycles:
        result["errors"].append("Query contains cyclic fragment expansions or circular type recursion.")
        result["passed"] = False
        result["risk_level"] = "HIGH"

    # 3. Check for Direct & Indirect BOLA candidates
    for cand in report.direct_bola_candidates:
        result["direct_bola_candidates"].append({
            "finding_id": cand.finding_id,
            "schema_path": cand.schema_path,
            "response_path": cand.response_path,
            "sink_type": cand.sensitive_sink.target_type if cand.sensitive_sink else "Unknown",
            "risk_assessment": cand.risk_assessment,
            "explanation": cand.explanation,
        })
        result["passed"] = False
        result["risk_level"] = "HIGH"

    for cand in report.indirect_bola_candidates:
        result["indirect_bola_candidates"].append({
            "finding_id": cand.finding_id,
            "schema_path": cand.schema_path,
            "response_path": cand.response_path,
            "sink_type": cand.sensitive_sink.target_type if cand.sensitive_sink else "Unknown",
            "risk_assessment": cand.risk_assessment,
            "explanation": cand.explanation,
        })
        result["passed"] = False
        if result["risk_level"] != "HIGH":
            result["risk_level"] = "MEDIUM"

    # 4. Check for Alias Masking
    for step in report.propagation_steps:
        if step.field_name != step.response_name:
            result["alias_masking_detected"].append({
                "canonical_schema_path": step.schema_path,
                "client_response_path": step.response_path,
                "field_name": step.field_name,
                "response_name": step.response_name,
            })

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline CI/CD GraphQL Query Security Linter for BOLA and AST anomalies."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--query", "-q", type=str, help="Raw GraphQL query string to analyze.")
    group.add_argument("--file", "-f", type=str, help="Path to a .graphql file to analyze.")
    group.add_argument("--dir", "-d", type=str, help="Directory containing .graphql files to analyze.")

    parser.add_argument(
        "--max-depth",
        type=int,
        default=15,
        help="Maximum allowed AST query depth (default: 15).",
    )
    parser.add_argument(
        "--fail-on-risk",
        action="store_true",
        help="Exit with non-zero code if any security risk or BOLA candidate is detected.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format.",
    )

    args = parser.parse_args()

    queries_to_lint: List[tuple[str, str]] = []

    if args.query:
        queries_to_lint.append(("inline_query", args.query))
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 1
        with open(args.file, "r", encoding="utf-8") as f:
            queries_to_lint.append((args.file, f.read()))
    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"Error: Directory not found: {args.dir}", file=sys.stderr)
            return 1
        patterns = [os.path.join(args.dir, "**", "*.graphql"), os.path.join(args.dir, "**", "*.gql")]
        found_files = []
        for p in patterns:
            found_files.extend(glob.glob(p, recursive=True))
        if not found_files:
            print(f"No .graphql or .gql files found in {args.dir}.", file=sys.stderr)
            return 0
        for fpath in found_files:
            with open(fpath, "r", encoding="utf-8") as f:
                queries_to_lint.append((fpath, f.read()))

    all_results: List[Dict[str, Any]] = []
    has_any_failure = False

    for source_name, query_str in queries_to_lint:
        res = lint_query(query_str, source_name=source_name, max_depth_threshold=args.max_depth)
        all_results.append(res)
        if not res["passed"]:
            has_any_failure = True

    if args.json:
        print(json.dumps({"results": all_results, "total": len(all_results), "failed": has_any_failure}, indent=2))
    else:
        print("=" * 80)
        print("           GRAPHQL SECURITY LINTER AUDIT REPORT")
        print("=" * 80)
        for res in all_results:
            status = "PASSED" if res["passed"] else f"FAILED ({res['risk_level']} RISK)"
            print(f"\n[FILE/SOURCE]: {res['source']}")
            print(f"  Status:       {status}")
            print(f"  Valid AST:    {res['is_valid']}")
            print(f"  Max Depth:    {res['max_depth']}")
            print(f"  Cycle Check:  {'CYCLES DETECTED' if res['has_cycles'] else 'Clean'}")

            if res["direct_bola_candidates"]:
                print(f"  Direct BOLA Candidates ({len(res['direct_bola_candidates'])}):")
                for c in res["direct_bola_candidates"]:
                    print(f"    - Schema Path:   {c['schema_path']}")
                    print(f"      Response Path: {c['response_path']}")
                    print(f"      Sensitive Sink:{c['sink_type']}")
                    print(f"      Rationale:     {c['explanation']}")

            if res["indirect_bola_candidates"]:
                print(f"  Indirect BOLA Candidates ({len(res['indirect_bola_candidates'])}):")
                for c in res["indirect_bola_candidates"]:
                    print(f"    - Schema Path:   {c['schema_path']}")
                    print(f"      Response Path: {c['response_path']}")
                    print(f"      Sensitive Sink:{c['sink_type']}")
                    print(f"      Rationale:     {c['explanation']}")

            if res["alias_masking_detected"]:
                print(f"  Alias Masking ({len(res['alias_masking_detected'])}):")
                for a in res["alias_masking_detected"]:
                    print(f"    - Alias: {a['response_name']} -> Field: {a['field_name']} (Path: {a['canonical_schema_path']})")

            if res["errors"]:
                print(f"  Violations / Errors:")
                for err in res["errors"]:
                    print(f"    ! {err}")

        print("\n" + "=" * 80)
        total_count = len(all_results)
        failed_count = sum(1 for r in all_results if not r["passed"])
        print(f"Audited: {total_count} operations | Passed: {total_count - failed_count} | Flagged: {failed_count}")
        print("=" * 80)

    if args.fail_on_risk and has_any_failure:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
