"""
CLI Query Taint Analyzer

Analyzes an incoming GraphQL query for direct and indirect BOLA candidate paths
using the AST-driven context-sensitive taint propagation engine.
"""

import argparse
import json
import os
import sys

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.security.taint_engine import analyze_query_taint


def run_cli():
    parser = argparse.ArgumentParser(description="Analyze a GraphQL query for BOLA taint propagation paths.")
    parser.add_argument("--query", "-q", type=str, help="GraphQL query string to analyze.")
    parser.add_argument("--file", "-f", type=str, help="Path to file containing GraphQL query.")
    parser.add_argument("--variables", "-v", type=str, default="{}", help="JSON string of variables.")
    parser.add_argument("--output", "-o", type=str, help="Path to write JSON analysis report.")

    args = parser.parse_args()

    query_str = args.query
    if not query_str and args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            query_str = f.read()

    if not query_str:
        # Default representative query showing direct and indirect navigation
        query_str = """
        query DemoAnalysis($userId: Int!) {
          myUser: user(id: $userId) {
            username
            resources {
              id
              name
            }
          }
        }
        """
        variables = {"userId": 101}
    else:
        try:
            variables = json.loads(args.variables)
        except Exception:
            variables = {}

    report = analyze_query_taint(query_str, variables=variables)

    summary = report.summary()
    print("=" * 60)
    print("GraphQL Shield: Query Taint Analysis Summary")
    print("=" * 60)
    print(f"Valid Query:                 {summary['is_valid_query']}")
    print(f"Operation:                   {summary['operation_type']} ({summary['operation_name']})")
    print(f"Fields Analyzed:             {summary['total_fields_analyzed']}")
    print(f"Max Depth:                   {summary['max_depth_reached']}")
    print(f"Cycles Detected:             {summary['has_cycles']}")
    print(f"Direct BOLA Candidates:      {summary['direct_bola_candidates_count']}")
    print(f"Indirect BOLA Candidates:    {summary['indirect_bola_candidates_count']}")
    print(f"Verified Protected Paths:    {summary['verified_protected_paths_count']}")
    print(f"Safe Unprotected Paths:      {summary['safe_unprotected_paths_count']}")
    print("=" * 60)

    if report.findings:
        print("\nFindings Details:")
        for idx, finding in enumerate(report.findings, 1):
            print(f"\n[{idx}] {finding.candidate_kind.value} (Risk: {finding.risk_assessment})")
            print(f"    Path:         {finding.propagation_context.field_path}")
            print(f"    Sink:         {finding.sensitive_sink.sink_id}")
            print(f"    Boundary:     {finding.boundary_evidence.classification.value}")
            print(f"    Explanation:  {finding.explanation}")
            if finding.assumptions_and_uncertainties:
                print("    Uncertainties:")
                for unc in finding.assumptions_and_uncertainties:
                    print(f"      - {unc}")

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report.to_json(indent=2))
        print(f"\n[Report Exported] Full JSON written to {args.output}")


if __name__ == "__main__":
    run_cli()
