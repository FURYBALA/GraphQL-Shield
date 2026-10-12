"""
Command-Line Interface for the GraphQL Authorization Differential Testing Engine
---------------------------------------------------------------------------------
Usage:
    python -m app.security.differential_testing.cli [options]

Options:
    --output-sarif PATH    Export results to SARIF 2.1.0 file
    --output-junit PATH    Export results to JUnit XML file
    --sample-limit N       Limit execution to N test cases
    --fail-on-divergence   Exit with code 1 if policy divergence occurs
    --quiet                Suppress per-case execution logging
"""

import argparse
import sys
import os

from app.main import app
from app.security.differential_testing.executor import run_differential_testing_suite
from app.security.differential_testing.exporters import export_sarif, export_junit_xml


def main():
    parser = argparse.ArgumentParser(
        description="GraphQL Authorization Differential Testing Engine CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--output-sarif", type=str, default=None, help="Save SARIF 2.1.0 report to file path")
    parser.add_argument("--output-junit", type=str, default=None, help="Save JUnit XML report to file path")
    parser.add_argument("--sample-limit", type=int, default=None, help="Limit number of differential test cases to run")
    parser.add_argument("--fail-on-divergence", action="store_true", help="Exit with code 1 if any policy divergence occurs")
    parser.add_argument("--quiet", action="store_true", help="Only output summary results")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("  GRAPHQL AUTHORIZATION DIFFERENTIAL TESTING ENGINE")
    print("=" * 70)
    print("Targeting: Gateway (/graphql) vs Baseline (/graphql-insecure)\n")

    report = run_differential_testing_suite(app, sample_limit=args.sample_limit)

    if not args.quiet:
        print(f"{'ID':<14} {'Category':<18} {'Caller':<10} {'Path':<20} {'Verdict':<24}")
        print("-" * 88)
        for r in report.results:
            caller_str = f"User {r.test_case.caller_id}" if r.test_case.caller_id else "Anon"
            print(f"{r.test_case.test_id:<14} {r.test_case.category:<18} {caller_str:<10} {r.test_case.schema_path:<20} {r.verdict:<24}")
        print("-" * 88)

    print("\n[RESEARCH EVALUATION SUMMARY]")
    print(f"  Total Test Cases Executed      : {report.total_test_cases}")
    print(f"  Schema Path Coverage           : {report.schema_path_coverage_pct}% ({report.schema_paths_tested}/{report.schema_paths_discovered} paths)")
    print(f"  Vulnerability Prevention Rate  : {report.vulnerability_prevention_rate_pct}% ({report.seeded_defects_prevented}/{report.seeded_defects_evaluated} defects)")
    print(f"  Policy Divergence Count        : {report.policy_divergence_count}")
    print(f"  Path Inconsistencies Captured  : {report.path_inconsistencies_detected}")
    print(f"  Reproducibility Rate           : {report.reproducibility_rate_pct}%")
    print(f"  Mean Execution Latency         : {report.mean_latency_per_test_ms} ms/test\n")

    # Export SARIF
    if args.output_sarif:
        import json
        sarif_data = export_sarif(report)
        with open(args.output_sarif, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)
        print(f"[+] SARIF 2.1.0 report exported to: {args.output_sarif}")

    # Export JUnit XML
    if args.output_junit:
        xml_data = export_junit_xml(report)
        with open(args.output_junit, "w", encoding="utf-8") as f:
            f.write(xml_data)
        print(f"[+] JUnit XML report exported to: {args.output_junit}")

    print("=" * 70 + "\n")

    if args.fail_on_divergence and report.policy_divergence_count > 0:
        print(f"[!] FAILED: {report.policy_divergence_count} policy divergence(s) detected.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
