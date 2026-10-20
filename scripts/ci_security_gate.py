#!/usr/bin/env python3
"""
CCNS CI/CD Security Quality Gate
=================================
Automated CI/CD security quality gate for GraphQL BOLA auditing.
Executes the differential testing suite, verifies that all unauthorized
access attempts are properly intercepted and denied by the GraphQL Shield
gateway, exports standard SARIF 2.1.0 results for GitHub Code Scanning,
and exits with code 0 on pass or code 1 on unmitigated vulnerability.

Usage:
    python scripts/ci_security_gate.py [--output-sarif path.sarif] [--sample-limit N]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from app.main import app, startup_event
from app.security.differential_testing import (
    run_differential_testing_suite,
    export_sarif,
)


def run_security_gate(
    output_sarif: str = "ccns_bola_findings.sarif",
    sample_limit: int | None = None,
    fail_on_vulnerability: bool = True,
) -> int:
    """
    Executes the security gate verification:
      1. Initializes backend services and ownership inference engine.
      2. Executes differential test suite across root, nested, and mutation paths.
      3. Generates SARIF 2.1.0 report.
      4. Validates that zero unauthorized requests bypassed the protected gateway.
      5. Returns exit code (0 for pass, 1 for failure).
    """
    print("=" * 70)
    print("CCNS GraphQL Shield: CI/CD BOLA Security Gate")
    print("=" * 70)

    # 1. Initialize
    startup_event()

    # 2. Execute differential suite
    print(f"Executing differential evaluation (sample limit: {sample_limit or 'ALL'})...")
    report = run_differential_testing_suite(app, sample_limit=sample_limit)

    total_tests = len(report.results)
    mitigated = sum(1 for r in report.results if r.vulnerability_mitigated_by_gateway)
    failed = [
        r for r in report.results
        if r.test_case.expected_decision == "DENY" and (r.gateway_http_status == 200 or r.gateway_decision != "DENY")
    ]

    print("\n" + "-" * 70)
    print("Evaluation Summary:")
    print("-" * 70)
    print(f"Total Test Cases Evaluated : {total_tests}")
    print(f"Vulnerabilities Mitigated  : {mitigated} ({mitigated / total_tests * 100:.1f}%)" if total_tests else "0")
    print(f"Unmitigated BOLA Breaches  : {len(failed)}")

    # 3. Export SARIF
    sarif_doc = export_sarif(report)
    sarif_dir = os.path.dirname(os.path.abspath(output_sarif))
    if sarif_dir and not os.path.exists(sarif_dir):
        os.makedirs(sarif_dir, exist_ok=True)

    with open(output_sarif, mode="w", encoding="utf-8") as f:
        json.dump(sarif_doc, f, indent=2)
    print(f"SARIF 2.1.0 findings written to: {output_sarif}")

    # 4. Enforce quality gate
    if failed:
        print("\n" + "!" * 70)
        print("[GATE FAILED] Unmitigated BOLA Vulnerabilities Detected in Gateway:")
        print("!" * 70)
        for r in failed:
            tc = r.test_case
            print(f"  [CRITICAL] Test {tc.test_id} ({tc.name}):")
            print(f"             Path: {tc.schema_path} | Caller: {tc.caller_id} ({tc.caller_role})")
            print(f"             Gateway returned HTTP {r.gateway_http_status} with decision {r.gateway_decision}")
        if fail_on_vulnerability:
            return 1

    print("\n" + "=" * 70)
    print("[GATE PASSED] All authorization boundaries enforced. Zero BOLA leaks.")
    print("=" * 70)
    return 0


def main():
    parser = argparse.ArgumentParser(description="CCNS CI/CD GraphQL BOLA Security Gate")
    parser.add_argument("--output-sarif", default="ccns_bola_findings.sarif", help="Path to write SARIF 2.1.0 output")
    parser.add_argument("--sample-limit", type=int, default=None, help="Maximum number of test cases to sample")
    parser.add_argument("--no-fail", dest="fail_on_vulnerability", action="store_false", help="Do not exit with error on findings")

    args = parser.parse_args()
    exit_code = run_security_gate(
        output_sarif=args.output_sarif,
        sample_limit=args.sample_limit,
        fail_on_vulnerability=args.fail_on_vulnerability,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
