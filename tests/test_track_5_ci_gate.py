"""
Tests for Track 5: CI/CD GitHub Actions & SARIF Quality Gate
=============================================================
Verifies:
1. Programmatic execution of run_security_gate().
2. SARIF 2.1.0 output generation, structure, and schema compliance.
3. Quality gate passes with exit code 0 when all BOLA attacks are prevented.
"""

import json
import os
import pytest

from scripts.ci_security_gate import run_security_gate


def test_ci_security_gate_execution(tmp_path):
    """Verify CI security gate runs, writes valid SARIF 2.1.0, and returns 0."""
    sarif_file = tmp_path / "test_findings.sarif"

    # Run with a sample limit of 5 to keep the test rapid while exercising full pipeline
    exit_code = run_security_gate(
        output_sarif=str(sarif_file),
        sample_limit=5,
        fail_on_vulnerability=True,
    )

    assert exit_code == 0
    assert sarif_file.exists()

    with open(sarif_file, mode="r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    assert sarif_data.get("version") == "2.1.0"
    assert "runs" in sarif_data
    assert len(sarif_data["runs"]) > 0

    run = sarif_data["runs"][0]
    assert "tool" in run
    assert run["tool"]["driver"]["name"] == "GraphQL-Shield-Differential-Testing-Engine"
    assert "rules" in run["tool"]["driver"]
    assert len(run["tool"]["driver"]["rules"]) >= 4

    # Confirm rule IDs match standard schema
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert "GQL-BOLA-001" in rule_ids
    assert "GQL-NESTED-BOLA-002" in rule_ids


def test_ci_security_gate_full_suite(tmp_path):
    """Verify security gate passes cleanly over the full differential test suite."""
    sarif_file = tmp_path / "full_suite.sarif"

    exit_code = run_security_gate(
        output_sarif=str(sarif_file),
        sample_limit=None,
        fail_on_vulnerability=True,
    )

    assert exit_code == 0
    assert sarif_file.exists()
