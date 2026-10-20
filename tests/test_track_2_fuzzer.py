"""
Tests for Track 2: Synthetic Adversarial Query Fuzzer
=====================================================
Validates all 5 mutation classes and end-to-end fuzzing stress testing.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.security.research.fuzzer import (
    SyntheticQueryFuzzer,
    run_adversarial_fuzzing_evaluation,
)

client = TestClient(app)

def test_fuzzer_alias_mutation():
    """Alias mutation must inject unique client aliases into selection roots."""
    fuzzer = SyntheticQueryFuzzer(seed=42)
    base_query = "query { resource(id: 101) { id name } }"
    variant = fuzzer.apply_alias_mutation(base_query)

    assert variant.mutation_class == "ALIAS_INDIRECT"
    assert len(variant.injected_aliases) >= 1
    assert any(a in variant.fuzzed_query for a in variant.injected_aliases)


def test_fuzzer_variable_indirection():
    """Variable indirection must replace literal IDs with typed variables."""
    fuzzer = SyntheticQueryFuzzer(seed=42)
    base_query = "query { resource(id: 101) { id } }"
    variant = fuzzer.apply_variable_indirection(base_query, target_id=101)

    assert variant.mutation_class == "VARIABLE_INDIRECTION"
    assert "$" in variant.fuzzed_query
    assert len(variant.injected_variables) == 1
    assert list(variant.injected_variables.values())[0] == 101


def test_fuzzer_fragment_encapsulation():
    """Fragment encapsulation must wrap field selections into inline fragments."""
    fuzzer = SyntheticQueryFuzzer(seed=42)
    base_query = "query { resource(id: 101) { id name } }"
    variant = fuzzer.apply_fragment_encapsulation(base_query)

    assert variant.mutation_class == "FRAGMENT_ENCAPSULATION"
    assert "... on Resource" in variant.fuzzed_query


def test_fuzzer_directive_complexity():
    """Directive complexity must inject @include(if: true) transparently."""
    fuzzer = SyntheticQueryFuzzer(seed=42)
    base_query = "query { resource(id: 101) { id name } }"
    variant = fuzzer.apply_directive_complexity(base_query)

    assert variant.mutation_class == "DIRECTIVE_COMPLEXITY"
    assert "@include(if: true)" in variant.fuzzed_query


def test_fuzzer_evaluation_report():
    """Adversarial fuzzing evaluation must return valid metrics across all 5 classes."""
    report = run_adversarial_fuzzing_evaluation()
    assert report.total_variants_generated == 15
    assert len(report.by_mutation_class) == 5
    assert report.correlated_defense_robustness_pct >= 80.0
    assert report.path_attribution_exact_match_pct >= 80.0


def test_fuzzer_rest_api_endpoint():
    """POST /api/v1/research/fuzzer/run must return 200 with FuzzingReport schema."""
    res = client.post("/api/v1/research/fuzzer/run")
    assert res.status_code == 200
    data = res.json()
    assert "total_variants_generated" in data
    assert "correlated_defense_robustness_pct" in data
    assert "summary" in data
