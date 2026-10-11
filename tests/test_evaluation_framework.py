"""
Test Suite for Ground-Truth Dataset and Evaluation Framework (Phase 6)

Verifies:
1. Benchmark corpus schema validity, completeness, and independence.
2. Confusion matrix and metric computation mathematical correctness.
3. Empty, missing, and malformed dataset error handling.
4. Category-level and syntax-level aggregation.
5. Absolute reproducibility across repeated evaluation runs.
6. Latency profiling metrics and bounds.
"""

import os
import pytest
from scripts.evaluate_taint_corpus import (
    load_and_validate_corpus,
    compute_metrics_for_predictions,
    compute_syntax_breakdown,
    profile_latency,
    run_full_evaluation,
    MethodMetrics,
)


CORPUS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "ground_truth_corpus.json")


def test_01_corpus_schema_and_size():
    """Corpus must contain at least 100 valid, schema-compliant test cases."""
    corpus = load_and_validate_corpus(CORPUS_PATH)
    assert len(corpus) >= 100, f"Expected at least 100 cases, found {len(corpus)}"
    assert len(corpus) == 115

    seen_ids = set()
    for case in corpus:
        c_id = case["id"]
        assert c_id not in seen_ids, f"Duplicate ID: {c_id}"
        seen_ids.add(c_id)

        assert case["ground_truth_security"] in ("VULNERABLE", "BENIGN", "MALFORMED")
        assert case["ground_truth_attack_type"] in ("DIRECT_BOLA", "INDIRECT_BOLA", "NONE", "SYNTAX_ERROR")
        assert case["expected_gateway_decision"] in ("ALLOW", "DENY", "ERROR")
        assert "caller" in case and "user_id" in case["caller"] and "role" in case["caller"]
        assert "rationale" in case and len(case["rationale"]) > 5


def test_02_label_distribution_balance():
    """Corpus must have balanced representation of attack and benign scenarios."""
    corpus = load_and_validate_corpus(CORPUS_PATH)
    vulnerable = [c for c in corpus if c["ground_truth_security"] == "VULNERABLE"]
    benign = [c for c in corpus if c["ground_truth_security"] == "BENIGN"]
    malformed = [c for c in corpus if c["ground_truth_security"] == "MALFORMED"]

    assert len(vulnerable) >= 40
    assert len(benign) >= 40
    assert len(malformed) >= 5

    direct_bola = [c for c in vulnerable if c["ground_truth_attack_type"] == "DIRECT_BOLA"]
    indirect_bola = [c for c in vulnerable if c["ground_truth_attack_type"] == "INDIRECT_BOLA"]

    assert len(direct_bola) >= 20
    assert len(indirect_bola) >= 20


def test_03_metric_calculation_mathematics():
    """Validates Precision, Recall, F1, Accuracy, and denial rate computations."""
    # Synthetic dataset with known ground-truth and predictions
    # 10 VULN (8 detected, 2 missed) -> TP=8, FN=2
    # 10 BENIGN (1 false alarm, 9 allowed) -> FP=1, TN=9
    predictions = []
    for i in range(8):
        predictions.append({
            "ground_truth_security": "VULNERABLE",
            "ground_truth_attack_type": "DIRECT_BOLA",
            "test_m": {"prediction": "VULNERABLE"}
        })
    for i in range(2):
        predictions.append({
            "ground_truth_security": "VULNERABLE",
            "ground_truth_attack_type": "DIRECT_BOLA",
            "test_m": {"prediction": "BENIGN"}
        })
    for i in range(1):
        predictions.append({
            "ground_truth_security": "BENIGN",
            "ground_truth_attack_type": "NONE",
            "test_m": {"prediction": "VULNERABLE"}
        })
    for i in range(9):
        predictions.append({
            "ground_truth_security": "BENIGN",
            "ground_truth_attack_type": "NONE",
            "test_m": {"prediction": "BENIGN"}
        })

    metrics = compute_metrics_for_predictions(predictions, "test_m", "Test Method")
    assert metrics.true_positives == 8
    assert metrics.false_negatives == 2
    assert metrics.false_positives == 1
    assert metrics.true_negatives == 9
    assert metrics.precision == round(8 / (8 + 1), 4)  # 8/9 = 0.8889
    assert metrics.recall == round(8 / (8 + 2), 4)     # 8/10 = 0.8000
    expected_f1 = round(2 * (8/9 * 0.8) / (8/9 + 0.8), 4)
    assert metrics.f1_score == expected_f1
    assert metrics.accuracy == round((8 + 9) / 20, 4)  # 17/20 = 0.8500
    assert metrics.legitimate_denial_rate == round(1 / 10, 4)  # 1/10 = 0.1000


def test_04_metric_edge_cases_zero_division():
    """Handles edge cases with zero predictions or zero candidates without division by zero."""
    # All benign, all predicted benign
    predictions = [
        {"ground_truth_security": "BENIGN", "ground_truth_attack_type": "NONE", "m": {"prediction": "BENIGN"}}
        for _ in range(5)
    ]
    metrics = compute_metrics_for_predictions(predictions, "m", "Zero Div Method")
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1_score == 0.0
    assert metrics.accuracy == 1.0
    assert metrics.legitimate_denial_rate == 0.0


def test_05_empty_and_malformed_dataset_validation(tmp_path):
    """Corpus validator must reject missing files, empty files, and invalid schemas."""
    # Non-existent file
    with pytest.raises(FileNotFoundError):
        load_and_validate_corpus("non_existent_file.json")

    # Empty list
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid or empty"):
        load_and_validate_corpus(str(empty_file))

    # Duplicate ID
    dup_file = tmp_path / "dup.json"
    dup_file.write_text('[{"id": "A", "name": "1", "category": "C", "caller": {}, "query": "q", "ground_truth_security": "BENIGN", "ground_truth_attack_type": "NONE"}, {"id": "A", "name": "2", "category": "C", "caller": {}, "query": "q", "ground_truth_security": "BENIGN", "ground_truth_attack_type": "NONE"}]', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate or missing"):
        load_and_validate_corpus(str(dup_file))


def test_06_category_level_aggregation():
    """Verifies category-level syntax aggregation calculations."""
    predictions = [
        {
            "id": "1", "syntax_type": "BASIC", "ground_truth_security": "VULNERABLE",
            "method_1_gateway": {"prediction": "VULNERABLE"},
            "method_2_static_taint": {"prediction": "VULNERABLE"},
            "method_3_correlated": {"prediction": "VULNERABLE"},
        },
        {
            "id": "2", "syntax_type": "BASIC", "ground_truth_security": "BENIGN",
            "method_1_gateway": {"prediction": "BENIGN"},
            "method_2_static_taint": {"prediction": "VULNERABLE"}, # FP
            "method_3_correlated": {"prediction": "BENIGN"},
        },
        {
            "id": "3", "syntax_type": "ALIAS", "ground_truth_security": "VULNERABLE",
            "method_1_gateway": {"prediction": "VULNERABLE"},
            "method_2_static_taint": {"prediction": "VULNERABLE"},
            "method_3_correlated": {"prediction": "VULNERABLE"},
        },
    ]
    breakdown = compute_syntax_breakdown(predictions)
    assert "BASIC" in breakdown
    assert "ALIAS" in breakdown
    assert breakdown["BASIC"]["total_cases"] == 2
    assert breakdown["BASIC"]["m1_gateway_detection_rate"] == 1.0
    assert breakdown["BASIC"]["m2_static_false_positives"] == 1
    assert breakdown["BASIC"]["m3_correlated_false_positives"] == 0


def test_07_evaluation_reproducibility():
    """Repeated evaluation runs on the corpus must produce identical metrics and classifications."""
    summary_run1 = run_full_evaluation(CORPUS_PATH, iterations=1)
    summary_run2 = run_full_evaluation(CORPUS_PATH, iterations=1)

    m1_run1 = summary_run1["method_comparison"]["method_1_gateway_alone"]
    m1_run2 = summary_run2["method_comparison"]["method_1_gateway_alone"]
    assert m1_run1["true_positives"] == m1_run2["true_positives"]
    assert m1_run1["false_positives"] == m1_run2["false_positives"]
    assert m1_run1["precision"] == m1_run2["precision"]
    assert m1_run1["recall"] == m1_run2["recall"]

    m2_run1 = summary_run1["method_comparison"]["method_2_static_taint_alone"]
    m2_run2 = summary_run2["method_comparison"]["method_2_static_taint_alone"]
    assert m2_run1["true_positives"] == m2_run2["true_positives"]
    assert m2_run1["false_positives"] == m2_run2["false_positives"]

    m3_run1 = summary_run1["method_comparison"]["method_3_correlated_defense"]
    m3_run2 = summary_run2["method_comparison"]["method_3_correlated_defense"]
    assert m3_run1["true_positives"] == m3_run2["true_positives"]
    assert m3_run1["f1_score"] == m3_run2["f1_score"]

    # Compare per-case predictions across runs
    preds1 = summary_run1["predictions"]
    preds2 = summary_run2["predictions"]
    assert len(preds1) == len(preds2)
    for p1, p2 in zip(preds1, preds2):
        assert p1["id"] == p2["id"]
        assert p1["method_1_gateway"]["prediction"] == p2["method_1_gateway"]["prediction"]
        assert p1["method_2_static_taint"]["prediction"] == p2["method_2_static_taint"]["prediction"]
        assert p1["method_3_correlated"]["prediction"] == p2["method_3_correlated"]["prediction"]


def test_08_latency_profiling():
    """Latency profiler must return positive execution timings and valid percentiles."""
    corpus = load_and_validate_corpus(CORPUS_PATH)[:10]  # Subset for fast test
    profile = profile_latency(corpus, iterations=2)
    assert profile.cold_start_ms > 0
    assert profile.warmed_mean_ms > 0
    assert profile.warmed_median_ms > 0
    assert profile.warmed_p95_ms >= profile.warmed_median_ms
    assert profile.warmed_min_ms <= profile.warmed_max_ms
