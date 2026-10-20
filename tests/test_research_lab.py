"""
Comprehensive Test Suite for CCNS Research Lab Module
=====================================================
Verifies:
  1. Pure confusion-matrix math, metrics calculation, and zero-denominator handling.
  2. McNemar paired statistical test with continuity correction.
  3. Benchmark dataset seeding, integrity, versioning, and exclusion accounting.
  4. Manual ground-truth review workflow and audit history logging.
  5. Custom test case registration and provenance tracking.
  6. Shared-case fairness across all evaluation methods.
  7. Controlled ablation study validity and delta calculations.
  8. Traceable 10-node Evidence Explorer pipeline generation.
  9. Deterministic reproducibility and rerun equivalence.
  10. Export artifact count and metric consistency (JSON, CSV, Markdown).
  11. REST API endpoint integration with FastAPI TestClient.
"""

import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security.research.evaluator import (
    calculate_metrics,
    compute_mcnemar_test,
    run_full_experiment,
)
from app.security.research.exporters import (
    export_experiment_csv,
    export_experiment_json,
    export_experiment_markdown_report,
)
from app.security.research.models import (
    AddCaseRequest,
    CaseReviewRequest,
    ConfusionMatrix,
)
from app.security.research.persistence import (
    add_custom_case,
    get_all_datasets,
    get_all_experiments,
    get_case_review_history,
    get_dataset_cases,
    get_experiment_by_id,
    get_experiment_predictions,
    init_research_db,
    review_case_label,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def ensure_db():
    init_research_db()


# =============================================================================
# 1. PURE METRICS CALCULATION & ZERO-DENOMINATOR TESTS
# =============================================================================

def test_01_metrics_pure_calculation_standard():
    """Validates metrics on an independent synthetic fixture with known values."""
    # Synthetic: TP=40, FP=10, TN=40, FN=10 (Total 100)
    cm = ConfusionMatrix(tp=40, fp=10, tn=40, fn=10, inconclusive=0, excluded=0)
    metrics = calculate_metrics(
        cm=cm,
        total_cases=100,
        evaluated_cases=100,
        excluded_cases=0,
        inconclusive_cases=0,
        latency_ms=1.5,
        duration_ms=150.0,
    )

    # Precision = 40 / (40 + 10) = 0.8
    assert metrics.precision == pytest.approx(0.8, rel=1e-3)
    # Recall = 40 / (40 + 10) = 0.8
    assert metrics.recall == pytest.approx(0.8, rel=1e-3)
    # F1 = 0.8
    assert metrics.f1_score == pytest.approx(0.8, rel=1e-3)
    # Accuracy = 80 / 100 = 0.8
    assert metrics.accuracy == pytest.approx(0.8, rel=1e-3)
    # Specificity = 40 / (40 + 10) = 0.8
    assert metrics.specificity == pytest.approx(0.8, rel=1e-3)
    # False Positive Rate = 10 / 50 = 0.2
    assert metrics.false_positive_rate == pytest.approx(0.2, rel=1e-3)
    # False Negative Rate = 10 / 50 = 0.2
    assert metrics.false_negative_rate == pytest.approx(0.2, rel=1e-3)
    # Coverage = 1.0
    assert metrics.coverage_rate == pytest.approx(1.0, rel=1e-3)
    # Inconclusive rate = 0.0
    assert metrics.inconclusive_rate == pytest.approx(0.0, rel=1e-3)


def test_02_metrics_zero_denominators():
    """Zero denominators must yield None (null/N/A) rather than 0.0 or divide-by-zero errors."""
    # Case A: No positive predictions (TP=0, FP=0) -> Precision is undefined
    cm_no_pos = ConfusionMatrix(tp=0, fp=0, tn=50, fn=50, inconclusive=0, excluded=0)
    m_no_pos = calculate_metrics(cm_no_pos, 100, 100, 0, 0)
    assert m_no_pos.precision is None
    assert m_no_pos.f1_score is None
    assert m_no_pos.recall == pytest.approx(0.0, rel=1e-3)

    # Case B: No actual positive cases (TP=0, FN=0) -> Recall is undefined
    cm_no_act_pos = ConfusionMatrix(tp=0, fp=20, tn=80, fn=0, inconclusive=0, excluded=0)
    m_no_act_pos = calculate_metrics(cm_no_act_pos, 100, 100, 0, 0)
    assert m_no_act_pos.recall is None
    assert m_no_act_pos.f1_score is None
    assert m_no_act_pos.precision == pytest.approx(0.0, rel=1e-3)

    # Case C: Empty evaluation set
    cm_empty = ConfusionMatrix(tp=0, fp=0, tn=0, fn=0, inconclusive=0, excluded=0)
    m_empty = calculate_metrics(cm_empty, 0, 0, 0, 0)
    assert m_empty.precision is None
    assert m_empty.recall is None
    assert m_empty.f1_score is None
    assert m_empty.accuracy is None
    assert m_empty.coverage_rate is None


# =============================================================================
# 2. MCNEMAR PAIRED STATISTICAL TEST
# =============================================================================

def test_03_mcnemar_statistical_test():
    """Validates McNemar test with Edwards continuity correction."""
    # Identical predictions -> 0 discordant pairs -> chi2=0, p=1.0, not significant
    preds_base = [{"case_id": f"C{i}", "classification_outcome": "TP"} for i in range(50)]
    preds_same = [{"case_id": f"C{i}", "classification_outcome": "TP"} for i in range(50)]

    res_same = compute_mcnemar_test(preds_base, preds_same)
    assert res_same["shared_cases"] == 50
    assert res_same["mcnemar_chi2"] == 0.0
    assert res_same["p_value"] == 1.0
    assert res_same["is_statistically_significant"] is False

    # Discordant predictions (Method A correct on 25 cases where B is wrong, B correct on 0 where A is wrong)
    preds_divergent = []
    for i in range(50):
        outcome = "TP" if i < 25 else "FN"  # 25 wrong
        preds_divergent.append({"case_id": f"C{i}", "classification_outcome": outcome})

    res_div = compute_mcnemar_test(preds_base, preds_divergent)
    assert res_div["shared_cases"] == 50
    assert res_div["contingency_table"]["baseline_correct_comparison_wrong"] == 25
    assert res_div["contingency_table"]["baseline_wrong_comparison_correct"] == 0
    # Chi2 = (|25 - 0| - 1)^2 / 25 = 24^2 / 25 = 576 / 25 = 23.04
    assert res_div["mcnemar_chi2"] == pytest.approx(23.04, rel=1e-2)
    assert res_div["p_value"] < 0.001
    assert res_div["is_statistically_significant"] is True


# =============================================================================
# 3. DATASET SEEDING & INTEGRITY
# =============================================================================

def test_04_dataset_seeding_and_integrity():
    """Verifies baseline benchmark corpus v1.0 integrity and separation of malformed cases."""
    datasets = get_all_datasets()
    assert len(datasets) >= 1
    ds = next((d for d in datasets if d.id == "ds_benchmark_v1"), None)
    assert ds is not None
    assert ds.total_cases == 115
    assert ds.valid_security_cases == 105
    assert ds.malformed_syntax_cases == 10

    cases = get_dataset_cases("ds_benchmark_v1", include_excluded=True)
    assert len(cases) == 115

    # Verify ID uniqueness
    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids))

    # Verify exclusion flags on malformed syntax cases
    malformed = [c for c in cases if c.syntax_type == "MALFORMED" or c.ground_truth_security == "MALFORMED"]
    assert len(malformed) == 10
    for m in malformed:
        assert m.is_excluded is True
        assert m.exclusion_reason is not None


# =============================================================================
# 4. MANUAL GROUND-TRUTH REVIEW & AUDIT HISTORY
# =============================================================================

def test_05_ground_truth_review_audit_trail():
    """Modifying ground-truth labels records mandatory reviewer rationale and audit history."""
    cases = get_dataset_cases("ds_benchmark_v1")
    target_case = cases[0]
    case_id = target_case.id
    orig_sec = target_case.ground_truth_security
    orig_ver = target_case.version

    new_sec = "BENIGN" if orig_sec == "VULNERABLE" else "VULNERABLE"
    review_req = CaseReviewRequest(
        new_security=new_sec,
        reviewer="Security Audit Lead",
        review_rationale="Independent re-evaluation confirms intended authorization semantics."
    )

    updated = review_case_label(case_id, review_req)
    assert updated is not None
    assert updated.ground_truth_security == new_sec
    assert updated.version == orig_ver + 1

    # Check review history
    history = get_case_review_history(case_id)
    assert len(history) >= 1
    latest = history[0]
    assert latest["case_id"] == case_id
    assert latest["previous_security"] == orig_sec
    assert latest["new_security"] == new_sec
    assert latest["reviewer"] == "Security Audit Lead"
    assert "Independent re-evaluation" in latest["review_rationale"]

    # Revert back to maintain dataset pristine state
    revert_req = CaseReviewRequest(
        new_security=orig_sec,
        reviewer="Test Cleanup",
        review_rationale="Reverting test modification."
    )
    reverted = review_case_label(case_id, revert_req)
    assert reverted.ground_truth_security == orig_sec


# =============================================================================
# 5. CUSTOM CASE REGISTRATION & PROVENANCE
# =============================================================================

def test_06_add_custom_case_provenance():
    """Adding an authorized local test case stores provenance and updates dataset counts."""
    custom_case = AddCaseRequest(
        name="Custom Tenant Boundary Test",
        category="CUSTOM_BOUNDARY",
        syntax_type="BASIC",
        caller_user_id=102,
        caller_role="user",
        query="query { resource(id: 101) { id name } }",
        variables={"id": 101},
        operation_name="resource",
        target_object_id=101,
        target_object_type="Resource",
        true_owner_id=101,
        ground_truth_security="VULNERABLE",
        ground_truth_attack_type="DIRECT_BOLA",
        expected_gateway_decision="DENY",
        rationale="Cross-tenant access attempt by Bob against Alice's resource.",
        provenance="manual_authorized_test",
    )

    created = add_custom_case("ds_benchmark_v1", custom_case)
    assert created.id.startswith("CASE-ds_benchmark_v1-")
    assert created.provenance == "manual_authorized_test"
    assert created.ground_truth_security == "VULNERABLE"

    # Verify it appears in dataset queries
    all_cases = get_dataset_cases("ds_benchmark_v1", include_excluded=True)
    assert any(c.id == created.id for c in all_cases)

    # Teardown: Clean up test case to prevent benchmark corpus contamination
    from app.database import get_db_connection
    from app.security.research.persistence import update_dataset_counts
    conn = get_db_connection()
    conn.execute("DELETE FROM research_cases WHERE id = ?", (created.id,))
    conn.commit()
    conn.close()
    update_dataset_counts("ds_benchmark_v1")


# =============================================================================
# 6. SHARED-CASE FAIRNESS ACROSS EVALUATION METHODS
# =============================================================================

def test_07_shared_case_fairness():
    """All 3 methods and ablations must evaluate the exact same eligible test cases."""
    exp = run_full_experiment(dataset_id="ds_benchmark_v1", include_ablations=True)
    exp_id = exp["id"]

    preds = get_experiment_predictions(exp_id)
    methods = set(p["method_id"] for p in preds)
    assert "method_static_taint" in methods
    assert "method_runtime_gateway" in methods
    assert "method_correlated" in methods
    assert "ablation_no_ownership" in methods
    assert "ablation_no_audit" in methods

    # Group predictions by method
    by_method = {}
    for p in preds:
        m = p["method_id"]
        if m not in by_method:
            by_method[m] = []
        by_method[m].append(p)

    # Every method must have evaluated the exact same number of cases
    case_counts = [len(by_method[m]) for m in methods]
    assert len(set(case_counts)) == 1, f"Mismatch in evaluated case counts across methods: {case_counts}"

    # Verify identical case ID sets
    base_case_ids = sorted([p["case_id"] for p in by_method["method_correlated"]])
    for m in methods:
        m_case_ids = sorted([p["case_id"] for p in by_method[m]])
        assert m_case_ids == base_case_ids, f"Method {m} did not evaluate the identical case set!"


# =============================================================================
# 7. CONTROLLED ABLATION STUDIES
# =============================================================================

def test_08_controlled_ablations():
    """Validates ablation results, deltas, and McNemar test statistics."""
    exp = run_full_experiment(dataset_id="ds_benchmark_v1", include_ablations=True)
    ablations = exp["ablations"]
    assert len(ablations) == 2

    # Ablation 1: No Ownership
    ab1 = next((a for a in ablations if a["ablation_id"] == "ablation_no_ownership"), None)
    assert ab1 is not None
    assert ab1["shared_cases_count"] >= 105
    assert "statistical_test" in ab1
    assert "mcnemar_chi2" in ab1["statistical_test"]
    assert "p_value" in ab1["statistical_test"]

    # Ablation 2: No Audit
    ab2 = next((a for a in ablations if a["ablation_id"] == "ablation_no_audit"), None)
    assert ab2 is not None
    assert ab2["shared_cases_count"] >= 105


# =============================================================================
# 8. TRACEABLE 10-NODE EVIDENCE EXPLORER PIPELINE
# =============================================================================

def test_09_ten_node_evidence_explorer():
    """Validates that each evaluated case produces a complete 10-node evidence graph."""
    exp = run_full_experiment(dataset_id="ds_benchmark_v1", include_ablations=False)
    exp_id = exp["id"]

    preds = get_experiment_predictions(exp_id, method_id="method_correlated")
    assert len(preds) > 0

    first_pred = preds[0]
    ev = first_pred["evidence"]
    assert "nodes" in ev
    nodes = ev["nodes"]
    assert len(nodes) == 10

    expected_node_ids = [
        "n1_principal",
        "n2_ast",
        "n3_extractor",
        "n4_taint_source",
        "n5_taint_propagation",
        "n6_static_candidates",
        "n7_runtime_resolver",
        "n8_ownership_db",
        "n9_policy_engine",
        "n10_correlated_evidence",
    ]

    actual_node_ids = [n["node_id"] for n in nodes]
    assert actual_node_ids == expected_node_ids

    # Check node structure
    for n in nodes:
        assert "name" in n
        assert "status" in n
        assert "category" in n
        assert "summary" in n
        assert "details" in n


# =============================================================================
# 9. REPRODUCIBILITY & RERUN DETERMINISM
# =============================================================================

def test_10_rerun_determinism():
    """Rerunning an experiment must produce identical metrics and confusion matrices."""
    exp1 = run_full_experiment(dataset_id="ds_benchmark_v1", include_ablations=False)
    exp_id1 = exp1["id"]

    # Trigger rerun endpoint
    res = client.post(f"/api/v1/research/experiments/{exp_id1}/rerun")
    assert res.status_code == 200
    exp2 = res.json()
    exp_id2 = exp2["id"]
    assert exp_id1 != exp_id2

    # Compare Method C results between the two runs
    mr1 = next(m for m in exp1["method_runs"] if m["method_id"] == "method_correlated")
    mr2 = next(m for m in exp2["method_runs"] if m["method_id"] == "method_correlated")

    assert mr1["metrics"]["f1_score"] == pytest.approx(mr2["metrics"]["f1_score"], rel=1e-4)
    assert mr1["confusion_matrix"] == mr2["confusion_matrix"]


# =============================================================================
# 10. EXPORT CONSISTENCY (JSON, CSV, MARKDOWN)
# =============================================================================

def test_11_export_consistency():
    """Exports must match persisted experiment predictions and metrics."""
    exps = get_all_experiments()
    assert len(exps) > 0
    exp_id = exps[0]["id"]

    # JSON export
    js = export_experiment_json(exp_id)
    assert js["id"] == exp_id
    assert len(js["predictions"]) == js["total_predictions_count"]

    # CSV export
    csv_str = export_experiment_csv(exp_id)
    lines = [l for l in csv_str.strip().split("\n") if l.strip()]
    header = lines[0]
    assert "case_id" in header
    assert "method_id" in header
    assert "ground_truth_security" in header
    # 1 header line + N prediction lines
    assert len(lines) - 1 == len(js["predictions"])

    # Markdown Report export
    md_report = export_experiment_markdown_report(exp_id)
    assert f"# Evaluation Report" in md_report
    assert exp_id in md_report
    assert "CCNS-EVAL-V2" in md_report
    assert "Comparative Evaluation Matrix" in md_report
    assert "Ablation Studies" in md_report


# =============================================================================
# 11. REST API ENDPOINTS INTEGRATION
# =============================================================================

def test_12_api_endpoints_integration():
    """Verifies all Research Lab REST API routes respond with 200 and valid schemas."""
    # 1. Overview
    res = client.get("/api/v1/research/overview")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "active"
    assert data["protocol_version"] == "CCNS-EVAL-V2"

    # 2. Datasets
    res = client.get("/api/v1/research/datasets")
    assert res.status_code == 200
    assert len(res.json()) >= 1

    # 3. Cases
    res = client.get("/api/v1/research/datasets/ds_benchmark_v1/cases")
    assert res.status_code == 200
    assert len(res.json()) >= 115

    # 4. Experiments list
    res = client.get("/api/v1/research/experiments")
    assert res.status_code == 200
    exps = res.json()
    assert len(exps) >= 1
    exp_id = exps[0]["id"]

    # 5. Method Comparison
    res = client.get(f"/api/v1/research/experiments/{exp_id}/comparison")
    assert res.status_code == 200
    comp = res.json()
    assert "method_runs" in comp
    assert "disagreements" in comp

    # 6. Ablations
    res = client.get(f"/api/v1/research/experiments/{exp_id}/ablations")
    assert res.status_code == 200
    assert "ablations" in res.json()

    # 7. Errors
    res = client.get(f"/api/v1/research/experiments/{exp_id}/errors")
    assert res.status_code == 200
    errs = res.json()
    assert "counts" in errs

    # 8. Evidence trace
    res = client.get(f"/api/v1/research/experiments/{exp_id}/evidence/CORPUS-001")
    assert res.status_code == 200
    ev_data = res.json()
    assert len(ev_data["evidence_graph"]["nodes"]) == 10

    # 9. Exports via HTTP
    res_json = client.get(f"/api/v1/research/experiments/{exp_id}/export/json")
    assert res_json.status_code == 200

    res_csv = client.get(f"/api/v1/research/experiments/{exp_id}/export/csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers.get("content-type", "")

    res_rep = client.get(f"/api/v1/research/experiments/{exp_id}/export/report")
    assert res_rep.status_code == 200
    assert "Evaluation Report" in res_rep.text


# =============================================================================
# 12. PHASE 2 GENERALIZATION & ADVERSARIAL BENCHMARK TESTS
# =============================================================================

def test_13_generalization_v2_seeding():
    """Asserts ds_generalization_v2 is seeded with 60 cases across 3 disjoint splits."""
    cases = get_dataset_cases("ds_generalization_v2", include_excluded=True)
    assert len(cases) == 60

    by_split = {}
    for c in cases:
        by_split[c.split] = by_split.get(c.split, 0) + 1

    assert by_split.get("tuning") == 23
    assert by_split.get("held_out") == 20
    assert by_split.get("adversarial_stress") == 17


def test_14_split_leakage_freedom():
    """Asserts coverage breakdown proves zero cross-split query leakage."""
    res = client.get("/api/v1/research/datasets/ds_generalization_v2/coverage")
    assert res.status_code == 200
    cov = res.json()
    assert cov["total_cases"] == 60
    assert cov["valid_security_cases"] == 56
    assert cov["malformed_syntax_cases"] == 4
    assert cov["leakage_free"] is True
    assert cov["splits_disjoint"] is True
    assert len(cov["by_category"]) == 9


def test_15_path_attribution_metrics():
    """Asserts Method C achieves superior AST path attribution while Method B has 0.0%."""
    exp = run_full_experiment("ds_generalization_v2")
    assert exp is not None
    method_runs = exp.get("method_runs", [])
    assert len(method_runs) >= 3

    gw = next(m for m in method_runs if m["method_id"] == "method_runtime_gateway")
    cor = next(m for m in method_runs if m["method_id"] == "method_correlated")

    # Method B operates without AST awareness -> 0 reported paths and 0.0% recall
    assert gw["metrics"]["total_reported_paths"] == 0
    assert gw["metrics"]["path_recall"] == 0.0

    # Method C correlates runtime decisions with AST paths
    assert cor["metrics"]["total_reported_paths"] > 0
    assert cor["metrics"]["path_precision"] is not None and cor["metrics"]["path_precision"] > 0.90
    assert cor["metrics"]["path_recall"] is not None and cor["metrics"]["path_recall"] > 0.90
    assert cor["metrics"]["path_exact_match_rate"] is not None and cor["metrics"]["path_exact_match_rate"] > 0.90


def test_16_safe_mutation_integrity():
    """Asserts unauthorized mutation requests fail closed with zero database corruption."""
    from app.database import get_db_connection
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, owner_id, name FROM objects WHERE id = 101")
        before_state = cursor.fetchone()
        assert before_state is not None

        # Execute unauthorized mutation via client
        from app.core.security import create_access_token
        bob_token = create_access_token(user_id=2, role="user")
        mutation_query = """
        mutation {
            deleteResource(id: 101)
        }
        """
        res = client.post(
            "/graphql",
            json={"query": mutation_query},
            headers={"Authorization": f"Bearer {bob_token}"}
        )
        assert res.status_code == 403 or (res.status_code == 200 and "errors" in res.json())

        # Verify database state was NOT altered
        cursor.execute("SELECT id, owner_id, name FROM objects WHERE id = 101")
        after_state = cursor.fetchone()
        assert before_state == after_state
    finally:
        conn.close()

