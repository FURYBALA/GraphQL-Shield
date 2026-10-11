#!/usr/bin/env python3
"""
Taint Analysis Corpus Evaluation & Multi-Method Benchmarking Script (Phase 6)

Performs a rigorous, reproducible, three-method comparative evaluation against
the 115-case independently labeled GraphQL BOLA benchmark corpus.

Evaluated Methods:
1. Existing Gateway Alone (Runtime Baseline)
2. Static Taint Analysis Alone (AST Engine without runtime context)
3. Correlated Defense (Phase 5 Integrated Taint + Dynamic Policy Gateway)

Metrics Computed:
- Precision, Recall, F1-Score for BOLA vulnerability detection
- True Positives, False Positives, True Negatives, False Negatives
- Legitimate-Request Denial Rate (False Alarm Rate)
- Direct vs. Indirect BOLA Detection Rates
- Performance breakdown by GraphQL syntax category
- Cold-start and Warmed-up execution latency (Min, Max, Median, P95, Mean, StDev)
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

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
# DATA STRUCTURES
# =============================================================================

@dataclass
class MethodMetrics:
    method_name: str
    total_evaluated: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    legitimate_denial_rate: float
    direct_bola_recall: float
    indirect_bola_recall: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LatencyProfile:
    cold_start_ms: float
    warmed_mean_ms: float
    warmed_median_ms: float
    warmed_min_ms: float
    warmed_max_ms: float
    warmed_p95_ms: float
    warmed_stdev_ms: float
    iterations: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# EVALUATION ENGINE
# =============================================================================

def load_and_validate_corpus(corpus_path: str) -> List[Dict[str, Any]]:
    """Loads and validates the ground-truth benchmark dataset."""
    if not os.path.exists(corpus_path):
        raise FileNotFoundError(f"Benchmark corpus file not found: {corpus_path}")

    with open(corpus_path, "r", encoding="utf-8") as f:
        corpus = json.load(f)

    if not isinstance(corpus, list) or len(corpus) == 0:
        raise ValueError(f"Invalid or empty corpus in {corpus_path}")

    seen_ids = set()
    for item in corpus:
        c_id = item.get("id")
        if not c_id or c_id in seen_ids:
            raise ValueError(f"Corpus schema error: duplicate or missing ID '{c_id}'")
        seen_ids.add(c_id)
        for req_field in ("name", "category", "caller", "query", "ground_truth_security", "ground_truth_attack_type"):
            if req_field not in item:
                raise ValueError(f"Corpus schema error: missing '{req_field}' in {c_id}")

    return corpus


def evaluate_single_query_methods(
    case: Dict[str, Any],
    policy_engine: PolicyEngine,
) -> Dict[str, Any]:
    """
    Evaluates one benchmark query across all three methods.
    Returns prediction dictionary for the case.
    """
    query = case["query"]
    variables = case.get("variables", {})
    caller = case["caller"]
    user_id = caller["user_id"]
    role = caller["role"]

    sanitized_vars = sanitize_variables(variables)

    # -------------------------------------------------------------------------
    # 1. Method 2: Static Taint Analysis Alone
    # -------------------------------------------------------------------------
    static_pred = "BENIGN"
    static_attack_type = "NONE"
    static_error = None
    report = None

    try:
        report = analyze_query_taint(query=query, variables=sanitized_vars)
        if not report.is_valid_query:
            static_pred = "MALFORMED"
            static_attack_type = "SYNTAX_ERROR"
            static_error = report.error_message
        elif len(report.direct_bola_candidates) > 0:
            static_pred = "VULNERABLE"
            static_attack_type = "DIRECT_BOLA"
        elif len(report.indirect_bola_candidates) > 0:
            static_pred = "VULNERABLE"
            static_attack_type = "INDIRECT_BOLA"
        else:
            static_pred = "BENIGN"
            static_attack_type = "NONE"
    except Exception as exc:
        static_pred = "MALFORMED"
        static_attack_type = "SYNTAX_ERROR"
        static_error = str(exc)

    # -------------------------------------------------------------------------
    # 2. Method 1: Existing Gateway Alone (Runtime Baseline)
    # -------------------------------------------------------------------------
    gateway_pred = "BENIGN"
    gateway_attack_type = "NONE"
    gateway_decision = "ALLOW"
    gateway_reason = "NO_OBJECTS"
    runtime_results = []

    try:
        normalized = normalize_query(query, variables)
        if not normalized:
            # Query could not be parsed by object extractor (malformed or unparseable)
            gateway_pred = "MALFORMED"
            gateway_attack_type = "SYNTAX_ERROR"
            gateway_decision = "ERROR"
        elif not normalized.get("objects"):
            # Public or non-object query
            gateway_pred = "BENIGN"
            gateway_attack_type = "NONE"
            gateway_decision = "ALLOW"
        else:
            denied_objects = []
            for obj in normalized["objects"]:
                obj_id = obj["id"]
                obj_type = obj["type"]
                obj_path = obj["path"]

                res = resolve_ownership(obj_type, obj_id)
                ctx = AuthorizationContext(
                    user_id=user_id,
                    role=role,
                    operation=normalized.get("operation") or "query",
                    object_type=obj_type,
                    object_id=obj_id,
                    path=obj_path,
                    owner_id=res.owner_id,
                    metadata={
                        "client_host": "127.0.0.1",
                        "ownership_status": res.status,
                        "ownership_source": res.source,
                        "ownership_detail": res.detail,
                    },
                )
                eval_res = policy_engine.evaluate(ctx)
                runtime_results.append((obj, eval_res))
                if eval_res["decision"] == "DENY":
                    denied_objects.append((obj, eval_res))

            if denied_objects:
                gateway_pred = "VULNERABLE"
                gateway_decision = "DENY"
                first_denied = denied_objects[0][1]
                gateway_reason = first_denied["reason"]
                # Distinguish direct vs nested violation based on policy reason or path
                if first_denied["reason"] == "NESTED_AUTHORIZATION_VIOLATION":
                    gateway_attack_type = "INDIRECT_BOLA"
                else:
                    gateway_attack_type = "DIRECT_BOLA"
            else:
                gateway_pred = "BENIGN"
                gateway_decision = "ALLOW"
                gateway_reason = runtime_results[0][1]["reason"] if runtime_results else "ALLOW"
    except Exception as exc:
        gateway_pred = "MALFORMED"
        gateway_attack_type = "SYNTAX_ERROR"
        gateway_decision = "ERROR"
        gateway_reason = str(exc)

    # -------------------------------------------------------------------------
    # 3. Method 3: Correlated Defense (Taint + Gateway Authorization)
    # -------------------------------------------------------------------------
    correlated_pred = "BENIGN"
    correlated_attack_type = "NONE"
    correlations = []

    if static_pred == "MALFORMED" or gateway_pred == "MALFORMED":
        correlated_pred = "MALFORMED"
        correlated_attack_type = "SYNTAX_ERROR"
    elif not runtime_results:
        # Public or unparameterized queries
        correlated_pred = "BENIGN"
        correlated_attack_type = "NONE"
    else:
        for obj, eval_res in runtime_results:
            corr = correlate_path_decision(
                path=obj["path"],
                object_type=obj["type"],
                object_id=obj["id"],
                runtime_result=eval_res,
                taint_report=report,
            )
            correlations.append(corr)

        # If any path is verified TRUE_POSITIVE_BLOCKED, correlated defense flags VULNERABLE
        tp_corrs = [c for c in correlations if c.status == CorrelationStatus.TRUE_POSITIVE_BLOCKED]
        if tp_corrs:
            correlated_pred = "VULNERABLE"
            first_tp = tp_corrs[0]
            if first_tp.static_candidate_kind == "INDIRECT_BOLA_CANDIDATE":
                correlated_attack_type = "INDIRECT_BOLA"
            else:
                correlated_attack_type = "DIRECT_BOLA"
        elif any(c.status == CorrelationStatus.POLICY_DENIED_UNCORRELATED for c in correlations):
            # Gateway denied an object that static analyzer missed
            correlated_pred = "VULNERABLE"
            correlated_attack_type = "DIRECT_BOLA"
        else:
            # Protected by runtime or benign authorized
            correlated_pred = "BENIGN"
            correlated_attack_type = "NONE"

    return {
        "id": case["id"],
        "name": case["name"],
        "category": case["category"],
        "syntax_type": case["syntax_type"],
        "ground_truth_security": case["ground_truth_security"],
        "ground_truth_attack_type": case["ground_truth_attack_type"],
        "method_1_gateway": {
            "prediction": gateway_pred,
            "attack_type": gateway_attack_type,
            "decision": gateway_decision,
            "reason": gateway_reason,
        },
        "method_2_static_taint": {
            "prediction": static_pred,
            "attack_type": static_attack_type,
            "direct_candidates_count": len(report.direct_bola_candidates) if report else 0,
            "indirect_candidates_count": len(report.indirect_bola_candidates) if report else 0,
            "error": static_error,
        },
        "method_3_correlated": {
            "prediction": correlated_pred,
            "attack_type": correlated_attack_type,
            "correlations": [c.to_dict() for c in correlations],
        },
    }


def compute_metrics_for_predictions(
    predictions: List[Dict[str, Any]],
    method_key: str,
    method_name: str,
) -> MethodMetrics:
    """Calculates statistical metrics for a specific method on valid security cases."""
    # Exclude malformed syntax cases from vulnerability confusion matrix
    valid_cases = [p for p in predictions if p["ground_truth_security"] in ("VULNERABLE", "BENIGN")]

    tp = 0  # GT: VULN, Pred: VULN
    fp = 0  # GT: BENIGN, Pred: VULN
    tn = 0  # GT: BENIGN, Pred: BENIGN
    fn = 0  # GT: VULN, Pred: BENIGN

    direct_gt = 0
    direct_tp = 0
    indirect_gt = 0
    indirect_tp = 0

    for c in valid_cases:
        gt_sec = c["ground_truth_security"]
        gt_atk = c["ground_truth_attack_type"]
        pred_sec = c[method_key]["prediction"]

        if gt_sec == "VULNERABLE":
            if pred_sec == "VULNERABLE":
                tp += 1
                if gt_atk == "DIRECT_BOLA":
                    direct_gt += 1
                    direct_tp += 1
                elif gt_atk == "INDIRECT_BOLA":
                    indirect_gt += 1
                    indirect_tp += 1
            else:
                fn += 1
                if gt_atk == "DIRECT_BOLA":
                    direct_gt += 1
                elif gt_atk == "INDIRECT_BOLA":
                    indirect_gt += 1
        elif gt_sec == "BENIGN":
            if pred_sec == "VULNERABLE":
                fp += 1
            else:
                tn += 1

    total_eval = len(valid_cases)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / total_eval) if total_eval > 0 else 0.0
    legit_denial_rate = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    direct_recall = (direct_tp / direct_gt) if direct_gt > 0 else 0.0
    indirect_recall = (indirect_tp / indirect_gt) if indirect_gt > 0 else 0.0

    return MethodMetrics(
        method_name=method_name,
        total_evaluated=total_eval,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        accuracy=round(accuracy, 4),
        legitimate_denial_rate=round(legit_denial_rate, 4),
        direct_bola_recall=round(direct_recall, 4),
        indirect_bola_recall=round(indirect_recall, 4),
    )


def compute_syntax_breakdown(predictions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Breaks down detection rates by GraphQL syntax type across all methods."""
    syntax_types = sorted(list({p["syntax_type"] for p in predictions}))
    breakdown = {}

    for st in syntax_types:
        subset = [p for p in predictions if p["syntax_type"] == st and p["ground_truth_security"] != "MALFORMED"]
        if not subset:
            continue

        vuln_subset = [p for p in subset if p["ground_truth_security"] == "VULNERABLE"]
        benign_subset = [p for p in subset if p["ground_truth_security"] == "BENIGN"]

        m1_detected = sum(1 for p in vuln_subset if p["method_1_gateway"]["prediction"] == "VULNERABLE")
        m2_detected = sum(1 for p in vuln_subset if p["method_2_static_taint"]["prediction"] == "VULNERABLE")
        m3_detected = sum(1 for p in vuln_subset if p["method_3_correlated"]["prediction"] == "VULNERABLE")

        m2_fp = sum(1 for p in benign_subset if p["method_2_static_taint"]["prediction"] == "VULNERABLE")
        m3_fp = sum(1 for p in benign_subset if p["method_3_correlated"]["prediction"] == "VULNERABLE")

        breakdown[st] = {
            "total_cases": len(subset),
            "vulnerable_count": len(vuln_subset),
            "benign_count": len(benign_subset),
            "m1_gateway_detection_rate": round(m1_detected / len(vuln_subset), 3) if vuln_subset else 1.0,
            "m2_static_detection_rate": round(m2_detected / len(vuln_subset), 3) if vuln_subset else 1.0,
            "m3_correlated_detection_rate": round(m3_detected / len(vuln_subset), 3) if vuln_subset else 1.0,
            "m2_static_false_positives": m2_fp,
            "m3_correlated_false_positives": m3_fp,
        }

    return breakdown


def profile_latency(corpus: List[Dict[str, Any]], iterations: int = 3) -> LatencyProfile:
    """Measures cold-start vs warmed-up execution latency over multiple iterations."""
    latencies: List[float] = []
    cold_start_ms = 0.0

    for iter_idx in range(iterations):
        for case in corpus:
            query = case["query"]
            variables = case.get("variables", {})
            sanitized_vars = sanitize_variables(variables)

            start_t = time.perf_counter()
            analyze_query_taint(query=query, variables=sanitized_vars)
            dur_ms = (time.perf_counter() - start_t) * 1000.0

            if iter_idx == 0 and len(latencies) == 0:
                cold_start_ms = dur_ms
            latencies.append(dur_ms)

    # Warmed-up metrics (excluding first 2 queries to eliminate module import & graph compilation)
    warmed_latencies = latencies[2:] if len(latencies) > 2 else latencies
    warmed_sorted = sorted(warmed_latencies)
    p95_idx = int(math.ceil(0.95 * len(warmed_sorted))) - 1
    p95_val = warmed_sorted[max(0, p95_idx)]

    return LatencyProfile(
        cold_start_ms=round(cold_start_ms, 3),
        warmed_mean_ms=round(statistics.mean(warmed_latencies), 3),
        warmed_median_ms=round(statistics.median(warmed_latencies), 3),
        warmed_min_ms=round(min(warmed_latencies), 3),
        warmed_max_ms=round(max(warmed_latencies), 3),
        warmed_p95_ms=round(p95_val, 3),
        warmed_stdev_ms=round(statistics.stdev(warmed_latencies), 3) if len(warmed_latencies) > 1 else 0.0,
        iterations=iterations,
    )


# =============================================================================
# REPORTING
# =============================================================================

def format_terminal_report(
    corpus_len: int,
    m1_metrics: MethodMetrics,
    m2_metrics: MethodMetrics,
    m3_metrics: MethodMetrics,
    latency: LatencyProfile,
    syntax_breakdown: Dict[str, Dict[str, Any]],
) -> None:
    """Prints a clear, comprehensive ASCII terminal comparison table."""
    print("\n" + "=" * 80)
    print("  GRAPHQL BOLA SECURITY EVALUATION: MULTI-METHOD COMPARISON (PHASE 6)")
    print("=" * 80)
    print(f"Total Benchmark Corpus Cases : {corpus_len}")
    print(f"Evaluated Valid Security Cases : {m1_metrics.total_evaluated}")
    print(f"Malformed Syntax Edge Cases   : {corpus_len - m1_metrics.total_evaluated}")
    print("-" * 80)

    # Method Comparison Table
    header = f"{'Metric':<30} | {'M1: Gateway Alone':<15} | {'M2: Static Alone':<16} | {'M3: Correlated':<15}"
    print(header)
    print("-" * 80)
    print(f"{'Precision':<30} | {m1_metrics.precision * 100:>13.1f}% | {m2_metrics.precision * 100:>14.1f}% | {m3_metrics.precision * 100:>13.1f}%")
    print(f"{'Recall':<30} | {m1_metrics.recall * 100:>13.1f}% | {m2_metrics.recall * 100:>14.1f}% | {m3_metrics.recall * 100:>13.1f}%")
    print(f"{'F1-Score':<30} | {m1_metrics.f1_score:>14.3f} | {m2_metrics.f1_score:>15.3f} | {m3_metrics.f1_score:>14.3f}")
    print(f"{'Accuracy':<30} | {m1_metrics.accuracy * 100:>13.1f}% | {m2_metrics.accuracy * 100:>14.1f}% | {m3_metrics.accuracy * 100:>13.1f}%")
    print(f"{'True Positives (TP)':<30} | {m1_metrics.true_positives:>14} | {m2_metrics.true_positives:>15} | {m3_metrics.true_positives:>14}")
    print(f"{'False Positives (FP)':<30} | {m1_metrics.false_positives:>14} | {m2_metrics.false_positives:>15} | {m3_metrics.false_positives:>14}")
    print(f"{'False Negatives (FN)':<30} | {m1_metrics.false_negatives:>14} | {m2_metrics.false_negatives:>15} | {m3_metrics.false_negatives:>14}")
    print(f"{'Legitimate Denial Rate (FP Rate)':<30} | {m1_metrics.legitimate_denial_rate * 100:>13.1f}% | {m2_metrics.legitimate_denial_rate * 100:>14.1f}% | {m3_metrics.legitimate_denial_rate * 100:>13.1f}%")
    print(f"{'Direct BOLA Recall':<30} | {m1_metrics.direct_bola_recall * 100:>13.1f}% | {m2_metrics.direct_bola_recall * 100:>14.1f}% | {m3_metrics.direct_bola_recall * 100:>13.1f}%")
    print(f"{'Indirect BOLA Recall':<30} | {m1_metrics.indirect_bola_recall * 100:>13.1f}% | {m2_metrics.indirect_bola_recall * 100:>14.1f}% | {m3_metrics.indirect_bola_recall * 100:>13.1f}%")
    print("-" * 80)

    # Latency Profiling
    print("Latency Overhead Profiling (Static Taint Propagation Engine):")
    print(f"  Cold-Start (Initial Run)    : {latency.cold_start_ms} ms")
    print(f"  Warmed-Up Median Latency    : {latency.warmed_median_ms} ms")
    print(f"  Warmed-Up Mean Latency      : {latency.warmed_mean_ms} ms")
    print(f"  Warmed-Up P95 Latency       : {latency.warmed_p95_ms} ms")
    print(f"  Warmed-Up Min / Max Latency : {latency.warmed_min_ms} ms / {latency.warmed_max_ms} ms")
    print("-" * 80)

    # Syntax Breakdown
    print("Detection Breakdown by GraphQL Syntax Category:")
    syntax_header = f"  {'Syntax Type':<20} | {'Cases':<6} | {'M1 Rec':<8} | {'M2 Rec':<8} | {'M3 Rec':<8} | {'M2 FP':<6} | {'M3 FP':<6}"
    print(syntax_header)
    print("  " + "-" * 76)
    for st, data in syntax_breakdown.items():
        print(f"  {st:<20} | {data['total_cases']:<6} | {data['m1_gateway_detection_rate'] * 100:>6.1f}% | {data['m2_static_detection_rate'] * 100:>6.1f}% | {data['m3_correlated_detection_rate'] * 100:>6.1f}% | {data['m2_static_false_positives']:<6} | {data['m3_correlated_false_positives']:<6}")
    print("=" * 80 + "\n")


def run_full_evaluation(corpus_path: str, iterations: int = 3) -> Dict[str, Any]:
    """Runs the complete multi-method evaluation and returns a structured dictionary."""
    corpus = load_and_validate_corpus(corpus_path)
    policy_engine = PolicyEngine()

    predictions = []
    for case in corpus:
        pred_record = evaluate_single_query_methods(case, policy_engine)
        predictions.append(pred_record)

    m1_metrics = compute_metrics_for_predictions(predictions, "method_1_gateway", "Method 1: Gateway Alone (Runtime Baseline)")
    m2_metrics = compute_metrics_for_predictions(predictions, "method_2_static_taint", "Method 2: Static Taint Analysis Alone")
    m3_metrics = compute_metrics_for_predictions(predictions, "method_3_correlated", "Method 3: Correlated Defense (Taint + Gateway)")

    syntax_breakdown = compute_syntax_breakdown(predictions)
    latency_profile = profile_latency(corpus, iterations=iterations)

    full_summary = {
        "metadata": {
            "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "corpus_file": corpus_path,
            "total_corpus_cases": len(corpus),
            "valid_security_cases": m1_metrics.total_evaluated,
            "malformed_syntax_cases": len(corpus) - m1_metrics.total_evaluated,
            "profiling_iterations": iterations,
        },
        "method_comparison": {
            "method_1_gateway_alone": m1_metrics.to_dict(),
            "method_2_static_taint_alone": m2_metrics.to_dict(),
            "method_3_correlated_defense": m3_metrics.to_dict(),
        },
        "latency_profile": latency_profile.to_dict(),
        "syntax_category_breakdown": syntax_breakdown,
        "predictions": predictions,
    }

    return full_summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate GraphQL BOLA Benchmark Corpus across Methods")
    parser.add_argument("--corpus", type=str, default="data/ground_truth_corpus.json", help="Path to ground-truth corpus JSON")
    parser.add_argument("--output", type=str, default=None, help="Path to export full JSON evaluation report")
    parser.add_argument("--iterations", type=int, default=3, help="Number of latency profiling iterations")
    parser.add_argument("--json", action="store_true", help="Print summary as JSON to stdout")
    args = parser.parse_args()

    summary = run_full_evaluation(args.corpus, iterations=args.iterations)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        m_comp = summary["method_comparison"]
        m1 = MethodMetrics(**m_comp["method_1_gateway_alone"])
        m2 = MethodMetrics(**m_comp["method_2_static_taint_alone"])
        m3 = MethodMetrics(**m_comp["method_3_correlated_defense"])
        lat = LatencyProfile(**summary["latency_profile"])
        format_terminal_report(
            corpus_len=summary["metadata"]["total_corpus_cases"],
            m1_metrics=m1,
            m2_metrics=m2,
            m3_metrics=m3,
            latency=lat,
            syntax_breakdown=summary["syntax_category_breakdown"],
        )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"Report exported to {args.output}")


if __name__ == "__main__":
    main()
