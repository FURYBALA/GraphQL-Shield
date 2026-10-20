"""
CCNS Research Lab - Data Models
===============================
Defines typed models for datasets, ground-truth cases, experiment definitions,
method configurations, per-case predictions, ablation studies, and evaluation metrics.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DatasetMetadata(BaseModel):
    id: str
    version: str
    name: str
    description: str
    source_file: str
    total_cases: int = 0
    valid_security_cases: int = 0
    malformed_syntax_cases: int = 0
    created_at: Optional[str] = None


class TestCaseRecord(BaseModel):
    id: str
    dataset_id: str
    name: str
    category: str
    syntax_type: str = "BASIC"
    split: str = "tuning"  # tuning, held_out, adversarial_stress
    caller_user_id: Optional[int] = None
    caller_role: str = "user"
    caller_tenant_id: Optional[str] = None
    query: str
    variables: Dict[str, Any] = Field(default_factory=dict)
    operation_name: Optional[str] = None
    target_object_id: Optional[int] = None
    target_object_type: str = "Resource"
    true_owner_id: Optional[int] = None
    target_tenant_id: Optional[str] = None
    expected_paths: List[str] = Field(default_factory=list)
    ground_truth_security: str  # VULNERABLE, BENIGN, MALFORMED, INCONCLUSIVE
    ground_truth_attack_type: Optional[str] = None
    expected_gateway_decision: str = "DENY"
    rationale: str = ""
    provenance: str = "constructed_benchmark"
    is_excluded: bool = False
    exclusion_reason: Optional[str] = None
    version: int = 1
    created_at: Optional[str] = None


class CaseReviewRequest(BaseModel):
    new_security: str  # VULNERABLE, BENIGN, MALFORMED, INCONCLUSIVE
    new_attack_type: Optional[str] = None
    reviewer: str = "Analyst"
    review_rationale: str


class AddCaseRequest(BaseModel):
    name: str
    category: str
    syntax_type: str = "BASIC"
    split: str = "tuning"
    caller_user_id: Optional[int] = None
    caller_role: str = "user"
    caller_tenant_id: Optional[str] = None
    query: str
    variables: Dict[str, Any] = Field(default_factory=dict)
    operation_name: Optional[str] = None
    target_object_id: Optional[int] = None
    target_object_type: str = "Resource"
    true_owner_id: Optional[int] = None
    target_tenant_id: Optional[str] = None
    expected_paths: List[str] = Field(default_factory=list)
    ground_truth_security: str  # VULNERABLE, BENIGN, MALFORMED, INCONCLUSIVE
    ground_truth_attack_type: Optional[str] = None
    expected_gateway_decision: str = "DENY"
    rationale: str = ""
    provenance: str = "manual_authorized_test"


class EvaluationMetrics(BaseModel):
    total_cases: int
    evaluated_cases: int
    excluded_cases: int
    inconclusive_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    accuracy: Optional[float] = None
    specificity: Optional[float] = None
    false_positive_rate: Optional[float] = None
    false_negative_rate: Optional[float] = None
    coverage_rate: Optional[float] = None
    inconclusive_rate: Optional[float] = None
    mean_latency_ms: Optional[float] = None
    duration_ms: Optional[float] = None
    # Phase 2 Path Attribution Metrics
    path_precision: Optional[float] = None
    path_recall: Optional[float] = None
    path_exact_match_rate: Optional[float] = None
    path_root_match_rate: Optional[float] = None
    total_expected_paths: int = 0
    total_reported_paths: int = 0
    total_matched_paths: int = 0
    target_object_match_rate: Optional[float] = None
    evidence_provenance_completeness: Optional[float] = None
    mutation_tamper_prevention_rate: Optional[float] = None
    total_mutations_tested: int = 0
    total_mutations_protected: int = 0


class ConfusionMatrix(BaseModel):
    tp: int
    fp: int
    tn: int
    fn: int
    inconclusive: int = 0
    excluded: int = 0


class PredictionRecord(BaseModel):
    case_id: str
    method_id: str
    predicted_security: str  # VULNERABLE, BENIGN, MALFORMED, INCONCLUSIVE
    predicted_attack_type: Optional[str] = None
    is_conclusive: bool = True
    inconclusive_reason: Optional[str] = None
    classification_outcome: str  # TP, FP, TN, FN, EXCLUDED, INCONCLUSIVE
    execution_id: Optional[str] = None
    reported_paths: List[str] = Field(default_factory=list)
    expected_paths: List[str] = Field(default_factory=list)
    path_exact_match: bool = False
    evidence: Dict[str, Any] = Field(default_factory=dict)


class MethodRunResult(BaseModel):
    method_id: str
    method_name: str
    method_version: str
    metrics: EvaluationMetrics
    confusion_matrix: ConfusionMatrix
    execution_time_ms: float = 0.0


class AblationResult(BaseModel):
    ablation_id: str
    ablation_name: str
    baseline_method_id: str
    ablated_method_id: str
    shared_cases_count: int
    metrics_baseline: EvaluationMetrics
    metrics_ablated: EvaluationMetrics
    precision_delta: Optional[float] = None
    recall_delta: Optional[float] = None
    f1_delta: Optional[float] = None
    changed_cases: List[Dict[str, Any]] = Field(default_factory=list)
    statistical_test: Optional[Dict[str, Any]] = None


class ExperimentManifest(BaseModel):
    experiment_id: str
    dataset_id: str
    dataset_version: str
    methods_evaluated: List[str]
    software_version: str = "2.1.0"
    python_version: str
    environment: str = "development"
    random_seed: int = 42
    timestamp: str
    protocol_version: str = "CCNS-EVAL-V2"
    exclusions_count: int = 0
    failures_count: int = 0


class ExperimentRunResponse(BaseModel):
    id: str
    name: str
    description: str
    dataset_id: str
    status: str
    manifest: ExperimentManifest
    method_runs: List[MethodRunResult]
    ablations: List[AblationResult]
    started_at: str
    completed_at: Optional[str] = None


class ExperimentRunRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    dataset_id: str = "ds_benchmark_v1"
    include_ablations: bool = True
    categories_filter: Optional[List[str]] = None
    split_filter: Optional[str] = None  # None (all), "tuning", "held_out", "adversarial_stress"
    exclude_malformed: bool = True


class CoverageBreakdown(BaseModel):
    dataset_id: str
    dataset_version: str
    total_cases: int
    valid_security_cases: int
    malformed_syntax_cases: int
    by_split: Dict[str, int]
    by_category: Dict[str, int]
    by_security: Dict[str, int]
    by_syntax: Dict[str, int]
    leakage_free: bool = True
    splits_disjoint: bool = True
    unsupported_features_limitations: List[str] = Field(default_factory=list)

