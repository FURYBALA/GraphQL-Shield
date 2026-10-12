"""
Data Models for the GraphQL Authorization Differential Testing Engine
-----------------------------------------------------------------------
Defines structured representations for discovered schema paths, generated
differential test cases, execution results, oracles, and research evaluation metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SchemaPathDescriptor(BaseModel):
    """Represents a discovered object-returning field or navigation path in the GraphQL schema."""
    canonical_path: str = Field(..., description="Canonical schema path (e.g. 'Query.user', 'UserType.resource')")
    path_key: str = Field(default="", description="Normalized query path key (e.g. 'user', 'user.resource')")
    root_field: str = Field(..., description="Root query field (e.g. 'user', 'resource')")
    field_name: str = Field(..., description="Leaf field name (e.g. 'resource')")
    parent_type: str = Field(..., description="Parent GraphQL type (e.g. 'Query', 'UserType')")
    target_type: str = Field(..., description="Return GraphQL type (e.g. 'ResourceType')")
    is_nested: bool = Field(False, description="True if reached via relationship edge")
    arguments: List[str] = Field(default_factory=list, description="Supported arguments (e.g. ['id'])")
    is_collection: bool = Field(False, description="True if returns a list")
    is_sensitive_sink: bool = Field(True, description="True if exposes a protected domain entity")


class DifferentialTestCase(BaseModel):
    """A generated controlled authorization test variant."""
    test_id: str
    name: str
    category: str = Field(..., description="DIRECT_BOLA, NESTED_BOLA, BENIGN_OWNER, ADMIN_OVERRIDE, ANONYMOUS, ALIAS_MASKING, VARIABLE_INJECTION")
    query: str
    variables: Dict[str, Any] = Field(default_factory=dict)
    operation_name: Optional[str] = None
    
    # Principal & Target Context
    caller_id: Optional[int] = None
    caller_role: str = "user"  # "user", "admin", "anonymous"
    target_object_type: str = "Resource"
    target_object_id: Optional[int] = None
    target_owner_id: Optional[int] = None
    
    # Path & Structure
    schema_path: str
    response_path: str
    is_nested: bool = False
    has_alias: bool = False
    
    # Authorization Oracle (Expected Outcome)
    expected_decision: str = "DENY"  # "ALLOW" or "DENY"
    expected_reason: str = "OWNERSHIP_MISMATCH"
    expected_http_status: int = 403  # 200, 401, 403
    oracle_rationale: str = ""


class DifferentialExecutionResult(BaseModel):
    """The observed outcome of executing a differential test case against Gateway and Baseline."""
    test_case: DifferentialTestCase
    
    # Gateway Enforcement Observation
    gateway_http_status: int
    gateway_decision: str  # "ALLOW", "DENY"
    gateway_reason: str
    gateway_risk_score: int
    gateway_risk_level: str
    gateway_data_returned: bool
    gateway_error_message: Optional[str] = None
    
    # Insecure Baseline Observation (Raw Resolver without Gateway)
    insecure_http_status: int
    insecure_data_returned: bool
    insecure_leaked_unauthorized_data: bool = False
    
    # Differential Analysis Verdict
    verdict: str = Field(..., description="PROTECTED_MATCH, VULNERABILITY_PREVENTED, POLICY_DIVERGENCE, PATH_INCONSISTENCY")
    is_conforming_to_oracle: bool = True
    vulnerability_mitigated_by_gateway: bool = False
    path_inconsistency_detected: bool = False
    
    # Reproducibility & Performance
    is_reproducible: bool = True
    execution_time_ms: float = 0.0
    
    # Trace & Minimizer Evidence
    minimized_query: Optional[str] = None
    taint_candidate_kind: Optional[str] = None
    taint_correlation_status: Optional[str] = None
    evidence_summary: str = ""


class DifferentialReport(BaseModel):
    """Comprehensive research evaluation report summarizing differential testing results."""
    timestamp: str
    total_test_cases: int
    schema_paths_discovered: int
    schema_paths_tested: int
    schema_path_coverage_pct: float
    
    # Findings & Security Metrics
    total_conforming_cases: int
    policy_divergence_count: int
    seeded_defects_evaluated: int
    seeded_defects_prevented: int
    vulnerability_prevention_rate_pct: float
    path_inconsistencies_detected: int
    false_positives: int
    false_positive_rate_pct: float
    reproducibility_rate_pct: float
    
    # Execution Cost
    total_duration_ms: float
    mean_latency_per_test_ms: float
    
    # Baseline Comparison
    baseline_comparison: Dict[str, Any] = Field(default_factory=dict)
    
    # Detailed Results
    results: List[DifferentialExecutionResult] = Field(default_factory=list)
