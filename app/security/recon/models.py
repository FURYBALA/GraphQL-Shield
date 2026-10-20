"""
Pydantic data models for the Real-Time GraphQL Authorization Research Engine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SchemaFieldRef(BaseModel):
    """A single object-returning field / navigation edge discovered from the real schema."""

    canonical_path: str = Field(..., description="e.g. 'Query.resource' or 'UserType.resource'")
    path_key: str = Field(..., description="Query navigation key, e.g. 'user.resource'")
    root_field: str
    field_name: str
    parent_type: str
    target_type: str
    is_nested: bool = False
    is_collection: bool = False
    arguments: List[str] = Field(default_factory=list)
    argument_types: Dict[str, str] = Field(default_factory=dict)
    id_argument: Optional[str] = None
    is_sensitive_sink: bool = False
    authorization_boundary_fields: List[str] = Field(default_factory=list)
    # discovered = explicitly reachable root entity accessor with an id argument
    # inferred   = relationship edge reachable from a root entity
    # unverified = object-returning field not reachable from any known root
    relationship_status: str = "discovered"
    discovery_source: str = "introspection"  # introspection | sdl


class DiscoveryResult(BaseModel):
    target: str
    source: str  # introspection | sdl
    introspectable: bool
    schema_types_analyzed: int
    roots: List[str] = Field(default_factory=list)
    operations: Dict[str, List[str]] = Field(default_factory=dict)
    fields: List[SchemaFieldRef] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)

    def by_status(self, status: str) -> List[SchemaFieldRef]:
        return [f for f in self.fields if f.relationship_status == status]


class GeneratedTest(BaseModel):
    test_id: str
    name: str
    category: str
    # seeded_fixture = derived from explicitly seeded local accounts/resources
    # exploratory    = derived from discovered structure without a known seed owner
    provenance: str = "seeded_fixture"
    schema_path: str
    query: str
    variables: Dict[str, Any] = Field(default_factory=dict)
    operation_name: Optional[str] = None
    caller_id: Optional[int] = None
    caller_role: str = "user"
    target_object_type: str = "Resource"
    target_object_id: Optional[int] = None
    target_owner_id: Optional[int] = None
    is_mutation: bool = False
    expected_decision: str = "DENY"
    expected_reason: str = "OWNERSHIP_MISMATCH"
    expected_http_status: int = 403
    oracle_rationale: str = ""
    generator_rule: str = ""


class Finding(BaseModel):
    test_id: str
    severity: str = "high"  # high | medium
    title: str
    schema_path: str
    category: str
    query: str
    variables: Dict[str, Any] = Field(default_factory=dict)
    caller_id: Optional[int] = None
    caller_role: str = "user"
    target_object_type: str = "Resource"
    target_object_id: Optional[int] = None
    expected: str = ""
    observed: str = ""
    evidence: str = ""
    # True  -> confirmed against the protected gateway (a real finding)
    # False -> observed on the labelled vulnerable local fixture (baseline signal)
    fixture: bool = False
    reproducible: bool = False
    minimized_query: Optional[str] = None
    repro_reexecuted: Optional[bool] = None


class TestExecution(BaseModel):
    test: GeneratedTest
    status: str = "PENDING"  # PASS | FAIL | INCONCLUSIVE
    reason_class: str = ""  # CONFIRMED_VULNERABILITY | ORACLE_FALSE_POSITIVE | FIXTURE_LEAK | OK_DENIED | OK_ALLOWED | ERROR
    gateway_http_status: Optional[int] = None
    gateway_decision: Optional[str] = None
    gateway_reason: Optional[str] = None
    gateway_risk_level: Optional[str] = None
    gateway_returned_object: Optional[Dict[str, Any]] = None
    gateway_error: Optional[str] = None
    insecure_http_status: Optional[int] = None
    insecure_returned_object: Optional[Dict[str, Any]] = None
    insecure_leaked: Optional[bool] = None
    insecure_state_changed: Optional[bool] = None
    state_changed: Optional[bool] = None
    duration_ms: float = 0.0
    verdict_detail: str = ""
    error: Optional[str] = None
    finding: Optional[Finding] = None


class RunState(BaseModel):
    session_id: str
    status: str = "pending"  # pending | running | completed | cancelled | failed
    base_url: str = ""
    concurrency: int = 4
    total: int = 0
    completed: int = 0
    started_at: str = ""
    finished_at: Optional[str] = None
    cancel_requested: bool = False
    current: Optional[str] = None
    error: Optional[str] = None
    discovery: Optional[DiscoveryResult] = None
    executions: List[TestExecution] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
