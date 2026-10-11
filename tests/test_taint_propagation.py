"""
Tests for AST-Driven Context-Sensitive Taint Propagation Engine (Phase 4)

Verifies:
1. Direct untrusted-ID lookup analysis.
2. Nested collection traversal without child ID (indirect candidate).
3. Explicit child-ID traversal.
4. Applicable verified boundary evidence (negative case: not vulnerable).
5. Missing / unverified boundary evidence recording uncertainty reasons.
6. Variables resolution and argument binding.
7. Alias preservation (tracking both response_path and schema_path).
8. Named fragment expansion.
9. Inline fragment expansion.
10. Multiple root field selections.
11. Cyclic type relationships and recursion bounding.
12. Public or non-sensitive fields (safe unprotected paths, no false positives).
13. Malformed queries and missing variables handling.
"""

from typing import List, Optional
import pytest
import strawberry

from app.security.security_graph import SecurityGraph
from app.security.taint_engine import (
    QueryAnalysisReport,
    TaintPropagationEngine,
    analyze_query_taint,
)
from app.security.taint_model import (
    BoundaryClassification,
    BoundaryEvidence,
    BoundaryScope,
    CandidateKind,
    TaintAnalysisModel,
)


# Module-level synthetic types for cyclic test
@strawberry.type
class CyclicPost:
    id: int
    author: "CyclicUser"

@strawberry.type
class CyclicUser:
    id: int
    posts: List[CyclicPost]

@strawberry.type
class CyclicQuery:
    @strawberry.field
    def user(self, id: int) -> Optional[CyclicUser]:
        raise NotImplementedError


# =============================================================================
# 1. POSITIVE & NEGATIVE CANDIDATE TESTS
# =============================================================================

def test_01_direct_untrusted_id_lookup():
    """Direct root lookup with untrusted ID produces DIRECT_BOLA_CANDIDATE."""
    query = "query { resource(id: 102) { name } }"
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    assert len(report.direct_bola_candidates) == 1
    assert len(report.indirect_bola_candidates) == 0

    candidate = report.direct_bola_candidates[0]
    assert candidate.propagation_context.field_path == "resource"
    assert candidate.propagation_context.step_depth == 0
    assert candidate.sensitive_sink.sink_id == "sink:ResourceType"
    assert candidate.risk_assessment == "HIGH"
    assert candidate.taint_source is not None
    assert candidate.taint_source.argument_name == "id"


def test_02_nested_collection_traversal_without_child_id():
    """Nested collection traversal without child ID produces INDIRECT_BOLA_CANDIDATE."""
    query = "query { user(id: 101) { resources { id name } } }"
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    assert len(report.direct_bola_candidates) == 1  # user
    assert len(report.indirect_bola_candidates) == 1  # user.resources

    indirect = report.indirect_bola_candidates[0]
    assert indirect.propagation_context.field_path == "user.resources"
    assert indirect.propagation_context.step_depth == 1
    assert indirect.propagation_context.is_collection is True
    assert indirect.sensitive_sink.sink_id == "sink:ResourceType"
    assert indirect.boundary_evidence.classification == BoundaryClassification.NO_BOUNDARY_IDENTIFIED
    assert "Collection navigation has no field-level identifier argument." in indirect.assumptions_and_uncertainties


def test_03_explicit_child_id_traversal():
    """Nested lookup with explicit child ID produces parameterized INDIRECT_BOLA_CANDIDATE."""
    query = "query { user(id: 101) { resource(id: 102) { name } } }"
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    assert len(report.direct_bola_candidates) == 1  # user
    assert len(report.indirect_bola_candidates) == 1  # user.resource

    indirect = report.indirect_bola_candidates[0]
    assert indirect.propagation_context.field_path == "user.resource"
    assert indirect.propagation_context.step_depth == 1
    assert indirect.propagation_context.argument_name == "id"
    assert indirect.taint_source is not None


def test_04_applicable_verified_boundary_negative_case():
    """Negative case: When verified boundary evidence is present, path is VERIFIED_PROTECTED_PATH."""
    query = "query { resource(id: 101) { name } }"

    def verified_boundary_evaluator(ctx, source, sink):
        return BoundaryEvidence(
            classification=BoundaryClassification.VERIFIED_BOUNDARY,
            scope=BoundaryScope.OBJECT_LEVEL,
            mechanism="GATEWAY_PRE_EXECUTION_POLICY",
            principal_bound=True,
            target_bound=True,
            mandatory_on_path=True,
            covers_operation=True,
            policy_enforced="OWNER_MATCH",
            uncertainty_reasons=(),
        )

    engine = TaintPropagationEngine(boundary_evaluator=verified_boundary_evaluator)
    report = engine.analyze_document(query)

    assert report.is_valid_query is True
    assert len(report.direct_bola_candidates) == 0
    assert len(report.verified_protected_paths) == 1

    verified_finding = report.verified_protected_paths[0]
    assert verified_finding.candidate_kind == CandidateKind.VERIFIED_PROTECTED_PATH
    assert verified_finding.risk_assessment == "LOW"
    assert verified_finding.boundary_evidence.is_verified is True


def test_05_missing_or_unverified_boundary_uncertainties():
    """Unverified boundaries record explicit assumptions and uncertainties."""
    query = "query { resource(id: 102) { name } }"
    report = analyze_query_taint(query)

    candidate = report.direct_bola_candidates[0]
    assert candidate.boundary_evidence.is_verified is False
    assert len(candidate.assumptions_and_uncertainties) >= 1
    assert any("ownership" in u.lower() for u in candidate.assumptions_and_uncertainties)


# =============================================================================
# 2. GRAPHQL SYNTAX & NORMALIZATION TESTS
# =============================================================================

def test_06_variables_resolution():
    """Resolves variable arguments and links them to taint sources."""
    query = "query GetResource($resId: Int!) { resource(id: $resId) { name } }"
    variables = {"resId": 505}
    report = analyze_query_taint(query, variables=variables)

    assert report.is_valid_query is True
    step = next(s for s in report.propagation_steps if s.schema_path == "resource")
    assert step.arguments["id"] == 505
    assert "resId" in step.source_variables
    assert step.relevant_id_arguments["id"] == 505


def test_07_aliases_preservation():
    """Preserves client response path while tracking canonical schema path."""
    query = "query { myResource: resource(id: 101) { secretName: name } }"
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    step1 = report.propagation_steps[0]
    assert step1.schema_path == "resource"
    assert step1.response_path == "myResource"
    assert step1.field_name == "resource"
    assert step1.response_name == "myResource"

    step2 = report.propagation_steps[1]
    assert step2.schema_path == "resource.name"
    assert step2.response_path == "myResource.secretName"


def test_08_named_fragments():
    """Expands and analyzes selections inside named fragment spreads."""
    query = """
    fragment ResDetails on ResourceType {
      id
      name
    }
    query {
      resource(id: 101) {
        ...ResDetails
      }
    }
    """
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    paths = [s.schema_path for s in report.propagation_steps]
    assert "resource" in paths
    assert "resource.id" in paths
    assert "resource.name" in paths


def test_09_inline_fragments():
    """Expands and analyzes selections inside inline fragments."""
    query = """
    query {
      resource(id: 101) {
        ... on ResourceType {
          name
        }
      }
    }
    """
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    paths = [s.schema_path for s in report.propagation_steps]
    assert "resource" in paths
    assert "resource.name" in paths


def test_10_multiple_root_fields():
    """Analyzes multi-root queries as parallel independent branches."""
    query = """
    query {
      r1: resource(id: 101) { name }
      r2: resource(id: 102) { name }
    }
    """
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    assert len(report.direct_bola_candidates) == 2
    paths = [f.propagation_context.field_path for f in report.direct_bola_candidates]
    assert paths == ["resource", "resource"]

    response_paths = [s.response_path for s in report.propagation_steps if s.field_name == "resource"]
    assert "r1" in response_paths
    assert "r2" in response_paths


# =============================================================================
# 3. ADVANCED TOPOLOGY & EDGE CASES
# =============================================================================

def test_11_cyclic_type_relationships():
    """Detects cycles and bounds traversal safely without recursion errors."""
    synth_schema = strawberry.Schema(query=CyclicQuery)
    graph = SecurityGraph.from_schema(synth_schema)
    engine = TaintPropagationEngine(security_graph=graph, max_traversal_depth=6)

    query = """
    query {
      user(id: 1) {
        posts {
          author {
            posts {
              author {
                posts {
                  id
                }
              }
            }
          }
        }
      }
    }
    """
    report = engine.analyze_document(query)

    assert report.is_valid_query is True
    assert report.has_cycles is True
    assert report.max_depth_reached <= 6


def test_12_public_non_sensitive_fields():
    """Public infrastructure fields produce SAFE_UNPROTECTED_PATH without false positive BOLA."""
    query = "query { health { status message } }"
    report = analyze_query_taint(query)

    assert report.is_valid_query is True
    assert len(report.direct_bola_candidates) == 0
    assert len(report.indirect_bola_candidates) == 0
    assert len(report.safe_unprotected_paths) == 1
    assert report.safe_unprotected_paths[0].propagation_context.field_path == "health"


def test_13_malformed_queries_and_missing_variables():
    """Malformed queries and missing variable values fail gracefully."""
    # Syntax error
    report_malformed = analyze_query_taint("query { resource(id: ) }")
    assert report_malformed.is_valid_query is False
    assert report_malformed.error_message is not None

    # Missing variable value
    query_var = "query Get($id: Int!) { resource(id: $id) { name } }"
    report_missing_var = analyze_query_taint(query_var, variables={})
    assert report_missing_var.is_valid_query is True
    step = next(s for s in report_missing_var.propagation_steps if s.schema_path == "resource")
    assert step.arguments["id"] is None
