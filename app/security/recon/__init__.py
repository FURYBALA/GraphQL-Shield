"""
Real-Time GraphQL Authorization Research Engine
===============================================
Extends the existing differential-testing engine with:

  * FEATURE 1  Live schema reconnaissance (HTTP introspection or SDL)
  * FEATURE 2  Automated authorization test generation from discovered operations
  * FEATURE 3  Real HTTP execution with bounded concurrency + cancellation
  * FEATURE 4  Differential security oracle against a labelled vulnerable fixture
  * FEATURE 5  AST-aware delta-debugging reproduction
  * FEATURE 6  Workbench API
  * FEATURE 7  Validated SARIF 2.1 / JUnit exports
  * FEATURE 8  Academic evaluation harness

This package deliberately reuses the gateway, AST taint analysis, schema-aware
ownership inference, policy engine, minimizer and exporters that already exist
in the repository rather than re-implementing them.
"""

from .models import (  # noqa: F401
    DiscoveryResult,
    SchemaFieldRef,
    GeneratedTest,
    Finding,
    TestExecution,
    RunState,
)
from .introspection import (  # noqa: F401
    discover_local_schema,
    discover_from_sdl,
    discover_from_introspection,
    discover_live,
    INTROSPECTION_QUERY,
)
from .generator import generate_tests_from_discovery  # noqa: F401
from .oracle import compute_expected_outcome, POLICY_ENGINE  # noqa: F401
from .executor import LiveExecutor, HttpObservation  # noqa: F401
from .reproducer import Reproducer, validate_reproduction  # noqa: F401
from .engine import AuthorizationEngine, ENGINE, run_engine_blocking  # noqa: F401

__all__ = [
    "DiscoveryResult",
    "SchemaFieldRef",
    "GeneratedTest",
    "Finding",
    "TestExecution",
    "RunState",
    "discover_local_schema",
    "discover_from_sdl",
    "discover_from_introspection",
    "discover_live",
    "INTROSPECTION_QUERY",
    "generate_tests_from_discovery",
    "compute_expected_outcome",
    "POLICY_ENGINE",
    "LiveExecutor",
    "HttpObservation",
    "Reproducer",
    "validate_reproduction",
    "AuthorizationEngine",
    "ENGINE",
    "run_engine_blocking",
]
