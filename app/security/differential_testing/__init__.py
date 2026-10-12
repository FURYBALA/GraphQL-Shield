"""
GraphQL Authorization Differential Testing Engine
-------------------------------------------------
Automated discovery of GraphQL schema paths, controlled test generation,
differential execution against Gateway vs Insecure Baseline, oracle comparison,
query delta-debugging minimization, and empirical research evaluation.
"""

from .models import (
    DifferentialTestCase,
    DifferentialExecutionResult,
    DifferentialReport,
    SchemaPathDescriptor,
)
from .generator import discover_schema_paths, generate_differential_suite
from .minimizer import minimize_query
from .executor import DifferentialTestExecutor, run_differential_testing_suite
from .exporters import (
    export_sarif,
    export_junit_xml,
    generate_poc_curl,
    generate_poc_python,
)

__all__ = [
    "DifferentialTestCase",
    "DifferentialExecutionResult",
    "DifferentialReport",
    "SchemaPathDescriptor",
    "discover_schema_paths",
    "generate_differential_suite",
    "minimize_query",
    "DifferentialTestExecutor",
    "run_differential_testing_suite",
    "export_sarif",
    "export_junit_xml",
    "generate_poc_curl",
    "generate_poc_python",
]
