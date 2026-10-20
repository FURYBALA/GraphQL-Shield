"""
FEATURE 7 - Real Exports (validated)
====================================
Produces SARIF 2.1.0 and JUnit XML **from actually executed results**, and
validates the generated documents against their expected structure.

Security policy for exports:
  * ``results`` in SARIF contain only findings confirmed against the *protected*
    gateway (real oracle contradictions).
  * Leaks observed on the labelled vulnerable fixture are recorded as
    informational baseline signals in ``run.properties.fixtureBaselineSignals``
    and never emitted as vulnerability findings.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_CATEGORY_RULE = {
    "DIRECT_BOLA": "GQL-BOLA-001",
    "NESTED_BOLA": "GQL-NESTED-BOLA-002",
    "MUTATION_BOLA": "GQL-MUTATION-BOLA-003",
    "ALIAS_MASKING": "GQL-ALIAS-BOLA-004",
    "VARIABLE_INJECTION": "GQL-VARIABLE-BOLA-005",
    "ORACLE_FALSE_POSITIVE": "GQL-ORACLE-FALSE-POSITIVE-006",
}

_RULES = [
    ("GQL-BOLA-001", "GraphQLDirectBOLA", "Direct Broken Object Level Authorization", "error"),
    ("GQL-NESTED-BOLA-002", "GraphQLNestedBOLA", "Nested relationship traversal BOLA", "error"),
    ("GQL-MUTATION-BOLA-003", "GraphQLMutationBOLA", "Unauthorized state-altering mutation", "error"),
    ("GQL-ALIAS-BOLA-004", "GraphQLAliasBOLA", "Alias-cloaked BOLA", "error"),
    ("GQL-VARIABLE-BOLA-005", "GraphQLVariableBOLA", "Variable-parameterized BOLA", "error"),
    ("GQL-ORACLE-FALSE-POSITIVE-006", "GraphQLOracleFalsePositive", "Authorization false positive", "warning"),
]


def _rule_id(category: str) -> str:
    return _CATEGORY_RULE.get(category, "GQL-BOLA-001")


def export_sarif(executions: List[Any], tool_version: str = "1.0.0") -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    fixture_signals: List[Dict[str, Any]] = []

    for ex in executions:
        test = ex.test
        if ex.finding is not None and not ex.finding.fixture:
            f = ex.finding
            results.append(
                {
                    "ruleId": _rule_id(f.category),
                    "level": "error" if f.severity == "high" else "warning",
                    "message": {"text": f"{f.title}. Expected {f.expected}; observed {f.observed}."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"schema/{f.schema_path}"},
                                "region": {"startLine": 1, "startColumn": 1},
                            }
                        }
                    ],
                    "fingerprints": {"graphql-shield/v1": f.test_id},
                    "properties": {
                        "test_id": f.test_id,
                        "caller_id": f.caller_id,
                        "target_object_id": f.target_object_id,
                        "expected": f.expected,
                        "observed": f.observed,
                        "evidence": f.evidence,
                        "reproducible": f.reproducible,
                        "minimized_query": f.minimized_query,
                        "query": f.query,
                    },
                }
            )
        elif ex.insecure_leaked:
            fixture_signals.append(
                {
                    "test_id": test.test_id,
                    "schema_path": test.schema_path,
                    "category": test.category,
                    "note": "Confirmed leak on the labelled local vulnerable fixture (baseline sensitivity signal, not a finding).",
                }
            )

    rules = [
        {
            "id": rid,
            "name": name,
            "shortDescription": {"text": desc},
            "defaultConfiguration": {"level": level},
        }
        for rid, name, desc, level in _RULES
    ]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GraphQL-Shield-Authorization-Engine",
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"fixtureBaselineSignals": fixture_signals},
            }
        ],
    }


def export_junit(executions: List[Any], suite_name: str = "GraphQL-Authorization-Engine") -> str:
    total = len(executions)
    failures = sum(1 for e in executions if e.status == "FAIL")
    skipped = sum(1 for e in executions if e.status == "INCONCLUSIVE")
    errors = 0
    total_time = round(sum(e.duration_ms for e in executions) / 1000.0, 3)

    def esc(text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="{esc(suite_name)}" tests="{total}" failures="{failures}" errors="{errors}" skipped="{skipped}" time="{total_time}">',
        f'  <testsuite name="{esc(suite_name)}" tests="{total}" failures="{failures}" errors="{errors}" skipped="{skipped}" time="{total_time}">',
    ]
    for ex in executions:
        name = esc(f"{ex.test.test_id}: {ex.test.name}")
        classname = esc(f"GraphQL.Engine.{ex.test.category}")
        t = round(ex.duration_ms / 1000.0, 4)
        lines.append(f'    <testcase classname="{classname}" name="{name}" time="{t}">')
        if ex.status == "FAIL" and ex.finding is not None:
            lines.append(
                f'      <failure message="{esc(ex.finding.title)}" type="{esc(ex.reason_class)}">'
                f'{esc(ex.finding.evidence)}'
                f'&#10;query: {esc(ex.finding.query)}'
                f'&#10;minimized: {esc(ex.finding.minimized_query or "n/a")}'
                f"</failure>"
            )
        elif ex.status == "INCONCLUSIVE":
            lines.append(f'      <skipped message="{esc(ex.verdict_detail or "inconclusive")}"/>')
        else:
            lines.append(f'      <system-out>{esc(ex.verdict_detail or ex.reason_class)}</system-out>')
        lines.append("    </testcase>")
    lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Structural validators
# ---------------------------------------------------------------------------

def validate_sarif(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if data.get("version") != "2.1.0":
        errors.append("version must be 2.1.0")
    if not isinstance(data.get("$schema"), str):
        errors.append("$schema missing")
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("runs must be a non-empty list")
        return (not errors), errors
    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    if not driver.get("name"):
        errors.append("tool.driver.name missing")
    if not isinstance(driver.get("rules"), list) or not driver["rules"]:
        errors.append("tool.driver.rules must be a non-empty list")
    for i, res in enumerate(run.get("results", [])):
        if not res.get("ruleId"):
            errors.append(f"results[{i}].ruleId missing")
        if not res.get("message", {}).get("text"):
            errors.append(f"results[{i}].message.text missing")
        if not res.get("locations"):
            errors.append(f"results[{i}].locations missing")
        if not res.get("fingerprints"):
            errors.append(f"results[{i}].fingerprints missing")
    return (not errors), errors


def validate_junit(xml_str: str) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        return False, [f"XML parse error: {exc}"]
    if root.tag != "testsuites":
        errors.append("root element must be <testsuites>")
    testcases = root.findall(".//testcase")
    declared = root.get("tests")
    if declared is None:
        errors.append("testsuites@tests missing")
    else:
        try:
            if int(declared) != len(testcases):
                errors.append(f"testsuites@tests ({declared}) != testcase count ({len(testcases)})")
        except ValueError:
            errors.append("testsuites@tests not an integer")
    for tc in testcases:
        if not tc.get("name"):
            errors.append("testcase@name missing")
        if not tc.get("classname"):
            errors.append("testcase@classname missing")
    return (not errors), errors
