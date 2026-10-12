"""
Exporters for the GraphQL Authorization Differential Testing Engine
---------------------------------------------------------------------
Provides:
1. SARIF 2.1.0 Exporter (Static Analysis Results Interchange Format for GitHub / CI/CD)
2. JUnit XML Exporter (Standard unit/integration reporting for CI pipelines)
3. PoC Exploit Exporters (Executable cURL commands & standalone Python exploit scripts)
"""

from __future__ import annotations

import json
import xml.sax.saxutils as saxutils
from typing import Any, Dict, List, Optional

from app.core.security import create_access_token
from app.security.differential_testing.models import (
    DifferentialExecutionResult,
    DifferentialReport,
    DifferentialTestCase,
)


def export_sarif(report: DifferentialReport) -> Dict[str, Any]:
    """
    Transforms the differential evaluation report into standard SARIF 2.1.0 format
    for direct integration into GitHub Code Scanning and enterprise vulnerability managers.
    """
    sarif_rules = [
        {
            "id": "GQL-BOLA-001",
            "name": "GraphQLBrokenObjectLevelAuthorization",
            "shortDescription": {"text": "Direct Broken Object Level Authorization (BOLA/IDOR)"},
            "fullDescription": {"text": "Unauthorized principal requested a direct top-level entity owned by another tenant."},
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        },
        {
            "id": "GQL-NESTED-BOLA-002",
            "name": "GraphQLNestedTraversalBOLA",
            "shortDescription": {"text": "Nested Relationship Traversal BOLA"},
            "fullDescription": {"text": "Unauthorized principal navigated indirect relation edges to access unowned objects."},
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        },
        {
            "id": "GQL-MUTATION-BOLA-003",
            "name": "GraphQLMutationStateAlteringBOLA",
            "shortDescription": {"text": "State-Altering Mutation Unauthorized Modification"},
            "fullDescription": {"text": "Unauthorized principal executed a mutation that modifies or deletes another tenant's object."},
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        },
        {
            "id": "GQL-EXCESSIVE-DATA-004",
            "name": "GraphQLExcessiveSensitiveDataExposure",
            "shortDescription": {"text": "Excessive Sensitive Field Data Exposure"},
            "fullDescription": {"text": "Unprivileged caller probed protected sensitive fields (e.g. secret keys or tokens)."},
            "defaultConfiguration": {"level": "warning"},
            "helpUri": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        },
    ]

    results: List[Dict[str, Any]] = []

    for r in report.results:
        # Report cases where insecure baseline leaked data or policy divergence was detected
        if r.insecure_leaked_unauthorized_data or r.verdict == "POLICY_DIVERGENCE":
            tc = r.test_case
            rule_id = "GQL-BOLA-001"
            if tc.category == "MUTATION_BOLA" or "mutation" in tc.category.lower():
                rule_id = "GQL-MUTATION-BOLA-003"
            elif tc.is_nested or tc.category == "NESTED_BOLA":
                rule_id = "GQL-NESTED-BOLA-002"
            elif "FIELD" in tc.category or "secret" in tc.query.lower():
                rule_id = "GQL-EXCESSIVE-DATA-004"

            level = "error" if r.verdict == "POLICY_DIVERGENCE" else "warning"
            message_text = (
                f"[{r.verdict}] Test {tc.test_id} ({tc.name}): "
                f"Baseline leaked unauthorized data (HTTP {r.insecure_http_status}). "
                f"Gateway enforcement: {r.gateway_decision} ({r.gateway_reason}, HTTP {r.gateway_http_status})."
            )

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message_text},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"schema/{tc.schema_path}"},
                        "region": {"startLine": 1, "startColumn": 1}
                    }
                }],
                "properties": {
                    "test_id": tc.test_id,
                    "caller_id": tc.caller_id,
                    "target_object_id": tc.target_object_id,
                    "verdict": r.verdict,
                    "minimized_query": r.minimized_query,
                }
            })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GraphQL-Shield-Differential-Testing-Engine",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/graphql-shield",
                    "rules": sarif_rules,
                }
            },
            "results": results,
        }]
    }


def export_junit_xml(report: DifferentialReport) -> str:
    """Transforms differential evaluation results into standard JUnit XML format."""
    total = len(report.results)
    failures = sum(1 for r in report.results if r.verdict == "POLICY_DIVERGENCE")
    errors = 0
    duration_sec = round(report.total_duration_ms / 1000.0, 3)

    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites time="{duration_sec}">',
        f'  <testsuite name="GraphQL-Authorization-Differential-Suite" tests="{total}" failures="{failures}" errors="{errors}" time="{duration_sec}">',
    ]

    for r in report.results:
        tc = r.test_case
        escaped_name = saxutils.escape(f"{tc.test_id}: {tc.name}")
        classname = f"GraphQL.Differential.{tc.category}"
        t_sec = round(r.execution_time_ms / 1000.0, 4)

        xml_lines.append(f'    <testcase name="{escaped_name}" classname="{classname}" time="{t_sec}">')
        if r.verdict == "POLICY_DIVERGENCE":
            xml_lines.append(
                f'      <failure message="Policy Divergence: Gateway outcome contradicts least-privilege oracle">'
                f'Expected: {tc.expected_decision} ({tc.expected_reason}), Got Gateway: {r.gateway_decision} ({r.gateway_reason})'
                f'</failure>'
            )
        else:
            msg = f"Verdict: {r.verdict} | Gateway: {r.gateway_decision} | Baseline: HTTP {r.insecure_http_status}"
            xml_lines.append(f'      <system-out>{saxutils.escape(msg)}</system-out>')
        xml_lines.append('    </testcase>')

    xml_lines.append('  </testsuite>')
    xml_lines.append('</testsuites>')
    return "\n".join(xml_lines)


def generate_poc_curl(test: DifferentialTestCase, base_url: str = "http://127.0.0.1:8000") -> str:
    """Generates an executable cURL command with pre-minted authentication header for reproducing the test case."""
    token = None
    if test.caller_id is not None and test.caller_role != "anonymous":
        token = create_access_token(user_id=test.caller_id, role=test.caller_role)

    payload = {"query": test.query, "variables": test.variables}
    payload_json = json.dumps(payload, indent=2)

    auth_header = f'  -H "Authorization: Bearer {token}" \\\n' if token else ""
    return (
        f"# --- GraphQL Shield PoC: {test.test_id} ({test.category}) ---\n"
        f"# Target Endpoint: {base_url}/graphql\n"
        f"curl -X POST {base_url}/graphql \\\n"
        f'  -H "Content-Type: application/json" \\\n'
        f"{auth_header}"
        f"  --data '{payload_json}'"
    )


def generate_poc_python(test: DifferentialTestCase, base_url: str = "http://127.0.0.1:8000") -> str:
    """Generates a standalone Python exploit script using requests for reproducing the test case."""
    token = None
    if test.caller_id is not None and test.caller_role != "anonymous":
        token = create_access_token(user_id=test.caller_id, role=test.caller_role)

    query_escaped = test.query.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
    variables_repr = json.dumps(test.variables)

    return f"""#!/usr/bin/env python3
\"\"\"
Standalone Exploit / Verification Script for {test.test_id}
Category: {test.category}
Expected Decision: {test.expected_decision} ({test.expected_reason})
\"\"\"

import requests

BASE_URL = "{base_url}"
TOKEN = "{token or ''}"

headers = {{"Content-Type": "application/json"}}
if TOKEN:
    headers["Authorization"] = f"Bearer {{TOKEN}}"

payload = {{
    "query": \"\"\"{test.query}\"\"\",
    "variables": {variables_repr}
}}

print("[*] Probing Protected Gateway (/graphql)...")
resp_gw = requests.post(f"{{BASE_URL}}/graphql", json=payload, headers=headers)
print(f"    Gateway Status:   HTTP {{resp_gw.status_code}}")
print(f"    Gateway Response: {{resp_gw.text[:200]}}")

print("[*] Probing Insecure Baseline (/graphql-insecure)...")
resp_base = requests.post(f"{{BASE_URL}}/graphql-insecure", json=payload, headers=headers)
print(f"    Baseline Status:   HTTP {{resp_base.status_code}}")
print(f"    Baseline Response: {{resp_base.text[:200]}}")

if resp_gw.status_code in (401, 403) and resp_base.status_code == 200:
    print("\\n[+] VERDICT: VULNERABILITY PREVENTED BY GRAPHQL SHIELD GATEWAY!")
elif resp_gw.status_code == 200:
    print("\\n[!] VERDICT: ALLOWED")
else:
    print(f"\\n[-] Status: {{resp_gw.status_code}}")
"""
