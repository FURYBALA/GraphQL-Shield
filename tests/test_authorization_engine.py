"""
Acceptance tests for the Real-Time GraphQL Authorization Research Engine
(``app/security/recon``).

The engine executes *real HTTP* requests. To avoid spawning a live server in CI
these tests drive the FastAPI app through ``httpx.ASGITransport`` (the same
request path the gateway serves over the network, minus the socket).

Covered acceptance criteria:
  1. start the application and discover the schema without manual paths
  2. generate tests from the discovered schema
  3. execute real requests and inspect their responses
  4. a legitimate owner request succeeds
  5. a cross-owner request is denied by the protected gateway
  6. the deliberately vulnerable local fixture demonstrates a real leak
  7. findings are verified against returned data / state, never HTTP status alone
  8. a confirmed violation reproduces and is minimized
  9. SARIF / JUnit exports are structurally valid and match executed results
 10. the automated suite runs and records results (summary)
"""

from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET

import httpx
import pytest

from app.main import app, startup_event
from app.security.recon.engine import AuthorizationEngine, ENGINE
from app.security.recon.executor import LiveExecutor
from app.security.recon.generator import generate_tests_from_discovery
from app.security.recon.introspection import (
    discover_from_sdl,
    discover_local_schema,
    discover_live,
)
from app.security.recon.models import GeneratedTest
from app.security.recon.reproducer import Reproducer, make_predicate
from app.seed import seed_database

BASE = "http://engine.test"


def _run_engine(**kwargs):
    async def go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE
        ) as client:
            return await ENGINE.run_now(BASE, client=client, **kwargs)

    return asyncio.run(go())


@pytest.fixture(scope="module")
def engine_run():
    seed_database()
    startup_event()
    return _run_engine(concurrency=4)


# ---------------------------------------------------------------------------
# 1. Schema reconnaissance (no hardcoded paths)
# ---------------------------------------------------------------------------
def _sample_sdl() -> str:
    return """
    type Query {
        gadget(id: Int!): Gadget
    }
    type Gadget {
        id: Int
        ownerId: Int
        label: String
    }
    """


def test_discovery_is_schema_driven_not_hardcoded():
    result = discover_from_sdl(_sample_sdl(), target="sample.graphql")
    assert result.source == "sdl"
    assert result.introspectable is False
    keys = {f.path_key for f in result.fields}
    assert "gadget" in keys, "discovery must follow the supplied schema, not a fixed list"
    gadget = next(f for f in result.fields if f.path_key == "gadget")
    assert gadget.id_argument == "id"
    assert gadget.target_type == "Gadget"
    assert "ownerId" in gadget.authorization_boundary_fields


def test_discovery_finds_real_application_schema():
    result = discover_local_schema()
    assert result.fields, "the real schema must yield object-returning fields"
    keys = {f.path_key for f in result.fields}
    assert "resource" in keys
    assert any(f.is_nested for f in result.fields), "nested relationships must be discovered"


def test_live_introspection_over_http(engine_run):
    discovery = engine_run.discovery
    assert discovery is not None
    assert discovery.source == "introspection"
    assert discovery.introspectable is True
    assert discovery.schema_types_analyzed > 0


# ---------------------------------------------------------------------------
# 2. Test generation
# ---------------------------------------------------------------------------
def test_generation_records_provenance_and_expectations():
    tests = generate_tests_from_discovery(discover_local_schema())
    assert len(tests) > 0
    categories = {t.category for t in tests}
    for expected in ("BENIGN_OWNER", "DIRECT_BOLA", "NESTED_BOLA", "MUTATION_BOLA"):
        assert expected in categories, f"missing generated category {expected}"
    for test in tests:
        assert test.provenance in ("seeded_fixture", "exploratory")
        assert test.expected_decision in ("ALLOW", "DENY")
        assert test.expected_reason
        assert test.oracle_rationale
        assert test.generator_rule


# ---------------------------------------------------------------------------
# 3-7, 10. Live execution + differential oracle
# ---------------------------------------------------------------------------
def test_pipeline_runs_to_completion(engine_run):
    assert engine_run.status == "completed"
    assert engine_run.total > 0
    assert len(engine_run.executions) == engine_run.total
    assert engine_run.summary
    # real requests reached the server
    assert all(e.gateway_http_status is not None for e in engine_run.executions)


def test_legitimate_owner_access_is_allowed(engine_run):
    allowed = [
        e for e in engine_run.executions
        if e.test.category == "BENIGN_OWNER" and e.status == "PASS"
        and e.gateway_decision == "ALLOW"
    ]
    assert allowed, "a legitimate owner request must succeed through the gateway"
    assert any(e.gateway_returned_object for e in allowed)


def test_cross_owner_access_is_denied_by_gateway(engine_run):
    bola = [e for e in engine_run.executions if e.test.category == "DIRECT_BOLA"]
    assert bola
    for e in bola:
        assert e.gateway_decision == "DENY"
        assert e.status == "PASS"
        assert e.gateway_http_status in (401, 403)


def test_fixture_demonstrates_real_leak(engine_run):
    leaks = [e for e in engine_run.executions if e.insecure_leaked]
    assert leaks, "the deliberately vulnerable local fixture must demonstrate a leak"
    # every leak is backed by concrete evidence: a returned foreign object
    # (query leaks) or an observed state change (mutation leaks) — never status alone
    for e in leaks:
        assert e.insecure_http_status == 200
        assert e.insecure_returned_object is not None or e.insecure_state_changed is True


def test_no_status_only_findings(engine_run):
    # No leak was confirmed against the protected gateway in this configuration:
    # every cross-owner request was actually denied and returned no foreign object.
    assert engine_run.summary["confirmed_vulnerabilities"] == 0
    assert engine_run.summary["false_positives"] == 0
    for e in engine_run.executions:
        if e.status == "FAIL":
            assert e.reason_class == "CONFIRMED_VULNERABILITY"
            assert e.gateway_returned_object is not None or e.state_changed


# ---------------------------------------------------------------------------
# 8. Reproduction + minimization
# ---------------------------------------------------------------------------
def test_reproducer_minimizes_a_real_reproduction():
    seed_database()
    startup_event()

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE
        ) as client:
            executor = LiveExecutor(BASE, client=client, concurrency=1)
            test = GeneratedTest(
                test_id="AE-MINIMIZE",
                name="minimize candidate",
                category="DIRECT_BOLA",
                schema_path="resource",
                query="query { resource(id: 102) { id name ownerId } }",
                caller_id=101,
                caller_role="user",
                target_object_id=102,
                expected_decision="DENY",
                expected_reason="OWNERSHIP_MISMATCH",
            )
            predicate = lambda r: bool(r.get("fixture_object")) and r.get("fixture_status") == 200
            reproducer = Reproducer(executor)
            still = await reproducer.validate(test)
            minimized, attempts, improved = await reproducer.minimize(test, predicate, max_attempts=12)
            return test, still, minimized, attempts, improved

    test, still, minimized, attempts, improved = asyncio.run(go())
    assert still is True, "the finding must re-execute successfully"
    assert improved is True, "delta debugging must reduce the query while still reproducing"
    assert attempts >= 1
    assert minimized is not None
    assert len(minimized) < len(test.query)


# ---------------------------------------------------------------------------
# 9. Exports
# ---------------------------------------------------------------------------
def test_exports_are_valid_and_match_executions(engine_run):
    engine = ENGINE
    session_id = engine_run.session_id

    sarif = engine.export_sarif(session_id)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["properties"]["validation"]["valid"] is True
    # SARIF carries only confirmed *protected gateway* findings (never fixture leaks)
    confirmed = [f for f in engine_run.findings if not f.fixture]
    assert len(sarif["runs"][0]["results"]) == len(confirmed)

    junit_xml = engine.export_junit(session_id)
    root = ET.fromstring(junit_xml)
    assert root.tag == "testsuites"
    suite = root.find("testsuite")
    assert int(suite.attrib["tests"]) == engine_run.total
    assert len(root.findall(".//testcase")) == engine_run.total


# ---------------------------------------------------------------------------
# Workbench UI + API surface
# ---------------------------------------------------------------------------
def test_workbench_is_served():
    from fastapi.testclient import TestClient

    response = TestClient(app).get("/workbench")
    assert response.status_code == 200
    assert "Authorization Research Engine" in response.text
    # the six research areas are present in the served document
    for area in ("Schema", "Tests", "Execution", "Gateway vs Fixture", "Findings", "Audit"):
        assert area in response.text


def test_api_discover_generate_and_runs():
    seed_database()
    startup_event()

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE
        ) as client:
            d = await client.post(
                "/api/v1/authorization-engine/discover",
                json={"base_url": "http://127.0.0.1:1"},  # unreachable -> documented fallback
            )
            g = await client.post(
                "/api/v1/authorization-engine/generate",
                json={"base_url": "http://127.0.0.1:1"},
            )
            runs = await client.get("/api/v1/authorization-engine/runs")
            return d.json(), g.json(), runs.json()

    discovery, generated, runs = asyncio.run(go())
    assert discovery["fields"], "discover endpoint must return discovered fields"
    assert generated["count"] > 0
    assert "tests" in generated and generated["tests"][0]["expected_decision"] in ("ALLOW", "DENY")
    assert "runs" in runs
