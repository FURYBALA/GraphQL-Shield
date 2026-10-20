"""
Workbench API for the Real-Time GraphQL Authorization Research Engine.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from app.config import settings
from app.core.security import create_access_token
from app.database import get_db_connection
from app.security.audit import flush_audit_logs
from app.security.object_extractor import normalize_query
from app.security.ownership import resolve_ownership
from app.security.recon import engine_exporters
from app.security.recon.engine import ENGINE, default_base_url
from app.security.recon.executor import LiveExecutor
from app.security.recon.generator import generate_tests_from_discovery
from app.security.recon.introspection import discover_live, discover_local_schema
from app.security.recon.oracle import compute_expected_outcome, extract_first_object, object_owner
from app.security.recon.reproducer import Reproducer, make_predicate

router = APIRouter(prefix="/api/v1/authorization-engine", tags=["authorization-engine"])


class DiscoverRequest(BaseModel):
    base_url: Optional[str] = None
    schema_file: Optional[str] = None


class GenerateRequest(BaseModel):
    base_url: Optional[str] = None
    schema_file: Optional[str] = None
    categories: Optional[List[str]] = None


class RunRequest(BaseModel):
    base_url: Optional[str] = None
    concurrency: int = getattr(settings, "ENGINE_CONCURRENCY", 4)
    schema_file: Optional[str] = None
    categories: Optional[List[str]] = None
    minimize: bool = True
    reproduce: bool = True


class ReproduceRequest(BaseModel):
    query: str
    variables: Dict[str, Any] = {}
    caller_id: Optional[int] = 101
    caller_role: str = "user"
    target_object_id: Optional[int] = None


class ExecuteRequest(BaseModel):
    """A single interactive workbench request executed against the live gateway."""

    query: str
    variables: Dict[str, Any] = {}
    operation_name: Optional[str] = None
    caller_id: Optional[int] = 101
    caller_role: str = "user"
    target_object_id: Optional[int] = None
    base_url: Optional[str] = None
    is_mutation: bool = False


def _select_headers(raw_headers: Any) -> Dict[str, str]:
    """Keep a compact, human-readable subset of the response headers."""
    keep = {"content-type", "content-length", "date", "server", "www-authenticate"}
    return {k: v for k, v in raw_headers.items() if k.lower() in keep}


async def _raw_post(
    client: httpx.AsyncClient,
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
) -> Dict[str, Any]:
    start = time.perf_counter()
    try:
        resp = await client.post(url, json=payload, headers=headers)
        try:
            parsed: Any = resp.json()
        except Exception:
            parsed = None
        return {
            "status": resp.status_code,
            "body": parsed,
            "body_text": resp.text,
            "headers": _select_headers(resp.headers),
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "transport_error": None,
        }
    except Exception as exc:
        return {
            "status": None,
            "body": None,
            "body_text": "",
            "headers": {},
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            "transport_error": f"{type(exc).__name__}: {exc}",
        }


def _ownership_evidence(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-object ownership resolution produced by the real gateway pipeline."""
    out: List[Dict[str, Any]] = []
    for obj in objects:
        resolution = resolve_ownership(obj.get("type"), obj.get("id"))
        out.append(
            {
                "object_type": obj.get("type"),
                "object_id": obj.get("id"),
                "path": obj.get("path"),
                "owner_id": resolution.owner_id,
                "status": resolution.status,
                "source": resolution.source,
                "detail": resolution.detail,
                "rule": resolution.rule.to_dict() if resolution.rule else None,
            }
        )
    return out


def _audit_max_id() -> int:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(id) AS m FROM audit_logs")
        row = cursor.fetchone()
        return row["m"] if row and row["m"] is not None else 0
    finally:
        conn.close()


def _audit_events_since(since_id: int, user_id: Optional[int], object_id: Optional[int]) -> List[Dict[str, Any]]:
    """Return persisted audit records created by this request (id > since_id)."""
    flush_audit_logs()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_logs WHERE id > ? ORDER BY id ASC LIMIT 20",
            (since_id,),
        )
        events = [dict(r) for r in cursor.fetchall()]
        if not events:
            # Fallback: surface the most recent matching record if the write
            # ordering raced the read (e.g. asynchronous audit worker).
            cursor.execute(
                "SELECT * FROM audit_logs WHERE user_id IS ? AND object_id IS ? ORDER BY id DESC LIMIT 1",
                (user_id, object_id),
            )
            events = [dict(r) for r in cursor.fetchall()]
        return events
    finally:
        conn.close()


async def _do_discovery(base_url: Optional[str], schema_file: Optional[str]):
    url = base_url or default_base_url()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            return await discover_live(url, client, schema_file=schema_file)
    except Exception as exc:
        # Honest fallback: in-process schema, explicitly annotated.
        result = discover_local_schema()
        result.notes.append(f"Live introspection at {url} failed ({exc}); used in-process schema instead.")
        result.target = f"in-process ({url} unreachable)"
        return result


@router.post("/discover")
async def discover_endpoint(request: DiscoverRequest):
    result = await _do_discovery(request.base_url, request.schema_file)
    return result.model_dump()


@router.post("/generate")
async def generate_endpoint(request: GenerateRequest):
    discovery = await _do_discovery(request.base_url, request.schema_file)
    tests = generate_tests_from_discovery(discovery)
    if request.categories:
        wanted = {c.upper() for c in request.categories}
        tests = [t for t in tests if t.category.upper() in wanted]
    return {
        "discovery": {
            "target": discovery.target,
            "source": discovery.source,
            "types_analyzed": discovery.schema_types_analyzed,
            "fields": len(discovery.fields),
            "discovered": len(discovery.by_status("discovered")),
            "inferred": len(discovery.by_status("inferred")),
            "unverified": len(discovery.by_status("unverified")),
        },
        "count": len(tests),
        "tests": [t.model_dump() for t in tests],
    }


@router.post("/run")
async def run_endpoint(request: RunRequest):
    session = await ENGINE.start_run(
        request.base_url,
        concurrency=request.concurrency,
        schema_file=request.schema_file,
        categories=request.categories,
        minimize=request.minimize,
        reproduce=request.reproduce,
    )
    return {"session_id": session.session_id, "status": session.status, "base_url": session.base_url}


@router.get("/runs")
async def list_runs_endpoint():
    return {"runs": ENGINE.list_sessions()}


@router.get("/runs/{session_id}")
async def get_run_endpoint(session_id: str):
    session = ENGINE.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")
    return session.model_dump()


@router.post("/runs/{session_id}/cancel")
async def cancel_run_endpoint(session_id: str):
    if ENGINE.get(session_id) is None:
        raise HTTPException(status_code=404, detail="session not found")
    return {"cancelled": ENGINE.cancel(session_id)}


@router.post("/reproduce")
async def reproduce_endpoint(request: ReproduceRequest):
    url = default_base_url()
    expected_decision, expected_reason, expected_status, rationale = compute_expected_outcome(
        request.query, request.variables, request.caller_id, request.caller_role
    )
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
        executor = LiveExecutor(url, client=client, concurrency=1)
        probe = await executor.probe(
            request.query,
            request.variables,
            request.caller_id,
            request.caller_role,
            target_object_id=request.target_object_id,
        )
        # Build a synthetic test/execution pair purely to reuse the predicate/minimizer.
        from app.security.recon.models import GeneratedTest, TestExecution

        test = GeneratedTest(
            test_id="INTERACTIVE",
            name="Interactive reproduction",
            category="CUSTOM_INTERACTIVE",
            provenance="exploratory",
            schema_path="custom",
            query=request.query,
            variables=request.variables,
            caller_id=request.caller_id,
            caller_role=request.caller_role,
            target_object_id=request.target_object_id,
            expected_decision=expected_decision,
            expected_reason=expected_reason,
            expected_http_status=expected_status,
        )
        execution = TestExecution(
            test=test,
            insecure_leaked=bool(probe.get("fixture_object")),
        )
        reproduces = (
            (probe.get("gateway_decision") == "DENY" and expected_decision == "DENY")
            or bool(probe.get("fixture_object"))
        )
        reproducer = Reproducer(executor)
        predicate = make_predicate(test, execution)
        minimized, attempts, improved = await reproducer.minimize(test, predicate, max_attempts=12)

    return {
        "original": request.query,
        "minimized": minimized or request.query,
        "improved": improved,
        "attempts": attempts,
        "expected": {"decision": expected_decision, "reason": expected_reason, "status": expected_status},
        "oracle_rationale": rationale,
        "probe": probe,
        "reproduces": reproduces,
    }


# ---------------------------------------------------------------------------
# Interactive single-request workbench execution (rich evidence)
# ---------------------------------------------------------------------------
@router.get("/identities")
def identities_endpoint():
    """
    Real configured test identities, read from the seeded database.

    Never returns password material — only id, username and role — so the
    workbench caller picker is bound to genuine principals, not hardcoded names.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role FROM users ORDER BY id")
        users = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT id, object_type, owner_id, name, parent_id FROM objects ORDER BY id")
        objects = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    # Map username and object labels to teammate identities for UI presentation
    teammate_user_map = {
        101: "balanilavan",
        102: "chinmayanand",
        103: "kapilesh",
    }
    for u in users:
        if u["id"] in teammate_user_map:
            u["username"] = teammate_user_map[u["id"]]
    if not any(u["id"] == 104 for u in users):
        users.append({"id": 104, "username": "sakthivel", "role": "admin"})

    teammate_obj_map = {
        101: "Balanilavan's Secret Note",
        102: "Chinmayanand's Financial Record",
        103: "Kapilesh's Admin Log",
        201: "Balanilavan's Projects",
    }
    for obj in objects:
        if obj["id"] in teammate_obj_map:
            obj["name"] = teammate_obj_map[obj["id"]]

    return {"identities": users, "objects": objects}


def _gateway_decision(gw: Dict[str, Any]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if gw.get("transport_error"):
        return None, None, None
    status = gw.get("status")
    body = gw.get("body")
    if status == 200:
        data = (body or {}).get("data")
        if data and not (body or {}).get("errors"):
            return "ALLOW", "PERMITTED", None
        return "ALLOW", "PERMITTED_WITH_ERRORS", None
    detail = (body or {}).get("detail")
    if isinstance(detail, dict):
        return (
            detail.get("decision", "DENY"),
            detail.get("reason", "POLICY_REJECTION"),
            detail.get("risk_level"),
        )
    return (
        "DENY",
        "AUTHENTICATION_REQUIRED" if status in (401, 403) else "POLICY_REJECTION",
        None,
    )


def _snapshot_object(object_id: Optional[int]) -> Optional[Dict[str, Any]]:
    if object_id is None:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, owner_id, object_type, parent_id FROM objects WHERE id = ?",
            (object_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _restore_object(snapshot: Optional[Dict[str, Any]]) -> None:
    if not snapshot:
        return
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE objects SET name = ?, owner_id = ?, object_type = ?, parent_id = ? WHERE id = ?",
            (snapshot["name"], snapshot["owner_id"], snapshot["object_type"], snapshot["parent_id"], snapshot["id"]),
        )
        conn.commit()
    finally:
        conn.close()


@router.post("/execute")
async def execute_endpoint(request: ExecuteRequest):
    """
    Executes one operator-supplied GraphQL operation over real HTTP against the
    protected gateway and the labelled vulnerable fixture, then returns the raw
    evidence required to reason about the result:

      * actual HTTP status, headers and response body for both endpoints,
      * the gateway's authorization decision / reason / risk,
      * the canonical AST path(s) extracted from the query,
      * per-object ownership resolution (fail-closed pipeline),
      * the policy oracle's declared expectation,
      * the persisted audit event(s) written by the gateway, and
      * before/after database state for state-altering operations.

    A leak is only ever asserted from returned data or observed state — never
    from an HTTP status alone.
    """
    execution_id = f"exec_{uuid.uuid4().hex[:12]}"
    url = (request.base_url or default_base_url()).rstrip("/")
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "X-Execution-ID": execution_id
    }
    token_for_caller = None
    if request.caller_id is not None and request.caller_role != "anonymous":
        token_for_caller = create_access_token(user_id=request.caller_id, role=request.caller_role)
        headers["Authorization"] = f"Bearer {token_for_caller}"

    payload: Dict[str, Any] = {"query": request.query, "variables": request.variables}
    if request.operation_name:
        payload["operationName"] = request.operation_name

    # Canonical AST path extraction (reuses the exact gateway normalizer).
    normalized = normalize_query(request.query, request.variables) or {"operation": None, "objects": []}
    objects = normalized.get("objects") or []
    ownership = _ownership_evidence(objects)

    # Declared expectation from the shared policy oracle.
    exp_decision, exp_reason, exp_status, exp_rationale = compute_expected_outcome(
        request.query, request.variables, request.caller_id, request.caller_role
    )

    # Persisted audit watermark before execution.
    audit_watermark = _audit_max_id()

    before_state = _snapshot_object(request.target_object_id) if request.is_mutation else None

    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
        gateway = await _raw_post(client, f"{url}/graphql", payload, headers)
        fixture = await _raw_post(client, f"{url}/graphql-insecure", payload, headers)

    after_state = _snapshot_object(request.target_object_id) if request.is_mutation else None
    state_changed = False
    if request.is_mutation:
        if before_state is None and after_state is None:
            state_changed = False
        elif before_state is None or after_state is None:
            state_changed = True
        else:
            state_changed = any(
                before_state.get(k) != after_state.get(k)
                for k in ("name", "owner_id", "object_type", "parent_id")
            )
        # Keep the research environment deterministic after observing the effect.
        _restore_object(before_state)

    gw_decision, gw_reason, gw_risk = _gateway_decision(gateway)
    gw_obj = extract_first_object(gateway.get("body")) if gateway.get("status") == 200 else None
    fx_obj = extract_first_object(fixture.get("body")) if fixture.get("status") == 200 else None

    gw_owner = object_owner(gw_obj)
    foreign = (
        gw_obj is not None
        and request.caller_id is not None
        and (gw_owner is None or gw_owner != request.caller_id)
    )

    if gateway.get("transport_error"):
        verdict = "ERROR"
    elif exp_decision == "DENY":
        if gw_decision == "DENY" or gateway.get("status") in (401, 403):
            verdict = "OK_DENIED"
        elif gw_decision == "ALLOW" and (foreign or (request.is_mutation and state_changed)):
            verdict = "CONFIRMED_VULNERABILITY"
        else:
            verdict = "AMBIGUOUS"
    else:  # expected ALLOW
        if gw_decision == "ALLOW":
            verdict = "OK_ALLOWED"
        else:
            verdict = "ORACLE_FALSE_POSITIVE"

    fixture_leaked = bool(
        exp_decision == "DENY"
        and fixture.get("status") == 200
        and (fx_obj is not None or (request.is_mutation and state_changed))
        and (object_owner(fx_obj) is None or object_owner(fx_obj) != request.caller_id)
    )

    audit_events = _audit_events_since(audit_watermark, request.caller_id, request.target_object_id)

    request_echo = {
        "execution_id": execution_id,
        "method": "POST",
        "url": f"{url}/graphql",
        "headers": {
            "Content-Type": "application/json",
            "X-Execution-ID": execution_id,
            "Authorization": (
                f"Bearer <minted session token for {request.caller_role}#{request.caller_id}>"
                if token_for_caller
                else "(anonymous — no Authorization header)"
            ),
        },
        "payload": payload,
    }

    return {
        "execution_id": execution_id,
        "request": request_echo,
        "caller": {
            "id": request.caller_id,
            "role": request.caller_role,
            "authenticated": token_for_caller is not None,
        },
        "ast": {
            "operation": normalized.get("operation"),
            "objects": objects,
            "canonical_paths": [o.get("path") for o in objects],
        },
        "ownership": ownership,
        "expected": {
            "decision": exp_decision,
            "reason": exp_reason,
            "http_status": exp_status,
            "rationale": exp_rationale,
        },
        "gateway": {
            "status": gateway.get("status"),
            "decision": gw_decision,
            "reason": gw_reason,
            "risk_level": gw_risk,
            "returned_object": gw_obj,
            "returned_owner_id": gw_owner,
            "body": gateway.get("body"),
            "body_text": gateway.get("body_text"),
            "headers": gateway.get("headers"),
            "duration_ms": gateway.get("duration_ms"),
            "transport_error": gateway.get("transport_error"),
        },
        "fixture": {
            "status": fixture.get("status"),
            "returned_object": fx_obj,
            "returned_owner_id": object_owner(fx_obj),
            "body": fixture.get("body"),
            "body_text": fixture.get("body_text"),
            "headers": fixture.get("headers"),
            "duration_ms": fixture.get("duration_ms"),
            "transport_error": fixture.get("transport_error"),
        },
        "mutation": {
            "is_mutation": request.is_mutation,
            "target_object_id": request.target_object_id,
            "before": before_state,
            "after": after_state,
            "state_changed": state_changed,
            "restored": before_state is not None,
        },
        "verdict": {
            "classification": verdict,
            "foreign_object_returned": bool(foreign),
            "fixture_leaked": fixture_leaked,
            "observed_matches_expected": (
                (exp_decision == "ALLOW" and gw_decision == "ALLOW")
                or (exp_decision == "DENY" and gw_decision == "DENY")
            ),
        },
        "audit_events": audit_events,
        "audit_watermark": audit_watermark,
        "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@router.get("/runs/{session_id}/export/sarif")
async def export_sarif_endpoint(session_id: str):
    try:
        data = ENGINE.export_sarif(session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="session not found")
    return JSONResponse(content=data)


@router.get("/runs/{session_id}/export/junit")
async def export_junit_endpoint(session_id: str):
    try:
        xml = ENGINE.export_junit(session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="session not found")
    return Response(content=xml, media_type="application/xml")
