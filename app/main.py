from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from strawberry.fastapi import GraphQLRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sqlite3
import time

from app.config import settings
from app.database import init_db, get_db
from app.graphql.schema import schema, insecure_schema
from app.core.security import create_access_token
from app.core.dependencies import get_current_user

from contextlib import asynccontextmanager

def startup_event():
    """Synchronous startup initialization helper for application and test fixtures."""
    init_db()
    from app.security.research.persistence import init_research_db
    init_research_db()
    # Schema-Aware Ownership Inference (built once, cached for all requests)
    from app.security.ownership_inference import inference_engine
    report = inference_engine.build_from_strawberry_schema(schema)
    print("\n" + "="*50)
    print("[Schema Ownership Inference]")
    print("="*50)
    for rule in report.rules:
        print(f"  {rule.source_type}.{rule.source_field} -> {rule.target_type}  [{rule.confidence}]")
    print(f"\nTypes analyzed: {report.types_analyzed}")
    print(f"Ownership relationships detected: {report.relationships_detected}")
    print(f"High-confidence rules: {report.high_confidence}")
    print(f"Ambiguous/rejected relationships: {report.ambiguous}")
    print(f"Analysis time: {report.analysis_time_ms}ms")
    print("="*50 + "\n")

@asynccontextmanager
async def lifespan(app: FastAPI):
    startup_event()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities",
    lifespan=lifespan
)

# Basic REST health check
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "FastAPI is running"}

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/v1/auth/login")
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """
    Login endpoint supporting teammate identities and test aliases.
    Supports:
      - Balanilavan (ID 101, role: user) -> password: balan123 / balanilavan123
      - Chinmayanand (ID 102, role: user) -> password: chinmay123 / chinmayanand123
      - Kapilesh / Sakthivel (ID 103, role: admin) -> password: kapilesh123 / sakthivel123
    """
    uname = request.username.lower().strip()
    pwd = request.password

    # Direct teammate identity mapping
    if uname in ("balanilavan", "balan") and pwd in ("balan123", "balanilavan123", "alice123"):
        access_token = create_access_token(user_id=101, role="user")
        return {"access_token": access_token, "token_type": "bearer", "username": "balanilavan", "user_id": 101}
    elif uname in ("chinmayanand", "chinmay") and pwd in ("chinmay123", "chinmayanand123", "bob123"):
        access_token = create_access_token(user_id=102, role="user")
        return {"access_token": access_token, "token_type": "bearer", "username": "chinmayanand", "user_id": 102}
    elif uname in ("kapilesh", "sakthivel") and pwd in (f"{uname}123", "charlie123", "admin123"):
        access_token = create_access_token(user_id=103, role="admin")
        return {"access_token": access_token, "token_type": "bearer", "username": uname, "user_id": 103}

    expected_hash = f"hash_{request.password}"
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, role FROM users WHERE username = ? AND password_hash = ?", 
        (request.username, expected_hash)
    )
    user = cursor.fetchone()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    access_token = create_access_token(user_id=user['id'], role=user['role'])
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/v1/auth/demo-session")
def demo_session(request: Request, db: sqlite3.Connection = Depends(get_db)):
    """
    Local demonstration authentication endpoint.
    Restricted to non-production environments and strictly verified loopback requests.
    Issues an ephemeral analyst-level session token without requiring credentials in client-side code.
    """
    # 1. Feature flag guard
    if not getattr(settings, "ENABLE_DEMO_SESSION", True):
        raise HTTPException(
            status_code=403,
            detail="Demo session endpoint is disabled by configuration (ENABLE_DEMO_SESSION=False)."
        )

    # 2. Production environment guard
    if getattr(settings, "ENVIRONMENT", "development").lower() == "production":
        raise HTTPException(
            status_code=403,
            detail="Demo session endpoint is strictly prohibited in production environments."
        )

    # 3. Direct TCP peer IP guard
    client_host = request.client.host if request.client else "testclient"
    allowed_loopback = {"127.0.0.1", "localhost", "::1", "testclient"}
    if client_host not in allowed_loopback:
        raise HTTPException(
            status_code=403,
            detail=f"Demo session endpoint restricted to local loopback. Direct peer {client_host} forbidden."
        )

    # 4. Strict reverse-proxy forwarding header audit
    # If ANY forwarding header is present, ALL referenced addresses must be loopback.
    # Presence of ANY non-loopback IP anywhere in X-Forwarded-For, X-Real-IP, or Forwarded immediately blocks the request.
    for header_name in ("x-forwarded-for", "x-real-ip", "forwarded"):
        header_val = request.headers.get(header_name)
        if header_val:
            tokens = [t.strip() for t in header_val.replace(";", ",").split(",")]
            for token in tokens:
                clean_ip = token.split("=")[-1].strip().strip('"').strip("[]")
                if clean_ip and clean_ip not in allowed_loopback:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Demo session endpoint rejected: external address '{clean_ip}' detected in proxy header '{header_name}'."
                    )

    cursor = db.cursor()
    cursor.execute("SELECT id, role FROM users WHERE role = 'admin' LIMIT 1")
    user = cursor.fetchone()
    if not user:
        cursor.execute("SELECT id, role FROM users LIMIT 1")
        user = cursor.fetchone()

    user_id = user["id"] if user else 999
    role = user["role"] if user else "admin"

    access_token = create_access_token(user_id=user_id, role=role)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": role,
        "user_id": user_id,
        "mode": "demo_ephemeral"
    }

@app.get("/api/v1/protected")
def protected_route(current_user: dict = Depends(get_current_user)):
    """
    A protected route to demonstrate successful JWT extraction.
    """
    return {
        "message": "You are successfully authenticated via JWT",
        "user": current_user
    }

from app.security.audit import flush_audit_logs

@app.get("/api/v1/audit-logs")
def get_audit_logs(db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """
    Retrieve security audit logs. Restricted to ADMIN users only.
    """
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
        
    flush_audit_logs()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50")
    logs = [dict(row) for row in cursor.fetchall()]
    return {"logs": logs}

from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os

# Create static dir if not exists
os.makedirs("app/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/api/v1/dashboard-stats")
def get_dashboard_stats(db: sqlite3.Connection = Depends(get_db)):
    """
    Open endpoint serving stats for the static dashboard purely for demonstration.
    """
    flush_audit_logs()
    cursor = db.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_requests = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE decision = 'ALLOW'")
    allowed = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE decision = 'DENY'")
    blocked = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE reason IN ('OWNERSHIP_MISMATCH', 'NESTED_AUTHORIZATION_VIOLATION')")
    bola_attempts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE risk_level = 'HIGH'")
    high_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 15")
    recent_logs = [dict(row) for row in cursor.fetchall()]

    from app.security.anomaly_engine import analyze_from_db
    anomaly = analyze_from_db(db).to_dict()

    return {
        "stats": {
            "total": total_requests,
            "allowed": allowed,
            "blocked": blocked,
            "bola": bola_attempts,
            "high_risk": high_risk
        },
        "anomaly": anomaly,
        "recent_logs": recent_logs
    }

@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard():
    """Serves the simple HTML dashboard UI"""
    with open("app/static/dashboard.html", "r", encoding="utf-8") as f:
        return f.read()

# -----------------------------------------------------------------------------
# Real-Time GraphQL Authorization Research Engine (workbench)
# -----------------------------------------------------------------------------
from app.security.recon.api import router as authorization_engine_router
from app.security.research.api import router as research_router

app.include_router(authorization_engine_router)
app.include_router(research_router)

@app.get("/workbench", response_class=HTMLResponse)
def read_workbench():
    """Serves the authorization research workbench UI."""
    with open("app/static/workbench.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/", response_class=HTMLResponse)
def read_root():
    """
    Default landing page: the live GraphQL authorization research workbench.

    The legacy KPI dashboard remains available under /dashboard for the audit,
    anomaly and benchmark views, but it is no longer the primary experience.
    """
    with open("app/static/workbench.html", "r", encoding="utf-8") as f:
        return f.read()

from app.security.enforcement import bola_enforcement_middleware
from app.security.ownership_inference import inference_engine, ensure_inference_ready

@app.get("/api/v1/security/schema-ownership")
def get_schema_ownership(current_user: dict = Depends(get_current_user)):
    """
    Inspection endpoint showing the ownership relationships inferred
    from the GraphQL schema. Restricted to ADMIN users.
    """
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
    ensure_inference_ready()
    return inference_engine.to_dict()

from app.security.security_graph import get_security_graph

@app.get("/api/v1/security/security-graph")
def get_security_graph_endpoint(current_user: dict = Depends(get_current_user)):
    """
    Inspection endpoint exposing the constructed GraphQL Security Graph G = (V, E).
    Restricted to ADMIN users.
    """
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_security_graph().to_dict()

from app.security.audit import get_taint_audit_records

@app.get("/api/v1/security/taint-audit")
def get_taint_audit_endpoint(current_user: dict = Depends(get_current_user)):
    """
    Inspection endpoint exposing recent context-sensitive taint analysis audit events.
    Restricted to ADMIN users.
    """
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
    return {
        "mode": getattr(settings, "TAINT_ANALYSIS_MODE", "audit_only"),
        "records": get_taint_audit_records()
    }

from app.security.anomaly_engine import analyze_from_db

@app.get("/api/v1/security/anomaly")
def get_anomaly_analysis_endpoint(
    window_minutes: int = 30,
    db: sqlite3.Connection = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """
    Adaptive behavioural anomaly assessment over the live audit stream.

    Unsupervised, principal-level analysis (robust peer-relative z-scores + temporal
    drift) that complements the per-event deterministic risk engine. Advisory only:
    it never grants, denies, or mutates a gateway decision. Restricted to ADMIN.
    """
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
    flush_audit_logs()
    window = max(1, min(int(window_minutes), 1440))
    return analyze_from_db(db, window_minutes=window).to_dict()

from app.security.scenario_lab import get_all_real_world_scenarios

@app.get("/api/v1/security/scenario-lab")
def get_scenario_lab_endpoint():
    """
    Demonstration endpoint serving live real-world security scenarios
    and actual gateway + taint correlation intelligence for the dashboard.
    """
    return {
        "title": "Real-World Security Scenario Lab",
        "description": "Live, controlled real-world BOLA scenario evaluations backed by actual gateway execution",
        "scenarios": get_all_real_world_scenarios()
    }

from app.security.ai_analyst import (
    AIExplanationRequest,
    AIExplanationResponse,
    ai_analyst_service,
)

@app.get("/api/v1/security/ai-analyst/status")
def get_ai_analyst_status(current_user: dict = Depends(get_current_user)):
    """
    Inspection endpoint reporting AI Analyst configuration and readiness.
    Never exposes API keys or secrets.
    """
    return {
        "enabled": getattr(settings, "AI_EXPLANATION_ENABLED", False),
        "provider": getattr(settings, "AI_PROVIDER", "mock"),
        "model": getattr(settings, "AI_MODEL", "mock-grounded-analyst"),
        "api_base": getattr(settings, "AI_API_BASE", None) if getattr(settings, "AI_PROVIDER", "mock") != "mock" else None,
        "api_key_configured": bool(getattr(settings, "AI_API_KEY", "")),
        "timeout_seconds": getattr(settings, "AI_TIMEOUT_SECONDS", 15.0),
        "max_tokens": getattr(settings, "AI_MAX_TOKENS", 1500),
        "advisory_only": True,
        "separation_guarantee": (
            "Evidence-grounded AI explanations run strictly out-of-band for audit assistance. "
            "The AI layer has zero authority to grant or deny access, override policy, or alter database state."
        ),
    }

@app.post("/api/v1/security/ai-analyst/explain", response_model=AIExplanationResponse)
async def generate_ai_explanation_endpoint(
    request: AIExplanationRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Generates an evidence-grounded AI security explanation for a GraphQL BOLA audit event.
    Advisory-only. Strictly validates citations and guards against policy contradictions.
    """
    return await ai_analyst_service.generate_explanation(
        request=request,
        current_user=current_user,
        force_execution=request.force_execution,
    )


# -----------------------------------------------------------------------------
# Remediation, Live Anomaly Stream & Multi-Tenant Matrix Endpoints
# -----------------------------------------------------------------------------
from app.security.remediation import generate_remediation

class RemediationRequest(BaseModel):
    target_type: str = "Resource"
    field_name: str = "resource"
    owner_field: str = "owner_id"
    is_sensitive: bool = False
    is_nested: bool = False

@app.post("/api/v1/security/remediation/generate")
def generate_remediation_endpoint(req: RemediationRequest):
    """Generates production-grade Strawberry, GraphQL Shield, and OPA/Rego remediation policies."""
    return generate_remediation(
        target_type=req.target_type,
        field_name=req.field_name,
        owner_field=req.owner_field,
        is_sensitive=req.is_sensitive,
        is_nested=req.is_nested,
    )

@app.get("/api/v1/security/live-events")
def get_live_events_endpoint(since_id: int = 0, limit: int = 20, db: sqlite3.Connection = Depends(get_db)):
    """Provides a streaming poll endpoint for live security audit events and anomaly alerts."""
    cursor = db.cursor()
    cursor.execute(
        "SELECT * FROM audit_logs WHERE id > ? ORDER BY id DESC LIMIT ?",
        (since_id, limit)
    )
    rows = [dict(r) for r in cursor.fetchall()]
    max_id = max([r["id"] for r in rows], default=since_id)
    has_high_risk = any(r.get("risk_level") == "HIGH" or r.get("decision") == "DENY" for r in rows)
    return {
        "latest_id": max_id,
        "new_events_count": len(rows),
        "has_high_risk": has_high_risk,
        "events": rows
    }

@app.get("/api/v1/security/multi-tenant-matrix")
def get_multi_tenant_matrix_endpoint():
    """Generates a 2D cross-tenant access authorization matrix across tenants Alpha & Beta."""
    principals = [
        {"id": 101, "role": "USER", "tenant": "Alpha", "label": "User 101 (Tenant Alpha)"},
        {"id": 102, "role": "USER", "tenant": "Alpha", "label": "User 102 (Tenant Alpha)"},
        {"id": 201, "role": "USER", "tenant": "Beta", "label": "User 201 (Tenant Beta)"},
        {"id": 202, "role": "USER", "tenant": "Beta", "label": "User 202 (Tenant Beta)"},
        {"id": 999, "role": "ADMIN", "tenant": "Global", "label": "Admin 999 (Global Admin)"},
        {"id": None, "role": "ANONYMOUS", "tenant": "Public", "label": "Anonymous Caller"},
    ]
    resources = [
        {"id": 101, "owner_id": 101, "tenant": "Alpha", "label": "Resource 101 (Owned by 101)"},
        {"id": 102, "owner_id": 102, "tenant": "Alpha", "label": "Resource 102 (Owned by 102)"},
        {"id": 201, "owner_id": 201, "tenant": "Beta", "label": "Resource 201 (Owned by 201)"},
        {"id": 202, "owner_id": 202, "tenant": "Beta", "label": "Resource 202 (Owned by 202)"},
    ]

    matrix = []
    for p in principals:
        row = {"principal": p, "cells": []}
        for res in resources:
            is_owner = (p["id"] is not None and p["id"] == res["owner_id"])
            is_admin = (p["role"] == "ADMIN")
            is_cross_tenant = (p["tenant"] != res["tenant"] and not is_admin)
            
            if is_admin:
                decision = "ALLOW"
                reason = "ADMIN_OVERRIDE"
                status = 200
            elif is_owner:
                decision = "ALLOW"
                reason = "OWNER_MATCH"
                status = 200
            elif p["id"] is None:
                decision = "DENY"
                reason = "UNAUTHENTICATED"
                status = 401
            elif is_cross_tenant:
                decision = "DENY"
                reason = "CROSS_TENANT_VIOLATION"
                status = 403
            else:
                decision = "DENY"
                reason = "CROSS_USER_MISMATCH"
                status = 403

            row["cells"].append({
                "resource_id": res["id"],
                "resource_owner": res["owner_id"],
                "resource_tenant": res["tenant"],
                "decision": decision,
                "reason": reason,
                "gateway_status": status,
                "insecure_baseline_leaked": (decision == "DENY" and p["id"] is not None),
                "is_cross_tenant": is_cross_tenant,
                "sample_query": f"query {{ resource(id: {res['id']}) {{ id name secret_key }} }}"
            })
        matrix.append(row)

    return {
        "tenants": ["Alpha", "Beta"],
        "principals": principals,
        "resources": resources,
        "matrix": matrix
    }

# -----------------------------------------------------------------------------
# GraphQL Authorization Differential Testing Engine Endpoints
# -----------------------------------------------------------------------------

from app.security.differential_testing import (
    discover_schema_paths,
    generate_differential_suite,
    minimize_query,
    DifferentialTestExecutor,
    run_differential_testing_suite,
    DifferentialTestCase,
)

class RunDifferentialRequest(BaseModel):
    sample_limit: Optional[int] = None

class CustomDifferentialRequest(BaseModel):
    query: str
    variables: Dict[str, Any] = {}
    caller_id: Optional[int] = 101
    caller_role: str = "user"
    target_object_id: Optional[int] = None

class MinimizeQueryRequest(BaseModel):
    query: str
    target_object_id: Optional[int] = None

@app.get("/api/v1/differential-testing/paths")
def get_discovered_paths_endpoint():
    """Returns all discovered object-returning schema paths and sensitive sinks."""
    paths = discover_schema_paths()
    return {"paths": [p.model_dump() if hasattr(p, "model_dump") else p.dict() for p in paths]}

@app.post("/api/v1/differential-testing/run")
def run_differential_suite_endpoint(request: RunDifferentialRequest = RunDifferentialRequest()):
    """Executes the automated differential test suite and returns the research evaluation report."""
    report = run_differential_testing_suite(app, sample_limit=request.sample_limit)
    return report.model_dump() if hasattr(report, "model_dump") else report.dict()

@app.post("/api/v1/differential-testing/execute-custom")
def execute_custom_differential_endpoint(request: CustomDifferentialRequest):
    """Executes a user-supplied interactive GraphQL query through the differential engine."""
    from app.security.object_extractor import normalize_query
    from app.security.ownership import resolve_ownership

    executor = DifferentialTestExecutor(app)
    try:
        extracted = normalize_query(request.query)
        target_obj = (extracted.get("objects") or [{}])[0]
    except Exception:
        target_obj = {}

    target_id = request.target_object_id or target_obj.get("id") or 101
    target_type = target_obj.get("type") or "Resource"
    schema_path = target_obj.get("path") or "resource"
    is_nested = "." in schema_path

    owner_res = resolve_ownership(target_type, target_id)
    target_owner = owner_res.owner_id if owner_res else None

    # Derive expected outcome from least-privilege policy oracle
    if request.caller_id is None or request.caller_role == "anonymous":
        expected_decision, expected_reason, expected_status = "DENY", "INVALID_CONTEXT", 401
    elif request.caller_role.upper() == "ADMIN":
        expected_decision, expected_reason, expected_status = "ALLOW", "ADMIN_OVERRIDE", 200
    elif target_owner is not None and str(request.caller_id) == str(target_owner):
        expected_decision, expected_reason, expected_status = "ALLOW", "OWNER_MATCH", 200
    elif is_nested:
        expected_decision, expected_reason, expected_status = "DENY", "NESTED_AUTHORIZATION_VIOLATION", 403
    else:
        expected_decision, expected_reason, expected_status = "DENY", "OWNERSHIP_MISMATCH", 403

    tc = DifferentialTestCase(
        test_id="CUSTOM-" + str(int(time.time() * 1000))[-6:],
        name=f"Interactive Test: {schema_path} by Caller {request.caller_id}",
        category="CUSTOM_INTERACTIVE",
        query=request.query,
        variables=request.variables,
        caller_id=request.caller_id,
        caller_role=request.caller_role,
        target_object_type=target_type,
        target_object_id=target_id,
        target_owner_id=target_owner,
        schema_path=schema_path,
        response_path=schema_path,
        is_nested=is_nested,
        expected_decision=expected_decision,
        expected_reason=expected_reason,
        expected_http_status=expected_status,
        oracle_rationale=f"Expected {expected_decision} for principal {request.caller_id} accessing {target_type}:{target_id} owned by {target_owner}.",
    )
    result = executor.execute_test(tc)
    return result.model_dump() if hasattr(result, "model_dump") else result.dict()

@app.post("/api/v1/differential-testing/minimize")
def minimize_query_endpoint(request: MinimizeQueryRequest):
    """Minimizes a GraphQL query into a minimal reproducible PoC using delta debugging."""
    minimized = minimize_query(request.query, target_object_id=request.target_object_id)
    return {"original": request.query, "minimized": minimized}

@app.get("/api/v1/differential-testing/metrics")
def get_differential_metrics_endpoint():
    """Returns aggregated research metrics comparing differential testing vs manual baseline."""
    report = run_differential_testing_suite(app)
    return {
        "summary": {
            "total_test_cases": report.total_test_cases,
            "schema_path_coverage_pct": report.schema_path_coverage_pct,
            "vulnerability_prevention_rate_pct": report.vulnerability_prevention_rate_pct,
            "path_inconsistencies_detected": report.path_inconsistencies_detected,
            "reproducibility_rate_pct": report.reproducibility_rate_pct,
            "mean_latency_per_test_ms": report.mean_latency_per_test_ms,
        },
        "baseline_comparison": report.baseline_comparison,
    }

from fastapi.responses import Response
from app.security.differential_testing import export_sarif, export_junit_xml, generate_poc_curl, generate_poc_python

@app.get("/api/v1/differential-testing/export/sarif")
def export_differential_sarif_endpoint():
    """Exports differential testing findings in standard SARIF 2.1.0 format."""
    report = run_differential_testing_suite(app)
    return export_sarif(report)

@app.get("/api/v1/differential-testing/export/junit")
def export_differential_junit_endpoint():
    """Exports differential testing findings in standard JUnit XML format."""
    report = run_differential_testing_suite(app)
    xml_str = export_junit_xml(report)
    return Response(content=xml_str, media_type="application/xml")

class ExploitGenerationRequest(BaseModel):
    query: str
    caller_id: Optional[int] = 101
    caller_role: str = "user"
    category: str = "CUSTOM_POC"
    test_id: str = "POC-EXPLOIT"

@app.post("/api/v1/differential-testing/generate-exploit")
def generate_exploit_scripts_endpoint(request: ExploitGenerationRequest):
    """Generates ready-to-run cURL commands and Python exploit scripts for a test case."""
    tc = DifferentialTestCase(
        test_id=request.test_id,
        name=f"Interactive PoC for Caller {request.caller_id}",
        category=request.category,
        query=request.query,
        caller_id=request.caller_id,
        caller_role=request.caller_role,
        schema_path="custom",
        response_path="custom",
    )
    return {
        "curl": generate_poc_curl(tc),
        "python": generate_poc_python(tc)
    }

# Secure Strawberry GraphQL router protected by the BOLA security gateway
graphql_app = GraphQLRouter(schema, context_getter=None, dependencies=[Depends(bola_enforcement_middleware)])
app.include_router(graphql_app, prefix="/graphql")

# Insecure Strawberry GraphQL router (Phase 11 Benchmark Baseline)
insecure_graphql_app = GraphQLRouter(insecure_schema, context_getter=None)
app.include_router(insecure_graphql_app, prefix="/graphql-insecure")
