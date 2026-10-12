from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from strawberry.fastapi import GraphQLRouter
from pydantic import BaseModel
import sqlite3

from app.config import settings
from app.database import init_db, get_db
from app.graphql.schema import schema
from app.core.security import create_access_token
from app.core.dependencies import get_current_user

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities"
)

# Initialize database and schema ownership inference on startup
@app.on_event("startup")
def startup_event():
    init_db()
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
    Development login endpoint.
    Expects seed usernames like 'alice', 'bob'.
    Seed passwords are structured as 'username123' matching 'hash_username123' in the DB.
    """
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

@app.get("/api/v1/protected")
def protected_route(current_user: dict = Depends(get_current_user)):
    """
    A protected route to demonstrate successful JWT extraction.
    """
    return {
        "message": "You are successfully authenticated via JWT",
        "user": current_user
    }

@app.get("/api/v1/audit-logs")
def get_audit_logs(db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """
    Retrieve security audit logs. Restricted to ADMIN users only.
    """
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin access required")
        
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
    
    return {
        "stats": {
            "total": total_requests,
            "allowed": allowed,
            "blocked": blocked,
            "bola": bola_attempts,
            "high_risk": high_risk
        },
        "recent_logs": recent_logs
    }

@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard():
    """Serves the simple HTML dashboard UI"""
    with open("app/static/dashboard.html", "r", encoding="utf-8") as f:
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
    )

# Secure Strawberry GraphQL router protected by the BOLA security gateway
graphql_app = GraphQLRouter(schema, context_getter=None, dependencies=[Depends(bola_enforcement_middleware)])
app.include_router(graphql_app, prefix="/graphql")

# Insecure Strawberry GraphQL router (Phase 11 Benchmark Baseline)
insecure_graphql_app = GraphQLRouter(schema, context_getter=None)
app.include_router(insecure_graphql_app, prefix="/graphql-insecure")
