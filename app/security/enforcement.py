import json
import time
from fastapi import Request, HTTPException, Depends
from app.config import settings
from app.core.dependencies import get_current_user
from .object_extractor import normalize_query
from .ownership import resolve_ownership
from .authorization import AuthorizationContext, PolicyEngine
from .audit import log_decision, record_taint_audit
from .taint_engine import analyze_query_taint
from .taint_correlation import (
    sanitize_variables,
    correlate_path_decision,
    CorrelationStatus,
    PathCorrelation,
)

policy_engine = PolicyEngine()

async def bola_enforcement_middleware(request: Request, current_user: dict = Depends(get_current_user)):
    """
    Centralized Security Gateway dependency.
    Runs BEFORE the GraphQL backend, blocking BOLA attacks at the edge.
    Now integrates Phase 5 Context-Sensitive AST Taint Analysis in audit-only mode.
    """
    if request.method != "POST":
        return

    try:
        body = await request.body()
        data = json.loads(body)
    except Exception:
        return

    query = data.get("query", "")
    variables = data.get("variables", {})
    operation_name = data.get("operationName")

    # Phase 5: AST-Driven Context-Sensitive Taint Analysis (Audit-Only)
    mode = getattr(settings, "TAINT_ANALYSIS_MODE", "audit_only")
    taint_report = None
    taint_duration_ms = 0.0

    if mode != "disabled" and isinstance(query, str) and query.strip():
        start_time = time.perf_counter()
        try:
            sanitized_vars = sanitize_variables(variables) if isinstance(variables, dict) else {}
            taint_report = analyze_query_taint(
                query=query,
                variables=sanitized_vars,
                operation_name=operation_name,
            )
            taint_duration_ms = round((time.perf_counter() - start_time) * 1000, 3)
        except Exception as exc:
            taint_duration_ms = round((time.perf_counter() - start_time) * 1000, 3)
            # Fail-safe: internal analyzer errors must never crash live requests
            print(f"[TAINT ANALYSIS WARNING] Analysis error: {type(exc).__name__}: {exc}")
            taint_report = None

    # Attach to request state for inspection, testing, and downstream audit
    if hasattr(request, "state"):
        request.state.taint_report = taint_report
        request.state.taint_duration_ms = taint_duration_ms
        request.state.taint_mode = mode
        request.state.taint_correlations = []

    user_id = current_user.get("user_id")
    role = current_user.get("role", "user")

    normalized = normalize_query(query, variables)
    
    if not normalized or not normalized["objects"]:
        # Record audit-only static analysis event if findings were identified on unparameterized query
        if taint_report and mode != "disabled":
            record_taint_audit({
                "operation_name": operation_name or taint_report.operation_name,
                "query_snippet": query[:120].strip(),
                "findings_count": len(taint_report.findings),
                "direct_bola_candidates": len(taint_report.direct_bola_candidates),
                "indirect_bola_candidates": len(taint_report.indirect_bola_candidates),
                "user_id": user_id,
                "role": role,
                "mode": mode,
                "duration_ms": taint_duration_ms,
                "correlations": [],
            })
        return

    # Phase 6 & Phase 5: Contextual Policy Evaluation with Taint Correlation
    for obj in normalized["objects"]:
        object_id = obj["id"]
        object_type = obj["type"]
        path = obj["path"]
        
        # Resolve ownership: explicit rule > schema-inferred rule > fail closed
        resolution = resolve_ownership(object_type, object_id)
        owner_id = resolution.owner_id
        
        # Assemble structured context
        context = AuthorizationContext(
            user_id=user_id,
            role=role,
            operation=normalized["operation"] or "query",
            object_type=object_type,
            object_id=object_id,
            path=path,
            owner_id=owner_id,
            metadata={
                "client_host": request.client.host if request.client else "unknown",
                "ownership_status": resolution.status,
                "ownership_source": resolution.source,
                "ownership_detail": resolution.detail,
            }
        )
        
        # Evaluate policy engine rules
        result = policy_engine.evaluate(context)

        # Correlate taint candidate with runtime authorization decision
        correlation = correlate_path_decision(
            path=path,
            object_type=object_type,
            object_id=object_id,
            runtime_result=result,
            taint_report=taint_report,
        )
        if hasattr(request, "state") and hasattr(request.state, "taint_correlations"):
            request.state.taint_correlations.append(correlation)

        # Record structured audit-only taint log
        if mode != "disabled":
            record_taint_audit({
                "operation_name": operation_name or (taint_report.operation_name if taint_report else None),
                "schema_path": path,
                "response_path": path,
                "object_type": object_type,
                "object_id": object_id,
                "user_id": user_id,
                "role": role,
                "mode": mode,
                "duration_ms": taint_duration_ms,
                "finding_category": correlation.static_candidate_kind or "NONE",
                "runtime_decision": result["decision"],
                "runtime_reason": result["reason"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "correlation_status": correlation.status.value,
                "rationale": correlation.rationale,
            })
        
        # Live Security Debug View (Terminal Logging)
        print("\n" + "="*50)
        print("[GraphQL Shield: Live Security Trace]")
        print("="*50)
        print(f"[AUTH]")
        print(f"User ID: {user_id}")
        print(f"Role:    {role.upper()}")
        print(f"\n[GRAPHQL]")
        print(f"Path:      {path}")
        print(f"Object:    {object_type}")
        print(f"Object ID: {object_id}")
        print(f"\n[OWNERSHIP]")
        print(f"Requesting User: {user_id}")
        print(f"True Owner ID:   {owner_id}")
        print(f"Resolution:      {resolution.status} ({resolution.source})")
        # Show schema inference info if available
        inferred_rule = resolution.rule
        if inferred_rule:
            print(f"Schema Rule:     {inferred_rule.source_type}.{inferred_rule.source_field} -> {inferred_rule.target_type} [{inferred_rule.confidence}] ({inferred_rule.source})")
        else:
            print("Schema Rule:     NONE - explicit policy required")
        print(f"\n[AUTHORIZATION]")
        print(f"Decision: {result['decision']}")
        print(f"Reason:   {result['reason']}")
        print(f"Risk:     {result['risk_level']} ({result['risk_score']}/100)")
        print(f"\n[TAINT ANALYSIS (AUDIT ONLY)]")
        print(f"Mode:        {mode}")
        if taint_report:
            print(f"Duration:    {taint_duration_ms}ms")
            print(f"Candidates:  {len(taint_report.direct_bola_candidates)} direct, {len(taint_report.indirect_bola_candidates)} indirect")
            print(f"Correlation: {correlation.status.value}")
            print(f"Rationale:   {correlation.rationale}")
        else:
            print(f"Status:      Skipped or unanalyzable (fail-safe active)")
        
        # Audit log the decision (enforcement must never depend on audit success)
        try:
            log_decision(
                user_id=user_id,
                role=role,
                operation=context.operation,
                object_type=object_type,
                object_id=object_id,
                path=path,
                decision=result["decision"],
                reason=result["reason"],
                risk_score=result["risk_score"],
                risk_level=result["risk_level"]
            )
        except Exception as audit_error:
            print(f"[AUDIT] Failed to persist decision: {audit_error}")
        
        # Enforcement Block
        if result["decision"] == "DENY":
            print("[ENFORCEMENT]\nHTTP 403 Forbidden - Request Dropped.")
            print("="*50 + "\n")
            raise HTTPException(
                status_code=403, 
                detail={
                    "decision": result["decision"],
                    "user_id": user_id,
                    "object_id": object_id,
                    "reason": result["reason"],
                    "risk_score": result["risk_score"],
                    "risk_level": result["risk_level"]
                }
            )
        else:
            print("[ENFORCEMENT]\nALLOW - Executing GraphQL Backend...")
            print("="*50 + "\n")
