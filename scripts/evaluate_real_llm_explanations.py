#!/usr/bin/env python3
"""
scripts/evaluate_real_llm_explanations.py

Phase 10.2: Controlled Real-LLM Evaluation Framework for Research Paper.
Evaluates the Evidence-Grounded AI Security Analyst using a live OpenAI-compatible LLM
(e.g., GPT-4o-mini, vLLM, Ollama) against a fixed, pre-registered subset of real-world scenarios.

ACADEMIC INTEGRITY DIRECTIVES:
1. Independent Ground Truth: Expected facts, decisions, paths, and entities are defined independently
   before generating any explanation. The model's own response is NEVER treated as ground truth.
2. Honest Prerequisite Check: If no real provider credentials or endpoints are configured,
   the evaluation HALTS cleanly and documents the environment limitation.
   Mock outputs are NEVER disguised as real-model evaluations.
3. No Secret Leakage: API keys and credentials are never printed, logged, or saved to artifacts.
4. Distinguish Mechanical vs. Semantic: Mechanical evidence-ID verification is reported separately
   from semantic factual correctness.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import httpx

from app.config import settings
from app.security.ai_analyst.evidence import EvidencePackage
from app.security.ai_analyst.providers import HTTPLLMProvider
from app.security.ai_analyst.schema import AIExplanationRequest, AIExplanationResponse
from app.security.ai_analyst.service import SYSTEM_PROMPT


# ==============================================================================
# 1. FIXED PRE-REGISTERED EVALUATION SET (4 REPRESENTATIVE ARCHETYPES)
# ==============================================================================

@dataclass
class ExpectedGroundTruth:
    """Independently defined ground-truth facts for an evaluation scenario."""
    scenario_id: str
    scenario_name: str
    selection_rationale: str
    expected_gateway_decision: str       # "ALLOW" or "DENY"
    expected_policy_reason: str          # e.g., "OWNERSHIP_MISMATCH", "OWNER_MATCH"
    expected_canonical_path: str         # e.g., "Query.resource", "Query.user.resources"
    expected_client_response_path: str   # e.g., "resource", "targetUser.userDocs"
    caller_principal_id: int
    caller_role: str
    target_owner_id: int
    target_object_id: int
    target_object_type: str
    required_factual_elements: List[str] # Specific facts supported by supplied evidence
    forbidden_claims: List[str]          # Unacceptable contradictory claims
    expected_remediation_intent: str     # Nature of developer fix required


FIXED_EVALUATION_SET: List[ExpectedGroundTruth] = [
    ExpectedGroundTruth(
        scenario_id="REAL-HOPP-001",
        scenario_name="Hoppscotch Collection IDOR: Unauthorized cross-tenant collection lookup",
        selection_rationale="Core CVE-2026-28217 pattern: Direct BOLA vulnerability on root field lookup with tenancy mismatch.",
        expected_gateway_decision="DENY",
        expected_policy_reason="OWNERSHIP_MISMATCH",
        expected_canonical_path="Query.resource",
        expected_client_response_path="resource",
        caller_principal_id=101,
        caller_role="user",
        target_owner_id=102,
        target_object_id=102,
        target_object_type="Resource",
        required_factual_elements=[
            "Caller user_id=101 lacks ownership of Resource:102",
            "Target Resource:102 is owned by user_id=102",
            "Gateway denied the request with OWNERSHIP_MISMATCH (HTTP 403)",
            "Path refers to canonical query root 'resource'",
        ],
        forbidden_claims=[
            "Claims request was permitted or authorized",
            "Claims user 101 is the legitimate owner of resource 102",
            "Attributes attack to path other than resource",
        ],
        expected_remediation_intent="Enforce ownership validation in field resolver and reject cross-tenant IDs.",
    ),
    ExpectedGroundTruth(
        scenario_id="REAL-HOPP-002",
        scenario_name="Hoppscotch Collection IDOR: Legitimate owner collection access",
        selection_rationale="Benign paired counterpart to REAL-HOPP-001: Verifies model does not falsely accuse legitimate owner access.",
        expected_gateway_decision="ALLOW",
        expected_policy_reason="OWNER_MATCH",
        expected_canonical_path="Query.resource",
        expected_client_response_path="resource",
        caller_principal_id=102,
        caller_role="user",
        target_owner_id=102,
        target_object_id=102,
        target_object_type="Resource",
        required_factual_elements=[
            "Caller user_id=102 is the legitimate owner of Resource:102",
            "Gateway permitted the request under OWNER_MATCH (HTTP 200)",
            "No adverse security impact occurred",
        ],
        forbidden_claims=[
            "Claims request was blocked or dropped",
            "Claims caller committed unauthorized BOLA",
            "Recommends denying legitimate owner access",
        ],
        expected_remediation_intent="Preserve existing ownership rule; maintain automated regression tests.",
    ),
    ExpectedGroundTruth(
        scenario_id="REAL-NEST-001",
        scenario_name="Team Workspace: Indirect BOLA on nested collections with client aliases",
        selection_rationale="Relational complexity with GraphQL alias masking ('targetUser.userDocs' vs canonical 'user.resources').",
        expected_gateway_decision="DENY",
        expected_policy_reason="OWNERSHIP_MISMATCH",
        expected_canonical_path="Query.user.resources",
        expected_client_response_path="targetUser.userDocs",
        caller_principal_id=101,
        caller_role="user",
        target_owner_id=102,
        target_object_id=102,
        target_object_type="User",
        required_factual_elements=[
            "Caller user_id=101 attempted nested traversal on foreign user node 102",
            "Client response alias 'targetUser.userDocs' masks canonical path 'user.resources'",
            "Gateway denied execution due to ownership boundary violation",
        ],
        forbidden_claims=[
            "Confuses client response alias with schema coordinate",
            "Claims request was authorized",
        ],
        expected_remediation_intent="Enforce relational authorization across nested collection edges and disambiguate aliases.",
    ),
    ExpectedGroundTruth(
        scenario_id="REAL-SAAS-003",
        scenario_name="SaaS Multi-Tenant: Legitimate tenant private document retrieval",
        selection_rationale="Multi-tenant boundary verification for legitimate tenant operations under isolation guarantees.",
        expected_gateway_decision="ALLOW",
        expected_policy_reason="OWNER_MATCH",
        expected_canonical_path="Query.resource",
        expected_client_response_path="resource",
        caller_principal_id=101,
        caller_role="user",
        target_owner_id=101,
        target_object_id=101,
        target_object_type="Resource",
        required_factual_elements=[
            "Caller tenant user_id=101 accessed own Resource:101",
            "Multi-tenant data isolation verified by gateway",
            "Execution allowed with HTTP 200",
        ],
        forbidden_claims=[
            "Claims multi-tenant boundary was violated",
            "Claims request was dropped",
        ],
        expected_remediation_intent="Preserve tenant-isolated resolver filtering rules.",
    ),
]


# ==============================================================================
# 2. BLINDED HUMAN & PROGRAMMATIC EVALUATION RUBRIC (10 POINTS TOTAL)
# ==============================================================================

BLINDED_RUBRIC_SPEC = {
    "dimensions": [
        {
            "name": "Factual Support & Citation Grounding",
            "max_points": 3,
            "description": (
                "3: Every factual assertion is directly supported by evidence items [E1]..[E11]; zero invalid IDs; zero hallucinated CVEs. "
                "2: Minor unsupported assertion not altering security meaning; citations valid. "
                "1: Moderate unsupported claims or at least one missing citation for key entity. "
                "0: Hallucinated evidence IDs, fabricated incidents, or ungrounded assertions."
            ),
        },
        {
            "name": "Metadata & Entity Completeness",
            "max_points": 3,
            "description": (
                "3: Explicitly identifies caller principal, target object ID/type, database owner, canonical path, and gateway decision. "
                "2: Captures 4 of the 5 core entities. "
                "1: Captures 2-3 of the core entities. "
                "0: Captures 1 or fewer core entities."
            ),
        },
        {
            "name": "Policy & Boundary Clarity",
            "max_points": 2,
            "description": (
                "2: Explains exact authorization rationale without confusing client aliases with canonical paths or contradicting gateway. "
                "1: Ambiguous rationale or slight confusion of aliases, but correct binary decision. "
                "0: Contradicts gateway decision (e.g. claims ALLOW on DENY) or completely misidentifies boundary."
            ),
        },
        {
            "name": "Actionable Remediation Quality",
            "max_points": 2,
            "description": (
                "2: Provides specific resolver/gateway code fix and concrete GraphQL test query without weakening security. "
                "1: Generic remediation advice (e.g., 'check permissions') without concrete code or test query. "
                "0: Misleading, insecure, or absent remediation advice."
            ),
        },
    ],
    "total_max_points": 10,
}


# ==============================================================================
# 3. BOUNDED RETRY CALLER FOR REAL HTTP LLM PROVIDER
# ==============================================================================

async def call_real_provider_with_retry(
    provider: HTTPLLMProvider,
    package: EvidencePackage,
    system_prompt: str,
    user_prompt: str,
    max_retries: int = 2,
    base_backoff_sec: float = 1.0,
) -> Dict[str, Any]:
    """
    Calls HTTPLLMProvider with bounded retries and exponential backoff.
    NEVER silently falls back to MockAIProvider: reports actual failure if provider fails.
    """
    attempt = 0
    last_error: Optional[str] = None
    start_time = time.perf_counter()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {provider.api_key}",
    }
    payload = {
        "model": provider.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
        "max_tokens": provider.max_tokens,
    }
    url = f"{provider.api_base}/chat/completions"

    while attempt <= max_retries:
        attempt += 1
        try:
            async with httpx.AsyncClient(timeout=provider.timeout_seconds) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed_json = json.loads(content)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                usage = data.get("usage", {})

                # Construct AIExplanationResponse and run validator
                ai_resp = AIExplanationResponse(
                    summary=parsed_json.get("summary", ""),
                    attack_pattern=parsed_json.get("attack_pattern", ""),
                    observed_facts=parsed_json.get("observed_facts", []),
                    security_interpretation=parsed_json.get("security_interpretation", ""),
                    canonical_path=parsed_json.get("canonical_path", package.canonical_schema_path),
                    authorization_explanation=parsed_json.get("authorization_explanation", ""),
                    impact_assessment=parsed_json.get("impact_assessment", ""),
                    root_cause=parsed_json.get("root_cause", ""),
                    recommended_remediation=parsed_json.get("recommended_remediation", ""),
                    suggested_regression_tests=parsed_json.get("suggested_regression_tests", []),
                    evidence_references=parsed_json.get("evidence_references", []),
                    uncertainties=parsed_json.get("uncertainties", []),
                    model_metadata={
                        "provider": "real_http_llm",
                        "model": provider.model,
                        "latency_ms": duration_ms,
                        "tokens_prompt": usage.get("prompt_tokens", 0),
                        "tokens_completion": usage.get("completion_tokens", 0),
                        "tokens_total": usage.get("total_tokens", 0),
                        "attempt": attempt,
                        "is_simulated": False,
                    },
                )
                ai_resp.validate_grounding(package)

                return {
                    "success": True,
                    "response": ai_resp,
                    "raw_json": parsed_json,
                    "attempts": attempt,
                    "duration_ms": duration_ms,
                    "error": None,
                }
        except Exception as e:
            last_error = str(e)
            if attempt <= max_retries:
                await asyncio.sleep(base_backoff_sec * (2 ** (attempt - 1)))

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    return {
        "success": False,
        "response": None,
        "raw_json": None,
        "attempts": attempt,
        "duration_ms": duration_ms,
        "error": last_error,
    }


# ==============================================================================
# 4. EVALUATION HARNESS
# ==============================================================================

async def evaluate_scenario_explanation(
    gt: ExpectedGroundTruth,
    ai_resp: AIExplanationResponse,
) -> Dict[str, Any]:
    """
    Evaluates a generated AIExplanationResponse against the independent ExpectedGroundTruth.
    Measures decision consistency, path correctness, required fact coverage, contradiction detection,
    and mechanical citation validity.
    """
    # 1. Decision Consistency
    decision_matches = (
        ai_resp.summary.lower().find("allow") != -1 if gt.expected_gateway_decision == "ALLOW"
        else (ai_resp.summary.lower().find("block") != -1 or ai_resp.summary.lower().find("den") != -1)
    )
    no_validator_contradiction = not any("contradicts" in w for w in ai_resp.validation_warnings)
    decision_consistent = decision_matches and no_validator_contradiction

    # 2. Canonical Path Correctness
    path_matches = (gt.expected_canonical_path.lower() in ai_resp.canonical_path.lower() or
                    gt.expected_canonical_path.replace("Query.", "").lower() in ai_resp.canonical_path.lower())

    # 3. Mechanical Citation Reference Validity (ID Existence)
    total_citations = len(ai_resp.evidence_references)
    valid_citation_ids = [f"E{i}" for i in range(1, 12)]
    valid_citations = [c for c in ai_resp.evidence_references if c in valid_citation_ids]
    invalid_citations = [c for c in ai_resp.evidence_references if c not in valid_citation_ids]
    citation_validity_rate = (len(valid_citations) / total_citations) if total_citations > 0 else 0.0

    # 4. Required Fact Coverage (Semantic Entity Check)
    full_text = " ".join([
        ai_resp.summary,
        ai_resp.security_interpretation,
        ai_resp.authorization_explanation,
        ai_resp.root_cause,
        " ".join(ai_resp.observed_facts),
    ]).lower()

    facts_covered = 0
    # Check caller ID mention
    if str(gt.caller_principal_id) in full_text:
        facts_covered += 1
    # Check target ID mention
    if str(gt.target_object_id) in full_text:
        facts_covered += 1
    # Check decision policy mention
    if gt.expected_policy_reason.lower() in full_text or ("owner" in full_text and gt.expected_gateway_decision.lower() in full_text):
        facts_covered += 1
    # Check path mention
    if gt.expected_client_response_path.lower() in full_text or gt.expected_canonical_path.lower() in full_text:
        facts_covered += 1

    fact_coverage_rate = facts_covered / 4.0

    # 5. Contradiction & Forbidden Claims Check
    forbidden_claims_detected: List[str] = []
    for fc in gt.forbidden_claims:
        if "claims request was permitted" in fc.lower() and gt.expected_gateway_decision == "DENY":
            if "permitted" in ai_resp.summary.lower() or "allowed" in ai_resp.summary.lower():
                forbidden_claims_detected.append(fc)
        if "claims request was blocked" in fc.lower() and gt.expected_gateway_decision == "ALLOW":
            if "blocked" in ai_resp.summary.lower() or "denied" in ai_resp.summary.lower():
                forbidden_claims_detected.append(fc)

    # 6. Remediation Relevance
    remediation_present = bool(ai_resp.recommended_remediation) and len(ai_resp.suggested_regression_tests) > 0
    remediation_relevant = remediation_present and (
        "resolver" in ai_resp.recommended_remediation.lower() or
        "owner" in ai_resp.recommended_remediation.lower() or
        "gateway" in ai_resp.recommended_remediation.lower()
    )

    return {
        "scenario_id": gt.scenario_id,
        "gateway_decision_ground_truth": gt.expected_gateway_decision,
        "decision_consistent": decision_consistent,
        "path_correct": path_matches,
        "canonical_path_claimed": ai_resp.canonical_path,
        "canonical_path_expected": gt.expected_canonical_path,
        "citation_metrics": {
            "total_cited": total_citations,
            "valid_count": len(valid_citations),
            "invalid_count": len(invalid_citations),
            "invalid_ids": invalid_citations,
            "validity_rate": round(citation_validity_rate * 100, 1),
        },
        "required_fact_coverage": {
            "facts_checked": 4,
            "facts_covered": facts_covered,
            "coverage_rate_pct": round(fact_coverage_rate * 100, 1),
        },
        "contradictions_detected": forbidden_claims_detected,
        "remediation_relevant": remediation_relevant,
        "grounding_score": ai_resp.grounding_score,
        "is_grounded_contract": ai_resp.is_grounded,
        "validation_warnings": ai_resp.validation_warnings,
        "model_metadata": ai_resp.model_metadata,
    }


# ==============================================================================
# 5. MAIN EXECUTION PIPELINE
# ==============================================================================

async def main():
    print("=" * 80)
    print("PHASE 10.2: CONTROLLED REAL-LLM EVALUATION FOR RESEARCH PAPER")
    print("=" * 80)
    print("Scientific Directives:")
    print("  - Fixed Pre-Registered Scenario Subset (4 Archetypes)")
    print("  - Independent Fact & Decision Ground Truths")
    print("  - Honest Prerequisite Check: Never substitute mock data as real LLM output")
    print("  - Zero Credential Printing or Committing")
    print("-" * 80)

    # 1. Prerequisite Inspection
    provider_type = getattr(settings, "AI_PROVIDER", "mock").lower()
    api_key = getattr(settings, "AI_API_KEY", "") or os.environ.get("OPENAI_API_KEY", "")
    api_base = getattr(settings, "AI_API_BASE", "https://api.openai.com/v1")
    model_name = getattr(settings, "AI_MODEL", "gpt-4o-mini")

    has_live_credentials = bool(api_key.strip())
    is_live_provider = (provider_type == "http") or has_live_credentials

    print(f"Configured Provider Type : {provider_type}")
    print(f"Configured Model Name    : {model_name}")
    print(f"API Base URL             : {api_base}")
    print(f"API Credentials Present  : {'YES (Non-empty key detected)' if has_live_credentials else 'NO (Key is empty)'}")
    print("-" * 80)

    protocol_artifact_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "docs",
        "AI_REAL_LLM_EVALUATION_PROTOCOL.json",
    )

    if not is_live_provider or not has_live_credentials:
        # PREREQUISITE CHECK FAILED: Stop live evaluation and report limitation honestly.
        print("\n[PREREQUISITE STATUS: LIVE EVALUATION HALTED]")
        print("  Reason: No live LLM API credentials or active endpoints are configured in this environment.")
        print("  Academic Action: Per strict Phase 10.2 integrity guidelines, mock runs will NOT be disguised")
        print("  or reported as real-model evaluations.")
        print("  Preserved Action: The 4-scenario evaluation set, independent ground truth definitions, and")
        print("  blinded scoring rubric have been formalized as a reproducible evaluation protocol.")
        print("=" * 80)

        halted_protocol = {
            "protocol_title": "Controlled Real-LLM Evaluation Protocol for GraphQL BOLA Security Analyst",
            "phase": "Phase 10.2",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "HALTED_PREREQUISITE_ABSENT",
            "reason": "AI_API_KEY is unset and AI_PROVIDER is set to 'mock'. No live model endpoint available.",
            "prerequisite_check": {
                "ai_provider_configured": provider_type,
                "api_key_present": False,
                "api_base": api_base,
                "model_name": model_name,
                "instructions_to_enable": "Copy .env.example to .env, set AI_PROVIDER=http and AI_API_KEY=..., then re-run.",
            },
            "fixed_evaluation_set": [asdict(gt) for gt in FIXED_EVALUATION_SET],
            "blinded_evaluation_rubric": BLINDED_RUBRIC_SPEC,
            "independent_ground_truth_policy": (
                "Ground truths are established independently prior to generation. "
                "Gateway PolicyEngine decisions (ALLOW/DENY), canonical Security Graph paths, "
                "and database tenancy bounds serve as the sole ground truth."
            ),
            "measured_live_results": None,
            "academic_reporting_stance": (
                "The research paper explicitly reports that live LLM evaluations require active API credentials "
                "or local inference endpoints. Deterministic mock fixture benchmarks are reported in Section 7.3, "
                "and the live LLM evaluation protocol is established in Section 7.4 as reproducible methodology."
            ),
        }

        with open(protocol_artifact_path, "w", encoding="utf-8") as f:
            json.dump(halted_protocol, f, indent=2)

        print(f"Saved pre-registered protocol artifact to {protocol_artifact_path}")
        return

    # 2. Live Provider Execution
    print("\n[PREREQUISITE STATUS: LIVE PROVIDER DETECTED]")
    print(f"Initializing HTTPLLMProvider ({model_name})...")
    provider = HTTPLLMProvider(
        api_base=api_base,
        api_key=api_key,
        model=model_name,
        timeout_seconds=getattr(settings, "AI_TIMEOUT_SECONDS", 15.0),
        max_tokens=getattr(settings, "AI_MAX_TOKENS", 1500),
    )

    eval_results = []
    total_tokens_used = 0
    total_latency_ms = 0.0

    for gt in FIXED_EVALUATION_SET:
        print(f"\nEvaluating Case {gt.scenario_id}: {gt.scenario_name}")
        pkg = EvidencePackage.from_scenario_or_finding(
            finding_id=gt.scenario_id,
            query=f"query {{ {gt.expected_client_response_path} }}",
            variables={"id": gt.target_object_id},
            canonical_path=gt.expected_canonical_path,
            response_path=gt.expected_client_response_path,
            caller_id=gt.caller_principal_id,
            caller_role=gt.caller_role,
            target_type=gt.target_object_type,
            target_id=gt.target_object_id,
            owner_id=gt.target_owner_id,
            decision=gt.expected_gateway_decision,
            reason=gt.expected_policy_reason,
            risk_score=90 if gt.expected_gateway_decision == "DENY" else 10,
            risk_level="HIGH" if gt.expected_gateway_decision == "DENY" else "LOW",
            correlation_status="TRUE_POSITIVE_BLOCKED" if gt.expected_gateway_decision == "DENY" else "RUNTIME_PROTECTED_ALLOWED",
            candidate_kind="DIRECT_BOLA" if "resources" not in gt.expected_canonical_path else "INDIRECT_BOLA",
            taint_source_arg="id",
            sensitive_sink_type=gt.target_object_type,
            boundary_verified=True,
        )

        user_prompt = f"Analyze the following verifiable evidence package and produce a grounded JSON security audit report:\n\n{pkg.format_for_llm_prompt()}"

        call_res = await call_real_provider_with_retry(
            provider=provider,
            package=pkg,
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        if not call_res["success"]:
            print(f"  [ERROR] Provider generation failed after {call_res['attempts']} attempts: {call_res['error']}")
            eval_results.append({
                "scenario_id": gt.scenario_id,
                "status": "GENERATION_FAILED",
                "error": call_res["error"],
                "attempts": call_res["attempts"],
            })
            continue

        ai_resp: AIExplanationResponse = call_res["response"]
        sc_metrics = await evaluate_scenario_explanation(gt, ai_resp)
        eval_results.append(sc_metrics)

        meta = ai_resp.model_metadata
        tokens = meta.get("tokens_total", 0)
        lat = meta.get("latency_ms", 0.0)
        total_tokens_used += tokens
        total_latency_ms += lat

        print(f"  Outcome: Grounding Score {sc_metrics['grounding_score']:.2f} | "
              f"Decision Consistent: {sc_metrics['decision_consistent']} | "
              f"Path Correct: {sc_metrics['path_correct']} | "
              f"Citations: {sc_metrics['citation_metrics']['valid_count']}/{sc_metrics['citation_metrics']['total_cited']} | "
              f"Latency: {lat:.1f}ms | Tokens: {tokens}")

    # Save live results
    live_protocol = {
        "protocol_title": "Controlled Real-LLM Evaluation for GraphQL BOLA Security Analyst",
        "phase": "Phase 10.2",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "COMPLETED_LIVE_EVALUATION",
        "model_evaluated": model_name,
        "api_base": api_base,
        "scenarios_evaluated": len(eval_results),
        "total_tokens_used": total_tokens_used,
        "mean_latency_ms": round(total_latency_ms / len(eval_results), 2) if eval_results else 0.0,
        "evaluation_results": eval_results,
        "blinded_evaluation_rubric": BLINDED_RUBRIC_SPEC,
    }

    with open(protocol_artifact_path, "w", encoding="utf-8") as f:
        json.dump(live_protocol, f, indent=2)

    print("\n" + "=" * 80)
    print("LIVE EVALUATION COMPLETE")
    print(f"Saved live results to {protocol_artifact_path}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
