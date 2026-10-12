"""
AI Explanation Providers
Supports deterministic offline Mock, deliberate FlawedMock (for safety testing),
and live OpenAI-compatible HTTP LLM providers.
"""

from __future__ import annotations

import abc
import json
import time
from typing import Any, Dict, Optional
import httpx

from app.security.ai_analyst.evidence import EvidencePackage
from app.security.ai_analyst.schema import AIExplanationResponse


class BaseAIProvider(abc.ABC):
    """Abstract base class for all AI explanation generation providers."""
    
    @abc.abstractmethod
    async def generate_explanation(
        self,
        package: EvidencePackage,
        system_prompt: str,
        user_prompt: str,
    ) -> AIExplanationResponse:
        """Generates an evidence-grounded explanation response."""
        raise NotImplementedError


class MockAIProvider(BaseAIProvider):
    """
    Deterministic mock provider for offline development, CI/CD, and reproducibility.
    Produces strictly grounded explanations citing valid evidence items (E1..E11).
    """

    def __init__(self, model_name: str = "mock-grounded-analyst"):
        self.model_name = model_name

    async def generate_explanation(
        self,
        package: EvidencePackage,
        system_prompt: str,
        user_prompt: str,
    ) -> AIExplanationResponse:
        start_time = time.perf_counter()
        
        is_blocked = (package.gateway_decision.upper() == "DENY")
        is_alias = package.is_alias_masked
        target_type = package.target_object_type or "Resource"
        target_id = package.target_object_id or 1
        caller_id = package.caller_user_id or "Anonymous"
        owner_id = package.target_owner_id or "Unknown"

        # Determine pattern
        if is_blocked:
            if package.candidate_kind == "INDIRECT_BOLA" or "nested" in package.canonical_schema_path.lower():
                pattern = "Indirect Nested Broken Object-Level Authorization (BOLA)"
                summary = (
                    f"Blocked indirect BOLA attempt targeting nested {target_type}:{target_id} "
                    f"via canonical schema path '{package.canonical_schema_path}' [E2]. "
                    f"Caller {caller_id} attempted unauthorized access across object relationships [E6, E7, E8]."
                )
            else:
                pattern = "Direct Broken Object-Level Authorization (BOLA) IDOR"
                summary = (
                    f"Blocked direct BOLA attempt on {target_type}:{target_id} "
                    f"via canonical path '{package.canonical_schema_path}' [E2]. "
                    f"Caller principal {caller_id} does not own the requested target entity [E6, E7, E8]."
                )
        else:
            if package.caller_role == "admin":
                pattern = "Privileged Administrative Access (Benign Authorized)"
                summary = (
                    f"Authorized privileged access to {target_type}:{target_id} "
                    f"under role '{package.caller_role}' [E7] via path '{package.canonical_schema_path}' [E2]. "
                    f"Administrative override verified in policy engine [E8]."
                )
            elif caller_id == owner_id:
                pattern = "Resource Owner Access (Benign Authorized)"
                summary = (
                    f"Authorized self-owned access to {target_type}:{target_id} "
                    f"by resource owner {caller_id} [E6, E7] via path '{package.canonical_schema_path}' [E2]. "
                    f"Gateway correctly permitted access [E8]."
                )
            else:
                pattern = "Authorized Field Access (Benign Policy Allowed)"
                summary = (
                    f"Authorized operation on path '{package.canonical_schema_path}' [E2] "
                    f"by principal {caller_id} [E7]. Gateway permitted request under policy '{package.policy_reason}' [E8]."
                )

        # Observations with citations
        observed_facts = [
            f"GraphQL query executed targeting canonical schema path '{package.canonical_schema_path}' [E1, E2].",
            f"Client response alias resolution: path '{package.client_response_path}', alias masking {'active' if is_alias else 'inactive'} [E3].",
            f"Taint source input '{package.taint_source_argument or 'none'}' reaching sink '{package.sensitive_sink_type or 'none'}' [E4, E5].",
            f"Target {target_type}:{target_id} owned by user {owner_id}, requested by principal {caller_id} (role: {package.caller_role}) [E6, E7].",
            f"Gateway enforcement outcome: decision '{package.gateway_decision}', policy reason '{package.policy_reason}', risk score {package.risk_score} [E8, E9].",
            f"Runtime correlation classification: '{package.correlation_status}' [E10] with boundary verification: {'VERIFIED' if package.boundary_criteria_verified_in_program else 'UNVERIFIED'} [E11].",
        ]

        if is_blocked:
            interpretation = (
                f"The request represents an unauthorized cross-tenant object access attempt. "
                f"Caller {caller_id} supplied object identifier {target_id} belonging to user {owner_id} [E6, E7]. "
                f"The GraphQL Gateway detected the ownership mismatch and denied request execution prior to resolver dispatch [E8]."
            )
            auth_explanation = (
                f"Access denied [E8] because caller identity (user_id={caller_id}) does not match target owner (owner_id={owner_id}) [E6, E7], "
                f"and caller lacks administrative override permissions. Reason: {package.policy_reason}."
            )
            impact = (
                f"Confidentiality breach prevented. If unprotected, attacker could inspect private records belonging to user {owner_id} "
                f"via sensitive sink '{package.sensitive_sink_type}' [E5]."
            )
            root_cause = (
                f"GraphQL query arguments allow direct object referencing without implicit caller scoping at the field resolver layer [E2, E4]."
            )
            remediation = (
                f"Enforce object ownership checks inside the resolver for '{package.canonical_schema_path}' "
                f"and configure the GraphQL Gateway to filter or validate target IDs against caller session context [E2, E8]."
            )
            regression_tests = [
                f"# Verify cross-tenant access rejection on {package.canonical_schema_path}\n"
                f"query CheckBOLA {{ {package.query_sanitized} }}"
            ]
        else:
            interpretation = (
                f"The request conforms to legitimate authorization constraints. "
                f"Caller {caller_id} either owns target resource {target_id} or possesses administrative rights [E6, E7]. "
                f"The gateway correctly permitted execution [E8]."
            )
            auth_explanation = (
                f"Access permitted [E8] under policy rule '{package.policy_reason}' because principal identity matches resource ownership or role privileges [E6, E7]."
            )
            impact = (
                f"No adverse security impact detected. Operation complies with least-privilege boundary specifications [E8, E11]."
            )
            root_cause = (
                f"Expected system behavior for legitimate user interaction."
            )
            remediation = (
                f"Maintain current policy enforcement rules and automated regression test coverage."
            )
            regression_tests = [
                f"# Regression test to ensure legitimate access remains functional\n"
                f"query VerifyAuthorizedAccess {{ {package.query_sanitized} }}"
            ]

        uncertainties = []
        if not package.boundary_criteria_verified_in_program:
            uncertainties.append(
                "Runtime boundary criteria were evaluated via gateway policy rules rather than in-resolver assertions [E11]."
            )
        if is_alias:
            uncertainties.append(
                f"Client used GraphQL alias masking ('{package.client_response_path}') which required Security Graph canonicalization [E2, E3]."
            )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        resp = AIExplanationResponse(
            summary=summary,
            attack_pattern=pattern,
            observed_facts=observed_facts,
            security_interpretation=interpretation,
            canonical_path=package.canonical_schema_path,
            authorization_explanation=auth_explanation,
            impact_assessment=impact,
            root_cause=root_cause,
            recommended_remediation=remediation,
            suggested_regression_tests=regression_tests,
            evidence_references=["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "E10", "E11"],
            uncertainties=uncertainties,
            model_metadata={
                "provider": "mock",
                "model": self.model_name,
                "latency_ms": duration_ms,
                "tokens_used": 0,
                "is_simulated": True,
            },
        )
        resp.validate_grounding(package)
        return resp


class FlawedMockAIProvider(BaseAIProvider):
    """
    Intentionally flawed mock provider used exclusively for safety, hallucination,
    and grounding evaluation tests (RQ3).
    Allows injecting specific defects: hallucinated citations, decision contradictions,
    and path misattributions.
    """

    def __init__(
        self,
        inject_hallucinated_citations: bool = False,
        inject_decision_contradiction: bool = False,
        inject_path_mismatch: bool = False,
        omit_essential_citations: bool = False,
    ):
        self.inject_hallucinated_citations = inject_hallucinated_citations
        self.inject_decision_contradiction = inject_decision_contradiction
        self.inject_path_mismatch = inject_path_mismatch
        self.omit_essential_citations = omit_essential_citations

    async def generate_explanation(
        self,
        package: EvidencePackage,
        system_prompt: str,
        user_prompt: str,
    ) -> AIExplanationResponse:
        # Start from base mock
        base_mock = MockAIProvider()
        resp = await base_mock.generate_explanation(package, system_prompt, user_prompt)

        # Inject requested defects
        if self.inject_hallucinated_citations:
            resp.observed_facts.append("Discovered undocumented vulnerability referencing CVE-2026-99999 [E99, E100].")
            resp.evidence_references.extend(["E99", "E100"])

        if self.inject_decision_contradiction:
            if package.gateway_decision.upper() == "DENY":
                resp.summary = "The gateway allowed the request successfully without any policy blocks."
                resp.authorization_explanation = "The request was allowed because user passed all checks."
                resp.security_interpretation = "The request was verified as authorized and permitted by gateway policy."
            else:
                resp.summary = "The gateway blocked the request due to critical violations."
                resp.authorization_explanation = "The request was denied and blocked by security gateway."
                resp.security_interpretation = "The request violated authorization boundaries and was rejected."

        if self.inject_path_mismatch:
            resp.canonical_path = "Mutation.maliciousInjectedField.exploit"

        if self.omit_essential_citations:
            resp.evidence_references = ["E1"]
            resp.observed_facts = [f"Observed query length [E1]."]
            resp.authorization_explanation = "Authorization evaluated without citing entities."

        resp.model_metadata["flawed_mock_injected"] = True
        resp.validate_grounding(package)
        return resp


class HTTPLLMProvider(BaseAIProvider):
    """
    Production-ready OpenAI-compatible HTTP LLM provider using httpx.
    Supports OpenAI, Azure OpenAI, vLLM, Ollama, and local OpenAI-compatible endpoints.
    """

    def __init__(
        self,
        api_base: str,
        api_key: str,
        model: str = "gpt-4o-mini",
        timeout_seconds: float = 15.0,
        max_tokens: int = 1500,
    ):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens

    async def generate_explanation(
        self,
        package: EvidencePackage,
        system_prompt: str,
        user_prompt: str,
    ) -> AIExplanationResponse:
        start_time = time.perf_counter()
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,  # Low temperature for factual grounding
            "max_tokens": self.max_tokens,
        }

        url = f"{self.api_base}/chat/completions"

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            try:
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                
                content = data["choices"][0]["message"]["content"]
                parsed_json = json.loads(content)
                
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                tokens_used = data.get("usage", {}).get("total_tokens", 0)

                resp = AIExplanationResponse(
                    summary=parsed_json.get("summary", "No summary provided"),
                    attack_pattern=parsed_json.get("attack_pattern", "Unknown"),
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
                        "provider": "http_llm",
                        "model": self.model,
                        "latency_ms": duration_ms,
                        "tokens_used": tokens_used,
                    },
                )
                resp.validate_grounding(package)
                return resp

            except Exception as e:
                # Safe fallback to mock if external provider fails
                fallback_mock = MockAIProvider(model_name=f"fallback-{self.model}")
                fallback_resp = await fallback_mock.generate_explanation(package, system_prompt, user_prompt)
                fallback_resp.model_metadata["external_provider_error"] = str(e)
                fallback_resp.uncertainties.append(f"External LLM call failed ({str(e)}). Fallback explanation generated.")
                fallback_resp.validate_grounding(package)
                return fallback_resp


class OllamaLLMProvider(BaseAIProvider):
    """
    Local Ollama LLM provider for zero-cost, private offline evaluation (e.g. llama3.1:8b, mistral).
    Connects to local daemon (default http://127.0.0.1:11434/api/chat).
    """

    def __init__(
        self,
        api_base: str = "http://127.0.0.1:11434",
        model: str = "llama3.1:8b",
        timeout_seconds: float = 30.0,
    ):
        self.api_base = api_base.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    async def generate_explanation(
        self,
        package: EvidencePackage,
        system_prompt: str,
        user_prompt: str,
    ) -> AIExplanationResponse:
        start_time = time.perf_counter()
        url = f"{self.api_base}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                content = data.get("message", {}).get("content", "{}")
                parsed_json = json.loads(content)
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                resp = AIExplanationResponse(
                    summary=parsed_json.get("summary", "No summary provided"),
                    attack_pattern=parsed_json.get("attack_pattern", "Unknown"),
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
                        "provider": "ollama",
                        "model": self.model,
                        "latency_ms": duration_ms,
                    },
                )
                resp.validate_grounding(package)
                return resp
            except Exception as e:
                # Safe fallback to mock if Ollama daemon is offline or model missing
                fallback_mock = MockAIProvider(model_name=f"fallback-ollama-{self.model}")
                fallback_resp = await fallback_mock.generate_explanation(package, system_prompt, user_prompt)
                fallback_resp.model_metadata["ollama_error"] = str(e)
                fallback_resp.uncertainties.append(f"Local Ollama provider failed ({str(e)}). Fallback explanation generated.")
                fallback_resp.validate_grounding(package)
                return fallback_resp

