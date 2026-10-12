"""
Pydantic Schemas for Evidence-Grounded AI Security Analyst
Defines the strict output structure, explanation components, and grounding validation rules.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.security.ai_analyst.evidence import EvidencePackage


class AIExplanationRequest(BaseModel):
    """Request payload to generate an AI explanation for a security event or finding."""
    finding_id: Optional[str] = Field(None, description="ID of a recorded finding to explain")
    query: Optional[str] = Field(None, description="Raw GraphQL query string (optional if finding_id supplied)")
    variables: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Query variables")
    evidence_package: Optional[EvidencePackage] = Field(None, description="Pre-assembled evidence package if available")
    user_context_notes: Optional[str] = Field(None, description="Optional security analyst notes")


class GroundingValidationResult(BaseModel):
    """Outcome of automated grounding and safety verification checks."""
    is_grounded: bool = True
    grounding_score: float = 1.0  # 0.0 to 1.0
    valid_citations: List[str] = Field(default_factory=list)
    invalid_citations: List[str] = Field(default_factory=list)
    decision_consistent: bool = True
    path_consistent: bool = True
    contradictions: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class AIExplanationResponse(BaseModel):
    """
    Structured, evidence-grounded security explanation.
    Every factual claim and attribution must be backed by evidence citations.
    """
    summary: str = Field(..., description="Concise executive summary of the finding")
    attack_pattern: str = Field(..., description="Classified pattern (e.g. Direct BOLA, Indirect BOLA, Benign Authorized Access)")
    observed_facts: List[str] = Field(default_factory=list, description="Verified facts directly referencing evidence items")
    security_interpretation: str = Field(..., description="Contextual security interpretation connecting facts to risk")
    canonical_path: str = Field(..., description="Attributed canonical schema path in the typed Security Graph")
    authorization_explanation: str = Field(..., description="Principal vs target ownership evaluation and policy rationale")
    impact_assessment: str = Field(..., description="Realistic impact assessment grounded in the affected resource sensitivity")
    root_cause: str = Field(..., description="Architectural root cause at GraphQL AST / resolver level")
    recommended_remediation: str = Field(..., description="Concrete, actionable remediation advice for developers")
    suggested_regression_tests: List[str] = Field(default_factory=list, description="Concrete test queries or test cases to verify fix")
    evidence_references: List[str] = Field(default_factory=list, description="List of cited evidence IDs (e.g. ['E1', 'E2', 'E6', 'E7', 'E8'])")
    uncertainties: List[str] = Field(default_factory=list, description="Explicit assumptions, ambiguities, or unverified claims")
    
    # Execution & Safety metadata
    model_metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata on LLM provider, model, latency, tokens")
    is_grounded: bool = True
    grounding_score: float = 1.0
    validation_warnings: List[str] = Field(default_factory=list)

    def extract_citations_from_text(self) -> List[str]:
        """Extracts all [E#] or E# citation tokens from explanation text fields."""
        text_corpus = " ".join([
            self.summary,
            self.attack_pattern,
            " ".join(self.observed_facts),
            self.security_interpretation,
            self.authorization_explanation,
            self.impact_assessment,
            self.root_cause,
            self.recommended_remediation,
            " ".join(self.uncertainties),
        ])
        # Find citations like [E1], [E10], E1, E2
        citations = re.findall(r"\bE(\d+)\b", text_corpus)
        normalized = [f"E{c}" for c in citations]
        # Merge with explicitly listed evidence_references
        combined = list(dict.fromkeys(self.evidence_references + normalized))
        return combined

    def validate_grounding(self, package: EvidencePackage) -> GroundingValidationResult:
        """
        Validates the explanation against the provided verifiable evidence package.
        Detects hallucinated citations, policy contradictions, and path discrepancies.
        """
        citations = self.extract_citations_from_text()
        valid_citations: List[str] = []
        invalid_citations: List[str] = []
        contradictions: List[str] = []
        warnings: List[str] = []

        available_eids = set(package.evidence_items.keys())

        for cit in citations:
            if cit in available_eids:
                valid_citations.append(cit)
            else:
                invalid_citations.append(cit)
                warnings.append(f"Hallucinated evidence citation '{cit}' not present in verifiable package.")

        # Check decision consistency
        decision_consistent = True
        summary_and_auth = (self.summary + " " + self.authorization_explanation).lower()
        if package.gateway_decision.upper() == "DENY":
            claims_allowed = any(phrase in summary_and_auth for phrase in ["gateway allowed", "was allowed", "permitted by gateway", "access allowed", "successfully allowed"])
            claims_blocked = any(phrase in summary_and_auth for phrase in ["blocked", "denied", "denial", "forbidden", "rejection", "rejected"])
            if claims_allowed or ("allowed" in summary_and_auth and not claims_blocked):
                decision_consistent = False
                contradictions.append("Explanation contradicts gateway decision: claims access was allowed, but gateway DENIED.")
        elif package.gateway_decision.upper() == "ALLOW":
            claims_denied = any(phrase in summary_and_auth for phrase in ["gateway blocked", "was blocked", "was denied", "access denied", "gateway denied"])
            claims_permitted = any(phrase in summary_and_auth for phrase in ["allowed", "permitted", "authorized"])
            if claims_denied or ("blocked" in summary_and_auth and not claims_permitted):
                decision_consistent = False
                contradictions.append("Explanation contradicts gateway decision: claims access was blocked, but gateway ALLOWED.")

        # Check path consistency
        path_consistent = True
        if self.canonical_path != package.canonical_schema_path:
            path_consistent = False
            warnings.append(
                f"Path mismatch: explanation claims canonical path '{self.canonical_path}' "
                f"but Security Graph attributed '{package.canonical_schema_path}'."
            )

        # Check essential citations: target entity (E6), caller (E7), or decision (E8)
        essential_missing = []
        for ess in ["E6", "E7", "E8"]:
            if ess in available_eids and ess not in valid_citations:
                essential_missing.append(ess)
        if essential_missing:
            warnings.append(f"Explanation omitted citations for essential evidence items: {', '.join(essential_missing)}.")

        # Compute grounding score
        score = 1.0
        if invalid_citations:
            score -= 0.25 * min(len(invalid_citations), 3)
        if not decision_consistent:
            score -= 0.50
        if not path_consistent:
            score -= 0.20
        if essential_missing:
            score -= 0.05 * len(essential_missing)
        
        score = max(0.0, min(1.0, round(score, 2)))
        is_grounded = (score >= 0.70) and decision_consistent

        self.is_grounded = is_grounded
        self.grounding_score = score
        self.validation_warnings = warnings + contradictions
        self.evidence_references = list(dict.fromkeys(valid_citations))

        return GroundingValidationResult(
            is_grounded=is_grounded,
            grounding_score=score,
            valid_citations=valid_citations,
            invalid_citations=invalid_citations,
            decision_consistent=decision_consistent,
            path_consistent=path_consistent,
            contradictions=contradictions,
            warnings=warnings,
        )
