"""
Taint Candidate vs. Runtime Authorization Correlation Module

Correlates static AST-driven taint propagation findings with dynamic runtime
authorization decisions made by PolicyEngine and resolve_ownership.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from app.security.taint_model import CandidateKind


SENSITIVE_KEY_PATTERNS: Set[str] = {
    "password",
    "passwd",
    "secret",
    "token",
    "jwt",
    "auth",
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "credential",
    "hash",
}


def sanitize_variables(variables: Any) -> Any:
    """
    Recursively scrubs sensitive parameters (passwords, tokens, keys)
    from variable mappings before taint analysis or audit recording.
    """
    if isinstance(variables, dict):
        sanitized: Dict[str, Any] = {}
        for k, v in variables.items():
            lower_k = str(k).lower()
            if any(pat in lower_k for pat in SENSITIVE_KEY_PATTERNS):
                sanitized[k] = "[REDACTED]"
            elif isinstance(v, (dict, list)):
                sanitized[k] = sanitize_variables(v)
            else:
                sanitized[k] = v
        return sanitized
    elif isinstance(variables, list):
        return [sanitize_variables(item) for item in variables]
    return variables


class CorrelationStatus(str, Enum):
    """Categorization of correlation between static taint findings and runtime policy."""
    TRUE_POSITIVE_BLOCKED = "TRUE_POSITIVE_BLOCKED"
    RUNTIME_PROTECTED_ALLOWED = "RUNTIME_PROTECTED_ALLOWED"
    BENIGN_AUTHORIZED = "BENIGN_AUTHORIZED"
    UNANALYZED_OR_AMBIGUOUS = "UNANALYZED_OR_AMBIGUOUS"
    POLICY_DENIED_UNCORRELATED = "POLICY_DENIED_UNCORRELATED"


@dataclass
class PathCorrelation:
    """Structured correlation record for a specific GraphQL object path."""
    path: str
    object_type: str
    object_id: Any
    runtime_decision: str
    runtime_reason: str
    risk_level: str
    static_candidate_kind: Optional[str]
    status: CorrelationStatus
    rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "runtime_decision": self.runtime_decision,
            "runtime_reason": self.runtime_reason,
            "risk_level": self.risk_level,
            "static_candidate_kind": self.static_candidate_kind,
            "status": self.status.value,
            "rationale": self.rationale,
        }


def correlate_path_decision(
    path: str,
    object_type: str,
    object_id: Any,
    runtime_result: Dict[str, Any],
    taint_report: Optional[Any],
    response_path: Optional[str] = None,
) -> PathCorrelation:
    """
    Correlates a runtime policy decision on a path with static taint analysis findings.
    Supports both canonical schema paths and client-aliased response paths.
    """
    decision = runtime_result.get("decision", "DENY")
    reason = runtime_result.get("reason", "UNKNOWN")
    risk_level = runtime_result.get("risk_level", "UNKNOWN")
    effective_path = response_path or path

    # If taint report is missing or invalid query
    if taint_report is None or not getattr(taint_report, "is_valid_query", True):
        return PathCorrelation(
            path=effective_path,
            object_type=object_type,
            object_id=object_id,
            runtime_decision=decision,
            runtime_reason=reason,
            risk_level=risk_level,
            static_candidate_kind=None,
            status=CorrelationStatus.UNANALYZED_OR_AMBIGUOUS,
            rationale="Static taint analysis unavailable or query unanalyzable; relying solely on dynamic runtime policy.",
        )

    # Locate matching finding for this path or response path
    matching_findings = []
    norm_paths = {p.strip().lower() for p in (path, response_path) if p}

    for finding in getattr(taint_report, "findings", []):
        f_schema = getattr(finding, "schema_path", "")
        if not f_schema and hasattr(finding, "propagation_context"):
            f_schema = getattr(finding.propagation_context, "field_path", "")
        f_resp = getattr(finding, "response_path", f_schema)
        f_schema_norm = str(f_schema).strip().lower()
        f_resp_norm = str(f_resp).strip().lower()
        for np in norm_paths:
            if (
                f_schema_norm == np
                or f_resp_norm == np
                or np.endswith(f_schema_norm)
                or f_schema_norm.endswith(np)
                or np.endswith(f_resp_norm)
                or f_resp_norm.endswith(np)
            ):
                matching_findings.append(finding)
                break

    # Check propagation steps if no direct finding match on findings list
    if not matching_findings:
        for step in getattr(taint_report, "propagation_steps", []):
            s_schema = getattr(step, "schema_path", "").strip().lower()
            s_resp = getattr(step, "response_path", "").strip().lower()
            for np in norm_paths:
                if (
                    s_schema == np
                    or s_resp == np
                    or np.endswith(s_schema)
                    or s_schema.endswith(np)
                ):
                    if getattr(step, "finding", None):
                        matching_findings.append(step.finding)
                        break

    # Check for direct or indirect BOLA candidate
    bola_candidates = [
        f for f in matching_findings
        if getattr(f, "candidate_kind", None) in (CandidateKind.DIRECT_BOLA_CANDIDATE, CandidateKind.INDIRECT_BOLA_CANDIDATE)
    ]

    if bola_candidates:
        candidate = bola_candidates[0]
        cand_val = candidate.candidate_kind.value
        if decision == "DENY":
            return PathCorrelation(
                path=effective_path,
                object_type=object_type,
                object_id=object_id,
                runtime_decision=decision,
                runtime_reason=reason,
                risk_level=risk_level,
                static_candidate_kind=cand_val,
                status=CorrelationStatus.TRUE_POSITIVE_BLOCKED,
                rationale=f"Static candidate {cand_val} flagged untrusted path; runtime policy confirmed authorization failure ({reason}) and blocked.",
            )
        else:
            return PathCorrelation(
                path=effective_path,
                object_type=object_type,
                object_id=object_id,
                runtime_decision=decision,
                runtime_reason=reason,
                risk_level=risk_level,
                static_candidate_kind=cand_val,
                status=CorrelationStatus.RUNTIME_PROTECTED_ALLOWED,
                rationale=f"Static candidate {cand_val} flagged sensitive sink; runtime boundary verified valid principal access ({reason}).",
            )

    # No BOLA candidate identified
    if decision == "ALLOW":
        return PathCorrelation(
            path=effective_path,
            object_type=object_type,
            object_id=object_id,
            runtime_decision=decision,
            runtime_reason=reason,
            risk_level=risk_level,
            static_candidate_kind=None,
            status=CorrelationStatus.BENIGN_AUTHORIZED,
            rationale=f"Authorized by runtime policy ({reason}) without static taint vulnerability candidates.",
        )
    else:
        return PathCorrelation(
            path=effective_path,
            object_type=object_type,
            object_id=object_id,
            runtime_decision=decision,
            runtime_reason=reason,
            risk_level=risk_level,
            static_candidate_kind=None,
            status=CorrelationStatus.POLICY_DENIED_UNCORRELATED,
            rationale=f"Denied by runtime policy ({reason}); not flagged as a static BOLA candidate.",
        )
