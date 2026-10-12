from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class AuthorizationContext:
    """
    Structured context containing all information necessary for the 
    Policy Engine to make a zero-trust authorization decision.
    """
    user_id: int
    role: str
    operation: str
    object_type: str
    object_id: int
    path: str
    owner_id: Optional[int]
    metadata: Dict[str, Any]

from .risk_engine import calculate_risk

class PolicyEngine:
    """
    Rule-based Policy Engine.
    Evaluates the authorization context against predefined security policies.
    """
    def __init__(self):
        pass
        
    def evaluate(self, context: AuthorizationContext) -> dict:
        """
        Returns a decision dictionary including risk scoring.
        """
        caller_tenant = context.metadata.get("caller_tenant_id") or context.metadata.get("tenant_id") if context.metadata else None
        resource_tenant = context.metadata.get("resource_tenant_id") if context.metadata else None

        # Validate Context
        if not context.user_id or not context.object_type or context.object_id is None:
            base_decision, reason = "DENY", "INVALID_CONTEXT"

        # Multi-Tenant / Organization Isolation (ABAC Rule)
        elif caller_tenant is not None and resource_tenant is not None and str(caller_tenant) != str(resource_tenant):
            if context.role.upper() in ("SUPERADMIN", "SUPER_ADMIN"):
                base_decision, reason = "ALLOW", "SUPERADMIN_CROSS_TENANT_OVERRIDE"
            else:
                base_decision, reason = "DENY", "TENANT_ISOLATION_VIOLATION"
            
        # Policy 1: Object must exist to be accessed
        elif context.owner_id is None and (context.metadata or {}).get("ownership_status") == "UNKNOWN_OWNERSHIP":
            # Fail-closed: neither an explicit rule nor a validated schema-inferred
            # rule explains this object type -> explicit policy required.
            base_decision, reason = "DENY", "UNKNOWN_OWNERSHIP"

        # Policy 2: Object must exist to be accessed
        elif context.owner_id is None:
            base_decision, reason = "DENY", "OBJECT_NOT_FOUND"
            
        # Policy 3: Admins have unrestricted access to all resources
        elif context.role.upper() == "ADMIN":
            base_decision, reason = "ALLOW", "ADMIN_OVERRIDE"
            
        # Policy 4: Owner can access their own object
        elif str(context.user_id) == str(context.owner_id):
            base_decision, reason = "ALLOW", "OWNER_MATCH"

        # Policy 4b: Authorized collaborators can access shared objects
        elif context.metadata.get("collaborator_ids") and any(
            str(context.user_id) == str(cid) for cid in context.metadata.get("collaborator_ids", [])
        ):
            base_decision, reason = "ALLOW", "COLLABORATOR_MATCH"
            
        # Policy 5: Unauthorized nested resource access is explicitly denied
        elif "." in context.path:
            base_decision, reason = "DENY", "NESTED_AUTHORIZATION_VIOLATION"
            
        # Default Deny (Zero Trust: BOLA protection fallback)
        else:
            base_decision, reason = "DENY", "OWNERSHIP_MISMATCH"
            
        # Phase 8: Deterministic Risk Scoring
        score, risk_level = calculate_risk(context, reason)
        
        return {
            "decision": base_decision,
            "reason": reason,
            "risk_score": score,
            "risk_level": risk_level
        }
