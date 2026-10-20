"""
Field-Level Granular Authorization and Redaction Extension
==========================================================
Implements GraphQL RFC-compliant field masking and partial redaction.
When a query requests sensitive sink fields (e.g. secret_key, apiKey)
on an object where the requesting principal is not the owner or administrator,
this extension masks the field value to null and attaches a structured
GraphQL error to the response 'errors' array without terminating the entire query.
"""

from __future__ import annotations
from typing import Any, Callable
from graphql import GraphQLError, GraphQLResolveInfo
from strawberry.extensions import SchemaExtension
from app.config import settings

SENSITIVE_FIELD_NAMES = {
    "secret_key",
    "secretkey",
    "api_key",
    "apikey",
    "secret_token",
    "secrettoken",
    "token",
    "access_token",
    "accesstoken",
    "credentials",
    "ssn",
    "private_key",
    "privatekey"
}

class FieldLevelMaskingExtension(SchemaExtension):
    """
    Schema extension executing on every field resolution hop.
    Enforces least-privilege attribute-level authorization and redaction.
    """

    def resolve(
        self,
        _next: Callable,
        root: Any,
        info: GraphQLResolveInfo,
        *args: str,
        **kwargs: Any,
    ) -> Any:
        # Check if field-level redaction is enabled
        if not getattr(settings, "ENABLE_FIELD_LEVEL_REDACTION", True):
            return _next(root, info, *args, **kwargs)

        field_name_norm = info.field_name.lower().replace("_", "")
        
        # Check if current field matches known sensitive sinks
        if field_name_norm in SENSITIVE_FIELD_NAMES and root is not None:
            # Extract request and current_user from execution context
            ctx = info.context
            req = getattr(ctx, "request", None) if hasattr(ctx, "request") else (ctx.get("request") if isinstance(ctx, dict) else None)
            
            # Do not redact on the intentionally vulnerable baseline (/graphql-insecure)
            if req and hasattr(req, "url") and "insecure" in str(req.url.path):
                return _next(root, info, *args, **kwargs)

            current_user = getattr(req.state, "current_user", None) if (req and hasattr(req, "state")) else None

            # If user is admin -> allow access
            role = (current_user.get("role") or "").upper() if current_user else ""
            if role == "ADMIN":
                return _next(root, info, *args, **kwargs)

            # Determine owner ID of the parent object
            owner_id = getattr(root, "owner_id", None)
            caller_id = current_user.get("user_id") if current_user else None

            # If caller owns the object -> allow access
            if owner_id is not None and caller_id is not None and str(owner_id) == str(caller_id):
                return _next(root, info, *args, **kwargs)

            # Otherwise, redact field value to null and raise structured field error
            path_list = list(info.path.as_list()) if hasattr(info.path, "as_list") else list(info.path)
            raise GraphQLError(
                message=f"Field-level authorization denied: Sensitive field '{info.field_name}' requires owner access.",
                path=path_list,
                extensions={
                    "code": "FIELD_AUTHORIZATION_DENIED",
                    "field": info.field_name,
                    "reason": "RESTRICTED_SENSITIVE_SINK",
                    "object_owner_id": owner_id,
                    "caller_id": caller_id,
                    "risk_level": "HIGH"
                }
            )

        return _next(root, info, *args, **kwargs)
