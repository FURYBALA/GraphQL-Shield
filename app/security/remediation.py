"""
Automated BOLA Remediation & Policy Code Generation Engine
===========================================================
Generates production-grade, least-privilege authorization policies across
multiple target ecosystems when BOLA or unauthorized sensitive data leaks
are identified:
  1. Python / Strawberry Custom BasePermission classes & field decorators
  2. Node.js / TypeScript GraphQL Shield rules
  3. Open Policy Agent (OPA) / Rego declarative authorization bundles
"""

from __future__ import annotations
from typing import Any, Dict, Optional


def generate_remediation(
    target_type: str = "Resource",
    field_name: str = "resource",
    owner_field: str = "owner_id",
    is_sensitive: bool = False,
    is_nested: bool = False,
) -> Dict[str, Any]:
    """
    Generates declarative authorization rules and code snippets to remediate BOLA
    and unauthorized property-level data leaks.
    """
    pascal_type = target_type[0].upper() + target_type[1:] if target_type else "Resource"
    perm_class = f"Is{pascal_type}Owner"
    camel_field = field_name[0].lower() + field_name[1:] if field_name else "resource"

    # 1. Strawberry GraphQL (Python)
    strawberry_code = f'''# ----------------------------------------------------------------------
# 1. Strawberry GraphQL Resolver Security (Python)
# ----------------------------------------------------------------------
from typing import Any, Optional
import strawberry
from strawberry.permission import BasePermission
from strawberry.types import Info

class {perm_class}(BasePermission):
    message = "Authorization denied: Access to '{pascal_type}' requires verified entity ownership."

    def has_permission(self, source: Any, info: Info, **kwargs) -> bool:
        request = getattr(info.context, "request", None)
        user = getattr(request.state, "current_user", None) if request else None
        if not user:
            return False

        # Role-based administrator override
        if (user.get("role") or "").upper() == "ADMIN":
            return True

        # Extract parent entity owner
        owner_id = getattr(source, "{owner_field}", None) if source else kwargs.get("id")
        caller_id = user.get("user_id")

        return owner_id is not None and caller_id is not None and str(owner_id) == str(caller_id)

# Apply to Strawberry Schema resolvers:
@strawberry.type
class {pascal_type}Type:
    id: int
    name: str
    {owner_field}: int
    secret_key: Optional[str] = strawberry.field(
        permission_classes=[{perm_class}],
        description="Protected credential guarded by least-privilege ownership check."
    )
'''

    # 2. GraphQL Shield (TypeScript)
    shield_code = f'''// ----------------------------------------------------------------------
// 2. Declarative GraphQL Shield (TypeScript / Node.js)
// ----------------------------------------------------------------------
import {{ shield, rule, and, or, not }} from 'graphql-shield';

const isAuthenticated = rule({{ cache: 'contextual' }})(async (parent, args, ctx) => {{
  return ctx.user !== null && ctx.user !== undefined;
}});

const isAdmin = rule({{ cache: 'contextual' }})(async (parent, args, ctx) => {{
  return ctx.user && ctx.user.role === 'ADMIN';
}});

const {perm_class[0].lower() + perm_class[1:]} = rule({{ cache: 'strict' }})(async (parent, args, ctx) => {{
  if (!ctx.user) return false;
  // Resolve owner from parent object or input argument
  const targetOwnerId = parent ? parent.{owner_field} : args.id;
  return targetOwnerId !== undefined && String(targetOwnerId) === String(ctx.user.id);
}});

export const permissions = shield({{
  Query: {{
    {camel_field}: and(isAuthenticated, or(isAdmin, {perm_class[0].lower() + perm_class[1:]})),
  }},
  {pascal_type}Type: {{
    secretKey: or(isAdmin, {perm_class[0].lower() + perm_class[1:]}),
  }}
}}, {{
  fallbackRule: or(isAdmin, {perm_class[0].lower() + perm_class[1:]}),
  allowExternalErrors: true
}});
'''

    # 3. Open Policy Agent (Rego)
    rego_code = f'''# ----------------------------------------------------------------------
# 3. Open Policy Agent (Rego Policy)
# ----------------------------------------------------------------------
package graphql.bola.authz

import future.keywords.in

default allow := false

# Rule 1: Global administrator override
allow {{
    input.user.role == "ADMIN"
}}

# Rule 2: Object ownership access boundary
allow {{
    input.target_type == "{pascal_type}"
    input.user.id == input.target.{owner_field}
}}

# Rule 3: Field-level sensitive sink redaction
allow_sensitive_sink {{
    input.user.role == "ADMIN"
}}

allow_sensitive_sink {{
    input.user.id == input.target.{owner_field}
}}
'''

    return {
        "target_type": pascal_type,
        "field_name": camel_field,
        "owner_field": owner_field,
        "permission_class": perm_class,
        "is_sensitive": is_sensitive,
        "is_nested": is_nested,
        "strawberry_python": strawberry_code,
        "graphql_shield_ts": shield_code,
        "opa_rego": rego_code,
        "mitigation_summary": (
            f"Remediates BOLA on {pascal_type}.{camel_field} by enforcing strict identity matching "
            f"between caller_id and entity {owner_field}, with administrative override capability."
        )
    }
