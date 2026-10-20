"""
FEATURE 4 - Differential Security Oracle (expectation side)
===========================================================
Computes the *declared* authorization expectation for a test case by replaying
the exact same pipeline the live gateway uses:

    normalize_query()  ->  resolve_ownership()  ->  PolicyEngine.evaluate()

Because the oracle reuses the real ownership inference and policy engine there
is no second, drifting definition of "expected". The observation side of the
oracle lives in ``executor.py`` (data/state inspection) and ``reproducer.py``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from app.security.authorization import AuthorizationContext, PolicyEngine
from app.security.object_extractor import normalize_query
from app.security.ownership import resolve_ownership

POLICY_ENGINE = PolicyEngine()


def compute_expected_outcome(
    query: str,
    variables: Optional[Dict[str, Any]] = None,
    caller_id: Optional[int] = None,
    role: str = "user",
) -> Tuple[str, str, int, str]:
    """
    Returns ``(decision, reason, http_status, rationale)``.

    The gateway iterates every extracted object; the request is denied at the
    first object the policy engine rejects. This mirrors ``enforcement.py``.
    """
    variables = variables or {}
    normalized = normalize_query(query, variables)

    if not normalized or not normalized["objects"]:
        # No id-bearing entity accessor -> the gateway performs no entity-level
        # authorization (introspection/public fields pass through untouched).
        return "ALLOW", "PUBLIC_FIELD", 200, "No object accessor extracted; gateway applies no entity authorization."

    first_deny_reason: Optional[str] = None
    first_allow_reason: Optional[str] = None
    for obj in normalized["objects"]:
        resolution = resolve_ownership(obj["type"], obj["id"])
        context = AuthorizationContext(
            user_id=caller_id if caller_id is not None else 0,
            role=role,
            operation=normalized["operation"] or "query",
            object_type=obj["type"],
            object_id=obj["id"],
            path=obj["path"],
            owner_id=resolution.owner_id,
            metadata={
                "ownership_status": resolution.status,
                "ownership_source": resolution.source,
            },
        )
        result = POLICY_ENGINE.evaluate(context)
        if result["decision"] == "DENY" and first_deny_reason is None:
            first_deny_reason = result["reason"]
        if result["decision"] == "ALLOW" and first_allow_reason is None:
            first_allow_reason = result["reason"]

    if first_deny_reason is not None:
        status = 401 if first_deny_reason == "INVALID_CONTEXT" else 403
        return "DENY", first_deny_reason, status, f"Policy engine denies: {first_deny_reason}."

    return "ALLOW", first_allow_reason or "OWNER_MATCH", 200, f"Policy engine allows: {first_allow_reason or 'OWNER_MATCH'}."


# ---------------------------------------------------------------------------
# Observation-side helpers: did the observed object actually belong to caller?
# ---------------------------------------------------------------------------

_OWNER_KEYS = ("ownerId", "owner_id", "ownerid", "userId", "user_id", "userId")
_ID_KEYS = ("id",)


def extract_first_object(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Walk a GraphQL ``data`` payload and return the first object that carries an
    ``id`` field, regardless of aliasing or nesting. Returns ``None`` when the
    response contains only scalars/errors.
    """
    data = (payload or {}).get("data")
    if not isinstance(data, dict):
        return None

    stack = list(data.values())
    while stack:
        node = stack.pop(0)
        if isinstance(node, dict):
            if any(k in node for k in _ID_KEYS):
                return node
            stack.extend(node.values())
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, dict) and any(k in item for k in _ID_KEYS):
                    return item
                if isinstance(item, dict):
                    stack.append(item)
    return None


def object_owner(obj: Optional[Dict[str, Any]]) -> Optional[int]:
    if not obj:
        return None
    for key in _OWNER_KEYS:
        if key in obj and obj[key] is not None:
            try:
                return int(obj[key])
            except (TypeError, ValueError):
                return None
    return None
