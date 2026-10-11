from dataclasses import dataclass
from typing import Optional

from app.database import get_db_connection
from app.security.ownership_inference import (
    OwnershipRule,
    ensure_inference_ready,
)


def get_object_owner(object_type: str, object_id: int) -> int | None:
    """
    Looks up the owner of a given object from the database based on its type.
    This is the explicit (authoritative) ownership source.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if object_type.lower() == "user":
            # A user "owns" their own user record
            cursor.execute("SELECT id FROM users WHERE id = ?", (object_id,))
            row = cursor.fetchone()
            if row:
                return row["id"]
            return None
            
        else:
            # Default to resources/objects table
            cursor.execute("SELECT owner_id FROM objects WHERE id = ?", (object_id,))
            row = cursor.fetchone()
            if row:
                return row["owner_id"]
            return None
    finally:
        conn.close()


@dataclass
class OwnershipResolution:
    """Result of the ownership resolution step of the gateway pipeline."""
    object_type: str
    object_id: int | None
    owner_id: int | None
    status: str      # RESOLVED | OBJECT_NOT_FOUND | UNKNOWN_OWNERSHIP
    source: str      # EXPLICIT_DB | NONE
    rule: Optional[OwnershipRule]
    detail: str


def resolve_ownership(object_type: str, object_id: int | None) -> OwnershipResolution:
    """
    Ownership Resolution pipeline (fail-closed):

        1. Explicit configured ownership rule (if registered)   -> wins
        2. Validated schema-inferred ownership rule             -> accepted
        3. No rule at all                                       -> UNKNOWN_OWNERSHIP
                                                                   (explicit policy
                                                                    required, else DENY)

    When a rule exists, the actual owner of the instance is read from the
    explicit database ownership lookup. Schema inference never fabricates an
    owner id and never overrides the database.
    """
    engine = ensure_inference_ready()
    rule = engine.get_owner_type_for(object_type)

    if rule is None:
        return OwnershipResolution(
            object_type=object_type,
            object_id=object_id,
            owner_id=None,
            status="UNKNOWN_OWNERSHIP",
            source="NONE",
            rule=None,
            detail=(
                f"No explicit or schema-inferred ownership relationship for type "
                f"'{object_type}'; explicit policy required"
            ),
        )

    owner_id = get_object_owner(object_type, object_id) if object_id is not None else None

    if owner_id is None:
        return OwnershipResolution(
            object_type=object_type,
            object_id=object_id,
            owner_id=None,
            status="OBJECT_NOT_FOUND",
            source="NONE",
            rule=rule,
            detail=f"Ownership rule known but object '{object_type}#{object_id}' does not exist",
        )

    return OwnershipResolution(
        object_type=object_type,
        object_id=object_id,
        owner_id=owner_id,
        status="RESOLVED",
        source="EXPLICIT_DB",
        rule=rule,
        detail=f"Owner {owner_id} resolved via explicit database lookup",
    )
