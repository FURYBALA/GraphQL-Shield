import json
from fastapi import Request, HTTPException
from .database import get_db
from .auth import verify_token
from .audit import log_audit

class BOLAException(Exception):
    pass

async def bola_gateway(request: Request):
    """
    SECURITY GATEWAY (MIDDLEWARE)
    This is the core of the BOLA prevention prototype.
    """
    if request.method != "POST":
        return

    # 1. Read the JWT from the Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: Missing or invalid token")
    
    token = auth_header.split(" ")[1]
    
    # 2. Validate the JWT
    payload = verify_token(token)
    if not payload:
         raise HTTPException(status_code=401, detail="Unauthorized: Invalid or expired token")
    
    # 3. Extract the authenticated user's ID
    authenticated_user_id = payload.get("user_id")

    # 4. Identify the requested object ID from the GraphQL request
    try:
        body_bytes = await request.body()
        if not body_bytes:
            return
        data = json.loads(body_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    variables = data.get("variables") or {}
    query = data.get("query", "")
    
    # Look for ID in variables (as requested in demo)
    object_id = variables.get("id")
    
    # Also support extracting ID directly from string query for robustness
    if object_id is None and "object(id:" in query:
        # Simplistic parsing for demo purposes
        try:
            part = query.split("object(id:")[1]
            object_id_str = part.split(")")[0].strip()
            object_id = int(object_id_str)
        except:
            pass

    if object_id is None:
        # If no specific object ID is requested (e.g., introspection query), allow it.
        return

    # 5. Look up the object's owner in SQLite
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT owner_id FROM objects WHERE id = ?", (object_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Object not found")

    owner_id = row["owner_id"]

    # 6. Compare authenticated_user_id with object.owner_id
    """
    ACADEMIC NOTE ON SECURITY LOGIC:
    - What BOLA means: Broken Object Level Authorization. Attackers access objects they don't own by manipulating IDs.
    - Why authentication alone is insufficient: Alice (101) has a valid JWT, but she shouldn't access Bob's (102) objects.
    - Why ownership must be checked: To ensure data isolation between users.
    - How gateway detects it: By inspecting the request BEFORE it reaches the business logic (GraphQL resolver).
    - Why block before returning: Returning the object would leak sensitive data; blocking early preserves security and saves resources.
    """
    if str(authenticated_user_id) == str(owner_id):
        # Decision: ALLOW
        log_audit(authenticated_user_id, object_id, "ALLOW", "Owner")
        # Proceed with request...
    else:
        # Decision: BLOCK
        log_audit(authenticated_user_id, object_id, "BLOCK", "BOLA detected")
        raise BOLAException("User is not authorized to access this object")
