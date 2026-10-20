"""Tiny signed-token helper shared by the backend and the gateway.

A token looks like  <base64url(json claims)>.<hex HMAC-SHA256>
It is a simplified JWT (HS256) so the project has no extra dependencies.

When the gateway protects the main FastAPI application instead of ClinicHub, set GS_JWT_SECRET to that
app's JWT_SECRET: standard HS256 JWTs issued by /api/v1/auth/login are then accepted too, and their
{"user_id", "role"} claims are mapped to the gateway's {"uid", "role"}.
"""
import base64
import hashlib
import hmac
import json
import os
import time

SECRET = os.environ.get("GS_SECRET", "ccns-demo-secret-change-me").encode()
JWT_SECRET = os.environ.get("GS_JWT_SECRET", "").encode()


def _sign(payload: bytes) -> str:
    return hmac.new(SECRET, payload, hashlib.sha256).hexdigest()


def issue_token(uid: str, role: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"uid": uid, "role": role}).encode())
    return payload.decode() + "." + _sign(payload)


def verify_token(token: str):
    """Return the claims dict, or None if the token is missing/forged."""
    try:
        payload, sig = token.split(".", 1)
        if not hmac.compare_digest(_sign(payload.encode()), sig):
            return None
        return json.loads(base64.urlsafe_b64decode(payload.encode()))
    except Exception:
        return None


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def verify_jwt(token: str, secret: bytes = None):
    """Verify a standard HS256 JWT (header.payload.signature) and map it to gateway claims."""
    secret = secret if secret is not None else JWT_SECRET
    if not secret:
        return None
    try:
        header, payload, sig = token.split(".")
        if json.loads(_b64url_decode(header)).get("alg") != "HS256":
            return None
        expected = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig)):
            return None
        claims = json.loads(_b64url_decode(payload))
        if "exp" in claims and float(claims["exp"]) < time.time():
            return None
        uid = claims.get("user_id", claims.get("sub"))
        if uid is None:
            return None
        return {"uid": str(uid), "role": claims.get("role", "user")}
    except Exception:
        return None


def claims_from_header(header_value):
    if not header_value or not header_value.startswith("Bearer "):
        return None
    token = header_value[len("Bearer "):]
    return verify_token(token) or verify_jwt(token)


# The gateway uses this privileged identity for introspection and ownership look-ups.
SERVICE_TOKEN = issue_token("gateway", "service")
