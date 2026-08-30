import jwt
import datetime

SECRET_KEY = "bola_demo_secret"
ALGORITHM = "HS256"

def create_access_token(user_id: int, username: str):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": expiration
    }
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
