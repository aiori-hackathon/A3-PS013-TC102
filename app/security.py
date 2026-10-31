"""Password hashing and short-lived bearer tokens.

PBKDF2-HMAC-SHA256 uses the Python standard library, so no native password
hashing package is needed for this educational project.
"""
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import secrets
import jwt
from app.config import SECRET_KEY, ACCESS_TOKEN_MINUTES

ALGORITHM = "HS256"
PBKDF2_ITERATIONS = 310_000

def hash_password(password: str) -> str:
    """Store a salted, deliberately expensive password hash, never the password."""
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(derived).decode()}"

def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt_text, expected_text = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_text)
        expected = base64.b64decode(expected_text)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def create_access_token(user_id: int) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": expires}, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str) -> int:
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return int(payload["sub"])
