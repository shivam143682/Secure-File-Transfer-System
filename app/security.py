"""
Security & Authentication Helpers (security.py)
-----------------------------------------------
Handles:
1. Password hashing and verification using industry-standard bcrypt.
   Bcrypt uses salted one-way hashing with an adaptive work factor, meaning
   even identical passwords produce completely different hash strings.
2. JSON Web Token (JWT) creation and decoding using python-jose.
   JWT tokens are cryptographically signed with SECRET_KEY and HS256 to
   guarantee that token claims cannot be forged by an attacker.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Any
import bcrypt
from jose import JWTError, jwt
from app.config import settings

# JWT signing algorithm
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    """
    Hashes a plain text password using bcrypt with a generated salt.
    Never stores or logs the plain password.
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain text password against a stored bcrypt hash.
    Returns True if the password matches, False otherwise.
    Safe against timing attacks.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def create_access_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a cryptographically signed JSON Web Token (JWT).
    Payload typically contains:
      - 'sub': Subject identifier (username or user_id)
      - 'exp': Expiration timestamp
      - 'iat': Issued-at timestamp
    """
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)

    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": now_utc
    })

    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict[str, Any]]:
    """
    Decodes and validates a JWT token using SECRET_KEY and HS256.
    Returns the token payload if valid and not expired, or None if invalid.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
