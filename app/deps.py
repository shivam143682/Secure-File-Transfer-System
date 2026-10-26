"""
Dependencies & Audit Logging Helpers (deps.py)
----------------------------------------------
Provides:
1. get_current_user: FastAPI dependency extracting and validating JWT tokens from
   either HTTP-only cookies (for browser sessions) or the 'Authorization: Bearer' header (for APIs).
2. log_security_event: Helper to write structured audit records into transfer_logs.
"""

from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, TransferLog
from app.security import decode_access_token


def get_token_from_request(request: Request) -> Optional[str]:
    """
    Extracts JWT token from either:
    1. 'access_token' cookie (set for browser sessions)
    2. 'Authorization: Bearer <token>' header (for REST API / scripts)
    """
    # Check Cookie first
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        # If stored with 'Bearer ' prefix, strip it
        if cookie_token.startswith("Bearer "):
            return cookie_token[7:].strip()
        return cookie_token.strip()

    # Check Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    return None


def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    """
    Validates current user authentication.
    Rejects missing, expired, or tampered tokens with HTTP 401 Unauthorized.
    """
    token = get_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or token is invalid. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    username: Optional[str] = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token claims.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with this token no longer exists.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Non-raising version of get_current_user for web pages.
    Returns the User if logged in, or None if unauthenticated.
    """
    token = get_token_from_request(request)
    if not token:
        return None

    payload = decode_access_token(token)
    if not payload:
        return None

    username = payload.get("sub")
    if not username:
        return None

    return db.query(User).filter(User.username == username).first()


def log_security_event(
    db: Session,
    action: str,
    status: str,
    user_id: Optional[int] = None,
    transfer_id: Optional[int] = None,
    detail: Optional[str] = None
) -> Optional[TransferLog]:
    """
    Records an immutable security audit log entry in the transfer_logs table.
    Ensures non-repudiation and traceability for cybersecurity compliance.
    """
    try:
        log_entry = TransferLog(
            action=action,
            status=status,
            user_id=user_id,
            transfer_id=transfer_id,
            detail=detail
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
    except Exception as e:
        db.rollback()
        # Even if logging encounters a DB issue, avoid crashing the main transaction
        print(f"[SECURITY LOG ERROR] Failed to record log: {e}")
        return None
