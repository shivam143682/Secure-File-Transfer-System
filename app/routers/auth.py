"""
Authentication Router (routers/auth.py)
---------------------------------------
Handles:
- POST /auth/register: User account registration with bcrypt password hashing and duplicate check.
- POST /auth/login: User credential verification, JWT issuance, and HttpOnly cookie setting.
- POST /auth/logout: Revocation of session cookie.
- GET /auth/me: Returns current authenticated user profile.
- All actions are logged into transfer_logs for cybersecurity auditability.
"""

from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.schemas import UserRegisterRequest, UserLoginRequest, UserResponse, TokenResponse
from app.security import hash_password, verify_password, create_access_token
from app.deps import get_current_user, log_security_event
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account"
)
def register(
    payload: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Registers a new user:
    1. Validates username, email, and password complexity via Pydantic.
    2. Rejects duplicate username or email.
    3. Hashes password using bcrypt.
    4. Records the registration event in transfer_logs.
    """
    # Check for existing username
    existing_user = db.query(User).filter(User.username == payload.username).first()
    if existing_user:
        log_security_event(
            db=db,
            action="REGISTER",
            status="FAILURE",
            user_id=None,
            detail=f"Registration failed: username '{payload.username}' is already taken."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already taken."
        )

    # Check for existing email
    existing_email = db.query(User).filter(User.email == payload.email).first()
    if existing_email:
        log_security_event(
            db=db,
            action="REGISTER",
            status="FAILURE",
            user_id=None,
            detail=f"Registration failed: email '{payload.email}' is already registered."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered."
        )

    # Hash password with bcrypt - plain password is never saved!
    hashed_pwd = hash_password(payload.password)

    new_user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hashed_pwd
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log successful registration
    log_security_event(
        db=db,
        action="REGISTER",
        status="SUCCESS",
        user_id=new_user.id,
        detail=f"User '{new_user.username}' successfully registered."
    )

    return new_user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT token and HttpOnly cookie"
)
def login(
    payload: UserLoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Authenticates user credentials:
    1. Looks up user by username.
    2. Verifies bcrypt password hash.
    3. On failure: logs LOGIN_FAIL and returns generic 'Invalid username or password'.
    4. On success: logs LOGIN_SUCCESS, issues a 30-min JWT, and sets an HttpOnly cookie.
    """
    generic_error = "Invalid username or password"

    user = db.query(User).filter(User.username == payload.username).first()

    # If user doesn't exist or password hash does not match
    if not user or not verify_password(payload.password, user.password_hash):
        log_security_event(
            db=db,
            action="LOGIN_FAIL",
            status="FAILURE",
            user_id=user.id if user else None,
            detail=f"Failed login attempt for username '{payload.username}'."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=generic_error,
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Credentials are valid -> Generate JWT
    access_token = create_access_token(data={"sub": user.username})

    # Set JWT in an HttpOnly, SameSite=Lax cookie so frontend browser pages work smoothly
    # max_age in seconds (30 mins = 1800 seconds)
    cookie_max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=cookie_max_age,
        httponly=True,
        samesite="lax",
        secure=False  # Allows testing over localhost HTTP; set to True in HTTPS production
    )

    # Log successful login
    log_security_event(
        db=db,
        action="LOGIN_SUCCESS",
        status="SUCCESS",
        user_id=user.id,
        detail=f"User '{user.username}' logged in successfully."
    )

    return TokenResponse(access_token=access_token, token_type="bearer")


@router.post(
    "/logout",
    summary="Log out and clear session cookie"
)
def logout(response: Response, current_user: User = Depends(get_current_user)):
    """
    Logs out the authenticated user by clearing the access_token cookie.
    """
    response.delete_cookie(key="access_token")
    return {"message": f"User '{current_user.username}' logged out successfully."}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current logged in user profile"
)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns the profile of the currently authenticated user.
    """
    return current_user
