"""
Authentication Test Suite (tests/test_auth.py)
----------------------------------------------
Covers TC-01:
- Valid login accepted.
- Wrong password rejected with generic error.
- Password is stored ONLY as a bcrypt hash, never plaintext.
- Registration validation (complexity, duplicates).
- Audit logs created for REGISTER, LOGIN_SUCCESS, and LOGIN_FAIL.
"""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models import User, TransferLog
from app.security import verify_password


def test_tc01_auth_flow_and_password_hashing(client: TestClient, db_session: Session):
    """
    TC-01:
    1. Register user with valid credentials.
    2. Verify password is stored ONLY as a hash in the database.
    3. Wrong password rejected with generic error.
    4. Valid login accepted, returns JWT and sets HttpOnly cookie.
    5. Audit log entries recorded in transfer_logs.
    """
    plain_password = "SecurePassword123"
    register_payload = {
        "username": "alice",
        "email": "alice@university.edu",
        "password": plain_password
    }

    # Step 1: Register User
    reg_response = client.post("/auth/register", json=register_payload)
    assert reg_response.status_code == 201
    user_data = reg_response.json()
    assert user_data["username"] == "alice"
    assert user_data["email"] == "alice@university.edu"
    assert "password" not in user_data
    assert "password_hash" not in user_data

    # Step 2: Verify Password Storage in DB (Must ONLY be a bcrypt hash)
    db_user = db_session.query(User).filter(User.username == "alice").first()
    assert db_user is not None
    # Must NOT equal plain password
    assert db_user.password_hash != plain_password
    # Bcrypt hashes start with '$2b$' or '$2a$'
    assert db_user.password_hash.startswith("$2b$") or db_user.password_hash.startswith("$2a$")
    # Verify the hash actually works with verify_password
    assert verify_password(plain_password, db_user.password_hash) is True
    assert verify_password("WrongPassword999", db_user.password_hash) is False

    # Step 3: Wrong Password Rejected
    wrong_login_resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "WrongPassword999"}
    )
    assert wrong_login_resp.status_code == 401
    # Generic error message to prevent username/password enumeration
    assert wrong_login_resp.json()["detail"] == "Invalid username or password"

    # Step 4: Non-existent User Rejected with Same Generic Error
    ghost_login_resp = client.post(
        "/auth/login",
        json={"username": "ghost_user", "password": "AnyPassword123"}
    )
    assert ghost_login_resp.status_code == 401
    assert ghost_login_resp.json()["detail"] == "Invalid username or password"

    # Step 5: Valid Login Accepted
    valid_login_resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": plain_password}
    )
    assert valid_login_resp.status_code == 200
    token_json = valid_login_resp.json()
    assert "access_token" in token_json
    assert token_json["token_type"] == "bearer"

    # Verify HttpOnly cookie was set
    assert "access_token" in valid_login_resp.cookies
    cookie_val = valid_login_resp.cookies["access_token"]
    assert cookie_val == token_json["access_token"]

    # Step 6: Verify TransferLog entries
    logs = db_session.query(TransferLog).all()
    actions = [log.action for log in logs]
    statuses = [log.status for log in logs]

    assert "REGISTER" in actions
    assert "LOGIN_FAIL" in actions
    assert "LOGIN_SUCCESS" in actions
    assert "SUCCESS" in statuses
    assert "FAILURE" in statuses


def test_registration_duplicate_rejection(client: TestClient, db_session: Session):
    """Verifies that duplicate username or email is rejected."""
    payload1 = {
        "username": "bob",
        "email": "bob@university.edu",
        "password": "Password123"
    }
    resp1 = client.post("/auth/register", json=payload1)
    assert resp1.status_code == 201

    # Duplicate username
    payload2 = {
        "username": "bob",
        "email": "bob_other@university.edu",
        "password": "Password123"
    }
    resp2 = client.post("/auth/register", json=payload2)
    assert resp2.status_code == 400
    assert "already taken" in resp2.json()["detail"].lower()

    # Duplicate email
    payload3 = {
        "username": "bob2",
        "email": "bob@university.edu",
        "password": "Password123"
    }
    resp3 = client.post("/auth/register", json=payload3)
    assert resp3.status_code == 400
    assert "already registered" in resp3.json()["detail"].lower()


def test_password_complexity_rules(client: TestClient):
    """Verifies that weak passwords lacking letters, numbers, or length are rejected."""
    # Too short (< 8 chars)
    resp = client.post(
        "/auth/register",
        json={"username": "shorty", "email": "short@test.com", "password": "Ab1"}
    )
    assert resp.status_code == 422 or resp.status_code == 400

    # No digits
    resp_no_digit = client.post(
        "/auth/register",
        json={"username": "nodigit", "email": "nodigit@test.com", "password": "PasswordOnly"}
    )
    assert resp_no_digit.status_code == 422 or resp_no_digit.status_code == 400

    # No letters
    resp_no_letter = client.post(
        "/auth/register",
        json={"username": "noletter", "email": "noletter@test.com", "password": "1234567890"}
    )
    assert resp_no_letter.status_code == 422 or resp_no_letter.status_code == 400
