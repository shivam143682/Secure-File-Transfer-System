"""
Secure Upload Test Suite (tests/test_upload.py)
-----------------------------------------------
Covers TC-02:
- Stored bytes differ from original plain file (encrypted at rest).
- SHA-256 checksum is correctly saved and matches plaintext.
- Metadata (size, receiver, status) is accurate.
- Oversized file is rejected with 400.
- Disallowed file extension is rejected with 400.
- Self-transfer is rejected.
- Transfer log entry is written for UPLOAD.
- GET /files/sent and GET /files/received return metadata only.
"""

import io
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models import User, FileTransfer, TransferLog
from app.crypto import decrypt_file, sha256_checksum
from app.security import hash_password, create_access_token


def create_user(db: Session, username: str, email: str) -> tuple[User, str]:
    """Helper to create a user and return the user object + auth bearer token."""
    user = User(
        username=username,
        email=email,
        password_hash=hash_password("ValidPassword123")
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token({"sub": user.username})
    return user, token


def test_tc02_secure_upload_encryption_and_metadata(client: TestClient, db_session: Session):
    """
    TC-02:
    1. Upload valid document from sender (alice) to receiver (bob).
    2. Verify stored encrypted_data != original_bytes.
    3. Verify sha256_checksum matches original plaintext.
    4. Verify decrypt_file restores original bytes exactly.
    5. Verify metadata list via /files/sent and /files/received.
    6. Verify audit log entry.
    """
    alice, alice_token = create_user(db_session, "alice", "alice@test.com")
    bob, bob_token = create_user(db_session, "bob", "bob@test.com")

    headers = {"Authorization": f"Bearer {alice_token}"}
    plain_content = b"This is a confidential cybersecurity lab report for B.Tech."
    expected_hash = sha256_checksum(plain_content)

    # 1. Upload File
    file_payload = ("report.pdf", io.BytesIO(plain_content), "application/pdf")
    upload_resp = client.post(
        "/files/upload",
        data={"receiver_username": "bob"},
        files={"file": file_payload},
        headers=headers
    )

    assert upload_resp.status_code == 201
    res_data = upload_resp.json()
    transfer_id = res_data["transfer_id"]
    assert res_data["original_filename"] == "report.pdf"
    assert res_data["size_bytes"] == len(plain_content)
    assert res_data["sha256_checksum"] == expected_hash

    # 2. Check Database Record Directly
    transfer = db_session.query(FileTransfer).filter(FileTransfer.id == transfer_id).first()
    assert transfer is not None

    # Stored bytes MUST differ from original plain bytes (encrypted at rest)
    assert transfer.encrypted_data != plain_content
    # Stored bytes must not be plain text
    assert b"cybersecurity" not in transfer.encrypted_data

    # Checksum is saved and matches original
    assert transfer.sha256_checksum == expected_hash
    assert transfer.status == "UPLOADED"
    assert transfer.sender_id == alice.id
    assert transfer.receiver_id == bob.id

    # 3. Verify Decrypt Restores Original Content
    decrypted = decrypt_file(transfer.encrypted_data, transfer.wrapped_key)
    assert decrypted == plain_content

    # 4. Verify Transfer Log
    log_entry = (
        db_session.query(TransferLog)
        .filter(TransferLog.transfer_id == transfer_id, TransferLog.action == "UPLOAD")
        .first()
    )
    assert log_entry is not None
    assert log_entry.status == "SUCCESS"
    assert log_entry.user_id == alice.id

    # 5. Verify GET /files/sent (returns metadata, never file content)
    sent_resp = client.get("/files/sent", headers=headers)
    assert sent_resp.status_code == 200
    sent_list = sent_resp.json()
    assert len(sent_list) == 1
    assert sent_list[0]["original_filename"] == "report.pdf"
    assert sent_list[0]["receiver_username"] == "bob"
    assert "encrypted_data" not in sent_list[0]
    assert "wrapped_key" not in sent_list[0]

    # 6. Verify GET /files/received for bob
    bob_headers = {"Authorization": f"Bearer {bob_token}"}
    recv_resp = client.get("/files/received", headers=bob_headers)
    assert recv_resp.status_code == 200
    recv_list = recv_resp.json()
    assert len(recv_list) == 1
    assert recv_list[0]["original_filename"] == "report.pdf"
    assert recv_list[0]["sender_username"] == "alice"


def test_upload_disallowed_extension_rejected(client: TestClient, db_session: Session):
    """Verifies that executable or malicious extensions (e.g. .exe, .sh) are blocked."""
    alice, alice_token = create_user(db_session, "alice", "alice@test.com")
    bob, _ = create_user(db_session, "bob", "bob@test.com")
    headers = {"Authorization": f"Bearer {alice_token}"}

    bad_file = ("malware.exe", io.BytesIO(b"malicious payload"), "application/x-msdownload")
    resp = client.post(
        "/files/upload",
        data={"receiver_username": "bob"},
        files={"file": bad_file},
        headers=headers
    )
    assert resp.status_code == 400
    assert "disallowed" in resp.json()["detail"].lower()


def test_upload_oversized_file_rejected(client: TestClient, db_session: Session):
    """Verifies that files exceeding MAX_UPLOAD_MB (10 MB) are rejected."""
    alice, alice_token = create_user(db_session, "alice", "alice@test.com")
    bob, _ = create_user(db_session, "bob", "bob@test.com")
    headers = {"Authorization": f"Bearer {alice_token}"}

    # Create oversized mock payload (> 10 MB = 10 * 1024 * 1024 + 10 bytes)
    oversized_data = b"0" * (10 * 1024 * 1024 + 1024)
    big_file = ("huge.zip", io.BytesIO(oversized_data), "application/zip")

    resp = client.post(
        "/files/upload",
        data={"receiver_username": "bob"},
        files={"file": big_file},
        headers=headers
    )
    assert resp.status_code == 400
    assert "exceeds maximum allowed size" in resp.json()["detail"].lower()


def test_upload_empty_file_rejected(client: TestClient, db_session: Session):
    """Verifies that an empty 0-byte file is rejected."""
    alice, alice_token = create_user(db_session, "alice", "alice@test.com")
    bob, _ = create_user(db_session, "bob", "bob@test.com")
    headers = {"Authorization": f"Bearer {alice_token}"}

    empty_file = ("empty.txt", io.BytesIO(b""), "text/plain")
    resp = client.post(
        "/files/upload",
        data={"receiver_username": "bob"},
        files={"file": empty_file},
        headers=headers
    )
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


def test_upload_to_self_rejected(client: TestClient, db_session: Session):
    """Verifies that a user cannot transfer files to themselves."""
    alice, alice_token = create_user(db_session, "alice", "alice@test.com")
    headers = {"Authorization": f"Bearer {alice_token}"}

    file_payload = ("notes.txt", io.BytesIO(b"sample notes"), "text/plain")
    resp = client.post(
        "/files/upload",
        data={"receiver_username": "alice"},
        files={"file": file_payload},
        headers=headers
    )
    assert resp.status_code == 400
    assert "cannot transfer files to yourself" in resp.json()["detail"].lower()
