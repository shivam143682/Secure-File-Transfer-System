"""
Files Router (routers/files.py)
-------------------------------
Handles:
- POST /files/upload: Validates receiver, file size, extension whitelist,
  computes SHA-256 integrity hash, encrypts file in-memory using per-file Fernet DEK,
  wraps DEK using MASTER_KEY, saves ciphertext in PostgreSQL BYTEA, and logs the event.
  The plain file is NEVER saved to disk or DB.
- GET /files/sent: Lists file metadata sent by the authenticated user (no file content).
- GET /files/received: Lists file metadata received by the authenticated user (no file content).
"""

import os
import re
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, FileTransfer
from app.schemas import FileUploadResponse, FileMetadataResponse
from app.crypto import encrypt_file, sha256_checksum
from app.deps import get_current_user, log_security_event
from app.config import settings

router = APIRouter(prefix="/files", tags=["Files"])


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes filename to prevent directory traversal and OS injection attacks.
    Extracts base name and removes unsafe characters.
    """
    clean_base = os.path.basename(filename).strip()
    # Replace any character that is not alphanumeric, dot, underscore, or dash
    sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "_", clean_base)
    # Avoid empty filename
    return sanitized if sanitized else "uploaded_file"


@router.post(
    "/upload",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Securely encrypt and upload a file for a specific receiver"
)
async def upload_file(
    receiver_username: str = Form(..., description="Target username to receive the file"),
    file: UploadFile = File(..., description="File to upload"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Secure File Upload Flow:
    1. Validate receiver exists and is not self.
    2. Sanitize filename and validate file extension against security whitelist.
    3. Read file stream in-memory (never written to disk).
    4. Validate file size (not empty and <= MAX_UPLOAD_MB).
    5. Compute SHA-256 hash of original plain file.
    6. Encrypt file with unique per-file DEK; wrap DEK with server MASTER_KEY.
    7. Save ciphertext blob to PostgreSQL BYTEA column.
    8. Record audit log entry in transfer_logs.
    """
    target_username = receiver_username.strip()

    # 1. Receiver validation: Cannot send to self
    if target_username.lower() == current_user.username.lower():
        log_security_event(
            db=db,
            action="UPLOAD",
            status="FAILURE",
            user_id=current_user.id,
            detail=f"Upload rejected: sender '{current_user.username}' attempted to transfer to self."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot transfer files to yourself. Please select another registered user."
        )

    # 1. Receiver validation: Must exist in database
    receiver = db.query(User).filter(User.username == target_username).first()
    if not receiver:
        log_security_event(
            db=db,
            action="UPLOAD",
            status="FAILURE",
            user_id=current_user.id,
            detail=f"Upload rejected: receiver username '{target_username}' not found."
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Receiver '{target_username}' does not exist."
        )

    # 2. Filename sanitization
    raw_filename = file.filename or "unknown_file"
    safe_filename = sanitize_filename(raw_filename)

    # 2. Extension whitelist validation
    ext = safe_filename.rsplit(".", 1)[-1].lower() if "." in safe_filename else ""
    if ext not in settings.ALLOWED_EXTENSIONS:
        log_security_event(
            db=db,
            action="UPLOAD",
            status="FAILURE",
            user_id=current_user.id,
            detail=f"Upload rejected: disallowed extension '.{ext}' for file '{safe_filename}'."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Disallowed file extension '.{ext}'. Allowed types: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}."
        )

    # 3. Read file content strictly into memory
    content = await file.read()
    size_bytes = len(content)

    # 4. Size validation: Cannot be empty
    if size_bytes == 0:
        log_security_event(
            db=db,
            action="UPLOAD",
            status="FAILURE",
            user_id=current_user.id,
            detail=f"Upload rejected: file '{safe_filename}' is empty (0 bytes)."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes)."
        )

    # 4. Size validation: Must not exceed MAX_UPLOAD_MB
    if size_bytes > settings.max_upload_bytes:
        log_security_event(
            db=db,
            action="UPLOAD",
            status="FAILURE",
            user_id=current_user.id,
            detail=f"Upload rejected: file '{safe_filename}' ({size_bytes} bytes) exceeds {settings.MAX_UPLOAD_MB}MB limit."
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_MB} MB."
        )

    # 5. Compute SHA-256 checksum of the original plain file
    original_checksum = sha256_checksum(content)

    # 6. Envelope Encryption: Encrypt in-memory, wrap DEK with MASTER_KEY
    cipher_text, wrapped_key = encrypt_file(content)

    # 7. Persist to PostgreSQL database (ciphertext saved to BYTEA)
    transfer = FileTransfer(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        original_filename=safe_filename,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=size_bytes,
        encrypted_data=cipher_text,
        wrapped_key=wrapped_key,
        sha256_checksum=original_checksum,
        status="UPLOADED"
    )
    db.add(transfer)
    db.commit()
    db.refresh(transfer)

    # 8. Record successful upload in audit trail
    log_security_event(
        db=db,
        action="UPLOAD",
        status="SUCCESS",
        user_id=current_user.id,
        transfer_id=transfer.id,
        detail=f"File '{safe_filename}' ({size_bytes} bytes) encrypted and transferred to '{receiver.username}'."
    )

    return FileUploadResponse(
        transfer_id=transfer.id,
        message="File encrypted and stored successfully.",
        original_filename=safe_filename,
        size_bytes=size_bytes,
        sha256_checksum=original_checksum
    )


@router.get(
    "/sent",
    response_model=List[FileMetadataResponse],
    summary="List metadata of all files sent by the current user"
)
def get_sent_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns metadata list of files sent by the authenticated user.
    Never exposes encrypted bytes or encryption keys.
    """
    transfers = (
        db.query(FileTransfer)
        .filter(FileTransfer.sender_id == current_user.id)
        .order_by(FileTransfer.created_at.desc())
        .all()
    )

    results = []
    for t in transfers:
        results.append(
            FileMetadataResponse(
                id=t.id,
                original_filename=t.original_filename,
                content_type=t.content_type,
                size_bytes=t.size_bytes,
                sha256_checksum=t.sha256_checksum,
                status=t.status,
                created_at=t.created_at,
                sender_id=t.sender_id,
                receiver_id=t.receiver_id,
                sender_username=t.sender.username if t.sender else None,
                receiver_username=t.receiver.username if t.receiver else None
            )
        )
    return results


@router.get(
    "/received",
    response_model=List[FileMetadataResponse],
    summary="List metadata of all files received by the current user"
)
def get_received_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns metadata list of files received by the authenticated user.
    Never exposes encrypted bytes or encryption keys.
    """
    transfers = (
        db.query(FileTransfer)
        .filter(FileTransfer.receiver_id == current_user.id)
        .order_by(FileTransfer.created_at.desc())
        .all()
    )

    results = []
    for t in transfers:
        results.append(
            FileMetadataResponse(
                id=t.id,
                original_filename=t.original_filename,
                content_type=t.content_type,
                size_bytes=t.size_bytes,
                sha256_checksum=t.sha256_checksum,
                status=t.status,
                created_at=t.created_at,
                sender_id=t.sender_id,
                receiver_id=t.receiver_id,
                sender_username=t.sender.username if t.sender else None,
                receiver_username=t.receiver.username if t.receiver else None
            )
        )
    return results
