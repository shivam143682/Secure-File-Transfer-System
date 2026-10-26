"""
Pydantic Schemas Module (schemas.py)
------------------------------------
Defines request and response schemas for strict input validation and data serialization.
Ensures strong typing and data integrity before hitting database logic.
"""

import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict


# ==============================================================================
# User & Authentication Schemas
# ==============================================================================

class UserRegisterRequest(BaseModel):
    """
    Schema for user registration payload.
    Enforces password complexity rules: minimum 8 characters, at least 1 letter, and at least 1 digit.
    """
    username: str = Field(..., min_length=3, max_length=50, description="Alphanumeric username")
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, description="Password with min 8 chars, 1 letter, 1 number")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Username may only contain letters, numbers, underscores, and dashes.")
        return v

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[a-zA-Z]", v):
            raise ValueError("Password must contain at least one letter.")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one number.")
        return v


class UserLoginRequest(BaseModel):
    """
    Schema for user login credentials.
    """
    username: str = Field(..., description="Registered username")
    password: str = Field(..., description="Account password")


class UserResponse(BaseModel):
    """
    Public user profile response (never exposes password_hash).
    """
    id: int
    username: str
    email: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """
    JWT Access Token response structure.
    """
    access_token: str
    token_type: str = "bearer"


# ==============================================================================
# File Transfer Schemas
# ==============================================================================

class FileUploadResponse(BaseModel):
    """
    Response returned after a file has been securely encrypted and stored.
    """
    transfer_id: int
    message: str
    original_filename: str
    size_bytes: int
    sha256_checksum: str


class FileMetadataResponse(BaseModel):
    """
    Metadata schema for listing sent/received transfers.
    Never exposes encrypted_data bytes or wrapped_key.
    """
    id: int
    original_filename: str
    content_type: str
    size_bytes: int
    sha256_checksum: str
    status: str
    created_at: datetime
    sender_id: int
    receiver_id: int
    sender_username: Optional[str] = None
    receiver_username: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Audit Log Schemas
# ==============================================================================

class TransferLogResponse(BaseModel):
    """
    Schema for security audit trail entries.
    """
    id: int
    transfer_id: Optional[int] = None
    user_id: int
    action: str
    status: str
    detail: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
