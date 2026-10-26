"""
Database Models (models.py)
---------------------------
Defines the relational database tables using SQLAlchemy 2.0 ORM:
1. User: Stores registered user accounts with securely hashed passwords.
2. FileTransfer: Stores encrypted file metadata, encrypted data (BYTEA),
   wrapped encryption keys, and integrity checksums.
3. TransferLog: Immutable audit trail logging security actions (registration,
   login attempts, uploads) for non-repudiation.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, LargeBinary, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    """
    Represents a registered user in the Secure File Transfer System.
    Passwords are NEVER stored in plaintext - only as bcrypt hashes.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships:
    # A user can send multiple files
    sent_transfers = relationship(
        "FileTransfer",
        foreign_keys="[FileTransfer.sender_id]",
        back_populates="sender",
        cascade="all, delete-orphan"
    )

    # A user can receive multiple files
    received_transfers = relationship(
        "FileTransfer",
        foreign_keys="[FileTransfer.receiver_id]",
        back_populates="receiver",
        cascade="all, delete-orphan"
    )

    # A user has associated audit logs
    logs = relationship(
        "TransferLog",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}'>"


class FileTransfer(Base):
    """
    Represents an encrypted file transfer between a sender and a receiver.
    The file data is encrypted BEFORE storage and stored as raw bytes (BYTEA).
    Each file has a unique per-file Data Encryption Key (DEK) which is itself
    wrapped (encrypted) with the server's MASTER_KEY and saved in wrapped_key.
    """
    __tablename__ = "file_transfers"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=False)
    size_bytes = Column(Integer, nullable=False)

    # Ciphertext stored as PostgreSQL BYTEA (LargeBinary)
    encrypted_data = Column(LargeBinary, nullable=False)

    # The per-file DEK wrapped (encrypted) with the server MASTER_KEY
    wrapped_key = Column(String(255), nullable=False)

    # SHA-256 hex digest of the original plain file before encryption
    sha256_checksum = Column(String(64), nullable=False)

    # Status of the file transfer (e.g., "UPLOADED", "DOWNLOADED")
    status = Column(String(50), default="UPLOADED", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_transfers")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_transfers")
    logs = relationship("TransferLog", back_populates="transfer", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<FileTransfer id={self.id} file='{self.original_filename}' sender_id={self.sender_id} receiver_id={self.receiver_id}>"


class TransferLog(Base):
    """
    Immutable audit log table for cybersecurity compliance and non-repudiation.
    Records every security-relevant action: registration, logins (success/failure),
    and file upload attempts.
    """
    __tablename__ = "transfer_logs"

    id = Column(Integer, primary_key=True, index=True)
    transfer_id = Column(Integer, ForeignKey("file_transfers.id", ondelete="SET NULL"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    action = Column(String(50), nullable=False)       # e.g., 'REGISTER', 'LOGIN_SUCCESS', 'LOGIN_FAIL', 'UPLOAD'
    status = Column(String(20), nullable=False)       # 'SUCCESS' or 'FAILURE'
    detail = Column(Text, nullable=True)              # Contextual message (IP, filename, error reason)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    transfer = relationship("FileTransfer", back_populates="logs")
    user = relationship("User", back_populates="logs")

    def __repr__(self) -> str:
        return f"<TransferLog id={self.id} action='{self.action}' status='{self.status}' user_id={self.user_id}>"
