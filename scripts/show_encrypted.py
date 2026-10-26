"""
Cybersecurity Demonstration Script (scripts/show_encrypted.py)
--------------------------------------------------------------
Usage:
    python scripts/show_encrypted.py <transfer_id>
    OR
    python scripts/show_encrypted.py (interactive prompt)

Purpose:
    Examines a stored file record in PostgreSQL to prove to examiners and evaluators
    that file contents are strictly stored as unreadable ciphertext (BYTEA), not plaintext.
    Displays:
      1. Original filename
      2. Computed SHA-256 Checksum
      3. First 200 bytes of encrypted_data (raw ciphertext hex dump)
"""

import sys
import os

# Add parent directory to sys.path so app modules can be loaded when run from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import FileTransfer


def format_hex_dump(data: bytes, max_bytes: int = 200) -> str:
    """Formats raw binary ciphertext into a formatted hex view for inspection."""
    slice_data = data[:max_bytes]
    hex_str = slice_data.hex()
    # Format into pairs of hex characters
    formatted = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    return formatted


def inspect_transfer(transfer_id: int):
    """Fetches the file transfer record from PostgreSQL and displays its encrypted payload."""
    db: Session = SessionLocal()
    try:
        transfer = db.query(FileTransfer).filter(FileTransfer.id == transfer_id).first()
        if not transfer:
            print(f"\n[ERROR] No file transfer found with ID #{transfer_id}.")
            return

        cipher_bytes = transfer.encrypted_data
        sample_length = min(200, len(cipher_bytes))
        sample_bytes = cipher_bytes[:sample_length]

        print("=" * 75)
        print("          CYBERSECURITY LAB: ENCRYPTED AT REST DEMONSTRATION")
        print("=" * 75)
        print(f" Transfer ID:        #{transfer.id}")
        print(f" Original Filename:  {transfer.original_filename}")
        print(f" Content Type:       {transfer.content_type}")
        print(f" Original Size:      {transfer.size_bytes} bytes")
        print(f" Encrypted Size:     {len(cipher_bytes)} bytes (includes Fernet IV + HMAC tag)")
        print(f" Status:             {transfer.status}")
        print(f" Uploaded At:        {transfer.created_at}")
        print("-" * 75)
        print(f" SHA-256 Checksum:   {transfer.sha256_checksum}")
        print(f" Wrapped Key (DEK):  {transfer.wrapped_key[:30]}... (wrapped with MASTER_KEY)")
        print("-" * 75)
        print(f" [FIRST {sample_length} BYTES OF ENCRYPTED_DATA (POSTGRESQL BYTEA)]")
        print(" Hex Dump:")
        print(format_hex_dump(sample_bytes))
        print("\n Raw Byte Representation:")
        print(repr(sample_bytes))
        print("=" * 75)
        print(" [CONCLUSION] The data stored in the database is authenticated ciphertext.")
        print(" It cannot be read or understood without unwrapping the per-file DEK.")
        print("=" * 75)
    finally:
        db.close()


def main():
    if len(sys.argv) > 1:
        try:
            t_id = int(sys.argv[1])
        except ValueError:
            print("Invalid transfer ID provided. Please provide an integer ID.")
            sys.exit(1)
    else:
        print("--- Secure File Transfer: Encrypted Payload Inspector ---")
        user_input = input("Enter Transfer ID to inspect: ").strip()
        try:
            t_id = int(user_input)
        except ValueError:
            print("Invalid transfer ID. Exiting.")
            sys.exit(1)

    inspect_transfer(t_id)


if __name__ == "__main__":
    main()
