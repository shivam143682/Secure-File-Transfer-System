"""
Cryptography Module (crypto.py)
-------------------------------
Implements Envelope Encryption using Python's "cryptography" library (Fernet).

Concept - Envelope Encryption:
------------------------------
1. Why not encrypt all files with one key?
   If a single master key is compromised, all historical files are exposed.
   Also, encrypting millions of blocks under the same key leads to cryptographic key fatigue.

2. How Envelope Encryption solves this:
   - For every single uploaded file, a unique Data Encryption Key (DEK) is generated.
   - The file payload is encrypted using this DEK (AES-128-CBC + HMAC-SHA256 authenticated via Fernet).
   - The unique DEK itself is then encrypted ("wrapped") using the server's MASTER_KEY.
   - The database stores the ciphertext and the wrapped DEK in separate columns.
   - The original plaintext file and the plaintext DEK are NEVER saved to disk or DB.

3. Integrity verification:
   - A SHA-256 hash of the plain file is computed BEFORE encryption.
   - When the file is decrypted, comparing its hash guarantees that the file was not
     tampered with or corrupted in transit or storage.
"""

import hashlib
from cryptography.fernet import Fernet
from app.config import settings


def sha256_checksum(data: bytes) -> str:
    """
    Computes and returns the SHA-256 hex digest of the original plaintext bytes.
    Used for end-to-end integrity checks and non-repudiation.
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def encrypt_file(file_bytes: bytes) -> tuple[bytes, str]:
    """
    Encrypts raw file bytes using Envelope Encryption.

    Steps:
      1. Generate a brand new, unique Fernet key (Data Encryption Key / DEK).
      2. Encrypt the file data using this per-file DEK.
      3. Encrypt (wrap) the per-file DEK using the server MASTER_KEY.
      4. Return (ciphertext, wrapped_key).

    Returns:
      tuple: (cipher_text as bytes, wrapped_key as string)
    """
    # Step 1: Generate a fresh 32-byte Fernet key for this specific file
    per_file_dek = Fernet.generate_key()

    # Step 2: Encrypt the file content with the per-file DEK
    file_cipher = Fernet(per_file_dek)
    cipher_text = file_cipher.encrypt(file_bytes)

    # Step 3: Wrap (encrypt) the per-file DEK using the server's MASTER_KEY
    master_cipher = Fernet(settings.MASTER_KEY.encode("utf-8"))
    wrapped_key_bytes = master_cipher.encrypt(per_file_dek)
    wrapped_key_str = wrapped_key_bytes.decode("utf-8")

    return cipher_text, wrapped_key_str


def decrypt_file(cipher_text: bytes, wrapped_key: str) -> bytes:
    """
    Decrypts encrypted file bytes using Envelope Decryption.
    (Designed for Half 2 download flow; unit-tested in Half 1).

    Steps:
      1. Unwrap the per-file DEK using the server MASTER_KEY.
      2. Decrypt the ciphertext using the unwrapped per-file DEK.
      3. Return original plaintext bytes.
    """
    # Step 1: Unwrap the per-file DEK using the server's MASTER_KEY
    master_cipher = Fernet(settings.MASTER_KEY.encode("utf-8"))
    per_file_dek = master_cipher.decrypt(wrapped_key.encode("utf-8"))

    # Step 2: Decrypt the file data using the unwrapped DEK
    file_cipher = Fernet(per_file_dek)
    plain_bytes = file_cipher.decrypt(cipher_text)

    return plain_bytes
