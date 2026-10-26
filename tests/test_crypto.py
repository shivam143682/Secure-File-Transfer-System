"""
Cryptography Test Suite (tests/test_crypto.py)
----------------------------------------------
Verifies:
1. SHA-256 calculation matches standard hashlib digest.
2. encrypt_file produces ciphertext distinct from original plaintext.
3. Every encryption uses a fresh Data Encryption Key (DEK).
4. decrypt_file successfully restores original bytes.
5. Tampered ciphertext or corrupted wrapped key fails decryption.
"""

import hashlib
import pytest
from cryptography.fernet import InvalidToken
from app.crypto import encrypt_file, decrypt_file, sha256_checksum


def test_sha256_checksum():
    """Confirms sha256_checksum returns exact hex digest of original bytes."""
    test_data = b"Cybersecurity B.Tech Major Project - Secure File Transfer"
    expected_hash = hashlib.sha256(test_data).hexdigest()
    actual_hash = sha256_checksum(test_data)
    assert actual_hash == expected_hash
    assert len(actual_hash) == 64


def test_envelope_encryption_and_decryption():
    """
    Confirms:
    1. Ciphertext is not equal to original plaintext.
    2. decrypt_file cleanly reverses the envelope encryption.
    """
    original_data = b"Confidential university examination questions and answers 2026."
    
    # Encrypt
    cipher_text, wrapped_key = encrypt_file(original_data)

    # Stored bytes must differ completely from original plaintext
    assert cipher_text != original_data
    assert len(cipher_text) > 0
    assert len(wrapped_key) > 0

    # Decrypt
    decrypted_data = decrypt_file(cipher_text, wrapped_key)
    assert decrypted_data == original_data


def test_unique_dek_per_file():
    """
    Confirms that encrypting the same plaintext twice generates different
    wrapped keys (proving unique per-file DEKs) and different ciphertexts.
    """
    sample = b"Same plain message content"
    cipher_1, wrapped_key_1 = encrypt_file(sample)
    cipher_2, wrapped_key_2 = encrypt_file(sample)

    # Different ciphertexts due to Fernet timestamp/IV and different DEK
    assert cipher_1 != cipher_2
    # Different wrapped keys because each file generates a fresh DEK
    assert wrapped_key_1 != wrapped_key_2

    # Both decrypt back to identical plaintext
    assert decrypt_file(cipher_1, wrapped_key_1) == sample
    assert decrypt_file(cipher_2, wrapped_key_2) == sample


def test_tampered_ciphertext_rejected():
    """Confirms that modifying even a single byte of ciphertext raises InvalidToken."""
    data = b"Top secret classified memo"
    cipher_text, wrapped_key = encrypt_file(data)

    # Tamper with the ciphertext
    tampered_cipher = bytearray(cipher_text)
    tampered_cipher[15] = (tampered_cipher[15] + 1) % 256
    tampered_cipher = bytes(tampered_cipher)

    with pytest.raises(InvalidToken):
        decrypt_file(tampered_cipher, wrapped_key)


def test_tampered_wrapped_key_rejected():
    """Confirms that tampering with wrapped_key raises InvalidToken during unwrap."""
    data = b"Sensitive financial report"
    cipher_text, wrapped_key = encrypt_file(data)

    # Tamper with wrapped key string
    tampered_wrapped_key = wrapped_key[:-4] + "AAAA"

    with pytest.raises(Exception):
        decrypt_file(cipher_text, tampered_wrapped_key)
