"""
Cryptographic Security Utilities for QR Shield.

Implements two distinct cryptographic mechanisms:
1. SHA-256 Hashing: One-way cryptographic hash function (NOT encryption) used to generate
   deterministic fingerprints of URLs for indexing and duplicate detection.
2. AES-256-GCM Encryption: Authenticated symmetric encryption providing both confidentiality
   (ciphertext) and integrity/authenticity (16-byte GCM authentication tag).
"""

import base64
import binascii
import hashlib
import os
from typing import Tuple
from Crypto.Cipher import AES

from app.config import AES_KEY_BYTES

# Standard NIST-recommended nonce size for AES-GCM is 96 bits (12 bytes)
GCM_NONCE_SIZE = 12
# Standard AES-GCM authentication tag size is 128 bits (16 bytes)
GCM_TAG_SIZE = 16


class CryptoDecryptionError(Exception):
    """Raised safely when AES decryption or authentication verification fails."""
    pass


def generate_url_fingerprint(url: str) -> str:
    """
    Generates a deterministic SHA-256 hash fingerprint (64-char hex digest) of a URL.

    Important Distinction:
    SHA-256 is a one-way cryptographic hash function, NOT encryption.
    It cannot be reversed to recover the original URL. It serves solely as a unique
    fingerprint to check whether the same URL has been scanned previously.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string for fingerprinting.")

    normalized_url = url.strip()
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def encrypt_url(plaintext_url: str, key: bytes = AES_KEY_BYTES) -> Tuple[str, str]:
    """
    Encrypts a plaintext URL using AES-256 in Galois/Counter Mode (AES-GCM).

    Security Properties:
    - Uses a 256-bit (32-byte) secret key.
    - Generates a unique, cryptographically random 96-bit (12-byte) nonce for every call.
    - Produces both ciphertext and a 128-bit (16-byte) authentication tag.

    Returns:
        Tuple of (encrypted_url_b64, nonce_b64) as UTF-8 Base64 strings.
        Note: The 16-byte authentication tag is appended to the ciphertext.
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("AES-256 requires a strictly 32-byte (256-bit) encryption key.")

    if not isinstance(plaintext_url, str):
        raise ValueError("Plaintext URL must be a string.")

    # Generate a fresh, unique random nonce (CRITICAL: never reuse a nonce with the same key)
    nonce = os.urandom(GCM_NONCE_SIZE)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext_url.encode("utf-8"))

    # Combine ciphertext + authentication tag for unified storage
    combined_payload = ciphertext + auth_tag

    encrypted_b64 = base64.b64encode(combined_payload).decode("utf-8")
    nonce_b64 = base64.b64encode(nonce).decode("utf-8")

    return encrypted_b64, nonce_b64


def decrypt_url(encrypted_url_b64: str, nonce_b64: str, key: bytes = AES_KEY_BYTES) -> str:
    """
    Decrypts an AES-256-GCM encrypted URL and verifies its authentication tag.

    Safety Guarantee:
    Safely catches invalid keys, malformed Base64, wrong nonce sizes, corrupted
    ciphertext, or tampered authentication tags, raising CryptoDecryptionError.
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise CryptoDecryptionError("Decryption failed: invalid AES key length.")

    try:
        raw_payload = base64.b64decode(encrypted_url_b64, validate=True)
        nonce = base64.b64decode(nonce_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise CryptoDecryptionError("Decryption failed: corrupted Base64 encoding.")

    if len(nonce) != GCM_NONCE_SIZE:
        raise CryptoDecryptionError("Decryption failed: invalid nonce length.")

    if len(raw_payload) < GCM_TAG_SIZE:
        raise CryptoDecryptionError("Decryption failed: payload truncated or missing authentication tag.")

    # Split combined payload back into ciphertext and 16-byte authentication tag
    ciphertext = raw_payload[:-GCM_TAG_SIZE]
    auth_tag = raw_payload[-GCM_TAG_SIZE:]

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext, auth_tag)
        return plaintext_bytes.decode("utf-8")
    except (ValueError, KeyError, UnicodeDecodeError):
        raise CryptoDecryptionError(
            "Decryption failed: authentication tag mismatch (data tampered or incorrect key)."
        )
