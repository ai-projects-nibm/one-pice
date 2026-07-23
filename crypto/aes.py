"""AES-256-GCM encryption for sensitive fields (e.g. account numbers)."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_PATH = Path(__file__).resolve().parent.parent / "keys" / "aes.key"


def ensure_aes_key() -> bytes:
    """Load or create a 256-bit AES key stored on disk."""
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    KEY_PATH.write_bytes(key)
    try:
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass
    return key


def encrypt_aes(plaintext: str) -> str:
    """Encrypt plaintext with AES-256-GCM. Returns base64(nonce||ciphertext)."""
    key = ensure_aes_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_aes(token: str) -> str:
    """Decrypt a base64(nonce||ciphertext) token produced by encrypt_aes."""
    key = ensure_aes_key()
    aesgcm = AESGCM(key)
    raw = base64.b64decode(token.encode("utf-8"))
    nonce, ciphertext = raw[:12], raw[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
