"""RSA key generation and digital signatures for transactions."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "rsa_private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "rsa_public.pem"


def ensure_rsa_keys() -> None:
    """Generate RSA-2048 key pair if missing."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
        os.chmod(PUBLIC_KEY_PATH, 0o644)
    except OSError:
        pass


def _load_private_key():
    ensure_rsa_keys()
    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(), password=None
    )


def _load_public_key():
    ensure_rsa_keys()
    return serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())


def sign_data(data: str) -> str:
    """Sign SHA-256 digest of data with RSA-PSS. Returns base64 signature."""
    private_key = _load_private_key()
    signature = private_key.sign(
        data.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(data: str, signature_b64: str) -> bool:
    """Verify an RSA-PSS signature over data."""
    public_key = _load_public_key()
    try:
        public_key.verify(
            base64.b64decode(signature_b64.encode("utf-8")),
            data.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
