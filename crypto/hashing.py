"""Password hashing and content hashing helpers."""

from __future__ import annotations

import hashlib

import bcrypt


def hash_password(password: str) -> str:
    """Hash a password with bcrypt (adaptive, salted)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def sha256_hex(data: str) -> str:
    """Return SHA-256 digest of a string as lowercase hex."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
