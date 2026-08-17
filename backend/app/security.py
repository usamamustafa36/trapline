"""Auth primitives: API-key hashing, OTX-key encryption, admin bearer."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet

from .config import settings

# ── Per-VPS shipper API keys ────────────────────────────────────────────────
# Keys are shown once at creation, then only their hash is stored.


def generate_api_key() -> str:
    return f"{settings.api_key_prefix}{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """Deterministic keyed hash (HMAC-SHA256) so lookups stay O(1) by hash."""
    return hmac.new(settings.secret_key.encode(), api_key.encode(), hashlib.sha256).hexdigest()


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(api_key), stored_hash)


# ── OTX key encryption at rest ──────────────────────────────────────────────
# Demo uses Fernet. Production should back this with KMS / libsodium.


def _fernet() -> Fernet:
    key = settings.fernet_key
    if not key:
        # Deterministic dev fallback derived from secret_key (NOT for production).
        import base64

        digest = hashlib.sha256(settings.secret_key.encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


# ── Admin token (dashboard → privileged endpoints) ──────────────────────────
# MVP: single shared admin token derived from secret_key. Swap for real JWT/RBAC
# in Phase 3 (architecure.md §8).


def admin_token() -> str:
    return hashlib.sha256(f"admin:{settings.secret_key}".encode()).hexdigest()


def verify_admin_token(token: str) -> bool:
    return hmac.compare_digest(token, admin_token())
