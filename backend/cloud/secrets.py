"""
Encryption for stored provider credentials.

No secret manager exists in this deployment yet, so credentials are encrypted
with AES-256-GCM using VECTRA_SECRETS_KEY (32 random bytes, base64) before they
are written to a backend-only Firestore document. The integration's org id and
integration id are bound in as associated data, so a ciphertext copied onto a
different integration or organization fails to decrypt.

To move to Google Secret Manager later, replace `seal`/`open_sealed` — callers
only ever see plaintext dicts in memory.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cloud.errors import CloudProviderError

KEY_ENV = "VECTRA_SECRETS_KEY"
_VERSION = 1


def _key() -> bytes:
    raw = os.getenv(KEY_ENV, "").strip()
    if not raw:
        raise CloudProviderError(
            CloudProviderError.NOT_CONFIGURED,
            "Cloud Security is not configured on this Vectra deployment.",
            f"An administrator must set {KEY_ENV}.",
        )
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != 32:
        raise CloudProviderError(
            CloudProviderError.NOT_CONFIGURED,
            "Cloud Security is misconfigured on this Vectra deployment.",
            f"{KEY_ENV} must be 32 random bytes, base64-encoded.",
        )
    return key


def is_configured() -> bool:
    try:
        _key()
        return True
    except CloudProviderError:
        return False


def _aad(org_id: str, integration_id: str) -> bytes:
    return f"vectra-cloud-secret:v{_VERSION}:{org_id}:{integration_id}".encode()


def seal(org_id: str, integration_id: str, secret: dict) -> dict:
    """Encrypt a credential dict. Returns a Firestore-storable envelope."""
    nonce = os.urandom(12)
    plaintext = json.dumps(secret, separators=(",", ":")).encode()
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, _aad(org_id, integration_id))
    return {
        "v": _VERSION,
        "alg": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def open_sealed(org_id: str, integration_id: str, envelope: dict) -> dict:
    """Decrypt an envelope produced by `seal`. Never logs or echoes content."""
    try:
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        plaintext = AESGCM(_key()).decrypt(nonce, ciphertext, _aad(org_id, integration_id))
        return json.loads(plaintext)
    except CloudProviderError:
        raise
    except Exception:
        raise CloudProviderError(
            CloudProviderError.INVALID_CREDENTIALS,
            "Stored credentials for this integration could not be read.",
            "Reconnect the integration to store new credentials.",
        )


def aws_external_id(org_id: str) -> str:
    """
    Stable, unguessable STS ExternalId per organization.

    Derived with HMAC from the deployment key so it needs no storage, is the
    same every time an org views setup instructions, and cannot be predicted
    by another organization — which is what prevents confused-deputy role reuse.
    """
    digest = hmac.new(_key(), f"aws-external-id:{org_id}".encode(), hashlib.sha256).digest()
    return "vectra-" + base64.b32encode(digest).decode().rstrip("=").lower()[:40]
