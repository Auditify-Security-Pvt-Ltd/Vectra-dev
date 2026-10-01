"""
Firebase Admin bootstrap.

Gives the backend a verified identity for each request and server-side access
to Firestore, which is what makes quota enforcement and admin authorization
real rather than advisory.

CREDENTIAL SOURCES, in priority order
-------------------------------------
1. FIREBASE_SERVICE_ACCOUNT_JSON — the service-account JSON itself, inline.
   Suited to secret managers and container platforms (Cloud Run, Secret
   Manager, CI) where mounting a file is awkward. Base64 is also accepted so
   the value survives single-line env formats.

2. FIREBASE_CREDENTIALS / GOOGLE_APPLICATION_CREDENTIALS — path to the JSON.
   The convention for local development; keep the file outside the repo.

3. Application Default Credentials — no key material at all. On Google Cloud
   (Cloud Run, GKE, Compute Engine) the runtime service account is used
   automatically, which is the recommended production setup: nothing to leak,
   rotate or commit.

Nothing here is ever committed: only variable names live in the repo, never
values. The private key is never logged.

If no source resolves, the SDK stays uninitialised and `is_configured()`
returns False. Callers use that to decide whether identity can be trusted;
admin endpoints refuse outright rather than falling back to anything weaker.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import threading
from typing import Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

_lock = threading.Lock()
_app: Any = None
_db: Any = None
_init_attempted = False
_init_error: Optional[str] = None
_source: Optional[str] = None
_project_id: Optional[str] = None

_JSON_VAR = "FIREBASE_SERVICE_ACCOUNT_JSON"
_PATH_VARS = ("FIREBASE_CREDENTIALS", "GOOGLE_APPLICATION_CREDENTIALS")
_ADC_OPT_IN = "FIREBASE_USE_ADC"


def _inline_service_account() -> Optional[dict]:
    """Parse the service account from an env var holding raw or base64 JSON."""
    raw = os.getenv(_JSON_VAR, "").strip()
    if not raw:
        return None

    # Tolerate base64 so the value can be stored on a single line.
    if not raw.lstrip().startswith("{"):
        try:
            raw = base64.b64decode(raw, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            raise ValueError(f"{_JSON_VAR} is neither JSON nor valid base64-encoded JSON")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{_JSON_VAR} is not valid JSON: {exc.msg}")

    missing = [k for k in ("project_id", "private_key", "client_email") if not data.get(k)]
    if missing:
        raise ValueError(f"{_JSON_VAR} is missing required field(s): {', '.join(missing)}")
    return data


def _credentials_path() -> Optional[str]:
    for var in _PATH_VARS:
        path = os.getenv(var, "").strip()
        if path:
            return os.path.expanduser(path)
    return None


def _warn_on_project_mismatch(project_id: Optional[str]) -> None:
    """
    The backend and the browser must talk to the same Firebase project, or
    tokens minted for one will never verify against the other. Only the
    non-secret project id is compared, and only logged.
    """
    expected = os.getenv("FIREBASE_PROJECT_ID", "").strip() or \
               os.getenv("NEXT_PUBLIC_FIREBASE_PROJECT_ID", "").strip()
    if expected and project_id and expected != project_id:
        logger.error(
            f"[AUTH] Firebase project mismatch: service account belongs to "
            f"'{project_id}' but FIREBASE_PROJECT_ID is '{expected}'. ID tokens "
            "from the frontend will fail to verify."
        )


def _init() -> None:
    """Initialise the Admin SDK once. Never raises — records the error instead."""
    global _app, _db, _init_attempted, _init_error, _source, _project_id

    if _init_attempted:
        return
    _init_attempted = True

    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
    except ImportError:
        _init_error = "firebase-admin is not installed (pip install -r requirements.txt)"
        logger.error(f"[AUTH] {_init_error}")
        return

    cred = None
    tried: list[str] = []

    # 1. Inline JSON — container/secret-manager friendly.
    try:
        inline = _inline_service_account()
    except ValueError as exc:
        _init_error = str(exc)
        logger.error(f"[AUTH] {_init_error}")
        return
    if inline:
        cred = credentials.Certificate(inline)
        _source = f"{_JSON_VAR} (inline JSON)"
        _project_id = inline.get("project_id")
    else:
        tried.append(_JSON_VAR)

    # 2. Path to a JSON key — local development.
    if cred is None:
        path = _credentials_path()
        if path:
            if not os.path.isfile(path):
                _init_error = (
                    f"Service account file not found at {path} "
                    f"(from {' or '.join(_PATH_VARS)})"
                )
                logger.error(f"[AUTH] {_init_error}")
                return
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    _project_id = (json.load(fh) or {}).get("project_id")
            except Exception:
                _project_id = None
            cred = credentials.Certificate(path)
            _source = f"{_PATH_VARS[0]} (file)"
        else:
            tried.append("/".join(_PATH_VARS))

    # 3. Application Default Credentials — automatic on Google Cloud.
    #    Attempted last because on a developer machine it usually resolves to
    #    unrelated gcloud credentials; opt in explicitly to force it.
    if cred is None:
        force_adc = os.getenv(_ADC_OPT_IN, "").strip().lower() in {"1", "true", "yes"}
        on_gcp = bool(os.getenv("K_SERVICE") or os.getenv("GAE_ENV") or os.getenv("GCP_PROJECT"))
        if force_adc or on_gcp:
            try:
                cred = credentials.ApplicationDefault()
                _source = "Application Default Credentials"
                _project_id = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
            except Exception as exc:
                _init_error = f"Application Default Credentials unavailable: {exc}"
                logger.error(f"[AUTH] {_init_error}")
                return
        else:
            tried.append(f"Application Default Credentials (set {_ADC_OPT_IN}=true to force)")

    if cred is None:
        _init_error = (
            "No Firebase service account configured. Provide one of: "
            + "; ".join(tried)
            + ". Generate a key in Firebase Console -> Project Settings -> Service Accounts."
        )
        logger.warning(f"[AUTH] {_init_error}")
        return

    try:
        _app = firebase_admin.initialize_app(cred)
        _db = firestore.client()
        _warn_on_project_mismatch(_project_id)
        logger.info(
            f"[AUTH] Firebase Admin initialised via {_source}"
            + (f" (project: {_project_id})" if _project_id else "")
            + " — request identity is verified"
        )
    except Exception as exc:                      # pragma: no cover - config dependent
        _init_error = f"Failed to initialise Firebase Admin: {type(exc).__name__}: {exc}"
        logger.error(f"[AUTH] {_init_error}")
        _app = None
        _db = None


def is_configured() -> bool:
    """True when tokens can actually be verified and Firestore is reachable."""
    with _lock:
        _init()
    return _app is not None and _db is not None


def init_error() -> Optional[str]:
    with _lock:
        _init()
    return _init_error


def status() -> dict:
    """Non-sensitive diagnostic summary — safe to log or surface to an admin."""
    configured = is_configured()
    return {
        "configured": configured,
        "source":     _source,
        "projectId":  _project_id,
        "error":      None if configured else _init_error,
    }


def db() -> Any:
    """Firestore client. Raises if the SDK is not configured — callers check first."""
    if not is_configured():
        raise RuntimeError(init_error() or "Firebase Admin is not configured")
    return _db


def verify_id_token(token: str) -> dict:
    """
    Verify a Firebase ID token and return its decoded claims.
    Raises on an invalid, expired or forged token.
    """
    if not is_configured():
        raise RuntimeError(init_error() or "Firebase Admin is not configured")
    from firebase_admin import auth as fb_auth

    return fb_auth.verify_id_token(token)
