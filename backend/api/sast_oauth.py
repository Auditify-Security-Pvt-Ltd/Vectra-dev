"""
SAST OAuth Integration — GitHub and GitLab repository access.

Configure in backend/.env:
  GITHUB_CLIENT_ID=...
  GITHUB_CLIENT_SECRET=...
  GITLAB_CLIENT_ID=...
  GITLAB_CLIENT_SECRET=...
  FRONTEND_URL=http://localhost:3000        (where the React app runs)
  BACKEND_URL=http://localhost:8000         (where FastAPI runs)

OAuth flow:
  1. Frontend calls GET /sast/oauth/{provider}/authorize?userId=<uid>
     → Returns { url: "<provider OAuth URL>" }

  2. User is redirected to GitHub/GitLab; after approval the provider
     redirects to GET /sast/oauth/{provider}/callback?code=<code>&state=<state>

  3. Backend exchanges code for token, stores it keyed by userId, then
     redirects to FRONTEND_URL/app/sast/oauth/callback?provider=...&success=true

  4. Frontend popup page posts a message to the opener and closes.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse

from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/sast/oauth", tags=["SAST OAuth"])

# ── Environment ───────────────────────────────────────────────────────

_GH_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID",     "")
_GH_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
_GL_CLIENT_ID     = os.getenv("GITLAB_CLIENT_ID",     "")
_GL_CLIENT_SECRET = os.getenv("GITLAB_CLIENT_SECRET", "")
_FRONTEND_URL     = os.getenv("FRONTEND_URL",          "http://localhost:3000").rstrip("/")
_BACKEND_URL      = os.getenv("BACKEND_URL",           "http://localhost:8000").rstrip("/")

# ── In-memory token store (keyed "provider:userId") ───────────────────
# In production this should be an encrypted database column.
_TOKENS: Dict[str, str] = {}

# ── Public helpers (used by sast_scans.py) ────────────────────────────

def get_oauth_token(provider: str, user_id: str) -> Optional[str]:
    """Return stored access token or None."""
    return _TOKENS.get(f"{provider}:{user_id}")


def is_configured(provider: str) -> bool:
    if provider == "github":
        return bool(_GH_CLIENT_ID and _GH_CLIENT_SECRET)
    if provider == "gitlab":
        return bool(_GL_CLIENT_ID and _GL_CLIENT_SECRET)
    return False


async def download_repo_zip(
    provider: str,
    token: str,
    owner: str,
    repo: str,
    branch: str,
) -> bytes:
    """Download repository archive as ZIP bytes."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=300.0) as client:
        if provider == "github":
            url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Vectra-SAST/1.0",
            }
        else:
            encoded_path = urllib.parse.quote(f"{owner}/{repo}", safe="")
            url = (
                f"https://gitlab.com/api/v4/projects/{encoded_path}"
                f"/repository/archive.zip?sha={branch}"
            )
            headers = {"Authorization": f"Bearer {token}"}

        resp = await client.get(url, headers=headers)
        if resp.status_code == 401:
            raise RuntimeError("Access token expired or revoked. Please reconnect your account.")
        if resp.status_code == 404:
            raise RuntimeError(f"Repository {owner}/{repo}@{branch} not found or access denied.")
        resp.raise_for_status()
        return resp.content


async def get_repo_commit(
    provider: str,
    token: str,
    owner: str,
    repo: str,
    branch: str,
) -> dict:
    """Return {sha, message, author, date} for the tip commit of branch."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        if provider == "github":
            url = f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}"
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Vectra-SAST/1.0",
            }
            resp = await client.get(url, headers=headers)
            if not resp.is_success:
                return {}
            d = resp.json()
            return {
                "sha":     d.get("sha", "")[:12],
                "message": d.get("commit", {}).get("message", "").split("\n")[0][:100],
                "author":  d.get("commit", {}).get("author", {}).get("name", ""),
                "date":    d.get("commit", {}).get("author", {}).get("date", ""),
            }
        else:
            encoded_path = urllib.parse.quote(f"{owner}/{repo}", safe="")
            url = (
                f"https://gitlab.com/api/v4/projects/{encoded_path}"
                f"/repository/commits/{branch}"
            )
            headers = {"Authorization": f"Bearer {token}"}
            resp = await client.get(url, headers=headers)
            if not resp.is_success:
                return {}
            d = resp.json()
            return {
                "sha":     d.get("id", "")[:12],
                "message": d.get("title", "")[:100],
                "author":  d.get("author_name", ""),
                "date":    d.get("authored_date", ""),
            }


# ── State encoding (userId in OAuth state param) ──────────────────────

def _encode_state(user_id: str, provider: str) -> str:
    data = json.dumps({"uid": user_id, "p": provider, "ts": int(time.time())})
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def _decode_state(state: str) -> dict:
    try:
        padded = state + "=" * (4 - len(state) % 4)
        data   = base64.urlsafe_b64decode(padded.encode())
        return json.loads(data)
    except Exception:
        return {}


# ── Internal: exchange code for token ────────────────────────────────

async def _github_exchange(code: str) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id":     _GH_CLIENT_ID,
                "client_secret": _GH_CLIENT_SECRET,
                "code":          code,
            },
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        if "access_token" not in data:
            raise RuntimeError(data.get("error_description", "Token exchange failed"))
        return data["access_token"]


async def _gitlab_exchange(code: str, redirect_uri: str) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            "https://gitlab.com/oauth/token",
            data={
                "client_id":     _GL_CLIENT_ID,
                "client_secret": _GL_CLIENT_SECRET,
                "code":          code,
                "grant_type":    "authorization_code",
                "redirect_uri":  redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        if "access_token" not in data:
            raise RuntimeError("GitLab token exchange failed")
        return data["access_token"]


async def _github_user(token: str) -> dict:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Vectra-SAST/1.0",
            },
        )
        resp.raise_for_status()
        d = resp.json()
        return {
            "login":      d.get("login", ""),
            "name":       d.get("name") or d.get("login", ""),
            "avatar_url": d.get("avatar_url", ""),
        }


async def _gitlab_user(token: str) -> dict:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            "https://gitlab.com/api/v4/user",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        d = resp.json()
        return {
            "login":      d.get("username", ""),
            "name":       d.get("name", ""),
            "avatar_url": d.get("avatar_url", ""),
        }


# ── Routes ────────────────────────────────────────────────────────────

@router.get("/{provider}/authorize")
async def authorize(provider: str, userId: str = Query(...)) -> dict:
    """Return the OAuth authorization URL for the provider."""
    if provider not in ("github", "gitlab"):
        raise HTTPException(400, f"Unknown provider: {provider}")

    if not is_configured(provider):
        return {
            "configured": False,
            "error": "not_configured",
            "message": (
                f"Set {provider.upper()}_CLIENT_ID and "
                f"{provider.upper()}_CLIENT_SECRET in backend/.env"
            ),
        }

    state        = _encode_state(userId, provider)
    redirect_uri = f"{_BACKEND_URL}/sast/oauth/{provider}/callback"

    if provider == "github":
        params = urllib.parse.urlencode({
            "client_id":    _GH_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "scope":        "repo read:user",
            "state":        state,
        })
        url = f"https://github.com/login/oauth/authorize?{params}"
    else:
        params = urllib.parse.urlencode({
            "client_id":     _GL_CLIENT_ID,
            "redirect_uri":  redirect_uri,
            "response_type": "code",
            "scope":         "read_api read_repository",
            "state":         state,
        })
        url = f"https://gitlab.com/oauth/authorize?{params}"

    return {"configured": True, "url": url}


@router.get("/{provider}/callback")
async def callback(
    provider: str,
    code:  str  = Query(""),
    state: str  = Query(""),
    error: str  = Query(""),
) -> RedirectResponse:
    """
    OAuth callback — called by GitHub/GitLab after user approves.
    Exchanges the code for a token, stores it, redirects to the frontend.
    """
    frontend_cb = f"{_FRONTEND_URL}/app/sast/oauth/callback"

    if error:
        logger.warning(f"[OAuthCB] Provider denied access: {error}")
        return RedirectResponse(f"{frontend_cb}?provider={provider}&success=false&error={error}")

    state_data = _decode_state(state)
    user_id    = state_data.get("uid", "")
    if not user_id:
        return RedirectResponse(f"{frontend_cb}?provider={provider}&success=false&error=invalid_state")

    redirect_uri = f"{_BACKEND_URL}/sast/oauth/{provider}/callback"

    try:
        if provider == "github":
            token = await _github_exchange(code)
        elif provider == "gitlab":
            token = await _gitlab_exchange(code, redirect_uri)
        else:
            return RedirectResponse(f"{frontend_cb}?provider={provider}&success=false&error=unknown_provider")

        _TOKENS[f"{provider}:{user_id}"] = token
        logger.info(f"[OAuth] {provider} token stored for user {user_id}")
        return RedirectResponse(f"{frontend_cb}?provider={provider}&success=true")

    except Exception as exc:
        logger.error(f"[OAuthCB] Token exchange failed: {exc}")
        return RedirectResponse(
            f"{frontend_cb}?provider={provider}&success=false&error={urllib.parse.quote(str(exc))}"
        )


@router.get("/{provider}/status")
async def status(provider: str, userId: str = Query(...)) -> dict:
    """Return connection status and connected user info."""
    if not is_configured(provider):
        return {"configured": False, "connected": False}

    token = get_oauth_token(provider, userId)
    if not token:
        return {"configured": True, "connected": False}

    try:
        if provider == "github":
            user_info = await _github_user(token)
        else:
            user_info = await _gitlab_user(token)
        return {"configured": True, "connected": True, "user": user_info}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            _TOKENS.pop(f"{provider}:{userId}", None)
            return {"configured": True, "connected": False, "expired": True}
        return {"configured": True, "connected": False}
    except Exception:
        return {"configured": True, "connected": False}


@router.get("/{provider}/repos")
async def list_repos(
    provider: str,
    userId: str  = Query(...),
    search: str  = Query(""),
    page:   int  = Query(1),
) -> dict:
    """Return repository list for the connected user."""
    token = get_oauth_token(provider, userId)
    if not token:
        raise HTTPException(401, "Not connected. Authorize first.")

    try:
        repos = await _fetch_repos(provider, token, search, page)
        return {"repos": repos, "total": len(repos)}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            _TOKENS.pop(f"{provider}:{userId}", None)
            raise HTTPException(401, "Token expired. Please reconnect.")
        raise HTTPException(500, f"Failed to fetch repositories: {e}")
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.get("/{provider}/repos/{owner}/{repo}/branches")
async def list_branches(
    provider: str,
    owner:    str,
    repo:     str,
    userId:   str = Query(...),
) -> dict:
    """Return branches for the given repository."""
    token = get_oauth_token(provider, userId)
    if not token:
        raise HTTPException(401, "Not connected.")

    try:
        branches     = await _fetch_branches(provider, token, owner, repo)
        default_name = await _get_default_branch(provider, token, owner, repo)
        return {"branches": branches, "default": default_name}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.delete("/{provider}/disconnect")
async def disconnect(provider: str, userId: str = Query(...)) -> dict:
    """Remove stored OAuth token."""
    _TOKENS.pop(f"{provider}:{userId}", None)
    logger.info(f"[OAuth] Disconnected {provider} for user {userId}")
    return {"success": True}


# ── Internal fetch helpers ────────────────────────────────────────────

async def _fetch_repos(
    provider: str,
    token:    str,
    search:   str = "",
    page:     int = 1,
) -> List[dict]:
    per_page = 50
    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        if provider == "github":
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Vectra-SAST/1.0",
            }
            if search.strip():
                # Use search API — need username first
                user_resp = await client.get("https://api.github.com/user", headers=headers)
                login = user_resp.json().get("login", "") if user_resp.is_success else ""
                q = urllib.parse.quote(f"{search} user:{login}" if login else search)
                resp = await client.get(
                    f"https://api.github.com/search/repositories?q={q}&sort=updated&per_page={per_page}",
                    headers=headers,
                )
                resp.raise_for_status()
                items = resp.json().get("items", [])
            else:
                resp = await client.get(
                    f"https://api.github.com/user/repos?type=all&sort=updated&direction=desc&per_page={per_page}&page={page}",
                    headers=headers,
                )
                resp.raise_for_status()
                items = resp.json()

            return [
                {
                    "id":              r["id"],
                    "name":            r["name"],
                    "fullName":        r["full_name"],
                    "owner":           r["owner"]["login"],
                    "description":     r.get("description") or "",
                    "visibility":      "private" if r.get("private") else "public",
                    "defaultBranch":   r.get("default_branch", "main"),
                    "language":        r.get("language") or "",
                    "updatedAt":       r.get("updated_at", ""),
                    "stargazersCount": r.get("stargazers_count", 0),
                    "url":             r.get("html_url", ""),
                }
                for r in items
            ]

        else:  # gitlab
            headers = {"Authorization": f"Bearer {token}"}
            params: dict = {
                "membership": "true",
                "per_page":   str(per_page),
                "page":       str(page),
                "order_by":   "last_activity_at",
            }
            if search.strip():
                params["search"] = search

            resp = await client.get(
                "https://gitlab.com/api/v4/projects",
                headers=headers,
                params=params,
            )
            resp.raise_for_status()
            items = resp.json()

            return [
                {
                    "id":            r["id"],
                    "name":          r["path"],
                    "fullName":      r["path_with_namespace"],
                    "owner":         r.get("namespace", {}).get("path", ""),
                    "description":   r.get("description") or "",
                    "visibility":    r.get("visibility", "private"),
                    "defaultBranch": r.get("default_branch", "main"),
                    "language":      "",
                    "updatedAt":     r.get("last_activity_at", ""),
                    "stargazersCount": r.get("star_count", 0),
                    "url":           r.get("web_url", ""),
                }
                for r in items
            ]


async def _fetch_branches(
    provider: str,
    token:    str,
    owner:    str,
    repo:     str,
) -> List[str]:
    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
        if provider == "github":
            resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/branches?per_page=100",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "Vectra-SAST/1.0",
                },
            )
            resp.raise_for_status()
            return [b["name"] for b in resp.json()]
        else:
            encoded = urllib.parse.quote(f"{owner}/{repo}", safe="")
            resp = await client.get(
                f"https://gitlab.com/api/v4/projects/{encoded}/repository/branches?per_page=100",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return [b["name"] for b in resp.json()]


async def _get_default_branch(
    provider: str,
    token:    str,
    owner:    str,
    repo:     str,
) -> str:
    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        if provider == "github":
            resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "Vectra-SAST/1.0",
                },
            )
            if resp.is_success:
                return resp.json().get("default_branch", "main")
        else:
            encoded = urllib.parse.quote(f"{owner}/{repo}", safe="")
            resp = await client.get(
                f"https://gitlab.com/api/v4/projects/{encoded}",
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.is_success:
                return resp.json().get("default_branch", "main")
    return "main"
