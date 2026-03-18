"""
Account management API.

GET  /api/account/me          — current user info + session details
POST /api/account/password    — change password (writes to .env, reloads live)
GET  /api/account/token-info  — show token expiry and config
"""
import hmac
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, Request
from jose import jwt, JWTError
from pydantic import BaseModel

from api.routes.auth import (
    get_current_user,
    _create_access_token,
    _check_rate_limit,
    SECRET_KEY,
    ALGORITHM,
    AUTH_USERNAME,
    AUTH_PASSWORD,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    oauth2_scheme,
)

router = APIRouter(prefix="/account", tags=["account"])

ENV_FILE = Path(".env")


def _read_env() -> dict[str, str]:
    result: dict[str, str] = {}
    if not ENV_FILE.exists():
        return result
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip()
    return result


def _write_env_key(key: str, value: str) -> None:
    """Update a single key in .env, preserving all other lines."""
    lines: list[str] = []
    updated = False

    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            stripped = line.strip()
            if "=" in stripped and not stripped.startswith("#"):
                k = stripped.partition("=")[0].strip()
                if k == key:
                    lines.append(f"{key}={value}")
                    updated = True
                    continue
            lines.append(line)

    if not updated:
        lines.append(f"{key}={value}")

    ENV_FILE.write_text("\n".join(lines) + "\n")


# ── Schemas ────────────────────────────────────────────────────────────────────

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ChangePasswordResponse(BaseModel):
    success: bool
    message: str


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/me")
def get_me(
    request: Request,
    current_user: str = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
):
    """Return current user info, token expiry, and session metadata."""
    token_exp = None
    token_iat = None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp_ts = payload.get("exp")
        iat_ts = payload.get("iat")
        if exp_ts:
            token_exp = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
        if iat_ts:
            token_iat = datetime.fromtimestamp(iat_ts, tz=timezone.utc).isoformat()
    except JWTError:
        pass

    return {
        "username": current_user,
        "role": "admin",
        "token_expires_at": token_exp,
        "token_issued_at": token_iat,
        "token_lifetime_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
        "session_ip": request.client.host if request.client else None,
    }


@router.post("/password", response_model=ChangePasswordResponse)
def change_password(
    request: Request,
    body: ChangePasswordRequest,
    current_user: str = Depends(get_current_user),
):
    """Change the admin password. Writes the new value to .env."""
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    if len(body.new_password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 12 characters",
        )

    # Verify the current password
    if not hmac.compare_digest(body.current_password.encode(), AUTH_PASSWORD.encode()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Current password is incorrect",
        )

    # Write new password to .env
    _write_env_key("AUTH_PASSWORD", body.new_password)

    # Patch the live setting so subsequent logins work immediately
    import api.routes.auth as auth_module
    auth_module.AUTH_PASSWORD = body.new_password

    return ChangePasswordResponse(
        success=True,
        message="Password updated. All existing sessions remain valid until they expire.",
    )


@router.get("/token-info")
def token_info(
    current_user: str = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
):
    """Return raw token claims and configuration details (no sensitive data)."""
    claims: dict = {}
    try:
        claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        pass

    exp_ts = claims.get("exp", 0)
    seconds_remaining = max(0, int(exp_ts - time.time()))

    return {
        "algorithm": ALGORITHM,
        "token_lifetime_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
        "expires_at": datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat() if exp_ts else None,
        "seconds_remaining": seconds_remaining,
        "minutes_remaining": round(seconds_remaining / 60, 1),
    }
