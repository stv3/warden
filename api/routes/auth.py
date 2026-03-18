"""
Auth router — JWT-based authentication.

Credentials are read exclusively from environment variables. There are no
hardcoded defaults that would be safe to use — the startup security check
in api/main.py warns loudly (or blocks) if insecure values are detected.

  WARDEN_SECRET_KEY  — JWT signing key (min 32 chars, generate with secrets.token_hex(32))
  AUTH_USERNAME      — Login username (default: admin)
  AUTH_PASSWORD      — Login password (no safe default — set this before deploying)
  AUTH_TOKEN_EXPIRE_MINUTES — Token lifetime in minutes (default: 480 / 8 hours)
  AUTH_MAX_ATTEMPTS  — Failed login attempts before lockout (default: 10)
"""
import hmac
import os
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["auth"])

# ── Config ─────────────────────────────────────────────────────────────────────

SECRET_KEY = os.getenv("WARDEN_SECRET_KEY", "dev-secret-change-in-production-please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("AUTH_TOKEN_EXPIRE_MINUTES", "480"))

AUTH_USERNAME = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "warden-changeme")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# ── Brute-force protection ─────────────────────────────────────────────────────
# Per-IP attempt tracking in process memory.
# NOTE: This is effective for single-container deployments. For multi-worker
# or multi-replica production deployments, move this state to Redis so all
# instances share the same counters.

_lock = threading.Lock()
_attempts: dict[str, list[float]] = defaultdict(list)

_MAX_ATTEMPTS = int(os.getenv("AUTH_MAX_ATTEMPTS", "10"))
_WINDOW_SECONDS = 300   # 5-minute sliding window
_LOCKOUT_SECONDS = 900  # 15-minute lockout after exceeding limit


def _check_rate_limit(ip: str) -> None:
    now = time.time()
    with _lock:
        _attempts[ip] = [t for t in _attempts[ip] if now - t < _WINDOW_SECONDS]
        if len(_attempts[ip]) >= _MAX_ATTEMPTS:
            oldest = _attempts[ip][0]
            wait = int(_LOCKOUT_SECONDS - (now - oldest))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Try again in {wait} seconds.",
            )


def _record_attempt(ip: str) -> None:
    with _lock:
        _attempts[ip].append(time.time())


def _clear_attempts(ip: str) -> None:
    with _lock:
        _attempts.pop(ip, None)


# ── Schemas ────────────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    token_type: str


class UserInfo(BaseModel):
    username: str
    role: str


# ── Helpers ────────────────────────────────────────────────────────────────────

def _verify_credentials(username: str, password: str) -> bool:
    """Constant-time comparison to prevent timing-based credential enumeration."""
    username_ok = hmac.compare_digest(username.encode(), AUTH_USERNAME.encode())
    password_ok = hmac.compare_digest(password.encode(), AUTH_PASSWORD.encode())
    return username_ok and password_ok


def _create_access_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


# ── Dependency: get current user ───────────────────────────────────────────────

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/token", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    if not _verify_credentials(form_data.username, form_data.password):
        _record_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _clear_attempts(client_ip)
    return Token(access_token=_create_access_token(form_data.username), token_type="bearer")


@router.get("/me", response_model=UserInfo)
async def me(current_user: str = Depends(get_current_user)):
    return UserInfo(username=current_user, role="admin")
