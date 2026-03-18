import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from models import create_tables
from api.routes import findings, metrics, pipeline, export
from api.routes.auth import router as auth_router
from api.routes.connectors import router as connectors_router
from api.routes.account import router as account_router
from api.routes.app_settings import router as settings_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _startup_security_checks()
    create_tables()
    yield


app = FastAPI(
    title="Warden",
    description="Open-source vulnerability intelligence platform — KEV-first, multi-scanner, BI-ready",
    version="1.0.0",
    lifespan=lifespan,
    # Disable docs in production — set WARDEN_DOCS_ENABLED=true to re-enable
    docs_url="/docs" if os.getenv("WARDEN_DOCS_ENABLED", "false").lower() == "true" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("WARDEN_DOCS_ENABLED", "false").lower() == "true" else None,
)

# ── CORS ────────────────────────────────────────────────────────────────────────
# Read allowed origins from env so operators can configure without code changes.
# Example: CORS_ORIGINS=https://warden.example.com,https://dashboard.example.com
_raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3001")
_allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth_router)
app.include_router(findings.router, prefix="/api")
app.include_router(metrics.router, prefix="/api")
app.include_router(pipeline.router, prefix="/api")
app.include_router(export.router, prefix="/api")
app.include_router(connectors_router, prefix="/api")
app.include_router(account_router, prefix="/api")
app.include_router(settings_router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok", "app": "warden"}


# ── Startup security checks ─────────────────────────────────────────────────────

_INSECURE_SECRET = "dev-secret-change-in-production-please"
_INSECURE_PASSWORD = "warden-changeme"
_MIN_SECRET_LENGTH = 32


def _startup_security_checks() -> None:
    """
    Validate security-critical configuration at startup.

    In production (WARDEN_ENV=production), insecure defaults are a hard error.
    In development they produce loud warnings so developers notice them.
    """
    env = os.getenv("WARDEN_ENV", "development").lower()
    is_production = env == "production"
    errors: list[str] = []

    secret_key = os.getenv("WARDEN_SECRET_KEY", _INSECURE_SECRET)
    auth_password = os.getenv("AUTH_PASSWORD", _INSECURE_PASSWORD)

    if secret_key == _INSECURE_SECRET:
        msg = (
            "WARDEN_SECRET_KEY is set to the insecure default value. "
            "Generate a strong key with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        )
        errors.append(msg)

    elif len(secret_key) < _MIN_SECRET_LENGTH:
        errors.append(
            f"WARDEN_SECRET_KEY is too short ({len(secret_key)} chars). "
            f"Minimum is {_MIN_SECRET_LENGTH} characters."
        )

    if auth_password == _INSECURE_PASSWORD:
        errors.append(
            "AUTH_PASSWORD is set to the insecure default 'warden-changeme'. "
            "Set a strong password in your .env file."
        )

    if errors:
        for msg in errors:
            if is_production:
                logger.critical("SECURITY ERROR: %s", msg)
            else:
                logger.warning("SECURITY WARNING: %s", msg)

        if is_production:
            raise RuntimeError(
                "Warden cannot start in production with insecure credentials. "
                "Fix the SECURITY ERRORs above before deploying."
            )
