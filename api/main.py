from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from models import create_tables
from api.routes import findings, metrics, pipeline, export
from api.routes.auth import router as auth_router
from api.routes.connectors import router as connectors_router
from api.routes.account import router as account_router
from api.routes.app_settings import router as settings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield


app = FastAPI(
    title="Warden",
    description="Open-source vulnerability intelligence platform — KEV-first, multi-scanner, BI-ready",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow the Vite dev server and any same-origin production deployment
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev server
        "http://localhost:3001",   # alternative dev port
        "http://localhost:8000",   # same-origin (production)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
