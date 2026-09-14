from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import detection, evidence, forecast, health, threats
from app.core.config import settings
from app.database.connection import close_db, init_db
from app.utils.logger import app_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    app_logger.info(f"Starting {settings.APP_NAME} ({settings.APP_ENV})")

    if settings.DEBUG and settings.VERCEL:
        raise RuntimeError("DEBUG must be false on Vercel")

    await init_db()
    try:
        yield
    finally:
        await close_db()


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-powered network threat detection, forecasting, and blockchain-anchored evidence platform.",
    version="1.0.0",
    lifespan=lifespan,
    debug=settings.DEBUG,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix=settings.API_V1_PREFIX)
app.include_router(detection.router, prefix=settings.API_V1_PREFIX)
app.include_router(forecast.router, prefix=settings.API_V1_PREFIX)
app.include_router(threats.router, prefix=settings.API_V1_PREFIX)
app.include_router(evidence.router, prefix=settings.API_V1_PREFIX)


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "status": "running",
        "docs": "/docs",
    }
