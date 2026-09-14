from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import detection, evidence, forecast, health, threats
from app.core.config import settings
from app.database.connection import close_db, init_db
from app.services.live_forecast_service import live_forecast_service
from app.utils.logger import app_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    app_logger.info(f"Starting {settings.APP_NAME} ({settings.APP_ENV})")

    if settings.APP_ENV.lower() in {"production", "prod", "vercel"}:
        if not settings.SECRET_KEY or settings.SECRET_KEY == "change_this_to_a_random_secret_key":
            raise RuntimeError("SECRET_KEY must be configured in production")
        if settings.DEBUG:
            raise RuntimeError("DEBUG must be false in production")

    # init_db is a no-op for production/Vercel. Use Alembic for schema management.
    await init_db()
    try:
        yield
    finally:
        # Do not rely on background work surviving a serverless invocation.
        live_forecast_service.shutdown()
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
