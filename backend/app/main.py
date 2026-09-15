from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import auth, detection, evidence, forecast, health, threats
from app.core.config import settings
from app.database.connection import close_db, init_db
from app.utils.logger import app_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    app_logger.info(f"Starting {settings.APP_NAME} ({settings.APP_ENV})")
    production = settings.APP_ENV.lower() in {"production", "prod", "vercel"} or settings.VERCEL
    if production and (not settings.SECRET_KEY or len(settings.SECRET_KEY) < 32):
        raise RuntimeError("SECRET_KEY must be a strong random value of at least 32 characters in production")
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
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "X-CSRF-Token"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        # Avoid leaking stack traces or internal details to API clients.
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if settings.APP_ENV.lower() in {"production", "prod", "vercel"} or settings.VERCEL:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Auth intentionally lives at /api/auth to keep the required stable public contract.
app.include_router(auth.router, prefix="/api")
app.include_router(health.router, prefix=settings.API_V1_PREFIX)
app.include_router(detection.router, prefix=settings.API_V1_PREFIX)
app.include_router(forecast.router, prefix=settings.API_V1_PREFIX)
app.include_router(threats.router, prefix=settings.API_V1_PREFIX)
app.include_router(evidence.router, prefix=settings.API_V1_PREFIX)


@app.get("/")
async def root():
    return {"app": settings.APP_NAME, "status": "running", "docs": "/docs"}
