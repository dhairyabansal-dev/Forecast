from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    APP_NAME: str = "NetworkThreatForecast"
    APP_ENV: str = "development"
    DEBUG: bool = False
    VERCEL: bool = False

    API_V1_PREFIX: str = "/api/v1"
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    DATABASE_URL: str = ""

    # Supabase
    SUPABASE_URL: str = ""
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""

    ANOMALY_MODEL_PATH: str = str(PROJECT_ROOT / "ml_engine" / "saved_models" / "anomaly_model.pkl")
    TEMPORAL_MODEL_PATH: str = str(PROJECT_ROOT / "ml_engine" / "saved_models" / "temporal_model.pt")
    WORLD_MODEL_PATH: str = str(PROJECT_ROOT / "models" / "network_world_model.pth")
    FORECAST_HORIZON: int = 24
    SEQUENCE_LENGTH: int = 48

    BLOCKCHAIN_PROVIDER_URL: str = "http://localhost:8545"
    BLOCKCHAIN_CHAIN_ID: int = 1337
    BLOCKCHAIN_PRIVATE_KEY: str = ""
    THREAT_EVIDENCE_CONTRACT_ADDRESS: str = ""

    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/app.log"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
