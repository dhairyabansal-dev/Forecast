from datetime import timedelta
from typing import Optional

import numpy as np
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.constants import ForecastConfidence
from app.database.repositories.forecast_repository import ForecastRepository
from app.models.forecast import Forecast
from app.utils.helpers import utc_now
from app.utils.logger import app_logger


class ForecastService:
    """Threat forecasting service with an optional local PyTorch model and a Vercel-safe fallback."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ForecastRepository(session)
        self._model = None
        self._torch_available = None

    def _load_model(self):
        if self._model is not None or self._torch_available is False:
            return self._model

        try:
            import torch
        except ImportError:
            self._torch_available = False
            app_logger.info("PyTorch is not installed in this runtime; using the numerical forecast fallback.")
            return None

        try:
            self._model = torch.load(
                settings.TEMPORAL_MODEL_PATH,
                map_location="cpu",
                weights_only=False,
            )
            self._model.eval()
            self._torch_available = True
            app_logger.info(f"Loaded temporal model from {settings.TEMPORAL_MODEL_PATH}")
        except (FileNotFoundError, RuntimeError, ValueError, TypeError) as exc:
            self._torch_available = True
            app_logger.warning(
                f"Temporal model unavailable ({exc}); forecasts will use the numerical fallback."
            )
            self._model = None
        return self._model

    def _naive_forecast(self, horizon_hours: int) -> np.ndarray:
        """Stable bounded baseline used when no trained temporal model is available."""
        return np.full(horizon_hours, 0.1, dtype=np.float32)

    def _run_inference(self, sequence: np.ndarray, horizon_hours: int) -> np.ndarray:
        model = self._load_model()
        if model is None:
            return self._naive_forecast(horizon_hours)

        import torch

        with torch.no_grad():
            x = torch.tensor(sequence, dtype=torch.float32).unsqueeze(0)
            preds = model(x, horizon=horizon_hours)
            preds = preds.squeeze(0).clamp(0.0, 1.0).numpy()
        return preds

    def _confidence_from_spread(self, lower: np.ndarray, upper: np.ndarray) -> ForecastConfidence:
        avg_spread = float(np.mean(upper - lower))
        if avg_spread < 0.1:
            return ForecastConfidence.HIGH
        if avg_spread < 0.25:
            return ForecastConfidence.MEDIUM
        return ForecastConfidence.LOW

    async def generate_forecast(
        self,
        historical_sequence: np.ndarray,
        network_segment: Optional[str] = None,
        horizon_hours: int = 24,
        sequence_length: int = 48,
    ) -> Forecast:
        predictions = self._run_inference(historical_sequence, horizon_hours)

        uncertainty = np.clip(0.05 + 0.01 * np.arange(horizon_hours), 0, 0.3)
        lower = np.clip(predictions - uncertainty, 0, 1)
        upper = np.clip(predictions + uncertainty, 0, 1)

        now = utc_now()
        points = []
        for i in range(horizon_hours):
            points.append({
                "timestamp": (now + timedelta(hours=i + 1)).isoformat(),
                "predicted_threat_level": float(predictions[i]),
                "lower_bound": float(lower[i]),
                "upper_bound": float(upper[i]),
            })

        peak_idx = int(np.argmax(predictions))
        model_version = "v1-temporal" if self._model is not None else "v1-vercel-fallback"

        forecast = Forecast(
            network_segment=network_segment,
            horizon_hours=horizon_hours,
            sequence_length=sequence_length,
            confidence=self._confidence_from_spread(lower, upper).value,
            model_version=model_version,
            points=points,
            peak_threat_level=float(predictions[peak_idx]),
            peak_timestamp=now + timedelta(hours=peak_idx + 1),
            generated_at=now,
        )
        return await self.repo.create(forecast)

    async def get_forecast(self, forecast_id: str) -> Optional[Forecast]:
        return await self.repo.get_by_id(forecast_id)

    async def get_latest_forecast(self, network_segment: Optional[str] = None) -> Optional[Forecast]:
        return await self.repo.get_latest(network_segment)

    async def list_forecasts(self, **filters):
        return await self.repo.list(**filters)
