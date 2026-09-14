import sys
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sqlalchemy.ext.asyncio import AsyncSession

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.core.constants import DEFAULT_ANOMALY_CONTAMINATION
from app.database.repositories.anomaly_repository import AnomalyRepository
from app.models.anomaly import Anomaly
from app.utils.helpers import utc_now
from app.utils.logger import app_logger
from ml_engine.anomaly_detection.isolation_forest import AnomalyDetector


class DetectionService:
    """Wraps the Isolation Forest anomaly model for inference and persistence."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = AnomalyRepository(session)
        self._model = None

    def _load_model(self):
        if self._model is None:
            try:
                self._model = AnomalyDetector.load(settings.ANOMALY_MODEL_PATH)
                app_logger.info(f"Loaded anomaly model from {settings.ANOMALY_MODEL_PATH}")
            except FileNotFoundError:
                app_logger.warning(
                    f"Anomaly model not found at {settings.ANOMALY_MODEL_PATH}, "
                    "using an untrained fallback (all scores = 0)."
                )
                self._model = None
        return self._model

    def score_features(self, feature_vector: list[float]) -> tuple[float, bool]:
        """Run inference on a single feature vector. Returns (score, is_anomalous)."""
        model = self._load_model()
        if model is None:
            return 0.0, False

        metadata = getattr(model, "metadata", {})
        feature_names = metadata.get("feature_names")
        if feature_names is not None and len(feature_vector) != len(feature_names):
            raise ValueError(
                f"Anomaly feature dimension mismatch: expected {len(feature_names)}, "
                f"received {len(feature_vector)}"
            )

        aligned_vector = np.asarray(feature_vector, dtype=np.float32).copy()
        for feature_name, value in metadata.get("constant_features", {}).items():
            if feature_name not in (feature_names or []):
                raise ValueError(
                    f"Anomaly metadata references unknown feature '{feature_name}'"
                )
            aligned_vector[feature_names.index(feature_name)] = float(value)

        X = aligned_vector.reshape(1, -1)
        raw_score = model.decision_function(X)[0]  # higher = more normal
        prediction = model.predict(X)[0]  # -1 = anomaly, 1 = normal

        # Normalize decision_function output roughly into [-1, 1]
        score = float(np.clip(raw_score, -1.0, 1.0))
        is_anomalous = bool(prediction == -1)

        return score, is_anomalous

    async def detect_and_store(
        self,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        feature_vector: list[float],
        raw_features: Optional[dict] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> Anomaly:
        """Score a flow's features and persist the anomaly record."""
        score, is_anomalous = self.score_features(feature_vector)

        anomaly = Anomaly(
            flow_id=flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            anomaly_score=score,
            is_anomalous=is_anomalous,
            raw_features=raw_features,
            detected_at=utc_now(),
        )
        created = await self.repo.create(anomaly)

        if is_anomalous:
            app_logger.info(f"Anomaly detected: flow={flow_id} score={score:.4f}")

        return created

    async def batch_detect_and_store(
        self, flows: list[dict]
    ) -> list[Anomaly]:
        """
        Batch scoring for pipeline use.
        Each item in `flows` is expected to have: flow_id, src_ip, dst_ip,
        feature_vector, raw_features, src_port, dst_port, protocol.
        """
        anomalies = []
        for flow in flows:
            score, is_anomalous = self.score_features(flow["feature_vector"])
            anomalies.append(
                Anomaly(
                    flow_id=flow["flow_id"],
                    src_ip=flow["src_ip"],
                    dst_ip=flow["dst_ip"],
                    src_port=flow.get("src_port"),
                    dst_port=flow.get("dst_port"),
                    protocol=flow.get("protocol"),
                    anomaly_score=score,
                    is_anomalous=is_anomalous,
                    raw_features=flow.get("raw_features"),
                    detected_at=utc_now(),
                )
            )
        return await self.repo.bulk_create(anomalies)

    async def get_anomaly(self, anomaly_id: str) -> Optional[Anomaly]:
        return await self.repo.get_by_id(anomaly_id)

    async def list_anomalies(self, **filters):
        return await self.repo.list(**filters)

    async def update_status(self, anomaly_id: str, status: str, notes: Optional[str] = None):
        anomaly = await self.repo.get_by_id(anomaly_id)
        if anomaly is None:
            return None
        return await self.repo.update(anomaly, status=status, analyst_notes=notes)