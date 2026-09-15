from pathlib import Path
from typing import Optional

import joblib
import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    IsolationForest = None
    StandardScaler = None


class AnomalyDetector:
    """
    Wraps scikit-learn's IsolationForest with a scaler, so raw network-flow
    feature vectors can be trained on and scored consistently.
    """

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.02,
        max_samples: str | int = "auto",
        random_state: int = 42,
    ):
        if IsolationForest is not None:
            self.model = IsolationForest(
                n_estimators=n_estimators,
                contamination=contamination,
                max_samples=max_samples,
                random_state=random_state,
                n_jobs=-1,
            )
            self.scaler = StandardScaler()
        else:
            self.model = None
            self.scaler = None
        self._is_fitted = False
        self.metadata = {}

    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns -1 for anomalies, 1 for normal points."""
        self._check_fitted()
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Higher score = more normal; lower/negative = more anomalous."""
        self._check_fitted()
        X_scaled = self.scaler.transform(X)
        return self.model.decision_function(X_scaled)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        self._check_fitted()
        X_scaled = self.scaler.transform(X)
        return self.model.score_samples(X_scaled)

    def _check_fitted(self):
        if not self._is_fitted:
            raise RuntimeError("AnomalyDetector must be fit() before calling predict/score.")

    def save(self, path: str | Path, metadata: Optional[dict] = None) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "metadata": metadata or self.metadata,
            },
            path,
        )

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyDetector":
        payload = joblib.load(path)
        instance = cls()
        instance.model = payload["model"]
        instance.scaler = payload["scaler"]
        instance._is_fitted = True
        instance.metadata = payload.get("metadata", {})
        return instance