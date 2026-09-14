import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from isolation_forest import AnomalyDetector

DEFAULT_FEATURES_PATH = "data/processed/features/network_features.csv"
DEFAULT_MODEL_OUTPUT = "ml-engine/saved_models/anomaly_model.pkl"


def load_features(path: str) -> tuple[np.ndarray, list[str]]:
    df = pd.read_csv(path)
    feature_cols = [c for c in df.columns if c not in ("flow_id", "src_ip", "dst_ip", "label")]
    return df[feature_cols].to_numpy(dtype=np.float32), feature_cols


def main():
    parser = argparse.ArgumentParser(description="Train the Isolation Forest anomaly detector.")
    parser.add_argument("--features", default=DEFAULT_FEATURES_PATH)
    parser.add_argument("--output", default=DEFAULT_MODEL_OUTPUT)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--contamination", type=float, default=0.02)
    args = parser.parse_args()

    print(f"Loading features from {args.features} ...")
    X, feature_names = load_features(args.features)
    print(f"Loaded {X.shape[0]} samples with {X.shape[1]} features: {feature_names}")

    detector = AnomalyDetector(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
    )
    detector.fit(X)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    detector.save(args.output)
    print(f"Model saved to {args.output}")

    scores = detector.decision_function(X)
    predictions = detector.predict(X)
    n_anomalies = int((predictions == -1).sum())
    print(f"Training summary: {n_anomalies}/{len(X)} flagged as anomalous "
          f"(score range [{scores.min():.3f}, {scores.max():.3f}])")


if __name__ == "__main__":
    main()