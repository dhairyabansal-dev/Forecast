import argparse
import json

import numpy as np
import pandas as pd

from isolation_forest import AnomalyDetector

DEFAULT_MODEL_PATH = "ml-engine/saved_models/anomaly_model.pkl"


def predict_from_csv(model_path: str, features_csv: str) -> pd.DataFrame:
    detector = AnomalyDetector.load(model_path)
    df = pd.read_csv(features_csv)

    meta_cols = [c for c in ("flow_id", "src_ip", "dst_ip") if c in df.columns]
    feature_cols = [c for c in df.columns if c not in meta_cols + ["label"]]

    X = df[feature_cols].to_numpy(dtype=np.float32)
    scores = detector.decision_function(X)
    predictions = detector.predict(X)

    result = df[meta_cols].copy() if meta_cols else pd.DataFrame(index=df.index)
    result["anomaly_score"] = scores
    result["is_anomalous"] = predictions == -1
    return result


def predict_single(model_path: str, feature_vector: list[float]) -> dict:
    detector = AnomalyDetector.load(model_path)
    X = np.array(feature_vector, dtype=np.float32).reshape(1, -1)
    score = float(detector.decision_function(X)[0])
    is_anomalous = bool(detector.predict(X)[0] == -1)
    return {"anomaly_score": score, "is_anomalous": is_anomalous}


def main():
    parser = argparse.ArgumentParser(description="Run anomaly predictions on a features CSV.")
    parser.add_argument("--model", default=DEFAULT_MODEL_PATH)
    parser.add_argument("--features", required=True, help="Path to CSV of feature rows")
    parser.add_argument("--output", default=None, help="Optional path to save results CSV")
    args = parser.parse_args()

    result = predict_from_csv(args.model, args.features)

    if args.output:
        result.to_csv(args.output, index=False)
        print(f"Results saved to {args.output}")
    else:
        print(result.to_string(index=False))

    print(json.dumps({
        "total": len(result),
        "anomalies": int(result["is_anomalous"].sum()),
    }, indent=2))


if __name__ == "__main__":
    main()