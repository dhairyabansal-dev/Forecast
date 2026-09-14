from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from ml_engine.anomaly_detection.cic_feature_adapter import cic_dataframe_to_live_features
from ml_engine.anomaly_detection.isolation_forest import AnomalyDetector
from network_engine.feature_extractor import FeatureExtractor


DEFAULT_OUTPUT = ROOT_DIR / "ml_engine" / "saved_models" / "anomaly_model.pkl"


def discover_csv_files(data: str | Path, max_files: int | None) -> list[Path]:
    path = Path(data)
    if path.is_file() and path.suffix.lower() == ".csv":
        files = [path]
    elif path.is_dir():
        files = sorted(path.rglob("*.csv"))
    else:
        raise FileNotFoundError(f"Dataset path does not exist: {path}")

    if max_files is not None:
        files = files[:max_files]
    if not files:
        raise FileNotFoundError(f"No CSV files found in: {path}")
    return files


def load_training_features(
    files: list[Path],
    max_rows_per_file: int | None,
    chunksize: int,
) -> np.ndarray:
    chunks: list[np.ndarray] = []
    total_rows = 0

    for csv_file in files:
        print(f"Loading: {csv_file}")
        file_rows = 0
        reader = pd.read_csv(
            csv_file,
            low_memory=False,
            chunksize=chunksize,
            nrows=max_rows_per_file,
        )
        for dataframe in reader:
            features = cic_dataframe_to_live_features(dataframe)
            if features.shape[1] != len(FeatureExtractor.FEATURE_NAMES):
                raise ValueError(
                    f"Feature alignment produced {features.shape[1]} columns; "
                    f"expected {len(FeatureExtractor.FEATURE_NAMES)}"
                )
            chunks.append(features)
            file_rows += len(features)
            total_rows += len(features)
        print(f"Loaded {file_rows:,} usable rows from {csv_file.name}")

    if not chunks:
        raise RuntimeError("No usable training rows were loaded")
    matrix = np.concatenate(chunks, axis=0).astype(np.float32, copy=False)
    matrix = np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)
    if matrix.ndim != 2 or matrix.shape[1] != len(FeatureExtractor.FEATURE_NAMES):
        raise ValueError(f"Training matrix has incompatible shape: {matrix.shape}")
    print(f"Total training rows: {total_rows:,}")
    return matrix


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the live-compatible Isolation Forest anomaly model")
    parser.add_argument("--data", required=True, help="CSE-CIC-IDS2018 CSV file or directory")
    parser.add_argument("--max-rows-per-file", type=int, default=None)
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--chunksize", type=int, default=50_000)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not 0 < args.contamination <= 0.5:
        raise ValueError("contamination must be greater than 0 and at most 0.5")
    if args.max_rows_per_file is not None and args.max_rows_per_file < 1:
        raise ValueError("max-rows-per-file must be positive")
    if args.max_files is not None and args.max_files < 1:
        raise ValueError("max-files must be positive")
    if args.chunksize < 1 or args.n_estimators < 1:
        raise ValueError("chunksize and n-estimators must be positive")

    files = discover_csv_files(args.data, args.max_files)
    features = load_training_features(files, args.max_rows_per_file, args.chunksize)

    detector = AnomalyDetector(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=args.random_state,
    )
    detector.fit(features)

    metadata = {
        "model_type": "IsolationForest",
        "training_dataset": str(Path(args.data).resolve()),
        "training_files": [str(path.resolve()) for path in files],
        "feature_names": FeatureExtractor.FEATURE_NAMES.copy(),
        "feature_count": len(FeatureExtractor.FEATURE_NAMES),
        "feature_source": "network_engine.feature_extractor.FeatureExtractor",
        "cic_alignment": "CICFlowMeter columns mapped to live FeatureExtractor semantics",
        "constant_features": {
            "source_port": 0.0,
        },
        "contamination": args.contamination,
        "random_state": args.random_state,
        "n_estimators": args.n_estimators,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "training_records": int(features.shape[0]),
    }
    detector.save(args.output, metadata=metadata)

    if not args.output.exists() or args.output.stat().st_size == 0:
        raise RuntimeError(f"Model artifact was not written: {args.output}")

    loaded = joblib.load(args.output)
    if not isinstance(loaded, dict) or "model" not in loaded or "scaler" not in loaded:
        raise RuntimeError("Saved anomaly artifact is not a compatible detector payload")
    restored = AnomalyDetector.load(args.output)
    scores = restored.decision_function(features[: min(len(features), 10_000)])
    predictions = restored.predict(features[: min(len(features), 10_000)])
    print(
        f"Saved {args.output} ({args.output.stat().st_size:,} bytes) | "
        f"score min/max/mean/std={scores.min():.4f}/{scores.max():.4f}/"
        f"{scores.mean():.4f}/{scores.std():.4f} | "
        f"anomalies={int((predictions == -1).sum())}/{len(predictions)}"
    )
    print(f"Feature schema ({len(FeatureExtractor.FEATURE_NAMES)}): {FeatureExtractor.FEATURE_NAMES}")


if __name__ == "__main__":
    main()
