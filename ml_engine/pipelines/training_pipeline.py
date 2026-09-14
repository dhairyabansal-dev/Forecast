import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anomaly_detection.isolation_forest import AnomalyDetector
from feature_engineering.feature_pipeline import FeaturePipeline
from feature_engineering.temporal_features import (
    aggregate_to_time_buckets,
    build_threat_level_series,
)
from temporal_forecasting.dataset import ThreatSequenceDataset, train_val_split
from temporal_forecasting.model import build_model

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader


def run_anomaly_training(raw_flows_path: str, model_output: str):
    print("=== Anomaly Detection Training ===")
    flows_df = pd.read_json(raw_flows_path, lines=True) if raw_flows_path.endswith(".jsonl") \
        else pd.read_csv(raw_flows_path)

    pipeline = FeaturePipeline()
    features_df = pipeline.transform(flows_df.to_dict(orient="records"))
    X = pipeline.to_model_input(features_df)

    detector = AnomalyDetector()
    detector.fit(X)
    detector.save(model_output)
    print(f"Anomaly model saved to {model_output}")
    return features_df


def run_forecasting_training(
    anomalies_csv: str,
    model_output: str,
    sequence_length: int = 48,
    horizon: int = 24,
    epochs: int = 30,
):
    print("=== Temporal Forecasting Training ===")
    events_df = pd.read_csv(anomalies_csv)

    bucketed = aggregate_to_time_buckets(events_df, bucket_minutes=60)
    series = build_threat_level_series(bucketed)

    from temporal_forecasting.train import make_sliding_windows

    X, y = make_sliding_windows(series.astype(np.float32), sequence_length, horizon)
    (X_train, y_train), (X_val, y_val) = train_val_split(X, y, val_ratio=0.2)

    train_loader = DataLoader(ThreatSequenceDataset(X_train, y_train), batch_size=16, shuffle=True)
    val_loader = DataLoader(ThreatSequenceDataset(X_val, y_val), batch_size=16, shuffle=False)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = build_model(num_features=1, max_horizon=horizon).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = torch.nn.MSELoss()

    best_val_loss = float("inf")
    for epoch in range(1, epochs + 1):
        model.train()
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            preds = model(X_batch, horizon=y_batch.size(1))
            loss = criterion(preds, y_batch)
            loss.backward()
            optimizer.step()

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                preds = model(X_batch, horizon=y_batch.size(1))
                val_loss += criterion(preds, y_batch).item() * X_batch.size(0)
        val_loss /= len(val_loader.dataset)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            Path(model_output).parent.mkdir(parents=True, exist_ok=True)
            torch.save(model, model_output)

        if epoch % 5 == 0 or epoch == epochs:
            print(f"Epoch {epoch}/{epochs} - val_loss: {val_loss:.5f}")

    print(f"Forecasting model saved to {model_output}")


def main():
    parser = argparse.ArgumentParser(description="Run the full ML training pipeline.")
    parser.add_argument("--raw-flows", default="data/raw/datasets/flows.csv")
    parser.add_argument("--anomalies", default="data/processed/features/anomalies_history.csv")
    parser.add_argument("--anomaly-model-out", default="ml-engine/saved_models/anomaly_model.pkl")
    parser.add_argument("--temporal-model-out", default="ml-engine/saved_models/temporal_model.pt")
    parser.add_argument("--skip-anomaly", action="store_true")
    parser.add_argument("--skip-forecasting", action="store_true")
    args = parser.parse_args()

    if not args.skip_anomaly:
        run_anomaly_training(args.raw_flows, args.anomaly_model_out)

    if not args.skip_forecasting:
        run_forecasting_training(args.anomalies, args.temporal_model_out)


if __name__ == "__main__":
    main()