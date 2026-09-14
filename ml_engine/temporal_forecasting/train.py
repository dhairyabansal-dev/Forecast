import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader

from dataset import ThreatSequenceDataset, train_val_split
from model import build_model

DEFAULT_SERIES_PATH = "data/processed/sequences/threat_level_series.csv"
DEFAULT_MODEL_OUTPUT = "ml-engine/saved_models/temporal_model.pt"


def make_sliding_windows(series: np.ndarray, sequence_length: int, horizon: int):
    X, y = [], []
    for start in range(len(series) - sequence_length - horizon + 1):
        X.append(series[start: start + sequence_length])
        y.append(series[start + sequence_length: start + sequence_length + horizon])
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.float32)


def train_one_epoch(model, loader, optimizer, criterion, device) -> float:
    model.train()
    total_loss = 0.0
    for X_batch, y_batch in loader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)
        optimizer.zero_grad()
        preds = model(X_batch, horizon=y_batch.size(1))
        loss = criterion(preds, y_batch)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        total_loss += loss.item() * X_batch.size(0)
    return total_loss / len(loader.dataset)


@torch.no_grad()
def evaluate(model, loader, criterion, device) -> float:
    model.eval()
    total_loss = 0.0
    for X_batch, y_batch in loader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)
        preds = model(X_batch, horizon=y_batch.size(1))
        loss = criterion(preds, y_batch)
        total_loss += loss.item() * X_batch.size(0)
    return total_loss / len(loader.dataset)


def main():
    parser = argparse.ArgumentParser(description="Train the temporal threat forecasting LSTM.")
    parser.add_argument("--series", default=DEFAULT_SERIES_PATH)
    parser.add_argument("--output", default=DEFAULT_MODEL_OUTPUT)
    parser.add_argument("--sequence-length", type=int, default=48)
    parser.add_argument("--horizon", type=int, default=24)
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    df = pd.read_csv(args.series)
    series = df["threat_level"].to_numpy(dtype=np.float32)

    X, y = make_sliding_windows(series, args.sequence_length, args.horizon)
    print(f"Built {len(X)} training windows (seq_len={args.sequence_length}, horizon={args.horizon})")

    (X_train, y_train), (X_val, y_val) = train_val_split(X, y, val_ratio=0.2)

    train_loader = DataLoader(ThreatSequenceDataset(X_train, y_train), batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(ThreatSequenceDataset(X_val, y_val), batch_size=args.batch_size, shuffle=False)

    model = build_model(num_features=1, max_horizon=args.horizon).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = torch.nn.MSELoss()

    best_val_loss = float("inf")
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    for epoch in range(1, args.epochs + 1):
        train_loss = train_one_epoch(model, train_loader, optimizer, criterion, device)
        val_loss = evaluate(model, val_loader, criterion, device)

        print(f"Epoch {epoch}/{args.epochs} - train_loss: {train_loss:.5f} - val_loss: {val_loss:.5f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model, args.output)
            print(f"  New best model saved (val_loss={val_loss:.5f})")

    print(f"Training complete. Best val_loss: {best_val_loss:.5f}. Model at {args.output}")


if __name__ == "__main__":
    main()